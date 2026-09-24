// Command meeks is a URL-based, end-to-end encrypted group chat server.
//
//	meeks serve  [flags]   run the server (default)
//	meeks lookup [flags]   search the IP log (for disclosure requests)
package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"meeks/internal/iplog"
	"meeks/internal/signaling"
	"meeks/internal/store"
	"meeks/internal/turnserver"
	"meeks/web"
)

func main() {
	args := os.Args[1:]
	cmd := "serve"
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		cmd, args = args[0], args[1:]
	}
	var err error
	switch cmd {
	case "serve":
		err = serve(args)
	case "lookup":
		err = lookup(args)
	default:
		err = fmt.Errorf("unknown command %q (want serve or lookup)", cmd)
	}
	if err != nil {
		log.Fatal(err)
	}
}

func serve(args []string) error {
	fset := flag.NewFlagSet("serve", flag.ExitOnError)
	addr := fset.String("addr", ":8080", "HTTP listen address")
	tlsCert := fset.String("tls-cert", "", "TLS certificate file (HTTPS is required for camera access except on localhost)")
	tlsKey := fset.String("tls-key", "", "TLS key file")
	siteURL := fset.String("site-url", "", "public URL used in SEO metadata, e.g. https://meeks.example.com (default: from the request)")
	trustProxy := fset.Bool("trust-proxy", false, "trust X-Real-IP / X-Forwarded-For / X-Real-Port from a reverse proxy")
	maxPeers := fset.Int("max-peers", 16, "maximum participants per room")
	logDir := fset.String("iplog-dir", "data/iplog", "IP log directory")
	logDays := fset.Int("iplog-days", 730, "IP log retention in days (730 = 2 years)")
	stateFile := fset.String("state-file", "data/state.json", "file holding rooms and pending join requests")
	roomDays := fset.Int("room-days", 730, "forget rooms unused for this many days")
	turnOn := fset.Bool("turn", true, "run the embedded STUN/TURN server")
	turnAddr := fset.String("turn-addr", ":3478", "STUN/TURN listen address (UDP+TCP)")
	turnIP := fset.String("turn-public-ip", "127.0.0.1", "public IP advertised for TURN relays")
	turnHost := fset.String("turn-host", "", "hostname clients use for STUN/TURN (default: the HTTP Host)")
	turnSecret := fset.String("turn-secret", "", "shared secret for TURN credentials (default: random per start)")
	turnMin := fset.Uint("turn-relay-min", 49160, "lowest TURN relay port")
	turnMax := fset.Uint("turn-relay-max", 49200, "highest TURN relay port")
	turnPrivate := fset.Bool("turn-allow-private", false, "allow relaying to private/loopback addresses (development only)")
	fset.Parse(args)

	ipl, err := iplog.New(*logDir, time.Duration(*logDays)*24*time.Hour)
	if err != nil {
		return err
	}
	defer ipl.Close()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go ipl.Run(ctx)

	st, err := store.Open(*stateFile, time.Duration(*roomDays)*24*time.Hour)
	if err != nil {
		return err
	}
	go st.Run(ctx)

	var ice signaling.ICEProvider
	if *turnOn {
		secret := *turnSecret
		if secret == "" {
			secret = randomHex(32)
		}
		ts, err := turnserver.Start(turnserver.Config{
			ListenAddr:   *turnAddr,
			PublicIP:     *turnIP,
			Realm:        "meeks",
			Secret:       secret,
			RelayMinPort: uint16(*turnMin),
			RelayMaxPort: uint16(*turnMax),
			AllowPrivate: *turnPrivate,
			IPLog:        ipl,
		})
		if err != nil {
			return err
		}
		defer ts.Close()
		port := (*turnAddr)[strings.LastIndexByte(*turnAddr, ':')+1:]
		ice = func(peerID, host string) []signaling.ICEServer {
			if *turnHost != "" {
				host = *turnHost
			}
			if strings.Contains(host, ":") { // IPv6 literal
				host = "[" + host + "]"
			}
			user, pass, err := ts.Credentials(peerID)
			if err != nil {
				log.Printf("turn credentials: %v", err)
				return []signaling.ICEServer{{URLs: []string{"stun:" + host + ":" + port}}}
			}
			return []signaling.ICEServer{
				{URLs: []string{"stun:" + host + ":" + port}},
				{
					URLs: []string{
						"turn:" + host + ":" + port + "?transport=udp",
						"turn:" + host + ":" + port + "?transport=tcp",
					},
					Username: user, Credential: pass,
				},
			}
		}
		log.Printf("STUN/TURN listening on %s (relay IP %s)", *turnAddr, *turnIP)
	}

	hub := signaling.NewHub(signaling.Config{
		MaxPeers:   *maxPeers,
		TrustProxy: *trustProxy,
		IPLog:      ipl,
		ICE:        ice,
		Store:      st,
	})

	static, err := fs.Sub(web.Files, "static")
	if err != nil {
		return err
	}
	pages, err := newSite(static, web.Templates, *siteURL, *trustProxy)
	if err != nil {
		return err
	}
	mux := http.NewServeMux()
	pages.register(mux)
	mux.HandleFunc("GET /ws/{room}", hub.ServeWS)
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	})

	srv := &http.Server{
		Addr:              *addr,
		Handler:           securityHeaders(mux),
		ReadHeaderTimeout: 10 * time.Second,
	}
	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		srv.Shutdown(sctx)
	}()

	log.Printf("Meeks listening on %s", *addr)
	if *tlsCert != "" {
		err = srv.ListenAndServeTLS(*tlsCert, *tlsKey)
	} else {
		err = srv.ListenAndServe()
	}
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; "+
			"img-src 'self' blob: data:; media-src 'self' blob:; connect-src 'self' ws: wss:; "+
			"object-src 'none'; base-uri 'none'; frame-ancestors 'none'")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Permissions-Policy", "camera=(self), microphone=(self), geolocation=()")
		next.ServeHTTP(w, r)
	})
}

func lookup(args []string) error {
	fset := flag.NewFlagSet("lookup", flag.ExitOnError)
	dir := fset.String("iplog-dir", "data/iplog", "IP log directory")
	room := fset.String("room", "", "room ID (the path of the room URL, e.g. team-meeting)")
	ip := fset.String("ip", "", "IP address")
	from := fset.String("from", "", "start time, RFC3339 or YYYY-MM-DD (UTC)")
	to := fset.String("to", "", "end time (exclusive), RFC3339 or YYYY-MM-DD (UTC)")
	fset.Parse(args)

	q := iplog.Query{RoomID: *room, IP: *ip}
	var err error
	if q.From, err = parseTime(*from); err != nil {
		return err
	}
	if q.To, err = parseTime(*to); err != nil {
		return err
	}
	entries, err := iplog.Search(*dir, q)
	if err != nil {
		return err
	}
	enc := json.NewEncoder(os.Stdout)
	for _, e := range entries {
		enc.Encode(e)
	}
	return nil
}

func parseTime(s string) (time.Time, error) {
	if s == "" {
		return time.Time{}, nil
	}
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t, nil
	}
	return time.Parse("2006-01-02", s)
}

func randomHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}

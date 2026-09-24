// Package turnserver runs an embedded STUN/TURN server. STUN lets peers
// discover their public address for direct P2P connections; TURN relays
// traffic when a direct connection is impossible (symmetric NAT, strict
// firewalls). Relayed WebRTC traffic stays DTLS/SRTP-encrypted end to end,
// so the relay cannot read it.
//
// To keep the relay from being used by unrelated applications, credentials
// only work while the signaling session they were issued to is connected,
// and the number of simultaneous relays is capped per session and overall.
package turnserver

import (
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/pion/logging"
	"github.com/pion/turn/v4"

	"meeks/internal/iplog"
)

// CredentialTTL is how long issued TURN credentials stay valid.
const CredentialTTL = 12 * time.Hour

// Config configures the TURN server.
type Config struct {
	ListenAddr   string // e.g. ":3478" (UDP and TCP)
	PublicIP     string // address advertised in relay candidates
	Realm        string
	Secret       string
	RelayMinPort uint16
	RelayMaxPort uint16
	// AllowPrivate permits relaying to loopback/private addresses. Only
	// enable it for local development: otherwise the relay could be used to
	// reach the server's internal network.
	AllowPrivate bool
	IPLog        *iplog.Logger
	// Authorize reports whether the signaling session (peer ID) that a
	// credential was issued to is still connected. Nil allows every peer.
	Authorize func(peerID string) bool
	// MaxAllocsPerPeer and MaxAllocs cap simultaneous relays (0 = no cap).
	MaxAllocsPerPeer int
	MaxAllocs        int
}

// Server wraps a pion TURN server.
type Server struct {
	srv     *turn.Server
	secret  string
	udpAddr net.Addr

	mu     sync.Mutex
	logged map[string]time.Time
	ipLog  *iplog.Logger

	allocMu    sync.Mutex
	allocs     map[string]int // peer ID -> live relays
	allocTotal int
}

// Start listens on UDP and TCP.
func Start(cfg Config) (*Server, error) {
	ip := net.ParseIP(cfg.PublicIP)
	if ip == nil {
		return nil, fmt.Errorf("turn: invalid public IP %q", cfg.PublicIP)
	}
	udp, err := net.ListenPacket("udp4", cfg.ListenAddr)
	if err != nil {
		return nil, fmt.Errorf("turn: listen udp: %w", err)
	}
	tcp, err := net.Listen("tcp4", cfg.ListenAddr)
	if err != nil {
		udp.Close()
		return nil, fmt.Errorf("turn: listen tcp: %w", err)
	}

	s := &Server{secret: cfg.Secret, logged: map[string]time.Time{}, ipLog: cfg.IPLog, allocs: map[string]int{}}
	lf := logging.NewDefaultLoggerFactory()
	lf.DefaultLogLevel = logging.LogLevelWarn
	baseAuth := turn.LongTermTURNRESTAuthHandler(cfg.Secret, lf.NewLogger("turn"))

	relayGen := func() turn.RelayAddressGenerator {
		return &turn.RelayAddressGeneratorPortRange{
			RelayAddress: ip,
			Address:      "0.0.0.0",
			MinPort:      cfg.RelayMinPort,
			MaxPort:      cfg.RelayMaxPort,
		}
	}
	perm := func(_ net.Addr, peer net.IP) bool {
		if cfg.AllowPrivate {
			return true
		}
		return !(peer.IsLoopback() || peer.IsPrivate() || peer.IsUnspecified() ||
			peer.IsLinkLocalUnicast() || peer.IsMulticast())
	}

	srv, err := turn.NewServer(turn.ServerConfig{
		Realm:         cfg.Realm,
		LoggerFactory: lf,
		// Runs for every Allocate / Refresh / CreatePermission / ChannelBind,
		// so relays of a session that disconnected stop at their next refresh.
		AuthHandler: func(username, realm string, src net.Addr) ([]byte, bool) {
			if cfg.Authorize != nil && !cfg.Authorize(peerOf(username)) {
				return nil, false
			}
			key, ok := baseAuth(username, realm, src)
			if ok {
				s.logAuth(username, src)
			}
			return key, ok
		},
		QuotaHandler: func(username, _ string, _ net.Addr) bool {
			s.allocMu.Lock()
			defer s.allocMu.Unlock()
			if cfg.MaxAllocs > 0 && s.allocTotal >= cfg.MaxAllocs {
				return false
			}
			return cfg.MaxAllocsPerPeer <= 0 || s.allocs[peerOf(username)] < cfg.MaxAllocsPerPeer
		},
		EventHandler: turn.EventHandler{
			OnAllocationCreated: func(_, _ net.Addr, _, username, _ string, _ net.Addr, _ int) {
				s.allocMu.Lock()
				s.allocs[peerOf(username)]++
				s.allocTotal++
				s.allocMu.Unlock()
			},
			OnAllocationDeleted: func(_, _ net.Addr, _, username, _ string) {
				s.allocMu.Lock()
				p := peerOf(username)
				if s.allocs[p]--; s.allocs[p] <= 0 {
					delete(s.allocs, p)
				}
				s.allocTotal--
				s.allocMu.Unlock()
			},
		},
		PacketConnConfigs: []turn.PacketConnConfig{{
			PacketConn: udp, RelayAddressGenerator: relayGen(), PermissionHandler: perm,
		}},
		ListenerConfigs: []turn.ListenerConfig{{
			Listener: tcp, RelayAddressGenerator: relayGen(), PermissionHandler: perm,
		}},
	})
	if err != nil {
		udp.Close()
		tcp.Close()
		return nil, err
	}
	s.srv = srv
	s.udpAddr = udp.LocalAddr()
	return s, nil
}

// Credentials issues time-limited credentials tied to a signaling peer ID,
// so TURN usage in the IP log can be traced back to the room join.
func (s *Server) Credentials(peerID string) (username, password string, err error) {
	return turn.GenerateLongTermTURNRESTCredentials(s.secret, peerID, CredentialTTL)
}

// UDPAddr is the address the server listens on for UDP.
func (s *Server) UDPAddr() net.Addr { return s.udpAddr }

// Allocations returns the number of live relays (for tests and metrics).
func (s *Server) Allocations() int {
	s.allocMu.Lock()
	defer s.allocMu.Unlock()
	return s.allocTotal
}

// peerOf extracts the peer ID from a TURN REST username ("expiry:peerID").
func peerOf(username string) string {
	if i := strings.IndexByte(username, ':'); i >= 0 {
		return username[i+1:]
	}
	return username
}

// Close stops the server.
func (s *Server) Close() error { return s.srv.Close() }

// logAuth records each (credential, source address) pair once per hour.
// The auth handler runs for every authenticated request, so without this
// the log would grow with every allocation refresh.
func (s *Server) logAuth(username string, src net.Addr) {
	if s.ipLog == nil {
		return
	}
	key := username + "|" + src.String()
	now := time.Now()
	s.mu.Lock()
	if t, ok := s.logged[key]; ok && now.Sub(t) < time.Hour {
		s.mu.Unlock()
		return
	}
	s.logged[key] = now
	if len(s.logged) > 10000 {
		for k, t := range s.logged {
			if now.Sub(t) >= time.Hour {
				delete(s.logged, k)
			}
		}
	}
	s.mu.Unlock()

	var ip string
	var port int
	switch a := src.(type) {
	case *net.UDPAddr:
		ip, port = a.IP.String(), a.Port
	case *net.TCPAddr:
		ip, port = a.IP.String(), a.Port
	default:
		ip = src.String()
	}
	s.ipLog.Log(iplog.Entry{Event: iplog.EventTURNAuth, IP: ip, Port: port, Peer: peerOf(username)})
}

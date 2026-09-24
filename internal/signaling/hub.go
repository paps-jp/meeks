// Package signaling matches peers that share a room URL and forwards
// opaque, end-to-end encrypted payloads between them.
//
// The server never stores messages. It forwards three kinds of payloads:
//   - "kx": key holders announcing their key ID to each other.
//   - "signal": WebRTC session descriptions / ICE candidates used to set up
//     a direct P2P connection (encrypted with the room key).
//   - "relay": application data sent through the server when a P2P
//     connection cannot be established.
//
// Join approvals (see join.go) are the only state it keeps.
package signaling

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"log"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/coder/websocket"

	"meeks/internal/iplog"
	"meeks/internal/store"
)

const (
	// MaxMessageSize bounds a single inbound WebSocket message.
	MaxMessageSize = 1 << 20
	sendQueueLen   = 512
	pingInterval   = 25 * time.Second
	writeTimeout   = 10 * time.Second

	// Per-connection rate limits (per second).
	maxMsgsPerSec  = 1000
	maxBytesPerSec = 16 << 20
)

var roomIDPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)

// reservedRoomIDs are top-level paths the server uses itself (rooms live at
// /{room}).
var reservedRoomIDs = map[string]bool{"static": true, "ws": true, "r": true, "healthz": true}

// ReserveRoomIDs adds top-level paths that must not be used as rooms (for
// example localized landing pages such as /en). Call it before serving.
func ReserveRoomIDs(ids ...string) {
	for _, id := range ids {
		reservedRoomIDs[id] = true
	}
}

// ValidRoomID reports whether id can be used as a room identifier.
func ValidRoomID(id string) bool { return roomIDPattern.MatchString(id) && !reservedRoomIDs[id] }

// ICEServer is the RTCIceServer shape sent to browsers.
type ICEServer struct {
	URLs       []string `json:"urls"`
	Username   string   `json:"username,omitempty"`
	Credential string   `json:"credential,omitempty"`
}

// ICEProvider returns ICE servers for a newly joined peer.
// host is the hostname the client used to reach this server.
type ICEProvider func(peerID, host string) []ICEServer

// Config configures a Hub.
type Config struct {
	MaxPeers   int
	TrustProxy bool // take client IP from X-Forwarded-For / X-Real-IP
	IPLog      *iplog.Logger
	ICE        ICEProvider
	Store      *store.Store // rooms and join requests (required)
}

// Hub holds all rooms.
type Hub struct {
	cfg   Config
	mu    sync.Mutex
	rooms map[string]map[string]*client
}

type client struct {
	id   string
	room string
	ip   string
	port int
	send chan []byte
	// closed when the client must be dropped (e.g. its send queue overflowed)
	kick     chan struct{}
	kickOnce sync.Once
	// reqID is the join request this connection submitted, if any.
	// Guarded by Hub.mu.
	reqID string
}

func (c *client) drop() { c.kickOnce.Do(func() { close(c.kick) }) }

// inbound is a message from a browser.
type inbound struct {
	Type string          `json:"type"`
	To   string          `json:"to,omitempty"`
	Data json.RawMessage `json:"data,omitempty"`
}

// outbound is a message to a browser.
type outbound struct {
	Type  string          `json:"type"`
	ID    string          `json:"id,omitempty"`
	From  string          `json:"from,omitempty"`
	Peers []string        `json:"peers,omitempty"`
	ICE   []ICEServer     `json:"iceServers,omitempty"`
	Data  json.RawMessage `json:"data,omitempty"`
	Error string          `json:"error,omitempty"`

	Exists   *bool              `json:"exists,omitempty"`
	OK       *bool              `json:"ok,omitempty"`
	Requests []store.Request    `json:"requests,omitempty"`
	Request  *store.Request     `json:"request,omitempty"`
	InboxPub string             `json:"inboxPub,omitempty"`
	Message  *store.JoinMessage `json:"message,omitempty"`
}

// NewHub creates a hub.
func NewHub(cfg Config) *Hub {
	if cfg.MaxPeers <= 0 {
		cfg.MaxPeers = 16
	}
	return &Hub{cfg: cfg, rooms: map[string]map[string]*client{}}
}

// ServeWS handles GET /ws/{room}.
func (h *Hub) ServeWS(w http.ResponseWriter, r *http.Request) {
	roomID := r.PathValue("room")
	if !ValidRoomID(roomID) {
		http.Error(w, "invalid room", http.StatusBadRequest)
		return
	}
	// Default origin check: only same-host pages may connect.
	conn, err := websocket.Accept(w, r, nil)
	if err != nil {
		return
	}
	conn.SetReadLimit(MaxMessageSize)

	ip, port := ClientAddr(r, h.cfg.TrustProxy)
	c := &client{
		id:   newID(),
		room: roomID,
		ip:   ip,
		port: port,
		send: make(chan []byte, sendQueueLen),
		kick: make(chan struct{}),
	}

	peers, ok := h.join(c)
	if !ok {
		conn.Close(websocket.StatusPolicyViolation, "room is full")
		return
	}
	h.logEvent(iplog.EventConnect, ip, port, c, r.UserAgent())
	defer func() {
		h.logEvent(iplog.EventDisconnect, ip, port, c, "")
		h.leave(c)
	}()

	var ice []ICEServer
	if h.cfg.ICE != nil {
		ice = h.cfg.ICE(c.id, hostOnly(r.Host))
	}
	exists := h.cfg.Store.Exists(roomID)
	c.enqueue(mustJSON(outbound{
		Type: "welcome", ID: c.id, Peers: peers, ICE: ice,
		Exists: &exists, Requests: h.cfg.Store.Pending(roomID),
	}))

	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()
	go c.writeLoop(ctx, conn, cancel)
	h.readLoop(ctx, conn, c)
	conn.Close(websocket.StatusNormalClosure, "")
}

func (h *Hub) readLoop(ctx context.Context, conn *websocket.Conn, c *client) {
	window := time.Now()
	msgs, bytes := 0, 0
	for {
		typ, data, err := conn.Read(ctx)
		if err != nil {
			return
		}
		if typ != websocket.MessageText {
			continue
		}
		if now := time.Now(); now.Sub(window) >= time.Second {
			window, msgs, bytes = now, 0, 0
		}
		msgs++
		bytes += len(data)
		if msgs > maxMsgsPerSec || bytes > maxBytesPerSec {
			conn.Close(websocket.StatusPolicyViolation, "rate limit")
			return
		}

		var m inbound
		if err := json.Unmarshal(data, &m); err != nil {
			continue
		}
		switch m.Type {
		case "signal", "kx":
			if m.To == "" || len(m.Data) == 0 {
				continue
			}
			h.forward(c, m.To, mustJSON(outbound{Type: m.Type, From: c.id, Data: m.Data}))
		case "relay":
			if len(m.Data) == 0 {
				continue
			}
			h.forward(c, m.To, mustJSON(outbound{Type: "relay", From: c.id, Data: m.Data}))
		default:
			h.handleJoin(c, m)
		}
	}
}

func (c *client) writeLoop(ctx context.Context, conn *websocket.Conn, cancel context.CancelFunc) {
	defer cancel()
	ping := time.NewTicker(pingInterval)
	defer ping.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-c.kick:
			conn.Close(websocket.StatusTryAgainLater, "too slow")
			return
		case msg := <-c.send:
			wctx, wcancel := context.WithTimeout(ctx, writeTimeout)
			err := conn.Write(wctx, websocket.MessageText, msg)
			wcancel()
			if err != nil {
				return
			}
		case <-ping.C:
			pctx, pcancel := context.WithTimeout(ctx, writeTimeout)
			err := conn.Ping(pctx)
			pcancel()
			if err != nil {
				return
			}
		}
	}
}

// enqueue never blocks: a peer that cannot keep up is disconnected rather
// than silently losing messages (it will reconnect and resync).
func (c *client) enqueue(msg []byte) {
	select {
	case c.send <- msg:
	default:
		c.drop()
	}
}

func (h *Hub) join(c *client) (peers []string, ok bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	room := h.rooms[c.room]
	if room == nil {
		room = map[string]*client{}
		h.rooms[c.room] = room
	}
	if len(room) >= h.cfg.MaxPeers {
		return nil, false
	}
	joined := mustJSON(outbound{Type: "peer-joined", ID: c.id})
	for id, p := range room {
		peers = append(peers, id)
		p.enqueue(joined)
	}
	room[c.id] = c
	return peers, true
}

func (h *Hub) leave(c *client) {
	h.mu.Lock()
	defer h.mu.Unlock()
	room := h.rooms[c.room]
	delete(room, c.id)
	if len(room) == 0 {
		delete(h.rooms, c.room)
		return
	}
	left := mustJSON(outbound{Type: "peer-left", ID: c.id})
	for _, p := range room {
		p.enqueue(left)
	}
}

// forward sends msg to one peer (to != "") or every other peer in the room.
func (h *Hub) forward(from *client, to string, msg []byte) {
	h.mu.Lock()
	defer h.mu.Unlock()
	room := h.rooms[from.room]
	if to != "" {
		if p := room[to]; p != nil && p != from {
			p.enqueue(msg)
		}
		return
	}
	for _, p := range room {
		if p != from {
			p.enqueue(msg)
		}
	}
}

// RoomCount returns the number of active rooms (for tests/metrics).
func (h *Hub) RoomCount() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.rooms)
}

func (h *Hub) logEvent(event, ip string, port int, c *client, ua string) {
	if h.cfg.IPLog == nil {
		return
	}
	h.cfg.IPLog.Log(iplog.Entry{
		Event:     event,
		IP:        ip,
		Port:      port,
		Room:      iplog.RoomHash(c.room),
		Peer:      c.id,
		UserAgent: ua,
	})
}

// ClientAddr returns the client IP and source port. With trustProxy the
// values set by a reverse proxy are used (X-Real-IP / rightmost
// X-Forwarded-For, and X-Real-Port for the source port, which is needed to
// identify subscribers behind carrier-grade NAT).
func ClientAddr(r *http.Request, trustProxy bool) (string, int) {
	host, portStr, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	port, _ := strconv.Atoi(portStr)
	if !trustProxy {
		return host, port
	}
	if v := strings.TrimSpace(r.Header.Get("X-Real-IP")); v != "" {
		host = v
	} else if v := r.Header.Get("X-Forwarded-For"); v != "" {
		parts := strings.Split(v, ",")
		host = strings.TrimSpace(parts[len(parts)-1])
	}
	if v := r.Header.Get("X-Real-Port"); v != "" {
		if p, err := strconv.Atoi(v); err == nil {
			port = p
		} else {
			port = 0
		}
	} else {
		port = 0 // the proxy's port is meaningless
	}
	return host, port
}

func hostOnly(hostport string) string {
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		return h
	}
	return strings.Trim(hostport, "[]")
}

func newID() string {
	b := make([]byte, 12)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}

func mustJSON(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		log.Panicf("signaling: marshal: %v", err)
	}
	return b
}

package signaling

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"

	"meeks/internal/iplog"
	"meeks/internal/store"
)

func dial(t *testing.T, ctx context.Context, srv *httptest.Server, room string) *websocket.Conn {
	t.Helper()
	c, _, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(srv.URL, "http")+"/ws/"+room, nil)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func read(t *testing.T, ctx context.Context, c *websocket.Conn) outbound {
	t.Helper()
	_, b, err := c.Read(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var m outbound
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func write(t *testing.T, ctx context.Context, c *websocket.Conn, m inbound) {
	t.Helper()
	b, _ := json.Marshal(m)
	if err := c.Write(ctx, websocket.MessageText, b); err != nil {
		t.Fatal(err)
	}
}

func newTestHub(t *testing.T, maxPeers int) (*Hub, *httptest.Server) {
	t.Helper()
	logs, err := iplog.New(t.TempDir(), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(filepath.Join(t.TempDir(), "state.json"), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	hub := NewHub(Config{MaxPeers: maxPeers, IPLog: logs, Store: st})
	mux := http.NewServeMux()
	mux.HandleFunc("GET /ws/{room}", hub.ServeWS)
	srv := httptest.NewServer(mux)
	t.Cleanup(func() {
		srv.Close()
		// Let disconnect logging finish before the log directory is removed.
		for hub.RoomCount() > 0 {
			time.Sleep(10 * time.Millisecond)
		}
		logs.Close()
	})
	return hub, srv
}

func TestHubRouting(t *testing.T) {
	_, srv := newTestHub(t, 2)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	a := dial(t, ctx, srv, "room1")
	wa := read(t, ctx, a)
	if wa.Type != "welcome" || len(wa.Peers) != 0 {
		t.Fatalf("a welcome = %+v", wa)
	}
	b := dial(t, ctx, srv, "room1")
	wb := read(t, ctx, b)
	if len(wb.Peers) != 1 || wb.Peers[0] != wa.ID {
		t.Fatalf("b welcome = %+v", wb)
	}
	if j := read(t, ctx, a); j.Type != "peer-joined" || j.ID != wb.ID {
		t.Fatalf("a got %+v", j)
	}

	// A peer in another room must not receive anything.
	other := dial(t, ctx, srv, "room2")
	read(t, ctx, other)

	write(t, ctx, a, inbound{Type: "signal", To: wb.ID, Data: json.RawMessage(`"sdp"`)})
	if m := read(t, ctx, b); m.Type != "signal" || m.From != wa.ID || string(m.Data) != `"sdp"` {
		t.Fatalf("b got %+v", m)
	}
	write(t, ctx, b, inbound{Type: "kx", To: wa.ID, Data: json.RawMessage(`{"pub":"x"}`)})
	if m := read(t, ctx, a); m.Type != "kx" || m.From != wb.ID || string(m.Data) != `{"pub":"x"}` {
		t.Fatalf("a got %+v", m)
	}
	write(t, ctx, b, inbound{Type: "relay", Data: json.RawMessage(`"cipher"`)})
	if m := read(t, ctx, a); m.Type != "relay" || m.From != wb.ID || string(m.Data) != `"cipher"` {
		t.Fatalf("a got %+v", m)
	}

	// Room is full at 2.
	c := dial(t, ctx, srv, "room1")
	if _, _, err := c.Read(ctx); websocket.CloseStatus(err) != websocket.StatusPolicyViolation {
		t.Fatalf("third peer: err = %v", err)
	}

	b.Close(websocket.StatusNormalClosure, "")
	if m := read(t, ctx, a); m.Type != "peer-left" || m.ID != wb.ID {
		t.Fatalf("a got %+v", m)
	}

	shortCtx, shortCancel := context.WithTimeout(ctx, 200*time.Millisecond)
	defer shortCancel()
	if _, _, err := other.Read(shortCtx); err == nil {
		t.Fatal("peer in another room received a message")
	}

	a.Close(websocket.StatusNormalClosure, "")
	other.Close(websocket.StatusNormalClosure, "")
}

// A request made while nobody is online is approved later and delivered
// the next time the applicant connects.
func TestJoinApprovalOffline(t *testing.T) {
	hub, srv := newTestHub(t, 4)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	waitEmpty := func() {
		for hub.RoomCount() > 0 {
			time.Sleep(10 * time.Millisecond)
		}
	}
	pub := func(b byte) string {
		p := make([]byte, 65)
		p[0], p[1] = 4, b
		return base64.RawURLEncoding.EncodeToString(p)
	}

	// Alice creates the room and leaves.
	a := dial(t, ctx, srv, "room-r")
	if w := read(t, ctx, a); w.Exists == nil || *w.Exists {
		t.Fatalf("new room welcome = %+v", w)
	}
	write(t, ctx, a, inbound{Type: "claim", Data: json.RawMessage(`{"create":true}`)})
	if m := read(t, ctx, a); m.Type != "claim-result" || !*m.OK {
		t.Fatalf("claim = %+v", m)
	}
	a.Close(websocket.StatusNormalClosure, "")
	waitEmpty()

	// Bob applies with nobody online, then leaves.
	b := dial(t, ctx, srv, "room-r")
	if w := read(t, ctx, b); !*w.Exists {
		t.Fatalf("existing room welcome = %+v", w)
	}
	bobReq := json.RawMessage(`{"name":"Bob","pub":"` + pub(1) + `"}`)
	write(t, ctx, b, inbound{Type: "join-request", Data: bobReq})
	st := read(t, ctx, b)
	if st.Type != "join-status" || st.Request.Status != store.StatusPending {
		t.Fatalf("bob status = %+v", st)
	}
	read(t, ctx, b) // join-requests broadcast
	// An applicant cannot approve itself.
	write(t, ctx, b, inbound{Type: "join-approve", Data: json.RawMessage(
		`{"id":"` + st.Request.ID + `","pub":"` + pub(9) + `","wrap":"x"}`)})
	b.Close(websocket.StatusNormalClosure, "")
	waitEmpty()

	// Alice returns, sees the request and approves it.
	a = dial(t, ctx, srv, "room-r")
	w := read(t, ctx, a)
	if len(w.Requests) != 1 || w.Requests[0].Name != "Bob" {
		t.Fatalf("alice welcome requests = %+v", w.Requests)
	}
	write(t, ctx, a, inbound{Type: "join-approve", Data: json.RawMessage(
		`{"id":"` + st.Request.ID + `","pub":"` + pub(2) + `","wrap":"sealed"}`)})
	if m := read(t, ctx, a); m.Type != "join-requests" || len(m.Requests) != 0 {
		t.Fatalf("alice got %+v", m)
	}
	a.Close(websocket.StatusNormalClosure, "")
	waitEmpty()

	// Bob reconnects and receives the wrapped key.
	b = dial(t, ctx, srv, "room-r")
	read(t, ctx, b)
	write(t, ctx, b, inbound{Type: "join-request", Data: bobReq})
	got := read(t, ctx, b)
	if got.Request == nil || got.Request.Status != store.StatusApproved ||
		got.Request.Wrap != "sealed" || got.Request.ApproverPub != pub(2) {
		t.Fatalf("bob approval = %+v", got)
	}
	b.Close(websocket.StatusNormalClosure, "")
}

func TestClientAddr(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "10.0.0.1:1234"
	r.Header.Set("X-Forwarded-For", "203.0.113.5, 198.51.100.7")
	r.Header.Set("X-Real-Port", "51000")
	if ip, port := ClientAddr(r, false); ip != "10.0.0.1" || port != 1234 {
		t.Errorf("untrusted = %s:%d", ip, port)
	}
	if ip, port := ClientAddr(r, true); ip != "198.51.100.7" || port != 51000 {
		t.Errorf("trusted = %s:%d", ip, port)
	}
}

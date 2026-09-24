package turnserver

import (
	"net"
	"sync"
	"testing"
	"time"

	"github.com/pion/turn/v4"
)

type sessions struct {
	mu   sync.Mutex
	live map[string]bool
}

func (s *sessions) set(peer string, on bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.live[peer] = on
}

func (s *sessions) connected(peer string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.live[peer]
}

func startTest(t *testing.T, perPeer, total int) (*Server, *sessions) {
	t.Helper()
	sess := &sessions{live: map[string]bool{}}
	srv, err := Start(Config{
		ListenAddr: "127.0.0.1:0", PublicIP: "127.0.0.1", Realm: "meeks", Secret: "test-secret",
		RelayMinPort: 45100, RelayMaxPort: 45199, AllowPrivate: true,
		Authorize: sess.connected, MaxAllocsPerPeer: perPeer, MaxAllocs: total,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { srv.Close() })
	return srv, sess
}

// allocate opens a fresh TURN client for peer and tries to allocate a relay.
func allocate(t *testing.T, srv *Server, peer string) (net.PacketConn, *turn.Client, error) {
	t.Helper()
	user, pass, err := srv.Credentials(peer)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	c, err := turn.NewClient(&turn.ClientConfig{
		TURNServerAddr: srv.UDPAddr().String(), STUNServerAddr: srv.UDPAddr().String(),
		Conn: conn, Username: user, Password: pass, Realm: "meeks", RTO: 100 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Listen(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close(); conn.Close() })
	relay, err := c.Allocate()
	return relay, c, err
}

func waitAllocs(t *testing.T, srv *Server, want int) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for srv.Allocations() != want {
		if time.Now().After(deadline) {
			t.Fatalf("allocations = %d, want %d", srv.Allocations(), want)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestOnlyConnectedSessionsCanRelay(t *testing.T) {
	srv, sess := startTest(t, 0, 0)

	if _, _, err := allocate(t, srv, "stranger"); err == nil {
		t.Fatal("allocation succeeded for a session that is not connected")
	}

	sess.set("alice", true)
	relay, _, err := allocate(t, srv, "alice")
	if err != nil {
		t.Fatalf("connected session could not allocate: %v", err)
	}
	if !delivered(t, relay, "127.0.0.1") {
		t.Fatal("relay did not deliver while the session was connected")
	}

	// After the browser leaves the room the relay stops working: reaching a
	// new peer IP needs a permission, which needs authentication, which is
	// now refused. (Permissions are per IP, so a second address is used; the
	// periodic permission and allocation refreshes fail the same way, which
	// ends existing relays within a few minutes.)
	sess.set("alice", false)
	if delivered(t, relay, "127.0.0.2") {
		t.Fatal("relay still delivered after the session disconnected")
	}
}

// delivered sends a datagram through the relay to a fresh peer on ip and
// reports whether it arrived.
func delivered(t *testing.T, relay net.PacketConn, ip string) bool {
	t.Helper()
	peer, err := net.ListenPacket("udp4", ip+":0")
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	relay.WriteTo([]byte("ping"), peer.LocalAddr())
	peer.SetReadDeadline(time.Now().Add(700 * time.Millisecond))
	buf := make([]byte, 16)
	n, _, err := peer.ReadFrom(buf)
	return err == nil && string(buf[:n]) == "ping"
}

func TestAllocationQuotas(t *testing.T) {
	srv, sess := startTest(t, 2, 3)
	sess.set("bob", true)
	sess.set("carol", true)

	for i := 0; i < 2; i++ {
		if _, _, err := allocate(t, srv, "bob"); err != nil {
			t.Fatalf("bob allocation %d: %v", i+1, err)
		}
	}
	if _, _, err := allocate(t, srv, "bob"); err == nil {
		t.Fatal("per-user limit not enforced")
	}
	relay, _, err := allocate(t, srv, "carol")
	if err != nil {
		t.Fatalf("carol allocation: %v", err)
	}
	waitAllocs(t, srv, 3)
	if _, _, err := allocate(t, srv, "carol"); err == nil {
		t.Fatal("total limit not enforced")
	}

	// Closing a relay frees its slot.
	relay.Close()
	waitAllocs(t, srv, 2)
	if _, _, err := allocate(t, srv, "carol"); err != nil {
		t.Fatalf("slot not freed after close: %v", err)
	}
}

package iplog

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLogPurgeSearch(t *testing.T) {
	dir := t.TempDir()
	l, err := New(dir, 730*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 9, 25, 12, 0, 0, 0, time.UTC)
	old := now.AddDate(-2, 0, -2) // beyond retention
	edge := now.AddDate(-2, 0, 1) // just within retention
	l.Log(Entry{Time: old, Event: EventConnect, IP: "192.0.2.1", Room: RoomHash("r1"), Peer: "a"})
	l.Log(Entry{Time: edge, Event: EventConnect, IP: "192.0.2.2", Room: RoomHash("r1"), Peer: "b"})
	l.Log(Entry{Time: now, Event: EventConnect, IP: "192.0.2.3", Port: 40000, Room: RoomHash("r1"), Peer: "c"})
	l.Log(Entry{Time: now, Event: EventTURNAuth, IP: "192.0.2.3", Port: 50000, Peer: "c"})
	l.Log(Entry{Time: now, Event: EventConnect, IP: "198.51.100.9", Room: RoomHash("other"), Peer: "d"})
	l.Close()

	if err := l.Purge(now); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "ip-"+old.Format(dayLayout)+".jsonl")); !os.IsNotExist(err) {
		t.Errorf("expired file not purged: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "ip-"+edge.Format(dayLayout)+".jsonl")); err != nil {
		t.Errorf("file within retention was removed: %v", err)
	}

	got, err := Search(dir, Query{RoomID: "r1"})
	if err != nil {
		t.Fatal(err)
	}
	// b and c's connect + c's TURN auth (linked by peer ID); not "other".
	if len(got) != 3 {
		t.Fatalf("got %d entries, want 3: %+v", len(got), got)
	}
	if got[2].Event != EventTURNAuth || got[2].Port != 50000 {
		t.Errorf("TURN entry not linked to room: %+v", got[2])
	}

	got, _ = Search(dir, Query{IP: "198.51.100.9", From: now.Add(-time.Hour), To: now.Add(time.Hour)})
	if len(got) != 1 || got[0].Peer != "d" {
		t.Errorf("IP search = %+v", got)
	}
}

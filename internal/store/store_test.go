package store

import (
	"encoding/base64"
	"path/filepath"
	"testing"
	"time"
)

func testPub(b byte) string {
	p := make([]byte, 65)
	p[0] = 4
	p[1] = b
	return base64.RawURLEncoding.EncodeToString(p)
}

func TestJoinFlowPersists(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	s, err := Open(path, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Submit("r", "Bob", testPub(1)); err != ErrNotFound {
		t.Fatalf("submit to unknown room: %v", err)
	}
	if !s.Claim("r", true, "") || s.Claim("r", true, "") {
		t.Fatal("create claim should succeed exactly once")
	}
	if !s.Claim("r", false, "") {
		t.Fatal("touch claim failed")
	}
	if _, err := s.Submit("r", "Bob", "short"); err != ErrInvalid {
		t.Fatalf("bad pub: %v", err)
	}
	req, err := s.Submit("r", "Bob", testPub(1))
	if err != nil || req.Status != StatusPending {
		t.Fatalf("submit = %+v, %v", req, err)
	}

	// Survives a restart.
	s2, err := Open(path, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if p := s2.Pending("r"); len(p) != 1 || p[0].Name != "Bob" {
		t.Fatalf("pending after reopen = %+v", p)
	}
	if _, err := s2.Approve("r", req.ID, testPub(2), "wrapped"); err != nil {
		t.Fatal(err)
	}
	if _, err := s2.Reject("r", req.ID); err != ErrNotFound {
		t.Fatalf("second decision: %v", err)
	}
	again, _ := s2.Submit("r", "Bob", testPub(1))
	if again.Status != StatusApproved || again.Wrap != "wrapped" {
		t.Fatalf("resubmit after approval = %+v", again)
	}
	if len(s2.Pending("r")) != 0 {
		t.Fatal("approved request still pending")
	}
	s2.Done("r", req.ID)
	if again, _ := s2.Submit("r", "Bob", testPub(1)); again.Status != StatusPending {
		t.Fatalf("after done = %+v", again)
	}
}

func TestExpiry(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "state.json"), 30*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 9, 25, 0, 0, 0, 0, time.UTC)
	s.now = func() time.Time { return now }
	s.Claim("r", true, "")
	req, _ := s.Submit("r", "Eve", testPub(3))
	s.Reject("r", req.ID)

	now = now.Add(time.Hour)
	if got, _ := s.Submit("r", "Eve", testPub(3)); got.Status != StatusRejected {
		t.Fatalf("within cooldown = %+v", got)
	}
	now = now.Add(25 * time.Hour)
	if got, _ := s.Submit("r", "Eve", testPub(3)); got.Status != StatusPending {
		t.Fatalf("after cooldown = %+v", got)
	}

	now = now.Add(31 * 24 * time.Hour)
	s.Purge()
	if s.Exists("r") {
		t.Fatal("inactive room not purged")
	}
}

func TestJoinMessages(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "state.json"), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	s.Claim("r", true, testPub(7))
	if s.InboxPub("r") != testPub(7) {
		t.Fatal("inbox key not stored")
	}
	req, _ := s.Submit("r", "Bob", testPub(1))
	for i := 0; i < maxMsgsByRequest; i++ {
		if _, err := s.AddMessage("r", req.ID, string(rune('a'+i)), "cipher"); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.AddMessage("r", req.ID, "z", "cipher"); err != ErrFull {
		t.Fatalf("over limit: %v", err)
	}
	if p := s.Pending("r"); len(p[0].Messages) != maxMsgsByRequest {
		t.Fatalf("pending messages = %d", len(p[0].Messages))
	}
	s.Reject("r", req.ID)
	if _, err := s.AddMessage("r", req.ID, "y", "cipher"); err != ErrNotFound {
		t.Fatalf("message after decision: %v", err)
	}
}

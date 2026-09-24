// Package store persists the little state the server needs for join
// approvals: which rooms exist, and pending join requests.
//
// Nothing stored here lets the operator read a room: a request holds the
// applicant's display name and public key, messages exchanged before approval
// are encrypted with a key shared between the applicant and the room's inbox
// key pair, and an approval holds the room key encrypted to the applicant's
// public key. Rooms are identified by a hash of their ID.
package store

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
	"unicode/utf8"
)

// Request statuses.
const (
	StatusPending  = "pending"
	StatusApproved = "approved"
	StatusRejected = "rejected"
)

const (
	requestTTL       = 7 * 24 * time.Hour // pending / approved requests
	rejectCooldown   = 24 * time.Hour     // a rejected applicant must wait this long
	maxPendingByRoom = 10
	maxNameLen       = 32
	p256PubLen       = 65 // uncompressed P-256 point
	maxWrapLen       = 4096
	maxMsgsByRequest = 20
	maxMsgLen        = 4096 // base64 ciphertext
)

// Errors returned to clients.
var (
	ErrInvalid  = errors.New("invalid request")
	ErrTooMany  = errors.New("too many pending requests")
	ErrNotFound = errors.New("request not found")
	ErrFull     = errors.New("too many messages")
)

// JoinMessage is an encrypted message exchanged before approval.
type JoinMessage struct {
	ID   string    `json:"id"`
	Data string    `json:"data"`
	Time time.Time `json:"time"`
}

// Request is a join request.
type Request struct {
	ID          string        `json:"id"`
	Name        string        `json:"name"`
	Pub         string        `json:"pub"`
	Status      string        `json:"status"`
	Created     time.Time     `json:"created"`
	Updated     time.Time     `json:"updated"`
	ApproverPub string        `json:"approverPub,omitempty"`
	Wrap        string        `json:"wrap,omitempty"`
	Messages    []JoinMessage `json:"messages,omitempty"`
}

type room struct {
	Created    time.Time           `json:"created"`
	LastActive time.Time           `json:"lastActive"`
	InboxPub   string              `json:"inboxPub,omitempty"`
	Requests   map[string]*Request `json:"requests,omitempty"`
}

// Store is safe for concurrent use.
type Store struct {
	path          string
	roomRetention time.Duration
	now           func() time.Time

	mu    sync.Mutex
	rooms map[string]*room
}

// Open loads the state file (a missing file is fine).
func Open(path string, roomRetention time.Duration) (*Store, error) {
	s := &Store{path: path, roomRetention: roomRetention, now: time.Now, rooms: map[string]*room{}}
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return s, os.MkdirAll(filepath.Dir(path), 0o700)
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(b, &s.rooms); err != nil {
		return nil, err
	}
	return s, nil
}

func roomKey(roomID string) string {
	sum := sha256.Sum256([]byte(roomID))
	return hex.EncodeToString(sum[:])
}

// RequestID derives the request ID from the applicant's public key, so an
// applicant keeps the same request across reconnects.
func RequestID(pub string) string {
	sum := sha256.Sum256([]byte(pub))
	return hex.EncodeToString(sum[:16])
}

// Exists reports whether the room has been created.
func (s *Store) Exists(roomID string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.rooms[roomKey(roomID)] != nil
}

// Claim registers the room. With create, it succeeds only if the room did
// not exist yet (two people creating the same name at once: one wins).
// Without create, a key holder marks the room active, re-registering it if
// it had expired. inboxPub is the public half of the room's inbox key pair,
// which applicants use to write to members before approval.
func (s *Store) Claim(roomID string, create bool, inboxPub string) bool {
	if inboxPub != "" && !validPub(inboxPub) {
		inboxPub = ""
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	k := roomKey(roomID)
	now := s.now()
	r := s.rooms[k]
	if r != nil {
		if create {
			return false
		}
		r.LastActive = now
		if r.InboxPub == "" {
			r.InboxPub = inboxPub
		}
		s.save()
		return true
	}
	s.rooms[k] = &room{Created: now, LastActive: now, InboxPub: inboxPub}
	s.save()
	return true
}

// InboxPub returns the room's inbox public key ("" if unknown).
func (s *Store) InboxPub(roomID string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if r := s.rooms[roomKey(roomID)]; r != nil {
		return r.InboxPub
	}
	return ""
}

// AddMessage appends an encrypted message to a pending request.
func (s *Store) AddMessage(roomID, reqID, msgID, data string) (JoinMessage, error) {
	if msgID == "" || len(msgID) > 64 || data == "" || len(data) > maxMsgLen {
		return JoinMessage{}, ErrInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	r := s.rooms[roomKey(roomID)]
	if r == nil || r.Requests[reqID] == nil || r.Requests[reqID].Status != StatusPending {
		return JoinMessage{}, ErrNotFound
	}
	q := r.Requests[reqID]
	if len(q.Messages) >= maxMsgsByRequest {
		return JoinMessage{}, ErrFull
	}
	m := JoinMessage{ID: msgID, Data: data, Time: s.now()}
	q.Messages = append(q.Messages, m)
	q.Updated = m.Time
	s.save()
	return m, nil
}

// Pending lists pending requests, oldest first.
func (s *Store) Pending(roomID string) []Request {
	s.mu.Lock()
	defer s.mu.Unlock()
	r := s.rooms[roomKey(roomID)]
	if r == nil {
		return nil
	}
	var out []Request
	for _, q := range r.Requests {
		if q.Status == StatusPending && !s.expired(q) {
			out = append(out, q.clone())
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Created.Before(out[j].Created) })
	return out
}

// Submit creates or refreshes a join request and returns its current state
// (which may already be approved or rejected).
func (s *Store) Submit(roomID, name, pub string) (Request, error) {
	if !validPub(pub) {
		return Request{}, ErrInvalid
	}
	name = clip(name, maxNameLen)
	if name == "" {
		name = "?"
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	r := s.rooms[roomKey(roomID)]
	if r == nil {
		return Request{}, ErrNotFound
	}
	if r.Requests == nil {
		r.Requests = map[string]*Request{}
	}
	id := RequestID(pub)
	now := s.now()
	if q := r.Requests[id]; q != nil && !s.expired(q) {
		if q.Status == StatusPending {
			q.Name = name
		}
		q.Updated = now
		s.save()
		return q.clone(), nil
	}
	pending := 0
	for _, q := range r.Requests {
		if q.Status == StatusPending && !s.expired(q) {
			pending++
		}
	}
	if pending >= maxPendingByRoom {
		return Request{}, ErrTooMany
	}
	q := &Request{ID: id, Name: name, Pub: pub, Status: StatusPending, Created: now, Updated: now}
	r.Requests[id] = q
	s.save()
	return q.clone(), nil
}

func (q *Request) clone() Request {
	c := *q
	c.Messages = append([]JoinMessage(nil), q.Messages...)
	return c
}

// Approve stores the room key wrapped for the applicant.
func (s *Store) Approve(roomID, id, approverPub, wrap string) (Request, error) {
	if !validPub(approverPub) || wrap == "" || len(wrap) > maxWrapLen {
		return Request{}, ErrInvalid
	}
	return s.decide(roomID, id, func(q *Request) {
		q.Status, q.ApproverPub, q.Wrap = StatusApproved, approverPub, wrap
	})
}

// Reject marks the request rejected; the applicant cannot re-apply until the
// cooldown passes.
func (s *Store) Reject(roomID, id string) (Request, error) {
	return s.decide(roomID, id, func(q *Request) { q.Status = StatusRejected })
}

func (s *Store) decide(roomID, id string, f func(*Request)) (Request, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r := s.rooms[roomKey(roomID)]
	if r == nil || r.Requests[id] == nil || r.Requests[id].Status != StatusPending {
		return Request{}, ErrNotFound
	}
	q := r.Requests[id]
	f(q)
	q.Updated = s.now()
	s.save()
	return q.clone(), nil
}

// Done removes an approved request once the applicant has the key.
func (s *Store) Done(roomID, id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r := s.rooms[roomKey(roomID)]
	if r == nil || r.Requests[id] == nil || r.Requests[id].Status != StatusApproved {
		return
	}
	delete(r.Requests, id)
	s.save()
}

// Purge drops expired requests and rooms inactive beyond the retention.
func (s *Store) Purge() {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	changed := false
	for k, r := range s.rooms {
		if s.roomRetention > 0 && now.Sub(r.LastActive) > s.roomRetention {
			delete(s.rooms, k)
			changed = true
			continue
		}
		for id, q := range r.Requests {
			if s.expired(q) {
				delete(r.Requests, id)
				changed = true
			}
		}
	}
	if changed {
		s.save()
	}
}

// Run purges every hour until ctx is done.
func (s *Store) Run(ctx context.Context) {
	t := time.NewTicker(time.Hour)
	defer t.Stop()
	for {
		s.Purge()
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func (s *Store) expired(q *Request) bool {
	ttl := requestTTL
	if q.Status == StatusRejected {
		ttl = rejectCooldown
	}
	return s.now().Sub(q.Updated) > ttl
}

// save writes the whole state atomically. Callers hold s.mu.
func (s *Store) save() {
	b, err := json.Marshal(s.rooms)
	if err != nil {
		log.Printf("store: marshal: %v", err)
		return
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		log.Printf("store: write: %v", err)
		return
	}
	if err := os.Rename(tmp, s.path); err != nil {
		log.Printf("store: rename: %v", err)
	}
}

func validPub(pub string) bool {
	b, err := base64.RawURLEncoding.DecodeString(pub)
	return err == nil && len(b) == p256PubLen && b[0] == 4
}

func clip(s string, n int) string {
	if !utf8.ValidString(s) {
		return ""
	}
	r := []rune(s)
	if len(r) > n {
		r = r[:n]
	}
	return string(r)
}

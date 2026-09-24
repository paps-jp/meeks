// Package iplog records connection metadata (IP address, port, time) so the
// operator can answer sender-information disclosure requests
// (発信者情報開示請求). Message contents are never recorded — the server
// cannot read them anyway because they are end-to-end encrypted.
//
// Entries are appended to one JSON Lines file per UTC day and files older
// than the retention period are deleted automatically.
package iplog

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	filePrefix = "ip-"
	fileSuffix = ".jsonl"
	dayLayout  = "2006-01-02"
)

// Event kinds.
const (
	EventConnect    = "connect"
	EventDisconnect = "disconnect"
	EventTURNAuth   = "turn_auth"
	EventJoinReq    = "join_request"
)

// Entry is one log line.
type Entry struct {
	Time      time.Time `json:"time"`
	Event     string    `json:"event"`
	IP        string    `json:"ip"`
	Port      int       `json:"port,omitempty"`
	Room      string    `json:"room,omitempty"` // RoomHash(roomID)
	Peer      string    `json:"peer,omitempty"`
	UserAgent string    `json:"ua,omitempty"`
}

// RoomHash returns the identifier stored in the log for a room. Only the hash
// is stored; an operator who is given the room URL can compute it to search.
func RoomHash(roomID string) string {
	sum := sha256.Sum256([]byte(roomID))
	return hex.EncodeToString(sum[:])
}

// Logger appends entries to daily files.
type Logger struct {
	dir       string
	retention time.Duration

	mu  sync.Mutex
	day string
	f   *os.File
}

// New creates the log directory if needed.
func New(dir string, retention time.Duration) (*Logger, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	return &Logger{dir: dir, retention: retention}, nil
}

// Log appends an entry. Failures are reported but never block the caller:
// losing a log line must not take the chat down.
func (l *Logger) Log(e Entry) {
	if e.Time.IsZero() {
		e.Time = time.Now()
	}
	e.Time = e.Time.UTC()
	line, err := json.Marshal(e)
	if err != nil {
		log.Printf("iplog: marshal: %v", err)
		return
	}
	line = append(line, '\n')

	l.mu.Lock()
	defer l.mu.Unlock()
	day := e.Time.Format(dayLayout)
	if l.f == nil || l.day != day {
		if l.f != nil {
			l.f.Close()
		}
		f, err := os.OpenFile(filepath.Join(l.dir, filePrefix+day+fileSuffix),
			os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
		if err != nil {
			log.Printf("iplog: open: %v", err)
			l.f = nil
			return
		}
		l.f, l.day = f, day
	}
	if _, err := l.f.Write(line); err != nil {
		log.Printf("iplog: write: %v", err)
	}
}

// Purge deletes daily files whose whole day is older than the retention period.
func (l *Logger) Purge(now time.Time) error {
	cutoff := now.UTC().Add(-l.retention)
	days, err := listDays(l.dir)
	if err != nil {
		return err
	}
	for _, d := range days {
		// A file covers [d, d+24h); keep it while any part is within retention.
		if d.Add(24 * time.Hour).After(cutoff) {
			continue
		}
		name := filepath.Join(l.dir, filePrefix+d.Format(dayLayout)+fileSuffix)
		l.mu.Lock()
		if l.f != nil && l.day == d.Format(dayLayout) {
			l.f.Close()
			l.f = nil
		}
		l.mu.Unlock()
		if err := os.Remove(name); err != nil && !os.IsNotExist(err) {
			return err
		}
		log.Printf("iplog: purged %s", filepath.Base(name))
	}
	return nil
}

// Run purges expired files once now and then every hour until ctx is done.
func (l *Logger) Run(ctx context.Context) {
	t := time.NewTicker(time.Hour)
	defer t.Stop()
	for {
		if err := l.Purge(time.Now()); err != nil {
			log.Printf("iplog: purge: %v", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// Close closes the current file.
func (l *Logger) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.f == nil {
		return nil
	}
	err := l.f.Close()
	l.f = nil
	return err
}

func listDays(dir string) ([]time.Time, error) {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var days []time.Time
	for _, e := range ents {
		n := e.Name()
		if e.IsDir() || !strings.HasPrefix(n, filePrefix) || !strings.HasSuffix(n, fileSuffix) {
			continue
		}
		d, err := time.Parse(dayLayout, strings.TrimSuffix(strings.TrimPrefix(n, filePrefix), fileSuffix))
		if err != nil {
			continue
		}
		days = append(days, d)
	}
	sort.Slice(days, func(i, j int) bool { return days[i].Before(days[j]) })
	return days, nil
}

// Query selects entries for Search.
type Query struct {
	RoomID string    // raw room ID from the URL (hashed before matching)
	IP     string    // exact IP match
	From   time.Time // inclusive; zero = unbounded
	To     time.Time // exclusive; zero = unbounded
}

// Search scans the log directory. When RoomID is given, TURN entries of the
// peers that joined that room are included as well.
func Search(dir string, q Query) ([]Entry, error) {
	days, err := listDays(dir)
	if err != nil {
		return nil, err
	}
	room := ""
	if q.RoomID != "" {
		room = RoomHash(q.RoomID)
	}
	var all []Entry
	for _, d := range days {
		if !q.From.IsZero() && d.Add(24*time.Hour).Before(q.From) {
			continue
		}
		if !q.To.IsZero() && !d.Before(q.To) {
			continue
		}
		es, err := readFile(filepath.Join(dir, filePrefix+d.Format(dayLayout)+fileSuffix))
		if err != nil {
			return nil, err
		}
		all = append(all, es...)
	}

	peers := map[string]bool{}
	if room != "" {
		for _, e := range all {
			if e.Room == room && e.Peer != "" {
				peers[e.Peer] = true
			}
		}
	}
	var out []Entry
	for _, e := range all {
		if !q.From.IsZero() && e.Time.Before(q.From) {
			continue
		}
		if !q.To.IsZero() && !e.Time.Before(q.To) {
			continue
		}
		if q.IP != "" && e.IP != q.IP {
			continue
		}
		if room != "" && e.Room != room && !peers[e.Peer] {
			continue
		}
		out = append(out, e)
	}
	return out, nil
}

func readFile(name string) ([]Entry, error) {
	f, err := os.Open(name)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []Entry
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for n := 1; sc.Scan(); n++ {
		var e Entry
		if err := json.Unmarshal(sc.Bytes(), &e); err != nil {
			return nil, fmt.Errorf("%s:%d: %w", filepath.Base(name), n, err)
		}
		out = append(out, e)
	}
	return out, sc.Err()
}

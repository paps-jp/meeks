package cfturn

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeCloudflare mimics the TURN key API and the GraphQL analytics API.
type fakeCloudflare struct {
	mu        sync.Mutex
	egress    int64
	usageFail bool
	minted    int
	revoked   []string
	lastVars  map[string]string
}

func (f *fakeCloudflare) handler(t *testing.T) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /keys/key1/credentials/generate-ice-servers", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer keytoken" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		f.mu.Lock()
		f.minted++
		n := f.minted
		f.mu.Unlock()
		w.WriteHeader(http.StatusCreated)
		fmt.Fprintf(w, `{"iceServers":[
			{"urls":["stun:stun.cloudflare.com:3478"]},
			{"urls":["turn:turn.cloudflare.com:3478?transport=udp","turn:turn.cloudflare.com:80?transport=tcp","turns:turn.cloudflare.com:443?transport=tcp"],
			 "username":"user%d","credential":"secret%d"}]}`, n, n)
	})
	mux.HandleFunc("POST /keys/key1/credentials/{user}/revoke", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.revoked = append(f.revoked, r.PathValue("user"))
		f.mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("POST /graphql", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer analytics" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		var req struct {
			Variables map[string]string `json:"variables"`
		}
		json.NewDecoder(r.Body).Decode(&req)
		f.mu.Lock()
		defer f.mu.Unlock()
		f.lastVars = req.Variables
		if f.usageFail {
			http.Error(w, "boom", http.StatusInternalServerError)
			return
		}
		// Usage split over two hourly groups.
		fmt.Fprintf(w, `{"data":{"viewer":{"accounts":[{"callsTurnUsageAdaptiveGroups":[
			{"dimensions":{"datetimeHour":"a"},"sum":{"egressBytes":%d}},
			{"dimensions":{"datetimeHour":"b"},"sum":{"egressBytes":%d}}]}]}}}`, f.egress/2, f.egress-f.egress/2)
	})
	return mux
}

func newTest(t *testing.T, analytics bool) (*Provider, *fakeCloudflare, *time.Time) {
	t.Helper()
	fake := &fakeCloudflare{}
	srv := httptest.NewServer(fake.handler(t))
	t.Cleanup(srv.Close)
	now := time.Date(2026, 9, 25, 12, 0, 0, 0, time.UTC)
	cfg := Config{
		KeyID: "key1", KeyToken: "keytoken", MonthlyLimit: 900e9,
		APIBase: srv.URL + "/keys/", GraphQLURL: srv.URL + "/graphql",
		URLFilter: func(u string) bool {
			return strings.HasSuffix(u, ":3478?transport=udp") || strings.HasSuffix(u, ":443?transport=tcp")
		},
		Now: func() time.Time { return now },
	}
	if analytics {
		cfg.AccountID, cfg.AnalyticsToken = "acct", "analytics"
	}
	return New(cfg), fake, &now
}

func TestOffersFilteredServersUnderCap(t *testing.T) {
	p, fake, _ := newTest(t, true)
	fake.egress = 100e9
	p.Tick(context.Background())

	got := p.ICEServers()
	if len(got) != 1 || got[0].Username != "user1" {
		t.Fatalf("servers = %+v", got)
	}
	want := []string{"turn:turn.cloudflare.com:3478?transport=udp", "turns:turn.cloudflare.com:443?transport=tcp"}
	if strings.Join(got[0].URLs, " ") != strings.Join(want, " ") {
		t.Errorf("urls = %v, want %v", got[0].URLs, want)
	}
	if fake.lastVars["dateFrom"] != "2026-09-01" || fake.lastVars["dateTo"] != "2026-09-25" || fake.lastVars["accountTag"] != "acct" {
		t.Errorf("graphql variables = %v", fake.lastVars)
	}
}

func TestCredentialIsReusedThenRefreshed(t *testing.T) {
	p, fake, now := newTest(t, true)
	p.Tick(context.Background())
	*now = now.Add(10 * time.Minute)
	p.Tick(context.Background())
	if fake.minted != 1 {
		t.Fatalf("minted %d times within the refresh interval", fake.minted)
	}
	*now = now.Add(25 * time.Minute)
	p.Tick(context.Background())
	if fake.minted != 2 || p.ICEServers()[0].Username != "user2" {
		t.Fatalf("not refreshed: minted=%d servers=%+v", fake.minted, p.ICEServers())
	}
}

func TestOverCapWithholdsAndRevokes(t *testing.T) {
	p, fake, now := newTest(t, true)
	p.Tick(context.Background())
	if p.ICEServers() == nil {
		t.Fatal("expected servers under the cap")
	}

	fake.egress = 900e9
	p.Tick(context.Background())
	if p.ICEServers() != nil {
		t.Fatal("servers still offered at the cap")
	}
	if len(fake.revoked) != 1 || fake.revoked[0] != "user1" {
		t.Fatalf("revoked = %v", fake.revoked)
	}

	// Next month usage restarts from zero: offered again.
	*now = time.Date(2026, 10, 1, 0, 5, 0, 0, time.UTC)
	fake.egress = 0
	p.Tick(context.Background())
	if p.ICEServers() == nil {
		t.Fatal("not re-enabled in the new month")
	}
	if fake.lastVars["dateFrom"] != "2026-10-01" {
		t.Errorf("dateFrom = %s", fake.lastVars["dateFrom"])
	}
}

func TestUnknownUsageWithholdsWithoutRevoking(t *testing.T) {
	p, fake, _ := newTest(t, false)
	p.Tick(context.Background())
	if p.ICEServers() != nil {
		t.Fatal("offered Cloudflare TURN without being able to check usage")
	}
	if fake.minted != 0 {
		t.Fatal("minted credentials while withheld")
	}

	p2, fake2, _ := newTest(t, true)
	p2.Tick(context.Background())
	fake2.usageFail = true
	p2.Tick(context.Background())
	if p2.ICEServers() != nil {
		t.Fatal("offered while usage could not be read")
	}
	if len(fake2.revoked) != 0 {
		t.Fatal("a transient analytics failure must not revoke live credentials")
	}
	if !strings.Contains(p2.Status(), "last error") {
		t.Errorf("status = %s", p2.Status())
	}
}

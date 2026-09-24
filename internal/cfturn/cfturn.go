// Package cfturn adds Cloudflare Realtime TURN as a backup relay behind the
// embedded TURN server, with a monthly usage cap.
//
// Credentials are minted in the background and shared by all browsers, so a
// room join never waits for Cloudflare. Account-wide TURN egress for the
// current month is polled from the GraphQL analytics API; when it reaches
// the limit, Cloudflare servers are withheld and the live credential is
// revoked, stopping relays in use. If usage cannot be read (no analytics
// token, API errors), Cloudflare TURN is withheld: the cap is never assumed.
package cfturn

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"
)

const (
	defaultAPI     = "https://rtc.live.cloudflare.com/v1/turn/keys/"
	defaultGraphQL = "https://api.cloudflare.com/client/v4/graphql"
)

// Config configures the provider.
type Config struct {
	KeyID    string // TURN key ID
	KeyToken string // TURN key API token

	AccountID      string // Cloudflare account ID (for usage)
	AnalyticsToken string // API token with "Account Analytics: Read"
	MonthlyLimit   int64  // bytes of TURN egress per calendar month (UTC)

	CredentialTTL time.Duration // lifetime of minted credentials (default 2h)
	RefreshEvery  time.Duration // mint a new credential this often (default 30m)
	UsageEvery    time.Duration // poll usage this often (default 5m)

	// URLFilter keeps only the TURN URLs worth offering; nil keeps all.
	URLFilter func(url string) bool

	HTTP       *http.Client
	APIBase    string // for tests
	GraphQLURL string // for tests
	Now        func() time.Time
}

// Server is one ICE server entry for browsers.
type Server struct {
	URLs       []string
	Username   string
	Credential string
}

// Provider hands out Cloudflare TURN servers while usage is under the cap.
type Provider struct {
	cfg Config

	mu        sync.Mutex
	servers   []Server
	username  string // of the live credential, for revocation
	minted    time.Time
	usage     int64
	usageOK   bool // usage was read successfully and is under the limit
	lastError string
}

// New returns a provider; call Run to start it.
func New(cfg Config) *Provider {
	if cfg.CredentialTTL == 0 {
		cfg.CredentialTTL = 2 * time.Hour
	}
	if cfg.RefreshEvery == 0 {
		cfg.RefreshEvery = 30 * time.Minute
	}
	if cfg.UsageEvery == 0 {
		cfg.UsageEvery = 5 * time.Minute
	}
	if cfg.HTTP == nil {
		cfg.HTTP = &http.Client{Timeout: 15 * time.Second}
	}
	if cfg.APIBase == "" {
		cfg.APIBase = defaultAPI
	}
	if cfg.GraphQLURL == "" {
		cfg.GraphQLURL = defaultGraphQL
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &Provider{cfg: cfg}
}

// ICEServers returns the Cloudflare servers to offer, or nil while
// withheld (over the cap, usage unknown, or no credential yet).
func (p *Provider) ICEServers() []Server {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.usageOK {
		return nil
	}
	return p.servers
}

// Status summarizes the provider state for logs.
func (p *Provider) Status() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	state := "withheld"
	if p.usageOK && p.servers != nil {
		state = "active"
	}
	s := fmt.Sprintf("cloudflare turn %s, month usage %.2f GB of %.0f GB",
		state, float64(p.usage)/1e9, float64(p.cfg.MonthlyLimit)/1e9)
	if p.lastError != "" {
		s += ", last error: " + p.lastError
	}
	return s
}

// Run polls usage and refreshes credentials until ctx is done.
func (p *Provider) Run(ctx context.Context) {
	p.Tick(ctx)
	log.Print(p.Status())
	t := time.NewTicker(p.cfg.UsageEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			p.Tick(ctx)
		}
	}
}

// Tick checks usage once and mints or revokes credentials accordingly.
func (p *Provider) Tick(ctx context.Context) {
	usage, err := p.monthUsage(ctx)
	p.mu.Lock()
	wasOK := p.usageOK
	if err != nil {
		p.usageOK = false
		p.lastError = err.Error()
	} else {
		p.usage = usage
		p.usageOK = usage < p.cfg.MonthlyLimit
		p.lastError = ""
	}
	ok := p.usageOK
	needMint := ok && (p.servers == nil || p.cfg.Now().Sub(p.minted) >= p.cfg.RefreshEvery)
	var revoke string
	if !ok && p.username != "" && err == nil {
		// Over the cap: stop relays that are using the live credential.
		// (On a mere read error the credential is only withheld, not
		// revoked, so a transient API failure does not cut calls.)
		revoke, p.username, p.servers = p.username, "", nil
	}
	p.mu.Unlock()

	if ok != wasOK {
		log.Print(p.Status())
	}
	if revoke != "" {
		if err := p.revoke(ctx, revoke); err != nil {
			log.Printf("cfturn: revoke: %v", err)
		}
	}
	if needMint {
		servers, username, err := p.mint(ctx)
		p.mu.Lock()
		if err != nil {
			p.lastError = err.Error()
		} else {
			p.servers, p.username, p.minted = servers, username, p.cfg.Now()
		}
		p.mu.Unlock()
		if err != nil {
			log.Printf("cfturn: mint: %v", err)
		}
	}
}

func (p *Provider) mint(ctx context.Context) ([]Server, string, error) {
	body, _ := json.Marshal(map[string]int{"ttl": int(p.cfg.CredentialTTL.Seconds())})
	url := p.cfg.APIBase + p.cfg.KeyID + "/credentials/generate-ice-servers"
	var out struct {
		ICEServers []struct {
			URLs       []string `json:"urls"`
			Username   string   `json:"username"`
			Credential string   `json:"credential"`
		} `json:"iceServers"`
	}
	if err := p.post(ctx, url, p.cfg.KeyToken, body, &out); err != nil {
		return nil, "", err
	}
	var servers []Server
	var username string
	for _, s := range out.ICEServers {
		if s.Username == "" {
			continue // STUN: the embedded server already provides it
		}
		var urls []string
		for _, u := range s.URLs {
			if p.cfg.URLFilter == nil || p.cfg.URLFilter(u) {
				urls = append(urls, u)
			}
		}
		if len(urls) > 0 {
			servers = append(servers, Server{URLs: urls, Username: s.Username, Credential: s.Credential})
			username = s.Username
		}
	}
	if servers == nil {
		return nil, "", fmt.Errorf("no TURN servers in response")
	}
	return servers, username, nil
}

func (p *Provider) revoke(ctx context.Context, username string) error {
	url := p.cfg.APIBase + p.cfg.KeyID + "/credentials/" + username + "/revoke"
	return p.post(ctx, url, p.cfg.KeyToken, nil, nil)
}

// monthUsage returns account-wide TURN egress bytes for the current UTC month.
func (p *Provider) monthUsage(ctx context.Context) (int64, error) {
	if p.cfg.AccountID == "" || p.cfg.AnalyticsToken == "" {
		return 0, fmt.Errorf("usage unknown: account ID or analytics token not configured")
	}
	now := p.cfg.Now().UTC()
	from := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.UTC)
	query := `query ($accountTag: String!, $dateFrom: Date!, $dateTo: Date!) {
  viewer {
    accounts(filter: { accountTag: $accountTag }) {
      callsTurnUsageAdaptiveGroups(limit: 10000, filter: { date_geq: $dateFrom, date_leq: $dateTo }) {
        dimensions { datetimeHour }
        sum { egressBytes }
      }
    }
  }
}`
	body, _ := json.Marshal(map[string]any{
		"query": query,
		"variables": map[string]string{
			"accountTag": p.cfg.AccountID,
			"dateFrom":   from.Format("2006-01-02"),
			"dateTo":     now.Format("2006-01-02"),
		},
	})
	var out struct {
		Data struct {
			Viewer struct {
				Accounts []struct {
					Groups []struct {
						Sum struct {
							EgressBytes int64 `json:"egressBytes"`
						} `json:"sum"`
					} `json:"callsTurnUsageAdaptiveGroups"`
				} `json:"accounts"`
			} `json:"viewer"`
		} `json:"data"`
		Errors []struct {
			Message string `json:"message"`
		} `json:"errors"`
	}
	if err := p.post(ctx, p.cfg.GraphQLURL, p.cfg.AnalyticsToken, body, &out); err != nil {
		return 0, err
	}
	if len(out.Errors) > 0 {
		var msgs []string
		for _, e := range out.Errors {
			msgs = append(msgs, e.Message)
		}
		return 0, fmt.Errorf("graphql: %s", strings.Join(msgs, "; "))
	}
	if len(out.Data.Viewer.Accounts) == 0 {
		return 0, fmt.Errorf("graphql: account not found")
	}
	var total int64
	for _, g := range out.Data.Viewer.Accounts[0].Groups {
		total += g.Sum.EgressBytes
	}
	return total, nil
}

func (p *Provider) post(ctx context.Context, url, token string, body []byte, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := p.cfg.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("%s: HTTP %d: %s", strings.SplitN(url, "/credentials", 2)[0], resp.StatusCode, truncate(string(data), 200))
	}
	if out != nil {
		return json.Unmarshal(data, out)
	}
	return nil
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}

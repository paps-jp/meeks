package main

import (
	"io/fs"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"meeks/web"
)

func TestSite(t *testing.T) {
	static, err := fs.Sub(web.Files, "static")
	if err != nil {
		t.Fatal(err)
	}
	s, err := newSite(static, "", false)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	s.register(mux)
	get := func(path, host string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("GET", path, nil)
		r.Host = host
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, r)
		return w
	}

	idx := get("/", "meeks.example.com")
	if body := idx.Body.String(); strings.Contains(body, siteURLPlaceholder) ||
		!strings.Contains(body, `<link rel="canonical" href="http://meeks.example.com/">`) {
		t.Errorf("index SEO URLs not filled in")
	}
	if body := get("/", `evil"><script>`).Body.String(); strings.Contains(body, "<script>\"") || strings.Contains(body, `evil">`) {
		t.Error("Host header reflected into the page")
	}

	room := get("/team-meeting", "x")
	if room.Code != 200 || !strings.Contains(room.Header().Get("X-Robots-Tag"), "noindex") {
		t.Errorf("room page: code %d, X-Robots-Tag %q", room.Code, room.Header().Get("X-Robots-Tag"))
	}
	if w := get("/r/team-meeting?transport=relay", "x"); w.Code != http.StatusMovedPermanently ||
		w.Header().Get("Location") != "/team-meeting?transport=relay" {
		t.Errorf("legacy redirect: %d %q", w.Code, w.Header().Get("Location"))
	}
	for _, p := range []string{"/healthz", "/ws", "/bad.name"} {
		if w := get(p, "x"); w.Code != http.StatusNotFound {
			t.Errorf("%s: code %d, want 404", p, w.Code)
		}
	}
	if w := get("/robots.txt", "x"); !strings.Contains(w.Body.String(), "Sitemap: http://x/sitemap.xml") {
		t.Errorf("robots.txt = %q", w.Body.String())
	}
	if w := get("/sitemap.xml", "x"); !strings.Contains(w.Body.String(), "<loc>http://x/</loc>") {
		t.Errorf("sitemap = %q", w.Body.String())
	}
	if w := get("/static/manifest.webmanifest", "x"); w.Header().Get("Content-Type") != "application/manifest+json" {
		t.Errorf("manifest content type %q", w.Header().Get("Content-Type"))
	}

	css := get("/static/style.css", "x")
	tag := css.Header().Get("ETag")
	if tag == "" || css.Header().Get("Cache-Control") != "no-cache" {
		t.Fatalf("static caching headers: ETag %q, Cache-Control %q", tag, css.Header().Get("Cache-Control"))
	}
	r := httptest.NewRequest("GET", "/static/style.css", nil)
	r.Header.Set("If-None-Match", tag)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)
	if w.Code != http.StatusNotModified {
		t.Errorf("revalidation: code %d, want 304", w.Code)
	}
}

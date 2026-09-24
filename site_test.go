package main

import (
	"io/fs"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"meeks/internal/signaling"
	"meeks/web"
)

func newTestMux(t *testing.T) *http.ServeMux {
	t.Helper()
	static, err := fs.Sub(web.Files, "static")
	if err != nil {
		t.Fatal(err)
	}
	s, err := newSite(static, web.Templates, "", false)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	s.register(mux)
	return mux
}

func get(mux *http.ServeMux, path, host string) *httptest.ResponseRecorder {
	r := httptest.NewRequest("GET", path, nil)
	r.Host = host
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)
	return w
}

func TestSite(t *testing.T) {
	mux := newTestMux(t)

	idx := get(mux, "/", "meeks.example.com").Body.String()
	for _, want := range []string{
		`<html lang="ja" dir="ltr">`,
		`<link rel="canonical" href="http://meeks.example.com/">`,
		`<link rel="alternate" hreflang="en" href="http://meeks.example.com/en">`,
		`<link rel="alternate" hreflang="x-default" href="http://meeks.example.com/">`,
		`新しいルームを作成`,
		`"inLanguage":"ja"`,
	} {
		if !strings.Contains(idx, want) {
			t.Errorf("index missing %q", want)
		}
	}
	if strings.Contains(idx, "{{") {
		t.Error("unrendered template action in index")
	}
	if body := get(mux, "/", `evil"><script>`).Body.String(); strings.Contains(body, `evil">`) {
		t.Error("Host header reflected into the page")
	}

	room := get(mux, "/team-meeting", "x")
	if room.Code != 200 || !strings.Contains(room.Header().Get("X-Robots-Tag"), "noindex") {
		t.Errorf("room page: code %d, X-Robots-Tag %q", room.Code, room.Header().Get("X-Robots-Tag"))
	}
	if w := get(mux, "/r/team-meeting?transport=relay", "x"); w.Code != http.StatusMovedPermanently ||
		w.Header().Get("Location") != "/team-meeting?transport=relay" {
		t.Errorf("legacy redirect: %d %q", w.Code, w.Header().Get("Location"))
	}
	for _, p := range []string{"/healthz", "/ws", "/bad.name"} {
		if w := get(mux, p, "x"); w.Code != http.StatusNotFound {
			t.Errorf("%s: code %d, want 404", p, w.Code)
		}
	}
	if w := get(mux, "/robots.txt", "x"); !strings.Contains(w.Body.String(), "Sitemap: http://x/sitemap.xml") {
		t.Errorf("robots.txt = %q", w.Body.String())
	}
	if w := get(mux, "/static/manifest.webmanifest", "x"); w.Header().Get("Content-Type") != "application/manifest+json" {
		t.Errorf("manifest content type %q", w.Header().Get("Content-Type"))
	}

	css := get(mux, "/static/style.css", "x")
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

func TestLocalizedLanding(t *testing.T) {
	mux := newTestMux(t)
	for _, l := range languages {
		w := get(mux, langPath(l.Code), "x")
		body := w.Body.String()
		if w.Code != 200 || !strings.Contains(body, `<html lang="`+l.Code+`"`) {
			t.Errorf("%s: code %d", l.Code, w.Code)
			continue
		}
		if w.Header().Get("Content-Language") != l.Code {
			t.Errorf("%s: Content-Language %q", l.Code, w.Header().Get("Content-Language"))
		}
		if strings.Count(body, `hreflang=`) < 2*len(languages) { // <link> tags + switcher links
			t.Errorf("%s: hreflang links missing", l.Code)
		}
		if l.RTL != strings.Contains(body, `dir="rtl"`) {
			t.Errorf("%s: dir attribute wrong", l.Code)
		}
	}
	if !strings.Contains(get(mux, "/en", "x").Body.String(), "Create a new room") {
		t.Error("/en not translated")
	}
	if w := get(mux, "/ja", "x"); w.Code != http.StatusMovedPermanently || w.Header().Get("Location") != "/" {
		t.Errorf("/ja: %d %q", w.Code, w.Header().Get("Location"))
	}
	if signaling.ValidRoomID("en") || signaling.ValidRoomID("ar") {
		t.Error("language codes must not be usable as room IDs")
	}
	sm := get(mux, "/sitemap.xml", "x").Body.String()
	if strings.Count(sm, "<loc>") != len(languages) || !strings.Contains(sm, `hreflang="x-default"`) {
		t.Errorf("sitemap = %s", sm)
	}
}

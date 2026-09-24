package main

import (
	"bytes"
	"fmt"
	"io/fs"
	"mime"
	"net/http"
	"regexp"
	"strings"

	"meeks/internal/signaling"
)

// site serves the web pages: the landing page (with SEO metadata filled in
// for the public URL), robots.txt / sitemap.xml, and room pages at /{room}.
type site struct {
	static     fs.FS
	siteURL    string // e.g. https://meeks.example.com; derived from the request if empty
	trustProxy bool
	index      []byte
}

const siteURLPlaceholder = "{{SITE_URL}}"

// hostPattern keeps a request-derived origin from injecting markup through
// the Host header.
var hostPattern = regexp.MustCompile(`^[A-Za-z0-9.\-]+(:[0-9]{1,5})?$|^\[[0-9A-Fa-f:.]+\](:[0-9]{1,5})?$`)

func newSite(static fs.FS, siteURL string, trustProxy bool) (*site, error) {
	index, err := fs.ReadFile(static, "index.html")
	if err != nil {
		return nil, err
	}
	mime.AddExtensionType(".webmanifest", "application/manifest+json")
	return &site{static: static, siteURL: strings.TrimRight(siteURL, "/"), trustProxy: trustProxy, index: index}, nil
}

func (s *site) register(mux *http.ServeMux) {
	mux.Handle("GET /static/", http.StripPrefix("/static/", cacheFor(3600, http.FileServerFS(s.static))))
	mux.HandleFunc("GET /{$}", s.serveIndex)
	mux.HandleFunc("GET /robots.txt", s.serveRobots)
	mux.HandleFunc("GET /sitemap.xml", s.serveSitemap)
	mux.HandleFunc("GET /{room}", s.serveRoom)
	// Old invitation links used /r/{room}.
	mux.HandleFunc("GET /r/{room}", func(w http.ResponseWriter, r *http.Request) {
		target := "/" + r.PathValue("room")
		if r.URL.RawQuery != "" {
			target += "?" + r.URL.RawQuery
		}
		http.Redirect(w, r, target, http.StatusMovedPermanently)
	})
}

func (s *site) origin(r *http.Request) string {
	if s.siteURL != "" {
		return s.siteURL
	}
	scheme := "http"
	if r.TLS != nil || (s.trustProxy && r.Header.Get("X-Forwarded-Proto") == "https") {
		scheme = "https"
	}
	host := r.Host
	if !hostPattern.MatchString(host) {
		host = "localhost"
	}
	return scheme + "://" + host
}

func (s *site) serveIndex(w http.ResponseWriter, r *http.Request) {
	body := bytes.ReplaceAll(s.index, []byte(siteURLPlaceholder), []byte(s.origin(r)))
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	w.Write(body)
}

func (s *site) serveRoom(w http.ResponseWriter, r *http.Request) {
	if !signaling.ValidRoomID(r.PathValue("room")) {
		http.NotFound(w, r)
		return
	}
	// Room URLs are private invitations: keep them out of search results.
	w.Header().Set("X-Robots-Tag", "noindex, nofollow, noarchive")
	http.ServeFileFS(w, r, s.static, "room.html")
}

func (s *site) serveRobots(w http.ResponseWriter, r *http.Request) {
	// Room pages are not disallowed here on purpose: crawlers must be able
	// to fetch them to see their noindex header.
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	fmt.Fprintf(w, "User-agent: *\nAllow: /\nDisallow: /ws/\n\nSitemap: %s/sitemap.xml\n", s.origin(r))
}

func (s *site) serveSitemap(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/xml; charset=utf-8")
	fmt.Fprintf(w, `<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url><loc>%s/</loc><changefreq>monthly</changefreq><priority>1.0</priority></url>
</urlset>
`, s.origin(r))
}

func cacheFor(seconds int, h http.Handler) http.Handler {
	v := fmt.Sprintf("public, max-age=%d", seconds)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", v)
		h.ServeHTTP(w, r)
	})
}

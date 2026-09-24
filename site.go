package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/fs"
	"log"
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
	etags, err := fileETags(s.static)
	if err != nil {
		log.Printf("static etags: %v", err)
	}
	mux.Handle("GET /static/", http.StripPrefix("/static/", revalidate(etags, http.FileServerFS(s.static))))
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

// fileETags hashes every embedded file. Embedded files carry no
// modification time, so without an ETag browsers could not revalidate them.
func fileETags(fsys fs.FS) (map[string]string, error) {
	tags := map[string]string{}
	err := fs.WalkDir(fsys, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b, err := fs.ReadFile(fsys, path)
		if err != nil {
			return err
		}
		sum := sha256.Sum256(b)
		tags[path] = `"` + hex.EncodeToString(sum[:8]) + `"`
		return nil
	})
	return tags, err
}

// revalidate makes browsers check for updates on every use (cheap 304s via
// the ETag), so a new release is picked up immediately.
func revalidate(etags map[string]string, h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-cache")
		if tag, ok := etags[r.URL.Path]; ok {
			w.Header().Set("ETag", tag) // http.ServeContent answers If-None-Match with 304
		}
		h.ServeHTTP(w, r)
	})
}

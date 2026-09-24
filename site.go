package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"io/fs"
	"log"
	"mime"
	"net/http"
	"regexp"
	"strings"

	"meeks/internal/signaling"
)

// site serves the web pages: the landing page in every supported language
// (server-rendered, with SEO metadata for the public URL), robots.txt /
// sitemap.xml, and room pages at /{room}.
type site struct {
	static     fs.FS
	siteURL    string // e.g. https://meeks.example.com; derived from the request if empty
	trustProxy bool
	index      *template.Template
	tr         translations
}

// hostPattern keeps a request-derived origin from injecting markup through
// the Host header.
var hostPattern = regexp.MustCompile(`^[A-Za-z0-9.\-]+(:[0-9]{1,5})?$|^\[[0-9A-Fa-f:.]+\](:[0-9]{1,5})?$`)

func newSite(static, templates fs.FS, siteURL string, trustProxy bool) (*site, error) {
	index, err := template.ParseFS(templates, "templates/index.html")
	if err != nil {
		return nil, err
	}
	tr, err := loadTranslations(static)
	if err != nil {
		return nil, err
	}
	for _, l := range languages {
		signaling.ReserveRoomIDs(l.Code)
	}
	mime.AddExtensionType(".webmanifest", "application/manifest+json")
	return &site{
		static: static, siteURL: strings.TrimRight(siteURL, "/"), trustProxy: trustProxy,
		index: index, tr: tr,
	}, nil
}

func (s *site) register(mux *http.ServeMux) {
	etags, err := fileETags(s.static)
	if err != nil {
		log.Printf("static etags: %v", err)
	}
	mux.Handle("GET /static/", http.StripPrefix("/static/", revalidate(etags, http.FileServerFS(s.static))))
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) { s.serveIndex(w, r, defaultLang) })
	mux.HandleFunc("GET /robots.txt", s.serveRobots)
	mux.HandleFunc("GET /sitemap.xml", s.serveSitemap)
	mux.HandleFunc("GET /{room}", s.serveRoomOrLang)
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

// langLink is one entry of the language switcher / hreflang list.
type langLink struct {
	language
	Path    string
	URL     string
	Current bool
}

// indexPage is the data for templates/index.html.
type indexPage struct {
	Lang       language
	Dir        string
	SiteURL    string
	PageURL    string
	DefaultURL string
	Langs      []langLink
	LDJSON     template.JS
	tr         translations
}

// T returns the translation of key in the page language.
func (p indexPage) T(key string) string { return p.tr.text(p.Lang.Code, key) }

func (s *site) serveIndex(w http.ResponseWriter, r *http.Request, code string) {
	lang, _ := findLanguage(code)
	origin := s.origin(r)
	page := indexPage{
		Lang: lang, Dir: "ltr", SiteURL: origin,
		PageURL: origin + langPath(code), DefaultURL: origin + "/", tr: s.tr,
	}
	if lang.RTL {
		page.Dir = "rtl"
	}
	for _, l := range languages {
		page.Langs = append(page.Langs, langLink{
			language: l, Path: langPath(l.Code), URL: origin + langPath(l.Code), Current: l.Code == code,
		})
	}
	ld, err := json.Marshal(map[string]any{
		"@context":            "https://schema.org",
		"@type":               "WebApplication",
		"name":                "Meeks",
		"url":                 page.PageURL,
		"description":         page.T("meta.ldDescription"),
		"applicationCategory": "CommunicationApplication",
		"operatingSystem":     "Web",
		"inLanguage":          code,
		"image":               origin + "/static/img/og.png",
		"offers":              map[string]string{"@type": "Offer", "price": "0", "priceCurrency": "JPY"},
		"publisher":           map[string]string{"@type": "Organization", "name": "PAPS"},
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	page.LDJSON = template.JS(ld) // json.Marshal escapes <, > and & so this cannot break out of <script>

	var buf bytes.Buffer
	if err := s.index.Execute(&buf, page); err != nil {
		log.Printf("index template: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Language", code)
	w.Header().Set("Cache-Control", "no-cache")
	w.Write(buf.Bytes())
}

// serveRoomOrLang serves a localized landing page (/en, /ko, ...) or a room.
func (s *site) serveRoomOrLang(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("room")
	if _, ok := findLanguage(name); ok {
		if name == defaultLang {
			http.Redirect(w, r, "/", http.StatusMovedPermanently)
			return
		}
		s.serveIndex(w, r, name)
		return
	}
	if !signaling.ValidRoomID(name) {
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
	origin := s.origin(r)
	var b strings.Builder
	b.WriteString(`<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9" xmlns:xhtml="http://www.w3.org/1999/xhtml">
`)
	for _, l := range languages {
		fmt.Fprintf(&b, "  <url>\n    <loc>%s%s</loc>\n", origin, langPath(l.Code))
		for _, alt := range languages {
			fmt.Fprintf(&b, "    <xhtml:link rel=\"alternate\" hreflang=\"%s\" href=\"%s%s\"/>\n", alt.Code, origin, langPath(alt.Code))
		}
		fmt.Fprintf(&b, "    <xhtml:link rel=\"alternate\" hreflang=\"x-default\" href=\"%s/\"/>\n", origin)
		b.WriteString("    <changefreq>monthly</changefreq>\n  </url>\n")
	}
	b.WriteString("</urlset>\n")
	w.Header().Set("Content-Type", "application/xml; charset=utf-8")
	w.Write([]byte(b.String()))
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

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

// site serves the web pages: the landing and safety pages in every supported
// language (server-rendered, with SEO metadata for the public URL),
// robots.txt / sitemap.xml, and room pages at /{room}.
type site struct {
	static     fs.FS
	siteURL    string // e.g. https://meeks.example.com; derived from the request if empty
	trustProxy bool
	pages      *template.Template
	tr         translations
}

// hostPattern keeps a request-derived origin from injecting markup through
// the Host header.
var hostPattern = regexp.MustCompile(`^[A-Za-z0-9.\-]+(:[0-9]{1,5})?$|^\[[0-9A-Fa-f:.]+\](:[0-9]{1,5})?$`)

func newSite(static, templates fs.FS, siteURL string, trustProxy bool) (*site, error) {
	pages, err := template.ParseFS(templates, "templates/*.html")
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
	signaling.ReserveRoomIDs(pageSafety)
	mime.AddExtensionType(".webmanifest", "application/manifest+json")
	return &site{
		static: static, siteURL: strings.TrimRight(siteURL, "/"), trustProxy: trustProxy,
		pages: pages, tr: tr,
	}, nil
}

func (s *site) register(mux *http.ServeMux) {
	etags, err := fileETags(s.static)
	if err != nil {
		log.Printf("static etags: %v", err)
	}
	mux.Handle("GET /static/", http.StripPrefix("/static/", revalidate(etags, http.FileServerFS(s.static))))
	for _, l := range languages {
		code := l.Code
		mux.HandleFunc("GET "+pagePath(code, pageSafety), func(w http.ResponseWriter, r *http.Request) {
			s.servePage(w, r, code, pageSafety)
		})
	}
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) { s.servePage(w, r, defaultLang, pageHome) })
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

// Pages rendered from web/templates.
const (
	pageHome   = "home"
	pageSafety = "safety"
)

// pagePath is the path of a page in a language: /, /en, /safety, /en/safety.
func pagePath(code, page string) string {
	p := langPath(code)
	if page != pageSafety {
		return p
	}
	if p == "/" {
		return "/" + pageSafety
	}
	return p + "/" + pageSafety
}

// langLink is one entry of the language switcher / hreflang list.
type langLink struct {
	language
	Path    string
	URL     string
	Current bool
}

// sitePage is the data for the page templates.
type sitePage struct {
	Lang          language
	Dir           string
	Page          string
	SiteURL       string
	PageURL       string
	DefaultURL    string
	HomePath      string
	SafetyPath    string
	Title         string
	Description   string
	OGDescription string
	OGImage       string
	Langs         []langLink
	LDJSON        template.JS
	tr            translations
}

// T returns the translation of key in the page language.
func (p sitePage) T(key string) string { return p.tr.text(p.Lang.Code, key) }

func (s *site) servePage(w http.ResponseWriter, r *http.Request, code, page string) {
	lang, _ := findLanguage(code)
	origin := s.origin(r)
	p := sitePage{
		Lang: lang, Dir: "ltr", Page: page, SiteURL: origin,
		PageURL: origin + pagePath(code, page), DefaultURL: origin + pagePath(defaultLang, page),
		HomePath: pagePath(code, pageHome), SafetyPath: pagePath(code, pageSafety),
		OGImage: origin + "/static/img/og-" + code + ".png", tr: s.tr,
	}
	if lang.RTL {
		p.Dir = "rtl"
	}
	for _, l := range languages {
		p.Langs = append(p.Langs, langLink{
			language: l, Path: pagePath(l.Code, page), URL: origin + pagePath(l.Code, page), Current: l.Code == code,
		})
	}

	tmpl := "index.html"
	if page == pageSafety {
		tmpl = "safety.html"
		p.Title, p.Description = p.T("safety.meta.title"), p.T("safety.meta.description")
		p.OGDescription = p.Description
	} else {
		p.Title, p.Description, p.OGDescription = p.T("meta.title"), p.T("meta.description"), p.T("meta.ogDescription")
		ld, err := json.Marshal(map[string]any{
			"@context":            "https://schema.org",
			"@type":               "WebApplication",
			"name":                "Meeks",
			"url":                 p.PageURL,
			"description":         p.T("meta.ldDescription"),
			"applicationCategory": "CommunicationApplication",
			"operatingSystem":     "Web",
			"inLanguage":          code,
			"image":               p.OGImage,
			"offers":              map[string]string{"@type": "Offer", "price": "0", "priceCurrency": "JPY"},
			"publisher":           map[string]string{"@type": "Organization", "name": "PAPS", "url": "https://paps.jp"},
		})
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		p.LDJSON = template.JS(ld) // json.Marshal escapes <, > and & so this cannot break out of <script>
	}

	var buf bytes.Buffer
	if err := s.pages.ExecuteTemplate(&buf, tmpl, p); err != nil {
		log.Printf("%s template: %v", tmpl, err)
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
		s.servePage(w, r, name, pageHome)
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
	for _, page := range []string{pageHome, pageSafety} {
		for _, l := range languages {
			fmt.Fprintf(&b, "  <url>\n    <loc>%s%s</loc>\n", origin, pagePath(l.Code, page))
			for _, alt := range languages {
				fmt.Fprintf(&b, "    <xhtml:link rel=\"alternate\" hreflang=\"%s\" href=\"%s%s\"/>\n", alt.Code, origin, pagePath(alt.Code, page))
			}
			fmt.Fprintf(&b, "    <xhtml:link rel=\"alternate\" hreflang=\"x-default\" href=\"%s%s\"/>\n", origin, pagePath(defaultLang, page))
			b.WriteString("    <changefreq>monthly</changefreq>\n  </url>\n")
		}
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

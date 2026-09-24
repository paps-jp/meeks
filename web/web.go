// Package web embeds the browser client.
package web

import "embed"

// Files holds the static client under "static/".
//
//go:embed static
var Files embed.FS

// Templates holds server-rendered pages under "templates/".
//
//go:embed templates
var Templates embed.FS

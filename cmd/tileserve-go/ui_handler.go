package main

import (
	_ "embed"
	"net/http"
)

//go:embed ui.html
var uiPage []byte

//go:embed vendor/maplibre-gl.js
var maplibreJS []byte

//go:embed vendor/maplibre-gl.css
var maplibreCSS []byte

// uiHandler serves the self-contained management UI. The page itself is
// public (it must be reachable before a token exists); every action it takes
// calls the normal authenticated JSON API with a token obtained via /login.
func uiHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		switch r.URL.Path {
		case "/ui/vendor/maplibre-gl.js":
			w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
			w.Write(maplibreJS)
		case "/ui/vendor/maplibre-gl.css":
			w.Header().Set("Content-Type", "text/css; charset=utf-8")
			w.Write(maplibreCSS)
		default:
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.Write(uiPage)
		}
	}
}

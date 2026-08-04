package main

import (
	_ "embed"
	"net/http"
)

//go:embed ui.html
var uiPage []byte

// uiHandler serves the self-contained management UI. The page itself is
// public (it must be reachable before a token exists); every action it takes
// calls the normal authenticated JSON API with a token obtained via /login.
func uiHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write(uiPage)
	}
}

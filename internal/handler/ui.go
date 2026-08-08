package handler

import (
	_ "embed"
	"net/http"
)

//go:embed ui.html
var uiPage []byte

// UIHandler serves the self-contained management UI. The page itself is
// public (it must be reachable before a token exists); every action it takes
// calls the normal authenticated JSON API with a token obtained via /login.
func UIHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write(uiPage)
	}
}

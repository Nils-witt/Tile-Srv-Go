package main

import (
	"context"
	_ "embed"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type contextKey string

const usernameContextKey contextKey = "username"

// usernameFromContext returns the JWT subject stored by requireAuth, or "" if absent.
func usernameFromContext(ctx context.Context) string {
	username, _ := ctx.Value(usernameContextKey).(string)
	return username
}

const (
	defaultTokenTTL = 24 * time.Hour
	maxTokenTTL     = 7 * 24 * time.Hour
)

//go:embed login.html
var loginPage []byte

type loginRequest struct {
	Username   string `json:"username"`
	Password   string `json:"password"`
	TTLSeconds int64  `json:"ttl_seconds,omitempty"`
}

type loginResponse struct {
	Token string `json:"token"`
}

// loginHandler serves GET /login (the static login page) and handles
// POST /login: it authenticates the given username/password against store
// and, on success, issues a signed JWT valid for the requested TTL (capped
// at maxTokenTTL, defaulting to defaultTokenTTL).
func loginHandler(secret []byte, store *Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = w.Write(loginPage)
			return
		}

		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		var req loginRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid request body", http.StatusBadRequest)
			return
		}

		if err := store.Authenticate(r.Context(), req.Username, req.Password); err != nil {
			http.Error(w, "invalid credentials", http.StatusUnauthorized)
			return
		}

		ttl := defaultTokenTTL
		if req.TTLSeconds > 0 {
			ttl = time.Duration(req.TTLSeconds) * time.Second
			if ttl > maxTokenTTL {
				ttl = maxTokenTTL
			}
		}

		claims := jwt.RegisteredClaims{
			Subject:   req.Username,
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(ttl)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		}
		token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(secret)
		if err != nil {
			http.Error(w, "failed to issue token", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(loginResponse{Token: token})
	}
}

// parseBearerToken extracts and validates a JWT from the request's
// Authorization header or ?token= query parameter. hadToken is false if the
// request supplied no token at all (distinct from supplying an invalid one),
// so callers can tell "anonymous" apart from "bad credentials".
func parseBearerToken(secret []byte, r *http.Request) (username string, hadToken bool, valid bool) {
	tokenString, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok || tokenString == "" {
		tokenString = r.URL.Query().Get("token")
	}
	if tokenString == "" {
		return "", false, false
	}

	claims := &jwt.RegisteredClaims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, jwt.ErrTokenSignatureInvalid
		}
		return secret, nil
	})
	if err != nil || !token.Valid {
		return "", true, false
	}
	return claims.Subject, true, true
}

// requireAuth is HTTP middleware that rejects any request without a valid
// bearer token (401) and otherwise stores the token's subject (username) in
// the request context for next to read via usernameFromContext.
func requireAuth(secret []byte, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		username, hadToken, valid := parseBearerToken(secret, r)
		if !hadToken {
			http.Error(w, "missing bearer token", http.StatusUnauthorized)
			return
		}
		if !valid {
			http.Error(w, "invalid or expired token", http.StatusUnauthorized)
			return
		}

		ctx := context.WithValue(r.Context(), usernameContextKey, username)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// optionalAuth is like requireAuth but lets a request with no bearer token
// at all through, with an empty username in the context (see
// usernameFromContext) rather than rejecting it outright. It's for routes
// that decide per-resource whether anonymous access is allowed (e.g. a
// map's anonymousAllowed setting) — everything else on such a route must
// still call requireAuthenticated itself. A token that IS present but
// invalid/expired is still rejected with 401, same as requireAuth.
func optionalAuth(secret []byte, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		username, hadToken, valid := parseBearerToken(secret, r)
		if hadToken && !valid {
			http.Error(w, "invalid or expired token", http.StatusUnauthorized)
			return
		}

		ctx := context.WithValue(r.Context(), usernameContextKey, username)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

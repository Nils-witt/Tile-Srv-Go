package handler

import (
	"context"
	_ "embed"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"nilswitt.dev/tileserve-go/internal/store"
)

type contextKey string

const usernameContextKey contextKey = "username"

// usernameFromContext returns the JWT subject stored by RequireAuth, or "" if absent.
func usernameFromContext(ctx context.Context) string {
	username, _ := ctx.Value(usernameContextKey).(string)
	return username
}

const (
	defaultTokenTTL = 1 * time.Hour
	maxTokenTTL     = 7 * 24 * time.Hour

	// refreshTokenTTL is how long a refresh token remains redeemable. It
	// deliberately outlives login token TTLs so a client can stay signed in
	// by refreshing well after its short-lived login token has expired.
	refreshTokenTTL = 30 * 24 * time.Hour
)

//go:embed login.html
var loginPage []byte

type loginRequest struct {
	Username   string `json:"username"`
	Password   string `json:"password"`
	TTLSeconds int64  `json:"ttl_seconds,omitempty"`
}

type loginResponse struct {
	Token        string `json:"token"`
	RefreshToken string `json:"refresh_token"`
}

// LoginHandler serves GET /login (the static login page) and handles
// POST /login: it authenticates the given username/password against st
// and, on success, issues a signed JWT valid for the requested TTL (capped
// at maxTokenTTL, defaulting to defaultTokenTTL) alongside a refresh token
// (valid for refreshTokenTTL) that can later be exchanged at POST /refresh
// for a new login JWT without re-sending credentials.
func LoginHandler(secret []byte, st *store.Store) http.HandlerFunc {
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
		if !decodeJSON(w, r, &req) {
			return
		}

		if err := st.Authenticate(r.Context(), req.Username, req.Password); err != nil {
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

		refreshToken, _, err := st.CreateRefreshToken(r.Context(), req.Username, refreshTokenTTL)
		if err != nil {
			http.Error(w, "failed to issue token", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(loginResponse{Token: token, RefreshToken: refreshToken})
	}
}

type refreshRequest struct {
	RefreshToken string `json:"refresh_token"`
}

// RefreshHandler serves POST /refresh: redeems a valid, unexpired refresh
// token (as previously issued by LoginHandler or a prior call to this
// handler) for a new login JWT, plus a new refresh token that replaces it.
// The old refresh token is revoked as part of the same exchange, so each
// one is single-use; reusing an already-redeemed refresh token is treated
// as invalid, same as an unknown or expired one.
func RefreshHandler(secret []byte, st *store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !requireMethod(w, r, http.MethodPost) {
			return
		}

		var req refreshRequest
		if !decodeJSON(w, r, &req) {
			return
		}
		if req.RefreshToken == "" {
			http.Error(w, "invalid request body", http.StatusBadRequest)
			return
		}

		username, newRefreshToken, _, err := st.RotateRefreshToken(r.Context(), req.RefreshToken, refreshTokenTTL)
		if err != nil {
			writeStoreError(w, err, store.ErrInvalidRefreshToken, http.StatusUnauthorized, "invalid or expired refresh token", "failed to refresh token")
			return
		}

		claims := jwt.RegisteredClaims{
			Subject:   username,
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(defaultTokenTTL)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		}
		token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(secret)
		if err != nil {
			http.Error(w, "failed to issue token", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(loginResponse{Token: token, RefreshToken: newRefreshToken})
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

// authMiddleware is the shared core of RequireAuth and OptionalAuth: it
// parses the bearer token and stores its subject (username, possibly empty)
// in the request context for next to read via usernameFromContext. A token
// that IS present but invalid/expired is always rejected with 401; whether a
// missing token is also rejected depends on requireToken.
func authMiddleware(secret []byte, next http.Handler, requireToken bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		username, hadToken, valid := parseBearerToken(secret, r)
		if requireToken && !hadToken {
			http.Error(w, "missing bearer token", http.StatusUnauthorized)
			return
		}
		if hadToken && !valid {
			http.Error(w, "invalid or expired token", http.StatusUnauthorized)
			return
		}

		ctx := context.WithValue(r.Context(), usernameContextKey, username)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// RequireAuth is HTTP middleware that rejects any request without a valid
// bearer token (401) and otherwise stores the token's subject (username) in
// the request context for next to read via usernameFromContext.
func RequireAuth(secret []byte, next http.Handler) http.Handler {
	return authMiddleware(secret, next, true)
}

// OptionalAuth is like RequireAuth but lets a request with no bearer token
// at all through, with an empty username in the context (see
// usernameFromContext) rather than rejecting it outright. It's for routes
// that decide per-resource whether anonymous access is allowed (e.g. a
// map's anonymousAllowed setting) — everything else on such a route must
// still call requireAuthenticated itself. A token that IS present but
// invalid/expired is still rejected with 401, same as RequireAuth.
func OptionalAuth(secret []byte, next http.Handler) http.Handler {
	return authMiddleware(secret, next, false)
}

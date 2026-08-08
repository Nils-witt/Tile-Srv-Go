package handler

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// signToken returns a signed JWT for subject, valid for ttl, using secret.
func signToken(t *testing.T, secret []byte, subject string, ttl time.Duration) string {
	t.Helper()
	claims := jwt.RegisteredClaims{
		Subject:   subject,
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(ttl)),
		IssuedAt:  jwt.NewNumericDate(time.Now()),
	}
	token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(secret)
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}
	return token
}

func TestParseBearerToken(t *testing.T) {
	secret := []byte("test-secret")
	validToken := signToken(t, secret, "alice", time.Hour)
	expiredToken := signToken(t, secret, "alice", -time.Hour)
	wrongSecretToken := signToken(t, []byte("other-secret"), "alice", time.Hour)

	tests := []struct {
		name         string
		authHeader   string
		queryToken   string
		wantUsername string
		wantHadToken bool
		wantValid    bool
	}{
		{
			name:         "no token at all",
			wantUsername: "",
			wantHadToken: false,
			wantValid:    false,
		},
		{
			name:         "valid bearer header",
			authHeader:   "Bearer " + validToken,
			wantUsername: "alice",
			wantHadToken: true,
			wantValid:    true,
		},
		{
			name:         "valid token via query param",
			queryToken:   validToken,
			wantUsername: "alice",
			wantHadToken: true,
			wantValid:    true,
		},
		{
			name:         "expired token",
			authHeader:   "Bearer " + expiredToken,
			wantUsername: "",
			wantHadToken: true,
			wantValid:    false,
		},
		{
			name:         "wrong signing secret",
			authHeader:   "Bearer " + wrongSecretToken,
			wantUsername: "",
			wantHadToken: true,
			wantValid:    false,
		},
		{
			name:         "malformed token",
			authHeader:   "Bearer not-a-jwt",
			wantUsername: "",
			wantHadToken: true,
			wantValid:    false,
		},
		{
			name:         "header missing Bearer prefix falls back to query, which is also empty",
			authHeader:   validToken,
			wantUsername: "",
			wantHadToken: false,
			wantValid:    false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/maps", nil)
			if tc.authHeader != "" {
				r.Header.Set("Authorization", tc.authHeader)
			}
			if tc.queryToken != "" {
				q := r.URL.Query()
				q.Set("token", tc.queryToken)
				r.URL.RawQuery = q.Encode()
			}

			username, hadToken, valid := parseBearerToken(secret, r)
			if username != tc.wantUsername || hadToken != tc.wantHadToken || valid != tc.wantValid {
				t.Fatalf("parseBearerToken() = (%q, %v, %v), want (%q, %v, %v)",
					username, hadToken, valid, tc.wantUsername, tc.wantHadToken, tc.wantValid)
			}
		})
	}
}

func TestRequireAuth(t *testing.T) {
	secret := []byte("test-secret")
	validToken := signToken(t, secret, "alice", time.Hour)

	nextCalled := false
	var gotUsername string
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		gotUsername = usernameFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	})

	t.Run("missing token is rejected", func(t *testing.T) {
		nextCalled = false
		r := httptest.NewRequest(http.MethodGet, "/maps", nil)
		w := httptest.NewRecorder()
		RequireAuth(secret, next).ServeHTTP(w, r)

		if nextCalled {
			t.Fatal("next should not be called without a token")
		}
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d, want %d", w.Code, http.StatusUnauthorized)
		}
	})

	t.Run("invalid token is rejected", func(t *testing.T) {
		nextCalled = false
		r := httptest.NewRequest(http.MethodGet, "/maps", nil)
		r.Header.Set("Authorization", "Bearer garbage")
		w := httptest.NewRecorder()
		RequireAuth(secret, next).ServeHTTP(w, r)

		if nextCalled {
			t.Fatal("next should not be called with an invalid token")
		}
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d, want %d", w.Code, http.StatusUnauthorized)
		}
	})

	t.Run("valid token passes through with username in context", func(t *testing.T) {
		nextCalled = false
		gotUsername = ""
		r := httptest.NewRequest(http.MethodGet, "/maps", nil)
		r.Header.Set("Authorization", "Bearer "+validToken)
		w := httptest.NewRecorder()
		RequireAuth(secret, next).ServeHTTP(w, r)

		if !nextCalled {
			t.Fatal("next should be called with a valid token")
		}
		if w.Code != http.StatusOK {
			t.Fatalf("status = %d, want %d", w.Code, http.StatusOK)
		}
		if gotUsername != "alice" {
			t.Fatalf("username in context = %q, want %q", gotUsername, "alice")
		}
	})
}

func TestOptionalAuth(t *testing.T) {
	secret := []byte("test-secret")
	validToken := signToken(t, secret, "alice", time.Hour)

	var nextCalled bool
	var gotUsername string
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		gotUsername = usernameFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	})

	t.Run("missing token passes through anonymously", func(t *testing.T) {
		nextCalled = false
		gotUsername = "unset"
		r := httptest.NewRequest(http.MethodGet, "/maps/some-id/version/1/0/0.png", nil)
		w := httptest.NewRecorder()
		OptionalAuth(secret, next).ServeHTTP(w, r)

		if !nextCalled {
			t.Fatal("next should be called even without a token")
		}
		if w.Code != http.StatusOK {
			t.Fatalf("status = %d, want %d", w.Code, http.StatusOK)
		}
		if gotUsername != "" {
			t.Fatalf("username in context = %q, want empty", gotUsername)
		}
	})

	t.Run("invalid token is still rejected", func(t *testing.T) {
		nextCalled = false
		r := httptest.NewRequest(http.MethodGet, "/maps", nil)
		r.Header.Set("Authorization", "Bearer garbage")
		w := httptest.NewRecorder()
		OptionalAuth(secret, next).ServeHTTP(w, r)

		if nextCalled {
			t.Fatal("next should not be called with an invalid token")
		}
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d, want %d", w.Code, http.StatusUnauthorized)
		}
	})

	t.Run("valid token passes through with username in context", func(t *testing.T) {
		nextCalled = false
		gotUsername = ""
		r := httptest.NewRequest(http.MethodGet, "/maps", nil)
		r.Header.Set("Authorization", "Bearer "+validToken)
		w := httptest.NewRecorder()
		OptionalAuth(secret, next).ServeHTTP(w, r)

		if !nextCalled {
			t.Fatal("next should be called with a valid token")
		}
		if gotUsername != "alice" {
			t.Fatalf("username in context = %q, want %q", gotUsername, "alice")
		}
	})
}

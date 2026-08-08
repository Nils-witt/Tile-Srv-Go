package handler

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/uuid"
)

func TestMapDir(t *testing.T) {
	id := uuid.MustParse("11111111-1111-1111-1111-111111111111")
	got := mapDir("/data/overlays", id)
	want := filepath.Join("/data/overlays", id.String())
	if got != want {
		t.Fatalf("mapDir() = %q, want %q", got, want)
	}
}

func TestMapVersionDir(t *testing.T) {
	id := uuid.MustParse("11111111-1111-1111-1111-111111111111")
	got := mapVersionDir("/data/overlays", id, "3")
	want := filepath.Join("/data/overlays", id.String(), "3")
	if got != want {
		t.Fatalf("mapVersionDir() = %q, want %q", got, want)
	}
	if got != filepath.Join(mapDir("/data/overlays", id), "3") {
		t.Fatalf("mapVersionDir() should build on top of mapDir()")
	}
}

func TestWriteJSON(t *testing.T) {
	w := httptest.NewRecorder()
	writeJSON(w, http.StatusCreated, map[string]string{"hello": "world"})

	if w.Code != http.StatusCreated {
		t.Errorf("status = %d, want %d", w.Code, http.StatusCreated)
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want %q", ct, "application/json")
	}

	var got map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("body is not valid JSON: %v", err)
	}
	if got["hello"] != "world" {
		t.Errorf("body = %v, want {hello: world}", got)
	}
}

func TestDecodeJSON(t *testing.T) {
	t.Run("valid body", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"name":"a"}`))
		w := httptest.NewRecorder()

		var v struct {
			Name string `json:"name"`
		}
		if ok := decodeJSON(w, r, &v); !ok {
			t.Fatal("decodeJSON() = false, want true")
		}
		if v.Name != "a" {
			t.Errorf("decoded Name = %q, want %q", v.Name, "a")
		}
		if w.Code != http.StatusOK {
			t.Errorf("no response should have been written, but status = %d", w.Code)
		}
	})

	t.Run("invalid body", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`not json`))
		w := httptest.NewRecorder()

		var v struct{}
		if ok := decodeJSON(w, r, &v); ok {
			t.Fatal("decodeJSON() = true, want false")
		}
		if w.Code != http.StatusBadRequest {
			t.Errorf("status = %d, want %d", w.Code, http.StatusBadRequest)
		}
	})
}

func TestRequireMethod(t *testing.T) {
	t.Run("matching method", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		w := httptest.NewRecorder()
		if ok := requireMethod(w, r, http.MethodGet); !ok {
			t.Fatal("requireMethod() = false, want true")
		}
		if w.Code != http.StatusOK {
			t.Errorf("no response should have been written, but status = %d", w.Code)
		}
	})

	t.Run("mismatched method", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodPost, "/", nil)
		w := httptest.NewRecorder()
		if ok := requireMethod(w, r, http.MethodGet); ok {
			t.Fatal("requireMethod() = true, want false")
		}
		if w.Code != http.StatusMethodNotAllowed {
			t.Errorf("status = %d, want %d", w.Code, http.StatusMethodNotAllowed)
		}
	})
}

func TestWriteStoreError(t *testing.T) {
	sentinel := errors.New("sentinel error")

	t.Run("sentinel error maps to its own status and message", func(t *testing.T) {
		w := httptest.NewRecorder()
		writeStoreError(w, sentinel, sentinel, http.StatusNotFound, "not found", "internal failure")

		if w.Code != http.StatusNotFound {
			t.Errorf("status = %d, want %d", w.Code, http.StatusNotFound)
		}
		if body := strings.TrimSpace(w.Body.String()); body != "not found" {
			t.Errorf("body = %q, want %q", body, "not found")
		}
	})

	t.Run("wrapped sentinel error still matches via errors.Is", func(t *testing.T) {
		w := httptest.NewRecorder()
		wrapped := fmt.Errorf("context: %w", sentinel)
		writeStoreError(w, wrapped, sentinel, http.StatusBadRequest, "bad request", "internal failure")

		if w.Code != http.StatusBadRequest {
			t.Errorf("status = %d, want %d", w.Code, http.StatusBadRequest)
		}
	})

	t.Run("other error falls back to 500", func(t *testing.T) {
		w := httptest.NewRecorder()
		writeStoreError(w, errors.New("boom"), sentinel, http.StatusNotFound, "not found", "internal failure")

		if w.Code != http.StatusInternalServerError {
			t.Errorf("status = %d, want %d", w.Code, http.StatusInternalServerError)
		}
		if body := strings.TrimSpace(w.Body.String()); body != "internal failure" {
			t.Errorf("body = %q, want %q", body, "internal failure")
		}
	})
}

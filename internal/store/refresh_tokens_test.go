package store

import (
	"encoding/hex"
	"testing"
)

func TestNewRefreshTokenValue(t *testing.T) {
	a, err := newRefreshTokenValue()
	if err != nil {
		t.Fatalf("newRefreshTokenValue: %v", err)
	}
	if a == "" {
		t.Fatal("newRefreshTokenValue returned an empty token")
	}

	b, err := newRefreshTokenValue()
	if err != nil {
		t.Fatalf("newRefreshTokenValue: %v", err)
	}
	if a == b {
		t.Fatal("newRefreshTokenValue produced the same token twice")
	}
}

func TestHashRefreshToken(t *testing.T) {
	hash := hashRefreshToken("token-a")

	if got, err := hex.DecodeString(hash); err != nil || len(got) != 32 {
		t.Fatalf("hashRefreshToken() = %q, want a 32-byte hex-encoded SHA-256 digest", hash)
	}
	if hashRefreshToken("token-a") != hash {
		t.Fatal("hashRefreshToken is not deterministic for the same input")
	}
	if hashRefreshToken("token-b") == hash {
		t.Fatal("hashRefreshToken produced the same digest for two different tokens")
	}
}

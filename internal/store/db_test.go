package store

import (
	"errors"
	"fmt"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
	"golang.org/x/crypto/bcrypt"
)

func TestHashPassword(t *testing.T) {
	hash, err := hashPassword("s3cret")
	if err != nil {
		t.Fatalf("hashPassword: %v", err)
	}
	if hash == "s3cret" {
		t.Fatal("hashPassword returned the plaintext password unchanged")
	}
	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte("s3cret")); err != nil {
		t.Fatalf("hash does not verify against the original password: %v", err)
	}
	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte("wrong")); err == nil {
		t.Fatal("hash verified against the wrong password")
	}

	// bcrypt salts each hash, so hashing the same password twice must not
	// produce identical output.
	hash2, err := hashPassword("s3cret")
	if err != nil {
		t.Fatalf("hashPassword: %v", err)
	}
	if hash == hash2 {
		t.Fatal("hashPassword produced identical hashes for two calls with the same password")
	}
}

func TestIsPgErrCode(t *testing.T) {
	uniqueViolation := &pgconn.PgError{Code: "23505"}

	tests := []struct {
		name string
		err  error
		code string
		want bool
	}{
		{name: "matching code", err: uniqueViolation, code: "23505", want: true},
		{name: "wrapped matching code", err: fmt.Errorf("insert: %w", uniqueViolation), code: "23505", want: true},
		{name: "different code", err: uniqueViolation, code: "23503", want: false},
		{name: "non-pg error", err: errors.New("boom"), code: "23505", want: false},
		{name: "nil error", err: nil, code: "23505", want: false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := isPgErrCode(tc.err, tc.code); got != tc.want {
				t.Errorf("isPgErrCode() = %v, want %v", got, tc.want)
			}
		})
	}
}

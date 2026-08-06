package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

var ErrInvalidRefreshToken = errors.New("invalid refresh token")

// refreshTokenBytes is how much crypto/rand entropy backs each issued
// refresh token before base64 encoding.
const refreshTokenBytes = 32

// newRefreshTokenValue returns a random, URL-safe refresh token string.
func newRefreshTokenValue() (string, error) {
	buf := make([]byte, refreshTokenBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("generate refresh token: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// hashRefreshToken returns the hex-encoded SHA-256 digest of token. Only
// this digest is ever persisted, so a database leak alone doesn't hand out
// usable refresh tokens; SHA-256 (rather than bcrypt) is fine here because
// the input is high-entropy random data, not a low-entropy user password.
func hashRefreshToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// CreateRefreshToken issues and stores a new refresh token for username,
// valid for ttl.
func (s *Store) CreateRefreshToken(ctx context.Context, username string, ttl time.Duration) (token string, expiresAt time.Time, err error) {
	token, err = newRefreshTokenValue()
	if err != nil {
		return "", time.Time{}, err
	}
	expiresAt = time.Now().Add(ttl)

	_, err = s.pool.Exec(ctx, `
		INSERT INTO refresh_tokens (token_hash, username, expires_at)
		VALUES ($1, $2, $3)
	`, hashRefreshToken(token), username, expiresAt)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("create refresh token: %w", err)
	}
	return token, expiresAt, nil
}

// RotateRefreshToken redeems oldToken for a new refresh token belonging to
// the same user: the old token is revoked and a new one issued in the same
// transaction, so each refresh token is single-use. It returns
// ErrInvalidRefreshToken if oldToken is unknown, expired, or already
// revoked — the last case includes reuse of a previously-rotated token,
// which signals the token was stolen rather than a legitimate double-use.
func (s *Store) RotateRefreshToken(ctx context.Context, oldToken string, ttl time.Duration) (username, newToken string, expiresAt time.Time, err error) {
	oldHash := hashRefreshToken(oldToken)

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return "", "", time.Time{}, fmt.Errorf("begin refresh transaction: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var oldExpiresAt time.Time
	err = tx.QueryRow(ctx, `
		SELECT username, expires_at FROM refresh_tokens
		WHERE token_hash = $1 AND revoked_at IS NULL
		FOR UPDATE
	`, oldHash).Scan(&username, &oldExpiresAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", "", time.Time{}, ErrInvalidRefreshToken
	}
	if err != nil {
		return "", "", time.Time{}, fmt.Errorf("look up refresh token: %w", err)
	}
	if time.Now().After(oldExpiresAt) {
		return "", "", time.Time{}, ErrInvalidRefreshToken
	}

	if _, err = tx.Exec(ctx, `UPDATE refresh_tokens SET revoked_at = now() WHERE token_hash = $1`, oldHash); err != nil {
		return "", "", time.Time{}, fmt.Errorf("revoke refresh token: %w", err)
	}

	newToken, err = newRefreshTokenValue()
	if err != nil {
		return "", "", time.Time{}, err
	}
	expiresAt = time.Now().Add(ttl)
	if _, err = tx.Exec(ctx, `
		INSERT INTO refresh_tokens (token_hash, username, expires_at)
		VALUES ($1, $2, $3)
	`, hashRefreshToken(newToken), username, expiresAt); err != nil {
		return "", "", time.Time{}, fmt.Errorf("insert rotated refresh token: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return "", "", time.Time{}, fmt.Errorf("commit refresh transaction: %w", err)
	}
	return username, newToken, expiresAt, nil
}

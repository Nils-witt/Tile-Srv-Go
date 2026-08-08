package store

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/crypto/bcrypt"
)

var ErrInvalidCredentials = errors.New("invalid credentials")

type Store struct {
	pool *pgxpool.Pool
}

// NewStore opens a connection pool to the postgres database at dsn and
// verifies it is reachable with a ping.
func NewStore(ctx context.Context, dsn string) (*Store, error) {
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return nil, fmt.Errorf("connect to postgres: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("ping postgres: %w", err)
	}
	return &Store{pool: pool}, nil
}

// Close releases the underlying database connection pool.
func (s *Store) Close() {
	s.pool.Close()
}

// Migrate creates the users, maps, map_versions, and map_permissions tables
// if they don't exist yet, and adds any columns introduced since the tables
// were first created. It is idempotent and safe to run on every startup.
func (s *Store) Migrate(ctx context.Context) error {
	_, err := s.pool.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS users (
			id            BIGSERIAL PRIMARY KEY,
			username      TEXT NOT NULL UNIQUE,
			password_hash TEXT NOT NULL,
			can_create    BOOLEAN NOT NULL DEFAULT true,
			can_edit      BOOLEAN NOT NULL DEFAULT true,
			can_delete    BOOLEAN NOT NULL DEFAULT true,
			is_admin      BOOLEAN NOT NULL DEFAULT true,
			created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
		)
	`)
	if err != nil {
		return fmt.Errorf("migrate users table: %w", err)
	}

	_, err = s.pool.Exec(ctx, `
		ALTER TABLE users ADD COLUMN IF NOT EXISTS can_create BOOLEAN NOT NULL DEFAULT true;
		ALTER TABLE users ADD COLUMN IF NOT EXISTS can_edit   BOOLEAN NOT NULL DEFAULT true;
		ALTER TABLE users ADD COLUMN IF NOT EXISTS can_delete BOOLEAN NOT NULL DEFAULT true;
		ALTER TABLE users ADD COLUMN IF NOT EXISTS is_admin   BOOLEAN NOT NULL DEFAULT true;
		ALTER TABLE users ADD COLUMN IF NOT EXISTS cn         TEXT NOT NULL DEFAULT '';
	`)
	if err != nil {
		return fmt.Errorf("migrate users permission columns: %w", err)
	}

	_, err = s.pool.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS maps (
			uuid            UUID PRIMARY KEY,
			name            TEXT NOT NULL,
			current_version TEXT NOT NULL DEFAULT '',
			created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
			updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
			created_by      TEXT NOT NULL,
			updated_by      TEXT NOT NULL
		)
	`)
	if err != nil {
		return fmt.Errorf("migrate maps table: %w", err)
	}

	_, err = s.pool.Exec(ctx, `
		ALTER TABLE maps ADD COLUMN IF NOT EXISTS visible_to_all     BOOLEAN NOT NULL DEFAULT false;
		ALTER TABLE maps ADD COLUMN IF NOT EXISTS anonymous_allowed  BOOLEAN NOT NULL DEFAULT false;
	`)
	if err != nil {
		return fmt.Errorf("migrate maps visibility column: %w", err)
	}

	_, err = s.pool.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS map_versions (
			map_uuid   UUID NOT NULL REFERENCES maps(uuid) ON DELETE CASCADE,
			version    TEXT NOT NULL,
			created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
			created_by TEXT NOT NULL,
			PRIMARY KEY (map_uuid, version)
		)
	`)
	if err != nil {
		return fmt.Errorf("migrate map_versions table: %w", err)
	}

	_, err = s.pool.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS map_permissions (
			map_uuid   UUID NOT NULL REFERENCES maps(uuid) ON DELETE CASCADE,
			username   TEXT NOT NULL REFERENCES users(username) ON DELETE CASCADE,
			can_edit   BOOLEAN NOT NULL DEFAULT false,
			can_delete BOOLEAN NOT NULL DEFAULT false,
			granted_at TIMESTAMPTZ NOT NULL DEFAULT now(),
			granted_by TEXT NOT NULL,
			PRIMARY KEY (map_uuid, username)
		)
	`)
	if err != nil {
		return fmt.Errorf("migrate map_permissions table: %w", err)
	}

	_, err = s.pool.Exec(ctx, `
		ALTER TABLE map_permissions ADD COLUMN IF NOT EXISTS can_view BOOLEAN NOT NULL DEFAULT false;
	`)
	if err != nil {
		return fmt.Errorf("migrate map_permissions view column: %w", err)
	}

	_, err = s.pool.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS refresh_tokens (
			token_hash TEXT PRIMARY KEY,
			username   TEXT NOT NULL REFERENCES users(username) ON DELETE CASCADE,
			expires_at TIMESTAMPTZ NOT NULL,
			created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
			revoked_at TIMESTAMPTZ
		)
	`)
	if err != nil {
		return fmt.Errorf("migrate refresh_tokens table: %w", err)
	}
	return nil
}

// Authenticate looks up username and verifies password against its bcrypt hash.
// It returns ErrInvalidCredentials for both an unknown username and a wrong password.
func (s *Store) Authenticate(ctx context.Context, username, password string) error {
	var hash string
	err := s.pool.QueryRow(ctx, `SELECT password_hash FROM users WHERE username = $1`, username).Scan(&hash)
	if err != nil {
		return ErrInvalidCredentials
	}
	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)); err != nil {
		return ErrInvalidCredentials
	}
	return nil
}

type Permissions struct {
	CanCreate bool
	CanEdit   bool
	CanDelete bool
	IsAdmin   bool
}

// GetPermissions returns the global create/edit/delete/admin permissions for username.
func (s *Store) GetPermissions(ctx context.Context, username string) (Permissions, error) {
	var p Permissions
	err := s.pool.QueryRow(ctx, `
		SELECT can_create, can_edit, can_delete, is_admin FROM users WHERE username = $1
	`, username).Scan(&p.CanCreate, &p.CanEdit, &p.CanDelete, &p.IsAdmin)
	if err != nil {
		return Permissions{}, fmt.Errorf("get permissions for %q: %w", username, err)
	}
	return p, nil
}

// SeedUser creates username with password if it doesn't already exist. Used to
// bootstrap the first account; it is a no-op if the username is already taken.
func (s *Store) SeedUser(ctx context.Context, username, password string) error {
	hash, err := hashPassword(password)
	if err != nil {
		return err
	}
	_, err = s.pool.Exec(ctx, `
		INSERT INTO users (username, password_hash) VALUES ($1, $2)
		ON CONFLICT (username) DO NOTHING
	`, username, hash)
	if err != nil {
		return fmt.Errorf("seed user %q: %w", username, err)
	}
	return nil
}

// hashPassword bcrypt-hashes password for storage.
func hashPassword(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", fmt.Errorf("hash password: %w", err)
	}
	return string(hash), nil
}

// isPgErrCode reports whether err is a *pgconn.PgError with the given SQLSTATE code.
func isPgErrCode(err error, code string) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == code
}

// collectRows runs query against pool and scans every returned row with
// scan, wrapping any error (including a scan failure) with label for
// context. It's shared by every Store List* method.
func collectRows[T any](ctx context.Context, pool *pgxpool.Pool, label, query string, scan func(pgx.Rows) (T, error), args ...any) ([]T, error) {
	rows, err := pool.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", label, err)
	}
	defer rows.Close()

	items := []T{}
	for rows.Next() {
		v, err := scan(rows)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", label, err)
		}
		items = append(items, v)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("%s: %w", label, err)
	}
	return items, nil
}

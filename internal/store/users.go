package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

var (
	ErrUserNotFound = errors.New("user not found")
	ErrUserExists   = errors.New("user already exists")
)

type UserRecord struct {
	Username  string    `json:"username"`
	CN        string    `json:"cn"`
	CanCreate bool      `json:"canCreate"`
	CanEdit   bool      `json:"canEdit"`
	CanDelete bool      `json:"canDelete"`
	IsAdmin   bool      `json:"isAdmin"`
	CreatedAt time.Time `json:"createdAt"`
}

// ListUsers returns every user, oldest first.
func (s *Store) ListUsers(ctx context.Context) ([]UserRecord, error) {
	return collectRows(ctx, s.pool, "list users", `
		SELECT username, cn, can_create, can_edit, can_delete, is_admin, created_at
		FROM users
		ORDER BY created_at ASC
	`, func(rows pgx.Rows) (UserRecord, error) {
		var u UserRecord
		err := rows.Scan(&u.Username, &u.CN, &u.CanCreate, &u.CanEdit, &u.CanDelete, &u.IsAdmin, &u.CreatedAt)
		return u, err
	})
}

// CreateUser creates a new user. It returns ErrUserExists if username is
// already taken.
func (s *Store) CreateUser(ctx context.Context, username, password, cn string, perms Permissions) (UserRecord, error) {
	hash, err := hashPassword(password)
	if err != nil {
		return UserRecord{}, err
	}

	u := UserRecord{
		Username:  username,
		CN:        cn,
		CanCreate: perms.CanCreate,
		CanEdit:   perms.CanEdit,
		CanDelete: perms.CanDelete,
		IsAdmin:   perms.IsAdmin,
	}
	err = s.pool.QueryRow(ctx, `
		INSERT INTO users (username, password_hash, cn, can_create, can_edit, can_delete, is_admin)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		RETURNING created_at
	`, username, hash, u.CN, u.CanCreate, u.CanEdit, u.CanDelete, u.IsAdmin).Scan(&u.CreatedAt)
	if err != nil {
		if isPgErrCode(err, "23505") {
			return UserRecord{}, ErrUserExists
		}
		return UserRecord{}, fmt.Errorf("create user: %w", err)
	}
	return u, nil
}

// UpdateUser sets username's cn and permissions, and its password too if
// newPassword is non-empty. It returns ErrUserNotFound if username doesn't
// exist.
func (s *Store) UpdateUser(ctx context.Context, username, cn string, perms Permissions, newPassword string) (UserRecord, error) {
	var u UserRecord
	var err error
	if newPassword != "" {
		var hash string
		hash, err = hashPassword(newPassword)
		if err != nil {
			return UserRecord{}, err
		}
		err = s.pool.QueryRow(ctx, `
			UPDATE users
			SET cn = $2, can_create = $3, can_edit = $4, can_delete = $5, is_admin = $6, password_hash = $7
			WHERE username = $1
			RETURNING username, cn, can_create, can_edit, can_delete, is_admin, created_at
		`, username, cn, perms.CanCreate, perms.CanEdit, perms.CanDelete, perms.IsAdmin, hash).
			Scan(&u.Username, &u.CN, &u.CanCreate, &u.CanEdit, &u.CanDelete, &u.IsAdmin, &u.CreatedAt)
	} else {
		err = s.pool.QueryRow(ctx, `
			UPDATE users
			SET cn = $2, can_create = $3, can_edit = $4, can_delete = $5, is_admin = $6
			WHERE username = $1
			RETURNING username, cn, can_create, can_edit, can_delete, is_admin, created_at
		`, username, cn, perms.CanCreate, perms.CanEdit, perms.CanDelete, perms.IsAdmin).
			Scan(&u.Username, &u.CN, &u.CanCreate, &u.CanEdit, &u.CanDelete, &u.IsAdmin, &u.CreatedAt)
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return UserRecord{}, ErrUserNotFound
	}
	if err != nil {
		return UserRecord{}, fmt.Errorf("update user: %w", err)
	}
	return u, nil
}

// DeleteUser deletes username. It returns ErrUserNotFound if it doesn't exist.
func (s *Store) DeleteUser(ctx context.Context, username string) error {
	tag, err := s.pool.Exec(ctx, `DELETE FROM users WHERE username = $1`, username)
	if err != nil {
		return fmt.Errorf("delete user: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrUserNotFound
	}
	return nil
}

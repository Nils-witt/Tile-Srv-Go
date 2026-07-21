package main

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"golang.org/x/crypto/bcrypt"
)

var (
	ErrUserNotFound = errors.New("user not found")
	ErrUserExists   = errors.New("user already exists")
)

type UserRecord struct {
	Username  string    `json:"username"`
	CanCreate bool      `json:"canCreate"`
	CanEdit   bool      `json:"canEdit"`
	CanDelete bool      `json:"canDelete"`
	IsAdmin   bool      `json:"isAdmin"`
	CreatedAt time.Time `json:"createdAt"`
}

func (s *Store) ListUsers(ctx context.Context) ([]UserRecord, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT username, can_create, can_edit, can_delete, is_admin, created_at
		FROM users
		ORDER BY created_at ASC
	`)
	if err != nil {
		return nil, fmt.Errorf("list users: %w", err)
	}
	defer rows.Close()

	users := []UserRecord{}
	for rows.Next() {
		var u UserRecord
		if err := rows.Scan(&u.Username, &u.CanCreate, &u.CanEdit, &u.CanDelete, &u.IsAdmin, &u.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan user: %w", err)
		}
		users = append(users, u)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list users: %w", err)
	}
	return users, nil
}

// CreateUser creates a new user. It returns ErrUserExists if username is
// already taken.
func (s *Store) CreateUser(ctx context.Context, username, password string, perms Permissions) (UserRecord, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return UserRecord{}, fmt.Errorf("hash password: %w", err)
	}

	u := UserRecord{
		Username:  username,
		CanCreate: perms.CanCreate,
		CanEdit:   perms.CanEdit,
		CanDelete: perms.CanDelete,
		IsAdmin:   perms.IsAdmin,
	}
	err = s.pool.QueryRow(ctx, `
		INSERT INTO users (username, password_hash, can_create, can_edit, can_delete, is_admin)
		VALUES ($1, $2, $3, $4, $5, $6)
		RETURNING created_at
	`, username, string(hash), u.CanCreate, u.CanEdit, u.CanDelete, u.IsAdmin).Scan(&u.CreatedAt)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return UserRecord{}, ErrUserExists
		}
		return UserRecord{}, fmt.Errorf("create user: %w", err)
	}
	return u, nil
}

// UpdateUser sets username's permissions, and its password too if newPassword
// is non-empty. It returns ErrUserNotFound if username doesn't exist.
func (s *Store) UpdateUser(ctx context.Context, username string, perms Permissions, newPassword string) (UserRecord, error) {
	var u UserRecord
	var err error
	if newPassword != "" {
		var hash []byte
		hash, err = bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
		if err != nil {
			return UserRecord{}, fmt.Errorf("hash password: %w", err)
		}
		err = s.pool.QueryRow(ctx, `
			UPDATE users
			SET can_create = $2, can_edit = $3, can_delete = $4, is_admin = $5, password_hash = $6
			WHERE username = $1
			RETURNING username, can_create, can_edit, can_delete, is_admin, created_at
		`, username, perms.CanCreate, perms.CanEdit, perms.CanDelete, perms.IsAdmin, string(hash)).
			Scan(&u.Username, &u.CanCreate, &u.CanEdit, &u.CanDelete, &u.IsAdmin, &u.CreatedAt)
	} else {
		err = s.pool.QueryRow(ctx, `
			UPDATE users
			SET can_create = $2, can_edit = $3, can_delete = $4, is_admin = $5
			WHERE username = $1
			RETURNING username, can_create, can_edit, can_delete, is_admin, created_at
		`, username, perms.CanCreate, perms.CanEdit, perms.CanDelete, perms.IsAdmin).
			Scan(&u.Username, &u.CanCreate, &u.CanEdit, &u.CanDelete, &u.IsAdmin, &u.CreatedAt)
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return UserRecord{}, ErrUserNotFound
	}
	if err != nil {
		return UserRecord{}, fmt.Errorf("update user: %w", err)
	}
	return u, nil
}

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

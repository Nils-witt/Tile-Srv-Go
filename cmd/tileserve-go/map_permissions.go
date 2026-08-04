package main

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

var ErrMapPermissionInvalid = errors.New("map or username does not exist")

// MapPermission is a user's per-map edit/delete grant. It only adds
// capability on top of a user's global Permissions (see Permissions in
// db.go); a grant is only consulted for a user who lacks the matching
// global flag, so it can never take capability away.
type MapPermission struct {
	CanEdit   bool
	CanDelete bool
}

type MapPermissionRecord struct {
	Username  string    `json:"username"`
	CanEdit   bool      `json:"canEdit"`
	CanDelete bool      `json:"canDelete"`
	GrantedAt time.Time `json:"grantedAt"`
	GrantedBy string    `json:"grantedBy"`
}

// GetMapPermission returns username's per-map grant for mapID, or the zero
// value (no edit/delete) if none exists.
func (s *Store) GetMapPermission(ctx context.Context, mapID uuid.UUID, username string) (MapPermission, error) {
	var mp MapPermission
	err := s.pool.QueryRow(ctx, `
		SELECT can_edit, can_delete FROM map_permissions WHERE map_uuid = $1 AND username = $2
	`, mapID, username).Scan(&mp.CanEdit, &mp.CanDelete)
	if errors.Is(err, pgx.ErrNoRows) {
		return MapPermission{}, nil
	}
	if err != nil {
		return MapPermission{}, fmt.Errorf("get map permission: %w", err)
	}
	return mp, nil
}

// ListMapPermissions returns every per-map grant for mapID, oldest first.
func (s *Store) ListMapPermissions(ctx context.Context, mapID uuid.UUID) ([]MapPermissionRecord, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT username, can_edit, can_delete, granted_at, granted_by
		FROM map_permissions
		WHERE map_uuid = $1
		ORDER BY granted_at ASC
	`, mapID)
	if err != nil {
		return nil, fmt.Errorf("list map permissions: %w", err)
	}
	defer rows.Close()

	perms := []MapPermissionRecord{}
	for rows.Next() {
		var p MapPermissionRecord
		if err := rows.Scan(&p.Username, &p.CanEdit, &p.CanDelete, &p.GrantedAt, &p.GrantedBy); err != nil {
			return nil, fmt.Errorf("scan map permission: %w", err)
		}
		perms = append(perms, p)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list map permissions: %w", err)
	}
	return perms, nil
}

// SetMapPermission creates or replaces username's per-map grant for mapID.
// It returns ErrMapPermissionInvalid if mapID or username don't exist.
func (s *Store) SetMapPermission(ctx context.Context, mapID uuid.UUID, username string, canEdit, canDelete bool, grantedBy string) (MapPermissionRecord, error) {
	p := MapPermissionRecord{Username: username, CanEdit: canEdit, CanDelete: canDelete, GrantedBy: grantedBy}
	err := s.pool.QueryRow(ctx, `
		INSERT INTO map_permissions (map_uuid, username, can_edit, can_delete, granted_by)
		VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (map_uuid, username)
		DO UPDATE SET can_edit = $3, can_delete = $4, granted_by = $5, granted_at = now()
		RETURNING granted_at
	`, mapID, username, canEdit, canDelete, grantedBy).Scan(&p.GrantedAt)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23503" {
			return MapPermissionRecord{}, ErrMapPermissionInvalid
		}
		return MapPermissionRecord{}, fmt.Errorf("set map permission: %w", err)
	}
	return p, nil
}

// DeleteMapPermission revokes username's per-map grant for mapID, if any.
func (s *Store) DeleteMapPermission(ctx context.Context, mapID uuid.UUID, username string) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM map_permissions WHERE map_uuid = $1 AND username = $2`, mapID, username)
	if err != nil {
		return fmt.Errorf("delete map permission: %w", err)
	}
	return nil
}

package main

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

var ErrMapNotFound = errors.New("map not found")

type MapRecord struct {
	UUID             uuid.UUID `json:"uuid"`
	Name             string    `json:"name"`
	CurrentVersion   string    `json:"currentVersion"`
	VisibleToAll     bool      `json:"visibleToAll"`
	AnonymousAllowed bool      `json:"anonymousAllowed"`
	CreatedAt        time.Time `json:"createdAt"`
	UpdatedAt        time.Time `json:"updatedAt"`
	CreatedBy        string    `json:"createdBy"`
	UpdatedBy        string    `json:"updatedBy"`
}

// CreateMap inserts a new map row with a fresh UUID, owned by createdBy.
func (s *Store) CreateMap(ctx context.Context, name, currentVersion string, visibleToAll, anonymousAllowed bool, createdBy string) (MapRecord, error) {
	m := MapRecord{
		UUID:             uuid.New(),
		Name:             name,
		CurrentVersion:   currentVersion,
		VisibleToAll:     visibleToAll,
		AnonymousAllowed: anonymousAllowed,
		CreatedBy:        createdBy,
		UpdatedBy:        createdBy,
	}
	err := s.pool.QueryRow(ctx, `
		INSERT INTO maps (uuid, name, current_version, visible_to_all, anonymous_allowed, created_by, updated_by)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		RETURNING created_at, updated_at
	`, m.UUID, m.Name, m.CurrentVersion, m.VisibleToAll, m.AnonymousAllowed, m.CreatedBy, m.UpdatedBy).Scan(&m.CreatedAt, &m.UpdatedAt)
	if err != nil {
		return MapRecord{}, fmt.Errorf("create map: %w", err)
	}
	return m, nil
}

// ListMaps returns every map visible to username: maps marked visible to
// all, maps username created, maps username holds a per-map view/edit/delete
// grant on, and (since they can already act on any map regardless of
// visibility) every map if bypassVisibility is true — meant to be passed as
// the acting user's is_admin || can_edit || can_delete.
func (s *Store) ListMaps(ctx context.Context, username string, bypassVisibility bool) ([]MapRecord, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT uuid, name, current_version, visible_to_all, anonymous_allowed, created_at, updated_at, created_by, updated_by
		FROM maps
		WHERE $2
		   OR visible_to_all
		   OR created_by = $1
		   OR EXISTS (
		        SELECT 1 FROM map_permissions mp
		        WHERE mp.map_uuid = maps.uuid AND mp.username = $1
		          AND (mp.can_view OR mp.can_edit OR mp.can_delete)
		      )
		ORDER BY created_at DESC
	`, username, bypassVisibility)
	if err != nil {
		return nil, fmt.Errorf("list maps: %w", err)
	}
	defer rows.Close()

	maps := []MapRecord{}
	for rows.Next() {
		var m MapRecord
		if err := rows.Scan(&m.UUID, &m.Name, &m.CurrentVersion, &m.VisibleToAll, &m.AnonymousAllowed, &m.CreatedAt, &m.UpdatedAt, &m.CreatedBy, &m.UpdatedBy); err != nil {
			return nil, fmt.Errorf("scan map: %w", err)
		}
		maps = append(maps, m)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list maps: %w", err)
	}
	return maps, nil
}

// GetMap fetches a single map by id. It returns ErrMapNotFound if it doesn't exist.
func (s *Store) GetMap(ctx context.Context, id uuid.UUID) (MapRecord, error) {
	var m MapRecord
	err := s.pool.QueryRow(ctx, `
		SELECT uuid, name, current_version, visible_to_all, anonymous_allowed, created_at, updated_at, created_by, updated_by
		FROM maps WHERE uuid = $1
	`, id).Scan(&m.UUID, &m.Name, &m.CurrentVersion, &m.VisibleToAll, &m.AnonymousAllowed, &m.CreatedAt, &m.UpdatedAt, &m.CreatedBy, &m.UpdatedBy)
	if errors.Is(err, pgx.ErrNoRows) {
		return MapRecord{}, ErrMapNotFound
	}
	if err != nil {
		return MapRecord{}, fmt.Errorf("get map: %w", err)
	}
	return m, nil
}

// UpdateMap overwrites a map's name, currentVersion, and visibility flags.
// It returns ErrMapNotFound if id doesn't exist.
func (s *Store) UpdateMap(ctx context.Context, id uuid.UUID, name, currentVersion string, visibleToAll, anonymousAllowed bool, updatedBy string) (MapRecord, error) {
	var m MapRecord
	err := s.pool.QueryRow(ctx, `
		UPDATE maps
		SET name = $2, current_version = $3, visible_to_all = $4, anonymous_allowed = $5, updated_by = $6, updated_at = now()
		WHERE uuid = $1
		RETURNING uuid, name, current_version, visible_to_all, anonymous_allowed, created_at, updated_at, created_by, updated_by
	`, id, name, currentVersion, visibleToAll, anonymousAllowed, updatedBy).Scan(&m.UUID, &m.Name, &m.CurrentVersion, &m.VisibleToAll, &m.AnonymousAllowed, &m.CreatedAt, &m.UpdatedAt, &m.CreatedBy, &m.UpdatedBy)
	if errors.Is(err, pgx.ErrNoRows) {
		return MapRecord{}, ErrMapNotFound
	}
	if err != nil {
		return MapRecord{}, fmt.Errorf("update map: %w", err)
	}
	return m, nil
}

// IncrementMapVersion reads the highest version recorded in map_versions for
// this map (treating no rows as 0), and atomically stores last+1 both as the
// map's current_version and as a new map_versions row. Using map_versions as
// the source of truth (rather than maps.current_version) means a PUT that
// manually edits currentVersion can't cause a later upload to reuse or
// overwrite an existing version directory.
//
// The map row lock held for the duration of the transaction serializes
// concurrent uploads for the same map so they can never be assigned the same
// version.
func (s *Store) IncrementMapVersion(ctx context.Context, id uuid.UUID, updatedBy string) (MapRecord, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return MapRecord{}, fmt.Errorf("begin transaction: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var exists bool
	err = tx.QueryRow(ctx, `SELECT true FROM maps WHERE uuid = $1 FOR UPDATE`, id).Scan(&exists)
	if errors.Is(err, pgx.ErrNoRows) {
		return MapRecord{}, ErrMapNotFound
	}
	if err != nil {
		return MapRecord{}, fmt.Errorf("lock map: %w", err)
	}

	var lastVersion int
	err = tx.QueryRow(ctx, `
		SELECT COALESCE(MAX(version::int), 0) FROM map_versions WHERE map_uuid = $1
	`, id).Scan(&lastVersion)
	if err != nil {
		return MapRecord{}, fmt.Errorf("get last map version: %w", err)
	}

	nextVersion := strconv.Itoa(lastVersion + 1)

	var m MapRecord
	err = tx.QueryRow(ctx, `
		UPDATE maps
		SET current_version = $2, updated_by = $3, updated_at = now()
		WHERE uuid = $1
		RETURNING uuid, name, current_version, visible_to_all, anonymous_allowed, created_at, updated_at, created_by, updated_by
	`, id, nextVersion, updatedBy).Scan(&m.UUID, &m.Name, &m.CurrentVersion, &m.VisibleToAll, &m.AnonymousAllowed, &m.CreatedAt, &m.UpdatedAt, &m.CreatedBy, &m.UpdatedBy)
	if err != nil {
		return MapRecord{}, fmt.Errorf("update map version: %w", err)
	}

	_, err = tx.Exec(ctx, `
		INSERT INTO map_versions (map_uuid, version, created_by) VALUES ($1, $2, $3)
	`, id, nextVersion, updatedBy)
	if err != nil {
		return MapRecord{}, fmt.Errorf("record map version: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return MapRecord{}, fmt.Errorf("commit: %w", err)
	}
	return m, nil
}

type MapVersionRecord struct {
	Version   string    `json:"version"`
	CreatedAt time.Time `json:"createdAt"`
	CreatedBy string    `json:"createdBy"`
}

// ListMapVersions returns the upload history for a map, most recent first.
// It returns ErrMapNotFound if the map itself doesn't exist.
func (s *Store) ListMapVersions(ctx context.Context, id uuid.UUID) ([]MapVersionRecord, error) {
	if _, err := s.GetMap(ctx, id); err != nil {
		return nil, err
	}

	rows, err := s.pool.Query(ctx, `
		SELECT version, created_at, created_by
		FROM map_versions
		WHERE map_uuid = $1
		ORDER BY created_at DESC
	`, id)
	if err != nil {
		return nil, fmt.Errorf("list map versions: %w", err)
	}
	defer rows.Close()

	versions := []MapVersionRecord{}
	for rows.Next() {
		var v MapVersionRecord
		if err := rows.Scan(&v.Version, &v.CreatedAt, &v.CreatedBy); err != nil {
			return nil, fmt.Errorf("scan map version: %w", err)
		}
		versions = append(versions, v)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list map versions: %w", err)
	}
	return versions, nil
}

// DeleteMap deletes a map by id (cascading to its versions and permission
// grants). It returns ErrMapNotFound if id doesn't exist.
func (s *Store) DeleteMap(ctx context.Context, id uuid.UUID) error {
	tag, err := s.pool.Exec(ctx, `DELETE FROM maps WHERE uuid = $1`, id)
	if err != nil {
		return fmt.Errorf("delete map: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrMapNotFound
	}
	return nil
}

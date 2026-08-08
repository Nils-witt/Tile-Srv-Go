package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

var ErrGeoObjectNotFound = errors.New("geo object not found")
var ErrGeoObjectInvalid = errors.New("map or version does not exist")

type GeoObjectRecord struct {
	UUID        uuid.UUID `json:"uuid"`
	MapUUID     uuid.UUID `json:"mapUuid"`
	Version     string    `json:"version"`
	Name        string    `json:"name"`
	ExternalID  string    `json:"externalId"`
	Latitude    float64   `json:"latitude"`
	Longitude   float64   `json:"longitude"`
	Street      string    `json:"street"`
	HouseNumber string    `json:"housenumber"`
	Postcode    string    `json:"postcode"`
	CreatedAt   time.Time `json:"createdAt"`
	UpdatedAt   time.Time `json:"updatedAt"`
	CreatedBy   string    `json:"createdBy"`
	UpdatedBy   string    `json:"updatedBy"`
}

// CreateGeoObject inserts a new geo object row with a fresh UUID, tied to
// mapID's version. It returns ErrGeoObjectInvalid if that map/version
// combination doesn't exist in map_versions.
func (s *Store) CreateGeoObject(ctx context.Context, mapID uuid.UUID, version, name, externalID string, latitude, longitude float64, street, houseNumber, postcode, createdBy string) (GeoObjectRecord, error) {
	g := GeoObjectRecord{
		UUID:        uuid.New(),
		MapUUID:     mapID,
		Version:     version,
		Name:        name,
		ExternalID:  externalID,
		Latitude:    latitude,
		Longitude:   longitude,
		Street:      street,
		HouseNumber: houseNumber,
		Postcode:    postcode,
		CreatedBy:   createdBy,
		UpdatedBy:   createdBy,
	}
	err := s.pool.QueryRow(ctx, `
		INSERT INTO geo_objects (uuid, map_uuid, version, name, external_id, latitude, longitude, street, housenumber, postcode, created_by, updated_by)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
		RETURNING created_at, updated_at
	`, g.UUID, g.MapUUID, g.Version, g.Name, g.ExternalID, g.Latitude, g.Longitude, g.Street, g.HouseNumber, g.Postcode, g.CreatedBy, g.UpdatedBy).Scan(&g.CreatedAt, &g.UpdatedAt)
	if err != nil {
		if isPgErrCode(err, "23503") {
			return GeoObjectRecord{}, ErrGeoObjectInvalid
		}
		return GeoObjectRecord{}, fmt.Errorf("create geo object: %w", err)
	}
	return g, nil
}

// ListGeoObjects returns every geo object tied to mapID's version, oldest first.
func (s *Store) ListGeoObjects(ctx context.Context, mapID uuid.UUID, version string) ([]GeoObjectRecord, error) {
	return collectRows(ctx, s.pool, "list geo objects", `
		SELECT uuid, map_uuid, version, name, external_id, latitude, longitude, street, housenumber, postcode, created_at, updated_at, created_by, updated_by
		FROM geo_objects
		WHERE map_uuid = $1 AND version = $2
		ORDER BY created_at ASC
	`, func(rows pgx.Rows) (GeoObjectRecord, error) {
		var g GeoObjectRecord
		err := rows.Scan(&g.UUID, &g.MapUUID, &g.Version, &g.Name, &g.ExternalID, &g.Latitude, &g.Longitude, &g.Street, &g.HouseNumber, &g.Postcode, &g.CreatedAt, &g.UpdatedAt, &g.CreatedBy, &g.UpdatedBy)
		return g, err
	}, mapID, version)
}

// GetGeoObject fetches a single geo object by id. It returns
// ErrGeoObjectNotFound if it doesn't exist.
func (s *Store) GetGeoObject(ctx context.Context, id uuid.UUID) (GeoObjectRecord, error) {
	var g GeoObjectRecord
	err := s.pool.QueryRow(ctx, `
		SELECT uuid, map_uuid, version, name, external_id, latitude, longitude, street, housenumber, postcode, created_at, updated_at, created_by, updated_by
		FROM geo_objects WHERE uuid = $1
	`, id).Scan(&g.UUID, &g.MapUUID, &g.Version, &g.Name, &g.ExternalID, &g.Latitude, &g.Longitude, &g.Street, &g.HouseNumber, &g.Postcode, &g.CreatedAt, &g.UpdatedAt, &g.CreatedBy, &g.UpdatedBy)
	if errors.Is(err, pgx.ErrNoRows) {
		return GeoObjectRecord{}, ErrGeoObjectNotFound
	}
	if err != nil {
		return GeoObjectRecord{}, fmt.Errorf("get geo object: %w", err)
	}
	return g, nil
}

// UpdateGeoObject overwrites a geo object's fields other than its map/version,
// which are immutable after creation. mapID and version scope the update to
// the caller's URL, so a mismatched id, map, or version all report as
// ErrGeoObjectNotFound in one query rather than requiring a separate lookup
// first.
func (s *Store) UpdateGeoObject(ctx context.Context, mapID uuid.UUID, version string, id uuid.UUID, name, externalID string, latitude, longitude float64, street, houseNumber, postcode, updatedBy string) (GeoObjectRecord, error) {
	var g GeoObjectRecord
	err := s.pool.QueryRow(ctx, `
		UPDATE geo_objects
		SET name = $4, external_id = $5, latitude = $6, longitude = $7, street = $8, housenumber = $9, postcode = $10, updated_by = $11, updated_at = now()
		WHERE uuid = $1 AND map_uuid = $2 AND version = $3
		RETURNING uuid, map_uuid, version, name, external_id, latitude, longitude, street, housenumber, postcode, created_at, updated_at, created_by, updated_by
	`, id, mapID, version, name, externalID, latitude, longitude, street, houseNumber, postcode, updatedBy).Scan(&g.UUID, &g.MapUUID, &g.Version, &g.Name, &g.ExternalID, &g.Latitude, &g.Longitude, &g.Street, &g.HouseNumber, &g.Postcode, &g.CreatedAt, &g.UpdatedAt, &g.CreatedBy, &g.UpdatedBy)
	if errors.Is(err, pgx.ErrNoRows) {
		return GeoObjectRecord{}, ErrGeoObjectNotFound
	}
	if err != nil {
		return GeoObjectRecord{}, fmt.Errorf("update geo object: %w", err)
	}
	return g, nil
}

// DeleteGeoObject deletes a geo object by id, scoped to mapID's version (see
// UpdateGeoObject). It returns ErrGeoObjectNotFound if no row matched.
func (s *Store) DeleteGeoObject(ctx context.Context, mapID uuid.UUID, version string, id uuid.UUID) error {
	tag, err := s.pool.Exec(ctx, `DELETE FROM geo_objects WHERE uuid = $1 AND map_uuid = $2 AND version = $3`, id, mapID, version)
	if err != nil {
		return fmt.Errorf("delete geo object: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrGeoObjectNotFound
	}
	return nil
}

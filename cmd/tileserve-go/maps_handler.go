package main

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/google/uuid"
)

// maxUploadSize caps the size of an uploaded map version archive.
const maxUploadSize = 1 << 30 // 1 GiB

// A map version's extracted contents may only consist of numerically named
// directories (e.g. a z/x/y tile pyramid) and numerically named .png files.
var (
	numericSegmentRE = regexp.MustCompile(`^[0-9]+$`)
	numericPNGRE     = regexp.MustCompile(`^[0-9]+\.png$`)
)

type mapRequest struct {
	Name             string `json:"name"`
	CurrentVersion   string `json:"currentVersion"`
	VisibleToAll     bool   `json:"visibleToAll"`
	AnonymousAllowed bool   `json:"anonymousAllowed"`
}

// writeJSON writes v as a JSON response body with the given HTTP status code.
func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// requireAuthenticated rejects a request with no bearer token. /maps/ is
// mounted behind optionalAuth (see main.go) so that a map's version file
// serving route can allow anonymous requests when that map opts in via
// anonymousAllowed; every other route under /maps/ calls this to restore
// the usual "must be logged in" requirement.
func requireAuthenticated(w http.ResponseWriter, r *http.Request) bool {
	if usernameFromContext(r.Context()) == "" {
		http.Error(w, "missing bearer token", http.StatusUnauthorized)
		return false
	}
	return true
}

// requirePermission checks the acting user's global permissions and writes an
// error response if the request should not proceed. It returns true when the
// caller may continue.
func requirePermission(w http.ResponseWriter, r *http.Request, store *Store, allowed func(Permissions) bool) bool {
	perms, err := store.GetPermissions(r.Context(), usernameFromContext(r.Context()))
	if err != nil {
		http.Error(w, "failed to check permissions", http.StatusInternalServerError)
		return false
	}
	if !allowed(perms) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return false
	}
	return true
}

// requireMapPermission checks whether the acting user may perform an action
// on a specific map: it passes if their global permissions allow it (admins
// always pass), or failing that, if they hold a matching per-map grant. A
// per-map grant only ever adds capability on top of the global flags, never
// removes it.
func requireMapPermission(w http.ResponseWriter, r *http.Request, store *Store, mapID uuid.UUID, globalAllowed func(Permissions) bool, mapAllowed func(MapPermission) bool) bool {
	username := usernameFromContext(r.Context())
	perms, err := store.GetPermissions(r.Context(), username)
	if err != nil {
		http.Error(w, "failed to check permissions", http.StatusInternalServerError)
		return false
	}
	if perms.IsAdmin || globalAllowed(perms) {
		return true
	}

	mp, err := store.GetMapPermission(r.Context(), mapID, username)
	if err != nil {
		http.Error(w, "failed to check permissions", http.StatusInternalServerError)
		return false
	}
	if !mapAllowed(mp) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return false
	}
	return true
}

// canViewMap reports whether username may see m. Maps are private by
// default: a user can see one because it's marked visible to everyone,
// because they created it, because they're an admin or already hold a
// global permission letting them modify any map (can_edit/can_delete —
// hiding a map from someone who can already act on it would be
// nonsensical), or because they hold a per-map grant (view, edit, or
// delete — any of the three implies visibility).
func canViewMap(ctx context.Context, store *Store, m MapRecord, username string) (bool, error) {
	if m.VisibleToAll || m.CreatedBy == username {
		return true, nil
	}

	perms, err := store.GetPermissions(ctx, username)
	if err != nil {
		return false, err
	}
	if perms.IsAdmin || perms.CanEdit || perms.CanDelete {
		return true, nil
	}

	mp, err := store.GetMapPermission(ctx, m.UUID, username)
	if err != nil {
		return false, err
	}
	return mp.CanView || mp.CanEdit || mp.CanDelete, nil
}

// requireMapView checks canViewMap and writes a 403 if it fails. It returns
// true when the caller may continue.
func requireMapView(w http.ResponseWriter, r *http.Request, store *Store, m MapRecord) bool {
	ok, err := canViewMap(r.Context(), store, m, usernameFromContext(r.Context()))
	if err != nil {
		http.Error(w, "failed to check permissions", http.StatusInternalServerError)
		return false
	}
	if !ok {
		http.Error(w, "forbidden", http.StatusForbidden)
		return false
	}
	return true
}

// getViewableMap fetches id and checks the acting user may view it, writing
// the appropriate error response (404/403/500) if not. ok is false when the
// caller should stop.
func getViewableMap(w http.ResponseWriter, r *http.Request, store *Store, id uuid.UUID) (m MapRecord, ok bool) {
	m, err := store.GetMap(r.Context(), id)
	switch {
	case errors.Is(err, ErrMapNotFound):
		http.Error(w, "map not found", http.StatusNotFound)
		return MapRecord{}, false
	case err != nil:
		http.Error(w, "failed to get map", http.StatusInternalServerError)
		return MapRecord{}, false
	}
	if !requireMapView(w, r, store, m) {
		return MapRecord{}, false
	}
	return m, true
}

// mapsCollectionHandler serves the /maps collection route: GET lists the
// maps visible to the caller, POST creates a new map (requires the
// can_create global permission).
func mapsCollectionHandler(store *Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			username := usernameFromContext(r.Context())
			perms, err := store.GetPermissions(r.Context(), username)
			if err != nil {
				http.Error(w, "failed to check permissions", http.StatusInternalServerError)
				return
			}
			bypassVisibility := perms.IsAdmin || perms.CanEdit || perms.CanDelete

			maps, err := store.ListMaps(r.Context(), username, bypassVisibility)
			if err != nil {
				http.Error(w, "failed to list maps", http.StatusInternalServerError)
				return
			}
			writeJSON(w, http.StatusOK, maps)

		case http.MethodPost:
			if !requirePermission(w, r, store, func(p Permissions) bool { return p.CanCreate }) {
				return
			}

			var req mapRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				http.Error(w, "invalid request body", http.StatusBadRequest)
				return
			}
			if req.Name == "" {
				http.Error(w, "name is required", http.StatusBadRequest)
				return
			}

			m, err := store.CreateMap(r.Context(), req.Name, req.CurrentVersion, req.VisibleToAll, req.AnonymousAllowed, usernameFromContext(r.Context()))
			if err != nil {
				http.Error(w, "failed to create map", http.StatusInternalServerError)
				return
			}
			writeJSON(w, http.StatusCreated, m)

		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	}
}

// mapsItemHandler dispatches every route nested under /maps/{id}/... by
// hand-parsing the path (the stdlib mux only matches the /maps/ prefix):
//
//   - /maps/{id}/version/{version}/...  (except .../bounds): serves the
//     extracted tile files for that version. The only route reachable
//     without a bearer token, when the map's anonymousAllowed is set.
//   - /maps/{id}/upload           (POST):   uploadMapVersionHandler
//   - /maps/{id}/versions         (GET):    mapVersionsHandler
//   - /maps/{id}/permissions[/{username}]:  mapPermissionsCollectionHandler /
//     mapPermissionItemHandler
//   - /maps/{id}/version/{version}/bounds (GET): mapVersionBoundsHandler
//   - /maps/{id}                  (GET/PUT/DELETE): fetch/update/delete the map itself
//
// Every route other than the version-file route requires a bearer token.
func mapsItemHandler(store *Store, dataRoot string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		path := strings.Trim(strings.TrimPrefix(r.URL.Path, "/maps/"), "/")
		segments := strings.Split(path, "/")

		id, err := uuid.Parse(segments[0])
		if err != nil {
			http.Error(w, "invalid map id", http.StatusBadRequest)
			return
		}

		// Version file serving (but not .../bounds, a distinct JSON
		// endpoint) is the one route that may be reached without a bearer
		// token at all, when the map itself opts in via anonymousAllowed.
		// It's handled before the blanket auth gate below so an anonymous
		// caller can reach it; every other route still requires a token.
		isVersionFile := len(segments) >= 3 && segments[1] == "version" &&
			(len(segments) != 4 || segments[3] != "bounds")
		if isVersionFile {
			m, err := store.GetMap(r.Context(), id)
			switch {
			case errors.Is(err, ErrMapNotFound):
				http.Error(w, "map not found", http.StatusNotFound)
				return
			case err != nil:
				http.Error(w, "failed to get map", http.StatusInternalServerError)
				return
			}
			if !m.AnonymousAllowed {
				if !requireAuthenticated(w, r) || !requireMapView(w, r, store, m) {
					return
				}
			}

			version := segments[2]
			versionDir := filepath.Join(dataRoot, id.String(), version)
			prefix := "/maps/" + strings.Join(segments[:3], "/") + "/"
			http.StripPrefix(prefix, http.FileServer(http.Dir(versionDir))).ServeHTTP(w, r)
			return
		}

		if !requireAuthenticated(w, r) {
			return
		}

		if len(segments) == 2 && segments[1] == "upload" {
			uploadMapVersionHandler(store, dataRoot, id)(w, r)
			return
		}
		if len(segments) == 2 && segments[1] == "versions" {
			if _, ok := getViewableMap(w, r, store, id); ok {
				mapVersionsHandler(store, id)(w, r)
			}
			return
		}
		if len(segments) == 2 && segments[1] == "permissions" {
			mapPermissionsCollectionHandler(store, id)(w, r)
			return
		}
		if len(segments) == 3 && segments[1] == "permissions" {
			mapPermissionItemHandler(store, id, segments[2])(w, r)
			return
		}
		if len(segments) == 4 && segments[1] == "version" && segments[3] == "bounds" {
			if _, ok := getViewableMap(w, r, store, id); ok {
				mapVersionBoundsHandler(dataRoot, id, segments[2])(w, r)
			}
			return
		}
		if len(segments) != 1 {
			http.NotFound(w, r)
			return
		}

		switch r.Method {
		case http.MethodGet:
			m, ok := getViewableMap(w, r, store, id)
			if ok {
				writeJSON(w, http.StatusOK, m)
			}

		case http.MethodPut:
			if !requireMapPermission(w, r, store, id,
				func(p Permissions) bool { return p.CanEdit },
				func(mp MapPermission) bool { return mp.CanEdit },
			) {
				return
			}

			var req mapRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				http.Error(w, "invalid request body", http.StatusBadRequest)
				return
			}
			if req.Name == "" {
				http.Error(w, "name is required", http.StatusBadRequest)
				return
			}

			m, err := store.UpdateMap(r.Context(), id, req.Name, req.CurrentVersion, req.VisibleToAll, req.AnonymousAllowed, usernameFromContext(r.Context()))
			switch {
			case errors.Is(err, ErrMapNotFound):
				http.Error(w, "map not found", http.StatusNotFound)
			case err != nil:
				http.Error(w, "failed to update map", http.StatusInternalServerError)
			default:
				writeJSON(w, http.StatusOK, m)
			}

		case http.MethodDelete:
			if !requireMapPermission(w, r, store, id,
				func(p Permissions) bool { return p.CanDelete },
				func(mp MapPermission) bool { return mp.CanDelete },
			) {
				return
			}

			err := store.DeleteMap(r.Context(), id)
			switch {
			case errors.Is(err, ErrMapNotFound):
				http.Error(w, "map not found", http.StatusNotFound)
			case err != nil:
				http.Error(w, "failed to delete map", http.StatusInternalServerError)
			default:
				w.WriteHeader(http.StatusNoContent)
			}

		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	}
}

// mapVersionsHandler returns the upload history for a map.
func mapVersionsHandler(store *Store, id uuid.UUID) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		versions, err := store.ListMapVersions(r.Context(), id)
		switch {
		case errors.Is(err, ErrMapNotFound):
			http.Error(w, "map not found", http.StatusNotFound)
		case err != nil:
			http.Error(w, "failed to list map versions", http.StatusInternalServerError)
		default:
			writeJSON(w, http.StatusOK, versions)
		}
	}
}

type mapPermissionRequest struct {
	CanView   bool `json:"canView"`
	CanEdit   bool `json:"canEdit"`
	CanDelete bool `json:"canDelete"`
}

// mapPermissionsCollectionHandler lists a map's per-user permission grants.
// Managing per-map permissions is admin-only, same as the global Users API.
func mapPermissionsCollectionHandler(store *Store, id uuid.UUID) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !requireAdmin(w, r, store) {
			return
		}
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		perms, err := store.ListMapPermissions(r.Context(), id)
		if err != nil {
			http.Error(w, "failed to list map permissions", http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, perms)
	}
}

// mapPermissionItemHandler grants or revokes a single user's per-map
// permission. Managing per-map permissions is admin-only, same as the global
// Users API.
func mapPermissionItemHandler(store *Store, id uuid.UUID, username string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !requireAdmin(w, r, store) {
			return
		}

		switch r.Method {
		case http.MethodPut:
			var req mapPermissionRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				http.Error(w, "invalid request body", http.StatusBadRequest)
				return
			}

			p, err := store.SetMapPermission(r.Context(), id, username, req.CanView, req.CanEdit, req.CanDelete, usernameFromContext(r.Context()))
			switch {
			case errors.Is(err, ErrMapPermissionInvalid):
				http.Error(w, "map or username does not exist", http.StatusBadRequest)
			case err != nil:
				http.Error(w, "failed to set map permission", http.StatusInternalServerError)
			default:
				writeJSON(w, http.StatusOK, p)
			}

		case http.MethodDelete:
			if err := store.DeleteMapPermission(r.Context(), id, username); err != nil {
				http.Error(w, "failed to delete map permission", http.StatusInternalServerError)
				return
			}
			w.WriteHeader(http.StatusNoContent)

		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	}
}

// tileBounds describes the real-world extent of a version's tile pyramid,
// derived by scanning the extracted z/x/y.png files on disk rather than any
// stored metadata (none is kept). CenterLng/CenterLat and MinZoom are meant
// to be used directly as a map preview's initial view: MinZoom is guaranteed
// to be a zoom level that actually has tiles, unlike an arbitrary computed
// zoom that might fall between levels.
type tileBounds struct {
	MinZoom   int     `json:"minZoom"`
	MaxZoom   int     `json:"maxZoom"`
	West      float64 `json:"west"`
	South     float64 `json:"south"`
	East      float64 `json:"east"`
	North     float64 `json:"north"`
	CenterLng float64 `json:"centerLng"`
	CenterLat float64 `json:"centerLat"`
}

// mapVersionBoundsHandler computes the tile extent of a map version for use
// as a preview map's initial view.
func mapVersionBoundsHandler(dataRoot string, id uuid.UUID, version string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if !numericSegmentRE.MatchString(version) {
			http.Error(w, "invalid version", http.StatusBadRequest)
			return
		}

		versionDir := filepath.Join(dataRoot, id.String(), version)
		bounds, err := computeTileBounds(versionDir)
		switch {
		case errors.Is(err, errNoTiles):
			http.Error(w, "no tiles found for this version", http.StatusNotFound)
		case err != nil:
			http.Error(w, "failed to compute bounds", http.StatusInternalServerError)
		default:
			writeJSON(w, http.StatusOK, bounds)
		}
	}
}

var errNoTiles = errors.New("no tiles found")

// computeTileBounds scans versionDir's zoom directories (top-level, numeric)
// to find the min and max zoom present, then unions the x/y extent of every
// tile at the minimum zoom into a lon/lat bounding box. The minimum zoom is
// used (rather than the maximum) because a tile pyramid's lower zoom levels
// still cover the same real-world area with fewer, coarser tiles, making
// that level's tile extent the cheapest accurate stand-in for the whole
// pyramid's coverage.
func computeTileBounds(versionDir string) (*tileBounds, error) {
	entries, err := os.ReadDir(versionDir)
	if errors.Is(err, os.ErrNotExist) {
		return nil, errNoTiles
	}
	if err != nil {
		return nil, fmt.Errorf("read version dir: %w", err)
	}

	var zooms []int
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		z, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		zooms = append(zooms, z)
	}
	if len(zooms) == 0 {
		return nil, errNoTiles
	}
	sort.Ints(zooms)
	minZoom, maxZoom := zooms[0], zooms[len(zooms)-1]

	minX, minY, maxX, maxY, err := tileExtentAtZoom(versionDir, minZoom)
	if err != nil {
		return nil, err
	}

	west, north := tileToLonLat(minX, minY, minZoom)
	east, south := tileToLonLat(maxX+1, maxY+1, minZoom)

	return &tileBounds{
		MinZoom:   minZoom,
		MaxZoom:   maxZoom,
		West:      west,
		South:     south,
		East:      east,
		North:     north,
		CenterLng: (west + east) / 2,
		CenterLat: (south + north) / 2,
	}, nil
}

// tileExtentAtZoom returns the min/max x and y tile coordinates found under
// versionDir/<z>/.
func tileExtentAtZoom(versionDir string, z int) (minX, minY, maxX, maxY int, err error) {
	zoomDir := filepath.Join(versionDir, strconv.Itoa(z))
	xEntries, err := os.ReadDir(zoomDir)
	if err != nil {
		return 0, 0, 0, 0, fmt.Errorf("read zoom dir: %w", err)
	}

	found := false
	for _, xe := range xEntries {
		if !xe.IsDir() {
			continue
		}
		x, err := strconv.Atoi(xe.Name())
		if err != nil {
			continue
		}

		yEntries, err := os.ReadDir(filepath.Join(zoomDir, xe.Name()))
		if err != nil {
			continue
		}
		for _, ye := range yEntries {
			y, err := strconv.Atoi(strings.TrimSuffix(ye.Name(), ".png"))
			if err != nil || !strings.HasSuffix(ye.Name(), ".png") {
				continue
			}
			if !found {
				minX, maxX, minY, maxY = x, x, y, y
				found = true
				continue
			}
			minX, maxX = min(minX, x), max(maxX, x)
			minY, maxY = min(minY, y), max(maxY, y)
		}
	}
	if !found {
		return 0, 0, 0, 0, errNoTiles
	}
	return minX, minY, maxX, maxY, nil
}

// tileToLonLat returns the lon/lat of a tile coordinate's top-left (north-west) corner.
func tileToLonLat(x, y, z int) (lon, lat float64) {
	n := math.Pow(2, float64(z))
	lon = float64(x)/n*360.0 - 180.0
	latRad := math.Atan(math.Sinh(math.Pi * (1 - 2*float64(y)/n)))
	lat = latRad * 180.0 / math.Pi
	return lon, lat
}

// uploadMapVersionHandler accepts a zip or tar (optionally gzip-compressed)
// archive as the raw request body, extracts it, and atomically bumps the
// map's current_version. Extraction happens into a staging directory next to
// the map's final location first; the DB version is only reserved (and the
// directory put in place) once extraction fully succeeds, so a bad upload
// never leaves the map pointing at a broken version.
func uploadMapVersionHandler(store *Store, dataRoot string, id uuid.UUID) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		if !requireMapPermission(w, r, store, id,
			func(p Permissions) bool { return p.CanCreate },
			func(mp MapPermission) bool { return mp.CanEdit },
		) {
			return
		}

		r.Body = http.MaxBytesReader(w, r.Body, maxUploadSize)

		tmpFile, err := os.CreateTemp("", "tileserve-upload-*")
		if err != nil {
			http.Error(w, "failed to buffer upload", http.StatusInternalServerError)
			return
		}
		defer func() { _ = os.Remove(tmpFile.Name()) }()
		defer func() { _ = tmpFile.Close() }()

		if _, err := io.Copy(tmpFile, r.Body); err != nil {
			var maxBytesErr *http.MaxBytesError
			if errors.As(err, &maxBytesErr) {
				http.Error(w, "upload too large", http.StatusRequestEntityTooLarge)
				return
			}
			http.Error(w, "failed to read upload", http.StatusBadRequest)
			return
		}
		if err := tmpFile.Close(); err != nil {
			http.Error(w, "failed to buffer upload", http.StatusInternalServerError)
			return
		}

		format, err := sniffArchiveFormat(tmpFile.Name())
		if err != nil {
			http.Error(w, "failed to inspect upload", http.StatusInternalServerError)
			return
		}
		if format == archiveUnknown {
			http.Error(w, "unsupported archive format: must be zip or tar", http.StatusBadRequest)
			return
		}

		mapDir := filepath.Join(dataRoot, id.String())
		if err := os.MkdirAll(mapDir, 0o755); err != nil {
			http.Error(w, "failed to prepare storage", http.StatusInternalServerError)
			return
		}

		// Staged inside mapDir (not os.TempDir) so the final rename below is
		// guaranteed to be same-filesystem and therefore atomic.
		stagingDir, err := os.MkdirTemp(mapDir, ".upload-*")
		if err != nil {
			http.Error(w, "failed to prepare extraction", http.StatusInternalServerError)
			return
		}
		defer func() { _ = os.RemoveAll(stagingDir) }()

		switch format {
		case archiveZip:
			err = extractZip(tmpFile.Name(), stagingDir)
		case archiveTarGz:
			err = extractTar(tmpFile.Name(), stagingDir, true)
		case archiveTar:
			err = extractTar(tmpFile.Name(), stagingDir, false)
		}
		if err != nil {
			http.Error(w, "invalid archive file: "+err.Error(), http.StatusBadRequest)
			return
		}

		m, err := store.IncrementMapVersion(r.Context(), id, usernameFromContext(r.Context()))
		switch {
		case errors.Is(err, ErrMapNotFound):
			http.Error(w, "map not found", http.StatusNotFound)
			return
		case err != nil:
			http.Error(w, "failed to record new version", http.StatusInternalServerError)
			return
		}

		destDir := filepath.Join(mapDir, m.CurrentVersion)
		if err := os.Rename(stagingDir, destDir); err != nil {
			http.Error(w, "failed to store version", http.StatusInternalServerError)
			return
		}

		writeJSON(w, http.StatusCreated, m)
	}
}

// archiveFormat identifies which extractor an uploaded archive needs.
type archiveFormat int

const (
	archiveUnknown archiveFormat = iota
	archiveZip
	archiveTarGz
	archiveTar
)

var (
	zipMagic      = []byte("PK\x03\x04")
	zipEmptyMagic = []byte("PK\x05\x06")
	gzipMagic     = []byte{0x1f, 0x8b}
	tarMagic      = []byte("ustar")
)

// sniffArchiveFormat inspects path's leading bytes to determine which
// extractor to use, rather than trusting the client-supplied filename or
// Content-Type (the server never reads either). zip and gzip both have
// unambiguous magic numbers at the start of the file; a plain (uncompressed)
// tar has no magic at offset 0, but the ustar format's magic string at byte
// offset 257 is a reliable-enough signal in practice.
func sniffArchiveFormat(path string) (archiveFormat, error) {
	f, err := os.Open(path)
	if err != nil {
		return archiveUnknown, fmt.Errorf("open upload: %w", err)
	}
	defer func() { _ = f.Close() }()

	header := make([]byte, 262)
	n, err := io.ReadFull(f, header)
	if err != nil && !errors.Is(err, io.ErrUnexpectedEOF) && !errors.Is(err, io.EOF) {
		return archiveUnknown, fmt.Errorf("read upload: %w", err)
	}
	header = header[:n]

	switch {
	case bytes.HasPrefix(header, zipMagic), bytes.HasPrefix(header, zipEmptyMagic):
		return archiveZip, nil
	case bytes.HasPrefix(header, gzipMagic):
		return archiveTarGz, nil
	case len(header) >= 262 && bytes.Equal(header[257:262], tarMagic):
		return archiveTar, nil
	default:
		return archiveUnknown, nil
	}
}

// extractTar extracts the tar archive at tarPath into destDir, transparently
// gunzipping first when gzipped is true. It applies the same zip-slip,
// symlink, and entry-name validation as extractZip, and likewise only
// returns an error for an unreadable archive or an actual filesystem
// failure while writing — invalid entries are skipped, not fatal.
func extractTar(tarPath, destDir string, gzipped bool) error {
	f, err := os.Open(tarPath)
	if err != nil {
		return fmt.Errorf("open tar: %w", err)
	}
	defer func() { _ = f.Close() }()

	var r io.Reader = f
	if gzipped {
		gr, err := gzip.NewReader(f)
		if err != nil {
			return fmt.Errorf("open gzip: %w", err)
		}
		defer func() { _ = gr.Close() }()
		r = gr
	}

	cleanDest := filepath.Clean(destDir)
	tr := tar.NewReader(r)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return fmt.Errorf("read tar: %w", err)
		}

		if hdr.Typeflag == tar.TypeSymlink || hdr.Typeflag == tar.TypeLink {
			log.Printf("upload: skipping symlink entry %q", hdr.Name)
			continue
		}

		isDir := hdr.Typeflag == tar.TypeDir
		name := hdr.Name
		if isDir && !strings.HasSuffix(name, "/") {
			name += "/"
		}
		if err := validateExtractedEntryName(name); err != nil {
			log.Printf("upload: skipping entry: %v", err)
			continue
		}

		targetPath := filepath.Join(cleanDest, strings.Trim(name, "/"))
		if targetPath != cleanDest && !strings.HasPrefix(targetPath, cleanDest+string(os.PathSeparator)) {
			log.Printf("upload: skipping entry with illegal path %q", hdr.Name)
			continue
		}

		if isDir {
			if err := os.MkdirAll(targetPath, 0o755); err != nil {
				return fmt.Errorf("create dir %s: %w", targetPath, err)
			}
			continue
		}
		if hdr.Typeflag != tar.TypeReg {
			log.Printf("upload: skipping non-regular entry %q", hdr.Name)
			continue
		}

		if err := os.MkdirAll(filepath.Dir(targetPath), 0o755); err != nil {
			return fmt.Errorf("create dir for %s: %w", targetPath, err)
		}
		if err := writeExtractedFile(tr, targetPath); err != nil {
			return err
		}
	}
	return nil
}

// extractZip extracts the zip file at zipPath into destDir. Entries that
// would escape destDir (zip-slip), that are symlinks, or whose name doesn't
// match the required numeric-directories/numeric-png-files layout are
// skipped rather than failing the whole upload. It only returns an error for
// an unreadable zip or an actual filesystem failure while writing.
func extractZip(zipPath, destDir string) error {
	zr, err := zip.OpenReader(zipPath)
	if err != nil {
		return fmt.Errorf("open zip: %w", err)
	}
	defer func() { _ = zr.Close() }()

	cleanDest := filepath.Clean(destDir)
	for _, f := range zr.File {
		if f.Mode()&os.ModeSymlink != 0 {
			log.Printf("upload: skipping symlink entry %q", f.Name)
			continue
		}
		if err := validateExtractedEntryName(f.Name); err != nil {
			log.Printf("upload: skipping entry: %v", err)
			continue
		}

		targetPath := filepath.Join(cleanDest, f.Name)
		if targetPath != cleanDest && !strings.HasPrefix(targetPath, cleanDest+string(os.PathSeparator)) {
			log.Printf("upload: skipping entry with illegal path %q", f.Name)
			continue
		}

		if f.FileInfo().IsDir() {
			if err := os.MkdirAll(targetPath, 0o755); err != nil {
				return fmt.Errorf("create dir %s: %w", targetPath, err)
			}
			continue
		}

		if err := os.MkdirAll(filepath.Dir(targetPath), 0o755); err != nil {
			return fmt.Errorf("create dir for %s: %w", targetPath, err)
		}
		if err := extractZipFile(f, targetPath); err != nil {
			return err
		}
	}
	return nil
}

// validateExtractedEntryName checks that a zip entry's path consists only of
// numeric directory segments, ending in either a numeric directory or a
// numeric ".png" file (e.g. "3/1/2.png"). name is the raw zip entry name,
// which uses "/" separators and a trailing "/" to mark directories.
func validateExtractedEntryName(name string) error {
	isDir := strings.HasSuffix(name, "/")
	segments := strings.Split(strings.Trim(name, "/"), "/")
	if len(segments) == 0 || segments[0] == "" {
		return fmt.Errorf("invalid entry name: %q", name)
	}

	dirSegments := segments
	if !isDir {
		dirSegments = segments[:len(segments)-1]
	}
	for _, seg := range dirSegments {
		if !numericSegmentRE.MatchString(seg) {
			return fmt.Errorf("invalid directory %q in %q: directory names must contain only digits", seg, name)
		}
	}

	if !isDir {
		last := segments[len(segments)-1]
		if !numericPNGRE.MatchString(last) {
			return fmt.Errorf("invalid file %q in %q: files must be named <number>.png", last, name)
		}
	}
	return nil
}

// extractZipFile copies a single zip entry's contents to targetPath,
// overwriting it if it already exists.
func extractZipFile(f *zip.File, targetPath string) error {
	rc, err := f.Open()
	if err != nil {
		return fmt.Errorf("open zip entry %s: %w", f.Name, err)
	}
	defer func() { _ = rc.Close() }()
	return writeExtractedFile(rc, targetPath)
}

// writeExtractedFile copies r's contents to targetPath, overwriting it if it
// already exists. Shared by the zip and tar extractors.
func writeExtractedFile(r io.Reader, targetPath string) error {
	out, err := os.OpenFile(targetPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		return fmt.Errorf("create file %s: %w", targetPath, err)
	}
	defer func() { _ = out.Close() }()

	if _, err := io.Copy(out, r); err != nil {
		return fmt.Errorf("write file %s: %w", targetPath, err)
	}
	if err := out.Close(); err != nil {
		return fmt.Errorf("close file %s: %w", targetPath, err)
	}
	return nil
}

package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/google/uuid"
)

// numericSegmentRE matches a purely numeric path segment. It's shared by
// mapVersionBoundsHandler below (validating a version path segment) and
// validateExtractedEntryName in upload.go (validating a z/x/y tile pyramid
// entry's directory segments during archive extraction).
var numericSegmentRE = regexp.MustCompile(`^[0-9]+$`)

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

package handler

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/google/uuid"

	"nilswitt.dev/tileserve-go/internal/store"
)

// numericSegmentRE matches a purely numeric path segment. It's shared by
// mapVersionBoundsHandler below (validating a version path segment) and
// validateExtractedEntryName in upload.go (validating a z/x/y tile pyramid
// entry's directory segments during archive extraction).
var numericSegmentRE = regexp.MustCompile(`^[0-9]+$`)

// mapDir returns a map's storage directory under dataRoot.
func mapDir(dataRoot string, id uuid.UUID) string {
	return filepath.Join(dataRoot, id.String())
}

// mapVersionDir returns a specific version's extracted-tiles directory under dataRoot.
func mapVersionDir(dataRoot string, id uuid.UUID, version string) string {
	return filepath.Join(mapDir(dataRoot, id), version)
}

// isVersionSubResourcePath reports whether segments (the /maps/{id}/...
// path, split on "/") addresses one of the JSON sub-resources nested under a
// map version — .../version/{version}/bounds or
// .../version/{version}/geo-objects[/{uuid}] — rather than a raw extracted
// tile file. Reserving these path segments is safe: uploaded tile entries
// are validated at extraction time to be purely numeric directories or
// <number>.png files, so a real extracted path can never start with
// "bounds" or "geo-objects".
func isVersionSubResourcePath(segments []string) bool {
	return len(segments) >= 4 && segments[1] == "version" &&
		(segments[3] == "bounds" || segments[3] == "geo-objects")
}

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

// decodeJSON decodes r's body as JSON into v, writing a 400 response and
// returning false if the body isn't valid JSON.
func decodeJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	if err := json.NewDecoder(r.Body).Decode(v); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return false
	}
	return true
}

// writeStoreError maps a Store error to an HTTP response: sentinel maps to
// sentinelStatus with sentinelMsg (e.g. a not-found or validation error),
// any other non-nil error maps to a 500 with failMsg.
func writeStoreError(w http.ResponseWriter, err error, sentinel error, sentinelStatus int, sentinelMsg, failMsg string) {
	if errors.Is(err, sentinel) {
		http.Error(w, sentinelMsg, sentinelStatus)
		return
	}
	http.Error(w, failMsg, http.StatusInternalServerError)
}

// requireMethod rejects a request whose method isn't method with a 405. It
// returns true when the caller may continue.
func requireMethod(w http.ResponseWriter, r *http.Request, method string) bool {
	if r.Method != method {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return false
	}
	return true
}

// getPermissionsOrFail fetches the acting user's global permissions, writing
// a 500 response and returning ok=false if that fails.
func getPermissionsOrFail(w http.ResponseWriter, r *http.Request, st *store.Store) (perms store.Permissions, ok bool) {
	perms, err := st.GetPermissions(r.Context(), usernameFromContext(r.Context()))
	if err != nil {
		http.Error(w, "failed to check permissions", http.StatusInternalServerError)
		return store.Permissions{}, false
	}
	return perms, true
}

// requireAuthenticated rejects a request with no bearer token. /maps/ is
// mounted behind OptionalAuth (see cmd/tileserve-go/main.go) so that a
// map's version file serving route can allow anonymous requests when that
// map opts in via anonymousAllowed; every other route under /maps/ calls
// this to restore the usual "must be logged in" requirement.
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
func requirePermission(w http.ResponseWriter, r *http.Request, st *store.Store, allowed func(store.Permissions) bool) bool {
	perms, ok := getPermissionsOrFail(w, r, st)
	if !ok {
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
func requireMapPermission(w http.ResponseWriter, r *http.Request, st *store.Store, mapID uuid.UUID, globalAllowed func(store.Permissions) bool, mapAllowed func(store.MapPermission) bool) bool {
	username := usernameFromContext(r.Context())
	perms, ok := getPermissionsOrFail(w, r, st)
	if !ok {
		return false
	}
	if perms.IsAdmin || globalAllowed(perms) {
		return true
	}

	mp, err := st.GetMapPermission(r.Context(), mapID, username)
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
func canViewMap(ctx context.Context, st *store.Store, m store.MapRecord, username string) (bool, error) {
	if m.VisibleToAll || m.CreatedBy == username {
		return true, nil
	}

	perms, err := st.GetPermissions(ctx, username)
	if err != nil {
		return false, err
	}
	if perms.IsAdmin || perms.CanEdit || perms.CanDelete {
		return true, nil
	}

	mp, err := st.GetMapPermission(ctx, m.UUID, username)
	if err != nil {
		return false, err
	}
	return mp.CanView || mp.CanEdit || mp.CanDelete, nil
}

// requireMapView checks canViewMap and writes a 403 if it fails. It returns
// true when the caller may continue.
func requireMapView(w http.ResponseWriter, r *http.Request, st *store.Store, m store.MapRecord) bool {
	ok, err := canViewMap(r.Context(), st, m, usernameFromContext(r.Context()))
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
func getViewableMap(w http.ResponseWriter, r *http.Request, st *store.Store, id uuid.UUID) (m store.MapRecord, ok bool) {
	m, err := st.GetMap(r.Context(), id)
	if err != nil {
		writeStoreError(w, err, store.ErrMapNotFound, http.StatusNotFound, "map not found", "failed to get map")
		return store.MapRecord{}, false
	}
	if !requireMapView(w, r, st, m) {
		return store.MapRecord{}, false
	}
	return m, true
}

// MapsCollectionHandler serves the /maps collection route: GET lists the
// maps visible to the caller, POST creates a new map (requires the
// can_create global permission).
func MapsCollectionHandler(st *store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			username := usernameFromContext(r.Context())
			perms, ok := getPermissionsOrFail(w, r, st)
			if !ok {
				return
			}
			bypassVisibility := perms.IsAdmin || perms.CanEdit || perms.CanDelete

			maps, err := st.ListMaps(r.Context(), username, bypassVisibility)
			if err != nil {
				http.Error(w, "failed to list maps", http.StatusInternalServerError)
				return
			}
			writeJSON(w, http.StatusOK, maps)

		case http.MethodPost:
			if !requirePermission(w, r, st, func(p store.Permissions) bool { return p.CanCreate }) {
				return
			}

			var req mapRequest
			if !decodeJSON(w, r, &req) {
				return
			}
			if req.Name == "" {
				http.Error(w, "name is required", http.StatusBadRequest)
				return
			}

			m, err := st.CreateMap(r.Context(), req.Name, req.CurrentVersion, req.VisibleToAll, req.AnonymousAllowed, usernameFromContext(r.Context()))
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

// MapsItemHandler dispatches every route nested under /maps/{id}/... by
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
//   - /maps/{id}/version/{version}/geo-objects[/{uuid}]:  geoObjectsCollectionHandler /
//     geoObjectItemHandler
//   - /maps/{id}                  (GET/PUT/DELETE): fetch/update/delete the map itself
//
// Every route other than the version-file route requires a bearer token.
func MapsItemHandler(st *store.Store, dataRoot string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		path := strings.Trim(strings.TrimPrefix(r.URL.Path, "/maps/"), "/")
		segments := strings.Split(path, "/")

		id, err := uuid.Parse(segments[0])
		if err != nil {
			http.Error(w, "invalid map id", http.StatusBadRequest)
			return
		}

		// Version file serving (but not a JSON sub-resource like .../bounds
		// or .../geo-objects[/...], see isVersionSubResourcePath) is the one
		// route that may be reached without a bearer token at all, when the
		// map itself opts in via anonymousAllowed. It's handled before the
		// blanket auth gate below so an anonymous caller can reach it; every
		// other route still requires a token.
		isVersionFile := len(segments) >= 3 && segments[1] == "version" && !isVersionSubResourcePath(segments)
		if isVersionFile {
			m, err := st.GetMap(r.Context(), id)
			if err != nil {
				writeStoreError(w, err, store.ErrMapNotFound, http.StatusNotFound, "map not found", "failed to get map")
				return
			}
			if !m.AnonymousAllowed {
				if !requireAuthenticated(w, r) || !requireMapView(w, r, st, m) {
					return
				}
			}

			version := segments[2]
			versionDir := mapVersionDir(dataRoot, id, version)
			prefix := "/maps/" + strings.Join(segments[:3], "/") + "/"
			http.StripPrefix(prefix, http.FileServer(http.Dir(versionDir))).ServeHTTP(w, r)
			return
		}

		if !requireAuthenticated(w, r) {
			return
		}

		if len(segments) == 2 && segments[1] == "upload" {
			uploadMapVersionHandler(st, dataRoot, id)(w, r)
			return
		}
		if len(segments) == 2 && segments[1] == "versions" {
			if _, ok := getViewableMap(w, r, st, id); ok {
				mapVersionsHandler(st, id)(w, r)
			}
			return
		}
		if len(segments) == 2 && segments[1] == "permissions" {
			mapPermissionsCollectionHandler(st, id)(w, r)
			return
		}
		if len(segments) == 3 && segments[1] == "permissions" {
			mapPermissionItemHandler(st, id, segments[2])(w, r)
			return
		}
		if len(segments) == 4 && segments[1] == "version" && segments[3] == "bounds" {
			if _, ok := getViewableMap(w, r, st, id); ok {
				mapVersionBoundsHandler(dataRoot, id, segments[2])(w, r)
			}
			return
		}
		if len(segments) == 4 && segments[1] == "version" && segments[3] == "geo-objects" {
			geoObjectsCollectionHandler(st, id, segments[2])(w, r)
			return
		}
		if len(segments) == 5 && segments[1] == "version" && segments[3] == "geo-objects" {
			geoObjID, err := uuid.Parse(segments[4])
			if err != nil {
				http.Error(w, "invalid geo object id", http.StatusBadRequest)
				return
			}
			geoObjectItemHandler(st, id, segments[2], geoObjID)(w, r)
			return
		}
		if len(segments) != 1 {
			http.NotFound(w, r)
			return
		}

		switch r.Method {
		case http.MethodGet:
			m, ok := getViewableMap(w, r, st, id)
			if ok {
				writeJSON(w, http.StatusOK, m)
			}

		case http.MethodPut:
			if !requireMapPermission(w, r, st, id,
				func(p store.Permissions) bool { return p.CanEdit },
				func(mp store.MapPermission) bool { return mp.CanEdit },
			) {
				return
			}

			var req mapRequest
			if !decodeJSON(w, r, &req) {
				return
			}
			if req.Name == "" {
				http.Error(w, "name is required", http.StatusBadRequest)
				return
			}

			m, err := st.UpdateMap(r.Context(), id, req.Name, req.CurrentVersion, req.VisibleToAll, req.AnonymousAllowed, usernameFromContext(r.Context()))
			if err != nil {
				writeStoreError(w, err, store.ErrMapNotFound, http.StatusNotFound, "map not found", "failed to update map")
				return
			}
			writeJSON(w, http.StatusOK, m)

		case http.MethodDelete:
			if !requireMapPermission(w, r, st, id,
				func(p store.Permissions) bool { return p.CanDelete },
				func(mp store.MapPermission) bool { return mp.CanDelete },
			) {
				return
			}

			if err := st.DeleteMap(r.Context(), id); err != nil {
				writeStoreError(w, err, store.ErrMapNotFound, http.StatusNotFound, "map not found", "failed to delete map")
				return
			}
			w.WriteHeader(http.StatusNoContent)

		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	}
}

// mapVersionsHandler returns the upload history for a map.
func mapVersionsHandler(st *store.Store, id uuid.UUID) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !requireMethod(w, r, http.MethodGet) {
			return
		}

		versions, err := st.ListMapVersions(r.Context(), id)
		if err != nil {
			writeStoreError(w, err, store.ErrMapNotFound, http.StatusNotFound, "map not found", "failed to list map versions")
			return
		}
		writeJSON(w, http.StatusOK, versions)
	}
}

type mapPermissionRequest struct {
	CanView   bool `json:"canView"`
	CanEdit   bool `json:"canEdit"`
	CanDelete bool `json:"canDelete"`
}

// mapPermissionsCollectionHandler lists a map's per-user permission grants.
// Managing per-map permissions is admin-only, same as the global Users API.
func mapPermissionsCollectionHandler(st *store.Store, id uuid.UUID) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !requireAdmin(w, r, st) {
			return
		}
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		perms, err := st.ListMapPermissions(r.Context(), id)
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
func mapPermissionItemHandler(st *store.Store, id uuid.UUID, username string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !requireAdmin(w, r, st) {
			return
		}

		switch r.Method {
		case http.MethodPut:
			var req mapPermissionRequest
			if !decodeJSON(w, r, &req) {
				return
			}

			p, err := st.SetMapPermission(r.Context(), id, username, req.CanView, req.CanEdit, req.CanDelete, usernameFromContext(r.Context()))
			if err != nil {
				writeStoreError(w, err, store.ErrMapPermissionInvalid, http.StatusBadRequest, "map or username does not exist", "failed to set map permission")
				return
			}
			writeJSON(w, http.StatusOK, p)

		case http.MethodDelete:
			if err := st.DeleteMapPermission(r.Context(), id, username); err != nil {
				http.Error(w, "failed to delete map permission", http.StatusInternalServerError)
				return
			}
			w.WriteHeader(http.StatusNoContent)

		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	}
}

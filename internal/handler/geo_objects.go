package handler

import (
	"net/http"

	"github.com/google/uuid"

	"nilswitt.dev/tileserve-go/internal/store"
)

type geoObjectRequest struct {
	Name        string   `json:"name"`
	ExternalID  string   `json:"externalId"`
	Latitude    *float64 `json:"latitude"`
	Longitude   *float64 `json:"longitude"`
	Street      string   `json:"street"`
	HouseNumber string   `json:"housenumber"`
	Postcode    string   `json:"postcode"`
}

// decodeGeoObjectRequest decodes and validates req's body, writing a 400
// response and returning ok=false if the name is empty or latitude/longitude
// are missing. Latitude/longitude are pointers specifically so an omitted
// value (nil) can be distinguished from an explicit 0.0 (a valid coordinate).
func decodeGeoObjectRequest(w http.ResponseWriter, r *http.Request) (req geoObjectRequest, ok bool) {
	if !decodeJSON(w, r, &req) {
		return geoObjectRequest{}, false
	}
	if req.Name == "" {
		http.Error(w, "name is required", http.StatusBadRequest)
		return geoObjectRequest{}, false
	}
	if req.Latitude == nil || req.Longitude == nil {
		http.Error(w, "latitude and longitude are required", http.StatusBadRequest)
		return geoObjectRequest{}, false
	}
	return req, true
}

// geoObjectsCollectionHandler serves the /maps/{id}/version/{version}/geo-objects
// collection route: GET lists the geo objects tied to this map version
// (requires view access to the map), POST creates a new one (requires the
// can_edit permission, global or per-map — implies view access, so no
// separate check is needed).
func geoObjectsCollectionHandler(st *store.Store, mapID uuid.UUID, version string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			if _, ok := getViewableMap(w, r, st, mapID); !ok {
				return
			}

			objs, err := st.ListGeoObjects(r.Context(), mapID, version)
			if err != nil {
				http.Error(w, "failed to list geo objects", http.StatusInternalServerError)
				return
			}
			writeJSON(w, http.StatusOK, objs)

		case http.MethodPost:
			if !requireMapPermission(w, r, st, mapID,
				func(p store.Permissions) bool { return p.CanEdit },
				func(mp store.MapPermission) bool { return mp.CanEdit },
			) {
				return
			}

			req, ok := decodeGeoObjectRequest(w, r)
			if !ok {
				return
			}

			g, err := st.CreateGeoObject(r.Context(), mapID, version, req.Name, req.ExternalID, *req.Latitude, *req.Longitude, req.Street, req.HouseNumber, req.Postcode, usernameFromContext(r.Context()))
			if err != nil {
				writeStoreError(w, err, store.ErrGeoObjectInvalid, http.StatusBadRequest, "map or version does not exist", "failed to create geo object")
				return
			}
			writeJSON(w, http.StatusCreated, g)

		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	}
}

// getScopedGeoObject fetches id and checks it actually belongs to mapID's
// version, writing a 404 if it doesn't (whether because the id is unknown or
// because it belongs to a different map/version). This keeps the URL's
// map/version scoping honest even though uuid alone is geo_objects' real
// primary key. Only used by the read path; PUT/DELETE scope their single
// write query directly (see UpdateGeoObject/DeleteGeoObject).
func getScopedGeoObject(w http.ResponseWriter, r *http.Request, st *store.Store, mapID uuid.UUID, version string, id uuid.UUID) (g store.GeoObjectRecord, ok bool) {
	g, err := st.GetGeoObject(r.Context(), id)
	if err != nil {
		writeStoreError(w, err, store.ErrGeoObjectNotFound, http.StatusNotFound, "geo object not found", "failed to get geo object")
		return store.GeoObjectRecord{}, false
	}
	if g.MapUUID != mapID || g.Version != version {
		http.Error(w, "geo object not found", http.StatusNotFound)
		return store.GeoObjectRecord{}, false
	}
	return g, true
}

// geoObjectItemHandler serves the
// /maps/{id}/version/{version}/geo-objects/{uuid} route: GET fetches a geo
// object (requires view access to the map), PUT replaces its fields
// (requires can_edit), DELETE removes it (requires can_delete). can_edit/
// can_delete each imply view access, so GET is the only method that checks
// it separately.
func geoObjectItemHandler(st *store.Store, mapID uuid.UUID, version string, id uuid.UUID) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			if _, ok := getViewableMap(w, r, st, mapID); !ok {
				return
			}

			g, ok := getScopedGeoObject(w, r, st, mapID, version, id)
			if ok {
				writeJSON(w, http.StatusOK, g)
			}

		case http.MethodPut:
			if !requireMapPermission(w, r, st, mapID,
				func(p store.Permissions) bool { return p.CanEdit },
				func(mp store.MapPermission) bool { return mp.CanEdit },
			) {
				return
			}

			req, ok := decodeGeoObjectRequest(w, r)
			if !ok {
				return
			}

			g, err := st.UpdateGeoObject(r.Context(), mapID, version, id, req.Name, req.ExternalID, *req.Latitude, *req.Longitude, req.Street, req.HouseNumber, req.Postcode, usernameFromContext(r.Context()))
			if err != nil {
				writeStoreError(w, err, store.ErrGeoObjectNotFound, http.StatusNotFound, "geo object not found", "failed to update geo object")
				return
			}
			writeJSON(w, http.StatusOK, g)

		case http.MethodDelete:
			if !requireMapPermission(w, r, st, mapID,
				func(p store.Permissions) bool { return p.CanDelete },
				func(mp store.MapPermission) bool { return mp.CanDelete },
			) {
				return
			}

			if err := st.DeleteGeoObject(r.Context(), mapID, version, id); err != nil {
				writeStoreError(w, err, store.ErrGeoObjectNotFound, http.StatusNotFound, "geo object not found", "failed to delete geo object")
				return
			}
			w.WriteHeader(http.StatusNoContent)

		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	}
}

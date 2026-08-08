package handler

import (
	"net/http"
	"strings"

	"nilswitt.dev/tileserve-go/internal/store"
)

type userRequest struct {
	Username  string `json:"username"`
	Password  string `json:"password"`
	CN        string `json:"cn"`
	CanCreate bool   `json:"canCreate"`
	CanEdit   bool   `json:"canEdit"`
	CanDelete bool   `json:"canDelete"`
	IsAdmin   bool   `json:"isAdmin"`
}

// permissions extracts the global Permissions fields carried by a userRequest.
func (req userRequest) permissions() store.Permissions {
	return store.Permissions{
		CanCreate: req.CanCreate,
		CanEdit:   req.CanEdit,
		CanDelete: req.CanDelete,
		IsAdmin:   req.IsAdmin,
	}
}

// requireAdmin is a shorthand for requiring the is_admin permission.
func requireAdmin(w http.ResponseWriter, r *http.Request, st *store.Store) bool {
	return requirePermission(w, r, st, func(p store.Permissions) bool { return p.IsAdmin })
}

// UsersCollectionHandler serves the /users collection route (admin-only):
// GET lists all users, POST creates a new one.
func UsersCollectionHandler(st *store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !requireAdmin(w, r, st) {
			return
		}

		switch r.Method {
		case http.MethodGet:
			users, err := st.ListUsers(r.Context())
			if err != nil {
				http.Error(w, "failed to list users", http.StatusInternalServerError)
				return
			}
			writeJSON(w, http.StatusOK, users)

		case http.MethodPost:
			var req userRequest
			if !decodeJSON(w, r, &req) {
				return
			}
			if req.Username == "" || req.Password == "" {
				http.Error(w, "username and password are required", http.StatusBadRequest)
				return
			}

			u, err := st.CreateUser(r.Context(), req.Username, req.Password, req.CN, req.permissions())
			if err != nil {
				writeStoreError(w, err, store.ErrUserExists, http.StatusConflict, "user already exists", "failed to create user")
				return
			}
			writeJSON(w, http.StatusCreated, u)

		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	}
}

// UserItemHandler serves the /users/{username} item route (admin-only): PUT
// updates the user's cn/permissions (and password, if given), DELETE removes
// the user (an admin may not delete their own account).
func UserItemHandler(st *store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		username := strings.Trim(strings.TrimPrefix(r.URL.Path, "/users/"), "/")
		if username == "" || strings.Contains(username, "/") {
			http.Error(w, "invalid username", http.StatusBadRequest)
			return
		}

		if !requireAdmin(w, r, st) {
			return
		}

		switch r.Method {
		case http.MethodPut:
			var req userRequest
			if !decodeJSON(w, r, &req) {
				return
			}

			u, err := st.UpdateUser(r.Context(), username, req.CN, req.permissions(), req.Password)
			if err != nil {
				writeStoreError(w, err, store.ErrUserNotFound, http.StatusNotFound, "user not found", "failed to update user")
				return
			}
			writeJSON(w, http.StatusOK, u)

		case http.MethodDelete:
			if username == usernameFromContext(r.Context()) {
				http.Error(w, "cannot delete your own account", http.StatusBadRequest)
				return
			}

			if err := st.DeleteUser(r.Context(), username); err != nil {
				writeStoreError(w, err, store.ErrUserNotFound, http.StatusNotFound, "user not found", "failed to delete user")
				return
			}
			w.WriteHeader(http.StatusNoContent)

		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	}
}

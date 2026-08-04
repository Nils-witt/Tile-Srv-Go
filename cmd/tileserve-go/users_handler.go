package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
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
func (req userRequest) permissions() Permissions {
	return Permissions{
		CanCreate: req.CanCreate,
		CanEdit:   req.CanEdit,
		CanDelete: req.CanDelete,
		IsAdmin:   req.IsAdmin,
	}
}

// requireAdmin is a shorthand for requiring the is_admin permission.
func requireAdmin(w http.ResponseWriter, r *http.Request, store *Store) bool {
	return requirePermission(w, r, store, func(p Permissions) bool { return p.IsAdmin })
}

// usersCollectionHandler serves the /users collection route (admin-only):
// GET lists all users, POST creates a new one.
func usersCollectionHandler(store *Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !requireAdmin(w, r, store) {
			return
		}

		switch r.Method {
		case http.MethodGet:
			users, err := store.ListUsers(r.Context())
			if err != nil {
				http.Error(w, "failed to list users", http.StatusInternalServerError)
				return
			}
			writeJSON(w, http.StatusOK, users)

		case http.MethodPost:
			var req userRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				http.Error(w, "invalid request body", http.StatusBadRequest)
				return
			}
			if req.Username == "" || req.Password == "" {
				http.Error(w, "username and password are required", http.StatusBadRequest)
				return
			}

			u, err := store.CreateUser(r.Context(), req.Username, req.Password, req.CN, req.permissions())
			switch {
			case errors.Is(err, ErrUserExists):
				http.Error(w, "user already exists", http.StatusConflict)
			case err != nil:
				http.Error(w, "failed to create user", http.StatusInternalServerError)
			default:
				writeJSON(w, http.StatusCreated, u)
			}

		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	}
}

// userItemHandler serves the /users/{username} item route (admin-only): PUT
// updates the user's cn/permissions (and password, if given), DELETE removes
// the user (an admin may not delete their own account).
func userItemHandler(store *Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		username := strings.Trim(strings.TrimPrefix(r.URL.Path, "/users/"), "/")
		if username == "" || strings.Contains(username, "/") {
			http.Error(w, "invalid username", http.StatusBadRequest)
			return
		}

		if !requireAdmin(w, r, store) {
			return
		}

		switch r.Method {
		case http.MethodPut:
			var req userRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				http.Error(w, "invalid request body", http.StatusBadRequest)
				return
			}

			u, err := store.UpdateUser(r.Context(), username, req.CN, req.permissions(), req.Password)
			switch {
			case errors.Is(err, ErrUserNotFound):
				http.Error(w, "user not found", http.StatusNotFound)
			case err != nil:
				http.Error(w, "failed to update user", http.StatusInternalServerError)
			default:
				writeJSON(w, http.StatusOK, u)
			}

		case http.MethodDelete:
			if username == usernameFromContext(r.Context()) {
				http.Error(w, "cannot delete your own account", http.StatusBadRequest)
				return
			}

			err := store.DeleteUser(r.Context(), username)
			switch {
			case errors.Is(err, ErrUserNotFound):
				http.Error(w, "user not found", http.StatusNotFound)
			case err != nil:
				http.Error(w, "failed to delete user", http.StatusInternalServerError)
			default:
				w.WriteHeader(http.StatusNoContent)
			}

		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	}
}

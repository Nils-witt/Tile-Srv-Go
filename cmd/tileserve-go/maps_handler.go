package main

import (
	"archive/zip"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/google/uuid"
)

// maxUploadSize caps the size of an uploaded map version zip.
const maxUploadSize = 1 << 30 // 1 GiB

// A map version's extracted contents may only consist of numerically named
// directories (e.g. a z/x/y tile pyramid) and numerically named .png files.
var (
	numericSegmentRE = regexp.MustCompile(`^[0-9]+$`)
	numericPNGRE     = regexp.MustCompile(`^[0-9]+\.png$`)
)

type mapRequest struct {
	Name           string `json:"name"`
	CurrentVersion string `json:"currentVersion"`
}

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
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

func mapsCollectionHandler(store *Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			maps, err := store.ListMaps(r.Context())
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

			m, err := store.CreateMap(r.Context(), req.Name, req.CurrentVersion, usernameFromContext(r.Context()))
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

func mapsItemHandler(store *Store, dataRoot string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		path := strings.Trim(strings.TrimPrefix(r.URL.Path, "/maps/"), "/")
		segments := strings.Split(path, "/")

		id, err := uuid.Parse(segments[0])
		if err != nil {
			http.Error(w, "invalid map id", http.StatusBadRequest)
			return
		}

		if len(segments) == 2 && segments[1] == "upload" {
			uploadMapVersionHandler(store, dataRoot, id)(w, r)
			return
		}
		if len(segments) == 2 && segments[1] == "versions" {
			mapVersionsHandler(store, id)(w, r)
			return
		}
		if len(segments) >= 3 && segments[1] == "version" {
			version := segments[2]
			versionDir := filepath.Join(dataRoot, id.String(), version)
			prefix := "/maps/" + strings.Join(segments[:3], "/") + "/"
			http.StripPrefix(prefix, http.FileServer(http.Dir(versionDir))).ServeHTTP(w, r)
			return
		}
		if len(segments) != 1 {
			http.NotFound(w, r)
			return
		}

		switch r.Method {
		case http.MethodGet:
			m, err := store.GetMap(r.Context(), id)
			switch {
			case errors.Is(err, ErrMapNotFound):
				http.Error(w, "map not found", http.StatusNotFound)
			case err != nil:
				http.Error(w, "failed to get map", http.StatusInternalServerError)
			default:
				writeJSON(w, http.StatusOK, m)
			}

		case http.MethodPut:
			if !requirePermission(w, r, store, func(p Permissions) bool { return p.CanEdit }) {
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

			m, err := store.UpdateMap(r.Context(), id, req.Name, req.CurrentVersion, usernameFromContext(r.Context()))
			switch {
			case errors.Is(err, ErrMapNotFound):
				http.Error(w, "map not found", http.StatusNotFound)
			case err != nil:
				http.Error(w, "failed to update map", http.StatusInternalServerError)
			default:
				writeJSON(w, http.StatusOK, m)
			}

		case http.MethodDelete:
			if !requirePermission(w, r, store, func(p Permissions) bool { return p.CanDelete }) {
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

// uploadMapVersionHandler accepts a zip file as the raw request body, extracts
// it, and atomically bumps the map's current_version. Extraction happens into
// a staging directory next to the map's final location first; the DB version
// is only reserved (and the directory put in place) once extraction fully
// succeeds, so a bad upload never leaves the map pointing at a broken version.
func uploadMapVersionHandler(store *Store, dataRoot string, id uuid.UUID) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		if !requirePermission(w, r, store, func(p Permissions) bool { return p.CanCreate }) {
			return
		}

		r.Body = http.MaxBytesReader(w, r.Body, maxUploadSize)

		tmpZip, err := os.CreateTemp("", "tileserve-upload-*.zip")
		if err != nil {
			http.Error(w, "failed to buffer upload", http.StatusInternalServerError)
			return
		}
		defer os.Remove(tmpZip.Name())
		defer tmpZip.Close()

		if _, err := io.Copy(tmpZip, r.Body); err != nil {
			var maxBytesErr *http.MaxBytesError
			if errors.As(err, &maxBytesErr) {
				http.Error(w, "upload too large", http.StatusRequestEntityTooLarge)
				return
			}
			http.Error(w, "failed to read upload", http.StatusBadRequest)
			return
		}
		if err := tmpZip.Close(); err != nil {
			http.Error(w, "failed to buffer upload", http.StatusInternalServerError)
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
		defer os.RemoveAll(stagingDir)

		if err := extractZip(tmpZip.Name(), stagingDir); err != nil {
			http.Error(w, "invalid zip file: "+err.Error(), http.StatusBadRequest)
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
	defer zr.Close()

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

func extractZipFile(f *zip.File, targetPath string) error {
	rc, err := f.Open()
	if err != nil {
		return fmt.Errorf("open zip entry %s: %w", f.Name, err)
	}
	defer rc.Close()

	out, err := os.OpenFile(targetPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		return fmt.Errorf("create file %s: %w", targetPath, err)
	}
	defer out.Close()

	if _, err := io.Copy(out, rc); err != nil {
		return fmt.Errorf("write file %s: %w", targetPath, err)
	}
	return nil
}

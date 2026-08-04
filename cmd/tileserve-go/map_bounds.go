package main

import (
	"errors"
	"fmt"
	"math"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/google/uuid"
)

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

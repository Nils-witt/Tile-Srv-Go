package handler

import (
	"errors"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

func approxEqual(a, b, epsilon float64) bool {
	return math.Abs(a-b) <= epsilon
}

func TestTileToLonLat(t *testing.T) {
	const epsilon = 1e-9

	tests := []struct {
		name    string
		x, y, z int
		wantLon float64
		wantLat float64
	}{
		{name: "top-left of the world at z0", x: 0, y: 0, z: 0, wantLon: -180, wantLat: 85.0511287798066},
		{name: "bottom-right of the world at z0", x: 1, y: 1, z: 0, wantLon: 180, wantLat: -85.0511287798066},
		{name: "center of the world at z1", x: 1, y: 1, z: 1, wantLon: 0, wantLat: 0},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			lon, lat := tileToLonLat(tc.x, tc.y, tc.z)
			if !approxEqual(lon, tc.wantLon, epsilon) || !approxEqual(lat, tc.wantLat, epsilon) {
				t.Fatalf("tileToLonLat(%d, %d, %d) = (%v, %v), want (%v, %v)",
					tc.x, tc.y, tc.z, lon, lat, tc.wantLon, tc.wantLat)
			}
		})
	}
}

// writeTileFile creates an empty file at versionDir/z/x/y.png.
func writeTileFile(t *testing.T, versionDir string, z, x, y int) {
	t.Helper()
	dir := filepath.Join(versionDir, strconv.Itoa(z), strconv.Itoa(x))
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, strconv.Itoa(y)+".png"), []byte("tile"), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestTileExtentAtZoom(t *testing.T) {
	dir := t.TempDir()
	writeTileFile(t, dir, 2, 3, 4)
	writeTileFile(t, dir, 2, 3, 5)
	writeTileFile(t, dir, 2, 5, 4)

	// Junk that must be skipped: a non-numeric x directory, and a
	// non-numeric / non-".png" file inside a valid x directory.
	if err := os.MkdirAll(filepath.Join(dir, "2", "notanumber"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "2", "3", "notes.txt"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}

	minX, minY, maxX, maxY, err := tileExtentAtZoom(dir, 2)
	if err != nil {
		t.Fatalf("tileExtentAtZoom: %v", err)
	}
	if minX != 3 || maxX != 5 || minY != 4 || maxY != 5 {
		t.Fatalf("extent = (minX=%d, minY=%d, maxX=%d, maxY=%d), want (3, 4, 5, 5)", minX, minY, maxX, maxY)
	}
}

func TestTileExtentAtZoomNoTiles(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "2"), 0o755); err != nil {
		t.Fatal(err)
	}

	if _, _, _, _, err := tileExtentAtZoom(dir, 2); !errors.Is(err, errNoTiles) {
		t.Fatalf("err = %v, want errNoTiles", err)
	}
}

func TestComputeTileBounds(t *testing.T) {
	dir := t.TempDir()
	// Two tiles at zoom 1 covering the whole world (x=0..1, y=0..1), plus a
	// higher zoom that must not affect the computed extent (only MaxZoom).
	writeTileFile(t, dir, 1, 0, 0)
	writeTileFile(t, dir, 1, 1, 1)
	writeTileFile(t, dir, 3, 2, 2)

	bounds, err := computeTileBounds(dir)
	if err != nil {
		t.Fatalf("computeTileBounds: %v", err)
	}
	if bounds.MinZoom != 1 {
		t.Errorf("MinZoom = %d, want 1", bounds.MinZoom)
	}
	if bounds.MaxZoom != 3 {
		t.Errorf("MaxZoom = %d, want 3", bounds.MaxZoom)
	}
	const epsilon = 1e-9
	if !approxEqual(bounds.West, -180, epsilon) || !approxEqual(bounds.East, 180, epsilon) {
		t.Errorf("West/East = %v/%v, want -180/180", bounds.West, bounds.East)
	}
	if !approxEqual(bounds.North, 85.0511287798066, epsilon) || !approxEqual(bounds.South, -85.0511287798066, epsilon) {
		t.Errorf("North/South = %v/%v, want ~85.05/~-85.05", bounds.North, bounds.South)
	}
	if !approxEqual(bounds.CenterLng, 0, epsilon) || !approxEqual(bounds.CenterLat, 0, epsilon) {
		t.Errorf("CenterLng/CenterLat = %v/%v, want 0/0", bounds.CenterLng, bounds.CenterLat)
	}
}

func TestComputeTileBoundsNoTiles(t *testing.T) {
	t.Run("missing directory", func(t *testing.T) {
		dir := filepath.Join(t.TempDir(), "does-not-exist")
		if _, err := computeTileBounds(dir); !errors.Is(err, errNoTiles) {
			t.Fatalf("err = %v, want errNoTiles", err)
		}
	})

	t.Run("empty directory", func(t *testing.T) {
		dir := t.TempDir()
		if _, err := computeTileBounds(dir); !errors.Is(err, errNoTiles) {
			t.Fatalf("err = %v, want errNoTiles", err)
		}
	})
}

package main

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"io"
	"os"
	"path/filepath"
	"testing"
)

// buildZip writes a zip archive to path containing the given entries. A
// trailing "/" in name marks a directory entry.
func buildZip(t *testing.T, path string, entries map[string]string) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()

	zw := zip.NewWriter(f)
	for name, content := range entries {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write([]byte(content)); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
}

// buildTar writes a tar archive (optionally gzip-compressed) to path
// containing the given regular-file entries.
func buildTar(t *testing.T, path string, gzipped bool, entries map[string]string) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()

	var w = io.Writer(f)
	var gw *gzip.Writer
	if gzipped {
		gw = gzip.NewWriter(f)
		w = gw
	}

	tw := tar.NewWriter(w)
	for name, content := range entries {
		hdr := &tar.Header{
			Name: name,
			Mode: 0o644,
			Size: int64(len(content)),
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(content)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if gw != nil {
		if err := gw.Close(); err != nil {
			t.Fatal(err)
		}
	}
}

func TestSniffArchiveFormat(t *testing.T) {
	dir := t.TempDir()

	zipPath := filepath.Join(dir, "a.zip")
	buildZip(t, zipPath, map[string]string{"1/2/3.png": "tile"})
	if got, err := sniffArchiveFormat(zipPath); err != nil || got != archiveZip {
		t.Fatalf("zip: got %v, %v; want archiveZip, nil", got, err)
	}

	tarGzPath := filepath.Join(dir, "a.tar.gz")
	buildTar(t, tarGzPath, true, map[string]string{"1/2/3.png": "tile"})
	if got, err := sniffArchiveFormat(tarGzPath); err != nil || got != archiveTarGz {
		t.Fatalf("tar.gz: got %v, %v; want archiveTarGz, nil", got, err)
	}

	tarPath := filepath.Join(dir, "a.tar")
	buildTar(t, tarPath, false, map[string]string{"1/2/3.png": "tile"})
	if got, err := sniffArchiveFormat(tarPath); err != nil || got != archiveTar {
		t.Fatalf("tar: got %v, %v; want archiveTar, nil", got, err)
	}

	unknownPath := filepath.Join(dir, "a.bin")
	if err := os.WriteFile(unknownPath, []byte("not an archive"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got, err := sniffArchiveFormat(unknownPath); err != nil || got != archiveUnknown {
		t.Fatalf("unknown: got %v, %v; want archiveUnknown, nil", got, err)
	}
}

func TestExtractZip(t *testing.T) {
	dir := t.TempDir()
	archivePath := filepath.Join(dir, "up.zip")
	destDir := filepath.Join(dir, "dest")
	if err := os.Mkdir(destDir, 0o755); err != nil {
		t.Fatal(err)
	}

	buildZip(t, archivePath, map[string]string{
		"3/1/2.png":        "tile-data",
		"../../etc/passwd": "escape attempt",
		"3/notes.txt":      "invalid entry name",
	})

	if err := extractZip(archivePath, destDir); err != nil {
		t.Fatalf("extractZip: %v", err)
	}

	got, err := os.ReadFile(filepath.Join(destDir, "3", "1", "2.png"))
	if err != nil {
		t.Fatalf("expected tile written: %v", err)
	}
	if string(got) != "tile-data" {
		t.Fatalf("tile content = %q, want %q", got, "tile-data")
	}

	if _, err := os.Stat(filepath.Join(dir, "etc", "passwd")); !os.IsNotExist(err) {
		t.Fatalf("zip-slip entry should not have escaped destDir")
	}
	if _, err := os.Stat(filepath.Join(destDir, "3", "notes.txt")); !os.IsNotExist(err) {
		t.Fatalf("invalidly named entry should have been skipped")
	}
}

func TestExtractTar(t *testing.T) {
	for _, gzipped := range []bool{false, true} {
		t.Run(map[bool]string{false: "plain", true: "gzip"}[gzipped], func(t *testing.T) {
			dir := t.TempDir()
			archivePath := filepath.Join(dir, "up.tar")
			destDir := filepath.Join(dir, "dest")
			if err := os.Mkdir(destDir, 0o755); err != nil {
				t.Fatal(err)
			}

			buildTar(t, archivePath, gzipped, map[string]string{
				"5/10/20.png":      "tile-data",
				"../../etc/passwd": "escape attempt",
				"5/notes.txt":      "invalid entry name",
			})

			if err := extractTar(archivePath, destDir, gzipped); err != nil {
				t.Fatalf("extractTar: %v", err)
			}

			got, err := os.ReadFile(filepath.Join(destDir, "5", "10", "20.png"))
			if err != nil {
				t.Fatalf("expected tile written: %v", err)
			}
			if string(got) != "tile-data" {
				t.Fatalf("tile content = %q, want %q", got, "tile-data")
			}

			if _, err := os.Stat(filepath.Join(dir, "etc", "passwd")); !os.IsNotExist(err) {
				t.Fatalf("tar-slip entry should not have escaped destDir")
			}
			if _, err := os.Stat(filepath.Join(destDir, "5", "notes.txt")); !os.IsNotExist(err) {
				t.Fatalf("invalidly named entry should have been skipped")
			}
		})
	}
}

func TestExtractZipAndTarProduceEquivalentOutput(t *testing.T) {
	entries := map[string]string{
		"7/3/4.png": "same-tile",
	}

	dir := t.TempDir()
	zipPath := filepath.Join(dir, "up.zip")
	tarPath := filepath.Join(dir, "up.tar")
	zipDest := filepath.Join(dir, "zip-dest")
	tarDest := filepath.Join(dir, "tar-dest")
	if err := os.MkdirAll(zipDest, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(tarDest, 0o755); err != nil {
		t.Fatal(err)
	}

	buildZip(t, zipPath, entries)
	buildTar(t, tarPath, false, entries)

	if err := extractZip(zipPath, zipDest); err != nil {
		t.Fatalf("extractZip: %v", err)
	}
	if err := extractTar(tarPath, tarDest, false); err != nil {
		t.Fatalf("extractTar: %v", err)
	}

	zipContent, err := os.ReadFile(filepath.Join(zipDest, "7", "3", "4.png"))
	if err != nil {
		t.Fatal(err)
	}
	tarContent, err := os.ReadFile(filepath.Join(tarDest, "7", "3", "4.png"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(zipContent, tarContent) {
		t.Fatalf("zip and tar extraction diverged: %q vs %q", zipContent, tarContent)
	}
}

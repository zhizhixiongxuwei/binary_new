package trivydb

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

const (
	testBundleID = "123e4567-e89b-42d3-a456-426614174000"
	testTrivyID  = "223e4567-e89b-42d3-a456-426614174001"
	testJavaID   = "323e4567-e89b-42d3-a456-426614174002"
)

func TestResolverLoadsFixedDualDatabaseBundle(t *testing.T) {
	root, manifest := writeTestBundle(t)
	resolver, err := NewResolver(root)
	if err != nil {
		t.Fatalf("NewResolver() error = %v", err)
	}
	snapshot, err := resolver.Resolve(context.Background(), JavaDBRequired)
	if err != nil {
		t.Fatalf("Resolve() error = %v", err)
	}
	if snapshot.Bundle.ID != testBundleID ||
		snapshot.Bundle.ContentSHA256 != manifest.ContentSHA256 ||
		snapshot.Trivy.ID != testTrivyID ||
		snapshot.Java == nil || snapshot.Java.ID != testJavaID {
		t.Fatalf("snapshot = %#v", snapshot)
	}

	workspace := t.TempDir()
	view, err := resolver.CreateCacheView(
		context.Background(),
		workspace,
		snapshot,
	)
	if err != nil {
		t.Fatalf("CreateCacheView() error = %v", err)
	}
	for _, name := range []string{"db", "java-db"} {
		info, err := os.Lstat(filepath.Join(view.Path(), name))
		if err != nil || info.Mode()&os.ModeSymlink == 0 {
			t.Fatalf("cache entry %s is not a symlink: info=%v err=%v", name, info, err)
		}
	}
	if err := view.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
}

func TestDecodeManifestRejectsMetadataHashMismatch(t *testing.T) {
	_, manifest := testManifest()
	manifest.ContentSHA256 = "f" + manifest.ContentSHA256[1:]
	raw, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	_, err = decodeManifest(raw, JavaDBRequired)
	if !errors.Is(err, ErrInvalidSnapshot) {
		t.Fatalf("decodeManifest() error = %v, want ErrInvalidSnapshot", err)
	}
}

func TestVerifyIntegrityRejectsDatabaseContentMismatch(t *testing.T) {
	root, manifest := writeTestBundle(t)
	path := filepath.Join(
		root, "db", "versions", manifest.Databases[0].ID, "trivy.db",
	)
	if err := os.Chmod(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("changed data!!"), 0o400); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o400); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Dir(path), 0o500); err != nil {
		t.Fatal(err)
	}

	resolver, err := NewResolver(root)
	if err != nil {
		t.Fatal(err)
	}
	_, err = resolver.VerifyIntegrity(context.Background(), JavaDBRequired)
	if !errors.Is(err, ErrInvalidSnapshot) {
		t.Fatalf("VerifyIntegrity() error = %v", err)
	}
}

func TestNewResolverRejectsFilesystemRoot(t *testing.T) {
	if _, err := NewResolver("/"); !errors.Is(err, ErrInvalidConfiguration) {
		t.Fatalf("NewResolver() error = %v, want ErrInvalidConfiguration", err)
	}
}

func writeTestBundle(t *testing.T) (string, bundleManifest) {
	t.Helper()
	root := t.TempDir()
	t.Cleanup(func() {
		_ = filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			if entry.IsDir() {
				_ = os.Chmod(path, 0o700)
			} else {
				_ = os.Chmod(path, 0o600)
			}
			return nil
		})
	})
	files, manifest := testManifest()
	for databaseIndex, database := range manifest.Databases {
		directory := filepath.Join(
			root,
			storageDirectoryForTest(database.DatabaseType),
			"versions",
			database.ID,
		)
		if err := os.MkdirAll(directory, 0o700); err != nil {
			t.Fatal(err)
		}
		for fileIndex, file := range database.Files {
			if err := os.WriteFile(
				filepath.Join(directory, file.Path),
				files[databaseIndex][fileIndex],
				0o400,
			); err != nil {
				t.Fatal(err)
			}
		}
		if err := os.Chmod(directory, 0o500); err != nil {
			t.Fatal(err)
		}
	}
	raw, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, manifestFilename), raw, 0o400); err != nil {
		t.Fatal(err)
	}
	return root, manifest
}

func testManifest() ([][][]byte, bundleManifest) {
	files := [][][]byte{
		{[]byte(`{"Version":2}`), []byte("trivy database")},
		{[]byte(`{"Version":1}`), []byte("java database")},
	}
	databases := []databaseManifest{
		{
			ID: testTrivyID, DatabaseType: DatabaseTrivy,
			Version: "2026.08.07", SchemaVersion: 2,
			StorageKey: "trivy/db/versions/" + testTrivyID,
			Files: manifestFiles(
				[]string{"metadata.json", "trivy.db"},
				files[0],
			),
		},
		{
			ID: testJavaID, DatabaseType: DatabaseTrivyJava,
			Version: "2026.08.07", SchemaVersion: 1,
			StorageKey: "trivy/java-db/versions/" + testJavaID,
			Files: manifestFiles(
				[]string{"metadata.json", "trivy-java.db"},
				files[1],
			),
		},
	}
	manifest := bundleManifest{
		SchemaVersion: BundleSchemaVersion,
		ID:            testBundleID,
		Version:       "2026.08.07",
		GeneratedAt:   "2026-08-07T00:00:00Z",
		Databases:     databases,
	}
	manifest.ContentSHA256 = calculatedBundleHash(databases)
	return files, manifest
}

func manifestFiles(names []string, values [][]byte) []File {
	result := make([]File, 0, len(names))
	for index, name := range names {
		hash := sha256.Sum256(values[index])
		result = append(result, File{
			Path:      name,
			SHA256:    hex.EncodeToString(hash[:]),
			SizeBytes: int64(len(values[index])),
		})
	}
	return result
}

func storageDirectoryForTest(databaseType string) string {
	if databaseType == DatabaseTrivyJava {
		return "java-db"
	}
	return "db"
}

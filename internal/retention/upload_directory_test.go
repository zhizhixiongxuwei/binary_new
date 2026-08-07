package retention

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

const (
	testUploadID  = "01234567-89ab-4cde-8fab-0123456789ab"
	otherUploadID = "11234567-89ab-4cde-8fab-0123456789ab"
)

func TestRepositoryUploadDirectoryDeleterRemovesOnlyExpectedLayout(t *testing.T) {
	root := t.TempDir()
	targetParts := filepath.Join(root, testUploadID, "parts")
	neighborParts := filepath.Join(root, otherUploadID, "parts")
	for _, directory := range []string{targetParts, neighborParts} {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for name, content := range map[string]string{
		"00000001.part":                      "part",
		"00000002.part.tmp.0123456789abcdef": "temporary",
	} {
		if err := os.WriteFile(
			filepath.Join(targetParts, name),
			[]byte(content),
			0o600,
		); err != nil {
			t.Fatal(err)
		}
	}
	neighbor := filepath.Join(neighborParts, "00000001.part")
	if err := os.WriteFile(neighbor, []byte("neighbor"), 0o600); err != nil {
		t.Fatal(err)
	}

	deleter, err := NewRepositoryUploadDirectoryDeleter(root)
	if err != nil {
		t.Fatal(err)
	}
	if err := deleter.Delete(context.Background(), testUploadID); err != nil {
		t.Fatalf("Delete(): %v", err)
	}
	if _, err := os.Lstat(filepath.Join(root, testUploadID)); !os.IsNotExist(err) {
		t.Fatalf("target upload still exists: %v", err)
	}
	content, err := os.ReadFile(neighbor)
	if err != nil || string(content) != "neighbor" {
		t.Fatalf("neighbor changed: content=%q error=%v", content, err)
	}
	if err := deleter.Delete(context.Background(), testUploadID); err != nil {
		t.Fatalf("idempotent Delete(): %v", err)
	}
}

func TestRepositoryUploadDirectoryDeleterRejectsUnsafeEntries(t *testing.T) {
	tests := []struct {
		name  string
		setup func(*testing.T, string, string)
	}{
		{
			name: "dangling symlink",
			setup: func(t *testing.T, root, parts string) {
				t.Helper()
				if err := os.Symlink(
					filepath.Join(root, "missing"),
					filepath.Join(parts, "00000002.part"),
				); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "nested directory",
			setup: func(t *testing.T, _, parts string) {
				t.Helper()
				if err := os.Mkdir(
					filepath.Join(parts, "00000002.part"),
					0o700,
				); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "unexpected file",
			setup: func(t *testing.T, _, parts string) {
				t.Helper()
				if err := os.WriteFile(
					filepath.Join(parts, "notes.txt"),
					[]byte("unexpected"),
					0o600,
				); err != nil {
					t.Fatal(err)
				}
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			parts := filepath.Join(root, testUploadID, "parts")
			if err := os.MkdirAll(parts, 0o700); err != nil {
				t.Fatal(err)
			}
			validPart := filepath.Join(parts, "00000001.part")
			if err := os.WriteFile(validPart, []byte("keep"), 0o600); err != nil {
				t.Fatal(err)
			}
			test.setup(t, root, parts)
			deleter, err := NewRepositoryUploadDirectoryDeleter(root)
			if err != nil {
				t.Fatal(err)
			}
			if err := deleter.Delete(
				context.Background(),
				testUploadID,
			); err == nil {
				t.Fatal("Delete() accepted unsafe upload contents")
			}
			content, err := os.ReadFile(validPart)
			if err != nil || string(content) != "keep" {
				t.Fatalf("valid part was removed: content=%q error=%v", content, err)
			}
		})
	}
}

func TestRepositoryUploadDirectoryDeleterDoesNotFollowUploadSymlink(t *testing.T) {
	root := t.TempDir()
	neighbor := filepath.Join(root, otherUploadID)
	if err := os.MkdirAll(filepath.Join(neighbor, "parts"), 0o700); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(neighbor, "parts", "00000001.part")
	if err := os.WriteFile(marker, []byte("neighbor"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(neighbor, filepath.Join(root, testUploadID)); err != nil {
		t.Fatal(err)
	}
	deleter, err := NewRepositoryUploadDirectoryDeleter(root)
	if err != nil {
		t.Fatal(err)
	}
	if err := deleter.Delete(context.Background(), testUploadID); err == nil {
		t.Fatal("Delete() followed an upload directory symlink")
	}
	if content, err := os.ReadFile(marker); err != nil || string(content) != "neighbor" {
		t.Fatalf("neighbor changed: content=%q error=%v", content, err)
	}
}

func TestRepositoryUploadDirectoryDeleterRejectsNonCanonicalID(t *testing.T) {
	root := t.TempDir()
	deleter, err := NewRepositoryUploadDirectoryDeleter(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{
		"../" + testUploadID,
		"01234567-89AB-4CDE-8FAB-0123456789AB",
		"01234567-89ab-1cde-8fab-0123456789ab",
	} {
		if err := deleter.Delete(context.Background(), id); err == nil {
			t.Fatalf("Delete() accepted %q", id)
		}
	}
}

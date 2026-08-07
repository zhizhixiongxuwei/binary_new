package retention

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestRepositoryBlobDeleterDeletesCanonicalRegularFile(t *testing.T) {
	root := t.TempDir()
	blob, path := writeTestBlob(t, root, []byte("retained sample"))
	deleter, err := NewRepositoryBlobDeleter(root)
	if err != nil {
		t.Fatal(err)
	}

	if err := deleter.Delete(context.Background(), blob); err != nil {
		t.Fatalf("Delete(): %v", err)
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("blob path still exists or cannot be inspected: %v", err)
	}
	if err := deleter.Delete(context.Background(), blob); err != nil {
		t.Fatalf("Delete() ENOENT replay: %v", err)
	}
}

func TestRepositoryBlobDeleterPreservesJSONAndHTMLReports(t *testing.T) {
	root := t.TempDir()
	blob, _ := writeTestBlob(t, root, []byte("expired sample"))
	reportDirectory := filepath.Join(
		root,
		"reports",
		"123e4567-e89b-42d3-a456-426614174000",
	)
	if err := os.MkdirAll(reportDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	reports := map[string][]byte{
		"report.json": []byte(`{"status":"complete"}`),
		"report.html": []byte("<!doctype html><title>complete</title>"),
	}
	for name, content := range reports {
		if err := os.WriteFile(
			filepath.Join(reportDirectory, name),
			content,
			0o600,
		); err != nil {
			t.Fatal(err)
		}
	}
	deleter, err := NewRepositoryBlobDeleter(root)
	if err != nil {
		t.Fatal(err)
	}

	if err := deleter.Delete(context.Background(), blob); err != nil {
		t.Fatalf("Delete(): %v", err)
	}
	for name, expected := range reports {
		actual, err := os.ReadFile(filepath.Join(reportDirectory, name))
		if err != nil {
			t.Fatalf("read retained %s report: %v", name, err)
		}
		if string(actual) != string(expected) {
			t.Fatalf("retained %s report changed", name)
		}
	}
}

func TestRepositoryBlobDeleterRejectsUnsafeTargets(t *testing.T) {
	content := []byte("retained sample")
	hash := fmt.Sprintf("%x", sha256.Sum256(content))
	canonicalKey := "blobs/sha256/" + hash[:2] + "/" + hash
	tests := []struct {
		name   string
		mutate func(*Blob)
	}{
		{
			name: "storage traversal",
			mutate: func(blob *Blob) {
				blob.StorageKey = "blobs/sha256/../../outside"
			},
		},
		{
			name: "wrong content address",
			mutate: func(blob *Blob) {
				blob.StorageKey = canonicalKey + ".other"
			},
		},
		{
			name: "uppercase digest",
			mutate: func(blob *Blob) {
				blob.SHA256 = "A" + blob.SHA256[1:]
			},
		},
		{
			name: "negative size",
			mutate: func(blob *Blob) {
				blob.SizeBytes = -1
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			blob, path := writeTestBlob(t, root, content)
			test.mutate(&blob)
			deleter, err := NewRepositoryBlobDeleter(root)
			if err != nil {
				t.Fatal(err)
			}
			if err := deleter.Delete(context.Background(), blob); !errors.Is(err, ErrUnsafeBlobPath) {
				t.Fatalf("Delete() error = %v, want ErrUnsafeBlobPath", err)
			}
			if _, err := os.Stat(path); err != nil {
				t.Fatalf("safe blob was changed: %v", err)
			}
		})
	}
}

func TestRepositoryBlobDeleterRejectsSymlinkAndDirectoryTargets(t *testing.T) {
	tests := []struct {
		name  string
		setup func(*testing.T, string, Blob, string)
	}{
		{
			name: "final symlink",
			setup: func(t *testing.T, root string, _ Blob, path string) {
				t.Helper()
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
				outside := filepath.Join(t.TempDir(), "outside")
				if err := os.WriteFile(outside, []byte("retained sample"), 0o600); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(outside, path); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "parent symlink",
			setup: func(t *testing.T, root string, blob Blob, path string) {
				t.Helper()
				prefix := filepath.Dir(path)
				if err := os.RemoveAll(prefix); err != nil {
					t.Fatal(err)
				}
				outside := filepath.Join(t.TempDir(), blob.SHA256[:2])
				if err := os.MkdirAll(outside, 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(
					filepath.Join(outside, blob.SHA256),
					[]byte("retained sample"),
					0o600,
				); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(outside, prefix); err != nil {
					t.Fatal(err)
				}
				_ = root
			},
		},
		{
			name: "directory target",
			setup: func(t *testing.T, _ string, _ Blob, path string) {
				t.Helper()
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
				if err := os.Mkdir(path, 0o700); err != nil {
					t.Fatal(err)
				}
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			blob, path := writeTestBlob(t, root, []byte("retained sample"))
			test.setup(t, root, blob, path)
			deleter, err := NewRepositoryBlobDeleter(root)
			if err != nil {
				t.Fatal(err)
			}
			if err := deleter.Delete(context.Background(), blob); err == nil {
				t.Fatal("Delete() error = nil, want unsafe target rejection")
			}
			if _, err := os.Lstat(path); err != nil {
				t.Fatalf("unsafe target was changed: %v", err)
			}
		})
	}
}

func TestRepositoryBlobDeleterRejectsChangedSizeAndRootSymlink(t *testing.T) {
	root := t.TempDir()
	blob, path := writeTestBlob(t, root, []byte("retained sample"))
	blob.SizeBytes++
	deleter, err := NewRepositoryBlobDeleter(root)
	if err != nil {
		t.Fatal(err)
	}
	if err := deleter.Delete(context.Background(), blob); !errors.Is(err, ErrUnsafeBlobPath) {
		t.Fatalf("Delete() error = %v, want ErrUnsafeBlobPath", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("size-mismatched blob was changed: %v", err)
	}

	link := filepath.Join(t.TempDir(), "repository-link")
	if err := os.Symlink(root, link); err != nil {
		t.Fatal(err)
	}
	deleter, err = NewRepositoryBlobDeleter(link)
	if err != nil {
		t.Fatal(err)
	}
	if err := deleter.Delete(context.Background(), blob); err == nil {
		t.Fatal("Delete() through repository root symlink succeeded")
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("root-symlink attempt changed blob: %v", err)
	}
}

func TestRepositoryBlobDeleterHonorsCancellationBeforeDeletion(t *testing.T) {
	root := t.TempDir()
	blob, path := writeTestBlob(t, root, []byte("retained sample"))
	deleter, err := NewRepositoryBlobDeleter(root)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := deleter.Delete(ctx, blob); !errors.Is(err, context.Canceled) {
		t.Fatalf("Delete() error = %v, want context.Canceled", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("cancelled deletion changed blob: %v", err)
	}
}

func writeTestBlob(t *testing.T, root string, content []byte) (Blob, string) {
	t.Helper()
	hash := fmt.Sprintf("%x", sha256.Sum256(content))
	key := "blobs/sha256/" + hash[:2] + "/" + hash
	path := filepath.Join(root, filepath.FromSlash(key))
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatal(err)
	}
	return Blob{
		ID: 1, SHA256: hash, SizeBytes: int64(len(content)), StorageKey: key,
	}, path
}

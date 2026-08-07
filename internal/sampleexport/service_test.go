package sampleexport

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type repositoryStub struct {
	values []BlobDescriptor
	errs   []error
	calls  int
}

func (s *repositoryStub) ResolveRootBlob(
	context.Context,
	string,
) (BlobDescriptor, error) {
	index := s.calls
	s.calls++
	if index < len(s.errs) && s.errs[index] != nil {
		return BlobDescriptor{}, s.errs[index]
	}
	if index >= len(s.values) {
		return BlobDescriptor{}, errors.New("unexpected repository call")
	}
	return s.values[index], nil
}

func TestServiceOpensOnlyTwiceConfirmedVerifiedCASBlob(t *testing.T) {
	root := t.TempDir()
	content := []byte("verified retained root sample")
	descriptor := writeSampleBlob(t, root, content)
	repository := &repositoryStub{
		values: []BlobDescriptor{descriptor, descriptor},
	}
	service, err := NewService(
		repository,
		Config{RepositoryRoot: root},
	)
	if err != nil {
		t.Fatal(err)
	}
	value, err := service.Open(
		context.Background(),
		"00000000-0000-4000-8000-000000000001",
	)
	if err != nil {
		t.Fatal(err)
	}
	defer value.Content.Close()
	actual, err := io.ReadAll(value.Content)
	if err != nil {
		t.Fatal(err)
	}
	if string(actual) != string(content) ||
		value.SizeBytes != uint64(len(content)) ||
		value.SHA256 != descriptor.SHA256 ||
		value.Filename != DownloadFilename ||
		repository.calls != 2 {
		t.Fatalf(
			"download/content/calls = %+v/%q/%d",
			value,
			actual,
			repository.calls,
		)
	}
}

func TestServiceRejectsUnsafeOrChangedFilesystemObjects(t *testing.T) {
	tests := []struct {
		name    string
		prepare func(*testing.T, string, BlobDescriptor) BlobDescriptor
	}{
		{
			name: "intermediate symlink",
			prepare: func(t *testing.T, root string, value BlobDescriptor) BlobDescriptor {
				t.Helper()
				if err := os.RemoveAll(filepath.Join(root, "blobs")); err != nil {
					t.Fatal(err)
				}
				outside := t.TempDir()
				if err := os.Symlink(outside, filepath.Join(root, "blobs")); err != nil {
					t.Fatal(err)
				}
				return value
			},
		},
		{
			name: "file symlink",
			prepare: func(t *testing.T, root string, value BlobDescriptor) BlobDescriptor {
				t.Helper()
				path := filepath.Join(root, filepath.FromSlash(value.StorageKey))
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
				outside := filepath.Join(t.TempDir(), "outside")
				if err := os.WriteFile(outside, []byte("outside"), 0o600); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(outside, path); err != nil {
					t.Fatal(err)
				}
				return value
			},
		},
		{
			name: "non regular file",
			prepare: func(t *testing.T, root string, value BlobDescriptor) BlobDescriptor {
				t.Helper()
				path := filepath.Join(root, filepath.FromSlash(value.StorageKey))
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
				if err := os.Mkdir(path, 0o700); err != nil {
					t.Fatal(err)
				}
				return value
			},
		},
		{
			name: "size changed",
			prepare: func(t *testing.T, root string, value BlobDescriptor) BlobDescriptor {
				t.Helper()
				path := filepath.Join(root, filepath.FromSlash(value.StorageKey))
				if err := os.WriteFile(path, []byte("changed-size"), 0o600); err != nil {
					t.Fatal(err)
				}
				return value
			},
		},
		{
			name: "hash changed",
			prepare: func(t *testing.T, root string, value BlobDescriptor) BlobDescriptor {
				t.Helper()
				path := filepath.Join(root, filepath.FromSlash(value.StorageKey))
				if err := os.WriteFile(path, []byte("tampered"), 0o600); err != nil {
					t.Fatal(err)
				}
				value.SizeBytes = uint64(len("tampered"))
				value.UploadDeclaredBytes = value.SizeBytes
				return value
			},
		},
		{
			name: "hard linked file",
			prepare: func(t *testing.T, root string, value BlobDescriptor) BlobDescriptor {
				t.Helper()
				path := filepath.Join(root, filepath.FromSlash(value.StorageKey))
				if err := os.Link(path, filepath.Join(root, "second-link")); err != nil {
					t.Fatal(err)
				}
				return value
			},
		},
		{
			name: "group readable file",
			prepare: func(t *testing.T, root string, value BlobDescriptor) BlobDescriptor {
				t.Helper()
				path := filepath.Join(root, filepath.FromSlash(value.StorageKey))
				if err := os.Chmod(path, 0o640); err != nil {
					t.Fatal(err)
				}
				return value
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			value := writeSampleBlob(t, root, []byte("original"))
			value = test.prepare(t, root, value)
			repository := &repositoryStub{
				values: []BlobDescriptor{value, value},
			}
			service, err := NewService(
				repository,
				Config{RepositoryRoot: root},
			)
			if err != nil {
				t.Fatal(err)
			}
			_, err = service.Open(
				context.Background(),
				"00000000-0000-4000-8000-000000000001",
			)
			if !errors.Is(err, ErrUnavailable) &&
				!errors.Is(err, ErrIntegrity) {
				t.Fatalf(
					"Open() error = %v, want unavailable/integrity",
					err,
				)
			}
		})
	}
}

func TestServiceRejectsInvalidDescriptorBeforeOpeningStorage(t *testing.T) {
	root := t.TempDir()
	value := writeSampleBlob(t, root, []byte("sample"))
	tests := []struct {
		name   string
		mutate func(*BlobDescriptor)
	}{
		{
			name: "non canonical storage key",
			mutate: func(value *BlobDescriptor) {
				value.StorageKey = "../outside"
			},
		},
		{
			name: "wrong task relation",
			mutate: func(value *BlobDescriptor) {
				value.TaskBlobID++
			},
		},
		{
			name: "deleted state",
			mutate: func(value *BlobDescriptor) {
				value.State = "deleted"
			},
		},
		{
			name: "missing reference",
			mutate: func(value *BlobDescriptor) {
				value.ReferenceCount = 0
			},
		},
		{
			name: "upload digest mismatch",
			mutate: func(value *BlobDescriptor) {
				value.UploadSHA256 = strings.Repeat("f", 64)
			},
		},
		{
			name: "expired upload retains blob relation",
			mutate: func(value *BlobDescriptor) {
				value.UploadStatus = "expired"
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			changed := value
			test.mutate(&changed)
			repository := &repositoryStub{
				values: []BlobDescriptor{changed},
			}
			service, err := NewService(
				repository,
				Config{RepositoryRoot: root},
			)
			if err != nil {
				t.Fatal(err)
			}
			_, err = service.Open(
				context.Background(),
				"00000000-0000-4000-8000-000000000001",
			)
			if !errors.Is(err, ErrIntegrity) {
				t.Fatalf("Open() error = %v, want ErrIntegrity", err)
			}
		})
	}
}

func TestServiceRejectsAssociationRemovedDuringVerification(t *testing.T) {
	root := t.TempDir()
	value := writeSampleBlob(t, root, []byte("sample"))
	repository := &repositoryStub{
		values: []BlobDescriptor{value},
		errs:   []error{nil, ErrNotFound},
	}
	service, err := NewService(
		repository,
		Config{RepositoryRoot: root},
	)
	if err != nil {
		t.Fatal(err)
	}
	_, err = service.Open(
		context.Background(),
		"00000000-0000-4000-8000-000000000001",
	)
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("Open() error = %v, want ErrUnavailable", err)
	}
}

func TestNewServiceRejectsSymlinkOrNonCanonicalRoot(t *testing.T) {
	realRoot := t.TempDir()
	link := filepath.Join(t.TempDir(), "repository")
	if err := os.Symlink(realRoot, link); err != nil {
		t.Fatal(err)
	}
	for _, root := range []string{link, realRoot + string(os.PathSeparator) + ".."} {
		_, err := NewService(
			&repositoryStub{},
			Config{RepositoryRoot: root},
		)
		if err == nil {
			t.Fatalf("NewService(%q) error = nil", root)
		}
	}
}

func TestServiceRejectsRepositoryRootReplacement(t *testing.T) {
	parent := t.TempDir()
	root := filepath.Join(parent, "repository")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	value := writeSampleBlob(t, root, []byte("sample"))
	repository := &repositoryStub{
		values: []BlobDescriptor{value, value},
	}
	service, err := NewService(
		repository,
		Config{RepositoryRoot: root},
	)
	if err != nil {
		t.Fatal(err)
	}
	replaced := filepath.Join(parent, "repository-replaced")
	if err := os.Rename(root, replaced); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	_, err = service.Open(
		context.Background(),
		"00000000-0000-4000-8000-000000000001",
	)
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("Open() error = %v, want ErrUnavailable", err)
	}
}

func writeSampleBlob(
	t *testing.T,
	root string,
	content []byte,
) BlobDescriptor {
	t.Helper()
	sum := sha256.Sum256(content)
	digest := hex.EncodeToString(sum[:])
	key := "blobs/sha256/" + digest[:2] + "/" + digest
	path := filepath.Join(root, filepath.FromSlash(key))
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatal(err)
	}
	blobID := uint64(17)
	return BlobDescriptor{
		ID: blobID, TaskBlobID: blobID, UploadBlobID: &blobID,
		StorageKey: key, SHA256: digest, SizeBytes: uint64(len(content)),
		State: "available", ReferenceCount: 2, UploadStatus: "completed",
		UploadSHA256: digest, UploadDeclaredBytes: uint64(len(content)),
	}
}

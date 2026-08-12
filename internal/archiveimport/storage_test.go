package archiveimport

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func TestBlobStorageOpenVerifiedReturnsUnlinkedContentSnapshot(t *testing.T) {
	storage, repository, key, digest, content := verifiedBlobFixture(t)
	var observedPath string
	storage.afterVerifiedTempCreate = func(path string) {
		observedPath = path
		file, openErr := os.Open(path)
		if openErr == nil {
			_ = file.Close()
			t.Error("verified snapshot remained name-addressable after creation")
		} else if !errors.Is(openErr, os.ErrNotExist) {
			t.Errorf("open unlinked snapshot: %v", openErr)
		}
	}
	reader, err := storage.OpenVerified(
		context.Background(), key, int64(len(content)), digest,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	if observedPath == "" {
		t.Fatal("verified snapshot unlink hook was not reached")
	}
	if err := os.WriteFile(
		filepath.Join(repository, filepath.FromSlash(key)),
		[]byte("same-size-mutated"), 0o600,
	); err != nil {
		t.Fatal(err)
	}
	actual, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	if string(actual) != string(content) {
		t.Fatalf("verified snapshot = %q, want %q", actual, content)
	}
}

func TestBlobStorageOpenVerifiedRejectsPathReplacement(t *testing.T) {
	storage, repository, key, digest, content := verifiedBlobFixture(t)
	path := filepath.Join(repository, filepath.FromSlash(key))
	var hookErr error
	storage.afterVerifiedSourceOpen = func() {
		hookErr = os.Rename(path, path+".original")
		if hookErr == nil {
			hookErr = os.WriteFile(path, []byte("same-size-mutated"), 0o600)
		}
	}
	_, err := storage.OpenVerified(
		context.Background(), key, int64(len(content)), digest,
	)
	if hookErr != nil {
		t.Fatal(hookErr)
	}
	if !errors.Is(err, ErrSourceUnavailable) {
		t.Fatalf("OpenVerified() error = %v, want ErrSourceUnavailable", err)
	}
}

func TestBlobStorageOpenVerifiedRejectsSameSizeContentMutation(t *testing.T) {
	storage, repository, key, digest, content := verifiedBlobFixture(t)
	path := filepath.Join(repository, filepath.FromSlash(key))
	storage.afterVerifiedSourceOpen = func() {
		if err := os.WriteFile(path, []byte("same-size-mutated"), 0o600); err != nil {
			t.Errorf("mutate source: %v", err)
		}
	}
	_, err := storage.OpenVerified(
		context.Background(), key, int64(len(content)), digest,
	)
	if !errors.Is(err, ErrConflict) {
		t.Fatalf("OpenVerified() error = %v, want ErrConflict", err)
	}
}

func TestBlobStoragePublishRejectsSourceSymlink(t *testing.T) {
	repository := t.TempDir()
	storage, err := NewBlobStorage(repository)
	if err != nil {
		t.Fatal(err)
	}
	source := filepath.Join(t.TempDir(), "member.bin")
	content := []byte("archive member")
	if err := os.WriteFile(source, content, 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(t.TempDir(), "member-link.bin")
	if err := os.Symlink(source, link); err != nil {
		t.Skipf("symlinks are unavailable: %v", err)
	}
	digest := sha256Hex(content)
	if _, err := storage.Publish(context.Background(), link, int64(len(content)), digest); !errors.Is(err, ErrSourceUnavailable) {
		t.Fatalf("Publish() error = %v, want ErrSourceUnavailable", err)
	}
}

func TestBlobStoragePublishRejectsSourceReplacementAfterOpen(t *testing.T) {
	repository := t.TempDir()
	storage, err := NewBlobStorage(repository)
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	source := filepath.Join(directory, "member.bin")
	original := []byte("original archive member")
	if err := os.WriteFile(source, original, 0o600); err != nil {
		t.Fatal(err)
	}
	var hookErr error
	storage.afterSourceOpen = func() {
		hookErr = os.Rename(source, source+".original")
		if hookErr == nil {
			hookErr = os.WriteFile(source, []byte("replacement bytes here"), 0o600)
		}
	}
	digest := sha256Hex(original)
	_, err = storage.Publish(context.Background(), source, int64(len(original)), digest)
	if hookErr != nil {
		t.Fatal(hookErr)
	}
	if !errors.Is(err, ErrSourceUnavailable) {
		t.Fatalf("Publish() error = %v, want ErrSourceUnavailable", err)
	}
	final := filepath.Join(repository, "blobs", "sha256", digest[:2], digest)
	if _, err := os.Lstat(final); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("final blob exists after source replacement: %v", err)
	}
}

func TestBlobStoragePublishRejectsExistingFinalSymlink(t *testing.T) {
	repository := t.TempDir()
	storage, err := NewBlobStorage(repository)
	if err != nil {
		t.Fatal(err)
	}
	content := []byte("archive member")
	source := filepath.Join(t.TempDir(), "member.bin")
	if err := os.WriteFile(source, content, 0o600); err != nil {
		t.Fatal(err)
	}
	digest := sha256Hex(content)
	directory := filepath.Join(repository, "blobs", "sha256", digest[:2])
	if err := os.MkdirAll(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(t.TempDir(), "outside.bin")
	if err := os.WriteFile(target, content, 0o600); err != nil {
		t.Fatal(err)
	}
	final := filepath.Join(directory, digest)
	if err := os.Symlink(target, final); err != nil {
		t.Skipf("symlinks are unavailable: %v", err)
	}
	if _, err := storage.Publish(context.Background(), source, int64(len(content)), digest); !errors.Is(err, ErrConflict) {
		t.Fatalf("Publish() error = %v, want ErrConflict", err)
	}
	info, err := os.Lstat(final)
	if err != nil || info.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("existing final symlink was altered: info=%v err=%v", info, err)
	}
}

func TestBlobStoragePublishRejectsSymlinkedCanonicalParent(t *testing.T) {
	repository := t.TempDir()
	storage, err := NewBlobStorage(repository)
	if err != nil {
		t.Fatal(err)
	}
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(repository, "blobs")); err != nil {
		t.Skipf("symlinks are unavailable: %v", err)
	}
	content := []byte("archive member")
	source := filepath.Join(t.TempDir(), "member.bin")
	if err := os.WriteFile(source, content, 0o600); err != nil {
		t.Fatal(err)
	}
	digest := sha256Hex(content)
	if _, err := storage.Publish(context.Background(), source, int64(len(content)), digest); err == nil {
		t.Fatal("Publish() succeeded through a symlinked canonical parent")
	}
	if entries, err := os.ReadDir(outside); err != nil || len(entries) != 0 {
		t.Fatalf("outside directory changed: entries=%v err=%v", entries, err)
	}
}

func TestBlobStoragePublishCreatesAndReusesCanonicalBlob(t *testing.T) {
	repository := t.TempDir()
	storage, err := NewBlobStorage(repository)
	if err != nil {
		t.Fatal(err)
	}
	content := []byte("archive member")
	source := filepath.Join(t.TempDir(), "member.bin")
	if err := os.WriteFile(source, content, 0o600); err != nil {
		t.Fatal(err)
	}
	digest := sha256Hex(content)
	want := "blobs/sha256/" + digest[:2] + "/" + digest
	for attempt := 0; attempt < 2; attempt++ {
		key, err := storage.Publish(context.Background(), source, int64(len(content)), digest)
		if err != nil {
			t.Fatalf("Publish() attempt %d: %v", attempt+1, err)
		}
		if key != want {
			t.Fatalf("storage key = %q, want %q", key, want)
		}
	}
	stored, err := os.ReadFile(filepath.Join(repository, filepath.FromSlash(want)))
	if err != nil {
		t.Fatal(err)
	}
	if string(stored) != string(content) {
		t.Fatalf("stored content = %q, want %q", stored, content)
	}
}

func sha256Hex(value []byte) string {
	digest := sha256.Sum256(value)
	return hex.EncodeToString(digest[:])
}

func verifiedBlobFixture(t *testing.T) (*BlobStorage, string, string, string, []byte) {
	t.Helper()
	repository := t.TempDir()
	storage, err := NewBlobStorage(repository)
	if err != nil {
		t.Fatal(err)
	}
	content := []byte("verified-content!")
	digest := sha256Hex(content)
	key := "blobs/sha256/" + digest[:2] + "/" + digest
	path := filepath.Join(repository, filepath.FromSlash(key))
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatal(err)
	}
	return storage, repository, key, digest, content
}

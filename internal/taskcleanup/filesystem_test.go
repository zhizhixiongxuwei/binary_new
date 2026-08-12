package taskcleanup

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

const (
	testTaskID     = "123e4567-e89b-42d3-a456-426614174000"
	testReportID   = "123e4567-e89b-42d3-a456-426614174001"
	testArtifactID = "523e4567-e89b-52d3-a456-426614174002"
	testResultID   = "123e4567-e89b-42d3-a456-426614174003"
)

func TestRepositoryFileDeleterRemovesVerifiedFilesAndOwnedScopes(
	t *testing.T,
) {
	root := t.TempDir()
	outside := filepath.Join(t.TempDir(), "outside")
	if err := os.WriteFile(outside, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	reportContent := []byte(`{"status":"complete"}`)
	reportKey := filepath.Join(
		"reports", testTaskID, testReportID+".json",
	)
	writeCleanupFile(t, root, reportKey, reportContent)
	staging := filepath.Join(
		root, "reports", testTaskID, "."+testReportID+".staging",
	)
	if err := os.WriteFile(staging, []byte("staged"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "reports", testTaskID, "outside-link")
	if err := os.Symlink(outside, link); err != nil {
		t.Fatal(err)
	}
	deleter, err := NewRepositoryFileDeleter(root)
	if err != nil {
		t.Fatal(err)
	}
	removed, err := deleter.DeleteFile(context.Background(), StoredFile{
		Kind: FileReport, TaskID: testTaskID, RecordID: testReportID,
		Format: "json", StorageKey: filepath.ToSlash(reportKey),
		SHA256: cleanupSHA(reportContent), SizeBytes: int64(len(reportContent)),
	})
	if err != nil || !removed {
		t.Fatalf("DeleteFile() = (%v, %v)", removed, err)
	}
	removed, err = deleter.DeleteFile(context.Background(), StoredFile{
		Kind: FileReport, TaskID: testTaskID, RecordID: testReportID,
		Format: "json", StorageKey: filepath.ToSlash(reportKey),
		SHA256: cleanupSHA(reportContent), SizeBytes: int64(len(reportContent)),
	})
	if err != nil || removed {
		t.Fatalf("replayed DeleteFile() = (%v, %v)", removed, err)
	}
	if err := deleter.DeleteScope(context.Background(), Scope{
		Kind: FileReport, TaskID: testTaskID,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(filepath.Join(root, "reports", testTaskID)); !errors.Is(
		err, os.ErrNotExist,
	) {
		t.Fatalf("report scope still exists: %v", err)
	}
	content, err := os.ReadFile(outside)
	if err != nil || string(content) != "keep" {
		t.Fatalf("scope deletion followed outside symlink: %q, %v", content, err)
	}
}

func TestRepositoryFileDeleterRejectsEscapesTamperingAndHardlinks(
	t *testing.T,
) {
	root := t.TempDir()
	deleter, err := NewRepositoryFileDeleter(root)
	if err != nil {
		t.Fatal(err)
	}
	content := []byte("expected")
	pathKey := filepath.Join(
		"decompile", testResultID, "Deleted.java",
	)
	writeCleanupFile(t, root, pathKey, []byte("tampered"))
	_, err = deleter.DeleteFile(context.Background(), StoredFile{
		Kind: FileDecompile, TaskID: testTaskID, RecordID: testResultID,
		StorageKey: filepath.ToSlash(pathKey), SHA256: cleanupSHA(content),
		SizeBytes: int64(len(content)),
	})
	if err == nil {
		t.Fatal("DeleteFile() accepted tampered output")
	}
	if _, err := os.Stat(filepath.Join(root, pathKey)); err != nil {
		t.Fatalf("tampered output was removed: %v", err)
	}
	_, err = deleter.DeleteFile(context.Background(), StoredFile{
		Kind: FileArtifact, TaskID: testTaskID, RecordID: testArtifactID,
		StorageKey: "../outside", SHA256: cleanupSHA(content),
		SizeBytes: int64(len(content)),
	})
	if err == nil {
		t.Fatal("DeleteFile() accepted parent traversal")
	}

	scopeDir := filepath.Join(root, "artifacts", testTaskID)
	if err := os.MkdirAll(scopeDir, 0o700); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(t.TempDir(), "outside")
	if err := os.WriteFile(outside, []byte("linked"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(outside, filepath.Join(scopeDir, "linked")); err != nil {
		t.Fatal(err)
	}
	if err := deleter.DeleteScope(context.Background(), Scope{
		Kind: FileArtifact, TaskID: testTaskID,
	}); err == nil {
		t.Fatal("DeleteScope() accepted a multi-link file")
	}
	if _, err := os.Stat(outside); err != nil {
		t.Fatalf("outside hardlink target was removed: %v", err)
	}
}

func TestRepositoryFileDeleterRemovesSourceProjectRootWithoutFollowingLinks(
	t *testing.T,
) {
	root := t.TempDir()
	projectID := "623e4567-e89b-42d3-a456-426614174006"
	projectRoot := filepath.Join(root, "source-projects", projectID)
	if err := os.MkdirAll(filepath.Join(projectRoot, "src"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(
		filepath.Join(projectRoot, "src", "decompiled.c"), []byte("void f() {}"), 0o600,
	); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(t.TempDir(), "keep")
	if err := os.WriteFile(outside, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(projectRoot, "outside-link")); err != nil {
		t.Fatal(err)
	}
	deleter, err := NewRepositoryFileDeleter(root)
	if err != nil {
		t.Fatal(err)
	}
	if err := deleter.DeleteScope(context.Background(), Scope{
		Kind: FileSourceProject, TaskID: testTaskID, RecordID: projectID,
	}); err != nil {
		t.Fatal(err)
	}
	if err := deleter.DeleteScope(context.Background(), Scope{
		Kind: FileSourceProject, TaskID: testTaskID, RecordID: projectID,
	}); err != nil {
		t.Fatalf("replayed source project cleanup: %v", err)
	}
	if _, err := os.Lstat(projectRoot); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("source project root still exists: %v", err)
	}
	content, err := os.ReadFile(outside)
	if err != nil || string(content) != "keep" {
		t.Fatalf("source project cleanup followed symlink: %q, %v", content, err)
	}
}

func TestRepositoryFileDeleterDetectsRootReplacement(t *testing.T) {
	parent := t.TempDir()
	root := filepath.Join(parent, "repository")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	deleter, err := NewRepositoryFileDeleter(root)
	if err != nil {
		t.Fatal(err)
	}
	old := filepath.Join(parent, "old")
	if err := os.Rename(root, old); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	err = deleter.DeleteScope(context.Background(), Scope{
		Kind: FileReport, TaskID: testTaskID,
	})
	if err == nil {
		t.Fatal("DeleteScope() accepted a replaced repository root")
	}
}

func writeCleanupFile(
	t *testing.T,
	root string,
	key string,
	content []byte,
) {
	t.Helper()
	full := filepath.Join(root, key)
	if err := os.MkdirAll(filepath.Dir(full), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, content, 0o600); err != nil {
		t.Fatal(err)
	}
}

func cleanupSHA(content []byte) string {
	sum := sha256.Sum256(content)
	return hex.EncodeToString(sum[:])
}

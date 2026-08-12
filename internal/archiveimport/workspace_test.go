package archiveimport

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

const workspaceTestImportID = "11111111-1111-4111-8111-111111111111"

func TestSafeWorkspaceRejectsIntermediateSymlink(t *testing.T) {
	workRoot := t.TempDir()
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(workRoot, "archive-imports")); err != nil {
		t.Skipf("symlinks are unavailable: %v", err)
	}
	root, err := newSafeWorkspaceRoot(workRoot)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := root.Create(Lease{
		Import: Import{ID: workspaceTestImportID, FencingToken: 1},
	}); err == nil {
		t.Fatal("Create() accepted a symlinked workspace namespace")
	}
	entries, err := os.ReadDir(outside)
	if err != nil || len(entries) != 0 {
		t.Fatalf("outside directory changed: entries=%v err=%v", entries, err)
	}
}

func TestSafeWorkspaceCleanupDoesNotDeleteReplacement(t *testing.T) {
	workRoot := t.TempDir()
	root, err := newSafeWorkspaceRoot(workRoot)
	if err != nil {
		t.Fatal(err)
	}
	workspace, err := root.Create(Lease{
		Import: Import{ID: workspaceTestImportID, FencingToken: 7},
	})
	if err != nil {
		t.Fatal(err)
	}
	canonical := filepath.Join(
		workRoot, "archive-imports", workspaceTestImportID, "7",
	)
	if err := os.WriteFile(filepath.Join(canonical, "owned.tmp"), []byte("owned"), 0o600); err != nil {
		t.Fatal(err)
	}
	moved := canonical + ".moved"
	if err := os.Rename(canonical, moved); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(canonical, 0o700); err != nil {
		t.Fatal(err)
	}
	sentinel := filepath.Join(canonical, "replacement.sentinel")
	if err := os.WriteFile(sentinel, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := workspace.Close(); err == nil {
		t.Fatal("Close() did not report a replaced fenced workspace")
	}
	if value, err := os.ReadFile(sentinel); err != nil || string(value) != "keep" {
		t.Fatalf("replacement sentinel changed: value=%q err=%v", value, err)
	}
	if _, err := os.Lstat(filepath.Join(moved, "owned.tmp")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("descriptor-bound original workspace was not cleaned: %v", err)
	}
}

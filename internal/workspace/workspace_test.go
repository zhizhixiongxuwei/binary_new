package workspace

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

type leaseCheckerStub struct {
	mu       sync.Mutex
	active   map[Identity]bool
	err      error
	onCheck  func(Identity) (bool, error)
	requests []Identity
}

func (s *leaseCheckerStub) WorkspaceLeaseActive(
	_ context.Context,
	identity Identity,
) (bool, error) {
	s.mu.Lock()
	s.requests = append(s.requests, identity)
	onCheck := s.onCheck
	s.mu.Unlock()
	if onCheck != nil {
		return onCheck(identity)
	}
	return s.active[identity], s.err
}

func TestCreateWritesBoundMarkerAndCleanupRemovesDirectory(t *testing.T) {
	root := t.TempDir()
	identity := testIdentity(1)
	directory, err := Create(root, identity)
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(directory.Path())
	if err != nil {
		t.Fatal(err)
	}
	if !info.IsDir() || info.Mode().Perm() != 0o700 {
		t.Fatalf("workspace mode = %v", info.Mode())
	}
	name := filepath.Base(directory.Path())
	if !safeWorkspaceName(name) ||
		!strings.HasPrefix(name, directoryPrefix(identity)) {
		t.Fatalf("workspace name %q is not bound to %+v", name, identity)
	}
	markerInfo, err := os.Lstat(
		filepath.Join(directory.Path(), markerFileName),
	)
	if err != nil {
		t.Fatal(err)
	}
	if !markerInfo.Mode().IsRegular() || markerInfo.Mode().Perm() != 0o600 {
		t.Fatalf("marker mode = %v", markerInfo.Mode())
	}
	content, err := os.ReadFile(
		filepath.Join(directory.Path(), markerFileName),
	)
	if err != nil {
		t.Fatal(err)
	}
	expected, err := canonicalMarker(identity)
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != string(expected) {
		t.Fatalf("marker = %q, want %q", content, expected)
	}
	if _, err := os.Lstat(
		filepath.Join(directory.Path(), pendingMarkerFileName),
	); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("pending marker remains after publish: %v", err)
	}
	if err := directory.Cleanup(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(directory.Path()); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("workspace still exists: %v", err)
	}
	if err := directory.Cleanup(); err != nil {
		t.Fatalf("idempotent Cleanup() error = %v", err)
	}
}

func TestPrepareCreatedDirectoryRejectsReplacementBeforeChmod(t *testing.T) {
	t.Run("directory", func(t *testing.T) {
		root := t.TempDir()
		name := "created"
		path := filepath.Join(root, name)
		if err := os.Mkdir(path, 0o700); err != nil {
			t.Fatal(err)
		}
		expected, err := os.Lstat(path)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(path, path+".moved"); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(path, 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, 0o750); err != nil {
			t.Fatal(err)
		}
		parent, err := os.Open(root)
		if err != nil {
			t.Fatal(err)
		}

		_, prepareErr := prepareCreatedDirectory(parent, name, expected)
		closeErr := parent.Close()

		if !errors.Is(prepareErr, ErrUnsafeWorkspace) {
			t.Fatalf(
				"prepareCreatedDirectory() error = %v, want ErrUnsafeWorkspace",
				prepareErr,
			)
		}
		if closeErr != nil {
			t.Fatal(closeErr)
		}
		info, err := os.Lstat(path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o750 {
			t.Fatalf("replacement mode = %o, want 0750", info.Mode().Perm())
		}
	})

	t.Run("symlink", func(t *testing.T) {
		root := t.TempDir()
		name := "created"
		path := filepath.Join(root, name)
		if err := os.Mkdir(path, 0o700); err != nil {
			t.Fatal(err)
		}
		expected, err := os.Lstat(path)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(path, path+".moved"); err != nil {
			t.Fatal(err)
		}
		target := t.TempDir()
		if err := os.Chmod(target, 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, path); err != nil {
			t.Fatal(err)
		}
		parent, err := os.Open(root)
		if err != nil {
			t.Fatal(err)
		}

		_, prepareErr := prepareCreatedDirectory(parent, name, expected)
		closeErr := parent.Close()

		if !errors.Is(prepareErr, ErrUnsafeWorkspace) {
			t.Fatalf(
				"prepareCreatedDirectory() error = %v, want ErrUnsafeWorkspace",
				prepareErr,
			)
		}
		if closeErr != nil {
			t.Fatal(closeErr)
		}
		info, err := os.Lstat(target)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o750 {
			t.Fatalf("symlink target mode = %o, want 0750", info.Mode().Perm())
		}
	})
}

func TestCleanupReportsReplacedWorkspaceAndDoesNotFollowSymlink(t *testing.T) {
	root := t.TempDir()
	directory, err := Create(root, testIdentity(2))
	if err != nil {
		t.Fatal(err)
	}
	original := directory.Path()
	moved := original + ".moved"
	if err := os.Rename(original, moved); err != nil {
		t.Fatal(err)
	}
	outside := t.TempDir()
	sentinel := filepath.Join(outside, "keep")
	if err := os.WriteFile(sentinel, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, original); err != nil {
		t.Fatal(err)
	}

	err = directory.Cleanup()
	if !errors.Is(err, ErrUnsafeWorkspace) {
		t.Fatalf("Cleanup() error = %v, want ErrUnsafeWorkspace", err)
	}
	if content, err := os.ReadFile(sentinel); err != nil ||
		string(content) != "keep" {
		t.Fatalf("outside sentinel changed: %q, %v", content, err)
	}
}

func TestCleanupRecursesWithoutFollowingWorkspaceChildSymlink(t *testing.T) {
	root := t.TempDir()
	directory, err := Create(root, testIdentity(15))
	if err != nil {
		t.Fatal(err)
	}
	nested := filepath.Join(directory.Path(), "nested")
	if err := os.Mkdir(nested, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(
		filepath.Join(nested, "payload"),
		[]byte("payload"),
		0o600,
	); err != nil {
		t.Fatal(err)
	}
	outside := t.TempDir()
	sentinel := filepath.Join(outside, "keep")
	if err := os.WriteFile(sentinel, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(nested, "outside")); err != nil {
		t.Fatal(err)
	}

	if err := directory.Cleanup(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(directory.Path()); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("workspace still exists: %v", err)
	}
	if content, err := os.ReadFile(sentinel); err != nil ||
		string(content) != "keep" {
		t.Fatalf("outside sentinel changed: %q, %v", content, err)
	}
}

func TestRemoveRootedTreeRejectsReplacementAgainstExpectedInode(t *testing.T) {
	rootPath := t.TempDir()
	name := directoryPrefix(testIdentity(16)) + strings.Repeat("b", 32)
	original := filepath.Join(rootPath, name)
	if err := os.Mkdir(original, 0o700); err != nil {
		t.Fatal(err)
	}
	expected, err := os.Lstat(original)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(original, original+".moved"); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(original, 0o700); err != nil {
		t.Fatal(err)
	}
	sentinel := filepath.Join(original, "replacement")
	if err := os.WriteFile(sentinel, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(rootPath)
	if err != nil {
		t.Fatal(err)
	}
	err = removeRootedTree(root, name, expected)
	closeErr := root.Close()
	if !errors.Is(err, ErrUnsafeWorkspace) {
		t.Fatalf("removeRootedTree() error = %v, want ErrUnsafeWorkspace", err)
	}
	if closeErr != nil {
		t.Fatal(closeErr)
	}
	if content, err := os.ReadFile(sentinel); err != nil ||
		string(content) != "keep" {
		t.Fatalf("replacement sentinel changed: %q, %v", content, err)
	}
}

func TestReaperRetainsActiveAndRemovesInactiveWorkspaces(t *testing.T) {
	root := t.TempDir()
	activeIdentity := testIdentity(3)
	expiredIdentity := testIdentity(4)
	expiredIdentity.Kind = "decompile"
	completedIdentity := testIdentity(10)
	activeDirectory := createAbandonedWorkspace(t, root, activeIdentity)
	expiredDirectory := createAbandonedWorkspace(t, root, expiredIdentity)
	completedDirectory := createAbandonedWorkspace(t, root, completedIdentity)
	checker := &leaseCheckerStub{
		active: map[Identity]bool{activeIdentity: true},
	}
	reaper, err := NewReaper(root, checker)
	if err != nil {
		t.Fatal(err)
	}

	report, err := reaper.Sweep(context.Background(), 10)
	if err != nil {
		t.Fatal(err)
	}
	if report.Scanned != 3 || report.Active != 1 ||
		report.Removed != 2 || report.Skipped != 0 {
		t.Fatalf("Sweep() report = %+v", report)
	}
	if _, err := os.Lstat(activeDirectory); err != nil {
		t.Fatalf("active workspace was removed: %v", err)
	}
	for label, directory := range map[string]string{
		"expired": expiredDirectory, "completed": completedDirectory,
	} {
		if _, err := os.Lstat(directory); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("%s workspace was retained: %v", label, err)
		}
	}
}

func TestReaperRejectsReplacedWorkspaceRoot(t *testing.T) {
	parent := t.TempDir()
	root := filepath.Join(parent, "task-work")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	checker := &leaseCheckerStub{active: map[Identity]bool{}}
	reaper, err := NewReaper(root, checker)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(root, root+".moved"); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	sentinel := filepath.Join(root, "keep")
	if err := os.WriteFile(sentinel, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}

	_, err = reaper.Sweep(context.Background(), 1)
	if !errors.Is(err, ErrUnsafeWorkspace) {
		t.Fatalf("Sweep() error = %v, want ErrUnsafeWorkspace", err)
	}
	if content, err := os.ReadFile(sentinel); err != nil ||
		string(content) != "keep" {
		t.Fatalf("replacement root sentinel changed: %q, %v", content, err)
	}
	if len(checker.requests) != 0 {
		t.Fatalf("lease checker requests = %+v", checker.requests)
	}
}

func TestReaperSkipsCorruptMarkerAndSymlinkWithoutFollowing(t *testing.T) {
	root := t.TempDir()
	corrupt := createAbandonedWorkspace(t, root, testIdentity(5))
	marker := filepath.Join(corrupt, markerFileName)
	if err := os.WriteFile(marker, []byte("{broken\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	outside := t.TempDir()
	sentinel := filepath.Join(outside, "keep")
	if err := os.WriteFile(sentinel, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	symlinkName := directoryPrefix(testIdentity(6)) + strings.Repeat("a", 32)
	symlinkPath := filepath.Join(root, symlinkName)
	if err := os.Symlink(outside, symlinkPath); err != nil {
		t.Fatal(err)
	}
	checker := &leaseCheckerStub{active: map[Identity]bool{}}
	reaper, err := NewReaper(root, checker)
	if err != nil {
		t.Fatal(err)
	}

	report, err := reaper.Sweep(context.Background(), 10)
	if err != nil {
		t.Fatal(err)
	}
	if report.Scanned != 2 || report.Removed != 0 ||
		report.Skipped != 2 || len(report.Diagnostics) != 2 {
		t.Fatalf("Sweep() report = %+v", report)
	}
	if _, err := os.Lstat(corrupt); err != nil {
		t.Fatalf("corrupt workspace was removed: %v", err)
	}
	if info, err := os.Lstat(symlinkPath); err != nil ||
		info.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("workspace symlink changed: %v, %v", info, err)
	}
	if content, err := os.ReadFile(sentinel); err != nil ||
		string(content) != "keep" {
		t.Fatalf("outside sentinel changed: %q, %v", content, err)
	}
	if len(checker.requests) != 0 {
		t.Fatalf("lease checker received unsafe candidates: %+v", checker.requests)
	}
}

func TestReaperIgnoresValidInstallOwnershipMarkerWithoutUsingBatch(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(
		filepath.Join(root, ownershipMarkerName),
		[]byte("123e4567-e89b-42d3-a456-426614174000\n"),
		ownershipMarkerMode,
	); err != nil {
		t.Fatal(err)
	}
	inactiveIdentity := testIdentity(14)
	inactiveDirectory := createAbandonedWorkspace(t, root, inactiveIdentity)
	checker := &leaseCheckerStub{active: map[Identity]bool{}}
	reaper, err := NewReaper(root, checker)
	if err != nil {
		t.Fatal(err)
	}

	report, err := reaper.Sweep(context.Background(), 1)
	if err != nil {
		t.Fatal(err)
	}
	if report.Scanned != 1 || report.Removed != 1 || report.Skipped != 0 {
		t.Fatalf("Sweep() report = %+v", report)
	}
	if _, err := os.Lstat(inactiveDirectory); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("inactive workspace was retained: %v", err)
	}
	if len(checker.requests) != 1 ||
		checker.requests[0] != inactiveIdentity {
		t.Fatalf("lease checker requests = %+v", checker.requests)
	}
	if info, err := os.Lstat(filepath.Join(root, ownershipMarkerName)); err != nil ||
		!exactOwnershipMarker(info) {
		t.Fatalf("ownership marker changed: %v, %v", info, err)
	}
}

func TestReaperDiagnosesSymlinkInstallOwnershipMarker(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	sentinel := filepath.Join(outside, "keep")
	if err := os.WriteFile(sentinel, []byte("keep"), ownershipMarkerMode); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(sentinel, filepath.Join(root, ownershipMarkerName)); err != nil {
		t.Fatal(err)
	}
	checker := &leaseCheckerStub{active: map[Identity]bool{}}
	reaper, err := NewReaper(root, checker)
	if err != nil {
		t.Fatal(err)
	}

	report, err := reaper.Sweep(context.Background(), 1)
	if err != nil {
		t.Fatal(err)
	}
	if report.Scanned != 1 || report.Removed != 0 ||
		report.Skipped != 1 || len(report.Diagnostics) != 1 {
		t.Fatalf("Sweep() report = %+v", report)
	}
	if content, err := os.ReadFile(sentinel); err != nil ||
		string(content) != "keep" {
		t.Fatalf("outside sentinel changed: %q, %v", content, err)
	}
	if len(checker.requests) != 0 {
		t.Fatalf("lease checker received metadata: %+v", checker.requests)
	}
}

func TestReaperRecoversAtomicallyUnpublishedMarkerDirectories(t *testing.T) {
	root := t.TempDir()
	activeIdentity := testIdentity(11)
	inactiveIdentity := testIdentity(12)
	activeDirectory := createAbandonedWorkspace(t, root, activeIdentity)
	inactiveDirectory := createAbandonedWorkspace(t, root, inactiveIdentity)
	for _, directory := range []string{activeDirectory, inactiveDirectory} {
		if err := os.Remove(filepath.Join(directory, markerFileName)); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(
		filepath.Join(inactiveDirectory, pendingMarkerFileName),
		[]byte("{interrupted"),
		0o600,
	); err != nil {
		t.Fatal(err)
	}
	checker := &leaseCheckerStub{
		active: map[Identity]bool{activeIdentity: true},
	}
	reaper, err := NewReaper(root, checker)
	if err != nil {
		t.Fatal(err)
	}

	report, err := reaper.Sweep(context.Background(), 10)
	if err != nil {
		t.Fatal(err)
	}
	if report.Scanned != 2 || report.Active != 1 ||
		report.Removed != 1 || report.Skipped != 0 {
		t.Fatalf("Sweep() report = %+v", report)
	}
	if _, err := os.Lstat(activeDirectory); err != nil {
		t.Fatalf("active interrupted workspace was removed: %v", err)
	}
	if _, err := os.Lstat(inactiveDirectory); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("inactive interrupted workspace was retained: %v", err)
	}
	if len(checker.requests) != 2 {
		t.Fatalf("lease checker requests = %+v", checker.requests)
	}
}

func TestReaperDoesNotDeleteWhenMarkerAppearsDuringLeaseCheck(t *testing.T) {
	root := t.TempDir()
	identity := testIdentity(13)
	directory := createAbandonedWorkspace(t, root, identity)
	markerPath := filepath.Join(directory, markerFileName)
	if err := os.Remove(markerPath); err != nil {
		t.Fatal(err)
	}
	checker := &leaseCheckerStub{
		onCheck: func(request Identity) (bool, error) {
			content, err := canonicalMarker(request)
			if err != nil {
				return false, err
			}
			if err := os.WriteFile(markerPath, content, 0o600); err != nil {
				return false, err
			}
			return false, nil
		},
	}
	reaper, err := NewReaper(root, checker)
	if err != nil {
		t.Fatal(err)
	}

	report, err := reaper.Sweep(context.Background(), 10)
	if err != nil {
		t.Fatal(err)
	}
	if report.Scanned != 1 || report.Removed != 0 ||
		report.Skipped != 1 || len(report.Diagnostics) != 1 {
		t.Fatalf("Sweep() report = %+v", report)
	}
	if _, err := os.Lstat(directory); err != nil {
		t.Fatalf("workspace changed during check was removed: %v", err)
	}
}

func TestReaperHonorsBatchLimitAndAdvancesCursor(t *testing.T) {
	root := t.TempDir()
	paths := make([]string, 0, 3)
	for index := 7; index <= 9; index++ {
		paths = append(
			paths,
			createAbandonedWorkspace(t, root, testIdentity(index)),
		)
	}
	reaper, err := NewReaper(
		root,
		&leaseCheckerStub{active: map[Identity]bool{}},
	)
	if err != nil {
		t.Fatal(err)
	}

	first, err := reaper.Sweep(context.Background(), 2)
	if err != nil {
		t.Fatal(err)
	}
	second, err := reaper.Sweep(context.Background(), 2)
	if err != nil {
		t.Fatal(err)
	}
	if first.Scanned != 2 || first.Removed != 2 ||
		second.Scanned != 1 || second.Removed != 1 {
		t.Fatalf("batch reports = first %+v second %+v", first, second)
	}
	for _, candidate := range paths {
		if _, err := os.Lstat(candidate); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("workspace %q was retained: %v", candidate, err)
		}
	}
}

func createAbandonedWorkspace(
	t *testing.T,
	root string,
	identity Identity,
) string {
	t.Helper()
	directory, err := Create(root, identity)
	if err != nil {
		t.Fatal(err)
	}
	directory.mu.Lock()
	if err := directory.root.Close(); err != nil {
		directory.mu.Unlock()
		t.Fatal(err)
	}
	directory.closed = true
	directory.mu.Unlock()
	return directory.Path()
}

func testIdentity(index int) Identity {
	return Identity{
		JobID:         fmtUUID(index*2 + 1),
		TaskID:        fmtUUID(index*2 + 2),
		TaskAttemptID: uint64(index + 10),
		FencingToken:  uint64(index + 20),
		Kind:          "scan",
	}
}

func TestCreateSupportsFencedTrivyWorkspace(t *testing.T) {
	root := t.TempDir()
	identity := testIdentity(101)
	identity.Kind = "trivy"
	directory, err := Create(root, identity)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(filepath.Base(directory.Path()), "-trivy-") {
		t.Fatalf("workspace path = %q", directory.Path())
	}
	if err := directory.Cleanup(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(directory.Path()); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("Trivy workspace still exists: %v", err)
	}
}

func TestCreateSupportsFencedManualImageWorkspace(t *testing.T) {
	root := t.TempDir()
	identity := testIdentity(103)
	identity.Kind = "image"
	directory, err := Create(root, identity)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(filepath.Base(directory.Path()), "-image-") {
		t.Fatalf("workspace path = %q", directory.Path())
	}
	if err := directory.Cleanup(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(directory.Path()); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("manual image workspace still exists: %v", err)
	}
}

func TestCreateSupportsFencedDecompileWorkspace(t *testing.T) {
	root := t.TempDir()
	identity := testIdentity(102)
	identity.Kind = "decompile"
	directory, err := Create(root, identity)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(filepath.Base(directory.Path()), "-decompile-") {
		t.Fatalf("workspace path = %q", directory.Path())
	}
	if err := directory.Cleanup(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(directory.Path()); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("decompile workspace still exists: %v", err)
	}
}

func fmtUUID(value int) string {
	return "123e4567-e89b-42d3-a456-" +
		fmt.Sprintf("%012x", value)
}

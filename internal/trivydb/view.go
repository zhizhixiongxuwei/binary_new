package trivydb

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"sync"

	"golang.org/x/sys/unix"
)

// CacheView is a read-only Trivy cache rooted at Path. Close is idempotent
// after a successful cleanup.
type CacheView struct {
	mu        sync.Mutex
	workspace *os.File
	path      string
	identity  fileIdentity
	names     []string
	snapshot  Snapshot
	closed    bool
}

// Path returns the cache directory passed to Trivy's --cache-dir.
func (v *CacheView) Path() string {
	if v == nil {
		return ""
	}
	return v.path
}

// Snapshot returns a defensive copy of the exact database identities exposed
// by this view.
func (v *CacheView) Snapshot() Snapshot {
	if v == nil {
		return Snapshot{}
	}
	return cloneSnapshot(v.snapshot)
}

// CreateCacheView builds and atomically publishes "trivy-cache" directly
// inside workspaceRoot. workspaceRoot must be an existing absolute,
// non-symlink per-job directory outside TrivyRoot.
func (r *Resolver) CreateCacheView(
	ctx context.Context,
	workspaceRoot string,
	snapshot Snapshot,
) (*CacheView, error) {
	if r == nil {
		return nil, fmt.Errorf("%w: nil resolver", ErrInvalidConfiguration)
	}
	if workspaceRoot == "" ||
		!filepath.IsAbs(workspaceRoot) ||
		filepath.Clean(workspaceRoot) != workspaceRoot {
		return nil, fmt.Errorf(
			"%w: workspace root must be an absolute clean path",
			ErrInvalidConfiguration,
		)
	}
	if pathsOverlap(r.trivyRoot, workspaceRoot) {
		return nil, fmt.Errorf(
			"%w: workspace and TrivyRoot must not overlap",
			ErrInvalidConfiguration,
		)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	sources, err := r.openSnapshotSources(ctx, snapshot)
	if err != nil {
		return nil, err
	}
	defer closeOpenedVersions(sources)

	workspace, err := openRoot(workspaceRoot)
	if err != nil {
		return nil, fmt.Errorf("%w: open workspace root: %v", ErrUnsafeStorage, err)
	}
	for _, source := range sources {
		if workspace.identity.sameFile(source.identity) {
			_ = workspace.close()
			return nil, fmt.Errorf(
				"%w: workspace is an active database version directory",
				ErrInvalidConfiguration,
			)
		}
	}
	keepWorkspace := false
	defer func() {
		if !keepWorkspace {
			_ = workspace.close()
		}
	}()

	stageName, err := createStageDirectory(int(workspace.file.Fd()))
	if err != nil {
		return nil, err
	}
	stageFD, err := unix.Openat(
		int(workspace.file.Fd()),
		stageName,
		unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC,
		0,
	)
	if err != nil {
		_ = unix.Unlinkat(
			int(workspace.file.Fd()),
			stageName,
			unix.AT_REMOVEDIR,
		)
		return nil, fmt.Errorf("open Trivy cache staging directory: %w", err)
	}
	stage := os.NewFile(uintptr(stageFD), stageName)
	if stage == nil {
		_ = unix.Close(stageFD)
		_ = unix.Unlinkat(
			int(workspace.file.Fd()),
			stageName,
			unix.AT_REMOVEDIR,
		)
		return nil, errors.New("wrap Trivy cache staging descriptor")
	}
	stageIdentity, err := descriptorIdentity(int(stage.Fd()))
	if err != nil {
		_ = stage.Close()
		_ = unix.Unlinkat(
			int(workspace.file.Fd()),
			stageName,
			unix.AT_REMOVEDIR,
		)
		return nil, fmt.Errorf("identify Trivy cache staging directory: %w", err)
	}
	published := false
	cleanupName := stageName
	defer func() {
		_ = stage.Close()
		if !keepWorkspace {
			_ = cleanupViewAt(
				int(workspace.file.Fd()),
				cleanupName,
				sources,
				stageIdentity,
			)
		}
	}()

	names := make([]string, 0, len(sources))
	for _, source := range sources {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if err := unix.Symlinkat(
			source.target,
			int(stage.Fd()),
			source.viewName,
		); err != nil {
			return nil, fmt.Errorf(
				"create %s cache link: %w",
				source.viewName,
				err,
			)
		}
		if err := verifyViewLink(stage, source); err != nil {
			return nil, err
		}
		names = append(names, source.viewName)
	}
	slices.Sort(names)
	if err := stage.Chmod(0o500); err != nil {
		return nil, fmt.Errorf("seal Trivy cache view: %w", err)
	}
	if err := stage.Sync(); err != nil {
		return nil, fmt.Errorf("sync Trivy cache view: %w", err)
	}
	if err := renameDirectoryNoReplaceAt(
		int(workspace.file.Fd()),
		stageName,
		cacheViewName,
	); err != nil {
		if errors.Is(err, errRenameDestinationExists) {
			return nil, ErrCacheViewExists
		}
		return nil, fmt.Errorf("publish Trivy cache view: %w", err)
	}
	published = true
	cleanupName = cacheViewName
	if err := workspace.file.Sync(); err != nil {
		return nil, fmt.Errorf("sync workspace after cache publish: %w", err)
	}
	finalIdentity, err := statAtNoFollow(
		int(workspace.file.Fd()),
		cacheViewName,
	)
	if err != nil ||
		!finalIdentity.isDirectory() ||
		!stageIdentity.sameFile(finalIdentity) {
		return nil, fmt.Errorf(
			"%w: cache view changed during publish",
			ErrUnsafeStorage,
		)
	}
	if !published {
		return nil, errors.New("Trivy cache view was not published")
	}

	keepWorkspace = true
	return &CacheView{
		workspace: workspace.file,
		path:      filepath.Join(workspaceRoot, cacheViewName),
		identity:  finalIdentity,
		names:     names,
		snapshot:  cloneSnapshot(snapshot),
	}, nil
}

func createStageDirectory(parentFD int) (string, error) {
	for attempt := 0; attempt < 10; attempt++ {
		random := make([]byte, 16)
		if _, err := io.ReadFull(rand.Reader, random); err != nil {
			return "", fmt.Errorf("generate Trivy cache staging name: %w", err)
		}
		name := ".trivy-cache-" + hex.EncodeToString(random)
		if err := unix.Mkdirat(parentFD, name, 0o700); errors.Is(err, unix.EEXIST) {
			continue
		} else if err != nil {
			return "", fmt.Errorf("create Trivy cache staging directory: %w", err)
		}
		return name, nil
	}
	return "", errors.New("create unique Trivy cache staging directory")
}

func verifyViewLink(stage *os.File, source *openedVersion) error {
	directoryFD, err := unix.Openat(
		int(stage.Fd()),
		source.viewName,
		unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC,
		0,
	)
	if err != nil {
		return fmt.Errorf(
			"%w: open new %s cache link: %v",
			ErrUnsafeStorage,
			source.viewName,
			err,
		)
	}
	directory := os.NewFile(uintptr(directoryFD), source.viewName)
	if directory == nil {
		_ = unix.Close(directoryFD)
		return fmt.Errorf("%w: wrap linked directory", ErrUnsafeStorage)
	}
	defer directory.Close()
	identity, err := descriptorIdentity(int(directory.Fd()))
	if err != nil || !source.identity.sameFile(identity) {
		return fmt.Errorf(
			"%w: %s cache link does not reference the opened version",
			ErrUnsafeStorage,
			source.viewName,
		)
	}
	for name, expected := range source.fileInfo {
		fd, openErr := unix.Openat(
			int(directory.Fd()),
			name,
			unix.O_RDONLY|unix.O_NONBLOCK|unix.O_NOFOLLOW|unix.O_CLOEXEC,
			0,
		)
		if openErr != nil {
			return fmt.Errorf(
				"%w: open linked %s/%s: %v",
				ErrUnsafeStorage,
				source.viewName,
				name,
				openErr,
			)
		}
		file := os.NewFile(uintptr(fd), name)
		if file == nil {
			_ = unix.Close(fd)
			return fmt.Errorf("%w: wrap linked database file", ErrUnsafeStorage)
		}
		actual, statErr := descriptorIdentity(int(file.Fd()))
		closeErr := file.Close()
		if statErr != nil || closeErr != nil || !expected.sameFile(actual) {
			return fmt.Errorf(
				"%w: linked %s/%s changed during view construction",
				ErrUnsafeStorage,
				source.viewName,
				name,
			)
		}
	}
	return nil
}

// Close securely unlinks the cache symlinks and then the exact view inode.
func (v *CacheView) Close() error {
	if v == nil {
		return errors.New("close nil Trivy cache view")
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.closed {
		return nil
	}
	fd, err := unix.Openat(
		int(v.workspace.Fd()),
		cacheViewName,
		unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC,
		0,
	)
	if err != nil {
		return fmt.Errorf("%w: open cache view for cleanup: %v", ErrUnsafeStorage, err)
	}
	directory := os.NewFile(uintptr(fd), cacheViewName)
	if directory == nil {
		_ = unix.Close(fd)
		return errors.New("wrap Trivy cache cleanup descriptor")
	}
	identity, statErr := descriptorIdentity(int(directory.Fd()))
	if statErr != nil || !v.identity.sameFile(identity) {
		_ = directory.Close()
		return fmt.Errorf(
			"%w: cache view was replaced before cleanup",
			ErrUnsafeStorage,
		)
	}
	entries, err := directory.ReadDir(-1)
	if err != nil {
		_ = directory.Close()
		return fmt.Errorf("list cache view for cleanup: %w", err)
	}
	actualNames := make([]string, 0, len(entries))
	for _, entry := range entries {
		identity, statErr := statAtNoFollow(int(directory.Fd()), entry.Name())
		if statErr != nil || !identity.isSymlink() {
			_ = directory.Close()
			return fmt.Errorf(
				"%w: cache view contains an unexpected entry",
				ErrUnsafeStorage,
			)
		}
		actualNames = append(actualNames, entry.Name())
	}
	slices.Sort(actualNames)
	if !slices.Equal(actualNames, v.names) {
		_ = directory.Close()
		return fmt.Errorf(
			"%w: cache view contents changed before cleanup",
			ErrUnsafeStorage,
		)
	}
	if err := directory.Chmod(0o700); err != nil {
		_ = directory.Close()
		return fmt.Errorf("unseal cache view for cleanup: %w", err)
	}
	for _, name := range actualNames {
		if err := unix.Unlinkat(int(directory.Fd()), name, 0); err != nil {
			_ = directory.Chmod(0o500)
			_ = directory.Close()
			return fmt.Errorf("unlink cache view entry %q: %w", name, err)
		}
	}
	directorySyncErr := directory.Sync()
	directoryCloseErr := directory.Close()
	current, err := statAtNoFollow(int(v.workspace.Fd()), cacheViewName)
	if err != nil ||
		!current.isDirectory() ||
		!current.sameFile(v.identity) {
		return errors.Join(
			wrapViewError(directorySyncErr, "sync emptied cache view"),
			wrapViewError(directoryCloseErr, "close emptied cache view"),
			fmt.Errorf(
				"%w: cache view changed before final cleanup",
				ErrUnsafeStorage,
			),
		)
	}
	if err := unix.Unlinkat(
		int(v.workspace.Fd()),
		cacheViewName,
		unix.AT_REMOVEDIR,
	); err != nil {
		return errors.Join(
			wrapViewError(directorySyncErr, "sync emptied cache view"),
			wrapViewError(directoryCloseErr, "close emptied cache view"),
			fmt.Errorf("remove Trivy cache view: %w", err),
		)
	}
	syncErr := v.workspace.Sync()
	closeErr := v.workspace.Close()
	v.closed = true
	return errors.Join(
		wrapViewError(directorySyncErr, "sync emptied cache view"),
		wrapViewError(directoryCloseErr, "close emptied cache view"),
		wrapViewError(syncErr, "sync workspace after cache cleanup"),
		wrapViewError(closeErr, "close cache workspace"),
	)
}

func cleanupViewAt(
	parentFD int,
	name string,
	sources []*openedVersion,
	expected fileIdentity,
) error {
	fd, err := unix.Openat(
		parentFD,
		name,
		unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC,
		0,
	)
	if errors.Is(err, unix.ENOENT) {
		return nil
	}
	if err != nil {
		return err
	}
	directory := os.NewFile(uintptr(fd), name)
	if directory == nil {
		_ = unix.Close(fd)
		return errors.New("wrap incomplete cache directory")
	}
	identity, err := descriptorIdentity(int(directory.Fd()))
	if err != nil || !identity.sameFile(expected) {
		_ = directory.Close()
		return fmt.Errorf(
			"%w: incomplete cache directory was replaced",
			ErrUnsafeStorage,
		)
	}
	_ = directory.Chmod(0o700)
	for _, source := range sources {
		if err := unix.Unlinkat(
			int(directory.Fd()),
			source.viewName,
			0,
		); err != nil && !errors.Is(err, unix.ENOENT) {
			_ = directory.Close()
			return err
		}
	}
	if err := directory.Close(); err != nil {
		return err
	}
	return unix.Unlinkat(parentFD, name, unix.AT_REMOVEDIR)
}

type fileIdentity struct {
	device uint64
	inode  uint64
	mode   uint32
}

func (i fileIdentity) sameFile(other fileIdentity) bool {
	return i.device == other.device && i.inode == other.inode
}

func (i fileIdentity) isDirectory() bool {
	return i.mode&unix.S_IFMT == unix.S_IFDIR
}

func (i fileIdentity) isSymlink() bool {
	return i.mode&unix.S_IFMT == unix.S_IFLNK
}

func descriptorIdentity(fd int) (fileIdentity, error) {
	var value unix.Stat_t
	if err := unix.Fstat(fd, &value); err != nil {
		return fileIdentity{}, err
	}
	return identityFromStat(&value), nil
}

func statAtNoFollow(parentFD int, name string) (fileIdentity, error) {
	var value unix.Stat_t
	if err := unix.Fstatat(
		parentFD,
		name,
		&value,
		unix.AT_SYMLINK_NOFOLLOW,
	); err != nil {
		return fileIdentity{}, err
	}
	return identityFromStat(&value), nil
}

func wrapViewError(err error, message string) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%s: %w", message, err)
}

func cloneSnapshot(value Snapshot) Snapshot {
	result := value
	result.Bundle.ManifestJSON = append([]byte(nil), value.Bundle.ManifestJSON...)
	result.Trivy.Files = append([]File(nil), value.Trivy.Files...)
	if value.Java != nil {
		java := *value.Java
		java.Files = append([]File(nil), value.Java.Files...)
		result.Java = &java
	}
	return result
}

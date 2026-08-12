package archiveimport

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
)

type safeWorkspaceRoot struct {
	path string
	info fs.FileInfo
}

type leaseWorkspace struct {
	archiveRoot *os.Root
	importRoot  *os.Root
	finalRoot   *os.Root
	directory   *os.File
	importID    string
	fenceName   string
	importInfo  fs.FileInfo
	finalInfo   fs.FileInfo
	closed      bool
}

func newSafeWorkspaceRoot(path string) (*safeWorkspaceRoot, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) == string(filepath.Separator) {
		return nil, errors.New("archive import work root must be an absolute subdirectory")
	}
	path = filepath.Clean(path)
	info, err := os.Lstat(path)
	if err != nil || !realStorageDirectory(info) {
		return nil, errors.New("archive import work root must be a real directory")
	}
	root, err := os.OpenRoot(path)
	if err != nil {
		return nil, fmt.Errorf("open archive import work root: %w", err)
	}
	opened, statErr := root.Stat(".")
	closeErr := root.Close()
	if statErr != nil || !realStorageDirectory(opened) || !os.SameFile(info, opened) {
		return nil, errors.Join(
			statErr, errors.New("archive import work root changed while opening"), closeErr,
		)
	}
	if closeErr != nil {
		return nil, closeErr
	}
	return &safeWorkspaceRoot{path: path, info: info}, nil
}

func (root *safeWorkspaceRoot) Create(lease Lease) (*leaseWorkspace, error) {
	if root == nil || !uuidPattern.MatchString(lease.ID) || lease.FencingToken == 0 {
		return nil, ErrInvalidInput
	}
	current, err := os.Lstat(root.path)
	if err != nil || !realStorageDirectory(current) || !os.SameFile(root.info, current) {
		return nil, errors.New("archive import work root was replaced")
	}
	openedRoot, err := os.OpenRoot(root.path)
	if err != nil {
		return nil, err
	}
	openedInfo, err := openedRoot.Stat(".")
	if err != nil || !os.SameFile(root.info, openedInfo) {
		_ = openedRoot.Close()
		return nil, errors.New("archive import work root identity changed")
	}
	archiveRoot, err := openOrCreateStorageDirectory(openedRoot, "archive-imports")
	_ = openedRoot.Close()
	if err != nil {
		return nil, fmt.Errorf("open archive import workspace namespace: %w", err)
	}
	importRoot, err := openOrCreateStorageDirectory(archiveRoot, lease.ID)
	if err != nil {
		_ = archiveRoot.Close()
		return nil, fmt.Errorf("open archive import workspace: %w", err)
	}
	importInfo, err := archiveRoot.Lstat(lease.ID)
	if err != nil || !realStorageDirectory(importInfo) {
		_ = importRoot.Close()
		_ = archiveRoot.Close()
		return nil, errors.New("archive import workspace identity is invalid")
	}
	fenceName := strconv.FormatUint(lease.FencingToken, 10)
	if err := importRoot.Mkdir(fenceName, 0o700); err != nil {
		_ = importRoot.Close()
		_ = archiveRoot.Close()
		if errors.Is(err, fs.ErrExist) {
			return nil, ErrConflict
		}
		return nil, fmt.Errorf("create fenced archive import workspace: %w", err)
	}
	finalInfo, err := importRoot.Lstat(fenceName)
	if err != nil || !realStorageDirectory(finalInfo) {
		_ = importRoot.Remove(fenceName)
		_ = importRoot.Close()
		_ = archiveRoot.Close()
		return nil, errors.New("fenced archive import workspace is invalid")
	}
	finalRoot, err := importRoot.OpenRoot(fenceName)
	if err != nil {
		_ = importRoot.Remove(fenceName)
		_ = importRoot.Close()
		_ = archiveRoot.Close()
		return nil, err
	}
	finalOpened, err := finalRoot.Stat(".")
	if err != nil || !os.SameFile(finalInfo, finalOpened) {
		_ = finalRoot.Close()
		_ = importRoot.Remove(fenceName)
		_ = importRoot.Close()
		_ = archiveRoot.Close()
		return nil, errors.New("fenced archive import workspace changed while opening")
	}
	directory, err := finalRoot.Open(".")
	if err != nil {
		_ = finalRoot.Close()
		_ = importRoot.Remove(fenceName)
		_ = importRoot.Close()
		_ = archiveRoot.Close()
		return nil, err
	}
	return &leaseWorkspace{
		archiveRoot: archiveRoot, importRoot: importRoot, finalRoot: finalRoot,
		directory: directory, importID: lease.ID, fenceName: fenceName,
		importInfo: importInfo, finalInfo: finalInfo,
	}, nil
}

func (workspace *leaseWorkspace) Directory() *os.File {
	if workspace == nil || workspace.closed {
		return nil
	}
	return workspace.directory
}

func (workspace *leaseWorkspace) Close() error {
	if workspace == nil || workspace.closed {
		return nil
	}
	workspace.closed = true
	var result error
	if workspace.directory != nil {
		result = errors.Join(result, workspace.directory.Close())
	}
	entries, err := fs.ReadDir(workspace.finalRoot.FS(), ".")
	if err != nil {
		result = errors.Join(result, fmt.Errorf("list archive import workspace: %w", err))
	} else {
		for _, entry := range entries {
			if err := workspace.finalRoot.RemoveAll(entry.Name()); err != nil {
				result = errors.Join(result, fmt.Errorf("clear archive import workspace: %w", err))
			}
		}
	}
	result = errors.Join(result, workspace.finalRoot.Close())
	currentFinal, err := workspace.importRoot.Lstat(workspace.fenceName)
	if err == nil && os.SameFile(workspace.finalInfo, currentFinal) {
		result = errors.Join(result, workspace.importRoot.Remove(workspace.fenceName))
	} else if err != nil && !errors.Is(err, fs.ErrNotExist) {
		result = errors.Join(result, err)
	} else if err == nil {
		result = errors.Join(result, errors.New("fenced archive import workspace was replaced"))
	}
	result = errors.Join(result, workspace.importRoot.Close())
	currentImport, err := workspace.archiveRoot.Lstat(workspace.importID)
	if err == nil && os.SameFile(workspace.importInfo, currentImport) {
		if removeErr := workspace.archiveRoot.Remove(workspace.importID); removeErr != nil &&
			!errors.Is(removeErr, fs.ErrNotExist) {
			// A concurrent or replaced fence is left for explicit reconciliation.
			result = errors.Join(result, removeErr)
		}
	} else if err != nil && !errors.Is(err, fs.ErrNotExist) {
		result = errors.Join(result, err)
	} else if err == nil {
		result = errors.Join(result, errors.New("archive import workspace was replaced"))
	}
	result = errors.Join(result, workspace.archiveRoot.Close())
	return result
}

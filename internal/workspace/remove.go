package workspace

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"strings"

	"golang.org/x/sys/unix"
)

// removeRootedTree is the Go 1.24-compatible equivalent of a narrowly scoped
// Root.RemoveAll. Every traversal step is relative to an opened directory
// descriptor and uses O_NOFOLLOW, so archive-created symlinks are only unlinked
// and never traversed.
func removeRootedTree(
	root *os.Root,
	name string,
	expected fs.FileInfo,
) (returnErr error) {
	if !safeWorkspaceName(name) {
		return fmt.Errorf("%w: invalid removal target", ErrUnsafeWorkspace)
	}
	info, err := root.Lstat(name)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect rooted removal target: %w", err)
	}
	if !realDirectory(info) {
		return fmt.Errorf(
			"%w: rooted removal target is not a 0700 real directory",
			ErrUnsafeWorkspace,
		)
	}
	if expected == nil || !os.SameFile(expected, info) {
		return fmt.Errorf(
			"%w: rooted removal target does not match expected inode",
			ErrUnsafeWorkspace,
		)
	}
	parent, err := root.Open(".")
	if err != nil {
		return fmt.Errorf("open workspace root for removal: %w", err)
	}
	defer func() {
		returnErr = errors.Join(returnErr, parent.Close())
	}()
	directory, err := openDirectoryAt(parent, name)
	if err != nil {
		return fmt.Errorf("open rooted removal target: %w", err)
	}
	openedInfo, statErr := directory.Stat()
	if statErr != nil || !realDirectory(openedInfo) ||
		!os.SameFile(info, openedInfo) ||
		!os.SameFile(expected, openedInfo) {
		closeErr := directory.Close()
		return errors.Join(
			wrapOptional(statErr, "inspect opened removal target"),
			fmt.Errorf("%w: removal target changed while opening", ErrUnsafeWorkspace),
			closeErr,
		)
	}
	if err := removeDirectoryContents(directory); err != nil {
		return errors.Join(
			fmt.Errorf("remove workspace contents: %w", err),
			directory.Close(),
		)
	}
	if err := directory.Close(); err != nil {
		return fmt.Errorf("close emptied workspace: %w", err)
	}
	currentInfo, err := root.Lstat(name)
	if err != nil || !realDirectory(currentInfo) ||
		!os.SameFile(expected, currentInfo) {
		return errors.Join(
			wrapOptional(err, "reinspect emptied workspace"),
			fmt.Errorf("%w: removal target changed before unlink", ErrUnsafeWorkspace),
		)
	}
	if err := unix.Unlinkat(
		int(parent.Fd()),
		name,
		unix.AT_REMOVEDIR,
	); errors.Is(err, unix.ENOENT) {
		return nil
	} else if err != nil {
		return fmt.Errorf("remove empty workspace directory: %w", err)
	}
	return nil
}

func removeDirectoryContents(directory *os.File) error {
	for {
		names, readErr := directory.Readdirnames(256)
		for _, name := range names {
			if err := removeEntryAt(directory, name); err != nil {
				return err
			}
		}
		if errors.Is(readErr, io.EOF) {
			return nil
		}
		if readErr != nil {
			return fmt.Errorf("list workspace directory: %w", readErr)
		}
	}
}

func removeEntryAt(parent *os.File, name string) error {
	if name == "" || name == "." || name == ".." ||
		strings.Contains(name, "/") {
		return fmt.Errorf("%w: invalid directory entry", ErrUnsafeWorkspace)
	}
	directory, err := openDirectoryAt(parent, name)
	if err == nil {
		if err := removeDirectoryContents(directory); err != nil {
			return errors.Join(err, directory.Close())
		}
		if err := directory.Close(); err != nil {
			return fmt.Errorf("close emptied child directory: %w", err)
		}
		if err := unix.Unlinkat(
			int(parent.Fd()),
			name,
			unix.AT_REMOVEDIR,
		); errors.Is(err, unix.ENOENT) {
			return nil
		} else if err != nil {
			return fmt.Errorf("remove child directory %q: %w", name, err)
		}
		return nil
	}
	if errors.Is(err, unix.ENOENT) {
		return nil
	}
	if !errors.Is(err, unix.ENOTDIR) && !errors.Is(err, unix.ELOOP) {
		return fmt.Errorf("open child entry %q: %w", name, err)
	}
	if err := unix.Unlinkat(
		int(parent.Fd()),
		name,
		0,
	); errors.Is(err, unix.ENOENT) {
		return nil
	} else if err != nil {
		return fmt.Errorf("remove child entry %q: %w", name, err)
	}
	return nil
}

func openDirectoryAt(parent *os.File, name string) (*os.File, error) {
	fd, err := unix.Openat(
		int(parent.Fd()),
		name,
		unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC,
		0,
	)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), name)
	if file == nil {
		_ = unix.Close(fd)
		return nil, errors.New("wrap opened directory descriptor")
	}
	return file, nil
}

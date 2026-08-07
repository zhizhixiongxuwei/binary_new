package taskcleanup

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"

	"golang.org/x/sys/unix"
)

const (
	maxCleanupDepth   = 32
	maxCleanupEntries = 100_000
)

var (
	canonicalID = regexp.MustCompile(
		`^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`,
	)
	canonicalDigest = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

type RepositoryFileDeleter struct {
	root string
	dev  uint64
	ino  uint64
}

func NewRepositoryFileDeleter(
	root string,
) (*RepositoryFileDeleter, error) {
	if !filepath.IsAbs(root) || filepath.Clean(root) != root ||
		root == string(filepath.Separator) {
		return nil, errors.New(
			"repository root must be a canonical absolute path below /",
		)
	}
	var info unix.Stat_t
	if err := unix.Lstat(root, &info); err != nil {
		return nil, fmt.Errorf("inspect repository root: %w", err)
	}
	if info.Mode&unix.S_IFMT != unix.S_IFDIR {
		return nil, errors.New("repository root is not a real directory")
	}
	fd, err := unix.Open(
		root,
		unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC,
		0,
	)
	if err != nil {
		return nil, fmt.Errorf("open repository root: %w", err)
	}
	defer unix.Close(fd)
	var opened unix.Stat_t
	if err := unix.Fstat(fd, &opened); err != nil {
		return nil, fmt.Errorf("inspect opened repository root: %w", err)
	}
	if opened.Dev != info.Dev || opened.Ino != info.Ino {
		return nil, errors.New("repository root changed while opening")
	}
	return &RepositoryFileDeleter{
		root: root, dev: uint64(opened.Dev), ino: opened.Ino,
	}, nil
}

func (d *RepositoryFileDeleter) DeleteFile(
	ctx context.Context,
	file StoredFile,
) (bool, error) {
	if err := validateStoredFile(file); err != nil {
		return false, err
	}
	if err := ctx.Err(); err != nil {
		return false, err
	}
	rootFD, err := d.openRoot()
	if err != nil {
		return false, err
	}
	defer unix.Close(rootFD)
	components := strings.Split(file.StorageKey, "/")
	parentFD, owned, missing, err := openParent(
		ctx, rootFD, components[:len(components)-1],
	)
	if owned {
		defer unix.Close(parentFD)
	}
	if err != nil {
		return false, err
	}
	if missing {
		return false, nil
	}
	name := components[len(components)-1]
	var before unix.Stat_t
	if err := unix.Fstatat(
		parentFD, name, &before, unix.AT_SYMLINK_NOFOLLOW,
	); errors.Is(err, unix.ENOENT) {
		return false, nil
	} else if err != nil {
		return false, fmt.Errorf("inspect task output: %w", err)
	}
	if before.Mode&unix.S_IFMT != unix.S_IFREG ||
		before.Size != file.SizeBytes ||
		uint64(before.Nlink) != 1 {
		return false, errors.New(
			"task output is not the expected single-link regular file",
		)
	}
	fd, err := unix.Openat(
		parentFD, name,
		unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC,
		0,
	)
	if err != nil {
		if errors.Is(err, unix.ENOENT) {
			return false, nil
		}
		return false, fmt.Errorf("open task output: %w", err)
	}
	opened := os.NewFile(uintptr(fd), file.StorageKey)
	if opened == nil {
		_ = unix.Close(fd)
		return false, errors.New("wrap task output descriptor")
	}
	hash, openedInfo, hashErr := hashTaskOutput(ctx, opened)
	closeErr := opened.Close()
	if hashErr != nil || closeErr != nil {
		return false, errors.Join(hashErr, closeErr)
	}
	if openedInfo.Dev != before.Dev || openedInfo.Ino != before.Ino ||
		openedInfo.Size != before.Size || uint64(openedInfo.Nlink) != 1 ||
		hash != file.SHA256 {
		return false, errors.New(
			"task output content or identity does not match its database record",
		)
	}
	if err := ctx.Err(); err != nil {
		return false, err
	}
	var current unix.Stat_t
	if err := unix.Fstatat(
		parentFD, name, &current, unix.AT_SYMLINK_NOFOLLOW,
	); errors.Is(err, unix.ENOENT) {
		return false, nil
	} else if err != nil {
		return false, fmt.Errorf("reinspect task output: %w", err)
	}
	if !sameStat(before, current) || uint64(current.Nlink) != 1 {
		return false, errors.New("task output changed before deletion")
	}
	if err := unix.Unlinkat(parentFD, name, 0); errors.Is(err, unix.ENOENT) {
		return false, nil
	} else if err != nil {
		return false, fmt.Errorf("unlink task output: %w", err)
	}
	if err := syncDirectory(parentFD); err != nil {
		return false, fmt.Errorf("sync task output directory: %w", err)
	}
	return true, nil
}

func (d *RepositoryFileDeleter) DeleteScope(
	ctx context.Context,
	scope Scope,
) error {
	scopeKey, err := cleanupScopeKey(scope)
	if err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	rootFD, err := d.openRoot()
	if err != nil {
		return err
	}
	defer unix.Close(rootFD)
	components := strings.Split(scopeKey, "/")
	parentFD, owned, missing, err := openParent(
		ctx, rootFD, components[:len(components)-1],
	)
	if owned {
		defer unix.Close(parentFD)
	}
	if err != nil || missing {
		return err
	}
	name := components[len(components)-1]
	directoryFD, err := unix.Openat(
		parentFD, name,
		unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC,
		0,
	)
	if errors.Is(err, unix.ENOENT) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("open task output scope: %w", err)
	}
	directory := os.NewFile(uintptr(directoryFD), scopeKey)
	if directory == nil {
		_ = unix.Close(directoryFD)
		return errors.New("wrap task output scope descriptor")
	}
	var opened unix.Stat_t
	if err := unix.Fstat(directoryFD, &opened); err != nil {
		_ = directory.Close()
		return fmt.Errorf("inspect task output scope: %w", err)
	}
	count := 0
	if err := removeDirectoryContents(ctx, directory, 0, &count); err != nil {
		return errors.Join(err, directory.Close())
	}
	if err := directory.Close(); err != nil {
		return fmt.Errorf("close task output scope: %w", err)
	}
	var current unix.Stat_t
	if err := unix.Fstatat(
		parentFD, name, &current, unix.AT_SYMLINK_NOFOLLOW,
	); errors.Is(err, unix.ENOENT) {
		return nil
	} else if err != nil {
		return fmt.Errorf("reinspect task output scope: %w", err)
	}
	if !sameDirectory(opened, current) ||
		current.Mode&unix.S_IFMT != unix.S_IFDIR {
		return errors.New("task output scope changed before deletion")
	}
	if err := unix.Unlinkat(
		parentFD, name, unix.AT_REMOVEDIR,
	); errors.Is(err, unix.ENOENT) {
		return nil
	} else if err != nil {
		return fmt.Errorf("remove task output scope: %w", err)
	}
	return syncDirectory(parentFD)
}

func (d *RepositoryFileDeleter) openRoot() (int, error) {
	fd, err := unix.Open(
		d.root,
		unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC,
		0,
	)
	if err != nil {
		return -1, fmt.Errorf("open repository root: %w", err)
	}
	var info unix.Stat_t
	if err := unix.Fstat(fd, &info); err != nil {
		_ = unix.Close(fd)
		return -1, fmt.Errorf("inspect repository root: %w", err)
	}
	if uint64(info.Dev) != d.dev || info.Ino != d.ino {
		_ = unix.Close(fd)
		return -1, errors.New("repository root was replaced")
	}
	return fd, nil
}

func validateStoredFile(file StoredFile) error {
	if !canonicalID.MatchString(file.TaskID) ||
		!canonicalID.MatchString(file.RecordID) ||
		!canonicalDigest.MatchString(file.SHA256) ||
		file.SizeBytes < 0 ||
		!canonicalStorageKey(file.StorageKey) {
		return errors.New("task output descriptor is invalid")
	}
	var expected string
	switch file.Kind {
	case FileReport:
		if file.Format != "json" && file.Format != "html" {
			return errors.New("task report format is invalid")
		}
		expected = path.Join(
			"reports", file.TaskID, file.RecordID+"."+file.Format,
		)
	case FileArtifact:
		expected = path.Join("artifacts", file.TaskID) + "/"
		if !strings.HasPrefix(file.StorageKey, expected) {
			return errors.New("task artifact storage key is outside its task")
		}
		return nil
	case FileDecompile:
		expected = path.Join("decompile", file.RecordID) + "/"
		if !strings.HasPrefix(file.StorageKey, expected) {
			return errors.New(
				"task decompile storage key is outside its result",
			)
		}
		relative := strings.TrimPrefix(file.StorageKey, expected)
		if relative == "" || strings.Contains(relative, "/") {
			return errors.New(
				"task decompile storage key must name one result file",
			)
		}
		return nil
	default:
		return errors.New("task output kind is invalid")
	}
	if file.StorageKey != expected {
		return errors.New("task output storage key is not canonical")
	}
	return nil
}

func cleanupScopeKey(scope Scope) (string, error) {
	if !canonicalID.MatchString(scope.TaskID) {
		return "", errors.New("task output scope task ID is invalid")
	}
	switch scope.Kind {
	case FileReport:
		if scope.RecordID != "" {
			return "", errors.New("task report scope is invalid")
		}
		return path.Join("reports", scope.TaskID), nil
	case FileArtifact:
		if scope.RecordID != "" {
			return "", errors.New("task artifact scope is invalid")
		}
		return path.Join("artifacts", scope.TaskID), nil
	case FileDecompile:
		if !canonicalID.MatchString(scope.RecordID) {
			return "", errors.New("task decompile scope is invalid")
		}
		return path.Join("decompile", scope.RecordID), nil
	default:
		return "", errors.New("task output scope kind is invalid")
	}
}

func canonicalStorageKey(value string) bool {
	if value == "" || len(value) > 1024 || path.IsAbs(value) ||
		filepath.IsAbs(value) || path.Clean(value) != value ||
		strings.Contains(value, `\`) || strings.ContainsRune(value, 0) {
		return false
	}
	for _, component := range strings.Split(value, "/") {
		if component == "" || component == "." || component == ".." {
			return false
		}
	}
	return true
}

func openParent(
	ctx context.Context,
	rootFD int,
	components []string,
) (fd int, owned bool, missing bool, returnErr error) {
	fd = rootFD
	for _, component := range components {
		if err := ctx.Err(); err != nil {
			return fd, owned, false, err
		}
		next, err := unix.Openat(
			fd, component,
			unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC,
			0,
		)
		if errors.Is(err, unix.ENOENT) {
			return fd, owned, true, nil
		}
		if err != nil {
			return fd, owned, false, fmt.Errorf(
				"open task output parent: %w", err,
			)
		}
		if owned {
			if err := unix.Close(fd); err != nil {
				_ = unix.Close(next)
				return fd, false, false, err
			}
		}
		fd = next
		owned = true
	}
	return fd, owned, false, nil
}

func hashTaskOutput(
	ctx context.Context,
	file *os.File,
) (string, unix.Stat_t, error) {
	var info unix.Stat_t
	if err := unix.Fstat(int(file.Fd()), &info); err != nil {
		return "", info, fmt.Errorf("inspect opened task output: %w", err)
	}
	hasher := sha256.New()
	buffer := make([]byte, 256<<10)
	for {
		if err := ctx.Err(); err != nil {
			return "", info, err
		}
		read, err := file.Read(buffer)
		if read > 0 {
			_, _ = hasher.Write(buffer[:read])
		}
		if errors.Is(err, io.EOF) {
			return hex.EncodeToString(hasher.Sum(nil)), info, nil
		}
		if err != nil {
			return "", info, fmt.Errorf("hash task output: %w", err)
		}
		if read == 0 {
			return "", info, errors.New("hash task output made no progress")
		}
	}
}

func removeDirectoryContents(
	ctx context.Context,
	directory *os.File,
	depth int,
	count *int,
) error {
	if depth > maxCleanupDepth {
		return errors.New("task output cleanup depth limit exceeded")
	}
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		names, readErr := directory.Readdirnames(256)
		for _, name := range names {
			*count = *count + 1
			if *count > maxCleanupEntries {
				return errors.New("task output cleanup entry limit exceeded")
			}
			if err := removeEntry(ctx, directory, name, depth, count); err != nil {
				return err
			}
		}
		if errors.Is(readErr, io.EOF) {
			return syncDirectory(int(directory.Fd()))
		}
		if readErr != nil {
			return fmt.Errorf("list task output scope: %w", readErr)
		}
	}
}

func removeEntry(
	ctx context.Context,
	parent *os.File,
	name string,
	depth int,
	count *int,
) error {
	if name == "" || name == "." || name == ".." ||
		strings.Contains(name, "/") {
		return errors.New("task output scope contains an invalid entry")
	}
	parentFD := int(parent.Fd())
	childFD, err := unix.Openat(
		parentFD, name,
		unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC,
		0,
	)
	if err == nil {
		child := os.NewFile(uintptr(childFD), name)
		if child == nil {
			_ = unix.Close(childFD)
			return errors.New("wrap task output child directory")
		}
		var opened unix.Stat_t
		if err := unix.Fstat(childFD, &opened); err != nil {
			_ = child.Close()
			return fmt.Errorf("inspect task output child directory: %w", err)
		}
		if err := removeDirectoryContents(
			ctx, child, depth+1, count,
		); err != nil {
			return errors.Join(err, child.Close())
		}
		if err := child.Close(); err != nil {
			return fmt.Errorf("close task output child directory: %w", err)
		}
		var current unix.Stat_t
		if err := unix.Fstatat(
			parentFD, name, &current, unix.AT_SYMLINK_NOFOLLOW,
		); errors.Is(err, unix.ENOENT) {
			return nil
		} else if err != nil {
			return fmt.Errorf("reinspect task output child: %w", err)
		}
		if !sameDirectory(opened, current) ||
			current.Mode&unix.S_IFMT != unix.S_IFDIR {
			return errors.New("task output child changed before deletion")
		}
		if err := unix.Unlinkat(
			parentFD, name, unix.AT_REMOVEDIR,
		); errors.Is(err, unix.ENOENT) {
			return nil
		} else if err != nil {
			return fmt.Errorf("remove task output child directory: %w", err)
		}
		return nil
	}
	if errors.Is(err, unix.ENOENT) {
		return nil
	}
	if !errors.Is(err, unix.ENOTDIR) && !errors.Is(err, unix.ELOOP) {
		return fmt.Errorf("open task output child: %w", err)
	}
	var info unix.Stat_t
	if err := unix.Fstatat(
		parentFD, name, &info, unix.AT_SYMLINK_NOFOLLOW,
	); errors.Is(err, unix.ENOENT) {
		return nil
	} else if err != nil {
		return fmt.Errorf("inspect task output child: %w", err)
	}
	switch info.Mode & unix.S_IFMT {
	case unix.S_IFREG:
		if uint64(info.Nlink) != 1 {
			return errors.New("refuse multi-link task output scope file")
		}
	case unix.S_IFLNK:
		// Unlink the link itself. O_NOFOLLOW above guarantees it was not traversed.
	default:
		return errors.New("refuse special task output scope entry")
	}
	if err := unix.Unlinkat(parentFD, name, 0); errors.Is(err, unix.ENOENT) {
		return nil
	} else if err != nil {
		return fmt.Errorf("remove task output scope entry: %w", err)
	}
	return nil
}

func sameStat(left unix.Stat_t, right unix.Stat_t) bool {
	return left.Dev == right.Dev && left.Ino == right.Ino &&
		left.Mode == right.Mode && left.Size == right.Size
}

func sameDirectory(left unix.Stat_t, right unix.Stat_t) bool {
	return left.Dev == right.Dev && left.Ino == right.Ino &&
		left.Mode == right.Mode &&
		left.Mode&unix.S_IFMT == unix.S_IFDIR &&
		right.Mode&unix.S_IFMT == unix.S_IFDIR
}

func syncDirectory(fd int) error {
	err := unix.Fsync(fd)
	if errors.Is(err, unix.EINVAL) || errors.Is(err, unix.ENOTSUP) {
		return nil
	}
	return err
}

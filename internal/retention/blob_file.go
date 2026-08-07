package retention

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"

	"golang.org/x/sys/unix"
)

var (
	ErrUnsafeBlobPath = errors.New("unsafe blob storage path")
	canonicalSHA256   = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

type RepositoryBlobDeleter struct {
	root string
}

func NewRepositoryBlobDeleter(root string) (*RepositoryBlobDeleter, error) {
	if !filepath.IsAbs(root) ||
		filepath.Clean(root) != root ||
		root == string(filepath.Separator) {
		return nil, errors.New("repository root must be a canonical absolute path below /")
	}
	return &RepositoryBlobDeleter{root: root}, nil
}

func (d *RepositoryBlobDeleter) Delete(ctx context.Context, blob Blob) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if blob.SizeBytes < 0 ||
		!canonicalSHA256.MatchString(blob.SHA256) {
		return fmt.Errorf("%w: invalid content address", ErrUnsafeBlobPath)
	}
	expected := "blobs/sha256/" + blob.SHA256[:2] + "/" + blob.SHA256
	if blob.StorageKey != expected ||
		strings.Contains(blob.StorageKey, `\`) {
		return fmt.Errorf("%w: non-canonical storage key", ErrUnsafeBlobPath)
	}

	rootFD, err := unix.Open(
		d.root,
		unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC,
		0,
	)
	if err != nil {
		return fmt.Errorf("open repository root: %w", err)
	}
	defer unix.Close(rootFD)

	parentFD := rootFD
	ownedParent := false
	for _, segment := range []string{"blobs", "sha256", blob.SHA256[:2]} {
		nextFD, openErr := unix.Openat(
			parentFD,
			segment,
			unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC,
			0,
		)
		if ownedParent {
			_ = unix.Close(parentFD)
		}
		if openErr != nil {
			if errors.Is(openErr, unix.ENOENT) {
				return nil
			}
			return fmt.Errorf("open blob parent directory: %w", openErr)
		}
		parentFD = nextFD
		ownedParent = true
	}
	if ownedParent {
		defer unix.Close(parentFD)
	}

	var before unix.Stat_t
	if err := unix.Fstatat(
		parentFD,
		blob.SHA256,
		&before,
		unix.AT_SYMLINK_NOFOLLOW,
	); errors.Is(err, unix.ENOENT) {
		return nil
	} else if err != nil {
		return fmt.Errorf("inspect blob file: %w", err)
	}
	if before.Mode&unix.S_IFMT != unix.S_IFREG ||
		before.Size != blob.SizeBytes ||
		uint64(before.Nlink) != 1 {
		return fmt.Errorf("%w: blob target is not the expected regular file", ErrUnsafeBlobPath)
	}
	fileFD, err := unix.Openat(
		parentFD,
		blob.SHA256,
		unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC,
		0,
	)
	if err != nil {
		if errors.Is(err, unix.ENOENT) {
			return nil
		}
		return fmt.Errorf("open blob file: %w", err)
	}
	var opened unix.Stat_t
	statErr := unix.Fstat(fileFD, &opened)
	closeErr := unix.Close(fileFD)
	if statErr != nil {
		return fmt.Errorf("inspect opened blob file: %w", statErr)
	}
	if closeErr != nil {
		return fmt.Errorf("close opened blob file: %w", closeErr)
	}
	if opened.Mode&unix.S_IFMT != unix.S_IFREG ||
		opened.Dev != before.Dev ||
		opened.Ino != before.Ino ||
		opened.Size != before.Size ||
		uint64(opened.Nlink) != 1 {
		return fmt.Errorf("%w: blob target changed while opening", ErrUnsafeBlobPath)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	var current unix.Stat_t
	if err := unix.Fstatat(
		parentFD,
		blob.SHA256,
		&current,
		unix.AT_SYMLINK_NOFOLLOW,
	); errors.Is(err, unix.ENOENT) {
		return nil
	} else if err != nil {
		return fmt.Errorf("reinspect blob file: %w", err)
	}
	if current.Mode&unix.S_IFMT != unix.S_IFREG ||
		current.Dev != before.Dev ||
		current.Ino != before.Ino ||
		current.Size != before.Size ||
		uint64(current.Nlink) != 1 {
		return fmt.Errorf("%w: blob target changed before deletion", ErrUnsafeBlobPath)
	}
	if err := unix.Unlinkat(parentFD, blob.SHA256, 0); errors.Is(err, unix.ENOENT) {
		return nil
	} else if err != nil {
		return fmt.Errorf("unlink blob file: %w", err)
	}
	if err := unix.Fsync(parentFD); err != nil {
		return fmt.Errorf("sync blob parent directory: %w", err)
	}
	return nil
}

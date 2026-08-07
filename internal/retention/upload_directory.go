package retention

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"

	"golang.org/x/sys/unix"
)

const maxUploadDirectoryEntries = 100_000

var (
	canonicalUploadIDPattern = regexp.MustCompile(
		`^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$`,
	)
	uploadPartNamePattern = regexp.MustCompile(`^[0-9]{8}\.part$`)
	uploadTempNamePattern = regexp.MustCompile(
		`^[0-9]{8}\.part\.tmp\.(?:[a-f0-9]{16}|[0-9]+)$`,
	)
)

type RepositoryUploadDirectoryDeleter struct {
	root string
}

func NewRepositoryUploadDirectoryDeleter(
	root string,
) (*RepositoryUploadDirectoryDeleter, error) {
	if !filepath.IsAbs(root) {
		return nil, errors.New("upload root must be absolute")
	}
	cleaned := filepath.Clean(root)
	if cleaned == string(filepath.Separator) {
		return nil, errors.New("upload root must not be the filesystem root")
	}
	return &RepositoryUploadDirectoryDeleter{root: cleaned}, nil
}

func (d *RepositoryUploadDirectoryDeleter) Delete(
	ctx context.Context,
	uploadID string,
) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if !canonicalUploadIDPattern.MatchString(uploadID) {
		return errors.New("refuse non-canonical upload directory ID")
	}
	root, err := openRetentionDirectory(d.root)
	if err != nil {
		return fmt.Errorf("open upload root: %w", err)
	}
	defer root.Close()

	uploadDirectory, err := openRetentionDirectoryAt(root, uploadID)
	if errors.Is(err, unix.ENOENT) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("open upload directory: %w", err)
	}
	uploadOpen := true
	defer func() {
		if uploadOpen {
			_ = uploadDirectory.Close()
		}
	}()

	names, err := readRetentionDirectoryNames(ctx, uploadDirectory)
	if err != nil {
		return fmt.Errorf("inspect upload directory: %w", err)
	}
	switch {
	case len(names) == 0:
		// A previous attempt may have removed parts before a database commit
		// returned an ambiguous result.
	case len(names) == 1 && names[0] == "parts":
		if err := deleteUploadPartsDirectory(ctx, uploadDirectory); err != nil {
			return err
		}
	default:
		return errors.New("refuse upload directory with unexpected contents")
	}

	if err := syncRetentionDirectory(uploadDirectory); err != nil {
		return fmt.Errorf("sync emptied upload directory: %w", err)
	}
	if err := uploadDirectory.Close(); err != nil {
		return fmt.Errorf("close emptied upload directory: %w", err)
	}
	uploadOpen = false
	if err := unix.Unlinkat(
		int(root.Fd()),
		uploadID,
		unix.AT_REMOVEDIR,
	); errors.Is(err, unix.ENOENT) {
		return nil
	} else if err != nil {
		return fmt.Errorf("remove upload directory: %w", err)
	}
	if err := syncRetentionDirectory(root); err != nil {
		return fmt.Errorf("sync upload root: %w", err)
	}
	return nil
}

func deleteUploadPartsDirectory(
	ctx context.Context,
	uploadDirectory *os.File,
) error {
	parts, err := openRetentionDirectoryAt(uploadDirectory, "parts")
	if errors.Is(err, unix.ENOENT) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("open upload parts directory: %w", err)
	}
	partsOpen := true
	defer func() {
		if partsOpen {
			_ = parts.Close()
		}
	}()

	names, err := readRetentionDirectoryNames(ctx, parts)
	if err != nil {
		return fmt.Errorf("inspect upload parts directory: %w", err)
	}
	for _, name := range names {
		if !uploadPartNamePattern.MatchString(name) &&
			!uploadTempNamePattern.MatchString(name) {
			return fmt.Errorf("refuse unexpected upload part entry %q", name)
		}
		if err := requireRegularUploadPart(parts, name); err != nil {
			return err
		}
	}
	for _, name := range names {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := requireRegularUploadPart(parts, name); errors.Is(err, unix.ENOENT) {
			continue
		} else if err != nil {
			return err
		}
		if err := unix.Unlinkat(int(parts.Fd()), name, 0); errors.Is(err, unix.ENOENT) {
			continue
		} else if err != nil {
			return fmt.Errorf("remove upload part %q: %w", name, err)
		}
	}
	if err := syncRetentionDirectory(parts); err != nil {
		return fmt.Errorf("sync emptied upload parts directory: %w", err)
	}
	if err := parts.Close(); err != nil {
		return fmt.Errorf("close emptied upload parts directory: %w", err)
	}
	partsOpen = false
	if err := unix.Unlinkat(
		int(uploadDirectory.Fd()),
		"parts",
		unix.AT_REMOVEDIR,
	); errors.Is(err, unix.ENOENT) {
		return nil
	} else if err != nil {
		return fmt.Errorf("remove upload parts directory: %w", err)
	}
	return nil
}

func requireRegularUploadPart(parent *os.File, name string) error {
	var stat unix.Stat_t
	if err := unix.Fstatat(
		int(parent.Fd()),
		name,
		&stat,
		unix.AT_SYMLINK_NOFOLLOW,
	); err != nil {
		return err
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFREG {
		return fmt.Errorf("refuse non-regular upload part %q", name)
	}
	return nil
}

func openRetentionDirectory(path string) (*os.File, error) {
	fd, err := unix.Open(
		path,
		unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC,
		0,
	)
	if err != nil {
		return nil, err
	}
	return retentionDirectoryFile(fd, path)
}

func openRetentionDirectoryAt(parent *os.File, name string) (*os.File, error) {
	fd, err := unix.Openat(
		int(parent.Fd()),
		name,
		unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC,
		0,
	)
	if err != nil {
		return nil, err
	}
	return retentionDirectoryFile(fd, name)
}

func retentionDirectoryFile(fd int, name string) (*os.File, error) {
	file := os.NewFile(uintptr(fd), name)
	if file == nil {
		_ = unix.Close(fd)
		return nil, errors.New("wrap upload directory descriptor")
	}
	return file, nil
}

func readRetentionDirectoryNames(
	ctx context.Context,
	directory *os.File,
) ([]string, error) {
	names := make([]string, 0)
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		batch, err := directory.Readdirnames(256)
		names = append(names, batch...)
		if len(names) > maxUploadDirectoryEntries {
			return nil, errors.New("upload directory entry limit exceeded")
		}
		if errors.Is(err, io.EOF) {
			return names, nil
		}
		if err != nil {
			return nil, err
		}
	}
}

func syncRetentionDirectory(directory *os.File) error {
	err := unix.Fsync(int(directory.Fd()))
	if errors.Is(err, unix.EINVAL) || errors.Is(err, unix.ENOTSUP) {
		return nil
	}
	return err
}

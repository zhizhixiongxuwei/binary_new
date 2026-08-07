package systemstatus

import (
	"context"
	"errors"
	"fmt"
	"math"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

type DiskUsage struct {
	UsedBytes   uint64
	TotalBytes  uint64
	FreeBytes   uint64
	Writable    bool
	DeviceID    uint64
	DeviceKnown bool
}

type StorageProbe interface {
	Probe(context.Context, string) (DiskUsage, error)
}

type SecureStorageProbe struct{}

func (SecureStorageProbe) Probe(
	ctx context.Context,
	root string,
) (DiskUsage, error) {
	if err := ctx.Err(); err != nil {
		return DiskUsage{}, err
	}
	fd, err := secureOpenDirectory(root)
	if err != nil {
		return DiskUsage{}, err
	}
	defer unix.Close(fd)

	var directory unix.Stat_t
	if err := unix.Fstat(fd, &directory); err != nil {
		return DiskUsage{}, fmt.Errorf("identify configured storage filesystem: %w", err)
	}
	var statistics unix.Statfs_t
	if err := unix.Fstatfs(fd, &statistics); err != nil {
		return DiskUsage{}, fmt.Errorf("read configured storage filesystem: %w", err)
	}
	blockSize := uint64(statistics.Bsize)
	if blockSize == 0 {
		return DiskUsage{}, errors.New("configured storage filesystem has zero block size")
	}
	total, ok := checkedMultiply(statistics.Blocks, blockSize)
	if !ok {
		return DiskUsage{}, errors.New("configured storage capacity overflows uint64")
	}
	free, ok := checkedMultiply(statistics.Bavail, blockSize)
	if !ok {
		return DiskUsage{}, errors.New("configured storage availability overflows uint64")
	}
	if free > total {
		free = total
	}
	if err := ctx.Err(); err != nil {
		return DiskUsage{}, err
	}
	return DiskUsage{
		UsedBytes:  total - free,
		TotalBytes: total,
		FreeBytes:  free,
		Writable: unix.Faccessat(
			fd,
			".",
			unix.W_OK,
			unix.AT_EACCESS,
		) == nil,
		DeviceID:    uint64(directory.Dev),
		DeviceKnown: true,
	}, nil
}

func secureOpenDirectory(root string) (int, error) {
	if !filepath.IsAbs(root) || root == "/" || filepath.Clean(root) != root {
		return -1, errors.New("configured storage root is not canonical")
	}
	current, err := unix.Open(
		"/",
		unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC,
		0,
	)
	if err != nil {
		return -1, fmt.Errorf("open filesystem root: %w", err)
	}
	components := strings.Split(strings.TrimPrefix(root, "/"), "/")
	for _, component := range components {
		if component == "" || component == "." || component == ".." {
			unix.Close(current)
			return -1, errors.New("configured storage root has unsafe components")
		}
		next, openErr := unix.Openat(
			current,
			component,
			unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW,
			0,
		)
		unix.Close(current)
		if openErr != nil {
			return -1, fmt.Errorf("open configured storage component: %w", openErr)
		}
		current = next
	}
	return current, nil
}

func checkedMultiply(left, right uint64) (uint64, bool) {
	if left != 0 && right > math.MaxUint64/left {
		return 0, false
	}
	return left * right, true
}

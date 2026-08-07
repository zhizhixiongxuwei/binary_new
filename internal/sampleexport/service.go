package sampleexport

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"golang.org/x/sys/unix"
)

const maxSampleBytes = 2 * 1024 * 1024 * 1024

var (
	taskIDPattern = regexp.MustCompile(
		`^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`,
	)
	digestPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

type Repository interface {
	ResolveRootBlob(context.Context, string) (BlobDescriptor, error)
}

type Config struct {
	RepositoryRoot string
}

type Service struct {
	repository     Repository
	repositoryRoot string
	rootDevice     uint64
	rootInode      uint64
}

func NewService(repository Repository, config Config) (*Service, error) {
	if repository == nil {
		return nil, errors.New("sample export repository is required")
	}
	root := filepath.Clean(config.RepositoryRoot)
	if !filepath.IsAbs(root) ||
		root == string(filepath.Separator) ||
		root != config.RepositoryRoot {
		return nil, errors.New(
			"sample export repository root must be canonical, absolute, and below /",
		)
	}
	var before unix.Stat_t
	if err := unix.Lstat(root, &before); err != nil {
		return nil, fmt.Errorf("inspect sample export repository root: %w", err)
	}
	if before.Mode&unix.S_IFMT != unix.S_IFDIR {
		return nil, errors.New(
			"sample export repository root is not a real directory",
		)
	}
	rootFD, err := unix.Open(
		root,
		unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC,
		0,
	)
	if err != nil {
		return nil, fmt.Errorf("open sample export repository root: %w", err)
	}
	defer unix.Close(rootFD)
	var opened unix.Stat_t
	if err := unix.Fstat(rootFD, &opened); err != nil {
		return nil, fmt.Errorf(
			"inspect opened sample export repository root: %w",
			err,
		)
	}
	if opened.Dev != before.Dev || opened.Ino != before.Ino {
		return nil, errors.New(
			"sample export repository root changed while opening",
		)
	}
	return &Service{
		repository: repository, repositoryRoot: root,
		rootDevice: uint64(opened.Dev), rootInode: opened.Ino,
	}, nil
}

func (s *Service) Open(
	ctx context.Context,
	taskID string,
) (Download, error) {
	if err := ctx.Err(); err != nil {
		return Download{}, err
	}
	if !taskIDPattern.MatchString(taskID) {
		return Download{}, ErrInvalidInput
	}
	descriptor, err := s.repository.ResolveRootBlob(ctx, taskID)
	if err != nil {
		return Download{}, err
	}
	if err := validateDescriptor(descriptor); err != nil {
		return Download{}, err
	}
	file, err := s.openVerified(ctx, descriptor)
	if err != nil {
		return Download{}, err
	}
	current, err := s.repository.ResolveRootBlob(ctx, taskID)
	if err != nil {
		closeFile(file)
		if errors.Is(err, ErrNotFound) {
			return Download{}, ErrUnavailable
		}
		return Download{}, err
	}
	if err := validateDescriptor(current); err != nil ||
		!sameDescriptor(descriptor, current) {
		closeFile(file)
		return Download{}, ErrUnavailable
	}
	return Download{
		Content: file, SizeBytes: descriptor.SizeBytes,
		SHA256: descriptor.SHA256, Filename: DownloadFilename,
	}, nil
}

func validateDescriptor(value BlobDescriptor) error {
	if value.ID == 0 ||
		value.TaskBlobID != value.ID ||
		!digestPattern.MatchString(value.SHA256) ||
		value.SizeBytes > maxSampleBytes ||
		value.SizeBytes > math.MaxInt64 ||
		value.State != "available" ||
		value.ReferenceCount == 0 ||
		value.UploadSHA256 != value.SHA256 ||
		value.UploadDeclaredBytes != value.SizeBytes {
		return ErrIntegrity
	}
	expectedKey := "blobs/sha256/" +
		value.SHA256[:2] + "/" + value.SHA256
	if value.StorageKey != expectedKey {
		return ErrIntegrity
	}
	switch value.UploadStatus {
	case "completed":
		if value.UploadBlobID == nil || *value.UploadBlobID != value.ID {
			return ErrIntegrity
		}
	case "expired":
		if value.UploadBlobID != nil {
			return ErrIntegrity
		}
	default:
		return ErrIntegrity
	}
	return nil
}

func sameDescriptor(first, second BlobDescriptor) bool {
	if first.ID != second.ID ||
		first.TaskBlobID != second.TaskBlobID ||
		first.StorageKey != second.StorageKey ||
		first.SHA256 != second.SHA256 ||
		first.SizeBytes != second.SizeBytes ||
		first.State != second.State ||
		first.ReferenceCount != second.ReferenceCount ||
		first.UploadStatus != second.UploadStatus ||
		first.UploadSHA256 != second.UploadSHA256 ||
		first.UploadDeclaredBytes != second.UploadDeclaredBytes {
		return false
	}
	if first.UploadBlobID == nil || second.UploadBlobID == nil {
		return first.UploadBlobID == nil && second.UploadBlobID == nil
	}
	return *first.UploadBlobID == *second.UploadBlobID
}

func (s *Service) openVerified(
	ctx context.Context,
	descriptor BlobDescriptor,
) (*os.File, error) {
	rootFD, err := s.openRoot()
	if err != nil {
		return nil, err
	}
	currentFD := rootFD
	components := strings.Split(descriptor.StorageKey, "/")
	for _, component := range components[:len(components)-1] {
		nextFD, openErr := unix.Openat(
			currentFD,
			component,
			unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC,
			0,
		)
		_ = unix.Close(currentFD)
		if openErr != nil {
			return nil, ErrUnavailable
		}
		currentFD = nextFD
	}
	fileFD, openErr := unix.Openat(
		currentFD,
		components[len(components)-1],
		unix.O_RDONLY|unix.O_NONBLOCK|unix.O_NOFOLLOW|unix.O_CLOEXEC,
		0,
	)
	_ = unix.Close(currentFD)
	if openErr != nil {
		return nil, ErrUnavailable
	}
	file := os.NewFile(uintptr(fileFD), DownloadFilename)
	if file == nil {
		_ = unix.Close(fileFD)
		return nil, ErrUnavailable
	}
	if err := verifyOpenFile(ctx, file, descriptor); err != nil {
		closeFile(file)
		return nil, err
	}
	return file, nil
}

func (s *Service) openRoot() (int, error) {
	rootFD, err := unix.Open(
		s.repositoryRoot,
		unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC,
		0,
	)
	if err != nil {
		return -1, ErrUnavailable
	}
	var opened unix.Stat_t
	if err := unix.Fstat(rootFD, &opened); err != nil ||
		uint64(opened.Dev) != s.rootDevice ||
		opened.Ino != s.rootInode {
		_ = unix.Close(rootFD)
		return -1, ErrUnavailable
	}
	return rootFD, nil
}

func verifyOpenFile(
	ctx context.Context,
	file *os.File,
	descriptor BlobDescriptor,
) error {
	before, err := file.Stat()
	if err != nil ||
		!before.Mode().IsRegular() ||
		before.Mode().Perm()&0o077 != 0 ||
		before.Size() != int64(descriptor.SizeBytes) {
		return ErrIntegrity
	}
	var stat unix.Stat_t
	if err := unix.Fstat(int(file.Fd()), &stat); err != nil ||
		stat.Mode&unix.S_IFMT != unix.S_IFREG ||
		stat.Nlink != 1 {
		return ErrIntegrity
	}
	hasher := sha256.New()
	reader := &contextReader{
		ctx: ctx,
		reader: io.NewSectionReader(
			file,
			0,
			int64(descriptor.SizeBytes),
		),
	}
	written, err := io.CopyBuffer(
		hasher,
		reader,
		make([]byte, 1024*1024),
	)
	if err != nil {
		return fmt.Errorf("verify sample export: %w", err)
	}
	after, err := file.Stat()
	var afterStat unix.Stat_t
	statErr := unix.Fstat(int(file.Fd()), &afterStat)
	if err != nil ||
		statErr != nil ||
		!after.Mode().IsRegular() ||
		after.Size() != before.Size() ||
		after.ModTime() != before.ModTime() ||
		!os.SameFile(before, after) ||
		afterStat.Mode&unix.S_IFMT != unix.S_IFREG ||
		afterStat.Dev != stat.Dev ||
		afterStat.Ino != stat.Ino ||
		afterStat.Size != stat.Size ||
		afterStat.Nlink != 1 ||
		written != int64(descriptor.SizeBytes) ||
		hex.EncodeToString(hasher.Sum(nil)) != descriptor.SHA256 {
		return ErrIntegrity
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return ErrIntegrity
	}
	return nil
}

type contextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (r *contextReader) Read(value []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	count, err := r.reader.Read(value)
	if count > 0 {
		if contextErr := r.ctx.Err(); contextErr != nil {
			return count, contextErr
		}
	}
	return count, err
}

package trivyscan

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

type sourceFile struct {
	file *os.File
	size int64
	hash string
}

func openRepositorySource(
	repositoryRoot string,
	payload HandoffSource,
) (*sourceFile, error) {
	rootFD, err := unix.Open(
		repositoryRoot,
		unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC,
		0,
	)
	if err != nil {
		return nil, fmt.Errorf("%w: open repository root: %v", ErrUnsafeSource, err)
	}
	parts := strings.Split(payload.SourceStorageKey, "/")
	current := rootFD
	for _, component := range parts[:len(parts)-1] {
		next, openErr := unix.Openat(
			current,
			component,
			unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC,
			0,
		)
		_ = unix.Close(current)
		if openErr != nil {
			return nil, fmt.Errorf(
				"%w: open source directory: %v",
				ErrUnsafeSource,
				openErr,
			)
		}
		current = next
	}
	fileFD, openErr := unix.Openat(
		current,
		parts[len(parts)-1],
		unix.O_RDONLY|unix.O_NONBLOCK|unix.O_NOFOLLOW|unix.O_CLOEXEC,
		0,
	)
	closeErr := unix.Close(current)
	if openErr != nil {
		return nil, fmt.Errorf("%w: open source file: %v", ErrUnsafeSource, openErr)
	}
	if closeErr != nil {
		_ = unix.Close(fileFD)
		return nil, fmt.Errorf("%w: close source directory: %v", ErrUnsafeSource, closeErr)
	}
	file := os.NewFile(
		uintptr(fileFD),
		filepath.Join(repositoryRoot, filepath.FromSlash(payload.SourceStorageKey)),
	)
	if file == nil {
		_ = unix.Close(fileFD)
		return nil, fmt.Errorf("%w: wrap source descriptor", ErrUnsafeSource)
	}
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		_ = file.Close()
		return nil, fmt.Errorf("%w: source is not a regular file", ErrUnsafeSource)
	}
	source := &sourceFile{
		file: file,
		size: payload.SourceSizeBytes,
		hash: payload.SourceSHA256,
	}
	if info.Size() != source.size {
		_ = source.close()
		return nil, ErrSourceMismatch
	}
	return source, nil
}

func (s *sourceFile) close() error {
	if s == nil || s.file == nil {
		return nil
	}
	err := s.file.Close()
	s.file = nil
	return err
}

func (s *sourceFile) verify(ctx context.Context) error {
	if s == nil || s.file == nil {
		return ErrUnsafeSource
	}
	before, err := s.file.Stat()
	if err != nil || !before.Mode().IsRegular() || before.Size() != s.size {
		return ErrSourceMismatch
	}
	hasher := sha256.New()
	reader := &contextReader{
		ctx:    ctx,
		reader: io.NewSectionReader(s.file, 0, s.size),
	}
	written, err := io.CopyBuffer(hasher, reader, make([]byte, 1<<20))
	if err != nil {
		return fmt.Errorf("hash Trivy source: %w", err)
	}
	after, err := s.file.Stat()
	if err != nil || !after.Mode().IsRegular() ||
		after.Size() != s.size || !os.SameFile(before, after) ||
		written != s.size ||
		hex.EncodeToString(hasher.Sum(nil)) != s.hash {
		return ErrSourceMismatch
	}
	return nil
}

func (s *sourceFile) copyVerified(
	ctx context.Context,
	destinationDirectory string,
	name string,
) (string, error) {
	directoryFD, err := unix.Open(
		destinationDirectory,
		unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC,
		0,
	)
	if err != nil {
		return "", fmt.Errorf("open Trivy input directory: %w", err)
	}
	defer unix.Close(directoryFD)
	fileFD, err := unix.Openat(
		directoryFD,
		name,
		unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC,
		0o600,
	)
	if err != nil {
		return "", fmt.Errorf("create verified Trivy input: %w", err)
	}
	output := os.NewFile(uintptr(fileFD), name)
	if output == nil {
		_ = unix.Close(fileFD)
		_ = unix.Unlinkat(directoryFD, name, 0)
		return "", errors.New("wrap verified Trivy input")
	}
	keep := false
	defer func() {
		_ = output.Close()
		if !keep {
			_ = unix.Unlinkat(directoryFD, name, 0)
		}
	}()

	hasher := sha256.New()
	reader := &contextReader{
		ctx:    ctx,
		reader: io.NewSectionReader(s.file, 0, s.size),
	}
	written, err := io.CopyBuffer(
		io.MultiWriter(output, hasher),
		reader,
		make([]byte, 1<<20),
	)
	if err != nil {
		return "", fmt.Errorf("copy verified Trivy input: %w", err)
	}
	if written != s.size ||
		hex.EncodeToString(hasher.Sum(nil)) != s.hash {
		return "", ErrSourceMismatch
	}
	if err := output.Sync(); err != nil {
		return "", fmt.Errorf("sync verified Trivy input: %w", err)
	}
	if err := output.Chmod(0o400); err != nil {
		return "", fmt.Errorf("seal verified Trivy input: %w", err)
	}
	info, err := output.Stat()
	if err != nil || !info.Mode().IsRegular() ||
		info.Mode().Perm() != 0o400 || info.Size() != s.size {
		return "", fmt.Errorf("%w: verified input changed", ErrUnsafeSource)
	}
	if err := output.Close(); err != nil {
		return "", fmt.Errorf("close verified Trivy input: %w", err)
	}
	if err := unix.Fsync(directoryFD); err != nil {
		return "", fmt.Errorf("sync Trivy input directory: %w", err)
	}
	keep = true
	return filepath.Join(destinationDirectory, name), nil
}

type contextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (r *contextReader) Read(value []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	read, err := r.reader.Read(value)
	if read > 0 {
		if contextErr := r.ctx.Err(); contextErr != nil {
			return read, contextErr
		}
	}
	return read, err
}

package archiveimport

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

type BlobStorage struct {
	root     string
	rootInfo fs.FileInfo

	// afterSourceOpen is only set by race-focused package tests.
	afterSourceOpen         func()
	afterVerifiedSourceOpen func()
	afterVerifiedTempCreate func(string)
}

var canonicalBlobKey = regexp.MustCompile(
	`\Ablobs/sha256/([0-9a-f]{2})/([0-9a-f]{64})\z`,
)

func NewBlobStorage(repositoryRoot string) (*BlobStorage, error) {
	if !filepath.IsAbs(repositoryRoot) {
		return nil, errors.New("archive import repository root must be absolute")
	}
	repositoryRoot = filepath.Clean(repositoryRoot)
	if repositoryRoot == string(filepath.Separator) {
		return nil, errors.New("archive import repository root must be below filesystem root")
	}
	info, err := os.Lstat(repositoryRoot)
	if err != nil {
		return nil, fmt.Errorf("inspect archive import repository root: %w", err)
	}
	if !realStorageDirectory(info) {
		return nil, errors.New("archive import repository root must be a real directory")
	}
	root, err := os.OpenRoot(repositoryRoot)
	if err != nil {
		return nil, fmt.Errorf("open archive import repository root: %w", err)
	}
	opened, statErr := root.Stat(".")
	closeErr := root.Close()
	if statErr != nil || !realStorageDirectory(opened) || !os.SameFile(info, opened) {
		return nil, errors.Join(
			statErr,
			errors.New("archive import repository root changed while opening"),
			closeErr,
		)
	}
	if closeErr != nil {
		return nil, fmt.Errorf("close archive import repository root: %w", closeErr)
	}
	return &BlobStorage{root: repositoryRoot, rootInfo: info}, nil
}

func (storage *BlobStorage) Path(storageKey string) (string, error) {
	if _, err := parseBlobStorageKey(storageKey); err != nil {
		return "", err
	}
	return safeStorageJoin(storage.root, storageKey)
}

func (storage *BlobStorage) Publish(
	ctx context.Context,
	sourcePath string,
	size int64,
	expectedSHA string,
) (string, error) {
	if ctx == nil || size < 0 || len(expectedSHA) != 64 ||
		!filepath.IsAbs(sourcePath) {
		return "", ErrInvalidInput
	}
	before, err := os.Lstat(sourcePath)
	if err != nil || !before.Mode().IsRegular() ||
		before.Mode()&os.ModeSymlink != 0 || before.Size() != size {
		if err == nil {
			err = ErrSourceUnavailable
		}
		return "", fmt.Errorf("inspect archive member source: %w", err)
	}
	input, err := os.Open(sourcePath)
	if err != nil {
		return "", fmt.Errorf("open archive member source: %w", err)
	}
	defer input.Close()
	opened, err := input.Stat()
	if err != nil || !opened.Mode().IsRegular() || opened.Size() != size ||
		!os.SameFile(before, opened) {
		return "", ErrSourceUnavailable
	}
	afterOpen, err := os.Lstat(sourcePath)
	if err != nil || afterOpen.Mode()&os.ModeSymlink != 0 ||
		!os.SameFile(opened, afterOpen) {
		return "", ErrSourceUnavailable
	}
	if storage.afterSourceOpen != nil {
		storage.afterSourceOpen()
	}

	repositoryRoot, err := storage.openRepositoryRoot()
	if err != nil {
		return "", err
	}
	defer repositoryRoot.Close()
	prefix := expectedSHA[:2]
	finalDirectory, err := openOrCreateStorageDirectory(
		repositoryRoot, "blobs", "sha256", prefix,
	)
	if err != nil {
		return "", fmt.Errorf("open archive blob directory: %w", err)
	}
	defer finalDirectory.Close()
	stagingName, staging, err := createStorageTemp(finalDirectory)
	if err != nil {
		return "", fmt.Errorf("create archive blob staging file: %w", err)
	}
	defer finalDirectory.Remove(stagingName)
	hasher := sha256.New()
	written, copyErr := copyContext(
		ctx,
		io.MultiWriter(staging, hasher),
		io.LimitReader(input, size+1),
	)
	openedAfterCopy, statErr := input.Stat()
	afterCopy, lstatErr := os.Lstat(sourcePath)
	if copyErr != nil || statErr != nil || lstatErr != nil ||
		!os.SameFile(opened, openedAfterCopy) || openedAfterCopy.Size() != size ||
		afterCopy.Mode()&os.ModeSymlink != 0 || !os.SameFile(opened, afterCopy) {
		staging.Close()
		if copyErr != nil {
			return "", copyErr
		}
		return "", ErrSourceUnavailable
	}
	if written != size {
		staging.Close()
		return "", ErrSourceUnavailable
	}
	actualSHA := hex.EncodeToString(hasher.Sum(nil))
	if actualSHA != expectedSHA {
		staging.Close()
		return "", ErrConflict
	}
	if err := staging.Sync(); err != nil {
		staging.Close()
		return "", fmt.Errorf("sync archive blob staging file: %w", err)
	}
	if err := staging.Close(); err != nil {
		return "", fmt.Errorf("close archive blob staging file: %w", err)
	}
	if err := finalDirectory.Link(stagingName, expectedSHA); err != nil {
		if !errors.Is(err, os.ErrExist) {
			return "", fmt.Errorf("publish archive entry blob: %w", err)
		}
		if err := verifyBlobFile(ctx, finalDirectory, expectedSHA, size, expectedSHA); err != nil {
			return "", err
		}
	} else if err := finalDirectory.Remove(stagingName); err != nil {
		_ = finalDirectory.Remove(expectedSHA)
		return "", fmt.Errorf("remove linked archive staging file: %w", err)
	}
	if err := syncStorageRoot(finalDirectory); err != nil {
		return "", err
	}
	storageKey := "blobs/sha256/" + prefix + "/" + expectedSHA
	return storageKey, nil
}

// OpenVerified binds a canonical content-addressed blob to an unlinked private
// snapshot. The caller never parses bytes through the shared repository path,
// so same-UID replacement or in-place mutation cannot race validation.
func (storage *BlobStorage) OpenVerified(
	ctx context.Context,
	storageKey string,
	size int64,
	expectedSHA string,
) (*os.File, error) {
	if ctx == nil || size < 0 || len(expectedSHA) != 64 || !isLowerHex(expectedSHA) {
		return nil, ErrInvalidInput
	}
	digest, err := parseBlobStorageKey(storageKey)
	if err != nil || digest != expectedSHA {
		return nil, ErrInvalidInput
	}
	repositoryRoot, err := storage.openRepositoryRoot()
	if err != nil {
		return nil, err
	}
	defer repositoryRoot.Close()
	directory, err := openStorageDirectory(
		repositoryRoot, "blobs", "sha256", digest[:2],
	)
	if err != nil {
		return nil, fmt.Errorf("open verified archive blob directory: %w", err)
	}
	defer directory.Close()
	before, err := directory.Lstat(digest)
	if err != nil || !before.Mode().IsRegular() || before.Mode()&os.ModeSymlink != 0 ||
		before.Mode().Perm()&0o077 != 0 || before.Size() != size {
		return nil, ErrSourceUnavailable
	}
	source, err := directory.Open(digest)
	if err != nil {
		return nil, fmt.Errorf("open verified archive blob: %w", err)
	}
	defer source.Close()
	opened, err := source.Stat()
	if err != nil || !opened.Mode().IsRegular() || opened.Size() != size ||
		!os.SameFile(before, opened) {
		return nil, ErrSourceUnavailable
	}
	afterOpen, err := directory.Lstat(digest)
	if err != nil || afterOpen.Mode()&os.ModeSymlink != 0 ||
		!os.SameFile(opened, afterOpen) {
		return nil, ErrSourceUnavailable
	}
	if storage.afterVerifiedSourceOpen != nil {
		storage.afterVerifiedSourceOpen()
	}

	name, snapshot, err := createStorageTemp(directory)
	if err != nil {
		return nil, fmt.Errorf("create verified archive blob snapshot: %w", err)
	}
	if err := directory.Remove(name); err != nil {
		_ = snapshot.Close()
		return nil, fmt.Errorf("unlink verified archive blob snapshot: %w", err)
	}
	if storage.afterVerifiedTempCreate != nil {
		storage.afterVerifiedTempCreate(filepath.Join(
			storage.root, "blobs", "sha256", digest[:2], name,
		))
	}
	hasher := sha256.New()
	written, copyErr := copyContext(
		ctx, io.MultiWriter(snapshot, hasher), io.LimitReader(source, size+1),
	)
	openedAfter, statErr := source.Stat()
	pathAfter, lstatErr := directory.Lstat(digest)
	if copyErr != nil || statErr != nil || lstatErr != nil || written != size ||
		!os.SameFile(opened, openedAfter) || openedAfter.Size() != size ||
		pathAfter.Mode()&os.ModeSymlink != 0 || !os.SameFile(opened, pathAfter) {
		_ = snapshot.Close()
		if copyErr != nil {
			return nil, copyErr
		}
		return nil, ErrSourceUnavailable
	}
	if hex.EncodeToString(hasher.Sum(nil)) != expectedSHA {
		_ = snapshot.Close()
		return nil, ErrConflict
	}
	if err := snapshot.Sync(); err != nil {
		_ = snapshot.Close()
		return nil, fmt.Errorf("sync verified archive blob snapshot: %w", err)
	}
	if err := snapshot.Chmod(0o400); err != nil {
		_ = snapshot.Close()
		return nil, fmt.Errorf("protect verified archive blob snapshot: %w", err)
	}
	snapshotInfo, err := snapshot.Stat()
	if err != nil || !snapshotInfo.Mode().IsRegular() || snapshotInfo.Size() != size {
		_ = snapshot.Close()
		return nil, ErrSourceUnavailable
	}
	if _, err := snapshot.Seek(0, io.SeekStart); err != nil {
		_ = snapshot.Close()
		return nil, fmt.Errorf("rewind verified archive blob snapshot: %w", err)
	}
	return snapshot, nil
}

func (storage *BlobStorage) DeleteReleased(
	ctx context.Context,
	repository *MySQLRepository,
	values []ReleasedBlob,
) error {
	for _, value := range values {
		if err := ctx.Err(); err != nil {
			return err
		}
		digest, err := parseBlobStorageKey(value.StorageKey)
		if err != nil {
			return err
		}
		err = repository.WithBlobFence(ctx, digest, func() error {
			stillReleased, err := repository.BlobIsReleased(ctx, value)
			if err != nil || !stillReleased {
				return err
			}
			return storage.deleteReleasedFile(ctx, repository, value, digest)
		})
		if err != nil {
			return err
		}
	}
	return nil
}

func (storage *BlobStorage) deleteReleasedFile(
	ctx context.Context,
	repository *MySQLRepository,
	value ReleasedBlob,
	digest string,
) error {
	root, err := storage.openRepositoryRoot()
	if err != nil {
		return err
	}
	directory, openErr := openStorageDirectory(
		root, "blobs", "sha256", digest[:2],
	)
	if openErr != nil && !errors.Is(openErr, fs.ErrNotExist) {
		_ = root.Close()
		return openErr
	}
	if errors.Is(openErr, fs.ErrNotExist) {
		_ = root.Close()
		return repository.MarkBlobDeleted(ctx, value.ID)
	}
	info, statErr := directory.Lstat(digest)
	switch {
	case errors.Is(statErr, os.ErrNotExist):
	case statErr != nil:
		_ = directory.Close()
		_ = root.Close()
		return fmt.Errorf("inspect released archive blob: %w", statErr)
	case !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0:
		_ = directory.Close()
		_ = root.Close()
		return errors.New("released archive blob is not a regular file")
	default:
		if err := directory.Remove(digest); err != nil && !errors.Is(err, os.ErrNotExist) {
			_ = directory.Close()
			_ = root.Close()
			return fmt.Errorf("delete released archive blob: %w", err)
		}
		if err := syncStorageRoot(directory); err != nil {
			_ = directory.Close()
			_ = root.Close()
			return err
		}
	}
	closeErr := errors.Join(directory.Close(), root.Close())
	if closeErr != nil {
		return fmt.Errorf("close archive blob directory: %w", closeErr)
	}
	return repository.MarkBlobDeleted(ctx, value.ID)
}

func verifyBlobFile(
	ctx context.Context,
	directory *os.Root,
	name string,
	size int64,
	expectedSHA string,
) error {
	info, err := directory.Lstat(name)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 ||
		info.Size() != size {
		return ErrConflict
	}
	file, err := directory.Open(name)
	if err != nil {
		return err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) {
		return ErrConflict
	}
	hasher := sha256.New()
	written, err := copyContext(ctx, hasher, io.LimitReader(file, size+1))
	if err != nil || written != size || hex.EncodeToString(hasher.Sum(nil)) != expectedSHA {
		return ErrConflict
	}
	after, err := directory.Lstat(name)
	openedAfter, statErr := file.Stat()
	if err != nil || statErr != nil || !os.SameFile(opened, after) ||
		!os.SameFile(opened, openedAfter) || openedAfter.Size() != size {
		return ErrConflict
	}
	return nil
}

func (storage *BlobStorage) openRepositoryRoot() (*os.Root, error) {
	current, err := os.Lstat(storage.root)
	if err != nil || !realStorageDirectory(current) ||
		!os.SameFile(storage.rootInfo, current) {
		return nil, errors.New("archive import repository root was replaced")
	}
	root, err := os.OpenRoot(storage.root)
	if err != nil {
		return nil, err
	}
	opened, err := root.Stat(".")
	if err != nil || !realStorageDirectory(opened) ||
		!os.SameFile(storage.rootInfo, opened) {
		_ = root.Close()
		return nil, errors.New("archive import repository root changed while opening")
	}
	return root, nil
}

func openOrCreateStorageDirectory(root *os.Root, names ...string) (*os.Root, error) {
	current := root
	owned := false
	for _, name := range names {
		if name == "" || name == "." || name == ".." ||
			strings.ContainsAny(name, `/\`) || strings.ContainsRune(name, '\x00') {
			if owned {
				_ = current.Close()
			}
			return nil, ErrInvalidInput
		}
		if err := current.Mkdir(name, 0o700); err != nil && !errors.Is(err, fs.ErrExist) {
			if owned {
				_ = current.Close()
			}
			return nil, err
		}
		next, err := openRealStorageChild(current, name)
		if owned {
			_ = current.Close()
		}
		if err != nil {
			return nil, err
		}
		current = next
		owned = true
	}
	return current, nil
}

func openStorageDirectory(root *os.Root, names ...string) (*os.Root, error) {
	current := root
	owned := false
	for _, name := range names {
		next, err := openRealStorageChild(current, name)
		if owned {
			_ = current.Close()
		}
		if err != nil {
			return nil, err
		}
		current = next
		owned = true
	}
	return current, nil
}

func openRealStorageChild(parent *os.Root, name string) (*os.Root, error) {
	info, err := parent.Lstat(name)
	if err != nil {
		return nil, err
	}
	if !realStorageDirectory(info) {
		return nil, errors.New("archive blob parent is not a real directory")
	}
	child, err := parent.OpenRoot(name)
	if err != nil {
		return nil, err
	}
	opened, err := child.Stat(".")
	if err != nil || !realStorageDirectory(opened) || !os.SameFile(info, opened) {
		_ = child.Close()
		return nil, errors.New("archive blob parent changed while opening")
	}
	return child, nil
}

func createStorageTemp(directory *os.Root) (string, *os.File, error) {
	for attempt := 0; attempt < 100; attempt++ {
		id, err := newUUID()
		if err != nil {
			return "", nil, err
		}
		name := ".archive-import-" + id + ".part"
		file, err := directory.OpenFile(name, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600)
		if errors.Is(err, fs.ErrExist) {
			continue
		}
		return name, file, err
	}
	return "", nil, errors.New("archive blob staging name collision limit reached")
}

func parseBlobStorageKey(key string) (string, error) {
	matches := canonicalBlobKey.FindStringSubmatch(key)
	if len(matches) != 3 || !strings.HasPrefix(matches[2], matches[1]) {
		return "", ErrInvalidInput
	}
	return matches[2], nil
}

func realStorageDirectory(info fs.FileInfo) bool {
	return info != nil && info.IsDir() && info.Mode()&os.ModeSymlink == 0
}

func copyContext(ctx context.Context, destination io.Writer, source io.Reader) (int64, error) {
	buffer := make([]byte, 32<<10)
	var total int64
	for {
		if err := ctx.Err(); err != nil {
			return total, err
		}
		count, readErr := source.Read(buffer)
		if count > 0 {
			written, writeErr := destination.Write(buffer[:count])
			total += int64(written)
			if writeErr != nil {
				return total, writeErr
			}
			if written != count {
				return total, io.ErrShortWrite
			}
		}
		if readErr != nil {
			if errors.Is(readErr, io.EOF) {
				return total, nil
			}
			return total, readErr
		}
		if count == 0 {
			return total, io.ErrNoProgress
		}
	}
}

func safeStorageJoin(root, key string) (string, error) {
	if filepath.IsAbs(key) || strings.ContainsRune(key, '\x00') {
		return "", ErrInvalidInput
	}
	clean := filepath.Clean(filepath.FromSlash(key))
	if clean == "." || clean == ".." ||
		strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return "", ErrInvalidInput
	}
	path := filepath.Join(root, clean)
	relative, err := filepath.Rel(root, path)
	if err != nil || relative == ".." ||
		strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return "", ErrInvalidInput
	}
	return path, nil
}

func syncStorageRoot(root *os.Root) error {
	directory, err := root.Open(".")
	if err != nil {
		return fmt.Errorf("open archive storage directory: %w", err)
	}
	defer directory.Close()
	if err := directory.Sync(); err != nil {
		return fmt.Errorf("sync archive storage directory: %w", err)
	}
	return nil
}

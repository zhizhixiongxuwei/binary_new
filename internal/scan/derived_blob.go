package scan

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"binaryscan/internal/extract"
	"golang.org/x/sys/unix"
)

// publishDerivedBlob copies a retained extraction artifact into the repository
// CAS. The extraction workspace is private and ephemeral; Trivy jobs must only
// receive the returned durable storage key.
func publishDerivedBlob(
	ctx context.Context,
	repositoryRoot string,
	workspaceRoot string,
	image extract.ContainerImage,
) (string, error) {
	if ctx == nil || image.SizeBytes <= 0 ||
		!lowercaseSHA256Pattern.MatchString(image.SHA256) {
		return "", errors.New("publish nested image: invalid content identity")
	}
	relativeSource, err := filepath.Rel(workspaceRoot, image.WorkPath)
	if err != nil || relativeSource == "." || relativeSource == ".." ||
		filepath.IsAbs(relativeSource) ||
		strings.HasPrefix(relativeSource, ".."+string(filepath.Separator)) {
		return "", errors.New("publish nested image: source escaped workspace")
	}
	sourceRoot, err := openVerifiedRoot(workspaceRoot)
	if err != nil {
		return "", fmt.Errorf("publish nested image: %w", err)
	}
	defer sourceRoot.Close()
	sourceInfo, err := sourceRoot.Lstat(relativeSource)
	if err != nil || !sourceInfo.Mode().IsRegular() ||
		sourceInfo.Size() != image.SizeBytes {
		return "", errors.New("publish nested image: source is not a regular file")
	}
	source, err := sourceRoot.Open(relativeSource)
	if err != nil {
		return "", fmt.Errorf("publish nested image: open source: %w", err)
	}
	defer source.Close()
	openedInfo, err := source.Stat()
	if err != nil || !openedInfo.Mode().IsRegular() ||
		!os.SameFile(sourceInfo, openedInfo) ||
		openedInfo.Size() != image.SizeBytes {
		return "", errors.New("publish nested image: source changed")
	}

	repository, err := openVerifiedRoot(repositoryRoot)
	if err != nil {
		return "", fmt.Errorf("publish nested image: %w", err)
	}
	defer repository.Close()
	stagingDirectory := path.Join(".staging", "scan")
	if err := ensurePrivateRootDirectory(repository, stagingDirectory); err != nil {
		return "", fmt.Errorf("publish nested image: create staging directory: %w", err)
	}
	finalDirectory := path.Join("blobs", "sha256", image.SHA256[:2])
	if err := ensurePrivateRootDirectory(repository, finalDirectory); err != nil {
		return "", fmt.Errorf("publish nested image: create blob directory: %w", err)
	}
	stagingKey := path.Join(
		stagingDirectory,
		image.SHA256+"."+strconv.FormatInt(time.Now().UnixNano(), 36)+".part",
	)
	staged, err := repository.OpenFile(
		stagingKey,
		os.O_WRONLY|os.O_CREATE|os.O_EXCL,
		0o600,
	)
	if err != nil {
		return "", fmt.Errorf("publish nested image: create staging file: %w", err)
	}
	keepStaging := true
	defer func() {
		_ = staged.Close()
		if keepStaging {
			_ = repository.Remove(stagingKey)
		}
	}()

	hasher := sha256.New()
	written, err := io.CopyBuffer(
		io.MultiWriter(staged, hasher),
		&derivedContextReader{
			ctx:    ctx,
			reader: io.NewSectionReader(source, 0, image.SizeBytes),
		},
		make([]byte, 1<<20),
	)
	if err != nil {
		return "", fmt.Errorf("publish nested image: copy source: %w", err)
	}
	if written != image.SizeBytes ||
		hex.EncodeToString(hasher.Sum(nil)) != image.SHA256 {
		return "", errors.New("publish nested image: source content changed")
	}
	var extra [1]byte
	if count, readErr := source.ReadAt(extra[:], image.SizeBytes); count != 0 || !errors.Is(readErr, io.EOF) {
		return "", errors.New("publish nested image: source size changed")
	}
	if err := staged.Sync(); err != nil {
		return "", fmt.Errorf("publish nested image: sync staging file: %w", err)
	}
	if err := staged.Close(); err != nil {
		return "", fmt.Errorf("publish nested image: close staging file: %w", err)
	}

	storageKey := path.Join(finalDirectory, image.SHA256)
	if err := linkRepositoryFile(
		repositoryRoot,
		stagingKey,
		storageKey,
	); err != nil {
		if !errors.Is(err, fs.ErrExist) {
			return "", fmt.Errorf("publish nested image: publish CAS file: %w", err)
		}
		if err := verifyRootFile(
			ctx,
			repository,
			storageKey,
			image.SizeBytes,
			image.SHA256,
		); err != nil {
			return "", err
		}
	} else if err := syncRootDirectory(repository, finalDirectory); err != nil {
		return "", fmt.Errorf("publish nested image: sync blob directory: %w", err)
	}
	if err := repository.Remove(stagingKey); err != nil {
		return "", fmt.Errorf("publish nested image: remove staging link: %w", err)
	}
	keepStaging = false
	if err := syncRootDirectory(repository, stagingDirectory); err != nil {
		return "", fmt.Errorf("publish nested image: sync staging directory: %w", err)
	}
	return storageKey, nil
}

func linkRepositoryFile(
	repositoryRoot string,
	sourceKey string,
	destinationKey string,
) error {
	rootFD, err := unix.Open(
		repositoryRoot,
		unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC,
		0,
	)
	if err != nil {
		return err
	}
	defer unix.Close(rootFD)
	sourceDirectory, err := openRepositoryDirectoryFD(
		rootFD,
		path.Dir(sourceKey),
	)
	if err != nil {
		return err
	}
	defer unix.Close(sourceDirectory)
	destinationDirectory, err := openRepositoryDirectoryFD(
		rootFD,
		path.Dir(destinationKey),
	)
	if err != nil {
		return err
	}
	defer unix.Close(destinationDirectory)
	return unix.Linkat(
		sourceDirectory,
		path.Base(sourceKey),
		destinationDirectory,
		path.Base(destinationKey),
		0,
	)
}

func openRepositoryDirectoryFD(rootFD int, name string) (int, error) {
	current := rootFD
	owned := false
	for _, component := range strings.Split(name, "/") {
		next, err := unix.Openat(
			current,
			component,
			unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC,
			0,
		)
		if owned {
			_ = unix.Close(current)
		}
		if err != nil {
			return -1, err
		}
		current = next
		owned = true
	}
	if !owned {
		return -1, errors.New("repository directory key is empty")
	}
	return current, nil
}

func openVerifiedRoot(value string) (*os.Root, error) {
	info, err := os.Lstat(value)
	if err != nil {
		return nil, fmt.Errorf("inspect root: %w", err)
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("root is not a real directory")
	}
	root, err := os.OpenRoot(value)
	if err != nil {
		return nil, fmt.Errorf("open root: %w", err)
	}
	opened, err := root.Stat(".")
	if err != nil || !opened.IsDir() || !os.SameFile(info, opened) {
		root.Close()
		return nil, errors.New("root changed while opening")
	}
	return root, nil
}

func ensurePrivateRootDirectory(root *os.Root, name string) error {
	segments := strings.Split(name, "/")
	for index := range segments {
		current := path.Join(segments[:index+1]...)
		info, err := root.Lstat(current)
		if errors.Is(err, fs.ErrNotExist) {
			if err := root.Mkdir(current, 0o700); err != nil &&
				!errors.Is(err, fs.ErrExist) {
				return err
			}
			info, err = root.Lstat(current)
		}
		if err != nil {
			return err
		}
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return errors.New("repository directory component is unsafe")
		}
		opened, err := root.Open(current)
		if err != nil {
			return err
		}
		openedInfo, statErr := opened.Stat()
		closeErr := opened.Close()
		if statErr != nil || closeErr != nil ||
			!openedInfo.IsDir() || !os.SameFile(info, openedInfo) {
			return errors.New("repository directory component changed")
		}
	}
	return nil
}

func verifyRootFile(
	ctx context.Context,
	root *os.Root,
	name string,
	size int64,
	expectedHash string,
) error {
	info, err := root.Lstat(name)
	if err != nil || !info.Mode().IsRegular() ||
		info.Mode()&os.ModeSymlink != 0 || info.Size() != size {
		return errors.New("publish nested image: existing CAS file conflicts")
	}
	file, err := root.Open(name)
	if err != nil {
		return fmt.Errorf("publish nested image: open existing CAS file: %w", err)
	}
	defer file.Close()
	openedInfo, err := file.Stat()
	if err != nil || !openedInfo.Mode().IsRegular() ||
		!os.SameFile(info, openedInfo) || openedInfo.Size() != size {
		return errors.New("publish nested image: existing CAS file changed")
	}
	hasher := sha256.New()
	written, err := io.CopyBuffer(
		hasher,
		&derivedContextReader{
			ctx:    ctx,
			reader: io.NewSectionReader(file, 0, size),
		},
		make([]byte, 1<<20),
	)
	if err != nil || written != size ||
		hex.EncodeToString(hasher.Sum(nil)) != expectedHash {
		return errors.New("publish nested image: existing CAS content conflicts")
	}
	return nil
}

func syncRootDirectory(root *os.Root, name string) error {
	directory, err := root.Open(name)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

type derivedContextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (reader *derivedContextReader) Read(buffer []byte) (int, error) {
	if err := reader.ctx.Err(); err != nil {
		return 0, err
	}
	return reader.reader.Read(buffer)
}

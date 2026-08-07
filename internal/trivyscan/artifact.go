package trivyscan

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"

	trivyadapter "binaryscan/internal/analyzers/trivy"
	"binaryscan/internal/queue"

	"golang.org/x/sys/unix"
)

type publishedArtifact struct {
	storageKey string
	sha256     string
	sizeBytes  int64
	created    bool
}

func rawArtifactStorageKey(
	taskID string,
	taskAttemptID uint64,
	runID string,
) string {
	return path.Join(
		"artifacts",
		taskID,
		"trivy",
		strconv.FormatUint(taskAttemptID, 10),
		runID+".json",
	)
}

func (r *MySQLRepository) publishRawArtifact(
	ctx context.Context,
	lease queue.Lease,
	runID string,
	raw trivyadapter.RawReportMetadata,
) (publishedArtifact, error) {
	source, err := openConfinedRegular(
		r.taskWorkRoot,
		raw.Path,
		true,
	)
	if err != nil {
		return publishedArtifact{}, fmt.Errorf(
			"%w: open raw report: %v",
			ErrInvalidPublication,
			err,
		)
	}
	defer source.Close()
	if err := verifyOpenArtifact(
		ctx,
		source,
		raw.SHA256,
		raw.SizeBytes,
		r.maxArtifactBytes,
	); err != nil {
		return publishedArtifact{}, fmt.Errorf(
			"%w: raw report changed: %v",
			ErrInvalidPublication,
			err,
		)
	}
	storageKey := rawArtifactStorageKey(
		lease.TaskID,
		*lease.TaskAttemptID,
		runID,
	)
	components := strings.Split(storageKey, "/")
	directory, err := openOrCreateRepositoryPath(
		r.repositoryRoot,
		components[:len(components)-1],
	)
	if err != nil {
		return publishedArtifact{}, err
	}
	defer directory.Close()
	finalName := components[len(components)-1]
	created := false
	keepFinal := false
	defer func() {
		if created && !keepFinal {
			_ = unlinkMatchingAt(
				directory,
				finalName,
				raw.SHA256,
				raw.SizeBytes,
			)
		}
	}()

	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		return publishedArtifact{}, fmt.Errorf("generate raw artifact staging name: %w", err)
	}
	stagingName := "." + runID + "." + hex.EncodeToString(random[:]) + ".staging"
	stagingFD, err := unix.Openat(
		int(directory.Fd()),
		stagingName,
		unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC,
		0o600,
	)
	if err != nil {
		return publishedArtifact{}, fmt.Errorf("create raw artifact staging file: %w", err)
	}
	staging := os.NewFile(uintptr(stagingFD), stagingName)
	if staging == nil {
		_ = unix.Close(stagingFD)
		_ = unix.Unlinkat(int(directory.Fd()), stagingName, 0)
		return publishedArtifact{}, errors.New("wrap raw artifact staging file")
	}
	stagingOpen := true
	defer func() {
		if stagingOpen {
			_ = staging.Close()
		}
		_ = unix.Unlinkat(int(directory.Fd()), stagingName, 0)
	}()
	hasher := sha256.New()
	reader := &contextReader{
		ctx:    ctx,
		reader: io.NewSectionReader(source, 0, raw.SizeBytes),
	}
	written, err := io.CopyBuffer(
		io.MultiWriter(staging, hasher),
		reader,
		make([]byte, 1<<20),
	)
	if err != nil {
		return publishedArtifact{}, fmt.Errorf("copy raw Trivy artifact: %w", err)
	}
	digest := hex.EncodeToString(hasher.Sum(nil))
	if written != raw.SizeBytes || digest != raw.SHA256 {
		return publishedArtifact{}, ErrInvalidPublication
	}
	if err := staging.Sync(); err != nil {
		return publishedArtifact{}, fmt.Errorf("sync raw artifact staging file: %w", err)
	}
	if err := staging.Chmod(0o640); err != nil {
		return publishedArtifact{}, fmt.Errorf("seal raw artifact staging file: %w", err)
	}
	if err := staging.Close(); err != nil {
		stagingOpen = false
		return publishedArtifact{}, fmt.Errorf("close raw artifact staging file: %w", err)
	}
	stagingOpen = false

	if err := unix.Linkat(
		int(directory.Fd()),
		stagingName,
		int(directory.Fd()),
		finalName,
		0,
	); err == nil {
		created = true
	} else if !errors.Is(err, unix.EEXIST) {
		return publishedArtifact{}, fmt.Errorf("publish raw Trivy artifact: %w", err)
	}
	if err := unix.Unlinkat(
		int(directory.Fd()),
		stagingName,
		0,
	); err != nil {
		return publishedArtifact{}, fmt.Errorf("remove raw artifact staging link: %w", err)
	}
	if err := directory.Sync(); err != nil {
		return publishedArtifact{}, fmt.Errorf("sync raw artifact directory: %w", err)
	}
	final, err := openRegularAt(directory, finalName)
	if err != nil {
		return publishedArtifact{}, fmt.Errorf("open published raw artifact: %w", err)
	}
	verifyErr := verifyOpenArtifact(
		ctx,
		final,
		raw.SHA256,
		raw.SizeBytes,
		r.maxArtifactBytes,
	)
	closeErr := final.Close()
	if verifyErr != nil || closeErr != nil {
		return publishedArtifact{}, errors.Join(verifyErr, closeErr)
	}
	keepFinal = true
	return publishedArtifact{
		storageKey: storageKey,
		sha256:     raw.SHA256,
		sizeBytes:  raw.SizeBytes,
		created:    created,
	}, nil
}

func (r *MySQLRepository) verifyRepositoryArtifact(
	ctx context.Context,
	record artifactRecord,
) error {
	file, err := openConfinedRegular(
		r.repositoryRoot,
		record.storageKey,
		false,
	)
	if err != nil {
		return fmt.Errorf(
			"%w: open completed raw artifact: %v",
			ErrInvalidPublication,
			err,
		)
	}
	defer file.Close()
	if err := verifyOpenArtifact(
		ctx,
		file,
		record.sha256,
		record.sizeBytes,
		r.maxArtifactBytes,
	); err != nil {
		return fmt.Errorf(
			"%w: completed raw artifact changed: %v",
			ErrInvalidPublication,
			err,
		)
	}
	return nil
}

func (r *MySQLRepository) removePublishedArtifact(
	artifact publishedArtifact,
) error {
	if !artifact.created {
		return nil
	}
	components := strings.Split(artifact.storageKey, "/")
	directory, err := openRepositoryPath(
		r.repositoryRoot,
		components[:len(components)-1],
	)
	if err != nil {
		return fmt.Errorf("open raw artifact cleanup directory: %w", err)
	}
	defer directory.Close()
	if err := unlinkMatchingAt(
		directory,
		components[len(components)-1],
		artifact.sha256,
		artifact.sizeBytes,
	); err != nil {
		return fmt.Errorf("remove unpublished raw artifact: %w", err)
	}
	return directory.Sync()
}

func unlinkMatchingAt(
	directory *os.File,
	name string,
	expectedSHA string,
	expectedSize int64,
) error {
	file, err := openRegularAt(directory, name)
	if errors.Is(err, os.ErrNotExist) || errors.Is(err, unix.ENOENT) {
		return nil
	}
	if err != nil {
		return err
	}
	verifyErr := verifyOpenArtifact(
		context.Background(),
		file,
		expectedSHA,
		expectedSize,
		expectedSize,
	)
	closeErr := file.Close()
	if verifyErr != nil || closeErr != nil {
		return errors.Join(verifyErr, closeErr)
	}
	return unix.Unlinkat(int(directory.Fd()), name, 0)
}

func verifyOpenArtifact(
	ctx context.Context,
	file *os.File,
	expectedSHA string,
	expectedSize int64,
	maximum int64,
) error {
	if expectedSize <= 0 || expectedSize > maximum {
		return errors.New("artifact size is outside the configured limit")
	}
	before, err := file.Stat()
	if err != nil || !before.Mode().IsRegular() ||
		before.Size() != expectedSize {
		return errors.New("artifact metadata does not match")
	}
	hasher := sha256.New()
	reader := &contextReader{
		ctx:    ctx,
		reader: io.NewSectionReader(file, 0, expectedSize),
	}
	written, err := io.CopyBuffer(hasher, reader, make([]byte, 256<<10))
	if err != nil {
		return err
	}
	after, err := file.Stat()
	if err != nil || !os.SameFile(before, after) ||
		after.Size() != expectedSize ||
		written != expectedSize ||
		hex.EncodeToString(hasher.Sum(nil)) != expectedSHA {
		return errors.New("artifact content does not match")
	}
	return nil
}

func verifyDirectoryRoot(value string) error {
	fd, err := unix.Open(
		value,
		unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC,
		0,
	)
	if err != nil {
		return err
	}
	return unix.Close(fd)
}

func openConfinedRegular(
	root string,
	value string,
	absolute bool,
) (*os.File, error) {
	var relative string
	if absolute {
		cleaned := filepath.Clean(value)
		if !filepath.IsAbs(cleaned) {
			return nil, errors.New("confined path must be absolute")
		}
		candidate, err := filepath.Rel(root, cleaned)
		if err != nil {
			return nil, err
		}
		relative = filepath.ToSlash(candidate)
	} else {
		relative = value
	}
	if relative == "" || relative == "." || path.IsAbs(relative) ||
		path.Clean(relative) != relative ||
		relative == ".." || strings.HasPrefix(relative, "../") ||
		strings.Contains(relative, `\`) {
		return nil, errors.New("confined path escapes root")
	}
	components := strings.Split(relative, "/")
	directory, err := openRepositoryPath(root, components[:len(components)-1])
	if err != nil {
		return nil, err
	}
	file, openErr := openRegularAt(directory, components[len(components)-1])
	closeErr := directory.Close()
	if openErr != nil {
		return nil, openErr
	}
	if closeErr != nil {
		_ = file.Close()
		return nil, closeErr
	}
	return file, nil
}

func openRegularAt(directory *os.File, name string) (*os.File, error) {
	fd, err := unix.Openat(
		int(directory.Fd()),
		name,
		unix.O_RDONLY|unix.O_NONBLOCK|unix.O_NOFOLLOW|unix.O_CLOEXEC,
		0,
	)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), name)
	if file == nil {
		_ = unix.Close(fd)
		return nil, errors.New("wrap confined regular file")
	}
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		_ = file.Close()
		return nil, errors.New("confined file is not regular")
	}
	return file, nil
}

func openOrCreateRepositoryPath(
	root string,
	components []string,
) (*os.File, error) {
	return traverseRepositoryPath(root, components, true)
}

func openRepositoryPath(
	root string,
	components []string,
) (*os.File, error) {
	return traverseRepositoryPath(root, components, false)
}

func traverseRepositoryPath(
	root string,
	components []string,
	create bool,
) (*os.File, error) {
	currentFD, err := unix.Open(
		root,
		unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC,
		0,
	)
	if err != nil {
		return nil, err
	}
	for _, component := range components {
		if component == "" || component == "." || component == ".." ||
			strings.Contains(component, "/") {
			_ = unix.Close(currentFD)
			return nil, errors.New("repository path component is invalid")
		}
		nextFD, openErr := unix.Openat(
			currentFD,
			component,
			unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC,
			0,
		)
		if errors.Is(openErr, unix.ENOENT) && create {
			if mkdirErr := unix.Mkdirat(currentFD, component, 0o700); mkdirErr != nil && !errors.Is(mkdirErr, unix.EEXIST) {
				_ = unix.Close(currentFD)
				return nil, mkdirErr
			}
			nextFD, openErr = unix.Openat(
				currentFD,
				component,
				unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC,
				0,
			)
		}
		closeErr := unix.Close(currentFD)
		if openErr != nil {
			return nil, openErr
		}
		if closeErr != nil {
			_ = unix.Close(nextFD)
			return nil, closeErr
		}
		currentFD = nextFD
	}
	file := os.NewFile(uintptr(currentFD), path.Join(components...))
	if file == nil {
		_ = unix.Close(currentFD)
		return nil, errors.New("wrap repository directory")
	}
	return file, nil
}

func stableUUID(namespace string, values ...string) string {
	hasher := sha256.New()
	_, _ = io.WriteString(hasher, namespace)
	for _, value := range values {
		_, _ = hasher.Write([]byte{0})
		_, _ = io.WriteString(hasher, value)
	}
	raw := hasher.Sum(nil)[:16]
	raw[6] = (raw[6] & 0x0f) | 0x50
	raw[8] = (raw[8] & 0x3f) | 0x80
	encoded := hex.EncodeToString(raw)
	return encoded[0:8] + "-" + encoded[8:12] + "-" +
		encoded[12:16] + "-" + encoded[16:20] + "-" + encoded[20:32]
}

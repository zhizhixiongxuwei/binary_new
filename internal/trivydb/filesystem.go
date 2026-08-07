package trivydb

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"golang.org/x/sys/unix"
)

type openedRoot struct {
	file     *os.File
	identity fileIdentity
}

func openRoot(value string) (*openedRoot, error) {
	fd, err := unix.Open(
		value,
		unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC,
		0,
	)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), filepath.Base(value))
	if file == nil {
		_ = unix.Close(fd)
		return nil, errors.New("wrap root descriptor")
	}
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, err
	}
	if !info.IsDir() {
		_ = file.Close()
		return nil, errors.New("root is not a directory")
	}
	identity, err := descriptorIdentity(int(file.Fd()))
	if err != nil {
		_ = file.Close()
		return nil, err
	}
	return &openedRoot{file: file, identity: identity}, nil
}

func (r *openedRoot) close() error {
	if r == nil || r.file == nil {
		return nil
	}
	err := r.file.Close()
	r.file = nil
	return err
}

type openedVersion struct {
	directory *os.File
	identity  fileIdentity
	files     map[string]*os.File
	fileInfo  map[string]fileIdentity
	target    string
	viewName  string
}

func (v *openedVersion) close() error {
	if v == nil {
		return nil
	}
	var result error
	for _, file := range v.files {
		result = errors.Join(result, file.Close())
	}
	v.files = nil
	if v.directory != nil {
		result = errors.Join(result, v.directory.Close())
		v.directory = nil
	}
	return result
}

func (r *Resolver) verifySnapshotSources(
	ctx context.Context,
	snapshot Snapshot,
) error {
	sources, err := r.openSnapshotSources(ctx, snapshot)
	if err != nil {
		return err
	}
	var closeErr error
	for _, source := range sources {
		closeErr = errors.Join(closeErr, source.close())
	}
	if closeErr != nil {
		return fmt.Errorf("close Trivy database sources: %w", closeErr)
	}
	return nil
}

func (r *Resolver) verifySnapshotHashes(ctx context.Context, snapshot Snapshot) error {
	sources, err := r.openSnapshotSources(ctx, snapshot)
	if err != nil {
		return err
	}
	defer closeOpenedVersions(sources)

	versions := []Version{snapshot.Trivy}
	if snapshot.Java != nil {
		versions = append(versions, *snapshot.Java)
	}
	for index, version := range versions {
		for _, declared := range version.Files {
			file := sources[index].files[declared.Path]
			if file == nil {
				return fmt.Errorf("%w: declared database file is unavailable", ErrUnsafeStorage)
			}
			actual, err := hashFileContext(ctx, file, declared.SizeBytes)
			if err != nil {
				return fmt.Errorf(
					"%w: hash %s/%s: %v",
					ErrUnsafeStorage,
					version.DatabaseType,
					declared.Path,
					err,
				)
			}
			if actual != declared.SHA256 {
				return fmt.Errorf(
					"%w: %s/%s hash does not match bundle manifest",
					ErrInvalidSnapshot,
					version.DatabaseType,
					declared.Path,
				)
			}
		}
	}
	return nil
}

func hashFileContext(ctx context.Context, file *os.File, size int64) (string, error) {
	reader := io.NewSectionReader(file, 0, size)
	hash := sha256.New()
	buffer := make([]byte, 1024*1024)
	for {
		if err := ctx.Err(); err != nil {
			return "", err
		}
		read, err := reader.Read(buffer)
		if read > 0 {
			_, _ = hash.Write(buffer[:read])
		}
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return "", err
		}
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func (r *Resolver) openSnapshotSources(
	ctx context.Context,
	snapshot Snapshot,
) ([]*openedVersion, error) {
	if err := validateSnapshot(snapshot); err != nil {
		return nil, err
	}
	root, err := openRoot(r.trivyRoot)
	if err != nil {
		return nil, fmt.Errorf("%w: open TrivyRoot: %v", ErrUnsafeStorage, err)
	}
	defer root.close()

	versions := []Version{snapshot.Trivy}
	if snapshot.Java != nil {
		versions = append(versions, *snapshot.Java)
	}
	sources := make([]*openedVersion, 0, len(versions))
	for _, version := range versions {
		if err := ctx.Err(); err != nil {
			closeOpenedVersions(sources)
			return nil, err
		}
		source, err := r.openVersionAt(root, version)
		if err != nil {
			closeOpenedVersions(sources)
			return nil, err
		}
		sources = append(sources, source)
	}
	return sources, nil
}

func (r *Resolver) openVersionAt(
	root *openedRoot,
	version Version,
) (*openedVersion, error) {
	if err := validateStorageKey(version); err != nil {
		return nil, err
	}
	relative := strings.TrimPrefix(version.StorageKey, "trivy/")
	parts := strings.Split(relative, "/")
	if len(parts) != 3 ||
		parts[1] != "versions" ||
		parts[2] != version.ID {
		return nil, fmt.Errorf(
			"%w: unexpected database version path",
			ErrUnsafeStorage,
		)
	}

	current, err := unix.Openat(
		int(root.file.Fd()),
		".",
		unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC,
		0,
	)
	if err != nil {
		return nil, fmt.Errorf("%w: duplicate TrivyRoot: %v", ErrUnsafeStorage, err)
	}
	for _, part := range parts {
		next, openErr := unix.Openat(
			current,
			part,
			unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC,
			0,
		)
		_ = unix.Close(current)
		if openErr != nil {
			return nil, fmt.Errorf(
				"%w: open %s version directory: %v",
				ErrUnsafeStorage,
				version.DatabaseType,
				openErr,
			)
		}
		current = next
	}
	directory := os.NewFile(uintptr(current), version.ID)
	if directory == nil {
		_ = unix.Close(current)
		return nil, fmt.Errorf("%w: wrap version directory", ErrUnsafeStorage)
	}
	info, err := directory.Stat()
	if err != nil {
		_ = directory.Close()
		return nil, fmt.Errorf("%w: inspect version directory: %v", ErrUnsafeStorage, err)
	}
	if !info.IsDir() || info.Mode().Perm()&0o222 != 0 {
		_ = directory.Close()
		return nil, fmt.Errorf(
			"%w: version directory is not sealed read-only",
			ErrUnsafeStorage,
		)
	}
	identity, err := descriptorIdentity(int(directory.Fd()))
	if err != nil {
		_ = directory.Close()
		return nil, fmt.Errorf(
			"%w: identify version directory: %v",
			ErrUnsafeStorage,
			err,
		)
	}

	names, err := expectedFiles(version.DatabaseType)
	if err != nil {
		_ = directory.Close()
		return nil, err
	}
	entries, err := directory.ReadDir(-1)
	if err != nil {
		_ = directory.Close()
		return nil, fmt.Errorf(
			"%w: list %s version directory: %v",
			ErrUnsafeStorage,
			version.DatabaseType,
			err,
		)
	}
	actualNames := make([]string, 0, len(entries))
	for _, entry := range entries {
		actualNames = append(actualNames, entry.Name())
	}
	slices.Sort(actualNames)
	if !slices.Equal(actualNames, names) {
		_ = directory.Close()
		return nil, fmt.Errorf(
			"%w: %s version directory has an unexpected file set",
			ErrUnsafeStorage,
			version.DatabaseType,
		)
	}
	expectedSizes := make(map[string]int64, len(version.Files))
	for _, file := range version.Files {
		expectedSizes[file.Path] = file.SizeBytes
	}
	source := &openedVersion{
		directory: directory,
		identity:  identity,
		files:     make(map[string]*os.File, len(names)),
		fileInfo:  make(map[string]fileIdentity, len(names)),
		target:    filepath.Join(r.trivyRoot, filepath.FromSlash(relative)),
		viewName:  parts[0],
	}
	for _, name := range names {
		fd, openErr := unix.Openat(
			int(directory.Fd()),
			name,
			unix.O_RDONLY|unix.O_NONBLOCK|unix.O_NOFOLLOW|unix.O_CLOEXEC,
			0,
		)
		if openErr != nil {
			_ = source.close()
			return nil, fmt.Errorf(
				"%w: open %s/%s: %v",
				ErrUnsafeStorage,
				version.DatabaseType,
				name,
				openErr,
			)
		}
		file := os.NewFile(uintptr(fd), name)
		if file == nil {
			_ = unix.Close(fd)
			_ = source.close()
			return nil, fmt.Errorf("%w: wrap database file", ErrUnsafeStorage)
		}
		fileInfo, statErr := file.Stat()
		if statErr != nil ||
			!fileInfo.Mode().IsRegular() ||
			fileInfo.Mode().Perm()&0o222 != 0 ||
			fileInfo.Size() != expectedSizes[name] {
			_ = file.Close()
			_ = source.close()
			return nil, fmt.Errorf(
				"%w: %s/%s is not a sealed regular file",
				ErrUnsafeStorage,
				version.DatabaseType,
				name,
			)
		}
		source.files[name] = file
		identity, identityErr := descriptorIdentity(int(file.Fd()))
		if identityErr != nil {
			_ = source.close()
			return nil, fmt.Errorf(
				"%w: identify %s/%s: %v",
				ErrUnsafeStorage,
				version.DatabaseType,
				name,
				identityErr,
			)
		}
		source.fileInfo[name] = identity
	}
	return source, nil
}

func validateSnapshot(snapshot Snapshot) error {
	if !uuidPattern.MatchString(snapshot.Bundle.ID) ||
		!versionPattern.MatchString(snapshot.Bundle.Version) ||
		snapshot.Bundle.GeneratedAt.IsZero() ||
		!hashPattern.MatchString(snapshot.Bundle.ContentSHA256) ||
		!json.Valid(snapshot.Bundle.ManifestJSON) ||
		snapshot.Trivy.DatabaseType != DatabaseTrivy {
		return fmt.Errorf(
			"%w: primary database type must be %s",
			ErrInvalidSnapshot,
			DatabaseTrivy,
		)
	}
	versions := []Version{snapshot.Trivy}
	if snapshot.Java != nil {
		if snapshot.Java.DatabaseType != DatabaseTrivyJava {
			return fmt.Errorf(
				"%w: Java database type must be %s",
				ErrInvalidSnapshot,
				DatabaseTrivyJava,
			)
		}
		versions = append(versions, *snapshot.Java)
	}
	for _, version := range versions {
		if !uuidPattern.MatchString(version.ID) ||
			!versionPattern.MatchString(version.Version) ||
			version.DatabaseSchemaVersion <= 0 ||
			version.DatabaseSchemaVersion > 1000 ||
			len(version.Files) == 0 {
			return fmt.Errorf(
				"%w: incomplete %s identity",
				ErrInvalidSnapshot,
				version.DatabaseType,
			)
		}
		if err := validateStorageKey(version); err != nil {
			return err
		}
	}
	return nil
}

func closeOpenedVersions(values []*openedVersion) {
	for _, value := range values {
		_ = value.close()
	}
}

func pathsOverlap(first, second string) bool {
	relative, err := filepath.Rel(first, second)
	if err == nil &&
		(relative == "." ||
			(relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)))) {
		return true
	}
	relative, err = filepath.Rel(second, first)
	return err == nil &&
		(relative == "." ||
			(relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator))))
}

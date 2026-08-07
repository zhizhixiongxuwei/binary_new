package trivydb

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

const (
	DatabaseTrivy     = "trivy-db"
	DatabaseTrivyJava = "trivy-java-db"

	BundleSchemaVersion = 1
	cacheViewName       = "trivy-cache"
	manifestFilename    = "bundle.json"
	maxManifestBytes    = int64(1 << 20)
	maxDatabaseBytes    = int64(4 << 30)
)

var (
	ErrInvalidConfiguration = errors.New("invalid Trivy database configuration")
	ErrUnavailable          = errors.New("required Trivy database bundle is unavailable")
	ErrInvalidSnapshot      = errors.New("invalid Trivy database bundle")
	ErrUnsafeStorage        = errors.New("unsafe Trivy database storage")
	ErrCacheViewExists      = errors.New("Trivy cache view already exists")

	uuidPattern = regexp.MustCompile(
		`^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$`,
	)
	hashPattern    = regexp.MustCompile(`^[a-f0-9]{64}$`)
	versionPattern = regexp.MustCompile(
		`^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$`,
	)
)

// JavaDBPolicy controls whether a scan may proceed without the Java database.
// Production bundles contain both databases; optional mode is retained for
// image formats that cannot contain Java artifacts.
type JavaDBPolicy uint8

const (
	JavaDBOptional JavaDBPolicy = iota
	JavaDBRequired
)

// File identifies one immutable file declared by the database bundle.
type File struct {
	Path      string `json:"path"`
	SHA256    string `json:"sha256"`
	SizeBytes int64  `json:"size_bytes"`
}

// Bundle is the single provenance identity recorded for both Trivy databases.
type Bundle struct {
	ID            string
	Version       string
	GeneratedAt   time.Time
	ContentSHA256 string
	ManifestJSON  []byte
}

// Version identifies one database component inside a bundle.
type Version struct {
	ID                    string
	DatabaseType          string
	DatabaseSchemaVersion int
	Version               string
	StorageKey            string
	Files                 []File
}

// Snapshot is the exact, immutable pair exposed to one scan job.
type Snapshot struct {
	Bundle Bundle
	Trivy  Version
	Java   *Version
}

type bundleManifest struct {
	SchemaVersion int                `json:"schema_version"`
	ID            string             `json:"id"`
	Version       string             `json:"version"`
	GeneratedAt   string             `json:"generated_at"`
	ContentSHA256 string             `json:"content_sha256"`
	Databases     []databaseManifest `json:"databases"`
}

type databaseManifest struct {
	ID            string `json:"id"`
	DatabaseType  string `json:"database_type"`
	Version       string `json:"version"`
	SchemaVersion int    `json:"schema_version"`
	StorageKey    string `json:"storage_key"`
	Files         []File `json:"files"`
}

// Resolver reads one fixed bundle from the scanner image. It has no database,
// network, signature, activation, or rollback dependency.
type Resolver struct {
	trivyRoot string
}

// NewResolver creates a resolver rooted at a read-only directory containing
// bundle.json, db/versions, and java-db/versions.
func NewResolver(trivyRoot string) (*Resolver, error) {
	if trivyRoot == "" ||
		!filepath.IsAbs(trivyRoot) ||
		filepath.Clean(trivyRoot) != trivyRoot ||
		trivyRoot == string(filepath.Separator) {
		return nil, fmt.Errorf(
			"%w: TrivyRoot must be a canonical absolute path below /",
			ErrInvalidConfiguration,
		)
	}
	root, err := openRoot(trivyRoot)
	if err != nil {
		return nil, fmt.Errorf(
			"%w: open TrivyRoot: %v",
			ErrInvalidConfiguration,
			err,
		)
	}
	if err := root.close(); err != nil {
		return nil, fmt.Errorf(
			"%w: close TrivyRoot: %v",
			ErrInvalidConfiguration,
			err,
		)
	}
	return &Resolver{trivyRoot: trivyRoot}, nil
}

// Resolve validates the fixed manifest and the sealed database file layout.
func (r *Resolver) Resolve(
	ctx context.Context,
	javaPolicy JavaDBPolicy,
) (Snapshot, error) {
	if r == nil || r.trivyRoot == "" {
		return Snapshot{}, fmt.Errorf("%w: nil resolver", ErrInvalidConfiguration)
	}
	if javaPolicy != JavaDBOptional && javaPolicy != JavaDBRequired {
		return Snapshot{}, fmt.Errorf(
			"%w: unknown Java database policy",
			ErrInvalidConfiguration,
		)
	}
	if err := ctx.Err(); err != nil {
		return Snapshot{}, err
	}

	raw, err := r.readManifest()
	if err != nil {
		return Snapshot{}, err
	}
	snapshot, err := decodeManifest(raw, javaPolicy)
	if err != nil {
		return Snapshot{}, err
	}
	if err := r.verifySnapshotSources(ctx, snapshot); err != nil {
		return Snapshot{}, err
	}
	return snapshot, nil
}

// VerifyIntegrity resolves the bundle and hashes every declared database file.
// It is intended for image build and acceptance checks rather than per-job use.
func (r *Resolver) VerifyIntegrity(
	ctx context.Context,
	javaPolicy JavaDBPolicy,
) (Snapshot, error) {
	snapshot, err := r.Resolve(ctx, javaPolicy)
	if err != nil {
		return Snapshot{}, err
	}
	if err := r.verifySnapshotHashes(ctx, snapshot); err != nil {
		return Snapshot{}, err
	}
	return snapshot, nil
}

// PrepareCacheView exposes the immutable database directories in a job-local
// Trivy cache without copying the databases.
func (r *Resolver) PrepareCacheView(
	ctx context.Context,
	workspaceRoot string,
	javaPolicy JavaDBPolicy,
) (*CacheView, error) {
	snapshot, err := r.Resolve(ctx, javaPolicy)
	if err != nil {
		return nil, err
	}
	return r.CreateCacheView(ctx, workspaceRoot, snapshot)
}

func (r *Resolver) readManifest() ([]byte, error) {
	root, err := openRoot(r.trivyRoot)
	if err != nil {
		return nil, fmt.Errorf("%w: open TrivyRoot: %v", ErrUnsafeStorage, err)
	}
	defer root.close()
	fd, err := unix.Openat(
		int(root.file.Fd()),
		manifestFilename,
		unix.O_RDONLY|unix.O_NONBLOCK|unix.O_NOFOLLOW|unix.O_CLOEXEC,
		0,
	)
	if err != nil {
		return nil, fmt.Errorf("%w: open %s: %v", ErrUnavailable, manifestFilename, err)
	}
	opened := os.NewFile(uintptr(fd), manifestFilename)
	if opened == nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("%w: wrap bundle manifest", ErrUnsafeStorage)
	}
	defer opened.Close()
	info, err := opened.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o222 != 0 {
		return nil, fmt.Errorf(
			"%w: bundle manifest is not a sealed regular file",
			ErrUnsafeStorage,
		)
	}
	if info.Size() <= 0 || info.Size() > maxManifestBytes {
		return nil, fmt.Errorf("%w: bundle manifest size is invalid", ErrInvalidSnapshot)
	}
	raw, err := io.ReadAll(io.LimitReader(opened, maxManifestBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read bundle manifest: %w", err)
	}
	if int64(len(raw)) != info.Size() {
		return nil, fmt.Errorf("%w: bundle manifest changed while reading", ErrUnsafeStorage)
	}
	return raw, nil
}

func decodeManifest(raw []byte, javaPolicy JavaDBPolicy) (Snapshot, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var manifest bundleManifest
	if err := decoder.Decode(&manifest); err != nil {
		return Snapshot{}, fmt.Errorf("%w: decode bundle manifest: %v", ErrInvalidSnapshot, err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return Snapshot{}, fmt.Errorf("%w: bundle manifest has trailing JSON", ErrInvalidSnapshot)
	}
	if manifest.SchemaVersion != BundleSchemaVersion ||
		!uuidPattern.MatchString(manifest.ID) ||
		!versionPattern.MatchString(manifest.Version) ||
		!hashPattern.MatchString(manifest.ContentSHA256) {
		return Snapshot{}, fmt.Errorf("%w: bundle identity is invalid", ErrInvalidSnapshot)
	}
	generatedAt, err := time.Parse(time.RFC3339, manifest.GeneratedAt)
	if err != nil || generatedAt.IsZero() || generatedAt.Location() != time.UTC ||
		generatedAt.Format(time.RFC3339) != manifest.GeneratedAt {
		return Snapshot{}, fmt.Errorf(
			"%w: generated_at must be canonical UTC RFC3339",
			ErrInvalidSnapshot,
		)
	}
	if len(manifest.Databases) != 2 {
		return Snapshot{}, fmt.Errorf(
			"%w: bundle must contain trivy-db and trivy-java-db",
			ErrInvalidSnapshot,
		)
	}
	if calculatedBundleHash(manifest.Databases) != manifest.ContentSHA256 {
		return Snapshot{}, fmt.Errorf(
			"%w: content_sha256 does not match database metadata",
			ErrInvalidSnapshot,
		)
	}

	snapshot := Snapshot{Bundle: Bundle{
		ID:            manifest.ID,
		Version:       manifest.Version,
		GeneratedAt:   generatedAt,
		ContentSHA256: manifest.ContentSHA256,
		ManifestJSON:  append([]byte(nil), raw...),
	}}
	seen := make(map[string]struct{}, 2)
	for _, database := range manifest.Databases {
		version, err := validateDatabaseManifest(database)
		if err != nil {
			return Snapshot{}, err
		}
		if _, duplicate := seen[version.DatabaseType]; duplicate {
			return Snapshot{}, fmt.Errorf(
				"%w: duplicate %s component",
				ErrInvalidSnapshot,
				version.DatabaseType,
			)
		}
		seen[version.DatabaseType] = struct{}{}
		switch version.DatabaseType {
		case DatabaseTrivy:
			snapshot.Trivy = version
		case DatabaseTrivyJava:
			value := version
			snapshot.Java = &value
		}
	}
	if snapshot.Trivy.DatabaseType != DatabaseTrivy {
		return Snapshot{}, fmt.Errorf("%w: %s", ErrUnavailable, DatabaseTrivy)
	}
	if javaPolicy == JavaDBRequired && snapshot.Java == nil {
		return Snapshot{}, fmt.Errorf("%w: %s", ErrUnavailable, DatabaseTrivyJava)
	}
	return snapshot, nil
}

func validateDatabaseManifest(value databaseManifest) (Version, error) {
	if !uuidPattern.MatchString(value.ID) ||
		!versionPattern.MatchString(value.Version) {
		return Version{}, fmt.Errorf("%w: database identity is invalid", ErrInvalidSnapshot)
	}
	expectedSchema := 0
	switch value.DatabaseType {
	case DatabaseTrivy:
		expectedSchema = 2
	case DatabaseTrivyJava:
		expectedSchema = 1
	default:
		return Version{}, fmt.Errorf(
			"%w: unsupported database type %q",
			ErrInvalidSnapshot,
			value.DatabaseType,
		)
	}
	if value.SchemaVersion != expectedSchema {
		return Version{}, fmt.Errorf(
			"%w: unexpected %s schema version",
			ErrInvalidSnapshot,
			value.DatabaseType,
		)
	}
	version := Version{
		ID:                    value.ID,
		DatabaseType:          value.DatabaseType,
		DatabaseSchemaVersion: value.SchemaVersion,
		Version:               value.Version,
		StorageKey:            value.StorageKey,
		Files:                 append([]File(nil), value.Files...),
	}
	if err := validateStorageKey(version); err != nil {
		return Version{}, err
	}
	expectedFiles, err := expectedFiles(value.DatabaseType)
	if err != nil {
		return Version{}, err
	}
	if len(value.Files) != len(expectedFiles) {
		return Version{}, fmt.Errorf(
			"%w: %s has an unexpected file set",
			ErrInvalidSnapshot,
			value.DatabaseType,
		)
	}
	actualFiles := make([]string, 0, len(value.Files))
	total := int64(0)
	for _, file := range value.Files {
		if !hashPattern.MatchString(file.SHA256) || file.SizeBytes <= 0 ||
			file.SizeBytes > maxDatabaseBytes-total {
			return Version{}, fmt.Errorf(
				"%w: %s file metadata is invalid",
				ErrInvalidSnapshot,
				value.DatabaseType,
			)
		}
		if _, err := hex.DecodeString(file.SHA256); err != nil {
			return Version{}, fmt.Errorf(
				"%w: %s file hash is invalid",
				ErrInvalidSnapshot,
				value.DatabaseType,
			)
		}
		total += file.SizeBytes
		actualFiles = append(actualFiles, file.Path)
	}
	if !slices.Equal(actualFiles, expectedFiles) {
		return Version{}, fmt.Errorf(
			"%w: %s files must use canonical order",
			ErrInvalidSnapshot,
			value.DatabaseType,
		)
	}
	return version, nil
}

func calculatedBundleHash(databases []databaseManifest) string {
	values := append([]databaseManifest(nil), databases...)
	slices.SortFunc(values, func(left, right databaseManifest) int {
		return strings.Compare(left.DatabaseType, right.DatabaseType)
	})
	hash := sha256.New()
	for _, database := range values {
		_, _ = io.WriteString(hash, database.DatabaseType+"\x00")
		_, _ = io.WriteString(hash, database.ID+"\x00")
		_, _ = io.WriteString(hash, database.Version+"\x00")
		_, _ = io.WriteString(hash, strconv.Itoa(database.SchemaVersion)+"\x00")
		_, _ = io.WriteString(hash, database.StorageKey+"\x00")
		for _, file := range database.Files {
			_, _ = io.WriteString(hash, file.Path+"\x00")
			_, _ = io.WriteString(hash, file.SHA256+"\x00")
			_, _ = io.WriteString(hash, strconv.FormatInt(file.SizeBytes, 10)+"\x00")
		}
	}
	return hex.EncodeToString(hash.Sum(nil))
}

func validateStorageKey(version Version) error {
	directory, err := storageDirectory(version.DatabaseType)
	if err != nil {
		return err
	}
	expected := path.Join("trivy", directory, "versions", version.ID)
	if version.StorageKey != expected ||
		path.Clean(version.StorageKey) != version.StorageKey ||
		strings.Contains(version.StorageKey, `\`) {
		return fmt.Errorf(
			"%w: %s storage key must be %q",
			ErrUnsafeStorage,
			version.DatabaseType,
			expected,
		)
	}
	return nil
}

func storageDirectory(databaseType string) (string, error) {
	switch databaseType {
	case DatabaseTrivy:
		return "db", nil
	case DatabaseTrivyJava:
		return "java-db", nil
	default:
		return "", fmt.Errorf(
			"%w: unsupported database type %q",
			ErrInvalidSnapshot,
			databaseType,
		)
	}
}

func expectedFiles(databaseType string) ([]string, error) {
	switch databaseType {
	case DatabaseTrivy:
		return []string{"metadata.json", "trivy.db"}, nil
	case DatabaseTrivyJava:
		return []string{"metadata.json", "trivy-java.db"}, nil
	default:
		return nil, fmt.Errorf(
			"%w: unsupported database type %q",
			ErrInvalidSnapshot,
			databaseType,
		)
	}
}

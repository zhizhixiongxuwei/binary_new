// Package trivyscan implements the fenced, offline Trivy image-scan worker.
package trivyscan

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"time"

	trivyadapter "binaryscan/internal/analyzers/trivy"
	"binaryscan/internal/containerarchive"
	"binaryscan/internal/queue"
	"binaryscan/internal/trivydb"
	"binaryscan/internal/trivyhandoff"
)

const (
	// PayloadSchemaVersion remains the legacy single-source fixture version.
	// New scan workers write BatchedPayloadSchemaVersion.
	PayloadSchemaVersion        = trivyhandoff.LegacySchemaVersion
	BatchedPayloadSchemaVersion = trivyhandoff.SchemaVersion
	AnalyzerName                = "trivy"
)

var (
	ErrInvalidConfiguration = errors.New("Trivy scan configuration is invalid")
	ErrInvalidPayload       = errors.New("Trivy handoff payload is invalid")
	ErrUnsafeSource         = errors.New("Trivy source storage is unsafe")
	ErrSourceMismatch       = errors.New("Trivy source does not match handoff metadata")
	ErrInvalidPublication   = errors.New("Trivy publication is invalid")
)

type HandoffSource = trivyhandoff.Source

// HandoffPayload is normalized to Sources by DecodePayload. The legacy fields
// remain only so version-one queued jobs and tests can still be marshaled.
type HandoffPayload struct {
	SchemaVersion    int             `json:"schema_version"`
	Sources          []HandoffSource `json:"sources,omitempty"`
	MaxExpandedBytes int64           `json:"max_expanded_bytes,omitempty"`
	MaxArchiveRatio  int             `json:"max_archive_ratio,omitempty"`
	Format           string          `json:"format,omitempty"`
	SourceStorageKey string          `json:"source_storage_key,omitempty"`
	SourceSHA256     string          `json:"source_sha256,omitempty"`
	SourceSizeBytes  int64           `json:"source_size_bytes,omitempty"`
	ImageLogicalPath string          `json:"image_logical_path,omitempty"`
	UpstreamPartial  bool            `json:"upstream_partial"`
}

// Config fixes all processor-owned paths and aggregate limits.
type Config struct {
	RepositoryRoot       string
	TaskWorkRoot         string
	AnalyzerVersion      string
	JavaDBPolicy         trivydb.JavaDBPolicy
	ArchiveLimits        containerarchive.Limits
	MaxSourceBytes       int64
	MaxExpandedBytes     int64
	MaxReportBytes       int64
	MaxPublishedFindings int
	StorageMinFreeBytes  int64
	StorageGuard         StorageGuard
	Now                  func() time.Time
}

// StorageGuard atomically reserves the independently planned task-work and
// repository peaks while preserving both roots' low-water marks.
type StorageGuard interface {
	CheckCreate(context.Context, int64) error
	ReservePlan(context.Context, int64, int64) (func(), error)
}

// Analyzer is the narrow adapter boundary used for each explicit image target.
type Analyzer interface {
	Analyze(context.Context, trivyadapter.Request) (trivyadapter.Report, error)
}

// AdapterFactory creates one adapter bound to a job-local read-only cache and
// sibling input/output roots.
type AdapterFactory func(
	cacheDirectory string,
	workRoot string,
	inputRoots []string,
	maxWorkBytes int64,
) (Analyzer, error)

// NewAdapterFactory turns the fixed executable and limits in base into a
// per-job factory. Caller-supplied cache/work/input paths are always replaced.
func NewAdapterFactory(base trivyadapter.Config) AdapterFactory {
	return func(
		cacheDirectory string,
		workRoot string,
		inputRoots []string,
		maxWorkBytes int64,
	) (Analyzer, error) {
		if maxWorkBytes <= 0 ||
			(base.MaxWorkBytes > 0 && maxWorkBytes > base.MaxWorkBytes) {
			return nil, fmt.Errorf(
				"%w: per-job work limit is invalid",
				trivyadapter.ErrInvalidConfiguration,
			)
		}
		config := base
		config.CacheDirectory = cacheDirectory
		config.WorkRoot = workRoot
		config.InputRoots = append([]string(nil), inputRoots...)
		config.MaxWorkBytes = maxWorkBytes
		return trivyadapter.New(config)
	}
}

// DatabaseView is one immutable database snapshot exposed in a job cache.
type DatabaseView interface {
	Path() string
	Snapshot() trivydb.Snapshot
	Close() error
}

// DatabaseProvider resolves and builds a cache view inside workspaceRoot.
type DatabaseProvider func(
	ctx context.Context,
	workspaceRoot string,
	policy trivydb.JavaDBPolicy,
) (DatabaseView, error)

// NewDatabaseProvider adapts the hardened active-database resolver.
func NewDatabaseProvider(resolver *trivydb.Resolver) DatabaseProvider {
	return func(
		ctx context.Context,
		workspaceRoot string,
		policy trivydb.JavaDBPolicy,
	) (DatabaseView, error) {
		if resolver == nil {
			return nil, fmt.Errorf("%w: nil database resolver", ErrInvalidConfiguration)
		}
		return resolver.PrepareCacheView(ctx, workspaceRoot, policy)
	}
}

// Repository atomically publishes all completed target runs for one fenced
// Trivy job.
type Repository interface {
	Publish(context.Context, queue.Lease, Publication) error
}

type ProgressReporter interface {
	TaskProgress(context.Context, queue.Lease, queue.ProgressInput) error
	TaskActivity(context.Context, queue.Lease, queue.ActivityInput) error
}

// PublishSummary reports the effective persisted target states. It can differ
// from the current pass when a fenced retry reuses an already-completed run.
type PublishSummary struct {
	Succeeded         int
	Failed            int
	TransientFailures int
}

// SummaryRepository is implemented by repositories that can report effective
// idempotent replay state. Processor falls back to the current pass for simple
// test or alternate repositories.
type SummaryRepository interface {
	PublishWithSummary(
		context.Context,
		queue.Lease,
		Publication,
	) (PublishSummary, error)
}

// Publication is the complete database mutation for one processing pass.
type Publication struct {
	AnalyzerVersion  string
	SourceFormat     string
	SourceSHA256     string
	SourceStorageKey string
	StartedAt        time.Time
	CompletedAt      time.Time
	Snapshot         trivydb.Snapshot
	Runs             []RunResult
}

// RunResult represents exactly one Docker image or OCI manifest target.
type RunResult struct {
	TargetKey        string
	SourceFormat     string
	SourceSHA256     string
	SourceStorageKey string
	SourceSizeBytes  int64
	ImageLogicalPath string
	Platform         string
	ManifestDigest   string
	References       []string
	Status           string
	ErrorCode        string
	ErrorMessage     string
	Raw              *trivyadapter.RawReportMetadata
	Findings         []trivyadapter.Finding
}

type workDirectory interface {
	Path() string
	Cleanup() error
}

type workspaceFactory func(string, queue.Lease) (workDirectory, error)

type Processor struct {
	repository   Repository
	progress     ProgressReporter
	databases    DatabaseProvider
	newAdapter   AdapterFactory
	config       Config
	newWorkspace workspaceFactory
	storage      StorageGuard
}

// MySQLRepository persists analyzer runs, raw artifacts, and normalized
// findings under an exact active job lease.
type MySQLRepository struct {
	db               *sql.DB
	repositoryRoot   string
	taskWorkRoot     string
	maxArtifactBytes int64
}

type runParameters struct {
	SchemaVersion      int               `json:"schema_version"`
	Scanner            string            `json:"scanner"`
	Offline            bool              `json:"offline"`
	CacheBackend       string            `json:"cache_backend"`
	SourceFormat       string            `json:"source_format"`
	SourceSHA256       string            `json:"source_sha256"`
	SourceSizeBytes    int64             `json:"source_size_bytes,omitempty"`
	ImageLogicalPath   string            `json:"image_logical_path,omitempty"`
	TargetKey          string            `json:"target_key"`
	ManifestDigest     string            `json:"manifest_digest,omitempty"`
	Platform           string            `json:"platform"`
	References         []string          `json:"references"`
	ResultFindingCount int               `json:"result_finding_count"`
	Analyzer           analyzerIdentity  `json:"analyzer"`
	DatabaseBundle     bundleIdentity    `json:"database_bundle"`
	TrivyDB            databaseIdentity  `json:"trivy_db"`
	JavaDB             *databaseIdentity `json:"java_db,omitempty"`
	RawArtifact        *rawIdentity      `json:"raw_artifact,omitempty"`
}

type analyzerIdentity struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type bundleIdentity struct {
	ID            string    `json:"id"`
	Version       string    `json:"version"`
	GeneratedAt   time.Time `json:"generated_at"`
	ContentSHA256 string    `json:"content_sha256"`
}

type databaseIdentity struct {
	ID                    string `json:"id"`
	DatabaseType          string `json:"database_type"`
	Version               string `json:"version"`
	DatabaseSchemaVersion int    `json:"database_schema_version"`
}

type rawIdentity struct {
	SHA256        string `json:"sha256"`
	SizeBytes     int64  `json:"size_bytes"`
	SchemaVersion int    `json:"schema_version"`
	FindingCount  int    `json:"finding_count"`
}

type findingEvidence struct {
	PackageName      string                   `json:"package_name"`
	InstalledVersion string                   `json:"installed_version"`
	FixedVersion     string                   `json:"fixed_version,omitempty"`
	PackagePath      string                   `json:"package_path,omitempty"`
	Target           string                   `json:"target"`
	Class            string                   `json:"class"`
	Type             string                   `json:"type"`
	ImageLogicalPath string                   `json:"image_logical_path"`
	ImagePlatform    string                   `json:"image_platform,omitempty"`
	ImageReferences  []string                 `json:"image_references,omitempty"`
	ManifestDigest   string                   `json:"manifest_digest,omitempty"`
	DataSource       *trivyadapter.DataSource `json:"data_source,omitempty"`
}

func (p Publication) parameters(run RunResult) (json.RawMessage, error) {
	trivyIdentity := databaseIdentityFrom(p.Snapshot.Trivy)
	sourceFormat := run.SourceFormat
	if sourceFormat == "" {
		sourceFormat = p.SourceFormat
	}
	sourceSHA256 := run.SourceSHA256
	if sourceSHA256 == "" {
		sourceSHA256 = p.SourceSHA256
	}
	parameterSchemaVersion := 1
	imageLogicalPath := ""
	if run.SourceFormat != "" {
		parameterSchemaVersion = 2
		imageLogicalPath = run.ImageLogicalPath
	}
	value := runParameters{
		SchemaVersion:      parameterSchemaVersion,
		Scanner:            "vuln",
		Offline:            true,
		CacheBackend:       "memory",
		SourceFormat:       sourceFormat,
		SourceSHA256:       sourceSHA256,
		SourceSizeBytes:    run.SourceSizeBytes,
		ImageLogicalPath:   imageLogicalPath,
		TargetKey:          run.TargetKey,
		ManifestDigest:     run.ManifestDigest,
		Platform:           run.Platform,
		References:         append([]string(nil), run.References...),
		ResultFindingCount: len(run.Findings),
		Analyzer: analyzerIdentity{
			Name: AnalyzerName, Version: p.AnalyzerVersion,
		},
		DatabaseBundle: bundleIdentity{
			ID:            p.Snapshot.Bundle.ID,
			Version:       p.Snapshot.Bundle.Version,
			GeneratedAt:   p.Snapshot.Bundle.GeneratedAt,
			ContentSHA256: p.Snapshot.Bundle.ContentSHA256,
		},
		TrivyDB: trivyIdentity,
	}
	if p.Snapshot.Java != nil {
		javaIdentity := databaseIdentityFrom(*p.Snapshot.Java)
		value.JavaDB = &javaIdentity
	}
	if run.Raw != nil {
		value.RawArtifact = &rawIdentity{
			SHA256:        run.Raw.SHA256,
			SizeBytes:     run.Raw.SizeBytes,
			SchemaVersion: run.Raw.SchemaVersion,
			FindingCount:  run.Raw.FindingCount,
		}
	}
	raw, err := json.Marshal(value)
	if err != nil {
		return nil, fmt.Errorf("encode Trivy run parameters: %w", err)
	}
	return raw, nil
}

func databaseIdentityFrom(value trivydb.Version) databaseIdentity {
	return databaseIdentity{
		ID: value.ID, DatabaseType: value.DatabaseType, Version: value.Version,
		DatabaseSchemaVersion: value.DatabaseSchemaVersion,
	}
}

func cleanAbsoluteRoot(value string) (string, bool) {
	cleaned := filepath.Clean(value)
	return cleaned, filepath.IsAbs(cleaned) &&
		cleaned != string(filepath.Separator)
}

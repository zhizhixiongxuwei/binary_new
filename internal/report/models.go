package report

import (
	"context"
	"io"
	"time"
)

const SchemaVersion = "1.3.0"

type Format string

const (
	FormatJSON Format = "json"
	FormatHTML Format = "html"
	FormatDOCX Format = "docx"
)

type Report struct {
	ID              string     `json:"id"`
	TaskID          string     `json:"task_id"`
	Format          Format     `json:"format"`
	SchemaVersion   string     `json:"schema_version"`
	Status          string     `json:"status"`
	SnapshotState   string     `json:"snapshot_state"`
	Generation      uint64     `json:"generation"`
	SHA256          *string    `json:"sha256"`
	SizeBytes       *uint64    `json:"size_bytes"`
	ErrorCode       *string    `json:"error_code"`
	ErrorMessage    *string    `json:"error_message"`
	CreatedAt       time.Time  `json:"created_at"`
	CompletedAt     *time.Time `json:"completed_at"`
	GenerationOwner string     `json:"-"`
	GenerationFence uint64     `json:"-"`
}

type List struct {
	Items          []Report `json:"items"`
	SampleRelation string   `json:"sample_relation"`
}

type Claim struct {
	TaskID        string
	ReportID      string
	Format        Format
	SchemaVersion string
	CreatedAt     time.Time
	LeaseOwner    string
	LeaseDuration time.Duration
}

type SnapshotRequest struct {
	TaskID            string
	ReportID          string
	GeneratedAt       time.Time
	Dependencies      *[]CAnalysisDependency
	JavaDependencies  *[]JavaAnalysisDependency
	PythonDependencies *[]PythonAnalysisDependency
}

// CAnalysisDependency binds a report snapshot to the immutable C-analysis
// result selected for one source project. It deliberately contains only
// provenance, never source text or finding evidence.
type CAnalysisDependency struct {
	RunID        string
	ProjectID    string
	CompletedAt  time.Time
	SourceSHA256 string
}

// JavaAnalysisDependency binds a report snapshot to the immutable Java
// analysis selected for one source project. Source content and finding text are
// intentionally excluded from this persistence boundary.
type JavaAnalysisDependency struct {
	RunID                string
	ProjectID            string
	CompletedAt          time.Time
	SourceManifestSHA256 string
	InputSHA256          string
}

type ArtifactMetadata struct {
	StorageKey       string
	SHA256           string
	SizeBytes        uint64
	CompletedAt      time.Time
	Dependencies     []CAnalysisDependency
	JavaDependencies []JavaAnalysisDependency
}

type DownloadDescriptor struct {
	ReportID   string
	TaskID     string
	Format     Format
	Status     string
	StorageKey string
	SHA256     string
	SizeBytes  uint64
}

type ReadSeekCloser interface {
	io.Reader
	io.Seeker
	io.Closer
}

type Download struct {
	Content     ReadSeekCloser
	ContentType string
	Filename    string
	SHA256      string
	SizeBytes   uint64
}

type Repository interface {
	List(context.Context, string) (List, error)
	Claim(context.Context, Claim) (Report, bool, error)
	WriteJSONSnapshot(context.Context, SnapshotRequest, io.Writer) error
	WriteHTMLSnapshot(context.Context, SnapshotRequest, io.Writer) error
	WriteDOCXSnapshot(context.Context, SnapshotRequest, io.Writer) error
	Renew(context.Context, string, string, string, uint64, time.Duration) (bool, error)
	AuthorizePublish(context.Context, string, string, string, uint64) error
	Complete(context.Context, string, string, string, uint64, ArtifactMetadata) (Report, error)
	Fail(context.Context, string, string, string, uint64, string, string, time.Time) error
	Download(context.Context, string, string) (DownloadDescriptor, error)
}

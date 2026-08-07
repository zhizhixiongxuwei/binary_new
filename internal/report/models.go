package report

import (
	"context"
	"io"
	"time"
)

const SchemaVersion = "1.1.0"

type Format string

const (
	FormatJSON Format = "json"
	FormatHTML Format = "html"
)

type Report struct {
	ID              string     `json:"id"`
	TaskID          string     `json:"task_id"`
	Format          Format     `json:"format"`
	SchemaVersion   string     `json:"schema_version"`
	Status          string     `json:"status"`
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
	TaskID      string
	ReportID    string
	GeneratedAt time.Time
}

type ArtifactMetadata struct {
	StorageKey  string
	SHA256      string
	SizeBytes   uint64
	CompletedAt time.Time
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
	Renew(context.Context, string, string, string, uint64, time.Duration) (bool, error)
	AuthorizePublish(context.Context, string, string, string, uint64) error
	Complete(context.Context, string, string, string, uint64, ArtifactMetadata) (Report, error)
	Fail(context.Context, string, string, string, uint64, string, string, time.Time) error
	Download(context.Context, string, string) (DownloadDescriptor, error)
}

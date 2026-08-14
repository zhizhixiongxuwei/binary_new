// Package pythonanalysis implements the fenced Python static-analysis worker
// domain. It submits decompiled Python sources to the offline
// python-checker service and persists normalized runs and findings.
package pythonanalysis

import (
	"context"
	"errors"
	"time"

	"binaryscan/internal/auth"
	"binaryscan/internal/queue"
)

const (
	AnalyzerVersion = "0.1.0"
	RequestSchema  = "binaryscan-python-analysis-request/v1"
	ResponseSchema = "binaryscan-python-analysis-response/v1"
	RulesetVersion = "python-rules-v1"
	AnalyzerName   = "binaryscan-python-checker"

	MaxSourceFiles    = 200
	MaxFindings       = 10000
	MaxDiagnostics    = 1000
	MaxSourceBytes    = 134217728
	MaxResponseBytes  = 64 << 20
	MaxFileCount      = 3000
	MaxFileNameBytes  = 1024
	MaxMessageBytes   = 2048
	MaxDiagnosticCode = 128
	MaxFiles          = 200
	RequestSchemaVersion = "1.0"
)

var (
	ErrInvalidInput     = errors.New("python analysis input is invalid")
	ErrTaskNotFound     = errors.New("python analysis task is not found")
	ErrIdempotencyConflict = errors.New("python analysis idempotency conflict")
	ErrAlreadyActive    = errors.New("python analysis is already active")
	ErrRunNotFound      = errors.New("python analysis run is not found")
	ErrCheckerBusy      = errors.New("python checker is busy")
	ErrRunNotCancellable = errors.New("python analysis run is not cancellable")
	ErrRunNotDeletable   = errors.New("python analysis run is not deletable")
	ErrInvalidResponse  = errors.New("python analysis response is invalid")
	ErrCheckerRejected  = errors.New("python checker rejected the analysis")
	ErrCheckerTransient = errors.New("python checker request failed transiently")
	ErrCheckerTimedOut  = errors.New("python checker analysis timed out")
	ErrNotReady         = errors.New("python checker is not ready")
	ErrNotFound         = errors.New("python analysis run is not found")
)

// AnalysisRequest carries the bounded source snapshot and run metadata.
type AnalysisRequest struct {
	Source   []SourceFile
	Metadata RequestMetadata
}

// RequestMetadata identifies the run on both sides of the boundary.
type RequestMetadata struct {
	RunID    string
	TaskID   string
	JobID    string
	Attempt  uint32
	Manifest [32]byte
}
// Result is the validated checker outcome for one analysis request.
type Result struct {
	AnalyzedFiles        int
	ParsedFiles          int
	RecoveredFiles       int
	FailedFiles          int
	Findings             []Finding
	Diagnostics          []Diagnostic
	FindingsTruncated    bool
	DiagnosticsTruncated bool
}
// Severity counts derived from Findings.
func (result Result) SeverityCounts() (low, medium, high, critical int) {
	for _, finding := range result.Findings {
		switch finding.Severity {
		case "LOW":
			low++
		case "MEDIUM":
			medium++
		case "HIGH":
			high++
		case "CRITICAL":
			critical++
		}
	}
	return low, medium, high, critical
}

// ManifestFile is one manifest-verified source file of the project.
type ManifestFile struct {
	LogicalPath string
	SHA256      string
	SizeBytes   uint64
}

// ProjectSnapshot is the immutable decompiled-source project selected for
// analysis, including the manifest-verified file listing.
type ProjectSnapshot struct {
	TaskID                 string
	ProjectID              string
	ProjectStatus          string
	EngineName             string
	EngineVersion          string
	RootStorageKey         string
	ManifestStorageKey     string
	ManifestSHA256         string
	ManifestSizeBytes      uint64
	ProjectSourceFileCount uint64
	ProjectSourceSizeBytes uint64
	InputSHA256            string
	SourceSizeBytes        uint64
	Files                  []ManifestFile
}
// Checker is the narrow python-checker boundary used by the processor.
type Checker interface {
	Analyze(context.Context, AnalysisRequest) (Result, error)
	Ready(context.Context) error
}

// ProcessorRepository persists the fenced run lifecycle.
type ProcessorRepository interface {
	Begin(context.Context, queue.Lease) (ProjectSnapshot, error)
	Publish(context.Context, queue.Lease, RequestMetadata, Result) error
	PublishFailed(context.Context, queue.Lease, RequestMetadata, Result) error
	Retry(context.Context, queue.Lease, string, string) error
	Fail(context.Context, queue.Lease, string, string) error
}


// Run is the persisted analysis run row (API shape).
type Run struct {
	ID                   string         `json:"id"`
	TaskID               string         `json:"task_id"`
	SourceProjectID      string         `json:"source_project_id"`
	SourceProject        ProjectSummary `json:"source_project"`
	JobID                string         `json:"job_id"`
	Status               string         `json:"status"`
	AnalyzerName         string         `json:"analyzer_name"`
	AnalyzerVersion      string         `json:"analyzer_version"`
	RulesetVersion       string         `json:"ruleset_version"`
	SourceManifestSHA256 string         `json:"source_manifest_sha256"`
	InputSHA256          string         `json:"input_sha256"`
	BundleSHA256         string         `json:"bundle_sha256"`
	SourceSizeBytes      uint64         `json:"source_size_bytes"`
	SourceFileCount      uint32         `json:"source_file_count"`
	FindingCount         uint32         `json:"finding_count"`
	DiagnosticCount      uint32         `json:"diagnostic_count"`
	Coverage             Coverage       `json:"coverage"`
	SeverityCounts       SeverityCounts `json:"severity_counts"`
	FindingsTruncated    bool           `json:"findings_truncated"`
	DiagnosticsTruncated bool           `json:"diagnostics_truncated"`
	ErrorCode            *string        `json:"error_code"`
	ErrorMessage         *string        `json:"error_message"`
	StartedAt            *time.Time     `json:"started_at"`
	CompletedAt          *time.Time     `json:"completed_at"`
	CreatedAt            time.Time      `json:"created_at"`
	UpdatedAt            time.Time      `json:"updated_at"`
}



type ProjectSummary struct {
	ID            string `json:"id"`
	TargetPath    string `json:"target_path"`
	Status        string `json:"status"`
	EngineName    string `json:"engine_name"`
	EngineVersion string `json:"engine_version"`
}


type SeverityCounts struct {
	Low      uint32 `json:"LOW"`
	Medium   uint32 `json:"MEDIUM"`
	High     uint32 `json:"HIGH"`
	Critical uint32 `json:"CRITICAL"`
}


type Coverage struct {
	TotalFiles     uint32 `json:"total_files"`
	AnalyzedFiles  uint32 `json:"analyzed_files"`
	ParsedFiles    uint32 `json:"parsed_files"`
	RecoveredFiles uint32 `json:"recovered_files"`
	FailedFiles    uint32 `json:"failed_files"`
}


type FileIdentity struct {
	ResultID    string `json:"result_id"`
	LogicalPath string `json:"logical_path"`
	BinaryName  string `json:"binary_name"`
}

type SourceFile struct {
	FileIdentity
	Content     string `json:"content"`
	SHA256      string `json:"sha256"`
	SizeBytes   uint64 `json:"-"`
	LineCount   uint32 `json:"-"`
	OffsetBytes uint64 `json:"offset_bytes"`
	LengthBytes uint64 `json:"length_bytes"`
}

type CallableIdentity struct {
	Kind      string `json:"kind"`
	TypeName  string `json:"type_name"`
	Name      string `json:"name"`
	Signature string `json:"signature"`
}

type Location struct {
	StartLine   uint32 `json:"start_line"`
	StartColumn uint32 `json:"start_column"`
	EndLine     uint32 `json:"end_line"`
	EndColumn   uint32 `json:"end_column"`
}

type Finding struct {
	ID               string           `json:"id,omitempty"`
	CWE              string           `json:"cwe"`
	RuleID           string           `json:"rule_id"`
	Severity         string           `json:"severity"`
	File             FileIdentity     `json:"file"`
	Callable         CallableIdentity `json:"callable"`
	Location         Location         `json:"location"`
	Message          string           `json:"message"`
	Snippet          string           `json:"snippet,omitempty"`
	SnippetStartLine uint32           `json:"snippet_start_line,omitempty"`
	CreatedAt        time.Time        `json:"created_at,omitempty"`
}

type DiagnosticFile struct {
	ResultID    string `json:"result_id,omitempty"`
	LogicalPath string `json:"logical_path,omitempty"`
	BinaryName  string `json:"binary_name,omitempty"`
}

type Diagnostic struct {
	Code     string          `json:"code"`
	Message  string          `json:"message"`
	Severity string          `json:"severity,omitempty"`
	File     *DiagnosticFile `json:"file,omitempty"`
	Line     *uint32         `json:"line,omitempty"`
}


// API query and action types (aligned with the Java domain shapes).

type CreateInput struct {
	TaskID          string
	SourceProjectID string
	IdempotencyKey  string
	UserID          uint64
	Role            auth.Role
}

type ListQuery struct {
	TaskID          string
	SourceProjectID string
	After           *RunCursor
	PageSize        int
}

type RunCursor struct {
	CreatedAt time.Time
	ID        string
}

type RunPage struct {
	Items      []Run  `json:"items"`
	NextCursor string `json:"next_cursor,omitempty"`
	HasMore    bool   `json:"-"`
}

type RunQuery struct {
	TaskID string
	RunID  string
}

type FindingsQuery struct {
	TaskID   string
	RunID    string
	Cursor   uint64
	PageSize int
	CWE      string
	Severity string
	File     string
	Callable string
}

type FindingPage struct {
	Items      []Finding `json:"items"`
	NextCursor string    `json:"next_cursor,omitempty"`
}

type ActionInput struct {
	TaskID string
	RunID  string
	UserID uint64
	Role   auth.Role
}

type CheckerIdentity struct {
	Product string `json:"product"`
	Version string `json:"version"`
	Ruleset string `json:"ruleset"`
}

type ResultCoverage struct {
	FilesTotal     uint32 `json:"files_total"`
	FilesAnalyzed  uint32 `json:"files_analyzed"`
	FilesParsed    uint32 `json:"files_parsed"`
	FilesRecovered uint32 `json:"files_recovered"`
	FilesFailed    uint32 `json:"files_failed"`
}

type ResultSummary struct {
	FindingCount         uint32 `json:"finding_count"`
	DiagnosticCount      uint32 `json:"diagnostic_count"`
	FindingsTruncated    bool   `json:"findings_truncated"`
	DiagnosticsTruncated bool   `json:"diagnostics_truncated"`
}


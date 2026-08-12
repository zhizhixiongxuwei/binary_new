package javaanalysis

import (
	"context"
	"io"
	"time"

	"binaryscan/internal/auth"
	"binaryscan/internal/queue"
)

const (
	AnalyzerName                = "binaryscan-java-checker"
	AnalyzerVersion             = "0.1.0"
	RequestSchemaVersion        = "java-analysis-input-v1"
	ResponseSchemaVersion       = "java-analysis-response-v1"
	DefaultRulesetVersion       = "java-rules-v1"
	MaxSourceBytes        int64 = 128 << 20
	MaxFiles                    = 3_000
	MaxFileBytes          int64 = 8 << 20
	MaxFindings                 = 10_000
	MaxDiagnostics              = 1_000
	MaxResponseBytes      int64 = 32 << 20
	MaxManifestBytes      int64 = 16 << 20
	MaxPageSize                 = 200
)

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

type ProjectSnapshot struct {
	TaskID                 string
	ProjectID              string
	Status                 string
	SourceKind             string
	Language               string
	EngineName             string
	EngineVersion          string
	TargetPath             string
	RootStorageKey         string
	ManifestStorageKey     string
	ManifestSHA256         string
	ManifestSizeBytes      uint64
	ProjectSourceFileCount uint64
	ProjectSymbolCount     uint64
	ProjectSourceSizeBytes uint64
	AnalysisProjectStatus  string
	InputSHA256            string
	SourceSizeBytes        uint64
	Files                  []SourceFile
}

type RequestMetadata struct {
	SchemaVersion        string       `json:"schema_version"`
	AnalysisID           string       `json:"analysis_id"`
	InputSHA256          string       `json:"input_sha256"`
	BundleSHA256         string       `json:"bundle_sha256"`
	SourceManifestSHA256 string       `json:"source_manifest_sha256"`
	ProjectID            string       `json:"project_id"`
	Language             string       `json:"language"`
	ProjectStatus        string       `json:"project_status"`
	Files                []SourceFile `json:"files"`
}

type CheckerIdentity struct {
	Product string `json:"product"`
	Version string `json:"version"`
	Ruleset string `json:"ruleset"`
}

type Result struct {
	SchemaVersion string          `json:"schema_version"`
	AnalysisID    string          `json:"analysis_id"`
	Status        string          `json:"status"`
	Identity      CheckerIdentity `json:"identity"`
	InputSHA256   string          `json:"input_sha256"`
	BundleSHA256  string          `json:"bundle_sha256"`
	Coverage      ResultCoverage  `json:"coverage"`
	Summary       ResultSummary   `json:"summary"`
	Findings      []Finding       `json:"findings"`
	Diagnostics   []Diagnostic    `json:"diagnostics"`
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

type AnalysisRequest struct {
	Metadata RequestMetadata
	Source   io.Reader
}

type Checker interface {
	Analyze(context.Context, AnalysisRequest) (Result, error)
	Cancel(context.Context, string) error
	Ready(context.Context) error
}

type ProcessorRepository interface {
	Begin(context.Context, queue.Lease) (ProjectSnapshot, error)
	SetBundleIdentity(context.Context, queue.Lease, string) error
	Publish(context.Context, queue.Lease, RequestMetadata, Result) error
	PublishFailed(context.Context, queue.Lease, RequestMetadata, Result) error
	Retry(context.Context, queue.Lease, string, string) error
	Fail(context.Context, queue.Lease, string, string) error
	CancelRun(context.Context, queue.Lease) error
}

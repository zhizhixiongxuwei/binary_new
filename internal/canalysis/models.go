package canalysis

import (
	"context"
	"io"
	"time"

	"binaryscan/internal/auth"
	"binaryscan/internal/queue"
)

const (
	AnalyzerName                = "binaryscan-c-checker"
	AnalyzerVersion             = "0.1.0"
	RequestSchemaVersion        = "binaryscan-c-analysis-request/v1"
	ResponseSchemaVersion       = "binaryscan-c-analysis-response/v1"
	DefaultRulesetVersion       = "c-rules-v1"
	MaxSourceBytes        int64 = 128 << 20
	MaxFunctions                = 3_000
	MaxFindings                 = 10_000
	MaxDiagnostics              = 1_000
	MaxResponseBytes      int64 = 32 << 20
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
	RulesetVersion       string         `json:"ruleset_version,omitempty"`
	SourceSHA256         string         `json:"source_sha256"`
	SourceSizeBytes      uint64         `json:"source_size_bytes"`
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

type Function struct {
	ResultID    string `json:"result_id"`
	Address     string `json:"address"`
	Name        string `json:"name"`
	SHA256      string `json:"sha256"`
	OffsetBytes uint64 `json:"offset_bytes"`
	LengthBytes uint64 `json:"length_bytes"`
	StartLine   uint32 `json:"start_line"`
	EndLine     uint32 `json:"end_line"`
}

type FunctionIdentity struct {
	ResultID string `json:"result_id"`
	Address  string `json:"address"`
	Name     string `json:"name"`
}

type Location struct {
	StartLine   uint32 `json:"start_line"`
	StartColumn uint32 `json:"start_column"`
	EndLine     uint32 `json:"end_line"`
	EndColumn   uint32 `json:"end_column"`
}

type Finding struct {
	ID        string           `json:"id,omitempty"`
	CWE       string           `json:"cwe"`
	RuleID    string           `json:"rule_id"`
	Severity  string           `json:"severity"`
	Function  FunctionIdentity `json:"function"`
	Location  Location         `json:"location"`
	Message   string           `json:"message"`
	Snippet   string           `json:"snippet,omitempty"`
	CreatedAt time.Time        `json:"created_at,omitempty"`
}

type Diagnostic struct {
	FunctionResultID string  `json:"function_result_id,omitempty"`
	Code             string  `json:"code"`
	Message          string  `json:"message"`
	Line             *uint32 `json:"line,omitempty"`
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
	Function string
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
	TaskID              string
	ProjectID           string
	Status              string
	EngineName          string
	EngineVersion       string
	TargetPath          string
	RootStorageKey      string
	CanonicalStorageKey string
	CanonicalSHA256     string
	CanonicalSizeBytes  uint64
	Functions           []Function
}

type RequestMetadata struct {
	SchemaVersion      string     `json:"schema_version"`
	AnalysisID         string     `json:"analysis_id"`
	ProjectID          string     `json:"project_id"`
	CanonicalSHA256    string     `json:"canonical_sha256"`
	CanonicalSizeBytes uint64     `json:"canonical_size_bytes"`
	ProjectStatus      string     `json:"project_status"`
	EngineName         string     `json:"engine_name"`
	EngineVersion      string     `json:"engine_version"`
	Functions          []Function `json:"functions"`
}

type CheckerIdentity struct {
	Name           string `json:"name"`
	Version        string `json:"version"`
	RulesetVersion string `json:"ruleset_version"`
}

type Coverage struct {
	TotalFunctions  uint32 `json:"total_functions"`
	ParsedFunctions uint32 `json:"parsed_functions"`
	FailedFunctions uint32 `json:"failed_functions"`
}

type ResultSummary struct {
	FindingCount         uint32 `json:"finding_count"`
	DiagnosticCount      uint32 `json:"diagnostic_count"`
	FindingsTruncated    bool   `json:"findings_truncated"`
	DiagnosticsTruncated bool   `json:"diagnostics_truncated"`
}

type Result struct {
	SchemaVersion string          `json:"schema_version"`
	AnalysisID    string          `json:"analysis_id"`
	Status        string          `json:"status"`
	Checker       CheckerIdentity `json:"checker"`
	Coverage      Coverage        `json:"coverage"`
	Summary       ResultSummary   `json:"summary"`
	Findings      []Finding       `json:"findings"`
	Diagnostics   []Diagnostic    `json:"diagnostics"`
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
	Publish(context.Context, queue.Lease, Result) error
	PublishFailed(context.Context, queue.Lease, Result) error
	Retry(context.Context, queue.Lease, string, string) error
	Fail(context.Context, queue.Lease, string, string) error
	CancelRun(context.Context, queue.Lease) error
}

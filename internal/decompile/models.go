package decompile

import (
	"encoding/json"
	"io"
	"time"

	"binaryscan/internal/auth"
)

const (
	DefaultPageSize    = 50
	MaxPageSize        = 200
	DefaultSourceLimit = 256 << 10
	MaxSourceLimit     = 1 << 20
	JobPayloadVersion  = 1
)

const (
	TargetNative   = "native"
	TargetBytecode = "bytecode"

	EngineAuto           = "auto"
	EngineGhidra         = "ghidra"
	EngineVineflower     = "vineflower"
	EngineJADX           = "jadx"
	EnginePythonBytecode = "python-bytecode"
)

type CreateInput struct {
	TaskID         string
	FileNodeID     uint64
	UserID         uint64
	Role           auth.Role
	EngineTarget   string
	Options        json.RawMessage
	IdempotencyKey string
}

type CreateRecord struct {
	JobID         string
	RequestID     string
	TaskID        string
	FileNodeID    uint64
	UserID        uint64
	EngineTarget  string
	Options       json.RawMessage
	Limits        JobLimits
	JobRequestKey string
}

type Request struct {
	RequestID    string     `json:"request_id"`
	JobID        string     `json:"job_id"`
	TaskID       string     `json:"task_id"`
	FileNodeID   string     `json:"file_node_id"`
	TargetClass  string     `json:"target_class"`
	EngineTarget string     `json:"engine_target"`
	Status       string     `json:"status"`
	CreatedAt    time.Time  `json:"created_at"`
	ErrorCode    string     `json:"error_code,omitempty"`
	ErrorMessage string     `json:"error_message,omitempty"`
	CompletedAt  *time.Time `json:"completed_at,omitempty"`
}

type RequestQuery struct {
	TaskID string
	JobID  string
}

type JobLimits struct {
	MaxDurationSeconds     int64 `json:"max_duration_seconds"`
	MaxOutputBytes         int64 `json:"max_output_bytes"`
	MaxArtifacts           int   `json:"max_artifacts"`
	MaxStandardOutputBytes int64 `json:"max_standard_output_bytes"`
}

type JobTarget struct {
	FileNodeID   string `json:"file_node_id"`
	Class        string `json:"class"`
	Format       string `json:"format"`
	Architecture string `json:"architecture"`
	StorageKey   string `json:"storage_key"`
	SHA256       string `json:"sha256"`
	SizeBytes    uint64 `json:"size_bytes"`
}

type JobEngine struct {
	Target     string `json:"target"`
	WorkerKind string `json:"worker_kind"`
}

// JobPayload is the immutable API-to-worker contract. It intentionally does
// not claim an engine version: the future worker must record the actual pinned
// version in analyzer_runs and decompile_results.
type JobPayload struct {
	SchemaVersion int             `json:"schema_version"`
	RequestID     string          `json:"request_id"`
	RequestedBy   uint64          `json:"requested_by"`
	TaskID        string          `json:"task_id"`
	Target        JobTarget       `json:"target"`
	Engine        JobEngine       `json:"engine"`
	Options       json.RawMessage `json:"options"`
	Limits        JobLimits       `json:"limits"`
}

type Result struct {
	ID            string          `json:"id"`
	FileNodeID    string          `json:"file_node_id"`
	SymbolKey     string          `json:"symbol_key"`
	SymbolKind    string          `json:"symbol_kind"`
	DisplayName   string          `json:"display_name"`
	GroupName     string          `json:"group_name"`
	Location      string          `json:"location"`
	Signature     string          `json:"signature"`
	Detail        string          `json:"detail"`
	Language      string          `json:"language"`
	EngineName    string          `json:"engine_name"`
	EngineVersion string          `json:"engine_version"`
	Status        string          `json:"status"`
	SizeBytes     *uint64         `json:"size_bytes"`
	Diagnostics   json.RawMessage `json:"diagnostics"`
	CreatedAt     time.Time       `json:"created_at"`
	CompletedAt   *time.Time      `json:"completed_at"`
	StorageKey    string          `json:"-"`
	ContentSHA256 string          `json:"-"`
}

type ListQuery struct {
	TaskID   string
	Cursor   string
	After    *ListCursor
	PageSize int
}

type ListCursor struct {
	CreatedAt time.Time
	ID        string
}

type Page struct {
	Items      []Result `json:"items"`
	NextCursor string   `json:"next_cursor,omitempty"`
	HasMore    bool     `json:"-"`
}

type SourceQuery struct {
	TaskID   string
	ResultID string
	Offset   uint64
	Limit    int
}

type SourceArchiveQuery struct {
	TaskID          string
	IncludeCombined bool
}

type ReadSeekCloser interface {
	io.Reader
	io.Seeker
	io.Closer
}

type SourceArchive struct {
	Content     ReadSeekCloser
	Filename    string
	SHA256      string
	SizeBytes   uint64
	ResultCount int
}

type SourceDescriptor struct {
	ResultID   string
	Status     string
	StorageKey string
	SHA256     string
	SizeBytes  uint64
	SizeKnown  bool
}

type SourceChunk struct {
	ResultID   string  `json:"result_id"`
	Offset     uint64  `json:"offset"`
	Content    string  `json:"content"`
	NextOffset *uint64 `json:"next_offset,omitempty"`
	Complete   bool    `json:"complete"`
	SHA256     string  `json:"sha256"`
	SizeBytes  uint64  `json:"size_bytes"`
}

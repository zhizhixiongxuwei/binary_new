package task

import "time"

const (
	StatusQueued          = "QUEUED"
	StatusCancelRequested = "CANCEL_REQUESTED"
	StatusCancelled       = "CANCELLED"
	StatusDeleting        = "DELETING"
	StatusDeleted         = "DELETED"
	RiskUnknown           = "UNKNOWN"
	UnknownInput          = "unknown"
)

type LimitsSnapshot struct {
	MaxUploadBytes   int64 `json:"max_upload_bytes"`
	MaxExpandedBytes int64 `json:"max_expanded_bytes"`
	MaxArchiveRatio  int   `json:"max_archive_ratio"`
	MaxDepth         int   `json:"max_depth"`
	MaxFileNodes     int   `json:"max_file_nodes"`
	MaxNestedImages  int   `json:"max_nested_images"`
}

type CreateRecord struct {
	TaskID          string
	JobID           string
	UserID          uint64
	Administrator   bool
	UploadID        string
	Name            string
	IdempotencyKey  string
	LimitsSnapshot  []byte
	SampleExpiresAt time.Time
	CreatedAt       time.Time
}

type MutationRecord struct {
	TaskID          string
	UserID          uint64
	Administrator   bool
	IdempotencyKey  string
	SampleRetention time.Duration
}

type RetryRecord struct {
	MutationRecord
	JobID string
}

type RetentionRecord struct {
	TaskID                  string
	ExpectedSampleExpiresAt time.Time
	SampleExpiresAt         time.Time
}

type View struct {
	ID                    string     `json:"id"`
	Name                  string     `json:"name"`
	InputType             string     `json:"input_type"`
	Status                string     `json:"status"`
	RiskLevel             string     `json:"risk_level"`
	Progress              float64    `json:"progress"`
	ProgressIndeterminate bool       `json:"progress_indeterminate"`
	CreatorID             string     `json:"creator_id"`
	CreatorName           string     `json:"creator_name"`
	Tags                  []string   `json:"tags"`
	CreatedAt             time.Time  `json:"created_at"`
	UpdatedAt             time.Time  `json:"updated_at"`
	OriginalFilename      string     `json:"original_filename"`
	SizeBytes             uint64     `json:"size_bytes"`
	SHA256                string     `json:"sha256"`
	CurrentStage          string     `json:"current_stage"`
	ErrorCode             string     `json:"error_code"`
	ErrorMessage          string     `json:"error_message"`
	SampleExpiresAt       time.Time  `json:"sample_expires_at"`
	SampleDeletedAt       *time.Time `json:"sample_deleted_at"`
}

type ListQuery struct {
	Cursor      string
	After       *ListCursor
	PageSize    int
	Keyword     string
	Status      string
	InputType   string
	Creator     string
	Tag         string
	CreatedFrom string
	CreatedTo   string
}

type ListCursor struct {
	CreatedAt time.Time
	ID        string
}

type Page struct {
	Items      []View `json:"items"`
	NextCursor string `json:"next_cursor,omitempty"`
	HasMore    bool   `json:"-"`
}

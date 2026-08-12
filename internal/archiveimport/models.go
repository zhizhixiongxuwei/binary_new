package archiveimport

import (
	"context"
	"time"

	"binaryscan/internal/auth"
)

const (
	StatusQueued   = "queued"
	StatusRunning  = "running"
	StatusReady    = "ready"
	StatusFailed   = "failed"
	StatusDeleting = "deleting"
	StatusDeleted  = "deleted"

	EntryEligible = "eligible"
	EntrySkipped  = "skipped"
	EntryCreated  = "created"
	EntryFailed   = "failed"

	CategoryBinary    = "binary"
	CategoryContainer = "container"

	OutcomePending    = "pending"
	OutcomeProcessing = "processing"
	OutcomeCreated    = "created"
	OutcomeExisting   = "existing"
	OutcomeFailed     = "failed"
)

const (
	DefaultMaxUploadBytes   = int64(2 << 30)
	DefaultMaxExpandedBytes = int64(10 << 30)
	DefaultMaxArchiveRatio  = int64(50)
	DefaultMaxEntries       = 20_000
	DefaultMaxEntryBytes    = int64(2 << 30)
	DefaultMaxDepth         = 6
	MaximumBatchEntries     = 20
)

type Limits struct {
	MaxUploadBytes   int64 `json:"max_upload_bytes"`
	MaxExpandedBytes int64 `json:"max_expanded_bytes"`
	MaxArchiveRatio  int64 `json:"max_archive_ratio"`
	MaxEntries       int   `json:"max_entries"`
	MaxEntryBytes    int64 `json:"max_entry_bytes"`
	MaxDepth         int   `json:"max_depth"`
}

func DefaultLimits() Limits {
	return Limits{
		MaxUploadBytes:   DefaultMaxUploadBytes,
		MaxExpandedBytes: DefaultMaxExpandedBytes,
		MaxArchiveRatio:  DefaultMaxArchiveRatio,
		MaxEntries:       DefaultMaxEntries,
		MaxEntryBytes:    DefaultMaxEntryBytes,
		MaxDepth:         DefaultMaxDepth,
	}
}

type Import struct {
	ID              string     `json:"id"`
	UploadID        string     `json:"upload_id"`
	Filename        string     `json:"filename"`
	Status          string     `json:"status"`
	ScannedEntries  uint64     `json:"scanned_entries"`
	TotalEntries    uint64     `json:"total_entries"`
	EligibleEntries uint64     `json:"eligible_entries"`
	SkippedEntries  uint64     `json:"skipped_entries"`
	CreatedTasks    uint64     `json:"created_tasks"`
	ErrorCode       string     `json:"error_code,omitempty"`
	ErrorMessage    string     `json:"error_message,omitempty"`
	CreatedAt       time.Time  `json:"created_at"`
	UpdatedAt       time.Time  `json:"updated_at"`
	CompletedAt     *time.Time `json:"-"`

	CreatedBy    uint64 `json:"-"`
	RootFormat   string `json:"-"`
	Attempt      uint32 `json:"-"`
	MaxAttempts  uint32 `json:"-"`
	FencingToken uint64 `json:"-"`
}

type Entry struct {
	ID               string  `json:"id"`
	Path             string  `json:"path"`
	SizeBytes        uint64  `json:"size_bytes"`
	SHA256           *string `json:"sha256"`
	DetectedFormat   *string `json:"detected_format"`
	DetectedCategory *string `json:"detected_category"`
	Status           string  `json:"status"`
	SkipReason       string  `json:"skip_reason,omitempty"`
	TaskID           string  `json:"task_id,omitempty"`

	DatabaseID      uint64 `json:"-"`
	ImportID        string `json:"-"`
	BlobID          uint64 `json:"-"`
	DerivedUploadID string `json:"-"`
	ErrorCode       string `json:"-"`
	ErrorMessage    string `json:"-"`
}

type EntryPage struct {
	Items      []Entry `json:"items"`
	NextCursor string  `json:"next_cursor,omitempty"`
}

type ImportPage struct {
	Items      []Import `json:"items"`
	NextCursor string   `json:"next_cursor,omitempty"`
}

type ImportListQuery struct {
	Cursor   string
	PageSize int
}

type EntryListQuery struct {
	Filter   string
	Cursor   string
	AfterID  uint64
	PageSize int
}

type EnsureInput struct {
	UploadID       string
	CreatedBy      uint64
	Filename       string
	Size           int64
	SHA256         string
	DetectedFormat string
}

type Lease struct {
	Import
	Owner        string
	LeaseUntil   time.Time
	SourceBlobID uint64
	SourceKey    string
	SourceSHA    string
	SourceSize   int64
	Limits       Limits
}

type PersistEntry struct {
	PublicID        string
	Ordinal         uint32
	LogicalPath     string
	LogicalPathHash [32]byte
	Size            int64
	SHA256          string
	Format          string
	Category        string
	Status          string
	SkipReason      string
	ErrorCode       string
	ErrorMessage    string
	BlobStorageKey  string
}

type BatchInput struct {
	ImportID       string
	EntryIDs       []string
	CreatedBy      uint64
	Role           auth.Role
	IdempotencyKey string
}

type BatchItem struct {
	EntryID   string `json:"entry_id"`
	Outcome   string `json:"outcome"`
	TaskID    string `json:"task_id,omitempty"`
	ErrorCode string `json:"error_code,omitempty"`
	Message   string `json:"message,omitempty"`

	EntryDatabaseID uint64 `json:"-"`
	Ordinal         uint8  `json:"-"`
}

type BatchResult struct {
	Items []BatchItem `json:"items"`
}

type Batch struct {
	ID          string
	ImportID    string
	CreatedBy   uint64
	Fingerprint string
	Status      string
	Items       []BatchItem
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

type BatchWorkItem struct {
	BatchID         string
	EntryDatabaseID uint64
	EntryID         string
	Ordinal         uint8
	ImportID        string
	ParentUploadID  string
	ArchiveName     string
	SourceOwner     uint64
	Actor           uint64
	ActorRole       auth.Role
	Path            string
	Size            int64
	SHA256          string
	Format          string
	Category        string
	BlobID          uint64
	DerivedUploadID string
	TaskID          string
	Outcome         string
	FencingToken    uint64
	LeaseOwner      string
}

type DerivedUploadInput struct {
	CreatedBy      uint64
	Filename       string
	ContentType    string
	Size           int64
	SHA256         string
	BlobID         uint64
	InputCategory  string
	DetectedFormat string
	ParentUploadID string
	ArchiveName    string
	EntryPath      string
	IdempotencyKey string
}

type DerivedUploadResult struct {
	ID string
}

type DerivedUploadCreator interface {
	CreateDerivedCompleted(
		context.Context,
		DerivedUploadInput,
	) (DerivedUploadResult, bool, error)
}

type DerivedUploadDeleter interface {
	DeleteDerivedCompleted(context.Context, string, uint64) error
}

type TaskCreator interface {
	Create(
		context.Context,
		uint64,
		auth.Role,
		string,
		string,
		string,
	) (string, bool, error)
}

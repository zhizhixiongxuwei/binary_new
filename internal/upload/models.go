package upload

import (
	"time"

	"binaryscan/internal/auth"
	"binaryscan/internal/inputcategory"
)

const DefaultPartSize int64 = 32 * 1024 * 1024

type Upload struct {
	ID             string
	CreatedBy      uint64
	OriginalName   []byte
	DisplayName    string
	ContentType    string
	DeclaredSize   int64
	PartSize       int64
	ExpectedSHA256 string
	ActualSHA256   string
	Status         string
	BlobID         *uint64
	ExpiresAt      time.Time
	CompletedAt    *time.Time
	PartsCleanedAt *time.Time
	CreatedAt      time.Time
	IntakeProfile  *IntakeProfile
}

const (
	ValidationPending     = "pending"
	ValidationValid       = "valid"
	ValidationMismatch    = "mismatch"
	ValidationUnsupported = "unsupported"
	SourceDirect          = "direct"
	SourceArchiveEntry    = "archive_entry"
)

type IntakeProfile struct {
	UploadID               string
	InputCategory          inputcategory.Category
	DetectedCategory       inputcategory.Category
	DetectedFormat         string
	ValidationStatus       string
	ValidationErrorCode    string
	ValidationErrorMessage string
	SourceKind             string
	SourceParentUploadID   string
	SourceArchiveName      string
	SourceEntryPath        string
	ArchiveImportID        string
	ValidatedAt            *time.Time
	CreatedAt              time.Time
	UpdatedAt              time.Time
}

type ValidationErrorView struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

type Part struct {
	UploadID     string
	Number       uint32
	Size         int64
	SHA256       string
	ContentRange string
	StorageKey   string
	CreatedAt    time.Time
}

type Range struct {
	Start int64
	End   int64
	Total int64
	Raw   string
}

func (r Range) Size() int64 {
	return r.End - r.Start + 1
}

type View struct {
	ID               string                 `json:"id"`
	PartSize         int64                  `json:"part_size"`
	Status           string                 `json:"status"`
	UploadedParts    []uint32               `json:"uploaded_parts"`
	ExpiresAt        time.Time              `json:"expires_at"`
	SHA256           string                 `json:"sha256,omitempty"`
	SizeBytes        *int64                 `json:"size_bytes,omitempty"`
	InputCategory    inputcategory.Category `json:"input_category,omitempty"`
	ValidationStatus string                 `json:"validation_status,omitempty"`
	DetectedCategory inputcategory.Category `json:"detected_category,omitempty"`
	DetectedFormat   string                 `json:"detected_format,omitempty"`
	ValidationError  *ValidationErrorView   `json:"validation_error,omitempty"`
	ArchiveImportID  string                 `json:"archive_import_id,omitempty"`
	TaskID           string                 `json:"task_id,omitempty"`
}

type CreateInput struct {
	Filename       string
	Size           int64
	ContentType    string
	CreatedBy      uint64
	IdempotencyKey string
	InputCategory  inputcategory.Category
}

type ValidationResult struct {
	Status           string
	InputCategory    inputcategory.Category
	DetectedCategory inputcategory.Category
	DetectedFormat   string
	ErrorCode        string
	ErrorMessage     string
	ValidatedAt      time.Time
}

type ArchiveImportRequest struct {
	UploadID       string
	CreatedBy      uint64
	Filename       string
	Size           int64
	SHA256         string
	DetectedFormat string
}

type ArchiveImportCandidate struct {
	UploadID       string
	CreatedBy      uint64
	Filename       string
	Size           int64
	SHA256         string
	DetectedFormat string
}

type ArchiveImportRecoveryDiagnostic struct {
	UploadID string
	Err      error
}

type ArchiveImportRecoveryReport struct {
	Candidates  int
	Ensured     int
	Failures    int
	Wrapped     bool
	Diagnostics []ArchiveImportRecoveryDiagnostic
}

type ArchiveImportDeleteRequest struct {
	UploadID string
	Actor    auth.Principal
}

type DirectTaskRequest struct {
	UploadID       string
	CreatedBy      uint64
	Filename       string
	TaskName       string
	IdempotencyKey string
	InputCategory  inputcategory.Category
	DetectedFormat string
}

type DirectTaskCandidate struct {
	UploadID       string
	CreatedBy      uint64
	Filename       string
	InputCategory  inputcategory.Category
	DetectedFormat string
}

type DirectTaskRecoveryDiagnostic struct {
	UploadID string
	Err      error
}

type DirectTaskRecoveryReport struct {
	Candidates  int
	Ensured     int
	Failures    int
	Wrapped     bool
	Diagnostics []DirectTaskRecoveryDiagnostic
}

type DerivedCompletedInput struct {
	CreatedBy      uint64
	Filename       string
	ContentType    string
	Size           int64
	SHA256         string
	BlobID         uint64
	InputCategory  inputcategory.Category
	DetectedFormat string
	ParentUploadID string
	ArchiveName    string
	EntryPath      string
	IdempotencyKey string
}

type DerivedCompletedRecord struct {
	Upload             Upload
	IdempotencyKey     string
	RequestFingerprint string
}

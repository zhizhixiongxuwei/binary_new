package decompile

import (
	"context"
	"time"

	"binaryscan/internal/auth"
	"binaryscan/internal/taskcleanup"
)

const (
	SourceProjectDeletionTokenTTL = 5 * time.Minute
	MaxSourceProjectDeletionBatch = 25
)

type SourceProjectDeletionCounts struct {
	CAnalysisRuns        uint64 `json:"c_analysis_runs"`
	CAnalysisFindings    uint64 `json:"c_analysis_findings"`
	JavaAnalysisRuns     uint64 `json:"java_analysis_runs"`
	JavaAnalysisFindings uint64 `json:"java_analysis_findings"`
	Reports              uint64 `json:"reports"`
	ReportFiles          uint64 `json:"report_files"`
	Artifacts            uint64 `json:"artifacts"`
	DecompileResults     uint64 `json:"decompile_results"`
	SourceFiles          uint64 `json:"source_files"`
}

type SourceProjectDeletionPreviewInput struct {
	TaskID    string
	ProjectID string
	UserID    uint64
	Role      auth.Role
}

type SourceProjectDeletionPreview struct {
	ProjectID         string                      `json:"project_id"`
	Counts            SourceProjectDeletionCounts `json:"counts"`
	TypedSuffix       string                      `json:"typed_suffix"`
	ConfirmationToken string                      `json:"confirmation_token"`
	ExpiresAt         time.Time                   `json:"expires_at"`
}

type ConfirmSourceProjectDeletionInput struct {
	TaskID            string
	ProjectID         string
	UserID            uint64
	Role              auth.Role
	ConfirmationToken string
	Cascade           bool
	TypedSuffix       string
}

type SourceProjectDeletionOperationQuery struct {
	TaskID      string
	OperationID string
}

type SourceProjectDeletionOperation struct {
	ID           string                      `json:"id"`
	ProjectID    string                      `json:"project_id"`
	Status       string                      `json:"status"`
	Counts       SourceProjectDeletionCounts `json:"counts"`
	CreatedAt    time.Time                   `json:"created_at"`
	CompletedAt  *time.Time                  `json:"completed_at"`
	ErrorCode    *string                     `json:"error_code"`
	ErrorMessage *string                     `json:"error_message"`
}

type sourceProjectDeletionPreviewRecord struct {
	TaskID            string
	ProjectID         string
	UserID            uint64
	TokenHash         string
	ProjectGeneration uint64
	Counts            SourceProjectDeletionCounts
	CountsSHA256      string
	ExpiresAt         time.Time
}

type sourceProjectDeletionConfirmRecord struct {
	TaskID      string
	ProjectID   string
	UserID      uint64
	TokenHash   string
	TypedSuffix string
	OperationID string
	CreatedAt   time.Time
}

type SourceProjectDeletionClaim struct {
	OperationID string
	TaskID      string
	ProjectID   string
	LeaseOwner  string
	Fence       uint64
	Attempt     uint32
	Counts      SourceProjectDeletionCounts
	Files       []taskcleanup.StoredFile
	Scopes      []taskcleanup.Scope
	ReportIDs   []string
	ArtifactIDs []string
	RunIDs      []string
	JobIDs      []string
	JavaRunIDs  []string
	JavaJobIDs  []string
}

type SourceProjectDeletionSweepReport struct {
	Claimed      int
	Completed    int
	FilesDeleted int
	Deferred     int
	Failures     int
	Conflicts    int
}

type sourceProjectDeletionRepository interface {
	CreateSourceProjectDeletionPreview(
		context.Context,
		sourceProjectDeletionPreviewRecord,
	) (SourceProjectDeletionCounts, error)
	ConfirmSourceProjectDeletion(
		context.Context,
		sourceProjectDeletionConfirmRecord,
	) (SourceProjectDeletionOperation, error)
	GetSourceProjectDeletionOperation(
		context.Context,
		SourceProjectDeletionOperationQuery,
	) (SourceProjectDeletionOperation, error)
}

type SourceProjectDeletionSweepRepository interface {
	ListReadySourceProjectDeletions(context.Context, int) ([]string, error)
	ClaimSourceProjectDeletion(
		context.Context,
		string,
		string,
		time.Duration,
	) (SourceProjectDeletionClaim, bool, bool, error)
	RenewSourceProjectDeletion(
		context.Context,
		SourceProjectDeletionClaim,
		time.Duration,
	) (bool, error)
	FinalizeSourceProjectCascadeDeletion(
		context.Context,
		SourceProjectDeletionClaim,
	) (bool, error)
	FailSourceProjectCascadeDeletion(
		context.Context,
		SourceProjectDeletionClaim,
		string,
	) (bool, error)
}

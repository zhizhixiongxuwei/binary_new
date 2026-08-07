package retention

import (
	"context"
	"time"

	"binaryscan/internal/taskcleanup"
)

const MaxBatchSize = 100

type Report struct {
	TaskSamplesReleased   int
	UploadPartsCleaned    int
	UploadsExpired        int
	BlobsDeleted          int
	Failures              int
	DecompileFilesDeleted int
	TaskSampleConflicts   int
}

type TaskSampleClaim struct {
	TaskID       string
	LeaseOwner   string
	FencingToken uint64
	Attempt      uint32
	LeaseUntil   time.Time
	Files        []taskcleanup.StoredFile
	Scopes       []taskcleanup.Scope
}

type Config struct {
	LeaseOwner    string
	LeaseDuration time.Duration
	OutputDeleter taskcleanup.FileDeleter
}

type Blob struct {
	ID         uint64
	SHA256     string
	SizeBytes  int64
	StorageKey string
}

type BlobDeleter interface {
	Delete(context.Context, Blob) error
}

type UploadDirectoryDeleter interface {
	Delete(context.Context, string) error
}

type Repository interface {
	ListExpiredTaskIDs(context.Context, int) ([]string, error)
	ClaimExpiredTaskSample(
		context.Context, string, string, time.Duration,
	) (TaskSampleClaim, bool, error)
	RenewExpiredTaskSample(
		context.Context, TaskSampleClaim, time.Duration,
	) (bool, error)
	CompleteExpiredTaskSample(
		context.Context, TaskSampleClaim,
	) (bool, error)
	FailExpiredTaskSample(
		context.Context, TaskSampleClaim, string,
	) (bool, error)
	ListPendingUploadPartCleanupIDs(context.Context, int) ([]string, error)
	CleanupUploadParts(context.Context, string, func() error) (bool, error)
	ListExpiredUploadIDs(context.Context, int) ([]string, error)
	ExpireUpload(context.Context, string, func() error) (bool, error)
	ListDeletingBlobIDs(context.Context, int) ([]uint64, error)
	FinalizeDeletingBlob(
		context.Context,
		uint64,
		func(Blob) error,
	) (bool, error)
}

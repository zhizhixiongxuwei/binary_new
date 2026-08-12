package taskcleanup

import (
	"context"
	"time"
)

const (
	maxSweepBatch  = 100
	maxOutputFiles = 100_000
)

type FileKind string

const (
	FileReport        FileKind = "report"
	FileArtifact      FileKind = "artifact"
	FileDecompile     FileKind = "decompile"
	FileSourceProject FileKind = "source-project"
)

type StoredFile struct {
	Kind       FileKind
	TaskID     string
	RecordID   string
	Format     string
	StorageKey string
	SHA256     string
	SizeBytes  int64
}

type Scope struct {
	Kind     FileKind
	TaskID   string
	RecordID string
}

type Claim struct {
	TaskID       string
	LeaseOwner   string
	FencingToken uint64
	Attempt      uint32
	LeaseUntil   time.Time
	Files        []StoredFile
	Scopes       []Scope
}

type Failure struct {
	Code string
}

type Report struct {
	Claimed      int
	Completed    int
	FilesDeleted int
	Failures     int
	Conflicts    int
}

type Repository interface {
	ListReady(context.Context, int) ([]string, error)
	Claim(context.Context, string, string, time.Duration) (Claim, bool, error)
	Renew(context.Context, Claim, time.Duration) (bool, error)
	Complete(context.Context, Claim) (bool, error)
	Fail(context.Context, Claim, Failure) (bool, error)
}

type FileDeleter interface {
	DeleteFile(context.Context, StoredFile) (bool, error)
	DeleteScope(context.Context, Scope) error
}

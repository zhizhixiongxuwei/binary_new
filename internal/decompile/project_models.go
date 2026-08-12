package decompile

import (
	"context"
	"time"

	"binaryscan/internal/auth"
)

const (
	SourceProjectLayoutV1       = "project-v1"
	SourceProjectLayoutLegacyV1 = "legacy-v1"

	SourceProjectKindGhidraPseudoC = "ghidra-pseudoc"
	SourceProjectKindJava          = "java"
	SourceProjectKindKotlin        = "kotlin"
	SourceProjectKindPython        = "python"
	SourceProjectKindBytecode      = "bytecode"
)

type SourceProject struct {
	ID                string     `json:"id"`
	TaskID            string     `json:"task_id"`
	JobID             string     `json:"job_id,omitempty"`
	FileNodeID        string     `json:"file_node_id"`
	TargetPath        string     `json:"target_path"`
	LayoutVersion     string     `json:"layout_version"`
	SourceKind        string     `json:"source_kind"`
	Language          string     `json:"language"`
	EngineName        string     `json:"engine_name"`
	EngineVersion     string     `json:"engine_version"`
	Status            string     `json:"status"`
	SourceFileCount   uint64     `json:"source_file_count"`
	SymbolCount       uint64     `json:"symbol_count"`
	SourceSizeBytes   uint64     `json:"source_size_bytes"`
	CanonicalFilename string     `json:"canonical_filename,omitempty"`
	ManifestAvailable bool       `json:"manifest_available"`
	CreatedAt         time.Time  `json:"created_at"`
	CompletedAt       *time.Time `json:"completed_at,omitempty"`
}

type SourceProjectListQuery struct {
	TaskID   string
	Cursor   string
	After    *SourceProjectCursor
	PageSize int
}

type SourceProjectCursor struct {
	CreatedAt time.Time
	ID        string
}

type SourceProjectPage struct {
	Items      []SourceProject `json:"items"`
	NextCursor string          `json:"next_cursor,omitempty"`
	HasMore    bool            `json:"-"`
}

type SourceProjectQuery struct {
	TaskID    string
	ProjectID string
}

type DeleteSourceProjectInput struct {
	TaskID    string
	ProjectID string
	UserID    uint64
	Role      auth.Role
}

type SourceProjectArchiveQuery struct {
	TaskID    string
	ProjectID string
}

type sourceProjectRecord struct {
	SourceProject
	RootStorageKey      string
	CanonicalStorageKey string
	CanonicalSHA256     string
	CanonicalSizeBytes  uint64
	CanonicalSizeKnown  bool
	ManifestStorageKey  string
	ManifestSHA256      string
	ManifestSizeBytes   uint64
	ManifestSizeKnown   bool
	DeletedAt           *time.Time
	StorageDeletedAt    *time.Time
}

type sourceProjectDeletion struct {
	Project         sourceProjectRecord
	LegacyFiles     []legacySourceProjectFile
	AlreadyComplete bool
}

type legacySourceProjectFile struct {
	ResultID   string
	StorageKey string
}

type legacySourceProjectEntry struct {
	Result     Result
	Descriptor SourceDescriptor
}

type sourceProjectRepository interface {
	ListSourceProjects(
		context.Context,
		SourceProjectListQuery,
	) (SourceProjectPage, error)
	GetSourceProject(
		context.Context,
		SourceProjectQuery,
	) (sourceProjectRecord, error)
	BeginSourceProjectDeletion(
		context.Context,
		SourceProjectQuery,
	) (sourceProjectDeletion, error)
	CompleteSourceProjectDeletion(
		context.Context,
		SourceProjectQuery,
	) error
	ListLegacySourceProjectEntries(
		context.Context,
		SourceProjectQuery,
	) ([]legacySourceProjectEntry, error)
}

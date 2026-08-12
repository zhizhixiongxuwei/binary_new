package extract

import "encoding/json"

// Limits are enforced across one recursive extraction operation.
type Limits struct {
	MaxExpandedBytes int64
	MaxEntryBytes    int64
	MaxNodes         int
	MaxDepth         int
	MaxRatio         int64
}

// Node describes one archive entry. The input root is owned by the caller and
// is not repeated in Result.Nodes. SourceContainerLocalID is zero for that
// root, or the local ID of the concrete nested archive that produced the node.
type Node struct {
	LocalID                int
	ParentLocalID          int
	SourceContainerLocalID int
	LogicalPath            string
	DisplayName            string
	ArchiveNameID          string
	NodeType               string
	Depth                  int
	Format                 string
	MIMEType               string
	Architecture           string
	SizeBytes              int64
	SHA256                 string
	StorageKey             string
	ExtractionStatus       string
	MetadataJSON           json.RawMessage
	ErrorCode              string
	ErrorMessage           string
}

// ContainerImage is a verified materialization of a nested Docker/OCI archive.
// WorkPath is valid only until the caller removes the extraction workspace and
// is deliberately never persisted as file-tree metadata.
type ContainerImage struct {
	LocalID     int
	LogicalPath string
	Format      string
	SHA256      string
	SizeBytes   int64
	WorkPath    string
}

// MaterializedFile is a regular logical-package member retained in the
// caller-provided work directory. WorkPath is valid only until that directory
// is removed and must never be persisted as a storage location.
type MaterializedFile struct {
	LocalID  int
	WorkPath string
}

// Result contains all nodes retained before completion or a configured limit.
type Result struct {
	Nodes             []Node
	ContainerImages   []ContainerImage
	MaterializedFiles []MaterializedFile
	ExpandedBytes     int64
	Partial           bool
	LimitCode         string

	// Kept unexported for lifecycle regression tests. These values are not
	// part of persisted results or the API contract.
	parserDecoderMemoryPeak int64
	parserDecoderMemoryUsed int64
}

const (
	NodeTypeFile      = "file"
	NodeTypeDirectory = "directory"
	NodeTypeSymlink   = "symlink"
	NodeTypeHardlink  = "hardlink"
	NodeTypeSpecial   = "special"
)

const (
	StatusExtracted        = "extracted"
	StatusRecorded         = "recorded"
	StatusUnsupported      = "unsupported"
	StatusPasswordRequired = "password_required"
	StatusInvalidPath      = "invalid_path"
	StatusCorrupt          = "corrupt"
	StatusDepthLimited     = "depth_limited"
	StatusLimitExceeded    = "limit_exceeded"
	StatusCancelled        = "cancelled"
)

const (
	LimitMaxExpandedBytes   = "max_expanded_bytes"
	LimitMaxEntryBytes      = "max_entry_bytes"
	LimitMaxNodes           = "max_nodes"
	LimitMaxDepth           = "max_depth"
	LimitMaxRatio           = "max_ratio"
	LimitMaxArchiveMetadata = "max_archive_metadata_bytes"
	LimitMaxDecoderMemory   = "max_decoder_memory_bytes"
	LimitContextCancelled   = "context_cancelled"
	LimitMaxContainerImages = "max_auto_container_images"
	LimitMaxContainerBytes  = "max_auto_container_bytes"
	LimitMaxImageReadBytes  = "max_image_read_bytes"
	LimitMaxImageExtents    = "max_image_extents"
	LimitMaxImagePartitions = "max_image_partitions"
)

package imageextract

import (
	"context"
	"io"
)

const (
	DefaultMaxInputBytes    = int64(10 << 30)
	DefaultMaxReadBytes     = int64(50 << 30)
	DefaultMaxExpandedBytes = int64(50 << 30)
	DefaultMaxEntryBytes    = int64(10 << 30)
	DefaultMaxEntries       = 100_000
	DefaultMaxExtents       = 200_000
	DefaultMaxPartitions    = 256
	DefaultMaxDepth         = 10
)

// Limits are security ceilings for one Engine.Extract call. Non-positive
// values use defaults; values above project ceilings are clamped.
type Limits struct {
	MaxInputBytes    int64
	MaxReadBytes     int64
	MaxExpandedBytes int64
	MaxEntryBytes    int64
	MaxEntries       int
	MaxExtents       int
	MaxPartitions    int
	MaxDepth         int
}

// Request identifies one image source. Depth is zero for a root sample and is
// the already-consumed containment depth when another dispatcher opens a
// nested image. Engine replaces Source with a read-only, range-confined view
// before invoking an Extractor.
type Request struct {
	Format    string
	Source    io.ReaderAt
	SizeBytes int64
	Depth     int
}

// Extractor inspects one image and emits bounded metadata through Sink. It
// never owns or closes Request.Source.
type Extractor interface {
	Extract(context.Context, Request, Sink) error
}

// ExtractorFunc adapts a function to Extractor.
type ExtractorFunc func(context.Context, Request, Sink) error

func (function ExtractorFunc) Extract(
	ctx context.Context,
	request Request,
	sink Sink,
) error {
	return function(ctx, request, sink)
}

// Sink is the only supported way for an Extractor to publish results. Entry
// IDs must be contiguous, start at one, and precede their children.
type Sink interface {
	AddEntry(Entry) error
	AddPartition(Partition) error
}

type EntryKind string

const (
	EntryFile      EntryKind = "file"
	EntryDirectory EntryKind = "directory"
	EntrySymlink   EntryKind = "symlink"
	EntryHardlink  EntryKind = "hardlink"
	EntrySpecial   EntryKind = "special"
)

type Status string

const (
	StatusIndexed     Status = "indexed"
	StatusRecorded    Status = "recorded"
	StatusUnsupported Status = "unsupported"
	StatusCorrupt     Status = "corrupt"
)

// Extent is one ordered content segment in the immutable image source. An
// Entry can use multiple extents to describe fragmented or ISO multi-extent
// content without exposing a host path or block device.
type Extent struct {
	OffsetBytes int64 `json:"offset_bytes"`
	SizeBytes   int64 `json:"size_bytes"`
}

// Entry is a logical image member. LogicalPath is an absolute POSIX logical
// path; it is never a host destination. File extents are ordered by logical
// content and are the only byte ranges authorized for later materialization.
// They never authorize writes to the source.
type Entry struct {
	ID           uint64    `json:"id"`
	ParentID     uint64    `json:"parent_id"`
	PartitionID  string    `json:"partition_id,omitempty"`
	LogicalPath  string    `json:"logical_path"`
	Kind         EntryKind `json:"kind"`
	LinkTarget   string    `json:"link_target,omitempty"`
	Extents      []Extent  `json:"extents,omitempty"`
	Depth        int       `json:"depth"`
	SizeBytes    int64     `json:"size_bytes"`
	Format       string    `json:"format,omitempty"`
	Status       Status    `json:"status"`
	ErrorCode    string    `json:"error_code,omitempty"`
	ErrorMessage string    `json:"error_message,omitempty"`
}

// Partition describes a byte range in the immutable source. ParentID supports
// nested partition tables without requiring any host block-device attachment.
type Partition struct {
	ID               string `json:"id"`
	ParentID         string `json:"parent_id,omitempty"`
	Index            uint32 `json:"index"`
	Scheme           string `json:"scheme,omitempty"`
	Type             string `json:"type,omitempty"`
	StartOffsetBytes int64  `json:"start_offset_bytes"`
	SizeBytes        int64  `json:"size_bytes"`
	Filesystem       string `json:"filesystem,omitempty"`
	Status           Status `json:"status"`
	ErrorCode        string `json:"error_code,omitempty"`
	ErrorMessage     string `json:"error_message,omitempty"`
}

type LimitCode string

const (
	LimitMaxInputBytes    LimitCode = "max_input_bytes"
	LimitMaxReadBytes     LimitCode = "max_read_bytes"
	LimitMaxExpandedBytes LimitCode = "max_expanded_bytes"
	LimitMaxEntryBytes    LimitCode = "max_entry_bytes"
	LimitMaxEntries       LimitCode = "max_entries"
	LimitMaxExtents       LimitCode = "max_extents"
	LimitMaxPartitions    LimitCode = "max_partitions"
	LimitMaxDepth         LimitCode = "max_depth"
	LimitContextCancelled LimitCode = "context_cancelled"
)

// Result contains only validated, bounded metadata emitted before completion
// or a limit. Slices are always non-nil.
type Result struct {
	Format        string      `json:"format"`
	Entries       []Entry     `json:"entries"`
	Partitions    []Partition `json:"partitions"`
	ExpandedBytes int64       `json:"expanded_bytes"`
	ReadBytes     int64       `json:"read_bytes"`
	ExtentCount   int         `json:"extent_count"`
	Partial       bool        `json:"partial"`
	LimitCode     LimitCode   `json:"limit_code,omitempty"`
	ErrorCode     string      `json:"error_code,omitempty"`
	ErrorMessage  string      `json:"error_message,omitempty"`
}

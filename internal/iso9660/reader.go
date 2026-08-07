// Package iso9660 provides a bounded, read-only ISO 9660 filesystem reader.
//
// It reads directly from io.ReaderAt. It never mounts the image, invokes an
// external command, or follows a link found inside the image.
package iso9660

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"path"
	"strings"
)

const (
	descriptorSectorSize = int64(2048)
	descriptorStartLBA   = int64(16)
	maxDescriptors       = 256

	defaultMaxNodes   = 100_000
	defaultMaxDepth   = 10
	defaultMaxExtents = 200_000
	defaultMaxBytes   = int64(50 * 1024 * 1024 * 1024)

	hardMaxNodes   = 100_000
	hardMaxDepth   = 64
	hardMaxExtents = 400_000
	hardMaxBytes   = int64(50 * 1024 * 1024 * 1024)

	copyBufferSize = 32 * 1024
	maxPathBytes   = 4096
)

var (
	ErrInvalidArgument = errors.New("invalid ISO 9660 reader argument")
	ErrInvalidFormat   = errors.New("invalid ISO 9660 format")
	ErrCorrupt         = errors.New("corrupt ISO 9660 filesystem")
	ErrLimitExceeded   = errors.New("ISO 9660 limit exceeded")
	ErrNotFound        = errors.New("ISO 9660 entry not found")
	ErrNotRegular      = errors.New("ISO 9660 entry is not a regular file")
)

// Limit identifies the resource bound that stopped image parsing.
type Limit string

const (
	LimitNodes   Limit = "nodes"
	LimitDepth   Limit = "depth"
	LimitExtents Limit = "extents"
	LimitBytes   Limit = "bytes"
)

// LimitError preserves the exact exhausted resource while matching
// ErrLimitExceeded with errors.Is.
type LimitError struct {
	Limit Limit
	Max   int64
}

func (e *LimitError) Error() string {
	return fmt.Sprintf("%v: %s maximum is %d", ErrLimitExceeded, e.Limit, e.Max)
}

func (e *LimitError) Unwrap() error { return ErrLimitExceeded }

// Limits bounds all filesystem data accepted during Open. MaxBytes is the
// aggregate declared size of root, directory, file, and link-data extents;
// it therefore also bounds all content that CopyFile can expose. MaxExtents
// counts every directory record examined, including dot records, so malformed
// images cannot use metadata-only record floods to bypass MaxNodes.
type Limits struct {
	MaxNodes   int
	MaxDepth   int
	MaxExtents int
	MaxBytes   int64
}

// DefaultLimits returns the project defaults without sharing mutable state.
func DefaultLimits() Limits {
	return Limits{
		MaxNodes:   defaultMaxNodes,
		MaxDepth:   defaultMaxDepth,
		MaxExtents: defaultMaxExtents,
		MaxBytes:   defaultMaxBytes,
	}
}

// EntryType is the safe, caller-visible interpretation of a directory record.
type EntryType string

const (
	TypeFile      EntryType = "file"
	TypeDirectory EntryType = "directory"
	TypeSymlink   EntryType = "symlink"
	TypeSpecial   EntryType = "special"
)

// Entry describes one path below the ISO root. Paths are normalized relative
// slash paths. SymlinkTarget is metadata only; the Reader never resolves it.
// Mode, UID, and GID are populated when a Rock Ridge PX record is present.
type Entry struct {
	Path          string
	Name          string
	Type          EntryType
	Size          int64
	Mode          uint32
	UID           uint32
	GID           uint32
	SymlinkTarget string
	ExtentCount   int
}

// Volume describes the selected ISO namespace.
type Volume struct {
	Identifier       string
	LogicalBlockSize uint32
	Joliet           bool
	RockRidge        bool
}

// Extent identifies one validated byte range in the source image. Extents are
// returned in logical file order and are safe to hand to a bounded
// materializer. They never describe bytes outside the selected volume.
type Extent struct {
	OffsetBytes int64
	SizeBytes   int64
}

type extent struct {
	offset int64
	length int64
}

type indexedEntry struct {
	entry   Entry
	extents []extent
}

// Reader is an immutable index over one validated ISO filesystem.
type Reader struct {
	source  io.ReaderAt
	size    int64
	volume  Volume
	limits  Limits
	entries []Entry
	byPath  map[string]indexedEntry
}

// Open validates and indexes an ISO 9660 filesystem. It prefers Rock Ridge on
// the primary volume descriptor, then Joliet, then the base ISO namespace. If
// a later directory record is corrupt or a limit is reached, Open returns an
// immutable Reader containing the fully validated prefix together with the
// error. A descriptor-level failure returns no Reader.
func Open(
	ctx context.Context,
	source io.ReaderAt,
	size int64,
	limits Limits,
) (*Reader, error) {
	if ctx == nil || source == nil || size <= 0 {
		return nil, ErrInvalidArgument
	}
	normalized, err := normalizeLimits(limits)
	if err != nil {
		return nil, err
	}
	minimum := descriptorStartLBA*descriptorSectorSize + descriptorSectorSize
	if size < minimum {
		return nil, fmt.Errorf("%w: image is smaller than the descriptor area", ErrInvalidFormat)
	}

	parser := imageParser{
		ctx:     ctx,
		source:  source,
		size:    size,
		limits:  normalized,
		byPath:  make(map[string]indexedEntry),
		dirSeen: make(map[string]string),
	}
	selected, err := parser.selectVolume()
	if err != nil {
		return nil, err
	}
	parser.volume = selected
	walkErr := parser.walkRoot()
	reader := &Reader{
		source:  source,
		size:    size,
		volume:  selected.info,
		limits:  normalized,
		entries: append([]Entry(nil), parser.entries...),
		byPath:  parser.byPath,
	}
	if walkErr != nil {
		// Every retained entry and extent was completely validated before it
		// entered parser.entries. Returning that immutable prefix lets callers
		// report a local corrupt branch or an exact limit without discarding
		// safe siblings that preceded it.
		return reader, walkErr
	}
	return reader, nil
}

func normalizeLimits(limits Limits) (Limits, error) {
	defaults := DefaultLimits()
	if limits.MaxNodes == 0 {
		limits.MaxNodes = defaults.MaxNodes
	}
	if limits.MaxDepth == 0 {
		limits.MaxDepth = defaults.MaxDepth
	}
	if limits.MaxExtents == 0 {
		limits.MaxExtents = defaults.MaxExtents
	}
	if limits.MaxBytes == 0 {
		limits.MaxBytes = defaults.MaxBytes
	}
	if limits.MaxNodes < 1 || limits.MaxNodes > hardMaxNodes ||
		limits.MaxDepth < 1 || limits.MaxDepth > hardMaxDepth ||
		limits.MaxExtents < 1 || limits.MaxExtents > hardMaxExtents ||
		limits.MaxBytes < 1 || limits.MaxBytes > hardMaxBytes {
		return Limits{}, ErrInvalidArgument
	}
	return limits, nil
}

// Volume returns a copy of selected namespace metadata.
func (r *Reader) Volume() Volume { return r.volume }

// Entries returns a copy of the validated entries in deterministic depth-first
// directory-record order. The synthetic root is not included.
func (r *Reader) Entries() []Entry {
	return append([]Entry(nil), r.entries...)
}

// Lookup returns one indexed entry by normalized relative path.
func (r *Reader) Lookup(name string) (Entry, bool) {
	if r == nil || name == "" || name == "." || path.IsAbs(name) ||
		path.Clean(name) != name {
		return Entry{}, false
	}
	value, ok := r.byPath[name]
	return value.entry, ok
}

// Extents returns a fresh copy of the validated source ranges for an entry.
// Mutating the returned slice cannot affect Reader state. Directory and link
// extents are available for inspection, but callers should use CopyFile only
// for regular-file materialization.
func (r *Reader) Extents(name string) ([]Extent, error) {
	if r == nil {
		return nil, ErrInvalidArgument
	}
	value, ok := r.byPath[name]
	if !ok {
		return nil, ErrNotFound
	}
	result := make([]Extent, len(value.extents))
	for index, item := range value.extents {
		result[index] = Extent{
			OffsetBytes: item.offset,
			SizeBytes:   item.length,
		}
	}
	return result, nil
}

// CopyFile copies exactly the validated logical bytes for a regular file.
// Multi-extent files are exposed as one contiguous stream. Symlinks and
// special files are never opened or followed.
func (r *Reader) CopyFile(
	ctx context.Context,
	name string,
	destination io.Writer,
) (int64, error) {
	if r == nil || ctx == nil || destination == nil {
		return 0, ErrInvalidArgument
	}
	value, ok := r.byPath[name]
	if !ok {
		return 0, ErrNotFound
	}
	if value.entry.Type != TypeFile {
		return 0, ErrNotRegular
	}
	buffer := make([]byte, copyBufferSize)
	var copied int64
	for _, item := range value.extents {
		var extentOffset int64
		for extentOffset < item.length {
			if err := ctx.Err(); err != nil {
				return copied, err
			}
			remaining := item.length - extentOffset
			chunk := int64(len(buffer))
			if remaining < chunk {
				chunk = remaining
			}
			part := buffer[:int(chunk)]
			if err := readAtFull(
				ctx,
				r.source,
				r.size,
				part,
				item.offset+extentOffset,
			); err != nil {
				return copied, fmt.Errorf("copy %q: %w", name, err)
			}
			written, err := destination.Write(part)
			if written < 0 || written > len(part) {
				return copied, fmt.Errorf("copy %q: invalid writer count %d", name, written)
			}
			copied += int64(written)
			if err != nil {
				return copied, err
			}
			if written != len(part) {
				return copied, io.ErrShortWrite
			}
			extentOffset += chunk
		}
	}
	if copied != value.entry.Size {
		return copied, fmt.Errorf("%w: copied size differs from indexed size", ErrCorrupt)
	}
	return copied, nil
}

func readAtFull(
	ctx context.Context,
	source io.ReaderAt,
	sourceSize int64,
	destination []byte,
	offset int64,
) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if offset < 0 || int64(len(destination)) > sourceSize-offset {
		return fmt.Errorf("%w: read is outside the image", ErrCorrupt)
	}
	read, err := source.ReadAt(destination, offset)
	if read != len(destination) {
		if err == nil {
			err = io.ErrUnexpectedEOF
		}
		return fmt.Errorf("read image at %d: %w", offset, err)
	}
	if err != nil && !errors.Is(err, io.EOF) {
		return fmt.Errorf("read image at %d: %w", offset, err)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return nil
}

func checkedAdd(left int64, right int64) (int64, bool) {
	if left < 0 || right < 0 || left > math.MaxInt64-right {
		return 0, false
	}
	return left + right, true
}

func checkedMultiply(left int64, right int64) (int64, bool) {
	if left < 0 || right < 0 || (left != 0 && right > math.MaxInt64/left) {
		return 0, false
	}
	return left * right, true
}

func extentIdentity(extents []extent) string {
	var builder strings.Builder
	for _, item := range extents {
		fmt.Fprintf(&builder, "%d:%d;", item.offset, item.length)
	}
	return builder.String()
}

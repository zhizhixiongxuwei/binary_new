package extract

import (
	"archive/zip"
	"context"
	"errors"
	"fmt"
	"math"
	"os"
)

const (
	zipParserFixedMemoryBytes        = uint64(1 << 20)
	zipParserEntryMemoryBytes        = uint64(512)
	zipEntryDecoderMemoryReservation = int64(1 << 20)
)

func (state *operationState) extractZIP(
	source *os.File,
	sourceSize int64,
	parentID int,
	prefix string,
	parentDepth int,
	budget *containerBudget,
) error {
	directory, err := preflightZIPDirectory(
		state.ctx,
		source,
		sourceSize,
		state.engine.limits.MaxNodes-len(state.nodes),
	)
	if err != nil {
		var limit *limitError
		switch {
		case errors.As(err, &limit):
			state.markLimit(limit.code)
			if limit.global {
				state.stopped = true
			}
			return limit
		case errors.Is(err, context.Canceled),
			errors.Is(err, context.DeadlineExceeded):
			return err
		case errors.Is(err, errUnsupportedZIPMultiVolume):
			return state.appendZIPUnsupportedArchiveNode(
				parentID,
				prefix,
			)
		default:
			return state.appendCorruptArchiveNode(
				parentID, prefix, parentDepth+1, "zip_archive_corrupt", err,
			)
		}
	}
	release, memoryLimit := state.memory.acquire(
		estimateZIPParserMemory(directory),
		LimitMaxArchiveMetadata,
	)
	if memoryLimit != nil {
		state.markLimit(memoryLimit.code)
		return memoryLimit
	}
	// archive.File retains every central-directory entry. Keep that memory
	// charged for the complete ZIP walk, including recursive child parsing.
	defer release()

	archive, err := zip.NewReader(source, sourceSize)
	if err != nil {
		return state.appendCorruptArchiveNode(
			parentID, prefix, parentDepth+1, "zip_archive_corrupt", err,
		)
	}
	for _, entry := range archive.File {
		if err := state.ctx.Err(); err != nil {
			return err
		}
		if state.stopped {
			return &limitError{code: state.limitCode, global: true}
		}
		isDirectory := entry.FileInfo().IsDir()
		location, prepared, pathErr := state.prepareEntryWithNameSuffix(
			prefix, entry.Name, isDirectory, parentID, parentDepth,
		)
		if pathErr != nil {
			if err := state.appendRejectedPath(
				entry.Name, parentID, prefix, parentDepth+1,
			); err != nil {
				return err
			}
			continue
		}
		if !prepared {
			continue
		}
		metadata := map[string]any{
			"archive":            "zip",
			"compressed_bytes":   entry.CompressedSize64,
			"declared_bytes":     entry.UncompressedSize64,
			"compression_method": entry.Method,
			"crc32":              fmt.Sprintf("%08x", entry.CRC32),
		}
		node := Node{
			ParentLocalID: location.parentID,
			LogicalPath:   location.logical,
			DisplayName:   location.display,
			Depth:         location.depth,
			SizeBytes:     safeSize(entry.UncompressedSize64),
			MetadataJSON:  metadataJSON(metadata),
		}
		mode := entry.Mode()
		switch {
		case isDirectory:
			if location.directoryNode >= 0 {
				directory := &state.nodes[location.directoryNode]
				directoryMetadata := map[string]any{
					"archive":   "zip",
					"synthetic": false,
				}
				state.applyNamespaceCollision(
					location,
					directory,
					directoryMetadata,
				)
				directory.MetadataJSON = metadataJSON(directoryMetadata)
			}
		case mode&os.ModeSymlink != 0:
			node.NodeType = NodeTypeSymlink
			node.ExtractionStatus = StatusRecorded
			state.applyNamespaceCollision(location, &node, metadata)
			if _, err := state.appendNode(node); err != nil {
				return err
			}
		case !mode.IsRegular():
			node.NodeType = NodeTypeSpecial
			node.ExtractionStatus = StatusRecorded
			state.applyNamespaceCollision(location, &node, metadata)
			if _, err := state.appendNode(node); err != nil {
				return err
			}
		case entry.Flags&0x1 != 0:
			node.NodeType = NodeTypeFile
			node.ExtractionStatus = StatusPasswordRequired
			node.ErrorCode = "password_required"
			node.ErrorMessage = "encrypted ZIP entry requires a password"
			state.applyNamespaceCollision(location, &node, metadata)
			if _, err := state.appendNode(node); err != nil {
				return err
			}
			state.partial = true
		default:
			node.NodeType = NodeTypeFile
			state.applyNamespaceCollision(location, &node, metadata)
			nodeLocalID := state.nextID
			entryDecoderMemory := int64(0)
			if entry.Method != zip.Store {
				entryDecoderMemory = zipEntryDecoderMemoryReservation
			}
			releaseEntryDecoder, decoderMemoryLimit := state.memory.acquire(
				entryDecoderMemory,
				LimitMaxDecoderMemory,
			)
			if decoderMemoryLimit != nil {
				node.ExtractionStatus = StatusLimitExceeded
				node.ErrorCode = decoderMemoryLimit.code
				node.ErrorMessage = "ZIP entry decoder exceeds the task memory budget"
				if _, appendErr := state.appendNode(node); appendErr != nil {
					return appendErr
				}
				state.markLimit(decoderMemoryLimit.code)
				continue
			}
			input, err := entry.Open()
			if err != nil {
				releaseEntryDecoder()
				node.ExtractionStatus = StatusCorrupt
				node.ErrorCode = "zip_entry_open_failed"
				node.ErrorMessage = err.Error()
				if _, appendErr := state.appendNode(node); appendErr != nil {
					return appendErr
				}
				state.partial = true
				continue
			}
			materialized, limit, extractErr := state.materializeRegular(
				input,
				node,
				metadata,
				budget,
			)
			closeErr := input.Close()
			// A child is only inspected after the entry decoder has been
			// closed and its task-level reservation released.
			releaseEntryDecoder()
			if extractErr != nil {
				if materialized != nil {
					materialized.close()
				}
				return extractErr
			}
			if closeErr != nil {
				state.partial = true
				if extracted := state.nodeByLocalID(nodeLocalID); extracted != nil &&
					extracted.ExtractionStatus != StatusLimitExceeded &&
					extracted.ExtractionStatus != StatusCancelled &&
					extracted.ExtractionStatus != StatusInvalidPath {
					extracted.ExtractionStatus = StatusCorrupt
					extracted.ErrorCode = "zip_entry_close_failed"
					extracted.ErrorMessage = boundedText(closeErr.Error(), 2048)
					extracted.SHA256 = ""
				}
				if materialized != nil {
					materialized.close()
				}
				if limit != nil {
					return limit
				}
				continue
			}
			if limit != nil {
				if materialized != nil {
					materialized.close()
				}
				return limit
			}
			if err := state.completeMaterializedStream(
				materialized,
				nil,
				nil,
			); err != nil {
				return err
			}
		}
	}
	return nil
}

func (state *operationState) appendZIPUnsupportedArchiveNode(
	parentID int,
	prefix string,
) error {
	location, err := state.uniqueQuarantineLocation(parentID, "unsupported")
	if err != nil {
		return err
	}
	state.reserveLogicalPath(location.logical)
	metadata := map[string]any{
		"archive":   "zip",
		"synthetic": true,
	}
	if prefix != "" {
		metadata["archive_container_path"] = prefix
	}
	_, err = state.appendNode(Node{
		ParentLocalID:          location.parentID,
		SourceContainerLocalID: parentID,
		LogicalPath:            location.logical,
		DisplayName:            "unsupported-entry",
		NodeType:               NodeTypeSpecial,
		Depth:                  location.depth,
		ExtractionStatus:       StatusUnsupported,
		MetadataJSON:           metadataJSON(metadata),
		ErrorCode:              "multi_volume_unsupported",
		ErrorMessage:           "multi-volume ZIP archives are not supported",
	})
	state.partial = true
	return err
}

// estimateZIPParserMemory conservatively covers archive/zip's File objects
// plus copied names, comments, extras, and parser bookkeeping. Saturating to
// MaxInt64 makes malformed or future wider metadata fail closed in acquire.
func estimateZIPParserMemory(directory zipDirectoryInfo) int64 {
	const directoryCopies = uint64(3)
	if directory.size > math.MaxUint64/directoryCopies {
		return math.MaxInt64
	}
	estimated := directory.size * directoryCopies
	if directory.records >
		(math.MaxUint64-estimated)/zipParserEntryMemoryBytes {
		return math.MaxInt64
	}
	estimated += directory.records * zipParserEntryMemoryBytes
	if estimated > math.MaxUint64-zipParserFixedMemoryBytes {
		return math.MaxInt64
	}
	estimated += zipParserFixedMemoryBytes
	if estimated > math.MaxInt64 {
		return math.MaxInt64
	}
	return int64(estimated)
}

func safeSize(value uint64) int64 {
	if value > uint64(defaultMaxExpandedBytes) {
		return defaultMaxExpandedBytes
	}
	return int64(value)
}

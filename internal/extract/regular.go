package extract

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"strings"
)

const streamBufferSize = 32 << 10

type materializedRegular struct {
	file      *os.File
	path      string
	nodeIndex int
	size      int64
	scanDepth int
	retained  bool
}

func (materialized *materializedRegular) close() {
	if materialized == nil {
		return
	}
	_ = materialized.file.Close()
	if !materialized.retained {
		_ = os.Remove(materialized.path)
	}
}

func (state *operationState) extractRegular(
	input io.Reader,
	node Node,
	metadata map[string]any,
	container *containerBudget,
) (*limitError, error) {
	materialized, limit, err := state.materializeRegular(
		input,
		node,
		metadata,
		container,
	)
	if materialized == nil {
		return limit, err
	}
	defer materialized.close()
	if err != nil || limit != nil {
		return limit, err
	}
	return state.expandMaterializedRegular(materialized)
}

// materializeRegular consumes and detects an entry, but deliberately does not
// recurse into it. Stream decoders use this split lifecycle so their memory can
// be released before a child parser or decoder is created.
func (state *operationState) materializeRegular(
	input io.Reader,
	node Node,
	metadata map[string]any,
	container *containerBudget,
) (_ *materializedRegular, _ *limitError, returnedErr error) {
	if node.ExtractionStatus == "" {
		node.ExtractionStatus = StatusExtracted
	}
	node.MetadataJSON = metadataJSON(metadata)
	index, err := state.appendNode(node)
	if err != nil {
		var limit *limitError
		if errors.As(err, &limit) {
			return nil, limit, nil
		}
		return nil, nil, err
	}
	if state.nodes[index].LogicalPath != node.LogicalPath {
		metadata["duplicate_logical_path"] = node.LogicalPath
		state.nodes[index].MetadataJSON = metadataJSON(metadata)
	}

	temp, err := os.CreateTemp(state.workDir, "extract-*")
	if err != nil {
		return nil, nil, fmt.Errorf("extract: create work file: %w", err)
	}
	tempPath := temp.Name()
	retainTemp := false
	defer func() {
		if retainTemp {
			return
		}
		_ = temp.Close()
		_ = os.Remove(tempPath)
	}()
	if err := temp.Chmod(0o600); err != nil {
		return nil, nil, fmt.Errorf("extract: chmod work file: %w", err)
	}

	hash := sha256.New()
	buffer := make([]byte, streamBufferSize)
	var written int64
	for {
		if err := state.ctx.Err(); err != nil {
			state.nodes[index].ExtractionStatus = StatusCancelled
			state.nodes[index].ErrorCode = LimitContextCancelled
			state.nodes[index].ErrorMessage = "extraction was cancelled"
			return nil, nil, err
		}
		count, readErr := input.Read(buffer)
		if count > 0 {
			requested := int64(count)
			entryRemaining := state.engine.limits.MaxEntryBytes - written
			if entryRemaining < 0 {
				entryRemaining = 0
			}
			entryExceeded := requested > entryRemaining
			if entryExceeded &&
				state.reservationCapacity(container) > entryRemaining {
				requested = entryRemaining
			}
			allowed, limit := state.reserve(requested, container)
			if allowed > 0 {
				chunk := buffer[:allowed]
				outputCount, writeErr := temp.Write(chunk)
				if writeErr != nil {
					return nil, nil, fmt.Errorf(
						"extract: write work file: %w",
						writeErr,
					)
				}
				if outputCount != len(chunk) {
					return nil, nil, io.ErrShortWrite
				}
				_, _ = hash.Write(chunk)
				written += allowed
			}
			if limit != nil {
				state.nodes[index].SizeBytes = written
				state.nodes[index].ExtractionStatus = StatusLimitExceeded
				state.nodes[index].ErrorCode = limit.code
				state.nodes[index].ErrorMessage = "entry extraction stopped at configured limit"
				return nil, limit, nil
			}
			if entryExceeded {
				state.markEntryByteLimit(index, written)
				return nil, nil, nil
			}
		}
		if readErr != nil {
			var decoderLimit *limitError
			if errors.As(readErr, &decoderLimit) {
				state.markLimit(decoderLimit.code)
				if decoderLimit.global {
					state.stopped = true
				}
				state.nodes[index].SizeBytes = written
				state.nodes[index].ExtractionStatus = StatusLimitExceeded
				state.nodes[index].ErrorCode = decoderLimit.code
				state.nodes[index].ErrorMessage = "entry decoding stopped at configured limit"
				return nil, decoderLimit, nil
			}
			if errors.Is(readErr, context.Canceled) ||
				errors.Is(readErr, context.DeadlineExceeded) {
				state.nodes[index].SizeBytes = written
				state.nodes[index].ExtractionStatus = StatusCancelled
				state.nodes[index].ErrorCode = LimitContextCancelled
				state.nodes[index].ErrorMessage = "extraction was cancelled"
				return nil, nil, readErr
			}
			if errors.Is(readErr, io.EOF) {
				break
			}
			state.partial = true
			state.nodes[index].SizeBytes = written
			state.nodes[index].ExtractionStatus = StatusCorrupt
			state.nodes[index].ErrorCode = "archive_entry_corrupt"
			state.nodes[index].ErrorMessage = readErr.Error()
			return nil, nil, nil
		}
		if count == 0 {
			state.partial = true
			state.nodes[index].SizeBytes = written
			state.nodes[index].ExtractionStatus = StatusCorrupt
			state.nodes[index].ErrorCode = "archive_entry_stalled"
			state.nodes[index].ErrorMessage = "archive entry returned no data and no error"
			return nil, nil, nil
		}
	}
	state.nodes[index].SizeBytes = written
	state.nodes[index].SHA256 = hex.EncodeToString(hash.Sum(nil))

	detected, err := detectContent(state.ctx, state.engine.detector, temp, written)
	if err != nil {
		return nil, nil, fmt.Errorf("extract: detect entry %q: %w",
			state.nodes[index].LogicalPath, err)
	}
	state.nodes[index].Format = detected.Format
	state.nodes[index].MIMEType = detected.MIMEType
	state.nodes[index].Architecture = detected.Architecture
	if len(detected.Metadata) > 0 {
		metadata["detection"] = detected.Metadata
		state.nodes[index].MetadataJSON = metadataJSON(metadata)
	}
	retainForContainerScan := detected.Format == "docker-tar" ||
		detected.Format == "oci-tar"
	if retainForContainerScan {
		state.containerImages = append(state.containerImages, ContainerImage{
			LocalID:     state.nodes[index].LocalID,
			LogicalPath: state.nodes[index].LogicalPath,
			Format:      state.nodes[index].Format,
			SHA256:      state.nodes[index].SHA256,
			SizeBytes:   state.nodes[index].SizeBytes,
			WorkPath:    tempPath,
		})
	}
	if state.logicalPackage {
		state.materializedFiles = append(
			state.materializedFiles,
			MaterializedFile{
				LocalID:  state.nodes[index].LocalID,
				WorkPath: tempPath,
			},
		)
	}
	retainTemp = true
	return &materializedRegular{
		file:      temp,
		path:      tempPath,
		nodeIndex: index,
		size:      written,
		retained:  retainForContainerScan || state.logicalPackage,
		// Scan depth follows archive containment, not the display-tree
		// parent. Quarantine may move a node to a shorter safe ancestor and
		// must never reset the recursive extraction limit.
		scanDepth: container.scanDepth + 1,
	}, nil, nil
}

func (state *operationState) markEntryByteLimit(index int, written int64) {
	node := &state.nodes[index]
	node.SizeBytes = written
	node.SHA256 = ""
	node.ExtractionStatus = StatusLimitExceeded
	node.ErrorCode = LimitMaxEntryBytes
	node.ErrorMessage = "entry exceeds the configured per-entry size limit"
	state.markLimit(LimitMaxEntryBytes)
}

// limitDeclaredRegular records a regular entry whose logical size is already
// known to exceed the per-entry limit. Charging the full permitted size keeps
// sparse TAR entries equivalent to streaming their synthesized zero regions.
func (state *operationState) limitDeclaredRegular(
	node Node,
	metadata map[string]any,
	declaredSize int64,
	container *containerBudget,
) (*limitError, error) {
	node.SizeBytes = 0
	node.ExtractionStatus = StatusLimitExceeded
	node.ErrorCode = LimitMaxEntryBytes
	node.ErrorMessage = "entry exceeds the configured per-entry size limit"
	node.MetadataJSON = metadataJSON(metadata)
	index, err := state.appendNode(node)
	if err != nil {
		var limit *limitError
		if errors.As(err, &limit) {
			return limit, nil
		}
		return nil, err
	}
	if state.nodes[index].LogicalPath != node.LogicalPath {
		metadata["duplicate_logical_path"] = node.LogicalPath
		state.nodes[index].MetadataJSON = metadataJSON(metadata)
	}

	requested := state.engine.limits.MaxEntryBytes
	if state.reservationCapacity(container) <= requested {
		requested = declaredSize
	}
	allowed, limit := state.reserve(requested, container)
	state.nodes[index].SizeBytes = allowed
	if limit != nil {
		state.nodes[index].ErrorCode = limit.code
		state.nodes[index].ErrorMessage = "entry extraction stopped at configured limit"
		return limit, nil
	}
	state.markLimit(LimitMaxEntryBytes)
	return nil, nil
}

func (state *operationState) expandMaterializedRegular(
	materialized *materializedRegular,
) (*limitError, error) {
	index := materialized.nodeIndex
	detectedFormat := state.nodes[index].Format
	if state.logicalPackage && !state.shouldExpandLogicalWrapper(index) {
		return nil, nil
	}
	if !state.engine.Supports(detectedFormat) {
		if isKnownContainerFormat(detectedFormat) {
			state.nodes[index].ExtractionStatus = StatusUnsupported
			state.nodes[index].ErrorCode = "unsupported_nested_format"
			state.nodes[index].ErrorMessage = "nested format is not supported by this extraction engine"
			state.partial = true
		}
		return nil, nil
	}
	if materialized.scanDepth >= state.engine.limits.MaxDepth {
		state.nodes[index].ExtractionStatus = StatusDepthLimited
		state.nodes[index].ErrorCode = LimitMaxDepth
		state.nodes[index].ErrorMessage = "nested extraction depth limit reached"
		state.markLimit(LimitMaxDepth)
		return nil, nil
	}

	childBudget := containerBudget{
		sourceSize: materialized.size,
		scanDepth:  materialized.scanDepth,
	}
	err := state.extractContainer(
		materialized.file,
		materialized.size,
		detectedFormat,
		state.nodes[index].LocalID,
		state.nodes[index].LogicalPath,
		state.nodes[index].Depth,
		&childBudget,
	)
	if err == nil {
		return nil, nil
	}
	var limit *limitError
	if errors.As(err, &limit) {
		state.nodes[index].ExtractionStatus = StatusLimitExceeded
		state.nodes[index].ErrorCode = limit.code
		state.nodes[index].ErrorMessage = "nested extraction stopped at configured limit"
		if limit.global {
			return limit, nil
		}
		return nil, nil
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		state.nodes[index].ExtractionStatus = StatusCancelled
		state.nodes[index].ErrorCode = LimitContextCancelled
		state.nodes[index].ErrorMessage = "nested extraction was cancelled"
		return nil, err
	}
	return nil, err
}

func (state *operationState) shouldExpandLogicalWrapper(index int) bool {
	if index < 0 || index >= len(state.nodes) {
		return false
	}
	node := state.nodes[index]
	parentFormat := ""
	if parent := state.nodeByLocalID(node.ParentLocalID); parent != nil {
		parentFormat = parent.Format
	}
	// A member produced by TAR/CPIO is a logical leaf even when it is itself
	// another archive. This is the boundary that prevents recursive imports.
	if isTARFamilyFormat(parentFormat) || parentFormat == "cpio" {
		return false
	}
	switch state.rootFormat {
	case "gzip", "bzip2", "xz", "zstd":
		return node.ParentLocalID == 0 && isTARFamilyFormat(node.Format)
	case "rpm":
		return node.ParentLocalID == 0 && node.Format == "cpio"
	case "deb":
		if node.ParentLocalID == 0 {
			base := path.Base(node.LogicalPath)
			return (strings.HasPrefix(base, "control.tar") ||
				strings.HasPrefix(base, "data.tar")) &&
				isLogicalPackageWrapperFormat(node.Format)
		}
		return isLogicalPackageStreamFormat(parentFormat) &&
			isTARFamilyFormat(node.Format)
	default:
		return false
	}
}

func isLogicalPackageStreamFormat(format string) bool {
	switch format {
	case "gzip", "bzip2", "xz", "zstd", "lzma":
		return true
	default:
		return false
	}
}

func isLogicalPackageWrapperFormat(format string) bool {
	return isLogicalPackageStreamFormat(format) || isTARFamilyFormat(format)
}

func isKnownContainerFormat(format string) bool {
	switch format {
	case "7z", "apk", "ar", "bzip2", "cab", "cpio", "deb",
		"docker-tar", "ear", "ext2", "ext3", "ext4", "gpt-img",
		"gzip", "iso9660", "jar", "lzma", "mbr-img", "oci-tar", "rar",
		"rpm", "squashfs", "tar", "udf", "war", "xz", "zip", "zstd":
		return true
	default:
		return false
	}
}

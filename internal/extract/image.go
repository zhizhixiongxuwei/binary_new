package extract

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"

	"binaryscan/internal/imageextract"
)

func (state *operationState) extractImage(
	source io.ReaderAt,
	sourceSize int64,
	format string,
	parentID int,
	prefix string,
	parentDepth int,
	budget *containerBudget,
) error {
	if state.engine.imageEngine == nil {
		return errors.New("extract: image engine is unavailable")
	}
	result, extractErr := state.engine.imageEngine.Extract(
		state.ctx,
		imageextract.Request{
			Format: format, Source: source, SizeBytes: sourceSize,
			Depth: parentDepth,
		},
	)

	if err := state.importImagePartitions(
		source,
		result.Partitions,
		parentID,
		prefix,
		parentDepth,
		budget,
	); err != nil {
		return err
	}
	if err := state.importImageEntries(
		source,
		format,
		result.Entries,
		parentID,
		prefix,
		parentDepth,
		budget,
	); err != nil {
		return err
	}

	if result.LimitCode != "" {
		limit := imageLimitError(result.LimitCode)
		state.markLimit(limit.code)
		if limit.global {
			state.stopped = true
		}
		return limit
	}
	if extractErr == nil {
		if result.Partial {
			state.partial = true
		}
		return nil
	}
	if errors.Is(extractErr, context.Canceled) ||
		errors.Is(extractErr, context.DeadlineExceeded) {
		return extractErr
	}
	code := result.ErrorCode
	if code == "" {
		code = "image_extract_failed"
	}
	message := extractErr
	if result.ErrorMessage != "" {
		message = errors.New(result.ErrorMessage)
	}
	return state.appendCorruptArchiveNode(
		parentID,
		prefix,
		parentDepth+1,
		code,
		message,
	)
}

func (state *operationState) importImageEntries(
	source io.ReaderAt,
	imageFormat string,
	entries []imageextract.Entry,
	parentID int,
	prefix string,
	parentDepth int,
	budget *containerBudget,
) error {
	for _, entry := range entries {
		if err := state.ctx.Err(); err != nil {
			return err
		}
		if state.stopped {
			return &limitError{code: state.limitCode, global: true}
		}
		relative := strings.TrimPrefix(entry.LogicalPath, "/")
		isDirectory := entry.Kind == imageextract.EntryDirectory
		location, prepared, pathErr := state.prepareEntryWithNameSuffix(
			prefix,
			relative,
			isDirectory,
			parentID,
			parentDepth,
		)
		if pathErr != nil {
			if err := state.appendRejectedPath(
				entry.LogicalPath,
				parentID,
				prefix,
				parentDepth+1,
			); err != nil {
				return err
			}
			continue
		}
		if !prepared {
			continue
		}
		metadata := map[string]any{
			"image_format":   imageFormat,
			"image_path":     entry.LogicalPath,
			"declared_bytes": entry.SizeBytes,
			"extent_count":   len(entry.Extents),
		}
		if entry.PartitionID != "" {
			metadata["partition_id"] = entry.PartitionID
		}
		node := Node{
			ParentLocalID: location.parentID,
			LogicalPath:   location.logical,
			DisplayName:   location.display,
			Depth:         location.depth,
			SizeBytes:     entry.SizeBytes,
			MetadataJSON:  metadataJSON(metadata),
		}
		switch entry.Kind {
		case imageextract.EntryDirectory:
			if location.directoryNode >= 0 {
				directory := &state.nodes[location.directoryNode]
				metadata["synthetic"] = false
				state.applyNamespaceCollision(location, directory, metadata)
				if imageEntryIsPartial(entry) {
					applyImageEntryStatus(directory, entry)
					state.partial = true
				}
				directory.MetadataJSON = metadataJSON(metadata)
			}
		case imageextract.EntryFile:
			node.NodeType = NodeTypeFile
			state.applyNamespaceCollision(location, &node, metadata)
			if entry.Status != "" && entry.Status != imageextract.StatusIndexed {
				applyImageEntryStatus(&node, entry)
				if _, err := state.appendNode(node); err != nil {
					return err
				}
				state.partial = true
				continue
			}
			if entry.SizeBytes > state.engine.limits.MaxEntryBytes {
				limit, err := state.limitDeclaredRegular(
					node, metadata, entry.SizeBytes, budget,
				)
				if err != nil {
					return err
				}
				if limit != nil {
					return limit
				}
				continue
			}
			limit, err := state.extractRegular(
				newExtentReader(source, entry.Extents),
				node,
				metadata,
				budget,
			)
			if err != nil {
				return err
			}
			if limit != nil {
				return limit
			}
		case imageextract.EntrySymlink, imageextract.EntryHardlink:
			if entry.Kind == imageextract.EntrySymlink {
				node.NodeType = NodeTypeSymlink
			} else {
				node.NodeType = NodeTypeHardlink
			}
			node.ExtractionStatus = StatusRecorded
			if imageEntryIsPartial(entry) {
				applyImageEntryStatus(&node, entry)
				state.partial = true
			}
			metadata["link_target"] = entry.LinkTarget
			state.applyNamespaceCollision(location, &node, metadata)
			if _, err := state.appendNode(node); err != nil {
				return err
			}
		default:
			node.NodeType = NodeTypeSpecial
			node.ExtractionStatus = StatusRecorded
			if imageEntryIsPartial(entry) {
				applyImageEntryStatus(&node, entry)
				state.partial = true
			}
			state.applyNamespaceCollision(location, &node, metadata)
			if _, err := state.appendNode(node); err != nil {
				return err
			}
		}
	}
	return nil
}

func (state *operationState) importImagePartitions(
	source io.ReaderAt,
	partitions []imageextract.Partition,
	parentID int,
	prefix string,
	parentDepth int,
	budget *containerBudget,
) error {
	for _, partition := range partitions {
		if err := state.ctx.Err(); err != nil {
			return err
		}
		name := fmt.Sprintf("partition-%03d", partition.Index)
		location, prepared, err := state.prepareEntryWithNameSuffix(
			prefix,
			name,
			true,
			parentID,
			parentDepth,
		)
		if err != nil {
			return err
		}
		if !prepared || location.directoryNode < 0 {
			continue
		}
		node := &state.nodes[location.directoryNode]
		metadata := map[string]any{
			"image_partition":  true,
			"partition_id":     partition.ID,
			"partition_index":  partition.Index,
			"partition_scheme": partition.Scheme,
			"partition_type":   partition.Type,
			"offset_bytes":     partition.StartOffsetBytes,
			"size_bytes":       partition.SizeBytes,
			"synthetic":        false,
		}
		section := io.NewSectionReader(
			source,
			partition.StartOffsetBytes,
			partition.SizeBytes,
		)
		if partition.Status == imageextract.StatusUnsupported ||
			partition.Status == imageextract.StatusCorrupt {
			if partition.Status == imageextract.StatusUnsupported {
				node.ExtractionStatus = StatusUnsupported
			} else {
				node.ExtractionStatus = StatusCorrupt
			}
			node.ErrorCode = partition.ErrorCode
			node.ErrorMessage = partition.ErrorMessage
			node.MetadataJSON = metadataJSON(metadata)
			state.partial = true
			continue
		}
		detected, detectErr := detectContent(
			state.ctx,
			state.engine.detector,
			section,
			partition.SizeBytes,
		)
		if detectErr != nil {
			node.ExtractionStatus = StatusCorrupt
			node.ErrorCode = "partition_detection_failed"
			node.ErrorMessage = detectErr.Error()
			state.partial = true
			node.MetadataJSON = metadataJSON(metadata)
			continue
		}
		node.Format = detected.Format
		node.MIMEType = detected.MIMEType
		node.Architecture = detected.Architecture
		metadata["detection"] = detected.Metadata
		if partition.Filesystem != "" {
			metadata["filesystem"] = partition.Filesystem
		}
		state.applyNamespaceCollision(location, node, metadata)
		node.MetadataJSON = metadataJSON(metadata)
		if !state.engine.Supports(detected.Format) {
			if isKnownContainerFormat(detected.Format) {
				node.ExtractionStatus = StatusUnsupported
				node.ErrorCode = "unsupported_partition_format"
				node.ErrorMessage = "partition format is not supported by this extraction engine"
				state.partial = true
			}
			continue
		}
		if !isImageExtractionFormat(detected.Format) {
			node.ExtractionStatus = StatusUnsupported
			node.ErrorCode = "unsupported_partition_payload"
			node.ErrorMessage = "partition payload is not a supported filesystem image"
			state.partial = true
			continue
		}
		if node.Depth >= state.engine.limits.MaxDepth {
			node.ExtractionStatus = StatusDepthLimited
			node.ErrorCode = LimitMaxDepth
			node.ErrorMessage = "partition extraction depth limit reached"
			state.markLimit(LimitMaxDepth)
			continue
		}
		childBudget := containerBudget{
			sourceSize: partition.SizeBytes,
			scanDepth:  budget.scanDepth + 1,
		}
		if err := state.extractImage(
			section,
			partition.SizeBytes,
			detected.Format,
			node.LocalID,
			node.LogicalPath,
			node.Depth,
			&childBudget,
		); err != nil {
			var limit *limitError
			if errors.As(err, &limit) {
				node.ExtractionStatus = StatusLimitExceeded
				node.ErrorCode = limit.code
				node.ErrorMessage = "partition extraction stopped at configured limit"
				if limit.global {
					return limit
				}
				continue
			}
			if errors.Is(err, context.Canceled) ||
				errors.Is(err, context.DeadlineExceeded) {
				return err
			}
			return err
		}
	}
	return nil
}

func applyImageEntryStatus(node *Node, entry imageextract.Entry) {
	switch entry.Status {
	case imageextract.StatusUnsupported:
		node.ExtractionStatus = StatusUnsupported
	case imageextract.StatusCorrupt:
		node.ExtractionStatus = StatusCorrupt
	default:
		node.ExtractionStatus = StatusRecorded
	}
	node.ErrorCode = entry.ErrorCode
	node.ErrorMessage = entry.ErrorMessage
}

func imageEntryIsPartial(entry imageextract.Entry) bool {
	return entry.Status == imageextract.StatusUnsupported ||
		entry.Status == imageextract.StatusCorrupt
}

func imageLimitError(code imageextract.LimitCode) *limitError {
	switch code {
	case imageextract.LimitMaxExpandedBytes:
		return &limitError{code: LimitMaxExpandedBytes, global: true}
	case imageextract.LimitMaxEntryBytes,
		imageextract.LimitMaxInputBytes:
		return &limitError{code: LimitMaxEntryBytes}
	case imageextract.LimitMaxEntries:
		return &limitError{code: LimitMaxNodes, global: true}
	case imageextract.LimitMaxDepth:
		return &limitError{code: LimitMaxDepth}
	case imageextract.LimitMaxReadBytes:
		return &limitError{code: LimitMaxImageReadBytes}
	case imageextract.LimitMaxExtents:
		return &limitError{code: LimitMaxImageExtents}
	case imageextract.LimitMaxPartitions:
		return &limitError{code: LimitMaxImagePartitions}
	default:
		return &limitError{code: string(code)}
	}
}

func newExtentReader(
	source io.ReaderAt,
	extents []imageextract.Extent,
) io.Reader {
	readers := make([]io.Reader, 0, len(extents))
	for _, extent := range extents {
		readers = append(
			readers,
			io.NewSectionReader(source, extent.OffsetBytes, extent.SizeBytes),
		)
	}
	return io.MultiReader(readers...)
}

func isImageExtractionFormat(format string) bool {
	switch format {
	case "raw-img", "mbr-img", "gpt-img", "iso9660":
		return true
	default:
		return false
	}
}

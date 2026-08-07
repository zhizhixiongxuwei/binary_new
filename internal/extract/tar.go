package extract

import (
	"archive/tar"
	"context"
	"errors"
	"io"
	"os"
)

func (state *operationState) extractTAR(
	source *os.File,
	sourceSize int64,
	parentID int,
	prefix string,
	parentDepth int,
	budget *containerBudget,
) error {
	raw := newTARMetadataReader(
		state.ctx,
		io.NewSectionReader(source, 0, sourceSize),
	)
	archive := tar.NewReader(raw)
	for {
		if err := state.ctx.Err(); err != nil {
			return err
		}
		if state.stopped {
			return &limitError{code: state.limitCode, global: true}
		}
		releaseHeaderGate, headerMemoryLimit := state.memory.acquire(
			estimateTARParserMemory(maxTARMetadataBytes),
			LimitMaxArchiveMetadata,
		)
		if headerMemoryLimit != nil {
			state.markLimit(headerMemoryLimit.code)
			return headerMemoryLimit
		}
		raw.beginHeader()
		header, err := archive.Next()
		headerMetadataBytes := raw.endHeader()
		// Next may allocate sparse/PAX structures while it reads. Reserve for
		// the worst case before calling it, then replace that reservation with
		// the measured retained-header estimate for recursive regular entries.
		releaseHeaderGate()
		if errors.Is(err, io.EOF) {
			trailingErr := validateTARTrailingPadding(
				state.ctx,
				source,
				sourceSize,
				raw.totalBytesConsumed(),
			)
			if trailingErr == nil {
				return nil
			}
			var limit *limitError
			switch {
			case errors.As(trailingErr, &limit):
				state.markLimit(limit.code)
				if limit.global {
					state.stopped = true
				}
				return limit
			case errors.Is(trailingErr, context.Canceled),
				errors.Is(trailingErr, context.DeadlineExceeded):
				return trailingErr
			default:
				return state.appendCorruptArchiveNode(
					parentID,
					prefix,
					parentDepth+1,
					"tar_trailing_data",
					trailingErr,
				)
			}
		}
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
			default:
				return state.appendCorruptArchiveNode(
					parentID, prefix, parentDepth+1, "tar_header_corrupt", err,
				)
			}
		}
		isDirectory := header.Typeflag == tar.TypeDir
		location, prepared, pathErr := state.prepareEntryWithNameSuffix(
			prefix, header.Name, isDirectory, parentID, parentDepth,
		)
		if pathErr != nil {
			if err := state.appendRejectedPath(
				header.Name, parentID, prefix, parentDepth+1,
			); err != nil {
				return err
			}
			continue
		}
		if !prepared {
			continue
		}
		metadata := map[string]any{
			"archive":        "tar",
			"declared_bytes": header.Size,
			"mode":           header.Mode,
			"tar_type":       header.Typeflag,
		}
		node := Node{
			ParentLocalID: location.parentID,
			LogicalPath:   location.logical,
			DisplayName:   location.display,
			Depth:         location.depth,
			SizeBytes:     safeSignedSize(header.Size),
			MetadataJSON:  metadataJSON(metadata),
		}
		switch header.Typeflag {
		case tar.TypeDir:
			if location.directoryNode >= 0 {
				directory := &state.nodes[location.directoryNode]
				directoryMetadata := map[string]any{
					"archive":   "tar",
					"mode":      header.Mode,
					"synthetic": false,
				}
				state.applyNamespaceCollision(
					location,
					directory,
					directoryMetadata,
				)
				directory.MetadataJSON = metadataJSON(directoryMetadata)
			}
		case tar.TypeSymlink:
			node.NodeType = NodeTypeSymlink
			node.ExtractionStatus = StatusRecorded
			linkTarget := boundedText(header.Linkname, maxLogicalPathBytes)
			metadata["link_target"] = linkTarget
			metadata["link_target_truncated"] = linkTarget != header.Linkname
			node.MetadataJSON = metadataJSON(metadata)
			state.applyNamespaceCollision(location, &node, metadata)
			if _, err := state.appendNode(node); err != nil {
				return err
			}
		case tar.TypeLink:
			node.NodeType = NodeTypeHardlink
			node.ExtractionStatus = StatusRecorded
			linkTarget := boundedText(header.Linkname, maxLogicalPathBytes)
			metadata["link_target"] = linkTarget
			metadata["link_target_truncated"] = linkTarget != header.Linkname
			node.MetadataJSON = metadataJSON(metadata)
			state.applyNamespaceCollision(location, &node, metadata)
			if _, err := state.appendNode(node); err != nil {
				return err
			}
		case tar.TypeReg, tar.TypeRegA:
			node.NodeType = NodeTypeFile
			state.applyNamespaceCollision(location, &node, metadata)
			if header.Size > state.engine.limits.MaxEntryBytes {
				limit, limitErr := state.limitDeclaredRegular(
					node,
					metadata,
					header.Size,
					budget,
				)
				if limitErr != nil {
					return limitErr
				}
				if limit != nil {
					return limit
				}
				// tar.Reader.Next discards only the current entry's physical
				// bytes. For sparse files it does not synthesize or walk the
				// logical holes, so safe siblings can still be inspected.
				continue
			}
			releaseParser, parserMemoryLimit := state.memory.acquire(
				estimateTARParserMemory(headerMetadataBytes),
				LimitMaxArchiveMetadata,
			)
			if parserMemoryLimit != nil {
				state.markLimit(parserMemoryLimit.code)
				return parserMemoryLimit
			}
			limit, extractErr := state.extractRegular(archive, node, metadata, budget)
			// tar.Reader retains the current PAX/sparse representation while
			// a child is inspected, so release it only after recursion returns.
			releaseParser()
			if extractErr != nil {
				return extractErr
			}
			if limit != nil {
				return limit
			}
		default:
			node.NodeType = NodeTypeSpecial
			node.ExtractionStatus = StatusRecorded
			state.applyNamespaceCollision(location, &node, metadata)
			if _, err := state.appendNode(node); err != nil {
				return err
			}
		}
	}
}

func safeSignedSize(value int64) int64 {
	if value < 0 {
		return 0
	}
	if value > defaultMaxExpandedBytes {
		return defaultMaxExpandedBytes
	}
	return value
}

func (state *operationState) appendCorruptArchiveNode(
	parentID int,
	prefix string,
	_ int,
	code string,
	cause error,
) error {
	location, locationErr := state.uniqueQuarantineLocation(
		parentID,
		"corrupt",
	)
	if locationErr != nil {
		return locationErr
	}
	state.reserveLogicalPath(location.logical)
	metadata := map[string]any{"synthetic": true}
	if prefix != "" {
		metadata["archive_container_path"] = prefix
	}
	_, err := state.appendNode(Node{
		ParentLocalID:          location.parentID,
		SourceContainerLocalID: parentID,
		LogicalPath:            location.logical,
		DisplayName:            "corrupt-entry",
		NodeType:               NodeTypeSpecial,
		Depth:                  location.depth,
		ExtractionStatus:       StatusCorrupt,
		MetadataJSON:           metadataJSON(metadata),
		ErrorCode:              code,
		ErrorMessage:           cause.Error(),
	})
	state.partial = true
	return err
}

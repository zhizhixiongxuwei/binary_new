package extract

import (
	"compress/bzip2"
	"compress/gzip"
	"context"
	"errors"
	"io"
	"os"

	"github.com/klauspost/compress/zstd"
	xzlib "github.com/ulikunitz/xz"
)

const (
	gzipDecoderMemoryReservation  = int64(1 << 20)
	bzip2DecoderMemoryReservation = int64(8 << 20)
)

func (state *operationState) extractGZIP(
	source *os.File,
	sourceSize int64,
	parentID int,
	prefix string,
	parentDepth int,
	budget *containerBudget,
) error {
	release, memoryLimit := state.memory.acquire(
		gzipDecoderMemoryReservation,
		LimitMaxDecoderMemory,
	)
	if memoryLimit != nil {
		return state.handleStreamInitializationError(
			memoryLimit,
			parentID,
			prefix,
			parentDepth,
			"gzip_archive_corrupt",
		)
	}
	materialized, limit, materializeErr := func() (
		*materializedRegular,
		*limitError,
		error,
	) {
		defer release()
		input, err := gzip.NewReader(contextAwareReader{
			ctx:    state.ctx,
			reader: io.NewSectionReader(source, 0, sourceSize),
		})
		if err != nil {
			return nil, nil, state.appendCorruptArchiveNode(
				parentID,
				prefix,
				parentDepth+1,
				"gzip_archive_corrupt",
				err,
			)
		}
		defer input.Close()
		name := input.Name
		if name == "" {
			name = "content"
		}
		location, prepared, pathErr := state.prepareEntry(
			prefix,
			name,
			false,
			parentID,
			parentDepth,
		)
		if pathErr != nil {
			return nil, nil, state.appendRejectedPath(
				name,
				parentID,
				prefix,
				parentDepth+1,
			)
		}
		if !prepared {
			return nil, nil, nil
		}
		metadata := map[string]any{"archive": "gzip"}
		if input.Comment != "" {
			comment := boundedText(input.Comment, maxLogicalPathBytes)
			metadata["comment"] = comment
			metadata["comment_truncated"] = comment != input.Comment
		}
		if !input.ModTime.IsZero() {
			metadata["modified_at"] = input.ModTime.UTC().Format(
				"2006-01-02T15:04:05.999999999Z",
			)
		}
		node := Node{
			ParentLocalID: location.parentID,
			LogicalPath:   location.logical,
			DisplayName:   location.display,
			NodeType:      NodeTypeFile,
			Depth:         location.depth,
		}
		state.applyNamespaceCollision(location, &node, metadata)
		return state.materializeRegular(input, node, metadata, budget)
	}()
	return state.completeMaterializedStream(
		materialized,
		limit,
		materializeErr,
	)
}

func (state *operationState) extractBZIP2(
	source *os.File,
	sourceSize int64,
	parentID int,
	prefix string,
	parentDepth int,
	budget *containerBudget,
) error {
	release, memoryLimit := state.memory.acquire(
		bzip2DecoderMemoryReservation,
		LimitMaxDecoderMemory,
	)
	if memoryLimit != nil {
		return state.handleStreamInitializationError(
			memoryLimit,
			parentID,
			prefix,
			parentDepth,
			"bzip2_archive_corrupt",
		)
	}
	materialized, limit, materializeErr := func() (
		*materializedRegular,
		*limitError,
		error,
	) {
		defer release()
		return state.materializeSingleStream(
			bzip2.NewReader(contextAwareReader{
				ctx:    state.ctx,
				reader: io.NewSectionReader(source, 0, sourceSize),
			}),
			"bzip2",
			"bzip2_archive_corrupt",
			parentID,
			prefix,
			parentDepth,
			budget,
		)
	}()
	return state.completeMaterializedStream(
		materialized,
		limit,
		materializeErr,
	)
}

func (state *operationState) extractXZ(
	source *os.File,
	sourceSize int64,
	parentID int,
	prefix string,
	parentDepth int,
	budget *containerBudget,
) error {
	info, err := preflightXZ(state.ctx, source, sourceSize)
	if err != nil {
		return state.handleStreamInitializationError(
			err,
			parentID,
			prefix,
			parentDepth,
			"xz_archive_corrupt",
		)
	}
	release, memoryLimit := state.memory.acquire(
		info.MaxDictionaryBytes,
		LimitMaxDecoderMemory,
	)
	if memoryLimit != nil {
		return state.handleStreamInitializationError(
			memoryLimit,
			parentID,
			prefix,
			parentDepth,
			"xz_archive_corrupt",
		)
	}

	materialized, limit, materializeErr := func() (
		*materializedRegular,
		*limitError,
		error,
	) {
		defer release()
		// DictCap is deliberately zero. The XZ preflight has already bounded
		// every declared dictionary, and the library then allocates the
		// dictionary declared by each block instead of 64 MiB for every block.
		input, err := (xzlib.ReaderConfig{
			DictCap:      0,
			SingleStream: true,
		}).NewReader(contextAwareReader{
			ctx:    state.ctx,
			reader: io.NewSectionReader(source, 0, sourceSize),
		})
		if err != nil {
			return nil, nil, state.appendCorruptArchiveNode(
				parentID,
				prefix,
				parentDepth+1,
				"xz_archive_corrupt",
				err,
			)
		}
		return state.materializeSingleStream(
			input,
			"xz",
			"xz_archive_corrupt",
			parentID,
			prefix,
			parentDepth,
			budget,
		)
	}()
	return state.completeMaterializedStream(
		materialized,
		limit,
		materializeErr,
	)
}

func (state *operationState) extractZSTD(
	source *os.File,
	sourceSize int64,
	parentID int,
	prefix string,
	parentDepth int,
	budget *containerBudget,
) error {
	release, memoryLimit := state.memory.acquire(
		int64(maxStreamDecoderMemoryBytes),
		LimitMaxDecoderMemory,
	)
	if memoryLimit != nil {
		return state.handleStreamInitializationError(
			memoryLimit,
			parentID,
			prefix,
			parentDepth,
			"zstd_archive_corrupt",
		)
	}

	materialized, limit, materializeErr := func() (
		*materializedRegular,
		*limitError,
		error,
	) {
		defer release()
		decoder, err := zstd.NewReader(
			contextAwareReader{
				ctx:    state.ctx,
				reader: io.NewSectionReader(source, 0, sourceSize),
			},
			zstd.WithDecoderConcurrency(1),
			zstd.WithDecoderLowmem(true),
			zstd.WithDecoderMaxMemory(maxStreamDecoderMemoryBytes),
			zstd.WithDecoderMaxWindow(maxStreamDecoderMemoryBytes),
			zstd.WithDecodeBuffersBelow(0),
		)
		if err != nil {
			return nil, nil, state.handleStreamInitializationError(
				mapZSTDDecoderLimit(err),
				parentID,
				prefix,
				parentDepth,
				"zstd_archive_corrupt",
			)
		}
		defer decoder.Close()
		return state.materializeSingleStream(
			zstdLimitReader{reader: decoder},
			"zstd",
			"zstd_archive_corrupt",
			parentID,
			prefix,
			parentDepth,
			budget,
		)
	}()
	return state.completeMaterializedStream(
		materialized,
		limit,
		materializeErr,
	)
}

func (state *operationState) materializeSingleStream(
	input io.Reader,
	archiveName string,
	corruptCode string,
	parentID int,
	prefix string,
	parentDepth int,
	budget *containerBudget,
) (*materializedRegular, *limitError, error) {
	location, prepared, err := state.prepareEntry(
		prefix, "content", false, parentID, parentDepth,
	)
	if err != nil {
		return nil, nil, err
	}
	if !prepared {
		return nil, nil, nil
	}
	nodeLocalID := state.nextID
	metadata := map[string]any{"archive": archiveName}
	node := Node{
		ParentLocalID: location.parentID,
		LogicalPath:   location.logical,
		DisplayName:   location.display,
		NodeType:      NodeTypeFile,
		Depth:         location.depth,
	}
	state.applyNamespaceCollision(location, &node, metadata)
	materialized, limit, err := state.materializeRegular(
		input,
		node,
		metadata,
		budget,
	)
	if extracted := state.nodeByLocalID(nodeLocalID); extracted != nil &&
		extracted.ExtractionStatus == StatusCorrupt &&
		extracted.ErrorCode == "archive_entry_corrupt" {
		extracted.ErrorCode = corruptCode
	}
	if err != nil {
		return nil, nil, err
	}
	if limit != nil {
		return nil, limit, nil
	}
	return materialized, nil, nil
}

func (state *operationState) completeMaterializedStream(
	materialized *materializedRegular,
	limit *limitError,
	err error,
) error {
	if materialized == nil {
		if err != nil {
			return err
		}
		if limit != nil {
			return limit
		}
		return nil
	}
	defer materialized.close()
	if err != nil {
		return err
	}
	if limit != nil {
		return limit
	}
	nestedLimit, err := state.expandMaterializedRegular(materialized)
	if err != nil {
		return err
	}
	if nestedLimit != nil {
		return nestedLimit
	}
	return nil
}

func (state *operationState) handleStreamInitializationError(
	err error,
	parentID int,
	prefix string,
	parentDepth int,
	corruptCode string,
) error {
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
			parentID,
			prefix,
			parentDepth+1,
			corruptCode,
			err,
		)
	}
}

type zstdLimitReader struct {
	reader io.Reader
}

func (reader zstdLimitReader) Read(buffer []byte) (int, error) {
	count, err := reader.reader.Read(buffer)
	return count, mapZSTDDecoderLimit(err)
}

func mapZSTDDecoderLimit(err error) error {
	if errors.Is(err, zstd.ErrWindowSizeExceeded) ||
		errors.Is(err, zstd.ErrDecoderSizeExceeded) {
		return &limitError{code: LimitMaxDecoderMemory}
	}
	return err
}

type contextAwareReader struct {
	ctx    context.Context
	reader io.Reader
}

func (reader contextAwareReader) Read(buffer []byte) (int, error) {
	if err := reader.ctx.Err(); err != nil {
		return 0, err
	}
	count, err := reader.reader.Read(buffer)
	if contextErr := reader.ctx.Err(); contextErr != nil {
		return count, contextErr
	}
	return count, err
}

package extract

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"os"

	lzmalib "github.com/ulikunitz/xz/lzma"
)

const (
	lzmaAloneHeaderLength    = int64(lzmalib.HeaderLen)
	lzmaDecoderOverheadBytes = int64(8 << 20)
)

var errInvalidLZMAStream = errors.New("invalid LZMA-Alone stream")

type lzmaPreflightInfo struct {
	DictionaryBytes    int64
	DecoderMemoryBytes int64
}

// lzmaSourceReader deliberately implements io.Reader but not io.ByteReader.
// ulikunitz/lzma therefore uses its unbuffered one-byte adapter after reading
// the fixed header, so consumed is the exact compressed-stream position rather
// than the position of a buffered read ahead.
type lzmaSourceReader struct {
	input    io.Reader
	consumed int64
}

func (reader *lzmaSourceReader) Read(buffer []byte) (int, error) {
	count, err := reader.input.Read(buffer)
	reader.consumed += int64(count)
	return count, err
}

// extractLZMA decodes the LZMA-Alone variant permitted for data.tar.lzma
// members. It is intentionally not exposed through content-only detection:
// LZMA-Alone has no magic bytes and is dispatched only by a validated DEB
// member name.
func (state *operationState) extractLZMA(
	source *os.File,
	sourceSize int64,
	parentID int,
	prefix string,
	parentDepth int,
	budget *containerBudget,
) error {
	info, err := preflightLZMA(state.ctx, source, sourceSize)
	if err != nil {
		return state.handleStreamInitializationError(
			err,
			parentID,
			prefix,
			parentDepth,
			"lzma_archive_corrupt",
		)
	}
	release, memoryLimit := state.memory.acquire(
		info.DecoderMemoryBytes,
		LimitMaxDecoderMemory,
	)
	if memoryLimit != nil {
		return state.handleStreamInitializationError(
			memoryLimit,
			parentID,
			prefix,
			parentDepth,
			"lzma_archive_corrupt",
		)
	}

	materialized, limit, materializeErr := func() (
		*materializedRegular,
		*limitError,
		error,
	) {
		defer release()
		compressed := &lzmaSourceReader{
			input: contextAwareReader{
				ctx: state.ctx,
				reader: io.NewSectionReader(
					source,
					0,
					sourceSize,
				),
			},
		}
		input, err := (lzmalib.ReaderConfig{
			DictCap: int(maxStreamDecoderMemoryBytes),
		}).NewReader(compressed)
		if err != nil {
			return nil, nil, state.handleStreamInitializationError(
				mapLZMAReaderError(err),
				parentID,
				prefix,
				parentDepth,
				"lzma_archive_corrupt",
			)
		}
		materialized, limit, materializeErr := state.materializeSingleStream(
			input,
			"lzma",
			"lzma_archive_corrupt",
			parentID,
			prefix,
			parentDepth,
			budget,
		)
		if materialized != nil &&
			limit == nil &&
			materializeErr == nil &&
			compressed.consumed != sourceSize {
			node := &state.nodes[materialized.nodeIndex]
			node.ExtractionStatus = StatusCorrupt
			node.ErrorCode = "lzma_archive_corrupt"
			node.ErrorMessage = fmt.Sprintf(
				"%s: compressed stream consumed %d of %d bytes",
				errInvalidLZMAStream,
				compressed.consumed,
				sourceSize,
			)
			state.partial = true
			materialized.close()
			materialized = nil
		}
		return materialized, limit, materializeErr
	}()
	return state.completeMaterializedStream(
		materialized,
		limit,
		materializeErr,
	)
}

func preflightLZMA(
	ctx context.Context,
	reader io.ReaderAt,
	size int64,
) (lzmaPreflightInfo, error) {
	if ctx == nil {
		return lzmaPreflightInfo{},
			errors.New("extract: nil LZMA preflight context")
	}
	if reader == nil || size < lzmaAloneHeaderLength {
		return lzmaPreflightInfo{}, errInvalidLZMAStream
	}
	if err := ctx.Err(); err != nil {
		return lzmaPreflightInfo{}, err
	}
	var header [lzmalib.HeaderLen]byte
	count, err := reader.ReadAt(header[:], 0)
	if count != len(header) {
		if err == nil {
			err = io.ErrUnexpectedEOF
		}
		return lzmaPreflightInfo{}, fmt.Errorf(
			"%w: read header: %v",
			errInvalidLZMAStream,
			err,
		)
	}
	if err != nil {
		return lzmaPreflightInfo{}, err
	}
	if err := ctx.Err(); err != nil {
		return lzmaPreflightInfo{}, err
	}
	if _, err := lzmalib.PropertiesForCode(header[0]); err != nil {
		return lzmaPreflightInfo{}, fmt.Errorf(
			"%w: invalid properties: %v",
			errInvalidLZMAStream,
			err,
		)
	}

	dictionaryBytes := int64(binary.LittleEndian.Uint32(header[1:5]))
	if dictionaryBytes > int64(maxStreamDecoderMemoryBytes) {
		return lzmaPreflightInfo{},
			&limitError{code: LimitMaxDecoderMemory}
	}
	if dictionaryBytes < int64(lzmalib.MinDictCap) {
		dictionaryBytes = int64(lzmalib.MinDictCap)
	}
	maxDictionaryBytes := int64(maxStreamDecoderMemoryBytes)
	if maxDictionaryBytes > math.MaxInt64-lzmaDecoderOverheadBytes ||
		maxDictionaryBytes+lzmaDecoderOverheadBytes >
			maxTaskParserDecoderMemoryBytes {
		return lzmaPreflightInfo{},
			&limitError{code: LimitMaxDecoderMemory}
	}
	decoderMemoryBytes := dictionaryBytes + lzmaDecoderOverheadBytes

	declaredSize := binary.LittleEndian.Uint64(header[5:13])
	if declaredSize != math.MaxUint64 && declaredSize > math.MaxInt64 {
		return lzmaPreflightInfo{}, fmt.Errorf(
			"%w: declared size exceeds int64",
			errInvalidLZMAStream,
		)
	}
	return lzmaPreflightInfo{
		DictionaryBytes:    dictionaryBytes,
		DecoderMemoryBytes: decoderMemoryBytes,
	}, nil
}

func mapLZMAReaderError(err error) error {
	var dictionaryError *lzmalib.ErrDictSize
	if errors.As(err, &dictionaryError) {
		return &limitError{code: LimitMaxDecoderMemory}
	}
	return err
}

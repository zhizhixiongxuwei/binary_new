package extract

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math"
)

const (
	maxTARMetadataBytes             = int64(4 << 20)
	maxTARStreamMetadataBytes       = int64(64 << 20)
	maxTARTrailingPaddingBytes      = int64(1 << 20)
	tarRecordSizeBytes              = int64(512)
	tarTrailingReadBufferBytes      = 32 << 10
	tarParserMemoryAmplification    = int64(8)
	tarParserFixedMemoryReservation = int64(1 << 20)
)

var errTARTrailingData = errors.New("tar archive has invalid trailing data")

// tarMetadataReader bounds raw input consumed while tar.Reader.Next parses a
// header. Four MiB per Next is deliberately tight: archive/tar already limits
// each PAX or GNU long-name record to 1 MiB, while this still permits several
// chained records and hundreds of thousands of legitimate sparse extents. The
// 64 MiB stream allowance also bounds repeated parser allocation and GC work.
type tarMetadataReader struct {
	ctx             context.Context
	input           io.Reader
	gated           bool
	remaining       int64
	streamRemaining int64
	consumed        int64
	totalConsumed   int64
}

func newTARMetadataReader(ctx context.Context, input io.Reader) *tarMetadataReader {
	return &tarMetadataReader{
		ctx:             ctx,
		input:           input,
		streamRemaining: maxTARStreamMetadataBytes,
	}
}

func (reader *tarMetadataReader) beginHeader() {
	reader.gated = true
	reader.remaining = maxTARMetadataBytes
	reader.consumed = 0
}

func (reader *tarMetadataReader) endHeader() int64 {
	consumed := reader.consumed
	reader.gated = false
	reader.remaining = 0
	reader.consumed = 0
	return consumed
}

func (reader *tarMetadataReader) Read(buffer []byte) (int, error) {
	if err := reader.ctx.Err(); err != nil {
		return 0, err
	}
	if len(buffer) == 0 {
		return 0, nil
	}
	if reader.gated {
		if reader.remaining <= 0 || reader.streamRemaining <= 0 {
			return 0, &limitError{code: LimitMaxArchiveMetadata}
		}
		if int64(len(buffer)) > reader.remaining {
			buffer = buffer[:reader.remaining]
		}
		if int64(len(buffer)) > reader.streamRemaining {
			buffer = buffer[:reader.streamRemaining]
		}
	}
	count, err := reader.input.Read(buffer)
	if int64(count) > math.MaxInt64-reader.totalConsumed {
		reader.totalConsumed = math.MaxInt64
	} else {
		reader.totalConsumed += int64(count)
	}
	if reader.gated {
		reader.remaining -= int64(count)
		reader.streamRemaining -= int64(count)
		reader.consumed += int64(count)
	}
	return count, err
}

func (reader *tarMetadataReader) totalBytesConsumed() int64 {
	return reader.totalConsumed
}

// validateTARTrailingPadding permits only bounded, complete zero records after
// archive/tar reaches its logical end marker. A second archive or opaque bytes
// must not disappear behind the first pair of zero records.
func validateTARTrailingPadding(
	ctx context.Context,
	source io.ReaderAt,
	sourceSize int64,
	consumed int64,
) error {
	if ctx == nil {
		return errors.New("extract: nil TAR trailing-data context")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if source == nil || sourceSize < 0 || consumed < 0 ||
		consumed > sourceSize {
		return fmt.Errorf(
			"%w: invalid source or consumed offset",
			errTARTrailingData,
		)
	}
	remaining := sourceSize - consumed
	if remaining == 0 {
		return nil
	}
	if remaining%tarRecordSizeBytes != 0 {
		return fmt.Errorf(
			"%w: trailing bytes are not aligned to a 512-byte record",
			errTARTrailingData,
		)
	}
	if remaining > maxTARTrailingPaddingBytes {
		return &limitError{code: LimitMaxArchiveMetadata}
	}

	var buffer [tarTrailingReadBufferBytes]byte
	offset := consumed
	for remaining > 0 {
		if err := ctx.Err(); err != nil {
			return err
		}
		length := int64(len(buffer))
		if length > remaining {
			length = remaining
		}
		count, readErr := source.ReadAt(buffer[:int(length)], offset)
		if count > 0 {
			for index, current := range buffer[:count] {
				if current != 0 {
					return fmt.Errorf(
						"%w: non-zero byte at offset %d",
						errTARTrailingData,
						offset+int64(index),
					)
				}
			}
			offset += int64(count)
			remaining -= int64(count)
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if count != int(length) {
			if readErr == nil {
				readErr = io.ErrUnexpectedEOF
			}
			return fmt.Errorf(
				"%w: read trailing padding: %v",
				errTARTrailingData,
				readErr,
			)
		}
		if readErr != nil && !errors.Is(readErr, io.EOF) {
			return fmt.Errorf(
				"%w: read trailing padding: %v",
				errTARTrailingData,
				readErr,
			)
		}
	}
	return ctx.Err()
}

// estimateTARParserMemory covers retained PAX maps and GNU sparse extents.
// The densest accepted 1.0 sparse map can expand each four MiB of raw
// metadata into two 16-byte extent slices; the factor of eight accounts for
// both slices and the fixed allowance covers maps, strings, and Reader state.
func estimateTARParserMemory(metadataBytes int64) int64 {
	if metadataBytes < 0 ||
		metadataBytes > (math.MaxInt64-tarParserFixedMemoryReservation)/
			tarParserMemoryAmplification {
		return math.MaxInt64
	}
	return tarParserFixedMemoryReservation +
		metadataBytes*tarParserMemoryAmplification
}

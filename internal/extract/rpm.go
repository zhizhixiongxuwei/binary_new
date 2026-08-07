package extract

import (
	"bufio"
	"bytes"
	"compress/bzip2"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"os"

	rpmformat "binaryscan/internal/rpm"

	"github.com/klauspost/compress/zstd"
	xzlib "github.com/ulikunitz/xz"
	lzmalib "github.com/ulikunitz/xz/lzma"
)

var (
	rpmStrippedCPIOMagic = []byte("07070X")

	errRPMPayloadVariantUnsupported = errors.New(
		"RPM stripped CPIO (07070X) payload is not supported",
	)
)

func (state *operationState) extractRPM(
	source *os.File,
	sourceSize int64,
	parentID int,
	prefix string,
	parentDepth int,
	budget *containerBudget,
) error {
	parsed, err := rpmformat.Parse(state.ctx, source, sourceSize)
	if err != nil {
		switch {
		case errors.Is(err, rpmformat.ErrMetadataLimit):
			limit := &limitError{code: LimitMaxArchiveMetadata}
			state.markLimit(limit.code)
			return limit
		case errors.Is(err, context.Canceled),
			errors.Is(err, context.DeadlineExceeded):
			return err
		default:
			return state.appendCorruptArchiveNode(
				parentID,
				prefix,
				parentDepth+1,
				"rpm_archive_corrupt",
				err,
			)
		}
	}

	metadata := rpmPayloadMetadata(parsed)
	if parsed.FormatVersion != 3 && parsed.FormatVersion != 4 {
		message := fmt.Sprintf(
			"RPM format version %d payload is not supported",
			parsed.FormatVersion,
		)
		if parsed.FormatVersion == 6 {
			message = "RPM format version 6 stripped CPIO (07070X) payload is not supported"
		}
		return state.appendRPMPayloadDiagnostic(
			parentID,
			prefix,
			parentDepth,
			metadata,
			StatusUnsupported,
			"rpm_payload_format_version_unsupported",
			message,
		)
	}
	if parsed.PayloadFormat == "" || parsed.PayloadCompressor == "" {
		return state.appendRPMPayloadDiagnostic(
			parentID,
			prefix,
			parentDepth,
			metadata,
			StatusCorrupt,
			"rpm_payload_metadata_invalid",
			"RPM payload format or compressor tag is missing",
		)
	}
	if parsed.PayloadFormat != "cpio" {
		return state.appendRPMPayloadDiagnostic(
			parentID,
			prefix,
			parentDepth,
			metadata,
			StatusUnsupported,
			"rpm_payload_format_unsupported",
			fmt.Sprintf(
				"RPM payload format %q is not supported",
				boundedText(parsed.PayloadFormat, 64),
			),
		)
	}

	expectedFormat, supported := rpmCompressedFormat(
		parsed.PayloadCompressor,
	)
	if !supported {
		return state.appendRPMPayloadDiagnostic(
			parentID,
			prefix,
			parentDepth,
			metadata,
			StatusUnsupported,
			"rpm_payload_compressor_unsupported",
			fmt.Sprintf(
				"RPM payload compressor %q is not supported",
				boundedText(parsed.PayloadCompressor, 64),
			),
		)
	}
	if parsed.PayloadCompressor == "none" {
		stripped, probeErr := probeRawRPMStrippedCPIO(
			state.ctx,
			source,
			parsed,
		)
		if probeErr != nil {
			return probeErr
		}
		if stripped {
			return state.appendRPMPayloadDiagnostic(
				parentID,
				prefix,
				parentDepth,
				metadata,
				StatusUnsupported,
				"rpm_payload_variant_unsupported",
				"RPM stripped CPIO (07070X) payload is not supported",
			)
		}
	}

	payload := io.NewSectionReader(
		source,
		parsed.PayloadOffset,
		parsed.PayloadBytes,
	)
	detected, err := detectContent(
		state.ctx,
		state.engine.detector,
		payload,
		parsed.PayloadBytes,
	)
	if err != nil {
		return fmt.Errorf("extract: detect RPM payload: %w", err)
	}
	metadata["detected_payload_format"] = detected.Format
	if detected.Format != expectedFormat {
		return state.appendRPMPayloadDiagnostic(
			parentID,
			prefix,
			parentDepth,
			metadata,
			StatusCorrupt,
			"rpm_payload_compressor_mismatch",
			fmt.Sprintf(
				"RPM payload content is %q, expected %q",
				detected.Format,
				expectedFormat,
			),
		)
	}

	location, prepared, pathErr := state.prepareEntry(
		prefix,
		"payload",
		false,
		parentID,
		parentDepth,
	)
	if pathErr != nil {
		return pathErr
	}
	if !prepared {
		return nil
	}
	node := Node{
		ParentLocalID: location.parentID,
		LogicalPath:   location.logical,
		DisplayName:   location.display,
		NodeType:      NodeTypeFile,
		Depth:         location.depth,
	}
	state.applyNamespaceCollision(location, &node, metadata)
	nodeLocalID := state.nextID

	materialized, limit, materializeErr := func() (
		*materializedRegular,
		*limitError,
		error,
	) {
		input, closeInput, openErr := state.openRPMPayload(
			source,
			parsed,
		)
		if openErr != nil {
			return nil, nil, openErr
		}
		defer closeInput()
		buffered := bufio.NewReaderSize(
			input,
			len(rpmStrippedCPIOMagic),
		)
		prefix, probeErr := buffered.Peek(len(rpmStrippedCPIOMagic))
		if probeErr == nil &&
			bytes.Equal(prefix, rpmStrippedCPIOMagic) {
			return nil, nil, errRPMPayloadVariantUnsupported
		}
		return state.materializeRegular(
			buffered,
			node,
			metadata,
			budget,
		)
	}()
	if materialized == nil {
		if extracted := state.nodeByLocalID(nodeLocalID); extracted != nil &&
			extracted.ErrorCode == "archive_entry_corrupt" {
			extracted.ErrorCode = "rpm_payload_corrupt"
		}
		if materializeErr != nil {
			var decoderLimit *limitError
			switch {
			case errors.Is(
				materializeErr,
				errRPMPayloadVariantUnsupported,
			):
				return state.appendRPMPayloadDiagnostic(
					parentID,
					prefix,
					parentDepth,
					metadata,
					StatusUnsupported,
					"rpm_payload_variant_unsupported",
					materializeErr.Error(),
				)
			case errors.As(materializeErr, &decoderLimit):
				state.markLimit(decoderLimit.code)
				if decoderLimit.global {
					state.stopped = true
				}
				return decoderLimit
			case errors.Is(materializeErr, context.Canceled),
				errors.Is(materializeErr, context.DeadlineExceeded):
				return materializeErr
			default:
				return state.appendRPMPayloadDiagnostic(
					parentID,
					prefix,
					parentDepth,
					metadata,
					StatusCorrupt,
					"rpm_payload_corrupt",
					materializeErr.Error(),
				)
			}
		}
		if limit != nil {
			return limit
		}
		return nil
	}
	defer materialized.close()
	if materializeErr != nil {
		return materializeErr
	}
	if limit != nil {
		return limit
	}

	extracted := state.nodeByLocalID(nodeLocalID)
	if extracted == nil {
		return errors.New("extract: RPM payload node disappeared")
	}
	if extracted.Format != "cpio" {
		if extracted.ErrorCode == "" {
			extracted.ExtractionStatus = StatusCorrupt
			extracted.ErrorCode = "rpm_payload_format_mismatch"
			extracted.ErrorMessage = fmt.Sprintf(
				"decoded RPM payload is %q, expected CPIO",
				extracted.Format,
			)
		}
		state.partial = true
		return nil
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

func probeRawRPMStrippedCPIO(
	ctx context.Context,
	source io.ReaderAt,
	parsed rpmformat.Package,
) (bool, error) {
	if parsed.PayloadBytes < int64(len(rpmStrippedCPIOMagic)) {
		return false, nil
	}
	if err := ctx.Err(); err != nil {
		return false, err
	}
	var prefix [6]byte
	count, err := source.ReadAt(prefix[:], parsed.PayloadOffset)
	if count != len(prefix) {
		if err != nil && !errors.Is(err, io.EOF) {
			return false, fmt.Errorf(
				"extract: probe RPM payload: %w",
				err,
			)
		}
		return false, nil
	}
	if err != nil && !errors.Is(err, io.EOF) {
		return false, fmt.Errorf("extract: probe RPM payload: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return false, err
	}
	return bytes.Equal(prefix[:], rpmStrippedCPIOMagic), nil
}

func rpmPayloadMetadata(parsed rpmformat.Package) map[string]any {
	metadata := map[string]any{
		"archive":                 "rpm",
		"compressed_bytes":        parsed.PayloadBytes,
		"header_bytes":            parsed.MainHeader.TotalBytes,
		"header_entries":          parsed.MainHeader.IndexCount,
		"major_version":           parsed.MajorVersion,
		"minor_version":           parsed.MinorVersion,
		"package_type":            parsed.PackageType,
		"payload_compressor":      parsed.PayloadCompressor,
		"payload_format":          parsed.PayloadFormat,
		"payload_offset":          parsed.PayloadOffset,
		"rpm_format_version":      parsed.FormatVersion,
		"signature_bytes":         parsed.Signature.TotalBytes,
		"signature_entries":       parsed.Signature.IndexCount,
		"wrapper_architecture":    parsed.Architecture,
		"wrapper_architecture_id": parsed.ArchitectureCode,
		"lead_fields_trusted":     false,
	}
	if parsed.PayloadFlags != "" {
		metadata["payload_flags"] = parsed.PayloadFlags
	}
	return metadata
}

func rpmCompressedFormat(compressor string) (string, bool) {
	switch compressor {
	case "none":
		return "cpio", true
	case "gzip", "bzip2", "xz", "zstd":
		return compressor, true
	case "lzma":
		// LZMA-Alone has no reliable magic. It is only dispatched because
		// the strictly parsed RPM header declares it, and its decoded bytes
		// are still required to pass content-only CPIO detection.
		return "unknown", true
	default:
		return "", false
	}
}

func (state *operationState) openRPMPayload(
	source *os.File,
	parsed rpmformat.Package,
) (io.Reader, func(), error) {
	section := io.NewSectionReader(
		source,
		parsed.PayloadOffset,
		parsed.PayloadBytes,
	)
	switch parsed.PayloadCompressor {
	case "none":
		return contextAwareReader{
			ctx:    state.ctx,
			reader: section,
		}, func() {}, nil
	case "gzip":
		release, limit := state.memory.acquire(
			gzipDecoderMemoryReservation,
			LimitMaxDecoderMemory,
		)
		if limit != nil {
			return nil, func() {}, limit
		}
		decoder, err := gzip.NewReader(contextAwareReader{
			ctx:    state.ctx,
			reader: section,
		})
		if err != nil {
			release()
			return nil, func() {}, err
		}
		return decoder, func() {
			_ = decoder.Close()
			release()
		}, nil
	case "bzip2":
		release, limit := state.memory.acquire(
			bzip2DecoderMemoryReservation,
			LimitMaxDecoderMemory,
		)
		if limit != nil {
			return nil, func() {}, limit
		}
		return bzip2.NewReader(contextAwareReader{
			ctx:    state.ctx,
			reader: section,
		}), release, nil
	case "xz":
		info, err := preflightXZ(
			state.ctx,
			section,
			parsed.PayloadBytes,
		)
		if err != nil {
			return nil, func() {}, err
		}
		release, limit := state.memory.acquire(
			info.MaxDictionaryBytes,
			LimitMaxDecoderMemory,
		)
		if limit != nil {
			return nil, func() {}, limit
		}
		decoder, err := (xzlib.ReaderConfig{
			DictCap:      0,
			SingleStream: true,
		}).NewReader(contextAwareReader{
			ctx:    state.ctx,
			reader: section,
		})
		if err != nil {
			release()
			return nil, func() {}, err
		}
		return decoder, release, nil
	case "zstd":
		release, limit := state.memory.acquire(
			int64(maxStreamDecoderMemoryBytes),
			LimitMaxDecoderMemory,
		)
		if limit != nil {
			return nil, func() {}, limit
		}
		decoder, err := zstd.NewReader(
			contextAwareReader{
				ctx:    state.ctx,
				reader: section,
			},
			zstd.WithDecoderConcurrency(1),
			zstd.WithDecoderLowmem(true),
			zstd.WithDecoderMaxMemory(maxStreamDecoderMemoryBytes),
			zstd.WithDecoderMaxWindow(maxStreamDecoderMemoryBytes),
			zstd.WithDecodeBuffersBelow(0),
		)
		if err != nil {
			release()
			return nil, func() {}, mapZSTDDecoderLimit(err)
		}
		return zstdLimitReader{reader: decoder}, func() {
			decoder.Close()
			release()
		}, nil
	case "lzma":
		info, err := preflightLZMA(
			state.ctx,
			section,
			parsed.PayloadBytes,
		)
		if err != nil {
			return nil, func() {}, err
		}
		release, limit := state.memory.acquire(
			info.DecoderMemoryBytes,
			LimitMaxDecoderMemory,
		)
		if limit != nil {
			return nil, func() {}, limit
		}
		compressed := &lzmaSourceReader{
			input: contextAwareReader{
				ctx: state.ctx,
				reader: io.NewSectionReader(
					source,
					parsed.PayloadOffset,
					parsed.PayloadBytes,
				),
			},
		}
		decoder, err := (lzmalib.ReaderConfig{
			DictCap: int(maxStreamDecoderMemoryBytes),
		}).NewReader(compressed)
		if err != nil {
			release()
			return nil, func() {}, mapLZMAReaderError(err)
		}
		return &rpmLZMAReader{
			reader:     decoder,
			compressed: compressed,
			sourceSize: parsed.PayloadBytes,
		}, release, nil
	default:
		return nil, func() {}, fmt.Errorf(
			"unsupported RPM payload compressor %q",
			parsed.PayloadCompressor,
		)
	}
}

// rpmLZMAReader prevents a valid LZMA stream with attacker-controlled trailing
// bytes from being accepted as the complete RPM payload.
type rpmLZMAReader struct {
	reader       io.Reader
	compressed   *lzmaSourceReader
	sourceSize   int64
	pendingError error
}

func (reader *rpmLZMAReader) Read(buffer []byte) (int, error) {
	if reader.pendingError != nil {
		err := reader.pendingError
		reader.pendingError = nil
		return 0, err
	}
	count, err := reader.reader.Read(buffer)
	if !errors.Is(err, io.EOF) ||
		reader.compressed.consumed == reader.sourceSize {
		return count, err
	}
	trailingErr := fmt.Errorf(
		"%w: compressed stream consumed %d of %d bytes",
		errInvalidLZMAStream,
		reader.compressed.consumed,
		reader.sourceSize,
	)
	if count > 0 {
		reader.pendingError = trailingErr
		return count, nil
	}
	return 0, trailingErr
}

func (state *operationState) appendRPMPayloadDiagnostic(
	parentID int,
	prefix string,
	parentDepth int,
	metadata map[string]any,
	status string,
	code string,
	message string,
) error {
	location, prepared, err := state.prepareEntry(
		prefix,
		"payload",
		false,
		parentID,
		parentDepth,
	)
	if err != nil {
		return err
	}
	if !prepared {
		return nil
	}
	node := Node{
		ParentLocalID:    location.parentID,
		LogicalPath:      location.logical,
		DisplayName:      location.display,
		NodeType:         NodeTypeSpecial,
		Depth:            location.depth,
		ExtractionStatus: status,
		ErrorCode:        code,
		ErrorMessage:     message,
	}
	state.applyNamespaceCollision(location, &node, metadata)
	node.MetadataJSON = metadataJSON(metadata)
	_, err = state.appendNode(node)
	state.partial = true
	return err
}

package extract

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"time"

	"github.com/nwaples/rardecode/v2"
)

const (
	// rardecode can retain a decode window, a same-sized filter input, and a
	// filter result with twice that capacity. Hold one conservative reservation
	// for the sequential RAR5 walk. Legacy RAR compression is rejected by the
	// preflight until it can run in an isolated decoder process.
	rarParserDecoderMemoryReservation = int64(320 << 20)
	rarMaxDictionarySize              = int64(64 << 20)
	rarSignatureScanBytes             = int64((1 << 20) + 8)
	rarSignatureBufferBytes           = 32 << 10
)

var (
	rar4Signature = []byte("Rar!\x1a\x07\x00")
	rar5Signature = []byte("Rar!\x1a\x07\x01\x00")

	errRARDecoderPanic = errors.New(
		"RAR decoder rejected malformed input",
	)
)

type rarErrorDisposition struct {
	status    string
	code      string
	message   string
	limitCode string
}

type trackedRARReader struct {
	reader io.Reader
	err    error
}

func (reader *trackedRARReader) Read(
	buffer []byte,
) (count int, err error) {
	defer func() {
		if recover() == nil {
			return
		}
		count = 0
		err = errRARDecoderPanic
		if reader.err == nil {
			reader.err = err
		}
	}()
	count, err = reader.reader.Read(buffer)
	if err != nil && !errors.Is(err, io.EOF) && reader.err == nil {
		reader.err = err
	}
	return count, err
}

func newRARReaderSafely(input io.Reader) (
	archive *rardecode.Reader,
	err error,
) {
	defer func() {
		if recover() != nil {
			archive = nil
			err = errRARDecoderPanic
		}
	}()
	return rardecode.NewReader(
		input,
		rardecode.MaxDictionarySize(rarMaxDictionarySize),
	)
}

func nextRARHeaderSafely(
	archive *rardecode.Reader,
) (header *rardecode.FileHeader, err error) {
	defer func() {
		if recover() != nil {
			header = nil
			err = errRARDecoderPanic
		}
	}()
	return archive.Next()
}

func (state *operationState) extractRAR(
	source *os.File,
	sourceSize int64,
	parentID int,
	prefix string,
	parentDepth int,
	budget *containerBudget,
) error {
	releaseRARMemory, memoryLimit := state.memory.acquire(
		rarParserDecoderMemoryReservation,
		LimitMaxDecoderMemory,
	)
	if memoryLimit != nil {
		state.markLimit(memoryLimit.code)
		return memoryLimit
	}
	defer releaseRARMemory()

	version, signatureOffset, err := locateRARSignature(
		state.ctx,
		source,
		sourceSize,
	)
	if err != nil {
		releaseRARMemory()
		return state.handleRARArchiveError(
			err,
			parentID,
			prefix,
			parentDepth,
		)
	}
	if err := preflightRARMetadata(
		state.ctx,
		source,
		sourceSize,
		version,
		signatureOffset,
	); err != nil {
		releaseRARMemory()
		return state.handleRARArchiveError(
			err,
			parentID,
			prefix,
			parentDepth,
		)
	}

	var materialized []*materializedRegular
	defer func() {
		for _, current := range materialized {
			if current != nil {
				current.close()
			}
		}
	}()

	archive, err := newRARReaderSafely(
		contextAwareReader{
			ctx:    state.ctx,
			reader: io.NewSectionReader(source, 0, sourceSize),
		},
	)
	if err != nil {
		releaseRARMemory()
		return state.handleRARArchiveError(
			err,
			parentID,
			prefix,
			parentDepth,
		)
	}

	walkErr := state.walkRAR(
		archive,
		version,
		parentID,
		prefix,
		parentDepth,
		budget,
		&materialized,
	)
	// NewReader has no Close method. Dropping the only reader reference after
	// the sequential walk makes its decoder state collectible. The accounting
	// reservation is released before any nested parser is entered.
	archive = nil
	releaseRARMemory()
	if walkErr != nil {
		var limit *limitError
		if !errors.As(walkErr, &limit) {
			return walkErr
		}
	}

	for index, current := range materialized {
		reopened, err := os.Open(current.path)
		if err != nil {
			return fmt.Errorf(
				"extract: reopen materialized RAR entry: %w",
				err,
			)
		}
		current.file = reopened
		materialized[index] = nil
		if err := state.completeMaterializedStream(
			current,
			nil,
			nil,
		); err != nil {
			return err
		}
	}
	return walkErr
}

func (state *operationState) walkRAR(
	archive *rardecode.Reader,
	version int,
	parentID int,
	prefix string,
	parentDepth int,
	budget *containerBudget,
	materialized *[]*materializedRegular,
) error {
	maxEntries := state.engine.limits.MaxNodes - len(state.nodes)
	if maxEntries < 0 {
		maxEntries = 0
	}
	entriesSeen := 0

	for {
		if err := state.ctx.Err(); err != nil {
			return err
		}
		if state.stopped {
			return &limitError{code: state.limitCode, global: true}
		}

		header, err := nextRARHeaderSafely(archive)
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return state.handleRARArchiveError(
				err,
				parentID,
				prefix,
				parentDepth,
			)
		}
		if entriesSeen >= maxEntries {
			limit := &limitError{
				code:   LimitMaxNodes,
				global: true,
			}
			state.markLimit(limit.code)
			state.stopped = true
			return limit
		}
		entriesSeen++

		isDirectory := header.IsDir
		declaredOversized := !header.UnKnownSize &&
			header.UnPackedSize > state.engine.limits.MaxEntryBytes
		location, prepared, pathErr := state.prepareEntry(
			prefix,
			header.Name,
			isDirectory,
			parentID,
			parentDepth,
		)
		if pathErr != nil {
			// A data-bearing unsafe entry still receives a logical quarantine
			// node so its bytes can be detected and recursively inspected.
			// Draining alone would let an attacker hide a nested archive behind
			// a path parser edge case.
			location, prepared, pathErr =
				state.prepareInvalidArchivePathEntry(
					prefix,
					header.Name,
					"unsafe_archive_path",
					isDirectory,
					parentID,
				)
			if pathErr != nil {
				return pathErr
			}
			if !prepared {
				return nil
			}
		}
		if !prepared && declaredOversized {
			location, prepared, pathErr =
				state.prepareInvalidArchivePathEntry(
					prefix,
					header.Name,
					"declared_entry_limit",
					isDirectory,
					parentID,
				)
			if pathErr != nil {
				return pathErr
			}
		}
		if !prepared {
			if header.Encrypted {
				return state.handleRARArchiveError(
					rardecode.ErrArchivedFileEncrypted,
					parentID,
					prefix,
					parentDepth,
				)
			}
			tracked := &trackedRARReader{reader: archive}
			_, limit, drainErr := state.drainRAREntry(tracked, budget)
			if limit != nil {
				return limit
			}
			if drainErr != nil {
				return state.handleRARArchiveError(
					drainErr,
					parentID,
					prefix,
					parentDepth,
				)
			}
			continue
		}

		metadata := rarEntryMetadata(header, version)
		node := Node{
			ParentLocalID: location.parentID,
			LogicalPath:   location.logical,
			DisplayName:   location.display,
			Depth:         location.depth,
			SizeBytes:     safeSignedSize(header.UnPackedSize),
			MetadataJSON:  metadataJSON(metadata),
		}

		mode := header.Mode()
		if declaredOversized {
			switch {
			case isDirectory:
				if location.directoryNode < 0 {
					return nil
				}
				directory := &state.nodes[location.directoryNode]
				directoryMetadata := rarEntryMetadata(header, version)
				directoryMetadata["synthetic"] = false
				state.applyNamespaceCollision(
					location,
					directory,
					directoryMetadata,
				)
				directory.MetadataJSON = metadataJSON(directoryMetadata)
				limit := state.limitDeclaredRARExisting(
					location.directoryNode,
					header.UnPackedSize,
					budget,
				)
				if limit != nil {
					return limit
				}
				return nil
			case mode&fs.ModeSymlink != 0:
				node.NodeType = NodeTypeSymlink
				metadata["content_materialized"] = false
			case rarEntryIsSpecial(header, mode):
				node.NodeType = NodeTypeSpecial
				metadata["content_materialized"] = false
			default:
				node.NodeType = NodeTypeFile
			}
			node.MetadataJSON = metadataJSON(metadata)
			state.applyNamespaceCollision(location, &node, metadata)
			limit, limitErr := state.limitDeclaredRegular(
				node,
				metadata,
				header.UnPackedSize,
				budget,
			)
			if limitErr != nil {
				return limitErr
			}
			if limit != nil {
				return limit
			}
			return nil
		}

		switch {
		case isDirectory:
			if location.directoryNode >= 0 {
				directory := &state.nodes[location.directoryNode]
				directoryMetadata := rarEntryMetadata(header, version)
				directoryMetadata["synthetic"] = false
				state.applyNamespaceCollision(
					location,
					directory,
					directoryMetadata,
				)
				directory.MetadataJSON = metadataJSON(directoryMetadata)
				if header.Encrypted {
					applyRAREncryptedNode(directory)
					state.partial = true
					return nil
				}
				tracked := &trackedRARReader{reader: archive}
				consumed, limit, drainErr :=
					state.drainRAREntry(tracked, budget)
				directory.SizeBytes = consumed
				if limit != nil {
					state.applyRAREntryError(directory.LocalID, limit)
					return limit
				}
				if drainErr != nil {
					return state.applyRAREntryError(
						directory.LocalID,
						drainErr,
					)
				}
			}

		case mode&fs.ModeSymlink != 0:
			node.NodeType = NodeTypeSymlink
			node.ExtractionStatus = StatusRecorded
			metadata["content_materialized"] = false
			node.MetadataJSON = metadataJSON(metadata)
			state.applyNamespaceCollision(location, &node, metadata)
			nodeLocalID := state.nextID
			if header.Encrypted {
				applyRAREncryptedNode(&node)
				if _, err := state.appendNode(node); err != nil {
					return err
				}
				state.partial = true
				return nil
			}
			if _, err := state.appendNode(node); err != nil {
				return err
			}
			tracked := &trackedRARReader{reader: archive}
			consumed, limit, drainErr :=
				state.drainRAREntry(tracked, budget)
			if extracted := state.nodeByLocalID(nodeLocalID); extracted != nil {
				extracted.SizeBytes = consumed
			}
			if limit != nil {
				state.applyRAREntryError(nodeLocalID, limit)
				return limit
			}
			if drainErr != nil {
				return state.applyRAREntryError(nodeLocalID, drainErr)
			}

		case rarEntryIsSpecial(header, mode):
			node.NodeType = NodeTypeSpecial
			node.ExtractionStatus = StatusRecorded
			metadata["content_materialized"] = false
			node.MetadataJSON = metadataJSON(metadata)
			state.applyNamespaceCollision(location, &node, metadata)
			nodeLocalID := state.nextID
			if header.Encrypted {
				applyRAREncryptedNode(&node)
				if _, err := state.appendNode(node); err != nil {
					return err
				}
				state.partial = true
				return nil
			}
			if _, err := state.appendNode(node); err != nil {
				return err
			}
			tracked := &trackedRARReader{reader: archive}
			consumed, limit, drainErr :=
				state.drainRAREntry(tracked, budget)
			if extracted := state.nodeByLocalID(nodeLocalID); extracted != nil {
				extracted.SizeBytes = consumed
			}
			if limit != nil {
				state.applyRAREntryError(nodeLocalID, limit)
				return limit
			}
			if drainErr != nil {
				return state.applyRAREntryError(nodeLocalID, drainErr)
			}

		default:
			node.NodeType = NodeTypeFile
			state.applyNamespaceCollision(location, &node, metadata)
			if header.Encrypted {
				applyRAREncryptedNode(&node)
				if _, err := state.appendNode(node); err != nil {
					return err
				}
				state.partial = true
				return nil
			}

			nodeLocalID := state.nextID
			tracked := &trackedRARReader{reader: archive}
			current, limit, extractErr := state.materializeRegular(
				tracked,
				node,
				metadata,
				budget,
			)
			if extractErr != nil {
				if current != nil {
					current.close()
				}
				return extractErr
			}
			if limit != nil {
				if current != nil {
					current.close()
				}
				return limit
			}
			if current == nil {
				extracted := state.nodeByLocalID(nodeLocalID)
				if extracted != nil &&
					extracted.ExtractionStatus == StatusLimitExceeded {
					// A per-entry streaming limit is already the most useful
					// diagnosis even if the same final Read also reported a
					// checksum error.
					return nil
				}
			}
			if tracked.err != nil {
				if current != nil {
					current.close()
				}
				return state.applyRAREntryError(
					nodeLocalID,
					tracked.err,
				)
			}
			if current != nil {
				if closeErr := current.file.Close(); closeErr != nil {
					current.close()
					if current.nodeIndex >= 0 &&
						current.nodeIndex < len(state.nodes) {
						extracted := &state.nodes[current.nodeIndex]
						extracted.ExtractionStatus = StatusCorrupt
						extracted.ErrorCode = "rar_work_file_close_failed"
						extracted.ErrorMessage = closeErr.Error()
						extracted.SHA256 = ""
					}
					state.partial = true
					return nil
				}
				*materialized = append(*materialized, current)
				continue
			}
			// materializeRegular records a stalled/corrupt stream in-place and
			// returns no file. Do not call Next: a solid decoder could otherwise
			// expand and discard the unconsumed suffix outside the byte budget.
			return nil
		}
	}
}

// limitDeclaredRARExisting is the already-appended directory counterpart of
// limitDeclaredRegular. It deliberately uses the same reservation ordering:
// global or ratio exhaustion wins when it is reached at or before the
// per-entry boundary.
func (state *operationState) limitDeclaredRARExisting(
	index int,
	declaredSize int64,
	container *containerBudget,
) *limitError {
	node := &state.nodes[index]
	node.SizeBytes = 0
	node.SHA256 = ""
	node.ExtractionStatus = StatusLimitExceeded
	node.ErrorCode = LimitMaxEntryBytes
	node.ErrorMessage = "entry exceeds the configured per-entry size limit"

	requested := state.engine.limits.MaxEntryBytes
	if state.reservationCapacity(container) <= requested {
		requested = declaredSize
	}
	allowed, limit := state.reserve(requested, container)
	node.SizeBytes = allowed
	if limit != nil {
		node.ErrorCode = limit.code
		node.ErrorMessage = "entry extraction stopped at configured limit"
		return limit
	}
	state.markLimit(LimitMaxEntryBytes)
	return nil
}

func detectRARVersion(
	ctx context.Context,
	source io.ReaderAt,
	sourceSize int64,
) (int, error) {
	version, _, err := locateRARSignature(ctx, source, sourceSize)
	return version, err
}

func locateRARSignature(
	ctx context.Context,
	source io.ReaderAt,
	sourceSize int64,
) (int, int64, error) {
	if sourceSize <= 0 {
		return 0, 0, rardecode.ErrNoSig
	}
	scanSize := sourceSize
	if scanSize > rarSignatureScanBytes {
		scanSize = rarSignatureScanBytes
	}
	reader := bufio.NewReaderSize(
		io.NewSectionReader(source, 0, scanSize),
		rarSignatureBufferBytes,
	)
	window := make([]byte, 0, len(rar5Signature))
	var position int64
	for {
		if err := ctx.Err(); err != nil {
			return 0, 0, err
		}
		current, err := reader.ReadByte()
		if err != nil {
			if errors.Is(err, io.EOF) {
				return 0, 0, rardecode.ErrNoSig
			}
			return 0, 0, err
		}
		position++
		if len(window) == cap(window) {
			copy(window, window[1:])
			window = window[:len(window)-1]
		}
		window = append(window, current)
		if len(window) >= len(rar5Signature) &&
			bytes.Equal(window[len(window)-len(rar5Signature):], rar5Signature) {
			return 5, position - int64(len(rar5Signature)), nil
		}
		if len(window) >= len(rar4Signature) &&
			bytes.Equal(window[len(window)-len(rar4Signature):], rar4Signature) {
			return 4, position - int64(len(rar4Signature)), nil
		}
	}
}

func rarEntryMetadata(
	header *rardecode.FileHeader,
	version int,
) map[string]any {
	metadata := map[string]any{
		"archive":             "rar",
		"rar_version":         version,
		"packed_bytes":        header.PackedSize,
		"declared_bytes":      header.UnPackedSize,
		"declared_size_known": !header.UnKnownSize,
		"solid":               header.Solid,
		"encrypted":           header.Encrypted,
		"header_encrypted":    header.HeaderEncrypted,
		"host_os":             header.HostOS,
		"attributes":          header.Attributes,
		"mode":                uint32(header.Mode()),
	}
	addRARTimeMetadata(metadata, "modified_at", header.ModificationTime)
	addRARTimeMetadata(metadata, "created_at", header.CreationTime)
	addRARTimeMetadata(metadata, "accessed_at", header.AccessTime)
	if header.Version != 0 {
		metadata["file_version"] = header.Version
	}
	return metadata
}

func addRARTimeMetadata(
	metadata map[string]any,
	key string,
	value time.Time,
) {
	if !value.IsZero() {
		metadata[key] = value.UTC().Format(time.RFC3339Nano)
	}
}

func rarEntryIsSpecial(
	header *rardecode.FileHeader,
	mode fs.FileMode,
) bool {
	if header.HostOS != rardecode.HostOSUnix {
		return !mode.IsRegular()
	}
	const unixTypeMask = int64(0170000)
	const unixRegular = int64(0100000)
	fileType := header.Attributes & unixTypeMask
	return fileType != 0 && fileType != unixRegular
}

func applyRAREncryptedNode(node *Node) {
	node.ExtractionStatus = StatusPasswordRequired
	node.ErrorCode = "password_required"
	node.ErrorMessage = "encrypted RAR entry requires a password"
}

func (state *operationState) drainRAREntry(
	input io.Reader,
	budget *containerBudget,
) (int64, *limitError, error) {
	buffer := make([]byte, streamBufferSize)
	var consumed int64
	for {
		if err := state.ctx.Err(); err != nil {
			return consumed, nil, err
		}
		count, readErr := input.Read(buffer)
		if count > 0 {
			requested := int64(count)
			entryRemaining := state.engine.limits.MaxEntryBytes - consumed
			if entryRemaining < 0 {
				entryRemaining = 0
			}
			entryExceeded := requested > entryRemaining
			if entryExceeded &&
				state.reservationCapacity(budget) > entryRemaining {
				requested = entryRemaining
			}
			allowed, limit := state.reserve(requested, budget)
			consumed += allowed
			if limit != nil {
				return consumed, limit, nil
			}
			if entryExceeded {
				state.markLimit(LimitMaxEntryBytes)
				return consumed, &limitError{
					code: LimitMaxEntryBytes,
				}, nil
			}
		}
		if readErr != nil {
			if errors.Is(readErr, io.EOF) {
				return consumed, nil, nil
			}
			return consumed, nil, readErr
		}
		if count == 0 {
			return consumed, nil, io.ErrNoProgress
		}
	}
}

func classifyRARError(err error) rarErrorDisposition {
	var limit *limitError
	switch {
	case errors.As(err, &limit):
		return rarErrorDisposition{
			status:    StatusLimitExceeded,
			code:      limit.code,
			message:   "RAR extraction stopped at the configured limit",
			limitCode: limit.code,
		}
	case errors.Is(err, rardecode.ErrArchiveEncrypted),
		errors.Is(err, rardecode.ErrArchivedFileEncrypted),
		errors.Is(err, rardecode.ErrBadPassword):
		return rarErrorDisposition{
			status:  StatusPasswordRequired,
			code:    "password_required",
			message: "encrypted RAR content requires a password",
		}
	case errors.Is(err, errRARMultiVolumeUnsupported),
		errors.Is(err, rardecode.ErrMultiVolume),
		errors.Is(err, rardecode.ErrFileNameRequired):
		return rarErrorDisposition{
			status:  StatusUnsupported,
			code:    "multi_volume_unsupported",
			message: "multi-volume RAR archives are not supported",
		}
	case errors.Is(err, errRARLegacyCompressionUnsupported):
		return rarErrorDisposition{
			status: StatusUnsupported,
			code:   "rar_legacy_compression_unsupported",
			message: "compressed legacy RAR entries require an isolated " +
				"decoder and are not supported",
		}
	case errors.Is(err, rardecode.ErrDictionaryTooLarge):
		return rarErrorDisposition{
			status:    StatusLimitExceeded,
			code:      LimitMaxDecoderMemory,
			message:   "RAR decode dictionary exceeds the 64 MiB limit",
			limitCode: LimitMaxDecoderMemory,
		}
	default:
		code := "rar_archive_corrupt"
		if errors.Is(err, rardecode.ErrBadFileChecksum) {
			code = "rar_entry_checksum_mismatch"
		}
		return rarErrorDisposition{
			status:  StatusCorrupt,
			code:    code,
			message: boundedText(err.Error(), 2048),
		}
	}
}

func (state *operationState) applyRAREntryError(
	localID int,
	err error,
) error {
	if errors.Is(err, context.Canceled) ||
		errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	disposition := classifyRARError(err)
	node := state.nodeByLocalID(localID)
	if node == nil {
		return fmt.Errorf("extract: RAR entry node %d is missing", localID)
	}
	node.ExtractionStatus = disposition.status
	node.ErrorCode = disposition.code
	node.ErrorMessage = disposition.message
	if disposition.status == StatusCorrupt {
		node.SHA256 = ""
	}
	state.partial = true
	if disposition.limitCode != "" {
		limit := &limitError{code: disposition.limitCode}
		state.markLimit(limit.code)
		return limit
	}
	// Stop this archive after a local decoder/checksum error. Previously
	// materialized siblings are retained and inspected after decoder release.
	return nil
}

func (state *operationState) handleRARArchiveError(
	err error,
	parentID int,
	prefix string,
	parentDepth int,
) error {
	if errors.Is(err, context.Canceled) ||
		errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	disposition := classifyRARError(err)
	if appendErr := state.appendRARDiagnosticNode(
		parentID,
		prefix,
		parentDepth,
		disposition,
	); appendErr != nil {
		return appendErr
	}
	if disposition.limitCode != "" {
		limit := &limitError{code: disposition.limitCode}
		state.markLimit(limit.code)
		return limit
	}
	return nil
}

func (state *operationState) appendRARDiagnosticNode(
	parentID int,
	prefix string,
	_ int,
	disposition rarErrorDisposition,
) error {
	location, err := state.uniqueQuarantineLocation(
		parentID,
		"corrupt",
	)
	if err != nil {
		return err
	}
	state.reserveLogicalPath(location.logical)
	metadata := map[string]any{
		"archive":   "rar",
		"synthetic": true,
	}
	if prefix != "" {
		metadata["archive_container_path"] = prefix
	}
	_, err = state.appendNode(Node{
		ParentLocalID:          location.parentID,
		SourceContainerLocalID: parentID,
		LogicalPath:            location.logical,
		DisplayName:            "rar-diagnostic",
		NodeType:               NodeTypeSpecial,
		Depth:                  location.depth,
		ExtractionStatus:       disposition.status,
		MetadataJSON:           metadataJSON(metadata),
		ErrorCode:              disposition.code,
		ErrorMessage:           disposition.message,
	})
	state.partial = true
	return err
}

package extract

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
)

const (
	cpioMagicNewc = "070701"
	cpioMagicCRC  = "070702"
	cpioMagicODC  = "070707"

	cpioNewcHeaderBytes   = int64(110)
	cpioODCHeaderBytes    = int64(76)
	cpioBinaryHeaderBytes = int64(26)

	cpioNewcAlignment   = int64(4)
	cpioODCAlignment    = int64(1)
	cpioBinaryAlignment = int64(2)

	maxCPIONameBytes        = int64(maxLogicalPathBytes + 1)
	maxCPIOMetadataBytes    = int64(64 << 20)
	maxCPIOTrailingPadBytes = int64(1 << 20)

	// Symlink targets are retained inside JSON and may expand sixfold when
	// encoding control bytes. Keep that resident subset well below the
	// archive metadata ceiling, independently of the 100,000-node limit.
	maxCPIORetainedSymlinkMetadataBytes = int64(16 << 20)
	cpioSymlinkJSONFixedEstimateBytes   = int64(2 << 10)
	cpioEmptyMetadataJSONBytes          = int64(2)

	// Leave enough room for every possible node in the operation to carry a
	// minimal "{}" local-limit diagnostic. Accepted target JSON is held below
	// this content ceiling, while the operation counter tracks both kinds.
	maxCPIORetainedSymlinkContentBytes = maxCPIORetainedSymlinkMetadataBytes -
		int64(defaultMaxNodes)*cpioEmptyMetadataJSONBytes

	cpioModeTypeMask = uint64(0170000)
	cpioModeFIFO     = uint64(0010000)
	cpioModeChar     = uint64(0020000)
	cpioModeDir      = uint64(0040000)
	cpioModeBlock    = uint64(0060000)
	cpioModeRegular  = uint64(0100000)
	cpioModeSymlink  = uint64(0120000)
	cpioModeSocket   = uint64(0140000)
)

var (
	errInvalidCPIO     = errors.New("invalid CPIO archive")
	errCPIOCRCMismatch = errors.New("CPIO data checksum mismatch")
)

type cpioHeader struct {
	encoding string
	name     string

	inode     uint64
	mode      uint64
	uid       uint64
	gid       uint64
	nlink     uint64
	mtime     uint64
	fileSize  uint64
	devMajor  uint64
	devMinor  uint64
	rdevMajor uint64
	rdevMinor uint64
	checksum  uint32

	alignment    int64
	metadataSize int64
}

type cpioParser struct {
	ctx    context.Context
	source io.ReaderAt
	size   int64
	offset int64
}

func (state *operationState) extractCPIO(
	source *os.File,
	sourceSize int64,
	parentID int,
	prefix string,
	parentDepth int,
	budget *containerBudget,
) error {
	parser := cpioParser{
		ctx:    state.ctx,
		source: source,
		size:   sourceSize,
	}
	expectedEncoding := ""
	headerCount := 0
	maxHeaders := state.engine.limits.MaxNodes - len(state.nodes)
	if maxHeaders < 0 {
		maxHeaders = 0
	}
	var metadataBytes int64

	for {
		if err := state.ctx.Err(); err != nil {
			return err
		}
		if state.stopped {
			return &limitError{code: state.limitCode, global: true}
		}

		header, err := parser.nextHeader()
		if err != nil {
			return state.handleCPIOParserError(
				err,
				parentID,
				prefix,
				parentDepth,
			)
		}
		if expectedEncoding == "" {
			expectedEncoding = header.encoding
		} else if header.encoding != expectedEncoding {
			return state.appendCorruptArchiveNode(
				parentID,
				prefix,
				parentDepth+1,
				"cpio_mixed_encoding",
				fmt.Errorf(
					"%w: entry encoding changed from %s to %s",
					errInvalidCPIO,
					expectedEncoding,
					header.encoding,
				),
			)
		}
		if header.metadataSize >
			maxCPIOMetadataBytes-metadataBytes {
			limit := &limitError{code: LimitMaxArchiveMetadata}
			state.markLimit(limit.code)
			return limit
		}
		metadataBytes += header.metadataSize

		body, err := parser.prepareBody(header)
		if err != nil {
			return state.handleCPIOParserError(
				err,
				parentID,
				prefix,
				parentDepth,
			)
		}
		if header.name == "TRAILER!!!" {
			if header.fileSize != 0 || header.checksum != 0 {
				return state.appendCorruptArchiveNode(
					parentID,
					prefix,
					parentDepth+1,
					"cpio_trailer_invalid",
					fmt.Errorf(
						"%w: TRAILER!!! must have zero size and checksum",
						errInvalidCPIO,
					),
				)
			}
			if err := parser.validateTrailingPadding(); err != nil {
				return state.handleCPIOParserError(
					err,
					parentID,
					prefix,
					parentDepth,
				)
			}
			return nil
		}

		if headerCount >= maxHeaders {
			limit := &limitError{
				code:   LimitMaxNodes,
				global: true,
			}
			state.markLimit(limit.code)
			state.stopped = true
			return limit
		}
		headerCount++
		if header.nlink == 0 {
			if err := state.appendCorruptArchiveNode(
				parentID,
				prefix,
				parentDepth+1,
				"cpio_header_corrupt",
				fmt.Errorf("%w: zero link count", errInvalidCPIO),
			); err != nil {
				return err
			}
			continue
		}

		fileType := header.mode & cpioModeTypeMask
		isDirectory := fileType == cpioModeDir
		if !validCPIOFileType(fileType) {
			if err := state.appendCorruptArchiveNode(
				parentID,
				prefix,
				parentDepth+1,
				"cpio_mode_invalid",
				fmt.Errorf(
					"%w: unsupported mode type %#o",
					errInvalidCPIO,
					fileType,
				),
			); err != nil {
				return err
			}
			continue
		}
		if (isDirectory || isCPIOSpecial(fileType)) &&
			header.fileSize != 0 {
			if err := state.appendCorruptArchiveNode(
				parentID,
				prefix,
				parentDepth+1,
				"cpio_special_size_invalid",
				fmt.Errorf(
					"%w: mode %#o must have zero data size",
					errInvalidCPIO,
					fileType,
				),
			); err != nil {
				return err
			}
			continue
		}

		location, prepared, pathErr := state.prepareEntry(
			prefix,
			header.name,
			isDirectory,
			parentID,
			parentDepth,
		)
		if pathErr != nil {
			if err := state.appendRejectedPath(
				header.name,
				parentID,
				prefix,
				parentDepth+1,
			); err != nil {
				return err
			}
			if err := verifyCPIOBody(
				state.ctx,
				body,
				header.encoding,
				header.checksum,
			); err != nil {
				if errors.Is(err, errCPIOCRCMismatch) {
					if appendErr := state.appendCorruptArchiveNode(
						parentID,
						prefix,
						parentDepth+1,
						"cpio_crc_mismatch",
						err,
					); appendErr != nil {
						return appendErr
					}
					continue
				}
				return state.handleCPIOParserError(
					err,
					parentID,
					prefix,
					parentDepth,
				)
			}
			continue
		}
		if !prepared {
			if err := verifyCPIOBody(
				state.ctx,
				body,
				header.encoding,
				header.checksum,
			); err != nil {
				if errors.Is(err, errCPIOCRCMismatch) {
					if appendErr := state.appendCorruptArchiveNode(
						parentID,
						prefix,
						parentDepth+1,
						"cpio_crc_mismatch",
						err,
					); appendErr != nil {
						return appendErr
					}
					continue
				}
				return err
			}
			continue
		}

		metadata := cpioMetadata(header)
		node := Node{
			ParentLocalID: location.parentID,
			LogicalPath:   location.logical,
			DisplayName:   location.display,
			Depth:         location.depth,
			SizeBytes:     int64(header.fileSize),
		}
		if fileType != cpioModeSymlink {
			node.MetadataJSON = metadataJSON(metadata)
		}

		switch {
		case isDirectory:
			if location.directoryNode >= 0 {
				directory := &state.nodes[location.directoryNode]
				metadata["synthetic"] = false
				state.applyNamespaceCollision(
					location,
					directory,
					metadata,
				)
				directory.MetadataJSON = metadataJSON(metadata)
				if header.encoding == "crc" && header.checksum != 0 {
					directory.ExtractionStatus = StatusCorrupt
					directory.ErrorCode = "cpio_crc_mismatch"
					directory.ErrorMessage = errCPIOCRCMismatch.Error()
					state.partial = true
				}
			}

		case fileType == cpioModeSymlink:
			if header.fileSize > uint64(maxLogicalPathBytes) {
				if err := state.appendCPIOSymlinkLimit(
					node,
					"CPIO symlink target exceeds the metadata limit",
				); err != nil {
					return err
				}
				continue
			}
			estimatedJSONBytes := estimateCPIOSymlinkJSONBytes(
				header,
				location,
			)
			if estimatedJSONBytes >
				maxCPIORetainedSymlinkContentBytes-
					state.retainedCPIOSymlinkMetadataBytes {
				if err := state.appendCPIOSymlinkLimit(
					node,
					"CPIO symlink metadata exceeds the retained metadata limit",
				); err != nil {
					return err
				}
				continue
			}
			target, checksum, err := readCPIOBody(
				state.ctx,
				body,
				int(header.fileSize),
			)
			if err != nil {
				return err
			}
			node.NodeType = NodeTypeSymlink
			node.ExtractionStatus = StatusRecorded
			linkTarget := boundedText(string(target), maxLogicalPathBytes)
			metadata["link_target"] = linkTarget
			metadata["link_target_truncated"] =
				linkTarget != string(target)
			if header.encoding == "crc" && checksum != header.checksum {
				node.ExtractionStatus = StatusCorrupt
				node.ErrorCode = "cpio_crc_mismatch"
				node.ErrorMessage = errCPIOCRCMismatch.Error()
				state.partial = true
			}
			state.applyNamespaceCollision(location, &node, metadata)
			if node.MetadataJSON == nil {
				node.MetadataJSON = metadataJSON(metadata)
			}
			actualJSONBytes := int64(len(node.MetadataJSON))
			if actualJSONBytes > estimatedJSONBytes ||
				actualJSONBytes >
					maxCPIORetainedSymlinkContentBytes-
						state.retainedCPIOSymlinkMetadataBytes {
				if err := state.appendCPIOSymlinkLimit(
					node,
					"CPIO symlink metadata exceeds the retained metadata limit",
				); err != nil {
					return err
				}
				continue
			}
			if _, err := state.appendNode(node); err != nil {
				return err
			}
			state.retainedCPIOSymlinkMetadataBytes +=
				actualJSONBytes

		case fileType == cpioModeRegular &&
			header.nlink > 1 &&
			header.fileSize == 0:
			node.NodeType = NodeTypeHardlink
			node.ExtractionStatus = StatusRecorded
			if err := verifyCPIOBody(
				state.ctx,
				body,
				header.encoding,
				header.checksum,
			); err != nil {
				if errors.Is(err, errCPIOCRCMismatch) {
					node.ExtractionStatus = StatusCorrupt
					node.ErrorCode = "cpio_crc_mismatch"
					node.ErrorMessage = err.Error()
					state.partial = true
				} else {
					return err
				}
			}
			state.applyNamespaceCollision(location, &node, metadata)
			if _, err := state.appendNode(node); err != nil {
				return err
			}

		case fileType == cpioModeRegular:
			if header.nlink > 1 {
				metadata["hardlink_data_member"] = true
				node.MetadataJSON = metadataJSON(metadata)
			}
			node.NodeType = NodeTypeFile
			state.applyNamespaceCollision(location, &node, metadata)
			nodeLocalID := state.nextID
			checksumReader := &cpioChecksumReader{reader: body}
			materialized, limit, extractErr := state.materializeRegular(
				checksumReader,
				node,
				metadata,
				budget,
			)
			if extractErr != nil {
				if materialized != nil {
					materialized.close()
				}
				return extractErr
			}
			if limit != nil {
				if materialized != nil {
					materialized.close()
				}
				return limit
			}
			if materialized != nil &&
				header.encoding == "crc" &&
				checksumReader.checksum != header.checksum {
				if materialized != nil {
					materialized.close()
				}
				if extracted := state.nodeByLocalID(nodeLocalID); extracted != nil {
					extracted.ExtractionStatus = StatusCorrupt
					extracted.ErrorCode = "cpio_crc_mismatch"
					extracted.ErrorMessage = errCPIOCRCMismatch.Error()
					extracted.SHA256 = ""
				}
				state.partial = true
				continue
			}
			if err := state.completeMaterializedStream(
				materialized,
				nil,
				nil,
			); err != nil {
				return err
			}

		default:
			node.NodeType = NodeTypeSpecial
			node.ExtractionStatus = StatusRecorded
			if header.encoding == "crc" && header.checksum != 0 {
				node.ExtractionStatus = StatusCorrupt
				node.ErrorCode = "cpio_crc_mismatch"
				node.ErrorMessage = errCPIOCRCMismatch.Error()
				state.partial = true
			}
			state.applyNamespaceCollision(location, &node, metadata)
			if _, err := state.appendNode(node); err != nil {
				return err
			}
		}
	}
}

func (state *operationState) appendCPIOSymlinkLimit(
	node Node,
	message string,
) error {
	node.NodeType = NodeTypeSymlink
	node.ExtractionStatus = StatusLimitExceeded
	node.ErrorCode = LimitMaxArchiveMetadata
	node.ErrorMessage = message
	// Do not retain the attacker-controlled target or collision strings in a
	// limit node. The content ceiling reserves two bytes for every possible
	// node, so this diagnostic remains inside the operation-wide 16 MiB cap.
	node.MetadataJSON = []byte("{}")
	if _, err := state.appendNode(node); err != nil {
		return err
	}
	state.retainedCPIOSymlinkMetadataBytes +=
		cpioEmptyMetadataJSONBytes
	state.markLimit(LimitMaxArchiveMetadata)
	return nil
}

func estimateCPIOSymlinkJSONBytes(
	header cpioHeader,
	location entryLocation,
) int64 {
	estimated := cpioSymlinkJSONFixedEstimateBytes +
		int64(header.fileSize)*6
	if location.collision != nil {
		// applyNamespaceCollision may retain four path-sized strings. Use
		// their maximum encoded size rather than examining untrusted text.
		estimated += int64(4 * maxLogicalPathBytes * 6)
	}
	return estimated
}

func (state *operationState) handleCPIOParserError(
	err error,
	parentID int,
	prefix string,
	parentDepth int,
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
			"cpio_archive_corrupt",
			err,
		)
	}
}

func (parser *cpioParser) nextHeader() (cpioHeader, error) {
	var magic [6]byte
	if err := parser.readExact(magic[:]); err != nil {
		return cpioHeader{}, fmt.Errorf(
			"%s: read magic: %w",
			errInvalidCPIO,
			err,
		)
	}
	var (
		header cpioHeader
		err    error
	)
	switch {
	case binary.BigEndian.Uint16(magic[:2]) == 0x71c7:
		header, err = parser.readBinaryHeader(magic, binary.BigEndian)
	case binary.LittleEndian.Uint16(magic[:2]) == 0x71c7:
		header, err = parser.readBinaryHeader(magic, binary.LittleEndian)
	default:
		switch string(magic[:]) {
		case cpioMagicNewc, cpioMagicCRC:
			header, err = parser.readNewcHeader(string(magic[:]))
		case cpioMagicODC:
			header, err = parser.readODCHeader()
		default:
			return cpioHeader{}, fmt.Errorf(
				"%w: unknown magic %q",
				errInvalidCPIO,
				magic,
			)
		}
	}
	if err != nil {
		return cpioHeader{}, err
	}

	nameSize := header.metadataSize
	if nameSize <= 1 || nameSize > maxCPIONameBytes {
		return cpioHeader{}, &limitError{
			code: LimitMaxArchiveMetadata,
		}
	}
	name := make([]byte, int(nameSize))
	if err := parser.readExact(name); err != nil {
		return cpioHeader{}, fmt.Errorf(
			"%s: read name: %w",
			errInvalidCPIO,
			err,
		)
	}
	if name[len(name)-1] != 0 ||
		bytes.IndexByte(name[:len(name)-1], 0) >= 0 {
		return cpioHeader{}, fmt.Errorf(
			"%w: name is not exactly NUL-terminated",
			errInvalidCPIO,
		)
	}
	header.name = string(name[:len(name)-1])
	header.metadataSize += cpioHeaderSize(header.encoding)
	padding, err := parser.consumeAlignment(header.alignment)
	if err != nil {
		return cpioHeader{}, err
	}
	header.metadataSize += padding
	return header, nil
}

func (parser *cpioParser) readBinaryHeader(
	prefix [6]byte,
	order binary.ByteOrder,
) (cpioHeader, error) {
	var raw [cpioBinaryHeaderBytes]byte
	copy(raw[:], prefix[:])
	if err := parser.readExact(raw[len(prefix):]); err != nil {
		return cpioHeader{}, fmt.Errorf(
			"%s: truncated binary header: %w",
			errInvalidCPIO,
			err,
		)
	}
	var fields [13]uint16
	for index := range fields {
		fields[index] = order.Uint16(raw[index*2 : (index+1)*2])
	}
	if fields[0] != 0x71c7 {
		return cpioHeader{}, fmt.Errorf(
			"%w: invalid binary magic",
			errInvalidCPIO,
		)
	}
	fileSize := uint64(fields[11])<<16 | uint64(fields[12])
	if fileSize > math.MaxInt32 {
		return cpioHeader{}, fmt.Errorf(
			"%w: binary file size exceeds signed 32-bit range",
			errInvalidCPIO,
		)
	}
	encoding := "binary-little-endian"
	if order == binary.BigEndian {
		encoding = "binary-big-endian"
	}
	return cpioHeader{
		encoding:     encoding,
		devMinor:     uint64(fields[1]),
		inode:        uint64(fields[2]),
		mode:         uint64(fields[3]),
		uid:          uint64(fields[4]),
		gid:          uint64(fields[5]),
		nlink:        uint64(fields[6]),
		rdevMinor:    uint64(fields[7]),
		mtime:        uint64(fields[8])<<16 | uint64(fields[9]),
		fileSize:     fileSize,
		alignment:    cpioBinaryAlignment,
		metadataSize: int64(fields[10]),
	}, nil
}

func (parser *cpioParser) readNewcHeader(
	magic string,
) (cpioHeader, error) {
	var raw [104]byte
	if err := parser.readExact(raw[:]); err != nil {
		return cpioHeader{}, fmt.Errorf(
			"%s: truncated %s header: %w",
			errInvalidCPIO,
			magic,
			err,
		)
	}
	fields := make([]uint64, 13)
	for index := range fields {
		value, err := parseCPIONumber(
			raw[index*8:(index+1)*8],
			16,
		)
		if err != nil {
			return cpioHeader{}, fmt.Errorf(
				"%w: %s field %d: %v",
				errInvalidCPIO,
				magic,
				index,
				err,
			)
		}
		fields[index] = value
	}
	checksum := uint32(fields[12])
	if magic == cpioMagicNewc && checksum != 0 {
		return cpioHeader{}, fmt.Errorf(
			"%w: newc checksum field is not zero",
			errInvalidCPIO,
		)
	}
	encoding := "newc"
	if magic == cpioMagicCRC {
		encoding = "crc"
	}
	return cpioHeader{
		encoding:     encoding,
		inode:        fields[0],
		mode:         fields[1],
		uid:          fields[2],
		gid:          fields[3],
		nlink:        fields[4],
		mtime:        fields[5],
		fileSize:     fields[6],
		devMajor:     fields[7],
		devMinor:     fields[8],
		rdevMajor:    fields[9],
		rdevMinor:    fields[10],
		checksum:     checksum,
		alignment:    cpioNewcAlignment,
		metadataSize: int64(fields[11]),
	}, nil
}

func (parser *cpioParser) readODCHeader() (cpioHeader, error) {
	var raw [70]byte
	if err := parser.readExact(raw[:]); err != nil {
		return cpioHeader{}, fmt.Errorf(
			"%s: truncated odc header: %w",
			errInvalidCPIO,
			err,
		)
	}
	widths := [...]int{6, 6, 6, 6, 6, 6, 6, 11, 6, 11}
	fields := make([]uint64, len(widths))
	offset := 0
	for index, width := range widths {
		value, err := parseCPIONumber(raw[offset:offset+width], 8)
		if err != nil {
			return cpioHeader{}, fmt.Errorf(
				"%w: odc field %d: %v",
				errInvalidCPIO,
				index,
				err,
			)
		}
		fields[index] = value
		offset += width
	}
	return cpioHeader{
		encoding:     "odc",
		devMinor:     fields[0],
		inode:        fields[1],
		mode:         fields[2],
		uid:          fields[3],
		gid:          fields[4],
		nlink:        fields[5],
		rdevMinor:    fields[6],
		mtime:        fields[7],
		fileSize:     fields[9],
		alignment:    cpioODCAlignment,
		metadataSize: int64(fields[8]),
	}, nil
}

func parseCPIONumber(raw []byte, base int) (uint64, error) {
	var value uint64
	for _, current := range raw {
		var digit byte
		switch {
		case current >= '0' && current <= '9':
			digit = current - '0'
		case base == 16 && current >= 'a' && current <= 'f':
			digit = current - 'a' + 10
		case base == 16 && current >= 'A' && current <= 'F':
			digit = current - 'A' + 10
		default:
			return 0, fmt.Errorf("invalid base-%d digit %#x", base, current)
		}
		if int(digit) >= base ||
			value > (math.MaxUint64-uint64(digit))/uint64(base) {
			return 0, errors.New("numeric field overflows")
		}
		value = value*uint64(base) + uint64(digit)
	}
	return value, nil
}

func (parser *cpioParser) prepareBody(
	header cpioHeader,
) (io.Reader, error) {
	if header.fileSize > math.MaxInt64 ||
		int64(header.fileSize) > parser.size-parser.offset {
		return nil, fmt.Errorf(
			"%w: entry data is truncated",
			errInvalidCPIO,
		)
	}
	dataOffset := parser.offset
	parser.offset += int64(header.fileSize)
	if _, err := parser.consumeAlignment(header.alignment); err != nil {
		return nil, err
	}
	return io.NewSectionReader(
		parser.source,
		dataOffset,
		int64(header.fileSize),
	), nil
}

func (parser *cpioParser) consumeAlignment(
	alignment int64,
) (int64, error) {
	if alignment <= 1 {
		return 0, nil
	}
	padding := (alignment - parser.offset%alignment) % alignment
	if padding == 0 {
		return 0, nil
	}
	paddingOffset := parser.offset
	var raw [4]byte
	if err := parser.readExact(raw[:padding]); err != nil {
		return 0, fmt.Errorf(
			"%s: truncated alignment padding: %w",
			errInvalidCPIO,
			err,
		)
	}
	for _, current := range raw[:padding] {
		if current != 0 {
			return 0, fmt.Errorf(
				"%w: non-zero alignment padding at offset %d",
				errInvalidCPIO,
				paddingOffset,
			)
		}
	}
	return padding, nil
}

func (parser *cpioParser) validateTrailingPadding() error {
	remaining := parser.size - parser.offset
	if remaining < 0 {
		return fmt.Errorf("%w: invalid trailing offset", errInvalidCPIO)
	}
	if remaining > maxCPIOTrailingPadBytes {
		return &limitError{code: LimitMaxArchiveMetadata}
	}
	var buffer [32 << 10]byte
	for remaining > 0 {
		if err := parser.ctx.Err(); err != nil {
			return err
		}
		count := int64(len(buffer))
		if count > remaining {
			count = remaining
		}
		if err := parser.readExact(buffer[:count]); err != nil {
			return err
		}
		for _, current := range buffer[:count] {
			if current != 0 {
				return fmt.Errorf(
					"%w: non-zero data after TRAILER!!!",
					errInvalidCPIO,
				)
			}
		}
		remaining -= count
	}
	return nil
}

func (parser *cpioParser) readExact(buffer []byte) error {
	for len(buffer) > 0 {
		if err := parser.ctx.Err(); err != nil {
			return err
		}
		count, err := parser.source.ReadAt(buffer, parser.offset)
		parser.offset += int64(count)
		buffer = buffer[count:]
		if err != nil {
			if len(buffer) == 0 {
				return nil
			}
			if errors.Is(err, io.EOF) {
				return io.ErrUnexpectedEOF
			}
			return err
		}
		if count == 0 {
			return io.ErrNoProgress
		}
	}
	return nil
}

func cpioHeaderSize(encoding string) int64 {
	if encoding == "odc" {
		return cpioODCHeaderBytes
	}
	if encoding == "binary-little-endian" ||
		encoding == "binary-big-endian" {
		return cpioBinaryHeaderBytes
	}
	return cpioNewcHeaderBytes
}

func validCPIOFileType(fileType uint64) bool {
	switch fileType {
	case cpioModeFIFO, cpioModeChar, cpioModeDir, cpioModeBlock,
		cpioModeRegular, cpioModeSymlink, cpioModeSocket:
		return true
	default:
		return false
	}
}

func isCPIOSpecial(fileType uint64) bool {
	switch fileType {
	case cpioModeFIFO, cpioModeChar, cpioModeBlock, cpioModeSocket:
		return true
	default:
		return false
	}
}

func cpioMetadata(header cpioHeader) map[string]any {
	return map[string]any{
		"archive":        "cpio",
		"encoding":       header.encoding,
		"inode":          header.inode,
		"mode":           header.mode,
		"uid":            header.uid,
		"gid":            header.gid,
		"nlink":          header.nlink,
		"modified_at":    header.mtime,
		"declared_bytes": header.fileSize,
		"device_major":   header.devMajor,
		"device_minor":   header.devMinor,
		"rdev_major":     header.rdevMajor,
		"rdev_minor":     header.rdevMinor,
		"checksum":       header.checksum,
	}
}

type cpioChecksumReader struct {
	reader   io.Reader
	checksum uint32
}

func (reader *cpioChecksumReader) Read(buffer []byte) (int, error) {
	count, err := reader.reader.Read(buffer)
	for _, current := range buffer[:count] {
		reader.checksum += uint32(current)
	}
	return count, err
}

func verifyCPIOBody(
	ctx context.Context,
	body io.Reader,
	encoding string,
	expected uint32,
) error {
	if encoding != "crc" {
		return nil
	}
	_, checksum, err := readCPIOBody(ctx, body, 0)
	if err != nil {
		return err
	}
	if checksum != expected {
		return errCPIOCRCMismatch
	}
	return nil
}

func readCPIOBody(
	ctx context.Context,
	body io.Reader,
	capture int,
) ([]byte, uint32, error) {
	var captured []byte
	if capture > 0 {
		captured = make([]byte, 0, capture)
	}
	var checksum uint32
	var buffer [32 << 10]byte
	for {
		if err := ctx.Err(); err != nil {
			return nil, 0, err
		}
		count, err := body.Read(buffer[:])
		if count > 0 {
			for _, current := range buffer[:count] {
				checksum += uint32(current)
			}
			if len(captured) < capture {
				retained := count
				if retained > capture-len(captured) {
					retained = capture - len(captured)
				}
				captured = append(captured, buffer[:retained]...)
			}
		}
		if errors.Is(err, io.EOF) {
			return captured, checksum, nil
		}
		if err != nil {
			return nil, 0, err
		}
		if count == 0 {
			return nil, 0, io.ErrNoProgress
		}
	}
}

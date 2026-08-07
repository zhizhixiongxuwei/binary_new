// Package rpm parses the bounded wrapper and metadata headers of an RPM file.
package rpm

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

const (
	leadBytes        = int64(96)
	headerIntroBytes = int64(16)
	indexEntryBytes  = int64(16)

	maxHeaderEntries       = uint32(100_000)
	maxTotalHeaderEntries  = uint64(100_000)
	maxHeaderMetadataBytes = uint64(64 << 20)
	maxTagStringBytes      = int64(64)

	headerTypeChar        = uint32(1)
	headerTypeInt8        = uint32(2)
	headerTypeInt16       = uint32(3)
	headerTypeInt32       = uint32(4)
	headerTypeInt64       = uint32(5)
	headerTypeString      = uint32(6)
	headerTypeBin         = uint32(7)
	headerTypeStringArray = uint32(8)
	headerTypeI18NString  = uint32(9)

	tagHeaderImmutable   = uint32(63)
	tagArchitecture      = uint32(1022)
	tagPayloadFormat     = uint32(1124)
	tagPayloadCompressor = uint32(1125)
	tagPayloadFlags      = uint32(1126)
	tagRPMFormat         = uint32(5114)
)

var (
	rpmMagic    = []byte{0xed, 0xab, 0xee, 0xdb}
	headerMagic = []byte{0x8e, 0xad, 0xe8, 0x01, 0, 0, 0, 0}

	// ErrInvalid identifies malformed or structurally inconsistent RPM input.
	ErrInvalid = errors.New("invalid RPM package")
	// ErrMetadataLimit identifies an RPM header that exceeds parser ceilings.
	ErrMetadataLimit = errors.New("RPM metadata limit exceeded")
)

// Header describes one validated RPM header structure.
type Header struct {
	Offset     int64
	IndexCount uint32
	DataBytes  uint32
	TotalBytes int64
	DataOffset int64
	HeaderEnd  int64
}

// Package describes the validated RPM wrapper and the payload metadata needed
// to dispatch the embedded CPIO archive.
type Package struct {
	// The lead fields are retained as bounded legacy observations only. RPM
	// readers must not use them to decide whether the package is valid.
	MajorVersion     uint8
	MinorVersion     uint8
	PackageType      uint16
	ArchitectureCode uint16
	// Architecture comes from the validated main-header tag.
	Architecture string
	// FormatVersion is the stored RPMFORMAT value, or the v3/v4 version
	// inferred from HEADERIMMUTABLE when RPMFORMAT is absent.
	FormatVersion     uint32
	Signature         Header
	MainHeader        Header
	PayloadOffset     int64
	PayloadBytes      int64
	PayloadFormat     string
	PayloadCompressor string
	PayloadFlags      string
}

type headerValues struct {
	architecture         string
	format               string
	compressor           string
	flags                string
	headerImmutable      bool
	formatVersion        uint32
	formatVersionPresent bool
}

// Parse validates the RPM lead magic, both headers, and the exact payload
// location. Other legacy lead fields are observed but never validated.
func Parse(
	ctx context.Context,
	reader io.ReaderAt,
	size int64,
) (Package, error) {
	if ctx == nil {
		return Package{}, errors.New("rpm: nil context")
	}
	if reader == nil {
		return Package{}, errors.New("rpm: nil reader")
	}
	if size < leadBytes+headerIntroBytes*2 {
		return Package{}, invalidf("package is too short")
	}
	if err := ctx.Err(); err != nil {
		return Package{}, err
	}

	var lead [leadBytes]byte
	if err := readExactAt(ctx, reader, size, lead[:], 0); err != nil {
		return Package{}, err
	}
	if !bytes.Equal(lead[:4], rpmMagic) {
		return Package{}, invalidf("invalid lead magic")
	}
	packageType := binary.BigEndian.Uint16(lead[6:8])

	signature, _, err := parseHeader(
		ctx,
		reader,
		size,
		leadBytes,
		false,
	)
	if err != nil {
		return Package{}, err
	}
	mainOffset, ok := alignUp(signature.HeaderEnd, 8)
	if !ok || mainOffset > size {
		return Package{}, invalidf("signature padding overflows package")
	}
	if err := validateZeroRange(
		ctx,
		reader,
		size,
		signature.HeaderEnd,
		mainOffset-signature.HeaderEnd,
	); err != nil {
		return Package{}, err
	}

	mainHeader, values, err := parseHeader(
		ctx,
		reader,
		size,
		mainOffset,
		true,
	)
	if err != nil {
		return Package{}, err
	}
	if uint64(signature.IndexCount)+uint64(mainHeader.IndexCount) >
		maxTotalHeaderEntries {
		return Package{}, metadataLimitf("header entry count exceeds limit")
	}
	metadataBytes := uint64(signature.TotalBytes) +
		uint64(mainHeader.TotalBytes)
	if metadataBytes > maxHeaderMetadataBytes {
		return Package{}, metadataLimitf("header bytes exceed limit")
	}
	if mainHeader.HeaderEnd >= size {
		return Package{}, invalidf("RPM payload is empty")
	}
	formatVersion := uint32(3)
	if values.headerImmutable {
		formatVersion = 4
	}
	if values.formatVersionPresent {
		formatVersion = values.formatVersion
	}

	return Package{
		MajorVersion:      lead[4],
		MinorVersion:      lead[5],
		PackageType:       packageType,
		ArchitectureCode:  binary.BigEndian.Uint16(lead[8:10]),
		Architecture:      values.architecture,
		FormatVersion:     formatVersion,
		Signature:         signature,
		MainHeader:        mainHeader,
		PayloadOffset:     mainHeader.HeaderEnd,
		PayloadBytes:      size - mainHeader.HeaderEnd,
		PayloadFormat:     values.format,
		PayloadCompressor: values.compressor,
		PayloadFlags:      values.flags,
	}, nil
}

func parseHeader(
	ctx context.Context,
	reader io.ReaderAt,
	size int64,
	offset int64,
	capturePayloadTags bool,
) (Header, headerValues, error) {
	var intro [headerIntroBytes]byte
	if err := readExactAt(ctx, reader, size, intro[:], offset); err != nil {
		return Header{}, headerValues{}, err
	}
	if !bytes.Equal(intro[:8], headerMagic) {
		return Header{}, headerValues{}, invalidf("invalid header magic")
	}
	indexCount := binary.BigEndian.Uint32(intro[8:12])
	dataBytes := binary.BigEndian.Uint32(intro[12:16])
	if indexCount > maxHeaderEntries {
		return Header{}, headerValues{},
			metadataLimitf("header entry count exceeds limit")
	}
	indexBytes := uint64(indexCount) * uint64(indexEntryBytes)
	totalBytes := uint64(headerIntroBytes) + indexBytes + uint64(dataBytes)
	if totalBytes > maxHeaderMetadataBytes {
		return Header{}, headerValues{},
			metadataLimitf("header bytes exceed limit")
	}
	if uint64(offset) > uint64(size) ||
		totalBytes > uint64(size)-uint64(offset) {
		return Header{}, headerValues{}, invalidf("header exceeds package")
	}
	dataOffset := offset + headerIntroBytes + int64(indexBytes)
	headerEnd := offset + int64(totalBytes)
	header := Header{
		Offset:     offset,
		IndexCount: indexCount,
		DataBytes:  dataBytes,
		TotalBytes: int64(totalBytes),
		DataOffset: dataOffset,
		HeaderEnd:  headerEnd,
	}

	var values headerValues
	var previousTag uint32
	for index := uint32(0); index < indexCount; index++ {
		if index&0x3ff == 0 {
			if err := ctx.Err(); err != nil {
				return Header{}, headerValues{}, err
			}
		}
		var encoded [indexEntryBytes]byte
		entryOffset := offset + headerIntroBytes +
			int64(index)*indexEntryBytes
		if err := readExactAt(
			ctx,
			reader,
			size,
			encoded[:],
			entryOffset,
		); err != nil {
			return Header{}, headerValues{}, err
		}
		tag := binary.BigEndian.Uint32(encoded[0:4])
		valueType := binary.BigEndian.Uint32(encoded[4:8])
		valueOffset := int64(int32(binary.BigEndian.Uint32(encoded[8:12])))
		count := binary.BigEndian.Uint32(encoded[12:16])
		if index > 0 && tag <= previousTag {
			return Header{}, headerValues{},
				invalidf("header tags are not strictly ordered")
		}
		previousTag = tag
		if err := validateIndexEntry(
			valueType,
			valueOffset,
			count,
			int64(dataBytes),
		); err != nil {
			return Header{}, headerValues{}, err
		}
		if !capturePayloadTags {
			continue
		}
		if tag == tagHeaderImmutable {
			values.headerImmutable = true
			continue
		}
		if tag == tagRPMFormat {
			if valueType != headerTypeInt32 || count != 1 {
				return Header{}, headerValues{},
					invalidf("RPM format tag has invalid type")
			}
			var encodedValue [4]byte
			if err := readExactAt(
				ctx,
				reader,
				size,
				encodedValue[:],
				dataOffset+valueOffset,
			); err != nil {
				return Header{}, headerValues{}, err
			}
			values.formatVersion = binary.BigEndian.Uint32(
				encodedValue[:],
			)
			values.formatVersionPresent = true
			continue
		}
		target := (*string)(nil)
		switch tag {
		case tagArchitecture:
			target = &values.architecture
		case tagPayloadFormat:
			target = &values.format
		case tagPayloadCompressor:
			target = &values.compressor
		case tagPayloadFlags:
			target = &values.flags
		default:
			continue
		}
		if valueType != headerTypeString || count != 1 {
			return Header{}, headerValues{},
				invalidf("RPM payload tag has invalid type")
		}
		value, err := readCString(
			ctx,
			reader,
			size,
			dataOffset+valueOffset,
			int64(dataBytes)-valueOffset,
		)
		if err != nil {
			return Header{}, headerValues{}, err
		}
		*target = value
	}
	return header, values, nil
}

func validateIndexEntry(
	valueType uint32,
	offset int64,
	count uint32,
	dataBytes int64,
) error {
	if offset < 0 || offset > dataBytes {
		return invalidf("header value offset is outside data")
	}
	remaining := uint64(dataBytes - offset)
	var width uint64
	switch valueType {
	case headerTypeChar, headerTypeInt8, headerTypeBin:
		width = 1
	case headerTypeInt16:
		width = 2
	case headerTypeInt32:
		width = 4
	case headerTypeInt64:
		width = 8
	case headerTypeString:
		if count != 1 || remaining == 0 {
			return invalidf("invalid string entry")
		}
		return nil
	case headerTypeStringArray, headerTypeI18NString:
		if uint64(count) > remaining {
			return invalidf("string array count exceeds data")
		}
		return nil
	default:
		return invalidf("unknown header value type")
	}
	if width > 1 && uint64(offset)%width != 0 {
		return invalidf("integer entry is misaligned")
	}
	if uint64(count) > remaining/width {
		return invalidf("header value exceeds data")
	}
	return nil
}

func readCString(
	ctx context.Context,
	reader io.ReaderAt,
	size int64,
	offset int64,
	available int64,
) (string, error) {
	if available <= 0 {
		return "", invalidf("string value is empty")
	}
	readBytes := available
	if readBytes > maxTagStringBytes+1 {
		readBytes = maxTagStringBytes + 1
	}
	buffer := make([]byte, int(readBytes))
	if err := readExactAt(ctx, reader, size, buffer, offset); err != nil {
		return "", err
	}
	terminator := bytes.IndexByte(buffer, 0)
	if terminator < 0 {
		return "", invalidf("string value is unterminated or too long")
	}
	if terminator == 0 {
		return "", invalidf("string value is empty")
	}
	return string(buffer[:terminator]), nil
}

func validateZeroRange(
	ctx context.Context,
	reader io.ReaderAt,
	size int64,
	offset int64,
	length int64,
) error {
	if length == 0 {
		return nil
	}
	if length < 0 || length > 7 {
		return invalidf("invalid signature padding length")
	}
	var padding [7]byte
	if err := readExactAt(
		ctx,
		reader,
		size,
		padding[:length],
		offset,
	); err != nil {
		return err
	}
	if !allZero(padding[:length]) {
		return invalidf("signature padding is non-zero")
	}
	return nil
}

func readExactAt(
	ctx context.Context,
	reader io.ReaderAt,
	size int64,
	buffer []byte,
	offset int64,
) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if offset < 0 || offset > size ||
		int64(len(buffer)) > size-offset {
		return invalidf("read exceeds package")
	}
	count, err := reader.ReadAt(buffer, offset)
	if count != len(buffer) {
		if err != nil && !errors.Is(err, io.EOF) {
			return fmt.Errorf("rpm: read package: %w", err)
		}
		return invalidf("truncated package")
	}
	if err != nil && !errors.Is(err, io.EOF) {
		return fmt.Errorf("rpm: read package: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return nil
}

func alignUp(value int64, alignment int64) (int64, bool) {
	if value < 0 || alignment <= 0 {
		return 0, false
	}
	remainder := value % alignment
	if remainder == 0 {
		return value, true
	}
	add := alignment - remainder
	if value > int64(^uint64(0)>>1)-add {
		return 0, false
	}
	return value + add, true
}

func allZero(value []byte) bool {
	for _, current := range value {
		if current != 0 {
			return false
		}
	}
	return true
}

func invalidf(message string) error {
	return fmt.Errorf("%w: %s", ErrInvalid, message)
}

func metadataLimitf(message string) error {
	return fmt.Errorf("%w: %s", ErrMetadataLimit, message)
}

package extract

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"math"
)

const (
	rar5MaxHeaderBytes          = int64(2 << 20)
	rarPreflightMaxBlocks       = 100_000
	rarPreflightMaxExtraRecords = 100_000
	rarPreflightMaxMetadata     = int64(64 << 20)

	rar5BlockArchive = uint64(1)
	rar5BlockFile    = uint64(2)
	rar5BlockEncrypt = uint64(4)
	rar5BlockEnd     = uint64(5)

	rar5BlockHasExtra = uint64(0x0001)
	rar5BlockHasData  = uint64(0x0002)

	rar4BlockArchive = byte(0x73)
	rar4BlockFile    = byte(0x74)
	rar4BlockComment = byte(0x75)
	rar4BlockService = byte(0x7a)
	rar4BlockEnd     = byte(0x7b)

	rarPreflight4BlockHasData     = uint16(0x8000)
	rarPreflight4ArchiveVolume    = uint16(0x0001)
	rarPreflight4ArchiveComment   = uint16(0x0002)
	rarPreflight4ArchiveEncrypted = uint16(0x0080)
	rarPreflight4FileEncrypted    = uint16(0x0004)
	rarPreflight4FileLargeData    = uint16(0x0100)
)

var (
	errInvalidRARMetadata              = errors.New("invalid RAR metadata")
	errRARLegacyCompressionUnsupported = errors.New(
		"compressed legacy RAR entries require an isolated decoder",
	)
	errRARMultiVolumeUnsupported = errors.New(
		"multi-volume RAR archives are not supported",
	)
)

// preflightRARMetadata validates the length-bearing fields that rardecode
// converts to int before the third-party parser sees them. It never reads entry
// bodies and retains at most one bounded header.
func preflightRARMetadata(
	ctx context.Context,
	source io.ReaderAt,
	sourceSize int64,
	version int,
	signatureOffset int64,
) error {
	switch version {
	case 4:
		return preflightRAR4(ctx, source, sourceSize, signatureOffset)
	case 5:
		return preflightRAR5(ctx, source, sourceSize, signatureOffset)
	default:
		return invalidRARMetadataf("unsupported RAR version %d", version)
	}
}

func preflightRAR5(
	ctx context.Context,
	source io.ReaderAt,
	sourceSize int64,
	signatureOffset int64,
) error {
	offset := signatureOffset + int64(len(rar5Signature))
	scratch := make([]byte, int(rar5MaxHeaderBytes)+3)
	var metadataBytes int64
	extraRecords := 0
	for block := 0; ; block++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		if block >= rarPreflightMaxBlocks {
			return &limitError{code: LimitMaxArchiveMetadata}
		}
		if offset == sourceSize {
			return nil
		}
		if offset < 0 || sourceSize-offset < 5 {
			return invalidRARMetadataf("truncated RAR5 block header")
		}

		var encodedCRC [4]byte
		if err := readRARAt(ctx, source, sourceSize, encodedCRC[:], offset); err != nil {
			return err
		}
		headerBytes, sizeBytes, err := readRAR5HeaderSize(
			ctx, source, sourceSize, offset+4,
		)
		if err != nil {
			return err
		}
		if headerBytes < 2 || headerBytes > rar5MaxHeaderBytes {
			return invalidRARMetadataf("RAR5 header size is outside limits")
		}
		totalHeader := int64(sizeBytes) + headerBytes
		if totalHeader > sourceSize-(offset+4) {
			return invalidRARMetadataf("RAR5 header exceeds archive")
		}
		if metadataBytes > rarPreflightMaxMetadata-totalHeader {
			return &limitError{code: LimitMaxArchiveMetadata}
		}
		metadataBytes += totalHeader

		header := scratch[:totalHeader]
		if err := readRARAt(
			ctx, source, sourceSize, header, offset+4,
		); err != nil {
			return err
		}
		if crc32.ChecksumIEEE(header) != binary.LittleEndian.Uint32(encodedCRC[:]) {
			return invalidRARMetadataf("RAR5 header checksum mismatch")
		}

		cursor := rar5Cursor{data: header[sizeBytes:]}
		blockType, err := cursor.uvarint()
		if err != nil {
			return err
		}
		blockFlags, err := cursor.uvarint()
		if err != nil {
			return err
		}
		extraBytes := 0
		if blockFlags&rar5BlockHasExtra != 0 {
			extraBytes, err = cursor.intLength("RAR5 extra area")
			if err != nil {
				return err
			}
		}
		var dataBytes int64
		if blockFlags&rar5BlockHasData != 0 {
			value, readErr := cursor.uvarint()
			if readErr != nil {
				return readErr
			}
			if value > math.MaxInt64 {
				return invalidRARMetadataf("RAR5 data size exceeds int64")
			}
			dataBytes = int64(value)
		}
		if extraBytes > len(cursor.data) {
			return invalidRARMetadataf("RAR5 extra area exceeds header")
		}
		headerDataBytes := len(cursor.data) - extraBytes
		headerData, err := cursor.bytes(headerDataBytes)
		if err != nil {
			return err
		}
		extraData, err := cursor.bytes(extraBytes)
		if err != nil {
			return err
		}
		recordCount, err := validateRAR5ExtraRecords(
			ctx,
			extraData,
			blockType == rar5BlockFile,
			rarPreflightMaxExtraRecords-extraRecords,
		)
		if err != nil {
			return err
		}
		extraRecords += recordCount
		stopAfterBlock := false
		var stopError error
		switch blockType {
		case rar5BlockArchive:
			multiVolume, err := validateRAR5ArchiveHeader(headerData)
			if err != nil {
				return err
			}
			if multiVolume {
				stopError = errRARMultiVolumeUnsupported
			}
		case rar5BlockFile:
			if err := validateRAR5FileHeader(headerData); err != nil {
				return err
			}
		case rar5BlockEncrypt:
			if err := validateRAR5EncryptionHeader(headerData); err != nil {
				return err
			}
			// Following headers are encrypted and are intentionally left to the
			// password-required path in rardecode.
			stopAfterBlock = true
		case rar5BlockEnd:
			if err := requireRAR5Uvarint(headerData, "RAR5 end flags"); err != nil {
				return err
			}
		}

		blockEnd := offset + 4 + totalHeader
		if dataBytes > sourceSize-blockEnd {
			return invalidRARMetadataf("RAR5 block data exceeds archive")
		}
		offset = blockEnd + dataBytes
		if stopError != nil {
			return stopError
		}
		if stopAfterBlock || blockType == rar5BlockEnd {
			return nil
		}
	}
}

func validateRAR5ExtraRecords(
	ctx context.Context,
	data []byte,
	validateFileRecords bool,
	remaining int,
) (int, error) {
	cursor := rar5Cursor{data: data}
	count := 0
	for len(cursor.data) > 0 {
		if count&0xff == 0 {
			if err := ctx.Err(); err != nil {
				return count, err
			}
		}
		if count >= remaining {
			return count, &limitError{code: LimitMaxArchiveMetadata}
		}
		size, err := cursor.intLength("RAR5 extra record")
		if err != nil {
			return count, err
		}
		if size <= 0 || size > len(cursor.data) {
			return count, invalidRARMetadataf(
				"RAR5 extra record exceeds extra area",
			)
		}
		record, err := cursor.bytes(size)
		if err != nil {
			return count, err
		}
		recordCursor := rar5Cursor{data: record}
		fieldType, err := recordCursor.uvarint()
		if err != nil {
			return count, err
		}
		if validateFileRecords && fieldType == 4 {
			if _, err := recordCursor.uvarint(); err != nil {
				return count, err
			}
			if _, err := recordCursor.intLength("RAR5 file version"); err != nil {
				return count, err
			}
		}
		count++
	}
	return count, nil
}

func validateRAR5ArchiveHeader(data []byte) (bool, error) {
	cursor := rar5Cursor{data: data}
	flags, err := cursor.uvarint()
	if err != nil {
		return false, err
	}
	if flags&0x0002 != 0 {
		if _, err := cursor.intLength("RAR5 volume number"); err != nil {
			return false, err
		}
	}
	return flags&0x0001 != 0, nil
}

func validateRAR5FileHeader(data []byte) error {
	cursor := rar5Cursor{data: data}
	fileFlags, err := cursor.uvarint()
	if err != nil {
		return err
	}
	unpacked, err := cursor.uvarint()
	if err != nil {
		return err
	}
	if unpacked > math.MaxInt64 {
		return invalidRARMetadataf("RAR5 unpacked size exceeds int64")
	}
	attributes, err := cursor.uvarint()
	if err != nil {
		return err
	}
	if attributes > math.MaxInt64 {
		return invalidRARMetadataf("RAR5 attributes exceed int64")
	}
	if fileFlags&0x0002 != 0 {
		if _, err := cursor.bytes(4); err != nil {
			return invalidRARMetadataf("truncated RAR5 modification time")
		}
	}
	if fileFlags&0x0004 != 0 {
		if _, err := cursor.bytes(4); err != nil {
			return invalidRARMetadataf("truncated RAR5 checksum")
		}
	}
	if _, err := cursor.uvarint(); err != nil {
		return err
	}
	if _, err := cursor.uvarint(); err != nil {
		return err
	}
	nameBytes, err := cursor.intLength("RAR5 file name")
	if err != nil {
		return err
	}
	if nameBytes > len(cursor.data) {
		return invalidRARMetadataf("RAR5 file name exceeds header")
	}
	if _, err := cursor.bytes(nameBytes); err != nil {
		return err
	}
	return nil
}

func validateRAR5EncryptionHeader(data []byte) error {
	cursor := rar5Cursor{data: data}
	if _, err := cursor.uvarint(); err != nil {
		return err
	}
	flags, err := cursor.uvarint()
	if err != nil {
		return err
	}
	fixed := 17
	if flags&0x0001 != 0 {
		fixed += 12
	}
	if len(cursor.data) < fixed {
		return invalidRARMetadataf("truncated RAR5 encryption header")
	}
	return nil
}

func requireRAR5Uvarint(data []byte, field string) error {
	cursor := rar5Cursor{data: data}
	if _, err := cursor.uvarint(); err != nil {
		return invalidRARMetadataf("%s is invalid", field)
	}
	return nil
}

type rar5Cursor struct {
	data []byte
}

func (cursor *rar5Cursor) uvarint() (uint64, error) {
	if len(cursor.data) == 0 {
		return 0, invalidRARMetadataf("truncated RAR5 varint")
	}
	value, count := binary.Uvarint(cursor.data)
	if count <= 0 {
		return 0, invalidRARMetadataf("unterminated or overflowing RAR5 varint")
	}
	cursor.data = cursor.data[count:]
	return value, nil
}

func (cursor *rar5Cursor) intLength(field string) (int, error) {
	value, err := cursor.uvarint()
	if err != nil {
		return 0, err
	}
	if value > uint64(maxIntValue()) {
		return 0, invalidRARMetadataf("%s exceeds int", field)
	}
	return int(value), nil
}

func (cursor *rar5Cursor) bytes(count int) ([]byte, error) {
	if count < 0 || count > len(cursor.data) {
		return nil, invalidRARMetadataf("RAR5 field exceeds header")
	}
	value := cursor.data[:count]
	cursor.data = cursor.data[count:]
	return value, nil
}

func readRAR5HeaderSize(
	ctx context.Context,
	source io.ReaderAt,
	sourceSize int64,
	offset int64,
) (int64, int, error) {
	var encoded [3]byte
	for index := range encoded {
		if err := readRARAt(
			ctx, source, sourceSize, encoded[index:index+1], offset+int64(index),
		); err != nil {
			return 0, 0, err
		}
		if encoded[index]&0x80 == 0 {
			value, count := binary.Uvarint(encoded[:index+1])
			if count != index+1 {
				return 0, 0, invalidRARMetadataf("invalid RAR5 header size")
			}
			return int64(value), count, nil
		}
	}
	return 0, 0, invalidRARMetadataf("unterminated RAR5 header size")
}

func preflightRAR4(
	ctx context.Context,
	source io.ReaderAt,
	sourceSize int64,
	signatureOffset int64,
) error {
	offset := signatureOffset + int64(len(rar4Signature))
	scratch := make([]byte, math.MaxUint16)
	var metadataBytes int64
	for block := 0; ; block++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		if block >= rarPreflightMaxBlocks {
			return &limitError{code: LimitMaxArchiveMetadata}
		}
		if offset == sourceSize {
			return nil
		}
		var base [7]byte
		if err := readRARAt(ctx, source, sourceSize, base[:], offset); err != nil {
			return err
		}
		blockType := base[2]
		flags := binary.LittleEndian.Uint16(base[3:5])
		headerBytes := int64(binary.LittleEndian.Uint16(base[5:7]))
		if blockType == rar4BlockArchive &&
			flags&rarPreflight4ArchiveComment != 0 {
			headerBytes = 13
		}
		if headerBytes < 7 || headerBytes > int64(len(scratch)) ||
			headerBytes > sourceSize-offset {
			return invalidRARMetadataf("RAR4 header size is invalid")
		}
		if metadataBytes > rarPreflightMaxMetadata-headerBytes {
			return &limitError{code: LimitMaxArchiveMetadata}
		}
		metadataBytes += headerBytes
		header := scratch[:headerBytes]
		if err := readRARAt(ctx, source, sourceSize, header, offset); err != nil {
			return err
		}
		checksumData := header[2:]
		if blockType == rar4BlockComment {
			if len(header) < 13 {
				return invalidRARMetadataf("truncated RAR4 comment header")
			}
			checksumData = header[2:13]
		}
		if uint16(crc32.ChecksumIEEE(checksumData)) !=
			binary.LittleEndian.Uint16(header[:2]) {
			return invalidRARMetadataf("RAR4 header checksum mismatch")
		}

		headerData := header[7:]
		var dataBytes uint64
		if flags&rarPreflight4BlockHasData != 0 {
			if len(headerData) < 4 {
				return invalidRARMetadataf("truncated RAR4 data size")
			}
			dataBytes = uint64(binary.LittleEndian.Uint32(headerData[:4]))
			headerData = headerData[4:]
		}
		if (blockType == rar4BlockFile || blockType == rar4BlockService) &&
			flags&rarPreflight4FileLargeData != 0 {
			if len(headerData) < 25 {
				return invalidRARMetadataf("truncated RAR4 large-file header")
			}
			dataBytes |= uint64(binary.LittleEndian.Uint32(
				headerData[21:25],
			)) << 32
		}
		if dataBytes > math.MaxInt64 {
			return invalidRARMetadataf("RAR4 data size exceeds int64")
		}
		if blockType == rar4BlockFile {
			if err := validateRAR4FileHeader(headerData, flags); err != nil {
				return err
			}
		}
		blockEnd := offset + headerBytes
		if int64(dataBytes) > sourceSize-blockEnd {
			return invalidRARMetadataf("RAR4 block data exceeds archive")
		}
		offset = blockEnd + int64(dataBytes)
		if blockType == rar4BlockEnd {
			return nil
		}
		if blockType == rar4BlockArchive {
			if flags&rarPreflight4ArchiveEncrypted != 0 {
				return nil
			}
			if flags&rarPreflight4ArchiveVolume != 0 {
				return errRARMultiVolumeUnsupported
			}
		}
	}
}

func validateRAR4FileHeader(data []byte, flags uint16) error {
	if len(data) < 21 {
		return invalidRARMetadataf("truncated RAR4 file header")
	}
	if data[14] != 0x30 && flags&rarPreflight4FileEncrypted == 0 {
		return errRARLegacyCompressionUnsupported
	}
	unpacked := uint64(binary.LittleEndian.Uint32(data[:4]))
	nameBytes := int(binary.LittleEndian.Uint16(data[15:17]))
	nameOffset := 21
	if flags&rarPreflight4FileLargeData != 0 {
		if len(data) < 29 {
			return invalidRARMetadataf("truncated RAR4 large-file fields")
		}
		unpacked |= uint64(binary.LittleEndian.Uint32(data[25:29])) << 32
		nameOffset = 29
	}
	if unpacked > math.MaxInt64 && unpacked != math.MaxUint64 {
		return invalidRARMetadataf("RAR4 unpacked size exceeds int64")
	}
	if nameBytes > len(data)-nameOffset {
		return invalidRARMetadataf("RAR4 file name exceeds header")
	}
	return nil
}

func readRARAt(
	ctx context.Context,
	source io.ReaderAt,
	sourceSize int64,
	buffer []byte,
	offset int64,
) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if offset < 0 || offset > sourceSize ||
		int64(len(buffer)) > sourceSize-offset {
		return invalidRARMetadataf("RAR metadata read exceeds archive")
	}
	count, err := source.ReadAt(buffer, offset)
	if count != len(buffer) {
		if err != nil && !errors.Is(err, io.EOF) {
			return fmt.Errorf("extract: read RAR metadata: %w", err)
		}
		return invalidRARMetadataf("truncated RAR metadata")
	}
	if err != nil && !errors.Is(err, io.EOF) {
		return fmt.Errorf("extract: read RAR metadata: %w", err)
	}
	return ctx.Err()
}

func maxIntValue() int {
	return int(^uint(0) >> 1)
}

func invalidRARMetadataf(format string, values ...any) error {
	return fmt.Errorf("%w: %s", errInvalidRARMetadata, fmt.Sprintf(format, values...))
}

package extract

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
)

const (
	zipDirectoryHeaderSignature    = 0x02014b50
	zipDirectoryEndSignature       = 0x06054b50
	zipDirectory64LocatorSignature = 0x07064b50
	zipDirectory64EndSignature     = 0x06064b50
	zipDirectoryDigitalSignature   = 0x05054b50

	zipDirectoryHeaderLength    = 46
	zipDirectoryEndLength       = 22
	zipDirectory64LocatorLength = 20
	zipDirectory64EndLength     = 56
	zipMaxCommentLength         = 1<<16 - 1

	maxZIPDirectoryMetadataBytes = uint64(64 << 20)
)

var (
	errInvalidZIPDirectory       = errors.New("invalid ZIP central directory")
	errUnsupportedZIPMultiVolume = errors.New(
		"multi-volume ZIP archive is unsupported",
	)
)

type zipDirectoryInfo struct {
	offset       int64
	size         uint64
	records      uint64
	zip64        bool
	baseOffset   int64
	directoryEnd int64
}

type zipEndRecord struct {
	eocdOffset       int64
	directoryEnd     int64
	directorySize    uint64
	directoryOffset  uint64
	directoryRecords uint64
	zip64            bool
}

// preflightZIPDirectory bounds archive/zip's in-memory directory parsing.
// It deliberately counts real central-directory headers instead of trusting
// the 16-bit EOCD count, which is commonly truncated by older ZIP writers.
func preflightZIPDirectory(
	ctx context.Context,
	reader io.ReaderAt,
	size int64,
	maxEntries int,
) (zipDirectoryInfo, error) {
	if ctx == nil {
		return zipDirectoryInfo{}, errors.New("extract: nil ZIP preflight context")
	}
	if reader == nil || size < 0 {
		return zipDirectoryInfo{}, errInvalidZIPDirectory
	}
	end, err := readZIPEndRecord(ctx, reader, size)
	if err != nil {
		return zipDirectoryInfo{}, err
	}
	if end.directorySize > uint64(end.directoryEnd) {
		return zipDirectoryInfo{}, fmt.Errorf(
			"%w: central directory size is outside the archive",
			errInvalidZIPDirectory,
		)
	}
	directoryStart := uint64(end.directoryEnd) - end.directorySize
	if end.directoryOffset > directoryStart {
		return zipDirectoryInfo{}, fmt.Errorf(
			"%w: central directory offset is outside the archive",
			errInvalidZIPDirectory,
		)
	}
	baseOffset := directoryStart - end.directoryOffset
	if baseOffset > math.MaxInt64 {
		return zipDirectoryInfo{}, errInvalidZIPDirectory
	}
	if baseOffset > 0 {
		// archive/zip has a compatibility fallback that discards baseOffset
		// when directoryOffset itself appears to contain a directory header.
		// Reject that ambiguous layout so NewReader cannot parse a different,
		// unbounded header stream than the one checked below.
		var signature [4]byte
		if err := zipReadAt(
			ctx,
			reader,
			signature[:],
			int64(end.directoryOffset),
		); err != nil {
			return zipDirectoryInfo{}, err
		}
		if binary.LittleEndian.Uint32(signature[:]) ==
			zipDirectoryHeaderSignature {
			return zipDirectoryInfo{}, fmt.Errorf(
				"%w: ambiguous central directory base offset",
				errInvalidZIPDirectory,
			)
		}
	}
	if end.directorySize > maxZIPDirectoryMetadataBytes {
		return zipDirectoryInfo{}, &limitError{
			code: LimitMaxArchiveMetadata,
		}
	}
	if maxEntries < 0 {
		maxEntries = 0
	}
	actualRecords, err := scanZIPDirectory(
		ctx,
		reader,
		int64(directoryStart),
		end.directorySize,
		maxEntries,
	)
	if err != nil {
		return zipDirectoryInfo{}, err
	}
	if end.zip64 {
		if actualRecords != end.directoryRecords {
			return zipDirectoryInfo{}, fmt.Errorf(
				"%w: ZIP64 entry count mismatch",
				errInvalidZIPDirectory,
			)
		}
	} else if uint16(actualRecords) != uint16(end.directoryRecords) {
		return zipDirectoryInfo{}, fmt.Errorf(
			"%w: entry count mismatch",
			errInvalidZIPDirectory,
		)
	}
	return zipDirectoryInfo{
		offset:       int64(directoryStart),
		size:         end.directorySize,
		records:      actualRecords,
		zip64:        end.zip64,
		baseOffset:   int64(baseOffset),
		directoryEnd: end.directoryEnd,
	}, nil
}

func readZIPEndRecord(
	ctx context.Context,
	reader io.ReaderAt,
	size int64,
) (zipEndRecord, error) {
	if size < zipDirectoryEndLength {
		return zipEndRecord{}, errInvalidZIPDirectory
	}
	tailLength := int64(zipDirectoryEndLength + zipMaxCommentLength)
	if tailLength > size {
		tailLength = size
	}
	tail := make([]byte, int(tailLength))
	if err := zipReadAt(ctx, reader, tail, size-tailLength); err != nil {
		return zipEndRecord{}, err
	}
	eocdIndex := -1
	for index := len(tail) - zipDirectoryEndLength; index >= 0; index-- {
		if err := ctx.Err(); err != nil {
			return zipEndRecord{}, err
		}
		if binary.LittleEndian.Uint32(tail[index:index+4]) !=
			zipDirectoryEndSignature {
			continue
		}
		commentLength := int(binary.LittleEndian.Uint16(
			tail[index+20 : index+22],
		))
		if index+zipDirectoryEndLength+commentLength <= len(tail) {
			eocdIndex = index
			break
		}
	}
	if eocdIndex < 0 {
		return zipEndRecord{}, errInvalidZIPDirectory
	}
	if err := ctx.Err(); err != nil {
		return zipEndRecord{}, err
	}
	eocd := tail[eocdIndex : eocdIndex+zipDirectoryEndLength]
	eocdOffset := size - tailLength + int64(eocdIndex)
	diskNumber := binary.LittleEndian.Uint16(eocd[4:6])
	directoryDisk := binary.LittleEndian.Uint16(eocd[6:8])
	recordsOnDisk := binary.LittleEndian.Uint16(eocd[8:10])
	records := binary.LittleEndian.Uint16(eocd[10:12])
	directorySize32 := binary.LittleEndian.Uint32(eocd[12:16])
	directoryOffset32 := binary.LittleEndian.Uint32(eocd[16:20])
	if diskNumber != 0 || directoryDisk != 0 {
		return zipEndRecord{}, fmt.Errorf(
			"%w: disk=%d directory_disk=%d",
			errUnsupportedZIPMultiVolume,
			diskNumber,
			directoryDisk,
		)
	}
	// This intentionally mirrors archive/zip.readDirectoryEnd in the Go
	// version used by this project. Its historical size sentinel is 0xffff,
	// not 0xffffffff. Parsing a different EOCD variant here would allow
	// NewReader to consume an unchecked central-directory stream.
	usesZIP64 := records == math.MaxUint16 ||
		directorySize32 == math.MaxUint16 ||
		directoryOffset32 == math.MaxUint32
	if !usesZIP64 {
		if recordsOnDisk != records {
			return zipEndRecord{}, fmt.Errorf(
				"%w: inconsistent entry counts",
				errInvalidZIPDirectory,
			)
		}
		return zipEndRecord{
			eocdOffset:       eocdOffset,
			directoryEnd:     eocdOffset,
			directorySize:    uint64(directorySize32),
			directoryOffset:  uint64(directoryOffset32),
			directoryRecords: uint64(records),
		}, nil
	}
	zip64, err := readZIP64EndRecord(
		ctx,
		reader,
		eocdOffset,
		recordsOnDisk,
		records,
		directorySize32,
		directoryOffset32,
	)
	if err != nil {
		return zipEndRecord{}, err
	}
	zip64.eocdOffset = eocdOffset
	zip64.zip64 = true
	return zip64, nil
}

func readZIP64EndRecord(
	ctx context.Context,
	reader io.ReaderAt,
	eocdOffset int64,
	recordsOnDisk16 uint16,
	records16 uint16,
	directorySize32 uint32,
	directoryOffset32 uint32,
) (zipEndRecord, error) {
	locatorOffset := eocdOffset - zipDirectory64LocatorLength
	if locatorOffset < 0 {
		return zipEndRecord{}, errInvalidZIPDirectory
	}
	var locator [zipDirectory64LocatorLength]byte
	if err := zipReadAt(ctx, reader, locator[:], locatorOffset); err != nil {
		return zipEndRecord{}, err
	}
	if binary.LittleEndian.Uint32(locator[0:4]) !=
		zipDirectory64LocatorSignature {
		return zipEndRecord{}, fmt.Errorf(
			"%w: invalid ZIP64 locator",
			errInvalidZIPDirectory,
		)
	}
	locatorDisk := binary.LittleEndian.Uint32(locator[4:8])
	totalDisks := binary.LittleEndian.Uint32(locator[16:20])
	if locatorDisk != 0 || totalDisks != 1 {
		return zipEndRecord{}, fmt.Errorf(
			"%w: directory_disk=%d total_disks=%d",
			errUnsupportedZIPMultiVolume,
			locatorDisk,
			totalDisks,
		)
	}
	recordOffset64 := binary.LittleEndian.Uint64(locator[8:16])
	if recordOffset64 > math.MaxInt64 {
		return zipEndRecord{}, errInvalidZIPDirectory
	}
	recordOffset := int64(recordOffset64)
	if recordOffset < 0 ||
		recordOffset > locatorOffset-zipDirectory64EndLength {
		return zipEndRecord{}, fmt.Errorf(
			"%w: ZIP64 end record is outside the archive",
			errInvalidZIPDirectory,
		)
	}
	var record [zipDirectory64EndLength]byte
	if err := zipReadAt(ctx, reader, record[:], recordOffset); err != nil {
		return zipEndRecord{}, err
	}
	if binary.LittleEndian.Uint32(record[0:4]) !=
		zipDirectory64EndSignature {
		return zipEndRecord{}, fmt.Errorf(
			"%w: missing ZIP64 end record",
			errInvalidZIPDirectory,
		)
	}
	recordPayloadSize := binary.LittleEndian.Uint64(record[4:12])
	if recordPayloadSize < zipDirectory64EndLength-12 ||
		recordPayloadSize > math.MaxInt64-12 ||
		recordOffset > math.MaxInt64-int64(recordPayloadSize)-12 ||
		recordOffset+int64(recordPayloadSize)+12 != locatorOffset {
		return zipEndRecord{}, fmt.Errorf(
			"%w: invalid ZIP64 end record size",
			errInvalidZIPDirectory,
		)
	}
	diskNumber := binary.LittleEndian.Uint32(record[16:20])
	directoryDisk := binary.LittleEndian.Uint32(record[20:24])
	recordsOnDisk := binary.LittleEndian.Uint64(record[24:32])
	records := binary.LittleEndian.Uint64(record[32:40])
	directorySize := binary.LittleEndian.Uint64(record[40:48])
	directoryOffset := binary.LittleEndian.Uint64(record[48:56])
	if diskNumber != 0 || directoryDisk != 0 || recordsOnDisk != records {
		return zipEndRecord{}, fmt.Errorf(
			"%w: disk=%d directory_disk=%d records_on_disk=%d records=%d",
			errUnsupportedZIPMultiVolume,
			diskNumber,
			directoryDisk,
			recordsOnDisk,
			records,
		)
	}
	if (recordsOnDisk16 != math.MaxUint16 &&
		uint64(recordsOnDisk16) != recordsOnDisk) ||
		(records16 != math.MaxUint16 && uint64(records16) != records) ||
		(directorySize32 != math.MaxUint16 &&
			directorySize32 != math.MaxUint32 &&
			uint64(directorySize32) != directorySize) ||
		(directoryOffset32 != math.MaxUint32 &&
			uint64(directoryOffset32) != directoryOffset) {
		return zipEndRecord{}, fmt.Errorf(
			"%w: inconsistent ZIP64 fallback fields",
			errInvalidZIPDirectory,
		)
	}
	return zipEndRecord{
		directoryEnd:     recordOffset,
		directorySize:    directorySize,
		directoryOffset:  directoryOffset,
		directoryRecords: records,
	}, nil
}

func scanZIPDirectory(
	ctx context.Context,
	reader io.ReaderAt,
	offset int64,
	size uint64,
	maxEntries int,
) (uint64, error) {
	if offset < 0 || size > math.MaxInt64 ||
		offset > math.MaxInt64-int64(size) {
		return 0, errInvalidZIPDirectory
	}
	end := offset + int64(size)
	var records uint64
	for offset < end {
		if err := ctx.Err(); err != nil {
			return 0, err
		}
		remaining := end - offset
		if remaining < 4 {
			return 0, fmt.Errorf(
				"%w: truncated central directory signature",
				errInvalidZIPDirectory,
			)
		}
		var signature [4]byte
		if err := zipReadAt(ctx, reader, signature[:], offset); err != nil {
			return 0, err
		}
		switch binary.LittleEndian.Uint32(signature[:]) {
		case zipDirectoryHeaderSignature:
			if remaining < zipDirectoryHeaderLength {
				return 0, fmt.Errorf(
					"%w: truncated central directory header",
					errInvalidZIPDirectory,
				)
			}
			var header [zipDirectoryHeaderLength]byte
			copy(header[:4], signature[:])
			if err := zipReadAt(
				ctx,
				reader,
				header[4:],
				offset+4,
			); err != nil {
				return 0, err
			}
			variableLength := uint64(binary.LittleEndian.Uint16(header[28:30])) +
				uint64(binary.LittleEndian.Uint16(header[30:32])) +
				uint64(binary.LittleEndian.Uint16(header[32:34]))
			entryLength := uint64(zipDirectoryHeaderLength) + variableLength
			if entryLength > uint64(remaining) {
				return 0, fmt.Errorf(
					"%w: central directory entry exceeds its range",
					errInvalidZIPDirectory,
				)
			}
			records++
			if records > uint64(maxEntries) {
				return 0, &limitError{
					code:   LimitMaxNodes,
					global: true,
				}
			}
			if err := ctx.Err(); err != nil {
				return 0, err
			}
			offset += int64(entryLength)
		case zipDirectoryDigitalSignature:
			if remaining < 6 {
				return 0, fmt.Errorf(
					"%w: truncated central directory signature record",
					errInvalidZIPDirectory,
				)
			}
			var length [2]byte
			if err := zipReadAt(ctx, reader, length[:], offset+4); err != nil {
				return 0, err
			}
			recordLength := int64(6 + binary.LittleEndian.Uint16(length[:]))
			if recordLength != remaining {
				return 0, fmt.Errorf(
					"%w: invalid central directory signature range",
					errInvalidZIPDirectory,
				)
			}
			offset += recordLength
		default:
			return 0, fmt.Errorf(
				"%w: unexpected central directory record",
				errInvalidZIPDirectory,
			)
		}
	}
	if offset != end {
		return 0, errInvalidZIPDirectory
	}
	return records, nil
}

func zipReadAt(
	ctx context.Context,
	reader io.ReaderAt,
	buffer []byte,
	offset int64,
) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if offset < 0 || offset > math.MaxInt64-int64(len(buffer)) {
		return errInvalidZIPDirectory
	}
	count, err := reader.ReadAt(buffer, offset)
	if count != len(buffer) {
		if err == nil {
			err = io.ErrUnexpectedEOF
		}
		return err
	}
	if err != nil {
		return err
	}
	return ctx.Err()
}

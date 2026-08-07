package extract

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"hash/crc32"
	"io"
	"math"
)

const (
	maxStreamDecoderMemoryBytes = uint64(64 << 20)
	// Each XZ Block constructs a fresh LZMA2 decoder and dictionary. A
	// separate Block count keeps tiny/empty Blocks from turning preflight
	// and decoder setup into an unbounded CPU/allocation loop. With at most
	// 1,024 records, even an Index using two maximum-length VLIs per record
	// is smaller than 32 KiB.
	maxXZBlocks = uint64(1_024)
	// A 10 GiB stream using 64 KiB chunks has 163,840 chunks. This
	// stream-wide ceiling leaves headroom while bounding the number of
	// context checks and ReaderAt calls across all Blocks.
	maxXZChunksPerStream             = uint64(262_144)
	maxXZIndexBytes                  = int64(32 << 10)
	maxXZTotalDecoderAllocationBytes = int64(256 << 20)
	xzStreamHeaderLength             = 12
	xzLZMA2FilterID                  = 0x21
)

var errInvalidXZStream = errors.New("invalid XZ stream")

type xzPreflightInfo struct {
	MaxDictionaryBytes          int64
	TotalDecoderAllocationBytes int64
	BlockCount                  uint64
	ChunkCount                  uint64
}

// preflightXZ prevents the decoder library from honoring an attacker-chosen
// multi-gigabyte LZMA2 dictionary. It walks the real LZMA2 chunk boundaries,
// so every block header the decoder can reach is checked before decoding.
// github.com/ulikunitz/xz constructs a new dictionary for every Block, so the
// cumulative allocation budget is checked as well as the per-Block peak.
func preflightXZ(
	ctx context.Context,
	reader io.ReaderAt,
	size int64,
) (xzPreflightInfo, error) {
	if ctx == nil {
		return xzPreflightInfo{},
			errors.New("extract: nil XZ preflight context")
	}
	if reader == nil || size < xzStreamHeaderLength {
		return xzPreflightInfo{}, errInvalidXZStream
	}
	var streamHeader [xzStreamHeaderLength]byte
	if err := xzReadAt(ctx, reader, size, streamHeader[:], 0); err != nil {
		return xzPreflightInfo{}, err
	}
	if !bytes.Equal(
		streamHeader[:6],
		[]byte{0xfd, '7', 'z', 'X', 'Z', 0},
	) ||
		streamHeader[6] != 0 ||
		crc32.ChecksumIEEE(streamHeader[6:8]) !=
			binary.LittleEndian.Uint32(streamHeader[8:12]) {
		return xzPreflightInfo{}, fmt.Errorf(
			"%w: invalid stream header",
			errInvalidXZStream,
		)
	}
	checkSize, ok := xzCheckSize(streamHeader[7])
	if !ok {
		return xzPreflightInfo{}, fmt.Errorf(
			"%w: unsupported check type",
			errInvalidXZStream,
		)
	}

	var info xzPreflightInfo
	offset := int64(xzStreamHeaderLength)
	unpaddedSizes := make([]uint64, 0, 16)
	for {
		if err := ctx.Err(); err != nil {
			return xzPreflightInfo{}, err
		}
		var first [1]byte
		if err := xzReadAt(ctx, reader, size, first[:], offset); err != nil {
			return xzPreflightInfo{}, err
		}
		if first[0] == 0 {
			if err := validateXZTail(
				ctx,
				reader,
				size,
				offset,
				streamHeader[7],
				unpaddedSizes,
			); err != nil {
				return xzPreflightInfo{}, err
			}
			return info, nil
		}
		if info.BlockCount >= maxXZBlocks {
			return xzPreflightInfo{},
				&limitError{code: LimitMaxArchiveMetadata}
		}
		headerLength := int64(int(first[0])+1) * 4
		if headerLength < 8 || headerLength > 1024 {
			return xzPreflightInfo{}, fmt.Errorf(
				"%w: invalid block header size",
				errInvalidXZStream,
			)
		}
		header := make([]byte, int(headerLength))
		header[0] = first[0]
		if err := xzReadAt(
			ctx,
			reader,
			size,
			header[1:],
			offset+1,
		); err != nil {
			return xzPreflightInfo{}, err
		}
		declaredCompressed, dictionarySize, err := parseXZBlockHeader(header)
		if err != nil {
			return xzPreflightInfo{}, err
		}
		if dictionarySize > maxStreamDecoderMemoryBytes {
			return xzPreflightInfo{},
				&limitError{code: LimitMaxDecoderMemory}
		}
		if dictionarySize >
			uint64(maxXZTotalDecoderAllocationBytes-
				info.TotalDecoderAllocationBytes) {
			return xzPreflightInfo{},
				&limitError{code: LimitMaxDecoderMemory}
		}
		dictionaryBytes := int64(dictionarySize)
		info.TotalDecoderAllocationBytes += dictionaryBytes
		if dictionaryBytes > info.MaxDictionaryBytes {
			info.MaxDictionaryBytes = dictionaryBytes
		}
		info.BlockCount++

		dataOffset := offset + headerLength
		compressedSize, blockChunks, err := scanXZLZMA2(
			ctx,
			reader,
			size,
			dataOffset,
			maxXZChunksPerStream-info.ChunkCount,
		)
		if err != nil {
			return xzPreflightInfo{}, err
		}
		info.ChunkCount += blockChunks
		if declaredCompressed >= 0 &&
			uint64(declaredCompressed) != uint64(compressedSize) {
			return xzPreflightInfo{}, fmt.Errorf(
				"%w: compressed block size mismatch",
				errInvalidXZStream,
			)
		}
		paddingSize := (4 - compressedSize%4) % 4
		if paddingSize > 0 {
			var padding [3]byte
			if err := xzReadAt(
				ctx,
				reader,
				size,
				padding[:paddingSize],
				dataOffset+compressedSize,
			); err != nil {
				return xzPreflightInfo{}, err
			}
			for _, value := range padding[:paddingSize] {
				if value != 0 {
					return xzPreflightInfo{}, fmt.Errorf(
						"%w: non-zero block padding",
						errInvalidXZStream,
					)
				}
			}
		}
		nextOffset := dataOffset + compressedSize + paddingSize
		if nextOffset < dataOffset ||
			int64(checkSize) > size-nextOffset {
			return xzPreflightInfo{}, fmt.Errorf(
				"%w: truncated block check",
				errInvalidXZStream,
			)
		}
		unpaddedSizes = append(
			unpaddedSizes,
			uint64(headerLength+compressedSize+int64(checkSize)),
		)
		offset = nextOffset + int64(checkSize)
	}
}

func validateXZTail(
	ctx context.Context,
	reader io.ReaderAt,
	size int64,
	indexOffset int64,
	checkType byte,
	unpaddedSizes []uint64,
) error {
	if indexOffset < 0 || indexOffset >= size {
		return fmt.Errorf("%w: missing Index", errInvalidXZStream)
	}
	index := &xzIndexReader{
		ctx: ctx,
		reader: bufio.NewReaderSize(
			io.NewSectionReader(reader, indexOffset, size-indexOffset),
			streamBufferSize,
		),
		crc: crc32.NewIEEE(),
	}
	indicator, err := index.readByte(true)
	if err != nil {
		return err
	}
	if indicator != 0 {
		return fmt.Errorf("%w: invalid Index indicator", errInvalidXZStream)
	}
	recordCount, err := index.readVLI()
	if err != nil {
		return err
	}
	if recordCount != uint64(len(unpaddedSizes)) {
		return fmt.Errorf("%w: Index record count mismatch", errInvalidXZStream)
	}
	for _, wantUnpadded := range unpaddedSizes {
		unpadded, readErr := index.readVLI()
		if readErr != nil {
			return readErr
		}
		if unpadded != wantUnpadded {
			return fmt.Errorf(
				"%w: Index block size mismatch",
				errInvalidXZStream,
			)
		}
		if _, readErr := index.readVLI(); readErr != nil {
			return readErr
		}
	}
	paddingSize := (4 - index.consumed%4) % 4
	for count := int64(0); count < paddingSize; count++ {
		value, readErr := index.readByte(true)
		if readErr != nil {
			return readErr
		}
		if value != 0 {
			return fmt.Errorf(
				"%w: invalid Index padding",
				errInvalidXZStream,
			)
		}
	}
	expectedCRC := index.crc.Sum32()
	var encodedCRC [4]byte
	if err := index.readFull(encodedCRC[:], false); err != nil {
		return err
	}
	if binary.LittleEndian.Uint32(encodedCRC[:]) != expectedCRC {
		return fmt.Errorf("%w: Index checksum mismatch", errInvalidXZStream)
	}
	indexSize := index.consumed
	var footer [12]byte
	if err := index.readFull(footer[:], false); err != nil {
		return fmt.Errorf("%w: truncated stream footer", errInvalidXZStream)
	}
	if !bytes.Equal(footer[10:12], []byte{'Y', 'Z'}) ||
		footer[8] != 0 ||
		footer[9] != checkType ||
		crc32.ChecksumIEEE(footer[4:10]) !=
			binary.LittleEndian.Uint32(footer[0:4]) ||
		(uint64(binary.LittleEndian.Uint32(footer[4:8]))+1)*4 !=
			uint64(indexSize) {
		return fmt.Errorf("%w: invalid stream footer", errInvalidXZStream)
	}
	if indexOffset+index.consumed != size {
		return fmt.Errorf(
			"%w: trailing or concatenated stream data",
			errInvalidXZStream,
		)
	}
	return ctx.Err()
}

type xzIndexReader struct {
	ctx      context.Context
	reader   *bufio.Reader
	crc      hash.Hash32
	consumed int64
}

func (reader *xzIndexReader) readByte(includeInCRC bool) (byte, error) {
	if err := reader.ctx.Err(); err != nil {
		return 0, err
	}
	if reader.consumed >= maxXZIndexBytes {
		return 0, &limitError{code: LimitMaxArchiveMetadata}
	}
	value, err := reader.reader.ReadByte()
	if err != nil {
		return 0, err
	}
	reader.consumed++
	if includeInCRC {
		_, _ = reader.crc.Write([]byte{value})
	}
	return value, reader.ctx.Err()
}

func (reader *xzIndexReader) readFull(
	buffer []byte,
	includeInCRC bool,
) error {
	for index := range buffer {
		value, err := reader.readByte(includeInCRC)
		if err != nil {
			return err
		}
		buffer[index] = value
	}
	return nil
}

func (reader *xzIndexReader) readVLI() (uint64, error) {
	var value uint64
	for shift := uint(0); shift < 63; shift += 7 {
		current, err := reader.readByte(true)
		if err != nil {
			return 0, err
		}
		value |= uint64(current&0x7f) << shift
		if current&0x80 == 0 {
			return value, nil
		}
	}
	return 0, fmt.Errorf("%w: Index VLI overflow", errInvalidXZStream)
}

func parseXZBlockHeader(header []byte) (
	compressedSize int64,
	dictionarySize uint64,
	err error,
) {
	if len(header) < 8 || len(header)%4 != 0 ||
		(int(header[0])+1)*4 != len(header) {
		return 0, 0, fmt.Errorf(
			"%w: invalid block header length",
			errInvalidXZStream,
		)
	}
	contentEnd := len(header) - 4
	if crc32.ChecksumIEEE(header[:contentEnd]) !=
		binary.LittleEndian.Uint32(header[contentEnd:]) {
		return 0, 0, fmt.Errorf(
			"%w: block header checksum mismatch",
			errInvalidXZStream,
		)
	}
	flags := header[1]
	if flags&0x3c != 0 || flags&0x03 != 0 {
		return 0, 0, fmt.Errorf(
			"%w: unsupported block flags",
			errInvalidXZStream,
		)
	}
	cursor := 2
	compressedSize = -1
	if flags&0x40 != 0 {
		value, readErr := readXZVLI(header, &cursor, contentEnd)
		if readErr != nil || value > math.MaxInt64 {
			return 0, 0, fmt.Errorf(
				"%w: invalid compressed size",
				errInvalidXZStream,
			)
		}
		compressedSize = int64(value)
	}
	if flags&0x80 != 0 {
		value, readErr := readXZVLI(header, &cursor, contentEnd)
		if readErr != nil || value > math.MaxInt64 {
			return 0, 0, fmt.Errorf(
				"%w: invalid uncompressed size",
				errInvalidXZStream,
			)
		}
	}
	filterID, err := readXZVLI(header, &cursor, contentEnd)
	if err != nil || filterID != xzLZMA2FilterID {
		return 0, 0, fmt.Errorf(
			"%w: unsupported block filter",
			errInvalidXZStream,
		)
	}
	propertiesLength, err := readXZVLI(header, &cursor, contentEnd)
	if err != nil || propertiesLength != 1 || cursor >= contentEnd {
		return 0, 0, fmt.Errorf(
			"%w: invalid LZMA2 properties",
			errInvalidXZStream,
		)
	}
	dictionarySize, err = xzDictionarySize(header[cursor])
	if err != nil {
		return 0, 0, err
	}
	cursor++
	for _, value := range header[cursor:contentEnd] {
		if value != 0 {
			return 0, 0, fmt.Errorf(
				"%w: non-zero block header padding",
				errInvalidXZStream,
			)
		}
	}
	return compressedSize, dictionarySize, nil
}

func scanXZLZMA2(
	ctx context.Context,
	reader io.ReaderAt,
	size int64,
	offset int64,
	remainingChunks uint64,
) (int64, uint64, error) {
	start := offset
	var chunks uint64
	for {
		if err := ctx.Err(); err != nil {
			return 0, 0, err
		}
		var control [1]byte
		if err := xzReadAt(ctx, reader, size, control[:], offset); err != nil {
			return 0, 0, err
		}
		if control[0] == 0 {
			return offset + 1 - start, chunks, nil
		}
		if chunks >= remainingChunks {
			return 0, 0, &limitError{code: LimitMaxArchiveMetadata}
		}
		chunks++
		headerLength := 0
		payloadSize := int64(0)
		switch {
		case control[0] == 1 || control[0] == 2:
			headerLength = 3
			var header [3]byte
			header[0] = control[0]
			if err := xzReadAt(
				ctx,
				reader,
				size,
				header[1:],
				offset+1,
			); err != nil {
				return 0, 0, err
			}
			payloadSize = int64(binary.BigEndian.Uint16(header[1:3])) + 1
		case control[0]&0x80 != 0:
			headerLength = 5
			if control[0]&0x40 != 0 {
				headerLength = 6
			}
			var header [6]byte
			header[0] = control[0]
			if err := xzReadAt(
				ctx,
				reader,
				size,
				header[1:headerLength],
				offset+1,
			); err != nil {
				return 0, 0, err
			}
			payloadSize = int64(binary.BigEndian.Uint16(header[3:5])) + 1
		default:
			return 0, 0, fmt.Errorf(
				"%w: invalid LZMA2 chunk control",
				errInvalidXZStream,
			)
		}
		nextOffset := offset + int64(headerLength) + payloadSize
		if nextOffset < offset || nextOffset > size {
			return 0, 0, fmt.Errorf(
				"%w: LZMA2 chunk exceeds source range",
				errInvalidXZStream,
			)
		}
		offset = nextOffset
	}
}

func readXZVLI(data []byte, cursor *int, end int) (uint64, error) {
	if cursor == nil || *cursor < 0 || end > len(data) || *cursor >= end {
		return 0, errInvalidXZStream
	}
	var value uint64
	for shift := uint(0); shift < 63; shift += 7 {
		if *cursor >= end {
			return 0, io.ErrUnexpectedEOF
		}
		current := data[*cursor]
		(*cursor)++
		value |= uint64(current&0x7f) << shift
		if current&0x80 == 0 {
			return value, nil
		}
	}
	return 0, fmt.Errorf("%w: VLI overflow", errInvalidXZStream)
}

func xzDictionarySize(property byte) (uint64, error) {
	if property > 40 {
		return 0, fmt.Errorf(
			"%w: invalid LZMA2 dictionary property",
			errInvalidXZStream,
		)
	}
	if property == 40 {
		return math.MaxUint32, nil
	}
	return uint64(2|property&1) << (uint(property/2) + 11), nil
}

func xzCheckSize(flag byte) (int, bool) {
	switch flag {
	case 0:
		return 0, true
	case 1:
		return 4, true
	case 4:
		return 8, true
	case 10:
		return 32, true
	default:
		return 0, false
	}
}

func xzReadAt(
	ctx context.Context,
	reader io.ReaderAt,
	size int64,
	buffer []byte,
	offset int64,
) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if offset < 0 || size < 0 || offset > size ||
		int64(len(buffer)) > size-offset {
		return fmt.Errorf("%w: read outside source range", errInvalidXZStream)
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

// Package diskimage parses disk partition tables without mounting the image or
// attaching it to a host loop device.
package diskimage

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"math"
	"sort"
	"strings"
	"unicode/utf16"
)

const (
	defaultMaxPartitions = 1024
	defaultMaxEBRDepth   = 128
	maxGPTEntryBytes     = 64 << 20
)

var (
	ErrInvalidInput = errors.New("diskimage: invalid input")
	ErrCorruptTable = errors.New("diskimage: corrupt partition table")
	ErrLimit        = errors.New("diskimage: partition limit reached")
)

type TableKind string

const (
	TableRaw TableKind = "raw"
	TableMBR TableKind = "mbr"
	TableGPT TableKind = "gpt"
)

type Options struct {
	MaxPartitions int
	MaxEBRDepth   int
}

type Partition struct {
	Index       int
	Table       TableKind
	Type        string
	Name        string
	StartLBA    uint64
	EndLBA      uint64
	OffsetBytes int64
	SizeBytes   int64
	Bootable    bool
	Logical     bool
}

type Diagnostic struct {
	Code    string
	Message string
	Index   int
}

type Result struct {
	Table       TableKind
	SectorSize  uint64
	Partitions  []Partition
	Partial     bool
	Diagnostics []Diagnostic
}

func Parse(
	ctx context.Context,
	reader io.ReaderAt,
	size int64,
	options Options,
) (Result, error) {
	if ctx == nil || reader == nil || size <= 0 {
		return Result{}, ErrInvalidInput
	}
	if options.MaxPartitions <= 0 || options.MaxPartitions > defaultMaxPartitions {
		options.MaxPartitions = defaultMaxPartitions
	}
	if options.MaxEBRDepth <= 0 || options.MaxEBRDepth > defaultMaxEBRDepth {
		options.MaxEBRDepth = defaultMaxEBRDepth
	}
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}

	var gptError error
	for _, sectorSize := range []uint64{512, 4096} {
		result, found, err := parseGPT(ctx, reader, size, sectorSize, options)
		if err != nil {
			if errors.Is(err, errGPTNotPresent) {
				continue
			}
			if gptError == nil {
				gptError = err
			}
			continue
		}
		if found {
			return result, nil
		}
	}
	if gptError != nil {
		return Result{}, gptError
	}

	sector, err := readBytes(reader, size, 0, 512)
	if err != nil || !bytes.Equal(sector[510:512], []byte{0x55, 0xaa}) {
		return rawResult(size), nil
	}
	return parseMBR(ctx, reader, size, sector, options)
}

func rawResult(size int64) Result {
	return Result{
		Table: TableRaw,
		Partitions: []Partition{{
			Index: 1, Table: TableRaw, Type: "raw",
			OffsetBytes: 0, SizeBytes: size,
		}},
	}
}

var errGPTNotPresent = errors.New("gpt header not present")

type gptHeader struct {
	currentLBA      uint64
	backupLBA       uint64
	firstUsable     uint64
	lastUsable      uint64
	diskGUID        [16]byte
	entryLBA        uint64
	entryCount      uint32
	entrySize       uint32
	entryArrayCRC32 uint32
}

func parseGPT(
	ctx context.Context,
	reader io.ReaderAt,
	size int64,
	sectorSize uint64,
	options Options,
) (Result, bool, error) {
	if uint64(size) < sectorSize*2 {
		return Result{}, false, errGPTNotPresent
	}
	header, err := readGPTHeader(reader, size, sectorSize, 1)
	if err != nil {
		return Result{}, false, err
	}
	if header == nil {
		return Result{}, false, errGPTNotPresent
	}
	totalSectors := uint64(size) / sectorSize
	if header.currentLBA != 1 || header.backupLBA >= totalSectors ||
		header.firstUsable > header.lastUsable ||
		header.lastUsable >= totalSectors || header.entryLBA < 2 {
		return Result{}, false, ErrCorruptTable
	}
	entryBytes := uint64(header.entryCount) * uint64(header.entrySize)
	if header.entryCount == 0 || int(header.entryCount) > options.MaxPartitions ||
		header.entrySize < 128 || header.entrySize > 4096 ||
		header.entrySize%8 != 0 || entryBytes > maxGPTEntryBytes {
		return Result{}, false, ErrLimit
	}
	entrySectors := (entryBytes + sectorSize - 1) / sectorSize
	if entrySectors == 0 || header.entryLBA > math.MaxUint64-entrySectors ||
		header.entryLBA+entrySectors > header.firstUsable {
		return Result{}, false, ErrCorruptTable
	}
	backup, err := readGPTHeader(
		reader, size, sectorSize, header.backupLBA,
	)
	if err != nil || backup == nil ||
		backup.currentLBA != header.backupLBA || backup.backupLBA != 1 ||
		backup.firstUsable != header.firstUsable ||
		backup.lastUsable != header.lastUsable ||
		backup.diskGUID != header.diskGUID ||
		backup.entryCount != header.entryCount ||
		backup.entrySize != header.entrySize ||
		backup.entryArrayCRC32 != header.entryArrayCRC32 ||
		backup.entryLBA <= backup.lastUsable ||
		backup.entryLBA > math.MaxUint64-entrySectors ||
		backup.entryLBA+entrySectors > backup.currentLBA {
		return Result{}, false, ErrCorruptTable
	}
	entryOffset, ok := byteRange(header.entryLBA, sectorSize, entryBytes, size)
	if !ok {
		return Result{}, false, ErrCorruptTable
	}
	backupEntryOffset, ok := byteRange(
		backup.entryLBA, sectorSize, entryBytes, size,
	)
	if !ok {
		return Result{}, false, ErrCorruptTable
	}
	checksum, err := sectionCRC32(ctx, reader, entryOffset, int64(entryBytes))
	if err != nil {
		return Result{}, false, err
	}
	if checksum != header.entryArrayCRC32 {
		return Result{}, false, ErrCorruptTable
	}
	backupChecksum, err := sectionCRC32(
		ctx, reader, backupEntryOffset, int64(entryBytes),
	)
	if err != nil {
		return Result{}, false, err
	}
	if backupChecksum != header.entryArrayCRC32 {
		return Result{}, false, ErrCorruptTable
	}

	result := Result{Table: TableGPT, SectorSize: sectorSize}
	for index := uint32(0); index < header.entryCount; index++ {
		if err := ctx.Err(); err != nil {
			return Result{}, false, err
		}
		offset := entryOffset + int64(uint64(index)*uint64(header.entrySize))
		entry, err := readBytes(reader, size, offset, int(header.entrySize))
		if err != nil {
			return Result{}, false, ErrCorruptTable
		}
		if allZero(entry[:16]) {
			continue
		}
		first := binary.LittleEndian.Uint64(entry[32:40])
		last := binary.LittleEndian.Uint64(entry[40:48])
		if first < header.firstUsable || last > header.lastUsable || last < first {
			result.addDiagnostic(
				"invalid_gpt_partition", "GPT partition range is invalid", int(index+1),
			)
			continue
		}
		partitionOffset, partitionSize, ok := lbaRange(first, last, sectorSize, size)
		if !ok {
			result.addDiagnostic(
				"gpt_partition_out_of_bounds", "GPT partition exceeds the image", int(index+1),
			)
			continue
		}
		result.Partitions = append(result.Partitions, Partition{
			Index: int(index + 1), Table: TableGPT,
			Type: guidString(entry[:16]), Name: decodeGPTName(entry[56:]),
			StartLBA: first, EndLBA: last,
			OffsetBytes: partitionOffset, SizeBytes: partitionSize,
		})
	}
	result.rejectOverlaps()
	if len(result.Partitions) == 0 {
		return Result{}, false, ErrCorruptTable
	}
	return result, true, nil
}

func readGPTHeader(
	reader io.ReaderAt,
	size int64,
	sectorSize uint64,
	lba uint64,
) (*gptHeader, error) {
	offset, ok := multiplyToInt64(lba, sectorSize)
	if !ok || offset > size-92 {
		return nil, nil
	}
	fixed, err := readBytes(reader, size, offset, 92)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(fixed[:8], []byte("EFI PART")) {
		return nil, nil
	}
	headerSize := binary.LittleEndian.Uint32(fixed[12:16])
	if binary.LittleEndian.Uint32(fixed[8:12]) != 0x00010000 ||
		headerSize < 92 || uint64(headerSize) > sectorSize {
		return nil, ErrCorruptTable
	}
	raw, err := readBytes(reader, size, offset, int(headerSize))
	if err != nil {
		return nil, ErrCorruptTable
	}
	expected := binary.LittleEndian.Uint32(raw[16:20])
	copyForCRC := append([]byte(nil), raw...)
	clear(copyForCRC[16:20])
	if crc32.ChecksumIEEE(copyForCRC) != expected {
		return nil, ErrCorruptTable
	}
	value := &gptHeader{
		currentLBA:      binary.LittleEndian.Uint64(raw[24:32]),
		backupLBA:       binary.LittleEndian.Uint64(raw[32:40]),
		firstUsable:     binary.LittleEndian.Uint64(raw[40:48]),
		lastUsable:      binary.LittleEndian.Uint64(raw[48:56]),
		entryLBA:        binary.LittleEndian.Uint64(raw[72:80]),
		entryCount:      binary.LittleEndian.Uint32(raw[80:84]),
		entrySize:       binary.LittleEndian.Uint32(raw[84:88]),
		entryArrayCRC32: binary.LittleEndian.Uint32(raw[88:92]),
	}
	copy(value.diskGUID[:], raw[56:72])
	return value, nil
}

func parseMBR(
	ctx context.Context,
	reader io.ReaderAt,
	size int64,
	mbr []byte,
	options Options,
) (Result, error) {
	sectorSize := detectMBRSectorSize(reader, size, mbr)
	result := Result{Table: TableMBR, SectorSize: sectorSize}
	validEntries := 0
	for slot := 0; slot < 4; slot++ {
		entry := mbr[446+slot*16 : 446+(slot+1)*16]
		boot, kind, start, sectors, valid := decodeMBREntry(entry)
		if !valid {
			result.addDiagnostic(
				"invalid_mbr_partition", "MBR partition entry is invalid", slot+1,
			)
			continue
		}
		if kind == 0 {
			continue
		}
		validEntries++
		if isExtendedType(kind) {
			remainingPartitions := options.MaxPartitions - len(result.Partitions)
			if remainingPartitions <= 0 {
				result.addDiagnostic(
					"partition_limit",
					"partition parsing stopped at the configured limit",
					slot+1,
				)
				result.rejectOverlaps()
				return result, ErrLimit
			}
			chainOptions := options
			chainOptions.MaxPartitions = remainingPartitions
			logical, diagnostics, err := parseEBRChain(
				ctx, reader, size, sectorSize, start, sectors,
				len(result.Partitions)+1, chainOptions,
			)
			result.Partitions = append(result.Partitions, logical...)
			for _, diagnostic := range diagnostics {
				result.addDiagnostic(diagnostic.Code, diagnostic.Message, diagnostic.Index)
			}
			if err != nil {
				if errors.Is(err, ErrLimit) {
					result.addDiagnostic(
						"partition_limit",
						"partition parsing stopped at the configured limit",
						len(result.Partitions)+1,
					)
					result.rejectOverlaps()
					return result, err
				}
				return result, err
			}
			continue
		}
		partition, ok := mbrPartition(
			len(result.Partitions)+1, kind, start, sectors,
			sectorSize, size, boot, false,
		)
		if !ok {
			result.addDiagnostic(
				"mbr_partition_out_of_bounds", "MBR partition exceeds the image", slot+1,
			)
			continue
		}
		if len(result.Partitions) >= options.MaxPartitions {
			result.addDiagnostic(
				"partition_limit",
				"partition parsing stopped at the configured limit",
				slot+1,
			)
			result.rejectOverlaps()
			return result, ErrLimit
		}
		result.Partitions = append(result.Partitions, partition)
	}
	if validEntries == 0 || len(result.Partitions) == 0 {
		return Result{}, ErrCorruptTable
	}
	result.rejectOverlaps()
	if len(result.Partitions) == 0 {
		return Result{}, ErrCorruptTable
	}
	return result, nil
}

func parseEBRChain(
	ctx context.Context,
	reader io.ReaderAt,
	size int64,
	sectorSize uint64,
	base uint64,
	containerSectors uint64,
	firstIndex int,
	options Options,
) ([]Partition, []Diagnostic, error) {
	if containerSectors == 0 || base > math.MaxUint64-containerSectors {
		return nil, []Diagnostic{{
			Code: "invalid_extended_partition", Message: "extended partition range is invalid",
			Index: firstIndex,
		}}, nil
	}
	containerEnd := base + containerSectors - 1
	visited := make(map[uint64]struct{})
	currentRelative := uint64(0)
	partitions := make([]Partition, 0)
	diagnostics := make([]Diagnostic, 0)
	for depth := 0; depth < options.MaxEBRDepth; depth++ {
		if err := ctx.Err(); err != nil {
			return partitions, diagnostics, err
		}
		current := base + currentRelative
		if current < base || current > containerEnd {
			diagnostics = append(diagnostics, Diagnostic{
				Code: "ebr_out_of_bounds", Message: "EBR lies outside its extended partition",
				Index: firstIndex + len(partitions),
			})
			break
		}
		if _, duplicate := visited[current]; duplicate {
			diagnostics = append(diagnostics, Diagnostic{
				Code: "ebr_cycle", Message: "EBR chain contains a cycle",
				Index: firstIndex + len(partitions),
			})
			break
		}
		visited[current] = struct{}{}
		offset, ok := multiplyToInt64(current, sectorSize)
		if !ok || offset > size-512 {
			diagnostics = append(diagnostics, Diagnostic{
				Code: "ebr_out_of_bounds", Message: "EBR exceeds the image",
				Index: firstIndex + len(partitions),
			})
			break
		}
		raw, err := readBytes(reader, size, offset, 512)
		if err != nil || !bytes.Equal(raw[510:512], []byte{0x55, 0xaa}) {
			diagnostics = append(diagnostics, Diagnostic{
				Code: "invalid_ebr", Message: "EBR signature is invalid",
				Index: firstIndex + len(partitions),
			})
			break
		}
		boot, kind, relativeStart, sectors, valid := decodeMBREntry(raw[446:462])
		if valid && kind != 0 && !isExtendedType(kind) {
			start := current + relativeStart
			partition, accepted := mbrPartition(
				firstIndex+len(partitions), kind, start, sectors,
				sectorSize, size, boot, true,
			)
			if accepted && start >= base && partition.EndLBA <= containerEnd {
				if len(partitions) >= options.MaxPartitions {
					return partitions, diagnostics, ErrLimit
				}
				partitions = append(partitions, partition)
			} else {
				diagnostics = append(diagnostics, Diagnostic{
					Code:    "logical_partition_out_of_bounds",
					Message: "logical partition exceeds its extended partition",
					Index:   firstIndex + len(partitions),
				})
			}
		} else if kind != 0 || relativeStart != 0 || sectors != 0 {
			diagnostics = append(diagnostics, Diagnostic{
				Code: "invalid_logical_partition", Message: "logical partition entry is invalid",
				Index: firstIndex + len(partitions),
			})
		}
		_, nextKind, nextRelative, nextSectors, nextValid := decodeMBREntry(raw[462:478])
		if nextKind == 0 && nextRelative == 0 && nextSectors == 0 {
			return partitions, diagnostics, nil
		}
		if !nextValid || !isExtendedType(nextKind) || nextSectors == 0 {
			diagnostics = append(diagnostics, Diagnostic{
				Code: "invalid_ebr_link", Message: "EBR link entry is invalid",
				Index: firstIndex + len(partitions),
			})
			return partitions, diagnostics, nil
		}
		currentRelative = nextRelative
	}
	if len(visited) >= options.MaxEBRDepth {
		diagnostics = append(diagnostics, Diagnostic{
			Code: "ebr_depth_limit", Message: "EBR chain exceeds the configured limit",
			Index: firstIndex + len(partitions),
		})
	}
	return partitions, diagnostics, nil
}

func decodeMBREntry(entry []byte) (
	bootable bool,
	kind byte,
	start uint64,
	sectors uint64,
	valid bool,
) {
	if len(entry) != 16 {
		return false, 0, 0, 0, false
	}
	if entry[0] != 0 && entry[0] != 0x80 {
		return false, entry[4], uint64(binary.LittleEndian.Uint32(entry[8:12])),
			uint64(binary.LittleEndian.Uint32(entry[12:16])), false
	}
	kind = entry[4]
	start = uint64(binary.LittleEndian.Uint32(entry[8:12]))
	sectors = uint64(binary.LittleEndian.Uint32(entry[12:16]))
	if kind == 0 {
		return false, kind, start, sectors, start == 0 && sectors == 0
	}
	return entry[0] == 0x80, kind, start, sectors, start > 0 && sectors > 0
}

func mbrPartition(
	index int,
	kind byte,
	start uint64,
	sectors uint64,
	sectorSize uint64,
	size int64,
	bootable bool,
	logical bool,
) (Partition, bool) {
	if sectors == 0 || start > math.MaxUint64-(sectors-1) {
		return Partition{}, false
	}
	end := start + sectors - 1
	offset, partitionSize, ok := lbaRange(start, end, sectorSize, size)
	if !ok {
		return Partition{}, false
	}
	return Partition{
		Index: index, Table: TableMBR, Type: fmt.Sprintf("0x%02x", kind),
		StartLBA: start, EndLBA: end,
		OffsetBytes: offset, SizeBytes: partitionSize,
		Bootable: bootable, Logical: logical,
	}, true
}

func detectMBRSectorSize(reader io.ReaderAt, size int64, mbr []byte) uint64 {
	bestSector := uint64(512)
	bestScore := -1
	for _, sectorSize := range []uint64{512, 4096} {
		score := 0
		valid := true
		for slot := 0; slot < 4; slot++ {
			_, kind, start, sectors, entryValid := decodeMBREntry(
				mbr[446+slot*16 : 446+(slot+1)*16],
			)
			if !entryValid {
				valid = false
				break
			}
			if kind == 0 || isExtendedType(kind) {
				continue
			}
			if _, _, ok := lbaRange(start, start+sectors-1, sectorSize, size); !ok {
				valid = false
				break
			}
			offset, ok := multiplyToInt64(start, sectorSize)
			if ok {
				score += filesystemSignatureScore(reader, size, offset)
			}
		}
		if valid && score > bestScore {
			bestSector, bestScore = sectorSize, score
		}
	}
	return bestSector
}

func filesystemSignatureScore(reader io.ReaderAt, size int64, offset int64) int {
	score := 0
	if magic, err := readBytes(reader, size, offset+1024+0x38, 2); err == nil &&
		bytes.Equal(magic, []byte{0x53, 0xef}) {
		score += 4
	}
	if magic, err := readBytes(reader, size, offset, 4); err == nil &&
		(bytes.Equal(magic, []byte("hsqs")) || bytes.Equal(magic, []byte("sqsh"))) {
		score += 4
	}
	if magic, err := readBytes(reader, size, offset+3, 8); err == nil &&
		bytes.Equal(magic, []byte("NTFS    ")) {
		score += 3
	}
	if magic, err := readBytes(reader, size, offset+16*2048+1, 5); err == nil &&
		bytes.Equal(magic, []byte("CD001")) {
		score += 4
	}
	return score
}

func (result *Result) addDiagnostic(code string, message string, index int) {
	result.Partial = true
	result.Diagnostics = append(result.Diagnostics, Diagnostic{
		Code: code, Message: message, Index: index,
	})
}

func (result *Result) rejectOverlaps() {
	type indexedPartition struct {
		partition Partition
		order     int
	}
	ordered := make([]indexedPartition, len(result.Partitions))
	for index, partition := range result.Partitions {
		ordered[index] = indexedPartition{partition: partition, order: index}
	}
	sort.SliceStable(ordered, func(left int, right int) bool {
		if ordered[left].partition.OffsetBytes == ordered[right].partition.OffsetBytes {
			return ordered[left].partition.SizeBytes < ordered[right].partition.SizeBytes
		}
		return ordered[left].partition.OffsetBytes < ordered[right].partition.OffsetBytes
	})
	rejected := make(map[int]struct{})
	var previousEnd int64 = -1
	for _, candidate := range ordered {
		if candidate.partition.OffsetBytes < previousEnd {
			rejected[candidate.order] = struct{}{}
			result.addDiagnostic(
				"overlapping_partition", "partition overlaps an earlier accepted partition",
				candidate.partition.Index,
			)
			continue
		}
		previousEnd = candidate.partition.OffsetBytes + candidate.partition.SizeBytes
	}
	if len(rejected) == 0 {
		return
	}
	kept := result.Partitions[:0]
	for index, partition := range result.Partitions {
		if _, found := rejected[index]; !found {
			kept = append(kept, partition)
		}
	}
	result.Partitions = kept
}

func readBytes(reader io.ReaderAt, size int64, offset int64, length int) ([]byte, error) {
	if offset < 0 || length < 0 || int64(length) > size || offset > size-int64(length) {
		return nil, io.ErrUnexpectedEOF
	}
	value := make([]byte, length)
	read, err := reader.ReadAt(value, offset)
	if err != nil && !(errors.Is(err, io.EOF) && read == length) {
		return nil, err
	}
	if read != length {
		return nil, io.ErrUnexpectedEOF
	}
	return value, nil
}

func sectionCRC32(
	ctx context.Context,
	reader io.ReaderAt,
	offset int64,
	length int64,
) (uint32, error) {
	hash := crc32.NewIEEE()
	section := io.NewSectionReader(reader, offset, length)
	buffer := make([]byte, 64<<10)
	for {
		if err := ctx.Err(); err != nil {
			return 0, err
		}
		read, err := section.Read(buffer)
		if read > 0 {
			_, _ = hash.Write(buffer[:read])
		}
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return 0, err
		}
	}
	return hash.Sum32(), nil
}

func byteRange(lba uint64, sectorSize uint64, length uint64, size int64) (int64, bool) {
	offset, ok := multiplyToInt64(lba, sectorSize)
	if !ok || length > math.MaxInt64 || offset > size-int64(length) {
		return 0, false
	}
	return offset, true
}

func lbaRange(
	first uint64,
	last uint64,
	sectorSize uint64,
	size int64,
) (int64, int64, bool) {
	if last < first || last == math.MaxUint64 {
		return 0, 0, false
	}
	offset, ok := multiplyToInt64(first, sectorSize)
	if !ok {
		return 0, 0, false
	}
	sectors := last - first + 1
	length, ok := multiplyToInt64(sectors, sectorSize)
	if !ok || offset > size-length {
		return 0, 0, false
	}
	return offset, length, true
}

func multiplyToInt64(left uint64, right uint64) (int64, bool) {
	if right != 0 && left > math.MaxUint64/right {
		return 0, false
	}
	value := left * right
	if value > math.MaxInt64 {
		return 0, false
	}
	return int64(value), true
}

func isExtendedType(kind byte) bool {
	return kind == 0x05 || kind == 0x0f || kind == 0x85
}

func allZero(value []byte) bool {
	for _, current := range value {
		if current != 0 {
			return false
		}
	}
	return true
}

func guidString(raw []byte) string {
	if len(raw) < 16 {
		return ""
	}
	return fmt.Sprintf(
		"%08x-%04x-%04x-%02x%02x-%012x",
		binary.LittleEndian.Uint32(raw[0:4]),
		binary.LittleEndian.Uint16(raw[4:6]),
		binary.LittleEndian.Uint16(raw[6:8]),
		raw[8], raw[9], raw[10:16],
	)
}

func decodeGPTName(raw []byte) string {
	units := make([]uint16, 0, len(raw)/2)
	for index := 0; index+1 < len(raw); index += 2 {
		value := binary.LittleEndian.Uint16(raw[index : index+2])
		if value == 0 {
			break
		}
		units = append(units, value)
	}
	return strings.ToValidUTF8(string(utf16.Decode(units)), "\ufffd")
}

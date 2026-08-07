package filetype

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"hash/crc32"
	"path"
	"strconv"
	"strings"
)

const (
	maxArchiveEntries = 100_000
	maxDirectoryBytes = int64(8 << 20)
	maxEmptyTARBytes  = int64(1 << 20)
)

var (
	errZIPMultiVolume        = errors.New("multi-volume ZIP archive")
	errZIPDeferredValidation = errors.New(
		"ZIP central directory validation deferred",
	)
)

func detectZIP(reader *boundedReader) (Result, bool, error) {
	magic, ok, err := reader.readAt(0, 4)
	if err != nil || !ok {
		return Result{}, false, err
	}
	signature := binary.LittleEndian.Uint32(magic)
	if signature != 0x04034b50 && signature != 0x06054b50 && signature != 0x08074b50 {
		_, _, _, _, endErr := zipDirectory(reader)
		if errors.Is(endErr, errZIPMultiVolume) {
			return result(
				"zip",
				"application/zip",
				"",
				map[string]any{
					"classification_limited": true,
					"multi_volume":           true,
				},
			), true, nil
		}
		return Result{}, false, nil
	}
	directoryOffset, directorySize, entries, valid, err := zipDirectory(reader)
	if errors.Is(err, errZIPMultiVolume) {
		return result(
			"zip",
			"application/zip",
			"",
			map[string]any{
				"classification_limited": true,
				"multi_volume":           true,
			},
		), true, nil
	}
	if errors.Is(err, errZIPDeferredValidation) {
		return result(
			"zip",
			"application/zip",
			"",
			map[string]any{
				"classification_limited": true,
				"metadata_validation":    "deferred_to_extractor",
			},
		), true, nil
	}
	if err != nil || !valid {
		return Result{}, false, err
	}
	metadata := map[string]any{"entries": entries}
	if entries == 0 {
		return result("zip", "application/zip", "", metadata), true, nil
	}
	if entries > maxArchiveEntries || directorySize > maxDirectoryBytes {
		metadata["classification_limited"] = true
		return result("zip", "application/zip", "", metadata), true, nil
	}
	directory, ok, err := reader.readAt(directoryOffset, directorySize)
	if err != nil || !ok {
		return Result{}, false, err
	}
	names, valid, err := zipEntryNames(reader, directory, entries)
	if err != nil {
		return Result{}, false, err
	}
	if !valid {
		return Result{}, false, nil
	}
	format, mime := classifyZIP(names)
	return result(format, mime, "", metadata), true, nil
}

func zipDirectory(reader *boundedReader) (offset, length int64, entries uint64, valid bool, err error) {
	tailSize := reader.size
	if tailSize > 65_557 {
		tailSize = 65_557
	}
	tail, ok, err := reader.readAt(reader.size-tailSize, tailSize)
	if err != nil || !ok {
		return 0, 0, 0, false, err
	}
	index := bytes.LastIndex(tail, []byte{'P', 'K', 0x05, 0x06})
	if index < 0 || index+22 > len(tail) {
		return 0, 0, 0, false, nil
	}
	eocd := tail[index:]
	commentLength := int(binary.LittleEndian.Uint16(eocd[20:22]))
	if index+22+commentLength != len(tail) {
		return 0, 0, 0, false, nil
	}
	if binary.LittleEndian.Uint16(eocd[4:6]) != 0 ||
		binary.LittleEndian.Uint16(eocd[6:8]) != 0 {
		return 0, 0, 0, false, errZIPMultiVolume
	}
	entries = uint64(binary.LittleEndian.Uint16(eocd[10:12]))
	if binary.LittleEndian.Uint16(eocd[8:10]) != uint16(entries) {
		return 0, 0, 0, false, errZIPDeferredValidation
	}
	length64 := uint64(binary.LittleEndian.Uint32(eocd[12:16]))
	offset64 := uint64(binary.LittleEndian.Uint32(eocd[16:20]))
	if entries == 0xffff || length64 == 0xffffffff || offset64 == 0xffffffff {
		eocdOffset := reader.size - tailSize + int64(index)
		if eocdOffset < 20 {
			return 0, 0, 0, false, nil
		}
		locator, ok, readErr := reader.readAt(eocdOffset-20, 20)
		if readErr != nil || !ok {
			return 0, 0, 0, false, readErr
		}
		if binary.LittleEndian.Uint32(locator[:4]) != 0x07064b50 {
			return 0, 0, 0, false, nil
		}
		if binary.LittleEndian.Uint32(locator[4:8]) != 0 ||
			binary.LittleEndian.Uint32(locator[16:20]) != 1 {
			return 0, 0, 0, false, errZIPMultiVolume
		}
		zip64Offset := binary.LittleEndian.Uint64(locator[8:16])
		if zip64Offset > uint64(reader.size) {
			return 0, 0, 0, false, nil
		}
		record, ok, readErr := reader.readAt(int64(zip64Offset), 56)
		if readErr != nil || !ok {
			return 0, 0, 0, false, readErr
		}
		if binary.LittleEndian.Uint32(record[:4]) != 0x06064b50 ||
			binary.LittleEndian.Uint64(record[4:12]) < 44 {
			return 0, 0, 0, false, nil
		}
		if binary.LittleEndian.Uint32(record[16:20]) != 0 ||
			binary.LittleEndian.Uint32(record[20:24]) != 0 {
			return 0, 0, 0, false, errZIPMultiVolume
		}
		entries = binary.LittleEndian.Uint64(record[32:40])
		if binary.LittleEndian.Uint64(record[24:32]) != entries {
			return 0, 0, 0, false, errZIPDeferredValidation
		}
		length64 = binary.LittleEndian.Uint64(record[40:48])
		offset64 = binary.LittleEndian.Uint64(record[48:56])
	}
	if offset64 > uint64(reader.size) || length64 > uint64(reader.size)-offset64 {
		return 0, 0, 0, false, nil
	}
	return int64(offset64), int64(length64), entries, true, nil
}

func zipEntryNames(
	reader *boundedReader,
	directory []byte,
	expected uint64,
) (map[string]bool, bool, error) {
	names := make(map[string]bool)
	offset := 0
	for index := uint64(0); index < expected; index++ {
		if offset+46 > len(directory) ||
			binary.LittleEndian.Uint32(directory[offset:offset+4]) != 0x02014b50 {
			return nil, false, nil
		}
		nameLength := int(binary.LittleEndian.Uint16(directory[offset+28 : offset+30]))
		extraLength := int(binary.LittleEndian.Uint16(directory[offset+30 : offset+32]))
		commentLength := int(binary.LittleEndian.Uint16(directory[offset+32 : offset+34]))
		next := offset + 46 + nameLength + extraLength + commentLength
		if nameLength == 0 || next < offset || next > len(directory) {
			return nil, false, nil
		}
		localOffset := int64(binary.LittleEndian.Uint32(
			directory[offset+42 : offset+46],
		))
		local, localOK, err := reader.readAt(localOffset, 30)
		if err != nil || !localOK {
			return nil, false, err
		}
		if binary.LittleEndian.Uint32(local[:4]) != 0x04034b50 {
			return nil, false, nil
		}
		localNameLength := int64(binary.LittleEndian.Uint16(local[26:28]))
		localExtraLength := int64(binary.LittleEndian.Uint16(local[28:30]))
		if localOffset > reader.size-30-localNameLength-localExtraLength {
			return nil, false, nil
		}
		name := strings.TrimPrefix(strings.ReplaceAll(
			string(directory[offset+46:offset+46+nameLength]), "\\", "/",
		), "./")
		names[name] = true
		offset = next
	}
	return names, offset <= len(directory), nil
}

func classifyZIP(names map[string]bool) (string, string) {
	switch {
	case names["AndroidManifest.xml"]:
		return "apk", "application/vnd.android.package-archive"
	case names["WEB-INF/web.xml"]:
		return "war", "application/java-archive"
	case names["META-INF/application.xml"]:
		return "ear", "application/java-archive"
	case names["META-INF/MANIFEST.MF"]:
		return "jar", "application/java-archive"
	default:
		return "zip", "application/zip"
	}
}

type tarSummary struct {
	entries        int
	hasManifest    bool
	dockerManifest bool
	dockerRefs     []string
	hasOCILayout   bool
	validOCILayout bool
	hasOCIIndex    bool
	validOCIIndex  bool
	ociBlobRefs    []string
	regularNames   map[string]bool
}

func detectTAR(reader *boundedReader) (Result, bool, error) {
	first, ok, err := reader.readAt(0, 512)
	if err != nil || !ok {
		return Result{}, false, err
	}
	if allZero(first) {
		valid, validateErr := validEmptyTAR(reader)
		if validateErr != nil || !valid {
			return Result{}, false, validateErr
		}
		return result(
			"tar",
			"application/x-tar",
			"",
			map[string]any{"entries": 0},
		), true, nil
	}
	if !validTARHeader(first) {
		return Result{}, false, nil
	}
	summary, valid, err := scanTAR(reader)
	if err != nil || !valid {
		return Result{}, false, err
	}
	metadata := map[string]any{"entries": summary.entries}
	switch {
	case summary.hasOCILayout && summary.validOCILayout &&
		summary.hasOCIIndex && summary.validOCIIndex:
		return result("oci-tar", "application/vnd.oci.image.layout.v1+tar", "", metadata), true, nil
	case summary.hasManifest && summary.dockerManifest:
		return result("docker-tar", "application/vnd.docker.image.rootfs.diff.tar", "", metadata), true, nil
	default:
		return result("tar", "application/x-tar", "", metadata), true, nil
	}
}

func validEmptyTAR(reader *boundedReader) (bool, error) {
	if reader.size < 1024 ||
		reader.size > maxEmptyTARBytes ||
		reader.size%512 != 0 {
		return false, nil
	}
	remainder, ok, err := reader.readAt(512, reader.size-512)
	if err != nil || !ok {
		return false, err
	}
	return allZero(remainder), nil
}

func scanTAR(reader *boundedReader) (tarSummary, bool, error) {
	summary := tarSummary{
		regularNames: make(map[string]bool),
	}
	offset := int64(0)
	zeroBlocks := 0
	for summary.entries < 4096 && offset <= reader.size-512 {
		header, ok, err := reader.readAt(offset, 512)
		if err != nil || !ok {
			return summary, false, err
		}
		if allZero(header) {
			zeroBlocks++
			offset += 512
			if zeroBlocks == 2 {
				finalizeTARSummary(&summary)
				return summary, true, nil
			}
			continue
		}
		zeroBlocks = 0
		if !validTARHeader(header) {
			return summary, false, nil
		}
		entrySize, ok := tarNumber(header[124:136])
		if !ok || entrySize < 0 {
			return summary, false, nil
		}
		name := tarName(header)
		if header[156] == 0 || header[156] == tarTypeRegular {
			summary.regularNames[name] = true
		}
		summary.entries++
		switch name {
		case "manifest.json":
			summary.hasManifest = true
			content, contentOK, readErr := readSmallTAREntry(reader, offset+512, entrySize)
			if readErr != nil {
				return summary, false, readErr
			}
			if contentOK {
				var manifest []struct {
					Config   string   `json:"Config"`
					RepoTags []string `json:"RepoTags"`
					Layers   []string `json:"Layers"`
				}
				if json.Unmarshal(content, &manifest) == nil && len(manifest) > 0 {
					summary.dockerManifest = true
					for _, image := range manifest {
						if !safeArchiveReference(image.Config) || len(image.Layers) == 0 {
							summary.dockerManifest = false
							break
						}
						summary.dockerRefs = append(summary.dockerRefs, image.Config)
						for _, layer := range image.Layers {
							if !safeArchiveReference(layer) {
								summary.dockerManifest = false
								break
							}
							summary.dockerRefs = append(summary.dockerRefs, layer)
						}
					}
				}
			}
		case "oci-layout":
			summary.hasOCILayout = true
			content, contentOK, readErr := readSmallTAREntry(reader, offset+512, entrySize)
			if readErr != nil {
				return summary, false, readErr
			}
			if contentOK {
				var layout struct {
					Version string `json:"imageLayoutVersion"`
				}
				summary.validOCILayout = json.Unmarshal(content, &layout) == nil &&
					layout.Version == "1.0.0"
			}
		case "index.json":
			summary.hasOCIIndex = true
			content, contentOK, readErr := readSmallTAREntry(reader, offset+512, entrySize)
			if readErr != nil {
				return summary, false, readErr
			}
			if contentOK {
				var index struct {
					SchemaVersion int `json:"schemaVersion"`
					Manifests     []struct {
						Digest string `json:"digest"`
					} `json:"manifests"`
				}
				if json.Unmarshal(content, &index) == nil &&
					index.SchemaVersion == 2 && len(index.Manifests) > 0 {
					summary.validOCIIndex = true
					for _, manifest := range index.Manifests {
						algorithm, digest, found := strings.Cut(manifest.Digest, ":")
						_, decodeErr := hex.DecodeString(digest)
						if !found || algorithm != "sha256" || len(digest) != 64 ||
							decodeErr != nil {
							summary.validOCIIndex = false
							break
						}
						summary.ociBlobRefs = append(summary.ociBlobRefs,
							"blobs/sha256/"+digest)
					}
				}
			}
		}
		padded := (entrySize + 511) &^ 511
		if padded < entrySize || offset > reader.size-512-padded {
			return summary, false, nil
		}
		offset += 512 + padded
	}
	finalizeTARSummary(&summary)
	return summary, summary.entries > 0, nil
}

func finalizeTARSummary(summary *tarSummary) {
	if summary.dockerManifest {
		for _, reference := range summary.dockerRefs {
			if !summary.regularNames[reference] {
				summary.dockerManifest = false
				break
			}
		}
	}
	if summary.validOCIIndex {
		for _, reference := range summary.ociBlobRefs {
			if !summary.regularNames[reference] {
				summary.validOCIIndex = false
				break
			}
		}
	}
}

const tarTypeRegular = '0'

func safeArchiveReference(value string) bool {
	if value == "" || path.IsAbs(value) || path.Clean(value) != value ||
		strings.Contains(value, "\\") || strings.ContainsRune(value, '\x00') {
		return false
	}
	for _, segment := range strings.Split(value, "/") {
		if segment == "" || segment == "." || segment == ".." {
			return false
		}
	}
	return true
}

func readSmallTAREntry(reader *boundedReader, offset, length int64) ([]byte, bool, error) {
	if length < 0 || length > 1<<20 {
		return nil, false, nil
	}
	return reader.readAt(offset, length)
}

func validTARHeader(header []byte) bool {
	if len(header) != 512 {
		return false
	}
	v7 := isV7TARHeader(header)
	if !v7 &&
		!bytes.Equal(header[257:263], []byte("ustar\x00")) &&
		!bytes.Equal(header[257:263], []byte("ustar ")) {
		return false
	}
	if tarName(header) == "" {
		return false
	}
	size, sizeOK := tarNumber(header[124:136])
	if !sizeOK || size < 0 {
		return false
	}
	if v7 && !validV7TARType(header[156]) {
		return false
	}
	expected, ok := tarNumber(header[148:156])
	if !ok {
		return false
	}
	var unsigned, signed int64
	for index, value := range header {
		if index >= 148 && index < 156 {
			value = ' '
		}
		unsigned += int64(value)
		signed += int64(int8(value))
	}
	return expected == unsigned || expected == signed
}

func isV7TARHeader(header []byte) bool {
	if len(header) != 512 {
		return false
	}
	// The V7 header ends immediately after typeflag. A fully zero extension
	// area prevents a forged checksum plus empty ustar magic from classifying
	// arbitrary binary data as a legacy tar archive.
	return allZero(header[257:512])
}

func validV7TARType(value byte) bool {
	return value == 0 || value >= '0' && value <= '7'
}

func tarName(header []byte) string {
	name := strings.TrimRight(string(header[:100]), "\x00")
	if !isV7TARHeader(header) {
		prefix := strings.TrimRight(string(header[345:500]), "\x00")
		if prefix != "" {
			name = prefix + "/" + name
		}
	}
	return strings.TrimPrefix(name, "./")
}

func tarNumber(field []byte) (int64, bool) {
	if len(field) == 0 {
		return 0, false
	}
	if field[0]&0x80 != 0 {
		if field[0]&0x40 != 0 || len(field) > 8 {
			return 0, false
		}
		var value uint64
		for index, current := range field {
			if index == 0 {
				current &= 0x7f
			}
			value = value<<8 | uint64(current)
		}
		if value > uint64(^uint64(0)>>1) {
			return 0, false
		}
		return int64(value), true
	}
	raw := strings.Trim(string(field), " \x00")
	if raw == "" {
		return 0, true
	}
	value, err := strconv.ParseInt(raw, 8, 64)
	return value, err == nil
}

func allZero(value []byte) bool {
	for _, current := range value {
		if current != 0 {
			return false
		}
	}
	return true
}

func detectGZIP(reader *boundedReader) (Result, bool, error) {
	header, ok, err := reader.readAt(0, 10)
	if err != nil || !ok || !bytes.Equal(header[:3], []byte{0x1f, 0x8b, 8}) {
		return Result{}, false, err
	}
	if header[3]&0xe0 != 0 {
		return Result{}, false, nil
	}
	if reader.size < 18 {
		return Result{}, false, nil
	}
	headerLimit := reader.size - 8
	if headerLimit > 1<<20 {
		headerLimit = 1 << 20
	}
	fullHeader, ok, err := reader.readAt(0, headerLimit)
	if err != nil || !ok {
		return Result{}, false, err
	}
	offset := 10
	if header[3]&0x04 != 0 {
		if offset+2 > len(fullHeader) {
			return Result{}, false, nil
		}
		extraLength := int(binary.LittleEndian.Uint16(fullHeader[offset : offset+2]))
		offset += 2 + extraLength
		if offset > len(fullHeader) {
			return Result{}, false, nil
		}
	}
	for _, flag := range []byte{0x08, 0x10} {
		if header[3]&flag == 0 {
			continue
		}
		end := bytes.IndexByte(fullHeader[offset:], 0)
		if end < 0 {
			return Result{}, false, nil
		}
		offset += end + 1
	}
	if header[3]&0x02 != 0 {
		offset += 2
	}
	if offset > len(fullHeader) || int64(offset) > reader.size-8 {
		return Result{}, false, nil
	}
	return result("gzip", "application/gzip", "", nil), true, nil
}

func detectBZIP2(reader *boundedReader) (Result, bool, error) {
	header, ok, err := reader.readAt(0, 10)
	if err != nil || !ok || !bytes.Equal(header[:3], []byte("BZh")) ||
		header[3] < '1' || header[3] > '9' ||
		(!bytes.Equal(header[4:10], []byte{0x31, 0x41, 0x59, 0x26, 0x53, 0x59}) &&
			!bytes.Equal(header[4:10], []byte{0x17, 0x72, 0x45, 0x38, 0x50, 0x90})) {
		return Result{}, false, err
	}
	return result("bzip2", "application/x-bzip2", "", nil), true, nil
}

func detectXZ(reader *boundedReader) (Result, bool, error) {
	header, ok, err := reader.readAt(0, 12)
	if err != nil || !ok || !bytes.Equal(header[:6], []byte{0xfd, '7', 'z', 'X', 'Z', 0}) {
		return Result{}, false, err
	}
	if header[6] != 0 || header[7]&0xf0 != 0 ||
		crc32.ChecksumIEEE(header[6:8]) != binary.LittleEndian.Uint32(header[8:12]) {
		return Result{}, false, nil
	}
	return result("xz", "application/x-xz", "", nil), true, nil
}

func detectZSTD(reader *boundedReader) (Result, bool, error) {
	header, ok, err := reader.readAt(0, 5)
	if err != nil || !ok || !bytes.Equal(header[:4], []byte{0x28, 0xb5, 0x2f, 0xfd}) {
		return Result{}, false, err
	}
	descriptor := header[4]
	if descriptor&0x18 != 0 {
		return Result{}, false, nil
	}
	singleSegment := descriptor&0x20 != 0
	offset := 5
	if !singleSegment {
		offset++
	}
	dictionarySize := []int{0, 1, 2, 4}[descriptor&0x03]
	offset += dictionarySize
	contentSizeCode := descriptor >> 6
	contentSizeBytes := []int{0, 2, 4, 8}[contentSizeCode]
	if singleSegment && contentSizeCode == 0 {
		contentSizeBytes = 1
	}
	offset += contentSizeBytes
	prefix, ok, err := reader.readAt(0, int64(offset+3))
	if err != nil || !ok {
		return Result{}, false, err
	}
	blockHeader := prefix[offset : offset+3]
	blockValue := uint32(blockHeader[0]) |
		uint32(blockHeader[1])<<8 |
		uint32(blockHeader[2])<<16
	blockType := (blockValue >> 1) & 0x3
	blockSize := uint64(blockValue >> 3)
	if blockType == 3 || blockSize > uint64(reader.size)-uint64(offset+3) {
		return Result{}, false, nil
	}
	return result("zstd", "application/zstd", "", nil), true, nil
}

func detect7Z(reader *boundedReader) (Result, bool, error) {
	header, ok, err := reader.readAt(0, 32)
	if err != nil || !ok || !bytes.Equal(header[:6], []byte{'7', 'z', 0xbc, 0xaf, 0x27, 0x1c}) {
		return Result{}, false, err
	}
	if crc32.ChecksumIEEE(header[12:32]) != binary.LittleEndian.Uint32(header[8:12]) {
		return Result{}, false, nil
	}
	nextOffset := binary.LittleEndian.Uint64(header[12:20])
	nextSize := binary.LittleEndian.Uint64(header[20:28])
	if nextOffset > uint64(reader.size-32) || nextSize > uint64(reader.size-32)-nextOffset {
		return Result{}, false, nil
	}
	nextHeader, ok, err := reader.readAt(32+int64(nextOffset), int64(nextSize))
	if err != nil || !ok {
		return Result{}, false, err
	}
	if crc32.ChecksumIEEE(nextHeader) != binary.LittleEndian.Uint32(header[28:32]) {
		return Result{}, false, nil
	}
	return result("7z", "application/x-7z-compressed", "", map[string]any{
		"version": strconv.Itoa(int(header[6])) + "." + strconv.Itoa(int(header[7])),
	}), true, nil
}

func detectRAR(reader *boundedReader) (Result, bool, error) {
	header, ok, err := reader.readAt(0, 14)
	if err != nil || !ok {
		return Result{}, false, err
	}
	switch {
	case bytes.Equal(header[:7], []byte{'R', 'a', 'r', '!', 0x1a, 0x07, 0x00}):
		headerSize := binary.LittleEndian.Uint16(header[12:14])
		if header[9] != 0x73 || headerSize < 13 ||
			int64(7+headerSize) > reader.size {
			return Result{}, false, nil
		}
		return result("rar", "application/vnd.rar", "", map[string]any{"version": 4}), true, nil
	case bytes.Equal(header[:8], []byte{'R', 'a', 'r', '!', 0x1a, 0x07, 0x01, 0x00}):
		prefixLength := reader.size
		if prefixLength > 2<<20 {
			prefixLength = 2 << 20
		}
		record, recordOK, readErr := reader.readAt(8, prefixLength-8)
		if readErr != nil || !recordOK || len(record) < 6 {
			return Result{}, false, readErr
		}
		headerSize, sizeBytes, valid := decodeRARVInt(record[4:])
		if !valid || headerSize == 0 || headerSize > 2<<20 ||
			4+sizeBytes+int(headerSize) > len(record) {
			return Result{}, false, nil
		}
		checksummed := record[4 : 4+sizeBytes+int(headerSize)]
		if crc32.ChecksumIEEE(checksummed) != binary.LittleEndian.Uint32(record[:4]) {
			return Result{}, false, nil
		}
		headerType, _, valid := decodeRARVInt(record[4+sizeBytes:])
		if !valid || (headerType != 1 && headerType != 4) {
			return Result{}, false, nil
		}
		return result("rar", "application/vnd.rar", "", map[string]any{"version": 5}), true, nil
	default:
		return Result{}, false, nil
	}
}

func decodeRARVInt(value []byte) (uint64, int, bool) {
	var result uint64
	for index := 0; index < len(value) && index < 10; index++ {
		current := value[index]
		if index == 9 && current > 1 {
			return 0, 0, false
		}
		result |= uint64(current&0x7f) << (7 * index)
		if current&0x80 == 0 {
			return result, index + 1, true
		}
	}
	return 0, 0, false
}

package filetype

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math"
)

const (
	maxPESections            = 96
	maxELFSegments           = 128
	maxELFSectionHeaders     = 1024
	maxMachLoadCommands      = 4096
	maxMachSegments          = 128
	maxMachSections          = 1024
	maxMachFatSlices         = 32
	maxMachLoadCommandBytes  = 8 << 20
	peSectionHeaderSize      = int64(40)
	elf32ProgramHeaderSize   = uint16(32)
	elf64ProgramHeaderSize   = uint16(56)
	elf32SectionHeaderSize   = uint16(40)
	elf64SectionHeaderSize   = uint16(64)
	mach32SegmentCommandSize = uint32(56)
	mach64SegmentCommandSize = uint32(72)
	mach32SectionCommandSize = uint32(68)
	mach64SectionCommandSize = uint32(80)
	machMainEntryCommandSize = uint32(24)
	machMainEntryCommand     = uint32(0x80000028)
	mach32SegmentCommand     = uint32(0x1)
	mach64SegmentCommand     = uint32(0x19)
)

// executableEntryPoint deliberately makes the address interpretation explicit.
// Virtual addresses are hexadecimal strings so 64-bit values survive JSON
// consumers that cannot represent every uint64 exactly.
type executableEntryPoint struct {
	AddressKind            string  `json:"address_kind"`
	VirtualAddress         string  `json:"virtual_address,omitempty"`
	RelativeVirtualAddress string  `json:"relative_virtual_address,omitempty"`
	FileOffset             *uint64 `json:"file_offset,omitempty"`
	ContainerFileOffset    *uint64 `json:"container_file_offset,omitempty"`
}

// executableRegion is the common, bounded section/segment summary. It contains
// structural values only; the detector never copies region contents.
type executableRegion struct {
	Name                   string `json:"name,omitempty"`
	Type                   string `json:"type"`
	FileOffset             uint64 `json:"file_offset"`
	VirtualAddress         string `json:"virtual_address"`
	RelativeVirtualAddress string `json:"relative_virtual_address,omitempty"`
	FileSize               uint64 `json:"file_size"`
	MemorySize             uint64 `json:"memory_size"`
	Permissions            string `json:"permissions"`
	Flags                  string `json:"flags"`
}

func detectPE(reader *boundedReader) (Result, bool, error) {
	header, ok, err := reader.readAt(0, 64)
	if err != nil || !ok || !bytes.Equal(header[:2], []byte("MZ")) {
		return Result{}, false, err
	}
	peOffset := int64(binary.LittleEndian.Uint32(header[0x3c:]))
	coff, ok, err := reader.readAt(peOffset, 26)
	if err != nil || !ok || !bytes.Equal(coff[:4], []byte{'P', 'E', 0, 0}) {
		return Result{}, false, err
	}
	optionalSize := int64(binary.LittleEndian.Uint16(coff[20:22]))
	sectionCount := binary.LittleEndian.Uint16(coff[6:8])
	optionalOffset := peOffset + 24
	if optionalSize < 70 ||
		!int64RangeWithin(optionalOffset, optionalSize, reader.size) {
		return Result{}, false, nil
	}
	sectionTableOffset := optionalOffset + optionalSize
	if sectionCount == 0 || sectionCount > maxPESections ||
		!int64RangeWithin(
			sectionTableOffset,
			int64(sectionCount)*peSectionHeaderSize,
			reader.size,
		) {
		return Result{}, false, nil
	}
	optional, ok, err := reader.readAt(optionalOffset, 70)
	if err != nil || !ok {
		return Result{}, false, err
	}
	magic := binary.LittleEndian.Uint16(optional[:2])
	format := ""
	bits := 0
	switch magic {
	case 0x10b:
		if optionalSize < 96 {
			return Result{}, false, nil
		}
		format = "pe32"
		bits = 32
	case 0x20b:
		if optionalSize < 112 {
			return Result{}, false, nil
		}
		format = "pe32+"
		bits = 64
	default:
		return Result{}, false, nil
	}
	entryRVA := binary.LittleEndian.Uint32(optional[16:20])
	var imageBase uint64
	if bits == 32 {
		imageBase = uint64(binary.LittleEndian.Uint32(optional[28:32]))
	} else {
		imageBase = binary.LittleEndian.Uint64(optional[24:32])
	}
	entryAddress, entryOK := addVirtualAddress(imageBase, uint64(entryRVA), bits)
	if !entryOK {
		return Result{}, false, nil
	}
	sectionTable, ok, err := reader.readAt(
		sectionTableOffset,
		int64(sectionCount)*peSectionHeaderSize,
	)
	if err != nil || !ok {
		return Result{}, false, err
	}
	sectionSummaries := make([]executableRegion, 0, int(sectionCount))
	for index := uint16(0); index < sectionCount; index++ {
		start := int(index) * int(peSectionHeaderSize)
		section := sectionTable[start : start+int(peSectionHeaderSize)]
		name := safeExecutableName(
			section[:8],
			fmt.Sprintf("section-%d", index+1),
		)
		memorySize := binary.LittleEndian.Uint32(section[8:12])
		rva := binary.LittleEndian.Uint32(section[12:16])
		fileSize := binary.LittleEndian.Uint32(section[16:20])
		fileOffset := binary.LittleEndian.Uint32(section[20:24])
		flags := binary.LittleEndian.Uint32(section[36:40])
		if fileSize > 0 && (fileOffset == 0 ||
			!uint64RangeWithin(
				uint64(fileOffset),
				uint64(fileSize),
				uint64(reader.size),
			)) {
			return Result{}, false, nil
		}
		virtualAddress, addressOK := addVirtualAddress(
			imageBase,
			uint64(rva),
			bits,
		)
		if !addressOK || !virtualRangeFits(
			virtualAddress,
			uint64(memorySize),
			bits,
		) {
			return Result{}, false, nil
		}
		sectionSummaries = append(sectionSummaries, executableRegion{
			Name:                   name,
			Type:                   peSectionType(flags),
			FileOffset:             uint64(fileOffset),
			VirtualAddress:         formatVirtualAddress(virtualAddress, bits),
			RelativeVirtualAddress: formatRelativeVirtualAddress(uint64(rva)),
			FileSize:               uint64(fileSize),
			MemorySize:             uint64(memorySize),
			Permissions:            pePermissions(flags),
			Flags:                  fmt.Sprintf("0x%08x", flags),
		})
	}
	machine := binary.LittleEndian.Uint16(coff[4:6])
	characteristics := binary.LittleEndian.Uint16(coff[22:24])
	subsystem := binary.LittleEndian.Uint16(optional[68:70])
	binaryKind := "image"
	switch {
	case characteristics&0x2000 != 0:
		binaryKind = "dll"
	case characteristics&0x0002 != 0:
		binaryKind = "executable"
	}
	metadata := map[string]any{
		"machine":          fmt.Sprintf("0x%04x", machine),
		"section_count":    sectionCount,
		"sections":         sectionSummaries,
		"image_base":       formatVirtualAddress(imageBase, bits),
		"kind":             binaryKind,
		"subsystem":        peSubsystem(subsystem),
		"driver_candidate": subsystem == 1 || (subsystem >= 10 && subsystem <= 13),
		"bits":             bits,
		"endianness":       "little",
	}
	if entryRVA != 0 {
		metadata["entry_point"] = executableEntryPoint{
			AddressKind:            "virtual_address",
			VirtualAddress:         formatVirtualAddress(entryAddress, bits),
			RelativeVirtualAddress: formatRelativeVirtualAddress(uint64(entryRVA)),
		}
	}
	return result(format, "application/vnd.microsoft.portable-executable",
		peArchitecture(machine), metadata), true, nil
}

func peSectionType(flags uint32) string {
	switch {
	case flags&0x00000020 != 0:
		return "code"
	case flags&0x00000040 != 0:
		return "initialized-data"
	case flags&0x00000080 != 0:
		return "uninitialized-data"
	default:
		return "other"
	}
}

func pePermissions(flags uint32) string {
	return permissionString(
		flags&0x40000000 != 0,
		flags&0x80000000 != 0,
		flags&0x20000000 != 0,
	)
}

func peArchitecture(machine uint16) string {
	switch machine {
	case 0x014c:
		return "x86"
	case 0x8664:
		return "x86_64"
	case 0x01c0, 0x01c2, 0x01c4:
		return "arm"
	case 0xaa64:
		return "arm64"
	case 0x0200:
		return "ia64"
	default:
		return ""
	}
}

func peSubsystem(value uint16) string {
	switch value {
	case 0:
		return "unknown"
	case 1:
		return "native"
	case 2:
		return "windows-gui"
	case 3:
		return "windows-console"
	case 7:
		return "posix-console"
	case 8:
		return "native-windows"
	case 9:
		return "windows-ce-gui"
	case 10:
		return "efi-application"
	case 11:
		return "efi-boot-service-driver"
	case 12:
		return "efi-runtime-driver"
	case 13:
		return "efi-rom"
	case 14:
		return "xbox"
	case 16:
		return "windows-boot-application"
	default:
		return fmt.Sprintf("subsystem-%d", value)
	}
}

func detectELF(reader *boundedReader) (Result, bool, error) {
	ident, ok, err := reader.readAt(0, 20)
	if err != nil || !ok || !bytes.Equal(ident[:4], []byte{0x7f, 'E', 'L', 'F'}) {
		return Result{}, false, err
	}
	class, data := ident[4], ident[5]
	if ident[6] != 1 || (data != 1 && data != 2) {
		return Result{}, false, nil
	}
	var order binary.ByteOrder = binary.LittleEndian
	endian := "little"
	if data == 2 {
		order = binary.BigEndian
		endian = "big"
	}
	var format string
	var headerSize int64
	switch class {
	case 1:
		format, headerSize = "elf32", 52
	case 2:
		format, headerSize = "elf64", 64
	default:
		return Result{}, false, nil
	}
	header, ok, err := reader.readAt(0, headerSize)
	if err != nil || !ok {
		return Result{}, false, err
	}
	if order.Uint32(header[20:24]) != 1 {
		return Result{}, false, nil
	}
	var (
		entryPoint       uint64
		programOffset    uint64
		sectionOffset    uint64
		programEntrySize uint16
		programCount     uint16
		sectionEntrySize uint16
		sectionCount     uint16
		sectionNameIndex uint16
	)
	switch class {
	case 1:
		if int64(order.Uint16(header[0x28:0x2a])) != headerSize {
			return Result{}, false, nil
		}
		entryPoint = uint64(order.Uint32(header[0x18:0x1c]))
		programOffset = uint64(order.Uint32(header[0x1c:0x20]))
		sectionOffset = uint64(order.Uint32(header[0x20:0x24]))
		programEntrySize = order.Uint16(header[0x2a:0x2c])
		programCount = order.Uint16(header[0x2c:0x2e])
		sectionEntrySize = order.Uint16(header[0x2e:0x30])
		sectionCount = order.Uint16(header[0x30:0x32])
		sectionNameIndex = order.Uint16(header[0x32:0x34])
	case 2:
		if int64(order.Uint16(header[0x34:0x36])) != headerSize {
			return Result{}, false, nil
		}
		entryPoint = order.Uint64(header[0x18:0x20])
		programOffset = order.Uint64(header[0x20:0x28])
		sectionOffset = order.Uint64(header[0x28:0x30])
		programEntrySize = order.Uint16(header[0x36:0x38])
		programCount = order.Uint16(header[0x38:0x3a])
		sectionEntrySize = order.Uint16(header[0x3a:0x3c])
		sectionCount = order.Uint16(header[0x3c:0x3e])
		sectionNameIndex = order.Uint16(header[0x3e:0x40])
	}
	expectedProgramEntrySize := elf32ProgramHeaderSize
	expectedSectionEntrySize := elf32SectionHeaderSize
	if class == 2 {
		expectedProgramEntrySize = elf64ProgramHeaderSize
		expectedSectionEntrySize = elf64SectionHeaderSize
	}
	if !validELFTable(
		programOffset,
		programEntrySize,
		programCount,
		expectedProgramEntrySize,
		maxELFSegments,
		uint64(reader.size),
	) {
		return Result{}, false, nil
	}
	if !validELFSectionTable(
		sectionOffset,
		sectionEntrySize,
		sectionCount,
		sectionNameIndex,
		expectedSectionEntrySize,
		uint64(reader.size),
	) {
		return Result{}, false, nil
	}
	segmentSummaries, segmentsOK, err := parseELFSegments(
		reader,
		order,
		class,
		programOffset,
		programEntrySize,
		programCount,
	)
	if err != nil || !segmentsOK {
		return Result{}, false, err
	}
	machine := order.Uint16(header[18:20])
	bits := map[byte]int{1: 32, 2: 64}[class]
	metadata := map[string]any{
		"machine":       machine,
		"bits":          bits,
		"endianness":    endian,
		"segment_count": programCount,
		"segments":      segmentSummaries,
	}
	if entryPoint != 0 {
		metadata["entry_point"] = executableEntryPoint{
			AddressKind:    "virtual_address",
			VirtualAddress: formatVirtualAddress(entryPoint, bits),
		}
	}
	return result(format, "application/x-elf", elfArchitecture(machine, class),
		metadata), true, nil
}

func validELFTable(
	offset uint64,
	entrySize uint16,
	count uint16,
	expectedEntrySize uint16,
	maxCount uint16,
	fileSize uint64,
) bool {
	if count == 0 {
		return offset == 0 && (entrySize == 0 || entrySize == expectedEntrySize)
	}
	if count > maxCount || offset == 0 || entrySize != expectedEntrySize {
		return false
	}
	return uint64RangeWithin(
		offset,
		uint64(entrySize)*uint64(count),
		fileSize,
	)
}

func validELFSectionTable(
	offset uint64,
	entrySize uint16,
	count uint16,
	nameIndex uint16,
	expectedEntrySize uint16,
	fileSize uint64,
) bool {
	// Extended section numbering relies on section zero and is intentionally
	// rejected until that representation is parsed explicitly.
	if count == 0 {
		return offset == 0 && nameIndex == 0 &&
			(entrySize == 0 || entrySize == expectedEntrySize)
	}
	if count > maxELFSectionHeaders || offset == 0 ||
		entrySize != expectedEntrySize ||
		nameIndex == math.MaxUint16 ||
		(nameIndex != 0 && nameIndex >= count) {
		return false
	}
	return uint64RangeWithin(
		offset,
		uint64(entrySize)*uint64(count),
		fileSize,
	)
}

func parseELFSegments(
	reader *boundedReader,
	order binary.ByteOrder,
	class byte,
	tableOffset uint64,
	entrySize uint16,
	count uint16,
) ([]executableRegion, bool, error) {
	summaries := make([]executableRegion, 0, int(count))
	bits := 32
	if class == 2 {
		bits = 64
	}
	for index := uint16(0); index < count; index++ {
		offset := tableOffset + uint64(index)*uint64(entrySize)
		header, ok, err := reader.readAt(int64(offset), int64(entrySize))
		if err != nil || !ok {
			return nil, false, err
		}
		var (
			segmentType    uint32
			flags          uint32
			fileOffset     uint64
			virtualAddress uint64
			fileSize       uint64
			memorySize     uint64
			alignment      uint64
		)
		if class == 1 {
			segmentType = order.Uint32(header[0:4])
			fileOffset = uint64(order.Uint32(header[4:8]))
			virtualAddress = uint64(order.Uint32(header[8:12]))
			fileSize = uint64(order.Uint32(header[16:20]))
			memorySize = uint64(order.Uint32(header[20:24]))
			flags = order.Uint32(header[24:28])
			alignment = uint64(order.Uint32(header[28:32]))
		} else {
			segmentType = order.Uint32(header[0:4])
			flags = order.Uint32(header[4:8])
			fileOffset = order.Uint64(header[8:16])
			virtualAddress = order.Uint64(header[16:24])
			fileSize = order.Uint64(header[32:40])
			memorySize = order.Uint64(header[40:48])
			alignment = order.Uint64(header[48:56])
		}
		if !uint64RangeWithin(
			fileOffset,
			fileSize,
			uint64(reader.size),
		) || !virtualRangeFits(virtualAddress, memorySize, bits) ||
			(alignment > 1 && alignment&(alignment-1) != 0) ||
			(segmentType == 1 && fileSize > memorySize) {
			return nil, false, nil
		}
		summaries = append(summaries, executableRegion{
			Type:           elfSegmentType(segmentType),
			FileOffset:     fileOffset,
			VirtualAddress: formatVirtualAddress(virtualAddress, bits),
			FileSize:       fileSize,
			MemorySize:     memorySize,
			Permissions: permissionString(
				flags&0x4 != 0,
				flags&0x2 != 0,
				flags&0x1 != 0,
			),
			Flags: fmt.Sprintf("0x%08x", flags),
		})
	}
	return summaries, true, nil
}

func elfSegmentType(value uint32) string {
	switch value {
	case 0:
		return "null"
	case 1:
		return "load"
	case 2:
		return "dynamic"
	case 3:
		return "interpreter"
	case 4:
		return "note"
	case 5:
		return "shared-library"
	case 6:
		return "program-header"
	case 7:
		return "thread-local-storage"
	case 0x6474e550:
		return "gnu-eh-frame"
	case 0x6474e551:
		return "gnu-stack"
	case 0x6474e552:
		return "gnu-relro"
	default:
		return fmt.Sprintf("type-0x%08x", value)
	}
}

func elfArchitecture(machine uint16, class byte) string {
	switch machine {
	case 3:
		return "x86"
	case 8:
		if class == 2 {
			return "mips64"
		}
		return "mips"
	case 20:
		return "powerpc"
	case 21:
		return "powerpc64"
	case 40:
		return "arm"
	case 62:
		return "x86_64"
	case 183:
		return "arm64"
	case 243:
		if class == 2 {
			return "riscv64"
		}
		return "riscv32"
	default:
		return ""
	}
}

func detectJavaClass(reader *boundedReader) (Result, bool, error) {
	header, ok, err := reader.readAt(0, 10)
	if err != nil || !ok || !bytes.Equal(header[:4], []byte{0xca, 0xfe, 0xba, 0xbe}) {
		return Result{}, false, err
	}
	minor := binary.BigEndian.Uint16(header[4:6])
	major := binary.BigEndian.Uint16(header[6:8])
	constantPoolCount := binary.BigEndian.Uint16(header[8:10])
	if major < 45 || major > 100 || constantPoolCount == 0 {
		return Result{}, false, nil
	}
	offset := int64(10)
	for index := uint32(1); index < uint32(constantPoolCount); index++ {
		tag, ok, err := reader.readAt(offset, 1)
		if err != nil || !ok {
			return Result{}, false, err
		}
		offset++
		var length int64
		switch tag[0] {
		case 1:
			rawLength, ok, err := reader.readAt(offset, 2)
			if err != nil || !ok {
				return Result{}, false, err
			}
			length = 2 + int64(binary.BigEndian.Uint16(rawLength))
		case 3, 4:
			length = 4
		case 5, 6:
			if index+1 >= uint32(constantPoolCount) {
				return Result{}, false, nil
			}
			length = 8
			index++
		case 7, 8, 16, 19, 20:
			length = 2
		case 9, 10, 11, 12, 17, 18:
			length = 4
		case 15:
			length = 3
		default:
			return Result{}, false, nil
		}
		if length < 0 || offset > reader.size-length {
			return Result{}, false, nil
		}
		offset += length
	}
	classHeader, ok, err := reader.readAt(offset, 8)
	if err != nil || !ok || binary.BigEndian.Uint16(classHeader[2:4]) == 0 {
		return Result{}, false, err
	}
	offset += 8 + int64(binary.BigEndian.Uint16(classHeader[6:8]))*2
	if offset > reader.size {
		return Result{}, false, nil
	}
	offset, ok, err = skipJavaMembers(reader, offset)
	if err != nil || !ok {
		return Result{}, false, err
	}
	offset, ok, err = skipJavaMembers(reader, offset)
	if err != nil || !ok {
		return Result{}, false, err
	}
	offset, ok, err = skipJavaAttributes(reader, offset)
	if err != nil || !ok || offset != reader.size {
		return Result{}, false, err
	}
	return result("java-class", "application/java-vm", "", map[string]any{
		"major_version": major,
		"minor_version": minor,
	}), true, nil
}

func skipJavaMembers(reader *boundedReader, offset int64) (int64, bool, error) {
	countBytes, ok, err := reader.readAt(offset, 2)
	if err != nil || !ok {
		return offset, false, err
	}
	count := binary.BigEndian.Uint16(countBytes)
	offset += 2
	for index := uint16(0); index < count; index++ {
		member, memberOK, readErr := reader.readAt(offset, 8)
		if readErr != nil || !memberOK {
			return offset, false, readErr
		}
		offset += 8
		attributes := binary.BigEndian.Uint16(member[6:8])
		offset, ok, err = skipJavaAttributeCount(reader, offset, attributes)
		if err != nil || !ok {
			return offset, false, err
		}
	}
	return offset, true, nil
}

func skipJavaAttributes(reader *boundedReader, offset int64) (int64, bool, error) {
	countBytes, ok, err := reader.readAt(offset, 2)
	if err != nil || !ok {
		return offset, false, err
	}
	return skipJavaAttributeCount(
		reader, offset+2, binary.BigEndian.Uint16(countBytes),
	)
}

func skipJavaAttributeCount(
	reader *boundedReader,
	offset int64,
	count uint16,
) (int64, bool, error) {
	for index := uint16(0); index < count; index++ {
		attribute, ok, err := reader.readAt(offset, 6)
		if err != nil || !ok {
			return offset, false, err
		}
		length := int64(binary.BigEndian.Uint32(attribute[2:6]))
		if offset > reader.size-6-length {
			return offset, false, nil
		}
		offset += 6 + length
	}
	return offset, true, nil
}

func detectMachO(reader *boundedReader) (Result, bool, error) {
	magicBytes, ok, err := reader.readAt(0, 8)
	if err != nil || !ok {
		return Result{}, false, err
	}
	magic := binary.BigEndian.Uint32(magicBytes[:4])
	switch magic {
	case 0xcafebabe, 0xcafebabf, 0xbebafeca, 0xbfbafeca:
		return detectFatMachO(reader, magic)
	case 0xfeedface, 0xfeedfacf, 0xcefaedfe, 0xcffaedfe:
		return detectThinMachO(reader, magic)
	default:
		return Result{}, false, nil
	}
}

type machThinSummary struct {
	Architecture     string
	CPU              uint32
	Bits             int
	Endianness       string
	FileType         string
	LoadCommandCount uint32
	Segments         []executableRegion
	EntryPoint       *executableEntryPoint
}

func (summary machThinSummary) metadata() map[string]any {
	metadata := map[string]any{
		"bits":               summary.Bits,
		"endianness":         summary.Endianness,
		"file_type":          summary.FileType,
		"load_command_count": summary.LoadCommandCount,
		"segment_count":      len(summary.Segments),
		"segments":           summary.Segments,
	}
	if summary.EntryPoint != nil {
		metadata["entry_point"] = *summary.EntryPoint
	}
	return metadata
}

type machFatSliceSummary struct {
	Architecture     string                `json:"architecture"`
	FileOffset       uint64                `json:"file_offset"`
	FileSize         uint64                `json:"file_size"`
	Bits             int                   `json:"bits"`
	Endianness       string                `json:"endianness"`
	FileType         string                `json:"file_type"`
	LoadCommandCount uint32                `json:"load_command_count"`
	SegmentCount     int                   `json:"segment_count"`
	Segments         []executableRegion    `json:"segments"`
	EntryPoint       *executableEntryPoint `json:"entry_point,omitempty"`
}

func detectThinMachO(reader *boundedReader, magic uint32) (Result, bool, error) {
	summary, ok, err := parseThinMachO(
		reader,
		0,
		reader.size,
		magic,
		maxMachSegments,
	)
	if err != nil || !ok {
		return Result{}, false, err
	}
	return result(
		"macho-thin",
		"application/x-mach-binary",
		summary.Architecture,
		summary.metadata(),
	), true, nil
}

func parseThinMachO(
	reader *boundedReader,
	base int64,
	sliceSize int64,
	magic uint32,
	segmentLimit int,
) (machThinSummary, bool, error) {
	is64 := magic == 0xfeedfacf || magic == 0xcffaedfe
	little := magic == 0xcefaedfe || magic == 0xcffaedfe
	var order binary.ByteOrder = binary.BigEndian
	endian := "big"
	if little {
		order = binary.LittleEndian
		endian = "little"
	}
	headerSize := int64(28)
	if is64 {
		headerSize = 32
	}
	header, ok, err := readMachSliceAt(
		reader,
		base,
		sliceSize,
		0,
		headerSize,
	)
	if err != nil || !ok {
		return machThinSummary{}, false, err
	}
	if binary.BigEndian.Uint32(header[:4]) != magic {
		return machThinSummary{}, false, nil
	}
	commandCount := order.Uint32(header[16:20])
	commandBytes := order.Uint32(header[20:24])
	fileType := order.Uint32(header[12:16])
	if fileType == 0 || fileType > 12 || commandCount > maxMachLoadCommands ||
		commandBytes > maxMachLoadCommandBytes ||
		uint64(commandCount)*8 > uint64(commandBytes) ||
		!int64RangeWithin(headerSize, int64(commandBytes), sliceSize) ||
		(commandCount == 0) != (commandBytes == 0) {
		return machThinSummary{}, false, nil
	}
	cpu := order.Uint32(header[4:8])
	architecture := machArchitecture(cpu)
	if architecture == "" {
		architecture = fmt.Sprintf("cpu-%d", cpu)
	}
	bits := 32
	if is64 {
		bits = 64
	}
	summary := machThinSummary{
		Architecture:     architecture,
		CPU:              cpu,
		Bits:             bits,
		Endianness:       endian,
		FileType:         machFileType(fileType),
		LoadCommandCount: commandCount,
		Segments:         make([]executableRegion, 0),
	}
	var traversed uint64
	totalSections := uint64(0)
	for index := uint32(0); index < commandCount; index++ {
		if traversed > uint64(commandBytes) ||
			uint64(commandBytes)-traversed < 8 {
			return machThinSummary{}, false, nil
		}
		command, commandOK, readErr := readMachSliceAt(
			reader,
			base,
			sliceSize,
			headerSize+int64(traversed),
			8,
		)
		if readErr != nil || !commandOK {
			return machThinSummary{}, false, readErr
		}
		commandType := order.Uint32(command[:4])
		commandSize := order.Uint32(command[4:8])
		if commandSize < 8 || commandSize%4 != 0 ||
			uint64(commandSize) > uint64(commandBytes)-traversed {
			return machThinSummary{}, false, nil
		}
		switch commandType {
		case mach32SegmentCommand, mach64SegmentCommand:
			expectedCommand := mach32SegmentCommand
			segmentHeaderSize := mach32SegmentCommandSize
			sectionSize := mach32SectionCommandSize
			if is64 {
				expectedCommand = mach64SegmentCommand
				segmentHeaderSize = mach64SegmentCommandSize
				sectionSize = mach64SectionCommandSize
			}
			if commandType != expectedCommand ||
				commandSize < segmentHeaderSize {
				return machThinSummary{}, false, nil
			}
			segmentHeader, segmentOK, segmentErr := readMachSliceAt(
				reader,
				base,
				sliceSize,
				headerSize+int64(traversed),
				int64(segmentHeaderSize),
			)
			if segmentErr != nil || !segmentOK {
				return machThinSummary{}, false, segmentErr
			}
			sectionCountOffset := 48
			if is64 {
				sectionCountOffset = 64
			}
			sectionCount := order.Uint32(
				segmentHeader[sectionCountOffset : sectionCountOffset+4],
			)
			requiredSize := uint64(segmentHeaderSize) +
				uint64(sectionCount)*uint64(sectionSize)
			if sectionCount > maxMachSections ||
				totalSections+uint64(sectionCount) > maxMachSections ||
				requiredSize != uint64(commandSize) ||
				len(summary.Segments) >= segmentLimit {
				return machThinSummary{}, false, nil
			}
			totalSections += uint64(sectionCount)
			region, regionOK := parseMachSegment(
				segmentHeader,
				order,
				is64,
				uint32(len(summary.Segments)+1),
				uint64(sliceSize),
			)
			if !regionOK {
				return machThinSummary{}, false, nil
			}
			summary.Segments = append(summary.Segments, region)
		case machMainEntryCommand:
			if commandSize != machMainEntryCommandSize ||
				summary.EntryPoint != nil {
				return machThinSummary{}, false, nil
			}
			entryCommand, entryOK, entryErr := readMachSliceAt(
				reader,
				base,
				sliceSize,
				headerSize+int64(traversed),
				int64(machMainEntryCommandSize),
			)
			if entryErr != nil || !entryOK {
				return machThinSummary{}, false, entryErr
			}
			fileOffset := order.Uint64(entryCommand[8:16])
			if fileOffset >= uint64(sliceSize) {
				return machThinSummary{}, false, nil
			}
			summary.EntryPoint = &executableEntryPoint{
				AddressKind: "file_offset",
				FileOffset:  uint64Pointer(fileOffset),
			}
		}
		traversed += uint64(commandSize)
	}
	if traversed != uint64(commandBytes) {
		return machThinSummary{}, false, nil
	}
	return summary, true, nil
}

func detectFatMachO(reader *boundedReader, magic uint32) (Result, bool, error) {
	is64 := magic == 0xcafebabf || magic == 0xbfbafeca
	little := magic == 0xbebafeca || magic == 0xbfbafeca
	var order binary.ByteOrder = binary.BigEndian
	if little {
		order = binary.LittleEndian
	}
	header, ok, err := reader.readAt(0, 8)
	if err != nil || !ok {
		return Result{}, false, err
	}
	count := order.Uint32(header[4:8])
	if count == 0 || count > maxMachFatSlices {
		return Result{}, false, nil
	}
	entrySize := int64(20)
	if is64 {
		entrySize = 32
	}
	table, ok, err := reader.readAt(8, int64(count)*entrySize)
	if err != nil || !ok {
		return Result{}, false, err
	}
	architectures := make([]string, 0, count)
	slices := make([]machFatSliceSummary, 0, count)
	type sliceRange struct {
		offset uint64
		length uint64
	}
	ranges := make([]sliceRange, 0, count)
	tableEnd := uint64(8 + int64(count)*entrySize)
	totalSegments := 0
	for index := uint32(0); index < count; index++ {
		entry := table[int64(index)*entrySize:]
		cpu := order.Uint32(entry[:4])
		var offset, length uint64
		if is64 {
			offset = order.Uint64(entry[8:16])
			length = order.Uint64(entry[16:24])
		} else {
			offset = uint64(order.Uint32(entry[8:12]))
			length = uint64(order.Uint32(entry[12:16]))
		}
		if length == 0 || offset < tableEnd ||
			!uint64RangeWithin(offset, length, uint64(reader.size)) {
			return Result{}, false, nil
		}
		alignOffset := 16
		if is64 {
			alignOffset = 24
		}
		align := order.Uint32(entry[alignOffset : alignOffset+4])
		if align > 62 ||
			(uint64(1)<<align) > 1 &&
				offset%(uint64(1)<<align) != 0 ||
			is64 && order.Uint32(entry[28:32]) != 0 {
			return Result{}, false, nil
		}
		for _, previous := range ranges {
			if rangesOverlap(offset, length, previous.offset, previous.length) {
				return Result{}, false, nil
			}
		}
		ranges = append(ranges, sliceRange{offset: offset, length: length})
		sliceHeader, sliceOK, readErr := reader.readAt(int64(offset), 8)
		if readErr != nil || !sliceOK {
			return Result{}, false, readErr
		}
		sliceMagic := binary.BigEndian.Uint32(sliceHeader[:4])
		if !thinMachMagic(sliceMagic) {
			return Result{}, false, nil
		}
		remainingSegments := maxMachSegments - totalSegments
		summary, sliceValid, parseErr := parseThinMachO(
			reader,
			int64(offset),
			int64(length),
			sliceMagic,
			remainingSegments,
		)
		if parseErr != nil || !sliceValid {
			return Result{}, false, parseErr
		}
		if summary.CPU != cpu {
			return Result{}, false, nil
		}
		totalSegments += len(summary.Segments)
		var entryPoint *executableEntryPoint
		if summary.EntryPoint != nil {
			entryPointValue := *summary.EntryPoint
			containerOffset := offset + *entryPointValue.FileOffset
			entryPointValue.ContainerFileOffset = uint64Pointer(containerOffset)
			entryPoint = &entryPointValue
		}
		architectures = append(architectures, summary.Architecture)
		slices = append(slices, machFatSliceSummary{
			Architecture:     summary.Architecture,
			FileOffset:       offset,
			FileSize:         length,
			Bits:             summary.Bits,
			Endianness:       summary.Endianness,
			FileType:         summary.FileType,
			LoadCommandCount: summary.LoadCommandCount,
			SegmentCount:     len(summary.Segments),
			Segments:         summary.Segments,
			EntryPoint:       entryPoint,
		})
	}
	return result("macho-fat", "application/x-mach-binary", "universal",
		map[string]any{
			"architectures": architectures,
			"slice_count":   count,
			"slices":        slices,
		}), true, nil
}

func parseMachSegment(
	header []byte,
	order binary.ByteOrder,
	is64 bool,
	index uint32,
	sliceSize uint64,
) (executableRegion, bool) {
	name := safeExecutableName(
		header[8:24],
		fmt.Sprintf("segment-%d", index),
	)
	var (
		virtualAddress uint64
		memorySize     uint64
		fileOffset     uint64
		fileSize       uint64
		permissions    uint32
		flags          uint32
	)
	if is64 {
		virtualAddress = order.Uint64(header[24:32])
		memorySize = order.Uint64(header[32:40])
		fileOffset = order.Uint64(header[40:48])
		fileSize = order.Uint64(header[48:56])
		permissions = order.Uint32(header[60:64])
		flags = order.Uint32(header[68:72])
	} else {
		virtualAddress = uint64(order.Uint32(header[24:28]))
		memorySize = uint64(order.Uint32(header[28:32]))
		fileOffset = uint64(order.Uint32(header[32:36]))
		fileSize = uint64(order.Uint32(header[36:40]))
		permissions = order.Uint32(header[44:48])
		flags = order.Uint32(header[52:56])
	}
	bits := 32
	if is64 {
		bits = 64
	}
	if !uint64RangeWithin(fileOffset, fileSize, sliceSize) ||
		!virtualRangeFits(virtualAddress, memorySize, bits) {
		return executableRegion{}, false
	}
	return executableRegion{
		Name:           name,
		Type:           "segment",
		FileOffset:     fileOffset,
		VirtualAddress: formatVirtualAddress(virtualAddress, bits),
		FileSize:       fileSize,
		MemorySize:     memorySize,
		Permissions: permissionString(
			permissions&0x1 != 0,
			permissions&0x2 != 0,
			permissions&0x4 != 0,
		),
		Flags: fmt.Sprintf("0x%08x", flags),
	}, true
}

func readMachSliceAt(
	reader *boundedReader,
	base int64,
	sliceSize int64,
	offset int64,
	length int64,
) ([]byte, bool, error) {
	if !int64RangeWithin(offset, length, sliceSize) ||
		!int64RangeWithin(base, sliceSize, reader.size) ||
		base > math.MaxInt64-offset {
		return nil, false, nil
	}
	return reader.readAt(base+offset, length)
}

func thinMachMagic(magic uint32) bool {
	switch magic {
	case 0xfeedface, 0xfeedfacf, 0xcefaedfe, 0xcffaedfe:
		return true
	default:
		return false
	}
}

func machFileType(value uint32) string {
	switch value {
	case 1:
		return "object"
	case 2:
		return "executable"
	case 3:
		return "fixed-vm-library"
	case 4:
		return "core"
	case 5:
		return "preloaded-executable"
	case 6:
		return "dynamic-library"
	case 7:
		return "dynamic-linker"
	case 8:
		return "bundle"
	case 9:
		return "dynamic-library-stub"
	case 10:
		return "debug-symbols"
	case 11:
		return "kernel-extension"
	case 12:
		return "fileset"
	default:
		return "unknown"
	}
}

func machArchitecture(cpu uint32) string {
	switch cpu {
	case 7:
		return "x86"
	case 0x01000007:
		return "x86_64"
	case 12:
		return "arm"
	case 0x0100000c:
		return "arm64"
	case 18:
		return "powerpc"
	case 0x01000012:
		return "powerpc64"
	default:
		return ""
	}
}

func int64RangeWithin(offset, length, limit int64) bool {
	return offset >= 0 &&
		length >= 0 &&
		limit >= 0 &&
		offset <= limit &&
		length <= limit-offset
}

func uint64RangeWithin(offset, length, limit uint64) bool {
	return offset <= limit && length <= limit-offset
}

func rangesOverlap(
	firstOffset uint64,
	firstLength uint64,
	secondOffset uint64,
	secondLength uint64,
) bool {
	return firstOffset < secondOffset+secondLength &&
		secondOffset < firstOffset+firstLength
}

func addVirtualAddress(base, relative uint64, bits int) (uint64, bool) {
	if relative > math.MaxUint64-base {
		return 0, false
	}
	value := base + relative
	if bits == 32 && value > math.MaxUint32 {
		return 0, false
	}
	return value, true
}

func virtualRangeFits(address, size uint64, bits int) bool {
	if size == 0 {
		if bits == 32 {
			return address <= math.MaxUint32
		}
		return true
	}
	maximum := uint64(math.MaxUint64)
	if bits == 32 {
		maximum = math.MaxUint32
	}
	return address <= maximum && size-1 <= maximum-address
}

func formatVirtualAddress(value uint64, bits int) string {
	if bits == 32 {
		return fmt.Sprintf("0x%08x", value)
	}
	return fmt.Sprintf("0x%016x", value)
}

func formatRelativeVirtualAddress(value uint64) string {
	return fmt.Sprintf("0x%08x", value)
}

func permissionString(read, write, execute bool) string {
	value := []byte{'-', '-', '-'}
	if read {
		value[0] = 'r'
	}
	if write {
		value[1] = 'w'
	}
	if execute {
		value[2] = 'x'
	}
	return string(value)
}

func safeExecutableName(raw []byte, fallback string) string {
	end := len(raw)
	for index, value := range raw {
		if value == 0 {
			end = index
			for _, trailing := range raw[index+1:] {
				if trailing != 0 {
					return fallback
				}
			}
			break
		}
	}
	if end == 0 {
		return fallback
	}
	for _, value := range raw[:end] {
		if !safeExecutableNameByte(value) {
			return fallback
		}
	}
	return string(raw[:end])
}

func safeExecutableNameByte(value byte) bool {
	return value >= 'a' && value <= 'z' ||
		value >= 'A' && value <= 'Z' ||
		value >= '0' && value <= '9' ||
		value == '.' ||
		value == '_' ||
		value == '$' ||
		value == '-' ||
		value == '+'
}

func uint64Pointer(value uint64) *uint64 {
	return &value
}

func detectDEX(reader *boundedReader) (Result, bool, error) {
	header, ok, err := reader.readAt(0, 0x70)
	if err != nil || !ok || !bytes.Equal(header[:4], []byte{'d', 'e', 'x', '\n'}) ||
		header[7] != 0 || header[4] < '0' || header[4] > '9' ||
		header[5] < '0' || header[5] > '9' || header[6] < '0' || header[6] > '9' {
		return Result{}, false, err
	}
	version := string(header[4:7])
	if version != "035" && version != "037" && version != "038" &&
		version != "039" && version != "040" && version != "041" {
		return Result{}, false, nil
	}
	fileSize := binary.LittleEndian.Uint32(header[32:36])
	headerSize := binary.LittleEndian.Uint32(header[36:40])
	endianTag := binary.LittleEndian.Uint32(header[40:44])
	if endianTag != 0x12345678 && endianTag != 0x78563412 {
		return Result{}, false, nil
	}
	if version == "041" {
		header, ok, err = reader.readAt(0, 0x78)
		if err != nil || !ok {
			return Result{}, false, err
		}
		containerSize := binary.LittleEndian.Uint32(header[112:116])
		headerOffset := binary.LittleEndian.Uint32(header[116:120])
		if headerSize != 0x78 || containerSize == 0 ||
			int64(containerSize) > reader.size ||
			uint64(headerOffset)+uint64(fileSize) > uint64(containerSize) ||
			fileSize < headerSize {
			return Result{}, false, nil
		}
	} else if headerSize != 0x70 || int64(fileSize) != reader.size {
		return Result{}, false, nil
	}
	return result("dex", "application/vnd.android.dex", "", map[string]any{
		"version": version,
	}), true, nil
}

func detectPYC(reader *boundedReader) (Result, bool, error) {
	magicBytes, ok, err := reader.readAt(0, 4)
	if err != nil || !ok || magicBytes[2] != '\r' || magicBytes[3] != '\n' {
		return Result{}, false, err
	}
	magic := binary.LittleEndian.Uint16(magicBytes[:2])
	version, known := knownCPythonMagic[magic]
	if !known {
		return Result{}, false, nil
	}
	header, ok, err := reader.readAt(0, int64(version.headerSize+1))
	if err != nil || !ok {
		return Result{}, false, err
	}
	if header[version.headerSize]&0x7f != 'c' {
		return Result{}, false, nil
	}
	metadata := map[string]any{
		"magic":          fmt.Sprintf("0x%04x", magic),
		"python_version": version.python,
		"header_size":    version.headerSize,
	}
	if version.headerSize == 16 {
		flags := binary.LittleEndian.Uint32(header[4:8])
		if flags&^uint32(3) != 0 {
			return Result{}, false, nil
		}
		metadata["flags"] = flags
	}
	return result("pyc", "application/x-python-bytecode", "", metadata), true, nil
}

type pycVersion struct {
	python     string
	headerSize int
}

// Accepted CPython magic values and their version-specific header sizes. Some
// values originated in prereleases but remain accepted for compatibility.
// Add a value here only when that bytecode/header combination is supported.
var knownCPythonMagic = map[uint16]pycVersion{
	62211: {python: "2.7", headerSize: 8},
	3230:  {python: "3.3", headerSize: 12},
	3310:  {python: "3.4", headerSize: 12},
	3350:  {python: "3.5", headerSize: 12},
	3351:  {python: "3.5", headerSize: 12},
	3379:  {python: "3.6", headerSize: 12},
	3394:  {python: "3.7", headerSize: 16},
	3413:  {python: "3.8", headerSize: 16},
	3425:  {python: "3.9", headerSize: 16},
	3439:  {python: "3.10", headerSize: 16},
	3495:  {python: "3.11", headerSize: 16},
	3531:  {python: "3.12", headerSize: 16},
	3571:  {python: "3.13", headerSize: 16},
	3619:  {python: "3.14", headerSize: 16},
	3627:  {python: "3.14", headerSize: 16},
}

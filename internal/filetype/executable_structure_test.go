package filetype

import (
	"encoding/binary"
	"encoding/json"
	"strings"
	"testing"
)

func TestPEStructureMetadataIncludesExplicitEntryPointAndSections(t *testing.T) {
	for _, is64 := range []bool{false, true} {
		name := "pe32"
		if is64 {
			name = "pe32+"
		}
		t.Run(name, func(t *testing.T) {
			detected := mustDetect(t, structuredPEFixture(is64))
			if detected.Format != name {
				t.Fatalf("format = %q, want %q", detected.Format, name)
			}
			entry, ok := detected.Metadata["entry_point"].(executableEntryPoint)
			if !ok || entry.AddressKind != "virtual_address" ||
				entry.RelativeVirtualAddress != "0x00001008" {
				t.Fatalf("entry point = %#v", detected.Metadata["entry_point"])
			}
			expectedAddress := "0x00401008"
			if is64 {
				expectedAddress = "0x0000000140001008"
			}
			if entry.VirtualAddress != expectedAddress {
				t.Fatalf("entry virtual address = %q, want %q",
					entry.VirtualAddress, expectedAddress)
			}
			sections, ok := detected.Metadata["sections"].([]executableRegion)
			if !ok || len(sections) != 1 ||
				detected.Metadata["section_count"] != uint16(1) {
				t.Fatalf("section metadata = %#v", detected.Metadata)
			}
			section := sections[0]
			if section.Name != ".text" ||
				section.Type != "code" ||
				section.FileSize != 16 ||
				section.MemorySize != 0x200 ||
				section.Permissions != "r-x" ||
				section.RelativeVirtualAddress != "0x00001000" {
				t.Fatalf("section = %+v", section)
			}
		})
	}
}

func TestPEUnsafeSectionNameUsesBoundedSafeLabel(t *testing.T) {
	data := structuredPEFixture(false)
	sectionOffset := 0x80 + 24 + 96
	copy(data[sectionOffset:sectionOffset+8], []byte("<script!"))

	detected := mustDetect(t, data)
	if detected.Format != "pe32" {
		t.Fatalf("format = %q", detected.Format)
	}
	sections := detected.Metadata["sections"].([]executableRegion)
	if sections[0].Name != "section-1" {
		t.Fatalf("unsafe section name exposed as %q", sections[0].Name)
	}
	encoded, err := json.Marshal(detected.Metadata)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "<script") {
		t.Fatalf("unsafe section name leaked into metadata: %s", encoded)
	}
}

func TestELFStructureMetadataIncludesExplicitEntryPointAndSegments(t *testing.T) {
	tests := []struct {
		name            string
		is64            bool
		bigEndian       bool
		expectedEntry   string
		expectedAddress string
	}{
		{
			name:            "elf32-big",
			bigEndian:       true,
			expectedEntry:   "0x08048004",
			expectedAddress: "0x08048000",
		},
		{
			name:            "elf64-little",
			is64:            true,
			expectedEntry:   "0x0000000000400004",
			expectedAddress: "0x0000000000400000",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			detected := mustDetect(
				t,
				structuredELFFixture(test.is64, test.bigEndian),
			)
			entry, ok := detected.Metadata["entry_point"].(executableEntryPoint)
			if !ok || entry.AddressKind != "virtual_address" ||
				entry.VirtualAddress != test.expectedEntry {
				t.Fatalf("entry point = %#v", detected.Metadata["entry_point"])
			}
			segments, ok := detected.Metadata["segments"].([]executableRegion)
			if !ok || len(segments) != 1 ||
				detected.Metadata["segment_count"] != uint16(1) {
				t.Fatalf("segment metadata = %#v", detected.Metadata)
			}
			segment := segments[0]
			if segment.Type != "load" ||
				segment.VirtualAddress != test.expectedAddress ||
				segment.Permissions != "r-x" ||
				segment.FileOffset != 0 ||
				segment.FileSize == 0 ||
				segment.MemorySize <= segment.FileSize {
				t.Fatalf("segment = %+v", segment)
			}
		})
	}
}

func TestMachOStructureMetadataIncludesThinAndFatSlices(t *testing.T) {
	for _, test := range []struct {
		name   string
		is64   bool
		little bool
		bits   int
	}{
		{name: "thin32-big", bits: 32},
		{name: "thin64-little", is64: true, little: true, bits: 64},
	} {
		t.Run(test.name, func(t *testing.T) {
			data := structuredMachThinFixture(test.is64, test.little)
			detected := mustDetect(t, data)
			if detected.Format != "macho-thin" ||
				detected.Metadata["bits"] != test.bits ||
				detected.Metadata["segment_count"] != 1 {
				t.Fatalf("thin metadata = %#v", detected.Metadata)
			}
			entry, ok := detected.Metadata["entry_point"].(executableEntryPoint)
			if !ok || entry.AddressKind != "file_offset" ||
				entry.FileOffset == nil ||
				*entry.FileOffset >= uint64(len(data)) ||
				entry.ContainerFileOffset != nil {
				t.Fatalf("thin entry point = %#v", detected.Metadata["entry_point"])
			}
			segments := detected.Metadata["segments"].([]executableRegion)
			if len(segments) != 1 ||
				segments[0].Name != "__TEXT" ||
				segments[0].Permissions != "r-x" {
				t.Fatalf("thin segments = %+v", segments)
			}
		})
	}

	fat := structuredMachFatFixture()
	detected := mustDetect(t, fat)
	if detected.Format != "macho-fat" ||
		detected.Metadata["slice_count"] != uint32(2) {
		t.Fatalf("fat metadata = %#v", detected.Metadata)
	}
	slices, ok := detected.Metadata["slices"].([]machFatSliceSummary)
	if !ok || len(slices) != 2 ||
		slices[0].Bits != 32 ||
		slices[1].Bits != 64 {
		t.Fatalf("fat slices = %#v", detected.Metadata["slices"])
	}
	for _, slice := range slices {
		if slice.EntryPoint == nil ||
			slice.EntryPoint.FileOffset == nil ||
			slice.EntryPoint.ContainerFileOffset == nil ||
			*slice.EntryPoint.ContainerFileOffset !=
				slice.FileOffset+*slice.EntryPoint.FileOffset {
			t.Fatalf("fat slice entry point = %+v", slice)
		}
		if len(slice.Segments) != 1 {
			t.Fatalf("fat slice segments = %+v", slice.Segments)
		}
	}
}

func TestExecutableStructureRejectsCorruptAndOversizedTables(t *testing.T) {
	peCount := peFixture(false, false, 3)
	binary.LittleEndian.PutUint16(
		peCount[0x86:0x88],
		uint16(maxPESections+1),
	)
	peRawRange := structuredPEFixture(false)
	peSectionOffset := 0x80 + 24 + 96
	binary.LittleEndian.PutUint32(
		peRawRange[peSectionOffset+20:peSectionOffset+24],
		uint32(len(peRawRange)-4),
	)
	binary.LittleEndian.PutUint32(
		peRawRange[peSectionOffset+16:peSectionOffset+20],
		64,
	)
	peEntryOverflow := structuredPEFixture(false)
	binary.LittleEndian.PutUint32(peEntryOverflow[0x98+28:0x98+32], 0xfffff000)
	binary.LittleEndian.PutUint32(peEntryOverflow[0x98+16:0x98+20], 0x2000)

	elfCount := elfFixture(true)
	binary.LittleEndian.PutUint64(elfCount[0x20:0x28], 64)
	binary.LittleEndian.PutUint16(elfCount[0x36:0x38], elf64ProgramHeaderSize)
	binary.LittleEndian.PutUint16(
		elfCount[0x38:0x3a],
		uint16(maxELFSegments+1),
	)
	elfOffset := elfFixture(true)
	binary.LittleEndian.PutUint64(elfOffset[0x20:0x28], ^uint64(0))
	binary.LittleEndian.PutUint16(elfOffset[0x36:0x38], elf64ProgramHeaderSize)
	binary.LittleEndian.PutUint16(elfOffset[0x38:0x3a], 1)
	elfSegmentRange := structuredELFFixture(true, false)
	binary.LittleEndian.PutUint64(elfSegmentRange[64+8:64+16], uint64(len(elfSegmentRange)-4))
	binary.LittleEndian.PutUint64(elfSegmentRange[64+32:64+40], 64)

	machCommands := machThinFixture()
	binary.BigEndian.PutUint32(
		machCommands[16:20],
		uint32(maxMachLoadCommands+1),
	)
	machSections := structuredMachThinFixture(true, false)
	binary.BigEndian.PutUint32(
		machSections[32+64:32+68],
		uint32(maxMachSections+1),
	)
	machEntry := structuredMachThinFixture(true, false)
	binary.BigEndian.PutUint64(
		machEntry[32+72+8:32+72+16],
		uint64(len(machEntry)),
	)
	fatCount := make([]byte, 8)
	binary.BigEndian.PutUint32(fatCount[:4], 0xcafebabe)
	binary.BigEndian.PutUint32(
		fatCount[4:8],
		uint32(maxMachFatSlices+1),
	)

	tests := []struct {
		name string
		data []byte
	}{
		{name: "pe section count", data: peCount},
		{name: "pe raw range", data: peRawRange},
		{name: "pe entry overflow", data: peEntryOverflow},
		{name: "elf segment count", data: elfCount},
		{name: "elf table offset", data: elfOffset},
		{name: "elf segment range", data: elfSegmentRange},
		{name: "Mach-O command count", data: machCommands},
		{name: "Mach-O section count", data: machSections},
		{name: "Mach-O entry offset", data: machEntry},
		{name: "fat slice count", data: fatCount},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if detected := mustDetect(t, test.data); detected.Format != "unknown" {
				t.Fatalf("corrupt structure detected as %+v", detected)
			}
		})
	}
}

func TestExecutableMetadataJSONIsBoundedAndRoundTrips(t *testing.T) {
	data := peFixture(false, false, 3)
	optionalSize := 96
	sectionTableOffset := 0x80 + 24 + optionalSize
	binary.LittleEndian.PutUint16(
		data[0x86:0x88],
		uint16(maxPESections),
	)
	data = append(
		data,
		make([]byte, (maxPESections-1)*int(peSectionHeaderSize))...,
	)
	for index := 0; index < maxPESections; index++ {
		start := sectionTableOffset + index*int(peSectionHeaderSize)
		copy(data[start:start+8], []byte(".section"))
	}

	detected := mustDetect(t, data)
	if detected.Format != "pe32" {
		t.Fatalf("format = %q", detected.Format)
	}
	encoded, err := json.Marshal(detected.Metadata)
	if err != nil {
		t.Fatal(err)
	}
	if len(encoded) > 128<<10 {
		t.Fatalf("metadata JSON is not bounded: %d bytes", len(encoded))
	}
	var roundTrip map[string]any
	if err := json.Unmarshal(encoded, &roundTrip); err != nil {
		t.Fatal(err)
	}
	sections, ok := roundTrip["sections"].([]any)
	if !ok || len(sections) != maxPESections {
		t.Fatalf("round-trip sections = %#v", roundTrip["sections"])
	}
	first, ok := sections[0].(map[string]any)
	if !ok ||
		first["file_offset"] != float64(0) ||
		first["virtual_address"] != "0x00000000" ||
		first["permissions"] != "---" {
		t.Fatalf("round-trip first section = %#v", sections[0])
	}
}

func structuredPEFixture(is64 bool) []byte {
	data := peFixture(is64, false, 3)
	optionalSize := 96
	if is64 {
		optionalSize = 112
	}
	optionalOffset := 0x80 + 24
	binary.LittleEndian.PutUint32(
		data[optionalOffset+16:optionalOffset+20],
		0x1008,
	)
	if is64 {
		binary.LittleEndian.PutUint64(
			data[optionalOffset+24:optionalOffset+32],
			0x0000000140000000,
		)
	} else {
		binary.LittleEndian.PutUint32(
			data[optionalOffset+28:optionalOffset+32],
			0x00400000,
		)
	}
	sectionOffset := optionalOffset + optionalSize
	copy(data[sectionOffset:sectionOffset+8], []byte(".text"))
	binary.LittleEndian.PutUint32(
		data[sectionOffset+8:sectionOffset+12],
		0x200,
	)
	binary.LittleEndian.PutUint32(
		data[sectionOffset+12:sectionOffset+16],
		0x1000,
	)
	binary.LittleEndian.PutUint32(
		data[sectionOffset+16:sectionOffset+20],
		16,
	)
	binary.LittleEndian.PutUint32(
		data[sectionOffset+20:sectionOffset+24],
		uint32(len(data)),
	)
	binary.LittleEndian.PutUint32(
		data[sectionOffset+36:sectionOffset+40],
		0x60000020,
	)
	return append(data, make([]byte, 16)...)
}

func structuredELFFixture(is64, bigEndian bool) []byte {
	headerSize := 52
	programSize := int(elf32ProgramHeaderSize)
	class := byte(1)
	machine := uint16(3)
	virtualAddress := uint64(0x08048000)
	var order binary.ByteOrder = binary.LittleEndian
	if bigEndian {
		order = binary.BigEndian
	}
	if is64 {
		headerSize = 64
		programSize = int(elf64ProgramHeaderSize)
		class = 2
		machine = 62
		virtualAddress = 0x00400000
	}
	data := make([]byte, headerSize+programSize+16)
	encoding := byte(1)
	if bigEndian {
		encoding = 2
	}
	copy(data, []byte{0x7f, 'E', 'L', 'F', class, encoding, 1})
	order.PutUint16(data[16:18], 2)
	order.PutUint16(data[18:20], machine)
	order.PutUint32(data[20:24], 1)
	program := data[headerSize : headerSize+programSize]
	if is64 {
		order.PutUint64(data[0x18:0x20], virtualAddress+4)
		order.PutUint64(data[0x20:0x28], uint64(headerSize))
		order.PutUint16(data[0x34:0x36], uint16(headerSize))
		order.PutUint16(data[0x36:0x38], elf64ProgramHeaderSize)
		order.PutUint16(data[0x38:0x3a], 1)
		order.PutUint32(program[0:4], 1)
		order.PutUint32(program[4:8], 5)
		order.PutUint64(program[8:16], 0)
		order.PutUint64(program[16:24], virtualAddress)
		order.PutUint64(program[32:40], uint64(len(data)))
		order.PutUint64(program[40:48], uint64(len(data)+0x100))
		order.PutUint64(program[48:56], 0x1000)
	} else {
		order.PutUint32(data[0x18:0x1c], uint32(virtualAddress+4))
		order.PutUint32(data[0x1c:0x20], uint32(headerSize))
		order.PutUint16(data[0x28:0x2a], uint16(headerSize))
		order.PutUint16(data[0x2a:0x2c], elf32ProgramHeaderSize)
		order.PutUint16(data[0x2c:0x2e], 1)
		order.PutUint32(program[0:4], 1)
		order.PutUint32(program[4:8], 0)
		order.PutUint32(program[8:12], uint32(virtualAddress))
		order.PutUint32(program[16:20], uint32(len(data)))
		order.PutUint32(program[20:24], uint32(len(data)+0x100))
		order.PutUint32(program[24:28], 5)
		order.PutUint32(program[28:32], 0x1000)
	}
	return data
}

func structuredMachThinFixture(is64, little bool) []byte {
	headerSize := 28
	segmentSize := int(mach32SegmentCommandSize)
	segmentCommand := mach32SegmentCommand
	magic := uint32(0xfeedface)
	cpu := uint32(7)
	virtualAddress := uint64(0x1000)
	var order binary.ByteOrder = binary.BigEndian
	if is64 {
		headerSize = 32
		segmentSize = int(mach64SegmentCommandSize)
		segmentCommand = mach64SegmentCommand
		magic = 0xfeedfacf
		cpu = 0x01000007
		virtualAddress = 0x0000000100000000
	}
	if little {
		order = binary.LittleEndian
		if is64 {
			magic = 0xcffaedfe
		} else {
			magic = 0xcefaedfe
		}
	}
	commandBytes := segmentSize + int(machMainEntryCommandSize)
	entryOffset := headerSize + commandBytes
	data := make([]byte, entryOffset+32)
	binary.BigEndian.PutUint32(data[:4], magic)
	order.PutUint32(data[4:8], cpu)
	order.PutUint32(data[12:16], 2)
	order.PutUint32(data[16:20], 2)
	order.PutUint32(data[20:24], uint32(commandBytes))

	segment := data[headerSize : headerSize+segmentSize]
	order.PutUint32(segment[0:4], segmentCommand)
	order.PutUint32(segment[4:8], uint32(segmentSize))
	copy(segment[8:24], []byte("__TEXT"))
	if is64 {
		order.PutUint64(segment[24:32], virtualAddress)
		order.PutUint64(segment[32:40], uint64(len(data)))
		order.PutUint64(segment[40:48], 0)
		order.PutUint64(segment[48:56], uint64(len(data)))
		order.PutUint32(segment[56:60], 7)
		order.PutUint32(segment[60:64], 5)
	} else {
		order.PutUint32(segment[24:28], uint32(virtualAddress))
		order.PutUint32(segment[28:32], uint32(len(data)))
		order.PutUint32(segment[32:36], 0)
		order.PutUint32(segment[36:40], uint32(len(data)))
		order.PutUint32(segment[40:44], 7)
		order.PutUint32(segment[44:48], 5)
	}
	entry := data[headerSize+segmentSize : entryOffset]
	order.PutUint32(entry[0:4], machMainEntryCommand)
	order.PutUint32(entry[4:8], machMainEntryCommandSize)
	order.PutUint64(entry[8:16], uint64(entryOffset))
	return data
}

func structuredMachFatFixture() []byte {
	first := structuredMachThinFixture(false, false)
	second := structuredMachThinFixture(true, true)
	const tableSize = 8 + 2*20
	firstOffset := uint32(tableSize)
	secondOffset := firstOffset + uint32(len(first))
	data := make([]byte, int(secondOffset)+len(second))
	binary.BigEndian.PutUint32(data[:4], 0xcafebabe)
	binary.BigEndian.PutUint32(data[4:8], 2)
	binary.BigEndian.PutUint32(data[8:12], 7)
	binary.BigEndian.PutUint32(data[16:20], firstOffset)
	binary.BigEndian.PutUint32(data[20:24], uint32(len(first)))
	binary.BigEndian.PutUint32(data[28:32], 0x01000007)
	binary.BigEndian.PutUint32(data[36:40], secondOffset)
	binary.BigEndian.PutUint32(data[40:44], uint32(len(second)))
	copy(data[firstOffset:], first)
	copy(data[secondOffset:], second)
	return data
}

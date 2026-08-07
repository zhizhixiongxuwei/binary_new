package diskimage

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"hash/crc32"
	"math"
	"strconv"
	"testing"
	"unicode/utf16"
)

func TestParseRawImage(t *testing.T) {
	image := make([]byte, 8192)
	result, err := Parse(context.Background(), bytes.NewReader(image), int64(len(image)), Options{})
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if result.Table != TableRaw || result.SectorSize != 0 ||
		len(result.Partitions) != 1 || result.Partitions[0].SizeBytes != int64(len(image)) {
		t.Fatalf("Parse() = %#v", result)
	}
}

func TestParseMBRPrimaryPartitions(t *testing.T) {
	image := make([]byte, 4096*512)
	writeMBR(image, []mbrFixtureEntry{
		{slot: 0, bootable: true, kind: 0x83, start: 64, sectors: 100},
		{slot: 1, kind: 0x07, start: 256, sectors: 200},
	})
	result, err := Parse(context.Background(), bytes.NewReader(image), int64(len(image)), Options{})
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if result.Table != TableMBR || result.SectorSize != 512 || result.Partial ||
		len(result.Partitions) != 2 {
		t.Fatalf("Parse() = %#v", result)
	}
	if !result.Partitions[0].Bootable || result.Partitions[0].OffsetBytes != 64*512 ||
		result.Partitions[1].Type != "0x07" {
		t.Fatalf("partitions = %#v", result.Partitions)
	}
}

func TestParseMBRAutoDetects4096ByteSector(t *testing.T) {
	image := make([]byte, 128*4096)
	writeMBR(image, []mbrFixtureEntry{{
		slot: 0, kind: 0x83, start: 8, sectors: 32,
	}})
	extOffset := 8*4096 + 1024 + 0x38
	copy(image[extOffset:extOffset+2], []byte{0x53, 0xef})
	result, err := Parse(context.Background(), bytes.NewReader(image), int64(len(image)), Options{})
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if result.SectorSize != 4096 || len(result.Partitions) != 1 ||
		result.Partitions[0].OffsetBytes != 8*4096 {
		t.Fatalf("Parse() = %#v", result)
	}
}

func TestParseExtendedMBRAndBoundCycle(t *testing.T) {
	image := make([]byte, 4096*512)
	writeMBR(image, []mbrFixtureEntry{{
		slot: 0, kind: 0x0f, start: 100, sectors: 1000,
	}})
	writeEBR(image, 100, mbrFixtureEntry{kind: 0x83, start: 1, sectors: 100},
		mbrFixtureEntry{kind: 0x0f, start: 200, sectors: 700})
	writeEBR(image, 300, mbrFixtureEntry{kind: 0x83, start: 1, sectors: 100},
		mbrFixtureEntry{kind: 0x0f, start: 200, sectors: 700})
	result, err := Parse(context.Background(), bytes.NewReader(image), int64(len(image)), Options{})
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if len(result.Partitions) != 2 || !result.Partitions[0].Logical ||
		!result.Partitions[1].Logical || !result.Partial ||
		!hasDiagnostic(result, "ebr_cycle") {
		t.Fatalf("Parse() = %#v", result)
	}
}

func TestParseMBRRejectsOverlappingPartition(t *testing.T) {
	image := make([]byte, 4096*512)
	writeMBR(image, []mbrFixtureEntry{
		{slot: 0, kind: 0x83, start: 64, sectors: 200},
		{slot: 1, kind: 0x07, start: 128, sectors: 200},
	})
	result, err := Parse(context.Background(), bytes.NewReader(image), int64(len(image)), Options{})
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if len(result.Partitions) != 1 || !result.Partial ||
		!hasDiagnostic(result, "overlapping_partition") {
		t.Fatalf("Parse() = %#v", result)
	}
}

func TestParseGPT512And4096(t *testing.T) {
	for _, sectorSize := range []uint64{512, 4096} {
		t.Run(strconv.FormatUint(sectorSize, 10), func(t *testing.T) {
			image := gptFixture(t, sectorSize, false)
			result, err := Parse(
				context.Background(), bytes.NewReader(image), int64(len(image)), Options{},
			)
			if err != nil {
				t.Fatalf("Parse() error = %v", err)
			}
			if result.Table != TableGPT || result.SectorSize != sectorSize ||
				result.Partial || len(result.Partitions) != 2 {
				t.Fatalf("Parse() = %#v", result)
			}
			if result.Partitions[0].Name != "rootfs" ||
				result.Partitions[1].Name != "data" {
				t.Fatalf("partitions = %#v", result.Partitions)
			}
		})
	}
}

func TestParseGPT4096IgnoresCorrupt512ByteDecoyHeader(t *testing.T) {
	image := gptFixture(t, 4096, false)
	copy(image[512:520], "EFI PART")
	binary.LittleEndian.PutUint32(image[520:524], 0x00010000)
	binary.LittleEndian.PutUint32(image[524:528], 92)
	result, err := Parse(
		context.Background(), bytes.NewReader(image), int64(len(image)), Options{},
	)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if result.Table != TableGPT || result.SectorSize != 4096 ||
		len(result.Partitions) != 2 {
		t.Fatalf("Parse() = %#v", result)
	}
}

func TestParseGPTRejectsOverlapWithoutPublishingIt(t *testing.T) {
	image := gptFixture(t, 512, true)
	result, err := Parse(context.Background(), bytes.NewReader(image), int64(len(image)), Options{})
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if len(result.Partitions) != 1 || !result.Partial ||
		!hasDiagnostic(result, "overlapping_partition") {
		t.Fatalf("Parse() = %#v", result)
	}
}

func TestParseGPTRejectsCorruptHeaderAndEntryArray(t *testing.T) {
	t.Run("header CRC", func(t *testing.T) {
		image := gptFixture(t, 512, false)
		image[512+24] ^= 0xff
		_, err := Parse(context.Background(), bytes.NewReader(image), int64(len(image)), Options{})
		if !errors.Is(err, ErrCorruptTable) {
			t.Fatalf("Parse() error = %v", err)
		}
	})
	t.Run("entry CRC", func(t *testing.T) {
		image := gptFixture(t, 512, false)
		image[2*512+32] ^= 0xff
		_, err := Parse(context.Background(), bytes.NewReader(image), int64(len(image)), Options{})
		if !errors.Is(err, ErrCorruptTable) {
			t.Fatalf("Parse() error = %v", err)
		}
	})
	t.Run("backup entry CRC", func(t *testing.T) {
		image := gptFixture(t, 512, false)
		image[(256-2)*512+32] ^= 0xff
		_, err := Parse(context.Background(), bytes.NewReader(image), int64(len(image)), Options{})
		if !errors.Is(err, ErrCorruptTable) {
			t.Fatalf("Parse() error = %v", err)
		}
	})
}

func TestParseHonorsContextAndPartitionLimit(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	image := gptFixture(t, 512, false)
	if _, err := Parse(ctx, bytes.NewReader(image), int64(len(image)), Options{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled Parse() error = %v", err)
	}
	if _, err := Parse(
		context.Background(), bytes.NewReader(image), int64(len(image)),
		Options{MaxPartitions: 1},
	); !errors.Is(err, ErrLimit) {
		t.Fatalf("limited Parse() error = %v", err)
	}

	extended := make([]byte, 4096*512)
	writeMBR(extended, []mbrFixtureEntry{{
		slot: 0, kind: 0x0f, start: 100, sectors: 1000,
	}})
	writeEBR(extended, 100,
		mbrFixtureEntry{kind: 0x83, start: 1, sectors: 100},
		mbrFixtureEntry{kind: 0x0f, start: 200, sectors: 700})
	writeEBR(extended, 300,
		mbrFixtureEntry{kind: 0x83, start: 1, sectors: 100},
		mbrFixtureEntry{})
	limited, err := Parse(
		context.Background(), bytes.NewReader(extended), int64(len(extended)),
		Options{MaxPartitions: 1},
	)
	if !errors.Is(err, ErrLimit) {
		t.Fatalf("limited EBR Parse() error = %v", err)
	}
	if len(limited.Partitions) != 1 || !limited.Partial ||
		!hasDiagnostic(limited, "partition_limit") {
		t.Fatalf("limited EBR Parse() result = %#v", limited)
	}

	primaryThenExtended := make([]byte, 4096*512)
	writeMBR(primaryThenExtended, []mbrFixtureEntry{
		{slot: 0, kind: 0x83, start: 64, sectors: 16},
		{slot: 1, kind: 0x0f, start: 100, sectors: 1000},
	})
	writeEBR(primaryThenExtended, 100,
		mbrFixtureEntry{kind: 0x83, start: 1, sectors: 100},
		mbrFixtureEntry{})
	limited, err = Parse(
		context.Background(),
		bytes.NewReader(primaryThenExtended),
		int64(len(primaryThenExtended)),
		Options{MaxPartitions: 1},
	)
	if !errors.Is(err, ErrLimit) || len(limited.Partitions) != 1 ||
		limited.Partitions[0].Logical || !limited.Partial ||
		!hasDiagnostic(limited, "partition_limit") {
		t.Fatalf("primary+extended limit result = (%#v, %v)", limited, err)
	}
}

func FuzzParse(f *testing.F) {
	f.Add(make([]byte, 4096))
	mbr := make([]byte, 4096*512)
	writeMBR(mbr, []mbrFixtureEntry{{slot: 0, kind: 0x83, start: 8, sectors: 8}})
	f.Add(mbr)
	f.Fuzz(func(t *testing.T, image []byte) {
		if len(image) == 0 || len(image) > 8<<20 {
			t.Skip()
		}
		_, _ = Parse(context.Background(), bytes.NewReader(image), int64(len(image)), Options{})
	})
}

type mbrFixtureEntry struct {
	slot     int
	bootable bool
	kind     byte
	start    uint32
	sectors  uint32
}

func writeMBR(image []byte, entries []mbrFixtureEntry) {
	image[510], image[511] = 0x55, 0xaa
	for _, entry := range entries {
		writeMBREntry(image[446+entry.slot*16:446+(entry.slot+1)*16], entry)
	}
}

func writeEBR(
	image []byte,
	lba uint32,
	logical mbrFixtureEntry,
	next mbrFixtureEntry,
) {
	sector := image[int(lba)*512 : (int(lba)+1)*512]
	sector[510], sector[511] = 0x55, 0xaa
	writeMBREntry(sector[446:462], logical)
	writeMBREntry(sector[462:478], next)
}

func writeMBREntry(target []byte, entry mbrFixtureEntry) {
	if entry.bootable {
		target[0] = 0x80
	}
	target[4] = entry.kind
	binary.LittleEndian.PutUint32(target[8:12], entry.start)
	binary.LittleEndian.PutUint32(target[12:16], entry.sectors)
}

func gptFixture(t *testing.T, sectorSize uint64, overlap bool) []byte {
	t.Helper()
	const totalSectors = uint64(256)
	image := make([]byte, totalSectors*sectorSize)
	writeMBR(image, []mbrFixtureEntry{{
		slot: 0, kind: 0xee, start: 1,
		sectors: uint32(min(totalSectors-1, uint64(math.MaxUint32))),
	}})
	entryCount := uint32(4)
	entrySize := uint32(128)
	entries := make([]byte, int(entryCount*entrySize))
	writeGPTEntry(entries[0:128], 40, 79, "rootfs", 1)
	secondStart := uint64(90)
	if overlap {
		secondStart = 70
	}
	writeGPTEntry(entries[128:256], secondStart, 119, "data", 2)
	entryCRC := crc32.ChecksumIEEE(entries)
	primaryEntryLBA := uint64(2)
	entrySectors := (uint64(len(entries)) + sectorSize - 1) / sectorSize
	backupHeaderLBA := totalSectors - 1
	backupEntryLBA := backupHeaderLBA - entrySectors
	copy(image[primaryEntryLBA*sectorSize:], entries)
	copy(image[backupEntryLBA*sectorSize:], entries)
	firstUsable := primaryEntryLBA + entrySectors
	lastUsable := backupEntryLBA - 1
	diskGUID := [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	writeGPTHeader(
		image[sectorSize:2*sectorSize], 1, backupHeaderLBA,
		firstUsable, lastUsable, primaryEntryLBA, entryCount, entrySize,
		entryCRC, diskGUID,
	)
	writeGPTHeader(
		image[backupHeaderLBA*sectorSize:(backupHeaderLBA+1)*sectorSize],
		backupHeaderLBA, 1, firstUsable, lastUsable, backupEntryLBA,
		entryCount, entrySize, entryCRC, diskGUID,
	)
	return image
}

func writeGPTHeader(
	target []byte,
	current uint64,
	backup uint64,
	firstUsable uint64,
	lastUsable uint64,
	entryLBA uint64,
	entryCount uint32,
	entrySize uint32,
	entryCRC uint32,
	diskGUID [16]byte,
) {
	copy(target[:8], []byte("EFI PART"))
	binary.LittleEndian.PutUint32(target[8:12], 0x00010000)
	binary.LittleEndian.PutUint32(target[12:16], 92)
	binary.LittleEndian.PutUint64(target[24:32], current)
	binary.LittleEndian.PutUint64(target[32:40], backup)
	binary.LittleEndian.PutUint64(target[40:48], firstUsable)
	binary.LittleEndian.PutUint64(target[48:56], lastUsable)
	copy(target[56:72], diskGUID[:])
	binary.LittleEndian.PutUint64(target[72:80], entryLBA)
	binary.LittleEndian.PutUint32(target[80:84], entryCount)
	binary.LittleEndian.PutUint32(target[84:88], entrySize)
	binary.LittleEndian.PutUint32(target[88:92], entryCRC)
	copyForCRC := append([]byte(nil), target[:92]...)
	clear(copyForCRC[16:20])
	binary.LittleEndian.PutUint32(target[16:20], crc32.ChecksumIEEE(copyForCRC))
}

func writeGPTEntry(
	target []byte,
	first uint64,
	last uint64,
	name string,
	seed byte,
) {
	for index := 0; index < 16; index++ {
		target[index] = seed + byte(index)
		target[16+index] = seed + 32 + byte(index)
	}
	binary.LittleEndian.PutUint64(target[32:40], first)
	binary.LittleEndian.PutUint64(target[40:48], last)
	units := utf16.Encode([]rune(name))
	for index, value := range units {
		binary.LittleEndian.PutUint16(target[56+index*2:58+index*2], value)
	}
}

func hasDiagnostic(result Result, code string) bool {
	for _, diagnostic := range result.Diagnostics {
		if diagnostic.Code == code {
			return true
		}
	}
	return false
}

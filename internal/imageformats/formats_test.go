package imageformats

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"testing"

	"binaryscan/internal/imageextract"
)

func TestBuiltinsExtractISOAndDiskImages(t *testing.T) {
	engine := builtinsEngine(t, imageextract.Limits{})

	t.Run("ISO file extent", func(t *testing.T) {
		image := minimalISO(t)
		result, err := engine.Extract(context.Background(), imageextract.Request{
			Format: "iso9660", Source: bytes.NewReader(image),
			SizeBytes: int64(len(image)),
		})
		if err != nil {
			t.Fatal(err)
		}
		if result.Partial || len(result.Entries) != 1 {
			t.Fatalf("ISO result = %#v", result)
		}
		entry := result.Entries[0]
		if entry.LogicalPath != "/HELLO.TXT" ||
			entry.Kind != imageextract.EntryFile || entry.SizeBytes != 5 ||
			len(entry.Extents) != 1 ||
			entry.Extents[0] != (imageextract.Extent{
				OffsetBytes: 21 * 2048, SizeBytes: 5,
			}) {
			t.Fatalf("ISO entry = %#v", entry)
		}
		start := entry.Extents[0].OffsetBytes
		end := start + entry.Extents[0].SizeBytes
		content := image[start:end]
		if string(content) != "hello" {
			t.Fatalf("ISO extent content = %q", content)
		}
	})

	t.Run("MBR partition", func(t *testing.T) {
		image := minimalMBR(false)
		result, err := engine.Extract(context.Background(), imageextract.Request{
			Format: "mbr-img", Source: bytes.NewReader(image),
			SizeBytes: int64(len(image)),
		})
		if err != nil {
			t.Fatal(err)
		}
		if result.Partial || len(result.Partitions) != 1 ||
			result.Partitions[0].StartOffsetBytes != 8*512 ||
			result.Partitions[0].SizeBytes != 16*512 {
			t.Fatalf("MBR result = %#v", result)
		}
	})

	t.Run("raw view", func(t *testing.T) {
		image := make([]byte, 8192)
		result, err := engine.Extract(context.Background(), imageextract.Request{
			Format: "raw-img", Source: bytes.NewReader(image),
			SizeBytes: int64(len(image)),
		})
		if err != nil || result.Partial || len(result.Partitions) != 1 ||
			result.Partitions[0].Scheme != "raw" ||
			result.Partitions[0].SizeBytes != int64(len(image)) {
			t.Fatalf("raw result = (%#v, %v)", result, err)
		}
	})
}

func TestDiskAdapterRetainsAcceptedPartitionsOnPartialTable(t *testing.T) {
	engine := builtinsEngine(t, imageextract.Limits{})
	image := minimalMBR(true)
	result, err := engine.Extract(context.Background(), imageextract.Request{
		Format: "mbr-img", Source: bytes.NewReader(image),
		SizeBytes: int64(len(image)),
	})
	if !errors.Is(err, imageextract.ErrCorruptImage) {
		t.Fatalf("Extract() error = %v", err)
	}
	if !result.Partial || len(result.Partitions) != 1 ||
		result.ErrorCode != "image_corrupt" {
		t.Fatalf("partial result = %#v", result)
	}
}

func TestISOAdapterRetainsValidatedPrefixOnLocalCorruption(t *testing.T) {
	engine := builtinsEngine(t, imageextract.Limits{})
	image := minimalISO(t)
	root := image[20*2048 : 21*2048]
	position := 0
	for position < len(root) && root[position] != 0 {
		position += int(root[position])
	}
	bad := isoRecord(33, 2048, 0x02, []byte("BAD"))
	copy(root[position:], bad)
	result, err := engine.Extract(context.Background(), imageextract.Request{
		Format: "iso9660", Source: bytes.NewReader(image),
		SizeBytes: int64(len(image)),
	})
	if !errors.Is(err, imageextract.ErrCorruptImage) {
		t.Fatalf("Extract() error = %v", err)
	}
	if !result.Partial || len(result.Entries) != 1 ||
		result.Entries[0].LogicalPath != "/HELLO.TXT" {
		t.Fatalf("partial ISO result = %#v", result)
	}
}

func TestDiskAdapterRejectsRequestedTableMismatch(t *testing.T) {
	engine := builtinsEngine(t, imageextract.Limits{})
	image := make([]byte, 8192)
	result, err := engine.Extract(context.Background(), imageextract.Request{
		Format: "gpt-img", Source: bytes.NewReader(image),
		SizeBytes: int64(len(image)),
	})
	if !errors.Is(err, imageextract.ErrCorruptImage) || !result.Partial ||
		len(result.Partitions) != 0 {
		t.Fatalf("mismatch result = (%#v, %v)", result, err)
	}
}

func TestDiskAdapterRetainsPartitionPrefixAtLimit(t *testing.T) {
	engine := builtinsEngine(t, imageextract.Limits{MaxPartitions: 1})
	image := make([]byte, 128*512)
	image[510], image[511] = 0x55, 0xaa
	writeMBRPartition(image[446:462], 0x83, 8, 16)
	writeMBRPartition(image[462:478], 0x07, 32, 16)
	result, err := engine.Extract(context.Background(), imageextract.Request{
		Format: "mbr-img", Source: bytes.NewReader(image),
		SizeBytes: int64(len(image)),
	})
	if err != nil {
		t.Fatalf("Extract() error = %v", err)
	}
	if !result.Partial || result.LimitCode != imageextract.LimitMaxPartitions ||
		len(result.Partitions) != 1 {
		t.Fatalf("limited disk result = %#v", result)
	}
}

func builtinsEngine(
	t *testing.T,
	limits imageextract.Limits,
) *imageextract.Engine {
	t.Helper()
	registry := imageextract.NewRegistry()
	if err := RegisterBuiltins(registry, limits); err != nil {
		t.Fatal(err)
	}
	engine, err := imageextract.NewEngine(registry, limits)
	if err != nil {
		t.Fatal(err)
	}
	return engine
}

func minimalMBR(overlap bool) []byte {
	image := make([]byte, 64*512)
	image[510], image[511] = 0x55, 0xaa
	writeMBRPartition(image[446:462], 0x83, 8, 16)
	if overlap {
		writeMBRPartition(image[462:478], 0x07, 12, 16)
	}
	return image
}

func writeMBRPartition(target []byte, kind byte, start, sectors uint32) {
	target[4] = kind
	binary.LittleEndian.PutUint32(target[8:12], start)
	binary.LittleEndian.PutUint32(target[12:16], sectors)
}

func minimalISO(t *testing.T) []byte {
	t.Helper()
	const sectors = uint32(32)
	image := make([]byte, int(sectors)*2048)
	primary := image[16*2048 : 17*2048]
	primary[0] = 1
	copy(primary[1:6], "CD001")
	primary[6] = 1
	for index := 40; index < 72; index++ {
		primary[index] = ' '
	}
	copy(primary[40:72], "IMAGEFORMATS")
	putBoth32(primary[80:88], sectors)
	putBoth16(primary[120:124], 1)
	putBoth16(primary[124:128], 1)
	putBoth16(primary[128:132], 2048)
	putBoth32(primary[132:140], 10)
	rootRecord := isoRecord(20, 2048, 0x02, []byte{0})
	copy(primary[156:], rootRecord)

	terminator := image[17*2048 : 18*2048]
	terminator[0] = 255
	copy(terminator[1:6], "CD001")
	terminator[6] = 1

	root := image[20*2048 : 21*2048]
	position := 0
	for _, record := range [][]byte{
		isoRecord(20, 2048, 0x02, []byte{0}),
		isoRecord(20, 2048, 0x02, []byte{1}),
		isoRecord(21, 5, 0, []byte("HELLO.TXT;1")),
	} {
		copy(root[position:], record)
		position += len(record)
	}
	copy(image[21*2048:], "hello")
	return image
}

func isoRecord(lba, size uint32, flags byte, identifier []byte) []byte {
	length := 33 + len(identifier)
	if len(identifier)%2 == 0 {
		length++
	}
	record := make([]byte, length)
	record[0] = byte(length)
	putBoth32(record[2:10], lba)
	putBoth32(record[10:18], size)
	record[25] = flags
	putBoth16(record[28:32], 1)
	record[32] = byte(len(identifier))
	copy(record[33:], identifier)
	return record
}

func putBoth16(target []byte, value uint16) {
	binary.LittleEndian.PutUint16(target[:2], value)
	binary.BigEndian.PutUint16(target[2:4], value)
}

func putBoth32(target []byte, value uint32) {
	binary.LittleEndian.PutUint32(target[:4], value)
	binary.BigEndian.PutUint32(target[4:8], value)
}

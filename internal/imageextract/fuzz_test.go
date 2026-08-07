package imageextract

import (
	"bytes"
	"context"
	"errors"
	"io"
	"testing"
)

func FuzzEngineDamagedExtractorOutput(f *testing.F) {
	for _, seed := range [][]byte{
		{},
		{1},
		{0xff, 0, 0x80, 0xff},
		[]byte("../escape\x00overlap"),
		[]byte("valid-ish-multi-extent"),
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, payload []byte) {
		if len(payload) > 256 {
			payload = payload[:256]
		}
		value := func(index int) byte {
			if len(payload) == 0 {
				return 0
			}
			return payload[index%len(payload)]
		}
		sourceSize := int64(len(payload))
		if sourceSize == 0 {
			sourceSize = 1
		}
		extractor := ExtractorFunc(func(
			ctx context.Context, request Request, sink Sink,
		) error {
			if value(0)&1 != 0 {
				if err := sink.AddPartition(Partition{
					ID: "p", Index: uint32(value(1) & 3),
					StartOffsetBytes: int64(int8(value(2))),
					SizeBytes:        int64(value(3) & 31),
				}); err != nil {
					return err
				}
			}
			entryCount := int(value(4)&3) + 1
			for entryIndex := 0; entryIndex < entryCount; entryIndex++ {
				extentCount := int(value(5+entryIndex) & 3)
				extents := make([]Extent, extentCount)
				for extentIndex := range extents {
					extents[extentIndex] = Extent{
						OffsetBytes: int64(int8(value(8 + extentIndex*2))),
						SizeBytes:   int64(value(9+extentIndex*2) & 15),
					}
				}
				pathBytes := payload
				if len(pathBytes) > 12 {
					pathBytes = pathBytes[:12]
				}
				kinds := []EntryKind{
					EntryFile, EntryDirectory, EntrySymlink, EntryHardlink,
					EntrySpecial, EntryKind("invalid"),
				}
				entry := Entry{
					ID:          uint64(value(20+entryIndex) & 7),
					ParentID:    uint64(value(24+entryIndex) & 3),
					LogicalPath: "/" + string(pathBytes),
					Kind:        kinds[int(value(28+entryIndex))%len(kinds)],
					LinkTarget:  string(pathBytes),
					Extents:     extents,
					Depth:       int(value(32+entryIndex) & 7),
					SizeBytes:   int64(value(36+entryIndex) & 31),
					Status:      Status(string([]byte{value(40 + entryIndex)})),
				}
				if err := sink.AddEntry(entry); err != nil {
					return err
				}
			}
			return nil
		})
		engine := newFuzzEngine(t, extractor)
		result, _ := engine.Extract(context.Background(), Request{
			Format: "fuzz", Source: bytes.NewReader(make([]byte, sourceSize)),
			SizeBytes: sourceSize,
		})
		if len(result.Entries) > 8 || len(result.Partitions) > 4 ||
			result.ExtentCount > 8 || result.ExpandedBytes > 64 {
			t.Fatalf("unbounded result: %+v", result)
		}
		for _, entry := range result.Entries {
			if err := validateLogicalPath(entry.LogicalPath); err != nil {
				t.Fatalf("invalid path escaped collector: %+v", entry)
			}
			var total int64
			for _, extent := range entry.Extents {
				if extent.OffsetBytes < 0 || extent.SizeBytes <= 0 ||
					extent.OffsetBytes > sourceSize ||
					extent.SizeBytes > sourceSize-extent.OffsetBytes {
					t.Fatalf("invalid extent escaped collector: %+v", entry)
				}
				total += extent.SizeBytes
			}
			if entry.Kind == EntryFile && total != entry.SizeBytes {
				t.Fatalf("extent total mismatch escaped collector: %+v", entry)
			}
			if entry.Kind != EntryFile && len(entry.Extents) != 0 {
				t.Fatalf("non-file content escaped collector: %+v", entry)
			}
		}
	})
}

func FuzzReadOnlySourceBounds(f *testing.F) {
	f.Add([]byte("image"), int64(0), uint8(5))
	f.Add([]byte("image"), int64(-1), uint8(1))
	f.Add([]byte("image"), int64(4), uint8(4))
	f.Add([]byte{}, int64(0), uint8(1))
	f.Fuzz(func(t *testing.T, payload []byte, offset int64, length uint8) {
		if len(payload) > 1024 {
			payload = payload[:1024]
		}
		source := &readOnlySource{
			ctx: context.Background(), source: bytes.NewReader(payload),
			size: int64(len(payload)),
		}
		buffer := make([]byte, int(length))
		count, err := source.ReadAt(buffer, offset)
		if count < 0 || count > len(buffer) {
			t.Fatalf("invalid count %d for buffer %d", count, len(buffer))
		}
		if offset < 0 {
			if count != 0 || !errors.Is(err, ErrInvalidRequest) {
				t.Fatalf("negative offset result = %d, %v", count, err)
			}
			return
		}
		if len(buffer) > 0 && offset >= int64(len(payload)) &&
			(count != 0 || !errors.Is(err, io.EOF)) {
			t.Fatalf("out-of-range result = %d, %v", count, err)
		}
		if count > 0 && !bytes.Equal(buffer[:count], payload[offset:offset+int64(count)]) {
			t.Fatalf("reader exposed unexpected bytes")
		}
	})
}

func newFuzzEngine(t *testing.T, extractor Extractor) *Engine {
	t.Helper()
	registry := NewRegistry()
	if err := registry.Register("fuzz", extractor); err != nil {
		t.Fatalf("register fuzz extractor: %v", err)
	}
	engine, err := NewEngine(registry, Limits{
		MaxInputBytes: 256, MaxExpandedBytes: 64, MaxEntryBytes: 32,
		MaxEntries: 8, MaxExtents: 8, MaxPartitions: 4, MaxDepth: 4,
	})
	if err != nil {
		t.Fatalf("new fuzz engine: %v", err)
	}
	return engine
}

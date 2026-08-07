package imageextract

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"
)

func TestEngineExtractsValidatedMetadata(t *testing.T) {
	var callerExtents []Extent
	engine := newTestEngine(t, Limits{}, ExtractorFunc(func(
		ctx context.Context,
		request Request,
		sink Sink,
	) error {
		if request.Format != "raw-img" {
			return fmt.Errorf("unexpected format %q", request.Format)
		}
		if err := sink.AddPartition(Partition{
			ID: "p1", Index: 1, Scheme: "gpt", Type: "linux",
			StartOffsetBytes: 8, SizeBytes: 80, Filesystem: "ext4",
		}); err != nil {
			return err
		}
		if err := sink.AddEntry(Entry{
			ID: 1, LogicalPath: "/root", Kind: EntryDirectory, Depth: 1,
		}); err != nil {
			return err
		}
		callerExtents = []Extent{
			{OffsetBytes: 20, SizeBytes: 2},
			{OffsetBytes: 10, SizeBytes: 2},
		}
		if err := sink.AddEntry(Entry{
			ID: 2, ParentID: 1, PartitionID: "p1",
			LogicalPath: "/root/file", Kind: EntryFile, Depth: 2,
			SizeBytes: 4, Extents: callerExtents, Format: "ELF",
		}); err != nil {
			return err
		}
		callerExtents[0].OffsetBytes = 70
		return sink.AddEntry(Entry{
			ID: 3, ParentID: 1, PartitionID: "p1",
			LogicalPath: "/root/link", Kind: EntrySymlink, Depth: 2,
			LinkTarget: "../file",
		})
	}))

	result, err := engine.Extract(context.Background(), testRequest(" RAW-IMG ", 128))
	if err != nil {
		t.Fatalf("extract: %v", err)
	}
	if result.Partial || result.Format != "raw-img" ||
		len(result.Partitions) != 1 || len(result.Entries) != 3 {
		t.Fatalf("unexpected result: %+v", result)
	}
	file := result.Entries[1]
	if file.Status != StatusIndexed || file.Format != "elf" ||
		result.ExpandedBytes != 4 || result.ExtentCount != 2 {
		t.Fatalf("file/result metadata = %+v / %+v", file, result)
	}
	if file.Extents[0].OffsetBytes != 20 || file.Extents[1].OffsetBytes != 10 {
		t.Fatalf("extents were aliased or reordered: %+v", file.Extents)
	}
	if result.Entries[2].Status != StatusRecorded {
		t.Fatalf("link default status = %q", result.Entries[2].Status)
	}

	result.Entries[1].Extents[0].OffsetBytes = 99
	again, err := engine.Extract(context.Background(), testRequest("raw-img", 128))
	if err != nil || again.Entries[1].Extents[0].OffsetBytes != 20 {
		t.Fatalf("result aliases engine state: result=%+v err=%v", again, err)
	}
}

func TestEngineConfinesSourceReads(t *testing.T) {
	engine := newTestEngine(t, Limits{}, ExtractorFunc(func(
		ctx context.Context,
		request Request,
		sink Sink,
	) error {
		buffer := make([]byte, 4)
		count, err := request.Source.ReadAt(buffer, 6)
		if count != 2 || !errors.Is(err, io.EOF) || !bytes.Equal(buffer[:2], []byte{6, 7}) {
			return fmt.Errorf("bounded read = %d %v %v", count, err, buffer)
		}
		if count, err = request.Source.ReadAt(buffer, 8); count != 0 || !errors.Is(err, io.EOF) {
			return fmt.Errorf("end read = %d %v", count, err)
		}
		if _, err = request.Source.ReadAt(buffer, -1); !errors.Is(err, ErrInvalidRequest) {
			return fmt.Errorf("negative read = %v", err)
		}
		return nil
	}))
	source := bytes.NewReader([]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9})
	result, err := engine.Extract(context.Background(), Request{
		Format: "raw-img", Source: source, SizeBytes: 8,
	})
	if err != nil || result.Partial {
		t.Fatalf("extract = %+v, %v", result, err)
	}
}

func TestEngineExactLimitsAndPlusOne(t *testing.T) {
	t.Run("input bytes", func(t *testing.T) {
		calls := 0
		engine := newTestEngine(t, Limits{MaxInputBytes: 4}, ExtractorFunc(func(
			context.Context, Request, Sink,
		) error {
			calls++
			return nil
		}))
		assertComplete(t, engine, testRequest("raw-img", 4))
		result, err := engine.Extract(context.Background(), testRequest("raw-img", 5))
		assertLimit(t, result, err, LimitMaxInputBytes)
		if calls != 1 {
			t.Fatalf("extractor calls = %d", calls)
		}
	})

	t.Run("cumulative reads", func(t *testing.T) {
		for extra, want := range map[bool]LimitCode{false: "", true: LimitMaxReadBytes} {
			extra, want := extra, want
			t.Run(fmt.Sprint(extra), func(t *testing.T) {
				engine := newTestEngine(t, Limits{MaxReadBytes: 4}, ExtractorFunc(func(
					ctx context.Context, request Request, sink Sink,
				) error {
					if _, err := request.Source.ReadAt(make([]byte, 4), 0); err != nil {
						return err
					}
					if extra {
						_, err := request.Source.ReadAt(make([]byte, 1), 4)
						return err
					}
					return nil
				}))
				result, err := engine.Extract(context.Background(), testRequest("raw-img", 8))
				if want == "" {
					if err != nil || result.Partial || result.ReadBytes != 4 {
						t.Fatalf("exact result = %+v, %v", result, err)
					}
				} else {
					assertLimit(t, result, err, want)
					if result.ReadBytes != 4 {
						t.Fatalf("read bytes = %d", result.ReadBytes)
					}
				}
			})
		}
	})

	t.Run("entry bytes", func(t *testing.T) {
		for size, want := range map[int64]LimitCode{4: "", 5: LimitMaxEntryBytes} {
			size, want := size, want
			t.Run(fmt.Sprint(size), func(t *testing.T) {
				engine := newTestEngine(t, Limits{MaxEntryBytes: 4}, fileExtractor(size))
				result, err := engine.Extract(context.Background(), testRequest("raw-img", 16))
				if want == "" {
					if err != nil || result.Partial || result.ExpandedBytes != 4 {
						t.Fatalf("exact result = %+v, %v", result, err)
					}
				} else {
					assertLimit(t, result, err, want)
					if len(result.Entries) != 0 || result.ExtentCount != 0 {
						t.Fatalf("offending entry was retained: %+v", result)
					}
				}
			})
		}
	})

	t.Run("expanded bytes", func(t *testing.T) {
		engine := newTestEngine(t, Limits{MaxExpandedBytes: 4}, ExtractorFunc(func(
			ctx context.Context, request Request, sink Sink,
		) error {
			if err := sink.AddEntry(rootDirectory(1, "/root", 1)); err != nil {
				return err
			}
			if err := sink.AddEntry(fileEntry(2, 1, "/root/a", 2, 3, 0)); err != nil {
				return err
			}
			return sink.AddEntry(fileEntry(3, 1, "/root/b", 2, 2, 4))
		}))
		result, err := engine.Extract(context.Background(), testRequest("raw-img", 16))
		assertLimit(t, result, err, LimitMaxExpandedBytes)
		if len(result.Entries) != 2 || result.ExpandedBytes != 3 {
			t.Fatalf("partial expanded result = %+v", result)
		}
	})

	t.Run("entries", func(t *testing.T) {
		engine := newTestEngine(t, Limits{MaxEntries: 1}, ExtractorFunc(func(
			ctx context.Context, request Request, sink Sink,
		) error {
			if err := sink.AddEntry(rootDirectory(1, "/a", 1)); err != nil {
				return err
			}
			return sink.AddEntry(rootDirectory(2, "/b", 1))
		}))
		result, err := engine.Extract(context.Background(), testRequest("raw-img", 1))
		assertLimit(t, result, err, LimitMaxEntries)
		if len(result.Entries) != 1 {
			t.Fatalf("entries = %d", len(result.Entries))
		}
	})

	t.Run("extents", func(t *testing.T) {
		for count, want := range map[int]LimitCode{2: "", 3: LimitMaxExtents} {
			count, want := count, want
			t.Run(fmt.Sprint(count), func(t *testing.T) {
				engine := newTestEngine(t, Limits{MaxExtents: 2}, ExtractorFunc(func(
					ctx context.Context, request Request, sink Sink,
				) error {
					extents := make([]Extent, count)
					for index := range extents {
						extents[index] = Extent{OffsetBytes: int64(index), SizeBytes: 1}
					}
					return sink.AddEntry(Entry{
						ID: 1, LogicalPath: "/file", Kind: EntryFile, Depth: 1,
						SizeBytes: int64(count), Extents: extents,
					})
				}))
				result, err := engine.Extract(context.Background(), testRequest("raw-img", 8))
				if want == "" {
					if err != nil || result.Partial || result.ExtentCount != 2 {
						t.Fatalf("exact result = %+v, %v", result, err)
					}
				} else {
					assertLimit(t, result, err, want)
				}
			})
		}
	})

	t.Run("partitions", func(t *testing.T) {
		engine := newTestEngine(t, Limits{MaxPartitions: 1}, ExtractorFunc(func(
			ctx context.Context, request Request, sink Sink,
		) error {
			if err := sink.AddPartition(Partition{
				ID: "p1", Index: 1, StartOffsetBytes: 0, SizeBytes: 4,
			}); err != nil {
				return err
			}
			return sink.AddPartition(Partition{
				ID: "p2", Index: 2, StartOffsetBytes: 4, SizeBytes: 4,
			})
		}))
		result, err := engine.Extract(context.Background(), testRequest("raw-img", 8))
		assertLimit(t, result, err, LimitMaxPartitions)
		if len(result.Partitions) != 1 {
			t.Fatalf("partitions = %d", len(result.Partitions))
		}
	})

	t.Run("depth", func(t *testing.T) {
		engine := newTestEngine(t, Limits{MaxDepth: 2}, ExtractorFunc(func(
			ctx context.Context, request Request, sink Sink,
		) error {
			if err := sink.AddEntry(rootDirectory(1, "/a", 1)); err != nil {
				return err
			}
			if err := sink.AddEntry(Entry{
				ID: 2, ParentID: 1, LogicalPath: "/a/b",
				Kind: EntryDirectory, Depth: 2,
			}); err != nil {
				return err
			}
			return sink.AddEntry(fileEntry(3, 2, "/a/b/c", 3, 1, 0))
		}))
		result, err := engine.Extract(context.Background(), testRequest("raw-img", 8))
		assertLimit(t, result, err, LimitMaxDepth)
		if len(result.Entries) != 2 {
			t.Fatalf("entries = %d", len(result.Entries))
		}
		request := testRequest("raw-img", 8)
		request.Depth = 2
		result, err = engine.Extract(context.Background(), request)
		assertLimit(t, result, err, LimitMaxDepth)
	})
}

func TestEngineNormalizesSecurityCeilings(t *testing.T) {
	engine := newTestEngine(t, Limits{
		MaxInputBytes:    DefaultMaxInputBytes + 1,
		MaxReadBytes:     -1,
		MaxExpandedBytes: 4,
		MaxEntryBytes:    8,
		MaxEntries:       DefaultMaxEntries + 1,
		MaxExtents:       DefaultMaxExtents + 1,
		MaxPartitions:    DefaultMaxPartitions + 1,
		MaxDepth:         DefaultMaxDepth + 1,
	}, ExtractorFunc(func(context.Context, Request, Sink) error { return nil }))
	got := engine.Limits()
	if got.MaxInputBytes != DefaultMaxInputBytes ||
		got.MaxReadBytes != DefaultMaxReadBytes ||
		got.MaxExpandedBytes != 4 || got.MaxEntryBytes != 4 ||
		got.MaxEntries != DefaultMaxEntries ||
		got.MaxExtents != DefaultMaxExtents ||
		got.MaxPartitions != DefaultMaxPartitions ||
		got.MaxDepth != DefaultMaxDepth {
		t.Fatalf("normalized limits = %+v", got)
	}
}

func TestEngineRejectsInvalidExtents(t *testing.T) {
	tests := map[string]Entry{
		"missing": fileEntry(1, 0, "/file", 1, 1, 0),
		"negative offset": {
			ID: 1, LogicalPath: "/file", Kind: EntryFile, Depth: 1,
			SizeBytes: 1, Extents: []Extent{{OffsetBytes: -1, SizeBytes: 1}},
		},
		"zero extent": {
			ID: 1, LogicalPath: "/file", Kind: EntryFile, Depth: 1,
			SizeBytes: 1, Extents: []Extent{{OffsetBytes: 0, SizeBytes: 0}},
		},
		"out of source": {
			ID: 1, LogicalPath: "/file", Kind: EntryFile, Depth: 1,
			SizeBytes: 2, Extents: []Extent{{OffsetBytes: 7, SizeBytes: 2}},
		},
		"sum too small": {
			ID: 1, LogicalPath: "/file", Kind: EntryFile, Depth: 1,
			SizeBytes: 3, Extents: []Extent{{OffsetBytes: 0, SizeBytes: 2}},
		},
		"sum too large": {
			ID: 1, LogicalPath: "/file", Kind: EntryFile, Depth: 1,
			SizeBytes: 2, Extents: []Extent{{OffsetBytes: 0, SizeBytes: 3}},
		},
		"overlap": {
			ID: 1, LogicalPath: "/file", Kind: EntryFile, Depth: 1,
			SizeBytes: 4, Extents: []Extent{
				{OffsetBytes: 0, SizeBytes: 2}, {OffsetBytes: 1, SizeBytes: 2},
			},
		},
		"empty file extent": {
			ID: 1, LogicalPath: "/file", Kind: EntryFile, Depth: 1,
			Extents: []Extent{{OffsetBytes: 0, SizeBytes: 1}},
		},
		"directory extent": {
			ID: 1, LogicalPath: "/dir", Kind: EntryDirectory, Depth: 1,
			Extents: []Extent{{OffsetBytes: 0, SizeBytes: 1}},
		},
	}
	tests["missing"] = Entry{
		ID: 1, LogicalPath: "/file", Kind: EntryFile, Depth: 1, SizeBytes: 1,
	}
	for name, entry := range tests {
		name, entry := name, entry
		t.Run(name, func(t *testing.T) {
			engine := newTestEngine(t, Limits{}, ExtractorFunc(func(
				ctx context.Context, request Request, sink Sink,
			) error {
				return sink.AddEntry(entry)
			}))
			result, err := engine.Extract(context.Background(), testRequest("raw-img", 8))
			if !errors.Is(err, ErrInvalidResult) || !result.Partial ||
				result.ErrorCode != "invalid_extractor_result" || len(result.Entries) != 0 {
				t.Fatalf("result = %+v, err=%v", result, err)
			}
		})
	}
}

func TestEngineRejectsExtentOutsidePartition(t *testing.T) {
	engine := newTestEngine(t, Limits{}, ExtractorFunc(func(
		ctx context.Context, request Request, sink Sink,
	) error {
		if err := sink.AddPartition(Partition{
			ID: "p1", Index: 1, StartOffsetBytes: 4, SizeBytes: 4,
		}); err != nil {
			return err
		}
		entry := fileEntry(1, 0, "/file", 1, 2, 0)
		entry.PartitionID = "p1"
		return sink.AddEntry(entry)
	}))
	result, err := engine.Extract(context.Background(), testRequest("raw-img", 8))
	if !errors.Is(err, ErrInvalidResult) || len(result.Entries) != 0 {
		t.Fatalf("result = %+v, err=%v", result, err)
	}
}

func TestEngineRejectsInvalidTreesAndPartitions(t *testing.T) {
	t.Run("root path skips parent", func(t *testing.T) {
		assertInvalidEntry(t, rootDirectory(1, "/a/b", 1))
	})
	t.Run("unclean path", func(t *testing.T) {
		assertInvalidEntry(t, rootDirectory(1, "/a/../b", 1))
	})
	t.Run("non NFC path", func(t *testing.T) {
		assertInvalidEntry(t, rootDirectory(1, "/e\u0301", 1))
	})
	t.Run("link target on file", func(t *testing.T) {
		entry := fileEntry(1, 0, "/file", 1, 1, 0)
		entry.LinkTarget = "/other"
		assertInvalidEntry(t, entry)
	})
	t.Run("missing link target", func(t *testing.T) {
		assertInvalidEntry(t, Entry{
			ID: 1, LogicalPath: "/link", Kind: EntrySymlink, Depth: 1,
		})
	})
	t.Run("child not immediate", func(t *testing.T) {
		engine := newTestEngine(t, Limits{}, ExtractorFunc(func(
			ctx context.Context, request Request, sink Sink,
		) error {
			if err := sink.AddEntry(rootDirectory(1, "/a", 1)); err != nil {
				return err
			}
			return sink.AddEntry(Entry{
				ID: 2, ParentID: 1, LogicalPath: "/a/b/c",
				Kind: EntryDirectory, Depth: 2,
			})
		}))
		_, err := engine.Extract(context.Background(), testRequest("raw-img", 8))
		if !errors.Is(err, ErrInvalidResult) {
			t.Fatalf("error = %v", err)
		}
	})

	partitionCases := map[string][]Partition{
		"zero index": {{ID: "p1", StartOffsetBytes: 0, SizeBytes: 1}},
		"zero size":  {{ID: "p1", Index: 1, StartOffsetBytes: 0}},
		"outside":    {{ID: "p1", Index: 1, StartOffsetBytes: 7, SizeBytes: 2}},
		"missing parent": {{
			ID: "p1", ParentID: "missing", Index: 1, SizeBytes: 1,
		}},
		"duplicate ID": {
			{ID: "p1", Index: 1, SizeBytes: 1},
			{ID: "p1", Index: 2, StartOffsetBytes: 1, SizeBytes: 1},
		},
		"duplicate index": {
			{ID: "p1", Index: 1, SizeBytes: 1},
			{ID: "p2", Index: 1, StartOffsetBytes: 1, SizeBytes: 1},
		},
		"overlap": {
			{ID: "p1", Index: 1, SizeBytes: 4},
			{ID: "p2", Index: 2, StartOffsetBytes: 3, SizeBytes: 2},
		},
	}
	for name, partitions := range partitionCases {
		name, partitions := name, partitions
		t.Run("partition "+name, func(t *testing.T) {
			engine := newTestEngine(t, Limits{}, ExtractorFunc(func(
				ctx context.Context, request Request, sink Sink,
			) error {
				for _, partition := range partitions {
					if err := sink.AddPartition(partition); err != nil {
						return err
					}
				}
				return nil
			}))
			result, err := engine.Extract(context.Background(), testRequest("raw-img", 8))
			if !errors.Is(err, ErrInvalidResult) || !result.Partial {
				t.Fatalf("result = %+v, error=%v", result, err)
			}
		})
	}
}

func TestEngineCancellationAndPartialErrors(t *testing.T) {
	t.Run("recorded local corruption is partial", func(t *testing.T) {
		engine := newTestEngine(t, Limits{}, ExtractorFunc(func(
			ctx context.Context, request Request, sink Sink,
		) error {
			return sink.AddEntry(Entry{
				ID: 1, LogicalPath: "/damaged", Kind: EntryFile, Depth: 1,
				Status: StatusCorrupt, ErrorCode: "bad_inode",
			})
		}))
		result, err := engine.Extract(context.Background(), testRequest("raw-img", 8))
		if err != nil || !result.Partial || len(result.Entries) != 1 {
			t.Fatalf("result = %+v, error=%v", result, err)
		}
	})

	t.Run("cancelled with retained result", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		started := make(chan struct{})
		engine := newTestEngine(t, Limits{}, ExtractorFunc(func(
			ctx context.Context, request Request, sink Sink,
		) error {
			if err := sink.AddPartition(Partition{
				ID: "p1", Index: 1, SizeBytes: 1,
			}); err != nil {
				return err
			}
			close(started)
			<-ctx.Done()
			return ctx.Err()
		}))
		go func() { <-started; cancel() }()
		result, err := engine.Extract(ctx, testRequest("raw-img", 8))
		if !errors.Is(err, context.Canceled) || !result.Partial ||
			result.LimitCode != LimitContextCancelled || len(result.Partitions) != 1 {
			t.Fatalf("result = %+v, error=%v", result, err)
		}
	})

	t.Run("corrupt with retained result", func(t *testing.T) {
		engine := newTestEngine(t, Limits{}, ExtractorFunc(func(
			ctx context.Context, request Request, sink Sink,
		) error {
			if err := sink.AddPartition(Partition{
				ID: "p1", Index: 1, SizeBytes: 1,
			}); err != nil {
				return err
			}
			return fmt.Errorf("bad superblock: %w", ErrCorruptImage)
		}))
		result, err := engine.Extract(context.Background(), testRequest("raw-img", 8))
		if !errors.Is(err, ErrCorruptImage) || !result.Partial ||
			result.ErrorCode != "image_corrupt" || len(result.Partitions) != 1 {
			t.Fatalf("result = %+v, error=%v", result, err)
		}
	})

	t.Run("panic is isolated with retained result", func(t *testing.T) {
		engine := newTestEngine(t, Limits{}, ExtractorFunc(func(
			ctx context.Context, request Request, sink Sink,
		) error {
			if err := sink.AddPartition(Partition{
				ID: "p1", Index: 1, SizeBytes: 1,
			}); err != nil {
				return err
			}
			panic("malformed image parser panic")
		}))
		result, err := engine.Extract(context.Background(), testRequest("raw-img", 8))
		if !errors.Is(err, ErrExtractorPanic) || !result.Partial ||
			result.ErrorCode != "extractor_panic" || len(result.Partitions) != 1 {
			t.Fatalf("result = %+v, error=%v", result, err)
		}
	})

	t.Run("bounded safe error", func(t *testing.T) {
		message := "bad\n" + strings.Repeat("界", maxTextBytes)
		engine := newTestEngine(t, Limits{}, ExtractorFunc(func(
			context.Context, Request, Sink,
		) error {
			return errors.New(message)
		}))
		result, err := engine.Extract(context.Background(), testRequest("raw-img", 8))
		if err == nil || len(result.ErrorMessage) > maxTextBytes ||
			!utf8.ValidString(result.ErrorMessage) {
			t.Fatalf("unsafe error message: %q", result.ErrorMessage)
		}
		for _, character := range result.ErrorMessage {
			if unicode.IsControl(character) {
				t.Fatalf("control character retained: %q", result.ErrorMessage)
			}
		}
	})
}

func TestSinkCannotBeUsedAfterExtractorReturns(t *testing.T) {
	var retained Sink
	engine := newTestEngine(t, Limits{}, ExtractorFunc(func(
		ctx context.Context, request Request, sink Sink,
	) error {
		retained = sink
		return nil
	}))
	assertComplete(t, engine, testRequest("raw-img", 8))
	err := retained.AddPartition(Partition{ID: "late", Index: 1, SizeBytes: 1})
	if !errors.Is(err, ErrInvalidResult) {
		t.Fatalf("late sink error = %v", err)
	}
}

func TestEngineRejectsInvalidRequests(t *testing.T) {
	engine := newTestEngine(t, Limits{}, ExtractorFunc(func(
		context.Context, Request, Sink,
	) error {
		return nil
	}))
	tests := []struct {
		name    string
		ctx     context.Context
		request Request
	}{
		{name: "nil context", request: testRequest("raw-img", 1)},
		{name: "nil source", ctx: context.Background(), request: Request{Format: "raw-img"}},
		{name: "negative size", ctx: context.Background(), request: Request{
			Format: "raw-img", Source: bytes.NewReader(nil), SizeBytes: -1,
		}},
		{name: "negative depth", ctx: context.Background(), request: Request{
			Format: "raw-img", Source: bytes.NewReader(nil), Depth: -1,
		}},
	}
	for _, test := range tests {
		_, err := engine.Extract(test.ctx, test.request)
		if !errors.Is(err, ErrInvalidRequest) {
			t.Errorf("%s error = %v", test.name, err)
		}
	}
	var nilEngine *Engine
	if _, err := nilEngine.Extract(context.Background(), testRequest("raw-img", 1)); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("nil engine error = %v", err)
	}
	if _, err := NewEngine(nil, Limits{}); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("nil registry error = %v", err)
	}
}

func newTestEngine(t *testing.T, limits Limits, extractor Extractor) *Engine {
	t.Helper()
	registry := NewRegistry()
	if err := registry.Register("raw-img", extractor); err != nil {
		t.Fatalf("register: %v", err)
	}
	engine, err := NewEngine(registry, limits)
	if err != nil {
		t.Fatalf("new engine: %v", err)
	}
	return engine
}

func testRequest(format string, size int64) Request {
	return Request{
		Format: format, Source: bytes.NewReader(make([]byte, size)), SizeBytes: size,
	}
}

func rootDirectory(id uint64, logicalPath string, depth int) Entry {
	return Entry{
		ID: id, LogicalPath: logicalPath, Kind: EntryDirectory, Depth: depth,
	}
}

func fileEntry(
	id, parentID uint64,
	logicalPath string,
	depth int,
	size, offset int64,
) Entry {
	entry := Entry{
		ID: id, ParentID: parentID, LogicalPath: logicalPath,
		Kind: EntryFile, Depth: depth, SizeBytes: size,
	}
	if size > 0 {
		entry.Extents = []Extent{{OffsetBytes: offset, SizeBytes: size}}
	}
	return entry
}

func fileExtractor(size int64) Extractor {
	return ExtractorFunc(func(ctx context.Context, request Request, sink Sink) error {
		return sink.AddEntry(fileEntry(1, 0, "/file", 1, size, 0))
	})
}

func assertComplete(t *testing.T, engine *Engine, request Request) Result {
	t.Helper()
	result, err := engine.Extract(context.Background(), request)
	if err != nil || result.Partial {
		t.Fatalf("expected complete result, got %+v, %v", result, err)
	}
	return result
}

func assertLimit(t *testing.T, result Result, err error, code LimitCode) {
	t.Helper()
	if err != nil || !result.Partial || result.LimitCode != code ||
		result.ErrorCode != string(code) || result.ErrorMessage == "" {
		t.Fatalf("expected limit %q, got %+v, %v", code, result, err)
	}
}

func assertInvalidEntry(t *testing.T, entry Entry) {
	t.Helper()
	engine := newTestEngine(t, Limits{}, ExtractorFunc(func(
		ctx context.Context, request Request, sink Sink,
	) error {
		return sink.AddEntry(entry)
	}))
	result, err := engine.Extract(context.Background(), testRequest("raw-img", 8))
	if !errors.Is(err, ErrInvalidResult) || !result.Partial {
		t.Fatalf("entry accepted: result=%+v error=%v", result, err)
	}
}

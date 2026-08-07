package extract

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	"binaryscan/internal/filetype"

	lzmalib "github.com/ulikunitz/xz/lzma"
)

func TestLZMAExtractionUsesDeclaredDictionaryBudget(t *testing.T) {
	payload := []byte("bounded LZMA-Alone extraction")
	data := lzmaAloneFixture(t, payload, lzmalib.MinDictCap)
	result, err := runLZMAExtract(
		t,
		context.Background(),
		data,
		generousLimits(),
	)
	if err != nil {
		t.Fatal(err)
	}
	node := findNode(t, result.Nodes, "/content")
	if result.Partial ||
		node.ExtractionStatus != StatusExtracted ||
		node.SizeBytes != int64(len(payload)) ||
		result.parserDecoderMemoryPeak !=
			int64(lzmalib.MinDictCap)+lzmaDecoderOverheadBytes ||
		result.parserDecoderMemoryUsed != 0 {
		t.Fatalf("result=%+v node=%+v", result, node)
	}
}

func TestLZMAKnownAndUnknownSizeRejectTrailingData(t *testing.T) {
	payload := []byte("one canonical LZMA-Alone stream")
	known := lzmaAloneFixture(t, payload, lzmalib.MinDictCap)
	unknown := lzmaAloneEOSFixture(t, payload, lzmalib.MinDictCap, nil)
	second := lzmaAloneFixture(
		t,
		[]byte("second stream"),
		lzmalib.MinDictCap,
	)
	tests := []struct {
		name    string
		data    []byte
		corrupt bool
	}{
		{name: "known-size", data: known},
		{name: "unknown-size-eos", data: unknown},
		{
			name:    "known-size-appended-garbage",
			data:    append(append([]byte(nil), known...), []byte("garbage")...),
			corrupt: true,
		},
		{
			name:    "known-size-single-trailing-byte",
			data:    append(append([]byte(nil), known...), 0),
			corrupt: true,
		},
		{
			name:    "unknown-size-appended-garbage",
			data:    append(append([]byte(nil), unknown...), []byte("garbage")...),
			corrupt: true,
		},
		{
			name:    "unknown-size-single-trailing-byte",
			data:    append(append([]byte(nil), unknown...), 0),
			corrupt: true,
		},
		{
			name:    "known-size-concatenated",
			data:    append(append([]byte(nil), known...), second...),
			corrupt: true,
		},
		{
			name:    "unknown-size-concatenated",
			data:    append(append([]byte(nil), unknown...), second...),
			corrupt: true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result, err := runLZMAExtract(
				t,
				context.Background(),
				test.data,
				generousLimits(),
			)
			if err != nil {
				t.Fatal(err)
			}
			node := findNode(t, result.Nodes, "/content")
			if test.corrupt {
				if !result.Partial ||
					node.ExtractionStatus != StatusCorrupt ||
					node.ErrorCode != "lzma_archive_corrupt" ||
					result.parserDecoderMemoryUsed != 0 {
					t.Fatalf("result=%+v node=%+v", result, node)
				}
				return
			}
			if result.Partial ||
				node.ExtractionStatus != StatusExtracted ||
				node.SizeBytes != int64(len(payload)) ||
				result.parserDecoderMemoryUsed != 0 {
				t.Fatalf("result=%+v node=%+v", result, node)
			}
		})
	}
}

func TestLZMAMaximumPropertiesUseConservativeOverhead(t *testing.T) {
	properties, err := lzmalib.PropertiesForCode(224)
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte("maximum legal LZMA properties")
	data := lzmaAloneFixtureWithConfig(
		t,
		payload,
		lzmalib.MinDictCap,
		&properties,
		true,
	)
	result, err := runLZMAExtract(
		t,
		context.Background(),
		data,
		generousLimits(),
	)
	if err != nil {
		t.Fatal(err)
	}
	node := findNode(t, result.Nodes, "/content")
	expectedPeak := int64(lzmalib.MinDictCap) + lzmaDecoderOverheadBytes
	if result.Partial ||
		node.ExtractionStatus != StatusExtracted ||
		node.SizeBytes != int64(len(payload)) ||
		result.parserDecoderMemoryPeak != expectedPeak ||
		result.parserDecoderMemoryUsed != 0 {
		t.Fatalf(
			"result=%+v node=%+v expected_peak=%d",
			result,
			node,
			expectedPeak,
		)
	}
}

func TestLZMAMaximumDictionaryReservationFitsTaskBudget(t *testing.T) {
	data := lzmaAloneFixture(t, []byte("small"), lzmalib.MinDictCap)
	binary.LittleEndian.PutUint32(
		data[1:5],
		uint32(maxStreamDecoderMemoryBytes),
	)
	info, err := preflightLZMA(
		context.Background(),
		bytes.NewReader(data),
		int64(len(data)),
	)
	if err != nil {
		t.Fatal(err)
	}
	expected := int64(maxStreamDecoderMemoryBytes) +
		lzmaDecoderOverheadBytes
	if info.DictionaryBytes != int64(maxStreamDecoderMemoryBytes) ||
		info.DecoderMemoryBytes != expected ||
		info.DecoderMemoryBytes > maxTaskParserDecoderMemoryBytes {
		t.Fatalf("info=%+v expected=%d", info, expected)
	}
}

func TestLZMAReleasesDictionaryBeforeNestedTAR(t *testing.T) {
	payload := tarStreamFixture(t, "payload.txt", []byte("nested"))
	data := lzmaAloneFixture(t, payload, lzmalib.MinDictCap)
	result, err := runLZMAExtract(
		t,
		context.Background(),
		data,
		generousLimits(),
	)
	if err != nil {
		t.Fatal(err)
	}
	container := findNode(t, result.Nodes, "/content")
	child := findNode(t, result.Nodes, "/content/payload.txt")
	expectedPeak := estimateTARParserMemory(maxTARMetadataBytes)
	if result.Partial ||
		container.Format != "tar" ||
		child.ParentLocalID != container.LocalID ||
		child.ExtractionStatus != StatusExtracted ||
		result.parserDecoderMemoryPeak != expectedPeak ||
		result.parserDecoderMemoryUsed != 0 {
		t.Fatalf(
			"result=%+v container=%+v child=%+v expected_peak=%d",
			result,
			container,
			child,
			expectedPeak,
		)
	}
}

func TestLZMADictionaryLimitIsRejectedBeforeDecoder(t *testing.T) {
	data := lzmaAloneFixture(t, []byte("small"), lzmalib.MinDictCap)
	binary.LittleEndian.PutUint32(
		data[1:5],
		uint32(maxStreamDecoderMemoryBytes+1),
	)
	result, err := runLZMAExtract(
		t,
		context.Background(),
		data,
		generousLimits(),
	)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Partial ||
		result.LimitCode != LimitMaxDecoderMemory ||
		len(result.Nodes) != 0 ||
		result.parserDecoderMemoryPeak != 0 ||
		result.parserDecoderMemoryUsed != 0 {
		t.Fatalf("result=%+v", result)
	}
}

func TestLZMACorruptHeadersAreDiagnosed(t *testing.T) {
	valid := lzmaAloneFixture(t, []byte("payload"), lzmalib.MinDictCap)
	oversizedLength := append([]byte(nil), valid...)
	binary.LittleEndian.PutUint64(oversizedLength[5:13], uint64(1)<<63)
	tests := []struct {
		name string
		data []byte
	}{
		{name: "truncated", data: valid[:lzmaAloneHeaderLength-1]},
		{name: "properties", data: append([]byte{0xff}, valid[1:]...)},
		{name: "declared-size", data: oversizedLength},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result, err := runLZMAExtract(
				t,
				context.Background(),
				test.data,
				generousLimits(),
			)
			if err != nil {
				t.Fatal(err)
			}
			if result.Partial != true ||
				len(result.Nodes) != 1 ||
				result.Nodes[0].ExtractionStatus != StatusCorrupt ||
				result.Nodes[0].ErrorCode != "lzma_archive_corrupt" ||
				result.parserDecoderMemoryUsed != 0 {
				t.Fatalf("result=%+v", result)
			}
		})
	}
}

func TestLZMACancellationIsPropagated(t *testing.T) {
	data := lzmaAloneFixture(
		t,
		bytes.Repeat([]byte("cancel"), 4096),
		lzmalib.MinDictCap,
	)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	result, err := runLZMAExtract(t, ctx, data, generousLimits())
	if !errors.Is(err, context.Canceled) ||
		!result.Partial ||
		result.LimitCode != LimitContextCancelled ||
		len(result.Nodes) != 0 ||
		result.parserDecoderMemoryUsed != 0 {
		t.Fatalf("result=%+v err=%v", result, err)
	}

	readCtx, readCancel := context.WithCancel(context.Background())
	source := &cancelAfterSequentialReads{
		reader:      bytes.NewReader(data),
		cancel:      readCancel,
		cancelAfter: 2,
	}
	_, err = (lzmalib.ReaderConfig{
		DictCap: int(maxStreamDecoderMemoryBytes),
	}).NewReader(contextAwareReader{ctx: readCtx, reader: source})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("NewReader() error=%v reads=%d", err, source.reads)
	}
}

func TestLZMAReusesExpandedByteRatioLimit(t *testing.T) {
	payload := bytes.Repeat([]byte{0}, 64<<10)
	data := lzmaAloneFixture(t, payload, lzmalib.MinDictCap)
	limits := generousLimits()
	limits.MaxRatio = 2
	result, err := runLZMAExtract(
		t,
		context.Background(),
		data,
		limits,
	)
	if err != nil {
		t.Fatal(err)
	}
	node := findNode(t, result.Nodes, "/content")
	if !result.Partial ||
		result.LimitCode != LimitMaxRatio ||
		node.ExtractionStatus != StatusLimitExceeded ||
		result.ExpandedBytes > int64(len(data))*limits.MaxRatio ||
		result.parserDecoderMemoryUsed != 0 {
		t.Fatalf("result=%+v node=%+v", result, node)
	}
}

func lzmaAloneFixture(
	t *testing.T,
	payload []byte,
	dictionaryBytes int,
) []byte {
	t.Helper()
	return lzmaAloneFixtureWithConfig(
		t,
		payload,
		dictionaryBytes,
		nil,
		true,
	)
}

func lzmaAloneEOSFixture(
	t *testing.T,
	payload []byte,
	dictionaryBytes int,
	properties *lzmalib.Properties,
) []byte {
	t.Helper()
	return lzmaAloneFixtureWithConfig(
		t,
		payload,
		dictionaryBytes,
		properties,
		false,
	)
}

func lzmaAloneFixtureWithConfig(
	t *testing.T,
	payload []byte,
	dictionaryBytes int,
	properties *lzmalib.Properties,
	sizeInHeader bool,
) []byte {
	t.Helper()
	var output bytes.Buffer
	config := lzmalib.WriterConfig{
		Properties: properties,
		DictCap:    dictionaryBytes,
	}
	if sizeInHeader {
		config.SizeInHeader = true
		config.Size = int64(len(payload))
	} else {
		config.EOSMarker = true
	}
	writer, err := config.NewWriter(&output)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Write(payload); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return append([]byte(nil), output.Bytes()...)
}

func runLZMAExtract(
	t *testing.T,
	ctx context.Context,
	data []byte,
	limits Limits,
) (Result, error) {
	t.Helper()
	sourcePath := filepath.Join(t.TempDir(), "input.lzma")
	if err := os.WriteFile(sourcePath, data, 0o600); err != nil {
		t.Fatal(err)
	}
	source, err := os.Open(sourcePath)
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()

	workDir := t.TempDir()
	engine := NewEngine(filetype.Detector{}, limits)
	state := operationState{
		engine:      engine,
		ctx:         ctx,
		workDir:     workDir,
		rootSize:    int64(len(data)),
		nextID:      1,
		paths:       make(map[string]struct{}),
		nodeIndex:   make(map[int]int),
		directories: make(map[string]int),
		memory: parserDecoderMemory{
			limit: engine.parserDecoderMemoryLimit,
		},
	}
	container := containerBudget{sourceSize: int64(len(data))}
	extractErr := state.extractLZMA(
		source,
		int64(len(data)),
		0,
		"",
		0,
		&container,
	)
	if extractErr != nil {
		var limit *limitError
		switch {
		case errors.As(extractErr, &limit):
			state.markLimit(limit.code)
			extractErr = nil
		case errors.Is(extractErr, context.Canceled),
			errors.Is(extractErr, context.DeadlineExceeded):
			state.markLimit(LimitContextCancelled)
		}
	}
	result := state.result()
	assertNodeGraph(t, result.Nodes)
	entries, readErr := os.ReadDir(workDir)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if len(entries) != 0 {
		t.Fatalf("work directory is not clean: %v", entries)
	}
	return result, extractErr
}

func TestLZMAContextAwareSourceCancelsWhileReading(t *testing.T) {
	data := lzmaAloneFixture(
		t,
		bytes.Repeat([]byte("context"), 4096),
		lzmalib.MinDictCap,
	)
	ctx, cancel := context.WithCancel(context.Background())
	source := &cancelAfterSequentialReads{
		reader:      bytes.NewReader(data),
		cancel:      cancel,
		cancelAfter: 3,
	}
	decoder, err := (lzmalib.ReaderConfig{
		DictCap: int(maxStreamDecoderMemoryBytes),
	}).NewReader(contextAwareReader{ctx: ctx, reader: source})
	if err != nil {
		if errors.Is(err, context.Canceled) {
			return
		}
		t.Fatal(err)
	}
	_, err = io.ReadAll(decoder)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("ReadAll() error=%v reads=%d", err, source.reads)
	}
}

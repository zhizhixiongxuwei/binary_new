package extract

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"io"
	"math"
	"os"
	"path/filepath"
	"testing"

	"binaryscan/internal/filetype"

	xzlib "github.com/ulikunitz/xz"
)

func TestEstimateZIPParserMemoryIsConservativeAndSaturating(t *testing.T) {
	empty := estimateZIPParserMemory(zipDirectoryInfo{})
	if empty != int64(zipParserFixedMemoryBytes) {
		t.Fatalf("empty estimate = %d", empty)
	}

	maximumAllowed := zipDirectoryInfo{
		size:    maxZIPDirectoryMetadataBytes,
		records: defaultMaxNodes,
	}
	estimated := estimateZIPParserMemory(maximumAllowed)
	expected := int64(
		3*maxZIPDirectoryMetadataBytes +
			defaultMaxNodes*zipParserEntryMemoryBytes +
			zipParserFixedMemoryBytes,
	)
	if estimated != expected ||
		estimated >= maxTaskParserDecoderMemoryBytes {
		t.Fatalf(
			"maximum estimate = %d, want %d below %d",
			estimated,
			expected,
			maxTaskParserDecoderMemoryBytes,
		)
	}

	for _, directory := range []zipDirectoryInfo{
		{size: math.MaxUint64},
		{records: math.MaxUint64},
	} {
		if got := estimateZIPParserMemory(directory); got != math.MaxInt64 {
			t.Fatalf("saturated estimate = %d for %+v", got, directory)
		}
	}
}

func TestEstimateTARParserMemoryIsConservativeAndSaturating(t *testing.T) {
	if got, want := estimateTARParserMemory(0),
		tarParserFixedMemoryReservation; got != want {
		t.Fatalf("empty estimate = %d, want %d", got, want)
	}
	if got, want := estimateTARParserMemory(maxTARMetadataBytes),
		tarParserFixedMemoryReservation+
			maxTARMetadataBytes*tarParserMemoryAmplification; got != want ||
		got >= maxTaskParserDecoderMemoryBytes {
		t.Fatalf(
			"maximum estimate = %d, want %d below %d",
			got,
			want,
			maxTaskParserDecoderMemoryBytes,
		)
	}
	for _, metadataBytes := range []int64{-1, math.MaxInt64} {
		if got := estimateTARParserMemory(metadataBytes); got != math.MaxInt64 {
			t.Fatalf("saturated estimate = %d for %d", got, metadataBytes)
		}
	}
}

func TestTaskMemoryBudgetLimitsNestedZIPBranches(t *testing.T) {
	largeDictionaryXZ := setXZDictionaryProperty(
		t,
		xzStreamFixture(t, []byte("xz")),
		28, // 64 MiB
	)
	outer := zipFixture(t, []zipEntry{
		{name: "limited.xz", body: largeDictionaryXZ, store: true},
		{name: "limited.zst", body: zstdStreamFixture(t, []byte("zstd")), store: true},
		{name: "safe.txt", body: []byte("safe"), store: true},
	})
	directory, err := preflightZIPDirectory(
		context.Background(),
		bytes.NewReader(outer),
		int64(len(outer)),
		10,
	)
	if err != nil {
		t.Fatal(err)
	}
	zipMemory := estimateZIPParserMemory(directory)
	engine := NewEngine(filetype.Detector{}, generousLimits())
	engine.parserDecoderMemoryLimit =
		zipMemory + int64(maxStreamDecoderMemoryBytes) - 1

	result := runExtractWithEngine(t, engine, outer, "zip")
	xzNode := findNode(t, result.Nodes, "/limited.xz")
	zstdNode := findNode(t, result.Nodes, "/limited.zst")
	safeNode := findNode(t, result.Nodes, "/safe.txt")
	if !result.Partial ||
		result.LimitCode != LimitMaxDecoderMemory ||
		xzNode.ExtractionStatus != StatusLimitExceeded ||
		xzNode.ErrorCode != LimitMaxDecoderMemory ||
		zstdNode.ExtractionStatus != StatusLimitExceeded ||
		zstdNode.ErrorCode != LimitMaxDecoderMemory ||
		safeNode.ExtractionStatus != StatusExtracted {
		t.Fatalf(
			"result=%+v xz=%+v zstd=%+v safe=%+v",
			result,
			xzNode,
			zstdNode,
			safeNode,
		)
	}
	if result.parserDecoderMemoryPeak != zipMemory ||
		result.parserDecoderMemoryUsed != 0 {
		t.Fatalf(
			"memory peak=%d used=%d, want peak=%d used=0",
			result.parserDecoderMemoryPeak,
			result.parserDecoderMemoryUsed,
			zipMemory,
		)
	}
}

func TestNestedStreamDecodersReleaseMemoryBeforeRecursion(t *testing.T) {
	const layers = 6
	tests := []struct {
		name        string
		format      string
		wrap        func([]byte) []byte
		expectedMax int64
	}{
		{
			name:   "zstd",
			format: "zstd",
			wrap: func(payload []byte) []byte {
				return zstdStreamFixture(t, payload)
			},
			expectedMax: int64(maxStreamDecoderMemoryBytes),
		},
		{
			name:   "xz",
			format: "xz",
			wrap: func(payload []byte) []byte {
				return xzStreamFixture(t, payload)
			},
			expectedMax: 8 << 20,
		},
		{
			name:   "gzip",
			format: "gzip",
			wrap: func(payload []byte) []byte {
				var output bytes.Buffer
				writer := gzip.NewWriter(&output)
				if _, err := writer.Write(payload); err != nil {
					t.Fatal(err)
				}
				if err := writer.Close(); err != nil {
					t.Fatal(err)
				}
				return output.Bytes()
			},
			expectedMax: gzipDecoderMemoryReservation,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			payload := []byte("leaf")
			for range layers {
				payload = test.wrap(payload)
			}
			result := runExtract(t, payload, test.format, generousLimits())
			if result.Partial || len(result.Nodes) != layers {
				t.Fatalf("result = %+v", result)
			}
			if result.parserDecoderMemoryPeak != test.expectedMax ||
				result.parserDecoderMemoryUsed != 0 {
				t.Fatalf(
					"memory peak=%d used=%d, want peak=%d used=0",
					result.parserDecoderMemoryPeak,
					result.parserDecoderMemoryUsed,
					test.expectedMax,
				)
			}
		})
	}
}

func TestNestedTARParserMemoryIsChargedAcrossRecursion(t *testing.T) {
	const layers = 6
	payload := []byte("leaf")
	for range layers {
		payload = tarStreamFixture(t, "nested", payload)
	}
	result := runExtract(t, payload, "tar", generousLimits())
	expectedPeak := estimateTARParserMemory(maxTARMetadataBytes) +
		int64(layers-1)*estimateTARParserMemory(512)
	if result.Partial || len(result.Nodes) != layers {
		t.Fatalf("result = %+v", result)
	}
	if result.parserDecoderMemoryPeak != expectedPeak ||
		result.parserDecoderMemoryUsed != 0 {
		t.Fatalf(
			"memory peak=%d used=%d, want peak=%d used=0",
			result.parserDecoderMemoryPeak,
			result.parserDecoderMemoryUsed,
			expectedPeak,
		)
	}
}

func TestXZDecoderSourcePropagatesCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	source := &cancelAfterSequentialReads{
		reader:      bytes.NewReader(xzStreamFixture(t, []byte("payload"))),
		cancel:      cancel,
		cancelAfter: 3,
	}
	decoder, err := (xzlib.ReaderConfig{
		DictCap:      0,
		SingleStream: true,
	}).NewReader(contextAwareReader{
		ctx:    ctx,
		reader: source,
	})
	if err != nil {
		t.Fatalf("NewReader() error = %v", err)
	}
	_, err = io.ReadAll(decoder)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("decoder error = %v, reads = %d", err, source.reads)
	}
}

type cancelAfterSequentialReads struct {
	reader      io.Reader
	cancel      context.CancelFunc
	cancelAfter int
	reads       int
}

func (reader *cancelAfterSequentialReads) Read(buffer []byte) (int, error) {
	count, err := reader.reader.Read(buffer)
	reader.reads++
	if reader.reads == reader.cancelAfter {
		reader.cancel()
	}
	return count, err
}

func runExtractWithEngine(
	t *testing.T,
	engine *Engine,
	data []byte,
	format string,
) Result {
	t.Helper()
	sourcePath := filepath.Join(t.TempDir(), "input")
	if err := os.WriteFile(sourcePath, data, 0o600); err != nil {
		t.Fatal(err)
	}
	source, err := os.Open(sourcePath)
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	workDir := t.TempDir()
	result, err := engine.Extract(
		context.Background(),
		source,
		format,
		workDir,
	)
	if err != nil {
		t.Fatalf("Extract() error = %v", err)
	}
	assertNodeGraph(t, result.Nodes)
	entries, err := os.ReadDir(workDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("work directory is not clean: %v", entries)
	}
	return result
}

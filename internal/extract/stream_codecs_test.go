package extract

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"hash/crc32"
	"testing"

	"binaryscan/internal/filetype"

	"github.com/klauspost/compress/zstd"
	xzlib "github.com/ulikunitz/xz"
)

func TestXZAndZSTDExtractionAndDetection(t *testing.T) {
	payload := []byte("bounded stream extraction")
	for _, codec := range streamCodecFixtures(t, payload) {
		t.Run(codec.format, func(t *testing.T) {
			detected, err := (filetype.Detector{}).Detect(
				bytes.NewReader(codec.data),
				int64(len(codec.data)),
			)
			if err != nil {
				t.Fatalf("Detect() error = %v", err)
			}
			if detected.Format != codec.format {
				t.Fatalf("detected format = %q", detected.Format)
			}
			result := runExtract(
				t,
				codec.data,
				codec.format,
				generousLimits(),
			)
			node := findNode(t, result.Nodes, "/content")
			if result.Partial ||
				node.ExtractionStatus != StatusExtracted ||
				node.SizeBytes != int64(len(payload)) {
				t.Fatalf("result=%+v node=%+v", result, node)
			}
		})
	}
}

func TestXZAndZSTDCorruptionIsRetainedAsPartialNode(t *testing.T) {
	payload := bytes.Repeat([]byte("corrupt-me"), 128)
	for _, codec := range streamCodecFixtures(t, payload) {
		t.Run(codec.format, func(t *testing.T) {
			data := append([]byte(nil), codec.data[:len(codec.data)-1]...)
			result := runExtract(t, data, codec.format, generousLimits())
			if !result.Partial || len(result.Nodes) != 1 ||
				result.Nodes[0].ExtractionStatus != StatusCorrupt ||
				result.Nodes[0].ErrorCode != codec.format+"_archive_corrupt" {
				t.Fatalf("result=%+v", result)
			}
		})
	}
}

func TestXZAndZSTDReuseExpandedByteAndRatioLimits(t *testing.T) {
	payload := bytes.Repeat([]byte{0}, 32<<10)
	for _, codec := range streamCodecFixtures(t, payload) {
		t.Run(codec.format+"/expanded", func(t *testing.T) {
			limits := generousLimits()
			limits.MaxExpandedBytes = 17
			result := runExtract(t, codec.data, codec.format, limits)
			node := findNode(t, result.Nodes, "/content")
			if !result.Partial ||
				result.LimitCode != LimitMaxExpandedBytes ||
				result.ExpandedBytes != 17 ||
				node.SizeBytes != 17 ||
				node.ExtractionStatus != StatusLimitExceeded {
				t.Fatalf("result=%+v node=%+v", result, node)
			}
		})
		t.Run(codec.format+"/ratio", func(t *testing.T) {
			limits := generousLimits()
			limits.MaxRatio = 2
			result := runExtract(t, codec.data, codec.format, limits)
			node := findNode(t, result.Nodes, "/content")
			if !result.Partial ||
				result.LimitCode != LimitMaxRatio ||
				node.ExtractionStatus != StatusLimitExceeded ||
				result.ExpandedBytes > int64(len(codec.data))*2 {
				t.Fatalf("result=%+v node=%+v", result, node)
			}
		})
	}
}

func TestXZAndZSTDRecursivelyExtractDetectedTAR(t *testing.T) {
	payload := tarStreamFixture(t, "payload.txt", []byte("nested"))
	for _, codec := range streamCodecFixtures(t, payload) {
		t.Run(codec.format, func(t *testing.T) {
			result := runExtract(
				t,
				codec.data,
				codec.format,
				generousLimits(),
			)
			container := findNode(t, result.Nodes, "/content")
			child := findNode(t, result.Nodes, "/content/payload.txt")
			if result.Partial ||
				container.Format != "tar" ||
				child.ParentLocalID != container.LocalID ||
				child.ExtractionStatus != StatusExtracted {
				t.Fatalf(
					"result=%+v container=%+v child=%+v",
					result,
					container,
					child,
				)
			}
		})
	}
}

func TestXZAndZSTDCancellationStopsBeforeDecoding(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for _, codec := range streamCodecFixtures(t, []byte("cancel")) {
		t.Run(codec.format, func(t *testing.T) {
			result, err := runExtractWithContext(
				t,
				ctx,
				codec.data,
				codec.format,
				generousLimits(),
			)
			if !errors.Is(err, context.Canceled) ||
				!result.Partial ||
				result.LimitCode != LimitContextCancelled ||
				len(result.Nodes) != 0 {
				t.Fatalf("result=%+v err=%v", result, err)
			}
		})
	}
}

func TestXZDictionaryMemoryLimitIsCheckedBeforeDecoder(t *testing.T) {
	data := xzStreamFixture(t, []byte("small"))
	data = setXZDictionaryProperty(t, data, 30) // 128 MiB
	result := runExtract(t, data, "xz", generousLimits())
	if !result.Partial ||
		result.LimitCode != LimitMaxDecoderMemory ||
		len(result.Nodes) != 0 {
		t.Fatalf("result = %+v", result)
	}
}

func TestXZPreflightChecksCancellationWhileWalkingBlocks(t *testing.T) {
	data := xzStreamFixture(t, []byte("cancel during preflight"))
	ctx, cancel := context.WithCancel(context.Background())
	reader := &cancelAfterReaderAt{
		reader:      bytes.NewReader(data),
		cancel:      cancel,
		cancelAfter: 2,
	}
	_, err := preflightXZ(ctx, reader, int64(len(data)))
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("preflight error = %v", err)
	}
}

func TestXZPreflightSupportsMultipleBlocksInOneStream(t *testing.T) {
	var output bytes.Buffer
	writer, err := (xzlib.WriterConfig{
		DictCap:   4 << 10,
		BlockSize: 8,
	}).NewWriter(&output)
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte("multiple-block-xz-payload")
	if _, err := writer.Write(payload); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	result := runExtract(t, output.Bytes(), "xz", generousLimits())
	node := findNode(t, result.Nodes, "/content")
	if result.Partial || node.SizeBytes != int64(len(payload)) ||
		node.ExtractionStatus != StatusExtracted {
		t.Fatalf("result=%+v node=%+v", result, node)
	}
}

func TestXZRejectsConcatenatedStreamBeforeSecondDecoder(t *testing.T) {
	first := xzStreamFixture(t, []byte("first"))
	second := setXZDictionaryProperty(
		t,
		xzStreamFixture(t, []byte("second")),
		30,
	)
	data := append(append([]byte(nil), first...), second...)
	result := runExtract(t, data, "xz", generousLimits())
	if !result.Partial ||
		result.LimitCode != "" ||
		len(result.Nodes) != 1 ||
		result.Nodes[0].ExtractionStatus != StatusCorrupt ||
		result.Nodes[0].ErrorCode != "xz_archive_corrupt" {
		t.Fatalf("result=%+v", result)
	}
}

func TestDecoderMemoryLimitIsBranchLocalForNestedStreams(t *testing.T) {
	limitedXZ := setXZDictionaryProperty(
		t,
		xzStreamFixture(t, []byte("xz")),
		30,
	)
	for _, test := range []struct {
		name string
		data []byte
	}{
		{name: "xz", data: limitedXZ},
		{name: "zstd", data: zstdLargeWindowFixture(t)},
	} {
		t.Run(test.name, func(t *testing.T) {
			outer := zipFixture(t, []zipEntry{
				{name: "limited." + test.name, body: test.data, store: true},
				{name: "safe.txt", body: []byte("safe"), store: true},
			})
			result := runExtract(t, outer, "zip", generousLimits())
			limited := findNode(
				t,
				result.Nodes,
				"/limited."+test.name,
			)
			safe := findNode(t, result.Nodes, "/safe.txt")
			if !result.Partial ||
				result.LimitCode != LimitMaxDecoderMemory ||
				limited.ExtractionStatus != StatusLimitExceeded ||
				limited.ErrorCode != LimitMaxDecoderMemory ||
				safe.ExtractionStatus != StatusExtracted {
				t.Fatalf(
					"result=%+v limited=%+v safe=%+v",
					result,
					limited,
					safe,
				)
			}
		})
	}
}

func TestZSTDDecoderMemoryLimitIsObservable(t *testing.T) {
	data := zstdLargeWindowFixture(t)
	result := runExtract(t, data, "zstd", generousLimits())
	if !result.Partial ||
		result.LimitCode != LimitMaxDecoderMemory ||
		len(result.Nodes) != 1 ||
		result.Nodes[0].ExtractionStatus != StatusLimitExceeded {
		t.Fatalf("result = %+v", result)
	}
}

func zstdLargeWindowFixture(t *testing.T) []byte {
	t.Helper()
	encoder, err := zstd.NewWriter(
		nil,
		zstd.WithEncoderConcurrency(1),
		zstd.WithWindowSize(128<<20),
		zstd.WithSingleSegment(false),
		zstd.WithEncoderCRC(true),
	)
	if err != nil {
		t.Fatal(err)
	}
	data := encoder.EncodeAll([]byte("small"), nil)
	encoder.Close()
	if len(data) < 6 || data[4]&0x20 != 0 {
		t.Fatalf("ZSTD fixture is not a non-single-segment frame: %x", data)
	}
	// Window_Descriptor exponent 17, mantissa 0: 128 MiB.
	data[5] = 17 << 3
	return data
}

type streamCodecFixture struct {
	format string
	data   []byte
}

func streamCodecFixtures(
	t *testing.T,
	payload []byte,
) []streamCodecFixture {
	t.Helper()
	return []streamCodecFixture{
		{format: "xz", data: xzStreamFixture(t, payload)},
		{format: "zstd", data: zstdStreamFixture(t, payload)},
	}
}

func xzStreamFixture(t *testing.T, payload []byte) []byte {
	t.Helper()
	var output bytes.Buffer
	writer, err := xzlib.NewWriter(&output)
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

func zstdStreamFixture(t *testing.T, payload []byte) []byte {
	t.Helper()
	encoder, err := zstd.NewWriter(
		nil,
		zstd.WithEncoderConcurrency(1),
		zstd.WithEncoderCRC(true),
	)
	if err != nil {
		t.Fatal(err)
	}
	data := encoder.EncodeAll(payload, nil)
	encoder.Close()
	return data
}

func tarStreamFixture(t *testing.T, name string, payload []byte) []byte {
	t.Helper()
	var output bytes.Buffer
	writer := tar.NewWriter(&output)
	if err := writer.WriteHeader(&tar.Header{
		Name:     name,
		Mode:     0o600,
		Size:     int64(len(payload)),
		Typeflag: tar.TypeReg,
	}); err != nil {
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

func setXZDictionaryProperty(
	t *testing.T,
	data []byte,
	property byte,
) []byte {
	t.Helper()
	result := append([]byte(nil), data...)
	if len(result) <= xzStreamHeaderLength {
		t.Fatal("XZ fixture has no block")
	}
	headerLength := (int(result[xzStreamHeaderLength]) + 1) * 4
	headerEnd := xzStreamHeaderLength + headerLength
	if headerLength < 8 || headerEnd > len(result) {
		t.Fatal("XZ fixture has an invalid block header")
	}
	header := result[xzStreamHeaderLength:headerEnd]
	contentEnd := len(header) - 4
	cursor := 2
	flags := header[1]
	if flags&0x40 != 0 {
		if _, err := readXZVLI(header, &cursor, contentEnd); err != nil {
			t.Fatal(err)
		}
	}
	if flags&0x80 != 0 {
		if _, err := readXZVLI(header, &cursor, contentEnd); err != nil {
			t.Fatal(err)
		}
	}
	filterID, err := readXZVLI(header, &cursor, contentEnd)
	if err != nil || filterID != xzLZMA2FilterID {
		t.Fatalf("XZ fixture filter = %d, err=%v", filterID, err)
	}
	propertiesLength, err := readXZVLI(header, &cursor, contentEnd)
	if err != nil || propertiesLength != 1 || cursor >= contentEnd {
		t.Fatalf(
			"XZ fixture properties length = %d, err=%v",
			propertiesLength,
			err,
		)
	}
	header[cursor] = property
	binary.LittleEndian.PutUint32(
		header[contentEnd:],
		crc32.ChecksumIEEE(header[:contentEnd]),
	)
	return result
}

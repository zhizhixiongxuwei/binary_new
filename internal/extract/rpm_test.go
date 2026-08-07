package extract

import (
	"bytes"
	"compress/bzip2"
	"compress/gzip"
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"sort"
	"testing"

	"github.com/klauspost/compress/zstd"
	xzlib "github.com/ulikunitz/xz"
	lzmalib "github.com/ulikunitz/xz/lzma"
)

const rpmBzip2CPIOHex = "425a68393141592653598b6efd54000021ff804c080408280378c0222414003e07d46020005454d1a643081934f29ea323d4191101a680681a004a83c428e5425820bc454906c3b456183592080440e0f60b6ea1ad2862de13001952a403d7646ca635277d13341b9ff8bb9229c284845b77eaa0"

func TestExtractRPMSupportedPayloadCompressors(t *testing.T) {
	cpioPayload := rpmTestCPIO(t)
	for _, compressor := range []string{
		"none",
		"gzip",
		"bzip2",
		"xz",
		"zstd",
		"lzma",
	} {
		t.Run(compressor, func(t *testing.T) {
			compressed := rpmCompressFixture(
				t,
				compressor,
				cpioPayload,
			)
			data := rpmArchiveFixture(
				t,
				compressed,
				stringPointer("cpio"),
				stringPointer(compressor),
			)
			result := runExtract(t, data, "rpm", generousLimits())
			payload := findNode(t, result.Nodes, "/payload")
			child := findNode(t, result.Nodes, "/payload/payload.txt")
			if result.Partial ||
				payload.Format != "cpio" ||
				payload.ExtractionStatus != StatusExtracted ||
				child.ParentLocalID != payload.LocalID ||
				child.ExtractionStatus != StatusExtracted ||
				child.SizeBytes != int64(len("rpm-content")) {
				t.Fatalf(
					"result=%+v payload=%+v child=%+v",
					result,
					payload,
					child,
				)
			}
			var metadata map[string]any
			if err := json.Unmarshal(payload.MetadataJSON, &metadata); err != nil {
				t.Fatal(err)
			}
			if metadata["archive"] != "rpm" ||
				metadata["payload_format"] != "cpio" ||
				metadata["payload_compressor"] != compressor {
				t.Fatalf("payload metadata = %#v", metadata)
			}
			assertCleanWorkDirectory(t)
		})
	}
}

func TestExtractRPMRecursesThroughCPIOIntoZIP(t *testing.T) {
	nested := zipFixture(t, []zipEntry{{
		name: "nested.txt",
		body: []byte("nested-rpm"),
	}})
	cpioPayload := cpioArchiveFixture(t, "newc", []cpioFixtureEntry{{
		name: "inner.zip",
		mode: cpioModeRegular | 0o600,
		body: nested,
	}}, true)
	data := rpmArchiveFixture(
		t,
		rpmCompressFixture(t, "zstd", cpioPayload),
		stringPointer("cpio"),
		stringPointer("zstd"),
	)
	result := runExtract(t, data, "rpm", generousLimits())
	payload := findNode(t, result.Nodes, "/payload")
	archive := findNode(t, result.Nodes, "/payload/inner.zip")
	child := findNode(
		t,
		result.Nodes,
		"/payload/inner.zip/nested.txt",
	)
	if result.Partial ||
		payload.Format != "cpio" ||
		archive.Format != "zip" ||
		archive.ParentLocalID != payload.LocalID ||
		child.ParentLocalID != archive.LocalID ||
		child.ExtractionStatus != StatusExtracted {
		t.Fatalf(
			"result=%+v payload=%+v archive=%+v child=%+v",
			result,
			payload,
			archive,
			child,
		)
	}
}

func TestExtractRPMRejectsPayloadMetadataMismatch(t *testing.T) {
	cpioPayload := rpmTestCPIO(t)
	tests := []struct {
		name       string
		payload    []byte
		format     *string
		compressor *string
		status     string
		code       string
	}{
		{
			name:       "compressor-content-mismatch",
			payload:    cpioPayload,
			format:     stringPointer("cpio"),
			compressor: stringPointer("gzip"),
			status:     StatusCorrupt,
			code:       "rpm_payload_compressor_mismatch",
		},
		{
			name:       "lzma-does-not-override-known-content",
			payload:    zipFixture(t, []zipEntry{{name: "hidden"}}),
			format:     stringPointer("cpio"),
			compressor: stringPointer("lzma"),
			status:     StatusCorrupt,
			code:       "rpm_payload_compressor_mismatch",
		},
		{
			name:       "missing-format",
			payload:    cpioPayload,
			compressor: stringPointer("none"),
			status:     StatusCorrupt,
			code:       "rpm_payload_metadata_invalid",
		},
		{
			name:    "missing-compressor",
			payload: cpioPayload,
			format:  stringPointer("cpio"),
			status:  StatusCorrupt,
			code:    "rpm_payload_metadata_invalid",
		},
		{
			name:       "unsupported-format",
			payload:    cpioPayload,
			format:     stringPointer("tar"),
			compressor: stringPointer("none"),
			status:     StatusUnsupported,
			code:       "rpm_payload_format_unsupported",
		},
		{
			name:       "unsupported-compressor",
			payload:    cpioPayload,
			format:     stringPointer("cpio"),
			compressor: stringPointer("brotli"),
			status:     StatusUnsupported,
			code:       "rpm_payload_compressor_unsupported",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := runExtract(
				t,
				rpmArchiveFixture(
					t,
					test.payload,
					test.format,
					test.compressor,
				),
				"rpm",
				generousLimits(),
			)
			payload := findNode(t, result.Nodes, "/payload")
			if !result.Partial ||
				payload.ExtractionStatus != test.status ||
				payload.ErrorCode != test.code ||
				len(result.Nodes) != 1 {
				t.Fatalf(
					"result=%+v payload=%+v",
					result,
					payload,
				)
			}
		})
	}
}

func TestExtractRPMV6StrippedCPIOIsExplicitlyUnsupported(t *testing.T) {
	formatVersion := uint32(6)
	data := rpmArchiveFixtureWithFormatVersion(
		t,
		[]byte("07070X00000000"),
		stringPointer("cpio"),
		stringPointer("none"),
		&formatVersion,
	)
	result := runExtract(t, data, "rpm", generousLimits())
	payload := findNode(t, result.Nodes, "/payload")
	if !result.Partial ||
		payload.ExtractionStatus != StatusUnsupported ||
		payload.ErrorCode != "rpm_payload_format_version_unsupported" ||
		!bytes.Contains(
			[]byte(payload.ErrorMessage),
			[]byte("07070X"),
		) ||
		len(result.Nodes) != 1 {
		t.Fatalf("result=%+v payload=%+v", result, payload)
	}
	var metadata map[string]any
	if err := json.Unmarshal(payload.MetadataJSON, &metadata); err != nil {
		t.Fatal(err)
	}
	if metadata["rpm_format_version"] != float64(6) {
		t.Fatalf("payload metadata = %#v", metadata)
	}
}

func TestExtractRPMV4StrippedCPIOVariantIsUnsupported(t *testing.T) {
	stripped := []byte("07070X00000000payload")
	for _, compressor := range []string{"none", "gzip"} {
		t.Run(compressor, func(t *testing.T) {
			data := rpmArchiveFixture(
				t,
				rpmCompressFixture(t, compressor, stripped),
				stringPointer("cpio"),
				stringPointer(compressor),
			)
			result := runExtract(t, data, "rpm", generousLimits())
			payload := findNode(t, result.Nodes, "/payload")
			if !result.Partial ||
				payload.ExtractionStatus != StatusUnsupported ||
				payload.ErrorCode != "rpm_payload_variant_unsupported" ||
				!bytes.Contains(
					[]byte(payload.ErrorMessage),
					[]byte("07070X"),
				) ||
				len(result.Nodes) != 1 {
				t.Fatalf("result=%+v payload=%+v", result, payload)
			}
			var metadata map[string]any
			if err := json.Unmarshal(
				payload.MetadataJSON,
				&metadata,
			); err != nil {
				t.Fatal(err)
			}
			if metadata["rpm_format_version"] != float64(4) {
				t.Fatalf("payload metadata = %#v", metadata)
			}
		})
	}
}

func TestExtractRPMRequiresDecodedCPIO(t *testing.T) {
	data := rpmArchiveFixture(
		t,
		rpmCompressFixture(t, "gzip", []byte("not a CPIO archive")),
		stringPointer("cpio"),
		stringPointer("gzip"),
	)
	result := runExtract(t, data, "rpm", generousLimits())
	payload := findNode(t, result.Nodes, "/payload")
	if !result.Partial ||
		payload.ExtractionStatus != StatusCorrupt ||
		payload.ErrorCode != "rpm_payload_format_mismatch" ||
		len(result.Nodes) != 1 {
		t.Fatalf("result=%+v payload=%+v", result, payload)
	}
}

func TestExtractRPMLZMARejectsTrailingPayloadBytes(t *testing.T) {
	compressed := rpmCompressFixture(t, "lzma", rpmTestCPIO(t))
	compressed = append(compressed, []byte("trailing")...)
	data := rpmArchiveFixture(
		t,
		compressed,
		stringPointer("cpio"),
		stringPointer("lzma"),
	)
	result := runExtract(t, data, "rpm", generousLimits())
	payload := findNode(t, result.Nodes, "/payload")
	if !result.Partial ||
		payload.ExtractionStatus != StatusCorrupt ||
		payload.ErrorCode != "rpm_payload_corrupt" ||
		len(result.Nodes) != 1 {
		t.Fatalf("result=%+v payload=%+v", result, payload)
	}
}

func TestExtractRPMHonorsExpandedByteLimit(t *testing.T) {
	data := rpmArchiveFixture(
		t,
		rpmCompressFixture(t, "gzip", rpmTestCPIO(t)),
		stringPointer("cpio"),
		stringPointer("gzip"),
	)
	result := runExtract(t, data, "rpm", Limits{
		MaxExpandedBytes: 64,
		MaxNodes:         100,
		MaxDepth:         10,
		MaxRatio:         100,
	})
	payload := findNode(t, result.Nodes, "/payload")
	if !result.Partial ||
		result.LimitCode != LimitMaxExpandedBytes ||
		payload.ExtractionStatus != StatusLimitExceeded ||
		payload.ErrorCode != LimitMaxExpandedBytes ||
		payload.SizeBytes != 64 {
		t.Fatalf("result=%+v payload=%+v", result, payload)
	}
}

func TestExtractRPMCorruptHeaderAndMetadataLimitAreLocal(t *testing.T) {
	valid := rpmArchiveFixture(
		t,
		rpmTestCPIO(t),
		stringPointer("cpio"),
		stringPointer("none"),
	)
	t.Run("invalid-header", func(t *testing.T) {
		data := append([]byte(nil), valid...)
		data[96] ^= 0xff
		result := runExtract(t, data, "rpm", generousLimits())
		if !result.Partial || len(result.Nodes) != 1 ||
			result.Nodes[0].ErrorCode != "rpm_archive_corrupt" ||
			result.Nodes[0].ExtractionStatus != StatusCorrupt {
			t.Fatalf("result=%+v", result)
		}
	})
	t.Run("metadata-limit", func(t *testing.T) {
		data := append([]byte(nil), valid...)
		binary.BigEndian.PutUint32(data[104:108], 100_001)
		result := runExtract(t, data, "rpm", generousLimits())
		if !result.Partial ||
			result.LimitCode != LimitMaxArchiveMetadata ||
			len(result.Nodes) != 0 {
			t.Fatalf("result=%+v", result)
		}
	})
}

func TestExtractRPMCancellationIsPropagated(t *testing.T) {
	data := rpmArchiveFixture(
		t,
		rpmTestCPIO(t),
		stringPointer("cpio"),
		stringPointer("none"),
	)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	result, err := runExtractWithContext(
		t,
		ctx,
		data,
		"rpm",
		generousLimits(),
	)
	if !errors.Is(err, context.Canceled) ||
		result.LimitCode != LimitContextCancelled ||
		!result.Partial ||
		len(result.Nodes) != 0 {
		t.Fatalf("error=%v result=%+v", err, result)
	}
}

func rpmTestCPIO(t *testing.T) []byte {
	t.Helper()
	return cpioArchiveFixture(t, "newc", []cpioFixtureEntry{{
		name: "payload.txt",
		mode: cpioModeRegular | 0o600,
		body: []byte("rpm-content"),
	}}, true)
}

func rpmCompressFixture(
	t *testing.T,
	compressor string,
	payload []byte,
) []byte {
	t.Helper()
	var output bytes.Buffer
	switch compressor {
	case "none":
		return append([]byte(nil), payload...)
	case "gzip":
		writer := gzip.NewWriter(&output)
		if _, err := writer.Write(payload); err != nil {
			t.Fatal(err)
		}
		if err := writer.Close(); err != nil {
			t.Fatal(err)
		}
	case "bzip2":
		encoded, err := hex.DecodeString(rpmBzip2CPIOHex)
		if err != nil {
			t.Fatal(err)
		}
		decoded, err := io.ReadAll(bzip2.NewReader(bytes.NewReader(encoded)))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(decoded, payload) {
			t.Fatalf(
				"embedded bzip2 fixture decoded to %d bytes, want %d",
				len(decoded),
				len(payload),
			)
		}
		return encoded
	case "xz":
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
	case "zstd":
		writer, err := zstd.NewWriter(
			&output,
			zstd.WithEncoderConcurrency(1),
		)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := writer.Write(payload); err != nil {
			t.Fatal(err)
		}
		if err := writer.Close(); err != nil {
			t.Fatal(err)
		}
	case "lzma":
		writer, err := lzmalib.NewWriter(&output)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := writer.Write(payload); err != nil {
			t.Fatal(err)
		}
		if err := writer.Close(); err != nil {
			t.Fatal(err)
		}
	default:
		t.Fatalf("unsupported fixture compressor %q", compressor)
	}
	return append([]byte(nil), output.Bytes()...)
}

type rpmHeaderEntry struct {
	tag          uint32
	valueType    uint32
	value        string
	integerValue uint32
	rawValue     []byte
}

func rpmArchiveFixture(
	t *testing.T,
	payload []byte,
	format *string,
	compressor *string,
) []byte {
	t.Helper()
	return rpmArchiveFixtureWithFormatVersion(
		t,
		payload,
		format,
		compressor,
		nil,
	)
}

func rpmArchiveFixtureWithFormatVersion(
	t *testing.T,
	payload []byte,
	format *string,
	compressor *string,
	formatVersion *uint32,
) []byte {
	t.Helper()
	lead := make([]byte, 96)
	copy(lead[:4], []byte{0xed, 0xab, 0xee, 0xdb})
	lead[4] = 3
	if formatVersion != nil && *formatVersion >= 6 {
		lead[4] = 4
	}
	binary.BigEndian.PutUint16(lead[8:10], 1)
	copy(lead[10:76], "fixture-1.0-1")
	binary.BigEndian.PutUint16(lead[76:78], 1)
	binary.BigEndian.PutUint16(lead[78:80], 5)

	signature := rpmHeaderFixture(t, nil)
	entries := []rpmHeaderEntry{
		{tag: 63, valueType: 7, rawValue: make([]byte, 16)},
		{tag: 1022, value: "x86_64"},
	}
	if format != nil {
		entries = append(
			entries,
			rpmHeaderEntry{tag: 1124, value: *format},
		)
	}
	if compressor != nil {
		entries = append(
			entries,
			rpmHeaderEntry{tag: 1125, value: *compressor},
		)
	}
	entries = append(
		entries,
		rpmHeaderEntry{tag: 1126, value: "9"},
	)
	if formatVersion != nil {
		entries = append(entries, rpmHeaderEntry{
			tag:          5114,
			valueType:    4,
			integerValue: *formatVersion,
		})
	}
	sort.Slice(entries, func(left, right int) bool {
		return entries[left].tag < entries[right].tag
	})
	main := rpmHeaderFixture(t, entries)

	output := append([]byte(nil), lead...)
	output = append(output, signature...)
	for len(output)%8 != 0 {
		output = append(output, 0)
	}
	output = append(output, main...)
	output = append(output, payload...)
	return output
}

func rpmHeaderFixture(
	t *testing.T,
	entries []rpmHeaderEntry,
) []byte {
	t.Helper()
	var index bytes.Buffer
	var data bytes.Buffer
	for _, entry := range entries {
		valueType := entry.valueType
		if valueType == 0 {
			valueType = 6
		}
		if valueType == 4 {
			for data.Len()%4 != 0 {
				data.WriteByte(0)
			}
		}
		var encoded [16]byte
		binary.BigEndian.PutUint32(encoded[0:4], entry.tag)
		binary.BigEndian.PutUint32(encoded[4:8], valueType)
		binary.BigEndian.PutUint32(
			encoded[8:12],
			uint32(data.Len()),
		)
		count := uint32(1)
		if valueType == 7 {
			count = uint32(len(entry.rawValue))
		}
		binary.BigEndian.PutUint32(encoded[12:16], count)
		index.Write(encoded[:])
		switch valueType {
		case 4:
			var encodedValue [4]byte
			binary.BigEndian.PutUint32(
				encodedValue[:],
				entry.integerValue,
			)
			data.Write(encodedValue[:])
		case 6:
			data.WriteString(entry.value)
			data.WriteByte(0)
		case 7:
			data.Write(entry.rawValue)
		default:
			t.Fatalf("unsupported RPM fixture value type %d", valueType)
		}
	}
	var intro [16]byte
	copy(intro[:8], []byte{0x8e, 0xad, 0xe8, 0x01})
	binary.BigEndian.PutUint32(intro[8:12], uint32(len(entries)))
	binary.BigEndian.PutUint32(intro[12:16], uint32(data.Len()))
	output := append([]byte(nil), intro[:]...)
	output = append(output, index.Bytes()...)
	output = append(output, data.Bytes()...)
	return output
}

func stringPointer(value string) *string {
	return &value
}

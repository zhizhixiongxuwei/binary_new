package extract

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"hash/crc32"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"binaryscan/internal/filetype"

	"github.com/nwaples/rardecode/v2"
)

func TestRAR4AndRAR5StoreEntriesRecurseAfterDecoderRelease(t *testing.T) {
	nested := zipFixture(t, []zipEntry{{
		name: "payload.txt",
		body: []byte("nested"),
	}})
	entries := []rarFixtureEntry{
		{
			name:       "plain.txt",
			body:       []byte("plain"),
			attributes: 0100644,
		},
		{
			name:       "nested.zip",
			body:       nested,
			attributes: 0100644,
		},
		{
			name:       "docs/readme.txt",
			body:       []byte("readme"),
			attributes: 0100644,
		},
	}
	for _, version := range []int{4, 5} {
		t.Run("rar"+string(rune('0'+version)), func(t *testing.T) {
			data := rarArchiveFixture(t, version, 0, 0, entries)
			result := runRARExtract(t, data, generousLimits())
			if result.Partial || result.LimitCode != "" {
				t.Fatalf("result = %+v", result)
			}
			plain := findNode(t, result.Nodes, "/plain.txt")
			nestedNode := findNode(t, result.Nodes, "/nested.zip")
			payload := findNode(
				t,
				result.Nodes,
				"/nested.zip/payload.txt",
			)
			readme := findNode(t, result.Nodes, "/docs/readme.txt")
			if plain.ExtractionStatus != StatusExtracted ||
				nestedNode.Format != "zip" ||
				payload.ParentLocalID != nestedNode.LocalID ||
				payload.ExtractionStatus != StatusExtracted ||
				readme.ExtractionStatus != StatusExtracted {
				t.Fatalf("nodes = %+v", result.Nodes)
			}
			if result.parserDecoderMemoryPeak !=
				rarParserDecoderMemoryReservation ||
				result.parserDecoderMemoryUsed != 0 {
				t.Fatalf(
					"RAR memory accounting = peak %d used %d",
					result.parserDecoderMemoryPeak,
					result.parserDecoderMemoryUsed,
				)
			}
		})
	}
}

func TestRARCompressedGoldenFixtures(t *testing.T) {
	// RAR3 source: ssokolow/rar-test-files at commit 16b785c2
	// (CC0). Its reproducible Makefile invokes RAR 3.93 under DOSBox 0.74:
	// RAR32.EXE a -m5 -ep1 -t -ai -cl -tl OUTFILE.RAR testfile.txt
	// The RAR3 compression method byte is 0x35 and its first decode29 block bit
	// selects PPM, so this covers legacy PPM in the RAR4-signature family.
	//
	// RAR5 source: github.com/gabriel-vasile/mimetype v1.4.3
	// testdata/rar.rar (MIT; see licenses/mimetype-v1.4.3.txt). Its packed bytes
	// are not plaintext and exercise rardecode's RAR5 LZ path. Both are
	// embedded to keep the suite offline.
	tests := []struct {
		name                         string
		encoded                      string
		sha256                       string
		logical                      string
		size                         int64
		legacyCompressionUnsupported bool
	}{
		{
			name:                         "rar3_method_35",
			encoded:                      "UmFyIRoHAM+QcwAADQAAAAAAAAA4m3QggCwAGwAAAAwAAAAA/o/BbgAAISodNQwAIAAAAHRlc3RmaWxlLnR4dKcYVBNehL0MdSfwO2HcUnaQEg0Av4hn9qn/1MQ9ewBABwA=",
			sha256:                       "dce342bc0c2852fcaa36a03da5e55abb7dd69c045bbd812faebebc1a3844f5a4",
			logical:                      "/testfile.txt",
			size:                         12,
			legacyCompressionUnsupported: true,
		},
		{
			name:    "rar5_lz",
			encoded: "UmFyIRoHAQAzkrXlCgEFBgAFAQGAgABGzTVJHAICnQEGuwG0gwKAAPNateoMI4ADAQZhc2QuZ2/FBZomVENC9mBE3ZOFQmqQFk3oOpdKCPBUtmRmQWS8HJHNCPelLkzdnFrsv8eqq5PZdHq0VRQffcfxBvgHuPEISMaEcR9TOk1yJwi5Bq4PhPCnZbRiy8PbmvwY8duWLs2WsQlEHekm6N6VH+El5Fuw/U+7eezC+YheVNAtBI5HKV8AkzgXAckVVuswvjQpidDdBz/lkCf1StT9VP6YHXdWUQMFBAA=",
			sha256:  "984c6e6bacfbe839cf1e94c6df87ed6b455901457e8d349050fd3899b5fb834f",
			logical: "/asd.go",
			size:    187,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			data, err := base64.StdEncoding.DecodeString(test.encoded)
			if err != nil {
				t.Fatal(err)
			}
			sum := fmt.Sprintf("%x", sha256.Sum256(data))
			if sum != test.sha256 {
				t.Fatalf("golden fixture SHA-256 = %s", sum)
			}
			if test.name == "rar3_method_35" &&
				(data[45] != 0x35 || data[64]&0x80 == 0) {
				// decode29 selects PPM when the first aligned block bit is 1.
				t.Fatalf(
					"RAR3 fixture no longer covers method 0x35 PPM: %x",
					data,
				)
			}
			result := runRARExtract(t, data, generousLimits())
			if test.legacyCompressionUnsupported {
				if !result.Partial ||
					result.LimitCode != "" ||
					len(result.Nodes) != 1 ||
					result.Nodes[0].ExtractionStatus != StatusUnsupported ||
					result.Nodes[0].ErrorCode !=
						"rar_legacy_compression_unsupported" {
					t.Fatalf("result=%+v", result)
				}
				return
			}
			node := findNode(t, result.Nodes, test.logical)
			if result.Partial ||
				node.ExtractionStatus != StatusExtracted ||
				node.SizeBytes != test.size ||
				node.SHA256 == "" {
				t.Fatalf("result=%+v node=%+v", result, node)
			}
		})
	}
}

func TestRAR5MalformedLengthMetadataIsLocalCorrupt(t *testing.T) {
	tests := []struct {
		name   string
		header []byte
		raw    []byte
	}{
		{
			name: "extra-size-int-overflow",
			header: append(
				appendUvarint(
					appendUvarint(nil, 3),
					rar5BlockHasExtra,
				),
				appendUvarint(nil, math.MaxUint64)...,
			),
		},
		{
			name: "extra-record-size-int-overflow",
			header: func() []byte {
				record := appendUvarint(nil, math.MaxUint64)
				header := appendUvarint(nil, 3)
				header = appendUvarint(header, rar5BlockHasExtra)
				header = appendUvarint(header, uint64(len(record)))
				return append(header, record...)
			}(),
		},
		{
			name: "file-name-size-int-overflow",
			header: func() []byte {
				header := appendUvarint(nil, rar5BlockFile)
				header = appendUvarint(header, 0)
				header = appendUvarint(header, 0)
				header = appendUvarint(header, 0)
				header = appendUvarint(header, 0100644)
				header = appendUvarint(header, 0)
				header = appendUvarint(header, 1)
				return appendUvarint(header, math.MaxUint64)
			}(),
		},
		{
			name: "extra-area-exceeds-header",
			header: func() []byte {
				header := appendUvarint(nil, 3)
				header = appendUvarint(header, rar5BlockHasExtra)
				return appendUvarint(header, 16)
			}(),
		},
		{
			name: "unterminated-header-size",
			raw: append(
				make([]byte, 4),
				[]byte{0x80, 0x80, 0x80}...,
			),
		},
		{
			name: "encrypted-block-data-exceeds-archive",
			header: func() []byte {
				header := appendUvarint(nil, rar5BlockEncrypt)
				header = appendUvarint(header, rar5BlockHasData)
				header = appendUvarint(header, 1)
				header = appendUvarint(header, 0)
				header = appendUvarint(header, 0)
				return append(header, make([]byte, 17)...)
			}(),
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			data := rar5ArchivePrefix(t)
			if test.raw != nil {
				data = append(data, test.raw...)
			} else {
				data = appendRawRAR5Header(data, test.header)
			}
			result := runRARExtract(t, data, generousLimits())
			if !result.Partial ||
				result.LimitCode != "" ||
				len(result.Nodes) != 1 ||
				result.Nodes[0].ExtractionStatus != StatusCorrupt ||
				result.Nodes[0].ErrorCode != "rar_archive_corrupt" {
				t.Fatalf("result = %+v", result)
			}
		})
	}
}

func TestRAR4MalformedLengthMetadataIsLocalCorrupt(t *testing.T) {
	regularFields := func() []byte {
		fields := make([]byte, 4+21)
		fields[4+14] = 0x30
		return fields
	}
	largeFields := func() []byte {
		fields := make([]byte, 4+29)
		fields[4+14] = 0x30
		return fields
	}

	nameTooLong := regularFields()
	binary.LittleEndian.PutUint16(nameTooLong[4+15:4+17], 1)
	packedTooLarge := largeFields()
	binary.LittleEndian.PutUint32(packedTooLarge[4+21:4+25], 0x80000000)
	unpackedTooLarge := largeFields()
	binary.LittleEndian.PutUint32(
		unpackedTooLarge[4+25:4+29],
		0x80000000,
	)
	truncated := make([]byte, 7)
	truncated[2] = rar4BlockFile
	binary.LittleEndian.PutUint16(truncated[5:7], 64)

	tests := []struct {
		name   string
		flags  uint16
		fields []byte
		raw    []byte
	}{
		{
			name:   "file-name-exceeds-header",
			flags:  rar4BlockHasData,
			fields: nameTooLong,
		},
		{
			name:   "packed-size-exceeds-int64",
			flags:  rar4BlockHasData | rarPreflight4FileLargeData,
			fields: packedTooLarge,
		},
		{
			name:   "unpacked-size-exceeds-int64",
			flags:  rar4BlockHasData | rarPreflight4FileLargeData,
			fields: unpackedTooLarge,
		},
		{
			name: "header-exceeds-archive",
			raw:  truncated,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			data := rar4ArchivePrefix(t)
			if test.raw != nil {
				data = append(data, test.raw...)
			} else {
				var block bytes.Buffer
				writeRAR4Block(
					t,
					&block,
					rar4BlockFile,
					test.flags,
					test.fields,
					nil,
				)
				data = append(data, block.Bytes()...)
			}
			result := runRARExtract(t, data, generousLimits())
			if !result.Partial ||
				result.LimitCode != "" ||
				len(result.Nodes) != 1 ||
				result.Nodes[0].ExtractionStatus != StatusCorrupt ||
				result.Nodes[0].ErrorCode != "rar_archive_corrupt" {
				t.Fatalf("result = %+v", result)
			}
		})
	}
}

func TestRARPreflightMetadataBlockLimit(t *testing.T) {
	data := rar5ArchivePrefix(t)
	serviceHeader := appendUvarint(nil, 3)
	serviceHeader = appendUvarint(serviceHeader, 0)
	encoded := appendRawRAR5Header(nil, serviceHeader)
	for index := 0; index < rarPreflightMaxBlocks; index++ {
		data = append(data, encoded...)
	}
	result := runRARExtract(t, data, generousLimits())
	if !result.Partial ||
		result.LimitCode != LimitMaxArchiveMetadata ||
		len(result.Nodes) != 1 ||
		result.Nodes[0].ExtractionStatus != StatusLimitExceeded ||
		result.Nodes[0].ErrorCode != LimitMaxArchiveMetadata ||
		result.parserDecoderMemoryPeak !=
			rarParserDecoderMemoryReservation ||
		result.parserDecoderMemoryUsed != 0 {
		t.Fatalf("result = %+v", result)
	}
}

func TestRARPreflightExtraRecordLimit(t *testing.T) {
	extra := bytes.Repeat(
		[]byte{1, 0},
		rarPreflightMaxExtraRecords+1,
	)
	fileHeader := appendUvarint(nil, 0)
	fileHeader = appendUvarint(fileHeader, 0)
	fileHeader = appendUvarint(fileHeader, 0100644)
	fileHeader = appendUvarint(fileHeader, 0)
	fileHeader = appendUvarint(fileHeader, 1)
	fileHeader = appendUvarint(fileHeader, 1)
	fileHeader = append(fileHeader, 'x')

	header := appendUvarint(nil, rar5BlockFile)
	header = appendUvarint(header, rar5BlockHasExtra)
	header = appendUvarint(header, uint64(len(extra)))
	header = append(header, fileHeader...)
	header = append(header, extra...)
	data := appendRawRAR5Header(rar5ArchivePrefix(t), header)

	result := runRARExtract(t, data, generousLimits())
	if !result.Partial ||
		result.LimitCode != LimitMaxArchiveMetadata ||
		len(result.Nodes) != 1 ||
		result.Nodes[0].ExtractionStatus != StatusLimitExceeded ||
		result.Nodes[0].ErrorCode != LimitMaxArchiveMetadata ||
		result.parserDecoderMemoryPeak !=
			rarParserDecoderMemoryReservation ||
		result.parserDecoderMemoryUsed != 0 {
		t.Fatalf("result = %+v", result)
	}
}

func TestRARSFXAndCancellationPassPreflightBoundary(t *testing.T) {
	t.Run("sfx", func(t *testing.T) {
		archive := rarArchiveFixture(t, 5, 0, 0, []rarFixtureEntry{{
			name:       "inside.txt",
			body:       []byte("inside"),
			attributes: 0100644,
		}})
		data := append(bytes.Repeat([]byte{0xcc}, 257), archive...)
		result := runRARExtract(t, data, generousLimits())
		inside := findNode(t, result.Nodes, "/inside.txt")
		if result.Partial ||
			inside.ExtractionStatus != StatusExtracted {
			t.Fatalf("result=%+v inside=%+v", result, inside)
		}
	})
	t.Run("cancelled", func(t *testing.T) {
		data := rarArchiveFixture(t, 5, 0, 0, []rarFixtureEntry{{
			name:       "inside.txt",
			body:       []byte("inside"),
			attributes: 0100644,
		}})
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		result, err := runExtractWithContext(
			t,
			ctx,
			data,
			"rar",
			generousLimits(),
		)
		if !errors.Is(err, context.Canceled) ||
			!result.Partial ||
			result.LimitCode != LimitContextCancelled ||
			len(result.Nodes) != 0 {
			t.Fatalf("error=%v result=%+v", err, result)
		}
	})
}

func TestRARDecoderPanicBoundariesReturnErrors(t *testing.T) {
	if _, err := newRARReaderSafely(panickingRARReader{}); !errors.Is(
		err,
		errRARDecoderPanic,
	) {
		t.Fatalf("newRARReaderSafely() error = %v", err)
	}
	if _, err := nextRARHeaderSafely(nil); !errors.Is(
		err,
		errRARDecoderPanic,
	) {
		t.Fatalf("nextRARHeaderSafely() error = %v", err)
	}
	tracked := &trackedRARReader{reader: panickingRARReader{}}
	if _, err := tracked.Read(make([]byte, 1)); !errors.Is(
		err,
		errRARDecoderPanic,
	) || !errors.Is(tracked.err, errRARDecoderPanic) {
		t.Fatalf("trackedRARReader.Read() error=%v tracked=%v", err, tracked.err)
	}
}

type panickingRARReader struct{}

func (panickingRARReader) Read([]byte) (int, error) {
	panic("fixture reader panic")
}

func TestRARUnsafeRegularPathIsQuarantinedAndRecursed(t *testing.T) {
	nested := zipFixture(t, []zipEntry{{
		name: "visible.txt",
		body: []byte("visible"),
	}})
	data := rarArchiveFixture(t, 5, 0, 0, []rarFixtureEntry{
		{
			name:       "../escape.zip",
			body:       nested,
			attributes: 0100644,
		},
		{
			name:       "safe.txt",
			body:       []byte("safe"),
			attributes: 0100644,
		},
	})

	result := runRARExtract(t, data, generousLimits())
	if !result.Partial || result.LimitCode != "" {
		t.Fatalf("result = %+v", result)
	}
	var quarantined Node
	for _, node := range result.Nodes {
		if node.ExtractionStatus == StatusInvalidPath &&
			node.Format == "zip" {
			quarantined = node
			break
		}
	}
	if quarantined.LocalID == 0 ||
		!strings.HasPrefix(
			quarantined.LogicalPath,
			"/__rejected_entry_",
		) {
		t.Fatalf("quarantined node = %+v", quarantined)
	}
	child := findNode(
		t,
		result.Nodes,
		quarantined.LogicalPath+"/visible.txt",
	)
	if child.ParentLocalID != quarantined.LocalID ||
		child.ExtractionStatus != StatusExtracted {
		t.Fatalf("nested quarantined child = %+v", child)
	}
	if findNode(
		t,
		result.Nodes,
		"/safe.txt",
	).ExtractionStatus != StatusExtracted {
		t.Fatal("safe RAR entry was not extracted")
	}
}

func TestRARSymlinkAndSpecialEntriesAreRecordedOnly(t *testing.T) {
	data := rarArchiveFixture(t, 5, 0, 0, []rarFixtureEntry{
		{
			name:       "link",
			body:       []byte("target"),
			attributes: 0120777,
		},
		{
			name:       "pipe",
			attributes: 0010644,
		},
	})
	result := runRARExtract(t, data, generousLimits())
	link := findNode(t, result.Nodes, "/link")
	pipe := findNode(t, result.Nodes, "/pipe")
	if result.Partial ||
		link.NodeType != NodeTypeSymlink ||
		link.ExtractionStatus != StatusRecorded ||
		link.SHA256 != "" ||
		pipe.NodeType != NodeTypeSpecial ||
		pipe.ExtractionStatus != StatusRecorded ||
		pipe.SHA256 != "" {
		t.Fatalf("result=%+v nodes=%+v", result, result.Nodes)
	}
}

func TestRARChecksumFailureKeepsEarlierMaterializedChildren(t *testing.T) {
	nested := zipFixture(t, []zipEntry{{
		name: "retained.txt",
		body: []byte("retained"),
	}})
	badCRC := uint32(0x12345678)
	data := rarArchiveFixture(t, 5, 0, 0, []rarFixtureEntry{
		{
			name:       "nested.zip",
			body:       nested,
			attributes: 0100644,
		},
		{
			name:        "bad.bin",
			body:        []byte("corrupt"),
			attributes:  0100644,
			crcOverride: &badCRC,
		},
		{
			name:       "after.bin",
			body:       []byte("not reached"),
			attributes: 0100644,
		},
	})

	result := runRARExtract(t, data, generousLimits())
	bad := findNode(t, result.Nodes, "/bad.bin")
	nestedNode := findNode(t, result.Nodes, "/nested.zip")
	retained := findNode(
		t,
		result.Nodes,
		"/nested.zip/retained.txt",
	)
	if !result.Partial ||
		bad.ExtractionStatus != StatusCorrupt ||
		bad.ErrorCode != "rar_entry_checksum_mismatch" ||
		bad.SHA256 != "" ||
		retained.ParentLocalID != nestedNode.LocalID ||
		retained.ExtractionStatus != StatusExtracted {
		t.Fatalf("result=%+v nodes=%+v", result, result.Nodes)
	}
	for _, node := range result.Nodes {
		if node.LogicalPath == "/after.bin" {
			t.Fatalf("entry after corrupt stream should not be trusted: %+v", node)
		}
	}
}

func TestRAREncryptionAndMultiVolumeMappings(t *testing.T) {
	tests := []struct {
		name      string
		data      []byte
		status    string
		errorCode string
		limitCode string
	}{
		{
			name: "encrypted_headers",
			data: rarArchiveFixture(
				t,
				4,
				rar4ArchiveEncrypted,
				0,
				nil,
			),
			status:    StatusPasswordRequired,
			errorCode: "password_required",
		},
		{
			name: "multi_volume_precedes_legacy_compression",
			data: rarArchiveFixture(
				t,
				4,
				rar4ArchiveVolume,
				rar4EndNotLast,
				[]rarFixtureEntry{{
					name:         "legacy.bin",
					body:         []byte{0},
					legacyMethod: 0x35,
				}},
			),
			status:    StatusUnsupported,
			errorCode: "multi_volume_unsupported",
		},
		{
			name: "rar5_multi_volume_with_volume_number",
			data: rarArchiveFixture(
				t,
				5,
				rar4ArchiveVolume|rar5ArchiveVolumeNumber,
				rar4EndNotLast,
				[]rarFixtureEntry{{
					name: "not-reached.bin",
					body: []byte{0},
				}},
			),
			status:    StatusUnsupported,
			errorCode: "multi_volume_unsupported",
		},
		{
			name: "encrypted_headers_precede_multi_volume",
			data: rarArchiveFixture(
				t,
				4,
				rar4ArchiveEncrypted|rar4ArchiveVolume,
				0,
				nil,
			),
			status:    StatusPasswordRequired,
			errorCode: "password_required",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := runRARExtract(t, test.data, generousLimits())
			if !result.Partial || len(result.Nodes) != 1 {
				t.Fatalf("result = %+v", result)
			}
			node := result.Nodes[0]
			if node.ExtractionStatus != test.status ||
				node.ErrorCode != test.errorCode ||
				result.LimitCode != test.limitCode {
				t.Fatalf("node=%+v result=%+v", node, result)
			}
		})
	}
}

func TestRARDictionaryLimitMapping(t *testing.T) {
	data := rarArchiveFixture(t, 5, 0, 0, []rarFixtureEntry{{
		name:             "large-dictionary.bin",
		body:             []byte{0},
		attributes:       0100644,
		unpackedSize:     128 << 20,
		compressionFlags: (1 << 7) | (10 << 10),
	}})
	result := runRARExtract(t, data, generousLimits())
	if !result.Partial ||
		result.LimitCode != LimitMaxDecoderMemory ||
		len(result.Nodes) != 1 ||
		result.Nodes[0].ExtractionStatus != StatusLimitExceeded ||
		result.Nodes[0].ErrorCode != LimitMaxDecoderMemory {
		t.Fatalf("result = %+v", result)
	}
}

func TestRARPerEntryLimitStopsLayerWithoutDecodingSibling(t *testing.T) {
	const maxEntryBytes = int64(16)
	tests := []struct {
		name       string
		attributes int64
		nodeType   string
	}{
		{
			name:       "regular",
			attributes: 0100644,
			nodeType:   NodeTypeFile,
		},
		{
			name:       "symlink",
			attributes: 0120777,
			nodeType:   NodeTypeSymlink,
		},
		{
			name:       "special",
			attributes: 0010644,
			nodeType:   NodeTypeSpecial,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			data := rarArchiveFixture(t, 5, 0, 0, []rarFixtureEntry{
				{
					name:       "oversized",
					body:       bytes.Repeat([]byte{'x'}, 17),
					attributes: test.attributes,
				},
				{
					name:       "must-not-decode.txt",
					body:       []byte("hidden"),
					attributes: 0100644,
				},
			})
			limits := generousLimits()
			limits.MaxEntryBytes = maxEntryBytes
			result := runRARExtract(t, data, limits)
			oversized := findNode(t, result.Nodes, "/oversized")
			if !result.Partial ||
				result.LimitCode != LimitMaxEntryBytes ||
				result.ExpandedBytes != maxEntryBytes ||
				oversized.NodeType != test.nodeType ||
				oversized.ExtractionStatus != StatusLimitExceeded ||
				oversized.ErrorCode != LimitMaxEntryBytes ||
				oversized.SizeBytes != maxEntryBytes {
				t.Fatalf(
					"result=%+v oversized=%+v",
					result,
					oversized,
				)
			}
			for _, node := range result.Nodes {
				if node.LogicalPath == "/must-not-decode.txt" {
					t.Fatalf("decoded sibling after entry limit: %+v", node)
				}
			}
		})
	}
}

func TestRARDeclaredEntryLimitStopsBeforeSolidBodyDecode(t *testing.T) {
	const (
		maxEntryBytes = int64(16)
		declaredBytes = int64(17)
	)
	tests := []struct {
		name       string
		attributes int64
		directory  bool
		nodeType   string
	}{
		{
			name:       "regular",
			attributes: 0100644,
			nodeType:   NodeTypeFile,
		},
		{
			name:       "symlink",
			attributes: 0120777,
			nodeType:   NodeTypeSymlink,
		},
		{
			name:       "special",
			attributes: 0010644,
			nodeType:   NodeTypeSpecial,
		},
		{
			name:       "directory_with_declared_data",
			attributes: 0040755,
			directory:  true,
			nodeType:   NodeTypeDirectory,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// PackedSize is zero while UnPackedSize exceeds the limit. Any
			// archive.Read would therefore report a short/corrupt stream.
			// The solid flags also make an accidental Next dangerous because
			// rardecode would try to drain the current decoder first.
			data := rarArchiveFixture(t, 5, 0x0004, 0, []rarFixtureEntry{
				{
					name:         "oversized",
					attributes:   test.attributes,
					directory:    test.directory,
					unpackedSize: declaredBytes,
					// Solid plus non-Store compression. Next initializes the
					// decoder, but only archive.Read can touch the empty body.
					compressionFlags: 0x00000040 | (1 << 7),
				},
				{
					name:       "must-not-read.txt",
					body:       []byte("hidden"),
					attributes: 0100644,
				},
			})
			limits := generousLimits()
			limits.MaxEntryBytes = maxEntryBytes
			result := runRARExtract(t, data, limits)
			oversized := findNode(t, result.Nodes, "/oversized")
			var metadata map[string]any
			if err := json.Unmarshal(
				oversized.MetadataJSON,
				&metadata,
			); err != nil {
				t.Fatal(err)
			}
			if !result.Partial ||
				result.LimitCode != LimitMaxEntryBytes ||
				result.ExpandedBytes != maxEntryBytes ||
				oversized.NodeType != test.nodeType ||
				oversized.ExtractionStatus != StatusLimitExceeded ||
				oversized.ErrorCode != LimitMaxEntryBytes ||
				oversized.SizeBytes != maxEntryBytes ||
				metadata["solid"] != true {
				t.Fatalf(
					"result=%+v oversized=%+v metadata=%+v",
					result,
					oversized,
					metadata,
				)
			}
			for _, node := range result.Nodes {
				if node.LogicalPath == "/must-not-read.txt" {
					t.Fatalf(
						"walked sibling after declared limit: %+v",
						node,
					)
				}
			}
		})
	}
}

func TestRARDeclaredEntryUsesGlobalLimitPriority(t *testing.T) {
	const boundary = int64(16)
	data := rarArchiveFixture(t, 5, 0, 0, []rarFixtureEntry{{
		name:         "oversized",
		attributes:   0100644,
		unpackedSize: boundary + 1,
	}})
	limits := generousLimits()
	limits.MaxExpandedBytes = boundary
	limits.MaxEntryBytes = boundary
	result := runRARExtract(t, data, limits)
	oversized := findNode(t, result.Nodes, "/oversized")
	if !result.Partial ||
		result.LimitCode != LimitMaxExpandedBytes ||
		result.ExpandedBytes != boundary ||
		oversized.ExtractionStatus != StatusLimitExceeded ||
		oversized.ErrorCode != LimitMaxExpandedBytes ||
		oversized.SizeBytes != boundary {
		t.Fatalf("result=%+v oversized=%+v", result, oversized)
	}
}

func TestRARDeclaredRootDirectoryIsQuarantinedWithoutDecode(t *testing.T) {
	const maxEntryBytes = int64(16)
	data := rarArchiveFixture(t, 5, 0x0004, 0, []rarFixtureEntry{
		{
			name:             ".",
			attributes:       0040755,
			directory:        true,
			unpackedSize:     maxEntryBytes + 1,
			compressionFlags: 0x00000040 | (1 << 7),
		},
		{
			name:       "must-not-read.txt",
			body:       []byte("hidden"),
			attributes: 0100644,
		},
	})
	limits := generousLimits()
	limits.MaxEntryBytes = maxEntryBytes
	result := runRARExtract(t, data, limits)
	if !result.Partial ||
		result.LimitCode != LimitMaxEntryBytes ||
		len(result.Nodes) != 1 ||
		result.Nodes[0].NodeType != NodeTypeDirectory ||
		result.Nodes[0].ExtractionStatus != StatusLimitExceeded ||
		result.Nodes[0].ErrorCode != LimitMaxEntryBytes ||
		result.Nodes[0].SizeBytes != maxEntryBytes ||
		!strings.HasPrefix(
			result.Nodes[0].LogicalPath,
			"/__rejected_entry_",
		) {
		t.Fatalf("result = %+v", result)
	}
}

func TestRAREncryptedEntryStopsWithoutDuplicateDiagnostic(t *testing.T) {
	data := rarArchiveFixture(t, 4, 0, 0, []rarFixtureEntry{
		{
			name:         "secret.bin",
			body:         []byte("ciphertext"),
			attributes:   0100644,
			encrypted:    true,
			legacyMethod: 0x35,
		},
		{
			name:       "after.txt",
			body:       []byte("not reached"),
			attributes: 0100644,
		},
	})
	result := runRARExtract(t, data, generousLimits())
	secret := findNode(t, result.Nodes, "/secret.bin")
	if !result.Partial ||
		len(result.Nodes) != 1 ||
		secret.ExtractionStatus != StatusPasswordRequired ||
		secret.ErrorCode != "password_required" {
		t.Fatalf("result=%+v secret=%+v", result, secret)
	}
}

func TestClassifyRARError(t *testing.T) {
	tests := []struct {
		name      string
		err       error
		status    string
		errorCode string
		limitCode string
	}{
		{
			name:      "entry_encrypted",
			err:       errors.Join(errors.New("wrapped"), rardecode.ErrArchivedFileEncrypted),
			status:    StatusPasswordRequired,
			errorCode: "password_required",
		},
		{
			name:      "bad_password",
			err:       rardecode.ErrBadPassword,
			status:    StatusPasswordRequired,
			errorCode: "password_required",
		},
		{
			name:      "multi_volume",
			err:       rardecode.ErrMultiVolume,
			status:    StatusUnsupported,
			errorCode: "multi_volume_unsupported",
		},
		{
			name:      "preflight_multi_volume",
			err:       errRARMultiVolumeUnsupported,
			status:    StatusUnsupported,
			errorCode: "multi_volume_unsupported",
		},
		{
			name:      "dictionary",
			err:       rardecode.ErrDictionaryTooLarge,
			status:    StatusLimitExceeded,
			errorCode: LimitMaxDecoderMemory,
			limitCode: LimitMaxDecoderMemory,
		},
		{
			name:      "checksum",
			err:       rardecode.ErrBadFileChecksum,
			status:    StatusCorrupt,
			errorCode: "rar_entry_checksum_mismatch",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := classifyRARError(test.err)
			if got.status != test.status ||
				got.code != test.errorCode ||
				got.limitCode != test.limitCode {
				t.Fatalf("classifyRARError(%v) = %+v", test.err, got)
			}
		})
	}
}

const (
	rar4ArchiveVolume       = uint16(0x0001)
	rar4ArchiveEncrypted    = uint16(0x0080)
	rar4EndNotLast          = uint16(0x0001)
	rar4BlockHasData        = uint16(0x8000)
	rar4FileEncrypted       = uint16(0x0004)
	rar4FileDirectory       = uint16(0x00e0)
	rar5ArchiveVolumeNumber = uint16(0x0002)
)

type rarFixtureEntry struct {
	name             string
	body             []byte
	attributes       int64
	directory        bool
	encrypted        bool
	unpackedSize     int64
	compressionFlags uint64
	legacyMethod     byte
	crcOverride      *uint32
}

// These compact fixture encoders follow RAR's published block layouts:
// https://www.rarlab.com/technote.htm. They only emit the fields used by the
// tests, keeping every fixture byte reviewable instead of relying on a host
// archiver or an opaque checked-in binary.
func rarArchiveFixture(
	t *testing.T,
	version int,
	archiveFlags uint16,
	endFlags uint16,
	entries []rarFixtureEntry,
) []byte {
	t.Helper()
	switch version {
	case 4:
		return rar4ArchiveFixture(
			t,
			archiveFlags,
			endFlags,
			entries,
		)
	case 5:
		return rar5ArchiveFixture(
			t,
			uint64(archiveFlags),
			uint64(endFlags),
			entries,
		)
	default:
		t.Fatalf("unsupported fixture version %d", version)
		return nil
	}
}

func rar4ArchiveFixture(
	t *testing.T,
	archiveFlags uint16,
	endFlags uint16,
	entries []rarFixtureEntry,
) []byte {
	t.Helper()
	var output bytes.Buffer
	output.Write(rar4Signature)
	writeRAR4Block(t, &output, 0x73, archiveFlags, make([]byte, 6), nil)
	for _, entry := range entries {
		flags := rar4BlockHasData
		if entry.directory {
			flags |= rar4FileDirectory
		}
		if entry.encrypted {
			flags |= rar4FileEncrypted
		}
		unpackedSize := entry.unpackedSize
		if unpackedSize == 0 {
			unpackedSize = int64(len(entry.body))
		}
		if unpackedSize < 0 ||
			unpackedSize > int64(^uint32(0)) ||
			len(entry.body) > int(^uint32(0)) {
			t.Fatal("RAR4 fixture size overflow")
		}
		attributes := entry.attributes
		if attributes == 0 {
			if entry.directory {
				attributes = 0040755
			} else {
				attributes = 0100644
			}
		}
		checksum := crc32.ChecksumIEEE(entry.body)
		if entry.crcOverride != nil {
			checksum = *entry.crcOverride
		}
		var fields bytes.Buffer
		_ = binary.Write(&fields, binary.LittleEndian, uint32(len(entry.body)))
		_ = binary.Write(&fields, binary.LittleEndian, uint32(unpackedSize))
		fields.WriteByte(3) // Unix host (RAR 4 stores enum value minus one).
		_ = binary.Write(&fields, binary.LittleEndian, checksum)
		_ = binary.Write(&fields, binary.LittleEndian, uint32(0))
		fields.WriteByte(29)
		method := entry.legacyMethod
		if method == 0 {
			method = 0x30
		}
		fields.WriteByte(method)
		_ = binary.Write(
			&fields,
			binary.LittleEndian,
			uint16(len(entry.name)),
		)
		_ = binary.Write(
			&fields,
			binary.LittleEndian,
			uint32(attributes),
		)
		fields.WriteString(entry.name)
		writeRAR4Block(
			t,
			&output,
			0x74,
			flags,
			fields.Bytes(),
			entry.body,
		)
	}
	writeRAR4Block(t, &output, 0x7b, endFlags, nil, nil)
	return append([]byte(nil), output.Bytes()...)
}

func writeRAR4Block(
	t *testing.T,
	output *bytes.Buffer,
	blockType byte,
	flags uint16,
	fields []byte,
	body []byte,
) {
	t.Helper()
	headerSize := 7 + len(fields)
	if headerSize > int(^uint16(0)) {
		t.Fatal("RAR4 fixture header overflow")
	}
	header := make([]byte, headerSize)
	header[2] = blockType
	binary.LittleEndian.PutUint16(header[3:5], flags)
	binary.LittleEndian.PutUint16(header[5:7], uint16(headerSize))
	copy(header[7:], fields)
	binary.LittleEndian.PutUint16(
		header[:2],
		uint16(crc32.ChecksumIEEE(header[2:])),
	)
	output.Write(header)
	output.Write(body)
}

func rar5ArchiveFixture(
	t *testing.T,
	archiveFlags uint64,
	endFlags uint64,
	entries []rarFixtureEntry,
) []byte {
	t.Helper()
	var output bytes.Buffer
	output.Write(rar5Signature)
	archiveFields := appendUvarint(nil, archiveFlags)
	if archiveFlags&uint64(rar5ArchiveVolumeNumber) != 0 {
		archiveFields = appendUvarint(archiveFields, 1)
	}
	writeRAR5Block(
		t,
		&output,
		1,
		0,
		nil,
		archiveFields,
	)
	for _, entry := range entries {
		unpackedSize := entry.unpackedSize
		if unpackedSize == 0 {
			unpackedSize = int64(len(entry.body))
		}
		if unpackedSize < 0 {
			t.Fatal("negative RAR5 fixture size")
		}
		attributes := entry.attributes
		if attributes == 0 {
			if entry.directory {
				attributes = 0040755
			} else {
				attributes = 0100644
			}
		}
		fileFlags := uint64(0x0004) // CRC32 is present.
		if entry.directory {
			fileFlags |= 0x0001
		}
		checksum := crc32.ChecksumIEEE(entry.body)
		if entry.crcOverride != nil {
			checksum = *entry.crcOverride
		}
		fields := appendUvarint(nil, fileFlags)
		fields = appendUvarint(fields, uint64(unpackedSize))
		fields = appendUvarint(fields, uint64(attributes))
		fields = binary.LittleEndian.AppendUint32(fields, checksum)
		fields = appendUvarint(fields, entry.compressionFlags)
		fields = appendUvarint(fields, 1) // Unix host.
		fields = appendUvarint(fields, uint64(len(entry.name)))
		fields = append(fields, entry.name...)
		writeRAR5Block(t, &output, 2, 0x0002, entry.body, fields)
	}
	writeRAR5Block(
		t,
		&output,
		5,
		0,
		nil,
		appendUvarint(nil, endFlags),
	)
	return append([]byte(nil), output.Bytes()...)
}

func rar5ArchivePrefix(t *testing.T) []byte {
	t.Helper()
	var output bytes.Buffer
	output.Write(rar5Signature)
	writeRAR5Block(
		t,
		&output,
		rar5BlockArchive,
		0,
		nil,
		appendUvarint(nil, 0),
	)
	return append([]byte(nil), output.Bytes()...)
}

func rar4ArchivePrefix(t *testing.T) []byte {
	t.Helper()
	var output bytes.Buffer
	output.Write(rar4Signature)
	writeRAR4Block(
		t,
		&output,
		rar4BlockArchive,
		0,
		make([]byte, 6),
		nil,
	)
	return append([]byte(nil), output.Bytes()...)
}

func appendRawRAR5Header(output []byte, header []byte) []byte {
	size := appendUvarint(nil, uint64(len(header)))
	checksummed := append(append([]byte(nil), size...), header...)
	output = binary.LittleEndian.AppendUint32(
		output,
		crc32.ChecksumIEEE(checksummed),
	)
	output = append(output, size...)
	return append(output, header...)
}

func writeRAR5Block(
	t *testing.T,
	output *bytes.Buffer,
	blockType uint64,
	flags uint64,
	body []byte,
	fields []byte,
) {
	t.Helper()
	header := appendUvarint(nil, blockType)
	header = appendUvarint(header, flags)
	if flags&0x0002 != 0 {
		header = appendUvarint(header, uint64(len(body)))
	}
	header = append(header, fields...)
	if len(header) > 2<<20 {
		t.Fatal("RAR5 fixture header overflow")
	}
	size := appendUvarint(nil, uint64(len(header)))
	checksummed := append(append([]byte(nil), size...), header...)
	_ = binary.Write(
		output,
		binary.LittleEndian,
		crc32.ChecksumIEEE(checksummed),
	)
	output.Write(size)
	output.Write(header)
	output.Write(body)
}

func appendUvarint(output []byte, value uint64) []byte {
	return binary.AppendUvarint(output, value)
}

func runRARExtract(
	t *testing.T,
	data []byte,
	limits Limits,
) Result {
	t.Helper()
	sourcePath := filepath.Join(t.TempDir(), "input.rar")
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
		engine:        engine,
		ctx:           context.Background(),
		workDir:       workDir,
		rootSize:      int64(len(data)),
		nextID:        1,
		paths:         make(map[string]struct{}),
		nodeIndex:     make(map[int]int),
		directories:   make(map[string]int),
		reservedPaths: make(map[string]struct{}),
		memory: parserDecoderMemory{
			limit: engine.parserDecoderMemoryLimit,
		},
	}
	budget := containerBudget{sourceSize: int64(len(data))}
	err = state.extractRAR(
		source,
		int64(len(data)),
		0,
		"",
		0,
		&budget,
	)
	if err != nil {
		var limit *limitError
		if errors.As(err, &limit) {
			state.markLimit(limit.code)
			err = nil
		}
	}
	if err != nil {
		t.Fatalf("RAR extraction error = %v", err)
	}
	result := state.result()
	assertNodeGraph(t, result.Nodes)
	workEntries, err := os.ReadDir(workDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(workEntries) != 0 {
		t.Fatalf("work directory is not clean: %v", workEntries)
	}
	return result
}

func TestRARFixtureIsReadableByUpstreamReader(t *testing.T) {
	for _, version := range []int{4, 5} {
		data := rarArchiveFixture(t, version, 0, 0, []rarFixtureEntry{{
			name:       "fixture.txt",
			body:       []byte("fixture"),
			attributes: 0100644,
		}})
		reader, err := rardecode.NewReader(
			bytes.NewReader(data),
			rardecode.MaxDictionarySize(rarMaxDictionarySize),
		)
		if err != nil {
			t.Fatalf("RAR%d NewReader() error = %v", version, err)
		}
		header, err := reader.Next()
		if err != nil {
			t.Fatalf("RAR%d Next() error = %v", version, err)
		}
		if header.Name != "fixture.txt" {
			t.Fatalf("RAR%d header = %+v", version, header)
		}
		var body bytes.Buffer
		if _, err := body.ReadFrom(reader); err != nil {
			t.Fatalf("RAR%d Read() error = %v", version, err)
		}
		if body.String() != "fixture" {
			t.Fatalf("RAR%d body = %q", version, body.String())
		}
	}
}

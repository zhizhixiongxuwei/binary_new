package extract

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"binaryscan/internal/filetype"
)

func TestZIPPreflightAcceptsClassicAndZIP64(t *testing.T) {
	classic := zipFixture(t, []zipEntry{
		{name: "first.txt", body: []byte("first")},
		{name: "second.txt", body: []byte("second")},
	})
	zip64 := forceZIP64(t, classic)
	prefixed := append([]byte("#!/bin/sh\n"), classic...)
	for name, data := range map[string][]byte{
		"classic":  classic,
		"prefixed": prefixed,
		"zip64":    zip64,
	} {
		t.Run(name, func(t *testing.T) {
			info, err := preflightZIPDirectory(
				context.Background(),
				bytes.NewReader(data),
				int64(len(data)),
				10,
			)
			if err != nil {
				t.Fatalf("preflightZIPDirectory() error = %v", err)
			}
			if info.records != 2 || info.size == 0 ||
				info.zip64 != (name == "zip64") {
				t.Fatalf("directory info = %+v", info)
			}
			result := runExtract(t, data, "zip", generousLimits())
			if result.Partial || len(result.Nodes) != 2 {
				t.Fatalf("result = %+v", result)
			}
		})
	}
}

func TestZIPPreflightMarksMultiVolumeArchivesUnsupported(t *testing.T) {
	classic := zipFixture(t, []zipEntry{{
		name: "classic.txt",
		body: []byte("classic"),
	}})
	classicEOCD := findTestZIPEOCD(t, classic)
	binary.LittleEndian.PutUint16(
		classic[classicEOCD+4:classicEOCD+6],
		1,
	)

	zip64 := forceZIP64(t, zipFixture(t, []zipEntry{{
		name: "zip64.txt",
		body: []byte("zip64"),
	}}))
	locator := bytes.LastIndex(zip64, []byte{'P', 'K', 6, 7})
	if locator < 0 {
		t.Fatal("ZIP64 locator not found")
	}
	binary.LittleEndian.PutUint32(zip64[locator+4:locator+8], 1)

	for name, data := range map[string][]byte{
		"classic": classic,
		"zip64":   zip64,
	} {
		t.Run(name, func(t *testing.T) {
			_, preflightErr := preflightZIPDirectory(
				context.Background(),
				bytes.NewReader(data),
				int64(len(data)),
				10,
			)
			if !errors.Is(
				preflightErr,
				errUnsupportedZIPMultiVolume,
			) {
				t.Fatalf("preflight error = %v", preflightErr)
			}

			result := runExtract(t, data, "zip", generousLimits())
			if !result.Partial ||
				result.LimitCode != "" ||
				len(result.Nodes) != 1 ||
				result.Nodes[0].ExtractionStatus != StatusUnsupported ||
				result.Nodes[0].ErrorCode != "multi_volume_unsupported" {
				t.Fatalf("result = %+v", result)
			}
		})
	}
}

func TestZIPPreflightMarksZIP64EndRecordMultiVolumeUnsupported(
	t *testing.T,
) {
	tests := []struct {
		name   string
		mutate func([]byte, int)
	}{
		{
			name: "current disk",
			mutate: func(data []byte, record int) {
				binary.LittleEndian.PutUint32(
					data[record+16:record+20],
					1,
				)
			},
		},
		{
			name: "directory disk",
			mutate: func(data []byte, record int) {
				binary.LittleEndian.PutUint32(
					data[record+20:record+24],
					1,
				)
			},
		},
		{
			name: "records on disk",
			mutate: func(data []byte, record int) {
				binary.LittleEndian.PutUint64(
					data[record+24:record+32],
					0,
				)
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			data := forceZIP64(t, zipFixture(t, []zipEntry{{
				name: "zip64.txt",
				body: []byte("zip64"),
			}}))
			record := bytes.LastIndex(data, []byte{'P', 'K', 6, 6})
			if record < 0 {
				t.Fatal("ZIP64 end record not found")
			}
			test.mutate(data, record)

			_, preflightErr := preflightZIPDirectory(
				context.Background(),
				bytes.NewReader(data),
				int64(len(data)),
				10,
			)
			if !errors.Is(
				preflightErr,
				errUnsupportedZIPMultiVolume,
			) {
				t.Fatalf("preflight error = %v", preflightErr)
			}

			result := runExtract(t, data, "zip", generousLimits())
			if !result.Partial ||
				result.LimitCode != "" ||
				len(result.Nodes) != 1 ||
				result.Nodes[0].ExtractionStatus != StatusUnsupported ||
				result.Nodes[0].ErrorCode !=
					"multi_volume_unsupported" {
				t.Fatalf("result = %+v", result)
			}
		})
	}
}

func TestNestedMultiVolumeZIPDiagnosticKeepsContainerParent(t *testing.T) {
	inner := zipFixture(t, []zipEntry{{
		name: "inner.txt",
		body: []byte("inner"),
	}})
	innerEOCD := findTestZIPEOCD(t, inner)
	binary.LittleEndian.PutUint16(inner[innerEOCD+4:innerEOCD+6], 1)
	outer := zipFixture(t, []zipEntry{{
		name: "inner.zip",
		body: inner,
	}})

	result := runExtract(t, outer, "zip", generousLimits())
	container := findNode(t, result.Nodes, "/inner.zip")
	var diagnostic Node
	for _, node := range result.Nodes {
		if node.ErrorCode == "multi_volume_unsupported" {
			diagnostic = node
			break
		}
	}
	if !result.Partial ||
		diagnostic.LocalID == 0 ||
		diagnostic.ParentLocalID != container.LocalID ||
		diagnostic.ExtractionStatus != StatusUnsupported ||
		!strings.HasPrefix(
			diagnostic.LogicalPath,
			container.LogicalPath+"/__unsupported_entry_",
		) {
		t.Fatalf(
			"result=%+v container=%+v diagnostic=%+v",
			result,
			container,
			diagnostic,
		)
	}
	var metadata map[string]any
	if err := json.Unmarshal(diagnostic.MetadataJSON, &metadata); err != nil {
		t.Fatal(err)
	}
	if metadata["archive"] != "zip" ||
		metadata["synthetic"] != true ||
		metadata["archive_container_path"] != container.LogicalPath {
		t.Fatalf("diagnostic metadata = %#v", metadata)
	}
}

func TestZIPPreflightRejectsForgedZIP64MillionCount(t *testing.T) {
	data := forceZIP64(t, zipFixture(t, []zipEntry{{
		name: "only.txt",
		body: []byte("only"),
	}}))
	record := bytes.LastIndex(data, []byte{'P', 'K', 6, 6})
	if record < 0 {
		t.Fatal("ZIP64 end record not found")
	}
	binary.LittleEndian.PutUint64(data[record+24:record+32], 1_000_000)
	binary.LittleEndian.PutUint64(data[record+32:record+40], 1_000_000)

	result := runExtract(t, data, "zip", generousLimits())
	if !result.Partial || len(result.Nodes) != 1 ||
		result.Nodes[0].ExtractionStatus != StatusCorrupt ||
		result.Nodes[0].ErrorCode != "zip_archive_corrupt" {
		t.Fatalf("result = %+v", result)
	}
}

func TestZIPPreflightMirrorsGoLegacyZIP64SizeSentinel(t *testing.T) {
	data := forceZIP64(t, zipFixture(t, []zipEntry{{
		name: "only.txt",
		body: []byte("only"),
	}}))
	record := bytes.LastIndex(data, []byte{'P', 'K', 6, 6})
	eocd := findTestZIPEOCD(t, data)
	if record < 0 {
		t.Fatal("ZIP64 end record not found")
	}
	records := binary.LittleEndian.Uint64(data[record+32 : record+40])
	directoryOffset := binary.LittleEndian.Uint64(
		data[record+48 : record+56],
	)
	binary.LittleEndian.PutUint16(
		data[eocd+8:eocd+10],
		uint16(records),
	)
	binary.LittleEndian.PutUint16(
		data[eocd+10:eocd+12],
		uint16(records),
	)
	// Go's archive/zip historically treats 0xffff, rather than
	// 0xffffffff, as the 32-bit directory-size ZIP64 sentinel.
	binary.LittleEndian.PutUint32(
		data[eocd+12:eocd+16],
		math.MaxUint16,
	)
	binary.LittleEndian.PutUint32(
		data[eocd+16:eocd+20],
		uint32(directoryOffset),
	)

	result := runExtract(t, data, "zip", generousLimits())
	if result.Partial ||
		findNode(t, result.Nodes, "/only.txt").ExtractionStatus !=
			StatusExtracted {
		t.Fatalf("legacy sentinel result = %+v", result)
	}

	attack := append([]byte(nil), data...)
	binary.LittleEndian.PutUint64(
		attack[record+24:record+32],
		1_000_000,
	)
	binary.LittleEndian.PutUint64(
		attack[record+32:record+40],
		1_000_000,
	)
	attackResult := runExtract(t, attack, "zip", generousLimits())
	if !attackResult.Partial || len(attackResult.Nodes) != 1 ||
		attackResult.Nodes[0].ExtractionStatus != StatusCorrupt ||
		attackResult.Nodes[0].ErrorCode != "zip_archive_corrupt" {
		t.Fatalf("attack result = %+v", attackResult)
	}
}

func TestZIPPreflightUsesActualCountForNodeLimit(t *testing.T) {
	data := zipFixture(t, []zipEntry{
		{name: "one", body: []byte("1")},
		{name: "two", body: []byte("2")},
		{name: "three", body: []byte("3")},
	})
	eocd := findTestZIPEOCD(t, data)
	// If preflight trusted this forged count, archive/zip.NewReader would
	// reject the archive before the configured node limit became observable.
	binary.LittleEndian.PutUint16(data[eocd+8:eocd+10], 1)
	binary.LittleEndian.PutUint16(data[eocd+10:eocd+12], 1)
	limits := generousLimits()
	limits.MaxNodes = 2

	_, preflightErr := preflightZIPDirectory(
		context.Background(),
		bytes.NewReader(data),
		int64(len(data)),
		limits.MaxNodes,
	)
	var preflightLimit *limitError
	if !errors.As(preflightErr, &preflightLimit) ||
		preflightLimit.code != LimitMaxNodes ||
		!preflightLimit.global {
		t.Fatalf("preflight error = %#v", preflightErr)
	}
	result := runExtract(t, data, "zip", limits)
	if !result.Partial || result.LimitCode != LimitMaxNodes ||
		len(result.Nodes) != 0 {
		t.Fatalf("result = %+v", result)
	}
}

func TestZIPPreflightMetadataLimitIsObservable(t *testing.T) {
	sourcePath := filepath.Join(t.TempDir(), "metadata-limit.zip")
	source, err := os.OpenFile(sourcePath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	directorySize := maxZIPDirectoryMetadataBytes + 1
	sourceSize := int64(directorySize) + zipDirectoryEndLength
	if err := source.Truncate(sourceSize); err != nil {
		t.Fatal(err)
	}
	eocd := make([]byte, zipDirectoryEndLength)
	binary.LittleEndian.PutUint32(eocd[0:4], zipDirectoryEndSignature)
	binary.LittleEndian.PutUint16(eocd[8:10], 1)
	binary.LittleEndian.PutUint16(eocd[10:12], 1)
	binary.LittleEndian.PutUint32(eocd[12:16], uint32(directorySize))
	if _, err := source.WriteAt(eocd, sourceSize-zipDirectoryEndLength); err != nil {
		t.Fatal(err)
	}

	_, preflightErr := preflightZIPDirectory(
		context.Background(),
		source,
		sourceSize,
		1000,
	)
	var preflightLimit *limitError
	if !errors.As(preflightErr, &preflightLimit) ||
		preflightLimit.code != LimitMaxArchiveMetadata ||
		preflightLimit.global {
		t.Fatalf("preflight error = %#v", preflightErr)
	}
	engine := NewEngine(filetype.Detector{}, generousLimits())
	result, err := engine.Extract(
		context.Background(),
		source,
		"zip",
		t.TempDir(),
	)
	if err != nil {
		t.Fatalf("Extract() error = %v", err)
	}
	if !result.Partial ||
		result.LimitCode != LimitMaxArchiveMetadata ||
		len(result.Nodes) != 0 {
		t.Fatalf("result = %+v", result)
	}
}

func TestZIPPreflightRejectsInvalidDirectoryRanges(t *testing.T) {
	sizeOutsideArchive := make([]byte, zipDirectoryEndLength)
	binary.LittleEndian.PutUint32(
		sizeOutsideArchive[0:4],
		zipDirectoryEndSignature,
	)
	binary.LittleEndian.PutUint32(sizeOutsideArchive[12:16], 1)

	offsetOutsideArchive := zipFixture(t, []zipEntry{{
		name: "file",
		body: []byte("x"),
	}})
	offsetEOCD := findTestZIPEOCD(t, offsetOutsideArchive)
	offset := binary.LittleEndian.Uint32(
		offsetOutsideArchive[offsetEOCD+16 : offsetEOCD+20],
	)
	binary.LittleEndian.PutUint32(
		offsetOutsideArchive[offsetEOCD+16:offsetEOCD+20],
		offset+1,
	)

	entryOutsideDirectory := zipFixture(t, []zipEntry{{
		name: "file",
		body: []byte("x"),
	}})
	central := bytes.Index(
		entryOutsideDirectory,
		[]byte{'P', 'K', 1, 2},
	)
	if central < 0 {
		t.Fatal("central directory not found")
	}
	binary.LittleEndian.PutUint16(
		entryOutsideDirectory[central+28:central+30],
		math.MaxUint16,
	)

	for name, data := range map[string][]byte{
		"size":   sizeOutsideArchive,
		"offset": offsetOutsideArchive,
		"entry":  entryOutsideDirectory,
	} {
		t.Run(name, func(t *testing.T) {
			result := runExtract(t, data, "zip", generousLimits())
			if !result.Partial || len(result.Nodes) != 1 ||
				result.Nodes[0].ExtractionStatus != StatusCorrupt ||
				result.Nodes[0].ErrorCode != "zip_archive_corrupt" {
				t.Fatalf("result = %+v", result)
			}
		})
	}
}

func TestZIPPreflightCancellationDuringDirectoryScan(t *testing.T) {
	data := zipFixture(t, []zipEntry{
		{name: "first", body: []byte("1")},
		{name: "second", body: []byte("2")},
	})
	ctx, cancel := context.WithCancel(context.Background())
	reader := &cancelAfterReaderAt{
		reader:      bytes.NewReader(data),
		cancel:      cancel,
		cancelAfter: 2,
	}
	_, err := preflightZIPDirectory(
		ctx,
		reader,
		int64(len(data)),
		10,
	)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("preflight error = %v", err)
	}
}

func TestZIPRecordedNodeSizeIsBoundedAndDeclaredSizeIsPreserved(t *testing.T) {
	const declaredSize = uint64(1 << 40)
	tests := []struct {
		name      string
		mode      os.FileMode
		encrypted bool
		nodeType  string
		status    string
	}{
		{
			name:      "encrypted",
			encrypted: true,
			nodeType:  NodeTypeFile,
			status:    StatusPasswordRequired,
		},
		{
			name:     "symlink",
			mode:     os.ModeSymlink | 0o777,
			nodeType: NodeTypeSymlink,
			status:   StatusRecorded,
		},
		{
			name:     "special",
			mode:     os.ModeDevice | 0o600,
			nodeType: NodeTypeSpecial,
			status:   StatusRecorded,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			data := zipFixture(t, []zipEntry{{
				name: test.name,
				body: []byte("content"),
				mode: test.mode,
			}})
			data = setZIPCentralDeclaredSize(t, data, declaredSize)
			if test.encrypted {
				setZIPEncryptionFlag(t, data)
			}
			result := runExtract(t, data, "zip", generousLimits())
			node := findNode(t, result.Nodes, "/"+test.name)
			if node.NodeType != test.nodeType ||
				node.ExtractionStatus != test.status ||
				node.SizeBytes != defaultMaxExpandedBytes {
				t.Fatalf("node = %+v", node)
			}
			decoder := json.NewDecoder(bytes.NewReader(node.MetadataJSON))
			decoder.UseNumber()
			var metadata map[string]any
			if err := decoder.Decode(&metadata); err != nil {
				t.Fatal(err)
			}
			declared, ok := metadata["declared_bytes"].(json.Number)
			if !ok || declared.String() != strconv.FormatUint(declaredSize, 10) {
				t.Fatalf("metadata = %s", node.MetadataJSON)
			}
		})
	}
}

func TestSafeSignedSizeUsesReportContractBound(t *testing.T) {
	if got := safeSignedSize(math.MaxInt64); got != defaultMaxExpandedBytes {
		t.Fatalf("safeSignedSize(max int64) = %d", got)
	}
	if got := safeSignedSize(-1); got != 0 {
		t.Fatalf("safeSignedSize(-1) = %d", got)
	}
}

type cancelAfterReaderAt struct {
	reader      io.ReaderAt
	cancel      context.CancelFunc
	cancelAfter int
	reads       int
}

func (reader *cancelAfterReaderAt) ReadAt(buffer []byte, offset int64) (int, error) {
	count, err := reader.reader.ReadAt(buffer, offset)
	reader.reads++
	if reader.reads == reader.cancelAfter {
		reader.cancel()
	}
	return count, err
}

func forceZIP64(t *testing.T, data []byte) []byte {
	t.Helper()
	eocdOffset := findTestZIPEOCD(t, data)
	eocd := append([]byte(nil), data[eocdOffset:]...)
	records := binary.LittleEndian.Uint16(eocd[10:12])
	directorySize := binary.LittleEndian.Uint32(eocd[12:16])
	directoryOffset := binary.LittleEndian.Uint32(eocd[16:20])

	zip64End := make([]byte, zipDirectory64EndLength)
	binary.LittleEndian.PutUint32(
		zip64End[0:4],
		zipDirectory64EndSignature,
	)
	binary.LittleEndian.PutUint64(
		zip64End[4:12],
		zipDirectory64EndLength-12,
	)
	binary.LittleEndian.PutUint16(zip64End[12:14], 45)
	binary.LittleEndian.PutUint16(zip64End[14:16], 45)
	binary.LittleEndian.PutUint64(zip64End[24:32], uint64(records))
	binary.LittleEndian.PutUint64(zip64End[32:40], uint64(records))
	binary.LittleEndian.PutUint64(
		zip64End[40:48],
		uint64(directorySize),
	)
	binary.LittleEndian.PutUint64(
		zip64End[48:56],
		uint64(directoryOffset),
	)

	locator := make([]byte, zipDirectory64LocatorLength)
	binary.LittleEndian.PutUint32(
		locator[0:4],
		zipDirectory64LocatorSignature,
	)
	binary.LittleEndian.PutUint64(locator[8:16], uint64(eocdOffset))
	binary.LittleEndian.PutUint32(locator[16:20], 1)

	binary.LittleEndian.PutUint16(eocd[8:10], math.MaxUint16)
	binary.LittleEndian.PutUint16(eocd[10:12], math.MaxUint16)
	binary.LittleEndian.PutUint32(eocd[12:16], math.MaxUint32)
	binary.LittleEndian.PutUint32(eocd[16:20], math.MaxUint32)

	result := make([]byte, 0, len(data)+len(zip64End)+len(locator))
	result = append(result, data[:eocdOffset]...)
	result = append(result, zip64End...)
	result = append(result, locator...)
	result = append(result, eocd...)
	return result
}

func setZIPCentralDeclaredSize(
	t *testing.T,
	data []byte,
	declaredSize uint64,
) []byte {
	t.Helper()
	central := bytes.Index(data, []byte{'P', 'K', 1, 2})
	eocd := findTestZIPEOCD(t, data)
	if central < 0 || central >= eocd {
		t.Fatal("ZIP central directory not found")
	}
	nameLength := int(binary.LittleEndian.Uint16(
		data[central+28 : central+30],
	))
	extraLength := int(binary.LittleEndian.Uint16(
		data[central+30 : central+32],
	))
	if extraLength > math.MaxUint16-12 {
		t.Fatal("ZIP fixture extra field is too large")
	}
	insertAt := central + zipDirectoryHeaderLength + nameLength + extraLength
	zip64Extra := make([]byte, 12)
	binary.LittleEndian.PutUint16(zip64Extra[0:2], 1)
	binary.LittleEndian.PutUint16(zip64Extra[2:4], 8)
	binary.LittleEndian.PutUint64(zip64Extra[4:12], declaredSize)

	result := make([]byte, 0, len(data)+len(zip64Extra))
	result = append(result, data[:insertAt]...)
	result = append(result, zip64Extra...)
	result = append(result, data[insertAt:]...)
	binary.LittleEndian.PutUint16(
		result[central+6:central+8],
		45,
	)
	binary.LittleEndian.PutUint32(
		result[central+24:central+28],
		math.MaxUint32,
	)
	binary.LittleEndian.PutUint16(
		result[central+30:central+32],
		uint16(extraLength+len(zip64Extra)),
	)
	newEOCD := eocd + len(zip64Extra)
	directorySize := binary.LittleEndian.Uint32(
		result[newEOCD+12 : newEOCD+16],
	)
	binary.LittleEndian.PutUint32(
		result[newEOCD+12:newEOCD+16],
		directorySize+uint32(len(zip64Extra)),
	)
	return result
}

func findTestZIPEOCD(t *testing.T, data []byte) int {
	t.Helper()
	offset := bytes.LastIndex(data, []byte{'P', 'K', 5, 6})
	if offset < 0 || offset+zipDirectoryEndLength > len(data) {
		t.Fatal("ZIP EOCD not found")
	}
	return offset
}

package extract

import (
	"archive/tar"
	"bytes"
	"encoding/json"
	"io"
	"math"
	"strconv"
	"testing"
)

func TestRegularEntryLimitPreservesBoundaryAndSafeSibling(t *testing.T) {
	const maxEntryBytes = int64(16)
	entries := []zipEntry{
		{name: "boundary.bin", body: bytes.Repeat([]byte{'b'}, 16), store: true},
		{name: "oversized.bin", body: bytes.Repeat([]byte{'x'}, 17), store: true},
		{name: "safe.txt", body: []byte("safe"), store: true},
	}
	tests := []struct {
		name   string
		format string
		data   []byte
	}{
		{name: "zip", format: "zip", data: zipFixture(t, entries)},
		{name: "tar", format: "tar", data: entryLimitTARFixture(t, entries)},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			limits := generousLimits()
			limits.MaxEntryBytes = maxEntryBytes
			result := runExtract(t, test.data, test.format, limits)
			boundary := findNode(t, result.Nodes, "/boundary.bin")
			oversized := findNode(t, result.Nodes, "/oversized.bin")
			safe := findNode(t, result.Nodes, "/safe.txt")

			if !result.Partial ||
				result.LimitCode != LimitMaxEntryBytes ||
				result.ExpandedBytes != 36 ||
				boundary.ExtractionStatus != StatusExtracted ||
				boundary.SizeBytes != maxEntryBytes ||
				boundary.SHA256 == "" ||
				oversized.ExtractionStatus != StatusLimitExceeded ||
				oversized.ErrorCode != LimitMaxEntryBytes ||
				oversized.SizeBytes != maxEntryBytes ||
				oversized.SHA256 != "" ||
				safe.ExtractionStatus != StatusExtracted ||
				safe.SizeBytes != 4 {
				t.Fatalf(
					"result=%+v boundary=%+v oversized=%+v safe=%+v",
					result,
					boundary,
					oversized,
					safe,
				)
			}
			assertCleanWorkDirectory(t)
		})
	}
}

func TestTARSparseLogicalSizeUsesEntryLimit(t *testing.T) {
	const (
		logicalBytes  = int64(17)
		maxEntryBytes = int64(16)
	)
	data := sparseLogicalTARFixture(t, logicalBytes)

	archive := tar.NewReader(bytes.NewReader(data))
	header, err := archive.Next()
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(archive)
	if err != nil {
		t.Fatal(err)
	}
	if header.Name != "sparse.bin" ||
		header.Size != logicalBytes ||
		len(body) != int(logicalBytes) ||
		!bytes.Equal(body, make([]byte, logicalBytes)) {
		t.Fatalf("sparse header=%+v body=%x", header, body)
	}

	limits := generousLimits()
	limits.MaxEntryBytes = maxEntryBytes
	result := runExtract(t, data, "tar", limits)
	sparse := findNode(t, result.Nodes, "/sparse.bin")
	safe := findNode(t, result.Nodes, "/safe.txt")
	var metadata map[string]any
	if err := json.Unmarshal(sparse.MetadataJSON, &metadata); err != nil {
		t.Fatal(err)
	}
	if !result.Partial ||
		result.LimitCode != LimitMaxEntryBytes ||
		result.ExpandedBytes != maxEntryBytes+4 ||
		sparse.ExtractionStatus != StatusLimitExceeded ||
		sparse.ErrorCode != LimitMaxEntryBytes ||
		sparse.SizeBytes != maxEntryBytes ||
		metadata["declared_bytes"] != float64(logicalBytes) ||
		safe.ExtractionStatus != StatusExtracted ||
		safe.SizeBytes != 4 {
		t.Fatalf(
			"result=%+v sparse=%+v safe=%+v metadata=%+v",
			result,
			sparse,
			safe,
			metadata,
		)
	}
	assertCleanWorkDirectory(t)
}

func TestTARHugeSparseEntryContinuesWithoutWalkingLogicalHole(t *testing.T) {
	const maxEntryBytes = int64(16)
	data := sparseLogicalTARFixture(t, math.MaxInt64)
	limits := generousLimits()
	limits.MaxEntryBytes = maxEntryBytes

	result := runExtract(t, data, "tar", limits)
	sparse := findNode(t, result.Nodes, "/sparse.bin")
	safe := findNode(t, result.Nodes, "/safe.txt")
	if !result.Partial ||
		result.LimitCode != LimitMaxEntryBytes ||
		result.ExpandedBytes != maxEntryBytes+4 ||
		sparse.ExtractionStatus != StatusLimitExceeded ||
		sparse.ErrorCode != LimitMaxEntryBytes ||
		sparse.SizeBytes != maxEntryBytes ||
		safe.ExtractionStatus != StatusExtracted ||
		safe.SizeBytes != 4 {
		t.Fatalf(
			"result=%+v sparse=%+v safe=%+v",
			result,
			sparse,
			safe,
		)
	}
	assertCleanWorkDirectory(t)
}

func TestTARSparsePhysicalExtentIsSkippedBeforeSafeSibling(t *testing.T) {
	const (
		logicalBytes  = int64(17)
		maxEntryBytes = int64(16)
	)
	data := sparsePhysicalExtentTARFixture(t, logicalBytes)

	archive := tar.NewReader(bytes.NewReader(data))
	header, err := archive.Next()
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(archive)
	if err != nil {
		t.Fatal(err)
	}
	if header.Size != logicalBytes ||
		len(body) != int(logicalBytes) ||
		!bytes.Equal(body[13:], []byte("data")) {
		t.Fatalf("sparse header=%+v body=%x", header, body)
	}

	limits := generousLimits()
	limits.MaxEntryBytes = maxEntryBytes
	result := runExtract(t, data, "tar", limits)
	sparse := findNode(t, result.Nodes, "/sparse.bin")
	safe := findNode(t, result.Nodes, "/safe.txt")
	if !result.Partial ||
		result.LimitCode != LimitMaxEntryBytes ||
		result.ExpandedBytes != maxEntryBytes+4 ||
		sparse.ExtractionStatus != StatusLimitExceeded ||
		sparse.ErrorCode != LimitMaxEntryBytes ||
		sparse.SizeBytes != maxEntryBytes ||
		safe.ExtractionStatus != StatusExtracted ||
		safe.SizeBytes != 4 {
		t.Fatalf(
			"result=%+v sparse=%+v safe=%+v",
			result,
			sparse,
			safe,
		)
	}
	assertCleanWorkDirectory(t)
}

func TestTARSparsePhysicalExtentsAreSkippedBeforeSafeSibling(t *testing.T) {
	const (
		logicalBytes  = int64(20)
		maxEntryBytes = int64(16)
	)
	data := sparseTARExtentsFixture(
		t,
		logicalBytes,
		[]sparseTestExtent{
			{offset: 2, data: []byte("abc")},
			{offset: 14, data: []byte("wxyz")},
		},
	)

	archive := tar.NewReader(bytes.NewReader(data))
	header, err := archive.Next()
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(archive)
	if err != nil {
		t.Fatal(err)
	}
	if header.Size != logicalBytes ||
		len(body) != int(logicalBytes) ||
		!bytes.Equal(body[2:5], []byte("abc")) ||
		!bytes.Equal(body[14:18], []byte("wxyz")) {
		t.Fatalf("sparse header=%+v body=%x", header, body)
	}

	limits := generousLimits()
	limits.MaxEntryBytes = maxEntryBytes
	result := runExtract(t, data, "tar", limits)
	sparse := findNode(t, result.Nodes, "/sparse.bin")
	safe := findNode(t, result.Nodes, "/safe.txt")
	if !result.Partial ||
		result.LimitCode != LimitMaxEntryBytes ||
		result.ExpandedBytes != maxEntryBytes+4 ||
		sparse.ExtractionStatus != StatusLimitExceeded ||
		sparse.ErrorCode != LimitMaxEntryBytes ||
		sparse.SizeBytes != maxEntryBytes ||
		safe.ExtractionStatus != StatusExtracted ||
		safe.SizeBytes != 4 {
		t.Fatalf(
			"result=%+v sparse=%+v safe=%+v",
			result,
			sparse,
			safe,
		)
	}
	assertCleanWorkDirectory(t)
}

func TestTARLimitedSparseTruncatedPhysicalDataIsReportedCorrupt(t *testing.T) {
	const (
		logicalBytes  = int64(32)
		maxEntryBytes = int64(16)
	)
	physical := []byte("unique-sparse-physical-data")
	data := sparseTARExtentsFixture(
		t,
		logicalBytes,
		[]sparseTestExtent{{
			offset: logicalBytes - int64(len(physical)),
			data:   physical,
		}},
	)
	physicalOffset := bytes.Index(data, physical)
	if physicalOffset < 0 {
		t.Fatal("sparse physical payload not found")
	}
	truncated := append(
		[]byte(nil),
		data[:physicalOffset+len(physical)/2]...,
	)

	limits := generousLimits()
	limits.MaxEntryBytes = maxEntryBytes
	result := runExtract(t, truncated, "tar", limits)
	sparse := findNode(t, result.Nodes, "/sparse.bin")
	if !result.Partial ||
		result.LimitCode != LimitMaxEntryBytes ||
		result.ExpandedBytes != maxEntryBytes ||
		sparse.ExtractionStatus != StatusLimitExceeded ||
		sparse.ErrorCode != LimitMaxEntryBytes ||
		sparse.SizeBytes != maxEntryBytes ||
		len(result.Nodes) != 2 ||
		result.Nodes[1].ExtractionStatus != StatusCorrupt ||
		result.Nodes[1].ErrorCode != "tar_header_corrupt" {
		t.Fatalf(
			"result=%+v sparse=%+v",
			result,
			sparse,
		)
	}
	assertCleanWorkDirectory(t)
}

func TestTARSparseBoundaryChargesSynthesizedLogicalBytes(t *testing.T) {
	const maxEntryBytes = int64(16)
	data := sparseLogicalTARFixture(t, maxEntryBytes)
	limits := generousLimits()
	limits.MaxEntryBytes = maxEntryBytes

	result := runExtract(t, data, "tar", limits)
	sparse := findNode(t, result.Nodes, "/sparse.bin")
	safe := findNode(t, result.Nodes, "/safe.txt")
	if result.Partial ||
		result.LimitCode != "" ||
		result.ExpandedBytes != maxEntryBytes+4 ||
		sparse.ExtractionStatus != StatusExtracted ||
		sparse.SizeBytes != maxEntryBytes ||
		sparse.SHA256 == "" ||
		safe.ExtractionStatus != StatusExtracted ||
		safe.SizeBytes != 4 {
		t.Fatalf(
			"result=%+v sparse=%+v safe=%+v",
			result,
			sparse,
			safe,
		)
	}
	assertCleanWorkDirectory(t)
}

func TestRegularEntryLimitContinuesARAndCPIO(t *testing.T) {
	const maxEntryBytes = int64(16)
	oversized := bytes.Repeat([]byte{'x'}, 17)
	tests := []struct {
		name   string
		format string
		data   []byte
	}{
		{
			name:   "ar",
			format: "ar",
			data: arArchiveFixture(t, []arFixtureEntry{
				{rawName: "oversized.bin/", body: oversized},
				{rawName: "safe.txt/", body: []byte("safe")},
			}),
		},
		{
			name:   "cpio-crc",
			format: "cpio",
			data: cpioArchiveFixture(t, "crc", []cpioFixtureEntry{
				{
					name: "oversized.bin",
					mode: cpioModeRegular | 0o600,
					body: oversized,
				},
				{
					name: "safe.txt",
					mode: cpioModeRegular | 0o600,
					body: []byte("safe"),
				},
			}, true),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			limits := generousLimits()
			limits.MaxEntryBytes = maxEntryBytes
			result := runExtract(t, test.data, test.format, limits)
			large := findNode(t, result.Nodes, "/oversized.bin")
			safe := findNode(t, result.Nodes, "/safe.txt")
			if !result.Partial ||
				result.LimitCode != LimitMaxEntryBytes ||
				result.ExpandedBytes != maxEntryBytes+4 ||
				large.ExtractionStatus != StatusLimitExceeded ||
				large.ErrorCode != LimitMaxEntryBytes ||
				large.SizeBytes != maxEntryBytes ||
				safe.ExtractionStatus != StatusExtracted ||
				safe.SizeBytes != 4 {
				t.Fatalf(
					"result=%+v oversized=%+v safe=%+v",
					result,
					large,
					safe,
				)
			}
			assertCleanWorkDirectory(t)
		})
	}
}

func TestNewEngineClampsEntryLimit(t *testing.T) {
	tests := []struct {
		name   string
		limits Limits
		want   int64
	}{
		{
			name:   "default",
			limits: Limits{},
			want:   defaultMaxEntryBytes,
		},
		{
			name: "security ceiling",
			limits: Limits{
				MaxExpandedBytes: defaultMaxExpandedBytes,
				MaxEntryBytes:    defaultMaxEntryBytes + 1,
			},
			want: defaultMaxEntryBytes,
		},
		{
			name: "expanded ceiling",
			limits: Limits{
				MaxExpandedBytes: 1024,
				MaxEntryBytes:    2048,
			},
			want: 1024,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			engine := NewEngine(errorDetector{}, test.limits)
			if engine.limits.MaxEntryBytes != test.want ||
				engine.limits.MaxEntryBytes > engine.limits.MaxExpandedBytes {
				t.Fatalf("limits = %+v", engine.limits)
			}
		})
	}
}

func entryLimitTARFixture(t *testing.T, entries []zipEntry) []byte {
	t.Helper()
	var output bytes.Buffer
	writer := tar.NewWriter(&output)
	for _, entry := range entries {
		if err := writer.WriteHeader(&tar.Header{
			Name:     entry.name,
			Mode:     0o600,
			Size:     int64(len(entry.body)),
			Typeflag: tar.TypeReg,
		}); err != nil {
			t.Fatal(err)
		}
		if _, err := writer.Write(entry.body); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return output.Bytes()
}

func sparseLogicalTARFixture(t *testing.T, logicalBytes int64) []byte {
	return sparseTARFixture(t, logicalBytes, nil)
}

func sparsePhysicalExtentTARFixture(
	t *testing.T,
	logicalBytes int64,
) []byte {
	t.Helper()
	if logicalBytes < 4 {
		t.Fatal("logical sparse size is too small for physical extent")
	}
	return sparseTARExtentsFixture(t, logicalBytes, []sparseTestExtent{{
		offset: logicalBytes - 4,
		data:   []byte("data"),
	}})
}

func sparseTARFixture(
	t *testing.T,
	logicalBytes int64,
	physical []byte,
) []byte {
	t.Helper()
	if len(physical) == 0 {
		return sparseTARExtentsFixture(t, logicalBytes, nil)
	}
	return sparseTARExtentsFixture(t, logicalBytes, []sparseTestExtent{{
		offset: logicalBytes - int64(len(physical)),
		data:   physical,
	}})
}

type sparseTestExtent struct {
	offset int64
	data   []byte
}

func sparseTARExtentsFixture(
	t *testing.T,
	logicalBytes int64,
	extents []sparseTestExtent,
) []byte {
	t.Helper()
	var paxBody []byte
	for _, record := range [][2]string{
		{"GNU.sparse.major", "1"},
		{"GNU.sparse.minor", "0"},
		{"GNU.sparse.name", "sparse.bin"},
		{"GNU.sparse.realsize", "17"},
	} {
		if record[0] == "GNU.sparse.realsize" {
			record[1] = strconv.FormatInt(logicalBytes, 10)
		}
		paxBody = append(paxBody, makePAXRecord(record[0], record[1])...)
	}
	paxPadded := (len(paxBody) + tarBlockBytes - 1) &^ (tarBlockBytes - 1)
	const sparseMapBytes = tarBlockBytes
	const safeBodyBytes = tarBlockBytes
	sparseMap := []byte("0\n")
	physicalBytes := 0
	if len(extents) > 0 {
		var mapBody bytes.Buffer
		mapBody.WriteString(strconv.Itoa(len(extents)))
		mapBody.WriteByte('\n')
		for _, extent := range extents {
			if extent.offset < 0 ||
				extent.offset > logicalBytes-int64(len(extent.data)) {
				t.Fatalf("invalid sparse extent: %+v", extent)
			}
			mapBody.WriteString(strconv.FormatInt(extent.offset, 10))
			mapBody.WriteByte('\n')
			mapBody.WriteString(strconv.Itoa(len(extent.data)))
			mapBody.WriteByte('\n')
			physicalBytes += len(extent.data)
		}
		sparseMap = mapBody.Bytes()
	}
	mainBodyBytes := sparseMapBytes + physicalBytes
	mainBodyPadded :=
		(mainBodyBytes + tarBlockBytes - 1) &^ (tarBlockBytes - 1)
	mainOffset := tarBlockBytes + paxPadded
	safeOffset := mainOffset + tarBlockBytes + mainBodyPadded
	endOffset := safeOffset + tarBlockBytes + safeBodyBytes
	output := make([]byte, endOffset+2*tarBlockBytes)

	paxHeader := output[:tarBlockBytes]
	putUSTARTARHeader(
		t,
		paxHeader,
		"PaxHeaders/sparse",
		tar.TypeXHeader,
		int64(len(paxBody)),
	)
	copy(output[tarBlockBytes:tarBlockBytes+len(paxBody)], paxBody)

	mainHeader := output[mainOffset : mainOffset+tarBlockBytes]
	putUSTARTARHeader(
		t,
		mainHeader,
		"placeholder",
		tar.TypeReg,
		int64(mainBodyBytes),
	)
	copy(
		output[mainOffset+tarBlockBytes:mainOffset+2*tarBlockBytes],
		sparseMap,
	)
	physicalOffset := mainOffset + 2*tarBlockBytes
	for _, extent := range extents {
		copy(output[physicalOffset:], extent.data)
		physicalOffset += len(extent.data)
	}

	safeHeader := output[safeOffset : safeOffset+tarBlockBytes]
	putUSTARTARHeader(t, safeHeader, "safe.txt", tar.TypeReg, 4)
	copy(output[safeOffset+tarBlockBytes:], []byte("safe"))
	return output
}

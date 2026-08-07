package extract

import (
	"archive/tar"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"binaryscan/internal/filetype"
)

const tarBlockBytes = 512

func TestTARMetadataGateRejectsOldGNUSparseExtensionChain(t *testing.T) {
	// A small completed fixture proves that this layout reaches archive/tar's
	// old GNU sparse extension parser rather than merely failing as a bad header.
	small := oldGNUSparseFixture(t, 2, false)
	header, err := tar.NewReader(bytes.NewReader(small)).Next()
	if err != nil || header.Typeflag != tar.TypeGNUSparse {
		t.Fatalf("small sparse fixture: header=%+v err=%v", header, err)
	}

	extensionBlocks := int(maxTARMetadataBytes/tarBlockBytes) + 1
	attack := oldGNUSparseFixture(t, extensionBlocks, true)
	result := runExtract(t, attack, "tar", generousLimits())
	if !result.Partial ||
		result.LimitCode != LimitMaxArchiveMetadata ||
		len(result.Nodes) != 0 {
		t.Fatalf("result = %+v", result)
	}
	assertCleanWorkDirectory(t)
}

func TestTARMetadataGateRejectsPAXSparseMap(t *testing.T) {
	small := paxSparseFixture(t, 2)
	header, err := tar.NewReader(bytes.NewReader(small)).Next()
	if err != nil ||
		header.Name != "sparse.bin" ||
		header.Typeflag != tar.TypeReg {
		t.Fatalf("small PAX sparse fixture: header=%+v err=%v", header, err)
	}

	// Each zero-length sparse extent needs only four raw bytes ("0\n0\n")
	// but expands into an archive/tar sparseEntry. Keep a complete oversized map
	// in the fixture and verify the raw gate stops it before that allocation.
	entries := int(maxTARMetadataBytes/4) + 4096
	attack := paxSparseFixture(t, entries)
	result := runExtract(t, attack, "tar", generousLimits())
	if !result.Partial ||
		result.LimitCode != LimitMaxArchiveMetadata ||
		len(result.Nodes) != 0 {
		t.Fatalf("result = %+v", result)
	}
	assertCleanWorkDirectory(t)
}

func TestNestedTARMetadataLimitIsBranchLocal(t *testing.T) {
	extensionBlocks := int(maxTARMetadataBytes/tarBlockBytes) + 1
	attack := oldGNUSparseFixture(t, extensionBlocks, true)
	outer := zipFixture(t, []zipEntry{
		{name: "sparse.tar", body: attack, store: true},
		{name: "safe.txt", body: []byte("safe"), store: true},
	})

	result := runExtractWithDetector(
		t,
		outer,
		"zip",
		generousLimits(),
		largePayloadTARDetector{minimum: int64(len(attack))},
	)
	container := findNode(t, result.Nodes, "/sparse.tar")
	safe := findNode(t, result.Nodes, "/safe.txt")
	if !result.Partial ||
		result.LimitCode != LimitMaxArchiveMetadata ||
		container.Format != "tar" ||
		container.ExtractionStatus != StatusLimitExceeded ||
		container.ErrorCode != LimitMaxArchiveMetadata ||
		safe.ExtractionStatus != StatusExtracted {
		t.Fatalf("result=%+v container=%+v safe=%+v", result, container, safe)
	}
	assertCleanWorkDirectory(t)
}

func TestTARMetadataGateObservesCancellationDuringNext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	input := &cancelingTARReader{
		input:    bytes.NewReader(oldGNUSparseFixture(t, 32, true)),
		cancel:   cancel,
		cancelAt: 4 * tarBlockBytes,
	}
	raw := newTARMetadataReader(ctx, input)
	archive := tar.NewReader(raw)
	raw.beginHeader()
	_, err := archive.Next()
	raw.endHeader()
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Next() error = %v, want context.Canceled", err)
	}
	if input.readBytes < input.cancelAt {
		t.Fatalf("reader consumed %d bytes, want at least %d", input.readBytes, input.cancelAt)
	}
}

func TestTARMetadataGateDoesNotCountRegularFileBodies(t *testing.T) {
	body := bytes.Repeat([]byte("payload-"), int(maxTARMetadataBytes/8)+1)
	data := tarStreamFixture(t, "large.bin", body)
	result := runExtract(t, data, "tar", generousLimits())
	node := findNode(t, result.Nodes, "/large.bin")
	if result.Partial ||
		result.LimitCode != "" ||
		node.ExtractionStatus != StatusExtracted ||
		node.SizeBytes != int64(len(body)) {
		t.Fatalf("result=%+v node=%+v", result, node)
	}
	assertCleanWorkDirectory(t)
}

func TestTARMetadataGateEnforcesCumulativeStreamBudget(t *testing.T) {
	reader := newTARMetadataReader(
		context.Background(),
		bytes.NewReader([]byte("abcdef")),
	)
	reader.streamRemaining = 5

	reader.beginHeader()
	buffer := make([]byte, 4)
	count, err := reader.Read(buffer)
	if err != nil || count != 4 {
		t.Fatalf("first Read() = %d, %v", count, err)
	}
	if consumed := reader.endHeader(); consumed != 4 {
		t.Fatalf("first header consumed = %d", consumed)
	}

	reader.beginHeader()
	count, err = reader.Read(buffer)
	if err != nil || count != 1 || string(buffer[:count]) != "e" {
		t.Fatalf("boundary Read() = %d, %v, %q", count, err, buffer[:count])
	}
	count, err = reader.Read(buffer)
	var limit *limitError
	if count != 0 || !errors.As(err, &limit) ||
		limit.code != LimitMaxArchiveMetadata {
		t.Fatalf("over-budget Read() = %d, %v", count, err)
	}
}

func TestTARMetadataGateDoesNotChargeQuarantinedBodyAsMetadata(t *testing.T) {
	var output bytes.Buffer
	writer := tar.NewWriter(&output)
	body := bytes.Repeat([]byte{0x5a}, int(maxTARMetadataBytes)+tarBlockBytes)
	if err := writer.WriteHeader(&tar.Header{
		Name:     "../rejected.bin",
		Mode:     0o600,
		Size:     int64(len(body)),
		Typeflag: tar.TypeReg,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Write(body); err != nil {
		t.Fatal(err)
	}
	if err := writer.WriteHeader(&tar.Header{
		Name:     "safe.txt",
		Mode:     0o600,
		Size:     4,
		Typeflag: tar.TypeReg,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Write([]byte("safe")); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}

	result := runExtract(t, output.Bytes(), "tar", generousLimits())
	rejected := findNodeWithCode(
		t,
		result.Nodes,
		"invalid_archive_path",
	)
	safe := findNode(t, result.Nodes, "/safe.txt")
	if !result.Partial ||
		result.LimitCode != "" ||
		len(result.Nodes) != 2 ||
		rejected.ExtractionStatus != StatusInvalidPath ||
		rejected.SizeBytes != int64(len(body)) ||
		safe.ExtractionStatus != StatusExtracted {
		t.Fatalf("result = %+v", result)
	}
	assertCleanWorkDirectory(t)
}

func TestTARMetadataGatePreservesNestedNormalExtraction(t *testing.T) {
	inner := tarStreamFixture(t, "payload.txt", []byte("nested"))
	outer := zipFixture(t, []zipEntry{{
		name: "inner.tar", body: inner, store: true,
	}})
	result := runExtract(t, outer, "zip", generousLimits())
	container := findNode(t, result.Nodes, "/inner.tar")
	payload := findNode(t, result.Nodes, "/inner.tar/payload.txt")
	if result.Partial ||
		container.Format != "tar" ||
		container.ExtractionStatus != StatusExtracted ||
		payload.ExtractionStatus != StatusExtracted ||
		payload.ParentLocalID != container.LocalID {
		t.Fatalf("result=%+v container=%+v payload=%+v", result, container, payload)
	}
	assertCleanWorkDirectory(t)
}

func TestTARTrailingDataIsRejectedAtRootAndNested(t *testing.T) {
	base := tarStreamFixture(t, "payload.txt", []byte("visible"))
	concatenated := tarStreamFixture(t, "hidden.txt", []byte("hidden"))
	elfTail := make([]byte, tarBlockBytes)
	copy(elfTail, []byte{0x7f, 'E', 'L', 'F'})

	for _, test := range []struct {
		name string
		tail []byte
	}{
		{name: "concatenated-tar", tail: concatenated},
		{name: "elf", tail: elfTail},
	} {
		t.Run(test.name+"/root", func(t *testing.T) {
			input := append(append([]byte(nil), base...), test.tail...)
			result := runExtract(t, input, "tar", generousLimits())
			payload := findNode(t, result.Nodes, "/payload.txt")
			if !result.Partial ||
				result.LimitCode != "" ||
				payload.ExtractionStatus != StatusExtracted ||
				countNodesWithCode(result.Nodes, "tar_trailing_data") != 1 {
				t.Fatalf("result=%+v payload=%+v", result, payload)
			}
			assertCleanWorkDirectory(t)
		})

		t.Run(test.name+"/nested", func(t *testing.T) {
			inner := append(append([]byte(nil), base...), test.tail...)
			outer := zipFixture(t, []zipEntry{{
				name:  "inner.tar",
				body:  inner,
				store: true,
			}})
			result := runExtract(t, outer, "zip", generousLimits())
			container := findNode(t, result.Nodes, "/inner.tar")
			payload := findNode(
				t,
				result.Nodes,
				"/inner.tar/payload.txt",
			)
			if !result.Partial ||
				container.Format != "tar" ||
				payload.ExtractionStatus != StatusExtracted ||
				countNodesWithCode(result.Nodes, "tar_trailing_data") != 1 {
				t.Fatalf(
					"result=%+v container=%+v payload=%+v",
					result,
					container,
					payload,
				)
			}
			assertCleanWorkDirectory(t)
		})
	}
}

func TestDEBTARTrailingDataIsNotHidden(t *testing.T) {
	data := tarStreamFixture(t, "payload.txt", []byte("visible"))
	tail := make([]byte, tarBlockBytes)
	copy(tail, []byte{0x7f, 'E', 'L', 'F'})
	data = append(data, tail...)
	deb := arArchiveFixture(t, []arFixtureEntry{
		{
			rawName: "debian-binary/",
			body:    []byte("2.0\n"),
		},
		{
			rawName: "control.tar/",
			body: arTARFixture(
				t,
				"control",
				[]byte("metadata"),
			),
		},
		{
			rawName: "data.tar/",
			body:    data,
		},
	})

	result := runExtract(t, deb, "deb", generousLimits())
	container := findNode(t, result.Nodes, "/data.tar")
	payload := findNode(t, result.Nodes, "/data.tar/payload.txt")
	trailingParent := 0
	for _, node := range result.Nodes {
		if node.ErrorCode == "tar_trailing_data" {
			trailingParent = node.ParentLocalID
		}
	}
	if !result.Partial ||
		container.Format != "tar" ||
		payload.ExtractionStatus != StatusExtracted ||
		countNodesWithCode(result.Nodes, "tar_trailing_data") != 1 ||
		trailingParent != container.LocalID {
		t.Fatalf(
			"result=%+v container=%+v payload=%+v trailing_parent=%d",
			result,
			container,
			payload,
			trailingParent,
		)
	}
	assertCleanWorkDirectory(t)
}

func TestTARTrailingZeroRecordPaddingIsBounded(t *testing.T) {
	base := tarStreamFixture(t, "payload.txt", []byte("visible"))

	for _, paddingBytes := range []int{
		4 * tarBlockBytes,
		int(maxTARTrailingPaddingBytes),
	} {
		t.Run(fmt.Sprintf("normal-%d", paddingBytes), func(t *testing.T) {
			input := append(
				append([]byte(nil), base...),
				make([]byte, paddingBytes)...,
			)
			result := runExtract(t, input, "tar", generousLimits())
			payload := findNode(t, result.Nodes, "/payload.txt")
			if result.Partial ||
				result.LimitCode != "" ||
				payload.ExtractionStatus != StatusExtracted {
				t.Fatalf("result=%+v payload=%+v", result, payload)
			}
			assertCleanWorkDirectory(t)
		})
	}

	t.Run("over-limit", func(t *testing.T) {
		input := append(
			append([]byte(nil), base...),
			make(
				[]byte,
				int(maxTARTrailingPaddingBytes)+tarBlockBytes,
			)...,
		)
		result := runExtract(t, input, "tar", generousLimits())
		payload := findNode(t, result.Nodes, "/payload.txt")
		if !result.Partial ||
			result.LimitCode != LimitMaxArchiveMetadata ||
			payload.ExtractionStatus != StatusExtracted ||
			countNodesWithCode(result.Nodes, "tar_trailing_data") != 0 {
			t.Fatalf("result=%+v payload=%+v", result, payload)
		}
		assertCleanWorkDirectory(t)
	})

	t.Run("unaligned", func(t *testing.T) {
		input := append(append([]byte(nil), base...), 0)
		result := runExtract(t, input, "tar", generousLimits())
		if !result.Partial ||
			result.LimitCode != "" ||
			countNodesWithCode(result.Nodes, "tar_trailing_data") != 1 {
			t.Fatalf("result=%+v", result)
		}
		assertCleanWorkDirectory(t)
	})
}

func TestTARTrailingPaddingValidationObservesCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	source := &cancelAfterReaderAt{
		reader:      bytes.NewReader(make([]byte, 64*tarBlockBytes)),
		cancel:      cancel,
		cancelAfter: 1,
	}
	err := validateTARTrailingPadding(
		ctx,
		source,
		int64(64*tarBlockBytes),
		0,
	)
	if !errors.Is(err, context.Canceled) || source.reads != 1 {
		t.Fatalf("validation error=%v reads=%d", err, source.reads)
	}
}

type cancelingTARReader struct {
	input     io.Reader
	cancel    context.CancelFunc
	cancelAt  int64
	readBytes int64
}

type largePayloadTARDetector struct {
	minimum int64
}

func (detector largePayloadTARDetector) Detect(
	_ io.ReaderAt,
	size int64,
) (filetype.Result, error) {
	if size >= detector.minimum {
		return filetype.Result{
			Format:   "tar",
			MIMEType: "application/x-tar",
		}, nil
	}
	return filetype.Result{
		Format:   "unknown",
		MIMEType: "application/octet-stream",
	}, nil
}

func (reader *cancelingTARReader) Read(buffer []byte) (int, error) {
	count, err := reader.input.Read(buffer)
	reader.readBytes += int64(count)
	if reader.readBytes >= reader.cancelAt {
		reader.cancel()
	}
	return count, err
}

func runExtractWithDetector(
	t *testing.T,
	data []byte,
	format string,
	limits Limits,
	detector Detector,
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
	lastWorkDirectory = workDir
	result, err := NewEngine(detector, limits).Extract(
		context.Background(),
		source,
		format,
		workDir,
	)
	if err != nil {
		t.Fatalf("Extract() error = %v", err)
	}
	assertNodeGraph(t, result.Nodes)
	return result
}

func oldGNUSparseFixture(
	t *testing.T,
	extensionBlocks int,
	neverEnding bool,
) []byte {
	t.Helper()
	if extensionBlocks < 0 {
		t.Fatal("negative extension block count")
	}
	entryCount := int64(4 + extensionBlocks*21)
	output := make([]byte, (1+extensionBlocks)*tarBlockBytes)
	header := output[:tarBlockBytes]
	copy(header[0:100], "sparse.bin")
	putTAROctal(t, header[100:108], 0o600)
	putTAROctal(t, header[108:116], 0)
	putTAROctal(t, header[116:124], 0)
	putTAROctal(t, header[124:136], entryCount)
	putTAROctal(t, header[136:148], 0)
	header[156] = tar.TypeGNUSparse
	copy(header[257:263], "ustar ")
	copy(header[263:265], " \x00")
	for index := 0; index < 4; index++ {
		putGNUSparseEntry(t, header[386+index*24:], int64(index))
	}
	if extensionBlocks > 0 {
		header[482] = 1
	}
	putTAROctal(t, header[483:495], entryCount*2)
	setTARChecksum(header)

	entryIndex := int64(4)
	for blockIndex := 0; blockIndex < extensionBlocks; blockIndex++ {
		start := (blockIndex + 1) * tarBlockBytes
		block := output[start : start+tarBlockBytes]
		for index := 0; index < 21; index++ {
			putGNUSparseEntry(t, block[index*24:], entryIndex)
			entryIndex++
		}
		if neverEnding || blockIndex+1 < extensionBlocks {
			block[504] = 1
		}
	}
	return output
}

func paxSparseFixture(t *testing.T, entries int) []byte {
	t.Helper()
	if entries < 0 {
		t.Fatal("negative PAX sparse entry count")
	}
	var paxBody []byte
	for _, record := range [][2]string{
		{"GNU.sparse.major", "1"},
		{"GNU.sparse.minor", "0"},
		{"GNU.sparse.name", "sparse.bin"},
		{"GNU.sparse.realsize", "0"},
	} {
		paxBody = append(paxBody, makePAXRecord(record[0], record[1])...)
	}
	paxPadded := (len(paxBody) + tarBlockBytes - 1) &^ (tarBlockBytes - 1)

	sparseMap := append(
		[]byte(strconv.Itoa(entries)+"\n"),
		bytes.Repeat([]byte("0\n0\n"), entries)...,
	)
	mapPadded := (len(sparseMap) + tarBlockBytes - 1) &^ (tarBlockBytes - 1)
	mainOffset := tarBlockBytes + paxPadded
	output := make([]byte, mainOffset+tarBlockBytes+mapPadded)

	paxHeader := output[:tarBlockBytes]
	putUSTARTARHeader(t, paxHeader, "PaxHeaders/sparse", tar.TypeXHeader, int64(len(paxBody)))
	copy(output[tarBlockBytes:tarBlockBytes+len(paxBody)], paxBody)

	mainHeader := output[mainOffset : mainOffset+tarBlockBytes]
	putUSTARTARHeader(t, mainHeader, "placeholder", tar.TypeReg, int64(mapPadded))
	copy(output[mainOffset+tarBlockBytes:], sparseMap)
	return output
}

func makePAXRecord(key, value string) []byte {
	payload := " " + key + "=" + value + "\n"
	length := len(payload) + 1
	for {
		encodedLength := strconv.Itoa(length)
		nextLength := len(encodedLength) + len(payload)
		if nextLength == length {
			return []byte(encodedLength + payload)
		}
		length = nextLength
	}
}

func putUSTARTARHeader(
	t *testing.T,
	header []byte,
	name string,
	typeflag byte,
	size int64,
) {
	t.Helper()
	copy(header[0:100], name)
	putTAROctal(t, header[100:108], 0o600)
	putTAROctal(t, header[108:116], 0)
	putTAROctal(t, header[116:124], 0)
	putTAROctal(t, header[124:136], size)
	putTAROctal(t, header[136:148], 0)
	header[156] = typeflag
	copy(header[257:263], "ustar\x00")
	copy(header[263:265], "00")
	putTAROctal(t, header[329:337], 0)
	putTAROctal(t, header[337:345], 0)
	setTARChecksum(header)
}

func putGNUSparseEntry(t *testing.T, field []byte, index int64) {
	t.Helper()
	putTAROctal(t, field[:12], index*2)
	putTAROctal(t, field[12:24], 1)
}

func putTAROctal(t *testing.T, field []byte, value int64) {
	t.Helper()
	encoded := fmt.Sprintf("%0*o", len(field)-1, value)
	if len(encoded) >= len(field) {
		t.Fatalf("octal value %d does not fit in %d bytes", value, len(field))
	}
	copy(field, encoded)
	field[len(field)-1] = 0
}

func setTARChecksum(header []byte) {
	for index := 148; index < 156; index++ {
		header[index] = ' '
	}
	var sum int64
	for _, value := range header {
		sum += int64(value)
	}
	copy(header[148:156], fmt.Sprintf("%06o\x00 ", sum))
}

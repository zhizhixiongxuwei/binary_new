package extract

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf8"

	"binaryscan/internal/filetype"
)

func TestSupports(t *testing.T) {
	engine := NewEngine(filetype.Detector{}, Limits{})
	for _, format := range []string{
		"zip", "jar", "war", "ear", "apk",
		"tar", "docker-tar", "oci-tar", "gzip", "bzip2",
		"xz", "zstd", "lzma", "ar", "deb", "rpm", "cpio",
		"rar", "raw-img", "mbr-img", "gpt-img", "iso9660",
	} {
		if !engine.Supports(format) {
			t.Errorf("Supports(%q) = false", format)
		}
	}
	for _, format := range []string{"", "unknown", "7z", "cab"} {
		if engine.Supports(format) {
			t.Errorf("Supports(%q) = true", format)
		}
	}
}

func TestEngineDispatchesNewArchiveFormats(t *testing.T) {
	tarBody := arTARFixture(t, "payload.txt", []byte("deb"))
	tests := []struct {
		name        string
		format      string
		data        []byte
		logicalPath string
	}{
		{
			name:   "ar",
			format: "ar",
			data: arArchiveFixture(t, []arFixtureEntry{{
				rawName: "payload.bin/",
				body:    []byte("ar"),
			}}),
			logicalPath: "/payload.bin",
		},
		{
			name:   "deb",
			format: "deb",
			data: arArchiveFixture(t, []arFixtureEntry{
				{rawName: "debian-binary/", body: []byte("2.0\n")},
				{rawName: "control.tar/", body: tarBody},
				{rawName: "data.tar/", body: tarBody},
			}),
			logicalPath: "/data.tar/payload.txt",
		},
		{
			name:   "cpio",
			format: "cpio",
			data: cpioArchiveFixture(t, "newc", []cpioFixtureEntry{{
				name: "payload.bin",
				mode: cpioModeRegular | 0o600,
				body: []byte("cpio"),
			}}, true),
			logicalPath: "/payload.bin",
		},
		{
			name:        "lzma",
			format:      "lzma",
			data:        lzmaAloneFixture(t, []byte("lzma"), 1<<12),
			logicalPath: "/content",
		},
		{
			name:   "rar",
			format: "rar",
			data: rarArchiveFixture(t, 5, 0, 0, []rarFixtureEntry{{
				name:       "payload.bin",
				body:       []byte("rar"),
				attributes: 0100644,
			}}),
			logicalPath: "/payload.bin",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := runExtract(t, test.data, test.format, generousLimits())
			node := findNode(t, result.Nodes, test.logicalPath)
			if result.Partial || node.ExtractionStatus != StatusExtracted {
				t.Fatalf("result=%+v node=%+v", result, node)
			}
		})
	}
}

func TestExtractZIPRecursesWithoutUsingArchivePathsOnDisk(t *testing.T) {
	inner := zipFixture(t, []zipEntry{{name: "payload.txt", body: []byte("nested")}})
	outer := zipFixture(t, []zipEntry{
		{name: "docs/readme.txt", body: []byte("hello")},
		{name: "inner.zip", body: inner},
	})
	result := runExtract(t, outer, "zip", generousLimits())
	if result.Partial || len(result.Nodes) != 4 {
		t.Fatalf("result = %+v", result)
	}
	readme := findNode(t, result.Nodes, "/docs/readme.txt")
	innerNode := findNode(t, result.Nodes, "/inner.zip")
	payload := findNode(t, result.Nodes, "/inner.zip/payload.txt")
	docs := findNode(t, result.Nodes, "/docs")
	if docs.NodeType != NodeTypeDirectory || docs.ParentLocalID != 0 || docs.Depth != 1 {
		t.Fatalf("docs node = %+v", docs)
	}
	if readme.ParentLocalID != docs.LocalID || readme.Depth != 2 ||
		readme.ExtractionStatus != StatusExtracted ||
		readme.SHA256 != "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824" {
		t.Fatalf("readme node = %+v", readme)
	}
	if innerNode.Format != "zip" || innerNode.Depth != 1 ||
		payload.ParentLocalID != innerNode.LocalID || payload.Depth != 2 ||
		payload.ExtractionStatus != StatusExtracted {
		t.Fatalf("nested nodes = inner %+v payload %+v", innerNode, payload)
	}
	assertCleanWorkDirectory(t)
}

func TestExtractLogicalPackageRetainsMembersWithoutRecursing(t *testing.T) {
	classFile := make([]byte, 31)
	copy(classFile, []byte{0xca, 0xfe, 0xba, 0xbe})
	classFile[7] = 61
	classFile[9] = 3
	classFile[10] = 1
	classFile[12] = 1
	classFile[13] = 'A'
	classFile[14] = 7
	classFile[16] = 1
	classFile[18] = 0x21
	classFile[20] = 2
	inner := zipFixture(t, []zipEntry{{name: "deep.class", body: classFile}})
	outer := zipFixture(t, []zipEntry{
		{name: "bin/tool.class", body: classFile},
		{name: "nested.zip", body: inner},
	})
	sourcePath := filepath.Join(t.TempDir(), "outer.zip")
	if err := os.WriteFile(sourcePath, outer, 0o600); err != nil {
		t.Fatal(err)
	}
	source, err := os.Open(sourcePath)
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	workDir := t.TempDir()
	engine := NewEngine(filetype.Detector{}, generousLimits())
	result, err := engine.ExtractLogicalPackage(
		context.Background(), source, "zip", workDir,
	)
	if err != nil {
		t.Fatal(err)
	}
	assertNodeGraph(t, result.Nodes)
	tool := findNode(t, result.Nodes, "/bin/tool.class")
	if tool.Format != "java-class" {
		t.Fatalf("tool format = %q", tool.Format)
	}
	findNode(t, result.Nodes, "/nested.zip")
	for _, node := range result.Nodes {
		if node.LogicalPath == "/nested.zip/deep.class" {
			t.Fatal("logical-package mode recursively expanded a member archive")
		}
	}
	if len(result.MaterializedFiles) != 2 {
		t.Fatalf("materialized files = %+v", result.MaterializedFiles)
	}
	for _, retained := range result.MaterializedFiles {
		info, err := os.Lstat(retained.WorkPath)
		if err != nil || !info.Mode().IsRegular() {
			t.Fatalf("retained member %d is unavailable: %v", retained.LocalID, err)
		}
	}
}

func TestExtractRejectsZipSlipAndUnsafeNames(t *testing.T) {
	data := zipFixture(t, []zipEntry{
		{name: "../escape", body: []byte("x")},
		{name: "/absolute", body: []byte("x")},
		{name: `C:drive`, body: []byte("x")},
		{name: `back\\slash`, body: []byte("x")},
		{name: "control\x01name", body: []byte("x")},
		{name: strings.Repeat("x", 3000), body: []byte("x")},
		{name: "safe.txt", body: []byte("safe")},
	})
	result := runExtract(t, data, "zip", generousLimits())
	if !result.Partial || len(result.Nodes) != 7 {
		t.Fatalf("result = %+v", result)
	}
	invalid := 0
	for _, node := range result.Nodes {
		if node.ExtractionStatus == StatusInvalidPath {
			invalid++
			if !strings.HasPrefix(node.LogicalPath, "/__rejected_entry_") ||
				path.Clean(node.LogicalPath) != node.LogicalPath {
				t.Fatalf("unsafe rejected logical path: %+v", node)
			}
			var metadata map[string]any
			if err := json.Unmarshal(node.MetadataJSON, &metadata); err != nil {
				t.Fatal(err)
			}
			archivePath, _ := metadata["archive_path"].(string)
			if len(archivePath) > maxLogicalPathBytes {
				t.Fatalf(
					"rejected archive path was not bounded: %d",
					len(archivePath),
				)
			}
		}
	}
	if invalid != 6 {
		t.Fatalf("invalid path nodes = %d, want 6", invalid)
	}
	if findNode(t, result.Nodes, "/safe.txt").ExtractionStatus != StatusExtracted {
		t.Fatal("safe entry was not extracted")
	}
	assertCleanWorkDirectory(t)
}

func TestDuplicateArchivePathsReceiveSafeUniqueLogicalPaths(t *testing.T) {
	nested := zipFixture(t, []zipEntry{{
		name: "payload.txt",
		body: []byte("visible"),
	}})
	data := zipFixture(t, []zipEntry{
		{name: "same.txt", body: []byte("first")},
		{name: "same.txt", body: nested},
	})
	result := runExtract(t, data, "zip", generousLimits())
	if !result.Partial || len(result.Nodes) != 3 {
		t.Fatalf("result = %+v", result)
	}
	duplicate := result.Nodes[1]
	if result.Nodes[0].LogicalPath != "/same.txt" ||
		duplicate.ExtractionStatus != StatusInvalidPath ||
		duplicate.Format != "zip" ||
		duplicate.ErrorCode != "duplicate_archive_name" ||
		!strings.HasPrefix(duplicate.LogicalPath, "/same.txt~") ||
		result.Nodes[0].LogicalPath == duplicate.LogicalPath {
		t.Fatalf("duplicate nodes = %+v", result.Nodes)
	}
	child := findNode(t, result.Nodes, duplicate.LogicalPath+"/payload.txt")
	if child.ParentLocalID != duplicate.LocalID ||
		child.ExtractionStatus != StatusExtracted {
		t.Fatalf("duplicate child = %+v", child)
	}
	var metadata map[string]any
	if err := json.Unmarshal(duplicate.MetadataJSON, &metadata); err != nil {
		t.Fatal(err)
	}
	if metadata["duplicate_logical_path"] != "/same.txt" {
		t.Fatalf("duplicate metadata = %+v", metadata)
	}
}

func TestNearMaxDuplicatePathMovesToSafeAncestorAndRecurses(t *testing.T) {
	nested := zipFixture(t, []zipEntry{{
		name: "payload.txt",
		body: []byte("visible"),
	}})
	archivePath := nearMaxArchivePath("x")
	originalLogical := "/" + archivePath
	data := zipFixture(t, []zipEntry{
		{name: archivePath, body: []byte("first")},
		{name: archivePath, body: nested},
	})

	result := runExtract(t, data, "zip", generousLimits())
	duplicate := findNodeWithCode(
		t,
		result.Nodes,
		"duplicate_logical_path",
	)
	payload := findNode(
		t,
		result.Nodes,
		duplicate.LogicalPath+"/payload.txt",
	)
	parent := nodeWithLocalID(t, result.Nodes, duplicate.ParentLocalID)
	if !result.Partial ||
		result.LimitCode != "" ||
		duplicate.ExtractionStatus != StatusInvalidPath ||
		duplicate.Format != "zip" ||
		len(duplicate.LogicalPath) > maxLogicalPathBytes ||
		path.Dir(duplicate.LogicalPath) == path.Dir(originalLogical) ||
		duplicate.Depth != parent.Depth+1 ||
		!strings.HasPrefix(duplicate.LogicalPath, parent.LogicalPath+"/") ||
		payload.ParentLocalID != duplicate.LocalID ||
		payload.Depth != duplicate.Depth+1 ||
		payload.ExtractionStatus != StatusExtracted {
		t.Fatalf(
			"result=%+v duplicate=%+v parent=%+v payload=%+v",
			result,
			duplicate,
			parent,
			payload,
		)
	}
	var metadata map[string]any
	if err := json.Unmarshal(duplicate.MetadataJSON, &metadata); err != nil {
		t.Fatal(err)
	}
	if metadata["duplicate_logical_path"] != originalLogical {
		t.Fatalf("duplicate metadata = %+v", metadata)
	}
}

func TestEncryptedDuplicatePreservesPasswordStatusAndMetadata(t *testing.T) {
	data := zipFixture(t, []zipEntry{
		{name: "same.bin", body: []byte("plain")},
		{name: "same.bin", body: []byte("encrypted")},
	})
	setNthZIPEncryptionFlag(t, data, 1)

	result := runExtract(t, data, "zip", generousLimits())
	if !result.Partial || len(result.Nodes) != 2 {
		t.Fatalf("result = %+v", result)
	}
	encrypted := result.Nodes[1]
	if encrypted.ExtractionStatus != StatusPasswordRequired ||
		encrypted.ErrorCode != "password_required" ||
		!strings.HasPrefix(encrypted.LogicalPath, "/same.bin~") {
		t.Fatalf("encrypted duplicate = %+v", encrypted)
	}
	var metadata map[string]any
	if err := json.Unmarshal(encrypted.MetadataJSON, &metadata); err != nil {
		t.Fatal(err)
	}
	if metadata["archive"] != "zip" ||
		metadata["duplicate_logical_path"] != "/same.bin" ||
		metadata["compression_method"] == nil ||
		metadata["crc32"] == nil {
		t.Fatalf("encrypted metadata = %+v", metadata)
	}
}

func TestExplicitDirectoryAfterChildMergesSyntheticDirectory(t *testing.T) {
	data := zipFixture(t, []zipEntry{
		{name: "folder/file.txt", body: []byte("content")},
		{name: "folder/", mode: os.ModeDir | 0o755},
	})
	result := runExtract(t, data, "zip", generousLimits())
	if result.Partial || len(result.Nodes) != 2 {
		t.Fatalf("result = %+v", result)
	}
	directory := findNode(t, result.Nodes, "/folder")
	child := findNode(t, result.Nodes, "/folder/file.txt")
	if directory.NodeType != NodeTypeDirectory ||
		child.ParentLocalID != directory.LocalID || child.Depth != directory.Depth+1 {
		t.Fatalf("directory=%+v child=%+v", directory, child)
	}
	var metadata map[string]any
	if err := json.Unmarshal(directory.MetadataJSON, &metadata); err != nil {
		t.Fatal(err)
	}
	if metadata["synthetic"] != false {
		t.Fatalf("directory metadata = %v", metadata)
	}
}

func TestExtractRecordsLinksAndSpecialFilesWithoutLanding(t *testing.T) {
	var buffer bytes.Buffer
	writer := tar.NewWriter(&buffer)
	if err := writer.WriteHeader(&tar.Header{
		Name: "target", Typeflag: tar.TypeReg, Mode: 0o600, Size: 6,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Write([]byte("target")); err != nil {
		t.Fatal(err)
	}
	headers := []*tar.Header{
		{Name: "directory/", Typeflag: tar.TypeDir, Mode: 0o755},
		{Name: "link", Typeflag: tar.TypeSymlink, Linkname: "../../outside"},
		{Name: "hard", Typeflag: tar.TypeLink, Linkname: "target"},
		{Name: "device", Typeflag: tar.TypeChar, Devmajor: 1, Devminor: 3},
	}
	for _, header := range headers {
		if err := writer.WriteHeader(header); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	result := runExtract(t, buffer.Bytes(), "tar", generousLimits())
	wantTypes := map[string]string{
		"/target":    NodeTypeFile,
		"/directory": NodeTypeDirectory,
		"/link":      NodeTypeSymlink,
		"/hard":      NodeTypeHardlink,
		"/device":    NodeTypeSpecial,
	}
	if len(result.Nodes) != len(wantTypes) {
		t.Fatalf("nodes = %+v", result.Nodes)
	}
	for logical, nodeType := range wantTypes {
		node := findNode(t, result.Nodes, logical)
		wantStatus := StatusRecorded
		if nodeType == NodeTypeFile {
			wantStatus = StatusExtracted
		}
		if node.NodeType != nodeType || node.ExtractionStatus != wantStatus ||
			(nodeType != NodeTypeFile && node.SHA256 != "") {
			t.Fatalf("%s node = %+v", logical, node)
		}
	}
	assertCleanWorkDirectory(t)
}

func TestContainerFormatAliasesUseUnderlyingExtractors(t *testing.T) {
	zipData := zipFixture(t, []zipEntry{{name: "file", body: []byte("x")}})
	for _, format := range []string{"jar", "war", "ear", "apk"} {
		result := runExtract(t, zipData, format, generousLimits())
		if findNode(t, result.Nodes, "/file").ExtractionStatus != StatusExtracted {
			t.Fatalf("%s result = %+v", format, result)
		}
	}
	var tarBuffer bytes.Buffer
	writer := tar.NewWriter(&tarBuffer)
	if err := writer.WriteHeader(&tar.Header{
		Name: "file", Mode: 0o600, Size: 1, Typeflag: tar.TypeReg,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	for _, format := range []string{"docker-tar", "oci-tar"} {
		result := runExtract(t, tarBuffer.Bytes(), format, generousLimits())
		if findNode(t, result.Nodes, "/file").ExtractionStatus != StatusExtracted {
			t.Fatalf("%s result = %+v", format, result)
		}
	}
}

func TestExtractGZIPAndBZIP2(t *testing.T) {
	var compressed bytes.Buffer
	gzipWriter := gzip.NewWriter(&compressed)
	gzipWriter.Name = "named.txt"
	if _, err := gzipWriter.Write([]byte("gzip content")); err != nil {
		t.Fatal(err)
	}
	if err := gzipWriter.Close(); err != nil {
		t.Fatal(err)
	}
	gzipResult := runExtract(t, compressed.Bytes(), "gzip", generousLimits())
	gzipNode := findNode(t, gzipResult.Nodes, "/named.txt")
	if gzipNode.SizeBytes != int64(len("gzip content")) ||
		gzipNode.ExtractionStatus != StatusExtracted {
		t.Fatalf("gzip node = %+v", gzipNode)
	}

	bzipData, err := hex.DecodeString(
		"425a6839314159265359555a44f70000021980400010001264c010200022" +
			"0069ea100305d3b62183c5dc914e14241556913dc0",
	)
	if err != nil {
		t.Fatal(err)
	}
	bzipResult := runExtract(t, bzipData, "bzip2", generousLimits())
	bzipNode := findNode(t, bzipResult.Nodes, "/content")
	if bzipNode.SizeBytes != int64(len("hello bzip2")) ||
		bzipNode.ExtractionStatus != StatusExtracted {
		t.Fatalf("bzip2 node = %+v", bzipNode)
	}
	assertCleanWorkDirectory(t)
}

func TestNestedGZIPReadsTemporaryFileFromOffsetZero(t *testing.T) {
	var compressed bytes.Buffer
	writer := gzip.NewWriter(&compressed)
	writer.Name = "nested.txt"
	if _, err := writer.Write([]byte("nested gzip")); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	outer := zipFixture(t, []zipEntry{{name: "data.gz", body: compressed.Bytes()}})
	result := runExtract(t, outer, "zip", generousLimits())
	container := findNode(t, result.Nodes, "/data.gz")
	child := findNode(t, result.Nodes, "/data.gz/nested.txt")
	if container.Format != "gzip" || child.ParentLocalID != container.LocalID ||
		child.Depth != 2 || child.ExtractionStatus != StatusExtracted {
		t.Fatalf("container=%+v child=%+v", container, child)
	}
	assertCleanWorkDirectory(t)
}

func TestEncryptedZIPIsPasswordRequired(t *testing.T) {
	data := zipFixture(t, []zipEntry{{name: "secret.txt", body: []byte("secret")}})
	setZIPEncryptionFlag(t, data)
	result := runExtract(t, data, "zip", generousLimits())
	node := findNode(t, result.Nodes, "/secret.txt")
	if !result.Partial || node.ExtractionStatus != StatusPasswordRequired ||
		node.ErrorCode != "password_required" || node.SHA256 != "" {
		t.Fatalf("result=%+v node=%+v", result, node)
	}
	assertCleanWorkDirectory(t)
}

func TestCorruptZIPEntryIsRecordedAndDoesNotFailOperation(t *testing.T) {
	payload := []byte("unique-corrupt-payload")
	data := zipFixture(t, []zipEntry{
		{name: "broken.bin", body: payload, store: true},
		{name: "safe.txt", body: []byte("safe"), store: true},
	})
	offset := bytes.Index(data, payload)
	if offset < 0 {
		t.Fatal("payload not found in ZIP fixture")
	}
	data[offset] ^= 0xff
	result := runExtract(t, data, "zip", generousLimits())
	broken := findNode(t, result.Nodes, "/broken.bin")
	safe := findNode(t, result.Nodes, "/safe.txt")
	if !result.Partial || broken.ExtractionStatus != StatusCorrupt ||
		broken.ErrorCode != "archive_entry_corrupt" ||
		safe.ExtractionStatus != StatusExtracted {
		t.Fatalf("result=%+v broken=%+v safe=%+v", result, broken, safe)
	}
	assertCleanWorkDirectory(t)
}

func TestExpandedByteLimitRetainsPartialResultAndCleansWorkFile(t *testing.T) {
	data := zipFixture(t, []zipEntry{{
		name: "large.bin", body: bytes.Repeat([]byte("a"), 100), store: true,
	}})
	limits := generousLimits()
	limits.MaxExpandedBytes = 10
	result := runExtract(t, data, "zip", limits)
	node := findNode(t, result.Nodes, "/large.bin")
	if !result.Partial || result.LimitCode != LimitMaxExpandedBytes ||
		result.ExpandedBytes != 10 || node.SizeBytes != 10 ||
		node.ExtractionStatus != StatusLimitExceeded {
		t.Fatalf("result=%+v node=%+v", result, node)
	}
	assertCleanWorkDirectory(t)
}

func TestRatioLimitStopsHighlyCompressedStream(t *testing.T) {
	var compressed bytes.Buffer
	writer := gzip.NewWriter(&compressed)
	if _, err := writer.Write(bytes.Repeat([]byte{0}, 32<<10)); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	limits := generousLimits()
	limits.MaxRatio = 2
	result := runExtract(t, compressed.Bytes(), "gzip", limits)
	node := findNode(t, result.Nodes, "/content")
	if !result.Partial || result.LimitCode != LimitMaxRatio ||
		node.ExtractionStatus != StatusLimitExceeded ||
		result.ExpandedBytes > int64(len(compressed.Bytes()))*2 {
		t.Fatalf("result=%+v node=%+v", result, node)
	}
	assertCleanWorkDirectory(t)
}

func TestNestedContainerRatioLimitDoesNotStopSafeSiblings(t *testing.T) {
	var compressed bytes.Buffer
	writer := gzip.NewWriter(&compressed)
	if _, err := writer.Write(bytes.Repeat([]byte{0}, 32<<10)); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	padding := make([]byte, 40<<10)
	for index := range padding {
		padding[index] = byte(index*31 + 17)
	}
	outer := zipFixture(t, []zipEntry{
		{name: "bomb.gz", body: compressed.Bytes(), store: true},
		{name: "padding.bin", body: padding, store: true},
		{name: "safe.txt", body: []byte("safe"), store: true},
	})
	limits := generousLimits()
	limits.MaxRatio = 2
	result := runExtract(t, outer, "zip", limits)
	container := findNode(t, result.Nodes, "/bomb.gz")
	bomb := findNode(t, result.Nodes, "/bomb.gz/content")
	safe := findNode(t, result.Nodes, "/safe.txt")
	if !result.Partial || result.LimitCode != LimitMaxRatio ||
		container.ExtractionStatus != StatusLimitExceeded ||
		bomb.ExtractionStatus != StatusLimitExceeded ||
		safe.ExtractionStatus != StatusExtracted {
		t.Fatalf("result=%+v container=%+v bomb=%+v safe=%+v",
			result, container, bomb, safe)
	}
}

func TestNodeAndDepthLimits(t *testing.T) {
	many := zipFixture(t, []zipEntry{
		{name: "a", body: []byte("a")},
		{name: "b", body: []byte("b")},
		{name: "c", body: []byte("c")},
	})
	nodeLimits := generousLimits()
	nodeLimits.MaxNodes = 2
	nodeResult := runExtract(t, many, "zip", nodeLimits)
	if !nodeResult.Partial || nodeResult.LimitCode != LimitMaxNodes ||
		len(nodeResult.Nodes) != 0 {
		t.Fatalf("node limit result = %+v", nodeResult)
	}

	inner := zipFixture(t, []zipEntry{{name: "payload", body: []byte("x")}})
	outer := zipFixture(t, []zipEntry{{name: "inner.zip", body: inner}})
	depthLimits := generousLimits()
	depthLimits.MaxDepth = 1
	depthResult := runExtract(t, outer, "zip", depthLimits)
	innerNode := findNode(t, depthResult.Nodes, "/inner.zip")
	if !depthResult.Partial || depthResult.LimitCode != LimitMaxDepth ||
		len(depthResult.Nodes) != 1 ||
		innerNode.ExtractionStatus != StatusDepthLimited {
		t.Fatalf("depth limit result = %+v", depthResult)
	}

	pathLimits := generousLimits()
	pathLimits.MaxDepth = 2
	pathResult := runExtract(t, zipFixture(t, []zipEntry{{
		name: "a/b/c.txt", body: []byte("x"),
	}}), "zip", pathLimits)
	if !pathResult.Partial || pathResult.LimitCode != LimitMaxDepth ||
		len(pathResult.Nodes) != 2 ||
		findNode(t, pathResult.Nodes, "/a/b").ExtractionStatus != StatusDepthLimited {
		t.Fatalf("path depth result = %+v", pathResult)
	}
	assertCleanWorkDirectory(t)
}

func TestContextCancellationReturnsRetainedPartialResult(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	data := zipFixture(t, []zipEntry{{name: "file", body: []byte("x")}})
	result, err := runExtractWithContext(t, ctx, data, "zip", generousLimits())
	if !errors.Is(err, context.Canceled) || !result.Partial ||
		result.LimitCode != LimitContextCancelled || len(result.Nodes) != 0 {
		t.Fatalf("result=%+v err=%v", result, err)
	}
	assertCleanWorkDirectory(t)
}

func TestMalformedRootArchivesBecomePartialSyntheticNodes(t *testing.T) {
	for _, test := range []struct {
		format string
		data   []byte
		code   string
	}{
		{"zip", []byte("not a zip"), "zip_archive_corrupt"},
		{"gzip", []byte{0x1f, 0x8b, 8}, "gzip_archive_corrupt"},
		{"tar", bytes.Repeat([]byte{0xff}, 512), "tar_header_corrupt"},
	} {
		t.Run(test.format, func(t *testing.T) {
			result := runExtract(t, test.data, test.format, generousLimits())
			if !result.Partial || len(result.Nodes) != 1 ||
				result.Nodes[0].ExtractionStatus != StatusCorrupt ||
				result.Nodes[0].ErrorCode != test.code ||
				result.Nodes[0].ParentLocalID != 0 ||
				result.Nodes[0].Depth != 1 {
				t.Fatalf("result = %+v", result)
			}
			assertCleanWorkDirectory(t)
		})
	}
}

func TestDetectorFailureIsOperationalError(t *testing.T) {
	var compressed bytes.Buffer
	writer := gzip.NewWriter(&compressed)
	if _, err := writer.Write([]byte("content")); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	sourceDir := t.TempDir()
	sourcePath := filepath.Join(sourceDir, "input.gz")
	if err := os.WriteFile(sourcePath, compressed.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	source, err := os.Open(sourcePath)
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	workDir := t.TempDir()
	engine := NewEngine(errorDetector{}, generousLimits())
	result, err := engine.Extract(context.Background(), source, "gzip", workDir)
	if err == nil || !strings.Contains(err.Error(), "detect entry") ||
		len(result.Nodes) != 1 {
		t.Fatalf("result=%+v err=%v", result, err)
	}
	entries, readErr := os.ReadDir(workDir)
	if readErr != nil || len(entries) != 0 {
		t.Fatalf("work cleanup entries=%v err=%v", entries, readErr)
	}
}

func TestLogicalPathLengthBoundary(t *testing.T) {
	valid := strings.Repeat("a/", 1023) + "a"
	logical, _, err := logicalPath("", valid, false)
	if err != nil || len(logical) != maxLogicalPathBytes {
		t.Fatalf("boundary path len=%d err=%v", len(logical), err)
	}
	if _, _, err := logicalPath("", valid+"/a", false); !errors.Is(err, errInvalidArchivePath) {
		t.Fatalf("oversized path error = %v", err)
	}
}

func TestArchivePathNormalizesOnlySafeDotPrefix(t *testing.T) {
	location, prepared, err := (&operationState{
		engine:      NewEngine(filetype.Detector{}, generousLimits()),
		nextID:      1,
		paths:       make(map[string]struct{}),
		nodeIndex:   make(map[int]int),
		directories: make(map[string]int),
	}).prepareEntry("", "././usr/bin/tool", false, 0, 0)
	if err != nil || !prepared || location.logical != "/usr/bin/tool" {
		t.Fatalf("prepareEntry() = %+v, %v, %v", location, prepared, err)
	}

	for _, root := range []string{".", "./", "././"} {
		_, prepared, err := (&operationState{
			engine:      NewEngine(filetype.Detector{}, generousLimits()),
			nextID:      1,
			paths:       make(map[string]struct{}),
			nodeIndex:   make(map[int]int),
			directories: make(map[string]int),
		}).prepareEntry("", root, true, 0, 0)
		if err != nil || prepared {
			t.Fatalf("root %q = prepared %v, error %v", root, prepared, err)
		}
	}

	for _, unsafe := range []string{"./../escape", "./C:/escape", "././../escape"} {
		if _, err := validateArchivePath(unsafe, false); !errors.Is(
			err,
			errInvalidArchivePath,
		) {
			t.Fatalf("validateArchivePath(%q) error = %v", unsafe, err)
		}
	}
}

func TestSafeSizeSaturatesUint64(t *testing.T) {
	if got := safeSize(^uint64(0)); got != defaultMaxExpandedBytes {
		t.Fatalf("safeSize(max uint64) = %d", got)
	}
	if got := safeSize(123); got != 123 {
		t.Fatalf("safeSize(123) = %d", got)
	}
}

func TestWorkDirectoryMustBeAbsoluteRealDirectory(t *testing.T) {
	engine := NewEngine(filetype.Detector{}, generousLimits())
	sourceDir := t.TempDir()
	sourcePath := filepath.Join(sourceDir, "input.zip")
	if err := os.WriteFile(sourcePath, zipFixture(t, nil), 0o600); err != nil {
		t.Fatal(err)
	}
	source, err := os.Open(sourcePath)
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	if _, err := engine.Extract(context.Background(), source, "zip", "."); err == nil {
		t.Fatal("relative work directory was accepted")
	}
	link := filepath.Join(sourceDir, "work-link")
	if err := os.Symlink(t.TempDir(), link); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if _, err := engine.Extract(context.Background(), source, "zip", link); err == nil {
		t.Fatal("symlink work directory was accepted")
	}
}

type zipEntry struct {
	name   string
	body   []byte
	mode   os.FileMode
	method uint16
	store  bool
}

type errorDetector struct{}

func (errorDetector) Detect(io.ReaderAt, int64) (filetype.Result, error) {
	return filetype.Result{}, errors.New("detector unavailable")
}

func zipFixture(t *testing.T, entries []zipEntry) []byte {
	t.Helper()
	var buffer bytes.Buffer
	writer := zip.NewWriter(&buffer)
	for _, entry := range entries {
		header := &zip.FileHeader{Name: entry.name, Method: entry.method}
		if entry.store {
			header.Method = zip.Store
		} else if entry.method == 0 {
			header.Method = zip.Deflate
		}
		if entry.mode != 0 {
			header.SetMode(entry.mode)
		}
		output, err := writer.CreateHeader(header)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := output.Write(entry.body); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return append([]byte(nil), buffer.Bytes()...)
}

func setZIPEncryptionFlag(t *testing.T, data []byte) {
	t.Helper()
	setNthZIPEncryptionFlag(t, data, 0)
}

func setNthZIPEncryptionFlag(t *testing.T, data []byte, entry int) {
	t.Helper()
	local := nthSignature(data, []byte{'P', 'K', 3, 4}, entry)
	central := nthSignature(data, []byte{'P', 'K', 1, 2}, entry)
	if local < 0 || central < 0 {
		t.Fatal("ZIP headers not found")
	}
	data[local+6] |= 1
	data[central+8] |= 1
}

func nthSignature(data []byte, signature []byte, target int) int {
	offset := 0
	for index := 0; index <= target; index++ {
		found := bytes.Index(data[offset:], signature)
		if found < 0 {
			return -1
		}
		offset += found
		if index == target {
			return offset
		}
		offset += len(signature)
	}
	return -1
}

func generousLimits() Limits {
	return Limits{
		MaxExpandedBytes: 32 << 20,
		MaxNodes:         1000,
		MaxDepth:         10,
		MaxRatio:         100,
	}
}

var lastWorkDirectory string

func runExtract(t *testing.T, data []byte, format string, limits Limits) Result {
	t.Helper()
	result, err := runExtractWithContext(t, context.Background(), data, format, limits)
	if err != nil {
		t.Fatalf("Extract() error = %v", err)
	}
	return result
}

func runExtractWithContext(
	t *testing.T,
	ctx context.Context,
	data []byte,
	format string,
	limits Limits,
) (Result, error) {
	t.Helper()
	sourceDir := t.TempDir()
	sourcePath := filepath.Join(sourceDir, "input")
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
	engine := NewEngine(filetype.Detector{}, limits)
	result, extractErr := engine.Extract(ctx, source, format, workDir)
	assertNodeGraph(t, result.Nodes)
	return result, extractErr
}

func assertNodeGraph(t *testing.T, nodes []Node) {
	t.Helper()
	byID := make(map[int]Node, len(nodes))
	paths := make(map[string]bool, len(nodes))
	for index, node := range nodes {
		if node.LocalID != index+1 {
			t.Fatalf("non-contiguous LocalID at index %d: %+v", index, node)
		}
		if node.LogicalPath == "/" || !strings.HasPrefix(node.LogicalPath, "/") ||
			path.Clean(node.LogicalPath) != node.LogicalPath ||
			len(node.LogicalPath) > maxLogicalPathBytes ||
			!utf8.ValidString(node.LogicalPath) || strings.Contains(node.LogicalPath, "\\") {
			t.Fatalf("invalid logical path: %+v", node)
		}
		if paths[node.LogicalPath] {
			t.Fatalf("duplicate logical path: %s", node.LogicalPath)
		}
		if node.DisplayName != path.Base(node.LogicalPath) {
			t.Fatalf("display name does not match logical path: %+v", node)
		}
		paths[node.LogicalPath] = true
		if node.ParentLocalID == 0 {
			if node.Depth != 1 {
				t.Fatalf("root child depth = %d: %+v", node.Depth, node)
			}
		} else {
			parent, found := byID[node.ParentLocalID]
			if !found || node.Depth != parent.Depth+1 ||
				!strings.HasPrefix(node.LogicalPath, parent.LogicalPath+"/") {
				t.Fatalf("invalid parent relation: parent=%+v child=%+v", parent, node)
			}
		}
		if node.Depth > defaultMaxDepth {
			t.Fatalf("node depth exceeds project maximum: %+v", node)
		}
		byID[node.LocalID] = node
	}
}

func assertCleanWorkDirectory(t *testing.T) {
	t.Helper()
	entries, err := os.ReadDir(lastWorkDirectory)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("work directory retained files: %+v", entries)
	}
}

func findNode(t *testing.T, nodes []Node, logical string) Node {
	t.Helper()
	for _, node := range nodes {
		if node.LogicalPath == logical {
			if !json.Valid(node.MetadataJSON) {
				t.Fatalf("node metadata is invalid JSON: %+v", node)
			}
			return node
		}
	}
	t.Fatalf("node %q not found in %+v", logical, nodes)
	return Node{}
}

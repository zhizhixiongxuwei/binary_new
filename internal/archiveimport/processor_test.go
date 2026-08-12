package archiveimport

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf8"

	"binaryscan/internal/extract"
	"binaryscan/internal/filetype"
)

func TestClassifyNodeConvertsCanonicalLogicalPathToRelativeCandidate(t *testing.T) {
	workPath := "/private/work/member"
	entry, candidate := classifyNode(
		extract.Node{
			LocalID: 7, LogicalPath: "/bin/tool.class",
			NodeType: extract.NodeTypeFile, ExtractionStatus: extract.StatusExtracted,
			Format: "java-class", SizeBytes: 31,
			SHA256: strings.Repeat("a", 64),
		},
		false,
		map[int]string{7: workPath},
	)
	if entry.Status != EntryEligible || entry.LogicalPath != "bin/tool.class" ||
		entry.Category != CategoryBinary || candidate != workPath {
		t.Fatalf("entry=%+v candidate=%q", entry, candidate)
	}
	if entry.LogicalPathHash != logicalPathDigest("bin/tool.class") {
		t.Fatal("relative logical path hash was not used")
	}
}

func TestArchiveStoragePlanReservesAllCopyPeaks(t *testing.T) {
	plan, err := archiveStoragePlan(Lease{
		SourceSize: 2 << 30,
		Limits: Limits{
			MaxExpandedBytes: 10 << 30, MaxArchiveRatio: 50,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if plan.SourceBytes != 2<<30 || plan.ExpandedBytes != 10<<30 {
		t.Fatalf("archiveStoragePlan() = %+v", plan)
	}
	plan, err = archiveStoragePlan(Lease{
		SourceSize: 4 << 10,
		Limits: Limits{
			MaxExpandedBytes: 10 << 30, MaxArchiveRatio: 50,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if plan.SourceBytes != 4<<10 || plan.ExpandedBytes != 200<<10 {
		t.Fatalf("small archiveStoragePlan() = %+v", plan)
	}
	if _, err := archiveStoragePlan(Lease{
		SourceSize: math.MaxInt64,
		Limits: Limits{
			MaxExpandedBytes: 1, MaxArchiveRatio: 50,
		},
	}); err == nil {
		t.Fatal("archiveStoragePlan() accepted an overflowing plan")
	}
}

func TestClassifyNodeNeverRecursesOrSelectsMemberArchive(t *testing.T) {
	entry, candidate := classifyNode(
		extract.Node{
			LocalID: 3, LogicalPath: "/nested.zip", NodeType: extract.NodeTypeFile,
			ExtractionStatus: extract.StatusExtracted, Format: "zip", SizeBytes: 100,
			SHA256: strings.Repeat("b", 64),
		},
		false,
		map[int]string{3: "/work/nested"},
	)
	if entry.Status != EntrySkipped || entry.SkipReason != "nested_archive" || candidate != "" {
		t.Fatalf("entry=%+v candidate=%q", entry, candidate)
	}
}

func TestMixedZIPPreviewContainsLeafFilesButNotStructuralNodes(t *testing.T) {
	classFile := minimalClassFixture()
	nested := zipArchiveFixture(t, map[string][]byte{
		"deep.class": classFile,
	})
	outer := zipArchiveFixture(t, map[string][]byte{
		"bin/tool.class":  classFile,
		"docs/readme.txt": []byte("not a task input"),
		"nested.zip":      nested,
	})
	sourcePath := filepath.Join(t.TempDir(), "mixed.zip")
	if err := os.WriteFile(sourcePath, outer, 0o600); err != nil {
		t.Fatal(err)
	}
	source, err := os.Open(sourcePath)
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	engine := extract.NewEngine(filetype.Detector{}, extract.Limits{
		MaxExpandedBytes: 1 << 20, MaxEntryBytes: 1 << 20,
		MaxNodes: 100, MaxDepth: 8, MaxRatio: 50,
	})
	result, err := engine.ExtractLogicalPackage(
		context.Background(), source, "zip", t.TempDir(),
	)
	if err != nil {
		t.Fatal(err)
	}
	materialized := make(map[int]string, len(result.MaterializedFiles))
	for _, file := range result.MaterializedFiles {
		materialized[file.LocalID] = file.WorkPath
	}
	hasChildren := make(map[int]bool)
	for _, node := range result.Nodes {
		if node.ParentLocalID > 0 {
			hasChildren[node.ParentLocalID] = true
		}
	}
	entries := make(map[string]PersistEntry)
	for _, node := range result.Nodes {
		wrapper := hasChildren[node.LocalID]
		if !persistablePreviewNode(node, wrapper) {
			continue
		}
		entry, _ := classifyNode(node, wrapper, materialized)
		entries[entry.LogicalPath] = entry
	}
	if len(entries) != 3 {
		t.Fatalf("preview entries = %+v", entries)
	}
	tool := entries["bin/tool.class"]
	if tool.Status != EntryEligible || tool.Category != CategoryBinary {
		t.Fatalf("tool entry = %+v", tool)
	}
	if entries["docs/readme.txt"].SkipReason != "unsupported_format" ||
		entries["nested.zip"].SkipReason != "nested_archive" {
		t.Fatalf("skipped leaf entries = %+v", entries)
	}
	if _, found := entries["bin"]; found {
		t.Fatal("structural directory bin was exposed as a preview entry")
	}
	for _, node := range result.Nodes {
		if node.LogicalPath == "/nested.zip/deep.class" {
			t.Fatal("member archive was recursively expanded")
		}
	}
}

func TestPersistablePreviewNodeKeepsDangerousSpecialMembers(t *testing.T) {
	if persistablePreviewNode(extract.Node{
		NodeType: extract.NodeTypeDirectory, ExtractionStatus: extract.StatusRecorded,
	}, false) {
		t.Fatal("ordinary directory should not be persisted")
	}
	if !persistablePreviewNode(extract.Node{
		NodeType: extract.NodeTypeSymlink, ExtractionStatus: extract.StatusRecorded,
	}, false) {
		t.Fatal("symlink safety finding should be persisted")
	}
	if persistablePreviewNode(extract.Node{
		NodeType: extract.NodeTypeFile, ExtractionStatus: extract.StatusExtracted,
	}, true) {
		t.Fatal("successfully traversed logical wrapper should not be persisted")
	}
}

func TestRelativeLogicalPathRejectsNonCanonicalValues(t *testing.T) {
	for _, value := range []string{"bin/tool", "//bin/tool", "/../tool", "/", "/a\x00b"} {
		if relative, reason := relativeLogicalPath(value); relative != "" || reason != "invalid_path" {
			t.Errorf("relativeLogicalPath(%q) = %q/%q", value, relative, reason)
		}
	}
}

func TestArchiveTaskNameIsDeterministicRuneSafeAndKeepsPathSuffix(t *testing.T) {
	archive := strings.Repeat("归档", 80) + ".zip"
	entry := "prefix/" + strings.Repeat("目录/", 100) + "末尾.class"
	first := ArchiveTaskName(archive, entry)
	second := ArchiveTaskName(archive, entry)
	if first != second || !utf8.ValidString(first) || utf8.RuneCountInString(first) > 255 {
		t.Fatalf("task name is not deterministic and bounded: %q", first)
	}
	if !strings.HasSuffix(first, "末尾.class") || !strings.Contains(first, " :: ...") {
		t.Fatalf("task name did not retain entry suffix: %q", first)
	}
}

func TestSkippedEntryJSONUsesNullDetectionFields(t *testing.T) {
	raw, err := json.Marshal(Entry{ID: "entry", Path: "link", Status: EntrySkipped})
	if err != nil {
		t.Fatal(err)
	}
	encoded := string(raw)
	for _, field := range []string{
		`"sha256":null`, `"detected_format":null`, `"detected_category":null`,
	} {
		if !strings.Contains(encoded, field) {
			t.Fatalf("entry JSON %s does not contain %s", encoded, field)
		}
	}
}

func zipArchiveFixture(t *testing.T, entries map[string][]byte) []byte {
	t.Helper()
	var buffer bytes.Buffer
	writer := zip.NewWriter(&buffer)
	for name, body := range entries {
		file, err := writer.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := file.Write(body); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return buffer.Bytes()
}

func minimalClassFixture() []byte {
	value := make([]byte, 31)
	copy(value, []byte{0xca, 0xfe, 0xba, 0xbe})
	value[7] = 61
	value[9] = 3
	value[10] = 1
	value[12] = 1
	value[13] = 'A'
	value[14] = 7
	value[16] = 1
	value[18] = 0x21
	value[20] = 2
	return value
}

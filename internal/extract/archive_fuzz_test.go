package extract

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"binaryscan/internal/filetype"
)

const (
	maxFuzzArchiveInputBytes = 128 << 10
	fuzzMaxExpandedBytes     = int64(256 << 10)
	fuzzMaxEntryBytes        = int64(64 << 10)
	fuzzMaxNodes             = 128
	fuzzMaxDepth             = 4
	fuzzMaxRatio             = int64(16)
	fuzzCaseTimeout          = 2 * time.Second
)

func FuzzExtractZIP(f *testing.F) {
	nestedGZIP := extractFuzzGZIP(
		"nested.tar",
		extractFuzzTAR("leaf.txt", []byte("leaf")),
	)
	valid := extractFuzzZIP(fuzzArchiveEntry{
		name: "payload.txt",
		body: []byte("payload"),
	})
	for _, seed := range [][]byte{
		valid,
		valid[:len(valid)/2],
		{'P', 'K', 0x03, 0x04},
		extractFuzzZIP(fuzzArchiveEntry{
			name: "../../outside.txt",
			body: []byte("must stay logical"),
		}),
		extractFuzzZIP(fuzzArchiveEntry{
			name: "nested.gz",
			body: nestedGZIP,
		}),
	} {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		fuzzExtractArchive(t, "zip", data)
	})
}

func FuzzExtractTAR(f *testing.F) {
	nestedZIP := extractFuzzZIP(fuzzArchiveEntry{
		name: "leaf.txt",
		body: []byte("leaf"),
	})
	valid := extractFuzzTAR("payload.txt", []byte("payload"))
	for _, seed := range [][]byte{
		valid,
		valid[:len(valid)/2],
		[]byte("not a tar"),
		extractFuzzTAR("../../outside.txt", []byte("must stay logical")),
		extractFuzzTAR("nested.zip", nestedZIP),
	} {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		fuzzExtractArchive(t, "tar", data)
	})
}

func FuzzExtractGZIP(f *testing.F) {
	nestedTAR := extractFuzzTAR("leaf.txt", []byte("leaf"))
	valid := extractFuzzGZIP("payload.txt", []byte("payload"))
	for _, seed := range [][]byte{
		valid,
		valid[:len(valid)/2],
		{0x1f, 0x8b, 0x08},
		extractFuzzGZIP("../../outside.txt", []byte("must stay logical")),
		extractFuzzGZIP("nested.tar", nestedTAR),
	} {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		fuzzExtractArchive(t, "gzip", data)
	})
}

func fuzzExtractArchive(t *testing.T, format string, data []byte) {
	t.Helper()
	if len(data) > maxFuzzArchiveInputBytes {
		return
	}

	workspace := newFuzzWorkspace(t)
	sourcePath := filepath.Join(workspace, "input")
	if err := os.WriteFile(sourcePath, data, 0o600); err != nil {
		t.Fatal(err)
	}
	source, err := os.Open(sourcePath)
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()

	workDir := filepath.Join(workspace, "work")
	if err := os.Mkdir(workDir, 0o700); err != nil {
		t.Fatal(err)
	}
	limits := Limits{
		MaxExpandedBytes: fuzzMaxExpandedBytes,
		MaxEntryBytes:    fuzzMaxEntryBytes,
		MaxNodes:         fuzzMaxNodes,
		MaxDepth:         fuzzMaxDepth,
		MaxRatio:         fuzzMaxRatio,
	}
	ctx, cancel := context.WithTimeout(context.Background(), fuzzCaseTimeout)
	defer cancel()
	result, extractErr := NewEngine(filetype.Detector{}, limits).Extract(
		ctx,
		source,
		format,
		workDir,
	)
	if extractErr != nil &&
		!errors.Is(extractErr, context.Canceled) &&
		!errors.Is(extractErr, context.DeadlineExceeded) {
		t.Fatalf("Extract(%q) returned an unexpected error: %v", format, extractErr)
	}
	assertFuzzResultBounds(t, result, workDir)
	assertFuzzWorkspaceBounds(t, workspace, len(data))
}

func assertFuzzResultBounds(t *testing.T, result Result, workDir string) {
	t.Helper()
	if len(result.Nodes) > fuzzMaxNodes {
		t.Fatalf("node limit bypassed: got %d, max %d", len(result.Nodes), fuzzMaxNodes)
	}
	if result.ExpandedBytes < 0 || result.ExpandedBytes > fuzzMaxExpandedBytes {
		t.Fatalf(
			"expanded-byte limit bypassed: got %d, max %d",
			result.ExpandedBytes,
			fuzzMaxExpandedBytes,
		)
	}
	if result.parserDecoderMemoryUsed != 0 {
		t.Fatalf(
			"parser/decoder memory reservation leaked: %d",
			result.parserDecoderMemoryUsed,
		)
	}
	assertNodeGraph(t, result.Nodes)
	for _, node := range result.Nodes {
		if !json.Valid(node.MetadataJSON) {
			t.Fatalf("node metadata is not JSON: %+v", node)
		}
		if len(node.MetadataJSON) > 64<<10 {
			t.Fatalf("node metadata is not bounded: %d bytes", len(node.MetadataJSON))
		}
	}
	for _, image := range result.ContainerImages {
		if !pathWithin(workDir, image.WorkPath) {
			t.Fatalf("retained image escaped work directory: %+v", image)
		}
		info, err := os.Lstat(image.WorkPath)
		if err != nil {
			t.Fatalf("retained image is unavailable: %v", err)
		}
		if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			t.Fatalf("retained image is not a regular file: %s", info.Mode())
		}
	}
}

func newFuzzWorkspace(t *testing.T) string {
	t.Helper()
	packageDir, err := filepath.Abs(".")
	if err != nil {
		t.Fatal(err)
	}
	repositoryRoot := filepath.Clean(filepath.Join(packageDir, "..", ".."))
	if info, statErr := os.Stat(filepath.Join(repositoryRoot, "go.mod")); statErr != nil || !info.Mode().IsRegular() {
		t.Fatalf("cannot locate repository root from %q", packageDir)
	}
	canonicalRepositoryRoot, err := filepath.EvalSymlinks(repositoryRoot)
	if err != nil {
		t.Fatal(err)
	}
	parent := filepath.Join(repositoryRoot, ".tools", "fuzz-work")
	if err := os.MkdirAll(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	canonicalParent, err := filepath.EvalSymlinks(parent)
	if err != nil {
		t.Fatal(err)
	}
	if !pathWithin(canonicalRepositoryRoot, canonicalParent) {
		t.Fatalf("fuzz workspace parent escaped repository: %q", canonicalParent)
	}
	workspace, err := os.MkdirTemp(parent, "case-")
	if err != nil {
		t.Fatal(err)
	}
	canonicalWorkspace, err := filepath.EvalSymlinks(workspace)
	if err != nil {
		t.Fatal(err)
	}
	if !pathWithin(canonicalRepositoryRoot, canonicalWorkspace) {
		t.Fatalf("fuzz workspace escaped repository: %q", workspace)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(canonicalWorkspace); err != nil {
			t.Errorf("remove fuzz workspace: %v", err)
		}
	})
	return canonicalWorkspace
}

func assertFuzzWorkspaceBounds(t *testing.T, workspace string, inputBytes int) {
	t.Helper()
	var files int
	var regularBytes int64
	err := filepath.WalkDir(workspace, func(current string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !pathWithin(workspace, current) {
			t.Fatalf("workspace walk escaped root: %q", current)
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			t.Fatalf("workspace contains a symlink: %q", current)
		}
		if !info.IsDir() && !info.Mode().IsRegular() {
			t.Fatalf("workspace contains a special file: %q (%s)", current, info.Mode())
		}
		if info.Mode().IsRegular() {
			files++
			regularBytes += info.Size()
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if files > fuzzMaxNodes+1 {
		t.Fatalf("workspace file count is not bounded: %d", files)
	}
	if regularBytes > int64(inputBytes)+fuzzMaxExpandedBytes {
		t.Fatalf(
			"workspace bytes are not bounded: %d > %d",
			regularBytes,
			int64(inputBytes)+fuzzMaxExpandedBytes,
		)
	}
}

func pathWithin(base string, target string) bool {
	base = filepath.Clean(base)
	target = filepath.Clean(target)
	relative, err := filepath.Rel(base, target)
	return err == nil &&
		relative != ".." &&
		!strings.HasPrefix(relative, ".."+string(filepath.Separator))
}

type fuzzArchiveEntry struct {
	name string
	body []byte
}

func extractFuzzZIP(entries ...fuzzArchiveEntry) []byte {
	var output bytes.Buffer
	writer := zip.NewWriter(&output)
	for _, entry := range entries {
		header := &zip.FileHeader{
			Name:   entry.name,
			Method: zip.Deflate,
		}
		part, err := writer.CreateHeader(header)
		if err != nil {
			panic(err)
		}
		if _, err := part.Write(entry.body); err != nil {
			panic(err)
		}
	}
	if err := writer.Close(); err != nil {
		panic(err)
	}
	return append([]byte(nil), output.Bytes()...)
}

func extractFuzzTAR(name string, body []byte) []byte {
	var output bytes.Buffer
	writer := tar.NewWriter(&output)
	if err := writer.WriteHeader(&tar.Header{
		Name: name,
		Mode: 0o600,
		Size: int64(len(body)),
	}); err != nil {
		panic(err)
	}
	if _, err := writer.Write(body); err != nil {
		panic(err)
	}
	if err := writer.Close(); err != nil {
		panic(err)
	}
	return append([]byte(nil), output.Bytes()...)
}

func extractFuzzGZIP(name string, body []byte) []byte {
	var output bytes.Buffer
	writer := gzip.NewWriter(&output)
	writer.Name = name
	if _, err := writer.Write(body); err != nil {
		panic(err)
	}
	if err := writer.Close(); err != nil {
		panic(err)
	}
	return append([]byte(nil), output.Bytes()...)
}

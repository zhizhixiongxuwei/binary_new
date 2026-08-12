package javaanalysis

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const (
	testProjectID = "123e4567-e89b-42d3-a456-426614174000"
	testRunID     = "223e4567-e89b-42d3-a456-426614174001"
	testResultA   = "323e4567-e89b-42d3-a456-426614174002"
	testResultB   = "423e4567-e89b-42d3-a456-426614174003"
	testResultC   = "523e4567-e89b-42d3-a456-426614174004"
)

func TestCanonicalInputSHA256UsesStableFramingAndPathOrder(t *testing.T) {
	files := []SourceFile{
		javaTestFile(testResultB, "src/main/java/z/Z.java", "z.Z", "b"),
		javaTestFile(testResultA, "src/main/java/a/A.java", "a.A", "alpha"),
	}
	got, err := canonicalInputSHA256(files)
	if err != nil {
		t.Fatal(err)
	}
	expectedRaw := RequestSchemaVersion + "\n" +
		testResultA + "\x00src/main/java/a/A.java\x00a.A\x005\x00" +
		javaDigest("alpha") + "\n" +
		testResultB + "\x00src/main/java/z/Z.java\x00z.Z\x001\x00" +
		javaDigest("b") + "\n"
	expected := sha256.Sum256([]byte(expectedRaw))
	if got != hex.EncodeToString(expected[:]) {
		t.Fatalf("input digest = %s, want %x", got, expected)
	}
}

func TestJavaLineCounterHandlesCRLFAndTerminalNewlines(t *testing.T) {
	tests := []struct {
		content string
		want    uint32
	}{
		{content: "", want: 0},
		{content: "class A {}", want: 1},
		{content: "class A {}\n", want: 1},
		{content: "a\r\nb", want: 2},
		{content: "a\rb\nc", want: 3},
		{content: "\r\n\r\n", want: 2},
	}
	for _, test := range tests {
		counter := javaLineCounter{}
		midpoint := len(test.content) / 2
		_, _ = counter.Write([]byte(test.content[:midpoint]))
		_, _ = counter.Write([]byte(test.content[midpoint:]))
		if got := counter.Count(); got != test.want {
			t.Errorf("line count for %q = %d, want %d", test.content, got, test.want)
		}
	}
}

func TestBuildVerifiedJavaBundleValidatesManifestAndConcatenatesSortedSources(
	t *testing.T,
) {
	repositoryRoot := t.TempDir()
	workRoot := t.TempDir()
	project, wantBundle := writeJavaProjectFixture(t, repositoryRoot)

	bundle, digest, files, err := buildVerifiedJavaBundle(
		t.Context(), repositoryRoot, workRoot, project,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer bundle.Close()
	gotBundle, err := io.ReadAll(bundle)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(gotBundle, wantBundle) {
		t.Fatalf("bundle = %q, want %q", gotBundle, wantBundle)
	}
	if digest != javaDigest(string(wantBundle)) {
		t.Fatalf("bundle digest = %s", digest)
	}
	if len(files) != 2 || files[0].LogicalPath != "src/main/java/a/A.java" ||
		files[0].OffsetBytes != 0 || files[0].LengthBytes != 10 ||
		files[0].LineCount != 1 ||
		files[1].LogicalPath != "src/main/java/z/Z.java" ||
		files[1].OffsetBytes != 10 || files[1].LengthBytes != 10 ||
		files[1].LineCount != 1 {
		t.Fatalf("bundle files = %#v", files)
	}
}

func TestBuildVerifiedJavaBundleKeepsFileAboveCheckerParseLimit(t *testing.T) {
	repositoryRoot := t.TempDir()
	workRoot := t.TempDir()
	rootKey := "source-projects/" + testProjectID
	logicalPath := "src/main/java/a/Oversized.java"
	content := bytes.Repeat([]byte{' '}, int(MaxFileBytes)+1)
	copy(content, []byte("class Oversized {}"))
	file := javaTestFile(testResultA, logicalPath, "a.Oversized", string(content))
	manifest := sourceProjectManifest{
		SchemaVersion: sourceProjectSchemaVersion,
		ProjectID:     testProjectID, LayoutVersion: "project-v1",
		SourceKind: "java", Language: "java", EngineName: "fixture",
		EngineVersion: "1", Status: "complete", SourceFileCount: 1,
		SymbolCount: 1,
		Files: []sourceProjectManifestFile{javaManifestFile(
			testResultA, logicalPath, "a.Oversized", "java", "complete",
			string(content),
		)},
	}
	rawManifest, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	rootPath := filepath.Join(repositoryRoot, filepath.FromSlash(rootKey))
	if err := os.MkdirAll(filepath.Dir(filepath.Join(rootPath, logicalPath)), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(rootPath, logicalPath), content, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(rootPath, "manifest.json"), rawManifest, 0o600); err != nil {
		t.Fatal(err)
	}
	project := ProjectSnapshot{
		ProjectID: testProjectID, Status: "complete", SourceKind: "java",
		Language: "java", EngineName: "fixture", EngineVersion: "1",
		RootStorageKey: rootKey, ManifestStorageKey: rootKey + "/manifest.json",
		ManifestSHA256:    javaDigest(string(rawManifest)),
		ManifestSizeBytes: uint64(len(rawManifest)), ProjectSourceFileCount: 1,
		ProjectSymbolCount: 1, ProjectSourceSizeBytes: uint64(len(content)),
		SourceSizeBytes: uint64(len(content)), Files: []SourceFile{file},
	}
	project.InputSHA256, err = canonicalInputSHA256(project.Files)
	if err != nil {
		t.Fatal(err)
	}
	bundle, _, files, err := buildVerifiedJavaBundle(
		t.Context(), repositoryRoot, workRoot, project,
	)
	if err != nil {
		t.Fatal(err)
	}
	bundle.Close()
	if len(files) != 1 || files[0].LengthBytes <= uint64(MaxFileBytes) ||
		files[0].LineCount != 1 {
		t.Fatalf("oversized checker input file = %#v", files)
	}
}

func TestBuildVerifiedJavaBundleRejectsSourceSymlink(t *testing.T) {
	repositoryRoot := t.TempDir()
	workRoot := t.TempDir()
	project, _ := writeJavaProjectFixture(t, repositoryRoot)
	key := filepath.Join(
		repositoryRoot, filepath.FromSlash(project.RootStorageKey),
		"src", "main", "java", "a", "A.java",
	)
	if err := os.Remove(key); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(t.TempDir(), "outside.java")
	if err := os.WriteFile(target, []byte("class A {}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, key); err != nil {
		t.Fatal(err)
	}
	_, _, _, err := buildVerifiedJavaBundle(
		t.Context(), repositoryRoot, workRoot, project,
	)
	if !errors.Is(err, ErrSourceUnavailable) {
		t.Fatalf("build bundle error = %v, want source unavailable", err)
	}
}

func TestDecodeManifestRejectsTraversalEvenWhenEntryIsNotSelected(t *testing.T) {
	project := ProjectSnapshot{
		ProjectID: testProjectID, Status: "partial", SourceKind: "java",
		Language: "mixed", EngineName: "vineflower-cfr-jadx",
		EngineVersion: "1.0", ProjectSourceFileCount: 1,
		ProjectSymbolCount: 1, ProjectSourceSizeBytes: 4,
	}
	manifest := sourceProjectManifest{
		SchemaVersion: sourceProjectSchemaVersion, ProjectID: testProjectID,
		LayoutVersion: "project-v1", SourceKind: "java", Language: "mixed",
		EngineName: project.EngineName, EngineVersion: project.EngineVersion,
		Status: "partial", SourceFileCount: 1, SymbolCount: 1,
		Files: []sourceProjectManifestFile{{
			ResultID: testResultA, BinaryName: "a.A", Language: "java-bytecode",
			Status: "bytecode_only", LogicalPath: "artifacts/bytecode/../../x.class",
			SHA256: javaDigest("data"), SizeBytes: 4,
		}},
	}
	raw, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decodeAndValidateManifest(bytes.NewReader(raw), project); !errors.Is(err, ErrSourceUnavailable) {
		t.Fatalf("decode manifest error = %v, want source unavailable", err)
	}
}

func writeJavaProjectFixture(
	t *testing.T,
	repositoryRoot string,
) (ProjectSnapshot, []byte) {
	t.Helper()
	rootKey := "source-projects/" + testProjectID
	root := filepath.Join(repositoryRoot, filepath.FromSlash(rootKey))
	contents := map[string]string{
		"src/main/java/z/Z.java":     "class Z {}",
		"src/main/java/a/A.java":     "class A {}",
		"artifacts/bytecode/B.class": "bytecode",
	}
	for name, content := range contents {
		filename := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(filename), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filename, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	files := []SourceFile{
		javaTestFile(testResultA, "src/main/java/a/A.java", "a.A", contents["src/main/java/a/A.java"]),
		javaTestFile(testResultC, "src/main/java/z/Z.java", "z.Z", contents["src/main/java/z/Z.java"]),
	}
	inputSHA, err := canonicalInputSHA256(files)
	if err != nil {
		t.Fatal(err)
	}
	manifest := sourceProjectManifest{
		SchemaVersion: sourceProjectSchemaVersion, ProjectID: testProjectID,
		LayoutVersion: "project-v1", SourceKind: "java", Language: "mixed",
		EngineName: "vineflower-cfr-jadx", EngineVersion: "1.0", Status: "partial",
		SourceFileCount: 3, SymbolCount: 3,
		Files: []sourceProjectManifestFile{
			javaManifestFile(testResultC, "src/main/java/z/Z.java", "z.Z", "java", "complete", contents["src/main/java/z/Z.java"]),
			javaManifestFile(testResultB, "artifacts/bytecode/B.class", "b.B", "java-bytecode", "bytecode_only", contents["artifacts/bytecode/B.class"]),
			javaManifestFile(testResultA, "src/main/java/a/A.java", "a.A", "java", "complete", contents["src/main/java/a/A.java"]),
		},
	}
	raw, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	manifestName := filepath.Join(root, "manifest.json")
	if err := os.WriteFile(manifestName, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	projectSourceSize := uint64(0)
	for _, content := range contents {
		projectSourceSize += uint64(len(content))
	}
	project := ProjectSnapshot{
		ProjectID: testProjectID, Status: "partial", SourceKind: "java",
		Language: "mixed", EngineName: manifest.EngineName,
		EngineVersion: manifest.EngineVersion, RootStorageKey: rootKey,
		ManifestStorageKey: rootKey + "/manifest.json",
		ManifestSHA256:     javaDigest(string(raw)), ManifestSizeBytes: uint64(len(raw)),
		ProjectSourceFileCount: 3, ProjectSymbolCount: 3,
		ProjectSourceSizeBytes: projectSourceSize,
		InputSHA256:            inputSHA, SourceSizeBytes: uint64(len("class A {}class Z {}")),
		Files: files,
	}
	return project, []byte("class A {}class Z {}")
}

func javaTestFile(
	resultID string,
	logicalPath string,
	binaryName string,
	content string,
) SourceFile {
	lines := javaLineCounter{}
	_, _ = lines.Write([]byte(content))
	return SourceFile{
		FileIdentity: FileIdentity{
			ResultID: resultID, LogicalPath: logicalPath, BinaryName: binaryName,
		},
		SHA256: javaDigest(content), SizeBytes: uint64(len(content)),
		LineCount: lines.Count(),
	}
}

func javaManifestFile(
	resultID string,
	logicalPath string,
	binaryName string,
	language string,
	status string,
	content string,
) sourceProjectManifestFile {
	return sourceProjectManifestFile{
		ResultID: resultID, SymbolKey: strings.TrimSuffix(binaryName, ".class"),
		BinaryName: binaryName, DisplayName: binaryName, Language: language,
		Status: status, LogicalPath: logicalPath, SHA256: javaDigest(content),
		SizeBytes: uint64(len(content)),
	}
}

func javaDigest(content string) string {
	digest := sha256.Sum256([]byte(content))
	return hex.EncodeToString(digest[:])
}

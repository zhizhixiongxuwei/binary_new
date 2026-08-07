package bytecode

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf8"
)

func TestJVMFallbackEngineSingleClass(t *testing.T) {
	payload := generatedJVMClass(t, "sample/Greeter", "greet", 61)
	result, workspace, err := executeJVMFixture(
		t, payload, FormatClass, JVMEngineConfig{}, Limits{},
	)
	if err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	if result.Status != StatusBytecodeOnly || len(result.Classes) != 1 ||
		len(result.Artifacts) != 1 || len(result.ClassErrors) != 0 {
		t.Fatalf("single class result = %#v", result)
	}
	class := result.Classes[0]
	artifact := result.Artifacts[0]
	if class.BinaryName != "sample.Greeter" || class.SourceFile != "Greeter.java" ||
		class.Status != ClassBytecodeOnly || len(class.Methods) != 1 ||
		class.Methods[0].Name != "greet" || class.Methods[0].Bytecode == nil ||
		class.Methods[0].Bytecode.SizeBytes != 1 ||
		len(class.ArtifactIDs) != 1 || class.ArtifactIDs[0] != artifact.ID ||
		len(artifact.ClassKeys) != 1 || artifact.ClassKeys[0] != class.Key ||
		artifact.Kind != ArtifactIndex || artifact.Validation != ValidationHashVerified {
		t.Fatalf("single class indexes = class %#v artifact %#v", class, artifact)
	}
	document, raw := readJVMIndexFixture(t, workspace, artifact)
	if !utf8.Valid(raw) || document.TargetJavaRelease != 21 ||
		document.Class.ClassKey != class.Key ||
		document.Class.BinaryName != "sample.Greeter" ||
		len(document.Class.Methods) != 1 ||
		document.Class.Methods[0].Code == nil ||
		document.Class.Methods[0].Code.BytecodeHex != "b1" {
		t.Fatalf("JVM index document = %#v; raw = %q", document, raw)
	}
	engine, err := NewJVMFallbackEngine(JVMEngineConfig{})
	if err != nil {
		t.Fatal(err)
	}
	if engine.Descriptor().Name != JVMFallbackEngineName ||
		!strings.Contains(engine.Descriptor().Version, "java21-cfg") ||
		len(engine.ConfigFingerprint()) != 64 {
		t.Fatalf("engine identity = %#v / %q", engine.Descriptor(), engine.ConfigFingerprint())
	}
	var contract Engine = engine
	_ = contract
}

func TestJVMFallbackEngineCreatesPerClassJARArtifacts(t *testing.T) {
	payload := generatedJVMArchive(t, []jvmZIPFixtureEntry{
		{name: "pkg/A.class", payload: generatedJVMClass(t, "pkg/A", "alpha", 61)},
		{name: "pkg/B.class", payload: generatedJVMClass(t, "pkg/B", "beta", 61)},
		{name: "META-INF/NOTICE", payload: []byte("offline fixture"), store: true},
	})
	result, workspace, err := executeJVMFixture(
		t, payload, FormatJAR, JVMEngineConfig{}, Limits{},
	)
	if err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	if result.Status != StatusBytecodeOnly || len(result.Classes) != 2 ||
		len(result.Artifacts) != 2 {
		t.Fatalf("JAR result = %#v", result)
	}
	artifacts := make(map[string]Artifact, len(result.Artifacts))
	for _, artifact := range result.Artifacts {
		artifacts[artifact.ID] = artifact
		if len(artifact.ClassKeys) != 1 {
			t.Fatalf("artifact is not class-local: %#v", artifact)
		}
		document, _ := readJVMIndexFixture(t, workspace, artifact)
		if document.Class.ClassKey != artifact.ClassKeys[0] {
			t.Fatalf("artifact payload/link mismatch: %#v", artifact)
		}
	}
	for _, class := range result.Classes {
		if len(class.ArtifactIDs) != 1 {
			t.Fatalf("class artifact links = %#v", class)
		}
		artifact := artifacts[class.ArtifactIDs[0]]
		if len(artifact.ClassKeys) != 1 || artifact.ClassKeys[0] != class.Key {
			t.Fatalf("reciprocal links = class %#v artifact %#v", class, artifact)
		}
	}
}

func TestJVMFallbackEngineEnumeratesWARAndEARClasses(t *testing.T) {
	tests := []struct {
		name       string
		format     Format
		entryPath  string
		binaryName string
	}{
		{
			name: "war", format: FormatWAR,
			entryPath:  "WEB-INF/classes/web/Controller.class",
			binaryName: "web.Controller",
		},
		{
			name: "ear", format: FormatEAR,
			entryPath:  "APP-INF/classes/app/Service.class",
			binaryName: "app.Service",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			payload := generatedJVMArchive(t, []jvmZIPFixtureEntry{{
				name: test.entryPath,
				payload: generatedJVMClass(
					t, strings.ReplaceAll(test.binaryName, ".", "/"), "run", 61,
				),
			}})
			result, workspace, err := executeJVMFixture(
				t, payload, test.format, JVMEngineConfig{}, Limits{},
			)
			if err != nil {
				t.Fatalf("Execute() error = %v", err)
			}
			if len(result.Classes) != 1 || result.Classes[0].BinaryName != test.binaryName {
				t.Fatalf("archive class = %#v", result.Classes)
			}
			document, _ := readJVMIndexFixture(t, workspace, result.Artifacts[0])
			if document.Class.EntryPath != test.entryPath {
				t.Fatalf("entry path = %q", document.Class.EntryPath)
			}
		})
	}
}

func TestJVMFallbackEngineSelectsMultiReleaseClass(t *testing.T) {
	payload := generatedJVMArchive(t, []jvmZIPFixtureEntry{
		{
			name:    "META-INF/MANIFEST.MF",
			payload: []byte("Manifest-Version: 1.0\r\nMulti-Release: true\r\n\r\n"),
		},
		{name: "pkg/Choice.class", payload: generatedJVMClass(t, "pkg/Choice", "base", 52)},
		{
			name:    "META-INF/versions/9/pkg/Choice.class",
			payload: generatedJVMClass(t, "pkg/Choice", "release9", 53),
		},
		{
			name:    "META-INF/versions/11/pkg/Choice.class",
			payload: generatedJVMClass(t, "pkg/Choice", "release11", 55),
		},
		{
			name:    "META-INF/versions/22/pkg/Choice.class",
			payload: generatedJVMClass(t, "pkg/Choice", "release22", 66),
		},
	})
	tests := []struct {
		target        int
		wantRelease   int
		wantMethod    string
		wantEntryPath string
	}{
		{
			target: 10, wantRelease: 9, wantMethod: "release9",
			wantEntryPath: "META-INF/versions/9/pkg/Choice.class",
		},
		{
			target: 21, wantRelease: 11, wantMethod: "release11",
			wantEntryPath: "META-INF/versions/11/pkg/Choice.class",
		},
	}
	for _, test := range tests {
		t.Run("java"+string(rune('0'+test.target%10)), func(t *testing.T) {
			result, workspace, err := executeJVMFixture(
				t, payload, FormatJAR,
				JVMEngineConfig{TargetJavaRelease: test.target}, Limits{},
			)
			if err != nil {
				t.Fatalf("Execute() error = %v", err)
			}
			if len(result.Classes) != 1 || len(result.Classes[0].Methods) != 1 ||
				result.Classes[0].Methods[0].Name != test.wantMethod {
				t.Fatalf("selected class = %#v", result.Classes)
			}
			document, _ := readJVMIndexFixture(t, workspace, result.Artifacts[0])
			if document.Class.SelectedRelease != test.wantRelease ||
				document.Class.EntryPath != test.wantEntryPath {
				t.Fatalf("selected index = %#v", document.Class)
			}
		})
	}
}

func TestJVMFallbackEngineIsolatesMalformedClasses(t *testing.T) {
	valid := generatedJVMClass(t, "pkg/Good", "ok", 61)
	archive := generatedJVMArchive(t, []jvmZIPFixtureEntry{
		{name: "pkg/Bad.class", payload: []byte("not a class"), store: true},
		{name: "pkg/Good.class", payload: valid},
	})
	result, _, err := executeJVMFixture(
		t, archive, FormatJAR, JVMEngineConfig{}, Limits{},
	)
	if err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	if result.Status != StatusPartial || len(result.Classes) != 2 ||
		len(result.ClassErrors) != 1 || len(result.Artifacts) != 1 {
		t.Fatalf("partial result = %#v", result)
	}
	successes, failures := 0, 0
	for _, class := range result.Classes {
		switch class.Status {
		case ClassBytecodeOnly:
			successes++
			if len(class.ArtifactIDs) != 1 || class.BinaryName != "pkg.Good" {
				t.Fatalf("successful class = %#v", class)
			}
		case ClassFailed:
			failures++
			if len(class.ArtifactIDs) != 0 {
				t.Fatalf("failed class has artifact: %#v", class)
			}
		}
	}
	if successes != 1 || failures != 1 || result.ClassErrors[0].Code != "invalid_class" {
		t.Fatalf("failure isolation = %#v", result)
	}

	single, _, err := executeJVMFixture(
		t, []byte("broken"), FormatClass, JVMEngineConfig{}, Limits{},
	)
	if err != nil || single.Status != StatusPartial || len(single.Classes) != 1 ||
		len(single.ClassErrors) != 1 || len(single.Artifacts) != 0 {
		t.Fatalf("malformed single class = %#v, error = %v", single, err)
	}
}

func TestJVMFallbackEngineRejectsUnsafeZIPArchives(t *testing.T) {
	class := generatedJVMClass(t, "Safe", "run", 61)
	tests := []struct {
		name    string
		payload []byte
		config  JVMEngineConfig
		want    error
	}{
		{
			name: "traversal",
			payload: generatedJVMArchive(t, []jvmZIPFixtureEntry{{
				name: "../Escape.class", payload: class,
			}}),
			want: ErrUnsafeJVMArchive,
		},
		{
			name: "duplicate path",
			payload: generatedJVMArchive(t, []jvmZIPFixtureEntry{
				{name: "Same.class", payload: class},
				{name: "Same.class", payload: class},
			}),
			want: ErrUnsafeJVMArchive,
		},
		{
			name: "compression ratio",
			payload: generatedJVMArchive(t, []jvmZIPFixtureEntry{{
				name: "payload.bin", payload: bytes.Repeat([]byte{0}, 32<<10),
			}}),
			config: JVMEngineConfig{MaxCompressionRatio: 2},
			want:   ErrJVMArchiveLimit,
		},
		{
			name: "entry count",
			payload: generatedJVMArchive(t, []jvmZIPFixtureEntry{
				{name: "one.txt", payload: []byte("1"), store: true},
				{name: "two.txt", payload: []byte("2"), store: true},
			}),
			config: JVMEngineConfig{MaxArchiveEntries: 1},
			want:   ErrJVMArchiveLimit,
		},
		{
			name: "expanded bytes",
			payload: generatedJVMArchive(t, []jvmZIPFixtureEntry{
				{name: "one.bin", payload: bytes.Repeat([]byte("a"), 160), store: true},
				{name: "two.bin", payload: bytes.Repeat([]byte("b"), 160), store: true},
			}),
			config: JVMEngineConfig{MaxExpandedBytes: 256, MaxClassBytes: 256},
			want:   ErrJVMArchiveLimit,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, _, err := executeJVMFixture(
				t, test.payload, FormatJAR, test.config, Limits{},
			)
			if !errors.Is(err, test.want) {
				t.Fatalf("Execute() error = %v, want %v", err, test.want)
			}
		})
	}
}

func TestJVMFallbackEngineEnforcesArtifactLimitsBeforePublishing(t *testing.T) {
	payload := generatedJVMArchive(t, []jvmZIPFixtureEntry{
		{name: "A.class", payload: generatedJVMClass(t, "A", "a", 61)},
		{name: "B.class", payload: generatedJVMClass(t, "B", "b", 61)},
	})
	_, workspace, err := executeJVMFixture(
		t, payload, FormatJAR, JVMEngineConfig{}, Limits{MaxArtifacts: 1},
	)
	if !errors.Is(err, ErrJVMArchiveLimit) {
		t.Fatalf("artifact count error = %v", err)
	}
	entries, readErr := os.ReadDir(workspace)
	if readErr != nil {
		t.Fatal(readErr)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".jvm-bytecode-") {
			t.Fatalf("failed run leaked artifact directory %q", entry.Name())
		}
	}
}

type jvmIndexFixtureDocument struct {
	SchemaVersion     string              `json:"schema_version"`
	Kind              string              `json:"kind"`
	TargetJavaRelease int                 `json:"target_java_release"`
	Class             jvmIndexClassRecord `json:"class"`
}

func readJVMIndexFixture(
	t *testing.T,
	workspace string,
	artifact Artifact,
) (jvmIndexFixtureDocument, []byte) {
	t.Helper()
	payload, err := os.ReadFile(filepath.Join(
		workspace, filepath.FromSlash(artifact.RelativePath),
	))
	if err != nil {
		t.Fatal(err)
	}
	var document jvmIndexFixtureDocument
	if err := json.Unmarshal(payload, &document); err != nil {
		t.Fatalf("decode JVM index: %v", err)
	}
	return document, payload
}

func executeJVMFixture(
	t *testing.T,
	payload []byte,
	format Format,
	config JVMEngineConfig,
	limits Limits,
) (Result, string, error) {
	t.Helper()
	workspace := t.TempDir()
	inputPath := filepath.Join(workspace, "fixture."+string(format))
	if err := os.WriteFile(inputPath, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	validator, err := NewFileArtifactValidator(nil)
	if err != nil {
		t.Fatal(err)
	}
	engine, err := NewJVMFallbackEngine(config)
	if err != nil {
		return Result{}, workspace, err
	}
	result, err := Execute(context.Background(), engine, Request{
		Input: Input{
			Path: inputPath, SHA256: digestOf(payload), Format: format,
			SizeBytes: int64(len(payload)),
		},
		Workspace: workspace, Limits: limits, ArtifactValidator: validator,
	})
	return result, workspace, err
}

type jvmZIPFixtureEntry struct {
	name    string
	payload []byte
	store   bool
}

func generatedJVMArchive(t *testing.T, entries []jvmZIPFixtureEntry) []byte {
	t.Helper()
	var output bytes.Buffer
	writer := zip.NewWriter(&output)
	for _, entry := range entries {
		header := &zip.FileHeader{Name: entry.name, Method: zip.Deflate}
		if entry.store {
			header.Method = zip.Store
		}
		file, err := writer.CreateHeader(header)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := file.Write(entry.payload); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return output.Bytes()
}

func generatedJVMClass(
	t *testing.T,
	internalName string,
	methodName string,
	majorVersion uint16,
) []byte {
	t.Helper()
	var output bytes.Buffer
	writeU1 := func(value byte) {
		if err := output.WriteByte(value); err != nil {
			t.Fatal(err)
		}
	}
	writeU2 := func(value uint16) {
		if err := binary.Write(&output, binary.BigEndian, value); err != nil {
			t.Fatal(err)
		}
	}
	writeU4 := func(value uint32) {
		if err := binary.Write(&output, binary.BigEndian, value); err != nil {
			t.Fatal(err)
		}
	}
	writeUTF8 := func(value string) {
		writeU1(1)
		writeU2(uint16(len(value)))
		if _, err := output.WriteString(value); err != nil {
			t.Fatal(err)
		}
	}

	writeU4(0xcafebabe)
	writeU2(0)
	writeU2(majorVersion)
	writeU2(10)
	writeUTF8(internalName) // #1
	writeU1(7)
	writeU2(1)                    // #2 Class
	writeUTF8("java/lang/Object") // #3
	writeU1(7)
	writeU2(3)              // #4 Class
	writeUTF8(methodName)   // #5
	writeUTF8("()V")        // #6
	writeUTF8("Code")       // #7
	writeUTF8("SourceFile") // #8
	sourceName := internalName
	if separator := strings.LastIndexByte(sourceName, '/'); separator >= 0 {
		sourceName = sourceName[separator+1:]
	}
	writeUTF8(sourceName + ".java") // #9

	writeU2(0x0021) // public, super
	writeU2(2)
	writeU2(4)
	writeU2(0) // interfaces
	writeU2(0) // fields
	writeU2(1) // methods
	writeU2(0x0009)
	writeU2(5)
	writeU2(6)
	writeU2(1)
	writeU2(7)
	writeU4(13)
	writeU2(0) // max stack
	writeU2(0) // max locals
	writeU4(1)
	writeU1(0xb1) // return
	writeU2(0)    // exception table
	writeU2(0)    // Code attributes
	writeU2(1)    // class attributes
	writeU2(8)
	writeU4(2)
	writeU2(9)
	return output.Bytes()
}

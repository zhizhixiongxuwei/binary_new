package bytecode

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const pycSourceFixtureScript = `#!/bin/sh
# fake pycdc: prints source on success, exits 1 on demand
if [ "${PYCDC_FAKE_FAIL:-0}" = "1" ]; then
  echo "Bad MAGIC!" >&2
  exit 1
fi
printf 'import os\n\ndef run(cmd):\n    os.system(cmd)\n'
`

func writeFakePYCDC(t *testing.T, directory string) string {
	t.Helper()
	path := filepath.Join(directory, "fake-pycdc")
	if err := os.WriteFile(path, []byte(pycSourceFixtureScript), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

func pycSourceFixtureRequest(
	t *testing.T,
	workspace string,
) Request {
	t.Helper()
	payload := goldenPYCFixture(3413, false)
	inputPath := filepath.Join(workspace, "fixture.pyc")
	if err := os.WriteFile(inputPath, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(payload)
	return Request{
		Input: Input{
			Path: inputPath, SHA256: hex.EncodeToString(digest[:]),
			Format: FormatPYC, SizeBytes: int64(len(payload)),
		},
		Workspace: workspace,
		Limits: Limits{
			MaxDuration: 30 * time.Second, MaxInputBytes: 1 << 20,
			MaxClasses: 10, MaxMethods: 100, MaxArtifacts: 10,
			MaxArtifactBytes: 1 << 20, MaxClassErrors: 10,
		},
		ArtifactValidator: mustPYCValidator(t),
	}
}

func newPYCSourceTestEngine(
	t *testing.T,
	executable string,
	workRoot string,
	fallback Engine,
) *PYCSourceEngine {
	t.Helper()
	engine, err := NewPYCSourceEngine(PYCSourceConfig{
		Executable: executable, WorkRoot: workRoot,
		MaxDuration:      20 * time.Second,
		TerminationGrace: time.Second,
		MaxStdoutBytes:   1 << 20, MaxStderrBytes: 1 << 20,
		MaxInputBytes: 1 << 20, MaxOutputBytes: 1 << 20,
		MaxArguments: 8, MaxArgumentBytes: 4 << 10,
		MaxTotalArgumentBytes: 64 << 10,
	}, fallback)
	if err != nil {
		t.Fatal(err)
	}
	return engine
}

func TestPYCSourceEngineDecompilesToPythonSource(t *testing.T) {
	canonical, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	workRoot := filepath.Join(canonical, "work")
	if err := os.Mkdir(workRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	executable := writeFakePYCDC(t, canonical)
	fallbackCalled := false
	fallback := EngineFunc{
		EngineDescriptor: Descriptor{Name: "stub-fallback", Version: "1"},
		SupportedFormats: []Format{FormatPYC},
		Run: func(context.Context, Request) (Output, error) {
			fallbackCalled = true
			return Output{
				Status: StatusBytecodeOnly,
				Classes: []ClassIndex{{
					Key: "fallback-module-key", Kind: KindModule,
					BinaryName: "main", DisplayName: "main",
					Language: "python-bytecode", Status: ClassBytecodeOnly,
					Methods: []MethodIndex{},
				}},
			}, nil
		},
	}
	engine := newPYCSourceTestEngine(t, executable, workRoot, fallback)
	request := pycSourceFixtureRequest(t, workRoot)
	result, err := Execute(context.Background(), engine, request)
	if err != nil {
		t.Fatal(err)
	}
	if fallbackCalled {
		t.Fatal("fallback was called on a successful pycdc run")
	}
	if result.Status != StatusComplete {
		t.Fatalf("status = %q, want complete", result.Status)
	}
	if result.Engine.Name != PYCSourceEngineName {
		t.Fatalf("engine = %q, want %q", result.Engine.Name, PYCSourceEngineName)
	}
	if len(result.Artifacts) != 1 ||
		result.Artifacts[0].Kind != ArtifactSource ||
		result.Artifacts[0].MediaType != "text/x-python" ||
		result.Artifacts[0].RelativePath != "output/main.py" {
		t.Fatalf("artifacts = %+v", result.Artifacts)
	}
	if len(result.Classes) != 1 ||
		result.Classes[0].Language != "python" ||
		result.Classes[0].Status != ClassSource ||
		len(result.Classes[0].ArtifactIDs) != 1 {
		t.Fatalf("classes = %+v", result.Classes)
	}
	content, err := os.ReadFile(filepath.Join(request.Workspace, "output", "main.py"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(content), "os.system") {
		t.Fatalf("decompiled source missing expected content: %q", content)
	}
}

func TestPYCSourceEngineFallsBackWhenPyCDCRejectsInput(t *testing.T) {
	canonical, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	workRoot := filepath.Join(canonical, "work")
	if err := os.Mkdir(workRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	executable := writeFakePYCDC(t, canonical)
	fallback := EngineFunc{
		EngineDescriptor: Descriptor{Name: "stub-fallback", Version: "1"},
		SupportedFormats: []Format{FormatPYC},
		Run: func(context.Context, Request) (Output, error) {
			return Output{
				Status: StatusUnsupported,
				Warnings: []string{
					"The PYC magic number is not recognized by the offline fallback.",
				},
			}, nil
		},
	}
	engine := newPYCSourceTestEngine(t, executable, workRoot, fallback)
	// Force the fake pycdc to reject the input.
	t.Setenv("PYCDC_FAKE_FAIL", "1")
	request := pycSourceFixtureRequest(t, workRoot)
	result, err := Execute(context.Background(), engine, request)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != StatusUnsupported {
		t.Fatalf("status = %q, want unsupported fallback", result.Status)
	}
	if len(result.Warnings) != 1 ||
		result.Warnings[0] != "The PYC magic number is not recognized by the offline fallback." {
		t.Fatalf("fallback output was not preserved: %+v", result.Warnings)
	}
}

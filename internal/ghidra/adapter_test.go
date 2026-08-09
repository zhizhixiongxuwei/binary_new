package ghidra

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const testProcessTimeout = 30 * time.Second

func TestAnalyzeUsesArgumentVectorAndParsesBoundedResult(t *testing.T) {
	root := t.TempDir()
	source := filepath.Join(root, "source;touch-pwn")
	if err := os.WriteFile(source, []byte("binary"), 0o600); err != nil {
		t.Fatal(err)
	}
	functionSource := []byte("int main(void) { return 0; }\n")
	digest := sha256.Sum256(functionSource)
	executable := filepath.Join(root, "analyzeHeadless")
	script := `#!/bin/sh
set -eu
test "$#" -eq 17
test "${11}" = "10"
test "${12}" = "4096"
test "${13}" = "10"
test "${14}" = "10"
test "${15}" = "640"
test "${16}" = "4096"
test "${17}" = "-deleteProject"
test -f "${4}"
test "$(cat "${4}")" = "binary"
test "$(basename "${4}")" = "source.snapshot"
case "${4}" in /proc/*|/dev/fd/*) exit 97 ;; esac
index="${9}"
output="${10}"
printf '%s\n' 'BINARYSCAN_GHIDRA_PROGRESS=0/1'
printf '%s\n' 'BINARYSCAN_GHIDRA_PROGRESS=1/1'
printf '%s' 'int main(void) { return 0; }
' > "$output/f-000000.c"
	printf '%s' '{"schema_version":3,"format":"ELF","architecture":"x86:LE:64:default","completeness":"complete","candidate_function_count":1,"decompiled_function_count":1,"entry_points":[{"address":"00401000","symbol":"_start"}],"segments":[{"name":".text","start":"00401000","end":"0040100f","size_bytes":16,"permissions":"r-x","initialized":true,"overlay":false}],"functions":[{"name":"main","address":"00401000","size_bytes":16,"source_file":"f-000000.c","sha256":"` +
		hex.EncodeToString(digest[:]) +
		`","source_size":29}],"call_edges":[{"caller_address":"00401000","callee_address":"EXTERNAL:00000001","callee_name":"puts","external":true}]}' > "$index"
`
	if err := os.WriteFile(executable, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	adapter := newTestAdapter(t, executable, testProcessTimeout)
	var progress []Progress
	request := testRequest(t, source, filepath.Join(root, "work"), 2)
	request.Progress = func(value Progress) {
		progress = append(progress, value)
	}
	result, err := adapter.Analyze(
		context.Background(), request,
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Index.Functions) != 1 ||
		result.Index.Functions[0].Name != "main" ||
		len(result.Index.EntryPoints) != 1 ||
		result.Index.EntryPoints[0].Symbol != "_start" ||
		len(result.Index.Segments) != 1 ||
		result.Index.Segments[0].Permissions != "r-x" ||
		len(result.Index.CallEdges) != 1 ||
		result.Index.CallEdges[0].CalleeName != "puts" {
		t.Fatalf("result = %#v", result)
	}
	if len(progress) != 2 || progress[0] != (Progress{Current: 0, Total: 1}) ||
		progress[1] != (Progress{Current: 1, Total: 1}) {
		t.Fatalf("progress = %#v", progress)
	}
	runRoot := filepath.Dir(result.OutputDir)
	snapshotInfo, err := os.Lstat(filepath.Join(runRoot, sourceSnapshotName))
	if err != nil || !snapshotInfo.Mode().IsRegular() ||
		snapshotInfo.Mode().Perm() != 0o400 {
		t.Fatalf("verified source snapshot = %#v, %v", snapshotInfo, err)
	}
	if result.Cleanup == nil {
		t.Fatal("successful analysis did not return a cleanup handle")
	}
	if err := result.Cleanup(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(runRoot); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("Ghidra run directory remains after cleanup: %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, "touch-pwn")); !errors.Is(
		err, os.ErrNotExist,
	) {
		t.Fatalf("source path was interpreted by a shell: %v", err)
	}
}

func TestAnalyzeTerminatesTimedOutProcessGroup(t *testing.T) {
	root := t.TempDir()
	source := filepath.Join(root, "source")
	if err := os.WriteFile(source, []byte("binary"), 0o600); err != nil {
		t.Fatal(err)
	}
	executable := filepath.Join(root, "analyzeHeadless")
	if err := os.WriteFile(
		executable, []byte("#!/bin/sh\nsleep 10\n"), 0o700,
	); err != nil {
		t.Fatal(err)
	}
	adapter := newTestAdapter(t, executable, 50*time.Millisecond)
	started := time.Now()
	request := testRequest(t, source, filepath.Join(root, "work"), 2)
	request.Limits.MaxDuration = 50 * time.Millisecond
	_, err := adapter.Analyze(context.Background(), request)
	if !errors.Is(err, ErrTimedOut) {
		t.Fatalf("Analyze() error = %v", err)
	}
	if time.Since(started) > time.Second {
		t.Fatal("timed out process group did not stop promptly")
	}
}

func TestAnalyzeContextCoversSourceSnapshotPreparation(t *testing.T) {
	root := t.TempDir()
	source := filepath.Join(root, "source")
	if err := os.WriteFile(source, []byte("binary"), 0o600); err != nil {
		t.Fatal(err)
	}
	invoked := filepath.Join(root, "invoked")
	executable := filepath.Join(root, "analyzeHeadless")
	if err := os.WriteFile(
		executable,
		[]byte("#!/bin/sh\nprintf invoked > '"+invoked+"'\n"),
		0o700,
	); err != nil {
		t.Fatal(err)
	}
	adapter := newTestAdapter(t, executable, testProcessTimeout)
	if _, err := adapter.Analyze(
		nil, testRequest(t, source, filepath.Join(root, "nil-work"), 1),
	); err == nil {
		t.Fatal("Analyze() accepted a nil context")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := adapter.Analyze(
		ctx, testRequest(t, source, filepath.Join(root, "work"), 1),
	)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Analyze() error = %v, want context.Canceled", err)
	}
	if _, err := os.Lstat(invoked); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("analyzeHeadless ran after preparation cancellation: %v", err)
	}
}

func TestAnalyzeRejectsUnknownIndexFields(t *testing.T) {
	root := t.TempDir()
	source := filepath.Join(root, "source")
	_ = os.WriteFile(source, []byte("binary"), 0o600)
	executable := filepath.Join(root, "analyzeHeadless")
	script := `#!/bin/sh
set -eu
	printf '%s' '{"schema_version":3,"format":"ELF","architecture":"x86","completeness":"complete","candidate_function_count":0,"decompiled_function_count":0,"entry_points":[],"segments":[],"functions":[],"call_edges":[],"extra":true}' > "${9}"
`
	_ = os.WriteFile(executable, []byte(script), 0o700)
	adapter := newTestAdapter(t, executable, testProcessTimeout)
	_, err := adapter.Analyze(
		context.Background(), testRequest(t, source, filepath.Join(root, "work"), 1),
	)
	if !errors.Is(err, ErrInvalidResult) {
		t.Fatalf("Analyze() error = %v", err)
	}
	runRoot := filepath.Join(
		root, "work", "ghidra",
		"123e4567-e89b-42d3-a456-426614174000-a1-f1",
	)
	if _, statErr := os.Lstat(runRoot); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("failed analysis leaked run directory: %v", statErr)
	}
}

func TestAnalyzeRejectsSymlinkWorkRoot(t *testing.T) {
	root := t.TempDir()
	source := filepath.Join(root, "source")
	_ = os.WriteFile(source, []byte("binary"), 0o600)
	executable := filepath.Join(root, "analyzeHeadless")
	_ = os.WriteFile(executable, []byte("#!/bin/sh\nexit 0\n"), 0o700)
	realWork := filepath.Join(root, "real-work")
	if err := os.Mkdir(realWork, 0o700); err != nil {
		t.Fatal(err)
	}
	workRoot := filepath.Join(root, "work")
	if err := os.Symlink(realWork, workRoot); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	adapter := newTestAdapter(t, executable, testProcessTimeout)
	_, err := adapter.Analyze(
		context.Background(), testRequest(t, source, workRoot, 1),
	)
	if err == nil || !strings.Contains(err.Error(), "not a real directory") {
		t.Fatalf("Analyze() error = %v", err)
	}
}

func TestAnalyzeClassifiesStructuredAndImporterFailures(t *testing.T) {
	tests := []struct {
		name   string
		stderr string
		want   error
	}{
		{
			name:   "architecture marker",
			stderr: "BINARYSCAN_GHIDRA_ERROR=unsupported_architecture",
			want:   ErrUnsupportedArchitecture,
		},
		{
			name:   "instruction marker",
			stderr: "BINARYSCAN_GHIDRA_ERROR=unsupported_instruction",
			want:   ErrUnsupportedInstruction,
		},
		{
			name:   "incomplete marker",
			stderr: "BINARYSCAN_GHIDRA_ERROR=decompile_incomplete",
			want:   ErrDecompileIncomplete,
		},
		{
			name:   "script limit marker",
			stderr: "BINARYSCAN_GHIDRA_ERROR=script_limit",
			want:   ErrScriptLimit,
		},
		{
			name:   "headless importer language failure",
			stderr: "ERROR Language not found for processor specification",
			want:   ErrUnsupportedArchitecture,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			source := filepath.Join(root, "source")
			if err := os.WriteFile(source, []byte("binary"), 0o600); err != nil {
				t.Fatal(err)
			}
			executable := filepath.Join(root, "analyzeHeadless")
			script := "#!/bin/sh\nprintf '%s\\n' '" + test.stderr +
				"' >&2\nexit 1\n"
			if err := os.WriteFile(executable, []byte(script), 0o700); err != nil {
				t.Fatal(err)
			}
			adapter := newTestAdapter(t, executable, testProcessTimeout)
			_, err := adapter.Analyze(
				context.Background(),
				testRequest(t, source, filepath.Join(root, "work"), 1),
			)
			if !errors.Is(err, test.want) {
				t.Fatalf("Analyze() error = %v, want %v", err, test.want)
			}
		})
	}
}

func TestAnalyzeTreatsStructuredMarkerAsFailureAfterZeroExit(t *testing.T) {
	root := t.TempDir()
	source := filepath.Join(root, "source")
	if err := os.WriteFile(source, []byte("binary"), 0o600); err != nil {
		t.Fatal(err)
	}
	executable := filepath.Join(root, "analyzeHeadless")
	if err := os.WriteFile(executable, []byte(
		"#!/bin/sh\nprintf '%s\\n' 'BINARYSCAN_GHIDRA_ERROR=script_limit' >&2\nexit 0\n",
	), 0o700); err != nil {
		t.Fatal(err)
	}
	adapter := newTestAdapter(t, executable, testProcessTimeout)
	_, err := adapter.Analyze(
		context.Background(), testRequest(t, source, filepath.Join(root, "work"), 1),
	)
	if !errors.Is(err, ErrScriptLimit) {
		t.Fatalf("Analyze() error = %v", err)
	}
}

func TestAnalyzeValidatesCompleteAndPartialZeroFunctionIndex(t *testing.T) {
	for _, test := range []struct {
		name      string
		candidate int
		complete  string
		wantErr   bool
	}{
		{name: "explicit empty", candidate: 0, complete: "complete"},
		{name: "omitted function", candidate: 1, complete: "complete", wantErr: true},
		{name: "bounded partial", candidate: 1, complete: "partial"},
		{name: "unbounded partial", candidate: 0, complete: "partial", wantErr: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			source := filepath.Join(root, "source")
			if err := os.WriteFile(source, []byte("binary"), 0o600); err != nil {
				t.Fatal(err)
			}
			executable := filepath.Join(root, "analyzeHeadless")
			index := fmt.Sprintf(
				`{"schema_version":3,"format":"ELF","architecture":"x86","completeness":%q,"candidate_function_count":%d,"decompiled_function_count":0,"entry_points":[],"segments":[],"functions":[],"call_edges":[]}`,
				test.complete, test.candidate,
			)
			script := "#!/bin/sh\nprintf '%s' '" + index + "' > \"${9}\"\n"
			if err := os.WriteFile(executable, []byte(script), 0o700); err != nil {
				t.Fatal(err)
			}
			adapter := newTestAdapter(t, executable, testProcessTimeout)
			result, err := adapter.Analyze(
				context.Background(),
				testRequest(t, source, filepath.Join(root, "work"), 1),
			)
			if test.wantErr && !errors.Is(err, ErrInvalidResult) {
				t.Fatalf("Analyze() error = %v", err)
			}
			if !test.wantErr && (err != nil || result.Index.CandidateFunctionCount != test.candidate) {
				t.Fatalf("Analyze() result = %+v, error = %v", result.Index, err)
			}
			if result.Cleanup != nil {
				_ = result.Cleanup()
			}
		})
	}
}

func TestAnalyzeKillsProcessWhenCombinedLogBudgetIsExceeded(t *testing.T) {
	root := t.TempDir()
	source := filepath.Join(root, "source")
	if err := os.WriteFile(source, []byte("binary"), 0o600); err != nil {
		t.Fatal(err)
	}
	executable := filepath.Join(root, "analyzeHeadless")
	if err := os.WriteFile(executable, []byte(
		"#!/bin/sh\nprintf '%02048d' 0\nsleep 10\n",
	), 0o700); err != nil {
		t.Fatal(err)
	}
	adapter := newTestAdapter(t, executable, testProcessTimeout)
	started := time.Now()
	_, err := adapter.Analyze(
		context.Background(), testRequest(t, source, filepath.Join(root, "work"), 1),
	)
	if !errors.Is(err, ErrOutputLimit) {
		t.Fatalf("Analyze() error = %v", err)
	}
	if time.Since(started) > 2*time.Second {
		t.Fatal("log budget overflow did not terminate the process promptly")
	}
}

func TestAnalyzeRejectsSourceDigestMismatchBeforeExecution(t *testing.T) {
	root := t.TempDir()
	source := filepath.Join(root, "source")
	if err := os.WriteFile(source, []byte("binary"), 0o600); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(root, "executed")
	executable := filepath.Join(root, "analyzeHeadless")
	if err := os.WriteFile(
		executable, []byte("#!/bin/sh\ntouch \""+marker+"\"\n"), 0o700,
	); err != nil {
		t.Fatal(err)
	}
	request := testRequest(t, source, filepath.Join(root, "work"), 1)
	request.SourceSHA256 = strings.Repeat("0", 64)
	adapter := newTestAdapter(t, executable, testProcessTimeout)
	_, err := adapter.Analyze(context.Background(), request)
	if err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("Analyze() error = %v", err)
	}
	if _, err := os.Lstat(marker); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("analyzer executed after source mismatch: %v", err)
	}
}

func TestAdapterIdentityIsDeterministicAndParameterBound(t *testing.T) {
	root := t.TempDir()
	config := Config{
		Executable:      filepath.Join(root, "analyzeHeadless"),
		ScriptDirectory: root,
		Version:         "12.1.2", MaxDuration: 30 * time.Minute,
		TerminationGrace: 5 * time.Second,
		MaxStdoutBytes:   8 << 20, MaxStderrBytes: 8 << 20,
		MaxIndexBytes: 64 << 20, MaxOutputBytes: 512 << 20,
		MaxFunctions: 10_000,
	}
	first, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	second, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	if first.Identity() != second.Identity() ||
		first.Identity().EngineVersion != config.Version ||
		!digestPattern.MatchString(first.Identity().ParametersSHA256) {
		t.Fatalf("identities = %+v / %+v", first.Identity(), second.Identity())
	}
	moved := config
	moved.Executable = filepath.Join(root, "elsewhere", "analyzeHeadless")
	moved.ScriptDirectory = filepath.Join(root, "elsewhere")
	third, err := New(moved)
	if err != nil {
		t.Fatal(err)
	}
	if third.Identity() != first.Identity() {
		t.Fatalf("installation path changed identity: %+v", third.Identity())
	}
	changed := config
	changed.MaxFunctions++
	fourth, err := New(changed)
	if err != nil {
		t.Fatal(err)
	}
	if fourth.Identity().ParametersSHA256 == first.Identity().ParametersSHA256 {
		t.Fatal("semantic limit did not change parameter digest")
	}
}

func TestAnalyzeRejectsUnindexedOutputFile(t *testing.T) {
	root := t.TempDir()
	source := filepath.Join(root, "source")
	_ = os.WriteFile(source, []byte("binary"), 0o600)
	executable := filepath.Join(root, "analyzeHeadless")
	script := `#!/bin/sh
set -eu
printf '%s' 'unexpected' > "${10}/orphan.bin"
	printf '%s' '{"schema_version":3,"format":"ELF","architecture":"x86","completeness":"complete","candidate_function_count":0,"decompiled_function_count":0,"entry_points":[],"segments":[],"functions":[],"call_edges":[]}' > "${9}"
`
	_ = os.WriteFile(executable, []byte(script), 0o700)
	adapter := newTestAdapter(t, executable, testProcessTimeout)
	_, err := adapter.Analyze(
		context.Background(), testRequest(t, source, filepath.Join(root, "work"), 1),
	)
	if !errors.Is(err, ErrInvalidResult) {
		t.Fatalf("Analyze() error = %v", err)
	}
}

func newTestAdapter(
	t *testing.T,
	executable string,
	duration time.Duration,
) *Adapter {
	t.Helper()
	adapter, err := New(Config{
		Executable: executable, ScriptDirectory: filepath.Dir(executable),
		Version: "test", MaxDuration: duration,
		TerminationGrace: 50 * time.Millisecond,
		MaxStdoutBytes:   1024, MaxStderrBytes: 1024,
		MaxIndexBytes: 4096, MaxOutputBytes: 4096, MaxFunctions: 10,
	})
	if err != nil {
		t.Fatal(err)
	}
	return adapter
}

func testRequest(
	t *testing.T,
	source string,
	workRoot string,
	fencingToken uint64,
) Request {
	t.Helper()
	content, err := os.ReadFile(source)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(content)
	return Request{
		SourcePath: source, SourceSHA256: hex.EncodeToString(digest[:]),
		SourceSize: uint64(len(content)), WorkRoot: workRoot,
		JobID:   "123e4567-e89b-42d3-a456-426614174000",
		Attempt: 1, FencingToken: fencingToken,
		Limits: ExecutionLimits{
			MaxDuration: testProcessTimeout, MaxOutputBytes: 4096,
			MaxFunctions: 10, MaxStandardOutputBytes: 1024,
		},
	}
}

func TestProbeVersionRequiresExactLine(t *testing.T) {
	root := t.TempDir()
	executable := filepath.Join(root, "tool")
	_ = os.WriteFile(
		executable,
		[]byte("#!/bin/sh\nprintf '%s\\n' 'Ghidra 12.1.2'\n"),
		0o700,
	)
	if err := ProbeVersion(
		context.Background(), executable, "Ghidra 12.1.2",
		testProcessTimeout, 50*time.Millisecond,
	); err != nil {
		t.Fatal(err)
	}
	err := ProbeVersion(
		context.Background(), executable, "Ghidra 11.2.2",
		testProcessTimeout, 50*time.Millisecond,
	)
	if err == nil || !strings.Contains(err.Error(), "mismatch") {
		t.Fatalf("ProbeVersion() error = %v", err)
	}
}

func TestProbeInstallationUsesMetadataWithoutStartingJava(t *testing.T) {
	root := t.TempDir()
	ghidraRoot := filepath.Join(root, "ghidra")
	scriptDirectory := filepath.Join(root, "scripts")
	javaRoot := filepath.Join(root, "jdk")
	for _, directory := range []string{
		filepath.Join(ghidraRoot, "support"),
		filepath.Join(ghidraRoot, "Ghidra"),
		scriptDirectory,
		filepath.Join(javaRoot, "bin"),
	} {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	ghidraExecutable := filepath.Join(ghidraRoot, "support", "analyzeHeadless")
	if err := os.WriteFile(ghidraExecutable, []byte("#!/bin/sh\nexit 99\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(
		filepath.Join(ghidraRoot, "Ghidra", "application.properties"),
		[]byte("application.name=Ghidra\napplication.version=12.1.2\n"), 0o600,
	); err != nil {
		t.Fatal(err)
	}
	javaExecutable := filepath.Join(javaRoot, "bin", "java")
	elf := make([]byte, 20)
	copy(elf, []byte{0x7f, 'E', 'L', 'F', 2, 1, 1})
	elf[18] = 62
	if err := os.WriteFile(javaExecutable, elf, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(
		filepath.Join(javaRoot, "release"),
		[]byte("JAVA_VERSION=\"21.0.7\"\nJAVA_VERSION_DATE=\"2025-04-15\"\nOS_NAME=\"Linux\"\nOS_ARCH=\"x86_64\"\n"), 0o600,
	); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(
		filepath.Join(scriptDirectory, exportScriptFilename),
		[]byte("// Ghidra export script\n"), 0o600,
	); err != nil {
		t.Fatal(err)
	}
	if err := ProbeInstallation(
		ghidraExecutable, scriptDirectory, "12.1.2", javaExecutable,
		`openjdk version "21.0.7" 2025-04-15 LTS`,
	); err != nil {
		t.Fatal(err)
	}
	if err := ProbeInstallation(
		ghidraExecutable, scriptDirectory, "12.1.1", javaExecutable,
		`openjdk version "21.0.7" 2025-04-15 LTS`,
	); err == nil {
		t.Fatal("ProbeInstallation accepted mismatched Ghidra metadata")
	}
	if err := os.Remove(filepath.Join(scriptDirectory, exportScriptFilename)); err != nil {
		t.Fatal(err)
	}
	if err := ProbeInstallation(
		ghidraExecutable, scriptDirectory, "12.1.2", javaExecutable,
		`openjdk version "21.0.7" 2025-04-15 LTS`,
	); err == nil {
		t.Fatal("ProbeInstallation accepted a missing Ghidra export script")
	}
}

package decompile

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"binaryscan/internal/ghidra"
	"binaryscan/internal/queue"
)

func TestNativeProcessorEndToEndWithFakeAnalyzeHeadless(t *testing.T) {
	repositoryRoot := t.TempDir()
	workRoot := t.TempDir()
	content := []byte("native-binary")
	digest := sha256.Sum256(content)
	key := "blobs/fixture/input.bin"
	source := filepath.Join(repositoryRoot, filepath.FromSlash(key))
	if err := os.MkdirAll(filepath.Dir(source), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(source, content, 0o600); err != nil {
		t.Fatal(err)
	}
	pseudo := []byte("int main(void) { return 0; }\n")
	pseudoDigest := sha256.Sum256(pseudo)
	executable := filepath.Join(t.TempDir(), "analyzeHeadless")
	script := `#!/bin/sh
set -eu
printf '%s\n' 'BINARYSCAN_GHIDRA_PROGRESS=0/1'
printf '%s' 'int main(void) { return 0; }
' > "${10}/f-000000.c"
printf '%s' '{"schema_version":3,"format":"ELF","architecture":"x86:LE:64","completeness":"complete","candidate_function_count":1,"decompiled_function_count":1,"entry_points":[{"address":"00401000","symbol":"_start"}],"segments":[{"name":".text","start":"00401000","end":"0040100f","size_bytes":16,"permissions":"r-x","initialized":true,"overlay":false}],"functions":[{"name":"main","address":"00401000","size_bytes":16,"source_file":"f-000000.c","sha256":"` +
		hex.EncodeToString(pseudoDigest[:]) +
		`","source_size":29}],"call_edges":[]}' > "${9}"
printf '%s\n' 'BINARYSCAN_GHIDRA_PROGRESS=1/1'
`
	if err := os.WriteFile(executable, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	adapter, err := ghidra.New(ghidra.Config{
		Executable: executable, ScriptDirectory: filepath.Dir(executable),
		Version: "12.1.2", MaxDuration: 30 * time.Second,
		TerminationGrace: 100 * time.Millisecond,
		MaxStdoutBytes:   1024, MaxStderrBytes: 1024,
		MaxIndexBytes: 4096, MaxOutputBytes: 4096, MaxFunctions: 10,
	})
	if err != nil {
		t.Fatal(err)
	}
	repository := &nativeRepositoryStub{}
	activity := &nativeActivityStub{}
	processor, err := NewNativeProcessor(
		repository, adapter, activity, NativeProcessorConfig{
			RepositoryRoot: repositoryRoot, TaskWorkRoot: workRoot,
			EngineVersion: "12.1.2",
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	processor.newID = func() (string, error) {
		return "323e4567-e89b-42d3-a456-426614174003", nil
	}
	payload := decompilePayload(decompileCreateRecord())
	payload.Target.StorageKey = key
	payload.Target.SHA256 = hex.EncodeToString(digest[:])
	payload.Target.SizeBytes = uint64(len(content))
	payload.Limits = JobLimits{
		MaxDurationSeconds: 30, MaxOutputBytes: 4096,
		MaxArtifacts: 10, MaxStandardOutputBytes: 1024,
	}
	raw, _ := json.Marshal(payload)
	finish, err := processor.Process(
		context.Background(), nativeProcessingLease(raw, "native-test", 2),
	)
	if err != nil || finish.Outcome != queue.OutcomeSucceeded ||
		len(repository.published) != 1 ||
		repository.beginParameterKey == "" ||
		repository.beginParameterKey != repository.publishParameterKey {
		t.Fatalf(
			"end-to-end finish=%+v err=%v results=%+v",
			finish, err, repository.published,
		)
	}
	assertNativeActivityPhases(
		t,
		activity.inputs,
		[]string{"preparing", "starting", "running", "running", "publishing", "completed"},
	)
	for _, private := range []string{
		filepath.Join(workRoot, "native-input", testJobID+"-a1-f2"),
		filepath.Join(workRoot, "ghidra", testJobID+"-a1-f2"),
	} {
		if _, err := os.Lstat(private); !os.IsNotExist(err) {
			t.Fatalf("private work directory leaked at %s: %v", private, err)
		}
	}
	entries, err := os.ReadDir(workRoot)
	if err != nil || len(entries) != 0 {
		t.Fatalf("native attempt workspace leaked: entries=%v err=%v", entries, err)
	}
}

func assertNativeActivityPhases(
	t *testing.T,
	inputs []queue.ActivityInput,
	wanted []string,
) {
	t.Helper()
	if len(inputs) != len(wanted) {
		t.Fatalf("activity count = %d, want %d: %+v", len(inputs), len(wanted), inputs)
	}
	for index, input := range inputs {
		var payload nativeActivityPayload
		if err := json.Unmarshal(input.Payload, &payload); err != nil {
			t.Fatalf("activity %d payload = %q: %v", index, input.Payload, err)
		}
		if payload.Phase != wanted[index] {
			t.Fatalf("activity %d phase = %q, want %q", index, payload.Phase, wanted[index])
		}
		if strings.Contains(string(input.Payload), repositoryRootMarker) {
			t.Fatalf("activity %d leaked an internal path: %s", index, input.Payload)
		}
	}
}

const repositoryRootMarker = "blobs/fixture"

type nativeRepositoryStub struct {
	begun               bool
	beginParameterKey   string
	publishParameterKey string
	publishCompleteness string
	publishedProject    PublishedSourceProject
	published           []NativePublishedResult
	publishErr          error
	failErr             error
	failed              string
}

func (s *nativeRepositoryStub) BeginNativeRun(
	_ context.Context, _ queue.Lease, _ JobPayload, _, _ string,
	parameterKey string,
) error {
	s.begun = true
	s.beginParameterKey = parameterKey
	return nil
}

func (s *nativeRepositoryStub) PublishNativeRun(
	ctx context.Context, _ queue.Lease, _ JobPayload, _, _ string,
	parameterKey string,
	completeness string,
	publish NativeResultPublisher,
) error {
	s.publishParameterKey = parameterKey
	s.publishCompleteness = completeness
	if s.publishErr != nil {
		return s.publishErr
	}
	project, results, _, err := publish(ctx)
	if err != nil {
		return err
	}
	s.publishedProject = project
	s.published = append([]NativePublishedResult(nil), results...)
	return nil
}

func (s *nativeRepositoryStub) FailNativeRun(
	_ context.Context, _ queue.Lease, _ string, code string, _ string,
) error {
	s.failed = code
	return s.failErr
}

type nativeAnalyzerStub struct {
	result   ghidra.Result
	err      error
	identity ghidra.Identity
	request  ghidra.Request
}

type nativeActivityStub struct {
	inputs []queue.ActivityInput
}

func (stub *nativeActivityStub) TaskActivity(
	_ context.Context,
	_ queue.Lease,
	input queue.ActivityInput,
) error {
	stub.inputs = append(stub.inputs, input)
	return nil
}

func (s *nativeAnalyzerStub) Analyze(
	_ context.Context, request ghidra.Request,
) (ghidra.Result, error) {
	s.request = request
	return s.result, s.err
}

func (s *nativeAnalyzerStub) Identity() ghidra.Identity {
	if s.identity.EngineVersion == "" {
		return ghidra.Identity{
			EngineVersion:    "12.1.2",
			ParametersSHA256: strings.Repeat("a", 64),
		}
	}
	return s.identity
}

func TestNativeProcessorPublishesOnlyAfterVerifiedAnalysis(t *testing.T) {
	repositoryRoot := t.TempDir()
	workRoot := t.TempDir()
	content := []byte("native-binary")
	digest := sha256.Sum256(content)
	key := "blobs/fixture/input.bin"
	source := filepath.Join(repositoryRoot, filepath.FromSlash(key))
	if err := os.MkdirAll(filepath.Dir(source), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(source, content, 0o600); err != nil {
		t.Fatal(err)
	}
	outputDir := t.TempDir()
	pseudo := []byte("int main(void) { return 0; }\n")
	pseudoDigest := sha256.Sum256(pseudo)
	if err := os.WriteFile(
		filepath.Join(outputDir, "f-000000.c"), pseudo, 0o600,
	); err != nil {
		t.Fatal(err)
	}
	repository := &nativeRepositoryStub{}
	analyzer := &nativeAnalyzerStub{result: ghidra.Result{
		OutputDir: outputDir,
		Index: ghidra.Index{
			SchemaVersion: ghidra.IndexSchemaVersion,
			Format:        "ELF", Architecture: "x86:LE:64",
			Completeness: "complete", CandidateFunctionCount: 1,
			DecompiledFunctionCount: 1,
			EntryPoints: []ghidra.EntryPoint{{
				Address: "00401000", Symbol: "_start",
			}},
			Segments: []ghidra.Segment{{
				Name: ".text", Start: "00401000", End: "0040100f",
				SizeBytes: 16, Permissions: "r-x", Initialized: true,
			}},
			Functions: []ghidra.Function{{
				Name: "main", Address: "00401000", SizeBytes: 16,
				SourceFile: "f-000000.c",
				SHA256:     hex.EncodeToString(pseudoDigest[:]),
				SourceSize: uint64(len(pseudo)),
			}},
			CallEdges: []ghidra.CallEdge{{
				CallerAddress: "00401000", CalleeAddress: "EXTERNAL:1",
				CalleeName: "puts", External: true,
			}},
		},
	}}
	processor, err := NewNativeProcessor(
		repository, analyzer,
		&nativeActivityStub{},
		NativeProcessorConfig{
			RepositoryRoot: repositoryRoot, TaskWorkRoot: workRoot,
			EngineVersion: "12.1.2",
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	ids := []string{
		"323e4567-e89b-42d3-a456-426614174003",
		"423e4567-e89b-42d3-a456-426614174004",
	}
	processor.newID = func() (string, error) {
		value := ids[0]
		ids = ids[1:]
		return value, nil
	}
	payload := decompilePayload(decompileCreateRecord())
	payload.Target.StorageKey = key
	payload.Target.SHA256 = hex.EncodeToString(digest[:])
	payload.Target.SizeBytes = uint64(len(content))
	raw, _ := json.Marshal(payload)
	lease := nativeProcessingLease(raw, "native-test", 2)
	finish, err := processor.Process(context.Background(), lease)
	if err != nil {
		t.Fatal(err)
	}
	if finish.Outcome != queue.OutcomeSucceeded || !repository.begun ||
		len(repository.published) != 1 {
		t.Fatalf("finish=%+v repository=%+v", finish, repository)
	}
	if analyzer.request.SourceSHA256 != payload.Target.SHA256 ||
		analyzer.request.SourceSize != payload.Target.SizeBytes ||
		analyzer.request.Limits.MaxDuration !=
			time.Duration(payload.Limits.MaxDurationSeconds)*time.Second ||
		analyzer.request.Limits.MaxOutputBytes != payload.Limits.MaxOutputBytes ||
		analyzer.request.Limits.MaxFunctions != payload.Limits.MaxArtifacts ||
		analyzer.request.Limits.MaxStandardOutputBytes !=
			payload.Limits.MaxStandardOutputBytes {
		t.Fatalf("analyzer request did not preserve payload limits: %+v", analyzer.request)
	}
	var diagnostics struct {
		IsEntryPoint bool              `json:"is_entry_point"`
		Outgoing     []ghidra.CallEdge `json:"outgoing_calls"`
		EntryCount   int               `json:"program_entry_point_count"`
		SegmentCount int               `json:"program_segment_count"`
		CallCount    int               `json:"program_call_edge_count"`
		Completeness string            `json:"program_completeness"`
		Candidate    int               `json:"candidate_function_count"`
		Decompiled   int               `json:"decompiled_function_count"`
	}
	if err := json.Unmarshal(
		repository.published[0].Diagnostics, &diagnostics,
	); err != nil || !diagnostics.IsEntryPoint || len(diagnostics.Outgoing) != 1 ||
		diagnostics.EntryCount != 1 || diagnostics.SegmentCount != 1 ||
		diagnostics.CallCount != 1 || diagnostics.Completeness != "complete" ||
		diagnostics.Candidate != 1 || diagnostics.Decompiled != 1 {
		t.Fatalf("published diagnostics = %+v, %v", diagnostics, err)
	}
	stored := filepath.Join(
		repositoryRoot,
		filepath.FromSlash(repository.published[0].StorageKey),
	)
	if value, err := os.ReadFile(stored); err != nil ||
		!strings.Contains(string(value), string(pseudo)) ||
		!strings.Contains(string(value), "BinaryScan Ghidra pseudo-C project") {
		t.Fatalf("published source = %q, %v", value, err)
	}
	if repository.publishedProject.CanonicalStorageKey !=
		repository.published[0].StorageKey ||
		repository.publishedProject.SourceFileCount != 1 {
		t.Fatalf("published project = %+v", repository.publishedProject)
	}
}

func TestNativeProjectPublishesOneCanonicalCFileWithExactFunctionRanges(t *testing.T) {
	repositoryRoot := t.TempDir()
	outputRoot := t.TempDir()
	first := []byte("int first(void) {\n  return 1;\n}")
	second := []byte("int second(void) {\n  return 2;\n}\n")
	for name, content := range map[string][]byte{
		"first.c": first, "second.c": second,
	} {
		if err := os.WriteFile(filepath.Join(outputRoot, name), content, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	processor := &NativeProcessor{config: NativeProcessorConfig{
		RepositoryRoot: repositoryRoot, EngineVersion: "12.1.2",
	}}
	runID := "323e4567-e89b-42d3-a456-426614174003"
	project, results, cleanup, err := processor.publishFiles(
		context.Background(), runID, ghidra.Result{
			OutputDir: outputRoot,
			Index: ghidra.Index{
				SchemaVersion: ghidra.IndexSchemaVersion,
				Format:        "ELF", Architecture: "x86:LE:64",
				Completeness: "complete", CandidateFunctionCount: 2,
				DecompiledFunctionCount: 2,
				Functions: []ghidra.Function{
					{
						Name: "second", Address: "00402000", SourceFile: "second.c",
						SourceSize: uint64(len(second)), SHA256: digestBytes(second),
					},
					{
						Name: "first", Address: "00401000", SourceFile: "first.c",
						SourceSize: uint64(len(first)), SHA256: digestBytes(first),
					},
				},
			},
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	if project.SourceFileCount != 1 || len(results) != 2 ||
		project.CanonicalStorageKey != "source-projects/"+runID+"/src/decompiled.c" {
		t.Fatalf("native project/results = %+v / %+v", project, results)
	}
	canonical, err := os.ReadFile(filepath.Join(
		repositoryRoot, filepath.FromSlash(project.CanonicalStorageKey),
	))
	if err != nil {
		t.Fatal(err)
	}
	wantSources := [][]byte{first, second}
	for index, result := range results {
		start := result.SourceOffsetBytes
		end := start + result.SourceLengthBytes
		if end > uint64(len(canonical)) ||
			!bytes.Equal(canonical[start:end], wantSources[index]) {
			t.Fatalf("function %d range %d:%d does not select its source", index, start, end)
		}
		wantStartLine := uint64(bytes.Count(canonical[:start], []byte("\n"))) + 1
		lineCount := uint64(bytes.Count(wantSources[index], []byte("\n"))) + 1
		if wantSources[index][len(wantSources[index])-1] == '\n' {
			lineCount--
		}
		if result.SourceStartLine != wantStartLine ||
			result.SourceEndLine != wantStartLine+lineCount-1 {
			t.Fatalf("function %d lines = %d:%d, want %d:%d", index,
				result.SourceStartLine, result.SourceEndLine,
				wantStartLine, wantStartLine+lineCount-1)
		}
	}
	var cFiles []string
	err = filepath.WalkDir(
		filepath.Join(repositoryRoot, "source-projects", runID),
		func(path string, entry os.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if !entry.IsDir() && strings.EqualFold(filepath.Ext(path), ".c") {
				cFiles = append(cFiles, path)
			}
			return nil
		},
	)
	if err != nil || len(cFiles) != 1 ||
		cFiles[0] != filepath.Join(repositoryRoot, filepath.FromSlash(project.CanonicalStorageKey)) {
		t.Fatalf("canonical C files = %v, error = %v", cFiles, err)
	}
}

func TestNativeResultLimitIncludesCanonicalProjectFraming(t *testing.T) {
	runID := "323e4567-e89b-42d3-a456-426614174003"
	index := ghidra.Index{Functions: []ghidra.Function{{
		Name: "near_limit", Address: "00401000", SourceSize: 96,
	}}}
	limits := JobLimits{
		MaxDurationSeconds: 30, MaxOutputBytes: 128,
		MaxArtifacts: 10, MaxStandardOutputBytes: 64,
	}
	if nativeResultWithinLimits(runID, index, limits) {
		t.Fatal("fragment-only size passed despite canonical header and banner overhead")
	}
	limits.MaxOutputBytes = 4096
	if !nativeResultWithinLimits(runID, index, limits) {
		t.Fatal("canonical project within the configured limit was rejected")
	}
}

func TestNativeProcessorRejectsBytecodePayloadBeforeRepository(t *testing.T) {
	repository := &nativeRepositoryStub{}
	processor, err := NewNativeProcessor(
		repository, &nativeAnalyzerStub{},
		&nativeActivityStub{},
		NativeProcessorConfig{
			RepositoryRoot: t.TempDir(), TaskWorkRoot: t.TempDir(),
			EngineVersion: "12.1.2",
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	payload := decompilePayload(decompileCreateRecord())
	payload.Engine.WorkerKind = TargetBytecode
	raw, _ := json.Marshal(payload)
	finish, err := processor.Process(
		context.Background(), nativeProcessingLease(raw, "native-test", 1),
	)
	if err != nil || finish.Outcome != queue.OutcomeDeterministicFailure ||
		repository.begun {
		t.Fatalf("finish=%+v err=%v begun=%v", finish, err, repository.begun)
	}
}

func TestNativeProcessorStalePublishCleansOnlyItsAttempt(t *testing.T) {
	repositoryRoot := t.TempDir()
	workRoot := t.TempDir()
	content := []byte("native-binary")
	digest := sha256.Sum256(content)
	key := "blobs/fixture/input.bin"
	source := filepath.Join(repositoryRoot, filepath.FromSlash(key))
	if err := os.MkdirAll(filepath.Dir(source), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(source, content, 0o600); err != nil {
		t.Fatal(err)
	}
	outputDir := t.TempDir()
	pseudo := []byte("int stale(void) { return 1; }\n")
	pseudoDigest := sha256.Sum256(pseudo)
	if err := os.WriteFile(
		filepath.Join(outputDir, "f-000000.c"), pseudo, 0o600,
	); err != nil {
		t.Fatal(err)
	}
	const (
		staleRun = "323e4567-e89b-42d3-a456-426614174003"
		newRun   = "423e4567-e89b-42d3-a456-426614174004"
		address  = "00401000"
	)
	newDirectory := filepath.Join(repositoryRoot, "source-projects", newRun, "src")
	if err := os.MkdirAll(newDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	newSource := filepath.Join(newDirectory, "source.c")
	if err := os.WriteFile(newSource, []byte("new-attempt"), 0o600); err != nil {
		t.Fatal(err)
	}
	analyzerCleaned := false
	repository := &nativeRepositoryStub{publishErr: ErrRequestConflict}
	processor, err := NewNativeProcessor(
		repository,
		&nativeAnalyzerStub{result: ghidra.Result{
			OutputDir: outputDir,
			Cleanup: func() error {
				analyzerCleaned = true
				return nil
			},
			Index: ghidra.Index{
				SchemaVersion: ghidra.IndexSchemaVersion,
				Format:        "ELF", Architecture: "x86:LE:64",
				Completeness: "complete", CandidateFunctionCount: 1,
				DecompiledFunctionCount: 1,
				Functions: []ghidra.Function{{
					Name: "stale", Address: address, SizeBytes: 16,
					SourceFile: "f-000000.c",
					SHA256:     hex.EncodeToString(pseudoDigest[:]),
					SourceSize: uint64(len(pseudo)),
				}},
			},
		}},
		&nativeActivityStub{},
		NativeProcessorConfig{
			RepositoryRoot: repositoryRoot, TaskWorkRoot: workRoot,
			EngineVersion: "12.1.2",
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	processor.newID = func() (string, error) { return staleRun, nil }
	payload := decompilePayload(decompileCreateRecord())
	payload.Target.StorageKey = key
	payload.Target.SHA256 = hex.EncodeToString(digest[:])
	payload.Target.SizeBytes = uint64(len(content))
	raw, _ := json.Marshal(payload)
	lease := nativeProcessingLease(raw, "stale-native", 2)
	_, err = processor.Process(context.Background(), lease)
	if !errors.Is(err, ErrRequestConflict) {
		t.Fatalf("Process() error = %v", err)
	}
	staleDirectory := filepath.Join(repositoryRoot, "source-projects", staleRun)
	if _, err := os.Lstat(staleDirectory); !os.IsNotExist(err) {
		t.Fatalf("stale attempt output remains: %v", err)
	}
	if value, err := os.ReadFile(newSource); err != nil ||
		string(value) != "new-attempt" {
		t.Fatalf("new attempt output changed: %q, %v", value, err)
	}
	if !analyzerCleaned {
		t.Fatal("analyzer work directory cleanup was not invoked")
	}
}

func TestNativeProcessorRejectsRepositorySourceSymlink(t *testing.T) {
	repositoryRoot := t.TempDir()
	workRoot := t.TempDir()
	content := []byte("native-binary")
	digest := sha256.Sum256(content)
	realSource := filepath.Join(repositoryRoot, "real.bin")
	if err := os.WriteFile(realSource, content, 0o600); err != nil {
		t.Fatal(err)
	}
	key := "blobs/input.bin"
	link := filepath.Join(repositoryRoot, filepath.FromSlash(key))
	if err := os.MkdirAll(filepath.Dir(link), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("../real.bin", link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	repository := &nativeRepositoryStub{}
	processor, err := NewNativeProcessor(
		repository, &nativeAnalyzerStub{},
		&nativeActivityStub{},
		NativeProcessorConfig{
			RepositoryRoot: repositoryRoot, TaskWorkRoot: workRoot,
			EngineVersion: "12.1.2",
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	processor.newID = func() (string, error) {
		return "323e4567-e89b-42d3-a456-426614174003", nil
	}
	payload := decompilePayload(decompileCreateRecord())
	payload.Target.StorageKey = key
	payload.Target.SHA256 = hex.EncodeToString(digest[:])
	payload.Target.SizeBytes = uint64(len(content))
	raw, _ := json.Marshal(payload)
	finish, err := processor.Process(
		context.Background(), nativeProcessingLease(raw, "native-test", 2),
	)
	if err != nil || finish.Outcome != queue.OutcomeDeterministicFailure ||
		repository.failed != "decompile_source_invalid" {
		t.Fatalf(
			"finish=%+v err=%v failed=%q", finish, err, repository.failed,
		)
	}
}

func TestNativeParameterCacheKeyBindsCanonicalOptionsAndAnalyzerIdentity(
	t *testing.T,
) {
	payload := decompilePayload(decompileCreateRecord())
	payload.Options, _ = canonicalOptions(
		json.RawMessage(`{"symbols":["public"],"analysis_mode":"default"}`),
	)
	identity := ghidra.Identity{
		EngineVersion:    "12.1.2",
		ParametersSHA256: strings.Repeat("a", 64),
	}
	first, err := nativeParameterCacheKey(payload, identity)
	if err != nil {
		t.Fatal(err)
	}
	reordered := payload
	reordered.Options, _ = canonicalOptions(
		json.RawMessage(`{"analysis_mode":"default","symbols":["public"]}`),
	)
	again, err := nativeParameterCacheKey(reordered, identity)
	if err != nil {
		t.Fatal(err)
	}
	if first != again || len(first) != 64 {
		t.Fatalf("parameter keys = %q / %q", first, again)
	}
	changedIdentity := identity
	changedIdentity.ParametersSHA256 = strings.Repeat("b", 64)
	changed, err := nativeParameterCacheKey(payload, changedIdentity)
	if err != nil {
		t.Fatal(err)
	}
	if changed == first {
		t.Fatal("analyzer parameter change retained cache key")
	}
}

func TestNewNativeProcessorRejectsAnalyzerVersionMismatch(t *testing.T) {
	_, err := NewNativeProcessor(
		&nativeRepositoryStub{},
		&nativeAnalyzerStub{identity: ghidra.Identity{
			EngineVersion:    "12.1.2",
			ParametersSHA256: strings.Repeat("a", 64),
		}},
		&nativeActivityStub{},
		NativeProcessorConfig{
			RepositoryRoot: t.TempDir(), TaskWorkRoot: t.TempDir(),
			EngineVersion: "12.1.3",
		},
	)
	if err == nil || !strings.Contains(err.Error(), "identity") {
		t.Fatalf("NewNativeProcessor() error = %v", err)
	}
}

func TestNativeProcessorClassifiesGhidraFailures(t *testing.T) {
	tests := []struct {
		name    string
		err     error
		outcome queue.Outcome
		code    string
	}{
		{
			name: "architecture", err: ghidra.ErrUnsupportedArchitecture,
			outcome: queue.OutcomeDeterministicFailure,
			code:    "ghidra_architecture_unsupported",
		},
		{
			name: "instruction", err: ghidra.ErrUnsupportedInstruction,
			outcome: queue.OutcomeDeterministicFailure,
			code:    "ghidra_instruction_unsupported",
		},
		{
			name: "script limit", err: ghidra.ErrScriptLimit,
			outcome: queue.OutcomeDeterministicFailure,
			code:    "ghidra_script_limit",
		},
		{
			name: "output limit", err: ghidra.ErrOutputLimit,
			outcome: queue.OutcomeDeterministicFailure,
			code:    "ghidra_output_limit",
		},
		{
			name: "invalid output", err: ghidra.ErrInvalidResult,
			outcome: queue.OutcomeDeterministicFailure,
			code:    "ghidra_output_invalid",
		},
		{
			name: "timeout", err: ghidra.ErrTimedOut,
			outcome: queue.OutcomeTransientFailure,
			code:    "ghidra_timeout",
		},
		{
			name: "execution", err: errors.New("process failed"),
			outcome: queue.OutcomeTransientFailure,
			code:    "ghidra_execution_failed",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			repositoryRoot := t.TempDir()
			workRoot := t.TempDir()
			content := []byte("native-binary")
			digest := sha256.Sum256(content)
			key := "blobs/fixture/input.bin"
			source := filepath.Join(repositoryRoot, filepath.FromSlash(key))
			if err := os.MkdirAll(filepath.Dir(source), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(source, content, 0o600); err != nil {
				t.Fatal(err)
			}
			repository := &nativeRepositoryStub{}
			activity := &nativeActivityStub{}
			processor, err := NewNativeProcessor(
				repository, &nativeAnalyzerStub{err: test.err},
				activity,
				NativeProcessorConfig{
					RepositoryRoot: repositoryRoot, TaskWorkRoot: workRoot,
					EngineVersion: "12.1.2",
				},
			)
			if err != nil {
				t.Fatal(err)
			}
			processor.newID = func() (string, error) {
				return "323e4567-e89b-42d3-a456-426614174003", nil
			}
			payload := decompilePayload(decompileCreateRecord())
			payload.Target.StorageKey = key
			payload.Target.SHA256 = hex.EncodeToString(digest[:])
			payload.Target.SizeBytes = uint64(len(content))
			raw, _ := json.Marshal(payload)
			finish, err := processor.Process(
				context.Background(),
				nativeProcessingLease(raw, "native-test", 2),
			)
			if err != nil || finish.Outcome != test.outcome ||
				finish.ErrorCode != test.code || repository.failed != test.code {
				t.Fatalf(
					"finish=%+v err=%v repository failure=%q",
					finish, err, repository.failed,
				)
			}
			if len(activity.inputs) == 0 {
				t.Fatal("failure did not emit a structured activity")
			}
			last := activity.inputs[len(activity.inputs)-1]
			var failure nativeActivityPayload
			if err := json.Unmarshal(last.Payload, &failure); err != nil ||
				last.EventType != "decompile.failed" ||
				failure.Phase != "failed" || failure.ErrorCode != test.code {
				t.Fatalf("failure activity = %#v payload=%+v err=%v", last, failure, err)
			}
		})
	}
}

func TestNativeProcessorDoesNotSwallowFailurePersistenceError(t *testing.T) {
	repositoryRoot := t.TempDir()
	workRoot := t.TempDir()
	content := []byte("native-binary")
	digest := sha256.Sum256(content)
	key := "blobs/fixture/input.bin"
	source := filepath.Join(repositoryRoot, filepath.FromSlash(key))
	if err := os.MkdirAll(filepath.Dir(source), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(source, content, 0o600); err != nil {
		t.Fatal(err)
	}
	persistErr := errors.New("failure row unavailable")
	repository := &nativeRepositoryStub{failErr: persistErr}
	processor, err := NewNativeProcessor(
		repository, &nativeAnalyzerStub{err: ghidra.ErrTimedOut},
		&nativeActivityStub{},
		NativeProcessorConfig{
			RepositoryRoot: repositoryRoot, TaskWorkRoot: workRoot,
			EngineVersion: "12.1.2",
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	processor.newID = func() (string, error) {
		return "323e4567-e89b-42d3-a456-426614174003", nil
	}
	payload := decompilePayload(decompileCreateRecord())
	payload.Target.StorageKey = key
	payload.Target.SHA256 = hex.EncodeToString(digest[:])
	payload.Target.SizeBytes = uint64(len(content))
	raw, _ := json.Marshal(payload)
	finish, err := processor.Process(
		context.Background(), nativeProcessingLease(raw, "native-test", 2),
	)
	if !errors.Is(err, persistErr) || !errors.Is(err, ghidra.ErrTimedOut) ||
		finish != (queue.FinishInput{}) {
		t.Fatalf("finish=%+v error=%v", finish, err)
	}
}

func TestNativeProcessorRejectsExplicitZeroFunctionResultAsSuccess(t *testing.T) {
	repositoryRoot := t.TempDir()
	workRoot := t.TempDir()
	content := []byte("native-binary")
	digest := sha256.Sum256(content)
	key := "blobs/fixture/input.bin"
	source := filepath.Join(repositoryRoot, filepath.FromSlash(key))
	if err := os.MkdirAll(filepath.Dir(source), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(source, content, 0o600); err != nil {
		t.Fatal(err)
	}
	repository := &nativeRepositoryStub{}
	processor, err := NewNativeProcessor(
		repository, &nativeAnalyzerStub{result: ghidra.Result{
			OutputDir: t.TempDir(), Index: ghidra.Index{
				SchemaVersion: ghidra.IndexSchemaVersion,
				Format:        "ELF", Architecture: "x86:LE:64",
				Completeness: "complete", CandidateFunctionCount: 0,
				DecompiledFunctionCount: 0,
				EntryPoints:             []ghidra.EntryPoint{}, Segments: []ghidra.Segment{},
				Functions: []ghidra.Function{}, CallEdges: []ghidra.CallEdge{},
			},
		}}, &nativeActivityStub{}, NativeProcessorConfig{
			RepositoryRoot: repositoryRoot, TaskWorkRoot: workRoot,
			EngineVersion: "12.1.2",
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	processor.newID = func() (string, error) {
		return "323e4567-e89b-42d3-a456-426614174003", nil
	}
	payload := decompilePayload(decompileCreateRecord())
	payload.Target.StorageKey = key
	payload.Target.SHA256 = hex.EncodeToString(digest[:])
	payload.Target.SizeBytes = uint64(len(content))
	raw, _ := json.Marshal(payload)
	finish, err := processor.Process(
		context.Background(), nativeProcessingLease(raw, "native-test", 2),
	)
	if err != nil || finish.Outcome != queue.OutcomeDeterministicFailure ||
		finish.ErrorCode != "ghidra_no_decompilable_functions" ||
		repository.publishParameterKey != "" ||
		repository.failed != "ghidra_no_decompilable_functions" {
		t.Fatalf("finish=%+v error=%v repository=%+v", finish, err, repository)
	}
}

func TestValidNativeResultEnvelopeAcceptsBoundedPartialOutput(t *testing.T) {
	t.Parallel()

	partial := ghidra.Index{
		SchemaVersion:           ghidra.IndexSchemaVersion,
		Completeness:            "partial",
		CandidateFunctionCount:  4,
		DecompiledFunctionCount: 3,
		Functions:               []ghidra.Function{{}, {}, {}},
	}
	if !validNativeResultEnvelope(partial) {
		t.Fatal("bounded partial native result was rejected")
	}
	partial.CandidateFunctionCount = 3
	if validNativeResultEnvelope(partial) {
		t.Fatal("partial result without omitted functions was accepted")
	}
}

func TestCopyVerifiedNativeSourceHonorsCancellationAndCleansPrivateCopy(t *testing.T) {
	repositoryRoot := t.TempDir()
	workRoot := t.TempDir()
	content := []byte("native-binary")
	digest := sha256.Sum256(content)
	key := "blobs/fixture/input.bin"
	source := filepath.Join(repositoryRoot, filepath.FromSlash(key))
	if err := os.MkdirAll(filepath.Dir(source), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(source, content, 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, _, err := copyVerifiedNativeSource(
		ctx, repositoryRoot, workRoot,
		queue.Lease{JobID: testJobID, Attempt: 1, FencingToken: 2},
		JobTarget{
			StorageKey: key, SHA256: hex.EncodeToString(digest[:]),
			SizeBytes: uint64(len(content)),
		},
	)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("copyVerifiedNativeSource() error = %v, want context.Canceled", err)
	}
	private := filepath.Join(
		workRoot, "native-input", testJobID+"-a1-f2",
	)
	if _, err := os.Lstat(private); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("cancelled private copy remains: %v", err)
	}
}

func nativeProcessingLease(
	payload json.RawMessage,
	owner string,
	fencingToken uint64,
) queue.Lease {
	attemptID := uint64(11)
	return queue.Lease{
		JobID: testJobID, TaskID: testTaskID, TaskAttemptID: &attemptID,
		Kind: queue.KindDecompile, Payload: payload,
		Attempt: 1, MaxAttempts: 3, FencingToken: fencingToken,
		Owner: owner,
	}
}

package decompile

import (
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

	"binaryscan/internal/bytecode"
	"binaryscan/internal/queue"
)

const testBytecodeParameterSHA = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"

type fakeBytecodeAnalyzer struct {
	identity BytecodeAnalyzerIdentity
	run      func(context.Context, bytecode.Request) (bytecode.Result, error)
	calls    int
}

type bytecodeActivityStub struct {
	inputs []queue.ActivityInput
}

func (stub *bytecodeActivityStub) TaskActivity(
	_ context.Context,
	_ queue.Lease,
	input queue.ActivityInput,
) error {
	stub.inputs = append(stub.inputs, input)
	return nil
}

func (analyzer *fakeBytecodeAnalyzer) Identity() BytecodeAnalyzerIdentity {
	return analyzer.identity
}

func (analyzer *fakeBytecodeAnalyzer) Analyze(
	ctx context.Context,
	request bytecode.Request,
) (bytecode.Result, error) {
	analyzer.calls++
	return analyzer.run(ctx, request)
}

type fakeBytecodeRunRepository struct {
	begin             func(context.Context) error
	beginErr          error
	publishErr        error
	invokeThenFail    bool
	beginCalls        int
	publishCalls      int
	failCalls         int
	published         []BytecodePublishedResult
	publishedProject  PublishedSourceProject
	identity          BytecodeRunIdentity
	cacheCandidate    BytecodeCacheCandidate
	cacheFound        bool
	cacheFindErr      error
	cachePublishErr   error
	cacheFindCalls    int
	cachePublishCalls int
}

func (repository *fakeBytecodeRunRepository) FindBytecodeCache(
	context.Context,
	queue.Lease,
	JobPayload,
	string,
	BytecodeRunIdentity,
) (BytecodeCacheCandidate, bool, error) {
	repository.cacheFindCalls++
	return repository.cacheCandidate, repository.cacheFound, repository.cacheFindErr
}

func (repository *fakeBytecodeRunRepository) PublishBytecodeCacheHit(
	_ context.Context,
	_ queue.Lease,
	_ JobPayload,
	_ string,
	_ BytecodeRunIdentity,
	_ BytecodeCacheCandidate,
	project PublishedSourceProject,
	values []BytecodePublishedResult,
) error {
	repository.cachePublishCalls++
	if repository.cachePublishErr == nil {
		repository.publishedProject = project
		repository.published = values
	}
	return repository.cachePublishErr
}

func (repository *fakeBytecodeRunRepository) BeginBytecodeRun(
	ctx context.Context,
	_ queue.Lease,
	_ JobPayload,
	_ string,
	identity BytecodeRunIdentity,
) error {
	repository.beginCalls++
	repository.identity = identity
	if repository.begin != nil {
		return repository.begin(ctx)
	}
	return repository.beginErr
}

func (repository *fakeBytecodeRunRepository) PublishBytecodeRun(
	ctx context.Context,
	_ queue.Lease,
	_ JobPayload,
	_ string,
	_ BytecodeRunIdentity,
	_ bytecode.Status,
	_ int,
	publish BytecodeResultPublisher,
) error {
	repository.publishCalls++
	if repository.publishErr != nil && !repository.invokeThenFail {
		return repository.publishErr
	}
	project, values, cleanup, err := publish(ctx)
	if err != nil {
		return err
	}
	if repository.publishErr != nil {
		if cleanup != nil {
			cleanup()
		}
		return repository.publishErr
	}
	repository.publishedProject = project
	repository.published = values
	return nil
}

func (repository *fakeBytecodeRunRepository) FailBytecodeRun(
	context.Context,
	queue.Lease,
	string,
	string,
	string,
) error {
	repository.failCalls++
	return nil
}

type bytecodeArtifactValidatorFunc func(
	context.Context,
	string,
	bytecode.Artifact,
) (bytecode.ArtifactValidation, error)

func (function bytecodeArtifactValidatorFunc) ValidateArtifact(
	ctx context.Context,
	workspace string,
	artifact bytecode.Artifact,
) (bytecode.ArtifactValidation, error) {
	return function(ctx, workspace, artifact)
}

func TestBytecodeProcessorPublishesVerifiedClassSource(t *testing.T) {
	repositoryRoot, workRoot, payload, lease := bytecodeProcessingFixture(t)
	repository := &fakeBytecodeRunRepository{}
	identity := bytecodeTestIdentity()
	analyzer := &fakeBytecodeAnalyzer{identity: identity}
	analyzer.run = func(
		_ context.Context,
		request bytecode.Request,
	) (bytecode.Result, error) {
		if request.Input.Format != bytecode.FormatClass ||
			request.Input.SHA256 != payload.Target.SHA256 ||
			request.Workspace == "" || request.ArtifactValidator == nil {
			t.Fatalf("analyzer request = %#v", request)
		}
		input, err := os.ReadFile(request.Input.Path)
		if err != nil || digestBytes(input) != payload.Target.SHA256 {
			t.Fatalf("private analyzer input: bytes=%q err=%v", input, err)
		}
		source := []byte("public class A { void run() {} }\n")
		artifactPath := filepath.Join(request.Workspace, "engine-out", "A.java")
		if err := os.MkdirAll(filepath.Dir(artifactPath), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(artifactPath, source, 0o600); err != nil {
			t.Fatal(err)
		}
		cacheKey, err := bytecode.CacheKey(
			request.Input.SHA256, request.Input.Format, identity.Engine,
			request.Arguments, request.Limits,
		)
		if err != nil {
			t.Fatal(err)
		}
		return bytecode.Result{
			SchemaVersion: bytecode.SchemaVersion, Engine: identity.Engine,
			Input: bytecode.Input{
				SHA256: request.Input.SHA256, Format: request.Input.Format,
				SizeBytes: request.Input.SizeBytes,
			},
			CacheKey: cacheKey, Status: bytecode.StatusComplete,
			Classes: []bytecode.ClassIndex{{
				Key: "class:A", Kind: bytecode.KindClass,
				BinaryName: "A", DisplayName: "A", SourceFile: "A.java",
				Language: "java", Status: bytecode.ClassSource,
				ArtifactIDs: []string{"source:A"},
				Methods: []bytecode.MethodIndex{{
					Key: "method:A.run", Name: "run",
					Source: &bytecode.SourceRange{StartLine: 1, EndLine: 1},
				}},
			}},
			Artifacts: []bytecode.Artifact{{
				ID: "source:A", Kind: bytecode.ArtifactSource,
				MediaType: "text/x-java-source", RelativePath: "engine-out/A.java",
				SHA256: digestBytes(source), SizeBytes: int64(len(source)),
				Validation: bytecode.ValidationContentVerified,
				Chunk:      bytecode.ArtifactChunk{SetID: "source:A", Index: 0, Count: 1},
				ClassKeys:  []string{"class:A"},
			}},
			ClassErrors: []bytecode.ClassError{}, Warnings: []string{},
			Execution: &bytecode.Execution{ExitCode: 0, OutputBytes: int64(len(source)), OutputFiles: 1},
		}, nil
	}
	processor := newTestBytecodeProcessor(
		t, repository, analyzer, repositoryRoot, workRoot,
	)
	finish, err := processor.Process(context.Background(), lease)
	if err != nil {
		t.Fatal(err)
	}
	if finish.Outcome != queue.OutcomeSucceeded || analyzer.calls != 1 ||
		repository.beginCalls != 1 || repository.publishCalls != 1 ||
		len(repository.published) != 1 {
		t.Fatalf(
			"finish=%+v analyzer=%d begin=%d publish=%d results=%d",
			finish, analyzer.calls, repository.beginCalls, repository.publishCalls,
			len(repository.published),
		)
	}
	published := repository.published[0]
	if published.SymbolKey != "class:A" || published.Status != "complete" ||
		published.Language != "java" || published.SizeBytes == 0 ||
		!json.Valid(published.Diagnostics) {
		t.Fatalf("published result = %#v", published)
	}
	stored, err := os.ReadFile(filepath.Join(
		repositoryRoot, filepath.FromSlash(published.StorageKey),
	))
	if err != nil || digestBytes(stored) != published.SHA256 ||
		!strings.Contains(string(stored), "class A") {
		t.Fatalf("stored source = %q, err=%v", stored, err)
	}
	if repository.identity.EngineName != "jvm-fallback" ||
		repository.identity.EngineVersion != "1.0.0" ||
		!sha256Pattern.MatchString(repository.identity.CacheParametersSHA) {
		t.Fatalf("run identity = %#v", repository.identity)
	}
	manifest, err := os.ReadFile(filepath.Join(
		repositoryRoot,
		filepath.FromSlash(repository.publishedProject.ManifestStorageKey),
	))
	if err != nil || !json.Valid(manifest) ||
		repository.publishedProject.SourceFileCount != 1 {
		t.Fatalf("published source project = %#v, manifest error = %v", repository.publishedProject, err)
	}
	activity := processor.activity.(*bytecodeActivityStub)
	phases := make([]string, 0, len(activity.inputs))
	for _, input := range activity.inputs {
		var payload bytecodeActivityPayload
		if err := json.Unmarshal(input.Payload, &payload); err != nil {
			t.Fatal(err)
		}
		if payload.Analyzer != EngineVineflower {
			t.Fatalf("activity analyzer = %q", payload.Analyzer)
		}
		phases = append(phases, payload.Phase)
	}
	if strings.Join(phases, ",") != "preparing,starting,running,publishing,completed" {
		t.Fatalf("activity phases = %v", phases)
	}
}

func TestBytecodeProcessorPublishesReadableBytecodeFallback(t *testing.T) {
	repositoryRoot, workRoot, _, lease := bytecodeProcessingFixture(t)
	repository := &fakeBytecodeRunRepository{}
	identity := bytecodeTestIdentity()
	analyzer := &fakeBytecodeAnalyzer{identity: identity}
	analyzer.run = func(_ context.Context, request bytecode.Request) (bytecode.Result, error) {
		listing := []byte("{\"class\":\"A\",\"methods\":[\"run()V\"]}\n")
		artifactPath := filepath.Join(request.Workspace, "A.bytecode.json")
		if err := os.WriteFile(artifactPath, listing, 0o600); err != nil {
			t.Fatal(err)
		}
		cacheKey, _ := bytecode.CacheKey(
			request.Input.SHA256, request.Input.Format, identity.Engine,
			request.Arguments, request.Limits,
		)
		return bytecode.Result{
			SchemaVersion: bytecode.SchemaVersion, Engine: identity.Engine,
			Input: bytecode.Input{
				SHA256: request.Input.SHA256, Format: request.Input.Format,
				SizeBytes: request.Input.SizeBytes,
			},
			CacheKey: cacheKey, Status: bytecode.StatusBytecodeOnly,
			Classes: []bytecode.ClassIndex{{
				Key: "class:A", Kind: bytecode.KindClass, BinaryName: "A",
				DisplayName: "A", Language: "java",
				Status:      bytecode.ClassBytecodeOnly,
				ArtifactIDs: []string{"bytecode:A"},
				Methods: []bytecode.MethodIndex{{
					Key: "method:A.run", Name: "run", Descriptor: "()V",
					Bytecode: &bytecode.BytecodeRange{OffsetBytes: 0, SizeBytes: 1},
				}},
			}},
			Artifacts: []bytecode.Artifact{{
				ID: "bytecode:A", Kind: bytecode.ArtifactBytecode,
				MediaType: "application/json", RelativePath: "A.bytecode.json",
				SHA256: digestBytes(listing), SizeBytes: int64(len(listing)),
				Validation: bytecode.ValidationHashVerified,
				Chunk:      bytecode.ArtifactChunk{SetID: "bytecode:A", Index: 0, Count: 1},
				ClassKeys:  []string{"class:A"},
			}},
			ClassErrors: []bytecode.ClassError{}, Warnings: []string{},
			Execution: &bytecode.Execution{ExitCode: 0},
		}, nil
	}
	processor := newTestBytecodeProcessor(
		t, repository, analyzer, repositoryRoot, workRoot,
	)
	finish, err := processor.Process(context.Background(), lease)
	if err != nil || finish.Outcome != queue.OutcomePartialSucceeded ||
		len(repository.published) != 1 {
		t.Fatalf("fallback process = (%+v, %v), rows=%d", finish, err, len(repository.published))
	}
	value := repository.published[0]
	if value.Status != "bytecode_only" || value.Language != "java-bytecode" ||
		!strings.HasSuffix(value.StorageKey, ".json") || value.SizeBytes == 0 {
		t.Fatalf("fallback result = %#v", value)
	}
	stored, readErr := os.ReadFile(filepath.Join(
		repositoryRoot, filepath.FromSlash(value.StorageKey),
	))
	if readErr != nil || !json.Valid(stored) {
		t.Fatalf("fallback artifact = %q, err=%v", stored, readErr)
	}
	var diagnostics struct {
		Methods []bytecode.MethodIndex `json:"methods"`
		Detail  string                 `json:"detail"`
	}
	if err := json.Unmarshal(value.Diagnostics, &diagnostics); err != nil ||
		len(diagnostics.Methods) != 1 || diagnostics.Methods[0].Descriptor != "()V" ||
		!strings.Contains(diagnostics.Detail, "bytecode_only") {
		t.Fatalf("fallback diagnostics = %+v, err=%v", diagnostics, err)
	}
	view := Result{SymbolKey: value.SymbolKey}
	applyDiagnostics(&view, value.Diagnostics)
	if view.SymbolKind != "class" || view.DisplayName != "A" ||
		view.GroupName != "Default package" || view.Location != "A" ||
		view.Signature != "A" || !strings.Contains(view.Detail, "indexed methods") {
		t.Fatalf("mapped fallback diagnostics = %+v", view)
	}
}

func TestPublishableBytecodeResultAcceptsFailureOnlyPartial(t *testing.T) {
	result := bytecode.Result{
		Status: bytecode.StatusPartial,
		Classes: []bytecode.ClassIndex{{
			Key: "class:Broken", Status: bytecode.ClassFailed,
		}},
		ClassErrors: []bytecode.ClassError{{
			ClassKey: "class:Broken", Code: "invalid_class",
			Message: "class header is truncated",
		}},
	}
	if !publishableBytecodeResult(result) {
		t.Fatal("failure-only partial result was rejected")
	}
}

func TestBytecodeProcessorCleansPublishedAttemptAfterStaleFence(t *testing.T) {
	repositoryRoot, workRoot, payload, lease := bytecodeProcessingFixture(t)
	repository := &fakeBytecodeRunRepository{
		publishErr: ErrRequestConflict, invokeThenFail: true,
	}
	identity := bytecodeTestIdentity()
	analyzer := &fakeBytecodeAnalyzer{identity: identity}
	analyzer.run = func(_ context.Context, request bytecode.Request) (bytecode.Result, error) {
		source := []byte("public class A {}\n")
		artifactPath := filepath.Join(request.Workspace, "A.java")
		if err := os.WriteFile(artifactPath, source, 0o600); err != nil {
			t.Fatal(err)
		}
		cacheKey, _ := bytecode.CacheKey(
			request.Input.SHA256, request.Input.Format, identity.Engine,
			request.Arguments, request.Limits,
		)
		return completeBytecodeTestResult(request, identity, cacheKey, source), nil
	}
	processor := newTestBytecodeProcessor(
		t, repository, analyzer, repositoryRoot, workRoot,
	)
	_, err := processor.Process(context.Background(), lease)
	if !errors.Is(err, ErrRequestConflict) || repository.failCalls != 1 {
		t.Fatalf("Process() error=%v fail calls=%d", err, repository.failCalls)
	}
	entries, readErr := os.ReadDir(filepath.Join(repositoryRoot, sourceProjectRootName))
	if readErr != nil || len(entries) != 0 {
		t.Fatalf("stale publication left entries=%v err=%v", entries, readErr)
	}
	_ = payload
}

func TestBytecodeProcessorReportsUnavailableAnalyzerTarget(t *testing.T) {
	repositoryRoot, workRoot, payload, lease := bytecodeProcessingFixture(t)
	payload.Engine.Target = EngineJADX
	payload.Target.Format = "apk"
	raw, _ := json.Marshal(payload)
	lease.Payload = raw
	repository := &fakeBytecodeRunRepository{}
	analyzer := &fakeBytecodeAnalyzer{
		identity: bytecodeTestIdentity(),
		run: func(context.Context, bytecode.Request) (bytecode.Result, error) {
			t.Fatal("unsupported target invoked analyzer")
			return bytecode.Result{}, nil
		},
	}
	processor := newTestBytecodeProcessor(
		t, repository, analyzer, repositoryRoot, workRoot,
	)
	finish, err := processor.Process(context.Background(), lease)
	if err != nil || finish.Outcome != queue.OutcomeDeterministicFailure ||
		finish.ErrorCode != "bytecode_engine_unavailable" ||
		repository.beginCalls != 0 {
		t.Fatalf("unsupported target = (%+v, %v), begin=%d", finish, err, repository.beginCalls)
	}
}

func TestBytecodeProcessorAttemptDeadlineIncludesBegin(t *testing.T) {
	repositoryRoot, workRoot, payload, lease := bytecodeProcessingFixture(t)
	payload.Limits.MaxDurationSeconds = 1
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	lease.Payload = raw
	repository := &fakeBytecodeRunRepository{
		begin: func(ctx context.Context) error {
			deadline, ok := ctx.Deadline()
			if !ok || time.Until(deadline) > time.Second {
				t.Fatalf("begin context deadline = %v, present=%t", deadline, ok)
			}
			<-ctx.Done()
			return ctx.Err()
		},
	}
	analyzer := &fakeBytecodeAnalyzer{
		identity: bytecodeTestIdentity(),
		run: func(context.Context, bytecode.Request) (bytecode.Result, error) {
			t.Fatal("timed out begin invoked analyzer")
			return bytecode.Result{}, nil
		},
	}
	processor := newTestBytecodeProcessor(
		t, repository, analyzer, repositoryRoot, workRoot,
	)
	finish, err := processor.Process(context.Background(), lease)
	if err != nil || finish.Outcome != queue.OutcomeTransientFailure ||
		finish.ErrorCode != "bytecode_timeout" || repository.beginCalls != 1 ||
		repository.publishCalls != 0 || repository.failCalls != 0 {
		t.Fatalf(
			"timed out begin = (%+v, %v), calls=(%d,%d,%d)",
			finish, err, repository.beginCalls, repository.publishCalls,
			repository.failCalls,
		)
	}
}

func TestBytecodeParameterAndResultCacheKeysAreIdentityBound(t *testing.T) {
	_, _, payload, _ := bytecodeProcessingFixture(t)
	identity := bytecodeTestIdentity()
	first, err := bytecodeParameterCacheKey(payload, identity)
	if err != nil {
		t.Fatal(err)
	}
	again, _ := bytecodeParameterCacheKey(payload, identity)
	if first != again || len(first) != 64 {
		t.Fatalf("parameter cache keys = %q / %q", first, again)
	}
	runIdentity := BytecodeRunIdentity{
		EngineName: identity.Engine.Name, EngineVersion: identity.Engine.Version,
		AnalyzerParametersSHA: identity.ParametersSHA256,
		CacheParametersSHA:    first,
		ReuseIdentitySHA:      strings.Repeat("c", 64),
	}
	resultKey := bytecodeResultCacheKey(payload, testJobID, runIdentity, "class:A")
	changed := runIdentity
	changed.EngineVersion = "1.0.1"
	if resultKey == bytecodeResultCacheKey(payload, testJobID, changed, "class:A") ||
		resultKey == bytecodeResultCacheKey(payload, testJobID, runIdentity, "class:B") ||
		resultKey == bytecodeResultCacheKey(payload, testRequestID, runIdentity, "class:A") {
		t.Fatal("bytecode result cache key ignored engine or symbol identity")
	}
}

func TestClassifyBytecodeFailureDoesNotRetryDeterministicJVMInputs(t *testing.T) {
	for _, test := range []struct {
		name string
		err  error
		code string
	}{
		{name: "archive limit", err: bytecode.ErrJVMArchiveLimit, code: "bytecode_archive_limit"},
		{name: "no classes", err: bytecode.ErrNoJVMClasses, code: "bytecode_no_classes"},
	} {
		t.Run(test.name, func(t *testing.T) {
			finish := classifyBytecodeFailure(test.err)
			if finish.Outcome != queue.OutcomeDeterministicFailure ||
				finish.ErrorCode != test.code {
				t.Fatalf("classification = %+v", finish)
			}
		})
	}
}

func newTestBytecodeProcessor(
	t *testing.T,
	repository BytecodeRunRepository,
	analyzer BytecodeAnalyzer,
	repositoryRoot string,
	workRoot string,
) *BytecodeProcessor {
	t.Helper()
	processor, err := NewBytecodeProcessor(
		repository, analyzer, &bytecodeActivityStub{},
		BytecodeProcessorConfig{
			RepositoryRoot: repositoryRoot, TaskWorkRoot: workRoot,
			EngineName: "jvm-fallback", EngineVersion: "1.0.0",
			ArtifactValidator: bytecodeArtifactValidatorFunc(func(
				context.Context, string, bytecode.Artifact,
			) (bytecode.ArtifactValidation, error) {
				return bytecode.ValidationContentVerified, nil
			}),
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	processor.newID = func() (string, error) {
		return "623e4567-e89b-42d3-a456-426614174006", nil
	}
	return processor
}

func TestSafeBytecodeProjectRelativePathBoundsCleanupDepth(t *testing.T) {
	minimumArchiveEntryBudget := defaultJobLimits.MaxArtifacts*
		maxBytecodeProjectPathComponents + 4
	if maxSourceProjectArchiveEntries < minimumArchiveEntryBudget {
		t.Fatalf(
			"archive entry budget %d cannot export publisher maximum %d",
			maxSourceProjectArchiveEntries, minimumArchiveEntryBudget,
		)
	}
	withinLimit := strings.Repeat("pkg/", maxBytecodeProjectPathComponents-1) + "Type.java"
	if got := safeBytecodeProjectRelativePath(withinLimit); got == "" {
		t.Fatal("path at component limit was rejected")
	}
	tooDeep := strings.Repeat("pkg/", maxBytecodeProjectPathComponents) + "Type.java"
	if got := safeBytecodeProjectRelativePath(tooDeep); got != "" {
		t.Fatalf("over-deep project path = %q, want fallback signal", got)
	}

	logicalPath, err := bytecodeProjectPath(bytecode.ClassIndex{
		BinaryName: strings.Repeat("pkg.", maxBytecodeProjectPathComponents) + "Type",
		SourceFile: "sources/" + tooDeep, Language: "java",
		Status: bytecode.ClassSource,
	}, nil, testResultID, map[string]struct{}{})
	if err != nil {
		t.Fatal(err)
	}
	want := "src/main/java/" + testResultID + ".java"
	if logicalPath != want {
		t.Fatalf("over-deep project path = %q, want %q", logicalPath, want)
	}
	tooLong := strings.Repeat("a", maxBytecodeProjectPathComponentBytes+1) + ".java"
	if got := safeBytecodeProjectRelativePath(tooLong); got != "" {
		t.Fatalf("overlong project filename = %q, want fallback signal", got)
	}

	nearLimit := strings.Repeat(strings.Repeat("p", 117)+"/", 8) + "Type.java"
	used := map[string]struct{}{}
	first, err := bytecodeProjectPath(bytecode.ClassIndex{
		BinaryName: "first.Type", SourceFile: "sources/" + nearLimit,
		Language: "java", Status: bytecode.ClassSource,
	}, nil, testResultID, used)
	if err != nil {
		t.Fatal(err)
	}
	second, err := bytecodeProjectPath(bytecode.ClassIndex{
		BinaryName: "second.Type", SourceFile: "sources/" + nearLimit,
		Language: "java", Status: bytecode.ClassSource,
	}, nil, testJobID, used)
	if err != nil {
		t.Fatal(err)
	}
	if len(first) > maxBytecodeProjectRelativePathBytes ||
		first == "src/main/java/"+testResultID+".java" ||
		second != "src/main/java/"+testJobID+".java" {
		t.Fatalf("near-limit collision paths = %q / %q", first, second)
	}
	samePrefixID := "223e4567-e89b-42d3-a456-426614174099"
	used = map[string]struct{}{}
	for _, resultID := range []string{testResultID, samePrefixID} {
		logicalPath, err := bytecodeProjectPath(bytecode.ClassIndex{
			BinaryName: strings.Repeat("x", maxBytecodeProjectPathComponentBytes+1),
			Language:   "java", Status: bytecode.ClassSource,
		}, nil, resultID, used)
		if err != nil {
			t.Fatalf("full-ID fallback for %s failed: %v", resultID, err)
		}
		if logicalPath != "src/main/java/"+resultID+".java" {
			t.Fatalf("full-ID fallback path = %q", logicalPath)
		}
	}
	used = map[string]struct{}{}
	upper, err := bytecodeProjectPath(bytecode.ClassIndex{
		BinaryName: "pkg.Foo", SourceFile: "sources/pkg/Foo.java",
		Language: "java", Status: bytecode.ClassSource,
	}, nil, testResultID, used)
	if err != nil {
		t.Fatal(err)
	}
	lower, err := bytecodeProjectPath(bytecode.ClassIndex{
		BinaryName: "pkg.foo", SourceFile: "sources/pkg/foo.java",
		Language: "java", Status: bytecode.ClassSource,
	}, nil, samePrefixID, used)
	if err != nil || strings.EqualFold(upper, lower) ||
		!strings.Contains(lower, samePrefixID) {
		t.Fatalf("case-only collision paths = %q / %q, error = %v", upper, lower, err)
	}
	if got := safeBytecodeProjectRelativePath("pkg/CON.java"); got != "pkg/_CON.java" {
		t.Fatalf("Windows-reserved project path = %q", got)
	}
}

func bytecodeProcessingFixture(
	t *testing.T,
) (string, string, JobPayload, queue.Lease) {
	t.Helper()
	repositoryRoot := t.TempDir()
	workRoot := t.TempDir()
	source := []byte("java class fixture")
	storageKey := filepath.ToSlash(filepath.Join(
		"blobs", "sha256", "aa", digestBytes(source),
	))
	sourcePath := filepath.Join(repositoryRoot, filepath.FromSlash(storageKey))
	if err := os.MkdirAll(filepath.Dir(sourcePath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(sourcePath, source, 0o600); err != nil {
		t.Fatal(err)
	}
	payload := JobPayload{
		SchemaVersion: JobPayloadVersion, RequestID: testRequestID,
		RequestedBy: 7, TaskID: testTaskID,
		Target: JobTarget{
			FileNodeID: "42", Class: TargetBytecode, Format: "java-class",
			StorageKey: storageKey, SHA256: digestBytes(source),
			SizeBytes: uint64(len(source)),
		},
		Engine:  JobEngine{Target: EngineVineflower, WorkerKind: TargetBytecode},
		Options: json.RawMessage(`{}`), Limits: defaultJobLimits,
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	attemptID := uint64(11)
	lease := queue.Lease{
		JobID: testJobID, TaskID: testTaskID, TaskAttemptID: &attemptID,
		Kind: queue.KindDecompile, Payload: raw, Attempt: 1, MaxAttempts: 3,
		FencingToken: 2, Owner: "bytecode-test",
	}
	return repositoryRoot, workRoot, payload, lease
}

func bytecodeTestIdentity() BytecodeAnalyzerIdentity {
	return BytecodeAnalyzerIdentity{
		Engine:           bytecode.Descriptor{Name: "jvm-fallback", Version: "1.0.0"},
		ParametersSHA256: testBytecodeParameterSHA,
		Arguments:        []string{"--fallback-mode=bytecode-only"},
		Targets:          []string{EngineVineflower},
	}
}

func completeBytecodeTestResult(
	request bytecode.Request,
	identity BytecodeAnalyzerIdentity,
	cacheKey string,
	source []byte,
) bytecode.Result {
	return bytecode.Result{
		SchemaVersion: bytecode.SchemaVersion, Engine: identity.Engine,
		Input: bytecode.Input{
			SHA256: request.Input.SHA256, Format: request.Input.Format,
			SizeBytes: request.Input.SizeBytes,
		},
		CacheKey: cacheKey, Status: bytecode.StatusComplete,
		Classes: []bytecode.ClassIndex{{
			Key: "class:A", Kind: bytecode.KindClass, BinaryName: "A",
			DisplayName: "A", Language: "java", Status: bytecode.ClassSource,
			ArtifactIDs: []string{"source:A"}, Methods: []bytecode.MethodIndex{},
		}},
		Artifacts: []bytecode.Artifact{{
			ID: "source:A", Kind: bytecode.ArtifactSource,
			MediaType: "text/x-java-source", RelativePath: "A.java",
			SHA256: digestBytes(source), SizeBytes: int64(len(source)),
			Validation: bytecode.ValidationContentVerified,
			Chunk:      bytecode.ArtifactChunk{SetID: "source:A", Index: 0, Count: 1},
			ClassKeys:  []string{"class:A"},
		}},
		ClassErrors: []bytecode.ClassError{}, Warnings: []string{},
		Execution: &bytecode.Execution{ExitCode: 0},
	}
}

func digestBytes(value []byte) string {
	digest := sha256.Sum256(value)
	return hex.EncodeToString(digest[:])
}

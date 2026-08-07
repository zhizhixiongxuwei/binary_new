package bytecode

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestExecuteProducesValidatedCompleteResult(t *testing.T) {
	request, sourceArtifact, validator := completeFixture(t)
	request.Arguments = []string{"--rename", "none"}
	output := completeOutput(sourceArtifact)
	output.Classes[0].Methods = []MethodIndex{
		{Key: "method:z", Name: "z", Descriptor: "()V"},
		{Key: "method:a", Name: "a", Descriptor: "()V"},
	}
	called := false
	engine := EngineFunc{
		EngineDescriptor: Descriptor{Name: "fixture", Version: "1.2.3"},
		SupportedFormats: []Format{FormatClass},
		Run: func(_ context.Context, received Request) (Output, error) {
			called = true
			received.Arguments[0] = "mutated"
			return output, nil
		},
	}
	result, err := Execute(context.Background(), engine, request)
	if err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	if !called || result.Status != StatusComplete ||
		result.SchemaVersion != SchemaVersion || len(result.CacheKey) != 64 ||
		result.Artifacts[0].Validation != ValidationContentVerified {
		t.Fatalf("Execute() result = %#v", result)
	}
	if request.Arguments[0] != "--rename" {
		t.Fatal("Execute() allowed engine to mutate caller arguments")
	}
	if result.Classes[0].Methods[0].Key != "method:a" ||
		result.Classes[0].Methods[1].Key != "method:z" {
		t.Fatalf("methods were not normalized: %#v", result.Classes[0].Methods)
	}
	output.Classes[0].DisplayName = "changed"
	output.Artifacts[0].ClassKeys[0] = "changed"
	if result.Classes[0].DisplayName != "A" ||
		result.Artifacts[0].ClassKeys[0] != "class:a" {
		t.Fatal("Execute() did not detach engine-owned result slices")
	}
	_ = validator
}

func TestExecuteDoesNotTreatExitZeroAsValidSource(t *testing.T) {
	request, _, _ := completeFixture(t)
	engine := EngineFunc{
		EngineDescriptor: Descriptor{Name: "fixture", Version: "1"},
		SupportedFormats: []Format{FormatClass},
		Run: func(context.Context, Request) (Output, error) {
			return Output{
				Status:    StatusComplete,
				Execution: &Execution{ExitCode: 0},
			}, nil
		},
	}
	_, err := Execute(context.Background(), engine, request)
	if !errors.Is(err, ErrInvalidResult) {
		t.Fatalf("exit-zero empty result error = %v", err)
	}
}

func TestExecuteBindsVerifiedInputSnapshotBeforeEngine(t *testing.T) {
	request, artifact, _ := completeFixture(t)
	originalPath := request.Input.Path
	original := []byte("class bytes")
	engine := EngineFunc{
		EngineDescriptor: Descriptor{Name: "fixture", Version: "1"},
		SupportedFormats: []Format{FormatClass},
		Run: func(_ context.Context, received Request) (Output, error) {
			if received.Input.Path != "" {
				return Output{}, errors.New("engine received caller path")
			}
			if err := os.WriteFile(originalPath, []byte("changed-now"), 0o600); err != nil {
				return Output{}, err
			}
			reader, err := received.Input.VerifiedReader()
			if err != nil {
				return Output{}, err
			}
			payload, err := io.ReadAll(reader)
			if err != nil {
				return Output{}, err
			}
			if string(payload) != string(original) {
				return Output{}, errors.New("verified snapshot bytes changed")
			}
			return completeOutput(artifact), nil
		},
	}
	result, err := Execute(context.Background(), engine, request)
	if err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	if result.Status != StatusComplete || result.Input.Path != originalPath {
		t.Fatalf("Execute() result input = %#v", result.Input)
	}
	if _, err := result.Input.VerifiedReader(); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("verified handle escaped Execute: %v", err)
	}
}

func TestExecuteRejectsDeclaredDigestThatDoesNotMatchInput(t *testing.T) {
	request, artifact, _ := completeFixture(t)
	request.Input.SHA256 = strings.Repeat("f", 64)
	called := false
	engine := EngineFunc{
		EngineDescriptor: Descriptor{Name: "fixture", Version: "1"},
		SupportedFormats: []Format{FormatClass},
		Run: func(context.Context, Request) (Output, error) {
			called = true
			return completeOutput(artifact), nil
		},
	}
	_, err := Execute(context.Background(), engine, request)
	if !errors.Is(err, ErrInvalidRequest) || called {
		t.Fatalf("Execute() error = %v, engine called = %v", err, called)
	}
}

func TestExecuteIgnoresEngineClaimedArtifactValidation(t *testing.T) {
	request, artifact, _ := completeFixture(t)
	request.ArtifactValidator = nil
	artifact.Validation = ValidationContentVerified
	engine := fixedEngine(FormatClass, completeOutput(artifact))
	_, err := Execute(context.Background(), engine, request)
	if !errors.Is(err, ErrInvalidResult) {
		t.Fatalf("unverified source error = %v", err)
	}
}

func TestExecuteRejectsSourceInspectorFailureDespiteExitZero(t *testing.T) {
	request, artifact, _ := completeFixture(t)
	validator, err := NewFileArtifactValidator(map[string]SourceInspector{
		"text/x-java-source": SourceInspectorFunc(func(
			context.Context,
			io.Reader,
		) error {
			return errors.New("invalid Java source")
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	request.ArtifactValidator = validator
	_, err = Execute(
		context.Background(), fixedEngine(FormatClass, completeOutput(artifact)), request,
	)
	if !errors.Is(err, ErrInvalidResult) {
		t.Fatalf("invalid source error = %v", err)
	}
}

func TestExecuteReturnsUnsupportedWithoutCallingEngine(t *testing.T) {
	request, _, _ := completeFixture(t)
	request.Input.Format = FormatAPK
	called := false
	engine := EngineFunc{
		EngineDescriptor: Descriptor{Name: "fixture", Version: "1"},
		SupportedFormats: []Format{FormatClass},
		Run: func(context.Context, Request) (Output, error) {
			called = true
			return Output{}, nil
		},
	}
	result, err := Execute(context.Background(), engine, request)
	if err != nil || called || result.Status != StatusUnsupported ||
		result.Classes == nil || result.Artifacts == nil ||
		result.ClassErrors == nil || result.Warnings == nil {
		t.Fatalf("unsupported result = %#v, called=%v, error=%v", result, called, err)
	}
}

func TestExecuteAcceptsPartialPerClassFailures(t *testing.T) {
	request, artifact, _ := completeFixture(t)
	output := completeOutput(artifact)
	output.Status = StatusPartial
	output.Classes = append(output.Classes, ClassIndex{
		Key: "class:b", Kind: KindClass, BinaryName: "B",
		DisplayName: "B", Language: "java", Status: ClassFailed,
		ArtifactIDs: []string{}, Methods: []MethodIndex{},
	})
	output.ClassErrors = []ClassError{{
		ClassKey: "class:b", Code: "malformed_constant_pool",
		Message: "constant pool entry is truncated",
	}}
	result, err := Execute(
		context.Background(), fixedEngine(FormatClass, output), request,
	)
	if err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	if result.Status != StatusPartial || len(result.ClassErrors) != 1 ||
		result.ClassErrors[0].ClassKey != "class:b" {
		t.Fatalf("partial result = %#v", result)
	}
}

func TestExecuteAcceptsPYCBytecodeOnlyModule(t *testing.T) {
	workspace := t.TempDir()
	input := []byte("pyc fixture")
	inputPath := filepath.Join(workspace, "module.pyc")
	if err := os.WriteFile(inputPath, input, 0o600); err != nil {
		t.Fatal(err)
	}
	bytecode := []byte(`{"instructions":["LOAD_CONST","RETURN_VALUE"]}`)
	if err := os.WriteFile(filepath.Join(workspace, "module.bytecode.json"), bytecode, 0o600); err != nil {
		t.Fatal(err)
	}
	validator, err := NewFileArtifactValidator(nil)
	if err != nil {
		t.Fatal(err)
	}
	request := Request{
		Input:     Input{Path: inputPath, SHA256: digestOf(input), Format: FormatPYC, SizeBytes: int64(len(input))},
		Workspace: workspace, ArtifactValidator: validator,
	}
	artifact := artifactFor(
		"bytecode-module", ArtifactBytecode, "application/json",
		"module.bytecode.json", bytecode, "module:fixture",
	)
	output := Output{
		Status: StatusBytecodeOnly,
		Classes: []ClassIndex{{
			Key: "module:fixture", Kind: KindModule,
			BinaryName: "fixture", DisplayName: "fixture", Language: "python",
			Status: ClassBytecodeOnly, ArtifactIDs: []string{artifact.ID},
			Methods: []MethodIndex{{
				Key: "method:fixture.main", Name: "main",
				QualifiedName: "fixture.main",
				Bytecode:      &BytecodeRange{OffsetBytes: 0, SizeBytes: 2},
			}},
		}},
		Artifacts: []Artifact{artifact}, ClassErrors: []ClassError{}, Warnings: []string{},
		Execution: &Execution{ExitCode: 0},
	}
	result, err := Execute(
		context.Background(), fixedEngine(FormatPYC, output), request,
	)
	if err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	if result.Status != StatusBytecodeOnly || result.Classes[0].Kind != KindModule ||
		result.Artifacts[0].Validation != ValidationHashVerified {
		t.Fatalf("bytecode-only result = %#v", result)
	}
}

func TestOutputStatusSemanticsAndIndexesAreFailClosed(t *testing.T) {
	valid := validatedCompleteOutput()
	tests := []struct {
		name   string
		mutate func(*Output)
	}{
		{"complete with error", func(output *Output) {
			output.ClassErrors = []ClassError{{ClassKey: "class:a", Code: "warning", Message: "not complete"}}
		}},
		{"partial without failure", func(output *Output) { output.Status = StatusPartial }},
		{"bytecode only with source", func(output *Output) { output.Status = StatusBytecodeOnly }},
		{"duplicate method", func(output *Output) {
			output.Classes[0].Methods = append(output.Classes[0].Methods, output.Classes[0].Methods[0])
		}},
		{"bad source range", func(output *Output) {
			output.Classes[0].Methods[0].Source = &SourceRange{StartLine: 9, EndLine: 2}
		}},
		{"missing reciprocal link", func(output *Output) { output.Artifacts[0].ClassKeys = nil }},
		{"incomplete chunk set", func(output *Output) { output.Artifacts[0].Chunk.Count = 2 }},
		{"failed class without error", func(output *Output) {
			output.Status = StatusBytecodeOnly
			output.Classes[0].Status = ClassFailed
			output.Classes[0].ArtifactIDs = nil
			output.Artifacts = nil
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidate := deepCopyAndNormalizeOutput(valid)
			test.mutate(&candidate)
			if err := validateOutput(candidate, mustLimits(t)); !errors.Is(err, ErrInvalidResult) {
				t.Fatalf("validateOutput() error = %v", err)
			}
		})
	}
}

func TestExecuteEnforcesTimeoutAndRejectsTypedNilEngine(t *testing.T) {
	request, _, _ := completeFixture(t)
	request.Limits.MaxDuration = 20 * time.Millisecond
	engine := EngineFunc{
		EngineDescriptor: Descriptor{Name: "fixture", Version: "1"},
		SupportedFormats: []Format{FormatClass},
		Run: func(ctx context.Context, _ Request) (Output, error) {
			<-ctx.Done()
			return Output{}, ctx.Err()
		},
	}
	if _, err := Execute(context.Background(), engine, request); !errors.Is(err, ErrTimedOut) {
		t.Fatalf("timeout error = %v", err)
	}

	var nilEngine *pointerEngine
	if _, err := Execute(context.Background(), nilEngine, request); !errors.Is(err, ErrInvalidConfiguration) {
		t.Fatalf("typed nil engine error = %v", err)
	}
}

func TestExecuteRejectsInvalidRequestAndEngineResultLimits(t *testing.T) {
	request, artifact, _ := completeFixture(t)
	request.Input.SizeBytes++
	if _, err := Execute(
		context.Background(), fixedEngine(FormatClass, completeOutput(artifact)), request,
	); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("input size error = %v", err)
	}

	request, artifact, _ = completeFixture(t)
	request.Limits.MaxMethods = 1
	output := completeOutput(artifact)
	output.Classes[0].Methods = []MethodIndex{
		{Key: "method:a", Name: "a"}, {Key: "method:b", Name: "b"},
	}
	if _, err := Execute(
		context.Background(), fixedEngine(FormatClass, output), request,
	); !errors.Is(err, ErrInvalidResult) {
		t.Fatalf("method limit error = %v", err)
	}
}

func TestExecutePrevalidatesArtifactStructureBeforeReadingArtifacts(t *testing.T) {
	tests := []struct {
		name   string
		limits Limits
		mutate func(*Output)
	}{
		{
			name: "artifact count", limits: Limits{MaxArtifacts: 1},
			mutate: func(output *Output) {
				second := output.Artifacts[0]
				second.ID = "source-b"
				second.RelativePath = "missing.java"
				second.Chunk.SetID = "source-b"
				second.ClassKeys = []string{}
				output.Artifacts = append(output.Artifacts, second)
			},
		},
		{
			name: "duplicate relative path",
			mutate: func(output *Output) {
				second := output.Artifacts[0]
				second.ID = "source-b"
				second.Chunk.SetID = "source-b"
				second.ClassKeys = []string{}
				output.Artifacts = append(output.Artifacts, second)
			},
		},
		{
			name: "declared bytes", limits: Limits{MaxArtifactBytes: 1},
			mutate: func(*Output) {},
		},
		{
			name: "method count", limits: Limits{MaxMethods: 1},
			mutate: func(output *Output) {
				output.Classes[0].Methods = append(
					output.Classes[0].Methods,
					MethodIndex{Key: "method:b", Name: "b"},
				)
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request, artifact, validator := completeFixture(t)
			counter := &countingArtifactValidator{delegate: validator}
			request.ArtifactValidator = counter
			request.Limits = test.limits
			output := completeOutput(artifact)
			test.mutate(&output)
			_, err := Execute(
				context.Background(), fixedEngine(FormatClass, output), request,
			)
			if !errors.Is(err, ErrInvalidResult) {
				t.Fatalf("Execute() error = %v", err)
			}
			if counter.calls != 0 {
				t.Fatalf("artifact validator called %d times before structural rejection", counter.calls)
			}
		})
	}
}

func TestExecuteDeepCopiesNestedEngineOutputBeforePublishing(t *testing.T) {
	request, artifact, _ := completeFixture(t)
	sourceRange := &SourceRange{StartLine: 1, EndLine: 2}
	bytecodeRange := &BytecodeRange{OffsetBytes: 3, SizeBytes: 4}
	output := completeOutput(artifact)
	output.Classes[0].Methods[0].Source = sourceRange
	output.Classes[0].Methods[0].Bytecode = bytecodeRange
	result, err := Execute(
		context.Background(), fixedEngine(FormatClass, output), request,
	)
	if err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	resultMethod := &result.Classes[0].Methods[0]
	if resultMethod.Source == sourceRange || resultMethod.Bytecode == bytecodeRange {
		t.Fatal("Execute() retained engine-owned nested pointers")
	}

	var wait sync.WaitGroup
	start := make(chan struct{})
	wait.Add(2)
	go func() {
		defer wait.Done()
		<-start
		for index := uint32(0); index < 1000; index++ {
			sourceRange.StartLine = index + 10
			bytecodeRange.OffsetBytes = uint64(index + 20)
			output.Artifacts[0].ClassKeys[0] = "class:mutated"
			output.Classes[0].ArtifactIDs[0] = "artifact:mutated"
		}
	}()
	go func() {
		defer wait.Done()
		<-start
		for index := 0; index < 1000; index++ {
			if resultMethod.Source.StartLine != 1 ||
				resultMethod.Bytecode.OffsetBytes != 3 ||
				result.Artifacts[0].ClassKeys[0] != "class:a" ||
				result.Classes[0].ArtifactIDs[0] != "source-a" {
				t.Errorf("published result changed after engine mutation")
				return
			}
		}
	}()
	close(start)
	wait.Wait()
}

func TestExecuteDoesNotPublishArtifactSliceRetainedByValidator(t *testing.T) {
	request, artifact, validator := completeFixture(t)
	retaining := &retainingArtifactValidator{delegate: validator}
	request.ArtifactValidator = retaining
	result, err := Execute(
		context.Background(), fixedEngine(FormatClass, completeOutput(artifact)), request,
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(retaining.classKeys) != 1 {
		t.Fatalf("validator retained %#v", retaining.classKeys)
	}
	var wait sync.WaitGroup
	wait.Add(2)
	start := make(chan struct{})
	go func() {
		defer wait.Done()
		<-start
		for index := 0; index < 1000; index++ {
			retaining.classKeys[0] = "class:validator-mutated"
		}
	}()
	go func() {
		defer wait.Done()
		<-start
		for index := 0; index < 1000; index++ {
			if result.Artifacts[0].ClassKeys[0] != "class:a" {
				t.Errorf("validator retained a slice published in Result")
				return
			}
		}
	}()
	close(start)
	wait.Wait()
	if result.Artifacts[0].ClassKeys[0] != "class:a" {
		t.Fatal("validator retained a slice published in Result")
	}
}

func TestExecuteRechecksContextAfterSupportsAndArtifactValidation(t *testing.T) {
	t.Run("supports", func(t *testing.T) {
		request, _, _ := completeFixture(t)
		ctx, cancel := context.WithCancel(context.Background())
		engine := &cancelingSupportsEngine{cancel: cancel}
		_, err := Execute(ctx, engine, request)
		if !errors.Is(err, context.Canceled) || engine.decompileCalled {
			t.Fatalf("Execute() error = %v, decompile=%v", err, engine.decompileCalled)
		}
	})
	t.Run("artifact validator", func(t *testing.T) {
		request, artifact, validator := completeFixture(t)
		ctx, cancel := context.WithCancel(context.Background())
		request.ArtifactValidator = ArtifactValidatorFunc(func(
			ctx context.Context,
			workspace string,
			artifact Artifact,
		) (ArtifactValidation, error) {
			validation, err := validator.ValidateArtifact(ctx, workspace, artifact)
			cancel()
			return validation, err
		})
		_, err := Execute(
			ctx, fixedEngine(FormatClass, completeOutput(artifact)), request,
		)
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Execute() error = %v", err)
		}
	})
}

type pointerEngine struct{}

type countingArtifactValidator struct {
	calls    int
	delegate ArtifactValidator
}

type retainingArtifactValidator struct {
	delegate  ArtifactValidator
	classKeys []string
}

func (validator *retainingArtifactValidator) ValidateArtifact(
	ctx context.Context,
	workspace string,
	artifact Artifact,
) (ArtifactValidation, error) {
	validator.classKeys = artifact.ClassKeys
	return validator.delegate.ValidateArtifact(ctx, workspace, artifact)
}

type ArtifactValidatorFunc func(
	context.Context,
	string,
	Artifact,
) (ArtifactValidation, error)

func (function ArtifactValidatorFunc) ValidateArtifact(
	ctx context.Context,
	workspace string,
	artifact Artifact,
) (ArtifactValidation, error) {
	return function(ctx, workspace, artifact)
}

type cancelingSupportsEngine struct {
	cancel          context.CancelFunc
	decompileCalled bool
}

func (*cancelingSupportsEngine) Descriptor() Descriptor {
	return Descriptor{Name: "canceling", Version: "1"}
}

func (engine *cancelingSupportsEngine) Supports(Format) bool {
	engine.cancel()
	return true
}

func (engine *cancelingSupportsEngine) Decompile(
	context.Context,
	Request,
) (Output, error) {
	engine.decompileCalled = true
	return Output{}, nil
}

func (validator *countingArtifactValidator) ValidateArtifact(
	ctx context.Context,
	workspace string,
	artifact Artifact,
) (ArtifactValidation, error) {
	validator.calls++
	return validator.delegate.ValidateArtifact(ctx, workspace, artifact)
}

func (*pointerEngine) Descriptor() Descriptor { return Descriptor{Name: "nil", Version: "1"} }
func (*pointerEngine) Supports(Format) bool   { return true }
func (*pointerEngine) Decompile(context.Context, Request) (Output, error) {
	return Output{}, nil
}

func fixedEngine(format Format, output Output) Engine {
	return EngineFunc{
		EngineDescriptor: Descriptor{Name: "fixture", Version: "1"},
		SupportedFormats: []Format{format},
		Run:              func(context.Context, Request) (Output, error) { return output, nil },
	}
}

func completeFixture(t *testing.T) (Request, Artifact, *FileArtifactValidator) {
	t.Helper()
	workspace := t.TempDir()
	input := []byte("class bytes")
	inputPath := filepath.Join(workspace, "A.class")
	if err := os.WriteFile(inputPath, input, 0o600); err != nil {
		t.Fatal(err)
	}
	source := []byte("public class A { void a() {} }\n")
	if err := os.WriteFile(filepath.Join(workspace, "A.java"), source, 0o600); err != nil {
		t.Fatal(err)
	}
	validator, err := NewFileArtifactValidator(map[string]SourceInspector{
		"text/x-java-source": SourceInspectorFunc(func(
			_ context.Context,
			reader io.Reader,
		) error {
			payload, err := io.ReadAll(reader)
			if err != nil {
				return err
			}
			if !strings.Contains(string(payload), "class A") {
				return errors.New("class declaration missing")
			}
			return nil
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	artifact := artifactFor(
		"source-a", ArtifactSource, "text/x-java-source", "A.java", source, "class:a",
	)
	request := Request{
		Input: Input{
			Path: inputPath, SHA256: digestOf(input), Format: FormatClass,
			SizeBytes: int64(len(input)),
		},
		Workspace: workspace, ArtifactValidator: validator,
	}
	return request, artifact, validator
}

func completeOutput(artifact Artifact) Output {
	return Output{
		Status: StatusComplete,
		Classes: []ClassIndex{{
			Key: "class:a", Kind: KindClass, BinaryName: "A", DisplayName: "A",
			SourceFile: "A.java", Language: "java", Status: ClassSource,
			ArtifactIDs: []string{artifact.ID},
			Methods: []MethodIndex{{
				Key: "method:a", Name: "a", QualifiedName: "A.a",
				Descriptor: "()V", Source: &SourceRange{StartLine: 1, EndLine: 1},
			}},
		}},
		Artifacts: []Artifact{artifact}, ClassErrors: []ClassError{}, Warnings: []string{},
		Execution: &Execution{ExitCode: 0, DurationMS: 10, OutputBytes: artifact.SizeBytes, OutputFiles: 1},
	}
}

func validatedCompleteOutput() Output {
	content := []byte("public class A {}")
	artifact := artifactFor(
		"source-a", ArtifactSource, "text/x-java-source", "A.java", content, "class:a",
	)
	artifact.Validation = ValidationContentVerified
	return completeOutput(artifact)
}

func mustLimits(t *testing.T) Limits {
	t.Helper()
	limits, err := normalizeLimits(Limits{})
	if err != nil {
		t.Fatal(err)
	}
	return limits
}

func digestOf(payload []byte) string {
	digest := sha256.Sum256(payload)
	return hex.EncodeToString(digest[:])
}

package bytecode

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

type sourceExecutorFunc func(context.Context, ProcessInvocation) (ProcessResult, error)

func (function sourceExecutorFunc) Run(
	ctx context.Context,
	invocation ProcessInvocation,
) (ProcessResult, error) {
	return function(ctx, invocation)
}

func TestJVMSourceEnginePublishesVineflowerJava(t *testing.T) {
	workRoot := t.TempDir()
	engine := &JVMSourceEngine{
		workRoot: workRoot,
		descriptor: Descriptor{
			Name: JVMSourceEngineName, Version: "vf1.12.0-cfr0.152",
		},
	}
	engine.runner = sourceExecutorFunc(func(
		_ context.Context,
		invocation ProcessInvocation,
	) (ProcessResult, error) {
		if len(invocation.Arguments) != 3 || invocation.Arguments[0] != "vineflower" {
			t.Fatalf("unexpected invocation: %#v", invocation)
		}
		writeSourceFixture(t, workRoot, invocation, "org/example/Demo.java")
		return ProcessResult{ExitCode: 0, OutputBytes: 42, OutputFiles: 3}, nil
	})

	result := executeSourceFixture(t, workRoot, engine, FormatJAR)
	if result.Status != StatusComplete || len(result.Classes) != 1 ||
		result.Classes[0].BinaryName != "org.example.Demo" ||
		result.Classes[0].Status != ClassSource || len(result.Artifacts) != 1 ||
		result.Artifacts[0].Validation != ValidationContentVerified {
		t.Fatalf("unexpected source result: %#v", result)
	}
}

func TestJVMSourceEngineFallsBackToCFR(t *testing.T) {
	workRoot := t.TempDir()
	calls := 0
	engine := &JVMSourceEngine{
		workRoot: workRoot,
		descriptor: Descriptor{
			Name: JVMSourceEngineName, Version: "vf1.12.0-cfr0.152",
		},
	}
	engine.runner = sourceExecutorFunc(func(
		_ context.Context,
		invocation ProcessInvocation,
	) (ProcessResult, error) {
		calls++
		if calls == 1 {
			return ProcessResult{ExitCode: 1}, nil
		}
		if invocation.Arguments[0] != "cfr" {
			t.Fatalf("fallback invocation = %#v", invocation.Arguments)
		}
		writeSourceFixture(t, workRoot, invocation, "Fallback.java")
		return ProcessResult{ExitCode: 0, OutputBytes: 21, OutputFiles: 1}, nil
	})

	result := executeSourceFixture(t, workRoot, engine, FormatClass)
	if calls != 2 || result.Status != StatusComplete || len(result.Warnings) != 1 ||
		result.Classes[0].BinaryName != "Fallback" {
		t.Fatalf("unexpected CFR fallback result: calls=%d result=%#v", calls, result)
	}
}

func TestJADXSourceEnginePublishesAPKJava(t *testing.T) {
	workRoot := t.TempDir()
	engine := &JADXSourceEngine{
		workRoot:   workRoot,
		descriptor: Descriptor{Name: JADXSourceEngineName, Version: "1.5.6"},
	}
	engine.runner = sourceExecutorFunc(func(
		_ context.Context,
		invocation ProcessInvocation,
	) (ProcessResult, error) {
		if invocation.Arguments[0] != "jadx" {
			t.Fatalf("unexpected JADX invocation: %#v", invocation)
		}
		writeSourceFixture(t, workRoot, invocation, "sources/app/MainActivity.java")
		return ProcessResult{ExitCode: 0, OutputBytes: 64, OutputFiles: 4}, nil
	})

	result := executeSourceFixture(t, workRoot, engine, FormatAPK)
	if result.Status != StatusComplete || len(result.Classes) != 1 ||
		result.Classes[0].BinaryName != "app.MainActivity" ||
		result.Classes[0].Language != "java" {
		t.Fatalf("unexpected JADX result: %#v", result)
	}
}

func executeSourceFixture(
	t *testing.T,
	workRoot string,
	engine Engine,
	format Format,
) Result {
	t.Helper()
	workspace := filepath.Join(workRoot, "workspace")
	if err := os.Mkdir(workspace, 0o700); err != nil {
		t.Fatal(err)
	}
	input := filepath.Join(workspace, "fixture.bin")
	payload := []byte("fixture bytecode input")
	if err := os.WriteFile(input, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(payload)
	validator, err := NewFileArtifactValidator(map[string]SourceInspector{
		"text/x-java-source":   SourceInspectorFunc(InspectUTF8Source),
		"text/x-kotlin-source": SourceInspectorFunc(InspectUTF8Source),
	})
	if err != nil {
		t.Fatal(err)
	}
	result, err := Execute(context.Background(), engine, Request{
		Input: Input{
			Path: input, SHA256: hex.EncodeToString(digest[:]),
			Format: format, SizeBytes: int64(len(payload)),
		},
		Workspace: workspace, ArtifactValidator: validator,
	})
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func writeSourceFixture(
	t *testing.T,
	workRoot string,
	invocation ProcessInvocation,
	name string,
) {
	t.Helper()
	output := filepath.Join(workRoot, invocation.OutputDirectory)
	target := filepath.Join(output, filepath.FromSlash(name))
	if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, []byte("package fixture;\npublic class Demo {}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
}

package analyzers

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

type adapterStub struct {
	called bool
}

func (*adapterStub) Name() string    { return "stub" }
func (*adapterStub) Version() string { return "1.0.0" }
func (a *adapterStub) Analyze(context.Context, Input) (Result, error) {
	a.called = true
	return Result{Status: StatusSucceeded}, nil
}

func TestExecuteHonorsCancelledContextBeforeAdapter(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	adapter := &adapterStub{}
	_, err := Execute(ctx, adapter, validInput())
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Execute() error = %v, want context.Canceled", err)
	}
	if adapter.called {
		t.Fatal("adapter was called after context cancellation")
	}
}

func TestInputRejectsUnsafeStorageKey(t *testing.T) {
	input := validInput()
	input.SourceStorageKey = "../../etc/passwd"
	if err := input.Validate(); err == nil {
		t.Fatal("Validate() error = nil, want unsafe storage key error")
	}
}

func TestResultEnforcesArtifactByteLimit(t *testing.T) {
	result := Result{
		Status: StatusSucceeded,
		Artifacts: []Artifact{{
			Kind: "metadata", MediaType: "application/json",
			StorageKey: "artifacts/task/result.json",
			SHA256:     strings.Repeat("a", 64), SizeBytes: 11,
		}},
	}
	if err := result.Validate(Limits{MaxArtifacts: 1, MaxOutputBytes: 10}); err == nil {
		t.Fatal("Validate() error = nil, want output limit error")
	}
}

func validInput() Input {
	return Input{
		TaskID: "task", JobID: "job", Attempt: 1, FencingToken: 1,
		SourceStorageKey: "blobs/sha256/ab/value",
		SourceSHA256:     strings.Repeat("b", 64),
		WorkDirectory:    "/data/task-work/task/1",
		Limits: Limits{
			MaxDuration: time.Minute, MaxOutputBytes: 1024,
			MaxArtifacts: 10, MaxStandardOutputBytes: 1024,
		},
	}
}

func TestExecuteProducesVersionedJSONDocument(t *testing.T) {
	document, err := Execute(context.Background(), &adapterStub{}, validInput())
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	var decoded Document
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.SchemaVersion != SchemaVersion ||
		decoded.Analyzer.Name != "stub" ||
		decoded.Input.StorageKey != validInput().SourceStorageKey ||
		decoded.Artifacts == nil || decoded.Warnings == nil || decoded.Errors == nil {
		t.Fatalf("unexpected analyzer document: %#v", decoded)
	}
	if err := decoded.Validate(validInput().Limits); err != nil {
		t.Fatalf("decoded document validation error = %v", err)
	}
}

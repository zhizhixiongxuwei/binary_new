package canalysis

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"binaryscan/internal/queue"
)

type processorRepositoryStub struct {
	project       ProjectSnapshot
	beginErr      error
	published     *Result
	failedResult  *Result
	retried       string
	failed        string
	failedMessage string
	cancelled     bool
}

func (s *processorRepositoryStub) Begin(
	context.Context,
	queue.Lease,
) (ProjectSnapshot, error) {
	return s.project, s.beginErr
}

func (s *processorRepositoryStub) Publish(
	_ context.Context,
	_ queue.Lease,
	result Result,
) error {
	s.published = &result
	return nil
}

func (s *processorRepositoryStub) PublishFailed(
	_ context.Context,
	_ queue.Lease,
	result Result,
) error {
	s.failedResult = &result
	return nil
}

func (s *processorRepositoryStub) Retry(
	_ context.Context,
	_ queue.Lease,
	code string,
	_ string,
) error {
	s.retried = code
	return nil
}

func (s *processorRepositoryStub) Fail(
	_ context.Context,
	_ queue.Lease,
	code string,
	message string,
) error {
	s.failed = code
	s.failedMessage = message
	return nil
}

func (s *processorRepositoryStub) CancelRun(context.Context, queue.Lease) error {
	s.cancelled = true
	return nil
}

type checkerStub struct {
	result              Result
	err                 error
	source              []byte
	meta                RequestMetadata
	started             chan struct{}
	waitForCancellation bool
	mu                  sync.Mutex
	cancelCalls         int
}

func (s *checkerStub) Analyze(
	ctx context.Context,
	request AnalysisRequest,
) (Result, error) {
	s.meta = request.Metadata
	if s.started != nil {
		close(s.started)
	}
	if s.waitForCancellation {
		<-ctx.Done()
		return Result{}, ctx.Err()
	}
	s.source, _ = io.ReadAll(request.Source)
	return s.result, s.err
}

func (s *checkerStub) Cancel(context.Context, string) error {
	s.mu.Lock()
	s.cancelCalls++
	s.mu.Unlock()
	return nil
}

func (s *checkerStub) Ready(context.Context) error { return nil }

func TestProcessorCopiesVerifiedSourceIntoFencedWorkspaceAndPublishes(t *testing.T) {
	repositoryRoot := t.TempDir()
	workRoot := t.TempDir()
	source := []byte("int main(void) { return 0; }\n")
	project := writeProcessorProject(t, repositoryRoot, source)
	repository := &processorRepositoryStub{project: project}
	checker := &checkerStub{result: Result{
		SchemaVersion: ResponseSchemaVersion, AnalysisID: testRunID,
		Status: "succeeded",
		Checker: CheckerIdentity{
			Name: AnalyzerName, Version: AnalyzerVersion,
			RulesetVersion: DefaultRulesetVersion,
		},
		Coverage: Coverage{TotalFunctions: 1, ParsedFunctions: 1},
		Summary:  ResultSummary{}, Findings: []Finding{}, Diagnostics: []Diagnostic{},
	}}
	processor, err := NewProcessor(repository, checker, ProcessorConfig{
		RepositoryRoot: repositoryRoot, TaskWorkRoot: workRoot,
	})
	if err != nil {
		t.Fatal(err)
	}
	finish, err := processor.Process(t.Context(), processorLease(t, project))
	if err != nil || finish.Outcome != queue.OutcomeSucceeded ||
		repository.published == nil || !bytes.Equal(checker.source, source) ||
		checker.meta.ProjectID != testProjectID ||
		checker.meta.CanonicalSHA256 != project.CanonicalSHA256 {
		t.Fatalf(
			"Process() = %+v / %v, published=%#v metadata=%#v source=%q",
			finish, err, repository.published, checker.meta, checker.source,
		)
	}
	entries, err := os.ReadDir(workRoot)
	if err != nil || len(entries) != 0 {
		t.Fatalf("workspace cleanup entries=%v error=%v", entries, err)
	}
	original, err := os.ReadFile(filepath.Join(
		repositoryRoot, filepath.FromSlash(project.CanonicalStorageKey),
	))
	if err != nil || !bytes.Equal(original, source) {
		t.Fatalf("source project was mutated: %q / %v", original, err)
	}
}

func TestProcessorCancellationCallsCheckerDelete(t *testing.T) {
	repositoryRoot := t.TempDir()
	workRoot := t.TempDir()
	project := writeProcessorProject(t, repositoryRoot, []byte("int f(void){}\n"))
	repository := &processorRepositoryStub{project: project}
	checker := &checkerStub{
		started: make(chan struct{}), waitForCancellation: true,
	}
	processor, err := NewProcessor(repository, checker, ProcessorConfig{
		RepositoryRoot: repositoryRoot, TaskWorkRoot: workRoot,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	type processResult struct {
		finish queue.FinishInput
		err    error
	}
	done := make(chan processResult, 1)
	go func() {
		finish, err := processor.Process(ctx, processorLease(t, project))
		done <- processResult{finish: finish, err: err}
	}()
	<-checker.started
	cancel()
	result := <-done
	checker.mu.Lock()
	cancelCalls := checker.cancelCalls
	checker.mu.Unlock()
	if result.err != nil || result.finish.Outcome != queue.OutcomeTransientFailure ||
		result.finish.ErrorCode != "c_analysis_interrupted" || cancelCalls != 1 ||
		repository.retried != "c_analysis_interrupted" || repository.published != nil {
		t.Fatalf(
			"cancel result=%+v calls=%d repository=%#v",
			result, cancelCalls, repository,
		)
	}
}

func TestProcessorRetriesOnlyTransientCheckerFailures(t *testing.T) {
	repositoryRoot := t.TempDir()
	workRoot := t.TempDir()
	project := writeProcessorProject(t, repositoryRoot, []byte("int f(void){}\n"))
	repository := &processorRepositoryStub{project: project}
	checker := &checkerStub{err: ErrCheckerTransient}
	processor, err := NewProcessor(repository, checker, ProcessorConfig{
		RepositoryRoot: repositoryRoot, TaskWorkRoot: workRoot,
	})
	if err != nil {
		t.Fatal(err)
	}
	finish, err := processor.Process(t.Context(), processorLease(t, project))
	if err != nil || finish.Outcome != queue.OutcomeTransientFailure ||
		repository.retried != "c_checker_unavailable" || repository.failed != "" {
		t.Fatalf("Process()=%+v/%v repository=%#v", finish, err, repository)
	}
}

func TestProcessorPersistsValidatedCheckerRejectionMessage(t *testing.T) {
	repositoryRoot := t.TempDir()
	project := writeProcessorProject(t, repositoryRoot, []byte("int f(void){}\n"))
	repository := &processorRepositoryStub{project: project}
	checker := &checkerStub{err: &CheckerRejection{
		StatusCode: http.StatusUnprocessableEntity,
		Code:       "function_sha256_mismatch",
		Message:    "functions[3].sha256 does not match its byte range",
	}}
	processor, err := NewProcessor(repository, checker, ProcessorConfig{
		RepositoryRoot: repositoryRoot, TaskWorkRoot: t.TempDir(),
	})
	if err != nil {
		t.Fatal(err)
	}
	finish, err := processor.Process(t.Context(), processorLease(t, project))
	if err != nil || finish.Outcome != queue.OutcomeDeterministicFailure ||
		finish.ErrorCode != "c_checker_rejected" ||
		repository.failed != "c_checker_rejected" ||
		repository.failedMessage != checker.err.(*CheckerRejection).Message {
		t.Fatalf("Process()=%+v/%v repository=%#v", finish, err, repository)
	}
}

func TestProcessorPublishesFailedCheckerCoverageAndDiagnostics(t *testing.T) {
	repositoryRoot := t.TempDir()
	workRoot := t.TempDir()
	project := writeProcessorProject(t, repositoryRoot, []byte("int f(void){}\n"))
	repository := &processorRepositoryStub{project: project}
	checker := &checkerStub{result: Result{
		SchemaVersion: ResponseSchemaVersion, AnalysisID: testRunID,
		Status: "failed",
		Checker: CheckerIdentity{
			Name: AnalyzerName, Version: AnalyzerVersion,
			RulesetVersion: DefaultRulesetVersion,
		},
		Coverage: Coverage{TotalFunctions: 1, FailedFunctions: 1},
		Summary: ResultSummary{
			DiagnosticCount: 1, DiagnosticsTruncated: true,
		},
		Findings: []Finding{},
		Diagnostics: []Diagnostic{{
			FunctionResultID: testResultID,
			Code:             "parse-error",
			Message:          "The checker could not parse main.",
		}},
	}}
	processor, err := NewProcessor(repository, checker, ProcessorConfig{
		RepositoryRoot: repositoryRoot, TaskWorkRoot: workRoot,
	})
	if err != nil {
		t.Fatal(err)
	}

	finish, err := processor.Process(t.Context(), processorLease(t, project))
	if err != nil || finish.Outcome != queue.OutcomeDeterministicFailure ||
		finish.ErrorCode != "c_checker_failed" || repository.failedResult == nil ||
		repository.failedResult.Coverage.FailedFunctions != 1 ||
		repository.failedResult.Summary.DiagnosticCount != 1 ||
		!repository.failedResult.Summary.DiagnosticsTruncated ||
		repository.failed != "" {
		t.Fatalf(
			"Process()=%+v/%v repository=%#v",
			finish, err, repository,
		)
	}
}

func TestProcessorCompletesQueueFinishReplayForPublishedCheckerFailure(t *testing.T) {
	project := ProjectSnapshot{
		CanonicalSHA256: testSHA, CanonicalSizeBytes: 128,
	}
	repository := &processorRepositoryStub{beginErr: ErrFailedResultPublished}
	processor, err := NewProcessor(repository, &checkerStub{}, ProcessorConfig{
		RepositoryRoot: t.TempDir(), TaskWorkRoot: t.TempDir(),
	})
	if err != nil {
		t.Fatal(err)
	}

	finish, err := processor.Process(t.Context(), processorLease(t, project))
	if err != nil || finish.Outcome != queue.OutcomeDeterministicFailure ||
		finish.ErrorCode != "c_checker_failed" || repository.failed != "" ||
		repository.failedResult != nil {
		t.Fatalf("Process()=%+v/%v repository=%#v", finish, err, repository)
	}
}

func writeProcessorProject(
	t *testing.T,
	repositoryRoot string,
	content []byte,
) ProjectSnapshot {
	t.Helper()
	digest := sha256.Sum256(content)
	digestText := hex.EncodeToString(digest[:])
	key := "source-projects/" + testProjectID + "/src/decompiled.c"
	filename := filepath.Join(repositoryRoot, filepath.FromSlash(key))
	if err := os.MkdirAll(filepath.Dir(filename), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filename, content, 0o600); err != nil {
		t.Fatal(err)
	}
	return ProjectSnapshot{
		TaskID: testTaskID, ProjectID: testProjectID,
		Status: "complete", EngineName: "ghidra", EngineVersion: "12.1.2",
		RootStorageKey:      "source-projects/" + testProjectID,
		CanonicalStorageKey: key, CanonicalSHA256: digestText,
		CanonicalSizeBytes: uint64(len(content)),
		Functions: []Function{{
			ResultID: testResultID, Address: "00401000", Name: "main",
			SHA256: digestText, OffsetBytes: 0, LengthBytes: uint64(len(content)),
			StartLine: 1, EndLine: 1,
		}},
	}
}

func processorLease(t *testing.T, project ProjectSnapshot) queue.Lease {
	t.Helper()
	payload, err := json.Marshal(jobPayload{
		SchemaVersion: jobPayloadSchemaVersion,
		RunID:         testRunID, ProjectID: testProjectID,
		SourceSHA256:    project.CanonicalSHA256,
		SourceSizeBytes: project.CanonicalSizeBytes,
	})
	if err != nil {
		t.Fatal(err)
	}
	attemptID := uint64(9)
	return queue.Lease{
		JobID: testJobID, TaskID: testTaskID, TaskAttemptID: &attemptID,
		Kind: queue.KindCAnalysis, Payload: payload,
		Attempt: 1, MaxAttempts: 3, FencingToken: 2, Owner: "c-analysis-test",
	}
}

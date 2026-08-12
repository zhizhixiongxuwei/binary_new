package javaanalysis

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"testing"

	"binaryscan/internal/queue"
)

func TestJavaCheckerAnalysisIDIsScopedToFencedDelivery(t *testing.T) {
	runID := "00000000-0000-4000-8000-000000000032"
	jobID := "00000000-0000-4000-8000-000000000033"
	first := javaCheckerAnalysisID(runID, jobID, 7)
	replay := javaCheckerAnalysisID(runID, jobID, 7)
	next := javaCheckerAnalysisID(runID, jobID, 8)
	if !uuidPattern.MatchString(first) {
		t.Fatalf("checker analysis ID = %q, want canonical UUID", first)
	}
	if replay != first {
		t.Fatalf("same fenced delivery IDs differ: %q != %q", replay, first)
	}
	if next == first {
		t.Fatalf("next fenced delivery reused checker analysis ID %q", first)
	}
}

type transientDeliveryRepository struct {
	project   ProjectSnapshot
	events    *[]string
	retryCode string
}

func (r *transientDeliveryRepository) Begin(
	context.Context,
	queue.Lease,
) (ProjectSnapshot, error) {
	return r.project, nil
}

func (*transientDeliveryRepository) SetBundleIdentity(
	context.Context,
	queue.Lease,
	string,
) error {
	return nil
}

func (*transientDeliveryRepository) Publish(
	context.Context,
	queue.Lease,
	RequestMetadata,
	Result,
) error {
	return nil
}

func (*transientDeliveryRepository) PublishFailed(
	context.Context,
	queue.Lease,
	RequestMetadata,
	Result,
) error {
	return nil
}

func (r *transientDeliveryRepository) Retry(
	_ context.Context,
	_ queue.Lease,
	code string,
	_ string,
) error {
	*r.events = append(*r.events, "retry")
	r.retryCode = code
	return nil
}

func (*transientDeliveryRepository) Fail(
	context.Context,
	queue.Lease,
	string,
	string,
) error {
	return nil
}

func (*transientDeliveryRepository) CancelRun(
	context.Context,
	queue.Lease,
) error {
	return nil
}

type transientDeliveryChecker struct {
	events           *[]string
	analyzeID        string
	cancelID         string
	cancelErr        error
	cancelContextErr error
}

func (c *transientDeliveryChecker) Analyze(
	_ context.Context,
	request AnalysisRequest,
) (Result, error) {
	*c.events = append(*c.events, "analyze")
	c.analyzeID = request.Metadata.AnalysisID
	return Result{}, ErrCheckerTransient
}

func (c *transientDeliveryChecker) Cancel(ctx context.Context, analysisID string) error {
	*c.events = append(*c.events, "cancel")
	c.cancelID = analysisID
	c.cancelContextErr = ctx.Err()
	return c.cancelErr
}

func (*transientDeliveryChecker) Ready(context.Context) error { return nil }

func TestProcessorCancelsPossiblyDeliveredRequestBeforeTransientRetry(t *testing.T) {
	repositoryRoot := t.TempDir()
	project, _ := writeJavaProjectFixture(t, repositoryRoot)
	events := make([]string, 0, 3)
	repository := &transientDeliveryRepository{
		project: project,
		events:  &events,
	}
	checker := &transientDeliveryChecker{
		events:    &events,
		cancelErr: errors.New("remote cleanup failed"),
	}
	processor, err := NewProcessor(repository, checker, ProcessorConfig{
		RepositoryRoot: repositoryRoot,
		TaskWorkRoot:   t.TempDir(),
	})
	if err != nil {
		t.Fatal(err)
	}
	lease := javaProcessorLease(t, project)

	finish, err := processor.Process(t.Context(), lease)
	if err != nil {
		t.Fatalf("Process() error = %v", err)
	}
	if finish.Outcome != queue.OutcomeTransientFailure ||
		finish.ErrorCode != "java_checker_unavailable" ||
		repository.retryCode != "java_checker_unavailable" {
		t.Fatalf("Process() finish = %+v, retry code = %q", finish, repository.retryCode)
	}
	expectedID := javaCheckerAnalysisID(testRunID, lease.JobID, lease.FencingToken)
	if checker.analyzeID != expectedID || checker.cancelID != expectedID {
		t.Fatalf(
			"checker delivery IDs = analyze %q, cancel %q, want %q",
			checker.analyzeID, checker.cancelID, expectedID,
		)
	}
	if checker.cancelContextErr != nil {
		t.Fatalf("Cancel() context error = %v", checker.cancelContextErr)
	}
	if !reflect.DeepEqual(events, []string{"analyze", "cancel", "retry"}) {
		t.Fatalf("checker/repository events = %#v", events)
	}
}

func javaProcessorLease(t *testing.T, project ProjectSnapshot) queue.Lease {
	t.Helper()
	payload, err := json.Marshal(jobPayload{
		SchemaVersion:        jobPayloadSchemaVersion,
		RunID:                testRunID,
		ProjectID:            project.ProjectID,
		SourceManifestSHA256: project.ManifestSHA256,
		InputSHA256:          project.InputSHA256,
		SourceSizeBytes:      project.SourceSizeBytes,
		SourceFileCount:      uint32(len(project.Files)),
	})
	if err != nil {
		t.Fatal(err)
	}
	attemptID := uint64(9)
	return queue.Lease{
		JobID: testJobID, TaskID: testTaskID, TaskAttemptID: &attemptID,
		Kind: queue.KindJavaAnalysis, Payload: payload,
		Attempt: 1, MaxAttempts: 3, FencingToken: 7,
		Owner: "java-analysis-test",
	}
}

package queue

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"binaryscan/internal/task"
	"binaryscan/internal/workspace"
)

type repositoryStub struct {
	claimRequest           claimRequest
	progressRequest        progressRequest
	activityRequest        activityRequest
	finishRequest          finishRequest
	recoverLimit           int
	recoverRetentionMicros int64
	workspaceLease         workspaceLeaseRequest
	workspaceActive        bool
	configuredHeavySlots   int
	configuredTrivySlots   int
	configuredNativeSlots  int
	err                    error
}

func (r *repositoryStub) ConfigureResourceLimits(
	_ context.Context,
	heavySlots int,
	trivySlots int,
	nativeSlots int,
) error {
	r.configuredHeavySlots = heavySlots
	r.configuredTrivySlots = trivySlots
	r.configuredNativeSlots = nativeSlots
	return r.err
}

func (r *repositoryStub) Claim(
	_ context.Context,
	request claimRequest,
) (Lease, bool, error) {
	r.claimRequest = request
	return testLease(), true, r.err
}

func (r *repositoryStub) Start(context.Context, Lease) error {
	return r.err
}

func (r *repositoryStub) Heartbeat(
	_ context.Context,
	lease Lease,
	_ int64,
) (Lease, error) {
	return lease, r.err
}

func (r *repositoryStub) TaskProgress(
	_ context.Context,
	request progressRequest,
) error {
	r.progressRequest = request
	return r.err
}

func (r *repositoryStub) TaskActivity(
	_ context.Context,
	request activityRequest,
) error {
	r.activityRequest = request
	return r.err
}

func (r *repositoryStub) Finish(
	_ context.Context,
	request finishRequest,
) error {
	r.finishRequest = request
	return r.err
}

func (r *repositoryStub) RecoverExpired(
	_ context.Context,
	limit int,
	_ int64,
	sampleRetentionMicros int64,
) (int, error) {
	r.recoverLimit = limit
	r.recoverRetentionMicros = sampleRetentionMicros
	return limit, r.err
}

func (r *repositoryStub) WorkspaceLeaseActive(
	_ context.Context,
	request workspaceLeaseRequest,
) (bool, error) {
	r.workspaceLease = request
	return r.workspaceActive, r.err
}

func TestServiceValidatesConfigurationAndClaimIdentity(t *testing.T) {
	repository := &repositoryStub{}
	if _, err := NewService(repository, Config{}); err == nil {
		t.Fatal("NewService() error = nil for zero lease duration")
	}
	if _, err := NewService(repository, Config{
		LeaseDuration:   time.Minute,
		SampleRetention: -time.Second,
	}); err == nil {
		t.Fatal("NewService() error = nil for negative sample retention")
	}
	if _, err := NewService(repository, Config{
		LeaseDuration:   time.Minute,
		HeavySlotLimit:  1,
		TrivySlotLimit:  1,
		NativeSlotLimit: 1,
	}); err != nil {
		t.Fatalf("NewService() rejected a single shared heavy slot: %v", err)
	}
	service := newTestQueueService(t, repository)
	if _, _, err := service.Claim(
		context.Background(), Kind("unknown"), testOwner,
	); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("Claim() kind error = %v, want ErrInvalidInput", err)
	}
	if _, _, err := service.Claim(
		context.Background(), KindScan, "worker\nname",
	); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("Claim() owner error = %v, want ErrInvalidInput", err)
	}
	for _, owner := range []string{" ", " worker", "worker "} {
		if _, _, err := service.Claim(
			context.Background(), KindScan, owner,
		); !errors.Is(err, ErrInvalidInput) {
			t.Errorf("Claim() owner %q error = %v, want ErrInvalidInput", owner, err)
		}
	}
	_, ok, err := service.Claim(context.Background(), KindScan, testOwner)
	if err != nil || !ok {
		t.Fatalf("Claim() = (_, %v, %v)", ok, err)
	}
	if repository.claimRequest.LeaseDurationMicros != int64(time.Minute/time.Microsecond) {
		t.Fatalf("lease duration micros = %d", repository.claimRequest.LeaseDurationMicros)
	}
	_, ok, err = service.ClaimDecompileWorker(
		context.Background(), KindNative, testOwner,
	)
	if err != nil || !ok ||
		repository.claimRequest.Kind != KindDecompile ||
		repository.claimRequest.PayloadWorkerKind != KindNative {
		t.Fatalf(
			"native decompile claim request = (%+v, %v, %v)",
			repository.claimRequest, ok, err,
		)
	}
	if _, _, err := service.ClaimDecompileWorker(
		context.Background(), KindScan, testOwner,
	); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("invalid decompile worker kind error = %v", err)
	}
	if err := service.ConfigureResourceLimits(context.Background()); err != nil {
		t.Fatal(err)
	}
	if repository.configuredHeavySlots != 2 ||
		repository.configuredTrivySlots != 1 ||
		repository.configuredNativeSlots != 1 {
		t.Fatalf(
			"configured slots = %d/%d/%d",
			repository.configuredHeavySlots,
			repository.configuredTrivySlots,
			repository.configuredNativeSlots,
		)
	}
}

func TestServiceValidatesAndQueriesWorkspaceLease(t *testing.T) {
	repository := &repositoryStub{workspaceActive: true}
	service := newTestQueueService(t, repository)
	identity := workspace.Identity{
		JobID: testJobID, TaskID: testTaskID, TaskAttemptID: 19,
		FencingToken: 2, Kind: "scan",
	}
	active, err := service.WorkspaceLeaseActive(context.Background(), identity)
	if err != nil || !active {
		t.Fatalf("WorkspaceLeaseActive() = (%v, %v)", active, err)
	}
	if repository.workspaceLease != (workspaceLeaseRequest{
		JobID: testJobID, TaskID: testTaskID, TaskAttemptID: 19,
		FencingToken: 2, Kind: KindScan,
	}) {
		t.Fatalf("workspace request = %+v", repository.workspaceLease)
	}
	identity.Kind = "decompile"
	active, err = service.WorkspaceLeaseActive(context.Background(), identity)
	if err != nil || !active || repository.workspaceLease.Kind != KindDecompile {
		t.Fatalf(
			"decompile WorkspaceLeaseActive() = (%v, %v), request=%+v",
			active, err, repository.workspaceLease,
		)
	}
	identity.FencingToken = 0
	if _, err := service.WorkspaceLeaseActive(
		context.Background(), identity,
	); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("invalid workspace identity error = %v", err)
	}
}

func TestServiceRejectsZeroTaskAttemptID(t *testing.T) {
	repository := &repositoryStub{}
	service := newTestQueueService(t, repository)
	lease := serviceTestLease()
	zero := uint64(0)
	lease.TaskAttemptID = &zero
	if err := service.Start(context.Background(), lease); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("Start() error = %v, want ErrInvalidInput", err)
	}
}

func TestServiceRequiresExactResourceSlotLease(t *testing.T) {
	repository := &repositoryStub{}
	service := newTestQueueService(t, repository)
	lease := testLease()
	if err := service.Start(
		context.Background(),
		lease,
	); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("missing resource slot error = %v", err)
	}
	lease.ResourceSlots = []ResourceSlotLease{{
		Pool: resourcePoolTrivy, SlotNumber: 1,
	}}
	if err := service.Start(
		context.Background(),
		lease,
	); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("wrong resource pool error = %v", err)
	}
	lease.ResourceSlots = []ResourceSlotLease{{
		Pool: resourcePoolGlobal, SlotNumber: 3,
	}}
	if err := service.Start(
		context.Background(),
		lease,
	); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("out-of-capacity slot error = %v", err)
	}
}

func TestServiceNormalizesAndValidatesProgress(t *testing.T) {
	repository := &repositoryStub{}
	service := newTestQueueService(t, repository)
	lease := serviceTestLease()
	halfStage := uint16(5_000)
	err := service.TaskProgress(context.Background(), lease, ProgressInput{
		TaskStatus: " scanning ", Stage: " scanning ",
		StageProgressBasisPoints: &halfStage,
	})
	if err != nil {
		t.Fatal(err)
	}
	if repository.progressRequest.Input.TaskStatus != "SCANNING" ||
		repository.progressRequest.Input.Stage != "SCANNING" ||
		repository.progressRequest.ProgressBasisPoints != 8_250 {
		t.Fatalf("progress request = %#v", repository.progressRequest)
	}
	err = service.TaskProgress(context.Background(), lease, ProgressInput{
		TaskStatus: "SUCCEEDED", Stage: "DONE",
	})
	if !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("terminal TaskProgress() error = %v, want ErrInvalidInput", err)
	}
	err = service.TaskProgress(context.Background(), lease, ProgressInput{
		TaskStatus: "SCANNING", Stage: "INDEXING",
	})
	if !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("mismatched stage error = %v, want ErrInvalidInput", err)
	}

	lease.Kind = KindTrivy
	lease.ResourceSlots = []ResourceSlotLease{
		{Pool: resourcePoolGlobal, SlotNumber: 1},
		{Pool: resourcePoolTrivy, SlotNumber: 1},
	}
	err = service.TaskProgress(context.Background(), lease, ProgressInput{
		TaskStatus: "REPORTING", Stage: "REPORTING",
	})
	if err != nil || repository.progressRequest.ProgressBasisPoints != 9_500 {
		t.Fatalf(
			"Trivy reporting progress = (%#v, %v)",
			repository.progressRequest,
			err,
		)
	}
}

func TestServiceValidatesAndCopiesTaskActivity(t *testing.T) {
	repository := &repositoryStub{}
	service := newTestQueueService(t, repository)
	lease := serviceTestLease()
	payload := json.RawMessage(`{"analyzer":"trivy","phase":"running","current":1,"total":2}`)
	err := service.TaskActivity(context.Background(), lease, ActivityInput{
		EventType: " trivy.progress ",
		Severity:  " INFO ",
		Message:   " Trivy scan is running. ",
		Payload:   payload,
	})
	if err != nil {
		t.Fatal(err)
	}
	request := repository.activityRequest
	if request.Input.EventType != "trivy.progress" ||
		request.Input.Severity != "info" ||
		request.Input.Message != "Trivy scan is running." ||
		string(request.Input.Payload) != string(payload) {
		t.Fatalf("activity request = %#v", request)
	}
	payload[2] = 'X'
	if string(request.Input.Payload) !=
		`{"analyzer":"trivy","phase":"running","current":1,"total":2}` {
		t.Fatal("activity payload was not copied")
	}

	for _, input := range []ActivityInput{
		{EventType: "bad event", Severity: "info", Message: "ok", Payload: json.RawMessage(`{}`)},
		{EventType: "trivy.progress", Severity: "critical", Message: "ok", Payload: json.RawMessage(`{}`)},
		{EventType: "trivy.progress", Severity: "info", Message: "bad\nmessage", Payload: json.RawMessage(`{}`)},
		{EventType: "trivy.progress", Severity: "info", Message: "ok", Payload: json.RawMessage(`[]`)},
	} {
		if err := service.TaskActivity(
			context.Background(), lease, input,
		); !errors.Is(err, ErrInvalidInput) {
			t.Fatalf("TaskActivity(%#v) error = %v", input, err)
		}
	}
}

func TestServiceValidatesFinishAndRecoveryInputs(t *testing.T) {
	repository := &repositoryStub{}
	service := newTestQueueService(t, repository)
	lease := serviceTestLease()
	err := service.Finish(context.Background(), lease, FinishInput{
		Outcome: OutcomeTransientFailure, ErrorCode: "bad code",
		ErrorMessage: "retry",
	})
	if !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("Finish() error = %v, want ErrInvalidInput", err)
	}
	err = service.Finish(context.Background(), lease, FinishInput{
		Outcome: OutcomeSucceeded, ErrorCode: "unexpected",
	})
	if !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("successful Finish() error = %v, want ErrInvalidInput", err)
	}
	err = service.Finish(context.Background(), lease, FinishInput{
		Outcome: OutcomeSucceeded,
	})
	if err != nil {
		t.Fatalf("valid Finish() error = %v", err)
	}
	if repository.finishRequest.SampleRetentionMicros !=
		task.DefaultSampleRetention.Microseconds() {
		t.Fatalf(
			"finish retention micros = %d",
			repository.finishRequest.SampleRetentionMicros,
		)
	}
	if _, err := service.RecoverExpired(context.Background(), 1001); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("RecoverExpired() error = %v, want ErrInvalidInput", err)
	}
	count, err := service.RecoverExpired(context.Background(), 100)
	if err != nil || count != 100 || repository.recoverLimit != 100 {
		t.Fatalf("RecoverExpired() = (%d, %v), limit=%d", count, err, repository.recoverLimit)
	}
	if repository.recoverRetentionMicros !=
		task.DefaultSampleRetention.Microseconds() {
		t.Fatalf(
			"recovery retention micros = %d",
			repository.recoverRetentionMicros,
		)
	}
}

func newTestQueueService(t *testing.T, repository Repository) *Service {
	t.Helper()
	service, err := NewService(repository, Config{
		LeaseDuration: time.Minute,
		RetryDelay:    5 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	return service
}

func serviceTestLease() Lease {
	lease := testLease()
	lease.ResourceSlots = []ResourceSlotLease{{
		Pool: resourcePoolGlobal, SlotNumber: 1,
	}}
	return lease
}

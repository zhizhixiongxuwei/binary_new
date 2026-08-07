package workerrunner

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"binaryscan/internal/queue"
)

type queueStub struct {
	recover   func(context.Context, int) (int, error)
	claim     func(context.Context, queue.Kind, string) (queue.Lease, bool, error)
	start     func(context.Context, queue.Lease) error
	heartbeat func(context.Context, queue.Lease) (queue.Lease, error)
	finish    func(context.Context, queue.Lease, queue.FinishInput) error
}

func (s *queueStub) RecoverExpired(
	ctx context.Context,
	limit int,
) (int, error) {
	if s.recover == nil {
		return 0, nil
	}
	return s.recover(ctx, limit)
}

func (s *queueStub) Claim(
	ctx context.Context,
	kind queue.Kind,
	owner string,
) (queue.Lease, bool, error) {
	return s.claim(ctx, kind, owner)
}

func (s *queueStub) Start(ctx context.Context, lease queue.Lease) error {
	if s.start == nil {
		return nil
	}
	return s.start(ctx, lease)
}

func (s *queueStub) Heartbeat(
	ctx context.Context,
	lease queue.Lease,
) (queue.Lease, error) {
	if s.heartbeat == nil {
		return lease, nil
	}
	return s.heartbeat(ctx, lease)
}

func (s *queueStub) Finish(
	ctx context.Context,
	lease queue.Lease,
	input queue.FinishInput,
) error {
	if s.finish == nil {
		return nil
	}
	return s.finish(ctx, lease, input)
}

type processorFunc func(context.Context, queue.Lease) (queue.FinishInput, error)

func (f processorFunc) Process(
	ctx context.Context,
	lease queue.Lease,
) (queue.FinishInput, error) {
	return f(ctx, lease)
}

func TestRunnerRecoversExpiredLeasesBeforeFirstClaim(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var recovered atomic.Bool
	var claims atomic.Int32
	stub := &queueStub{
		recover: func(_ context.Context, limit int) (int, error) {
			if limit != startupRecoveryLimit {
				return 0, errors.New("unexpected startup recovery limit")
			}
			recovered.Store(true)
			return 1, nil
		},
		claim: func(context.Context, queue.Kind, string) (queue.Lease, bool, error) {
			claims.Add(1)
			if !recovered.Load() {
				return queue.Lease{}, false, errors.New("claim ran before recovery")
			}
			return testLease(), true, nil
		},
		finish: func(context.Context, queue.Lease, queue.FinishInput) error {
			cancel()
			return nil
		},
	}
	runner := newTestRunner(t, stub, processorFunc(func(
		context.Context,
		queue.Lease,
	) (queue.FinishInput, error) {
		return queue.FinishInput{Outcome: queue.OutcomeSucceeded}, nil
	}), Config{
		Kind: queue.KindScan, Owner: "worker-1",
		PollInterval: time.Hour, HeartbeatInterval: time.Hour,
	})
	waitRun(t, runAsync(runner, ctx))
	if !recovered.Load() || claims.Load() != 1 {
		t.Fatalf(
			"startup recovered=%v claims=%d, want true/1",
			recovered.Load(), claims.Load(),
		)
	}
}

func TestRunnerDoesNotClaimWhenStartupRecoveryFails(t *testing.T) {
	recoveryErr := errors.New("database unavailable")
	var claimed atomic.Bool
	stub := &queueStub{
		recover: func(context.Context, int) (int, error) {
			return 0, recoveryErr
		},
		claim: func(context.Context, queue.Kind, string) (queue.Lease, bool, error) {
			claimed.Store(true)
			return queue.Lease{}, false, nil
		},
	}
	runner := newTestRunner(t, stub, processorFunc(func(
		context.Context,
		queue.Lease,
	) (queue.FinishInput, error) {
		t.Fatal("processor ran after startup recovery failure")
		return queue.FinishInput{}, nil
	}), Config{
		Kind: queue.KindScan, Owner: "worker-1",
		PollInterval: time.Hour, HeartbeatInterval: time.Hour,
	})
	err := runner.Run(context.Background())
	if !errors.Is(err, recoveryErr) ||
		!strings.Contains(err.Error(), "recover expired jobs on worker startup") {
		t.Fatalf("Run() error = %v", err)
	}
	if claimed.Load() {
		t.Fatal("worker claimed a job after startup recovery failure")
	}
}

func TestRunnerWaitsWhenNoJobAndStopsOnCancellation(t *testing.T) {
	var claims atomic.Int32
	firstClaim := make(chan struct{})
	var once sync.Once
	stub := &queueStub{
		claim: func(context.Context, queue.Kind, string) (queue.Lease, bool, error) {
			claims.Add(1)
			once.Do(func() { close(firstClaim) })
			return queue.Lease{}, false, nil
		},
	}
	runner := newTestRunner(t, stub, processorFunc(func(
		context.Context,
		queue.Lease,
	) (queue.FinishInput, error) {
		t.Error("processor was called without a job")
		return queue.FinishInput{}, nil
	}), Config{
		Kind: queue.KindScan, Owner: "worker-1",
		PollInterval: time.Hour, HeartbeatInterval: time.Hour,
	})
	ctx, cancel := context.WithCancel(context.Background())
	done := runAsync(runner, ctx)
	select {
	case <-firstClaim:
	case <-time.After(time.Second):
		t.Fatal("runner did not poll the queue")
	}
	cancel()
	waitRun(t, done)
	if claims.Load() != 1 {
		t.Fatalf("Claim() calls = %d, want 1", claims.Load())
	}
}

func TestRunnerStartsHeartbeatsAndFinishesWithRenewedLease(t *testing.T) {
	lease := testLease()
	renewedUntil := lease.LeaseUntil.Add(time.Minute)
	secondHeartbeat := make(chan struct{})
	var secondOnce sync.Once
	var heartbeatCalls atomic.Int32
	var heartbeatStopped atomic.Bool
	var finishCalls atomic.Int32
	var claims atomic.Int32
	var logOutput bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logOutput, nil))
	ctx, cancel := context.WithCancel(context.Background())
	stub := &queueStub{
		claim: func(_ context.Context, kind queue.Kind, owner string) (queue.Lease, bool, error) {
			claims.Add(1)
			if kind != queue.KindScan || owner != "worker-1" {
				return queue.Lease{}, false, errors.New("claim metadata mismatch")
			}
			return lease, true, nil
		},
		start: func(_ context.Context, actual queue.Lease) error {
			if actual.JobID != lease.JobID {
				return errors.New("wrong lease started")
			}
			return nil
		},
		heartbeat: func(heartbeatCtx context.Context, actual queue.Lease) (queue.Lease, error) {
			call := heartbeatCalls.Add(1)
			if call == 1 {
				actual.LeaseUntil = renewedUntil
				return actual, nil
			}
			secondOnce.Do(func() { close(secondHeartbeat) })
			<-heartbeatCtx.Done()
			heartbeatStopped.Store(true)
			return actual, heartbeatCtx.Err()
		},
		finish: func(finishCtx context.Context, actual queue.Lease, input queue.FinishInput) error {
			finishCalls.Add(1)
			if finishCtx.Err() != nil {
				return errors.New("finish context was already cancelled")
			}
			if !heartbeatStopped.Load() {
				return errors.New("finish ran before heartbeat stopped")
			}
			if !actual.LeaseUntil.Equal(renewedUntil) {
				return errors.New("finish did not receive renewed lease")
			}
			if input.Outcome != queue.OutcomeSucceeded {
				return errors.New("unexpected finish outcome")
			}
			cancel()
			return nil
		},
	}
	runner, err := New(
		stub,
		processorFunc(func(context.Context, queue.Lease) (queue.FinishInput, error) {
			select {
			case <-secondHeartbeat:
			case <-time.After(time.Second):
				return queue.FinishInput{}, errors.New("second heartbeat did not start")
			}
			return queue.FinishInput{Outcome: queue.OutcomeSucceeded}, nil
		}),
		logger,
		Config{
			Kind: queue.KindScan, Owner: "worker-1",
			PollInterval: time.Hour, HeartbeatInterval: time.Millisecond,
		},
	)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	waitRun(t, runAsync(runner, ctx))
	if finishCalls.Load() != 1 || claims.Load() != 1 || heartbeatCalls.Load() < 2 {
		t.Fatalf(
			"calls: finish=%d claim=%d heartbeat=%d",
			finishCalls.Load(), claims.Load(), heartbeatCalls.Load(),
		)
	}
	logs := logOutput.String()
	for _, expected := range []string{
		`"task_id":"10000000-0000-4000-8000-000000000001"`,
		`"job_id":"20000000-0000-4000-8000-000000000002"`,
		`"fencing_token":7`,
	} {
		if !strings.Contains(logs, expected) {
			t.Errorf("job log does not contain %s: %s", expected, logs)
		}
	}
}

func TestRunnerMapsProcessorErrorToTransientFinish(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	var finishCalls atomic.Int32
	stub := &queueStub{
		claim: func(context.Context, queue.Kind, string) (queue.Lease, bool, error) {
			return testLease(), true, nil
		},
		finish: func(_ context.Context, _ queue.Lease, input queue.FinishInput) error {
			finishCalls.Add(1)
			if input.Outcome != queue.OutcomeTransientFailure ||
				input.ErrorCode != "processor_error" ||
				input.ErrorMessage != "processor returned an error" {
				return errors.New("processor error was not normalized")
			}
			cancel()
			return nil
		},
	}
	runner := newTestRunner(t, stub, processorFunc(func(
		context.Context,
		queue.Lease,
	) (queue.FinishInput, error) {
		return queue.FinishInput{
			Outcome: queue.OutcomeSucceeded,
		}, errors.New("tool exited with status 2")
	}), Config{
		Kind: queue.KindScan, Owner: "worker-1",
		PollInterval: time.Hour, HeartbeatInterval: time.Hour,
	})
	waitRun(t, runAsync(runner, ctx))
	if finishCalls.Load() != 1 {
		t.Fatalf("Finish() calls = %d, want 1", finishCalls.Load())
	}
}

func TestRunnerContinuesAfterTaskScopedProcessorFailure(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	first := testLease()
	second := testLease()
	second.JobID = "20000000-0000-4000-8000-000000000003"
	second.TaskID = "10000000-0000-4000-8000-000000000003"
	var claims atomic.Int32
	var processed atomic.Int32
	var finished atomic.Int32
	stub := &queueStub{
		claim: func(context.Context, queue.Kind, string) (queue.Lease, bool, error) {
			switch claims.Add(1) {
			case 1:
				return first, true, nil
			case 2:
				return second, true, nil
			default:
				return queue.Lease{}, false, errors.New("unexpected third claim")
			}
		},
		finish: func(_ context.Context, lease queue.Lease, input queue.FinishInput) error {
			switch finished.Add(1) {
			case 1:
				if lease.JobID != first.JobID ||
					input.Outcome != queue.OutcomeTransientFailure ||
					input.ErrorCode != "processor_error" {
					return errors.New("first task failure was not isolated")
				}
			case 2:
				if lease.JobID != second.JobID || input.Outcome != queue.OutcomeSucceeded {
					return errors.New("second task did not complete after first failure")
				}
				cancel()
			}
			return nil
		},
	}
	runner := newTestRunner(t, stub, processorFunc(func(
		_ context.Context,
		lease queue.Lease,
	) (queue.FinishInput, error) {
		processed.Add(1)
		if lease.JobID == first.JobID {
			return queue.FinishInput{}, context.DeadlineExceeded
		}
		return queue.FinishInput{Outcome: queue.OutcomeSucceeded}, nil
	}), Config{
		Kind: queue.KindScan, Owner: "worker-1",
		PollInterval: time.Hour, HeartbeatInterval: time.Hour,
	})
	waitRun(t, runAsync(runner, ctx))
	if claims.Load() != 2 || processed.Load() != 2 || finished.Load() != 2 {
		t.Fatalf(
			"calls: claim=%d process=%d finish=%d, want 2/2/2",
			claims.Load(), processed.Load(), finished.Load(),
		)
	}
}

func TestRunnerCancelsProcessorAndSkipsFinishWhenLeaseLost(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	var claims atomic.Int32
	var finishCalls atomic.Int32
	processorCancelled := make(chan struct{})
	var cancelledOnce sync.Once
	stub := &queueStub{
		claim: func(context.Context, queue.Kind, string) (queue.Lease, bool, error) {
			if claims.Add(1) == 1 {
				return testLease(), true, nil
			}
			cancel()
			return queue.Lease{}, false, nil
		},
		heartbeat: func(context.Context, queue.Lease) (queue.Lease, error) {
			return queue.Lease{}, queue.ErrLeaseLost
		},
		finish: func(context.Context, queue.Lease, queue.FinishInput) error {
			finishCalls.Add(1)
			return nil
		},
	}
	runner := newTestRunner(t, stub, processorFunc(func(
		processCtx context.Context,
		_ queue.Lease,
	) (queue.FinishInput, error) {
		<-processCtx.Done()
		cancelledOnce.Do(func() { close(processorCancelled) })
		return queue.FinishInput{}, processCtx.Err()
	}), Config{
		Kind: queue.KindScan, Owner: "worker-1",
		PollInterval: time.Hour, HeartbeatInterval: time.Millisecond,
	})
	waitRun(t, runAsync(runner, ctx))
	select {
	case <-processorCancelled:
	default:
		t.Fatal("processor was not cancelled after lease loss")
	}
	if finishCalls.Load() != 0 {
		t.Fatalf("Finish() calls = %d, want 0 after lease loss", finishCalls.Load())
	}
}

func TestRunnerCancellationFinishesCurrentJobAndDoesNotClaimAnother(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	var claims atomic.Int32
	var finishCalls atomic.Int32
	processorStarted := make(chan struct{})
	var startedOnce sync.Once
	stub := &queueStub{
		claim: func(context.Context, queue.Kind, string) (queue.Lease, bool, error) {
			claims.Add(1)
			return testLease(), true, nil
		},
		finish: func(finishCtx context.Context, _ queue.Lease, input queue.FinishInput) error {
			finishCalls.Add(1)
			if finishCtx.Err() != nil {
				return errors.New("shutdown finish used cancelled context")
			}
			if input.Outcome != queue.OutcomeTransientFailure {
				return errors.New("cancelled processor was not transient")
			}
			return nil
		},
	}
	runner := newTestRunner(t, stub, processorFunc(func(
		processCtx context.Context,
		_ queue.Lease,
	) (queue.FinishInput, error) {
		startedOnce.Do(func() { close(processorStarted) })
		<-processCtx.Done()
		return queue.FinishInput{}, processCtx.Err()
	}), Config{
		Kind: queue.KindScan, Owner: "worker-1",
		PollInterval: time.Millisecond, HeartbeatInterval: time.Hour,
	})
	done := runAsync(runner, ctx)
	select {
	case <-processorStarted:
	case <-time.After(time.Second):
		t.Fatal("processor did not start")
	}
	cancel()
	waitRun(t, done)
	if claims.Load() != 1 {
		t.Fatalf("Claim() calls = %d, want no claim after cancellation", claims.Load())
	}
	if finishCalls.Load() != 1 {
		t.Fatalf("Finish() calls = %d, want 1", finishCalls.Load())
	}
}

func newTestRunner(
	t *testing.T,
	leaseQueue LeaseQueue,
	processor Processor,
	config Config,
) *Runner {
	t.Helper()
	runner, err := New(
		leaseQueue,
		processor,
		slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil)),
		config,
	)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	return runner
}

func testLease() queue.Lease {
	attemptID := uint64(11)
	return queue.Lease{
		JobID:  "20000000-0000-4000-8000-000000000002",
		TaskID: "10000000-0000-4000-8000-000000000001", TaskAttemptID: &attemptID,
		Kind: queue.KindScan, Attempt: 1, MaxAttempts: 3,
		FencingToken: 7, Owner: "worker-1",
		LeaseUntil: time.Now().UTC().Add(time.Minute),
	}
}

func runAsync(runner *Runner, ctx context.Context) <-chan error {
	done := make(chan error, 1)
	go func() {
		done <- runner.Run(ctx)
	}()
	return done
}

func waitRun(t *testing.T, done <-chan error) {
	t.Helper()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run() error = %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("runner did not stop")
	}
}

package workerrunner

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"binaryscan/internal/queue"
)

const (
	defaultFinishTimeout = 5 * time.Second
	startupRecoveryLimit = 1000
)

type LeaseQueue interface {
	RecoverExpired(context.Context, int) (int, error)
	Claim(context.Context, queue.Kind, string) (queue.Lease, bool, error)
	Start(context.Context, queue.Lease) error
	Heartbeat(context.Context, queue.Lease) (queue.Lease, error)
	Finish(context.Context, queue.Lease, queue.FinishInput) error
}

// Processor implementations must stop promptly when ctx is cancelled. Runner
// cancellation cannot forcibly terminate a processor that ignores its context.
type Processor interface {
	Process(context.Context, queue.Lease) (queue.FinishInput, error)
}

type Config struct {
	Kind              queue.Kind
	Owner             string
	PollInterval      time.Duration
	HeartbeatInterval time.Duration
	FinishTimeout     time.Duration
	ClaimGate         func(context.Context) error
}

type Runner struct {
	queue     LeaseQueue
	processor Processor
	logger    *slog.Logger
	config    Config
}

func New(
	leaseQueue LeaseQueue,
	processor Processor,
	logger *slog.Logger,
	config Config,
) (*Runner, error) {
	if leaseQueue == nil {
		return nil, errors.New("worker queue is required")
	}
	if processor == nil {
		return nil, errors.New("worker processor is required")
	}
	if !validKind(config.Kind) || strings.TrimSpace(config.Owner) == "" {
		return nil, errors.New("worker kind and owner are required")
	}
	if config.PollInterval <= 0 || config.HeartbeatInterval <= 0 {
		return nil, errors.New("worker poll and heartbeat intervals must be positive")
	}
	if config.FinishTimeout == 0 {
		config.FinishTimeout = defaultFinishTimeout
	}
	if config.FinishTimeout < 0 {
		return nil, errors.New("worker finish timeout must be positive")
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &Runner{
		queue: leaseQueue, processor: processor, logger: logger, config: config,
	}, nil
}

func (r *Runner) Run(ctx context.Context) error {
	if ctx.Err() != nil {
		return nil
	}
	recovered, err := r.queue.RecoverExpired(ctx, startupRecoveryLimit)
	if err != nil {
		if ctx.Err() != nil {
			return nil
		}
		return fmt.Errorf("recover expired jobs on worker startup: %w", err)
	}
	if recovered > 0 {
		r.logger.InfoContext(
			ctx,
			"expired jobs recovered before worker startup",
			slog.Int("recovered_jobs", recovered),
		)
	}
	for {
		if ctx.Err() != nil {
			return nil
		}
		if r.config.ClaimGate != nil {
			if err := r.config.ClaimGate(ctx); err != nil {
				if ctx.Err() != nil {
					return nil
				}
				r.logger.DebugContext(
					ctx, "worker claim gate is not ready",
					slog.String("worker_kind", string(r.config.Kind)),
					slog.String("error", err.Error()),
				)
				if !wait(ctx, r.config.PollInterval) {
					return nil
				}
				continue
			}
		}
		lease, found, err := r.queue.Claim(ctx, r.config.Kind, r.config.Owner)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("claim %s job: %w", r.config.Kind, err)
		}
		if !found {
			if !wait(ctx, r.config.PollInterval) {
				return nil
			}
			continue
		}
		if ctx.Err() != nil {
			return nil
		}

		jobLogger := r.logger.With(
			slog.String("task_id", lease.TaskID),
			slog.String("job_id", lease.JobID),
			slog.Uint64("fencing_token", lease.FencingToken),
			slog.String("worker_kind", string(lease.Kind)),
		)
		jobLogger.InfoContext(ctx, "job claimed")
		if err := r.queue.Start(ctx, lease); err != nil {
			if ctx.Err() != nil {
				return nil
			}
			if errors.Is(err, queue.ErrLeaseLost) {
				jobLogger.WarnContext(ctx, "job lease lost before processing")
				continue
			}
			return fmt.Errorf("start job %s: %w", lease.JobID, err)
		}

		stop, err := r.processLease(ctx, lease, jobLogger)
		if err != nil {
			return err
		}
		if stop {
			return nil
		}
	}
}

type processResult struct {
	finish queue.FinishInput
	err    error
}

type heartbeatResult struct {
	lease queue.Lease
	err   error
}

func (r *Runner) processLease(
	parent context.Context,
	lease queue.Lease,
	logger *slog.Logger,
) (bool, error) {
	processCtx, cancelProcess := context.WithCancel(parent)
	defer cancelProcess()
	heartbeatCtx, cancelHeartbeat := context.WithCancel(parent)
	defer cancelHeartbeat()

	processorDone := make(chan processResult, 1)
	go func() {
		finish, err := r.processor.Process(processCtx, lease)
		processorDone <- processResult{finish: finish, err: err}
	}()
	heartbeatDone := make(chan heartbeatResult, 1)
	go func() {
		renewed, err := r.heartbeatLoop(heartbeatCtx, lease, logger)
		heartbeatDone <- heartbeatResult{lease: renewed, err: err}
	}()

	var processed processResult
	var heartbeat heartbeatResult
	parentStopped := false
	select {
	case processed = <-processorDone:
		cancelHeartbeat()
		heartbeat = <-heartbeatDone
	case heartbeat = <-heartbeatDone:
		cancelProcess()
		processed = <-processorDone
	case <-parent.Done():
		parentStopped = true
		cancelProcess()
		cancelHeartbeat()
		processed = <-processorDone
		heartbeat = <-heartbeatDone
	}
	if parent.Err() != nil {
		parentStopped = true
	}

	if heartbeat.err != nil {
		if errors.Is(heartbeat.err, queue.ErrLeaseLost) {
			logger.WarnContext(
				context.WithoutCancel(parent),
				"job lease lost; processor cancelled",
				slog.String("error", heartbeat.err.Error()),
			)
			return parentStopped, nil
		}
		if parentStopped {
			logger.WarnContext(
				context.WithoutCancel(parent),
				"job heartbeat stopped during shutdown",
				slog.String("error", heartbeat.err.Error()),
			)
			return true, nil
		}
		return false, fmt.Errorf("heartbeat job %s: %w", lease.JobID, heartbeat.err)
	}

	finish := normalizedFinish(processed)
	if processed.err != nil {
		logger.WarnContext(
			context.WithoutCancel(parent),
			"job processor returned an error",
			slog.String("outcome", string(finish.Outcome)),
			slog.String("error", processed.err.Error()),
		)
	}
	finishCtx, cancelFinish := context.WithTimeout(
		context.WithoutCancel(parent),
		r.config.FinishTimeout,
	)
	defer cancelFinish()
	if err := r.queue.Finish(finishCtx, heartbeat.lease, finish); err != nil {
		if errors.Is(err, queue.ErrLeaseLost) {
			logger.WarnContext(finishCtx, "job lease lost before finish")
			return parentStopped, nil
		}
		if parentStopped {
			logger.ErrorContext(
				context.WithoutCancel(parent),
				"job finish failed during shutdown",
				slog.String("error", err.Error()),
			)
			return true, nil
		}
		return false, fmt.Errorf("finish job %s: %w", lease.JobID, err)
	}
	logger.InfoContext(
		context.WithoutCancel(parent),
		"job finished",
		slog.String("outcome", string(finish.Outcome)),
	)
	return parentStopped, nil
}

func (r *Runner) heartbeatLoop(
	ctx context.Context,
	lease queue.Lease,
	logger *slog.Logger,
) (queue.Lease, error) {
	ticker := time.NewTicker(r.config.HeartbeatInterval)
	defer ticker.Stop()
	current := lease
	for {
		select {
		case <-ctx.Done():
			return current, nil
		case <-ticker.C:
			renewed, err := r.queue.Heartbeat(ctx, current)
			if err != nil {
				if ctx.Err() != nil && !errors.Is(err, queue.ErrLeaseLost) {
					return current, nil
				}
				return current, err
			}
			if !sameLeaseIdentity(current, renewed) {
				return current, fmt.Errorf("%w: heartbeat changed lease identity", queue.ErrLeaseLost)
			}
			current = renewed
			logger.DebugContext(
				ctx,
				"job lease renewed",
				slog.Time("lease_until", current.LeaseUntil),
			)
		}
	}
}

func normalizedFinish(result processResult) queue.FinishInput {
	if result.err != nil {
		return queue.FinishInput{
			Outcome:      queue.OutcomeTransientFailure,
			ErrorCode:    "processor_error",
			ErrorMessage: "processor returned an error",
		}
	}
	finish := result.finish
	if finish.Outcome != "" {
		return finish
	}
	finish.Outcome = queue.OutcomeTransientFailure
	finish.ErrorCode = "processor_invalid_result"
	finish.ErrorMessage = "processor returned no outcome"
	return finish
}

func sameLeaseIdentity(current, renewed queue.Lease) bool {
	return current.JobID == renewed.JobID &&
		current.TaskID == renewed.TaskID &&
		optionalUint64Equal(current.TaskAttemptID, renewed.TaskAttemptID) &&
		current.Kind == renewed.Kind &&
		current.Attempt == renewed.Attempt &&
		current.MaxAttempts == renewed.MaxAttempts &&
		current.FencingToken == renewed.FencingToken &&
		current.Owner == renewed.Owner &&
		resourceSlotsEqual(current.ResourceSlots, renewed.ResourceSlots)
}

func resourceSlotsEqual(left, right []queue.ResourceSlotLease) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func optionalUint64Equal(left, right *uint64) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return *left == *right
}

func validKind(kind queue.Kind) bool {
	switch kind {
	case queue.KindScan, queue.KindImage, queue.KindNative, queue.KindBytecode,
		queue.KindTrivy, queue.KindReport, queue.KindDecompile,
		queue.KindCAnalysis, queue.KindJavaAnalysis:
		return true
	default:
		return false
	}
}

func wait(ctx context.Context, duration time.Duration) bool {
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

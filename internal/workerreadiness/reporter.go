package workerreadiness

import (
	"context"
	"errors"
	"log/slog"
	"time"
)

type Reporter struct {
	repository Repository
	value      Registration
	interval   time.Duration
	timeout    time.Duration
	logger     *slog.Logger
	now        func() time.Time
}

func NewReporter(
	repository Repository,
	value Registration,
	interval time.Duration,
	timeout time.Duration,
	logger *slog.Logger,
) (*Reporter, error) {
	if repository == nil {
		return nil, errors.New("worker readiness repository is required")
	}
	if err := validateRegistration(value); err != nil {
		return nil, err
	}
	if interval <= 0 || timeout <= 0 || timeout > interval {
		return nil, errors.New("worker readiness intervals are invalid")
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &Reporter{
		repository: repository,
		value:      value,
		interval:   interval,
		timeout:    timeout,
		logger:     logger,
		now:        time.Now,
	}, nil
}

func (r *Reporter) Register(ctx context.Context) error {
	operationCtx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()
	if err := r.repository.Prune(operationCtx, StaleBefore(r.now())); err != nil {
		return err
	}
	return r.repository.Register(operationCtx, r.value)
}

func (r *Reporter) Run(ctx context.Context) {
	ticker := time.NewTicker(r.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			operationCtx, cancel := context.WithTimeout(ctx, r.timeout)
			err := r.repository.Heartbeat(operationCtx, r.value.Owner)
			cancel()
			if err != nil && ctx.Err() == nil {
				r.logger.WarnContext(
					ctx,
					"worker readiness heartbeat failed",
					slog.String("worker_kind", r.value.WorkerKind),
					slog.String("error", err.Error()),
				)
			}
		}
	}
}

func (r *Reporter) Remove(ctx context.Context) error {
	operationCtx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()
	return r.repository.Remove(operationCtx, r.value.Owner)
}

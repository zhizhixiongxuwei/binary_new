package archiveimport

import (
	"context"
	"errors"
	"log/slog"
	"time"
)

type RunnerConfig struct {
	Owner         string
	PollInterval  time.Duration
	LeaseDuration time.Duration
	RetryDelay    time.Duration
	Logger        *slog.Logger
}

type Runner struct {
	repository *MySQLRepository
	processor  *Processor
	service    *Service
	config     RunnerConfig
}

func NewRunner(
	repository *MySQLRepository,
	processor *Processor,
	service *Service,
	config RunnerConfig,
) (*Runner, error) {
	if repository == nil || processor == nil || service == nil {
		return nil, errors.New("archive import runner dependencies are required")
	}
	if config.Owner == "" || len(config.Owner) > 255 || config.PollInterval <= 0 ||
		config.LeaseDuration <= 0 || config.RetryDelay < 0 {
		return nil, errors.New("archive import runner configuration is invalid")
	}
	if config.Logger == nil {
		config.Logger = slog.Default()
	}
	return &Runner{
		repository: repository, processor: processor, service: service, config: config,
	}, nil
}

func (runner *Runner) Run(ctx context.Context) error {
	for {
		if err := ctx.Err(); err != nil {
			return nil
		}
		if _, err := runner.repository.RecoverExpired(ctx, runner.config.RetryDelay); err != nil {
			runner.config.Logger.ErrorContext(
				ctx, "archive import lease recovery deferred", "error", err,
			)
		}
		if _, err := runner.service.RecoverTaskBatches(ctx, 20); err != nil &&
			!errors.Is(err, ErrInvalidInput) {
			runner.config.Logger.ErrorContext(
				ctx, "archive task batch recovery deferred", "error", err,
			)
		}
		lease, found, err := runner.repository.Claim(
			ctx, runner.config.Owner, runner.config.LeaseDuration,
		)
		if err != nil {
			return err
		}
		if !found {
			if !waitContext(ctx, runner.config.PollInterval) {
				return nil
			}
			continue
		}
		err = runner.processor.Process(ctx, lease)
		if err == nil {
			continue
		}
		if errors.Is(err, ErrLeaseLost) || errors.Is(err, context.Canceled) {
			runner.config.Logger.WarnContext(
				ctx, "archive import lease stopped",
				"archive_import_id", lease.ID, "error", err,
			)
			continue
		}
		code := "archive_import_internal_error"
		retryable := true
		message := err.Error()
		var processing *ProcessingError
		if errors.As(err, &processing) {
			code = processing.Code
			retryable = processing.Retryable
			message = processing.Message
			if processing.Cause != nil {
				message = processing.Error()
			}
		}
		if failErr := runner.repository.FailLease(
			context.WithoutCancel(ctx), lease, code, message,
			retryable, runner.config.RetryDelay,
		); failErr != nil && !errors.Is(failErr, ErrLeaseLost) {
			return errors.Join(err, failErr)
		}
		runner.config.Logger.ErrorContext(
			ctx, "archive import processing failed",
			"archive_import_id", lease.ID, "error_code", code,
			"retryable", retryable, "error", err,
		)
	}
}

func waitContext(ctx context.Context, duration time.Duration) bool {
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

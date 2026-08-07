package taskcleanup

import (
	"context"
	"errors"
	"fmt"
	"io"
	"time"
)

type Config struct {
	LeaseOwner    string
	LeaseDuration time.Duration
}

type Sweeper struct {
	repository    Repository
	deleter       FileDeleter
	leaseOwner    string
	leaseDuration time.Duration
}

func NewLeaseOwner(pid int, entropy io.Reader) (string, error) {
	if pid <= 0 {
		return "", errors.New("task deletion process ID must be positive")
	}
	if entropy == nil {
		return "", errors.New("task deletion owner entropy is required")
	}
	var random [12]byte
	if _, err := io.ReadFull(entropy, random[:]); err != nil {
		return "", fmt.Errorf("read task deletion owner entropy: %w", err)
	}
	return fmt.Sprintf("task-deletion/%d/%x", pid, random), nil
}

func NewSweeper(
	repository Repository,
	deleter FileDeleter,
	config Config,
) (*Sweeper, error) {
	if repository == nil {
		return nil, errors.New("task deletion repository is required")
	}
	if deleter == nil {
		return nil, errors.New("task deletion file deleter is required")
	}
	if config.LeaseOwner == "" || len(config.LeaseOwner) > 255 {
		return nil, errors.New("task deletion lease owner is invalid")
	}
	if config.LeaseDuration <= 0 {
		return nil, errors.New("task deletion lease duration must be positive")
	}
	if config.LeaseDuration/3 <= 0 {
		return nil, errors.New("task deletion lease duration is too short")
	}
	return &Sweeper{
		repository: repository, deleter: deleter,
		leaseOwner: config.LeaseOwner, leaseDuration: config.LeaseDuration,
	}, nil
}

func (s *Sweeper) Sweep(
	ctx context.Context,
	limit int,
) (Report, error) {
	if limit < 1 || limit > maxSweepBatch {
		return Report{}, errors.New(
			"task deletion batch size must be between 1 and 100",
		)
	}
	if err := ctx.Err(); err != nil {
		return Report{}, err
	}
	ids, err := s.repository.ListReady(ctx, limit)
	if err != nil {
		return Report{}, err
	}
	var report Report
	var failures []error
	for _, taskID := range ids {
		if err := ctx.Err(); err != nil {
			return report, errors.Join(append(failures, err)...)
		}
		claim, claimed, err := s.repository.Claim(
			ctx, taskID, s.leaseOwner, s.leaseDuration,
		)
		if err != nil {
			report.Failures++
			failures = append(failures, fmt.Errorf("claim deleting task: %w", err))
			continue
		}
		if !claimed {
			report.Conflicts++
			continue
		}
		if !validClaim(claim, taskID, s.leaseOwner) {
			report.Failures++
			failures = append(
				failures,
				errors.New("task deletion repository returned an invalid claim"),
			)
			continue
		}
		report.Claimed++
		deleted, err := s.deleteClaim(ctx, claim)
		report.FilesDeleted += deleted
		if err != nil {
			report.Failures++
			failures = append(
				failures,
				fmt.Errorf("clean deleting task outputs: %w", err),
			)
			s.recordFailure(claim, failureCode(err))
			continue
		}
		completed, err := s.repository.Complete(ctx, claim)
		if err != nil {
			report.Failures++
			failures = append(
				failures,
				fmt.Errorf("finalize deleting task: %w", err),
			)
			s.recordFailure(claim, "task_deletion_finalize_failed")
			continue
		}
		if !completed {
			report.Conflicts++
			continue
		}
		report.Completed++
	}
	return report, errors.Join(failures...)
}

func validClaim(claim Claim, taskID string, leaseOwner string) bool {
	return claim.TaskID == taskID &&
		claim.LeaseOwner == leaseOwner &&
		claim.FencingToken > 0 &&
		claim.Attempt > 0 &&
		len(claim.Files) <= maxOutputFiles &&
		len(claim.Scopes) <= maxOutputFiles+2
}

func (s *Sweeper) deleteClaim(
	ctx context.Context,
	claim Claim,
) (int, error) {
	cleanupCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	keeperDone := make(chan error, 1)
	go func() {
		ticker := time.NewTicker(s.leaseDuration / 3)
		defer ticker.Stop()
		for {
			select {
			case <-cleanupCtx.Done():
				keeperDone <- nil
				return
			case <-ticker.C:
				renewed, err := s.repository.Renew(
					cleanupCtx, claim, s.leaseDuration,
				)
				if err != nil {
					if cleanupCtx.Err() != nil {
						keeperDone <- nil
						return
					}
					keeperDone <- fmt.Errorf(
						"renew deletion lease: %w", err,
					)
					cancel()
					return
				}
				if !renewed {
					if cleanupCtx.Err() != nil {
						keeperDone <- nil
						return
					}
					keeperDone <- errors.New(
						"task deletion lease was lost",
					)
					cancel()
					return
				}
			}
		}
	}()
	deleted := 0
	for _, file := range claim.Files {
		if err := cleanupCtx.Err(); err != nil {
			cancel()
			keeperErr := <-keeperDone
			if keeperErr != nil {
				return deleted, keeperErr
			}
			return deleted, err
		}
		removed, err := s.deleter.DeleteFile(cleanupCtx, file)
		if err != nil {
			cancel()
			keeperErr := <-keeperDone
			if keeperErr != nil {
				return deleted, keeperErr
			}
			return deleted, err
		}
		if removed {
			deleted++
		}
	}
	for _, scope := range claim.Scopes {
		if err := cleanupCtx.Err(); err != nil {
			cancel()
			keeperErr := <-keeperDone
			if keeperErr != nil {
				return deleted, keeperErr
			}
			return deleted, err
		}
		if err := s.deleter.DeleteScope(cleanupCtx, scope); err != nil {
			cancel()
			keeperErr := <-keeperDone
			if keeperErr != nil {
				return deleted, keeperErr
			}
			return deleted, err
		}
	}
	cancel()
	if err := <-keeperDone; err != nil {
		return deleted, err
	}
	return deleted, nil
}

func (s *Sweeper) recordFailure(claim Claim, code string) {
	cleanupCtx, cancel := context.WithTimeout(
		context.WithoutCancel(context.Background()),
		5*time.Second,
	)
	defer cancel()
	_, _ = s.repository.Fail(cleanupCtx, claim, Failure{Code: code})
}

func failureCode(err error) string {
	switch {
	case errors.Is(err, context.Canceled),
		errors.Is(err, context.DeadlineExceeded):
		return "task_deletion_cancelled"
	default:
		return "task_deletion_file_cleanup_failed"
	}
}

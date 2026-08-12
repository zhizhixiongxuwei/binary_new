package decompile

import (
	"context"
	"errors"
	"fmt"
	"io"
	"time"

	"binaryscan/internal/taskcleanup"
)

type SourceProjectDeletionSweeperConfig struct {
	LeaseOwner    string
	LeaseDuration time.Duration
}

type SourceProjectDeletionSweeper struct {
	repository    SourceProjectDeletionSweepRepository
	deleter       taskcleanup.FileDeleter
	leaseOwner    string
	leaseDuration time.Duration
}

func NewSourceProjectDeletionLeaseOwner(pid int, entropy io.Reader) (string, error) {
	if pid <= 0 || entropy == nil {
		return "", errors.New("source project deletion lease owner input is invalid")
	}
	var random [12]byte
	if _, err := io.ReadFull(entropy, random[:]); err != nil {
		return "", fmt.Errorf("read source project deletion lease entropy: %w", err)
	}
	return fmt.Sprintf("source-project-deletion/%d/%x", pid, random), nil
}

func NewSourceProjectDeletionSweeper(
	repository SourceProjectDeletionSweepRepository,
	deleter taskcleanup.FileDeleter,
	config SourceProjectDeletionSweeperConfig,
) (*SourceProjectDeletionSweeper, error) {
	if repository == nil || deleter == nil {
		return nil, errors.New("source project deletion repository and deleter are required")
	}
	if config.LeaseOwner == "" || len(config.LeaseOwner) > 255 ||
		config.LeaseDuration <= 0 || config.LeaseDuration/3 <= 0 {
		return nil, errors.New("source project deletion lease configuration is invalid")
	}
	return &SourceProjectDeletionSweeper{
		repository: repository, deleter: deleter,
		leaseOwner: config.LeaseOwner, leaseDuration: config.LeaseDuration,
	}, nil
}

func (s *SourceProjectDeletionSweeper) Sweep(
	ctx context.Context,
	limit int,
) (SourceProjectDeletionSweepReport, error) {
	if limit < 1 || limit > MaxSourceProjectDeletionBatch {
		return SourceProjectDeletionSweepReport{}, errors.New("source project deletion batch size is invalid")
	}
	ids, err := s.repository.ListReadySourceProjectDeletions(ctx, limit)
	if err != nil {
		return SourceProjectDeletionSweepReport{}, err
	}
	var report SourceProjectDeletionSweepReport
	var failures []error
	for _, id := range ids {
		if err := ctx.Err(); err != nil {
			return report, errors.Join(append(failures, err)...)
		}
		claim, claimed, deferred, err := s.repository.ClaimSourceProjectDeletion(
			ctx, id, s.leaseOwner, s.leaseDuration,
		)
		if err != nil {
			report.Failures++
			failures = append(failures, fmt.Errorf("claim source project deletion: %w", err))
			continue
		}
		if deferred {
			report.Deferred++
			continue
		}
		if !claimed {
			report.Conflicts++
			continue
		}
		if !validSourceProjectDeletionClaim(claim) || claim.OperationID != id {
			report.Failures++
			failures = append(failures, errors.New("invalid source project deletion claim"))
			continue
		}
		report.Claimed++
		deleted, err := s.deleteClaim(ctx, claim)
		report.FilesDeleted += deleted
		if err != nil {
			report.Failures++
			failures = append(failures, fmt.Errorf("delete source project outputs: %w", err))
			s.fail(claim, "source_project_deletion_file_cleanup_failed")
			continue
		}
		completed, err := s.repository.FinalizeSourceProjectCascadeDeletion(ctx, claim)
		if err != nil {
			report.Failures++
			failures = append(failures, fmt.Errorf("finalize source project deletion: %w", err))
			s.fail(claim, "source_project_deletion_finalize_failed")
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

func (s *SourceProjectDeletionSweeper) deleteClaim(
	ctx context.Context,
	claim SourceProjectDeletionClaim,
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
				renewed, err := s.repository.RenewSourceProjectDeletion(
					cleanupCtx, claim, s.leaseDuration,
				)
				if err != nil || !renewed {
					if cleanupCtx.Err() != nil {
						keeperDone <- nil
						return
					}
					if err == nil {
						err = errors.New("source project deletion lease was lost")
					}
					keeperDone <- err
					cancel()
					return
				}
			}
		}
	}()
	deleted := 0
	for _, file := range claim.Files {
		removed, err := s.deleter.DeleteFile(cleanupCtx, file)
		if err != nil {
			cancel()
			keeperErr := <-keeperDone
			return deleted, errors.Join(err, keeperErr)
		}
		if removed {
			deleted++
		}
	}
	for _, scope := range claim.Scopes {
		if err := s.deleter.DeleteScope(cleanupCtx, scope); err != nil {
			cancel()
			keeperErr := <-keeperDone
			return deleted, errors.Join(err, keeperErr)
		}
	}
	cancel()
	if err := <-keeperDone; err != nil {
		return deleted, err
	}
	return deleted, nil
}

func (s *SourceProjectDeletionSweeper) fail(
	claim SourceProjectDeletionClaim,
	code string,
) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, _ = s.repository.FailSourceProjectCascadeDeletion(ctx, claim, code)
}

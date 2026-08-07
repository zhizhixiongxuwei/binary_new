package retention

import (
	"context"
	"errors"
	"fmt"
	"io"
	"time"

	"binaryscan/internal/taskcleanup"
)

type Sweeper struct {
	repository    Repository
	blobDeleter   BlobDeleter
	uploadDeleter UploadDirectoryDeleter
	outputDeleter taskcleanup.FileDeleter
	leaseOwner    string
	leaseDuration time.Duration
}

func NewLeaseOwner(pid int, entropy io.Reader) (string, error) {
	if pid <= 0 || entropy == nil {
		return "", errors.New("retention lease owner input is invalid")
	}
	var random [12]byte
	if _, err := io.ReadFull(entropy, random[:]); err != nil {
		return "", fmt.Errorf("read retention owner entropy: %w", err)
	}
	return fmt.Sprintf("sample-retention/%d/%x", pid, random), nil
}

func NewSweeper(
	repository Repository,
	blobDeleter BlobDeleter,
	uploadDeleter UploadDirectoryDeleter,
	config Config,
) (*Sweeper, error) {
	if repository == nil {
		return nil, errors.New("retention repository is required")
	}
	if blobDeleter == nil {
		return nil, errors.New("retention blob deleter is required")
	}
	if uploadDeleter == nil {
		return nil, errors.New("retention upload directory deleter is required")
	}
	if config.OutputDeleter == nil {
		return nil, errors.New("retention output deleter is required")
	}
	if config.LeaseOwner == "" || len(config.LeaseOwner) > 255 {
		return nil, errors.New("retention lease owner is invalid")
	}
	if config.LeaseDuration <= 0 || config.LeaseDuration/3 <= 0 {
		return nil, errors.New("retention lease duration is invalid")
	}
	return &Sweeper{
		repository: repository, blobDeleter: blobDeleter,
		uploadDeleter: uploadDeleter,
		outputDeleter: config.OutputDeleter,
		leaseOwner:    config.LeaseOwner,
		leaseDuration: config.LeaseDuration,
	}, nil
}

func (s *Sweeper) Sweep(ctx context.Context, limit int) (Report, error) {
	if err := ctx.Err(); err != nil {
		return Report{}, err
	}
	if limit < 1 || limit > MaxBatchSize {
		return Report{}, errors.New("retention batch size must be between 1 and 100")
	}

	var (
		report Report
		errs   []error
	)
	taskIDs, err := s.repository.ListExpiredTaskIDs(ctx, limit)
	if err != nil {
		report.Failures++
		errs = append(errs, fmt.Errorf("list expired task samples: %w", err))
	} else {
		for _, taskID := range taskIDs {
			if err := ctx.Err(); err != nil {
				return report, errors.Join(append(errs, err)...)
			}
			claim, claimed, err := s.repository.ClaimExpiredTaskSample(
				ctx, taskID, s.leaseOwner, s.leaseDuration,
			)
			if err != nil {
				report.Failures++
				errs = append(errs, fmt.Errorf("claim expired task sample: %w", err))
				continue
			}
			if !claimed {
				report.TaskSampleConflicts++
				continue
			}
			deleted, err := s.deleteTaskOutputs(ctx, claim)
			report.DecompileFilesDeleted += deleted
			if err != nil {
				report.Failures++
				errs = append(errs, fmt.Errorf(
					"delete expired decompile outputs: %w", err,
				))
				s.failTaskClaim(claim, "sample_retention_output_cleanup_failed")
				continue
			}
			released, err := s.repository.CompleteExpiredTaskSample(ctx, claim)
			if err != nil {
				report.Failures++
				errs = append(errs, fmt.Errorf(
					"complete expired task sample: %w", err,
				))
				s.failTaskClaim(claim, "sample_retention_finalize_failed")
				continue
			}
			if !released {
				report.TaskSampleConflicts++
				continue
			} else {
				report.TaskSamplesReleased++
			}
		}
	}

	if err := ctx.Err(); err != nil {
		return report, errors.Join(append(errs, err)...)
	}
	cleanupIDs, err := s.repository.ListPendingUploadPartCleanupIDs(ctx, limit)
	if err != nil {
		report.Failures++
		errs = append(errs, fmt.Errorf("list pending upload part cleanup: %w", err))
	} else {
		for _, uploadID := range cleanupIDs {
			if err := ctx.Err(); err != nil {
				return report, errors.Join(append(errs, err)...)
			}
			cleaned, err := s.repository.CleanupUploadParts(
				ctx,
				uploadID,
				func() error {
					return s.uploadDeleter.Delete(ctx, uploadID)
				},
			)
			if err != nil {
				report.Failures++
				errs = append(errs, fmt.Errorf("clean upload parts: %w", err))
				continue
			}
			if cleaned {
				report.UploadPartsCleaned++
			}
		}
	}

	if err := ctx.Err(); err != nil {
		return report, errors.Join(append(errs, err)...)
	}
	uploadIDs, err := s.repository.ListExpiredUploadIDs(ctx, limit)
	if err != nil {
		report.Failures++
		errs = append(errs, fmt.Errorf("list expired uploads: %w", err))
	} else {
		for _, uploadID := range uploadIDs {
			if err := ctx.Err(); err != nil {
				return report, errors.Join(append(errs, err)...)
			}
			expired, err := s.repository.ExpireUpload(
				ctx,
				uploadID,
				func() error {
					return s.uploadDeleter.Delete(ctx, uploadID)
				},
			)
			if err != nil {
				report.Failures++
				errs = append(errs, fmt.Errorf("expire upload: %w", err))
				continue
			}
			if expired {
				report.UploadsExpired++
			}
		}
	}

	if err := ctx.Err(); err != nil {
		return report, errors.Join(append(errs, err)...)
	}
	blobIDs, err := s.repository.ListDeletingBlobIDs(ctx, limit)
	if err != nil {
		report.Failures++
		errs = append(errs, fmt.Errorf("list deleting blobs: %w", err))
	} else {
		for _, blobID := range blobIDs {
			if err := ctx.Err(); err != nil {
				return report, errors.Join(append(errs, err)...)
			}
			deleted, err := s.repository.FinalizeDeletingBlob(
				ctx,
				blobID,
				func(blob Blob) error {
					return s.blobDeleter.Delete(ctx, blob)
				},
			)
			if err != nil {
				report.Failures++
				errs = append(errs, fmt.Errorf("delete retained blob: %w", err))
				continue
			}
			if deleted {
				report.BlobsDeleted++
			}
		}
	}
	return report, errors.Join(errs...)
}

func (s *Sweeper) deleteTaskOutputs(
	ctx context.Context,
	claim TaskSampleClaim,
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
				renewed, err := s.repository.RenewExpiredTaskSample(
					cleanupCtx, claim, s.leaseDuration,
				)
				if err != nil || !renewed {
					if cleanupCtx.Err() != nil {
						keeperDone <- nil
					} else if err != nil {
						keeperDone <- err
					} else {
						keeperDone <- errors.New(
							"sample retention lease was lost",
						)
					}
					cancel()
					return
				}
			}
		}
	}()
	deleted := 0
	for _, file := range claim.Files {
		removed, err := s.outputDeleter.DeleteFile(cleanupCtx, file)
		if err != nil {
			cancel()
			return deleted, errors.Join(err, <-keeperDone)
		}
		if removed {
			deleted++
		}
	}
	for _, scope := range claim.Scopes {
		if err := s.outputDeleter.DeleteScope(cleanupCtx, scope); err != nil {
			cancel()
			return deleted, errors.Join(err, <-keeperDone)
		}
	}
	cancel()
	return deleted, <-keeperDone
}

func (s *Sweeper) failTaskClaim(claim TaskSampleClaim, code string) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, _ = s.repository.FailExpiredTaskSample(ctx, claim, code)
}

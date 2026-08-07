package maintenance

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"binaryscan/internal/orphanreaper"
	reporting "binaryscan/internal/report"
	"binaryscan/internal/retention"
	"binaryscan/internal/taskcleanup"
	"binaryscan/internal/workspace"
)

const (
	recoveryBatchSize     = 100
	taskDeletionBatchSize = 10
	retentionBatchSize    = 25
	orphanSweepBatchSize  = 25
	// Root-confined recursive removal is not context-cancellable. Limit each
	// maintenance cycle to one bounded workspace so shutdown can be delayed by
	// at most one 50 GiB / 100,000-file task tree.
	workspaceSweepBatchSize = 1
)

type Database interface {
	PingContext(context.Context) error
}

type Recoverer interface {
	RecoverExpired(context.Context, int) (int, error)
}

type WorkspaceSweeper interface {
	Sweep(context.Context, int) (workspace.SweepReport, error)
}

type RetentionSweeper interface {
	Sweep(context.Context, int) (retention.Report, error)
}

type TaskDeletionSweeper interface {
	Sweep(context.Context, int) (taskcleanup.Report, error)
}

type OrphanSweeper interface {
	Sweep(context.Context, int) (orphanreaper.Report, error)
}

type ReportGenerationRecoverer interface {
	RecoverExpired(context.Context, int) (int, error)
}

type RunnerConfig struct {
	Interval         time.Duration
	PingTimeout      time.Duration
	Database         Database
	Queue            Recoverer
	ReportGeneration ReportGenerationRecoverer
	TaskDeletion     TaskDeletionSweeper
	Retention        RetentionSweeper
	Orphans          OrphanSweeper
	Workspace        WorkspaceSweeper
	Logger           *slog.Logger
}

type Runner struct {
	interval         time.Duration
	pingTimeout      time.Duration
	database         Database
	queue            Recoverer
	reportGeneration ReportGenerationRecoverer
	taskDeletion     TaskDeletionSweeper
	retention        RetentionSweeper
	orphans          OrphanSweeper
	workspace        WorkspaceSweeper
	logger           *slog.Logger
}

func NewRunner(config RunnerConfig) (*Runner, error) {
	if config.Interval <= 0 {
		return nil, errors.New("maintenance interval must be positive")
	}
	if config.PingTimeout <= 0 {
		return nil, errors.New("maintenance database ping timeout must be positive")
	}
	if config.Database == nil {
		return nil, errors.New("maintenance database is required")
	}
	if config.Queue == nil {
		return nil, errors.New("maintenance queue is required")
	}
	if config.TaskDeletion == nil {
		return nil, errors.New("maintenance task deletion sweeper is required")
	}
	if config.Retention == nil {
		return nil, errors.New("maintenance retention sweeper is required")
	}
	if config.Workspace == nil {
		return nil, errors.New("maintenance workspace sweeper is required")
	}
	if config.Logger == nil {
		return nil, errors.New("maintenance logger is required")
	}
	return &Runner{
		interval:         config.Interval,
		pingTimeout:      config.PingTimeout,
		database:         config.Database,
		queue:            config.Queue,
		reportGeneration: config.ReportGeneration,
		taskDeletion:     config.TaskDeletion,
		retention:        config.Retention,
		orphans:          config.Orphans,
		workspace:        config.Workspace,
		logger:           config.Logger,
	}, nil
}

func (r *Runner) Run(ctx context.Context) error {
	if ctx.Err() != nil {
		return nil
	}
	r.recover(ctx)

	ticker := time.NewTicker(r.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			r.recover(ctx)
		}
	}
}

func (r *Runner) recover(parent context.Context) {
	if parent.Err() != nil {
		return
	}
	pingCtx, cancel := context.WithTimeout(parent, r.pingTimeout)
	err := r.database.PingContext(pingCtx)
	cancel()
	if err != nil {
		if parent.Err() == nil {
			r.logger.WarnContext(parent, "maintenance database check failed", "error", err)
		}
		return
	}

	recovered, err := r.queue.RecoverExpired(parent, recoveryBatchSize)
	if err != nil {
		if parent.Err() == nil {
			r.logger.WarnContext(parent, "expired job recovery failed", "error", err)
		}
	} else if recovered > 0 {
		r.logger.InfoContext(
			parent,
			"expired jobs recovered",
			slog.Int("recovered_jobs", recovered),
		)
	}
	if parent.Err() != nil {
		return
	}
	if r.reportGeneration != nil {
		recoveredReports, reportErr := r.reportGeneration.RecoverExpired(
			parent, reporting.MaxRecoveryBatch,
		)
		if reportErr != nil {
			if parent.Err() == nil {
				r.logger.WarnContext(
					parent, "expired report generation recovery failed",
				)
			}
		} else if recoveredReports > 0 {
			r.logger.InfoContext(
				parent,
				"expired report generations recovered",
				slog.Int("recovered_reports", recoveredReports),
			)
		}
	}
	if parent.Err() != nil {
		return
	}
	deletionReport, err := r.taskDeletion.Sweep(
		parent, taskDeletionBatchSize,
	)
	if deletionReport.Claimed > 0 ||
		deletionReport.Completed > 0 ||
		deletionReport.FilesDeleted > 0 ||
		deletionReport.Failures > 0 ||
		deletionReport.Conflicts > 0 {
		r.logger.InfoContext(
			parent,
			"task deletion sweep completed",
			slog.Int("claimed_tasks", deletionReport.Claimed),
			slog.Int("deleted_tasks", deletionReport.Completed),
			slog.Int("deleted_files", deletionReport.FilesDeleted),
			slog.Int("failed_items", deletionReport.Failures),
			slog.Int("conflicts", deletionReport.Conflicts),
		)
	}
	if err != nil && parent.Err() == nil {
		r.logger.WarnContext(parent, "task deletion sweep failed")
	}
	if parent.Err() != nil {
		return
	}
	retentionReport, err := r.retention.Sweep(parent, retentionBatchSize)
	if retentionReport.TaskSamplesReleased > 0 ||
		retentionReport.UploadPartsCleaned > 0 ||
		retentionReport.UploadsExpired > 0 ||
		retentionReport.BlobsDeleted > 0 ||
		retentionReport.Failures > 0 {
		r.logger.InfoContext(
			parent,
			"retention sweep completed",
			slog.Int("task_samples_released", retentionReport.TaskSamplesReleased),
			slog.Int("upload_parts_cleaned", retentionReport.UploadPartsCleaned),
			slog.Int("uploads_expired", retentionReport.UploadsExpired),
			slog.Int("blobs_deleted", retentionReport.BlobsDeleted),
			slog.Int("failed_items", retentionReport.Failures),
		)
	}
	if err != nil && parent.Err() == nil {
		// Retention errors can include filesystem details. Keep operational logs
		// generic and rely on counters plus audit rows for safe diagnosis.
		r.logger.WarnContext(parent, "retention sweep failed")
	}
	if parent.Err() != nil {
		return
	}
	if r.orphans != nil {
		orphanReport, orphanErr := r.orphans.Sweep(parent, orphanSweepBatchSize)
		if orphanReport.BlobFilesScanned > 0 ||
			orphanReport.UploadDirsScanned > 0 ||
			orphanReport.StoredFilesScanned > 0 ||
			orphanReport.BlobReferencesScanned > 0 ||
			orphanReport.OrphanBlobs > 0 ||
			orphanReport.OrphanUploads > 0 ||
			orphanReport.OrphanStoredFiles > 0 ||
			orphanReport.RemovedBlobs > 0 ||
			orphanReport.RemovedUploads > 0 ||
			orphanReport.RemovedStoredFiles > 0 ||
			orphanReport.DriftedBlobReferences > 0 ||
			orphanReport.RecheckProtected > 0 ||
			orphanReport.Failures > 0 {
			r.logger.InfoContext(
				parent,
				"orphan reconciliation sweep completed",
				slog.Int("scanned_blob_files", orphanReport.BlobFilesScanned),
				slog.Int("scanned_upload_directories", orphanReport.UploadDirsScanned),
				slog.Int("scanned_stored_files", orphanReport.StoredFilesScanned),
				slog.Int("scanned_blob_references", orphanReport.BlobReferencesScanned),
				slog.Int("orphan_blob_files", orphanReport.OrphanBlobs),
				slog.Int("orphan_upload_directories", orphanReport.OrphanUploads),
				slog.Int("orphan_stored_files", orphanReport.OrphanStoredFiles),
				slog.Int("removed_blob_files", orphanReport.RemovedBlobs),
				slog.Int("removed_upload_directories", orphanReport.RemovedUploads),
				slog.Int("removed_stored_files", orphanReport.RemovedStoredFiles),
				slog.Int("drifted_blob_references", orphanReport.DriftedBlobReferences),
				slog.Int("corrected_blob_references", orphanReport.CorrectedBlobReferences),
				slog.Int("recheck_protected", orphanReport.RecheckProtected),
				slog.Int("failed_items", orphanReport.Failures),
				slog.Bool("dry_run", orphanReport.DryRun),
			)
		}
		if orphanErr != nil && parent.Err() == nil {
			// Candidate paths and storage keys are intentionally excluded here.
			// Per-item identities remain available through the returned report in
			// tests, while successful deletions have append-only audit events.
			r.logger.WarnContext(parent, "orphan reconciliation sweep failed")
		}
	}
	if parent.Err() != nil {
		return
	}
	report, err := r.workspace.Sweep(parent, workspaceSweepBatchSize)
	if err != nil {
		if parent.Err() == nil {
			r.logger.WarnContext(
				parent,
				"task workspace sweep failed",
				"error",
				err,
			)
		}
		return
	}
	for _, diagnostic := range report.Diagnostics {
		r.logger.WarnContext(
			parent,
			"task workspace skipped",
			"workspace",
			diagnostic.Name,
			"error",
			diagnostic.Err,
		)
	}
	if report.Removed > 0 {
		r.logger.InfoContext(
			parent,
			"inactive task workspaces removed",
			slog.Int("removed_workspaces", report.Removed),
			slog.Int("scanned_workspaces", report.Scanned),
			slog.Int("active_workspaces", report.Active),
			slog.Int("skipped_workspaces", report.Skipped),
		)
	}
}

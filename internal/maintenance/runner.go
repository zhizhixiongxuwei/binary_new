package maintenance

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"binaryscan/internal/decompile"
	"binaryscan/internal/orphanreaper"
	reporting "binaryscan/internal/report"
	"binaryscan/internal/retention"
	"binaryscan/internal/taskcleanup"
	"binaryscan/internal/upload"
	"binaryscan/internal/workspace"
)

const (
	recoveryBatchSize                = 100
	taskDeletionBatchSize            = 10
	sourceProjectDeletionBatchSize   = 10
	cAnalysisRunDeletionBatchSize    = 10
	javaAnalysisRunDeletionBatchSize = 10
	directTaskRecoveryBatchSize      = 100
	archiveAssociationBatchSize      = 100
	retentionBatchSize               = 25
	orphanSweepBatchSize             = 25
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

type SourceProjectDeletionSweeper interface {
	Sweep(context.Context, int) (decompile.SourceProjectDeletionSweepReport, error)
}

type OrphanSweeper interface {
	Sweep(context.Context, int) (orphanreaper.Report, error)
}

type ReportGenerationRecoverer interface {
	RecoverExpired(context.Context, int) (int, error)
}

type CAnalysisRunDeletionRecoverer interface {
	RecoverPending(context.Context, int) (int, error)
}

type DirectTaskRecoverer interface {
	RecoverDirectTasks(context.Context, int) (upload.DirectTaskRecoveryReport, error)
}

type ArchiveAssociationRecoverer interface {
	RecoverArchiveImports(context.Context, int) (upload.ArchiveImportRecoveryReport, error)
}

type RunnerConfig struct {
	Interval                time.Duration
	PingTimeout             time.Duration
	Database                Database
	Queue                   Recoverer
	ArchiveImport           CAnalysisRunDeletionRecoverer
	ReportGeneration        ReportGenerationRecoverer
	SourceProjectDeletion   SourceProjectDeletionSweeper
	CAnalysisRunDeletion    CAnalysisRunDeletionRecoverer
	JavaAnalysisRunDeletion CAnalysisRunDeletionRecoverer
	TaskDeletion            TaskDeletionSweeper
	DirectTaskRecovery      DirectTaskRecoverer
	ArchiveAssociation      ArchiveAssociationRecoverer
	Retention               RetentionSweeper
	Orphans                 OrphanSweeper
	Workspace               WorkspaceSweeper
	Logger                  *slog.Logger
}

type Runner struct {
	interval                time.Duration
	pingTimeout             time.Duration
	database                Database
	queue                   Recoverer
	archiveImport           CAnalysisRunDeletionRecoverer
	reportGeneration        ReportGenerationRecoverer
	sourceProjectDeletion   SourceProjectDeletionSweeper
	cAnalysisRunDeletion    CAnalysisRunDeletionRecoverer
	javaAnalysisRunDeletion CAnalysisRunDeletionRecoverer
	taskDeletion            TaskDeletionSweeper
	directTaskRecovery      DirectTaskRecoverer
	archiveAssociation      ArchiveAssociationRecoverer
	retention               RetentionSweeper
	orphans                 OrphanSweeper
	workspace               WorkspaceSweeper
	logger                  *slog.Logger
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
	if config.CAnalysisRunDeletion == nil {
		return nil, errors.New("maintenance C-analysis run deletion recovery is required")
	}
	if config.JavaAnalysisRunDeletion == nil {
		return nil, errors.New("maintenance Java-analysis run deletion recovery is required")
	}
	if config.TaskDeletion == nil {
		return nil, errors.New("maintenance task deletion sweeper is required")
	}
	if config.DirectTaskRecovery == nil {
		return nil, errors.New("maintenance direct task recovery is required")
	}
	if config.ArchiveAssociation == nil {
		return nil, errors.New("maintenance archive association recovery is required")
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
		interval:                config.Interval,
		pingTimeout:             config.PingTimeout,
		database:                config.Database,
		queue:                   config.Queue,
		archiveImport:           config.ArchiveImport,
		reportGeneration:        config.ReportGeneration,
		sourceProjectDeletion:   config.SourceProjectDeletion,
		cAnalysisRunDeletion:    config.CAnalysisRunDeletion,
		javaAnalysisRunDeletion: config.JavaAnalysisRunDeletion,
		taskDeletion:            config.TaskDeletion,
		directTaskRecovery:      config.DirectTaskRecovery,
		archiveAssociation:      config.ArchiveAssociation,
		retention:               config.Retention,
		orphans:                 config.Orphans,
		workspace:               config.Workspace,
		logger:                  config.Logger,
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
	if r.archiveImport != nil {
		recoveredImports, recoveryErr := r.archiveImport.RecoverPending(
			parent, recoveryBatchSize,
		)
		if recoveryErr != nil {
			if parent.Err() == nil {
				r.logger.WarnContext(parent, "archive import recovery failed")
			}
		} else if recoveredImports > 0 {
			r.logger.InfoContext(
				parent,
				"archive imports recovered",
				slog.Int("recovered_archive_imports", recoveredImports),
			)
		}
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
	if r.sourceProjectDeletion != nil {
		deletionReport, deletionErr := r.sourceProjectDeletion.Sweep(
			parent, sourceProjectDeletionBatchSize,
		)
		if deletionReport.Claimed > 0 || deletionReport.Completed > 0 ||
			deletionReport.FilesDeleted > 0 || deletionReport.Deferred > 0 ||
			deletionReport.Failures > 0 || deletionReport.Conflicts > 0 {
			r.logger.InfoContext(
				parent, "source project deletion sweep completed",
				slog.Int("claimed_operations", deletionReport.Claimed),
				slog.Int("completed_operations", deletionReport.Completed),
				slog.Int("deleted_files", deletionReport.FilesDeleted),
				slog.Int("deferred_operations", deletionReport.Deferred),
				slog.Int("failed_operations", deletionReport.Failures),
				slog.Int("conflicts", deletionReport.Conflicts),
			)
		}
		if deletionErr != nil && parent.Err() == nil {
			r.logger.WarnContext(parent, "source project deletion sweep failed")
		}
	}
	if parent.Err() != nil {
		return
	}
	if r.cAnalysisRunDeletion != nil {
		recoveredRuns, recoveryErr := r.cAnalysisRunDeletion.RecoverPending(
			parent, cAnalysisRunDeletionBatchSize,
		)
		if recoveryErr != nil {
			if parent.Err() == nil {
				r.logger.WarnContext(
					parent, "pending C-analysis run deletion recovery failed",
				)
			}
		} else if recoveredRuns > 0 {
			r.logger.InfoContext(
				parent,
				"pending C-analysis run deletions recovered",
				slog.Int("recovered_runs", recoveredRuns),
			)
		}
	}
	if parent.Err() != nil {
		return
	}
	if r.javaAnalysisRunDeletion != nil {
		recoveredRuns, recoveryErr := r.javaAnalysisRunDeletion.RecoverPending(
			parent, javaAnalysisRunDeletionBatchSize,
		)
		if recoveryErr != nil {
			if parent.Err() == nil {
				r.logger.WarnContext(
					parent, "pending Java-analysis run deletion recovery failed",
				)
			}
		} else if recoveredRuns > 0 {
			r.logger.InfoContext(
				parent,
				"pending Java-analysis run deletions recovered",
				slog.Int("recovered_runs", recoveredRuns),
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
	directTaskReport, directTaskErr := r.directTaskRecovery.RecoverDirectTasks(
		parent, directTaskRecoveryBatchSize,
	)
	if directTaskReport.Candidates > 0 || directTaskReport.Ensured > 0 ||
		directTaskReport.Failures > 0 || directTaskReport.Wrapped {
		r.logger.InfoContext(
			parent,
			"direct upload task recovery completed",
			slog.Int("candidates", directTaskReport.Candidates),
			slog.Int("ensured_tasks", directTaskReport.Ensured),
			slog.Int("failed_items", directTaskReport.Failures),
			slog.Bool("cursor_wrapped", directTaskReport.Wrapped),
		)
	}
	if directTaskErr != nil && parent.Err() == nil {
		r.logger.WarnContext(parent, "direct upload task recovery failed")
	}
	if parent.Err() != nil {
		return
	}
	archiveAssociationReport, archiveAssociationErr :=
		r.archiveAssociation.RecoverArchiveImports(parent, archiveAssociationBatchSize)
	if archiveAssociationReport.Candidates > 0 || archiveAssociationReport.Ensured > 0 ||
		archiveAssociationReport.Failures > 0 || archiveAssociationReport.Wrapped {
		r.logger.InfoContext(
			parent,
			"archive upload association recovery completed",
			slog.Int("candidates", archiveAssociationReport.Candidates),
			slog.Int("ensured_imports", archiveAssociationReport.Ensured),
			slog.Int("failed_items", archiveAssociationReport.Failures),
			slog.Bool("cursor_wrapped", archiveAssociationReport.Wrapped),
		)
	}
	if archiveAssociationErr != nil && parent.Err() == nil {
		r.logger.WarnContext(parent, "archive upload association recovery failed")
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
			attributes := make([]any, 0, 6)
			for index, diagnostic := range orphanReport.Diagnostics {
				if index == 3 {
					break
				}
				attributes = append(attributes,
					slog.String(fmt.Sprintf("diagnostic_%d_kind", index+1), diagnostic.Kind),
					slog.String(fmt.Sprintf("diagnostic_%d_error", index+1), diagnostic.Err.Error()),
				)
			}
			r.logger.WarnContext(parent, "orphan reconciliation sweep failed", attributes...)
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

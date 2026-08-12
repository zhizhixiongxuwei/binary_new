package report

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"math"
	"sort"
	"strings"

	"binaryscan/internal/taskcleanup"
)

var (
	ErrJavaAnalysisRunNotFound    = errors.New("Java analysis run not found")
	ErrJavaAnalysisRunNotTerminal = errors.New("Java analysis run is not terminal")
)

const MaxJavaAnalysisRunDeletionRecoveryBatch = 100

// JavaAnalysisRunCascadeDeleter owns the cross-domain deletion boundary for a
// terminal Java-analysis run. It first commits an invisible deletion tombstone,
// then removes files and finalizes rows. A crash can therefore leak only hidden,
// retryable storage, never a visible report whose file has already disappeared.
type JavaAnalysisRunCascadeDeleter struct {
	db      *sql.DB
	deleter taskcleanup.FileDeleter
}

type javaAnalysisRunDeletionPlan struct {
	jobID       string
	reportIDs   []string
	artifactIDs []string
	files       []taskcleanup.StoredFile
}

func NewJavaAnalysisRunCascadeDeleter(
	db *sql.DB,
	repositoryRoot string,
) (*JavaAnalysisRunCascadeDeleter, error) {
	if db == nil {
		return nil, errors.New("Java-analysis run cascade database is required")
	}
	deleter, err := taskcleanup.NewRepositoryFileDeleter(repositoryRoot)
	if err != nil {
		return nil, fmt.Errorf("initialize Java-analysis run cascade file deletion: %w", err)
	}
	return &JavaAnalysisRunCascadeDeleter{db: db, deleter: deleter}, nil
}

func (d *JavaAnalysisRunCascadeDeleter) Delete(
	ctx context.Context,
	taskID string,
	runID string,
) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if d == nil || d.db == nil || d.deleter == nil ||
		!uuidPattern.MatchString(taskID) || !uuidPattern.MatchString(runID) {
		return errors.New("Java-analysis run cascade input is invalid")
	}
	plan, err := d.prepare(ctx, taskID, runID)
	if err != nil {
		return err
	}
	for _, file := range plan.files {
		if _, err := d.deleter.DeleteFile(ctx, file); err != nil {
			return fmt.Errorf("delete Java-analysis dependent report output: %w", err)
		}
	}
	return d.finalize(ctx, taskID, runID, plan)
}

// RecoverPending completes deletions whose durable tombstone was committed
// before the API process could remove files or finalize database rows.
func (d *JavaAnalysisRunCascadeDeleter) RecoverPending(
	ctx context.Context,
	limit int,
) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	if d == nil || d.db == nil || d.deleter == nil || limit < 1 ||
		limit > MaxJavaAnalysisRunDeletionRecoveryBatch {
		return 0, errors.New("Java-analysis run deletion recovery input is invalid")
	}
	rows, err := d.db.QueryContext(ctx, `
SELECT run.task_id, run.id
FROM java_analysis_runs run
JOIN tasks task
  ON task.id = run.task_id AND task.deleted_at IS NULL
JOIN decompile_source_projects project
  ON project.task_id = run.task_id
 AND project.id = run.source_project_id
 AND project.deleted_at IS NULL
 AND project.storage_deleted_at IS NULL
WHERE run.deletion_started_at IS NOT NULL
  AND NOT EXISTS (
      SELECT 1
      FROM source_project_deletion_operations operation
      WHERE operation.active_project_id = run.source_project_id
  )
ORDER BY run.deletion_started_at ASC, run.id ASC
LIMIT ?`, limit)
	if err != nil {
		return 0, fmt.Errorf("list pending Java-analysis run deletions: %w", err)
	}
	type candidate struct {
		taskID string
		runID  string
	}
	candidates := make([]candidate, 0, limit)
	for rows.Next() {
		var value candidate
		if err := rows.Scan(&value.taskID, &value.runID); err != nil {
			rows.Close()
			return 0, fmt.Errorf("scan pending Java-analysis run deletion: %w", err)
		}
		if !uuidPattern.MatchString(value.taskID) ||
			!uuidPattern.MatchString(value.runID) || len(candidates) >= limit {
			rows.Close()
			return 0, errors.New("pending Java-analysis run deletion is invalid")
		}
		candidates = append(candidates, value)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return 0, fmt.Errorf("iterate pending Java-analysis run deletions: %w", err)
	}
	if err := rows.Close(); err != nil {
		return 0, fmt.Errorf("close pending Java-analysis run deletions: %w", err)
	}

	completed := 0
	failures := make([]error, 0)
	for _, candidate := range candidates {
		if err := ctx.Err(); err != nil {
			return completed, errors.Join(append(failures, err)...)
		}
		err := d.Delete(ctx, candidate.taskID, candidate.runID)
		if errors.Is(err, ErrJavaAnalysisRunNotFound) {
			continue
		}
		if err != nil {
			failures = append(
				failures,
				fmt.Errorf("recover pending Java-analysis run deletion: %w", err),
			)
			continue
		}
		completed++
	}
	return completed, errors.Join(failures...)
}

func (d *JavaAnalysisRunCascadeDeleter) prepare(
	ctx context.Context,
	taskID string,
	runID string,
) (javaAnalysisRunDeletionPlan, error) {
	tx, err := d.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return javaAnalysisRunDeletionPlan{}, fmt.Errorf(
			"begin Java-analysis run cascade preparation: %w", err,
		)
	}
	defer tx.Rollback()

	var taskMarker uint8
	err = tx.QueryRowContext(ctx, `
SELECT 1
FROM tasks
WHERE id = ? AND deleted_at IS NULL
FOR UPDATE`, taskID).Scan(&taskMarker)
	if errors.Is(err, sql.ErrNoRows) {
		return javaAnalysisRunDeletionPlan{}, ErrJavaAnalysisRunNotFound
	}
	if err != nil {
		return javaAnalysisRunDeletionPlan{}, fmt.Errorf(
			"lock Java-analysis run task: %w", err,
		)
	}

	var runStatus, jobID, jobStatus string
	err = tx.QueryRowContext(ctx, `
SELECT run.status, run.job_id, job.status
FROM java_analysis_runs run
JOIN jobs job ON job.task_id = run.task_id AND job.id = run.job_id
WHERE run.task_id = ? AND run.id = ?
FOR UPDATE`, taskID, runID).Scan(&runStatus, &jobID, &jobStatus)
	if errors.Is(err, sql.ErrNoRows) {
		return javaAnalysisRunDeletionPlan{}, ErrJavaAnalysisRunNotFound
	}
	if err != nil {
		return javaAnalysisRunDeletionPlan{}, fmt.Errorf(
			"lock Java-analysis run cascade: %w", err,
		)
	}
	if !terminalJavaAnalysisRunStatus(runStatus) || !terminalJavaAnalysisJobStatus(jobStatus) {
		return javaAnalysisRunDeletionPlan{}, ErrJavaAnalysisRunNotTerminal
	}

	reportIDs, artifactIDs, files, err := collectJavaAnalysisRunReportOutputs(
		ctx, tx, taskID,
	)
	if err != nil {
		return javaAnalysisRunDeletionPlan{}, err
	}
	if err := markJavaAnalysisRunDeletion(
		ctx, tx, taskID, runID, reportIDs, artifactIDs,
	); err != nil {
		return javaAnalysisRunDeletionPlan{}, err
	}
	if err := tx.Commit(); err != nil {
		return javaAnalysisRunDeletionPlan{}, fmt.Errorf(
			"commit Java-analysis run cascade tombstone: %w", err,
		)
	}
	return javaAnalysisRunDeletionPlan{
		jobID: jobID, reportIDs: reportIDs, artifactIDs: artifactIDs,
		files: files,
	}, nil
}

func (d *JavaAnalysisRunCascadeDeleter) finalize(
	ctx context.Context,
	taskID string,
	runID string,
	plan javaAnalysisRunDeletionPlan,
) error {
	tx, err := d.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return fmt.Errorf("begin Java-analysis run cascade finalization: %w", err)
	}
	defer tx.Rollback()
	var taskMarker uint8
	err = tx.QueryRowContext(ctx, `
SELECT 1
FROM tasks
WHERE id = ?
FOR UPDATE`, taskID).Scan(&taskMarker)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrJavaAnalysisRunNotFound
	}
	if err != nil {
		return fmt.Errorf("lock Java-analysis run task for finalization: %w", err)
	}
	var runStatus, jobID, jobStatus string
	var deletionStartedAt sql.NullTime
	err = tx.QueryRowContext(ctx, `
SELECT run.status, run.job_id, job.status, run.deletion_started_at
FROM java_analysis_runs run
JOIN jobs job ON job.task_id = run.task_id AND job.id = run.job_id
WHERE run.task_id = ? AND run.id = ?
FOR UPDATE`, taskID, runID).Scan(
		&runStatus, &jobID, &jobStatus, &deletionStartedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrJavaAnalysisRunNotFound
	}
	if err != nil {
		return fmt.Errorf("lock Java-analysis run cascade finalization: %w", err)
	}
	if !deletionStartedAt.Valid || jobID != plan.jobID ||
		!terminalJavaAnalysisRunStatus(runStatus) ||
		!terminalJavaAnalysisJobStatus(jobStatus) {
		return ErrJavaAnalysisRunNotTerminal
	}
	if err := deleteJavaAnalysisRunRows(
		ctx, tx, taskID, runID, jobID, plan.reportIDs, plan.artifactIDs,
	); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit Java-analysis run cascade: %w", err)
	}
	return nil
}

func markJavaAnalysisRunDeletion(
	ctx context.Context,
	tx *sql.Tx,
	taskID string,
	runID string,
	reportIDs []string,
	artifactIDs []string,
) error {
	if _, err := tx.ExecContext(ctx, `
UPDATE java_analysis_runs
SET deletion_started_at = COALESCE(deletion_started_at, UTC_TIMESTAMP(6))
WHERE task_id = ? AND id = ?
  AND status IN ('succeeded', 'partial', 'failed', 'cancelled')`,
		taskID, runID,
	); err != nil {
		return fmt.Errorf("tombstone Java-analysis run: %w", err)
	}
	if err := markJavaAnalysisRunRowsByID(
		ctx, tx, "reports", taskID, reportIDs,
	); err != nil {
		return err
	}
	return markJavaAnalysisRunRowsByID(
		ctx, tx, "artifacts", taskID, artifactIDs,
	)
}

func markJavaAnalysisRunRowsByID(
	ctx context.Context,
	tx *sql.Tx,
	table string,
	taskID string,
	ids []string,
) error {
	if len(ids) == 0 {
		return nil
	}
	arguments := make([]any, 0, len(ids)+1)
	arguments = append(arguments, taskID)
	for _, id := range ids {
		if !uuidPattern.MatchString(id) {
			return errors.New("Java-analysis run cascade row ID is invalid")
		}
		arguments = append(arguments, id)
	}
	placeholders := strings.TrimRight(strings.Repeat("?,", len(ids)), ",")
	var statement string
	switch table {
	case "reports":
		statement = `UPDATE reports
SET snapshot_state = 'stale',
    deleted_at = COALESCE(deleted_at, UTC_TIMESTAMP(6)),
    generation_owner = NULL, generation_lease_until = NULL,
    generation_heartbeat_at = NULL
WHERE task_id = ? AND id IN (` + placeholders + `)`
	case "artifacts":
		statement = `UPDATE artifacts
SET state = 'deleting',
    deleted_at = COALESCE(deleted_at, UTC_TIMESTAMP(6))
WHERE task_id = ? AND id IN (` + placeholders + `)`
	default:
		return errors.New("Java-analysis run cascade table is invalid")
	}
	if _, err := tx.ExecContext(ctx, statement, arguments...); err != nil {
		return fmt.Errorf("tombstone Java-analysis dependent %s: %w", table, err)
	}
	return nil
}

func collectJavaAnalysisRunReportOutputs(
	ctx context.Context,
	tx *sql.Tx,
	taskID string,
) ([]string, []string, []taskcleanup.StoredFile, error) {
	rows, err := tx.QueryContext(ctx, `
SELECT report.id, report.format, report.storage_key, report.sha256,
       report.size_bytes, report.artifact_id
FROM reports report
WHERE report.task_id = ?
ORDER BY report.id
FOR UPDATE`, taskID)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("list Java-analysis dependent reports: %w", err)
	}
	reportIDs := make([]string, 0)
	files := make([]taskcleanup.StoredFile, 0)
	artifactCandidates := make(map[string]struct{})
	for rows.Next() {
		var reportID, format string
		var storageKey, digest, artifactID sql.NullString
		var size sql.Null[uint64]
		if err := rows.Scan(
			&reportID, &format, &storageKey, &digest, &size, &artifactID,
		); err != nil {
			rows.Close()
			return nil, nil, nil, fmt.Errorf("scan Java-analysis dependent report: %w", err)
		}
		if !uuidPattern.MatchString(reportID) {
			rows.Close()
			return nil, nil, nil, errors.New("Java-analysis dependent report ID is invalid")
		}
		reportIDs = append(reportIDs, reportID)
		if storageKey.Valid || digest.Valid || size.Valid {
			if !storageKey.Valid || !digest.Valid || !size.Valid || size.V > math.MaxInt64 {
				rows.Close()
				return nil, nil, nil, errors.New("Java-analysis dependent report metadata is incomplete")
			}
			files = append(files, taskcleanup.StoredFile{
				Kind: taskcleanup.FileReport, TaskID: taskID, RecordID: reportID,
				Format: format, StorageKey: storageKey.String,
				SHA256: digest.String, SizeBytes: int64(size.V),
			})
		}
		if artifactID.Valid {
			if !uuidPattern.MatchString(artifactID.String) {
				rows.Close()
				return nil, nil, nil, errors.New("Java-analysis dependent artifact ID is invalid")
			}
			artifactCandidates[artifactID.String] = struct{}{}
		}
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, nil, nil, fmt.Errorf("iterate Java-analysis dependent reports: %w", err)
	}
	if err := rows.Close(); err != nil {
		return nil, nil, nil, fmt.Errorf("close Java-analysis dependent reports: %w", err)
	}

	artifactIDs := make([]string, 0, len(artifactCandidates))
	for artifactID := range artifactCandidates {
		artifactIDs = append(artifactIDs, artifactID)
	}
	sort.Strings(artifactIDs)
	exclusiveArtifacts := artifactIDs[:0]
	for _, artifactID := range artifactIDs {
		var storageKey, digest string
		var size uint64
		err := tx.QueryRowContext(ctx, `
SELECT artifact.storage_key, artifact.sha256, artifact.size_bytes
FROM artifacts artifact
WHERE artifact.task_id = ? AND artifact.id = ?
FOR UPDATE`, taskID, artifactID).Scan(&storageKey, &digest, &size)
		if errors.Is(err, sql.ErrNoRows) {
			continue
		}
		if err != nil {
			return nil, nil, nil, fmt.Errorf("lock Java-analysis dependent artifact: %w", err)
		}
		if size > math.MaxInt64 {
			return nil, nil, nil, errors.New("Java-analysis dependent artifact size is invalid")
		}
		exclusiveArtifacts = append(exclusiveArtifacts, artifactID)
		files = append(files, taskcleanup.StoredFile{
			Kind: taskcleanup.FileArtifact, TaskID: taskID, RecordID: artifactID,
			StorageKey: storageKey, SHA256: digest, SizeBytes: int64(size),
		})
	}
	return reportIDs, exclusiveArtifacts, files, nil
}

func deleteJavaAnalysisRunRows(
	ctx context.Context,
	tx *sql.Tx,
	taskID string,
	runID string,
	jobID string,
	reportIDs []string,
	artifactIDs []string,
) error {
	if err := deleteJavaAnalysisRunRowsByID(ctx, tx, "reports", taskID, reportIDs); err != nil {
		return err
	}
	if err := deleteJavaAnalysisRunRowsByID(ctx, tx, "artifacts", taskID, artifactIDs); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `
DELETE FROM task_events
WHERE task_id = ? AND event_type LIKE 'java_analysis.%'
  AND JSON_UNQUOTE(JSON_EXTRACT(payload, '$.run_id')) = ?`, taskID, runID); err != nil {
		return fmt.Errorf("delete Java-analysis run task events: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `
DELETE FROM java_analysis_findings
WHERE task_id = ? AND run_id = ?`, taskID, runID); err != nil {
		return fmt.Errorf("delete Java-analysis run findings: %w", err)
	}
	runResult, err := tx.ExecContext(ctx, `
DELETE FROM java_analysis_runs
WHERE task_id = ? AND id = ?
  AND deletion_started_at IS NOT NULL
  AND status IN ('succeeded', 'partial', 'failed', 'cancelled')`, taskID, runID)
	if err != nil {
		return fmt.Errorf("delete Java-analysis run: %w", err)
	}
	if err := requireJavaAnalysisRunDeletionCount(runResult, 1, "Java-analysis run"); err != nil {
		return err
	}
	analyzerResult, err := tx.ExecContext(ctx, `
DELETE FROM analyzer_runs
WHERE task_id = ? AND id = ?`, taskID, runID)
	if err != nil {
		return fmt.Errorf("delete Java-analysis analyzer run: %w", err)
	}
	if err := requireJavaAnalysisRunDeletionCount(analyzerResult, 1, "Java-analysis analyzer run"); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `
UPDATE job_resource_slots
SET job_id = NULL, job_fencing_token = NULL,
    lease_owner = NULL, acquired_at = NULL
WHERE job_id = ?`, jobID); err != nil {
		return fmt.Errorf("release Java-analysis run resources: %w", err)
	}
	jobResult, err := tx.ExecContext(ctx, `
DELETE FROM jobs
WHERE task_id = ? AND id = ?
  AND status IN ('succeeded', 'failed', 'cancelled')`, taskID, jobID)
	if err != nil {
		return fmt.Errorf("delete Java-analysis job: %w", err)
	}
	if err := requireJavaAnalysisRunDeletionCount(jobResult, 1, "Java-analysis job"); err != nil {
		return err
	}
	return nil
}

func deleteJavaAnalysisRunRowsByID(
	ctx context.Context,
	tx *sql.Tx,
	table string,
	taskID string,
	ids []string,
) error {
	if len(ids) == 0 {
		return nil
	}
	if table != "reports" && table != "artifacts" {
		return errors.New("Java-analysis run cascade table is invalid")
	}
	arguments := make([]any, 0, len(ids)+1)
	arguments = append(arguments, taskID)
	for _, id := range ids {
		if !uuidPattern.MatchString(id) {
			return errors.New("Java-analysis run cascade row ID is invalid")
		}
		arguments = append(arguments, id)
	}
	placeholders := strings.TrimRight(strings.Repeat("?,", len(ids)), ",")
	result, err := tx.ExecContext(
		ctx,
		`DELETE FROM `+table+` WHERE task_id = ? AND id IN (`+placeholders+`)`,
		arguments...,
	)
	if err != nil {
		return fmt.Errorf("delete Java-analysis dependent %s: %w", table, err)
	}
	return requireJavaAnalysisRunDeletionCount(result, int64(len(ids)), "dependent "+table)
}

func requireJavaAnalysisRunDeletionCount(
	result sql.Result,
	want int64,
	operation string,
) error {
	changed, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("inspect deleted %s: %w", operation, err)
	}
	if changed != want {
		return fmt.Errorf("deleted %s rows = %d, want %d", operation, changed, want)
	}
	return nil
}

func terminalJavaAnalysisRunStatus(status string) bool {
	return status == "succeeded" || status == "partial" ||
		status == "failed" || status == "cancelled"
}

func terminalJavaAnalysisJobStatus(status string) bool {
	return status == "succeeded" || status == "failed" || status == "cancelled"
}

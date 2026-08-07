package retention

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"math"
	"time"

	"binaryscan/internal/audit"
	"binaryscan/internal/taskcleanup"
	"binaryscan/internal/taskevent"
)

func (r *MySQLRepository) ClaimExpiredTaskSample(
	ctx context.Context,
	taskID string,
	leaseOwner string,
	leaseDuration time.Duration,
) (TaskSampleClaim, bool, error) {
	if taskID == "" || leaseOwner == "" || len(leaseOwner) > 255 ||
		leaseDuration <= 0 || leaseDuration.Microseconds() <= 0 {
		return TaskSampleClaim{}, false, errors.New(
			"sample retention claim input is invalid",
		)
	}
	tx, err := r.db.BeginTx(ctx, &sql.TxOptions{
		Isolation: sql.LevelReadCommitted,
	})
	if err != nil {
		return TaskSampleClaim{}, false, fmt.Errorf(
			"begin sample retention claim: %w", err,
		)
	}
	defer tx.Rollback()

	var databaseNow time.Time
	err = tx.QueryRowContext(ctx, `
SELECT UTC_TIMESTAMP(6)
FROM tasks t
WHERE t.id = ?`+expiredTaskPredicate+`
LIMIT 1
FOR UPDATE SKIP LOCKED`, taskID).Scan(&databaseNow)
	if errors.Is(err, sql.ErrNoRows) {
		return TaskSampleClaim{}, false, commitSkipped(
			tx, "sample retention claim",
		)
	}
	if err != nil {
		return TaskSampleClaim{}, false, fmt.Errorf(
			"lock sample retention candidate: %w", err,
		)
	}

	var (
		status        string
		previousFence uint64
		attempt       uint32
		leaseUntil    sql.NullTime
	)
	err = tx.QueryRowContext(ctx, `
SELECT status, fencing_token, attempt_count, lease_until
FROM task_sample_retention_operations
WHERE task_id = ?
FOR UPDATE`, taskID).Scan(
		&status, &previousFence, &attempt, &leaseUntil,
	)
	fence := uint64(1)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		attempt = 1
		_, err = tx.ExecContext(ctx, `
INSERT INTO task_sample_retention_operations (
    task_id, status, fencing_token, attempt_count,
    lease_owner, lease_until, started_at
) VALUES (
    ?, 'cleaning', 1, 1, ?,
    DATE_ADD(UTC_TIMESTAMP(6), INTERVAL ? MICROSECOND),
    UTC_TIMESTAMP(6)
)`, taskID, leaseOwner, leaseDuration.Microseconds())
		if err != nil {
			return TaskSampleClaim{}, false, fmt.Errorf(
				"create sample retention operation: %w", err,
			)
		}
	case err != nil:
		return TaskSampleClaim{}, false, fmt.Errorf(
			"lock sample retention operation: %w", err,
		)
	case status == "completed":
		return TaskSampleClaim{}, false, commitSkipped(
			tx, "completed sample retention claim",
		)
	case status == "cleaning" && leaseUntil.Valid &&
		leaseUntil.Time.After(databaseNow):
		return TaskSampleClaim{}, false, commitSkipped(
			tx, "active sample retention claim",
		)
	default:
		fence = previousFence + 1
		attempt++
		result, err := tx.ExecContext(ctx, `
UPDATE task_sample_retention_operations
SET status = 'cleaning',
    fencing_token = ?,
    attempt_count = ?,
    lease_owner = ?,
    lease_until = DATE_ADD(UTC_TIMESTAMP(6), INTERVAL ? MICROSECOND),
    last_error_code = NULL,
    started_at = COALESCE(started_at, UTC_TIMESTAMP(6)),
    completed_at = NULL
WHERE task_id = ? AND fencing_token = ?`,
			fence, attempt, leaseOwner, leaseDuration.Microseconds(),
			taskID, previousFence,
		)
		if err != nil {
			return TaskSampleClaim{}, false, fmt.Errorf(
				"reclaim sample retention operation: %w", err,
			)
		}
		if err := requireOne(result, "reclaim sample retention operation"); err != nil {
			return TaskSampleClaim{}, false, err
		}
	}
	claim := TaskSampleClaim{
		TaskID: taskID, LeaseOwner: leaseOwner, FencingToken: fence,
		Attempt: attempt, LeaseUntil: databaseNow.Add(leaseDuration),
	}
	if err := collectRetainedDecompileOutputs(ctx, tx, &claim); err != nil {
		return TaskSampleClaim{}, false, err
	}
	if err := audit.Append(ctx, tx, audit.Event{
		Action:     "retention.task_sample_cleanup_started",
		ObjectType: "task",
		ObjectID:   taskID,
		Outcome:    audit.OutcomeSuccess,
		Metadata: map[string]any{
			"attempt": attempt, "fencing_token": fence,
			"decompile_file_count": len(claim.Files),
		},
	}); err != nil {
		return TaskSampleClaim{}, false, fmt.Errorf(
			"append sample retention start audit: %w", err,
		)
	}
	if err := tx.Commit(); err != nil {
		return TaskSampleClaim{}, false, fmt.Errorf(
			"commit sample retention claim: %w", err,
		)
	}
	return claim, true, nil
}

func collectRetainedDecompileOutputs(
	ctx context.Context,
	tx *sql.Tx,
	claim *TaskSampleClaim,
) error {
	rows, err := tx.QueryContext(ctx, `
SELECT id, storage_key, content_sha256, size_bytes
FROM decompile_results
WHERE task_id = ? AND storage_key IS NOT NULL
ORDER BY id`, claim.TaskID)
	if err != nil {
		return fmt.Errorf("list retained decompile outputs: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var (
			id, key string
			digest  sql.NullString
			size    sql.Null[uint64]
		)
		if err := rows.Scan(&id, &key, &digest, &size); err != nil {
			return fmt.Errorf("scan retained decompile output: %w", err)
		}
		if !digest.Valid || !size.Valid || size.V > math.MaxInt64 {
			return errors.New("retained decompile output metadata is incomplete")
		}
		claim.Files = append(claim.Files, taskcleanup.StoredFile{
			Kind: taskcleanup.FileDecompile, TaskID: claim.TaskID,
			RecordID: id, StorageKey: key, SHA256: digest.String,
			SizeBytes: int64(size.V),
		})
		claim.Scopes = append(claim.Scopes, taskcleanup.Scope{
			Kind: taskcleanup.FileDecompile, TaskID: claim.TaskID,
			RecordID: id,
		})
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate retained decompile outputs: %w", err)
	}
	return nil
}

func (r *MySQLRepository) RenewExpiredTaskSample(
	ctx context.Context,
	claim TaskSampleClaim,
	leaseDuration time.Duration,
) (bool, error) {
	if !validTaskSampleClaim(claim) || leaseDuration <= 0 ||
		leaseDuration.Microseconds() <= 0 {
		return false, errors.New("sample retention renewal input is invalid")
	}
	result, err := r.db.ExecContext(ctx, `
UPDATE task_sample_retention_operations operation
JOIN tasks task ON task.id = operation.task_id
SET operation.lease_until =
        DATE_ADD(UTC_TIMESTAMP(6), INTERVAL ? MICROSECOND)
WHERE operation.task_id = ?
  AND operation.status = 'cleaning'
  AND operation.fencing_token = ?
  AND operation.lease_owner = ?
  AND task.sample_deleted_at IS NULL
  AND task.deleted_at IS NULL
  AND task.sample_expires_at <= UTC_TIMESTAMP(6)
  AND NOT EXISTS (
      SELECT 1 FROM jobs job
      WHERE job.task_id = task.id
        AND job.status IN ('leased', 'running', 'cancel_requested')
  )
  AND NOT EXISTS (
      SELECT 1 FROM reports report
      WHERE report.task_id = task.id
        AND report.status IN ('queued', 'generating')
  )
  AND NOT EXISTS (
      SELECT 1 FROM decompile_results result
      WHERE result.task_id = task.id
        AND result.status IN ('queued', 'running')
  )`,
		leaseDuration.Microseconds(), claim.TaskID,
		claim.FencingToken, claim.LeaseOwner,
	)
	if err != nil {
		return false, fmt.Errorf("renew sample retention lease: %w", err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("inspect sample retention renewal: %w", err)
	}
	return affected == 1, nil
}

func (r *MySQLRepository) CompleteExpiredTaskSample(
	ctx context.Context,
	claim TaskSampleClaim,
) (bool, error) {
	if !validTaskSampleClaim(claim) {
		return false, errors.New("sample retention completion claim is invalid")
	}
	tx, err := r.db.BeginTx(ctx, &sql.TxOptions{
		Isolation: sql.LevelReadCommitted,
	})
	if err != nil {
		return false, fmt.Errorf("begin sample retention completion: %w", err)
	}
	defer tx.Rollback()

	var blobID uint64
	err = tx.QueryRowContext(ctx, `
SELECT t.blob_id
FROM tasks t
WHERE t.id = ?`+expiredTaskPredicate+`
LIMIT 1
FOR UPDATE`, claim.TaskID).Scan(&blobID)
	if errors.Is(err, sql.ErrNoRows) {
		return false, commitSkipped(tx, "sample retention completion")
	}
	if err != nil {
		return false, fmt.Errorf("lock expiring task sample: %w", err)
	}
	var status string
	err = tx.QueryRowContext(ctx, `
SELECT status
FROM task_sample_retention_operations
WHERE task_id = ?
  AND fencing_token = ?
  AND lease_owner = ?
  AND lease_until > UTC_TIMESTAMP(6)
FOR UPDATE`, claim.TaskID, claim.FencingToken, claim.LeaseOwner).Scan(&status)
	if errors.Is(err, sql.ErrNoRows) || status != "cleaning" {
		return false, commitSkipped(tx, "stale sample retention completion")
	}
	if err != nil {
		return false, fmt.Errorf("lock sample retention operation: %w", err)
	}
	if err := cancelExpiredQueuedDecompileJobs(ctx, tx, claim.TaskID); err != nil {
		return false, err
	}
	if err := releaseTaskDerivedBlobReferences(ctx, tx, claim.TaskID); err != nil {
		return false, err
	}
	if err := releaseBlobReference(ctx, tx, blobID); err != nil {
		return false, err
	}
	if _, err := tx.ExecContext(ctx, `
UPDATE decompile_results
SET storage_key = NULL,
    content_sha256 = NULL,
    size_bytes = NULL
WHERE task_id = ?`, claim.TaskID); err != nil {
		return false, fmt.Errorf(
			"clear expired decompile output metadata: %w", err,
		)
	}
	result, err := tx.ExecContext(ctx, `
UPDATE tasks
SET sample_deleted_at = UTC_TIMESTAMP(6),
    updated_at = UTC_TIMESTAMP(6),
    event_sequence = event_sequence + 1
WHERE id = ?
  AND blob_id = ?
  AND sample_deleted_at IS NULL`, claim.TaskID, blobID)
	if err != nil {
		return false, fmt.Errorf("mark retained task sample deleted: %w", err)
	}
	if err := requireOne(result, "complete task sample retention"); err != nil {
		return false, err
	}
	if err := taskevent.AppendCurrentState(
		ctx, tx, claim.TaskID, "task.sample_deleted",
		"Task sample retention expired.",
	); err != nil {
		return false, err
	}
	result, err = tx.ExecContext(ctx, `
UPDATE task_sample_retention_operations
SET status = 'completed',
    lease_owner = NULL,
    lease_until = NULL,
    last_error_code = NULL,
    completed_at = UTC_TIMESTAMP(6)
WHERE task_id = ?
  AND status = 'cleaning'
  AND fencing_token = ?
  AND lease_owner = ?`,
		claim.TaskID, claim.FencingToken, claim.LeaseOwner,
	)
	if err != nil {
		return false, fmt.Errorf("complete sample retention operation: %w", err)
	}
	if err := requireOne(result, "complete sample retention operation"); err != nil {
		return false, err
	}
	if err := audit.Append(ctx, tx, audit.Event{
		Action:     "retention.task_sample_deleted",
		ObjectType: "task",
		ObjectID:   claim.TaskID,
		Outcome:    audit.OutcomeSuccess,
		Metadata: map[string]any{
			"reason":                    "sample_retention_expired",
			"attempt":                   claim.Attempt,
			"fencing_token":             claim.FencingToken,
			"decompile_sources_removed": true,
		},
	}); err != nil {
		return false, fmt.Errorf("append task sample retention audit: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return false, fmt.Errorf("commit sample retention completion: %w", err)
	}
	return true, nil
}

func (r *MySQLRepository) FailExpiredTaskSample(
	ctx context.Context,
	claim TaskSampleClaim,
	code string,
) (bool, error) {
	if !validTaskSampleClaim(claim) || code == "" || len(code) > 128 {
		return false, errors.New("sample retention failure input is invalid")
	}
	tx, err := r.db.BeginTx(ctx, &sql.TxOptions{
		Isolation: sql.LevelReadCommitted,
	})
	if err != nil {
		return false, fmt.Errorf("begin sample retention failure: %w", err)
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, `
UPDATE task_sample_retention_operations
SET status = 'failed',
    lease_owner = NULL,
    lease_until = NULL,
    last_error_code = ?,
    completed_at = NULL
WHERE task_id = ?
  AND status = 'cleaning'
  AND fencing_token = ?
  AND lease_owner = ?`,
		code, claim.TaskID, claim.FencingToken, claim.LeaseOwner,
	)
	if err != nil {
		return false, fmt.Errorf("fail sample retention operation: %w", err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("inspect sample retention failure: %w", err)
	}
	if affected == 0 {
		return false, commitSkipped(tx, "stale sample retention failure")
	}
	if affected != 1 {
		return false, errors.New("sample retention failure changed multiple rows")
	}
	if err := audit.Append(ctx, tx, audit.Event{
		Action:     "retention.task_sample_cleanup_failed",
		ObjectType: "task",
		ObjectID:   claim.TaskID,
		Outcome:    audit.OutcomeFailure,
		Metadata: map[string]any{
			"attempt": claim.Attempt, "fencing_token": claim.FencingToken,
			"error_code": code, "retryable": true,
		},
	}); err != nil {
		return false, fmt.Errorf("append sample retention failure audit: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return false, fmt.Errorf("commit sample retention failure: %w", err)
	}
	return true, nil
}

func validTaskSampleClaim(claim TaskSampleClaim) bool {
	return claim.TaskID != "" && claim.LeaseOwner != "" &&
		len(claim.LeaseOwner) <= 255 && claim.FencingToken > 0 &&
		claim.Attempt > 0
}

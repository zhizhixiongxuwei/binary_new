package taskcleanup

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"math"
	"sort"
	"time"

	"binaryscan/internal/audit"
	"binaryscan/internal/taskevent"
)

type MySQLRepository struct {
	db *sql.DB
}

func NewMySQLRepository(db *sql.DB) *MySQLRepository {
	return &MySQLRepository{db: db}
}

func (r *MySQLRepository) ListReady(
	ctx context.Context,
	limit int,
) ([]string, error) {
	if limit < 1 || limit > maxSweepBatch {
		return nil, errors.New(
			"task deletion list limit must be between 1 and 100",
		)
	}
	rows, err := r.db.QueryContext(ctx, `
SELECT task.id
FROM tasks task
WHERE task.status = 'DELETING'
  AND task.deleted_at IS NULL
  AND NOT EXISTS (
      SELECT 1
      FROM jobs job
      WHERE job.task_id = task.id
        AND job.status IN ('queued', 'leased', 'running', 'cancel_requested')
  )
  AND NOT EXISTS (
      SELECT 1
      FROM job_resource_slots slot
      JOIN jobs job ON job.id = slot.job_id
      WHERE job.task_id = task.id
  )
  AND NOT EXISTS (
      SELECT 1
      FROM reports report
      WHERE report.task_id = task.id
        AND report.status IN ('queued', 'generating')
  )
  AND NOT EXISTS (
      SELECT 1
      FROM task_deletion_operations operation
      WHERE operation.task_id = task.id
        AND (
            operation.status = 'completed'
            OR (
                operation.status = 'cleaning'
                AND operation.lease_until > UTC_TIMESTAMP(6)
            )
        )
  )
ORDER BY task.updated_at, task.id
LIMIT ?`, limit)
	if err != nil {
		return nil, fmt.Errorf("list tasks ready for deletion cleanup: %w", err)
	}
	defer rows.Close()
	ids := make([]string, 0, limit)
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("scan task deletion candidate: %w", err)
		}
		if id == "" || len(ids) >= limit {
			return nil, errors.New("task deletion candidate set is invalid")
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate task deletion candidates: %w", err)
	}
	return ids, nil
}

func (r *MySQLRepository) Claim(
	ctx context.Context,
	taskID string,
	leaseOwner string,
	leaseDuration time.Duration,
) (Claim, bool, error) {
	if !canonicalID.MatchString(taskID) ||
		leaseOwner == "" || len(leaseOwner) > 255 {
		return Claim{}, false, errors.New("task deletion claim input is invalid")
	}
	leaseMicros, err := validLeaseMicros(leaseDuration)
	if err != nil {
		return Claim{}, false, err
	}
	tx, err := r.db.BeginTx(ctx, &sql.TxOptions{
		Isolation: sql.LevelReadCommitted,
	})
	if err != nil {
		return Claim{}, false, fmt.Errorf("begin task deletion claim: %w", err)
	}
	defer tx.Rollback()

	var databaseNow time.Time
	err = tx.QueryRowContext(ctx, `
SELECT UTC_TIMESTAMP(6)
FROM tasks task
WHERE task.id = ?
  AND task.status = 'DELETING'
  AND task.deleted_at IS NULL
  AND NOT EXISTS (
      SELECT 1
      FROM jobs job
      WHERE job.task_id = task.id
        AND job.status IN ('queued', 'leased', 'running', 'cancel_requested')
  )
  AND NOT EXISTS (
      SELECT 1
      FROM job_resource_slots slot
      JOIN jobs job ON job.id = slot.job_id
      WHERE job.task_id = task.id
  )
  AND NOT EXISTS (
      SELECT 1
      FROM reports report
      WHERE report.task_id = task.id
        AND report.status IN ('queued', 'generating')
  )
LIMIT 1
FOR UPDATE SKIP LOCKED`, taskID).Scan(&databaseNow)
	if errors.Is(err, sql.ErrNoRows) {
		return Claim{}, false, commitSkipped(tx, "task deletion claim")
	}
	if err != nil {
		return Claim{}, false, fmt.Errorf("lock task deletion candidate: %w", err)
	}

	var (
		status       string
		fencingToken uint64
		attempt      uint32
		leaseUntil   sql.NullTime
	)
	err = tx.QueryRowContext(ctx, `
SELECT status, fencing_token, attempt_count, lease_until
FROM task_deletion_operations
WHERE task_id = ?
FOR UPDATE`, taskID).Scan(
		&status, &fencingToken, &attempt, &leaseUntil,
	)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		fencingToken = 1
		attempt = 1
		_, err = tx.ExecContext(ctx, `
INSERT INTO task_deletion_operations (
    task_id, status, fencing_token, attempt_count, lease_owner, lease_until,
    last_error_code, last_error_message, started_at, completed_at
) VALUES (?, 'cleaning', 1, 1, ?,
          DATE_ADD(UTC_TIMESTAMP(6), INTERVAL ? MICROSECOND),
          NULL, NULL, UTC_TIMESTAMP(6), NULL)`,
			taskID, leaseOwner, leaseMicros,
		)
		if err != nil {
			return Claim{}, false, fmt.Errorf(
				"create task deletion operation: %w", err,
			)
		}
	case err != nil:
		return Claim{}, false, fmt.Errorf(
			"lock task deletion operation: %w", err,
		)
	case status == "completed":
		return Claim{}, false, commitSkipped(tx, "completed task deletion")
	case status == "cleaning" && leaseUntil.Valid &&
		leaseUntil.Time.After(databaseNow):
		return Claim{}, false, commitSkipped(tx, "leased task deletion")
	default:
		if fencingToken == math.MaxUint64 || attempt == math.MaxUint32 {
			return Claim{}, false, errors.New(
				"task deletion fencing sequence is exhausted",
			)
		}
		previousStatus := status
		previousFence := fencingToken
		fencingToken++
		attempt++
		result, execErr := tx.ExecContext(ctx, `
UPDATE task_deletion_operations
SET status = 'cleaning',
    fencing_token = ?,
    attempt_count = ?,
    lease_owner = ?,
    lease_until = DATE_ADD(UTC_TIMESTAMP(6), INTERVAL ? MICROSECOND),
    last_error_code = NULL,
    last_error_message = NULL,
    started_at = COALESCE(started_at, UTC_TIMESTAMP(6)),
    completed_at = NULL
WHERE task_id = ?
  AND status = ?
  AND fencing_token = ?`,
			fencingToken, attempt, leaseOwner, leaseMicros,
			taskID, previousStatus, previousFence,
		)
		if execErr != nil {
			return Claim{}, false, fmt.Errorf(
				"reclaim task deletion operation: %w", execErr,
			)
		}
		if err := requireOne(result, "reclaim task deletion operation"); err != nil {
			return Claim{}, false, err
		}
	}

	claim := Claim{
		TaskID: taskID, LeaseOwner: leaseOwner,
		FencingToken: fencingToken, Attempt: attempt,
		LeaseUntil: databaseNow.Add(leaseDuration),
	}
	if err := collectOutputs(ctx, tx, &claim); err != nil {
		if failureErr := failClaimCollection(
			ctx, tx, claim,
		); failureErr != nil {
			return Claim{}, false, errors.Join(err, failureErr)
		}
		if commitErr := tx.Commit(); commitErr != nil {
			return Claim{}, false, errors.Join(
				err,
				fmt.Errorf(
					"commit invalid task deletion claim: %w",
					commitErr,
				),
			)
		}
		return Claim{}, false, err
	}
	if err := audit.Append(ctx, tx, audit.Event{
		Action:     "task.deletion_cleanup_started",
		ObjectType: "task",
		ObjectID:   taskID,
		Outcome:    audit.OutcomeSuccess,
		Metadata: map[string]any{
			"attempt":       attempt,
			"fencing_token": fencingToken,
			"file_count":    len(claim.Files),
		},
	}); err != nil {
		return Claim{}, false, fmt.Errorf(
			"append task deletion start audit: %w", err,
		)
	}
	if err := tx.Commit(); err != nil {
		return Claim{}, false, fmt.Errorf("commit task deletion claim: %w", err)
	}
	return claim, true, nil
}

func failClaimCollection(
	ctx context.Context,
	tx *sql.Tx,
	claim Claim,
) error {
	result, err := tx.ExecContext(ctx, `
UPDATE task_deletion_operations
SET status = 'failed',
    lease_owner = NULL,
    lease_until = NULL,
    last_error_code = 'task_deletion_metadata_invalid',
    last_error_message = 'Task deletion cleanup will be retried.',
    completed_at = NULL
WHERE task_id = ?
  AND status = 'cleaning'
  AND fencing_token = ?
  AND lease_owner = ?`,
		claim.TaskID, claim.FencingToken, claim.LeaseOwner,
	)
	if err != nil {
		return fmt.Errorf("fail invalid task deletion claim: %w", err)
	}
	if err := requireOne(result, "fail invalid task deletion claim"); err != nil {
		return err
	}
	if err := audit.Append(ctx, tx, audit.Event{
		Action:     "task.deletion_cleanup_started",
		ObjectType: "task",
		ObjectID:   claim.TaskID,
		Outcome:    audit.OutcomeSuccess,
		Metadata: map[string]any{
			"attempt":       claim.Attempt,
			"fencing_token": claim.FencingToken,
		},
	}); err != nil {
		return fmt.Errorf("append invalid task deletion start audit: %w", err)
	}
	if err := audit.Append(ctx, tx, audit.Event{
		Action:     "task.deletion_cleanup_failed",
		ObjectType: "task",
		ObjectID:   claim.TaskID,
		Outcome:    audit.OutcomeFailure,
		Metadata: map[string]any{
			"attempt":       claim.Attempt,
			"fencing_token": claim.FencingToken,
			"error_code":    "task_deletion_metadata_invalid",
			"retryable":     true,
		},
	}); err != nil {
		return fmt.Errorf("append invalid task deletion failure audit: %w", err)
	}
	return nil
}

func (r *MySQLRepository) Renew(
	ctx context.Context,
	claim Claim,
	leaseDuration time.Duration,
) (bool, error) {
	if !validRepositoryClaim(claim) {
		return false, errors.New("task deletion renewal claim is invalid")
	}
	leaseMicros, err := validLeaseMicros(leaseDuration)
	if err != nil {
		return false, err
	}
	result, err := r.db.ExecContext(ctx, `
UPDATE task_deletion_operations operation
JOIN tasks task ON task.id = operation.task_id
SET operation.lease_until =
        DATE_ADD(UTC_TIMESTAMP(6), INTERVAL ? MICROSECOND)
WHERE operation.task_id = ?
  AND operation.status = 'cleaning'
  AND operation.fencing_token = ?
  AND operation.lease_owner = ?
  AND task.status = 'DELETING'
  AND task.deleted_at IS NULL
  AND NOT EXISTS (
      SELECT 1
      FROM jobs job
      WHERE job.task_id = task.id
        AND job.status IN ('queued', 'leased', 'running', 'cancel_requested')
  )
  AND NOT EXISTS (
      SELECT 1
      FROM job_resource_slots slot
      JOIN jobs job ON job.id = slot.job_id
      WHERE job.task_id = task.id
  )
  AND NOT EXISTS (
      SELECT 1
      FROM reports report
      WHERE report.task_id = task.id
        AND report.status IN ('queued', 'generating')
  )`,
		leaseMicros, claim.TaskID, claim.FencingToken, claim.LeaseOwner,
	)
	if err != nil {
		return false, fmt.Errorf("renew task deletion operation: %w", err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("inspect task deletion renewal: %w", err)
	}
	return affected == 1, nil
}

func (r *MySQLRepository) Complete(
	ctx context.Context,
	claim Claim,
) (bool, error) {
	if !validRepositoryClaim(claim) {
		return false, errors.New("task deletion completion claim is invalid")
	}
	tx, err := r.db.BeginTx(ctx, &sql.TxOptions{
		Isolation: sql.LevelReadCommitted,
	})
	if err != nil {
		return false, fmt.Errorf("begin task deletion finalization: %w", err)
	}
	defer tx.Rollback()

	var blobID uint64
	var sampleDeletedAt sql.NullTime
	err = tx.QueryRowContext(ctx, `
SELECT blob_id, sample_deleted_at
FROM tasks task
WHERE task.id = ?
  AND task.status = 'DELETING'
  AND task.deleted_at IS NULL
  AND NOT EXISTS (
      SELECT 1
      FROM jobs job
      WHERE job.task_id = task.id
        AND job.status IN ('queued', 'leased', 'running', 'cancel_requested')
  )
  AND NOT EXISTS (
      SELECT 1
      FROM job_resource_slots slot
      JOIN jobs job ON job.id = slot.job_id
      WHERE job.task_id = task.id
  )
  AND NOT EXISTS (
      SELECT 1
      FROM reports report
      WHERE report.task_id = task.id
        AND report.status IN ('queued', 'generating')
  )
LIMIT 1
FOR UPDATE`, claim.TaskID).Scan(&blobID, &sampleDeletedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return false, commitSkipped(tx, "task deletion finalization")
	}
	if err != nil {
		return false, fmt.Errorf("lock deleting task for finalization: %w", err)
	}
	var operationStatus string
	err = tx.QueryRowContext(ctx, `
SELECT status
FROM task_deletion_operations
WHERE task_id = ?
  AND fencing_token = ?
  AND lease_owner = ?
  AND lease_until > UTC_TIMESTAMP(6)
FOR UPDATE`, claim.TaskID, claim.FencingToken, claim.LeaseOwner).Scan(
		&operationStatus,
	)
	if errors.Is(err, sql.ErrNoRows) || operationStatus != "cleaning" {
		return false, commitSkipped(tx, "stale task deletion finalization")
	}
	if err != nil {
		return false, fmt.Errorf("lock task deletion operation: %w", err)
	}

	if err := releaseNestedBlobReferences(ctx, tx, claim.TaskID); err != nil {
		return false, err
	}
	if !sampleDeletedAt.Valid {
		if err := releaseBlobReference(ctx, tx, blobID); err != nil {
			return false, err
		}
	}
	if err := deleteStructuredResults(ctx, tx, claim.TaskID); err != nil {
		return false, err
	}
	if _, err := tx.ExecContext(ctx, `
UPDATE task_attempts
SET status = 'cancelled',
    completed_at = COALESCE(completed_at, UTC_TIMESTAMP(6)),
    error_code = NULL,
    error_message = NULL
WHERE task_id = ? AND status IN ('queued', 'running')`, claim.TaskID); err != nil {
		return false, fmt.Errorf("close deleting task attempts: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `
UPDATE jobs
SET payload = NULL,
    error_code = NULL,
    error_message = NULL
WHERE task_id = ?`, claim.TaskID); err != nil {
		return false, fmt.Errorf("scrub deleting task job payloads: %w", err)
	}
	result, err := tx.ExecContext(ctx, `
UPDATE tasks
SET status = 'DELETED',
    stage = NULL,
    sample_deleted_at = COALESCE(sample_deleted_at, UTC_TIMESTAMP(6)),
    deleted_at = UTC_TIMESTAMP(6),
    updated_at = UTC_TIMESTAMP(6),
    event_sequence = event_sequence + 1
WHERE id = ? AND status = 'DELETING' AND deleted_at IS NULL`, claim.TaskID)
	if err != nil {
		return false, fmt.Errorf("mark task deleted: %w", err)
	}
	if err := requireOne(result, "mark task deleted"); err != nil {
		return false, err
	}
	if err := taskevent.AppendCurrentState(
		ctx, tx, claim.TaskID, "task.status_changed",
		"Task deletion completed.",
	); err != nil {
		return false, err
	}
	result, err = tx.ExecContext(ctx, `
UPDATE task_deletion_operations
SET status = 'completed',
    lease_owner = NULL,
    lease_until = NULL,
    last_error_code = NULL,
    last_error_message = NULL,
    completed_at = UTC_TIMESTAMP(6)
WHERE task_id = ?
  AND status = 'cleaning'
  AND fencing_token = ?
  AND lease_owner = ?`,
		claim.TaskID, claim.FencingToken, claim.LeaseOwner,
	)
	if err != nil {
		return false, fmt.Errorf("complete task deletion operation: %w", err)
	}
	if err := requireOne(result, "complete task deletion operation"); err != nil {
		return false, err
	}
	if err := audit.Append(ctx, tx, audit.Event{
		Action:     "task.deletion_cleanup_completed",
		ObjectType: "task",
		ObjectID:   claim.TaskID,
		Outcome:    audit.OutcomeSuccess,
		Metadata: map[string]any{
			"attempt":       claim.Attempt,
			"fencing_token": claim.FencingToken,
		},
	}); err != nil {
		return false, fmt.Errorf(
			"append task deletion completion audit: %w", err,
		)
	}
	if err := tx.Commit(); err != nil {
		return false, fmt.Errorf("commit task deletion finalization: %w", err)
	}
	return true, nil
}

func (r *MySQLRepository) Fail(
	ctx context.Context,
	claim Claim,
	failure Failure,
) (bool, error) {
	if !validRepositoryClaim(claim) {
		return false, errors.New("task deletion failure claim is invalid")
	}
	if failure.Code == "" || len(failure.Code) > 128 {
		return false, errors.New("task deletion failure code is invalid")
	}
	tx, err := r.db.BeginTx(ctx, &sql.TxOptions{
		Isolation: sql.LevelReadCommitted,
	})
	if err != nil {
		return false, fmt.Errorf("begin task deletion failure: %w", err)
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, `
UPDATE task_deletion_operations operation
JOIN tasks task ON task.id = operation.task_id
SET operation.status = 'failed',
    operation.lease_owner = NULL,
    operation.lease_until = NULL,
    operation.last_error_code = ?,
    operation.last_error_message = 'Task deletion cleanup will be retried.',
    operation.completed_at = NULL
WHERE operation.task_id = ?
  AND operation.status = 'cleaning'
  AND operation.fencing_token = ?
  AND operation.lease_owner = ?
  AND task.status = 'DELETING'
  AND task.deleted_at IS NULL`,
		failure.Code, claim.TaskID, claim.FencingToken, claim.LeaseOwner,
	)
	if err != nil {
		return false, fmt.Errorf("fail task deletion operation: %w", err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("inspect failed task deletion: %w", err)
	}
	if affected == 0 {
		return false, commitSkipped(tx, "stale task deletion failure")
	}
	if affected != 1 {
		return false, errors.New("task deletion failure changed multiple rows")
	}
	if err := audit.Append(ctx, tx, audit.Event{
		Action:     "task.deletion_cleanup_failed",
		ObjectType: "task",
		ObjectID:   claim.TaskID,
		Outcome:    audit.OutcomeFailure,
		Metadata: map[string]any{
			"attempt":       claim.Attempt,
			"fencing_token": claim.FencingToken,
			"error_code":    failure.Code,
			"retryable":     true,
		},
	}); err != nil {
		return false, fmt.Errorf(
			"append task deletion failure audit: %w", err,
		)
	}
	if err := tx.Commit(); err != nil {
		return false, fmt.Errorf("commit task deletion failure: %w", err)
	}
	return true, nil
}

func collectOutputs(
	ctx context.Context,
	tx *sql.Tx,
	claim *Claim,
) error {
	claim.Scopes = append(claim.Scopes, Scope{
		Kind: FileReport, TaskID: claim.TaskID,
	}, Scope{
		Kind: FileArtifact, TaskID: claim.TaskID,
	})
	if err := collectReportFiles(ctx, tx, claim); err != nil {
		return err
	}
	if err := collectArtifactFiles(ctx, tx, claim); err != nil {
		return err
	}
	if err := collectDecompileFiles(ctx, tx, claim); err != nil {
		return err
	}
	if len(claim.Files) > maxOutputFiles || len(claim.Scopes) > maxOutputFiles+2 {
		return errors.New("task deletion output limit exceeded")
	}
	sort.Slice(claim.Files, func(left, right int) bool {
		return claim.Files[left].StorageKey < claim.Files[right].StorageKey
	})
	for index := 1; index < len(claim.Files); index++ {
		if claim.Files[index-1].StorageKey == claim.Files[index].StorageKey {
			if claim.Files[index-1].SHA256 != claim.Files[index].SHA256 ||
				claim.Files[index-1].SizeBytes != claim.Files[index].SizeBytes {
				return errors.New(
					"task deletion output metadata conflicts for one storage key",
				)
			}
			claim.Files = append(
				claim.Files[:index], claim.Files[index+1:]...,
			)
			index--
		}
	}
	return nil
}

func collectReportFiles(
	ctx context.Context,
	tx *sql.Tx,
	claim *Claim,
) error {
	rows, err := tx.QueryContext(ctx, `
SELECT id, format, storage_key, sha256, size_bytes
FROM reports
WHERE task_id = ? AND deleted_at IS NULL AND storage_key IS NOT NULL
ORDER BY id`, claim.TaskID)
	if err != nil {
		return fmt.Errorf("list deleting task reports: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var file StoredFile
		var sha sql.NullString
		var size sql.Null[uint64]
		file.Kind = FileReport
		file.TaskID = claim.TaskID
		if err := rows.Scan(
			&file.RecordID, &file.Format, &file.StorageKey, &sha, &size,
		); err != nil {
			return fmt.Errorf("scan deleting task report: %w", err)
		}
		if err := applyStoredMetadata(&file, sha, size); err != nil {
			return err
		}
		claim.Files = append(claim.Files, file)
	}
	return rows.Err()
}

func collectArtifactFiles(
	ctx context.Context,
	tx *sql.Tx,
	claim *Claim,
) error {
	rows, err := tx.QueryContext(ctx, `
SELECT id, storage_key, sha256, size_bytes
FROM artifacts
WHERE task_id = ? AND state <> 'deleted'
ORDER BY id`, claim.TaskID)
	if err != nil {
		return fmt.Errorf("list deleting task artifacts: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var file StoredFile
		var size uint64
		file.Kind = FileArtifact
		file.TaskID = claim.TaskID
		if err := rows.Scan(
			&file.RecordID, &file.StorageKey, &file.SHA256, &size,
		); err != nil {
			return fmt.Errorf("scan deleting task artifact: %w", err)
		}
		if size > math.MaxInt64 {
			return errors.New("deleting task artifact size is invalid")
		}
		file.SizeBytes = int64(size)
		claim.Files = append(claim.Files, file)
	}
	return rows.Err()
}

func collectDecompileFiles(
	ctx context.Context,
	tx *sql.Tx,
	claim *Claim,
) error {
	rows, err := tx.QueryContext(ctx, `
SELECT id, storage_key, content_sha256, size_bytes
FROM decompile_results
WHERE task_id = ?
ORDER BY id`, claim.TaskID)
	if err != nil {
		return fmt.Errorf("list deleting task decompile results: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var (
			id         string
			storageKey sql.NullString
			sha        sql.NullString
			size       sql.Null[uint64]
		)
		if err := rows.Scan(&id, &storageKey, &sha, &size); err != nil {
			return fmt.Errorf("scan deleting task decompile result: %w", err)
		}
		claim.Scopes = append(claim.Scopes, Scope{
			Kind: FileDecompile, TaskID: claim.TaskID, RecordID: id,
		})
		if !storageKey.Valid {
			continue
		}
		file := StoredFile{
			Kind: FileDecompile, TaskID: claim.TaskID,
			RecordID: id, StorageKey: storageKey.String,
		}
		if err := applyStoredMetadata(&file, sha, size); err != nil {
			return err
		}
		claim.Files = append(claim.Files, file)
	}
	return rows.Err()
}

func applyStoredMetadata(
	file *StoredFile,
	sha sql.NullString,
	size sql.Null[uint64],
) error {
	if !sha.Valid || !size.Valid || size.V > math.MaxInt64 {
		return errors.New("deleting task output metadata is incomplete")
	}
	file.SHA256 = sha.String
	file.SizeBytes = int64(size.V)
	return nil
}

func releaseNestedBlobReferences(
	ctx context.Context,
	tx *sql.Tx,
	taskID string,
) error {
	rows, err := tx.QueryContext(ctx, `
SELECT file_node_id, blob_id
FROM file_node_blob_refs
WHERE task_id = ?
ORDER BY file_node_id
FOR UPDATE`, taskID)
	if err != nil {
		return fmt.Errorf("lock deleting task nested blob references: %w", err)
	}
	var blobIDs []uint64
	for rows.Next() {
		var fileNodeID, blobID uint64
		if err := rows.Scan(&fileNodeID, &blobID); err != nil {
			rows.Close()
			return fmt.Errorf("scan deleting task nested blob reference: %w", err)
		}
		if fileNodeID == 0 || blobID == 0 {
			rows.Close()
			return errors.New("deleting task nested blob reference is invalid")
		}
		blobIDs = append(blobIDs, blobID)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return fmt.Errorf("iterate deleting task nested blob references: %w", err)
	}
	if err := rows.Close(); err != nil {
		return fmt.Errorf("close deleting task nested blob references: %w", err)
	}
	for _, blobID := range blobIDs {
		if err := releaseBlobReference(ctx, tx, blobID); err != nil {
			return err
		}
	}
	if _, err := tx.ExecContext(ctx, `
DELETE FROM file_node_blob_refs
WHERE task_id = ?`, taskID); err != nil {
		return fmt.Errorf("delete task nested blob references: %w", err)
	}
	return nil
}

func releaseBlobReference(
	ctx context.Context,
	tx *sql.Tx,
	blobID uint64,
) error {
	var referenceCount uint64
	var state string
	err := tx.QueryRowContext(ctx, `
SELECT reference_count, state
FROM blobs
WHERE id = ?
FOR UPDATE`, blobID).Scan(&referenceCount, &state)
	if errors.Is(err, sql.ErrNoRows) {
		return errors.New("deleting task blob record is missing")
	}
	if err != nil {
		return fmt.Errorf("lock deleting task blob: %w", err)
	}
	if referenceCount == 0 || state != "available" {
		return errors.New("deleting task blob reference is inconsistent")
	}
	nextState := "available"
	if referenceCount == 1 {
		nextState = "deleting"
	}
	result, err := tx.ExecContext(ctx, `
UPDATE blobs
SET state = ?,
    reference_count = reference_count - 1
WHERE id = ? AND state = 'available' AND reference_count = ?`,
		nextState, blobID, referenceCount,
	)
	if err != nil {
		return fmt.Errorf("release deleting task blob reference: %w", err)
	}
	return requireOne(result, "release deleting task blob reference")
}

func deleteStructuredResults(
	ctx context.Context,
	tx *sql.Tx,
	taskID string,
) error {
	statements := []struct {
		name string
		sql  string
	}{
		{"reports", `DELETE FROM reports WHERE task_id = ?`},
		{"vulnerability findings", `DELETE FROM vulnerability_findings WHERE task_id = ?`},
		{"decompile results", `DELETE FROM decompile_results WHERE task_id = ?`},
		{"artifacts", `DELETE FROM artifacts WHERE task_id = ?`},
		{"analyzer runs", `DELETE FROM analyzer_runs WHERE task_id = ?`},
		{"file nodes", `DELETE FROM file_nodes WHERE task_id = ?`},
	}
	for _, statement := range statements {
		if _, err := tx.ExecContext(ctx, statement.sql, taskID); err != nil {
			return fmt.Errorf(
				"delete task %s: %w", statement.name, err,
			)
		}
	}
	return nil
}

func validLeaseMicros(duration time.Duration) (int64, error) {
	if duration <= 0 {
		return 0, errors.New("task deletion lease duration must be positive")
	}
	micros := duration.Microseconds()
	if micros <= 0 {
		return 0, errors.New("task deletion lease duration is too short")
	}
	return micros, nil
}

func validRepositoryClaim(claim Claim) bool {
	return canonicalID.MatchString(claim.TaskID) &&
		claim.LeaseOwner != "" &&
		len(claim.LeaseOwner) <= 255 &&
		claim.FencingToken > 0 &&
		claim.Attempt > 0
}

func requireOne(result sql.Result, operation string) error {
	affected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("inspect %s: %w", operation, err)
	}
	if affected != 1 {
		return fmt.Errorf("%s changed %d rows", operation, affected)
	}
	return nil
}

func commitSkipped(tx *sql.Tx, operation string) error {
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit skipped %s: %w", operation, err)
	}
	return nil
}

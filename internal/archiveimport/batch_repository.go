package archiveimport

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"binaryscan/internal/auth"
)

func (r *MySQLRepository) BeginBatch(
	ctx context.Context,
	batchID string,
	input BatchInput,
	fingerprint string,
) (Batch, bool, error) {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return Batch{}, false, fmt.Errorf("begin archive task batch: %w", err)
	}
	defer tx.Rollback()

	existing, found, err := findBatchByIdempotency(
		ctx, tx, input.ImportID, input.CreatedBy, input.IdempotencyKey, true,
	)
	if err != nil {
		return Batch{}, false, err
	}
	if found {
		if existing.Fingerprint != fingerprint {
			return Batch{}, false, ErrIdempotencyConflict
		}
		if err := tx.Commit(); err != nil {
			return Batch{}, false, fmt.Errorf("commit archive batch replay: %w", err)
		}
		value, err := r.LoadBatch(ctx, existing.ID)
		return value, false, err
	}

	archive, found, err := findImportByID(ctx, tx, input.ImportID, true)
	if err != nil {
		return Batch{}, false, err
	}
	if !found {
		return Batch{}, false, ErrNotFound
	}
	if archive.Status != StatusReady {
		return Batch{}, false, ErrConflict
	}
	// The import row serializes batch creation. A concurrent request can miss
	// the idempotency row before waiting for this lock, so resolve it again
	// after the lock is held.
	existing, found, err = findBatchByIdempotency(
		ctx, tx, input.ImportID, input.CreatedBy, input.IdempotencyKey, true,
	)
	if err != nil {
		return Batch{}, false, err
	}
	if found {
		if existing.Fingerprint != fingerprint {
			return Batch{}, false, ErrIdempotencyConflict
		}
		if err := tx.Commit(); err != nil {
			return Batch{}, false, fmt.Errorf("commit concurrent archive batch replay: %w", err)
		}
		value, err := r.LoadBatch(ctx, existing.ID)
		return value, false, err
	}
	var active int
	err = tx.QueryRowContext(ctx, `
SELECT COUNT(*)
FROM archive_import_task_batches
WHERE archive_import_id = ? AND status = 'processing'`, input.ImportID).Scan(&active)
	if err != nil {
		return Batch{}, false, fmt.Errorf("check active archive task batch: %w", err)
	}
	if active != 0 {
		return Batch{}, false, ErrConflict
	}

	type selectedEntry struct {
		databaseID uint64
		publicID   string
		status     string
		taskID     sql.NullString
	}
	selected := make([]selectedEntry, 0, len(input.EntryIDs))
	for _, publicID := range input.EntryIDs {
		var value selectedEntry
		err := tx.QueryRowContext(ctx, `
SELECT id, public_id, status, task_id
FROM archive_import_entries
WHERE archive_import_id = ? AND public_id = ?
FOR UPDATE`, input.ImportID, publicID).Scan(
			&value.databaseID, &value.publicID, &value.status, &value.taskID,
		)
		if errors.Is(err, sql.ErrNoRows) {
			return Batch{}, false, ErrInvalidInput
		}
		if err != nil {
			return Batch{}, false, fmt.Errorf("lock archive batch entry: %w", err)
		}
		if value.status != EntryEligible && value.status != EntryFailed &&
			value.status != EntryCreated {
			return Batch{}, false, ErrInvalidInput
		}
		selected = append(selected, value)
	}

	_, err = tx.ExecContext(ctx, `
INSERT INTO archive_import_task_batches (
    id, archive_import_id, created_by, created_by_role, idempotency_key,
    request_fingerprint, status, created_at, updated_at
) VALUES (?, ?, ?, ?, ?, ?, 'processing', UTC_TIMESTAMP(6), UTC_TIMESTAMP(6))`,
		batchID, input.ImportID, input.CreatedBy, string(input.Role),
		input.IdempotencyKey, fingerprint,
	)
	if err != nil {
		if isDuplicateKey(err) {
			return Batch{}, false, ErrConflict
		}
		return Batch{}, false, fmt.Errorf("create archive task batch: %w", err)
	}
	pending := 0
	for ordinal, entry := range selected {
		outcome := OutcomePending
		var taskID any
		if entry.status == EntryCreated {
			outcome = OutcomeExisting
			if entry.taskID.Valid {
				taskID = entry.taskID.String
			}
		}
		_, err := tx.ExecContext(ctx, `
INSERT INTO archive_import_task_batch_items (
    batch_id, entry_id, ordinal, outcome, task_id, created_at, updated_at
) VALUES (?, ?, ?, ?, ?, UTC_TIMESTAMP(6), UTC_TIMESTAMP(6))`,
			batchID, entry.databaseID, ordinal, outcome, taskID,
		)
		if err != nil {
			return Batch{}, false, fmt.Errorf("create archive task batch item: %w", err)
		}
		if outcome == OutcomePending {
			pending++
		}
	}
	if pending == 0 {
		if _, err := tx.ExecContext(ctx, `
UPDATE archive_import_task_batches
SET status = 'completed', completed_at = UTC_TIMESTAMP(6),
    updated_at = UTC_TIMESTAMP(6)
WHERE id = ?`, batchID); err != nil {
			return Batch{}, false, fmt.Errorf("complete replay-only archive batch: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return Batch{}, false, fmt.Errorf("commit archive task batch: %w", err)
	}
	value, err := r.LoadBatch(ctx, batchID)
	return value, true, err
}

func findBatchByIdempotency(
	ctx context.Context,
	query rowQueryer,
	importID string,
	createdBy uint64,
	key string,
	lock bool,
) (Batch, bool, error) {
	suffix := ""
	if lock {
		suffix = " FOR UPDATE"
	}
	var value Batch
	err := query.QueryRowContext(ctx, `
SELECT id, archive_import_id, created_by, request_fingerprint, status,
       created_at, updated_at
FROM archive_import_task_batches
WHERE archive_import_id = ? AND created_by = ? AND idempotency_key = ?`+suffix,
		importID, createdBy, key,
	).Scan(
		&value.ID, &value.ImportID, &value.CreatedBy, &value.Fingerprint,
		&value.Status, &value.CreatedAt, &value.UpdatedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return Batch{}, false, nil
	}
	if err != nil {
		return Batch{}, false, fmt.Errorf("find archive batch idempotency key: %w", err)
	}
	return value, true, nil
}

func (r *MySQLRepository) LoadBatch(
	ctx context.Context,
	batchID string,
) (Batch, error) {
	var value Batch
	err := r.db.QueryRowContext(ctx, `
SELECT id, archive_import_id, created_by, request_fingerprint, status,
       created_at, updated_at
FROM archive_import_task_batches
WHERE id = ?`, batchID).Scan(
		&value.ID, &value.ImportID, &value.CreatedBy, &value.Fingerprint,
		&value.Status, &value.CreatedAt, &value.UpdatedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return Batch{}, ErrNotFound
	}
	if err != nil {
		return Batch{}, fmt.Errorf("load archive task batch: %w", err)
	}
	rows, err := r.db.QueryContext(ctx, `
SELECT entry.public_id, item.ordinal, item.outcome, item.task_id,
       item.error_code, item.error_message
FROM archive_import_task_batch_items item
JOIN archive_import_entries entry ON entry.id = item.entry_id
WHERE item.batch_id = ?
ORDER BY item.ordinal ASC`, batchID)
	if err != nil {
		return Batch{}, fmt.Errorf("list archive task batch items: %w", err)
	}
	defer rows.Close()
	value.Items = make([]BatchItem, 0)
	for rows.Next() {
		var item BatchItem
		var taskID, errorCode, errorMessage sql.NullString
		if err := rows.Scan(
			&item.EntryID, &item.Ordinal, &item.Outcome, &taskID,
			&errorCode, &errorMessage,
		); err != nil {
			return Batch{}, fmt.Errorf("scan archive batch item: %w", err)
		}
		item.TaskID = taskID.String
		item.ErrorCode = errorCode.String
		item.Message = errorMessage.String
		value.Items = append(value.Items, item)
	}
	if err := rows.Err(); err != nil {
		return Batch{}, fmt.Errorf("iterate archive batch items: %w", err)
	}
	return value, nil
}

func (r *MySQLRepository) ClaimBatchItem(
	ctx context.Context,
	batchID string,
	owner string,
	leaseDuration time.Duration,
) (BatchWorkItem, bool, error) {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return BatchWorkItem{}, false, fmt.Errorf("begin archive batch item claim: %w", err)
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `
UPDATE archive_import_entries entry
JOIN archive_import_task_batch_items item ON item.entry_id = entry.id
SET entry.status = 'failed',
    entry.error_code = 'archive_entry_batch_attempts_exhausted',
    entry.error_message = 'Archive entry task creation exhausted recovery attempts.',
    entry.updated_at = UTC_TIMESTAMP(6)
WHERE item.batch_id = ? AND item.outcome = 'processing'
  AND item.lease_until <= UTC_TIMESTAMP(6)
  AND item.attempt >= item.max_attempts
  AND entry.status <> 'created'`, batchID); err != nil {
		return BatchWorkItem{}, false, fmt.Errorf("fail exhausted archive batch entries: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `
UPDATE archive_import_task_batch_items
SET outcome = 'failed', lease_owner = NULL, lease_until = NULL,
    heartbeat_at = NULL,
    error_code = 'archive_entry_batch_attempts_exhausted',
    error_message = 'Archive entry task creation exhausted recovery attempts.',
    updated_at = UTC_TIMESTAMP(6)
WHERE batch_id = ? AND outcome = 'processing'
  AND lease_until <= UTC_TIMESTAMP(6)
  AND attempt >= max_attempts`, batchID); err != nil {
		return BatchWorkItem{}, false, fmt.Errorf("fail exhausted archive batch items: %w", err)
	}
	var entryID uint64
	err = tx.QueryRowContext(ctx, `
SELECT item.entry_id
FROM archive_import_task_batch_items item
JOIN archive_import_task_batches batch ON batch.id = item.batch_id
WHERE item.batch_id = ? AND batch.status = 'processing'
  AND (item.outcome = 'pending' OR
       (item.outcome = 'processing' AND item.lease_until <= UTC_TIMESTAMP(6)))
  AND item.attempt < item.max_attempts
ORDER BY item.ordinal ASC
LIMIT 1
FOR UPDATE SKIP LOCKED`, batchID).Scan(&entryID)
	if errors.Is(err, sql.ErrNoRows) {
		if err := tx.Commit(); err != nil {
			return BatchWorkItem{}, false, fmt.Errorf("commit empty batch item claim: %w", err)
		}
		return BatchWorkItem{}, false, nil
	}
	if err != nil {
		return BatchWorkItem{}, false, fmt.Errorf("select archive batch item: %w", err)
	}
	result, err := tx.ExecContext(ctx, `
UPDATE archive_import_task_batch_items
SET outcome = 'processing', attempt = attempt + 1,
    fencing_token = fencing_token + 1, lease_owner = ?,
    lease_until = TIMESTAMPADD(MICROSECOND, ?, UTC_TIMESTAMP(6)),
    heartbeat_at = UTC_TIMESTAMP(6), error_code = NULL, error_message = NULL,
    updated_at = UTC_TIMESTAMP(6)
WHERE batch_id = ? AND entry_id = ?
  AND (outcome = 'pending' OR
       (outcome = 'processing' AND lease_until <= UTC_TIMESTAMP(6)))
  AND attempt < max_attempts`,
		owner, leaseDuration.Microseconds(), batchID, entryID,
	)
	if err != nil {
		return BatchWorkItem{}, false, fmt.Errorf("claim archive batch item: %w", err)
	}
	if err := requireOneRow(result, ErrConflict); err != nil {
		return BatchWorkItem{}, false, err
	}
	var work BatchWorkItem
	var derivedUploadID, taskID sql.NullString
	var actorRole string
	err = tx.QueryRowContext(ctx, `
SELECT batch.id, item.entry_id, entry.public_id, item.ordinal,
       batch.archive_import_id, archive_import.upload_id, parent.display_name,
       archive_import.created_by, batch.created_by, batch.created_by_role,
       entry.logical_path, entry.size_bytes, entry.sha256,
       entry.detected_format, entry.detected_category, entry.blob_id,
       entry.derived_upload_id, entry.task_id, item.outcome,
       item.fencing_token, item.lease_owner
FROM archive_import_task_batch_items item
JOIN archive_import_task_batches batch ON batch.id = item.batch_id
JOIN archive_import_entries entry ON entry.id = item.entry_id
JOIN archive_imports archive_import ON archive_import.id = batch.archive_import_id
JOIN uploads parent ON parent.id = archive_import.upload_id
WHERE item.batch_id = ? AND item.entry_id = ?
FOR UPDATE`, batchID, entryID).Scan(
		&work.BatchID, &work.EntryDatabaseID, &work.EntryID, &work.Ordinal,
		&work.ImportID, &work.ParentUploadID, &work.ArchiveName,
		&work.SourceOwner, &work.Actor, &actorRole, &work.Path, &work.Size,
		&work.SHA256, &work.Format, &work.Category, &work.BlobID,
		&derivedUploadID, &taskID, &work.Outcome, &work.FencingToken,
		&work.LeaseOwner,
	)
	if err != nil {
		return BatchWorkItem{}, false, fmt.Errorf("read archive batch work item: %w", err)
	}
	work.ActorRole = auth.Role(actorRole)
	work.DerivedUploadID = derivedUploadID.String
	work.TaskID = taskID.String
	if err := tx.Commit(); err != nil {
		return BatchWorkItem{}, false, fmt.Errorf("commit archive batch item claim: %w", err)
	}
	return work, true, nil
}

func (r *MySQLRepository) SaveDerivedUpload(
	ctx context.Context,
	work BatchWorkItem,
	uploadID string,
) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin archive derived upload save: %w", err)
	}
	defer tx.Rollback()
	if err := lockBatchItem(ctx, tx, work); err != nil {
		return err
	}
	var existing sql.NullString
	err = tx.QueryRowContext(ctx, `
SELECT derived_upload_id
FROM archive_import_entries
WHERE id = ?
FOR UPDATE`, work.EntryDatabaseID).Scan(&existing)
	if err != nil {
		return fmt.Errorf("lock archive derived upload link: %w", err)
	}
	if existing.Valid && existing.String != uploadID {
		return ErrConflict
	}
	if !existing.Valid {
		if _, err := tx.ExecContext(ctx, `
UPDATE archive_import_entries
SET derived_upload_id = ?, updated_at = UTC_TIMESTAMP(6)
WHERE id = ?`, uploadID, work.EntryDatabaseID); err != nil {
			return fmt.Errorf("save archive derived upload link: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit archive derived upload link: %w", err)
	}
	return nil
}

func (r *MySQLRepository) FinalizeBatchItem(
	ctx context.Context,
	work BatchWorkItem,
	uploadID string,
	taskID string,
	created bool,
) ([]ReleasedBlob, error) {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin archive batch item finalization: %w", err)
	}
	defer tx.Rollback()
	if err := lockBatchItem(ctx, tx, work); err != nil {
		return nil, err
	}
	var status string
	var blobID uint64
	var releasedAt sql.NullTime
	var existingUpload, existingTask sql.NullString
	err = tx.QueryRowContext(ctx, `
SELECT status, blob_id, blob_reference_released_at, derived_upload_id, task_id
FROM archive_import_entries
WHERE id = ? AND archive_import_id = ?
FOR UPDATE`, work.EntryDatabaseID, work.ImportID).Scan(
		&status, &blobID, &releasedAt, &existingUpload, &existingTask,
	)
	if err != nil {
		return nil, fmt.Errorf("lock finalized archive entry: %w", err)
	}
	if existingUpload.Valid && existingUpload.String != uploadID {
		return nil, ErrConflict
	}
	if existingTask.Valid && existingTask.String != taskID {
		return nil, ErrConflict
	}
	released := make([]ReleasedBlob, 0, 1)
	if !releasedAt.Valid {
		candidate, deleting, err := releaseBlob(ctx, tx, blobID)
		if err != nil {
			return nil, err
		}
		if deleting {
			released = append(released, candidate)
		}
	}
	if _, err := tx.ExecContext(ctx, `
UPDATE archive_import_entries
SET status = 'created', derived_upload_id = ?, task_id = ?,
    blob_reference_released_at = COALESCE(blob_reference_released_at, UTC_TIMESTAMP(6)),
    error_code = NULL, error_message = NULL, updated_at = UTC_TIMESTAMP(6)
WHERE id = ?`, uploadID, taskID, work.EntryDatabaseID); err != nil {
		return nil, fmt.Errorf("finalize archive import entry: %w", err)
	}
	outcome := OutcomeExisting
	if created {
		outcome = OutcomeCreated
	}
	result, err := tx.ExecContext(ctx, `
UPDATE archive_import_task_batch_items
SET outcome = ?, task_id = ?, lease_owner = NULL, lease_until = NULL,
    heartbeat_at = NULL, error_code = NULL, error_message = NULL,
    updated_at = UTC_TIMESTAMP(6)
WHERE batch_id = ? AND entry_id = ? AND outcome = 'processing'
  AND lease_owner = ? AND fencing_token = ?`,
		outcome, taskID, work.BatchID, work.EntryDatabaseID,
		work.LeaseOwner, work.FencingToken,
	)
	if err != nil {
		return nil, fmt.Errorf("finalize archive batch item: %w", err)
	}
	if err := requireOneRow(result, ErrLeaseLost); err != nil {
		return nil, err
	}
	if status != EntryCreated {
		if _, err := tx.ExecContext(ctx, `
UPDATE archive_imports
SET created_tasks = created_tasks + 1, updated_at = UTC_TIMESTAMP(6)
WHERE id = ?`, work.ImportID); err != nil {
			return nil, fmt.Errorf("increment archive created task count: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit archive batch item finalization: %w", err)
	}
	return released, nil
}

func (r *MySQLRepository) FailBatchItem(
	ctx context.Context,
	work BatchWorkItem,
	code string,
	message string,
) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin archive batch item failure: %w", err)
	}
	defer tx.Rollback()
	if err := lockBatchItem(ctx, tx, work); err != nil {
		return err
	}
	message = bounded(message, 2048)
	if _, err := tx.ExecContext(ctx, `
UPDATE archive_import_entries
SET status = 'failed', error_code = ?, error_message = ?,
    updated_at = UTC_TIMESTAMP(6)
WHERE id = ? AND status <> 'created'`,
		code, message, work.EntryDatabaseID,
	); err != nil {
		return fmt.Errorf("mark archive entry task failure: %w", err)
	}
	result, err := tx.ExecContext(ctx, `
UPDATE archive_import_task_batch_items
SET outcome = 'failed', lease_owner = NULL, lease_until = NULL,
    heartbeat_at = NULL, error_code = ?, error_message = ?,
    updated_at = UTC_TIMESTAMP(6)
WHERE batch_id = ? AND entry_id = ? AND outcome = 'processing'
  AND lease_owner = ? AND fencing_token = ?`,
		code, message, work.BatchID, work.EntryDatabaseID,
		work.LeaseOwner, work.FencingToken,
	)
	if err != nil {
		return fmt.Errorf("fail archive batch item: %w", err)
	}
	if err := requireOneRow(result, ErrLeaseLost); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit archive batch item failure: %w", err)
	}
	return nil
}

// RetryOrFailBatchItem records the attempt error while preserving durable
// retry semantics. The last permitted attempt is terminal; earlier attempts
// are returned to pending and may be claimed with a new fencing token.
func (r *MySQLRepository) RetryOrFailBatchItem(
	ctx context.Context,
	work BatchWorkItem,
	code string,
	message string,
) (bool, error) {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return false, fmt.Errorf("begin archive batch item retry: %w", err)
	}
	defer tx.Rollback()
	if err := lockBatchItem(ctx, tx, work); err != nil {
		return false, err
	}
	var attempt, maxAttempts uint32
	err = tx.QueryRowContext(ctx, `
SELECT attempt, max_attempts
FROM archive_import_task_batch_items
WHERE batch_id = ? AND entry_id = ?
FOR UPDATE`, work.BatchID, work.EntryDatabaseID).Scan(&attempt, &maxAttempts)
	if err != nil {
		return false, fmt.Errorf("read archive batch retry budget: %w", err)
	}
	message = bounded(message, 2048)
	retry := attempt < maxAttempts
	outcome := OutcomeFailed
	if retry {
		outcome = OutcomePending
	}
	if _, err := tx.ExecContext(ctx, `
UPDATE archive_import_entries
SET status = 'failed', error_code = ?, error_message = ?,
    updated_at = UTC_TIMESTAMP(6)
WHERE id = ? AND status <> 'created'`,
		code, message, work.EntryDatabaseID,
	); err != nil {
		return false, fmt.Errorf("record archive entry task attempt: %w", err)
	}
	result, err := tx.ExecContext(ctx, `
UPDATE archive_import_task_batch_items
SET outcome = ?, lease_owner = NULL, lease_until = NULL,
    heartbeat_at = NULL, error_code = ?, error_message = ?,
    updated_at = UTC_TIMESTAMP(6)
WHERE batch_id = ? AND entry_id = ? AND outcome = 'processing'
  AND lease_owner = ? AND fencing_token = ?`,
		outcome, code, message, work.BatchID, work.EntryDatabaseID,
		work.LeaseOwner, work.FencingToken,
	)
	if err != nil {
		return false, fmt.Errorf("record archive batch item attempt: %w", err)
	}
	if err := requireOneRow(result, ErrLeaseLost); err != nil {
		return false, err
	}
	if err := tx.Commit(); err != nil {
		return false, fmt.Errorf("commit archive batch item retry: %w", err)
	}
	return retry, nil
}

func lockBatchItem(
	ctx context.Context,
	tx *sql.Tx,
	work BatchWorkItem,
) error {
	var marker int
	err := tx.QueryRowContext(ctx, `
SELECT 1
FROM archive_import_task_batch_items
WHERE batch_id = ? AND entry_id = ? AND outcome = 'processing'
  AND lease_owner = ? AND fencing_token = ?
  AND lease_until > UTC_TIMESTAMP(6)
FOR UPDATE`, work.BatchID, work.EntryDatabaseID,
		work.LeaseOwner, work.FencingToken,
	).Scan(&marker)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrLeaseLost
	}
	if err != nil {
		return fmt.Errorf("lock archive batch item lease: %w", err)
	}
	return nil
}

func (r *MySQLRepository) CompleteBatch(
	ctx context.Context,
	batchID string,
) error {
	result, err := r.db.ExecContext(ctx, `
UPDATE archive_import_task_batches batch
SET batch.status = 'completed', batch.completed_at = UTC_TIMESTAMP(6),
    batch.updated_at = UTC_TIMESTAMP(6)
WHERE batch.id = ? AND batch.status = 'processing'
  AND NOT EXISTS (
      SELECT 1 FROM archive_import_task_batch_items item
      WHERE item.batch_id = batch.id
        AND item.outcome IN ('pending', 'processing')
  )`, batchID)
	if err != nil {
		return fmt.Errorf("complete archive task batch: %w", err)
	}
	if affected, err := result.RowsAffected(); err != nil {
		return err
	} else if affected > 1 {
		return errors.New("multiple archive task batches completed")
	}
	return nil
}

func (r *MySQLRepository) CompleteTerminalBatches(
	ctx context.Context,
	staleAfter time.Duration,
	limit int,
) (int64, error) {
	result, err := r.db.ExecContext(ctx, `
UPDATE archive_import_task_batches batch
SET batch.status = 'completed', batch.completed_at = UTC_TIMESTAMP(6),
    batch.updated_at = UTC_TIMESTAMP(6)
WHERE batch.status = 'processing'
  AND batch.updated_at <= TIMESTAMPADD(MICROSECOND, ?, UTC_TIMESTAMP(6))
  AND NOT EXISTS (
      SELECT 1 FROM archive_import_task_batch_items item
      WHERE item.batch_id = batch.id
        AND item.outcome IN ('pending', 'processing')
  )
ORDER BY batch.updated_at ASC, batch.id ASC
LIMIT ?`, -staleAfter.Microseconds(), limit)
	if err != nil {
		return 0, fmt.Errorf("complete terminal archive task batches: %w", err)
	}
	completed, err := result.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("inspect terminal archive task batch completion: %w", err)
	}
	return completed, nil
}

func (r *MySQLRepository) ListRecoverableBatches(
	ctx context.Context,
	staleAfter time.Duration,
	limit int,
) ([]string, error) {
	rows, err := r.db.QueryContext(ctx, `
SELECT batch.id
FROM archive_import_task_batches batch
WHERE batch.status = 'processing'
  AND batch.updated_at <= TIMESTAMPADD(MICROSECOND, ?, UTC_TIMESTAMP(6))
ORDER BY batch.updated_at ASC, batch.id ASC
LIMIT ?`, -staleAfter.Microseconds(), limit)
	if err != nil {
		return nil, fmt.Errorf("list recoverable archive task batches: %w", err)
	}
	ids := make([]string, 0)
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return nil, fmt.Errorf("scan recoverable archive batch: %w", err)
		}
		ids = append(ids, id)
	}
	if err := rows.Close(); err != nil {
		return nil, fmt.Errorf("iterate recoverable archive batches: %w", err)
	}
	reserved := make([]string, 0, len(ids))
	for _, id := range ids {
		result, err := r.db.ExecContext(ctx, `
UPDATE archive_import_task_batches
SET updated_at = UTC_TIMESTAMP(6)
WHERE id = ? AND status = 'processing'
  AND updated_at <= TIMESTAMPADD(MICROSECOND, ?, UTC_TIMESTAMP(6))`,
			id, -staleAfter.Microseconds())
		if err != nil {
			return nil, fmt.Errorf("reserve archive task batch recovery: %w", err)
		}
		affected, err := result.RowsAffected()
		if err != nil {
			return nil, fmt.Errorf("inspect archive batch recovery reservation: %w", err)
		}
		if affected == 0 {
			continue
		}
		if affected != 1 {
			return nil, errors.New("multiple archive task batches reserved")
		}
		reserved = append(reserved, id)
	}
	return reserved, nil
}

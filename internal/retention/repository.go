package retention

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"binaryscan/internal/audit"
	"binaryscan/internal/blobfence"
	"binaryscan/internal/taskevent"
)

const (
	uploadRetentionLockWaitSeconds = 0

	expiredTaskPredicate = `
	  AND t.sample_expires_at <= UTC_TIMESTAMP(6)
	  AND t.sample_deleted_at IS NULL
	  AND t.deleted_at IS NULL
	  AND t.status IN ('SUCCEEDED', 'PARTIAL_SUCCEEDED', 'FAILED', 'CANCELLED')
	  AND NOT EXISTS (
	      SELECT 1
	      FROM jobs j
	      WHERE j.task_id = t.id
	        AND (
	            j.status IN ('leased', 'running', 'cancel_requested')
	            OR (j.status = 'queued' AND j.kind <> 'decompile')
	        )
	  )
	  AND NOT EXISTS (
	      SELECT 1
	      FROM reports report
	      WHERE report.task_id = t.id
	        AND report.status IN ('queued', 'generating')
	  )
	  AND NOT EXISTS (
	      SELECT 1
	      FROM decompile_results result
	      WHERE result.task_id = t.id
	        AND result.status IN ('queued', 'running')
	  )`
	expiredUploadPredicate = `
  AND u.expires_at <= UTC_TIMESTAMP(6)
  AND (
      u.status <> 'expired'
      OR u.blob_id IS NOT NULL
      OR EXISTS (
          SELECT 1
          FROM upload_parts p
          WHERE p.upload_id = u.id
      )
  )
  AND NOT EXISTS (
      SELECT 1
      FROM upload_intake_profiles intake
      JOIN blobs candidate_blob ON candidate_blob.id = u.blob_id
      WHERE intake.upload_id = u.id
        AND u.status = 'completed'
        AND intake.source_kind = 'direct'
        AND intake.validation_status = 'valid'
        AND intake.input_category IN ('binary', 'container')
        AND intake.detected_category = intake.input_category
        AND intake.detected_format IS NOT NULL
        AND candidate_blob.state = 'available'
        AND NOT EXISTS (
            SELECT 1
            FROM tasks claimed_task
            WHERE claimed_task.upload_id = u.id
        )
  )
  AND NOT EXISTS (
      SELECT 1
      FROM upload_intake_profiles archive_intake
      JOIN blobs archive_blob ON archive_blob.id = u.blob_id
      WHERE archive_intake.upload_id = u.id
        AND u.status = 'completed'
        AND archive_intake.source_kind = 'direct'
        AND archive_intake.validation_status = 'valid'
        AND archive_intake.input_category = 'archive'
        AND archive_intake.detected_category = 'archive'
        AND archive_intake.detected_format IS NOT NULL
        AND archive_blob.state = 'available'
        AND (
            archive_intake.archive_import_id IS NULL
            OR EXISTS (
                SELECT 1
                FROM archive_imports active_import
                WHERE active_import.id = archive_intake.archive_import_id
                  AND active_import.upload_id = u.id
                  AND active_import.status IN ('queued', 'running')
            )
        )
  )
  AND NOT EXISTS (
      SELECT 1
      FROM archive_import_entries pending_entry
      JOIN upload_intake_profiles derived_intake
        ON derived_intake.upload_id = pending_entry.derived_upload_id
      WHERE pending_entry.derived_upload_id = u.id
        AND u.status = 'completed'
        AND derived_intake.source_kind = 'archive_entry'
        AND pending_entry.status IN ('eligible', 'failed')
  )
  AND NOT EXISTS (
      SELECT 1
      FROM upload_intake_profiles derived_provenance
      JOIN archive_imports parent_import
        ON parent_import.upload_id = derived_provenance.source_parent_upload_id
      JOIN uploads provenance_parent
        ON provenance_parent.id = parent_import.upload_id
      JOIN archive_import_entries pending_provenance
        ON pending_provenance.archive_import_id = parent_import.id
       AND pending_provenance.logical_path = derived_provenance.source_entry_path
       AND pending_provenance.status IN ('eligible', 'failed')
       AND pending_provenance.size_bytes = u.declared_size_bytes
       AND pending_provenance.sha256 = u.actual_sha256
       AND pending_provenance.detected_category = derived_provenance.input_category
       AND pending_provenance.detected_format = derived_provenance.detected_format
       AND pending_provenance.blob_id = u.blob_id
      WHERE derived_provenance.upload_id = u.id
        AND u.status = 'completed'
        AND derived_provenance.source_kind = 'archive_entry'
        AND derived_provenance.validation_status = 'valid'
        AND derived_provenance.source_archive_name = provenance_parent.display_name
        AND pending_provenance.derived_upload_id IS NULL
  )`
	pendingUploadPartCleanupPredicate = `
  AND u.parts_cleaned_at IS NULL
  AND u.status IN ('completed', 'failed', 'expired', 'cancelled')`
)

type MySQLRepository struct {
	db *sql.DB
}

func NewMySQLRepository(db *sql.DB) *MySQLRepository {
	return &MySQLRepository{db: db}
}

func (r *MySQLRepository) ListExpiredTaskIDs(
	ctx context.Context,
	limit int,
) ([]string, error) {
	rows, err := r.db.QueryContext(ctx, `
SELECT t.id
FROM tasks t
WHERE 1 = 1`+expiredTaskPredicate+`
  AND NOT EXISTS (
      SELECT 1
      FROM task_sample_retention_operations operation
      WHERE operation.task_id = t.id
        AND (
            operation.status = 'completed'
            OR (
                operation.status = 'cleaning'
                AND operation.lease_until > UTC_TIMESTAMP(6)
            )
        )
  )
ORDER BY t.sample_expires_at, t.id
LIMIT ?`, limit)
	if err != nil {
		return nil, fmt.Errorf("query expired task samples: %w", err)
	}
	defer rows.Close()
	return scanStringIDs(rows, limit, "expired task sample")
}

func (r *MySQLRepository) ReleaseExpiredTaskSample(
	ctx context.Context,
	taskID string,
) (bool, error) {
	tx, err := r.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return false, fmt.Errorf("begin task sample retention transaction: %w", err)
	}
	defer tx.Rollback()

	var blobID uint64
	err = tx.QueryRowContext(ctx, `
SELECT t.blob_id
FROM tasks t
WHERE t.id = ?`+expiredTaskPredicate+`
LIMIT 1
FOR UPDATE SKIP LOCKED`, taskID).Scan(&blobID)
	if errors.Is(err, sql.ErrNoRows) {
		return false, commitSkipped(tx, "task sample retention")
	}
	if err != nil {
		return false, fmt.Errorf("lock expired task sample: %w", err)
	}
	if err := cancelExpiredQueuedDecompileJobs(ctx, tx, taskID); err != nil {
		return false, err
	}
	if err := releaseTaskDerivedBlobReferences(ctx, tx, taskID); err != nil {
		return false, err
	}
	if err := releaseBlobReference(ctx, tx, blobID); err != nil {
		return false, err
	}
	result, err := tx.ExecContext(ctx, `
UPDATE tasks
SET sample_deleted_at = UTC_TIMESTAMP(6),
    updated_at = UTC_TIMESTAMP(6),
    event_sequence = event_sequence + 1
WHERE id = ?
  AND blob_id = ?
  AND sample_expires_at <= UTC_TIMESTAMP(6)
  AND sample_deleted_at IS NULL
  AND deleted_at IS NULL
  AND status IN ('SUCCEEDED', 'PARTIAL_SUCCEEDED', 'FAILED', 'CANCELLED')`,
		taskID,
		blobID,
	)
	if err != nil {
		return false, fmt.Errorf("mark task sample deleted: %w", err)
	}
	if err := requireOne(result, "task sample retention"); err != nil {
		return false, err
	}
	if err := taskevent.AppendCurrentState(
		ctx,
		tx,
		taskID,
		"task.sample_deleted",
		"Task sample retention expired.",
	); err != nil {
		return false, err
	}
	if err := audit.Append(ctx, tx, audit.Event{
		Action:     "retention.task_sample_deleted",
		ObjectType: "task",
		ObjectID:   taskID,
		Outcome:    audit.OutcomeSuccess,
		Metadata: map[string]any{
			"reason":                      "sample_retention_expired",
			"decompile_sources_preserved": true,
		},
	}); err != nil {
		return false, fmt.Errorf("append task sample retention audit: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return false, fmt.Errorf("commit task sample retention: %w", err)
	}
	return true, nil
}

func cancelExpiredQueuedDecompileJobs(
	ctx context.Context,
	tx *sql.Tx,
	taskID string,
) error {
	_, err := tx.ExecContext(ctx, `
UPDATE jobs
SET status = 'cancelled',
    lease_owner = NULL,
    lease_until = NULL,
    heartbeat_at = NULL,
    cancel_requested_at = COALESCE(cancel_requested_at, UTC_TIMESTAMP(6)),
    completed_at = UTC_TIMESTAMP(6),
    error_code = 'sample_expired',
    error_message = 'The retained sample expired before decompilation started.'
WHERE task_id = ?
  AND kind = 'decompile'
  AND status = 'queued'`, taskID)
	if err != nil {
		return fmt.Errorf(
			"cancel queued decompile jobs for expired sample: %w",
			err,
		)
	}
	return nil
}

func releaseTaskDerivedBlobReferences(
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
		return fmt.Errorf("lock retained nested image references: %w", err)
	}
	var blobIDs []uint64
	for rows.Next() {
		var fileNodeID, blobID uint64
		if err := rows.Scan(&fileNodeID, &blobID); err != nil {
			rows.Close()
			return fmt.Errorf("scan retained nested image reference: %w", err)
		}
		if fileNodeID == 0 || blobID == 0 {
			rows.Close()
			return errors.New("retained nested image reference is invalid")
		}
		blobIDs = append(blobIDs, blobID)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return fmt.Errorf("iterate retained nested image references: %w", err)
	}
	if err := rows.Close(); err != nil {
		return fmt.Errorf("close retained nested image references: %w", err)
	}
	for _, blobID := range blobIDs {
		if err := releaseBlobReference(ctx, tx, blobID); err != nil {
			return err
		}
	}
	if len(blobIDs) == 0 {
		return nil
	}
	if _, err := tx.ExecContext(ctx, `
UPDATE file_nodes node
JOIN file_node_blob_refs reference
  ON reference.task_id = node.task_id
 AND reference.file_node_id = node.id
SET node.storage_key = NULL
WHERE reference.task_id = ?`, taskID); err != nil {
		return fmt.Errorf("clear retained nested image storage keys: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `
DELETE FROM file_node_blob_refs
WHERE task_id = ?`, taskID); err != nil {
		return fmt.Errorf("delete retained nested image references: %w", err)
	}
	return nil
}

func (r *MySQLRepository) ListExpiredUploadIDs(
	ctx context.Context,
	limit int,
) ([]string, error) {
	rows, err := r.db.QueryContext(ctx, `
SELECT u.id
FROM uploads u
WHERE 1 = 1`+expiredUploadPredicate+`
ORDER BY u.expires_at, u.id
LIMIT ?`, limit)
	if err != nil {
		return nil, fmt.Errorf("query expired uploads: %w", err)
	}
	defer rows.Close()
	return scanStringIDs(rows, limit, "expired upload")
}

func (r *MySQLRepository) ListPendingUploadPartCleanupIDs(
	ctx context.Context,
	limit int,
) ([]string, error) {
	rows, err := r.db.QueryContext(ctx, `
SELECT u.id
FROM uploads u
WHERE 1 = 1`+pendingUploadPartCleanupPredicate+`
ORDER BY u.updated_at, u.id
LIMIT ?`, limit)
	if err != nil {
		return nil, fmt.Errorf("query pending upload part cleanup: %w", err)
	}
	defer rows.Close()
	return scanStringIDs(rows, limit, "pending upload part cleanup")
}

func (r *MySQLRepository) CleanupUploadParts(
	ctx context.Context,
	uploadID string,
	deleteDirectory func() error,
) (bool, error) {
	if deleteDirectory == nil {
		return false, errors.New("upload directory delete callback is required")
	}
	return r.withUploadLock(
		ctx,
		uploadID,
		"upload part cleanup",
		func(connection *sql.Conn) (bool, error) {
			return r.cleanupUploadPartsLocked(
				ctx,
				connection,
				uploadID,
				deleteDirectory,
			)
		},
	)
}

func (r *MySQLRepository) cleanupUploadPartsLocked(
	ctx context.Context,
	connection *sql.Conn,
	uploadID string,
	deleteDirectory func() error,
) (bool, error) {
	tx, err := connection.BeginTx(
		ctx,
		&sql.TxOptions{Isolation: sql.LevelReadCommitted},
	)
	if err != nil {
		return false, fmt.Errorf("begin upload part cleanup transaction: %w", err)
	}
	defer tx.Rollback()

	var status string
	err = tx.QueryRowContext(ctx, `
SELECT u.status
FROM uploads u
WHERE u.id = ?`+pendingUploadPartCleanupPredicate+`
LIMIT 1
FOR UPDATE SKIP LOCKED`, uploadID).Scan(&status)
	if errors.Is(err, sql.ErrNoRows) {
		return false, commitSkipped(tx, "upload part cleanup")
	}
	if err != nil {
		return false, fmt.Errorf("lock pending upload part cleanup: %w", err)
	}
	if err := deleteDirectory(); err != nil {
		return false, fmt.Errorf("delete upload part directory: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `
DELETE FROM upload_parts
WHERE upload_id = ?`, uploadID); err != nil {
		return false, fmt.Errorf("delete upload part records: %w", err)
	}
	result, err := tx.ExecContext(ctx, `
UPDATE uploads
SET parts_cleaned_at = UTC_TIMESTAMP(6),
    updated_at = UTC_TIMESTAMP(6)
WHERE id = ?
  AND status = ?
  AND parts_cleaned_at IS NULL`, uploadID, status)
	if err != nil {
		return false, fmt.Errorf("record upload part cleanup: %w", err)
	}
	if err := requireOne(result, "upload part cleanup"); err != nil {
		return false, err
	}
	if err := audit.Append(ctx, tx, audit.Event{
		Action:     "maintenance.upload_parts_cleaned",
		ObjectType: "upload",
		ObjectID:   uploadID,
		Outcome:    audit.OutcomeSuccess,
		Metadata: map[string]any{
			"upload_status": status,
		},
	}); err != nil {
		return false, fmt.Errorf("append upload part cleanup audit: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return false, fmt.Errorf("commit upload part cleanup: %w", err)
	}
	return true, nil
}

func (r *MySQLRepository) ExpireUpload(
	ctx context.Context,
	uploadID string,
	deleteDirectory func() error,
) (changed bool, returnErr error) {
	if deleteDirectory == nil {
		return false, errors.New("upload directory delete callback is required")
	}
	return r.withUploadLock(
		ctx,
		uploadID,
		"upload retention",
		func(connection *sql.Conn) (bool, error) {
			return r.expireUploadLocked(
				ctx,
				connection,
				uploadID,
				deleteDirectory,
			)
		},
	)
}

func (r *MySQLRepository) withUploadLock(
	ctx context.Context,
	uploadID string,
	action string,
	fn func(*sql.Conn) (bool, error),
) (changed bool, returnErr error) {
	connection, err := r.db.Conn(ctx)
	if err != nil {
		return false, fmt.Errorf("reserve %s lock connection: %w", action, err)
	}
	defer connection.Close()

	lockName := "binaryscan_upload_" + uploadID
	var acquired sql.NullInt64
	if err := connection.QueryRowContext(
		ctx,
		"SELECT GET_LOCK(?, ?)",
		lockName,
		uploadRetentionLockWaitSeconds,
	).Scan(&acquired); err != nil {
		return false, fmt.Errorf("acquire %s lock: %w", action, err)
	}
	if !acquired.Valid {
		return false, fmt.Errorf("%s lock returned no result", action)
	}
	if acquired.Int64 == 0 {
		return false, nil
	}
	if acquired.Int64 != 1 {
		return false, fmt.Errorf("%s lock returned an invalid result", action)
	}
	defer func() {
		releaseContext, cancel := context.WithTimeout(
			context.Background(),
			5*time.Second,
		)
		defer cancel()
		var released sql.NullInt64
		err := connection.QueryRowContext(
			releaseContext,
			"SELECT RELEASE_LOCK(?)",
			lockName,
		).Scan(&released)
		if err != nil {
			returnErr = errors.Join(
				returnErr,
				fmt.Errorf("release %s lock: %w", action, err),
			)
			return
		}
		if !released.Valid || released.Int64 != 1 {
			returnErr = errors.Join(
				returnErr,
				fmt.Errorf("%s lock was not released", action),
			)
		}
	}()

	return fn(connection)
}

func (r *MySQLRepository) expireUploadLocked(
	ctx context.Context,
	connection *sql.Conn,
	uploadID string,
	deleteDirectory func() error,
) (bool, error) {
	tx, err := connection.BeginTx(
		ctx,
		&sql.TxOptions{Isolation: sql.LevelReadCommitted},
	)
	if err != nil {
		return false, fmt.Errorf("begin upload retention transaction: %w", err)
	}
	defer tx.Rollback()

	var blobID sql.NullInt64
	err = tx.QueryRowContext(ctx, `
SELECT u.blob_id
FROM uploads u
WHERE u.id = ?`+expiredUploadPredicate+`
LIMIT 1
FOR UPDATE SKIP LOCKED`, uploadID).Scan(&blobID)
	if errors.Is(err, sql.ErrNoRows) {
		return false, commitSkipped(tx, "upload retention")
	}
	if err != nil {
		return false, fmt.Errorf("lock expired upload: %w", err)
	}
	if err := deleteDirectory(); err != nil {
		return false, fmt.Errorf("delete expired upload directory: %w", err)
	}
	if blobID.Valid {
		if blobID.Int64 <= 0 {
			return false, errors.New("expired upload has invalid blob reference")
		}
		if err := releaseBlobReference(ctx, tx, uint64(blobID.Int64)); err != nil {
			return false, err
		}
	}
	if _, err := tx.ExecContext(ctx, `
DELETE FROM upload_parts
WHERE upload_id = ?`, uploadID); err != nil {
		return false, fmt.Errorf("delete expired upload parts: %w", err)
	}
	result, err := tx.ExecContext(ctx, `
UPDATE uploads
SET status = 'expired',
    blob_id = NULL,
    parts_cleaned_at = UTC_TIMESTAMP(6),
    updated_at = UTC_TIMESTAMP(6)
WHERE id = ?
  AND expires_at <= UTC_TIMESTAMP(6)`, uploadID)
	if err != nil {
		return false, fmt.Errorf("mark upload expired: %w", err)
	}
	if err := requireOne(result, "upload retention"); err != nil {
		return false, err
	}
	if err := audit.Append(ctx, tx, audit.Event{
		Action:     "retention.upload_expired",
		ObjectType: "upload",
		ObjectID:   uploadID,
		Outcome:    audit.OutcomeSuccess,
		Metadata: map[string]any{
			"reason": "upload_session_expired",
		},
	}); err != nil {
		return false, fmt.Errorf("append upload retention audit: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return false, fmt.Errorf("commit upload retention: %w", err)
	}
	return true, nil
}

func (r *MySQLRepository) ListDeletingBlobIDs(
	ctx context.Context,
	limit int,
) ([]uint64, error) {
	rows, err := r.db.QueryContext(ctx, `
SELECT id
FROM blobs
WHERE state = 'deleting'
  AND reference_count = 0
ORDER BY id
LIMIT ?`, limit)
	if err != nil {
		return nil, fmt.Errorf("query deleting blobs: %w", err)
	}
	defer rows.Close()
	result := make([]uint64, 0, limit)
	for rows.Next() {
		var id uint64
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("scan deleting blob: %w", err)
		}
		result = append(result, id)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate deleting blobs: %w", err)
	}
	return result, nil
}

func (r *MySQLRepository) FinalizeDeletingBlob(
	ctx context.Context,
	blobID uint64,
	deleteFile func(Blob) error,
) (bool, error) {
	if deleteFile == nil {
		return false, errors.New("blob delete callback is required")
	}
	var sha256 string
	if err := r.db.QueryRowContext(ctx, `
SELECT sha256
FROM blobs
WHERE id = ?`, blobID).Scan(&sha256); errors.Is(err, sql.ErrNoRows) {
		return false, nil
	} else if err != nil {
		return false, fmt.Errorf("read deleting blob content address: %w", err)
	}
	var changed bool
	err := blobfence.With(ctx, r.db, sha256, func() error {
		var finalizeErr error
		changed, finalizeErr = r.finalizeDeletingBlob(ctx, blobID, deleteFile)
		return finalizeErr
	})
	if err != nil {
		return false, fmt.Errorf("fence deleting blob: %w", err)
	}
	return changed, nil
}

func (r *MySQLRepository) finalizeDeletingBlob(
	ctx context.Context,
	blobID uint64,
	deleteFile func(Blob) error,
) (bool, error) {
	tx, err := r.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return false, fmt.Errorf("begin blob deletion transaction: %w", err)
	}
	defer tx.Rollback()

	var blob Blob
	err = tx.QueryRowContext(ctx, `
SELECT id, sha256, size_bytes, storage_key
FROM blobs
WHERE id = ?
  AND state = 'deleting'
  AND reference_count = 0
LIMIT 1
FOR UPDATE SKIP LOCKED`, blobID).Scan(
		&blob.ID,
		&blob.SHA256,
		&blob.SizeBytes,
		&blob.StorageKey,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return false, commitSkipped(tx, "blob deletion")
	}
	if err != nil {
		return false, fmt.Errorf("lock deleting blob: %w", err)
	}
	if err := deleteFile(blob); err != nil {
		return false, fmt.Errorf("remove blob file: %w", err)
	}
	result, err := tx.ExecContext(ctx, `
UPDATE blobs
SET state = 'deleted',
    deleted_at = UTC_TIMESTAMP(6)
WHERE id = ?
  AND sha256 = ?
  AND size_bytes = ?
  AND storage_key = ?
  AND state = 'deleting'
  AND reference_count = 0`,
		blob.ID,
		blob.SHA256,
		blob.SizeBytes,
		blob.StorageKey,
	)
	if err != nil {
		return false, fmt.Errorf("finalize blob deletion: %w", err)
	}
	if err := requireOne(result, "blob deletion finalization"); err != nil {
		return false, err
	}
	if err := tx.Commit(); err != nil {
		return false, fmt.Errorf("commit blob deletion: %w", err)
	}
	return true, nil
}

func releaseBlobReference(
	ctx context.Context,
	tx *sql.Tx,
	blobID uint64,
) error {
	var (
		referenceCount uint64
		state          string
	)
	err := tx.QueryRowContext(ctx, `
SELECT reference_count, state
FROM blobs
WHERE id = ?
LIMIT 1
FOR UPDATE`, blobID).Scan(&referenceCount, &state)
	if errors.Is(err, sql.ErrNoRows) {
		return errors.New("retained blob does not exist")
	}
	if err != nil {
		return fmt.Errorf("lock retained blob: %w", err)
	}
	if referenceCount == 0 ||
		(state != "available" && state != "staging") {
		return errors.New("retained blob reference state is inconsistent")
	}
	nextState := state
	if referenceCount == 1 {
		nextState = "deleting"
	}
	result, err := tx.ExecContext(ctx, `
UPDATE blobs
SET state = ?,
    reference_count = reference_count - 1
WHERE id = ?
  AND state = ?
  AND reference_count = ?`,
		nextState,
		blobID,
		state,
		referenceCount,
	)
	if err != nil {
		return fmt.Errorf("release retained blob reference: %w", err)
	}
	return requireOne(result, "retained blob reference release")
}

func scanStringIDs(
	rows *sql.Rows,
	capacity int,
	description string,
) ([]string, error) {
	result := make([]string, 0, capacity)
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("scan %s: %w", description, err)
		}
		result = append(result, id)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate %ss: %w", description, err)
	}
	return result, nil
}

func requireOne(result sql.Result, action string) error {
	affected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("inspect %s: %w", action, err)
	}
	if affected != 1 {
		return fmt.Errorf("%s changed %d rows instead of one", action, affected)
	}
	return nil
}

func commitSkipped(tx *sql.Tx, action string) error {
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit skipped %s: %w", action, err)
	}
	return nil
}

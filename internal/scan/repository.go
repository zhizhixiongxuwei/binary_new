package scan

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"math"

	"binaryscan/internal/extract"
	"binaryscan/internal/queue"
	"binaryscan/internal/taskevent"
)

type MySQLRepository struct {
	db *sql.DB
}

func NewMySQLRepository(db *sql.DB) *MySQLRepository {
	return &MySQLRepository{db: db}
}

func (r *MySQLRepository) Load(
	ctx context.Context,
	lease queue.Lease,
) (Sample, error) {
	var sample Sample
	var uploadBlobID sql.NullInt64
	var sizeBytes, declaredSizeBytes uint64
	var uploadSHA256 sql.NullString
	var blobState, uploadStatus string
	var sampleDeletedAt, taskDeletedAt sql.NullTime
	var limitsSnapshot []byte
	err := r.db.QueryRowContext(ctx, `
SELECT task.id, upload.id, stored_blob.id, upload.blob_id,
       upload.display_name, stored_blob.size_bytes, upload.declared_size_bytes,
       stored_blob.sha256, upload.actual_sha256, stored_blob.storage_key,
       stored_blob.state, upload.status,
       task.limits_snapshot, task.sample_deleted_at, task.deleted_at
FROM tasks task
JOIN blobs stored_blob ON stored_blob.id = task.blob_id
JOIN uploads upload ON upload.id = task.upload_id
WHERE task.id = ?`, lease.TaskID).Scan(
		&sample.TaskID, &sample.UploadID, &sample.BlobID, &uploadBlobID,
		&sample.DisplayName, &sizeBytes, &declaredSizeBytes,
		&sample.SHA256, &uploadSHA256,
		&sample.StorageKey, &blobState, &uploadStatus,
		&limitsSnapshot, &sampleDeletedAt, &taskDeletedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return Sample{}, ErrSampleMissing
	}
	if err != nil {
		return Sample{}, fmt.Errorf("load scan sample: %w", err)
	}
	if sizeBytes > math.MaxInt64 {
		return Sample{}, ErrSampleMismatch
	}
	if !uploadBlobID.Valid || uploadBlobID.Int64 <= 0 ||
		uint64(uploadBlobID.Int64) != sample.BlobID ||
		declaredSizeBytes != sizeBytes ||
		!uploadSHA256.Valid || uploadSHA256.String != sample.SHA256 ||
		uploadStatus != "completed" {
		return Sample{}, ErrSampleMismatch
	}
	if blobState != "available" || sampleDeletedAt.Valid || taskDeletedAt.Valid {
		return Sample{}, ErrSampleMissing
	}
	limits, err := decodeExtractionLimits(limitsSnapshot)
	if err != nil {
		return Sample{}, err
	}
	sample.SizeBytes = int64(sizeBytes)
	sample.Limits = limits
	return sample, nil
}

type persistedTaskLimits struct {
	MaxUploadBytes   int64 `json:"max_upload_bytes"`
	MaxExpandedBytes int64 `json:"max_expanded_bytes"`
	MaxArchiveRatio  int64 `json:"max_archive_ratio"`
	MaxDepth         int   `json:"max_depth"`
	MaxFileNodes     int   `json:"max_file_nodes"`
}

func decodeExtractionLimits(raw []byte) (extract.Limits, error) {
	var persisted persistedTaskLimits
	if len(raw) == 0 || json.Unmarshal(raw, &persisted) != nil ||
		persisted.MaxUploadBytes <= 0 ||
		persisted.MaxUploadBytes > 10*1024*1024*1024 ||
		persisted.MaxExpandedBytes <= 0 ||
		persisted.MaxExpandedBytes > 50*1024*1024*1024 ||
		persisted.MaxArchiveRatio <= 0 || persisted.MaxArchiveRatio > 100 ||
		persisted.MaxDepth <= 0 || persisted.MaxDepth > 10 ||
		persisted.MaxFileNodes <= 0 || persisted.MaxFileNodes > 100_000 {
		return extract.Limits{}, ErrInvalidLimits
	}
	maxEntryBytes := persisted.MaxUploadBytes
	if maxEntryBytes > persisted.MaxExpandedBytes {
		maxEntryBytes = persisted.MaxExpandedBytes
	}
	return extract.Limits{
		MaxExpandedBytes: persisted.MaxExpandedBytes,
		MaxEntryBytes:    maxEntryBytes,
		MaxNodes:         persisted.MaxFileNodes - 1,
		MaxDepth:         persisted.MaxDepth,
		MaxRatio:         persisted.MaxArchiveRatio,
	}, nil
}

func (r *MySQLRepository) Publish(
	ctx context.Context,
	lease queue.Lease,
	node RootNode,
) error {
	if lease.TaskAttemptID == nil {
		return queue.ErrLeaseLost
	}
	transaction, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin root file publication: %w", err)
	}
	defer transaction.Rollback()

	if err := lockPublishingLease(ctx, transaction, lease); err != nil {
		return err
	}
	rootID, found, err := findRootNode(ctx, transaction, lease.TaskID)
	if err != nil {
		return err
	}
	if found {
		if err := updateRootNode(ctx, transaction, rootID, lease.TaskID, node); err != nil {
			return err
		}
	} else if err := insertRootNode(ctx, transaction, lease.TaskID, node); err != nil {
		return err
	}
	if err := revalidatePublishingLease(ctx, transaction, lease); err != nil {
		return err
	}
	result, err := transaction.ExecContext(ctx, `
UPDATE tasks
SET root_format = ?,
    updated_at = UTC_TIMESTAMP(6),
    event_sequence = event_sequence + 1
WHERE id = ? AND status = 'IDENTIFYING'`,
		node.Format, lease.TaskID,
	)
	if err != nil {
		return fmt.Errorf("publish task root format: %w", err)
	}
	if err := requireAtMostOne(result, "inspect task root format publication"); err != nil {
		return err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("inspect task root format event: %w", err)
	}
	if affected == 1 {
		if err := taskevent.AppendCurrentState(
			ctx, transaction, lease.TaskID,
			"task.metadata_changed", "Task root format identified.",
		); err != nil {
			return err
		}
	}
	if err := transaction.Commit(); err != nil {
		return fmt.Errorf("commit root file publication: %w", err)
	}
	return nil
}

func lockPublishingLease(
	ctx context.Context,
	transaction *sql.Tx,
	lease queue.Lease,
) error {
	var attemptID sql.NullInt64
	err := transaction.QueryRowContext(ctx, `
SELECT task_attempt_id
FROM jobs
WHERE id = ?
  AND task_id = ?
  AND kind = 'scan'
  AND status = 'running'
  AND lease_owner = ?
  AND fencing_token = ?
  AND lease_until > UTC_TIMESTAMP(6)
  AND cancel_requested_at IS NULL
FOR UPDATE`,
		lease.JobID, lease.TaskID, lease.Owner, lease.FencingToken,
	).Scan(&attemptID)
	if errors.Is(err, sql.ErrNoRows) {
		return queue.ErrLeaseLost
	}
	if err != nil {
		return fmt.Errorf("lock publishing scan job: %w", err)
	}
	if !attemptID.Valid || attemptID.Int64 <= 0 ||
		uint64(attemptID.Int64) != *lease.TaskAttemptID {
		return queue.ErrLeaseLost
	}

	var attemptFence uint64
	err = transaction.QueryRowContext(ctx, `
SELECT fencing_token
FROM task_attempts
WHERE id = ?
  AND task_id = ?
  AND status = 'running'
  AND fencing_token = ?
FOR UPDATE`,
		*lease.TaskAttemptID, lease.TaskID, lease.FencingToken,
	).Scan(&attemptFence)
	if errors.Is(err, sql.ErrNoRows) {
		return queue.ErrLeaseLost
	}
	if err != nil {
		return fmt.Errorf("lock publishing task attempt: %w", err)
	}
	if attemptFence != lease.FencingToken {
		return queue.ErrLeaseLost
	}

	var taskStatus string
	err = transaction.QueryRowContext(ctx, `
SELECT status
FROM tasks
WHERE id = ?
  AND status = 'IDENTIFYING'
  AND sample_deleted_at IS NULL
  AND deleted_at IS NULL
FOR UPDATE`, lease.TaskID).Scan(&taskStatus)
	if errors.Is(err, sql.ErrNoRows) {
		return queue.ErrLeaseLost
	}
	if err != nil {
		return fmt.Errorf("lock publishing scan task: %w", err)
	}
	return nil
}

func revalidatePublishingLease(
	ctx context.Context,
	transaction *sql.Tx,
	lease queue.Lease,
) error {
	var valid int
	err := transaction.QueryRowContext(ctx, `
SELECT 1
FROM jobs
WHERE id = ?
  AND task_id = ?
  AND status = 'running'
  AND lease_owner = ?
  AND fencing_token = ?
  AND lease_until > UTC_TIMESTAMP(6)
  AND cancel_requested_at IS NULL`,
		lease.JobID, lease.TaskID, lease.Owner, lease.FencingToken,
	).Scan(&valid)
	if errors.Is(err, sql.ErrNoRows) {
		return queue.ErrLeaseLost
	}
	if err != nil {
		return fmt.Errorf("revalidate publishing scan job: %w", err)
	}
	return nil
}

func findRootNode(
	ctx context.Context,
	transaction *sql.Tx,
	taskID string,
) (uint64, bool, error) {
	rows, err := transaction.QueryContext(ctx, `
SELECT id
FROM file_nodes
WHERE task_id = ? AND parent_id IS NULL AND depth = 0
ORDER BY id ASC
LIMIT 2
FOR UPDATE`, taskID)
	if err != nil {
		return 0, false, fmt.Errorf("find existing root file node: %w", err)
	}
	defer rows.Close()
	var ids []uint64
	for rows.Next() {
		var id uint64
		if err := rows.Scan(&id); err != nil {
			return 0, false, fmt.Errorf("scan existing root file node: %w", err)
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		return 0, false, fmt.Errorf("iterate existing root file nodes: %w", err)
	}
	if len(ids) > 1 {
		return 0, false, queue.ErrInconsistentState
	}
	if len(ids) == 0 {
		return 0, false, nil
	}
	return ids[0], true, nil
}

func insertRootNode(
	ctx context.Context,
	transaction *sql.Tx,
	taskID string,
	node RootNode,
) error {
	_, err := transaction.ExecContext(ctx, `
INSERT INTO file_nodes (
    task_id, parent_id, logical_path, logical_path_hash, display_name,
    node_type, depth, format, mime_type, architecture, size_bytes, sha256,
    storage_key, extraction_status, metadata_json
) VALUES (?, NULL, ?, ?, ?, 'file', 0, ?, NULLIF(?, ''), NULLIF(?, ''),
          ?, ?, ?, 'indexed', ?)`,
		taskID, node.LogicalPath, node.LogicalPathHash[:], node.DisplayName,
		node.Format, node.MIMEType, node.Architecture, node.SizeBytes,
		node.SHA256, node.StorageKey, []byte(node.MetadataJSON),
	)
	if err != nil {
		return fmt.Errorf("insert root file node: %w", err)
	}
	return nil
}

func updateRootNode(
	ctx context.Context,
	transaction *sql.Tx,
	rootID uint64,
	taskID string,
	node RootNode,
) error {
	result, err := transaction.ExecContext(ctx, `
UPDATE file_nodes
SET logical_path = ?,
    logical_path_hash = ?,
    display_name = ?,
    node_type = 'file',
    depth = 0,
    format = ?,
    mime_type = NULLIF(?, ''),
    architecture = NULLIF(?, ''),
    size_bytes = ?,
    sha256 = ?,
    storage_key = ?,
    extraction_status = 'indexed',
    metadata_json = ?,
    error_code = NULL,
    error_message = NULL
WHERE id = ? AND task_id = ? AND parent_id IS NULL`,
		node.LogicalPath, node.LogicalPathHash[:], node.DisplayName,
		node.Format, node.MIMEType, node.Architecture, node.SizeBytes,
		node.SHA256, node.StorageKey, []byte(node.MetadataJSON),
		rootID, taskID,
	)
	if err != nil {
		return fmt.Errorf("update root file node: %w", err)
	}
	return requireAtMostOne(result, "inspect root file node update")
}

func requireAtMostOne(result sql.Result, operation string) error {
	affected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("%s: %w", operation, err)
	}
	if affected > 1 {
		return queue.ErrInconsistentState
	}
	return nil
}

var _ Repository = (*MySQLRepository)(nil)

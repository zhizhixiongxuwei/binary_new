package orphanreaper

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"binaryscan/internal/audit"
)

type MySQLRepository struct {
	db *sql.DB
}

func NewMySQLRepository(db *sql.DB) *MySQLRepository {
	return &MySQLRepository{db: db}
}

func (r *MySQLRepository) ListBlobReferenceCandidates(
	ctx context.Context,
	afterID uint64,
	limit int,
) ([]BlobReferenceCandidate, error) {
	if r == nil || r.db == nil || limit < 1 || limit > MaxSweepBatch {
		return nil, errors.New("invalid blob reference reconciliation query")
	}
	rows, err := r.db.QueryContext(ctx, `
SELECT id
FROM blobs
WHERE id > ? AND state <> 'deleted'
ORDER BY id
LIMIT ?`, afterID, limit)
	if err != nil {
		return nil, fmt.Errorf("query blob reference reconciliation candidates: %w", err)
	}
	defer rows.Close()
	result := make([]BlobReferenceCandidate, 0, limit)
	for rows.Next() {
		var candidate BlobReferenceCandidate
		if err := rows.Scan(&candidate.ID); err != nil {
			return nil, fmt.Errorf("scan blob reference reconciliation candidate: %w", err)
		}
		if candidate.ID == 0 {
			return nil, errors.New("blob reference reconciliation candidate is invalid")
		}
		result = append(result, candidate)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate blob reference reconciliation candidates: %w", err)
	}
	return result, nil
}

func (r *MySQLRepository) ReconcileBlobReference(
	ctx context.Context,
	candidate BlobReferenceCandidate,
	staleBefore time.Time,
	dryRun bool,
) (BlobReferenceResult, error) {
	if r == nil || r.db == nil || candidate.ID == 0 || staleBefore.IsZero() {
		return BlobReferenceResult{}, errors.New("invalid blob reference reconciliation")
	}
	tx, err := r.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return BlobReferenceResult{}, fmt.Errorf("begin blob reference reconciliation: %w", err)
	}
	defer tx.Rollback()

	var result BlobReferenceResult
	var createdAt time.Time
	err = tx.QueryRowContext(ctx, `
SELECT reference_count, state, created_at
FROM blobs
WHERE id = ? AND state <> 'deleted'
FOR UPDATE`, candidate.ID).Scan(
		&result.PreviousCount, &result.PreviousState, &createdAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		if err := tx.Commit(); err != nil {
			return BlobReferenceResult{}, fmt.Errorf(
				"commit skipped blob reference reconciliation: %w", err,
			)
		}
		return result, nil
	}
	if err != nil {
		return BlobReferenceResult{}, fmt.Errorf("lock blob reference count: %w", err)
	}
	if err := tx.QueryRowContext(ctx, `
SELECT
    (SELECT COUNT(*) FROM uploads WHERE blob_id = ?) +
    (SELECT COUNT(*) FROM tasks
     WHERE blob_id = ? AND sample_deleted_at IS NULL AND deleted_at IS NULL) +
    (SELECT COUNT(*) FROM file_node_blob_refs WHERE blob_id = ?)`,
		candidate.ID, candidate.ID, candidate.ID,
	).Scan(&result.ActualCount); err != nil {
		return BlobReferenceResult{}, fmt.Errorf("calculate blob reference count: %w", err)
	}
	result.CurrentState = result.PreviousState
	switch {
	case result.ActualCount > 0 && result.PreviousState == "deleting":
		result.CurrentState = "available"
	case result.ActualCount == 0 && result.PreviousState == "available":
		result.CurrentState = "deleting"
	case result.ActualCount == 0 && result.PreviousState == "staging" &&
		!createdAt.After(staleBefore):
		result.CurrentState = "deleting"
	}
	result.Drifted = result.PreviousCount != result.ActualCount ||
		result.PreviousState != result.CurrentState
	if !result.Drifted || dryRun {
		if err := tx.Commit(); err != nil {
			return BlobReferenceResult{}, fmt.Errorf(
				"commit inspected blob reference reconciliation: %w", err,
			)
		}
		return result, nil
	}

	update, err := tx.ExecContext(ctx, `
UPDATE blobs
SET reference_count = ?,
    state = ?,
    deleted_at = CASE WHEN ? = 'available' THEN NULL ELSE deleted_at END
WHERE id = ? AND state = ? AND reference_count = ?`,
		result.ActualCount, result.CurrentState, result.CurrentState,
		candidate.ID, result.PreviousState, result.PreviousCount,
	)
	if err != nil {
		return BlobReferenceResult{}, fmt.Errorf("correct blob reference count: %w", err)
	}
	affected, err := update.RowsAffected()
	if err != nil {
		return BlobReferenceResult{}, fmt.Errorf("inspect blob reference correction: %w", err)
	}
	if affected != 1 {
		return BlobReferenceResult{}, errors.New("blob reference correction lost its fence")
	}
	if err := audit.Append(ctx, tx, audit.Event{
		Action: "maintenance.blob_reference_reconciled", ObjectType: "blob",
		ObjectID: fmt.Sprintf("%d", candidate.ID), Outcome: audit.OutcomeSuccess,
		Metadata: map[string]any{
			"previous_count": result.PreviousCount,
			"actual_count":   result.ActualCount,
			"previous_state": result.PreviousState,
			"current_state":  result.CurrentState,
		},
	}); err != nil {
		return BlobReferenceResult{}, fmt.Errorf("audit blob reference correction: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return BlobReferenceResult{}, fmt.Errorf("commit blob reference correction: %w", err)
	}
	result.Corrected = true
	return result, nil
}

func (r *MySQLRepository) BlobReferenced(
	ctx context.Context,
	candidate BlobCandidate,
) (bool, error) {
	if r == nil || r.db == nil || !validBlobCandidate(candidate) {
		return false, errors.New("invalid blob orphan reference query")
	}
	var referenced bool
	if err := r.db.QueryRowContext(ctx, `
SELECT EXISTS (
    SELECT 1
    FROM blobs
    WHERE sha256 = ? OR storage_key = ?
)`, candidate.SHA256, candidate.StorageKey).Scan(&referenced); err != nil {
		return false, fmt.Errorf("query blob orphan reference: %w", err)
	}
	return referenced, nil
}

func (r *MySQLRepository) UploadReferenced(
	ctx context.Context,
	candidate UploadCandidate,
) (bool, error) {
	if r == nil || r.db == nil || !canonicalUUID.MatchString(candidate.ID) {
		return false, errors.New("invalid upload orphan reference query")
	}
	var referenced bool
	if err := r.db.QueryRowContext(ctx, `
SELECT EXISTS (
    SELECT 1
    FROM uploads
    WHERE id = ?
)`, candidate.ID).Scan(&referenced); err != nil {
		return false, fmt.Errorf("query upload orphan reference: %w", err)
	}
	return referenced, nil
}

func (r *MySQLRepository) StoredFileReferenced(
	ctx context.Context,
	candidate StoredFileCandidate,
) (bool, error) {
	if r == nil || r.db == nil || !validStoredFileCandidate(candidate) {
		return false, errors.New("invalid stored-file orphan reference query")
	}
	query, err := storedFileReferenceQuery(candidate.Kind, false)
	if err != nil {
		return false, err
	}
	var referenced bool
	if err := r.db.QueryRowContext(ctx, query, candidate.StorageKey).Scan(
		&referenced,
	); err != nil {
		return false, fmt.Errorf("query stored-file orphan reference: %w", err)
	}
	return referenced, nil
}

func (r *MySQLRepository) DeleteOrphanBlob(
	ctx context.Context,
	candidate BlobCandidate,
	deleteFile func(context.Context) error,
) (bool, error) {
	if r == nil || r.db == nil || !validBlobCandidate(candidate) || deleteFile == nil {
		return false, errors.New("invalid blob orphan deletion")
	}
	tx, err := r.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
	if err != nil {
		return false, fmt.Errorf("begin blob orphan deletion: %w", err)
	}
	defer tx.Rollback()

	var id uint64
	err = tx.QueryRowContext(ctx, `
SELECT id
FROM blobs FORCE INDEX (uq_blobs_sha256)
WHERE sha256 = ?
LIMIT 1
FOR UPDATE`, candidate.SHA256).Scan(&id)
	if err == nil {
		return false, commitProtected(tx, "blob orphan deletion")
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return false, fmt.Errorf("lock blob orphan reference: %w", err)
	}
	// The missing unique-key locking read holds the SHA-256 index gap until
	// commit, fencing the upload path that creates or reuses the blob record.
	var storageReference bool
	if err := tx.QueryRowContext(ctx, `
SELECT EXISTS (
    SELECT 1
    FROM blobs
    WHERE storage_key = ?
)`, candidate.StorageKey).Scan(&storageReference); err != nil {
		return false, fmt.Errorf("recheck blob orphan storage key: %w", err)
	}
	if storageReference {
		return false, commitProtected(tx, "blob orphan storage-key protection")
	}
	if err := deleteFile(ctx); err != nil {
		return false, fmt.Errorf("delete orphan blob file: %w", err)
	}
	if err := audit.Append(ctx, tx, audit.Event{
		Action: "maintenance.orphan_blob_removed", ObjectType: "blob",
		ObjectID: candidate.SHA256, Outcome: audit.OutcomeSuccess,
		Metadata: map[string]any{
			"reason":     "filesystem_object_without_database_record",
			"size_bytes": candidate.SizeBytes,
		},
	}); err != nil {
		return false, fmt.Errorf("audit orphan blob deletion: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return false, fmt.Errorf("commit blob orphan deletion: %w", err)
	}
	return true, nil
}

func (r *MySQLRepository) DeleteOrphanUpload(
	ctx context.Context,
	candidate UploadCandidate,
	deleteDirectory func(context.Context) error,
) (bool, error) {
	if r == nil || r.db == nil || !canonicalUUID.MatchString(candidate.ID) ||
		deleteDirectory == nil {
		return false, errors.New("invalid upload orphan deletion")
	}
	tx, err := r.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
	if err != nil {
		return false, fmt.Errorf("begin upload orphan deletion: %w", err)
	}
	defer tx.Rollback()

	var id string
	err = tx.QueryRowContext(ctx, `
SELECT id
FROM uploads
WHERE id = ?
LIMIT 1
FOR UPDATE`, candidate.ID).Scan(&id)
	if err == nil {
		return false, commitProtected(tx, "upload orphan deletion")
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return false, fmt.Errorf("lock upload orphan reference: %w", err)
	}
	// The absent primary-key locking read prevents the same UUID from being
	// inserted while its stale staging directory is being removed.
	if err := deleteDirectory(ctx); err != nil {
		return false, fmt.Errorf("delete orphan upload directory: %w", err)
	}
	if err := audit.Append(ctx, tx, audit.Event{
		Action: "maintenance.orphan_upload_removed", ObjectType: "upload",
		ObjectID: candidate.ID, Outcome: audit.OutcomeSuccess,
		Metadata: map[string]any{
			"reason": "staging_directory_without_database_record",
		},
	}); err != nil {
		return false, fmt.Errorf("audit orphan upload deletion: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return false, fmt.Errorf("commit upload orphan deletion: %w", err)
	}
	return true, nil
}

func (r *MySQLRepository) DeleteOrphanStoredFile(
	ctx context.Context,
	candidate StoredFileCandidate,
	deleteFile func(context.Context) error,
) (bool, error) {
	if r == nil || r.db == nil || !validStoredFileCandidate(candidate) ||
		deleteFile == nil {
		return false, errors.New("invalid stored-file orphan deletion")
	}
	tx, err := r.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
	if err != nil {
		return false, fmt.Errorf("begin stored-file orphan deletion: %w", err)
	}
	defer tx.Rollback()
	query, err := storedFileReferenceQuery(candidate.Kind, true)
	if err != nil {
		return false, err
	}
	var id string
	err = tx.QueryRowContext(ctx, query, candidate.StorageKey).Scan(&id)
	if err == nil {
		return false, commitProtected(tx, "stored-file orphan deletion")
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return false, fmt.Errorf("lock stored-file orphan reference: %w", err)
	}
	if err := deleteFile(ctx); err != nil {
		return false, fmt.Errorf("delete stored-file orphan: %w", err)
	}
	if err := audit.Append(ctx, tx, audit.Event{
		Action: "maintenance.orphan_stored_file_removed", ObjectType: string(candidate.Kind),
		ObjectID: candidate.SHA256, Outcome: audit.OutcomeSuccess,
		Metadata: map[string]any{
			"reason":     "filesystem_object_without_active_database_record",
			"size_bytes": candidate.SizeBytes,
		},
	}); err != nil {
		return false, fmt.Errorf("audit stored-file orphan deletion: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return false, fmt.Errorf("commit stored-file orphan deletion: %w", err)
	}
	return true, nil
}

func storedFileReferenceQuery(kind StoredFileKind, locking bool) (string, error) {
	var query string
	switch kind {
	case StoredFileReport:
		query = `SELECT id
FROM reports FORCE INDEX (idx_reports_storage_key)
WHERE storage_key = ? AND deleted_at IS NULL
LIMIT 1`
	case StoredFileArtifact:
		query = `SELECT id
FROM artifacts FORCE INDEX (uq_artifacts_storage_key)
WHERE storage_key = ? AND deleted_at IS NULL
  AND state IN ('staged', 'published', 'deleting')
LIMIT 1`
	case StoredFileDecompile:
		query = `SELECT id
FROM decompile_results FORCE INDEX (idx_decompile_results_storage_key)
WHERE storage_key = ? AND deleted_at IS NULL
LIMIT 1`
	default:
		return "", errors.New("stored-file orphan kind is invalid")
	}
	if locking {
		query += "\nFOR UPDATE"
		return query, nil
	}
	return "SELECT EXISTS (\n" + query + "\n)", nil
}

func validBlobCandidate(candidate BlobCandidate) bool {
	if candidate.SizeBytes < 0 || !canonicalSHA256.MatchString(candidate.SHA256) {
		return false
	}
	expected := "blobs/sha256/" + candidate.SHA256[:2] + "/" + candidate.SHA256
	return candidate.StorageKey == expected
}

func commitProtected(tx *sql.Tx, operation string) error {
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit protected %s: %w", operation, err)
	}
	return nil
}

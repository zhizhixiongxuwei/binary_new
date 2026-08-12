package orphanreaper

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"path"
	"time"

	"binaryscan/internal/audit"
	"binaryscan/internal/blobfence"
)

type MySQLRepository struct {
	db *sql.DB
}

const blobDurableProtectionPredicate = `(
    b.state <> 'deleted'
    OR EXISTS (
        SELECT 1 FROM uploads WHERE blob_id = b.id
    )
    OR EXISTS (
        SELECT 1 FROM tasks
        WHERE blob_id = b.id
          AND sample_deleted_at IS NULL
          AND deleted_at IS NULL
    )
    OR EXISTS (
        SELECT 1 FROM file_node_blob_refs WHERE blob_id = b.id
    )
    OR EXISTS (
        SELECT 1 FROM archive_imports
        WHERE source_blob_id = b.id
          AND source_blob_reference_released_at IS NULL
    )
    OR EXISTS (
        SELECT 1 FROM archive_import_entries
        WHERE blob_id = b.id
          AND blob_reference_released_at IS NULL
    )
)`

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
    (SELECT COUNT(*) FROM file_node_blob_refs WHERE blob_id = ?) +
    (SELECT COUNT(*) FROM archive_imports
     WHERE source_blob_id = ?
       AND source_blob_reference_released_at IS NULL) +
    (SELECT COUNT(*) FROM archive_import_entries
     WHERE blob_id = ? AND blob_reference_released_at IS NULL)`,
		candidate.ID, candidate.ID, candidate.ID, candidate.ID, candidate.ID,
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
    FROM blobs b
    WHERE (b.sha256 = ? OR b.storage_key = ?)
      AND `+blobDurableProtectionPredicate+`
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

func (r *MySQLRepository) ListPendingSourceProjects(
	ctx context.Context,
	limit int,
) ([]PendingSourceProject, error) {
	if r == nil || r.db == nil || limit < 1 || limit > MaxSweepBatch {
		return nil, errors.New("invalid pending source project query")
	}
	rows, err := r.db.QueryContext(ctx, `
SELECT id, task_id, layout_version
FROM decompile_source_projects project
WHERE project.deleted_at IS NOT NULL
  AND project.storage_deleted_at IS NULL
  AND NOT EXISTS (
      SELECT 1
      FROM source_project_deletion_operations operation
      WHERE operation.active_project_id = project.id
  )
ORDER BY project.deleted_at, project.id
LIMIT ?`, limit)
	if err != nil {
		return nil, fmt.Errorf("query pending source project cleanup: %w", err)
	}
	defer rows.Close()
	projects := make([]PendingSourceProject, 0, limit)
	for rows.Next() {
		var candidate PendingSourceProject
		if err := rows.Scan(
			&candidate.ID, &candidate.TaskID, &candidate.LayoutVersion,
		); err != nil {
			return nil, fmt.Errorf("scan pending source project cleanup: %w", err)
		}
		if !validPendingSourceProject(candidate) || len(projects) >= limit {
			return nil, errors.New("pending source project cleanup is invalid")
		}
		projects = append(projects, candidate)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate pending source project cleanup: %w", err)
	}
	return projects, nil
}

func (r *MySQLRepository) SourceProjectReferenced(
	ctx context.Context,
	candidate SourceProjectCandidate,
) (bool, error) {
	if r == nil || r.db == nil || !validSourceProjectCandidate(candidate) {
		return false, errors.New("invalid source project reference query")
	}
	var referenced bool
	if err := r.db.QueryRowContext(ctx, `
SELECT EXISTS (
    SELECT 1
    FROM decompile_source_projects project
    WHERE project.id = ?
      AND project.layout_version = 'project-v1'
      AND project.root_storage_key = ?
      AND (
          project.deleted_at IS NULL OR
          EXISTS (
              SELECT 1
              FROM source_project_deletion_operations operation
              WHERE operation.active_project_id = project.id
          )
      )
)`, candidate.ID, candidate.StorageKey).Scan(&referenced); err != nil {
		return false, fmt.Errorf("query source project reference: %w", err)
	}
	return referenced, nil
}

func (r *MySQLRepository) CleanupPendingSourceProject(
	ctx context.Context,
	candidate PendingSourceProject,
	deleteProject func(context.Context, SourceProjectCleanupTarget) error,
) (bool, error) {
	if r == nil || r.db == nil || !validPendingSourceProject(candidate) ||
		deleteProject == nil {
		return false, errors.New("invalid pending source project cleanup")
	}
	tx, err := r.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
	if err != nil {
		return false, fmt.Errorf("begin pending source project cleanup: %w", err)
	}
	defer tx.Rollback()

	var layoutVersion string
	var rootStorageKey sql.NullString
	var activeDeletion bool
	err = tx.QueryRowContext(ctx, `
SELECT project.layout_version, project.root_storage_key,
       EXISTS (
           SELECT 1
           FROM source_project_deletion_operations operation
           WHERE operation.active_project_id = project.id
       )
FROM decompile_source_projects project
WHERE project.task_id = ? AND project.id = ?
  AND project.deleted_at IS NOT NULL
  AND project.storage_deleted_at IS NULL
LIMIT 1
FOR UPDATE`, candidate.TaskID, candidate.ID).Scan(
		&layoutVersion, &rootStorageKey, &activeDeletion,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return false, commitProtected(tx, "pending source project cleanup")
	}
	if err != nil {
		return false, fmt.Errorf("lock pending source project cleanup: %w", err)
	}
	if activeDeletion {
		return false, commitProtected(tx, "active source project deletion cleanup")
	}
	if layoutVersion != candidate.LayoutVersion {
		return false, errors.New("pending source project layout changed")
	}
	target := SourceProjectCleanupTarget{
		ProjectID: candidate.ID, TaskID: candidate.TaskID,
		LayoutVersion: layoutVersion,
	}
	switch layoutVersion {
	case "project-v1":
		if !rootStorageKey.Valid ||
			rootStorageKey.String != path.Join("source-projects", candidate.ID) {
			return false, errors.New("pending source project root is invalid")
		}
	case "legacy-v1":
		if rootStorageKey.Valid {
			return false, errors.New("legacy source project owns an unexpected root")
		}
		rows, err := tx.QueryContext(ctx, `
SELECT id
FROM decompile_results
WHERE task_id = ? AND analyzer_run_id = ?
ORDER BY id
LIMIT ?
FOR UPDATE`, candidate.TaskID, candidate.ID, maxDirectoryEntries+1)
		if err != nil {
			return false, fmt.Errorf("list pending legacy source files: %w", err)
		}
		for rows.Next() {
			var resultID string
			if err := rows.Scan(&resultID); err != nil {
				_ = rows.Close()
				return false, fmt.Errorf("scan pending legacy source file: %w", err)
			}
			if !canonicalObjectID.MatchString(resultID) {
				_ = rows.Close()
				return false, errors.New("pending legacy source result ID is invalid")
			}
			target.LegacyResultIDs = append(target.LegacyResultIDs, resultID)
			if len(target.LegacyResultIDs) > maxDirectoryEntries {
				_ = rows.Close()
				return false, errors.New(
					"pending legacy source project exceeds the entry limit",
				)
			}
		}
		if err := rows.Close(); err != nil {
			return false, fmt.Errorf("close pending legacy source files: %w", err)
		}
		if err := rows.Err(); err != nil {
			return false, fmt.Errorf("iterate pending legacy source files: %w", err)
		}
	default:
		return false, errors.New("pending source project layout is invalid")
	}
	if err := deleteProject(ctx, target); err != nil {
		return false, fmt.Errorf("delete pending source project files: %w", err)
	}
	if err := completeDeletedSourceProject(ctx, tx, candidate.TaskID, candidate.ID); err != nil {
		return false, err
	}
	if err := audit.Append(ctx, tx, audit.Event{
		Action:     "maintenance.deleted_source_project_cleaned",
		ObjectType: "decompile_source_project", ObjectID: candidate.ID,
		Outcome: audit.OutcomeSuccess,
		Metadata: map[string]any{
			"task_id": candidate.TaskID, "layout_version": layoutVersion,
		},
	}); err != nil {
		return false, fmt.Errorf("audit pending source project cleanup: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return false, fmt.Errorf("commit pending source project cleanup: %w", err)
	}
	return true, nil
}

func (r *MySQLRepository) DeleteOrphanSourceProject(
	ctx context.Context,
	candidate SourceProjectCandidate,
	deleteDirectory func(context.Context) error,
) (bool, error) {
	if r == nil || r.db == nil || !validSourceProjectCandidate(candidate) ||
		deleteDirectory == nil {
		return false, errors.New("invalid source project orphan deletion")
	}
	tx, err := r.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
	if err != nil {
		return false, fmt.Errorf("begin source project orphan deletion: %w", err)
	}
	defer tx.Rollback()
	var taskID, layoutVersion string
	var rootStorageKey sql.NullString
	var deletedAt, storageDeletedAt sql.NullTime
	var activeDeletion bool
	err = tx.QueryRowContext(ctx, `
SELECT project.task_id, project.layout_version, project.root_storage_key,
       project.deleted_at, project.storage_deleted_at,
       EXISTS (
           SELECT 1
           FROM source_project_deletion_operations operation
           WHERE operation.active_project_id = project.id
       )
FROM decompile_source_projects project
WHERE project.id = ?
LIMIT 1
FOR UPDATE`, candidate.ID).Scan(
		&taskID, &layoutVersion, &rootStorageKey, &deletedAt, &storageDeletedAt,
		&activeDeletion,
	)
	if err == nil && activeDeletion {
		return false, commitProtected(tx, "active source project deletion operation")
	}
	if err == nil && layoutVersion == "project-v1" && !deletedAt.Valid {
		if !rootStorageKey.Valid || rootStorageKey.String != candidate.StorageKey {
			return false, errors.New("active source project root is inconsistent")
		}
		return false, commitProtected(tx, "source project orphan deletion")
	}
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return false, fmt.Errorf("lock source project orphan reference: %w", err)
	}
	if err == nil && layoutVersion == "project-v1" && deletedAt.Valid &&
		!storageDeletedAt.Valid {
		if !rootStorageKey.Valid || rootStorageKey.String != candidate.StorageKey {
			return false, errors.New("deleted source project root is inconsistent")
		}
		if err := deleteDirectory(ctx); err != nil {
			return false, fmt.Errorf("delete pending source project directory: %w", err)
		}
		if err := completeDeletedSourceProject(ctx, tx, taskID, candidate.ID); err != nil {
			return false, err
		}
		if err := audit.Append(ctx, tx, audit.Event{
			Action:     "maintenance.deleted_source_project_cleaned",
			ObjectType: "decompile_source_project", ObjectID: candidate.ID,
			Outcome: audit.OutcomeSuccess,
			Metadata: map[string]any{
				"task_id": taskID, "layout_version": layoutVersion,
			},
		}); err != nil {
			return false, fmt.Errorf("audit deleted source project cleanup: %w", err)
		}
		if err := tx.Commit(); err != nil {
			return false, fmt.Errorf("commit deleted source project cleanup: %w", err)
		}
		return true, nil
	}
	if err := deleteDirectory(ctx); err != nil {
		return false, fmt.Errorf("delete orphan source project directory: %w", err)
	}
	if err := audit.Append(ctx, tx, audit.Event{
		Action:     "maintenance.orphan_source_project_removed",
		ObjectType: "decompile_source_project", ObjectID: candidate.ID,
		Outcome: audit.OutcomeSuccess,
		Metadata: map[string]any{
			"reason": "source_project_directory_without_active_database_record",
		},
	}); err != nil {
		return false, fmt.Errorf("audit orphan source project deletion: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return false, fmt.Errorf("commit source project orphan deletion: %w", err)
	}
	return true, nil
}

func completeDeletedSourceProject(
	ctx context.Context,
	tx *sql.Tx,
	taskID string,
	projectID string,
) error {
	if _, err := tx.ExecContext(ctx, `
UPDATE decompile_results
SET storage_key = NULL,
    content_sha256 = NULL,
    size_bytes = NULL,
    source_offset_bytes = NULL,
    source_length_bytes = NULL,
    source_start_line = NULL,
    source_end_line = NULL,
    deleted_at = COALESCE(deleted_at, UTC_TIMESTAMP(6))
WHERE task_id = ? AND analyzer_run_id = ?`, taskID, projectID); err != nil {
		return fmt.Errorf("clear deleted source project results: %w", err)
	}
	result, err := tx.ExecContext(ctx, `
UPDATE decompile_source_projects
SET root_storage_key = NULL,
    canonical_storage_key = NULL,
    canonical_sha256 = NULL,
    canonical_size_bytes = NULL,
    manifest_storage_key = NULL,
    manifest_sha256 = NULL,
    manifest_size_bytes = NULL,
    storage_deleted_at = UTC_TIMESTAMP(6)
WHERE task_id = ? AND id = ?
  AND deleted_at IS NOT NULL AND storage_deleted_at IS NULL`, taskID, projectID)
	if err != nil {
		return fmt.Errorf("complete deleted source project storage cleanup: %w", err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("inspect deleted source project cleanup: %w", err)
	}
	if affected != 1 {
		return errors.New("deleted source project cleanup lost its fence")
	}
	return nil
}

func (r *MySQLRepository) StoredFileReferenced(
	ctx context.Context,
	candidate StoredFileCandidate,
) (bool, error) {
	if r == nil || r.db == nil || !validStoredFileCandidate(candidate) {
		return false, errors.New("invalid stored-file orphan reference query")
	}
	query, arguments, err := storedFileReferenceQuery(candidate, false)
	if err != nil {
		return false, err
	}
	var referenced bool
	if err := r.db.QueryRowContext(ctx, query, arguments...).Scan(
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
	var removed bool
	err := blobfence.With(ctx, r.db, candidate.SHA256, func() error {
		var deleteErr error
		removed, deleteErr = r.deleteOrphanBlob(ctx, candidate, deleteFile)
		return deleteErr
	})
	if err != nil {
		return false, fmt.Errorf("fence blob orphan deletion: %w", err)
	}
	return removed, nil
}

func (r *MySQLRepository) deleteOrphanBlob(
	ctx context.Context,
	candidate BlobCandidate,
	deleteFile func(context.Context) error,
) (bool, error) {
	tx, err := r.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
	if err != nil {
		return false, fmt.Errorf("begin blob orphan deletion: %w", err)
	}
	defer tx.Rollback()

	var (
		id    uint64
		state string
	)
	err = tx.QueryRowContext(ctx, `
SELECT stored_blob.id, stored_blob.state
FROM blobs stored_blob FORCE INDEX (uq_blobs_sha256)
WHERE stored_blob.sha256 = ?
LIMIT 1
FOR UPDATE`, candidate.SHA256).Scan(&id, &state)
	if err == nil {
		if state != "deleted" {
			return false, commitProtected(tx, "blob orphan deletion")
		}
		owned, ownerErr := blobHasActiveOwner(ctx, tx, id)
		if ownerErr != nil {
			return false, ownerErr
		}
		if owned {
			return false, commitProtected(tx, "blob orphan owner protection")
		}
	}
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return false, fmt.Errorf("lock blob orphan reference: %w", err)
	}
	// A missing-row gap lock fences creation of this SHA. A deleted-row lock
	// fences reactivation while its newly appeared, unowned file is removed.
	var storageReference bool
	if err := tx.QueryRowContext(ctx, `
SELECT EXISTS (
    SELECT 1
    FROM blobs b
    WHERE b.storage_key = ?
      AND `+blobDurableProtectionPredicate+`
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
			"reason":     "filesystem_object_without_durable_reference",
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

func blobHasActiveOwner(
	ctx context.Context,
	query interface {
		QueryRowContext(context.Context, string, ...any) *sql.Row
	},
	blobID uint64,
) (bool, error) {
	var upload, task, fileNode, archiveSource, archiveEntry bool
	if err := query.QueryRowContext(ctx, `
SELECT
    EXISTS (SELECT 1 FROM uploads WHERE blob_id = ?),
    EXISTS (
        SELECT 1 FROM tasks
        WHERE blob_id = ?
          AND sample_deleted_at IS NULL
          AND deleted_at IS NULL
    ),
    EXISTS (SELECT 1 FROM file_node_blob_refs WHERE blob_id = ?),
    EXISTS (
        SELECT 1 FROM archive_imports
        WHERE source_blob_id = ?
          AND source_blob_reference_released_at IS NULL
    ),
    EXISTS (
        SELECT 1 FROM archive_import_entries
        WHERE blob_id = ?
          AND blob_reference_released_at IS NULL
    )`, blobID, blobID, blobID, blobID, blobID).Scan(
		&upload, &task, &fileNode, &archiveSource, &archiveEntry,
	); err != nil {
		return false, fmt.Errorf("recheck blob orphan owners: %w", err)
	}
	return upload || task || fileNode || archiveSource || archiveEntry, nil
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
	query, arguments, err := storedFileReferenceQuery(candidate, true)
	if err != nil {
		return false, err
	}
	var id string
	err = tx.QueryRowContext(ctx, query, arguments...).Scan(&id)
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

func storedFileReferenceQuery(
	candidate StoredFileCandidate,
	locking bool,
) (string, []any, error) {
	var query string
	arguments := []any{candidate.StorageKey}
	switch candidate.Kind {
	case StoredFileReport:
		query = `SELECT id
	FROM reports FORCE INDEX (idx_reports_storage_key)
	WHERE storage_key = ? AND deleted_at IS NULL
	LIMIT 1`
	case StoredFileReportStaging:
		taskID, reportID, valid := reportStagingIdentity(candidate.StorageKey)
		if !valid {
			return "", nil, errors.New("report staging orphan path is invalid")
		}
		query = `SELECT id
	FROM reports
	WHERE task_id = ? AND id = ? AND deleted_at IS NULL
	  AND snapshot_state = 'staged'
	  AND status IN ('queued', 'generating')
	LIMIT 1`
		arguments = []any{taskID, reportID}
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
		return "", nil, errors.New("stored-file orphan kind is invalid")
	}
	if locking {
		query += "\nFOR UPDATE"
		return query, arguments, nil
	}
	return "SELECT EXISTS (\n" + query + "\n)", arguments, nil
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

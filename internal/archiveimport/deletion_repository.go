package archiveimport

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"binaryscan/internal/auth"
)

type InactiveParentImport struct {
	UploadID string
	Owner    uint64
}

func (r *MySQLRepository) PrepareDeleteForUpload(
	ctx context.Context,
	uploadID string,
	actor auth.Principal,
) (DeletionPlan, error) {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return DeletionPlan{}, fmt.Errorf("begin archive import deletion: %w", err)
	}
	defer tx.Rollback()
	archive, found, err := findImportByUpload(ctx, tx, uploadID, true)
	if err != nil {
		return DeletionPlan{}, err
	}
	if !found {
		if err := tx.Commit(); err != nil {
			return DeletionPlan{}, fmt.Errorf("commit absent archive import deletion: %w", err)
		}
		return DeletionPlan{AlreadyDeleted: true}, nil
	}
	if actor.UserID == 0 || (actor.Role != auth.RoleAdministrator &&
		actor.Role != auth.RoleOperator) {
		return DeletionPlan{}, ErrForbidden
	}
	if actor.Role != auth.RoleAdministrator && actor.UserID != archive.CreatedBy {
		return DeletionPlan{}, ErrNotFound
	}
	if archive.Status == StatusDeleted {
		if err := tx.Commit(); err != nil {
			return DeletionPlan{}, fmt.Errorf("commit deleted archive import replay: %w", err)
		}
		return DeletionPlan{ImportID: archive.ID, AlreadyDeleted: true}, nil
	}
	if archive.Status == StatusRunning {
		return DeletionPlan{}, ErrConflict
	}
	var activeBatches int
	err = tx.QueryRowContext(ctx, `
SELECT COUNT(*)
FROM archive_import_task_batches
WHERE archive_import_id = ? AND status = 'processing'`, archive.ID).Scan(&activeBatches)
	if err != nil {
		return DeletionPlan{}, fmt.Errorf("check active archive batches for deletion: %w", err)
	}
	if activeBatches != 0 {
		return DeletionPlan{}, ErrConflict
	}
	if archive.Status != StatusDeleting {
		result, err := tx.ExecContext(ctx, `
UPDATE archive_imports
SET status = 'deleting', lease_owner = NULL, lease_until = NULL,
    heartbeat_at = NULL, updated_at = UTC_TIMESTAMP(6)
WHERE id = ? AND status IN ('queued', 'ready', 'failed')`, archive.ID)
		if err != nil {
			return DeletionPlan{}, fmt.Errorf("tombstone archive import: %w", err)
		}
		if err := requireOneRow(result, ErrConflict); err != nil {
			return DeletionPlan{}, err
		}
	}
	rows, err := tx.QueryContext(ctx, orphanDerivedUploadsSQL, archive.ID)
	if err != nil {
		return DeletionPlan{}, fmt.Errorf("list orphan derived uploads: %w", err)
	}
	derived := make([]DerivedUploadDeletion, 0)
	for rows.Next() {
		var value DerivedUploadDeletion
		if err := rows.Scan(&value.ID, &value.Owner); err != nil {
			rows.Close()
			return DeletionPlan{}, fmt.Errorf("scan orphan derived upload: %w", err)
		}
		derived = append(derived, value)
	}
	if err := rows.Close(); err != nil {
		return DeletionPlan{}, fmt.Errorf("close orphan derived uploads: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return DeletionPlan{}, fmt.Errorf("commit archive import tombstone: %w", err)
	}
	return DeletionPlan{ImportID: archive.ID, DerivedUploads: derived}, nil
}

func (r *MySQLRepository) LoadDeletingPlan(
	ctx context.Context,
	uploadID string,
) (DeletionPlan, error) {
	var importID string
	err := r.db.QueryRowContext(ctx, `
SELECT id FROM archive_imports
WHERE upload_id = ? AND status = 'deleting'`, uploadID).Scan(&importID)
	if errors.Is(err, sql.ErrNoRows) {
		return DeletionPlan{AlreadyDeleted: true}, nil
	}
	if err != nil {
		return DeletionPlan{}, fmt.Errorf("load deleting archive import: %w", err)
	}
	rows, err := r.db.QueryContext(ctx, orphanDerivedUploadsSQL, importID)
	if err != nil {
		return DeletionPlan{}, fmt.Errorf("load deleting derived uploads: %w", err)
	}
	defer rows.Close()
	plan := DeletionPlan{ImportID: importID}
	for rows.Next() {
		var value DerivedUploadDeletion
		if err := rows.Scan(&value.ID, &value.Owner); err != nil {
			return DeletionPlan{}, fmt.Errorf("scan deleting derived upload: %w", err)
		}
		plan.DerivedUploads = append(plan.DerivedUploads, value)
	}
	if err := rows.Err(); err != nil {
		return DeletionPlan{}, fmt.Errorf("iterate deleting derived uploads: %w", err)
	}
	return plan, nil
}

func (r *MySQLRepository) FinalizeDeleteForUpload(
	ctx context.Context,
	uploadID string,
) ([]ReleasedBlob, error) {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin archive import delete finalization: %w", err)
	}
	defer tx.Rollback()
	archive, found, err := findImportByUpload(ctx, tx, uploadID, true)
	if err != nil {
		return nil, err
	}
	if !found || archive.Status == StatusDeleted {
		if err := tx.Commit(); err != nil {
			return nil, fmt.Errorf("commit archive delete replay: %w", err)
		}
		return nil, nil
	}
	if archive.Status != StatusDeleting {
		return nil, ErrConflict
	}
	var orphanDerived int
	err = tx.QueryRowContext(ctx, `
SELECT COUNT(DISTINCT derived.id)
FROM archive_imports archive_import
JOIN upload_intake_profiles profile
  ON profile.source_parent_upload_id = archive_import.upload_id
 AND profile.source_kind = 'archive_entry'
JOIN uploads derived ON derived.id = profile.upload_id
LEFT JOIN archive_import_entries entry
  ON entry.archive_import_id = archive_import.id
 AND entry.logical_path = profile.source_entry_path
LEFT JOIN tasks task ON task.upload_id = derived.id
WHERE archive_import.id = ?
  AND task.id IS NULL
  AND (entry.id IS NULL OR entry.status <> 'created')
  AND NOT (
      derived.status = 'cancelled' OR
      (derived.status = 'expired' AND derived.blob_id IS NULL)
  )`, archive.ID).Scan(&orphanDerived)
	if err != nil {
		return nil, fmt.Errorf("verify orphan derived upload cleanup: %w", err)
	}
	if orphanDerived != 0 {
		return nil, ErrConflict
	}
	released, err := releaseEntryBlobs(ctx, tx, archive.ID)
	if err != nil {
		return nil, err
	}
	if source, deleting, err := releaseImportSource(ctx, tx, archive.ID); err != nil {
		return nil, err
	} else if deleting {
		released = append(released, source)
	}
	if _, err := tx.ExecContext(ctx, `
DELETE FROM archive_import_task_batches WHERE archive_import_id = ?`, archive.ID); err != nil {
		return nil, fmt.Errorf("delete archive import task batches: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `
DELETE FROM archive_import_entries WHERE archive_import_id = ?`, archive.ID); err != nil {
		return nil, fmt.Errorf("delete archive import entries: %w", err)
	}
	result, err := tx.ExecContext(ctx, `
UPDATE archive_imports
SET status = 'deleted', deleted_at = UTC_TIMESTAMP(6),
    completed_at = COALESCE(completed_at, UTC_TIMESTAMP(6)),
    error_code = NULL, error_message = NULL, updated_at = UTC_TIMESTAMP(6)
WHERE id = ? AND status = 'deleting'`, archive.ID)
	if err != nil {
		return nil, fmt.Errorf("finalize archive import deletion: %w", err)
	}
	if err := requireOneRow(result, ErrConflict); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit archive import deletion: %w", err)
	}
	return released, nil
}

// Provenance, rather than entry.derived_upload_id alone, is authoritative.
// This catches a derived upload committed immediately before its entry link.
// Created entries are permanent no-replay markers and their descendants are
// deliberately independent of parent deletion, even after task retention.
const orphanDerivedUploadsSQL = `
SELECT DISTINCT derived.id, derived.created_by
FROM archive_imports archive_import
JOIN upload_intake_profiles profile
  ON profile.source_parent_upload_id = archive_import.upload_id
 AND profile.source_kind = 'archive_entry'
JOIN uploads derived ON derived.id = profile.upload_id
LEFT JOIN archive_import_entries entry
  ON entry.archive_import_id = archive_import.id
 AND entry.logical_path = profile.source_entry_path
LEFT JOIN tasks task ON task.upload_id = derived.id
WHERE archive_import.id = ?
  AND task.id IS NULL
  AND (entry.id IS NULL OR entry.status <> 'created')
  AND NOT (
      derived.status = 'cancelled' OR
      (derived.status = 'expired' AND derived.blob_id IS NULL)
  )
ORDER BY derived.id ASC`

func (r *MySQLRepository) RecoverDeleting(
	ctx context.Context,
	staleAfter time.Duration,
	limit int,
) ([]string, error) {
	rows, err := r.db.QueryContext(ctx, `
SELECT id, upload_id
FROM archive_imports
WHERE status = 'deleting'
  AND updated_at <= TIMESTAMPADD(MICROSECOND, ?, UTC_TIMESTAMP(6))
ORDER BY updated_at ASC, id ASC
LIMIT ?`, -staleAfter.Microseconds(), limit)
	if err != nil {
		return nil, fmt.Errorf("list deleting archive imports: %w", err)
	}
	type candidate struct {
		id       string
		uploadID string
	}
	candidates := make([]candidate, 0)
	for rows.Next() {
		var value candidate
		if err := rows.Scan(&value.id, &value.uploadID); err != nil {
			rows.Close()
			return nil, fmt.Errorf("scan deleting archive upload: %w", err)
		}
		candidates = append(candidates, value)
	}
	if err := rows.Close(); err != nil {
		return nil, fmt.Errorf("iterate deleting archive imports: %w", err)
	}
	ids := make([]string, 0, len(candidates))
	for _, value := range candidates {
		result, err := r.db.ExecContext(ctx, `
UPDATE archive_imports
SET updated_at = UTC_TIMESTAMP(6)
WHERE id = ? AND status = 'deleting'
  AND updated_at <= TIMESTAMPADD(MICROSECOND, ?, UTC_TIMESTAMP(6))`,
			value.id, -staleAfter.Microseconds())
		if err != nil {
			return nil, fmt.Errorf("reserve deleting archive recovery: %w", err)
		}
		affected, err := result.RowsAffected()
		if err != nil {
			return nil, fmt.Errorf("inspect deleting archive recovery reservation: %w", err)
		}
		if affected == 0 {
			continue
		}
		if affected != 1 {
			return nil, errors.New("multiple deleting archive imports reserved")
		}
		ids = append(ids, value.uploadID)
	}
	return ids, nil
}

func (r *MySQLRepository) ListInactiveParentImports(
	ctx context.Context,
	staleAfter time.Duration,
	limit int,
) ([]InactiveParentImport, error) {
	rows, err := r.db.QueryContext(ctx, `
SELECT archive_import.id, archive_import.upload_id, archive_import.created_by
FROM archive_imports archive_import
JOIN uploads parent ON parent.id = archive_import.upload_id
WHERE parent.status IN ('expired', 'cancelled')
  AND archive_import.status IN ('queued', 'ready', 'failed')
  AND archive_import.updated_at <= TIMESTAMPADD(MICROSECOND, ?, UTC_TIMESTAMP(6))
  AND NOT EXISTS (
      SELECT 1
      FROM archive_import_task_batches batch
      WHERE batch.archive_import_id = archive_import.id
        AND batch.status = 'processing'
  )
ORDER BY archive_import.updated_at ASC, archive_import.id ASC
LIMIT ?`, -staleAfter.Microseconds(), limit)
	if err != nil {
		return nil, fmt.Errorf("list archive imports with inactive parents: %w", err)
	}
	type candidate struct {
		id    string
		value InactiveParentImport
	}
	candidates := make([]candidate, 0)
	for rows.Next() {
		var candidate candidate
		if err := rows.Scan(
			&candidate.id, &candidate.value.UploadID, &candidate.value.Owner,
		); err != nil {
			rows.Close()
			return nil, fmt.Errorf("scan archive import with inactive parent: %w", err)
		}
		candidates = append(candidates, candidate)
	}
	if err := rows.Close(); err != nil {
		return nil, fmt.Errorf("iterate archive imports with inactive parents: %w", err)
	}
	values := make([]InactiveParentImport, 0)
	for _, candidate := range candidates {
		result, err := r.db.ExecContext(ctx, `
UPDATE archive_imports
SET updated_at = UTC_TIMESTAMP(6)
WHERE id = ? AND status IN ('queued', 'ready', 'failed')
  AND updated_at <= TIMESTAMPADD(MICROSECOND, ?, UTC_TIMESTAMP(6))`,
			candidate.id, -staleAfter.Microseconds())
		if err != nil {
			return nil, fmt.Errorf("reserve inactive archive parent recovery: %w", err)
		}
		affected, err := result.RowsAffected()
		if err != nil {
			return nil, fmt.Errorf("inspect inactive archive parent reservation: %w", err)
		}
		if affected == 0 {
			continue
		}
		if affected != 1 {
			return nil, errors.New("multiple inactive archive parents reserved")
		}
		values = append(values, candidate.value)
	}
	return values, nil
}

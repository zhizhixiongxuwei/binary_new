package archiveimport

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

type EntryFact struct {
	DerivedUploadID string
	TaskID          string
}

func (r *MySQLRepository) ReconcileEntryFact(
	ctx context.Context,
	entryID uint64,
) (EntryFact, error) {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return EntryFact{}, fmt.Errorf("begin archive entry fact reconciliation: %w", err)
	}
	defer tx.Rollback()
	var (
		importID, parentUploadID, archiveName, logicalPath, category, format, status string
		sourceOwner                                                                  uint64
		blobID                                                                       uint64
		size                                                                         int64
		sha                                                                          string
		releasedAt                                                                   sql.NullTime
		existingDerived, existingTask                                                sql.NullString
	)
	err = tx.QueryRowContext(ctx, `
SELECT entry.archive_import_id, archive_import.upload_id, parent.display_name,
	       archive_import.created_by, entry.logical_path,
	       entry.detected_category, entry.detected_format, entry.status,
	       entry.size_bytes, entry.sha256,
	       entry.blob_id, entry.blob_reference_released_at,
       entry.derived_upload_id, entry.task_id
FROM archive_import_entries entry
JOIN archive_imports archive_import ON archive_import.id = entry.archive_import_id
JOIN uploads parent ON parent.id = archive_import.upload_id
WHERE entry.id = ?
FOR UPDATE`, entryID).Scan(
		&importID, &parentUploadID, &archiveName, &sourceOwner,
		&logicalPath, &category, &format, &status, &size, &sha,
		&blobID, &releasedAt, &existingDerived, &existingTask,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return EntryFact{}, ErrNotFound
	}
	if err != nil {
		return EntryFact{}, fmt.Errorf("lock archive entry fact: %w", err)
	}
	rows, err := tx.QueryContext(ctx, `
SELECT derived.id, task.id, derived.status
FROM upload_intake_profiles profile
JOIN uploads derived ON derived.id = profile.upload_id
LEFT JOIN tasks task ON task.upload_id = derived.id
WHERE profile.source_kind = 'archive_entry'
  AND profile.source_parent_upload_id = ?
  AND profile.source_archive_name = ?
  AND profile.source_entry_path = ?
  AND profile.validation_status = 'valid'
  AND profile.input_category = ?
  AND profile.detected_category = ?
  AND profile.detected_format = ?
  AND derived.created_by = ?
  AND derived.declared_size_bytes = ?
  AND derived.actual_sha256 = ?
  AND derived.blob_id = ?
ORDER BY derived.created_at ASC, derived.id ASC
FOR UPDATE`, parentUploadID, archiveName, logicalPath, category, category, format,
		sourceOwner, size, sha, blobID)
	if err != nil {
		return EntryFact{}, fmt.Errorf("find archive entry durable facts: %w", err)
	}
	type candidate struct {
		derivedID string
		taskID    sql.NullString
		status    string
	}
	candidates := make([]candidate, 0, 2)
	for rows.Next() {
		var value candidate
		if err := rows.Scan(&value.derivedID, &value.taskID, &value.status); err != nil {
			rows.Close()
			return EntryFact{}, fmt.Errorf("scan archive entry durable fact: %w", err)
		}
		candidates = append(candidates, value)
	}
	if err := rows.Close(); err != nil {
		return EntryFact{}, fmt.Errorf("close archive entry durable facts: %w", err)
	}
	var taskFact *candidate
	for index := range candidates {
		if !candidates[index].taskID.Valid {
			continue
		}
		if taskFact != nil && (taskFact.taskID.String != candidates[index].taskID.String ||
			taskFact.derivedID != candidates[index].derivedID) {
			return EntryFact{}, ErrConflict
		}
		taskFact = &candidates[index]
	}
	if taskFact != nil {
		if existingDerived.Valid && existingDerived.String != taskFact.derivedID {
			return EntryFact{}, ErrConflict
		}
		if existingTask.Valid && existingTask.String != taskFact.taskID.String {
			return EntryFact{}, ErrConflict
		}
		if !releasedAt.Valid {
			if _, _, err := releaseBlob(ctx, tx, blobID); err != nil {
				return EntryFact{}, err
			}
		}
		if _, err := tx.ExecContext(ctx, `
UPDATE archive_import_entries
SET status = 'created', derived_upload_id = ?, task_id = ?,
    blob_reference_released_at = COALESCE(
        blob_reference_released_at, UTC_TIMESTAMP(6)
    ),
    error_code = NULL, error_message = NULL, updated_at = UTC_TIMESTAMP(6)
WHERE id = ?`, taskFact.derivedID, taskFact.taskID.String, entryID); err != nil {
			return EntryFact{}, fmt.Errorf("reconcile committed archive task: %w", err)
		}
		if _, err := tx.ExecContext(ctx, `
UPDATE archive_import_task_batch_items
SET outcome = 'existing', task_id = ?, lease_owner = NULL,
    lease_until = NULL, heartbeat_at = NULL,
    error_code = NULL, error_message = NULL, updated_at = UTC_TIMESTAMP(6)
WHERE entry_id = ? AND outcome IN ('pending', 'processing', 'failed')`,
			taskFact.taskID.String, entryID,
		); err != nil {
			return EntryFact{}, fmt.Errorf("reconcile archive task batch outcomes: %w", err)
		}
		if status != EntryCreated {
			if _, err := tx.ExecContext(ctx, `
UPDATE archive_imports
SET created_tasks = created_tasks + 1, updated_at = UTC_TIMESTAMP(6)
WHERE id = ?`, importID); err != nil {
				return EntryFact{}, fmt.Errorf("reconcile archive created task count: %w", err)
			}
		}
		if err := tx.Commit(); err != nil {
			return EntryFact{}, fmt.Errorf("commit archive task fact reconciliation: %w", err)
		}
		return EntryFact{
			DerivedUploadID: taskFact.derivedID, TaskID: taskFact.taskID.String,
		}, nil
	}

	selected := existingDerived.String
	if selected != "" {
		matched := false
		for _, candidate := range candidates {
			if candidate.derivedID != selected {
				continue
			}
			matched = true
			if candidate.status != "completed" {
				return EntryFact{}, ErrConflict
			}
		}
		if !matched {
			return EntryFact{}, ErrConflict
		}
	}
	if selected == "" {
		for _, candidate := range candidates {
			if candidate.status != "completed" {
				continue
			}
			if selected != "" && selected != candidate.derivedID {
				return EntryFact{}, ErrConflict
			}
			selected = candidate.derivedID
		}
	}
	if selected != "" {
		if _, err := tx.ExecContext(ctx, `
UPDATE archive_import_entries
SET derived_upload_id = ?, updated_at = UTC_TIMESTAMP(6)
WHERE id = ? AND (derived_upload_id IS NULL OR derived_upload_id = ?)`,
			selected, entryID, selected,
		); err != nil {
			return EntryFact{}, fmt.Errorf("reconcile archive derived upload: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return EntryFact{}, fmt.Errorf("commit archive derived upload reconciliation: %w", err)
	}
	return EntryFact{DerivedUploadID: selected}, nil
}

func (r *MySQLRepository) ReconcileBatchFacts(
	ctx context.Context,
	batchID string,
) error {
	rows, err := r.db.QueryContext(ctx, `
SELECT entry_id
FROM archive_import_task_batch_items
WHERE batch_id = ? AND outcome IN ('pending', 'processing', 'failed')
ORDER BY ordinal ASC`, batchID)
	if err != nil {
		return fmt.Errorf("list archive batch reconciliation entries: %w", err)
	}
	ids := make([]uint64, 0)
	for rows.Next() {
		var id uint64
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return fmt.Errorf("scan archive batch reconciliation entry: %w", err)
		}
		ids = append(ids, id)
	}
	if err := rows.Close(); err != nil {
		return fmt.Errorf("close archive batch reconciliation entries: %w", err)
	}
	for _, id := range ids {
		if _, err := r.ReconcileEntryFact(ctx, id); err != nil &&
			!errors.Is(err, ErrNotFound) {
			return err
		}
	}
	return nil
}

func (r *MySQLRepository) ReconcileImportFacts(
	ctx context.Context,
	uploadID string,
) error {
	rows, err := r.db.QueryContext(ctx, `
SELECT entry.id
FROM archive_import_entries entry
JOIN archive_imports archive_import ON archive_import.id = entry.archive_import_id
WHERE archive_import.upload_id = ? AND entry.status <> 'created'
  AND entry.status IN ('eligible', 'failed')
ORDER BY entry.id ASC`, uploadID)
	if err != nil {
		return fmt.Errorf("list archive import reconciliation entries: %w", err)
	}
	ids := make([]uint64, 0)
	for rows.Next() {
		var id uint64
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return fmt.Errorf("scan archive import reconciliation entry: %w", err)
		}
		ids = append(ids, id)
	}
	if err := rows.Close(); err != nil {
		return fmt.Errorf("close archive import reconciliation entries: %w", err)
	}
	for _, id := range ids {
		if _, err := r.ReconcileEntryFact(ctx, id); err != nil &&
			!errors.Is(err, ErrNotFound) {
			return err
		}
	}
	return nil
}

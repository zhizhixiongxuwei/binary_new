package decompile

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"path"
	"strconv"
)

func (r *MySQLRepository) ListSourceProjects(
	ctx context.Context,
	query SourceProjectListQuery,
) (SourceProjectPage, error) {
	if err := ctx.Err(); err != nil {
		return SourceProjectPage{}, err
	}
	tx, err := r.db.BeginTx(ctx, &sql.TxOptions{
		Isolation: sql.LevelRepeatableRead,
		ReadOnly:  true,
	})
	if err != nil {
		return SourceProjectPage{}, fmt.Errorf("begin source project snapshot: %w", err)
	}
	defer tx.Rollback()
	if err := requireTask(ctx, tx, query.TaskID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return SourceProjectPage{}, ErrTaskNotFound
		}
		return SourceProjectPage{}, fmt.Errorf("find source project task: %w", err)
	}

	statement := sourceProjectSelect + `
WHERE project.task_id = ? AND project.deleted_at IS NULL`
	arguments := []any{query.TaskID}
	if query.After != nil {
		statement += `
  AND (
      project.created_at < ? OR
      (project.created_at = ? AND project.id < ?)
  )`
		arguments = append(
			arguments,
			query.After.CreatedAt,
			query.After.CreatedAt,
			query.After.ID,
		)
	}
	statement += `
ORDER BY project.created_at DESC, project.id DESC
LIMIT ?`
	arguments = append(arguments, query.PageSize+1)
	rows, err := tx.QueryContext(ctx, statement, arguments...)
	if err != nil {
		return SourceProjectPage{}, fmt.Errorf("list source projects: %w", err)
	}
	items := make([]SourceProject, 0, query.PageSize+1)
	for rows.Next() {
		record, err := scanSourceProject(rows)
		if err != nil {
			_ = rows.Close()
			return SourceProjectPage{}, fmt.Errorf("scan source project: %w", err)
		}
		items = append(items, record.SourceProject)
	}
	if err := rows.Close(); err != nil {
		return SourceProjectPage{}, fmt.Errorf("close source project rows: %w", err)
	}
	if err := rows.Err(); err != nil {
		return SourceProjectPage{}, fmt.Errorf("iterate source projects: %w", err)
	}
	page := SourceProjectPage{Items: items}
	if len(page.Items) > query.PageSize {
		page.HasMore = true
		page.Items = page.Items[:query.PageSize]
	}
	if err := tx.Commit(); err != nil {
		return SourceProjectPage{}, fmt.Errorf("commit source project snapshot: %w", err)
	}
	return page, nil
}

func (r *MySQLRepository) GetSourceProject(
	ctx context.Context,
	query SourceProjectQuery,
) (sourceProjectRecord, error) {
	if err := ctx.Err(); err != nil {
		return sourceProjectRecord{}, err
	}
	tx, err := r.db.BeginTx(ctx, &sql.TxOptions{
		Isolation: sql.LevelRepeatableRead,
		ReadOnly:  true,
	})
	if err != nil {
		return sourceProjectRecord{}, fmt.Errorf("begin source project read: %w", err)
	}
	defer tx.Rollback()
	if err := requireTask(ctx, tx, query.TaskID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return sourceProjectRecord{}, ErrTaskNotFound
		}
		return sourceProjectRecord{}, fmt.Errorf("find source project task: %w", err)
	}
	record, err := scanSourceProject(tx.QueryRowContext(ctx, sourceProjectSelect+`
WHERE project.task_id = ? AND project.id = ? AND project.deleted_at IS NULL
LIMIT 1`, query.TaskID, query.ProjectID))
	if errors.Is(err, sql.ErrNoRows) {
		return sourceProjectRecord{}, ErrProjectNotFound
	}
	if err != nil {
		return sourceProjectRecord{}, fmt.Errorf("read source project: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return sourceProjectRecord{}, fmt.Errorf("commit source project read: %w", err)
	}
	return record, nil
}

func (r *MySQLRepository) BeginSourceProjectDeletion(
	ctx context.Context,
	query SourceProjectQuery,
) (sourceProjectDeletion, error) {
	if err := ctx.Err(); err != nil {
		return sourceProjectDeletion{}, err
	}
	tx, err := r.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return sourceProjectDeletion{}, fmt.Errorf("begin source project deletion: %w", err)
	}
	defer tx.Rollback()
	if err := requireTask(ctx, tx, query.TaskID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return sourceProjectDeletion{}, ErrTaskNotFound
		}
		return sourceProjectDeletion{}, fmt.Errorf("find source project delete task: %w", err)
	}
	record, err := scanSourceProject(tx.QueryRowContext(ctx, sourceProjectSelect+`
WHERE project.task_id = ? AND project.id = ?
LIMIT 1
FOR UPDATE`, query.TaskID, query.ProjectID))
	if errors.Is(err, sql.ErrNoRows) {
		return sourceProjectDeletion{}, ErrProjectNotFound
	}
	if err != nil {
		return sourceProjectDeletion{}, fmt.Errorf("lock source project deletion: %w", err)
	}
	deletion := sourceProjectDeletion{
		Project:         record,
		AlreadyComplete: record.StorageDeletedAt != nil,
	}
	if !deletion.AlreadyComplete && record.LayoutVersion == SourceProjectLayoutLegacyV1 {
		rows, err := tx.QueryContext(ctx, `
SELECT id, storage_key
FROM decompile_results
WHERE task_id = ? AND analyzer_run_id = ? AND storage_key IS NOT NULL
ORDER BY id ASC`, query.TaskID, query.ProjectID)
		if err != nil {
			return sourceProjectDeletion{}, fmt.Errorf("list legacy source files: %w", err)
		}
		for rows.Next() {
			var file legacySourceProjectFile
			if err := rows.Scan(&file.ResultID, &file.StorageKey); err != nil {
				_ = rows.Close()
				return sourceProjectDeletion{}, fmt.Errorf("scan legacy source file: %w", err)
			}
			deletion.LegacyFiles = append(deletion.LegacyFiles, file)
		}
		if err := rows.Close(); err != nil {
			return sourceProjectDeletion{}, fmt.Errorf("close legacy source files: %w", err)
		}
		if err := rows.Err(); err != nil {
			return sourceProjectDeletion{}, fmt.Errorf("iterate legacy source files: %w", err)
		}
	}
	if record.DeletedAt == nil {
		if _, err := tx.ExecContext(ctx, `
UPDATE decompile_source_projects
SET deleted_at = UTC_TIMESTAMP(6)
WHERE task_id = ? AND id = ? AND deleted_at IS NULL`,
			query.TaskID, query.ProjectID,
		); err != nil {
			return sourceProjectDeletion{}, fmt.Errorf("mark source project deleted: %w", err)
		}
		if _, err := tx.ExecContext(ctx, `
UPDATE decompile_results
SET deleted_at = COALESCE(deleted_at, UTC_TIMESTAMP(6))
WHERE task_id = ? AND analyzer_run_id = ?`,
			query.TaskID, query.ProjectID,
		); err != nil {
			return sourceProjectDeletion{}, fmt.Errorf("hide source project results: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return sourceProjectDeletion{}, fmt.Errorf("commit source project deletion: %w", err)
	}
	return deletion, nil
}

func (r *MySQLRepository) CompleteSourceProjectDeletion(
	ctx context.Context,
	query SourceProjectQuery,
) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	tx, err := r.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return fmt.Errorf("begin source project cleanup completion: %w", err)
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, `
UPDATE decompile_source_projects
SET root_storage_key = NULL,
    canonical_storage_key = NULL,
    canonical_sha256 = NULL,
    canonical_size_bytes = NULL,
    manifest_storage_key = NULL,
    manifest_sha256 = NULL,
    manifest_size_bytes = NULL,
    storage_deleted_at = COALESCE(storage_deleted_at, UTC_TIMESTAMP(6))
WHERE task_id = ? AND id = ? AND deleted_at IS NOT NULL`,
		query.TaskID, query.ProjectID,
	)
	if err != nil {
		return fmt.Errorf("complete source project cleanup: %w", err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("inspect source project cleanup: %w", err)
	}
	if affected == 0 {
		var exists uint8
		if err := tx.QueryRowContext(ctx, `
SELECT EXISTS (
    SELECT 1
    FROM decompile_source_projects
    WHERE task_id = ? AND id = ? AND deleted_at IS NOT NULL
)`, query.TaskID, query.ProjectID).Scan(&exists); err != nil {
			return fmt.Errorf("confirm source project cleanup: %w", err)
		}
		if exists == 0 {
			return ErrProjectNotFound
		}
	}
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
WHERE task_id = ? AND analyzer_run_id = ?`,
		query.TaskID, query.ProjectID,
	); err != nil {
		return fmt.Errorf("clear source project result storage: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit source project cleanup completion: %w", err)
	}
	return nil
}

func (r *MySQLRepository) ListLegacySourceProjectEntries(
	ctx context.Context,
	query SourceProjectQuery,
) ([]legacySourceProjectEntry, error) {
	rows, err := r.db.QueryContext(ctx, `
SELECT result.id, result.file_node_id, result.symbol_key, result.language,
       result.engine_name, result.engine_version, result.status,
       result.size_bytes, result.diagnostics_json, result.created_at,
       result.completed_at, result.storage_key, result.content_sha256
FROM decompile_source_projects project
JOIN decompile_results result
  ON result.task_id = project.task_id
 AND result.analyzer_run_id = project.id
WHERE project.task_id = ?
  AND project.id = ?
  AND project.layout_version = 'legacy-v1'
  AND project.deleted_at IS NULL
  AND result.deleted_at IS NULL
	  AND result.storage_key IS NOT NULL
	  AND result.content_sha256 IS NOT NULL
	  AND result.size_bytes IS NOT NULL
	  AND result.status IN ('complete', 'partial', 'bytecode_only')
ORDER BY result.created_at ASC, result.id ASC`, query.TaskID, query.ProjectID)
	if err != nil {
		return nil, fmt.Errorf("list legacy source project results: %w", err)
	}
	entries := make([]legacySourceProjectEntry, 0)
	for rows.Next() {
		result, err := scanResult(rows)
		if err != nil {
			_ = rows.Close()
			return nil, fmt.Errorf("scan legacy source project result: %w", err)
		}
		descriptor := SourceDescriptor{
			ResultID:   result.ID,
			Status:     result.Status,
			StorageKey: result.StorageKey,
			SHA256:     result.ContentSHA256,
		}
		if result.SizeBytes != nil {
			descriptor.SizeBytes = *result.SizeBytes
			descriptor.SizeKnown = true
		}
		entries = append(entries, legacySourceProjectEntry{
			Result: result, Descriptor: descriptor,
		})
	}
	if err := rows.Close(); err != nil {
		return nil, fmt.Errorf("close legacy source project results: %w", err)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate legacy source project results: %w", err)
	}
	return entries, nil
}

const sourceProjectSelect = `
SELECT project.id, project.task_id, project.job_id, project.file_node_id,
       node.logical_path, project.layout_version, project.source_kind,
       project.language, project.engine_name, project.engine_version,
       project.status, project.source_file_count, project.symbol_count,
       project.source_size_bytes, project.created_at, project.completed_at,
       project.root_storage_key, project.canonical_storage_key,
       project.canonical_sha256, project.canonical_size_bytes,
       project.manifest_storage_key, project.manifest_sha256,
       project.manifest_size_bytes, project.deleted_at,
       project.storage_deleted_at
FROM decompile_source_projects project
JOIN file_nodes node
  ON node.task_id = project.task_id AND node.id = project.file_node_id
`

func scanSourceProject(scanner rowScanner) (sourceProjectRecord, error) {
	var record sourceProjectRecord
	var jobID, rootKey, canonicalKey, canonicalSHA, manifestKey, manifestSHA sql.NullString
	var fileNodeID uint64
	var completedAt, deletedAt, storageDeletedAt sql.NullTime
	var canonicalSize, manifestSize sql.Null[uint64]
	if err := scanner.Scan(
		&record.ID,
		&record.TaskID,
		&jobID,
		&fileNodeID,
		&record.TargetPath,
		&record.LayoutVersion,
		&record.SourceKind,
		&record.Language,
		&record.EngineName,
		&record.EngineVersion,
		&record.Status,
		&record.SourceFileCount,
		&record.SymbolCount,
		&record.SourceSizeBytes,
		&record.CreatedAt,
		&completedAt,
		&rootKey,
		&canonicalKey,
		&canonicalSHA,
		&canonicalSize,
		&manifestKey,
		&manifestSHA,
		&manifestSize,
		&deletedAt,
		&storageDeletedAt,
	); err != nil {
		return sourceProjectRecord{}, err
	}
	if fileNodeID == 0 {
		return sourceProjectRecord{}, errors.New("source project file node ID is invalid")
	}
	record.FileNodeID = strconv.FormatUint(fileNodeID, 10)
	if jobID.Valid {
		record.JobID = jobID.String
	}
	if completedAt.Valid {
		value := completedAt.Time
		record.CompletedAt = &value
	}
	if rootKey.Valid {
		record.RootStorageKey = rootKey.String
	}
	if canonicalKey.Valid {
		record.CanonicalStorageKey = canonicalKey.String
		record.CanonicalFilename = path.Base(canonicalKey.String)
	}
	if canonicalSHA.Valid {
		record.CanonicalSHA256 = canonicalSHA.String
	}
	if canonicalSize.Valid {
		record.CanonicalSizeBytes = canonicalSize.V
		record.CanonicalSizeKnown = true
	}
	if manifestKey.Valid {
		record.ManifestStorageKey = manifestKey.String
		record.ManifestAvailable = true
	}
	if manifestSHA.Valid {
		record.ManifestSHA256 = manifestSHA.String
	}
	if manifestSize.Valid {
		record.ManifestSizeBytes = manifestSize.V
		record.ManifestSizeKnown = true
	}
	if deletedAt.Valid {
		value := deletedAt.Time
		record.DeletedAt = &value
	}
	if storageDeletedAt.Valid {
		value := storageDeletedAt.Time
		record.StorageDeletedAt = &value
	}
	return record, nil
}

func insertPublishedSourceProject(
	ctx context.Context,
	tx *sql.Tx,
	taskID string,
	fileNodeID uint64,
	jobID string,
	engineName string,
	engineVersion string,
	status string,
	project PublishedSourceProject,
) error {
	if tx == nil || !uuidPattern.MatchString(taskID) || fileNodeID == 0 ||
		!uuidPattern.MatchString(jobID) || !safeEngineVersion(engineVersion) ||
		!validPublishedSourceProject(project.ID, project, project.SymbolCount) ||
		!validSourceProjectKind(project.SourceKind) ||
		!validSourceProjectStatus(status) || engineName == "" || len(engineName) > 128 {
		return ErrRequestConflict
	}
	var canonicalKey, canonicalSHA, canonicalSize any
	if project.CanonicalStorageKey != "" {
		canonicalKey = project.CanonicalStorageKey
		canonicalSHA = project.CanonicalSHA256
		canonicalSize = project.CanonicalSizeBytes
	}
	_, err := tx.ExecContext(ctx, `
INSERT INTO decompile_source_projects (
    id, task_id, file_node_id, job_id, layout_version, source_kind,
    language, engine_name, engine_version, status, root_storage_key,
    canonical_storage_key, canonical_sha256, canonical_size_bytes,
    manifest_storage_key, manifest_sha256, manifest_size_bytes,
    source_file_count, symbol_count, source_size_bytes, completed_at
) VALUES (
    ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
    UTC_TIMESTAMP(6)
)`,
		project.ID, taskID, fileNodeID, jobID, project.LayoutVersion,
		project.SourceKind, project.Language, engineName, engineVersion, status,
		project.RootStorageKey, canonicalKey, canonicalSHA, canonicalSize,
		project.ManifestStorageKey, project.ManifestSHA256,
		project.ManifestSizeBytes, project.SourceFileCount, project.SymbolCount,
		project.SourceSizeBytes,
	)
	if err != nil {
		return fmt.Errorf("insert decompile source project: %w", err)
	}
	return nil
}

func validSourceProjectKind(value string) bool {
	switch value {
	case SourceProjectKindGhidraPseudoC, SourceProjectKindJava,
		SourceProjectKindKotlin, SourceProjectKindPython,
		SourceProjectKindBytecode:
		return true
	default:
		return false
	}
}

func validSourceProjectStatus(value string) bool {
	return value == "complete" || value == "partial" || value == "bytecode_only"
}

var _ sourceProjectRepository = (*MySQLRepository)(nil)

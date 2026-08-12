package decompile

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"time"

	"binaryscan/internal/audit"
)

type deletionProjectState struct {
	Generation      uint64
	LayoutVersion   string
	RootStorageKey  sql.NullString
	SourceFileCount uint64
}

func (r *MySQLRepository) CreateSourceProjectDeletionPreview(
	ctx context.Context,
	record sourceProjectDeletionPreviewRecord,
) (SourceProjectDeletionCounts, error) {
	if err := ctx.Err(); err != nil {
		return SourceProjectDeletionCounts{}, err
	}
	if !validDeletionPreviewRecord(record) {
		return SourceProjectDeletionCounts{}, ErrInvalidInput
	}
	tx, err := r.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return SourceProjectDeletionCounts{}, fmt.Errorf("begin source project deletion preview: %w", err)
	}
	defer tx.Rollback()
	project, err := lockDeletionProject(ctx, tx, record.TaskID, record.ProjectID)
	if err != nil {
		return SourceProjectDeletionCounts{}, err
	}
	counts, err := loadSourceProjectDeletionCounts(ctx, tx, record.TaskID, record.ProjectID, project.SourceFileCount)
	if err != nil {
		return SourceProjectDeletionCounts{}, err
	}
	digest, err := sourceProjectDeletionCountsDigest(counts)
	if err != nil {
		return SourceProjectDeletionCounts{}, err
	}
	_, err = tx.ExecContext(ctx, `
INSERT INTO source_project_deletion_tokens (
    token_hash, user_id, project_id, project_generation,
    impact_counts_sha256, expires_at, created_at
) VALUES (?, ?, ?, ?, ?, ?, UTC_TIMESTAMP(6))`,
		record.TokenHash, record.UserID, record.ProjectID, project.Generation,
		digest, record.ExpiresAt,
	)
	if err != nil {
		return SourceProjectDeletionCounts{}, fmt.Errorf("store source project deletion token: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return SourceProjectDeletionCounts{}, fmt.Errorf("commit source project deletion preview: %w", err)
	}
	return counts, nil
}

func (r *MySQLRepository) ConfirmSourceProjectDeletion(
	ctx context.Context,
	record sourceProjectDeletionConfirmRecord,
) (SourceProjectDeletionOperation, error) {
	if err := ctx.Err(); err != nil {
		return SourceProjectDeletionOperation{}, err
	}
	if !validDeletionConfirmRecord(record) {
		return SourceProjectDeletionOperation{}, ErrInvalidInput
	}
	tx, err := r.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return SourceProjectDeletionOperation{}, fmt.Errorf("begin source project deletion confirmation: %w", err)
	}
	defer tx.Rollback()
	var tokenUser uint64
	var tokenProject string
	var tokenGeneration uint64
	var tokenCountsDigest string
	var expiresAt time.Time
	var usedAt sql.NullTime
	var databaseNow time.Time
	err = tx.QueryRowContext(ctx, `
SELECT user_id, project_id, project_generation, impact_counts_sha256,
       expires_at, used_at, UTC_TIMESTAMP(6)
FROM source_project_deletion_tokens
WHERE token_hash = ?
FOR UPDATE`, record.TokenHash).Scan(
		&tokenUser, &tokenProject, &tokenGeneration, &tokenCountsDigest,
		&expiresAt, &usedAt, &databaseNow,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return SourceProjectDeletionOperation{}, ErrDeletionConfirmationInvalid
	}
	if err != nil {
		return SourceProjectDeletionOperation{}, fmt.Errorf("lock source project deletion token: %w", err)
	}
	if usedAt.Valid || !expiresAt.After(databaseNow) || tokenUser != record.UserID ||
		tokenProject != record.ProjectID {
		return SourceProjectDeletionOperation{}, ErrDeletionConfirmationInvalid
	}
	project, err := lockDeletionProject(ctx, tx, record.TaskID, record.ProjectID)
	if err != nil {
		return SourceProjectDeletionOperation{}, err
	}
	if project.Generation != tokenGeneration ||
		record.TypedSuffix != deletionTypedSuffix(record.ProjectID) {
		return SourceProjectDeletionOperation{}, ErrDeletionConfirmationChanged
	}
	counts, err := loadSourceProjectDeletionCounts(ctx, tx, record.TaskID, record.ProjectID, project.SourceFileCount)
	if err != nil {
		return SourceProjectDeletionOperation{}, err
	}
	countsDigest, err := sourceProjectDeletionCountsDigest(counts)
	if err != nil {
		return SourceProjectDeletionOperation{}, err
	}
	if countsDigest != tokenCountsDigest {
		return SourceProjectDeletionOperation{}, ErrDeletionConfirmationChanged
	}
	var existingOperation uint8
	if err := tx.QueryRowContext(ctx, `
SELECT EXISTS (
    SELECT 1 FROM source_project_deletion_operations
    WHERE active_project_id = ?
)`, record.ProjectID).Scan(&existingOperation); err != nil {
		return SourceProjectDeletionOperation{}, fmt.Errorf("find active source project deletion: %w", err)
	}
	if existingOperation != 0 {
		return SourceProjectDeletionOperation{}, ErrProjectDeletionInProgress
	}
	consumed, err := tx.ExecContext(ctx, `
UPDATE source_project_deletion_tokens
SET used_at = UTC_TIMESTAMP(6)
WHERE token_hash = ? AND used_at IS NULL`, record.TokenHash)
	if err != nil {
		return SourceProjectDeletionOperation{}, fmt.Errorf("consume source project deletion token: %w", err)
	}
	if err := requireSingleDeletionMutation(consumed, "consume source project deletion token"); err != nil {
		return SourceProjectDeletionOperation{}, ErrDeletionConfirmationInvalid
	}
	tombstoned, err := tx.ExecContext(ctx, `
UPDATE decompile_source_projects
SET deleted_at = UTC_TIMESTAMP(6),
    deletion_generation = deletion_generation + 1
WHERE task_id = ? AND id = ? AND deleted_at IS NULL
  AND deletion_generation = ?`, record.TaskID, record.ProjectID, project.Generation)
	if err != nil {
		return SourceProjectDeletionOperation{}, fmt.Errorf("tombstone source project: %w", err)
	}
	if err := requireSingleDeletionMutation(tombstoned, "tombstone source project"); err != nil {
		return SourceProjectDeletionOperation{}, ErrDeletionConfirmationChanged
	}
	if _, err := tx.ExecContext(ctx, `
UPDATE reports
SET snapshot_state = 'stale',
    generation_owner = NULL, generation_lease_until = NULL,
    generation_heartbeat_at = NULL
WHERE task_id = ? AND deleted_at IS NULL
  AND snapshot_state IN ('current', 'staged')`, record.TaskID); err != nil {
		return SourceProjectDeletionOperation{}, fmt.Errorf("hide task reports for source project deletion: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `
UPDATE decompile_results
SET deleted_at = COALESCE(deleted_at, UTC_TIMESTAMP(6))
WHERE task_id = ? AND analyzer_run_id = ?`, record.TaskID, record.ProjectID); err != nil {
		return SourceProjectDeletionOperation{}, fmt.Errorf("hide source project results: %w", err)
	}
	active, err := cancelSourceProjectCAnalysisJobs(ctx, tx, record.TaskID, record.ProjectID)
	if err != nil {
		return SourceProjectDeletionOperation{}, err
	}
	javaActive, err := cancelSourceProjectJavaAnalysisJobs(
		ctx, tx, record.TaskID, record.ProjectID,
	)
	if err != nil {
		return SourceProjectDeletionOperation{}, err
	}
	status := "pending"
	if active || javaActive {
		status = "cancelling"
	}
	storageScope := any(nil)
	if project.LayoutVersion == SourceProjectLayoutV1 {
		expected := sourceProjectRoot(record.ProjectID)
		if !project.RootStorageKey.Valid || project.RootStorageKey.String != expected {
			return SourceProjectDeletionOperation{}, ErrSourceUnavailable
		}
		storageScope = expected
	}
	encodedCounts, err := json.Marshal(counts)
	if err != nil {
		return SourceProjectDeletionOperation{}, fmt.Errorf("encode source project deletion counts: %w", err)
	}
	_, err = tx.ExecContext(ctx, `
INSERT INTO source_project_deletion_operations (
    id, project_id, task_id, requested_by_user_id, project_generation,
    status, impact_counts_json, impact_counts_sha256, storage_scope,
    available_at, created_at
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, UTC_TIMESTAMP(6), ?)`,
		record.OperationID, record.ProjectID, record.TaskID, record.UserID,
		project.Generation+1, status, encodedCounts, countsDigest, storageScope,
		record.CreatedAt,
	)
	if err != nil {
		return SourceProjectDeletionOperation{}, fmt.Errorf("create source project deletion operation: %w", err)
	}
	operation := SourceProjectDeletionOperation{
		ID: record.OperationID, ProjectID: record.ProjectID, Status: status,
		Counts: counts, CreatedAt: record.CreatedAt,
	}
	if err := audit.Append(ctx, tx, audit.Event{
		ActorUserID: &record.UserID,
		Action:      "decompile.project_deletion_requested",
		ObjectType:  "decompile_project",
		ObjectID:    record.ProjectID,
		Outcome:     audit.OutcomeSuccess,
		Metadata: map[string]any{
			"task_id": record.TaskID, "operation_id": record.OperationID,
			"c_analysis_runs":        counts.CAnalysisRuns,
			"c_analysis_findings":    counts.CAnalysisFindings,
			"java_analysis_runs":     counts.JavaAnalysisRuns,
			"java_analysis_findings": counts.JavaAnalysisFindings,
			"reports":                counts.Reports,
		},
	}); err != nil {
		return SourceProjectDeletionOperation{}, fmt.Errorf("audit source project deletion request: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return SourceProjectDeletionOperation{}, fmt.Errorf("commit source project deletion confirmation: %w", err)
	}
	return operation, nil
}

func (r *MySQLRepository) GetSourceProjectDeletionOperation(
	ctx context.Context,
	query SourceProjectDeletionOperationQuery,
) (SourceProjectDeletionOperation, error) {
	if !uuidPattern.MatchString(query.TaskID) || !uuidPattern.MatchString(query.OperationID) {
		return SourceProjectDeletionOperation{}, ErrInvalidInput
	}
	return scanSourceProjectDeletionOperation(r.db.QueryRowContext(ctx, `
SELECT id, project_id, status, impact_counts_json, created_at, completed_at,
       last_error_code, last_error_message
FROM source_project_deletion_operations
WHERE task_id = ? AND id = ?
LIMIT 1`, query.TaskID, query.OperationID))
}

func scanSourceProjectDeletionOperation(scanner rowScanner) (SourceProjectDeletionOperation, error) {
	var value SourceProjectDeletionOperation
	var counts []byte
	var completedAt sql.NullTime
	var errorCode, errorMessage sql.NullString
	if err := scanner.Scan(
		&value.ID, &value.ProjectID, &value.Status, &counts, &value.CreatedAt,
		&completedAt, &errorCode, &errorMessage,
	); errors.Is(err, sql.ErrNoRows) {
		return SourceProjectDeletionOperation{}, ErrProjectDeletionNotFound
	} else if err != nil {
		return SourceProjectDeletionOperation{}, fmt.Errorf("read source project deletion operation: %w", err)
	}
	if err := json.Unmarshal(counts, &value.Counts); err != nil {
		return SourceProjectDeletionOperation{}, errors.New("stored source project deletion counts are invalid")
	}
	if completedAt.Valid {
		completed := completedAt.Time
		value.CompletedAt = &completed
	}
	if errorCode.Valid {
		code := errorCode.String
		value.ErrorCode = &code
	}
	if errorMessage.Valid {
		message := errorMessage.String
		value.ErrorMessage = &message
	}
	return value, nil
}

func lockDeletionProject(
	ctx context.Context,
	tx *sql.Tx,
	taskID string,
	projectID string,
) (deletionProjectState, error) {
	var value deletionProjectState
	var projectDeleted, storageDeleted sql.NullTime
	var taskStatus string
	err := tx.QueryRowContext(ctx, `
SELECT project.deletion_generation, project.layout_version,
       project.root_storage_key, project.source_file_count,
       project.deleted_at, project.storage_deleted_at, task.status
FROM decompile_source_projects project
JOIN tasks task ON task.id = project.task_id
WHERE project.task_id = ? AND project.id = ? AND task.deleted_at IS NULL
FOR UPDATE`, taskID, projectID).Scan(
		&value.Generation, &value.LayoutVersion, &value.RootStorageKey,
		&value.SourceFileCount, &projectDeleted, &storageDeleted, &taskStatus,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return deletionProjectState{}, ErrProjectNotFound
	}
	if err != nil {
		return deletionProjectState{}, fmt.Errorf("lock source project for deletion: %w", err)
	}
	if projectDeleted.Valid || storageDeleted.Valid {
		return deletionProjectState{}, ErrProjectDeletionInProgress
	}
	if taskStatus == "DELETING" || taskStatus == "DELETED" {
		return deletionProjectState{}, ErrTaskStateConflict
	}
	return value, nil
}

func loadSourceProjectDeletionCounts(
	ctx context.Context,
	tx *sql.Tx,
	taskID string,
	projectID string,
	sourceFiles uint64,
) (SourceProjectDeletionCounts, error) {
	value := SourceProjectDeletionCounts{SourceFiles: sourceFiles}
	err := tx.QueryRowContext(ctx, `
SELECT
	    (SELECT COUNT(*) FROM c_analysis_runs
	     WHERE task_id = ? AND source_project_id = ?),
    (SELECT COUNT(*) FROM c_analysis_findings finding
     JOIN c_analysis_runs run
       ON run.task_id = finding.task_id AND run.id = finding.run_id
     WHERE run.task_id = ? AND run.source_project_id = ?),
	    (SELECT COUNT(*) FROM java_analysis_runs
	     WHERE task_id = ? AND source_project_id = ?),
	    (SELECT COUNT(*) FROM java_analysis_findings finding
	     JOIN java_analysis_runs run
	       ON run.task_id = finding.task_id AND run.id = finding.run_id
	     WHERE run.task_id = ? AND run.source_project_id = ?),
	    (SELECT COUNT(*) FROM reports WHERE task_id = ?),
	    (SELECT COUNT(*) FROM reports
	     WHERE task_id = ? AND storage_key IS NOT NULL),
	    (SELECT COUNT(DISTINCT artifact_id) FROM reports
	     WHERE task_id = ? AND artifact_id IS NOT NULL),
	    (SELECT COUNT(*) FROM decompile_results
	     WHERE task_id = ? AND analyzer_run_id = ?)`,
		taskID, projectID, taskID, projectID,
		taskID, projectID, taskID, projectID,
		taskID, taskID, taskID, taskID, projectID,
	).Scan(
		&value.CAnalysisRuns, &value.CAnalysisFindings,
		&value.JavaAnalysisRuns, &value.JavaAnalysisFindings, &value.Reports,
		&value.ReportFiles, &value.Artifacts, &value.DecompileResults,
	)
	if err != nil {
		return SourceProjectDeletionCounts{}, fmt.Errorf("count source project deletion impact: %w", err)
	}
	return value, nil
}

func cancelSourceProjectCAnalysisJobs(
	ctx context.Context,
	tx *sql.Tx,
	taskID string,
	projectID string,
) (bool, error) {
	for _, pool := range []string{"global", "trivy", "native"} {
		if _, err := tx.ExecContext(ctx, `
UPDATE job_resource_slots slot
JOIN jobs job
  ON job.id = slot.job_id AND job.fencing_token = slot.job_fencing_token
JOIN c_analysis_runs run
  ON run.task_id = job.task_id AND run.job_id = job.id
SET slot.job_id = NULL, slot.job_fencing_token = NULL,
    slot.lease_owner = NULL, slot.acquired_at = NULL
WHERE run.task_id = ? AND run.source_project_id = ?
  AND slot.pool = ? AND job.status IN ('queued', 'leased')`,
			taskID, projectID, pool,
		); err != nil {
			return false, fmt.Errorf("release source project C-analysis %s slot: %w", pool, err)
		}
	}
	if _, err := tx.ExecContext(ctx, `
UPDATE jobs job
JOIN c_analysis_runs run
  ON run.task_id = job.task_id AND run.job_id = job.id
SET job.status = 'cancelled', job.lease_owner = NULL, job.lease_until = NULL,
    job.heartbeat_at = NULL,
    job.cancel_requested_at = COALESCE(job.cancel_requested_at, UTC_TIMESTAMP(6)),
    job.completed_at = UTC_TIMESTAMP(6), job.error_code = NULL,
    job.error_message = NULL
WHERE run.task_id = ? AND run.source_project_id = ?
  AND job.status IN ('queued', 'leased')`, taskID, projectID); err != nil {
		return false, fmt.Errorf("cancel inactive source project C-analysis jobs: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `
UPDATE c_analysis_runs run
JOIN jobs job ON job.task_id = run.task_id AND job.id = run.job_id
JOIN analyzer_runs analyzer
  ON analyzer.task_id = run.task_id AND analyzer.id = run.id
SET run.status = 'cancelled', run.completed_at = UTC_TIMESTAMP(6),
    run.error_code = NULL, run.error_message = NULL,
    analyzer.status = 'cancelled', analyzer.completed_at = UTC_TIMESTAMP(6),
    analyzer.error_code = NULL, analyzer.error_message = NULL
WHERE run.task_id = ? AND run.source_project_id = ?
  AND run.status = 'queued' AND job.status = 'cancelled'`, taskID, projectID); err != nil {
		return false, fmt.Errorf("cancel inactive source project C-analysis runs: %w", err)
	}
	_, err := tx.ExecContext(ctx, `
UPDATE jobs job
JOIN c_analysis_runs run
  ON run.task_id = job.task_id AND run.job_id = job.id
SET job.status = 'cancel_requested',
    job.cancel_requested_at = COALESCE(job.cancel_requested_at, UTC_TIMESTAMP(6)),
    run.status = 'cancel_requested'
WHERE run.task_id = ? AND run.source_project_id = ?
	AND job.status IN ('running', 'cancel_requested')
	AND run.status IN ('running', 'cancel_requested')`, taskID, projectID)
	if err != nil {
		return false, fmt.Errorf("request source project C-analysis cancellation: %w", err)
	}
	var active uint8
	if err := tx.QueryRowContext(ctx, `
SELECT EXISTS (
    SELECT 1
    FROM c_analysis_runs run
    JOIN jobs job ON job.task_id = run.task_id AND job.id = run.job_id
    WHERE run.task_id = ? AND run.source_project_id = ?
      AND (
          job.status IN ('queued', 'leased', 'running', 'cancel_requested') OR
          run.status IN ('queued', 'running', 'cancel_requested')
      )
)`, taskID, projectID).Scan(&active); err != nil {
		return false, fmt.Errorf("inspect source project C-analysis cancellation: %w", err)
	}
	return active != 0, nil
}

func cancelSourceProjectJavaAnalysisJobs(
	ctx context.Context,
	tx *sql.Tx,
	taskID string,
	projectID string,
) (bool, error) {
	for _, pool := range []string{"global", "trivy", "native"} {
		if _, err := tx.ExecContext(ctx, `
UPDATE job_resource_slots slot
JOIN jobs job
  ON job.id = slot.job_id AND job.fencing_token = slot.job_fencing_token
JOIN java_analysis_runs run
  ON run.task_id = job.task_id AND run.job_id = job.id
SET slot.job_id = NULL, slot.job_fencing_token = NULL,
    slot.lease_owner = NULL, slot.acquired_at = NULL
WHERE run.task_id = ? AND run.source_project_id = ?
  AND slot.pool = ? AND job.status IN ('queued', 'leased')`,
			taskID, projectID, pool,
		); err != nil {
			return false, fmt.Errorf(
				"release source project Java-analysis %s slot: %w", pool, err,
			)
		}
	}
	if _, err := tx.ExecContext(ctx, `
UPDATE jobs job
JOIN java_analysis_runs run
  ON run.task_id = job.task_id AND run.job_id = job.id
SET job.status = 'cancelled', job.lease_owner = NULL, job.lease_until = NULL,
    job.heartbeat_at = NULL,
    job.cancel_requested_at = COALESCE(job.cancel_requested_at, UTC_TIMESTAMP(6)),
    job.completed_at = UTC_TIMESTAMP(6), job.error_code = NULL,
    job.error_message = NULL
WHERE run.task_id = ? AND run.source_project_id = ?
  AND job.status IN ('queued', 'leased')`, taskID, projectID); err != nil {
		return false, fmt.Errorf(
			"cancel inactive source project Java-analysis jobs: %w", err,
		)
	}
	if _, err := tx.ExecContext(ctx, `
UPDATE java_analysis_runs run
JOIN jobs job ON job.task_id = run.task_id AND job.id = run.job_id
JOIN analyzer_runs analyzer
  ON analyzer.task_id = run.task_id AND analyzer.id = run.id
SET run.status = 'cancelled', run.completed_at = UTC_TIMESTAMP(6),
    run.error_code = NULL, run.error_message = NULL,
    analyzer.status = 'cancelled', analyzer.completed_at = UTC_TIMESTAMP(6),
    analyzer.error_code = NULL, analyzer.error_message = NULL
WHERE run.task_id = ? AND run.source_project_id = ?
  AND run.status = 'queued' AND job.status = 'cancelled'`, taskID, projectID); err != nil {
		return false, fmt.Errorf(
			"cancel inactive source project Java-analysis runs: %w", err,
		)
	}
	if _, err := tx.ExecContext(ctx, `
UPDATE jobs job
JOIN java_analysis_runs run
  ON run.task_id = job.task_id AND run.job_id = job.id
SET job.status = 'cancel_requested',
    job.cancel_requested_at = COALESCE(job.cancel_requested_at, UTC_TIMESTAMP(6)),
    run.status = 'cancel_requested'
WHERE run.task_id = ? AND run.source_project_id = ?
  AND job.status IN ('running', 'cancel_requested')
  AND run.status IN ('running', 'cancel_requested')`, taskID, projectID); err != nil {
		return false, fmt.Errorf(
			"request source project Java-analysis cancellation: %w", err,
		)
	}
	var active uint8
	if err := tx.QueryRowContext(ctx, `
SELECT EXISTS (
    SELECT 1
    FROM java_analysis_runs run
    JOIN jobs job ON job.task_id = run.task_id AND job.id = run.job_id
    WHERE run.task_id = ? AND run.source_project_id = ?
      AND (
          job.status IN ('queued', 'leased', 'running', 'cancel_requested') OR
          run.status IN ('queued', 'running', 'cancel_requested')
      )
)`, taskID, projectID).Scan(&active); err != nil {
		return false, fmt.Errorf(
			"inspect source project Java-analysis cancellation: %w", err,
		)
	}
	return active != 0, nil
}

func sourceProjectDeletionCountsDigest(counts SourceProjectDeletionCounts) (string, error) {
	encoded, err := json.Marshal(counts)
	if err != nil {
		return "", fmt.Errorf("encode source project deletion counts: %w", err)
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:]), nil
}

func legacySourceProjectDeletionCountsDigest(
	counts SourceProjectDeletionCounts,
) (string, error) {
	legacy := struct {
		CAnalysisRuns     uint64 `json:"c_analysis_runs"`
		CAnalysisFindings uint64 `json:"c_analysis_findings"`
		Reports           uint64 `json:"reports"`
		ReportFiles       uint64 `json:"report_files"`
		Artifacts         uint64 `json:"artifacts"`
		DecompileResults  uint64 `json:"decompile_results"`
		SourceFiles       uint64 `json:"source_files"`
	}{
		CAnalysisRuns:     counts.CAnalysisRuns,
		CAnalysisFindings: counts.CAnalysisFindings,
		Reports:           counts.Reports,
		ReportFiles:       counts.ReportFiles,
		Artifacts:         counts.Artifacts,
		DecompileResults:  counts.DecompileResults,
		SourceFiles:       counts.SourceFiles,
	}
	encoded, err := json.Marshal(legacy)
	if err != nil {
		return "", fmt.Errorf("encode legacy source project deletion counts: %w", err)
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:]), nil
}

func validDeletionPreviewRecord(record sourceProjectDeletionPreviewRecord) bool {
	return uuidPattern.MatchString(record.TaskID) &&
		uuidPattern.MatchString(record.ProjectID) && record.UserID > 0 &&
		sha256Pattern.MatchString(record.TokenHash) && !record.ExpiresAt.IsZero()
}

func validDeletionConfirmRecord(record sourceProjectDeletionConfirmRecord) bool {
	return uuidPattern.MatchString(record.TaskID) &&
		uuidPattern.MatchString(record.ProjectID) &&
		uuidPattern.MatchString(record.OperationID) && record.UserID > 0 &&
		sha256Pattern.MatchString(record.TokenHash) &&
		record.TypedSuffix == deletionTypedSuffix(record.ProjectID) &&
		!record.CreatedAt.IsZero()
}

func deletionTypedSuffix(projectID string) string {
	if len(projectID) < 8 {
		return ""
	}
	return projectID[len(projectID)-8:]
}

func sourceProjectDeletionScope(projectID string) string {
	return path.Join(sourceProjectRootName, projectID)
}

func requireSingleDeletionMutation(result sql.Result, operation string) error {
	changed, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("inspect %s: %w", operation, err)
	}
	if changed != 1 {
		return fmt.Errorf("%s affected %d rows", operation, changed)
	}
	return nil
}

var _ sourceProjectDeletionRepository = (*MySQLRepository)(nil)

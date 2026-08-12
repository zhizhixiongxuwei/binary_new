package decompile

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"path"
	"strings"
	"time"

	"binaryscan/internal/audit"
	"binaryscan/internal/taskcleanup"
)

func (r *MySQLRepository) ListReadySourceProjectDeletions(
	ctx context.Context,
	limit int,
) ([]string, error) {
	if limit < 1 || limit > MaxSourceProjectDeletionBatch {
		return nil, errors.New("source project deletion batch size is invalid")
	}
	if _, err := r.db.ExecContext(ctx, `
DELETE FROM source_project_deletion_tokens
WHERE expires_at <= UTC_TIMESTAMP(6) OR used_at IS NOT NULL
LIMIT 1000`); err != nil {
		return nil, fmt.Errorf("purge expired source project deletion tokens: %w", err)
	}
	rows, err := r.db.QueryContext(ctx, `
SELECT id
FROM source_project_deletion_operations
WHERE available_at <= UTC_TIMESTAMP(6)
  AND (
      status IN ('pending', 'cancelling', 'failed') OR
      (status = 'deleting' AND lease_until <= UTC_TIMESTAMP(6))
  )
ORDER BY available_at ASC, created_at ASC, id ASC
LIMIT ?`, limit)
	if err != nil {
		return nil, fmt.Errorf("list source project deletion operations: %w", err)
	}
	defer rows.Close()
	values := make([]string, 0, limit)
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("scan source project deletion operation: %w", err)
		}
		if !uuidPattern.MatchString(id) || len(values) >= limit {
			return nil, errors.New("source project deletion candidate is invalid")
		}
		values = append(values, id)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate source project deletion operations: %w", err)
	}
	return values, nil
}

func (r *MySQLRepository) ClaimSourceProjectDeletion(
	ctx context.Context,
	operationID string,
	leaseOwner string,
	leaseDuration time.Duration,
) (SourceProjectDeletionClaim, bool, bool, error) {
	if !uuidPattern.MatchString(operationID) || leaseOwner == "" ||
		len(leaseOwner) > 255 || leaseDuration <= 0 ||
		leaseDuration.Microseconds() <= 0 {
		return SourceProjectDeletionClaim{}, false, false,
			errors.New("source project deletion claim input is invalid")
	}
	tx, err := r.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return SourceProjectDeletionClaim{}, false, false,
			fmt.Errorf("begin source project deletion claim: %w", err)
	}
	defer tx.Rollback()
	var claim SourceProjectDeletionClaim
	var status string
	var countsJSON []byte
	var countsDigest string
	var projectGeneration uint64
	var attempt uint32
	var fence uint64
	var leaseUntil sql.NullTime
	var storageScope sql.NullString
	err = tx.QueryRowContext(ctx, `
SELECT operation.id, operation.task_id, operation.project_id,
       operation.status, operation.impact_counts_json,
       operation.impact_counts_sha256, operation.project_generation,
       operation.attempt_count, operation.fencing_token,
       operation.lease_until, operation.storage_scope
FROM source_project_deletion_operations operation
WHERE operation.id = ? AND operation.available_at <= UTC_TIMESTAMP(6)
  AND (
      operation.status IN ('pending', 'cancelling', 'failed') OR
      (operation.status = 'deleting' AND
       operation.lease_until <= UTC_TIMESTAMP(6))
  )
FOR UPDATE SKIP LOCKED`, operationID).Scan(
		&claim.OperationID, &claim.TaskID, &claim.ProjectID, &status,
		&countsJSON, &countsDigest, &projectGeneration, &attempt, &fence,
		&leaseUntil, &storageScope,
	)
	if errors.Is(err, sql.ErrNoRows) {
		if err := tx.Commit(); err != nil {
			return SourceProjectDeletionClaim{}, false, false,
				fmt.Errorf("commit skipped source project deletion claim: %w", err)
		}
		return SourceProjectDeletionClaim{}, false, false, nil
	}
	if err != nil {
		return SourceProjectDeletionClaim{}, false, false,
			fmt.Errorf("lock source project deletion operation: %w", err)
	}
	if err := json.Unmarshal(countsJSON, &claim.Counts); err != nil {
		return SourceProjectDeletionClaim{}, false, false,
			errors.New("source project deletion counts are invalid")
	}
	digest, err := sourceProjectDeletionCountsDigest(claim.Counts)
	if err != nil {
		return SourceProjectDeletionClaim{}, false, false,
			errors.New("source project deletion counts digest is invalid")
	}
	if digest != countsDigest {
		legacyDigest, legacyErr := legacySourceProjectDeletionCountsDigest(
			claim.Counts,
		)
		if legacyErr != nil || legacyDigest != countsDigest ||
			claim.Counts.JavaAnalysisRuns != 0 ||
			claim.Counts.JavaAnalysisFindings != 0 {
			return SourceProjectDeletionClaim{}, false, false,
				errors.New("source project deletion counts digest is invalid")
		}
	}
	var storedGeneration uint64
	var deletedAt sql.NullTime
	var projectLayout string
	var rootStorageKey sql.NullString
	err = tx.QueryRowContext(ctx, `
SELECT deletion_generation, deleted_at, layout_version, root_storage_key
FROM decompile_source_projects
WHERE task_id = ? AND id = ?
FOR UPDATE`, claim.TaskID, claim.ProjectID).Scan(
		&storedGeneration, &deletedAt, &projectLayout, &rootStorageKey,
	)
	if errors.Is(err, sql.ErrNoRows) || !deletedAt.Valid ||
		storedGeneration != projectGeneration {
		return SourceProjectDeletionClaim{}, false, false,
			errors.New("source project deletion tombstone changed")
	}
	if err != nil {
		return SourceProjectDeletionClaim{}, false, false,
			fmt.Errorf("lock deleting source project: %w", err)
	}
	switch projectLayout {
	case SourceProjectLayoutV1:
		expected := sourceProjectRoot(claim.ProjectID)
		if !storageScope.Valid || storageScope.String != expected ||
			!rootStorageKey.Valid || rootStorageKey.String != expected {
			return SourceProjectDeletionClaim{}, false, false,
				errors.New("source project deletion storage scope changed")
		}
	case SourceProjectLayoutLegacyV1:
		if storageScope.Valid {
			return SourceProjectDeletionClaim{}, false, false,
				errors.New("legacy source project deletion scope is invalid")
		}
	default:
		return SourceProjectDeletionClaim{}, false, false,
			errors.New("source project deletion layout is invalid")
	}
	if _, err := cancelSourceProjectCAnalysisJobs(
		ctx, tx, claim.TaskID, claim.ProjectID,
	); err != nil {
		return SourceProjectDeletionClaim{}, false, false, err
	}
	if _, err := cancelSourceProjectJavaAnalysisJobs(
		ctx, tx, claim.TaskID, claim.ProjectID,
	); err != nil {
		return SourceProjectDeletionClaim{}, false, false, err
	}
	var active uint8
	if err := tx.QueryRowContext(ctx, `
SELECT EXISTS (
    SELECT 1 FROM (
        SELECT run.status AS run_status, job.status AS job_status
        FROM c_analysis_runs run
        JOIN jobs job ON job.task_id = run.task_id AND job.id = run.job_id
        WHERE run.task_id = ? AND run.source_project_id = ?
        UNION ALL
        SELECT run.status AS run_status, job.status AS job_status
        FROM java_analysis_runs run
        JOIN jobs job ON job.task_id = run.task_id AND job.id = run.job_id
        WHERE run.task_id = ? AND run.source_project_id = ?
    ) active_analysis
    WHERE job_status IN ('queued', 'leased', 'running', 'cancel_requested')
       OR run_status IN ('queued', 'running', 'cancel_requested')
)`, claim.TaskID, claim.ProjectID, claim.TaskID, claim.ProjectID).Scan(&active); err != nil {
		return SourceProjectDeletionClaim{}, false, false,
			fmt.Errorf("check active source project analysis jobs: %w", err)
	}
	if active != 0 {
		_, err := tx.ExecContext(ctx, `
UPDATE source_project_deletion_operations
SET status = 'cancelling', lease_owner = NULL, lease_until = NULL,
    last_error_code = NULL, last_error_message = NULL,
    available_at = DATE_ADD(UTC_TIMESTAMP(6), INTERVAL 2 SECOND)
WHERE id = ?`, operationID)
		if err != nil {
			return SourceProjectDeletionClaim{}, false, false,
				fmt.Errorf("defer source project deletion cancellation: %w", err)
		}
		if err := tx.Commit(); err != nil {
			return SourceProjectDeletionClaim{}, false, false,
				fmt.Errorf("commit deferred source project deletion: %w", err)
		}
		return SourceProjectDeletionClaim{}, false, true, nil
	}
	if attempt == math.MaxUint32 || fence == math.MaxUint64 {
		return SourceProjectDeletionClaim{}, false, false,
			errors.New("source project deletion fencing sequence is exhausted")
	}
	claim.Attempt = attempt + 1
	claim.Fence = fence + 1
	claim.LeaseOwner = leaseOwner
	result, err := tx.ExecContext(ctx, `
UPDATE source_project_deletion_operations
SET status = 'deleting', attempt_count = ?, fencing_token = ?,
    lease_owner = ?,
    lease_until = DATE_ADD(UTC_TIMESTAMP(6), INTERVAL ? MICROSECOND),
    available_at = UTC_TIMESTAMP(6), last_error_code = NULL,
    last_error_message = NULL, completed_at = NULL
WHERE id = ? AND status = ? AND fencing_token = ?`,
		claim.Attempt, claim.Fence, leaseOwner, leaseDuration.Microseconds(),
		operationID, status, fence,
	)
	if err != nil {
		return SourceProjectDeletionClaim{}, false, false,
			fmt.Errorf("claim source project deletion: %w", err)
	}
	if changed, err := result.RowsAffected(); err != nil || changed != 1 {
		if err != nil {
			return SourceProjectDeletionClaim{}, false, false,
				fmt.Errorf("inspect source project deletion claim: %w", err)
		}
		return SourceProjectDeletionClaim{}, false, false, nil
	}
	if err := r.collectSourceProjectDeletionOutputs(ctx, tx, &claim); err != nil {
		return SourceProjectDeletionClaim{}, false, false, err
	}
	if err := audit.Append(ctx, tx, audit.Event{
		Action:     "decompile.project_deletion_cleanup_started",
		ObjectType: "decompile_project", ObjectID: claim.ProjectID,
		Outcome: audit.OutcomeSuccess,
		Metadata: map[string]any{
			"task_id": claim.TaskID, "operation_id": claim.OperationID,
			"attempt": claim.Attempt, "fencing_token": claim.Fence,
			"report_count": len(claim.ReportIDs),
			"run_count":    len(claim.RunIDs) + len(claim.JavaRunIDs),
		},
	}); err != nil {
		return SourceProjectDeletionClaim{}, false, false,
			fmt.Errorf("audit source project deletion cleanup start: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return SourceProjectDeletionClaim{}, false, false,
			fmt.Errorf("commit source project deletion claim: %w", err)
	}
	return claim, true, false, nil
}

func (r *MySQLRepository) collectSourceProjectDeletionOutputs(
	ctx context.Context,
	tx *sql.Tx,
	claim *SourceProjectDeletionClaim,
) error {
	var layout string
	var rootKey sql.NullString
	var storageDeletedAt sql.NullTime
	if err := tx.QueryRowContext(ctx, `
SELECT layout_version, root_storage_key, storage_deleted_at
FROM decompile_source_projects
WHERE task_id = ? AND id = ?`, claim.TaskID, claim.ProjectID).Scan(
		&layout, &rootKey, &storageDeletedAt,
	); err != nil {
		return fmt.Errorf("read deleting source project storage: %w", err)
	}
	if !storageDeletedAt.Valid {
		switch layout {
		case SourceProjectLayoutV1:
			expected := sourceProjectRoot(claim.ProjectID)
			if !rootKey.Valid || rootKey.String != expected {
				return errors.New("deleting source project scope is invalid")
			}
			claim.Scopes = append(claim.Scopes, taskcleanup.Scope{
				Kind: taskcleanup.FileSourceProject, TaskID: claim.TaskID,
				RecordID: claim.ProjectID,
			})
		case SourceProjectLayoutLegacyV1:
			rows, err := tx.QueryContext(ctx, `
SELECT id, storage_key
FROM decompile_results
WHERE task_id = ? AND analyzer_run_id = ? AND storage_key IS NOT NULL
ORDER BY id`, claim.TaskID, claim.ProjectID)
			if err != nil {
				return fmt.Errorf("list legacy source project scopes: %w", err)
			}
			for rows.Next() {
				var resultID, storageKey string
				if err := rows.Scan(&resultID, &storageKey); err != nil {
					rows.Close()
					return fmt.Errorf("scan legacy source project scope: %w", err)
				}
				if !uuidPattern.MatchString(resultID) ||
					!strings.HasPrefix(storageKey, path.Join("decompile", resultID)+"/") {
					rows.Close()
					return errors.New("legacy source project scope is invalid")
				}
				claim.Scopes = append(claim.Scopes, taskcleanup.Scope{
					Kind: taskcleanup.FileDecompile, TaskID: claim.TaskID,
					RecordID: resultID,
				})
			}
			if err := rows.Close(); err != nil {
				return fmt.Errorf("close legacy source project scopes: %w", err)
			}
			if err := rows.Err(); err != nil {
				return fmt.Errorf("iterate legacy source project scopes: %w", err)
			}
		default:
			return errors.New("deleting source project layout is invalid")
		}
	}
	rows, err := tx.QueryContext(ctx, `
SELECT DISTINCT report.id, report.format, report.storage_key, report.sha256,
       report.size_bytes, report.artifact_id
FROM reports report
WHERE report.task_id = ?
ORDER BY report.id`, claim.TaskID)
	if err != nil {
		return fmt.Errorf("list source project dependent reports: %w", err)
	}
	artifactCandidates := make(map[string]struct{})
	for rows.Next() {
		var reportID, format string
		var storageKey, digest, artifactID sql.NullString
		var size sql.Null[uint64]
		if err := rows.Scan(
			&reportID, &format, &storageKey, &digest, &size, &artifactID,
		); err != nil {
			rows.Close()
			return fmt.Errorf("scan source project dependent report: %w", err)
		}
		if !uuidPattern.MatchString(reportID) {
			rows.Close()
			return errors.New("dependent report ID is invalid")
		}
		claim.ReportIDs = append(claim.ReportIDs, reportID)
		if storageKey.Valid || digest.Valid || size.Valid {
			if !storageKey.Valid || !digest.Valid || !size.Valid || size.V > math.MaxInt64 {
				rows.Close()
				return errors.New("dependent report storage metadata is incomplete")
			}
			claim.Files = append(claim.Files, taskcleanup.StoredFile{
				Kind: taskcleanup.FileReport, TaskID: claim.TaskID,
				RecordID: reportID, Format: format, StorageKey: storageKey.String,
				SHA256: digest.String, SizeBytes: int64(size.V),
			})
		}
		if artifactID.Valid {
			artifactCandidates[artifactID.String] = struct{}{}
		}
	}
	if err := rows.Close(); err != nil {
		return fmt.Errorf("close source project dependent reports: %w", err)
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate source project dependent reports: %w", err)
	}
	for artifactID := range artifactCandidates {
		var storageKey, digest string
		var size uint64
		if err := tx.QueryRowContext(ctx, `
SELECT storage_key, sha256, size_bytes
FROM artifacts
WHERE task_id = ? AND id = ? AND state <> 'deleted'`,
			claim.TaskID, artifactID,
		).Scan(&storageKey, &digest, &size); errors.Is(err, sql.ErrNoRows) {
			continue
		} else if err != nil {
			return fmt.Errorf("read dependent report artifact: %w", err)
		}
		if size > math.MaxInt64 {
			return errors.New("dependent report artifact size is invalid")
		}
		claim.ArtifactIDs = append(claim.ArtifactIDs, artifactID)
		claim.Files = append(claim.Files, taskcleanup.StoredFile{
			Kind: taskcleanup.FileArtifact, TaskID: claim.TaskID,
			RecordID: artifactID, StorageKey: storageKey, SHA256: digest,
			SizeBytes: int64(size),
		})
	}
	runRows, err := tx.QueryContext(ctx, `
SELECT id, job_id
FROM c_analysis_runs
WHERE task_id = ? AND source_project_id = ?
  AND status IN ('succeeded', 'partial', 'failed', 'cancelled')
ORDER BY id`, claim.TaskID, claim.ProjectID)
	if err != nil {
		return fmt.Errorf("list deleting source project C-analysis runs: %w", err)
	}
	for runRows.Next() {
		var runID, jobID string
		if err := runRows.Scan(&runID, &jobID); err != nil {
			runRows.Close()
			return fmt.Errorf("scan deleting source project C-analysis run: %w", err)
		}
		if !uuidPattern.MatchString(runID) || !uuidPattern.MatchString(jobID) {
			runRows.Close()
			return errors.New("deleting source project C-analysis identity is invalid")
		}
		claim.RunIDs = append(claim.RunIDs, runID)
		claim.JobIDs = append(claim.JobIDs, jobID)
	}
	if err := runRows.Close(); err != nil {
		return fmt.Errorf("close deleting source project C-analysis runs: %w", err)
	}
	if err := runRows.Err(); err != nil {
		return fmt.Errorf("iterate deleting source project C-analysis runs: %w", err)
	}
	javaRunRows, err := tx.QueryContext(ctx, `
SELECT id, job_id
FROM java_analysis_runs
WHERE task_id = ? AND source_project_id = ?
  AND status IN ('succeeded', 'partial', 'failed', 'cancelled')
ORDER BY id`, claim.TaskID, claim.ProjectID)
	if err != nil {
		return fmt.Errorf("list deleting source project Java-analysis runs: %w", err)
	}
	for javaRunRows.Next() {
		var runID, jobID string
		if err := javaRunRows.Scan(&runID, &jobID); err != nil {
			javaRunRows.Close()
			return fmt.Errorf("scan deleting source project Java-analysis run: %w", err)
		}
		if !uuidPattern.MatchString(runID) || !uuidPattern.MatchString(jobID) {
			javaRunRows.Close()
			return errors.New(
				"deleting source project Java-analysis identity is invalid",
			)
		}
		claim.JavaRunIDs = append(claim.JavaRunIDs, runID)
		claim.JavaJobIDs = append(claim.JavaJobIDs, jobID)
	}
	if err := javaRunRows.Close(); err != nil {
		return fmt.Errorf("close deleting source project Java-analysis runs: %w", err)
	}
	if err := javaRunRows.Err(); err != nil {
		return fmt.Errorf("iterate deleting source project Java-analysis runs: %w", err)
	}
	return nil
}

func (r *MySQLRepository) RenewSourceProjectDeletion(
	ctx context.Context,
	claim SourceProjectDeletionClaim,
	leaseDuration time.Duration,
) (bool, error) {
	if !validSourceProjectDeletionClaim(claim) || leaseDuration <= 0 ||
		leaseDuration.Microseconds() <= 0 {
		return false, errors.New("source project deletion renewal is invalid")
	}
	result, err := r.db.ExecContext(ctx, `
UPDATE source_project_deletion_operations operation
SET lease_until = DATE_ADD(UTC_TIMESTAMP(6), INTERVAL ? MICROSECOND)
WHERE id = ? AND task_id = ? AND project_id = ? AND status = 'deleting'
  AND fencing_token = ? AND lease_owner = ?
  AND NOT EXISTS (
      SELECT 1
      FROM c_analysis_runs run
      JOIN jobs job ON job.task_id = run.task_id AND job.id = run.job_id
      WHERE run.task_id = operation.task_id
        AND run.source_project_id = operation.project_id
	        AND (
	            job.status IN ('queued', 'leased', 'running', 'cancel_requested') OR
	            run.status IN ('queued', 'running', 'cancel_requested')
	        )
	  )
	  AND NOT EXISTS (
	      SELECT 1
	      FROM java_analysis_runs run
	      JOIN jobs job ON job.task_id = run.task_id AND job.id = run.job_id
	      WHERE run.task_id = operation.task_id
	        AND run.source_project_id = operation.project_id
	        AND (
	            job.status IN ('queued', 'leased', 'running', 'cancel_requested') OR
	            run.status IN ('queued', 'running', 'cancel_requested')
	        )
	  )`, leaseDuration.Microseconds(), claim.OperationID, claim.TaskID,
		claim.ProjectID, claim.Fence, claim.LeaseOwner)
	if err != nil {
		return false, fmt.Errorf("renew source project deletion lease: %w", err)
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("inspect source project deletion renewal: %w", err)
	}
	return changed == 1, nil
}

func (r *MySQLRepository) FinalizeSourceProjectCascadeDeletion(
	ctx context.Context,
	claim SourceProjectDeletionClaim,
) (bool, error) {
	if !validSourceProjectDeletionClaim(claim) {
		return false, errors.New("source project deletion finalization claim is invalid")
	}
	tx, err := r.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return false, fmt.Errorf("begin source project deletion finalization: %w", err)
	}
	defer tx.Rollback()
	var status string
	err = tx.QueryRowContext(ctx, `
SELECT status
FROM source_project_deletion_operations
WHERE id = ? AND task_id = ? AND project_id = ?
  AND status = 'deleting' AND fencing_token = ? AND lease_owner = ?
  AND lease_until > UTC_TIMESTAMP(6)
FOR UPDATE`, claim.OperationID, claim.TaskID, claim.ProjectID,
		claim.Fence, claim.LeaseOwner).Scan(&status)
	if errors.Is(err, sql.ErrNoRows) {
		if err := tx.Commit(); err != nil {
			return false, fmt.Errorf("commit stale source project deletion finalization: %w", err)
		}
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("lock source project deletion finalization: %w", err)
	}
	var active uint8
	if err := tx.QueryRowContext(ctx, `
SELECT EXISTS (
    SELECT 1 FROM (
        SELECT run.status AS run_status, job.status AS job_status
        FROM c_analysis_runs run
        JOIN jobs job ON job.task_id = run.task_id AND job.id = run.job_id
        WHERE run.task_id = ? AND run.source_project_id = ?
        UNION ALL
        SELECT run.status AS run_status, job.status AS job_status
        FROM java_analysis_runs run
        JOIN jobs job ON job.task_id = run.task_id AND job.id = run.job_id
        WHERE run.task_id = ? AND run.source_project_id = ?
    ) active_analysis
    WHERE job_status IN ('queued', 'leased', 'running', 'cancel_requested')
       OR run_status IN ('queued', 'running', 'cancel_requested')
)`, claim.TaskID, claim.ProjectID, claim.TaskID, claim.ProjectID).Scan(
		&active,
	); err != nil {
		return false, fmt.Errorf("recheck active source project analysis jobs: %w", err)
	}
	if active != 0 {
		return false, ErrProjectDeletionInProgress
	}
	if err := deleteRowsByIDs(ctx, tx, "reports", "task_id", claim.TaskID, claim.ReportIDs); err != nil {
		return false, err
	}
	if err := deleteRowsByIDs(ctx, tx, "artifacts", "task_id", claim.TaskID, claim.ArtifactIDs); err != nil {
		return false, err
	}
	eventStatement := `
DELETE FROM task_events
WHERE task_id = ? AND event_type LIKE 'c_analysis.%'
  AND (
      JSON_UNQUOTE(JSON_EXTRACT(payload, '$.project_id')) = ? OR
      JSON_UNQUOTE(JSON_EXTRACT(payload, '$.source_project_id')) = ?`
	eventArguments := []any{claim.TaskID, claim.ProjectID, claim.ProjectID}
	if len(claim.RunIDs) > 0 {
		placeholders := strings.TrimRight(strings.Repeat("?,", len(claim.RunIDs)), ",")
		eventStatement += ` OR
      JSON_UNQUOTE(JSON_EXTRACT(payload, '$.run_id')) IN (` + placeholders + `)`
		eventArguments = append(eventArguments, idsAsAny(claim.RunIDs)...)
	}
	eventStatement += `
  )`
	if _, err := tx.ExecContext(ctx, eventStatement, eventArguments...); err != nil {
		return false, fmt.Errorf("delete source project C-analysis task events: %w", err)
	}
	javaEventStatement := `
DELETE FROM task_events
WHERE task_id = ? AND event_type LIKE 'java_analysis.%'
  AND (
      JSON_UNQUOTE(JSON_EXTRACT(payload, '$.project_id')) = ? OR
      JSON_UNQUOTE(JSON_EXTRACT(payload, '$.source_project_id')) = ?`
	javaEventArguments := []any{claim.TaskID, claim.ProjectID, claim.ProjectID}
	if len(claim.JavaRunIDs) > 0 {
		placeholders := strings.TrimRight(
			strings.Repeat("?,", len(claim.JavaRunIDs)), ",",
		)
		javaEventStatement += ` OR
      JSON_UNQUOTE(JSON_EXTRACT(payload, '$.run_id')) IN (` + placeholders + `)`
		javaEventArguments = append(
			javaEventArguments, idsAsAny(claim.JavaRunIDs)...,
		)
	}
	javaEventStatement += `
  )`
	if _, err := tx.ExecContext(
		ctx, javaEventStatement, javaEventArguments...,
	); err != nil {
		return false, fmt.Errorf(
			"delete source project Java-analysis task events: %w", err,
		)
	}
	if len(claim.RunIDs) > 0 {
		placeholders := strings.TrimRight(strings.Repeat("?,", len(claim.RunIDs)), ",")
		arguments := make([]any, 0, len(claim.RunIDs)+2)
		arguments = append(arguments, claim.TaskID, claim.ProjectID)
		for _, id := range claim.RunIDs {
			arguments = append(arguments, id)
		}
		if _, err := tx.ExecContext(ctx, `
DELETE finding
FROM c_analysis_findings finding
JOIN c_analysis_runs run
  ON run.task_id = finding.task_id AND run.id = finding.run_id
WHERE run.task_id = ? AND run.source_project_id = ?
  AND run.id IN (`+placeholders+`)`, arguments...); err != nil {
			return false, fmt.Errorf("delete source project C-analysis findings: %w", err)
		}
		if _, err := tx.ExecContext(ctx, `
DELETE FROM c_analysis_runs
WHERE task_id = ? AND source_project_id = ? AND id IN (`+placeholders+`)`, arguments...); err != nil {
			return false, fmt.Errorf("delete source project C-analysis runs: %w", err)
		}
		analyzerArguments := make([]any, 0, len(claim.RunIDs)+1)
		analyzerArguments = append(analyzerArguments, claim.TaskID)
		for _, id := range claim.RunIDs {
			analyzerArguments = append(analyzerArguments, id)
		}
		if _, err := tx.ExecContext(ctx, `
DELETE FROM analyzer_runs
WHERE task_id = ? AND id IN (`+placeholders+`)`, analyzerArguments...); err != nil {
			return false, fmt.Errorf("delete source project C-analysis analyzer runs: %w", err)
		}
	}
	if len(claim.JavaRunIDs) > 0 {
		placeholders := strings.TrimRight(
			strings.Repeat("?,", len(claim.JavaRunIDs)), ",",
		)
		arguments := make([]any, 0, len(claim.JavaRunIDs)+2)
		arguments = append(arguments, claim.TaskID, claim.ProjectID)
		arguments = append(arguments, idsAsAny(claim.JavaRunIDs)...)
		if _, err := tx.ExecContext(ctx, `
DELETE finding
FROM java_analysis_findings finding
JOIN java_analysis_runs run
  ON run.task_id = finding.task_id AND run.id = finding.run_id
WHERE run.task_id = ? AND run.source_project_id = ?
  AND run.id IN (`+placeholders+`)`, arguments...); err != nil {
			return false, fmt.Errorf(
				"delete source project Java-analysis findings: %w", err,
			)
		}
		if _, err := tx.ExecContext(ctx, `
DELETE FROM java_analysis_runs
WHERE task_id = ? AND source_project_id = ? AND id IN (`+placeholders+`)`,
			arguments...,
		); err != nil {
			return false, fmt.Errorf(
				"delete source project Java-analysis runs: %w", err,
			)
		}
		analyzerArguments := append(
			[]any{claim.TaskID}, idsAsAny(claim.JavaRunIDs)...,
		)
		if _, err := tx.ExecContext(ctx, `
DELETE FROM analyzer_runs
WHERE task_id = ? AND id IN (`+placeholders+`)`, analyzerArguments...); err != nil {
			return false, fmt.Errorf(
				"delete source project Java-analysis analyzer runs: %w", err,
			)
		}
	}
	if len(claim.JobIDs) > 0 {
		placeholders := strings.TrimRight(strings.Repeat("?,", len(claim.JobIDs)), ",")
		arguments := append([]any{claim.TaskID}, idsAsAny(claim.JobIDs)...)
		if _, err := tx.ExecContext(ctx, `
UPDATE jobs
SET payload = NULL, error_code = NULL, error_message = NULL
WHERE task_id = ? AND kind = 'c_analysis' AND id IN (`+placeholders+`)`,
			arguments...,
		); err != nil {
			return false, fmt.Errorf("scrub source project C-analysis jobs: %w", err)
		}
	}
	if len(claim.JavaJobIDs) > 0 {
		placeholders := strings.TrimRight(
			strings.Repeat("?,", len(claim.JavaJobIDs)), ",",
		)
		arguments := append([]any{claim.TaskID}, idsAsAny(claim.JavaJobIDs)...)
		if _, err := tx.ExecContext(ctx, `
UPDATE jobs
SET payload = NULL, error_code = NULL, error_message = NULL
WHERE task_id = ? AND kind = 'java_analysis' AND id IN (`+placeholders+`)`,
			arguments...,
		); err != nil {
			return false, fmt.Errorf(
				"scrub source project Java-analysis jobs: %w", err,
			)
		}
	}
	if _, err := tx.ExecContext(ctx, `
UPDATE decompile_results
SET symbol_key = 'deleted', diagnostics_json = NULL,
    storage_key = NULL, content_sha256 = NULL, size_bytes = NULL,
    source_offset_bytes = NULL, source_length_bytes = NULL,
    source_start_line = NULL, source_end_line = NULL,
    deleted_at = COALESCE(deleted_at, UTC_TIMESTAMP(6))
WHERE task_id = ? AND analyzer_run_id = ?`, claim.TaskID, claim.ProjectID); err != nil {
		return false, fmt.Errorf("clear source project decompile results: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `
UPDATE decompile_source_projects
SET root_storage_key = NULL, canonical_storage_key = NULL,
    canonical_sha256 = NULL, canonical_size_bytes = NULL,
    manifest_storage_key = NULL, manifest_sha256 = NULL,
    manifest_size_bytes = NULL,
    storage_deleted_at = COALESCE(storage_deleted_at, UTC_TIMESTAMP(6))
WHERE task_id = ? AND id = ? AND deleted_at IS NOT NULL`,
		claim.TaskID, claim.ProjectID,
	); err != nil {
		return false, fmt.Errorf("clear source project storage metadata: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `
DELETE FROM source_project_deletion_tokens
WHERE project_id = ?`, claim.ProjectID); err != nil {
		return false, fmt.Errorf("delete source project confirmation tokens: %w", err)
	}
	result, err := tx.ExecContext(ctx, `
UPDATE source_project_deletion_operations
SET status = 'complete', lease_owner = NULL, lease_until = NULL,
    last_error_code = NULL, last_error_message = NULL,
    completed_at = UTC_TIMESTAMP(6)
WHERE id = ? AND status = 'deleting' AND fencing_token = ? AND lease_owner = ?`,
		claim.OperationID, claim.Fence, claim.LeaseOwner,
	)
	if err != nil {
		return false, fmt.Errorf("complete source project deletion operation: %w", err)
	}
	if changed, err := result.RowsAffected(); err != nil || changed != 1 {
		if err != nil {
			return false, fmt.Errorf("inspect source project deletion completion: %w", err)
		}
		return false, errors.New("source project deletion completion lost its fence")
	}
	if err := audit.Append(ctx, tx, audit.Event{
		Action:     "decompile.project_deletion_cleanup_completed",
		ObjectType: "decompile_project", ObjectID: claim.ProjectID,
		Outcome: audit.OutcomeSuccess,
		Metadata: map[string]any{
			"task_id": claim.TaskID, "operation_id": claim.OperationID,
			"attempt": claim.Attempt, "fencing_token": claim.Fence,
			"c_analysis_runs":        claim.Counts.CAnalysisRuns,
			"c_analysis_findings":    claim.Counts.CAnalysisFindings,
			"java_analysis_runs":     claim.Counts.JavaAnalysisRuns,
			"java_analysis_findings": claim.Counts.JavaAnalysisFindings,
			"reports":                claim.Counts.Reports,
		},
	}); err != nil {
		return false, fmt.Errorf("audit source project deletion completion: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return false, fmt.Errorf("commit source project deletion finalization: %w", err)
	}
	return true, nil
}

func (r *MySQLRepository) FailSourceProjectCascadeDeletion(
	ctx context.Context,
	claim SourceProjectDeletionClaim,
	errorCode string,
) (bool, error) {
	if !validSourceProjectDeletionClaim(claim) || errorCode == "" || len(errorCode) > 128 {
		return false, errors.New("source project deletion failure input is invalid")
	}
	tx, err := r.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return false, fmt.Errorf("begin source project deletion failure: %w", err)
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, `
UPDATE source_project_deletion_operations
SET status = 'failed', lease_owner = NULL, lease_until = NULL,
    available_at = DATE_ADD(UTC_TIMESTAMP(6), INTERVAL 5 SECOND),
    last_error_code = ?,
    last_error_message = 'Source project deletion cleanup will be retried.',
    completed_at = NULL
WHERE id = ? AND status = 'deleting' AND fencing_token = ? AND lease_owner = ?`,
		errorCode, claim.OperationID, claim.Fence, claim.LeaseOwner,
	)
	if err != nil {
		return false, fmt.Errorf("fail source project deletion operation: %w", err)
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("inspect source project deletion failure: %w", err)
	}
	if changed == 0 {
		if err := tx.Commit(); err != nil {
			return false, fmt.Errorf("commit stale source project deletion failure: %w", err)
		}
		return false, nil
	}
	if err := audit.Append(ctx, tx, audit.Event{
		Action:     "decompile.project_deletion_cleanup_failed",
		ObjectType: "decompile_project", ObjectID: claim.ProjectID,
		Outcome: audit.OutcomeFailure,
		Metadata: map[string]any{
			"task_id": claim.TaskID, "operation_id": claim.OperationID,
			"attempt": claim.Attempt, "fencing_token": claim.Fence,
			"error_code": errorCode, "retryable": true,
		},
	}); err != nil {
		return false, fmt.Errorf("audit source project deletion failure: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return false, fmt.Errorf("commit source project deletion failure: %w", err)
	}
	return true, nil
}

func deleteRowsByIDs(
	ctx context.Context,
	tx *sql.Tx,
	table string,
	taskColumn string,
	taskID string,
	ids []string,
) error {
	if len(ids) == 0 {
		return nil
	}
	if table != "reports" && table != "artifacts" {
		return errors.New("source project deletion table is invalid")
	}
	placeholders := strings.TrimRight(strings.Repeat("?,", len(ids)), ",")
	arguments := append([]any{taskID}, idsAsAny(ids)...)
	if _, err := tx.ExecContext(ctx, `DELETE FROM `+table+` WHERE `+taskColumn+` = ? AND id IN (`+placeholders+`)`, arguments...); err != nil {
		return fmt.Errorf("delete source project dependent %s: %w", table, err)
	}
	return nil
}

func idsAsAny(ids []string) []any {
	values := make([]any, len(ids))
	for index, id := range ids {
		values[index] = id
	}
	return values
}

func validSourceProjectDeletionClaim(claim SourceProjectDeletionClaim) bool {
	return uuidPattern.MatchString(claim.OperationID) &&
		uuidPattern.MatchString(claim.TaskID) && uuidPattern.MatchString(claim.ProjectID) &&
		claim.LeaseOwner != "" && len(claim.LeaseOwner) <= 255 &&
		claim.Fence > 0 && claim.Attempt > 0
}

var _ SourceProjectDeletionSweepRepository = (*MySQLRepository)(nil)

package decompile

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"

	"binaryscan/internal/bytecode"
	"binaryscan/internal/queue"
)

func (r *MySQLRepository) FindBytecodeCache(
	ctx context.Context,
	lease queue.Lease,
	payload JobPayload,
	runID string,
	identity BytecodeRunIdentity,
) (BytecodeCacheCandidate, bool, error) {
	nodeID, err := targetNodeID(payload)
	if err != nil || nodeID == 0 || lease.TaskAttemptID == nil ||
		!uuidPattern.MatchString(runID) || !validBytecodeRunIdentity(identity) ||
		!validJobLimits(payload.Limits) {
		return BytecodeCacheCandidate{}, false, ErrRequestConflict
	}
	var candidate BytecodeCacheCandidate
	var resultStatus string
	err = r.db.QueryRowContext(ctx, `
SELECT source_run.id,
       source_run.task_id,
       JSON_UNQUOTE(JSON_EXTRACT(
           source_run.parameters_json, '$.result_status'
       ))
FROM jobs current_job
JOIN tasks current_task ON current_task.id = current_job.task_id
JOIN analyzer_runs current_run
  ON current_run.task_id = current_job.task_id AND current_run.id = ?
JOIN analyzer_runs source_run
  ON source_run.cache_identity = current_run.cache_identity
JOIN tasks source_task ON source_task.id = source_run.task_id
WHERE current_job.id = ?
  AND current_job.task_id = ?
  AND current_job.task_attempt_id = ?
  AND current_job.kind = 'decompile'
  AND current_job.status = 'running'
  AND current_job.lease_owner = ?
  AND current_job.fencing_token = ?
  AND current_job.lease_until > UTC_TIMESTAMP(6)
  AND current_task.status IN (
      'SUCCEEDED', 'PARTIAL_SUCCEEDED', 'FAILED', 'CANCELLED'
  )
  AND current_task.sample_deleted_at IS NULL
  AND current_task.sample_expires_at > UTC_TIMESTAMP(6)
  AND current_task.deleted_at IS NULL
  AND current_run.job_id = current_job.id
  AND current_run.task_attempt_id = current_job.task_attempt_id
  AND current_run.file_node_id = ?
  AND current_run.analyzer_name = ?
  AND current_run.analyzer_version = ?
  AND current_run.cache_identity = ?
  AND current_run.status = 'running'
  AND source_run.id <> current_run.id
  AND source_run.analyzer_name = current_run.analyzer_name
  AND source_run.analyzer_version = current_run.analyzer_version
  AND source_run.status = 'succeeded'
	AND source_run.completed_at IS NOT NULL
  AND source_task.status IN (
      'SUCCEEDED', 'PARTIAL_SUCCEEDED', 'FAILED', 'CANCELLED'
  )
  AND source_task.sample_deleted_at IS NULL
  AND source_task.sample_expires_at > UTC_TIMESTAMP(6)
  AND source_task.deleted_at IS NULL
  AND JSON_UNQUOTE(JSON_EXTRACT(
      source_run.parameters_json, '$.analyzer_parameters_sha256'
  )) = ?
  AND JSON_UNQUOTE(JSON_EXTRACT(
      source_run.parameters_json, '$.cache_parameters_sha256'
  )) = ?
  AND JSON_UNQUOTE(JSON_EXTRACT(
      source_run.parameters_json, '$.reuse_identity_sha256'
  )) = ?
	AND JSON_UNQUOTE(JSON_EXTRACT(
	    source_run.parameters_json, '$.reuse_contract'
	)) = ?
	AND JSON_UNQUOTE(JSON_EXTRACT(
	    source_run.parameters_json, '$.engine_target'
	)) = ?
  AND JSON_UNQUOTE(JSON_EXTRACT(
      source_run.parameters_json, '$.source_sha256'
  )) = ?
  AND JSON_UNQUOTE(JSON_EXTRACT(
      source_run.parameters_json, '$.source_size_bytes'
  )) = ?
  AND JSON_UNQUOTE(JSON_EXTRACT(
      source_run.parameters_json, '$.source_format'
  )) = ?
  AND JSON_UNQUOTE(JSON_EXTRACT(
      source_run.parameters_json, '$.source_architecture'
  )) = ?
  AND JSON_UNQUOTE(JSON_EXTRACT(
      source_run.parameters_json, '$.result_status'
  )) IN ('complete', 'bytecode_only')
  AND JSON_TYPE(JSON_EXTRACT(
      source_run.parameters_json, '$.result_count'
  )) = 'INTEGER'
  AND CAST(JSON_UNQUOTE(JSON_EXTRACT(
      source_run.parameters_json, '$.result_count'
  )) AS UNSIGNED) BETWEEN 1 AND ?
  AND (
      SELECT COUNT(*)
      FROM decompile_results source_result
      WHERE source_result.task_id = source_run.task_id
        AND source_result.analyzer_run_id = source_run.id
        AND source_result.deleted_at IS NULL
  ) = CAST(JSON_UNQUOTE(JSON_EXTRACT(
      source_run.parameters_json, '$.result_count'
  )) AS UNSIGNED)
  AND NOT EXISTS (
      SELECT 1
      FROM decompile_results source_result
      WHERE source_result.task_id = source_run.task_id
        AND source_result.analyzer_run_id = source_run.id
        AND (
            source_result.deleted_at IS NOT NULL OR
            source_result.file_node_id <> source_run.file_node_id OR
            source_result.engine_name <> source_run.analyzer_name OR
            source_result.engine_version <> source_run.analyzer_version OR
            source_result.status <> JSON_UNQUOTE(JSON_EXTRACT(
                source_run.parameters_json, '$.result_status'
            )) OR
			source_result.completed_at IS NULL OR
            source_result.storage_key IS NULL OR
            source_result.content_sha256 IS NULL OR
            source_result.size_bytes IS NULL OR
			source_result.size_bytes = 0 OR
			source_result.diagnostics_json IS NULL OR
			OCTET_LENGTH(source_result.diagnostics_json) NOT BETWEEN 1 AND ?
        )
  )
	AND (
	    SELECT COALESCE(SUM(source_result.size_bytes), 0)
	    FROM decompile_results source_result
	    WHERE source_result.task_id = source_run.task_id
	      AND source_result.analyzer_run_id = source_run.id
	      AND source_result.deleted_at IS NULL
	) BETWEEN 1 AND ?
	AND (
	    SELECT COALESCE(SUM(OCTET_LENGTH(
	        source_result.diagnostics_json
	    )), 0)
	    FROM decompile_results source_result
	    WHERE source_result.task_id = source_run.task_id
	      AND source_result.analyzer_run_id = source_run.id
	      AND source_result.deleted_at IS NULL
	) BETWEEN 1 AND ?
ORDER BY source_run.completed_at DESC, source_run.id DESC
LIMIT 1`,
		runID, lease.JobID, lease.TaskID, *lease.TaskAttemptID,
		lease.Owner, lease.FencingToken, nodeID, identity.EngineName,
		identity.EngineVersion, identity.ReuseIdentitySHA,
		identity.AnalyzerParametersSHA, identity.CacheParametersSHA,
		identity.ReuseIdentitySHA, bytecodeReuseContract, payload.Engine.Target,
		payload.Target.SHA256,
		fmt.Sprint(payload.Target.SizeBytes), payload.Target.Format,
		payload.Target.Architecture, bytecodeCacheResultLimit(payload.Limits),
		maxBytecodeDiagnosticsBytes, payload.Limits.MaxOutputBytes,
		maxBytecodeCacheDiagnosticsBytes,
	).Scan(&candidate.RunID, &candidate.TaskID, &resultStatus)
	if errors.Is(err, sql.ErrNoRows) {
		return BytecodeCacheCandidate{}, false, nil
	}
	if err != nil {
		return BytecodeCacheCandidate{}, false,
			fmt.Errorf("find bytecode cache candidate: %w", err)
	}
	candidate.ResultStatus = bytecode.Status(resultStatus)

	rows, err := r.db.QueryContext(ctx, `
SELECT result.id, result.symbol_key, result.language, result.status,
       result.storage_key, result.content_sha256, result.size_bytes,
       result.diagnostics_json
FROM decompile_results result
WHERE result.task_id = ?
  AND result.analyzer_run_id = ?
  AND result.deleted_at IS NULL
	AND result.size_bytes BETWEEN 1 AND ?
	AND OCTET_LENGTH(result.diagnostics_json) BETWEEN 1 AND ?
ORDER BY CAST(result.symbol_key AS BINARY), result.id
LIMIT ?`, candidate.TaskID, candidate.RunID, payload.Limits.MaxOutputBytes,
		maxBytecodeDiagnosticsBytes, bytecodeCacheResultLimit(payload.Limits)+1)
	if err != nil {
		return BytecodeCacheCandidate{}, false,
			fmt.Errorf("read bytecode cache candidate: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var value BytecodeCachedResult
		if err := rows.Scan(
			&value.ID, &value.SymbolKey, &value.Language, &value.Status,
			&value.StorageKey, &value.SHA256, &value.SizeBytes,
			&value.Diagnostics,
		); err != nil {
			return BytecodeCacheCandidate{}, false,
				fmt.Errorf("scan bytecode cache candidate: %w", err)
		}
		candidate.Results = append(candidate.Results, value)
	}
	if err := rows.Err(); err != nil {
		return BytecodeCacheCandidate{}, false,
			fmt.Errorf("iterate bytecode cache candidate: %w", err)
	}
	if !validBytecodeCacheCandidate(candidate, payload.Limits) {
		return BytecodeCacheCandidate{}, false, nil
	}
	return candidate, true, nil
}

func (r *MySQLRepository) PublishBytecodeCacheHit(
	ctx context.Context,
	lease queue.Lease,
	payload JobPayload,
	runID string,
	identity BytecodeRunIdentity,
	candidate BytecodeCacheCandidate,
	project PublishedSourceProject,
	results []BytecodePublishedResult,
) (returnErr error) {
	nodeID, err := targetNodeID(payload)
	if err != nil || nodeID == 0 || lease.TaskAttemptID == nil ||
		!uuidPattern.MatchString(runID) || !validBytecodeRunIdentity(identity) ||
		!validJobLimits(payload.Limits) ||
		!validBytecodeCacheCandidate(candidate, payload.Limits) ||
		!validBytecodeCachePublication(runID, candidate, results) ||
		!validPublishedSourceProject(runID, project, len(results)) {
		return ErrRequestConflict
	}
	tx, err := r.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return fmt.Errorf("begin bytecode cache publication: %w", err)
	}
	defer func() {
		if rollbackErr := tx.Rollback(); rollbackErr != nil &&
			!errors.Is(rollbackErr, sql.ErrTxDone) {
			returnErr = errors.Join(returnErr, rollbackErr)
		}
	}()
	if err := validateBytecodePublishingLease(
		ctx, tx, lease, payload, runID, identity, "running", true,
	); err != nil {
		return err
	}
	locked, err := lockBytecodeCacheCandidate(
		ctx, tx, payload, identity, candidate,
	)
	if err != nil {
		return err
	}
	if !sameBytecodeCacheCandidate(candidate, locked) {
		return errBytecodeCacheStale
	}

	for _, value := range results {
		cacheKey := bytecodeResultCacheKey(
			payload, lease.JobID, identity, value.SymbolKey,
		)
		if _, err := tx.ExecContext(ctx, `
INSERT INTO decompile_results (
    id, task_id, file_node_id, analyzer_run_id, cache_key,
    symbol_key, language, engine_name, engine_version, status,
    storage_key, content_sha256, size_bytes, diagnostics_json,
    completed_at
) VALUES (
    ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, UTC_TIMESTAMP(6)
)`,
			value.ID, lease.TaskID, nodeID, runID, cacheKey,
			value.SymbolKey, value.Language, identity.EngineName,
			identity.EngineVersion, value.Status, value.StorageKey,
			value.SHA256, value.SizeBytes, []byte(value.Diagnostics),
		); err != nil {
			return fmt.Errorf("insert bytecode cached result: %w", err)
		}
	}
	if err := insertPublishedSourceProject(
		ctx, tx, lease.TaskID, nodeID, lease.JobID,
		identity.EngineName, identity.EngineVersion,
		string(candidate.ResultStatus), project,
	); err != nil {
		return fmt.Errorf("insert cached bytecode source project: %w", err)
	}
	result, err := tx.ExecContext(ctx, `
UPDATE analyzer_runs
SET status = 'succeeded',
    exit_code = 0,
    error_code = NULL,
    error_message = NULL,
    parameters_json = JSON_SET(
        parameters_json,
        '$.result_status', ?,
        '$.result_count', ?,
        '$.cache_hit', TRUE,
        '$.cache_lookup', 'hit',
        '$.cache_source_task_id', ?,
        '$.cache_source_run_id', ?,
        '$.cache_copy_mode', 'private_verified_copy'
    ),
    completed_at = UTC_TIMESTAMP(6)
WHERE id = ?
  AND task_id = ?
  AND job_id = ?
  AND status = 'running'`,
		string(candidate.ResultStatus), len(results), candidate.TaskID,
		candidate.RunID, runID, lease.TaskID, lease.JobID,
	)
	if err != nil {
		return fmt.Errorf("complete bytecode cache hit: %w", err)
	}
	if err := requireBytecodeOne(result); err != nil {
		return err
	}
	if err := validateBytecodePublishingLease(
		ctx, tx, lease, payload, runID, identity, "succeeded", false,
	); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return errors.Join(
			errBytecodeCacheCommitUncertain,
			fmt.Errorf("commit bytecode cache publication: %w", err),
		)
	}
	return nil
}

func lockBytecodeCacheCandidate(
	ctx context.Context,
	tx *sql.Tx,
	payload JobPayload,
	identity BytecodeRunIdentity,
	candidate BytecodeCacheCandidate,
) (BytecodeCacheCandidate, error) {
	locked := BytecodeCacheCandidate{
		RunID: candidate.RunID, TaskID: candidate.TaskID,
	}
	rows, err := tx.QueryContext(ctx, `
SELECT JSON_UNQUOTE(JSON_EXTRACT(
           run.parameters_json, '$.result_status'
       )),
       result.id, result.symbol_key, result.language, result.status,
       result.storage_key, result.content_sha256, result.size_bytes,
       result.diagnostics_json
FROM analyzer_runs run
JOIN tasks task ON task.id = run.task_id
JOIN decompile_results result
  ON result.task_id = run.task_id AND result.analyzer_run_id = run.id
WHERE run.id = ?
  AND run.task_id = ?
  AND run.analyzer_name = ?
  AND run.analyzer_version = ?
  AND run.cache_identity = ?
  AND run.status = 'succeeded'
	AND run.completed_at IS NOT NULL
  AND task.status IN (
      'SUCCEEDED', 'PARTIAL_SUCCEEDED', 'FAILED', 'CANCELLED'
  )
  AND task.sample_deleted_at IS NULL
  AND task.sample_expires_at > UTC_TIMESTAMP(6)
  AND task.deleted_at IS NULL
  AND JSON_UNQUOTE(JSON_EXTRACT(
      run.parameters_json, '$.analyzer_parameters_sha256'
  )) = ?
  AND JSON_UNQUOTE(JSON_EXTRACT(
      run.parameters_json, '$.cache_parameters_sha256'
  )) = ?
  AND JSON_UNQUOTE(JSON_EXTRACT(
      run.parameters_json, '$.reuse_identity_sha256'
  )) = ?
	AND JSON_UNQUOTE(JSON_EXTRACT(
	    run.parameters_json, '$.reuse_contract'
	)) = ?
	AND JSON_UNQUOTE(JSON_EXTRACT(
	    run.parameters_json, '$.engine_target'
	)) = ?
  AND JSON_UNQUOTE(JSON_EXTRACT(
      run.parameters_json, '$.source_sha256'
  )) = ?
  AND JSON_UNQUOTE(JSON_EXTRACT(
      run.parameters_json, '$.source_size_bytes'
  )) = ?
  AND JSON_UNQUOTE(JSON_EXTRACT(
      run.parameters_json, '$.source_format'
  )) = ?
  AND JSON_UNQUOTE(JSON_EXTRACT(
      run.parameters_json, '$.source_architecture'
  )) = ?
  AND JSON_UNQUOTE(JSON_EXTRACT(
      run.parameters_json, '$.result_status'
  )) IN ('complete', 'bytecode_only')
  AND JSON_TYPE(JSON_EXTRACT(
      run.parameters_json, '$.result_count'
  )) = 'INTEGER'
  AND CAST(JSON_UNQUOTE(JSON_EXTRACT(
      run.parameters_json, '$.result_count'
  )) AS UNSIGNED) = ?
	AND (
	    SELECT COUNT(*)
	    FROM decompile_results counted_result
	    WHERE counted_result.task_id = run.task_id
	      AND counted_result.analyzer_run_id = run.id
	) = ?
	AND NOT EXISTS (
	    SELECT 1
	    FROM decompile_results invalid_result
	    WHERE invalid_result.task_id = run.task_id
	      AND invalid_result.analyzer_run_id = run.id
	      AND (
	          invalid_result.deleted_at IS NOT NULL OR
	          invalid_result.file_node_id <> run.file_node_id OR
	          invalid_result.engine_name <> run.analyzer_name OR
	          invalid_result.engine_version <> run.analyzer_version OR
	          invalid_result.status <> JSON_UNQUOTE(JSON_EXTRACT(
	              run.parameters_json, '$.result_status'
	          )) OR
	          invalid_result.completed_at IS NULL OR
	          invalid_result.storage_key IS NULL OR
	          invalid_result.content_sha256 IS NULL OR
	          invalid_result.size_bytes IS NULL OR
	          invalid_result.size_bytes = 0 OR
	          invalid_result.diagnostics_json IS NULL OR
	          OCTET_LENGTH(invalid_result.diagnostics_json) NOT BETWEEN 1 AND ?
	      )
	)
	AND (
	    SELECT COALESCE(SUM(sized_result.size_bytes), 0)
	    FROM decompile_results sized_result
	    WHERE sized_result.task_id = run.task_id
	      AND sized_result.analyzer_run_id = run.id
	) BETWEEN 1 AND ?
	AND (
	    SELECT COALESCE(SUM(OCTET_LENGTH(
	        diagnosed_result.diagnostics_json
	    )), 0)
	    FROM decompile_results diagnosed_result
	    WHERE diagnosed_result.task_id = run.task_id
	      AND diagnosed_result.analyzer_run_id = run.id
	) BETWEEN 1 AND ?
  AND result.deleted_at IS NULL
  AND result.file_node_id = run.file_node_id
  AND result.engine_name = run.analyzer_name
  AND result.engine_version = run.analyzer_version
  AND result.status = JSON_UNQUOTE(JSON_EXTRACT(
      run.parameters_json, '$.result_status'
  ))
  AND result.storage_key IS NOT NULL
  AND result.content_sha256 IS NOT NULL
  AND result.size_bytes IS NOT NULL
  AND result.size_bytes > 0
	AND result.completed_at IS NOT NULL
	AND OCTET_LENGTH(result.diagnostics_json) BETWEEN 1 AND ?
ORDER BY CAST(result.symbol_key AS BINARY), result.id
FOR SHARE`,
		candidate.RunID, candidate.TaskID, identity.EngineName,
		identity.EngineVersion, identity.ReuseIdentitySHA,
		identity.AnalyzerParametersSHA, identity.CacheParametersSHA,
		identity.ReuseIdentitySHA, bytecodeReuseContract, payload.Engine.Target,
		payload.Target.SHA256,
		fmt.Sprint(payload.Target.SizeBytes), payload.Target.Format,
		payload.Target.Architecture, len(candidate.Results),
		len(candidate.Results), maxBytecodeDiagnosticsBytes,
		payload.Limits.MaxOutputBytes, maxBytecodeCacheDiagnosticsBytes,
		maxBytecodeDiagnosticsBytes,
	)
	if err != nil {
		return BytecodeCacheCandidate{},
			fmt.Errorf("lock bytecode cache candidate: %w", err)
	}
	defer rows.Close()
	var resultStatus string
	for rows.Next() {
		var value BytecodeCachedResult
		if err := rows.Scan(
			&resultStatus, &value.ID, &value.SymbolKey, &value.Language,
			&value.Status, &value.StorageKey, &value.SHA256, &value.SizeBytes,
			&value.Diagnostics,
		); err != nil {
			return BytecodeCacheCandidate{},
				fmt.Errorf("scan locked bytecode cache candidate: %w", err)
		}
		if locked.ResultStatus != "" &&
			locked.ResultStatus != bytecode.Status(resultStatus) {
			return BytecodeCacheCandidate{}, errBytecodeCacheStale
		}
		locked.ResultStatus = bytecode.Status(resultStatus)
		locked.Results = append(locked.Results, value)
	}
	if err := rows.Err(); err != nil {
		return BytecodeCacheCandidate{},
			fmt.Errorf("iterate locked bytecode cache candidate: %w", err)
	}
	if !validBytecodeCacheCandidate(locked, payload.Limits) {
		return BytecodeCacheCandidate{}, errBytecodeCacheStale
	}
	return locked, nil
}

func validBytecodeCachePublication(
	runID string,
	candidate BytecodeCacheCandidate,
	results []BytecodePublishedResult,
) bool {
	if len(results) != len(candidate.Results) ||
		!validBytecodePublicationStatus(candidate.ResultStatus, results) {
		return false
	}
	for index, value := range results {
		cached := candidate.Results[index]
		if !validBytecodePublishedResult(runID, value) ||
			value.SymbolKey != cached.SymbolKey ||
			value.Language != cached.Language || value.Status != cached.Status ||
			value.SHA256 != cached.SHA256 || value.SizeBytes != cached.SizeBytes ||
			!jsonEqual(value.Diagnostics, cached.Diagnostics) {
			return false
		}
	}
	return true
}

func sameBytecodeCacheCandidate(
	left BytecodeCacheCandidate,
	right BytecodeCacheCandidate,
) bool {
	if left.RunID != right.RunID || left.TaskID != right.TaskID ||
		left.ResultStatus != right.ResultStatus ||
		len(left.Results) != len(right.Results) {
		return false
	}
	for index := range left.Results {
		first, second := left.Results[index], right.Results[index]
		if first.ID != second.ID || first.SymbolKey != second.SymbolKey ||
			first.Language != second.Language || first.Status != second.Status ||
			first.StorageKey != second.StorageKey || first.SHA256 != second.SHA256 ||
			first.SizeBytes != second.SizeBytes ||
			!jsonEqual(first.Diagnostics, second.Diagnostics) {
			return false
		}
	}
	return true
}

func jsonEqual(left, right json.RawMessage) bool {
	// Candidate diagnostics are copied byte-for-byte. Exact comparison avoids
	// lossy float64 normalization of large JSON numbers and fails closed if a
	// source row changes between discovery and its publication lock.
	return json.Valid(left) && json.Valid(right) && bytes.Equal(left, right)
}

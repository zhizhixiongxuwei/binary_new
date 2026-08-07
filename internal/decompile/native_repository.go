package decompile

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

	"binaryscan/internal/queue"
)

func (r *MySQLRepository) BeginNativeRun(
	ctx context.Context,
	lease queue.Lease,
	payload JobPayload,
	runID string,
	engineVersion string,
	parameterKey string,
) error {
	nodeID, err := targetNodeID(payload)
	if err != nil || nodeID == 0 || !uuidPattern.MatchString(runID) ||
		!safeEngineVersion(engineVersion) ||
		!sha256Pattern.MatchString(parameterKey) ||
		!validJobLimits(payload.Limits) ||
		lease.TaskAttemptID == nil {
		return ErrRequestConflict
	}
	tx, err := r.db.BeginTx(ctx, &sql.TxOptions{
		Isolation: sql.LevelReadCommitted,
	})
	if err != nil {
		return fmt.Errorf("begin native analyzer run: %w", err)
	}
	defer tx.Rollback()
	var (
		storageKey, digest, format, architecture string
		size                                     uint64
	)
	err = tx.QueryRowContext(ctx, `
SELECT node.storage_key, node.sha256, node.size_bytes, node.format,
       node.architecture
FROM jobs job
JOIN tasks task ON task.id = job.task_id
JOIN task_attempts attempt
  ON attempt.task_id = job.task_id AND attempt.id = job.task_attempt_id
JOIN file_nodes node ON node.task_id = task.id AND node.id = ?
WHERE job.id = ?
  AND job.task_id = ?
  AND job.task_attempt_id = ?
  AND job.kind = 'decompile'
  AND job.status = 'running'
  AND job.lease_owner = ?
  AND job.fencing_token = ?
  AND job.lease_until > UTC_TIMESTAMP(6)
  AND task.status IN ('SUCCEEDED', 'PARTIAL_SUCCEEDED', 'FAILED', 'CANCELLED')
  AND task.sample_deleted_at IS NULL
  AND task.sample_expires_at > UTC_TIMESTAMP(6)
  AND task.deleted_at IS NULL
  AND attempt.status IN ('succeeded', 'failed', 'cancelled')
FOR UPDATE`,
		nodeID, lease.JobID, lease.TaskID, *lease.TaskAttemptID,
		lease.Owner, lease.FencingToken,
	).Scan(&storageKey, &digest, &size, &format, &architecture)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrSourceUnavailable
	}
	if err != nil {
		return fmt.Errorf("lock native decompile source: %w", err)
	}
	if storageKey != payload.Target.StorageKey ||
		digest != payload.Target.SHA256 ||
		size != payload.Target.SizeBytes ||
		format != payload.Target.Format ||
		architecture != payload.Target.Architecture {
		return ErrRequestConflict
	}
	var alreadyPublished uint8
	if err := tx.QueryRowContext(ctx, `
SELECT EXISTS (
    SELECT 1
    FROM analyzer_runs
    WHERE task_id = ?
      AND task_attempt_id = ?
      AND job_id = ?
      AND file_node_id = ?
      AND analyzer_name = 'ghidra'
      AND analyzer_version = ?
      AND status = 'succeeded'
      AND JSON_UNQUOTE(JSON_EXTRACT(
          parameters_json, '$.cache_parameters_sha256'
      )) = ?
      AND JSON_UNQUOTE(JSON_EXTRACT(
          parameters_json, '$.source_storage_key'
      )) = ?
      AND JSON_UNQUOTE(JSON_EXTRACT(
          parameters_json, '$.source_sha256'
      )) = ?
      AND JSON_UNQUOTE(JSON_EXTRACT(
          parameters_json, '$.source_size_bytes'
      )) = ?
      AND JSON_UNQUOTE(JSON_EXTRACT(
          parameters_json, '$.source_format'
      )) = ?
      AND JSON_UNQUOTE(JSON_EXTRACT(
          parameters_json, '$.source_architecture'
      )) = ?
      AND EXISTS (
          SELECT 1
          FROM decompile_results result
          WHERE result.task_id = analyzer_runs.task_id
            AND result.analyzer_run_id = analyzer_runs.id
            AND result.file_node_id = analyzer_runs.file_node_id
            AND result.engine_name = 'ghidra'
            AND result.engine_version = analyzer_runs.analyzer_version
            AND result.status = 'complete'
            AND result.deleted_at IS NULL
      )
)`,
		lease.TaskID, *lease.TaskAttemptID, lease.JobID, nodeID, engineVersion,
		parameterKey, payload.Target.StorageKey, payload.Target.SHA256,
		fmt.Sprint(payload.Target.SizeBytes), payload.Target.Format,
		payload.Target.Architecture,
	).Scan(&alreadyPublished); err != nil {
		return fmt.Errorf("inspect native analyzer replay: %w", err)
	}
	if alreadyPublished != 0 {
		return errNativeAlreadyPublished
	}
	if _, err := tx.ExecContext(ctx, `
UPDATE analyzer_runs
SET status = 'failed',
    error_code = 'worker_replaced',
    error_message = 'A newer fenced worker attempt replaced this run.',
    completed_at = UTC_TIMESTAMP(6)
WHERE task_id = ?
  AND task_attempt_id = ?
  AND job_id = ?
  AND analyzer_name = 'ghidra'
  AND status IN ('queued', 'running')`,
		lease.TaskID, *lease.TaskAttemptID, lease.JobID,
	); err != nil {
		return fmt.Errorf("fence prior native analyzer runs: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `
INSERT INTO analyzer_runs (
    id, task_id, task_attempt_id, job_id, file_node_id,
    analyzer_name, analyzer_version, parameters_json, status, started_at
) VALUES (
	?, ?, ?, ?, ?, 'ghidra', ?,
    JSON_OBJECT(
        'job_attempt', ?, 'job_fencing_token', ?,
        'payload_schema_version', ?,
        'cache_parameters_sha256', ?,
        'source_storage_key', ?, 'source_sha256', ?,
        'source_size_bytes', ?, 'source_format', ?,
        'source_architecture', ?
    ),
    'running', UTC_TIMESTAMP(6)
)`,
		runID, lease.TaskID, *lease.TaskAttemptID, lease.JobID, nodeID, engineVersion,
		lease.Attempt, lease.FencingToken, payload.SchemaVersion, parameterKey,
		payload.Target.StorageKey, payload.Target.SHA256,
		payload.Target.SizeBytes, payload.Target.Format,
		payload.Target.Architecture,
	); err != nil {
		return fmt.Errorf("create native analyzer run: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit native analyzer run: %w", err)
	}
	return nil
}

func (r *MySQLRepository) PublishNativeRun(
	ctx context.Context,
	lease queue.Lease,
	payload JobPayload,
	runID string,
	engineVersion string,
	parameterKey string,
	completeness string,
	publish NativeResultPublisher,
) (returnErr error) {
	nodeID, err := targetNodeID(payload)
	if err != nil || nodeID == 0 || publish == nil ||
		!safeEngineVersion(engineVersion) ||
		!sha256Pattern.MatchString(parameterKey) ||
		(completeness != "complete" && completeness != "partial") ||
		!validJobLimits(payload.Limits) ||
		lease.TaskAttemptID == nil {
		return ErrRequestConflict
	}
	tx, err := r.db.BeginTx(ctx, &sql.TxOptions{
		Isolation: sql.LevelReadCommitted,
	})
	if err != nil {
		return fmt.Errorf("begin native result publication: %w", err)
	}
	finished := false
	commitAttempted := false
	published := false
	cleanupPublished := func() {}
	defer func() {
		if !finished {
			rollbackErr := tx.Rollback()
			if rollbackErr != nil && !errors.Is(rollbackErr, sql.ErrTxDone) {
				returnErr = errors.Join(
					returnErr,
					fmt.Errorf("rollback native result publication: %w", rollbackErr),
				)
			}
		}
		if returnErr != nil && published && !commitAttempted {
			cleanupPublished()
		}
	}()
	var marker uint8
	err = tx.QueryRowContext(ctx, `
SELECT 1
FROM jobs job
JOIN tasks task ON task.id = job.task_id
JOIN analyzer_runs run
  ON run.task_id = job.task_id AND run.id = ?
WHERE job.id = ?
  AND job.task_id = ?
  AND job.task_attempt_id = ?
  AND job.kind = 'decompile'
  AND job.status = 'running'
  AND job.lease_owner = ?
  AND job.fencing_token = ?
  AND job.lease_until > UTC_TIMESTAMP(6)
  AND task.sample_deleted_at IS NULL
  AND task.sample_expires_at > UTC_TIMESTAMP(6)
  AND task.deleted_at IS NULL
  AND run.job_id = job.id
  AND run.task_attempt_id = job.task_attempt_id
  AND run.file_node_id = ?
  AND run.analyzer_name = 'ghidra'
  AND run.analyzer_version = ?
  AND run.status = 'running'
  AND JSON_UNQUOTE(JSON_EXTRACT(
      run.parameters_json, '$.job_attempt'
  )) = ?
  AND JSON_UNQUOTE(JSON_EXTRACT(
      run.parameters_json, '$.job_fencing_token'
  )) = ?
  AND JSON_UNQUOTE(JSON_EXTRACT(
      run.parameters_json, '$.cache_parameters_sha256'
  )) = ?
  AND JSON_UNQUOTE(JSON_EXTRACT(
      run.parameters_json, '$.source_storage_key'
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
FOR UPDATE`,
		runID, lease.JobID, lease.TaskID, *lease.TaskAttemptID, lease.Owner,
		lease.FencingToken, nodeID, engineVersion, fmt.Sprint(lease.Attempt),
		fmt.Sprint(lease.FencingToken), parameterKey,
		payload.Target.StorageKey, payload.Target.SHA256,
		fmt.Sprint(payload.Target.SizeBytes), payload.Target.Format,
		payload.Target.Architecture,
	).Scan(&marker)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrRequestConflict
	}
	if err != nil {
		return fmt.Errorf("validate native result publication lease: %w", err)
	}
	results, cleanup, err := publish(ctx)
	if err != nil {
		return fmt.Errorf("publish native result files: %w", err)
	}
	published = true
	if cleanup != nil {
		cleanupPublished = cleanup
	}
	if len(results) == 0 || len(results) > payload.Limits.MaxArtifacts {
		return ErrRequestConflict
	}
	var totalSize uint64
	for _, value := range results {
		if !validNativePublishedResult(runID, value) {
			return ErrRequestConflict
		}
		if value.SizeBytes > uint64(payload.Limits.MaxOutputBytes)-totalSize {
			return ErrRequestConflict
		}
		totalSize += value.SizeBytes
		cache := nativeResultCacheKey(
			payload, lease.JobID, engineVersion, parameterKey, value.SymbolKey,
		)
		if _, err := tx.ExecContext(ctx, `
INSERT INTO decompile_results (
    id, task_id, file_node_id, analyzer_run_id, cache_key,
    symbol_key, language, engine_name, engine_version, status,
    storage_key, content_sha256, size_bytes, diagnostics_json,
    completed_at
) VALUES (
    ?, ?, ?, ?, ?, ?, 'c', 'ghidra', ?, 'complete',
    ?, ?, ?, ?, UTC_TIMESTAMP(6)
)`,
			value.ID, lease.TaskID, nodeID, runID,
			cache, value.SymbolKey, engineVersion,
			value.StorageKey, value.SHA256, value.SizeBytes,
			[]byte(value.Diagnostics),
		); err != nil {
			return fmt.Errorf("insert native decompile result: %w", err)
		}
	}
	result, err := tx.ExecContext(ctx, `
UPDATE analyzer_runs
SET status = ?,
    exit_code = 0,
    error_code = NULL,
    error_message = NULL,
    completed_at = UTC_TIMESTAMP(6)
WHERE id = ?
  AND task_id = ?
  AND job_id = ?
  AND status = 'running'`,
		nativeRunStatus(completeness), runID, lease.TaskID, lease.JobID,
	)
	if err != nil {
		return fmt.Errorf("complete native analyzer run: %w", err)
	}
	if err := requireNativeOne(result); err != nil {
		return err
	}
	if err := revalidateNativePublishingLease(
		ctx, tx, lease, payload, runID, engineVersion, parameterKey,
		nativeRunStatus(completeness),
	); err != nil {
		return err
	}
	commitAttempted = true
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit native result publication: %w", err)
	}
	finished = true
	return nil
}

func revalidateNativePublishingLease(
	ctx context.Context,
	tx *sql.Tx,
	lease queue.Lease,
	payload JobPayload,
	runID string,
	engineVersion string,
	parameterKey string,
	runStatus string,
) error {
	nodeID, nodeErr := targetNodeID(payload)
	if lease.TaskAttemptID == nil || nodeErr != nil || nodeID == 0 {
		return ErrRequestConflict
	}
	var marker uint8
	err := tx.QueryRowContext(ctx, `
SELECT 1
FROM jobs job
JOIN tasks task ON task.id = job.task_id
JOIN analyzer_runs run
  ON run.task_id = job.task_id AND run.id = ?
WHERE job.id = ?
  AND job.task_id = ?
  AND job.task_attempt_id = ?
  AND job.kind = 'decompile'
  AND job.status = 'running'
  AND job.lease_owner = ?
  AND job.fencing_token = ?
  AND job.lease_until > UTC_TIMESTAMP(6)
  AND task.sample_deleted_at IS NULL
  AND task.sample_expires_at > UTC_TIMESTAMP(6)
  AND task.deleted_at IS NULL
  AND run.job_id = job.id
  AND run.task_attempt_id = job.task_attempt_id
  AND run.file_node_id = ?
  AND run.analyzer_name = 'ghidra'
  AND run.analyzer_version = ?
  AND run.status = ?
  AND JSON_UNQUOTE(JSON_EXTRACT(
      run.parameters_json, '$.job_attempt'
  )) = ?
  AND JSON_UNQUOTE(JSON_EXTRACT(
      run.parameters_json, '$.job_fencing_token'
  )) = ?
  AND JSON_UNQUOTE(JSON_EXTRACT(
      run.parameters_json, '$.cache_parameters_sha256'
  )) = ?
  AND JSON_UNQUOTE(JSON_EXTRACT(
      run.parameters_json, '$.source_storage_key'
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
  )) = ?`,
		runID, lease.JobID, lease.TaskID, *lease.TaskAttemptID, lease.Owner,
		lease.FencingToken, nodeID, engineVersion, runStatus,
		fmt.Sprint(lease.Attempt),
		fmt.Sprint(lease.FencingToken), parameterKey,
		payload.Target.StorageKey, payload.Target.SHA256,
		fmt.Sprint(payload.Target.SizeBytes), payload.Target.Format,
		payload.Target.Architecture,
	).Scan(&marker)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrRequestConflict
	}
	if err != nil {
		return fmt.Errorf("revalidate native result publication lease: %w", err)
	}
	return nil
}

func nativeRunStatus(completeness string) string {
	if completeness == "partial" {
		return "partial"
	}
	return "succeeded"
}

func (r *MySQLRepository) FailNativeRun(
	ctx context.Context,
	lease queue.Lease,
	runID string,
	code string,
	message string,
) error {
	if !uuidPattern.MatchString(runID) || code == "" || len(code) > 128 ||
		message == "" || len(message) > 2048 {
		return ErrInvalidInput
	}
	result, err := r.db.ExecContext(ctx, `
UPDATE analyzer_runs run
JOIN jobs job ON job.task_id = run.task_id AND job.id = run.job_id
SET run.status = 'failed',
    run.error_code = ?,
    run.error_message = ?,
    run.completed_at = UTC_TIMESTAMP(6)
WHERE run.id = ?
  AND run.task_id = ?
  AND run.task_attempt_id = job.task_attempt_id
  AND run.status = 'running'
  AND job.id = ?
  AND job.kind = 'decompile'
  AND job.status IN ('leased', 'running', 'cancel_requested')
  AND job.lease_owner = ?
  AND job.fencing_token = ?`,
		code, message, runID, lease.TaskID, lease.JobID,
		lease.Owner, lease.FencingToken,
	)
	if err != nil {
		return fmt.Errorf("fail native analyzer run: %w", err)
	}
	return requireNativeOne(result)
}

func validNativePublishedResult(
	runID string,
	value NativePublishedResult,
) bool {
	return uuidPattern.MatchString(value.ID) &&
		value.ID == nativeResultID(runID, value.SymbolKey) &&
		value.SymbolKey != "" && len(value.SymbolKey) <= 512 &&
		value.StorageKey == "decompile/"+value.ID+"/source.c" &&
		sha256Pattern.MatchString(value.SHA256) &&
		value.SizeBytes > 0 && len(value.Diagnostics) > 0 &&
		json.Valid(value.Diagnostics)
}

func nativeResultCacheKey(
	payload JobPayload,
	jobID string,
	engineVersion string,
	parameterKey string,
	symbolKey string,
) string {
	// cache_key is also the globally unique identity of this materialized row.
	// Bind it to the durable job ID so retries remain stable while a later,
	// separately authorized job cannot collide before cross-job cache reuse is
	// implemented explicitly. Run IDs and fencing tokens stay retry-local.
	digest := sha256.Sum256([]byte(
		"binaryscan-native-result-cache-v3\x00" +
			payload.TaskID + "\x00" + jobID + "\x00" +
			payload.Target.FileNodeID + "\x00" +
			payload.Target.SHA256 + "\x00" + payload.Target.Format + "\x00" +
			payload.Target.Architecture + "\x00ghidra\x00" +
			engineVersion + "\x00" + parameterKey + "\x00" + symbolKey,
	))
	return hex.EncodeToString(digest[:])
}

func requireNativeOne(result sql.Result) error {
	affected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if affected != 1 {
		return ErrRequestConflict
	}
	return nil
}

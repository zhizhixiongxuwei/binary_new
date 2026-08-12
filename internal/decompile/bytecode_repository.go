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
	"strings"
	"unicode/utf8"

	"binaryscan/internal/bytecode"
	"binaryscan/internal/queue"
)

func (r *MySQLRepository) BeginBytecodeRun(
	ctx context.Context,
	lease queue.Lease,
	payload JobPayload,
	runID string,
	identity BytecodeRunIdentity,
) error {
	nodeID, err := targetNodeID(payload)
	if err != nil || nodeID == 0 || !uuidPattern.MatchString(runID) ||
		!validBytecodeRunIdentity(identity) || !validJobLimits(payload.Limits) ||
		lease.TaskAttemptID == nil {
		return ErrRequestConflict
	}
	tx, err := r.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return fmt.Errorf("begin bytecode analyzer run: %w", err)
	}
	defer tx.Rollback()
	var storageKey, digest, format, architecture string
	var size uint64
	err = tx.QueryRowContext(ctx, `
SELECT node.storage_key, node.sha256, node.size_bytes, node.format,
       COALESCE(node.architecture, '')
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
		return fmt.Errorf("lock bytecode decompile source: %w", err)
	}
	if storageKey != payload.Target.StorageKey || digest != payload.Target.SHA256 ||
		size != payload.Target.SizeBytes || format != payload.Target.Format ||
		architecture != payload.Target.Architecture {
		return ErrRequestConflict
	}
	var replayStatus string
	err = tx.QueryRowContext(ctx, `
SELECT COALESCE((
    SELECT JSON_UNQUOTE(JSON_EXTRACT(run.parameters_json, '$.result_status'))
    FROM analyzer_runs run
    WHERE run.task_id = ?
      AND run.task_attempt_id = ?
      AND run.job_id = ?
      AND run.file_node_id = ?
      AND run.analyzer_name = ?
      AND run.analyzer_version = ?
      AND run.cache_identity = ?
      AND run.status = 'succeeded'
      AND JSON_UNQUOTE(JSON_EXTRACT(
          run.parameters_json, '$.engine_target'
      )) = ?
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
      )) AS UNSIGNED) BETWEEN 1 AND ?
      AND (
          SELECT COUNT(*)
          FROM decompile_results result
          WHERE result.task_id = run.task_id
            AND result.analyzer_run_id = run.id
      ) = CAST(JSON_UNQUOTE(JSON_EXTRACT(
          run.parameters_json, '$.result_count'
      )) AS UNSIGNED)
      AND EXISTS (
          SELECT 1
          FROM decompile_results result
          WHERE result.task_id = run.task_id
            AND result.analyzer_run_id = run.id
            AND result.file_node_id = run.file_node_id
            AND result.engine_name = run.analyzer_name
            AND result.engine_version = run.analyzer_version
            AND result.deleted_at IS NULL
            AND result.storage_key IS NOT NULL
            AND result.content_sha256 IS NOT NULL
            AND result.size_bytes IS NOT NULL
      )
      AND NOT EXISTS (
          SELECT 1
          FROM decompile_results result
          WHERE result.task_id = run.task_id
            AND result.analyzer_run_id = run.id
            AND (
                result.deleted_at IS NOT NULL OR
                result.storage_key IS NULL OR
                result.content_sha256 IS NULL OR
                result.size_bytes IS NULL OR
                result.status <> JSON_UNQUOTE(JSON_EXTRACT(
                    run.parameters_json, '$.result_status'
                ))
            )
      )
    ORDER BY run.completed_at DESC, run.id DESC
    LIMIT 1
), '')`,
		lease.TaskID, *lease.TaskAttemptID, lease.JobID, nodeID,
		identity.EngineName, identity.EngineVersion, identity.ReuseIdentitySHA,
		payload.Engine.Target, identity.AnalyzerParametersSHA,
		identity.CacheParametersSHA, identity.ReuseIdentitySHA,
		payload.Target.SHA256,
		fmt.Sprint(payload.Target.SizeBytes), payload.Target.Format,
		payload.Target.Architecture, payload.Limits.MaxArtifacts,
	).Scan(&replayStatus)
	if err != nil {
		return fmt.Errorf("inspect bytecode analyzer replay: %w", err)
	}
	if replayStatus == string(bytecode.StatusComplete) ||
		replayStatus == string(bytecode.StatusBytecodeOnly) {
		return bytecodeAlreadyPublishedError{status: bytecode.Status(replayStatus)}
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
  AND analyzer_name = ?
  AND status IN ('queued', 'running')`,
		lease.TaskID, *lease.TaskAttemptID, lease.JobID, identity.EngineName,
	); err != nil {
		return fmt.Errorf("fence prior bytecode analyzer runs: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `
INSERT INTO analyzer_runs (
    id, task_id, task_attempt_id, job_id, file_node_id,
    analyzer_name, analyzer_version, parameters_json, cache_identity,
    status, started_at
) VALUES (
    ?, ?, ?, ?, ?, ?, ?,
    JSON_OBJECT(
        'job_attempt', ?, 'job_fencing_token', ?,
        'payload_schema_version', ?, 'engine_target', ?,
        'analyzer_parameters_sha256', ?,
        'cache_parameters_sha256', ?,
        'reuse_contract', ?, 'reuse_identity_sha256', ?,
        'cache_lookup', 'pending',
        'source_storage_key', ?, 'source_sha256', ?,
        'source_size_bytes', ?, 'source_format', ?,
        'source_architecture', ?
    ), ?,
    'running', UTC_TIMESTAMP(6)
)`,
		runID, lease.TaskID, *lease.TaskAttemptID, lease.JobID, nodeID,
		identity.EngineName, identity.EngineVersion,
		lease.Attempt, lease.FencingToken, payload.SchemaVersion,
		payload.Engine.Target, identity.AnalyzerParametersSHA,
		identity.CacheParametersSHA, bytecodeReuseContract,
		identity.ReuseIdentitySHA, payload.Target.StorageKey,
		payload.Target.SHA256, payload.Target.SizeBytes,
		payload.Target.Format, payload.Target.Architecture,
		identity.ReuseIdentitySHA,
	); err != nil {
		return fmt.Errorf("create bytecode analyzer run: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit bytecode analyzer run: %w", err)
	}
	return nil
}

func (r *MySQLRepository) PublishBytecodeRun(
	ctx context.Context,
	lease queue.Lease,
	payload JobPayload,
	runID string,
	identity BytecodeRunIdentity,
	resultStatus bytecode.Status,
	exitCode int,
	publish BytecodeResultPublisher,
) (returnErr error) {
	nodeID, err := targetNodeID(payload)
	if err != nil || nodeID == 0 || publish == nil ||
		!uuidPattern.MatchString(runID) || !validBytecodeRunIdentity(identity) ||
		!validBytecodeRunStatus(resultStatus) || exitCode < 0 ||
		!validJobLimits(payload.Limits) || lease.TaskAttemptID == nil {
		return ErrRequestConflict
	}
	tx, err := r.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return fmt.Errorf("begin bytecode result publication: %w", err)
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
					fmt.Errorf("rollback bytecode result publication: %w", rollbackErr),
				)
			}
		}
		if returnErr != nil && published && !commitAttempted {
			cleanupPublished()
		}
	}()
	if err := validateBytecodePublishingLease(
		ctx, tx, lease, payload, runID, identity, "running", true,
	); err != nil {
		return err
	}
	project, results, cleanup, err := publish(ctx)
	if err != nil {
		return fmt.Errorf("publish bytecode result files: %w", err)
	}
	published = true
	if cleanup != nil {
		cleanupPublished = cleanup
	}
	if len(results) == 0 || len(results) > payload.Limits.MaxArtifacts ||
		!validBytecodePublicationStatus(resultStatus, results) ||
		!validOptionalPublishedSourceProject(runID, project, results) {
		return ErrRequestConflict
	}
	var totalSize uint64
	for _, value := range results {
		if !validBytecodePublishedResult(runID, value) ||
			value.SizeBytes > uint64(payload.Limits.MaxOutputBytes)-totalSize {
			return ErrRequestConflict
		}
		totalSize += value.SizeBytes
		cache := bytecodeResultCacheKey(
			payload, lease.JobID, identity, value.SymbolKey,
		)
		var storageKey, contentSHA, sizeBytes any
		if value.StorageKey != "" {
			storageKey, contentSHA, sizeBytes = value.StorageKey, value.SHA256, value.SizeBytes
		}
		if _, err := tx.ExecContext(ctx, `
INSERT INTO decompile_results (
    id, task_id, file_node_id, analyzer_run_id, cache_key,
    symbol_key, language, engine_name, engine_version, status,
    storage_key, content_sha256, size_bytes, diagnostics_json,
    completed_at
) VALUES (
    ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, UTC_TIMESTAMP(6)
)`,
			value.ID, lease.TaskID, nodeID, runID, cache,
			value.SymbolKey, value.Language, identity.EngineName,
			identity.EngineVersion, value.Status, storageKey, contentSHA,
			sizeBytes, []byte(value.Diagnostics),
		); err != nil {
			return fmt.Errorf("insert bytecode decompile result: %w", err)
		}
	}
	if project.ID != "" {
		if err := insertPublishedSourceProject(
			ctx, tx, lease.TaskID, nodeID, lease.JobID,
			identity.EngineName, identity.EngineVersion,
			string(resultStatus), project,
		); err != nil {
			return fmt.Errorf("insert bytecode source project: %w", err)
		}
	}
	runStatus := "succeeded"
	if resultStatus == bytecode.StatusPartial {
		runStatus = "partial"
	}
	updateResult, err := tx.ExecContext(ctx, `
UPDATE analyzer_runs
SET status = ?,
    exit_code = ?,
    error_code = NULL,
    error_message = NULL,
    parameters_json = JSON_SET(
        parameters_json,
        '$.result_status', ?,
        '$.result_count', ?,
        '$.cache_hit', FALSE,
        '$.cache_lookup', 'miss_or_invalid'
    ),
    completed_at = UTC_TIMESTAMP(6)
WHERE id = ?
  AND task_id = ?
  AND job_id = ?
  AND status = 'running'`,
		runStatus, exitCode, string(resultStatus), len(results),
		runID, lease.TaskID, lease.JobID,
	)
	if err != nil {
		return fmt.Errorf("complete bytecode analyzer run: %w", err)
	}
	if err := requireBytecodeOne(updateResult); err != nil {
		return err
	}
	if err := validateBytecodePublishingLease(
		ctx, tx, lease, payload, runID, identity, runStatus, false,
	); err != nil {
		return err
	}
	commitAttempted = true
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit bytecode result publication: %w", err)
	}
	finished = true
	return nil
}

func validateBytecodePublishingLease(
	ctx context.Context,
	tx *sql.Tx,
	lease queue.Lease,
	payload JobPayload,
	runID string,
	identity BytecodeRunIdentity,
	runStatus string,
	lock bool,
) error {
	nodeID, err := targetNodeID(payload)
	if err != nil || nodeID == 0 || lease.TaskAttemptID == nil ||
		(runStatus != "running" && runStatus != "succeeded" && runStatus != "partial") {
		return ErrRequestConflict
	}
	query := `
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
  AND run.analyzer_name = ?
  AND run.analyzer_version = ?
  AND run.cache_identity = ?
  AND run.status = ?
  AND JSON_UNQUOTE(JSON_EXTRACT(
      run.parameters_json, '$.job_attempt'
  )) = ?
  AND JSON_UNQUOTE(JSON_EXTRACT(
      run.parameters_json, '$.job_fencing_token'
  )) = ?
  AND JSON_UNQUOTE(JSON_EXTRACT(
      run.parameters_json, '$.engine_target'
  )) = ?
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
  )) = ?`
	if lock {
		query += "\nFOR UPDATE"
	}
	var marker uint8
	err = tx.QueryRowContext(ctx, query,
		runID, lease.JobID, lease.TaskID, *lease.TaskAttemptID,
		lease.Owner, lease.FencingToken, nodeID, identity.EngineName,
		identity.EngineVersion, identity.ReuseIdentitySHA, runStatus,
		fmt.Sprint(lease.Attempt),
		fmt.Sprint(lease.FencingToken), payload.Engine.Target,
		identity.AnalyzerParametersSHA, identity.CacheParametersSHA,
		identity.ReuseIdentitySHA,
		payload.Target.StorageKey, payload.Target.SHA256,
		fmt.Sprint(payload.Target.SizeBytes), payload.Target.Format,
		payload.Target.Architecture,
	).Scan(&marker)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrRequestConflict
	}
	if err != nil {
		return fmt.Errorf("validate bytecode result publication lease: %w", err)
	}
	return nil
}

func (r *MySQLRepository) FailBytecodeRun(
	ctx context.Context,
	lease queue.Lease,
	runID string,
	code string,
	message string,
) error {
	if !uuidPattern.MatchString(runID) || code == "" || len(code) > 128 ||
		message == "" || len(message) > 2048 || lease.TaskAttemptID == nil {
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
  AND run.task_attempt_id = ?
  AND run.task_attempt_id = job.task_attempt_id
  AND run.status = 'running'
  AND job.id = ?
  AND job.kind = 'decompile'
  AND job.status IN ('leased', 'running', 'cancel_requested')
  AND job.lease_owner = ?
  AND job.fencing_token = ?
  AND job.lease_until > UTC_TIMESTAMP(6)`,
		code, message, runID, lease.TaskID, *lease.TaskAttemptID,
		lease.JobID, lease.Owner, lease.FencingToken,
	)
	if err != nil {
		return fmt.Errorf("fail bytecode analyzer run: %w", err)
	}
	return requireBytecodeOne(result)
}

func validBytecodeRunIdentity(value BytecodeRunIdentity) bool {
	return safeEngineVersion(value.EngineName) &&
		safeEngineVersion(value.EngineVersion) &&
		sha256Pattern.MatchString(value.AnalyzerParametersSHA) &&
		sha256Pattern.MatchString(value.CacheParametersSHA) &&
		sha256Pattern.MatchString(value.ReuseIdentitySHA)
}

func validBytecodeRunStatus(value bytecode.Status) bool {
	switch value {
	case bytecode.StatusComplete, bytecode.StatusPartial,
		bytecode.StatusBytecodeOnly, bytecode.StatusUnsupported:
		return true
	default:
		return false
	}
}

func validBytecodePublicationStatus(
	status bytecode.Status,
	results []BytecodePublishedResult,
) bool {
	complete, bytecodeOnly, unsupported, failed := 0, 0, 0, 0
	for _, value := range results {
		switch value.Status {
		case "complete":
			complete++
		case "bytecode_only":
			bytecodeOnly++
		case "unsupported":
			unsupported++
		case "failed":
			failed++
		default:
			return false
		}
	}
	switch status {
	case bytecode.StatusComplete:
		return complete == len(results)
	case bytecode.StatusPartial:
		return unsupported+failed > 0
	case bytecode.StatusBytecodeOnly:
		return complete == 0 && bytecodeOnly > 0
	case bytecode.StatusUnsupported:
		return len(results) == 1 && unsupported == 1
	default:
		return false
	}
}

func validBytecodePublishedResult(
	runID string,
	value BytecodePublishedResult,
) bool {
	if !uuidPattern.MatchString(value.ID) ||
		value.ID != bytecodeResultID(runID, value.SymbolKey) ||
		value.SymbolKey == "" || len(value.SymbolKey) > 512 ||
		!utf8.ValidString(value.SymbolKey) || strings.ContainsRune(value.SymbolKey, 0) ||
		value.Language == "" || len(value.Language) > 32 ||
		!utf8.ValidString(value.Language) ||
		len(value.Diagnostics) == 0 ||
		len(value.Diagnostics) > maxBytecodeDiagnosticsBytes ||
		!utf8.Valid(value.Diagnostics) || !json.Valid(value.Diagnostics) {
		return false
	}
	for _, character := range value.Language {
		if character < 0x21 || character > 0x7e {
			return false
		}
	}
	if value.Status == "complete" || value.Status == "bytecode_only" {
		expectedPrefix := sourceProjectRoot(runID) + "/"
		return strings.HasPrefix(value.StorageKey, expectedPrefix) &&
			path.Clean(value.StorageKey) == value.StorageKey &&
			!strings.Contains(value.StorageKey, `\`) &&
			sha256Pattern.MatchString(value.SHA256) && value.SizeBytes > 0
	}
	return (value.Status == "unsupported" || value.Status == "failed") &&
		value.StorageKey == "" &&
		value.SHA256 == "" && value.SizeBytes == 0
}

func bytecodeResultCacheKey(
	payload JobPayload,
	jobID string,
	identity BytecodeRunIdentity,
	symbolKey string,
) string {
	digest := sha256.Sum256([]byte(
		"binaryscan-bytecode-result-cache-v2\x00" + payload.TaskID + "\x00" +
			jobID + "\x00" + payload.Target.FileNodeID + "\x00" +
			payload.Target.SHA256 + "\x00" +
			fmt.Sprint(payload.Target.SizeBytes) + "\x00" +
			payload.Target.Format + "\x00" + payload.Target.Architecture + "\x00" +
			payload.Engine.Target + "\x00" +
			identity.EngineName + "\x00" + identity.EngineVersion + "\x00" +
			identity.AnalyzerParametersSHA + "\x00" +
			identity.CacheParametersSHA + "\x00" + symbolKey,
	))
	return hex.EncodeToString(digest[:])
}

func requireBytecodeOne(result sql.Result) error {
	affected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if affected != 1 {
		return ErrRequestConflict
	}
	return nil
}

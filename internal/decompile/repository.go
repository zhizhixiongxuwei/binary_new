package decompile

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"binaryscan/internal/taskevent"

	"github.com/go-sql-driver/mysql"
)

const maxEnqueueTransactionAttempts = 3

type MySQLRepository struct {
	db *sql.DB
}

func NewMySQLRepository(db *sql.DB) *MySQLRepository {
	return &MySQLRepository{db: db}
}

func (r *MySQLRepository) Enqueue(
	ctx context.Context,
	record CreateRecord,
) (Request, bool, error) {
	if err := ctx.Err(); err != nil {
		return Request{}, false, err
	}
	if !validCreateRecord(record) {
		return Request{}, false, ErrInvalidInput
	}
	for attempt := 0; attempt < maxEnqueueTransactionAttempts; attempt++ {
		value, created, err := r.enqueueOnce(ctx, record)
		if err == nil {
			return value, created, nil
		}
		if !retryableEnqueueTransaction(err) ||
			attempt == maxEnqueueTransactionAttempts-1 {
			return Request{}, false, err
		}
		timer := time.NewTimer(time.Duration(attempt+1) * 10 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return Request{}, false, ctx.Err()
		case <-timer.C:
		}
	}
	return Request{}, false, errors.New(
		"decompile request exhausted transaction attempts",
	)
}

func validCreateRecord(record CreateRecord) bool {
	if !uuidPattern.MatchString(record.JobID) ||
		!uuidPattern.MatchString(record.RequestID) ||
		record.JobID == record.RequestID ||
		!uuidPattern.MatchString(record.TaskID) ||
		record.FileNodeID == 0 ||
		record.UserID == 0 ||
		!validEngineTarget(record.EngineTarget) ||
		!validJobLimits(record.Limits) ||
		len(record.JobRequestKey) != len("decompile:")+64 ||
		!strings.HasPrefix(record.JobRequestKey, "decompile:") ||
		!sha256Pattern.MatchString(
			strings.TrimPrefix(record.JobRequestKey, "decompile:"),
		) {
		return false
	}
	options, err := canonicalOptions(record.Options)
	return err == nil && bytes.Equal(options, record.Options)
}

func (r *MySQLRepository) enqueueOnce(
	ctx context.Context,
	record CreateRecord,
) (Request, bool, error) {
	if err := ctx.Err(); err != nil {
		return Request{}, false, err
	}
	transaction, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return Request{}, false, fmt.Errorf(
			"begin decompile request: %w",
			err,
		)
	}
	defer transaction.Rollback()

	var (
		taskStatus      string
		sampleDeletedAt sql.NullTime
		sampleExpiresAt time.Time
		deletedAt       sql.NullTime
		databaseNow     time.Time
	)
	err = transaction.QueryRowContext(ctx, `
SELECT status, sample_deleted_at, sample_expires_at, deleted_at,
       UTC_TIMESTAMP(6)
FROM tasks
WHERE id = ?
FOR UPDATE`, record.TaskID).Scan(
		&taskStatus,
		&sampleDeletedAt,
		&sampleExpiresAt,
		&deletedAt,
		&databaseNow,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return Request{}, false, ErrTaskNotFound
	}
	if err != nil {
		return Request{}, false, fmt.Errorf(
			"lock task for decompile request: %w",
			err,
		)
	}
	if deletedAt.Valid || !decompileTaskStatusSupported(taskStatus) {
		return Request{}, false, ErrTaskStateConflict
	}
	if sampleDeletedAt.Valid || !sampleExpiresAt.After(databaseNow) {
		return Request{}, false, ErrSampleUnavailable
	}

	target, err := lockDecompileTarget(
		ctx,
		transaction,
		record.TaskID,
		record.FileNodeID,
	)
	if err != nil {
		return Request{}, false, err
	}
	engine, err := selectEngine(
		target.Class,
		target.Format,
		target.Architecture,
		record.EngineTarget,
	)
	if err != nil {
		return Request{}, false, err
	}
	taskAttemptID, err := lockCompletedTaskAttempt(
		ctx, transaction, record.TaskID, taskStatus,
	)
	if err != nil {
		return Request{}, false, err
	}
	payload := JobPayload{
		SchemaVersion: JobPayloadVersion,
		RequestID:     record.RequestID,
		RequestedBy:   record.UserID,
		TaskID:        record.TaskID,
		Target:        target,
		Engine:        engine,
		Options:       append(json.RawMessage(nil), record.Options...),
		Limits:        record.Limits,
	}

	existing, found, err := lockDecompileReplay(
		ctx,
		transaction,
		record.TaskID,
		record.JobRequestKey,
	)
	if err != nil {
		return Request{}, false, err
	}
	if found {
		if !existing.TaskAttemptID.Valid || existing.TaskAttemptID.Int64 <= 0 ||
			uint64(existing.TaskAttemptID.Int64) != taskAttemptID ||
			!sameDecompileRequest(existing.Payload, payload) {
			return Request{}, false, ErrRequestConflict
		}
		value, err := requestFromJob(
			existing.ID,
			existing.Status,
			existing.CreatedAt,
			existing.Payload,
		)
		if err != nil {
			return Request{}, false, err
		}
		if err := transaction.Commit(); err != nil {
			return Request{}, false, fmt.Errorf(
				"commit decompile request replay: %w",
				err,
			)
		}
		return value, false, nil
	}

	var activeJobID string
	err = transaction.QueryRowContext(ctx, `
SELECT id
FROM jobs
WHERE task_id = ?
  AND kind = 'decompile'
  AND status IN ('queued', 'leased', 'running', 'cancel_requested')
  AND JSON_UNQUOTE(JSON_EXTRACT(payload, '$.target.file_node_id')) = ?
ORDER BY created_at ASC, id ASC
LIMIT 1
FOR UPDATE`, record.TaskID, target.FileNodeID).Scan(&activeJobID)
	if err == nil {
		return Request{}, false, ErrDecompileInProgress
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return Request{}, false, fmt.Errorf(
			"find active decompile request: %w",
			err,
		)
	}

	encodedPayload, err := json.Marshal(payload)
	if err != nil {
		return Request{}, false, fmt.Errorf(
			"encode decompile job payload: %w",
			err,
		)
	}
	if _, err := transaction.ExecContext(ctx, `
INSERT INTO jobs (
    id, task_id, task_attempt_id, kind, status, priority, payload,
    available_at, attempt, max_attempts, fencing_token, idempotency_key,
    created_at, updated_at
) VALUES (?, ?, ?, 'decompile', 'queued', 0, ?,
          UTC_TIMESTAMP(6), 0, 3, 0, ?,
          UTC_TIMESTAMP(6), UTC_TIMESTAMP(6))`,
		record.JobID,
		record.TaskID,
		taskAttemptID,
		encodedPayload,
		record.JobRequestKey,
	); err != nil {
		return Request{}, false, fmt.Errorf(
			"insert decompile job: %w",
			err,
		)
	}

	taskResult, err := transaction.ExecContext(ctx, `
UPDATE tasks
SET event_sequence = event_sequence + 1
WHERE id = ?
  AND status = ?
  AND deleted_at IS NULL
  AND sample_deleted_at IS NULL
  AND sample_expires_at > UTC_TIMESTAMP(6)`,
		record.TaskID,
		taskStatus,
	)
	if err != nil {
		return Request{}, false, fmt.Errorf(
			"advance decompile task event sequence: %w",
			err,
		)
	}
	affected, err := taskResult.RowsAffected()
	if err != nil {
		return Request{}, false, fmt.Errorf(
			"inspect decompile task event sequence: %w",
			err,
		)
	}
	if affected != 1 {
		return Request{}, false, ErrSampleUnavailable
	}
	if err := taskevent.AppendCurrentState(
		ctx,
		transaction,
		record.TaskID,
		"decompile.queued",
		"Decompile request queued.",
	); err != nil {
		return Request{}, false, err
	}

	var created Request
	var rawPayload []byte
	err = transaction.QueryRowContext(ctx, `
SELECT id, status, payload, created_at
FROM jobs
WHERE id = ? AND task_id = ? AND kind = 'decompile'
LIMIT 1`,
		record.JobID,
		record.TaskID,
	).Scan(
		&created.JobID,
		&created.Status,
		&rawPayload,
		&created.CreatedAt,
	)
	if err != nil {
		return Request{}, false, fmt.Errorf(
			"read created decompile job: %w",
			err,
		)
	}
	storedPayload, err := decodeJobPayload(rawPayload)
	if err != nil {
		return Request{}, false, fmt.Errorf(
			"decode created decompile job: %w",
			err,
		)
	}
	created, err = requestFromJob(
		created.JobID,
		created.Status,
		created.CreatedAt,
		storedPayload,
	)
	if err != nil {
		return Request{}, false, err
	}
	if err := transaction.Commit(); err != nil {
		return Request{}, false, fmt.Errorf(
			"commit decompile request: %w",
			err,
		)
	}
	return created, true, nil
}

func lockCompletedTaskAttempt(
	ctx context.Context,
	transaction *sql.Tx,
	taskID string,
	taskStatus string,
) (uint64, error) {
	attemptStatus := ""
	switch taskStatus {
	case "SUCCEEDED", "PARTIAL_SUCCEEDED":
		attemptStatus = "succeeded"
	case "FAILED":
		attemptStatus = "failed"
	case "CANCELLED":
		attemptStatus = "cancelled"
	default:
		return 0, ErrTaskStateConflict
	}
	var attemptID uint64
	err := transaction.QueryRowContext(ctx, `
SELECT id
FROM task_attempts
WHERE task_id = ?
  AND status = ?
ORDER BY attempt_number DESC, id DESC
LIMIT 1
FOR UPDATE`, taskID, attemptStatus).Scan(&attemptID)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, ErrTaskStateConflict
	}
	if err != nil {
		return 0, fmt.Errorf("lock completed decompile task attempt: %w", err)
	}
	if attemptID == 0 {
		return 0, ErrTaskStateConflict
	}
	return attemptID, nil
}

func retryableEnqueueTransaction(err error) bool {
	var databaseError *mysql.MySQLError
	return errors.As(err, &databaseError) &&
		(databaseError.Number == 1205 || databaseError.Number == 1213)
}

type storedDecompileJob struct {
	ID            string
	TaskAttemptID sql.NullInt64
	Status        string
	Kind          string
	Payload       JobPayload
	CreatedAt     time.Time
}

func lockDecompileReplay(
	ctx context.Context,
	transaction *sql.Tx,
	taskID string,
	jobRequestKey string,
) (storedDecompileJob, bool, error) {
	var value storedDecompileJob
	var rawPayload []byte
	err := transaction.QueryRowContext(ctx, `
SELECT id, task_attempt_id, status, kind, payload, created_at
FROM jobs
WHERE task_id = ? AND idempotency_key = ?
	LIMIT 1
FOR UPDATE`, taskID, jobRequestKey).Scan(
		&value.ID,
		&value.TaskAttemptID,
		&value.Status,
		&value.Kind,
		&rawPayload,
		&value.CreatedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return storedDecompileJob{}, false, nil
	}
	if err != nil {
		return storedDecompileJob{}, false, fmt.Errorf(
			"lock decompile request replay: %w",
			err,
		)
	}
	if value.Kind != "decompile" {
		return storedDecompileJob{}, false, ErrRequestConflict
	}
	value.Payload, err = decodeJobPayload(rawPayload)
	if err != nil {
		return storedDecompileJob{}, false, fmt.Errorf(
			"decode stored decompile job: %w",
			err,
		)
	}
	return value, true, nil
}

func lockDecompileTarget(
	ctx context.Context,
	transaction *sql.Tx,
	taskID string,
	fileNodeID uint64,
) (JobTarget, error) {
	var (
		nodeType      string
		format        sql.NullString
		architecture  sql.NullString
		storageKey    sql.NullString
		sha256Value   sql.NullString
		sizeBytes     sql.Null[uint64]
		extractStatus string
	)
	err := transaction.QueryRowContext(ctx, `
SELECT node_type, format, architecture, storage_key, sha256, size_bytes,
       extraction_status
FROM file_nodes
WHERE task_id = ? AND id = ?
LIMIT 1
FOR UPDATE`, taskID, fileNodeID).Scan(
		&nodeType,
		&format,
		&architecture,
		&storageKey,
		&sha256Value,
		&sizeBytes,
		&extractStatus,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return JobTarget{}, ErrFileNodeNotFound
	}
	if err != nil {
		return JobTarget{}, fmt.Errorf(
			"lock decompile file node: %w",
			err,
		)
	}
	targetClass, _, supported := decompileTargetForTarget(
		format.String,
		architecture.String,
	)
	if nodeType != "file" ||
		!format.Valid ||
		!supported {
		return JobTarget{}, ErrUnsupportedTarget
	}
	if !storageKey.Valid ||
		validateStorageKey(storageKey.String) != nil ||
		!sha256Value.Valid ||
		!sha256Pattern.MatchString(sha256Value.String) ||
		!sizeBytes.Valid ||
		(extractStatus != "indexed" && extractStatus != "extracted") {
		return JobTarget{}, ErrSourceUnavailable
	}
	return JobTarget{
		FileNodeID:   strconv.FormatUint(fileNodeID, 10),
		Class:        targetClass,
		Format:       format.String,
		Architecture: architecture.String,
		StorageKey:   storageKey.String,
		SHA256:       sha256Value.String,
		SizeBytes:    sizeBytes.V,
	}, nil
}

func selectEngine(
	targetClass string,
	format string,
	architecture string,
	requested string,
) (JobEngine, error) {
	expectedClass, defaultEngine, supported := decompileTargetForTarget(
		format,
		architecture,
	)
	if !supported || expectedClass != targetClass {
		return JobEngine{}, ErrUnsupportedTarget
	}
	if requested != EngineAuto && requested != defaultEngine {
		return JobEngine{}, ErrUnsupportedTarget
	}
	return JobEngine{
		Target: defaultEngine, WorkerKind: targetClass,
	}, nil
}

func decompileTargetForTarget(
	format string,
	architecture string,
) (string, string, bool) {
	targetClass, engine, supported := decompileTargetForFormat(format)
	if !supported {
		return "", "", false
	}
	switch format {
	case "macho-thin":
		if architecture != "x86_64" {
			return "", "", false
		}
	case "macho-fat":
		// The API does not yet expose an explicit slice selector. Never let
		// Ghidra silently choose an architecture from a universal binary.
		return "", "", false
	}
	return targetClass, engine, true
}

func decompileTargetForFormat(format string) (string, string, bool) {
	switch format {
	case "pe32", "pe32+", "elf32", "elf64", "macho-thin", "macho-fat":
		return TargetNative, EngineGhidra, true
	case "java-class", "jar", "war", "ear":
		return TargetBytecode, EngineVineflower, true
	case "dex", "apk":
		return TargetBytecode, EngineJADX, true
	case "pyc":
		return TargetBytecode, EnginePythonBytecode, true
	default:
		return "", "", false
	}
}

func decompileTaskStatusSupported(status string) bool {
	switch status {
	case "SUCCEEDED", "PARTIAL_SUCCEEDED", "FAILED", "CANCELLED":
		return true
	default:
		return false
	}
}

func decodeJobPayload(raw []byte) (JobPayload, error) {
	if len(raw) == 0 || len(raw) > 64<<10 {
		return JobPayload{}, ErrRequestConflict
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var value JobPayload
	if err := decoder.Decode(&value); err != nil {
		return JobPayload{}, ErrRequestConflict
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return JobPayload{}, ErrRequestConflict
	}
	fileNodeID, err := strconv.ParseUint(value.Target.FileNodeID, 10, 64)
	if err != nil ||
		fileNodeID == 0 ||
		strconv.FormatUint(fileNodeID, 10) != value.Target.FileNodeID ||
		value.SchemaVersion != JobPayloadVersion ||
		!uuidPattern.MatchString(value.RequestID) ||
		!uuidPattern.MatchString(value.TaskID) ||
		value.RequestedBy == 0 ||
		validateStorageKey(value.Target.StorageKey) != nil ||
		!sha256Pattern.MatchString(value.Target.SHA256) ||
		!validJobLimits(value.Limits) {
		return JobPayload{}, ErrRequestConflict
	}
	expected, err := selectEngine(
		value.Target.Class,
		value.Target.Format,
		value.Target.Architecture,
		value.Engine.Target,
	)
	if err != nil || expected != value.Engine {
		return JobPayload{}, ErrRequestConflict
	}
	options, err := canonicalOptions(value.Options)
	if err != nil {
		return JobPayload{}, ErrRequestConflict
	}
	// MySQL's JSON type may reserialize objects with different insignificant
	// whitespace and key order. Normalize the nested options before comparing
	// an idempotent replay with the service's canonical request.
	value.Options = options
	return value, nil
}

func sameDecompileRequest(stored, requested JobPayload) bool {
	return stored.SchemaVersion == requested.SchemaVersion &&
		stored.RequestedBy == requested.RequestedBy &&
		stored.TaskID == requested.TaskID &&
		stored.Target == requested.Target &&
		stored.Engine == requested.Engine &&
		bytes.Equal(stored.Options, requested.Options) &&
		stored.Limits == requested.Limits
}

func requestFromJob(
	jobID string,
	status string,
	createdAt time.Time,
	payload JobPayload,
) (Request, error) {
	if !uuidPattern.MatchString(jobID) ||
		!validJobStatus(status) ||
		createdAt.IsZero() {
		return Request{}, ErrRequestConflict
	}
	return Request{
		RequestID:    payload.RequestID,
		JobID:        jobID,
		TaskID:       payload.TaskID,
		FileNodeID:   payload.Target.FileNodeID,
		TargetClass:  payload.Target.Class,
		EngineTarget: payload.Engine.Target,
		Status:       status,
		CreatedAt:    createdAt,
	}, nil
}

func validJobStatus(status string) bool {
	switch status {
	case "queued", "leased", "running", "succeeded", "failed",
		"cancel_requested", "cancelled":
		return true
	default:
		return false
	}
}

func (r *MySQLRepository) GetRequest(
	ctx context.Context,
	query RequestQuery,
) (Request, error) {
	if err := ctx.Err(); err != nil {
		return Request{}, err
	}
	var (
		jobID        string
		status       string
		rawPayload   []byte
		errorCode    sql.NullString
		errorMessage sql.NullString
		createdAt    time.Time
		completedAt  sql.NullTime
	)
	err := r.db.QueryRowContext(ctx, `
SELECT id, status, payload, error_code, error_message, created_at, completed_at
FROM jobs
WHERE task_id = ? AND id = ? AND kind = 'decompile'
LIMIT 1`, query.TaskID, query.JobID).Scan(
		&jobID,
		&status,
		&rawPayload,
		&errorCode,
		&errorMessage,
		&createdAt,
		&completedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return Request{}, ErrRequestNotFound
	}
	if err != nil {
		return Request{}, fmt.Errorf("read decompile request status: %w", err)
	}
	payload, err := decodeJobPayload(rawPayload)
	if err != nil {
		return Request{}, fmt.Errorf("decode decompile request status: %w", err)
	}
	value, err := requestFromJob(jobID, status, createdAt, payload)
	if err != nil || value.TaskID != query.TaskID {
		return Request{}, ErrRequestConflict
	}
	if errorCode.Valid {
		value.ErrorCode = errorCode.String
	}
	if errorMessage.Valid {
		value.ErrorMessage = errorMessage.String
	}
	if completedAt.Valid {
		value.CompletedAt = &completedAt.Time
	}
	return value, nil
}

func (r *MySQLRepository) List(
	ctx context.Context,
	query ListQuery,
) (Page, error) {
	if err := ctx.Err(); err != nil {
		return Page{}, err
	}
	transaction, err := r.db.BeginTx(ctx, &sql.TxOptions{
		Isolation: sql.LevelRepeatableRead,
		ReadOnly:  true,
	})
	if err != nil {
		return Page{}, fmt.Errorf("begin decompile result snapshot: %w", err)
	}
	defer transaction.Rollback()

	if err := requireTask(ctx, transaction, query.TaskID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return Page{}, ErrTaskNotFound
		}
		return Page{}, fmt.Errorf("find decompile result task: %w", err)
	}
	statement := `
	SELECT id, file_node_id, symbol_key, language, engine_name, engine_version,
	       status, size_bytes, diagnostics_json, created_at, completed_at,
	       storage_key, content_sha256
	FROM decompile_results
	WHERE task_id = ? AND deleted_at IS NULL`
	arguments := []any{query.TaskID}
	if query.After != nil {
		statement += `
	  AND (
	      created_at > ?
	      OR (created_at = ? AND id > ?)
	  )`
		arguments = append(
			arguments,
			query.After.CreatedAt,
			query.After.CreatedAt,
			query.After.ID,
		)
	}
	statement += `
	ORDER BY created_at ASC, id ASC
	LIMIT ?`
	arguments = append(arguments, query.PageSize+1)
	rows, err := transaction.QueryContext(ctx, statement, arguments...)
	if err != nil {
		return Page{}, fmt.Errorf("list decompile results: %w", err)
	}
	items := make([]Result, 0, query.PageSize+1)
	for rows.Next() {
		value, err := scanResult(rows)
		if err != nil {
			_ = rows.Close()
			return Page{}, fmt.Errorf("scan decompile result: %w", err)
		}
		items = append(items, value)
	}
	if err := rows.Close(); err != nil {
		return Page{}, fmt.Errorf("close decompile result rows: %w", err)
	}
	if err := rows.Err(); err != nil {
		return Page{}, fmt.Errorf("iterate decompile results: %w", err)
	}

	page := Page{Items: items}
	if len(page.Items) > query.PageSize {
		page.HasMore = true
		page.Items = page.Items[:query.PageSize]
	}
	if err := transaction.Commit(); err != nil {
		return Page{}, fmt.Errorf("commit decompile result snapshot: %w", err)
	}
	return page, nil
}

func (r *MySQLRepository) ListSourceArchiveSnapshot(
	ctx context.Context,
	taskID string,
	limit int,
) (sourceArchiveSnapshot, error) {
	if err := ctx.Err(); err != nil {
		return sourceArchiveSnapshot{}, err
	}
	if !uuidPattern.MatchString(taskID) || limit < 1 || limit > maxSourceArchiveResults {
		return sourceArchiveSnapshot{}, ErrInvalidInput
	}
	transaction, err := r.db.BeginTx(ctx, &sql.TxOptions{
		Isolation: sql.LevelRepeatableRead,
		ReadOnly:  true,
	})
	if err != nil {
		return sourceArchiveSnapshot{}, fmt.Errorf(
			"begin decompile source archive snapshot: %w", err,
		)
	}
	defer transaction.Rollback()
	if err := requireTask(ctx, transaction, taskID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return sourceArchiveSnapshot{}, ErrTaskNotFound
		}
		return sourceArchiveSnapshot{}, fmt.Errorf(
			"find decompile source archive task: %w", err,
		)
	}
	rows, err := transaction.QueryContext(ctx, `
	SELECT result.id, result.file_node_id, result.symbol_key,
	       result.language, result.engine_name, result.engine_version,
	       result.status, result.size_bytes, result.diagnostics_json,
	       result.created_at, result.completed_at,
	       result.storage_key, result.content_sha256,
	       result.source_offset_bytes, result.source_length_bytes,
	       project.canonical_storage_key, project.canonical_size_bytes
	FROM decompile_results result
	LEFT JOIN decompile_source_projects project
	  ON project.task_id = result.task_id
	 AND project.id = result.analyzer_run_id
	 AND project.deleted_at IS NULL
	WHERE result.task_id = ? AND result.deleted_at IS NULL
	ORDER BY result.created_at ASC, result.id ASC
	LIMIT ?`, taskID, limit+1)
	if err != nil {
		return sourceArchiveSnapshot{}, fmt.Errorf(
			"list decompile source archive snapshot: %w", err,
		)
	}
	items := make([]sourceArchiveSnapshotItem, 0, limit+1)
	for rows.Next() {
		var (
			value               Result
			fileNodeID          uint64
			sizeBytes           sql.Null[uint64]
			diagnostics         []byte
			completedAt         sql.NullTime
			storageKey          sql.NullString
			contentSHA256       sql.NullString
			sourceOffsetBytes   sql.Null[uint64]
			sourceLengthBytes   sql.Null[uint64]
			canonicalStorageKey sql.NullString
			canonicalSizeBytes  sql.Null[uint64]
		)
		if err := rows.Scan(
			&value.ID, &fileNodeID, &value.SymbolKey, &value.Language,
			&value.EngineName, &value.EngineVersion, &value.Status,
			&sizeBytes, &diagnostics, &value.CreatedAt, &completedAt,
			&storageKey, &contentSHA256,
			&sourceOffsetBytes, &sourceLengthBytes,
			&canonicalStorageKey, &canonicalSizeBytes,
		); err != nil {
			_ = rows.Close()
			return sourceArchiveSnapshot{}, fmt.Errorf(
				"scan decompile source archive snapshot: %w", err,
			)
		}
		value, err = finishScannedResult(
			value, fileNodeID, sizeBytes, diagnostics, completedAt,
			storageKey, contentSHA256,
		)
		if err != nil {
			_ = rows.Close()
			return sourceArchiveSnapshot{}, fmt.Errorf(
				"validate decompile source archive result: %w", err,
			)
		}
		descriptor, err := sourceDescriptorFromMetadata(
			value.ID, value.Status, storageKey, contentSHA256, sizeBytes,
			sourceOffsetBytes, sourceLengthBytes,
			canonicalStorageKey, canonicalSizeBytes,
		)
		if err != nil {
			_ = rows.Close()
			return sourceArchiveSnapshot{}, fmt.Errorf(
				"validate decompile source archive metadata: %w", err,
			)
		}
		items = append(items, sourceArchiveSnapshotItem{
			Result: value, Descriptor: descriptor,
		})
	}
	if err := rows.Close(); err != nil {
		return sourceArchiveSnapshot{}, fmt.Errorf(
			"close decompile source archive rows: %w", err,
		)
	}
	if err := rows.Err(); err != nil {
		return sourceArchiveSnapshot{}, fmt.Errorf(
			"iterate decompile source archive rows: %w", err,
		)
	}
	snapshot := sourceArchiveSnapshot{Items: items}
	if len(snapshot.Items) > limit {
		snapshot.HasMore = true
		snapshot.Items = snapshot.Items[:limit]
	}
	if err := transaction.Commit(); err != nil {
		return sourceArchiveSnapshot{}, fmt.Errorf(
			"commit decompile source archive snapshot: %w", err,
		)
	}
	return snapshot, nil
}

func (r *MySQLRepository) GetSource(
	ctx context.Context,
	query SourceQuery,
) (SourceDescriptor, error) {
	if err := ctx.Err(); err != nil {
		return SourceDescriptor{}, err
	}
	transaction, err := r.db.BeginTx(ctx, &sql.TxOptions{
		Isolation: sql.LevelRepeatableRead,
		ReadOnly:  true,
	})
	if err != nil {
		return SourceDescriptor{}, fmt.Errorf(
			"begin decompile source snapshot: %w", err,
		)
	}
	defer transaction.Rollback()

	if err := requireTask(ctx, transaction, query.TaskID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return SourceDescriptor{}, ErrTaskNotFound
		}
		return SourceDescriptor{}, fmt.Errorf("find decompile source task: %w", err)
	}
	var resultID string
	var status string
	var storageKey sql.NullString
	var sha256 sql.NullString
	var sizeBytes sql.Null[uint64]
	var sourceOffsetBytes sql.Null[uint64]
	var sourceLengthBytes sql.Null[uint64]
	var canonicalStorageKey sql.NullString
	var canonicalSizeBytes sql.Null[uint64]
	err = transaction.QueryRowContext(ctx, `
	SELECT result.id, result.status, result.storage_key,
	       result.content_sha256, result.size_bytes,
	       result.source_offset_bytes, result.source_length_bytes,
	       project.canonical_storage_key, project.canonical_size_bytes
	FROM decompile_results result
	LEFT JOIN decompile_source_projects project
	  ON project.task_id = result.task_id
	 AND project.id = result.analyzer_run_id
	 AND project.deleted_at IS NULL
	WHERE result.task_id = ? AND result.id = ?
	  AND result.deleted_at IS NULL
	LIMIT 1`, query.TaskID, query.ResultID).Scan(
		&resultID,
		&status,
		&storageKey,
		&sha256,
		&sizeBytes,
		&sourceOffsetBytes,
		&sourceLengthBytes,
		&canonicalStorageKey,
		&canonicalSizeBytes,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return SourceDescriptor{}, ErrResultNotFound
	}
	if err != nil {
		return SourceDescriptor{}, fmt.Errorf("read decompile source metadata: %w", err)
	}
	descriptor, err := sourceDescriptorFromMetadata(
		resultID, status, storageKey, sha256, sizeBytes,
		sourceOffsetBytes, sourceLengthBytes,
		canonicalStorageKey, canonicalSizeBytes,
	)
	if err != nil {
		return SourceDescriptor{}, fmt.Errorf("read decompile source metadata: %w", err)
	}
	if err := transaction.Commit(); err != nil {
		return SourceDescriptor{}, fmt.Errorf(
			"commit decompile source snapshot: %w", err,
		)
	}
	return descriptor, nil
}

func sourceDescriptorFromMetadata(
	resultID string,
	status string,
	storageKey sql.NullString,
	sha256 sql.NullString,
	sizeBytes sql.Null[uint64],
	sourceOffsetBytes sql.Null[uint64],
	sourceLengthBytes sql.Null[uint64],
	canonicalStorageKey sql.NullString,
	canonicalSizeBytes sql.Null[uint64],
) (SourceDescriptor, error) {
	descriptor := SourceDescriptor{ResultID: resultID, Status: status}
	if storageKey.Valid {
		descriptor.StorageKey = storageKey.String
	}
	if sha256.Valid {
		descriptor.SHA256 = sha256.String
	}
	if sizeBytes.Valid {
		descriptor.SizeBytes = sizeBytes.V
		descriptor.SizeKnown = true
	}
	if sourceOffsetBytes.Valid != sourceLengthBytes.Valid {
		return SourceDescriptor{}, errors.New("incomplete source range")
	}
	if sourceOffsetBytes.Valid {
		descriptor.SourceOffsetBytes = sourceOffsetBytes.V
		descriptor.SourceLengthBytes = sourceLengthBytes.V
		descriptor.SourceRangeKnown = true
		if canonicalStorageKey.Valid && storageKey.Valid &&
			canonicalStorageKey.String == storageKey.String &&
			canonicalSizeBytes.Valid {
			descriptor.StorageSizeBytes = canonicalSizeBytes.V
			descriptor.StorageSizeKnown = true
		}
	}
	return descriptor, nil
}

type rowQuerier interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

func requireTask(
	ctx context.Context,
	querier rowQuerier,
	taskID string,
) error {
	var marker uint8
	return querier.QueryRowContext(ctx, `
SELECT 1
FROM tasks
WHERE id = ? AND deleted_at IS NULL
LIMIT 1`, taskID).Scan(&marker)
}

type rowScanner interface {
	Scan(...any) error
}

func scanResult(scanner rowScanner) (Result, error) {
	var value Result
	var fileNodeID uint64
	var sizeBytes sql.Null[uint64]
	var diagnostics []byte
	var completedAt sql.NullTime
	var storageKey sql.NullString
	var contentSHA256 sql.NullString
	if err := scanner.Scan(
		&value.ID,
		&fileNodeID,
		&value.SymbolKey,
		&value.Language,
		&value.EngineName,
		&value.EngineVersion,
		&value.Status,
		&sizeBytes,
		&diagnostics,
		&value.CreatedAt,
		&completedAt,
		&storageKey,
		&contentSHA256,
	); err != nil {
		return Result{}, err
	}
	return finishScannedResult(
		value, fileNodeID, sizeBytes, diagnostics, completedAt,
		storageKey, contentSHA256,
	)
}

func finishScannedResult(
	value Result,
	fileNodeID uint64,
	sizeBytes sql.Null[uint64],
	diagnostics []byte,
	completedAt sql.NullTime,
	storageKey sql.NullString,
	contentSHA256 sql.NullString,
) (Result, error) {
	if fileNodeID == 0 {
		return Result{}, errors.New(
			"decompile result file node ID is outside accepted bounds",
		)
	}
	value.FileNodeID = strconv.FormatUint(fileNodeID, 10)
	if sizeBytes.Valid {
		size := sizeBytes.V
		value.SizeBytes = &size
	}
	if completedAt.Valid {
		completed := completedAt.Time
		value.CompletedAt = &completed
	}
	if storageKey.Valid {
		value.StorageKey = storageKey.String
	}
	if contentSHA256.Valid {
		value.ContentSHA256 = contentSHA256.String
	}
	applyDiagnostics(&value, diagnostics)
	return value, nil
}

func applyDiagnostics(value *Result, raw []byte) {
	value.SymbolKind = "unknown"
	value.DisplayName = value.SymbolKey
	if value.DisplayName == "" {
		value.DisplayName = "unnamed symbol"
	}
	value.GroupName = "Ungrouped"
	value.Diagnostics = json.RawMessage(`{}`)

	if len(raw) == 0 || !json.Valid(raw) {
		return
	}
	value.Diagnostics = append(json.RawMessage(nil), raw...)

	var object map[string]json.RawMessage
	if err := json.Unmarshal(raw, &object); err != nil {
		return
	}
	var nested map[string]json.RawMessage
	if symbol, found := object["symbol"]; found {
		_ = json.Unmarshal(symbol, &nested)
	}
	value.SymbolKind = normalizeSymbolKind(diagnosticString(
		object, nested, value.SymbolKind, "symbol_kind", "kind",
	))
	value.DisplayName = diagnosticString(
		object, nested, value.DisplayName, "display_name", "name",
	)
	value.GroupName = diagnosticString(
		object, nested, value.GroupName, "group_name", "group",
	)
	value.Location = diagnosticString(
		object, nested, "", "location",
	)
	value.Signature = diagnosticString(
		object, nested, "", "signature",
	)
	value.Detail = diagnosticString(
		object, nested, "", "detail",
	)
}

func normalizeSymbolKind(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "function":
		return "function"
	case "class":
		return "class"
	case "method":
		return "method"
	case "module":
		return "module"
	default:
		return "unknown"
	}
}

func diagnosticString(
	object map[string]json.RawMessage,
	nested map[string]json.RawMessage,
	fallback string,
	keys ...string,
) string {
	for _, source := range []map[string]json.RawMessage{object, nested} {
		for _, key := range keys {
			var value string
			raw, found := source[key]
			if found && json.Unmarshal(raw, &value) == nil &&
				value != "" && len(value) <= 8192 {
				return value
			}
		}
	}
	return fallback
}

var _ Repository = (*MySQLRepository)(nil)

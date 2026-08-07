package manualimagescan

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"regexp"
	"strconv"
	"strings"
	"time"

	"binaryscan/internal/task"
	"binaryscan/internal/taskevent"
	"binaryscan/internal/trivyhandoff"

	"github.com/go-sql-driver/mysql"
)

const (
	maxTransactionAttempts = 3
	maxSourceBytes         = int64(2 * 1024 * 1024 * 1024)
)

var sha256Pattern = regexp.MustCompile(`^[a-f0-9]{64}$`)

type MySQLRepository struct {
	db *sql.DB
}

func NewMySQLRepository(db *sql.DB) *MySQLRepository {
	return &MySQLRepository{db: db}
}

func (repository *MySQLRepository) Enqueue(
	ctx context.Context,
	record CreateRecord,
) (Request, bool, error) {
	if repository == nil || repository.db == nil || !validRecord(record) {
		return Request{}, false, ErrInvalidInput
	}
	for attempt := 0; attempt < maxTransactionAttempts; attempt++ {
		value, created, err := repository.enqueueOnce(ctx, record)
		if err == nil {
			return value, created, nil
		}
		if !retryableTransaction(err) || attempt == maxTransactionAttempts-1 {
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
		"manual image scan exhausted transaction attempts",
	)
}

func validRecord(record CreateRecord) bool {
	return uuidPattern.MatchString(record.JobID) &&
		uuidPattern.MatchString(record.TaskID) &&
		record.FileNodeID > 0 && record.UserID > 0 &&
		len(record.JobRequestKey) == len("image:manual:")+64 &&
		strings.HasPrefix(record.JobRequestKey, "image:manual:") &&
		sha256Pattern.MatchString(
			strings.TrimPrefix(record.JobRequestKey, "image:manual:"),
		)
}

func (repository *MySQLRepository) enqueueOnce(
	ctx context.Context,
	record CreateRecord,
) (Request, bool, error) {
	if err := ctx.Err(); err != nil {
		return Request{}, false, err
	}
	transaction, err := repository.db.BeginTx(ctx, nil)
	if err != nil {
		return Request{}, false, fmt.Errorf(
			"begin manual image scan request: %w",
			err,
		)
	}
	defer transaction.Rollback()

	var (
		taskStatus      string
		sampleDeletedAt sql.NullTime
		sampleExpiresAt time.Time
		deletedAt       sql.NullTime
		limitsRaw       []byte
		databaseNow     time.Time
	)
	err = transaction.QueryRowContext(ctx, `
SELECT status, sample_deleted_at, sample_expires_at, deleted_at,
       limits_snapshot, UTC_TIMESTAMP(6)
FROM tasks
WHERE id = ?
FOR UPDATE`, record.TaskID).Scan(
		&taskStatus,
		&sampleDeletedAt,
		&sampleExpiresAt,
		&deletedAt,
		&limitsRaw,
		&databaseNow,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return Request{}, false, ErrTaskNotFound
	}
	if err != nil {
		return Request{}, false, fmt.Errorf(
			"lock manual image scan task: %w",
			err,
		)
	}
	if deletedAt.Valid || !terminalTaskStatus(taskStatus) {
		return Request{}, false, ErrTaskStateConflict
	}
	if sampleDeletedAt.Valid || !sampleExpiresAt.After(databaseNow) {
		return Request{}, false, ErrSampleUnavailable
	}
	limits, err := decodeTaskLimits(limitsRaw)
	if err != nil {
		return Request{}, false, err
	}

	selected, err := lockTarget(
		ctx,
		transaction,
		record.TaskID,
		record.FileNodeID,
	)
	if err != nil {
		return Request{}, false, err
	}
	if selected.Source.SourceSizeBytes > limits.MaxExpandedBytes {
		return Request{}, false, ErrSourceUnavailable
	}
	attemptID, err := lockCompletedTaskAttempt(
		ctx,
		transaction,
		record.TaskID,
		taskStatus,
	)
	if err != nil {
		return Request{}, false, err
	}
	payload := trivyhandoff.Payload{
		SchemaVersion:    trivyhandoff.SchemaVersion,
		Sources:          []trivyhandoff.Source{selected.Source},
		MaxExpandedBytes: limits.MaxExpandedBytes,
		MaxArchiveRatio:  limits.MaxArchiveRatio,
		UpstreamPartial:  false,
	}
	encodedPayload, err := trivyhandoff.Encode(
		payload,
		maxSourceBytes,
		1,
	)
	if err != nil {
		return Request{}, false, ErrSourceUnavailable
	}

	existing, found, err := lockReplay(
		ctx,
		transaction,
		record.TaskID,
		record.JobRequestKey,
	)
	if err != nil {
		return Request{}, false, err
	}
	if found {
		if !existing.TaskAttemptID.Valid ||
			existing.TaskAttemptID.Int64 <= 0 ||
			uint64(existing.TaskAttemptID.Int64) != attemptID ||
			!samePayload(existing.Payload, payload) {
			return Request{}, false, ErrRequestConflict
		}
		value, err := requestFromStored(
			existing.ID,
			record.TaskID,
			record.FileNodeID,
			existing.Status,
			existing.CreatedAt,
		)
		if err != nil {
			return Request{}, false, err
		}
		if err := transaction.Commit(); err != nil {
			return Request{}, false, fmt.Errorf(
				"commit manual image scan replay: %w",
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
  AND kind = 'image'
  AND status IN ('queued', 'leased', 'running', 'cancel_requested')
  AND JSON_LENGTH(JSON_EXTRACT(payload, '$.sources')) = 1
  AND JSON_UNQUOTE(JSON_EXTRACT(
      payload, '$.sources[0].image_logical_path'
  )) = ?
ORDER BY created_at ASC, id ASC
LIMIT 1
FOR UPDATE`, record.TaskID, selected.Source.ImageLogicalPath).Scan(&activeJobID)
	if err == nil {
		return Request{}, false, ErrImageScanInProgress
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return Request{}, false, fmt.Errorf(
			"find active manual image scan: %w",
			err,
		)
	}

	if _, err := transaction.ExecContext(ctx, `
INSERT INTO jobs (
    id, task_id, task_attempt_id, kind, status, priority, payload,
    available_at, attempt, max_attempts, fencing_token, idempotency_key,
    created_at, updated_at
) VALUES (?, ?, ?, 'image', 'queued', 10, ?, UTC_TIMESTAMP(6),
          0, 3, 0, ?, UTC_TIMESTAMP(6), UTC_TIMESTAMP(6))`,
		record.JobID,
		record.TaskID,
		attemptID,
		encodedPayload,
		record.JobRequestKey,
	); err != nil {
		return Request{}, false, fmt.Errorf(
			"insert manual image scan job: %w",
			err,
		)
	}
	result, err := transaction.ExecContext(ctx, `
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
			"advance manual image scan event sequence: %w",
			err,
		)
	}
	if err := requireOne(result); err != nil {
		return Request{}, false, err
	}
	if err := taskevent.AppendCurrentState(
		ctx,
		transaction,
		record.TaskID,
		"image_scan.queued",
		"Manual container image scan queued.",
	); err != nil {
		return Request{}, false, err
	}

	var created Request
	created.TaskID = record.TaskID
	created.FileNodeID = strconv.FormatUint(record.FileNodeID, 10)
	err = transaction.QueryRowContext(ctx, `
SELECT id, status, created_at
FROM jobs
WHERE id = ? AND task_id = ? AND kind = 'image'
LIMIT 1`, record.JobID, record.TaskID).Scan(
		&created.JobID,
		&created.Status,
		&created.CreatedAt,
	)
	if err != nil {
		return Request{}, false, fmt.Errorf(
			"read created manual image scan job: %w",
			err,
		)
	}
	if err := validateRequest(created); err != nil {
		return Request{}, false, err
	}
	if err := transaction.Commit(); err != nil {
		return Request{}, false, fmt.Errorf(
			"commit manual image scan request: %w",
			err,
		)
	}
	return created, true, nil
}

func decodeTaskLimits(raw []byte) (task.LimitsSnapshot, error) {
	var value task.LimitsSnapshot
	if len(raw) == 0 || json.Unmarshal(raw, &value) != nil ||
		value.MaxExpandedBytes <= 0 || value.MaxExpandedBytes > 50<<30 ||
		value.MaxArchiveRatio <= 0 || value.MaxArchiveRatio > 100 {
		return task.LimitsSnapshot{}, ErrTaskStateConflict
	}
	return value, nil
}

func lockTarget(
	ctx context.Context,
	transaction *sql.Tx,
	taskID string,
	fileNodeID uint64,
) (target, error) {
	var (
		parentID         sql.NullInt64
		nodeType         string
		format           sql.NullString
		logicalPath      string
		storageKey       sql.NullString
		sha256Value      sql.NullString
		sizeBytes        sql.Null[uint64]
		extractionStatus string
		errorCode        sql.NullString
	)
	err := transaction.QueryRowContext(ctx, `
SELECT parent_id, node_type, format, logical_path, storage_key, sha256,
       size_bytes, extraction_status, error_code
FROM file_nodes
WHERE task_id = ? AND id = ?
LIMIT 1
FOR UPDATE`, taskID, fileNodeID).Scan(
		&parentID,
		&nodeType,
		&format,
		&logicalPath,
		&storageKey,
		&sha256Value,
		&sizeBytes,
		&extractionStatus,
		&errorCode,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return target{}, ErrFileNodeNotFound
	}
	if err != nil {
		return target{}, fmt.Errorf("lock manual image scan node: %w", err)
	}
	if !eligibleManualImageTarget(
		parentID,
		nodeType,
		format,
		extractionStatus,
		errorCode,
	) {
		return target{}, ErrManualScanNotRequired
	}
	if !storageKey.Valid || !sha256Value.Valid ||
		!sha256Pattern.MatchString(sha256Value.String) ||
		!sizeBytes.Valid || sizeBytes.V == 0 || sizeBytes.V > uint64(maxSourceBytes) ||
		!validStorageKey(storageKey.String, sha256Value.String) {
		return target{}, ErrSourceUnavailable
	}
	var (
		blobStorageKey string
		blobSHA256     string
		blobSize       uint64
		referenceCount uint64
		blobState      string
		blobDeletedAt  sql.NullTime
	)
	blobQuery := `
SELECT stored_blob.storage_key, stored_blob.sha256, stored_blob.size_bytes,
       stored_blob.reference_count, stored_blob.state, stored_blob.deleted_at
FROM file_node_blob_refs node_ref
JOIN blobs stored_blob ON stored_blob.id = node_ref.blob_id
WHERE node_ref.task_id = ? AND node_ref.file_node_id = ?
LIMIT 1
FOR UPDATE`
	blobQueryArguments := []any{taskID, fileNodeID}
	if !parentID.Valid {
		blobQuery = `
SELECT stored_blob.storage_key, stored_blob.sha256, stored_blob.size_bytes,
       stored_blob.reference_count, stored_blob.state, stored_blob.deleted_at
FROM tasks task_record
JOIN blobs stored_blob ON stored_blob.id = task_record.blob_id
WHERE task_record.id = ?
LIMIT 1
FOR UPDATE`
		blobQueryArguments = []any{taskID}
	}
	err = transaction.QueryRowContext(
		ctx,
		blobQuery,
		blobQueryArguments...,
	).Scan(
		&blobStorageKey,
		&blobSHA256,
		&blobSize,
		&referenceCount,
		&blobState,
		&blobDeletedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return target{}, ErrSourceUnavailable
	}
	if err != nil {
		return target{}, fmt.Errorf(
			"lock manual image scan blob reference: %w",
			err,
		)
	}
	if blobStorageKey != storageKey.String || blobSHA256 != sha256Value.String ||
		blobSize != sizeBytes.V || referenceCount == 0 ||
		blobState != "available" || blobDeletedAt.Valid {
		return target{}, ErrSourceUnavailable
	}
	return target{Source: trivyhandoff.Source{
		Format:           format.String,
		SourceStorageKey: storageKey.String,
		SourceSHA256:     sha256Value.String,
		SourceSizeBytes:  int64(sizeBytes.V),
		ImageLogicalPath: logicalPath,
	}}, nil
}

func eligibleManualImageTarget(
	parentID sql.NullInt64,
	nodeType string,
	format sql.NullString,
	extractionStatus string,
	errorCode sql.NullString,
) bool {
	isContainerImage := format.Valid &&
		(format.String == "docker-tar" || format.String == "oci-tar")
	isRootImage := !parentID.Valid
	isSkippedNestedImage := parentID.Valid && parentID.Int64 > 0 &&
		extractionStatus == "limit_reached" && errorCode.Valid &&
		errorCode.String == "max_auto_container_images"
	return nodeType == "file" && isContainerImage &&
		(isRootImage || isSkippedNestedImage)
}

func validStorageKey(value string, sha256Value string) bool {
	expected := path.Join(
		"blobs",
		"sha256",
		sha256Value[:2],
		sha256Value,
	)
	return value == expected && !path.IsAbs(value) && path.Clean(value) == value &&
		!strings.Contains(value, `\`)
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
WHERE task_id = ? AND status = ?
ORDER BY attempt_number DESC, id DESC
LIMIT 1
FOR UPDATE`, taskID, attemptStatus).Scan(&attemptID)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, ErrTaskStateConflict
	}
	if err != nil {
		return 0, fmt.Errorf(
			"lock completed manual image scan task attempt: %w",
			err,
		)
	}
	if attemptID == 0 {
		return 0, ErrTaskStateConflict
	}
	return attemptID, nil
}

type storedJob struct {
	ID            string
	TaskAttemptID sql.NullInt64
	Status        string
	Payload       trivyhandoff.Payload
	CreatedAt     time.Time
}

func lockReplay(
	ctx context.Context,
	transaction *sql.Tx,
	taskID string,
	idempotencyKey string,
) (storedJob, bool, error) {
	var value storedJob
	var kind string
	var rawPayload []byte
	err := transaction.QueryRowContext(ctx, `
SELECT id, task_attempt_id, kind, status, payload, created_at
FROM jobs
WHERE task_id = ? AND idempotency_key = ?
LIMIT 1
FOR UPDATE`, taskID, idempotencyKey).Scan(
		&value.ID,
		&value.TaskAttemptID,
		&kind,
		&value.Status,
		&rawPayload,
		&value.CreatedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return storedJob{}, false, nil
	}
	if err != nil {
		return storedJob{}, false, fmt.Errorf(
			"lock manual image scan replay: %w",
			err,
		)
	}
	if kind != "image" {
		return storedJob{}, false, ErrRequestConflict
	}
	value.Payload, err = trivyhandoff.Decode(rawPayload, maxSourceBytes, 1)
	if err != nil {
		return storedJob{}, false, ErrRequestConflict
	}
	return value, true, nil
}

func samePayload(left, right trivyhandoff.Payload) bool {
	return left.SchemaVersion == right.SchemaVersion &&
		left.MaxExpandedBytes == right.MaxExpandedBytes &&
		left.MaxArchiveRatio == right.MaxArchiveRatio &&
		left.UpstreamPartial == right.UpstreamPartial &&
		len(left.Sources) == 1 && len(right.Sources) == 1 &&
		left.Sources[0] == right.Sources[0]
}

func requestFromStored(
	jobID string,
	taskID string,
	fileNodeID uint64,
	status string,
	createdAt time.Time,
) (Request, error) {
	value := Request{
		JobID:      jobID,
		TaskID:     taskID,
		FileNodeID: strconv.FormatUint(fileNodeID, 10),
		Status:     status,
		CreatedAt:  createdAt,
	}
	if err := validateRequest(value); err != nil {
		return Request{}, err
	}
	return value, nil
}

func validateRequest(value Request) error {
	if !uuidPattern.MatchString(value.JobID) ||
		!uuidPattern.MatchString(value.TaskID) || value.FileNodeID == "" ||
		value.CreatedAt.IsZero() {
		return ErrRequestConflict
	}
	switch value.Status {
	case "queued", "leased", "running", "succeeded", "failed",
		"cancel_requested", "cancelled":
		return nil
	default:
		return ErrRequestConflict
	}
}

func terminalTaskStatus(value string) bool {
	switch value {
	case "SUCCEEDED", "PARTIAL_SUCCEEDED", "FAILED", "CANCELLED":
		return true
	default:
		return false
	}
}

func retryableTransaction(err error) bool {
	var databaseError *mysql.MySQLError
	return errors.As(err, &databaseError) &&
		(databaseError.Number == 1205 || databaseError.Number == 1213)
}

func requireOne(result sql.Result) error {
	affected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("inspect manual image scan mutation: %w", err)
	}
	if affected != 1 {
		return ErrSampleUnavailable
	}
	return nil
}

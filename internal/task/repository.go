package task

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"binaryscan/internal/taskevent"
	"binaryscan/internal/taskprogress"

	"github.com/go-sql-driver/mysql"
)

const taskSelectColumns = `
SELECT t.id, t.name, t.root_format, t.status, t.risk_level,
       t.progress_basis_points, creator.public_id, creator.display_name, t.tags,
       t.created_at, t.updated_at, upload.display_name,
       stored_blob.size_bytes, stored_blob.sha256, t.stage, t.error_code,
       t.error_message, t.sample_expires_at, t.sample_deleted_at
FROM tasks t
JOIN users creator ON creator.id = t.created_by
JOIN uploads upload ON upload.id = t.upload_id
JOIN blobs stored_blob ON stored_blob.id = t.blob_id`

type rowScanner interface {
	Scan(...any) error
}

type rowQuerier interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

type MySQLRepository struct {
	db *sql.DB
}

const (
	maxCreateTransactionAttempts    = 3
	initialCreateRetryBackoff       = 10 * time.Millisecond
	maxLifecycleTransactionAttempts = 3
)

func NewMySQLRepository(db *sql.DB) *MySQLRepository {
	return &MySQLRepository{db: db}
}

func (r *MySQLRepository) Create(
	ctx context.Context,
	record CreateRecord,
) (View, bool, error) {
	for attempt := 0; attempt < maxCreateTransactionAttempts; attempt++ {
		value, created, err := r.createOnce(ctx, record)
		if err == nil {
			return value, created, nil
		}
		if isDuplicateKey(err) {
			return r.resolveCreateDuplicate(ctx, record)
		}
		if !isRetryableTransactionError(err) || attempt == maxCreateTransactionAttempts-1 {
			return View{}, false, err
		}
		if err := waitForCreateRetry(ctx, attempt); err != nil {
			return View{}, false, err
		}
	}
	return View{}, false, errors.New("task creation exhausted transaction attempts")
}

func (r *MySQLRepository) createOnce(
	ctx context.Context,
	record CreateRecord,
) (View, bool, error) {
	transaction, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return View{}, false, fmt.Errorf("begin task creation transaction: %w", err)
	}
	defer transaction.Rollback()

	var replayTaskID string
	var replayUploadID string
	var replayName string
	err = transaction.QueryRowContext(ctx, `
SELECT id, upload_id, name
FROM tasks
WHERE created_by = ? AND idempotency_key = ?
LIMIT 1
FOR UPDATE`, record.UserID, record.IdempotencyKey).Scan(
		&replayTaskID, &replayUploadID, &replayName,
	)
	if err == nil {
		if replayUploadID != record.UploadID || replayName != record.Name {
			return View{}, false, ErrConflict
		}
		existing, queryErr := queryTaskByID(ctx, transaction, replayTaskID)
		if queryErr != nil {
			return View{}, false, fmt.Errorf("read idempotent task replay: %w", queryErr)
		}
		return existing, false, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return View{}, false, fmt.Errorf("find task idempotency key: %w", err)
	}

	var uploadOwner uint64
	var uploadStatus string
	var blobID sql.NullInt64
	var blobState sql.NullString
	err = transaction.QueryRowContext(ctx, `
SELECT upload.created_by, upload.status, upload.blob_id, stored_blob.state
FROM uploads upload
LEFT JOIN blobs stored_blob ON stored_blob.id = upload.blob_id
WHERE upload.id = ?
FOR UPDATE`, record.UploadID).Scan(
		&uploadOwner, &uploadStatus, &blobID, &blobState,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return View{}, false, ErrNotFound
	}
	if err != nil {
		return View{}, false, fmt.Errorf("lock task upload: %w", err)
	}
	if !record.Administrator && uploadOwner != record.UserID {
		return View{}, false, ErrForbidden
	}
	if uploadStatus != "completed" {
		return View{}, false, ErrUploadNotCompleted
	}

	existing, err := queryTaskByUpload(ctx, transaction, record.UploadID)
	if err == nil {
		return existing, false, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return View{}, false, fmt.Errorf("find existing task for upload: %w", err)
	}
	if !blobID.Valid || blobID.Int64 <= 0 || !blobState.Valid || blobState.String != "available" {
		return View{}, false, ErrConflict
	}

	// Upload completion owns one blob reference. A task owns a second reference so
	// upload-session cleanup cannot remove a sample still retained by the task.
	result, err := transaction.ExecContext(ctx, `
UPDATE blobs
SET reference_count = reference_count + 1
WHERE id = ? AND state = 'available'`, blobID.Int64)
	if err != nil {
		return View{}, false, fmt.Errorf("retain task blob: %w", err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return View{}, false, fmt.Errorf("inspect task blob retention: %w", err)
	}
	if affected != 1 {
		return View{}, false, ErrConflict
	}

	if _, err := transaction.ExecContext(ctx, `
	INSERT INTO tasks (
	    id, upload_id, idempotency_key, blob_id, created_by, name, tags, status, stage,
	    progress_basis_points, risk_level, limits_snapshot, root_format,
	    sample_expires_at, created_at, updated_at, event_sequence
	) VALUES (?, ?, ?, ?, ?, ?, JSON_ARRAY(), 'QUEUED', NULL, 0, 'UNKNOWN', ?, NULL, ?, ?, ?, 1)`,
		record.TaskID, record.UploadID, record.IdempotencyKey,
		blobID.Int64, record.UserID, record.Name,
		record.LimitsSnapshot, record.SampleExpiresAt, record.CreatedAt, record.CreatedAt,
	); err != nil {
		return View{}, false, fmt.Errorf("create task: %w", err)
	}
	if err := taskevent.AppendCurrentState(
		ctx, transaction, record.TaskID, "task.created", "Task created.",
	); err != nil {
		return View{}, false, err
	}

	attemptResult, err := transaction.ExecContext(ctx, `
INSERT INTO task_attempts (
    task_id, attempt_number, fencing_token, status, created_at
) VALUES (?, 1, 1, 'queued', ?)`, record.TaskID, record.CreatedAt)
	if err != nil {
		return View{}, false, fmt.Errorf("create initial task attempt: %w", err)
	}
	attemptID, err := attemptResult.LastInsertId()
	if err != nil {
		return View{}, false, fmt.Errorf("read initial task attempt ID: %w", err)
	}

	payload, err := json.Marshal(map[string]any{
		"attempt_number": 1,
		"task_id":        record.TaskID,
	})
	if err != nil {
		return View{}, false, fmt.Errorf("encode initial scan job: %w", err)
	}
	if _, err := transaction.ExecContext(ctx, `
INSERT INTO jobs (
    id, task_id, task_attempt_id, kind, status, payload, available_at,
    attempt, max_attempts, fencing_token, idempotency_key, created_at, updated_at
) VALUES (?, ?, ?, 'scan', 'queued', ?, ?, 0, 3, 1, ?, ?, ?)`,
		record.JobID, record.TaskID, attemptID, payload, record.CreatedAt,
		record.IdempotencyKey, record.CreatedAt, record.CreatedAt,
	); err != nil {
		return View{}, false, fmt.Errorf("create initial scan job: %w", err)
	}

	created, err := queryTaskByID(ctx, transaction, record.TaskID)
	if err != nil {
		return View{}, false, fmt.Errorf("read created task: %w", err)
	}
	if err := transaction.Commit(); err != nil {
		return View{}, false, fmt.Errorf("commit task creation: %w", err)
	}
	return created, true, nil
}

func (r *MySQLRepository) resolveCreateDuplicate(
	ctx context.Context,
	record CreateRecord,
) (View, bool, error) {
	transaction, err := r.db.BeginTx(ctx, &sql.TxOptions{
		Isolation: sql.LevelReadCommitted,
		ReadOnly:  true,
	})
	if err != nil {
		return View{}, false, fmt.Errorf("begin task duplicate resolution: %w", err)
	}
	defer transaction.Rollback()

	var replayTaskID string
	var replayUploadID string
	var replayName string
	err = transaction.QueryRowContext(ctx, `
SELECT id, upload_id, name
FROM tasks
WHERE created_by = ? AND idempotency_key = ?
LIMIT 1`, record.UserID, record.IdempotencyKey).Scan(
		&replayTaskID, &replayUploadID, &replayName,
	)
	if err == nil {
		if replayUploadID != record.UploadID || replayName != record.Name {
			if commitErr := transaction.Commit(); commitErr != nil {
				return View{}, false, fmt.Errorf("commit task duplicate resolution: %w", commitErr)
			}
			return View{}, false, ErrConflict
		}
		existing, queryErr := queryTaskByID(ctx, transaction, replayTaskID)
		if queryErr != nil {
			return View{}, false, fmt.Errorf("read duplicate task replay: %w", queryErr)
		}
		if commitErr := transaction.Commit(); commitErr != nil {
			return View{}, false, fmt.Errorf("commit task duplicate resolution: %w", commitErr)
		}
		return existing, false, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return View{}, false, fmt.Errorf("find duplicate task idempotency key: %w", err)
	}

	existing, err := queryTaskByUpload(ctx, transaction, record.UploadID)
	if err == nil {
		if commitErr := transaction.Commit(); commitErr != nil {
			return View{}, false, fmt.Errorf("commit task duplicate resolution: %w", commitErr)
		}
		return existing, false, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return View{}, false, fmt.Errorf("find duplicate task upload: %w", err)
	}
	if commitErr := transaction.Commit(); commitErr != nil {
		return View{}, false, fmt.Errorf("commit task duplicate resolution: %w", commitErr)
	}
	return View{}, false, ErrConflict
}

func (r *MySQLRepository) List(ctx context.Context, query ListQuery) (Page, error) {
	if query.PageSize < 1 || query.PageSize > maxPageSize {
		return Page{}, ErrInvalidInput
	}
	where, arguments, err := taskFilters(query)
	if err != nil {
		return Page{}, err
	}
	listArguments := append(arguments, query.PageSize+1)
	rows, err := r.db.QueryContext(ctx, taskSelectColumns+where+`
ORDER BY t.created_at DESC, t.id DESC
LIMIT ?`, listArguments...)
	if err != nil {
		return Page{}, fmt.Errorf("list tasks: %w", err)
	}
	defer rows.Close()

	items := make([]View, 0)
	for rows.Next() {
		item, err := scanTask(rows)
		if err != nil {
			return Page{}, fmt.Errorf("scan task list row: %w", err)
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return Page{}, fmt.Errorf("iterate task list: %w", err)
	}
	page := Page{Items: items}
	if len(page.Items) > query.PageSize {
		page.Items = page.Items[:query.PageSize]
		page.HasMore = true
	}
	return page, nil
}

func (r *MySQLRepository) Get(ctx context.Context, id string) (View, error) {
	value, err := queryTaskByID(ctx, r.db, id)
	if errors.Is(err, sql.ErrNoRows) {
		return View{}, ErrNotFound
	}
	if err != nil {
		return View{}, fmt.Errorf("get task: %w", err)
	}
	return value, nil
}

type lockedTaskState struct {
	CreatedBy       uint64
	Status          string
	SampleExpiresAt time.Time
	SampleDeletedAt sql.NullTime
	DeletedAt       sql.NullTime
	DatabaseNow     time.Time
}

func (r *MySQLRepository) Cancel(
	ctx context.Context,
	record MutationRecord,
) (View, error) {
	for attempt := 0; attempt < maxLifecycleTransactionAttempts; attempt++ {
		value, err := r.cancelOnce(ctx, record)
		if err == nil {
			return value, nil
		}
		if !isRetryableTransactionError(err) ||
			attempt == maxLifecycleTransactionAttempts-1 {
			return View{}, err
		}
		if err := waitForCreateRetry(ctx, attempt); err != nil {
			return View{}, err
		}
	}
	return View{}, errors.New("task cancellation exhausted transaction attempts")
}

func (r *MySQLRepository) cancelOnce(
	ctx context.Context,
	record MutationRecord,
) (View, error) {
	transaction, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return View{}, fmt.Errorf("begin task cancellation: %w", err)
	}
	defer transaction.Rollback()

	state, err := lockTaskState(ctx, transaction, record.TaskID)
	if errors.Is(err, sql.ErrNoRows) {
		return View{}, ErrNotFound
	}
	if err != nil {
		return View{}, fmt.Errorf("lock task for cancellation: %w", err)
	}
	replay, err := taskActionRecorded(
		ctx, transaction, record.TaskID, "cancel", record.IdempotencyKey,
	)
	if err != nil {
		return View{}, err
	}
	if replay {
		return queryTaskByID(ctx, transaction, record.TaskID)
	}
	switch state.Status {
	case StatusCancelRequested, StatusCancelled:
		if err := recordTaskAction(
			ctx, transaction, record.TaskID, "cancel", record.IdempotencyKey,
		); err != nil {
			return View{}, err
		}
		value, err := queryTaskByID(ctx, transaction, record.TaskID)
		if err != nil {
			return View{}, fmt.Errorf("read idempotently cancelled task: %w", err)
		}
		if err := transaction.Commit(); err != nil {
			return View{}, fmt.Errorf("commit idempotent task cancellation: %w", err)
		}
		return value, nil
	case StatusQueued, "VALIDATING", "IDENTIFYING", "EXTRACTING",
		"INDEXING", "SCANNING", "REPORTING":
		// These are the only states from which execution can still be stopped.
	default:
		return View{}, ErrInvalidState
	}

	running, err := cancelActiveJobs(ctx, transaction, record.TaskID)
	if err != nil {
		return View{}, err
	}
	nextStatus := StatusCancelled
	if running {
		nextStatus = StatusCancelRequested
	}
	if nextStatus == StatusCancelled && record.SampleRetention < time.Microsecond {
		return View{}, ErrInvalidInput
	}
	result, err := transaction.ExecContext(ctx, `
	UPDATE tasks
	SET status = ?,
	    stage = CASE WHEN ? = 'CANCELLED' THEN NULL ELSE stage END,
    completed_at = CASE
        WHEN ? = 'CANCELLED' THEN UTC_TIMESTAMP(6)
        ELSE NULL
	    END,
	    sample_expires_at = CASE
	        WHEN ? = 'CANCELLED'
	         AND sample_deleted_at IS NULL
	         AND deleted_at IS NULL
	        THEN GREATEST(
	            sample_expires_at,
	            DATE_ADD(UTC_TIMESTAMP(6), INTERVAL ? MICROSECOND)
	        )
	        ELSE sample_expires_at
	    END,
	    error_code = NULL,
	    error_message = NULL,
	    event_sequence = event_sequence + 1
WHERE id = ? AND status = ?`,
		nextStatus, nextStatus, nextStatus, nextStatus,
		record.SampleRetention.Microseconds(), record.TaskID, state.Status,
	)
	if err != nil {
		return View{}, fmt.Errorf("update cancelled task: %w", err)
	}
	if err := requireExactlyOne(result, "inspect cancelled task"); err != nil {
		return View{}, err
	}
	if err := taskevent.AppendCurrentState(
		ctx,
		transaction,
		record.TaskID,
		"task.status_changed",
		"Task cancellation state changed.",
	); err != nil {
		return View{}, err
	}
	if err := recordTaskAction(
		ctx, transaction, record.TaskID, "cancel", record.IdempotencyKey,
	); err != nil {
		return View{}, err
	}
	value, err := queryTaskByID(ctx, transaction, record.TaskID)
	if err != nil {
		return View{}, fmt.Errorf("read cancelled task: %w", err)
	}
	if err := transaction.Commit(); err != nil {
		return View{}, fmt.Errorf("commit task cancellation: %w", err)
	}
	return value, nil
}

func (r *MySQLRepository) Retry(
	ctx context.Context,
	record RetryRecord,
) (View, error) {
	for attempt := 0; attempt < maxLifecycleTransactionAttempts; attempt++ {
		value, err := r.retryOnce(ctx, record)
		if err == nil {
			return value, nil
		}
		if isDuplicateKey(err) {
			return r.resolveRetryDuplicate(ctx, record)
		}
		if !isRetryableTransactionError(err) ||
			attempt == maxLifecycleTransactionAttempts-1 {
			return View{}, err
		}
		if err := waitForCreateRetry(ctx, attempt); err != nil {
			return View{}, err
		}
	}
	return View{}, errors.New("task retry exhausted transaction attempts")
}

func (r *MySQLRepository) retryOnce(
	ctx context.Context,
	record RetryRecord,
) (View, error) {
	transaction, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return View{}, fmt.Errorf("begin task retry: %w", err)
	}
	defer transaction.Rollback()

	state, err := lockTaskState(ctx, transaction, record.TaskID)
	if errors.Is(err, sql.ErrNoRows) {
		return View{}, ErrNotFound
	}
	if err != nil {
		return View{}, fmt.Errorf("lock task for retry: %w", err)
	}
	replay, err := taskActionRecorded(
		ctx, transaction, record.TaskID, "retry", record.IdempotencyKey,
	)
	if err != nil {
		return View{}, err
	}
	if replay {
		return queryTaskByID(ctx, transaction, record.TaskID)
	}
	switch state.Status {
	case "FAILED", StatusCancelled, "PARTIAL_SUCCEEDED":
	default:
		return View{}, ErrInvalidState
	}
	if state.SampleDeletedAt.Valid ||
		!state.SampleExpiresAt.After(state.DatabaseNow) {
		return View{}, ErrSampleUnavailable
	}

	var maxAttemptNumber uint64
	var maxFencingToken uint64
	if err := transaction.QueryRowContext(ctx, `
SELECT COALESCE(MAX(attempt_number), 0),
       COALESCE(MAX(fencing_token), 0)
FROM task_attempts
WHERE task_id = ?`, record.TaskID).Scan(
		&maxAttemptNumber, &maxFencingToken,
	); err != nil {
		return View{}, fmt.Errorf("read task retry sequence: %w", err)
	}
	if maxAttemptNumber >= uint64(^uint32(0)) || maxFencingToken == ^uint64(0) {
		return View{}, ErrConflict
	}
	attemptNumber := maxAttemptNumber + 1
	fencingToken := maxFencingToken + 1
	attemptResult, err := transaction.ExecContext(ctx, `
INSERT INTO task_attempts (
    task_id, attempt_number, fencing_token, status, created_at
) VALUES (?, ?, ?, 'queued', UTC_TIMESTAMP(6))`,
		record.TaskID, attemptNumber, fencingToken,
	)
	if err != nil {
		return View{}, fmt.Errorf("create retry task attempt: %w", err)
	}
	attemptID, err := attemptResult.LastInsertId()
	if err != nil {
		return View{}, fmt.Errorf("read retry task attempt ID: %w", err)
	}

	payload, err := json.Marshal(map[string]any{
		"attempt_number": attemptNumber,
		"task_id":        record.TaskID,
	})
	if err != nil {
		return View{}, fmt.Errorf("encode retry scan job: %w", err)
	}
	if _, err := transaction.ExecContext(ctx, `
INSERT INTO jobs (
    id, task_id, task_attempt_id, kind, status, payload, available_at,
    attempt, max_attempts, fencing_token, idempotency_key, created_at, updated_at
) VALUES (?, ?, ?, 'scan', 'queued', ?, UTC_TIMESTAMP(6),
          0, 3, ?, NULL, UTC_TIMESTAMP(6), UTC_TIMESTAMP(6))`,
		record.JobID, record.TaskID, attemptID, payload,
		fencingToken,
	); err != nil {
		return View{}, fmt.Errorf("create retry scan job: %w", err)
	}
	result, err := transaction.ExecContext(ctx, `
UPDATE tasks
SET status = 'QUEUED',
    stage = NULL,
	    progress_basis_points = 0,
	    error_code = NULL,
	    error_message = NULL,
	    completed_at = NULL,
	    event_sequence = event_sequence + 1
WHERE id = ? AND status = ?`,
		record.TaskID, state.Status,
	)
	if err != nil {
		return View{}, fmt.Errorf("queue task retry: %w", err)
	}
	if err := requireExactlyOne(result, "inspect queued task retry"); err != nil {
		return View{}, err
	}
	if err := taskevent.AppendCurrentState(
		ctx,
		transaction,
		record.TaskID,
		"task.status_changed",
		"Task queued for retry.",
	); err != nil {
		return View{}, err
	}
	if err := recordTaskAction(
		ctx, transaction, record.TaskID, "retry", record.IdempotencyKey,
	); err != nil {
		return View{}, err
	}
	value, err := queryTaskByID(ctx, transaction, record.TaskID)
	if err != nil {
		return View{}, fmt.Errorf("read retried task: %w", err)
	}
	if err := transaction.Commit(); err != nil {
		return View{}, fmt.Errorf("commit task retry: %w", err)
	}
	return value, nil
}

func (r *MySQLRepository) resolveRetryDuplicate(
	ctx context.Context,
	record RetryRecord,
) (View, error) {
	transaction, err := r.db.BeginTx(ctx, &sql.TxOptions{
		Isolation: sql.LevelReadCommitted,
		ReadOnly:  true,
	})
	if err != nil {
		return View{}, fmt.Errorf("begin task retry duplicate resolution: %w", err)
	}
	defer transaction.Rollback()
	replay, err := taskActionRecorded(
		ctx, transaction, record.TaskID, "retry", record.IdempotencyKey,
	)
	if err != nil {
		return View{}, fmt.Errorf("resolve task retry idempotency key: %w", err)
	}
	if !replay {
		return View{}, ErrConflict
	}
	value, err := queryTaskByID(ctx, transaction, record.TaskID)
	if err != nil {
		return View{}, fmt.Errorf("read duplicate task retry: %w", err)
	}
	if err := transaction.Commit(); err != nil {
		return View{}, fmt.Errorf("commit task retry duplicate resolution: %w", err)
	}
	return value, nil
}

func (r *MySQLRepository) Delete(
	ctx context.Context,
	record MutationRecord,
) (View, error) {
	for attempt := 0; attempt < maxLifecycleTransactionAttempts; attempt++ {
		value, err := r.deleteOnce(ctx, record)
		if err == nil {
			return value, nil
		}
		if !isRetryableTransactionError(err) ||
			attempt == maxLifecycleTransactionAttempts-1 {
			return View{}, err
		}
		if err := waitForCreateRetry(ctx, attempt); err != nil {
			return View{}, err
		}
	}
	return View{}, errors.New("task deletion exhausted transaction attempts")
}

func (r *MySQLRepository) deleteOnce(
	ctx context.Context,
	record MutationRecord,
) (View, error) {
	transaction, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return View{}, fmt.Errorf("begin task deletion: %w", err)
	}
	defer transaction.Rollback()

	state, err := lockTaskState(ctx, transaction, record.TaskID)
	if errors.Is(err, sql.ErrNoRows) {
		return View{}, ErrNotFound
	}
	if err != nil {
		return View{}, fmt.Errorf("lock task for deletion: %w", err)
	}
	if !record.Administrator && state.CreatedBy != record.UserID {
		return View{}, ErrForbidden
	}
	if state.Status == StatusDeleting || state.Status == StatusDeleted {
		return queryTaskByID(ctx, transaction, record.TaskID)
	}
	var activeRetention uint8
	err = transaction.QueryRowContext(ctx, `
SELECT EXISTS (
    SELECT 1
    FROM task_sample_retention_operations operation
    WHERE operation.task_id = ?
      AND operation.status = 'cleaning'
      AND operation.lease_until > UTC_TIMESTAMP(6)
)`, record.TaskID).Scan(&activeRetention)
	if err != nil {
		return View{}, fmt.Errorf(
			"inspect active task sample retention: %w", err,
		)
	}
	if activeRetention != 0 {
		return View{}, ErrConflict
	}
	if _, err := cancelActiveJobs(ctx, transaction, record.TaskID); err != nil {
		return View{}, err
	}
	if err := cancelQueuedReports(ctx, transaction, record.TaskID); err != nil {
		return View{}, err
	}
	result, err := transaction.ExecContext(ctx, `
	UPDATE tasks
	SET status = 'DELETING',
	    stage = NULL,
	    event_sequence = event_sequence + 1
WHERE id = ? AND status = ?`,
		record.TaskID, state.Status,
	)
	if err != nil {
		return View{}, fmt.Errorf("mark task deleting: %w", err)
	}
	if err := requireExactlyOne(result, "inspect deleting task"); err != nil {
		return View{}, err
	}
	if err := taskevent.AppendCurrentState(
		ctx,
		transaction,
		record.TaskID,
		"task.status_changed",
		"Task entered deletion.",
	); err != nil {
		return View{}, err
	}
	value, err := queryTaskByID(ctx, transaction, record.TaskID)
	if err != nil {
		return View{}, fmt.Errorf("read deleting task: %w", err)
	}
	if err := transaction.Commit(); err != nil {
		return View{}, fmt.Errorf("commit task deletion: %w", err)
	}
	return value, nil
}

func (r *MySQLRepository) ExtendRetention(
	ctx context.Context,
	record RetentionRecord,
) (View, error) {
	for attempt := 0; attempt < maxLifecycleTransactionAttempts; attempt++ {
		value, err := r.extendRetentionOnce(ctx, record)
		if err == nil {
			return value, nil
		}
		if !isRetryableTransactionError(err) ||
			attempt == maxLifecycleTransactionAttempts-1 {
			return View{}, err
		}
		if err := waitForCreateRetry(ctx, attempt); err != nil {
			return View{}, err
		}
	}
	return View{}, errors.New("task retention extension exhausted transaction attempts")
}

func (r *MySQLRepository) extendRetentionOnce(
	ctx context.Context,
	record RetentionRecord,
) (View, error) {
	transaction, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return View{}, fmt.Errorf("begin task retention extension: %w", err)
	}
	defer transaction.Rollback()

	state, err := lockTaskState(ctx, transaction, record.TaskID)
	if errors.Is(err, sql.ErrNoRows) {
		return View{}, ErrNotFound
	}
	if err != nil {
		return View{}, fmt.Errorf("lock task for retention extension: %w", err)
	}
	if state.Status == StatusDeleting || state.Status == StatusDeleted ||
		state.DeletedAt.Valid {
		return View{}, ErrInvalidState
	}
	if state.SampleDeletedAt.Valid ||
		!state.SampleExpiresAt.After(state.DatabaseNow) {
		return View{}, ErrSampleUnavailable
	}

	if state.SampleExpiresAt.Equal(record.SampleExpiresAt) {
		value, err := queryTaskByID(ctx, transaction, record.TaskID)
		if err != nil {
			return View{}, fmt.Errorf("read replayed task retention extension: %w", err)
		}
		if err := transaction.Commit(); err != nil {
			return View{}, fmt.Errorf("commit replayed task retention extension: %w", err)
		}
		return value, nil
	}
	if !state.SampleExpiresAt.Equal(record.ExpectedSampleExpiresAt) {
		return View{}, ErrConflict
	}

	result, err := transaction.ExecContext(ctx, `
	UPDATE tasks
	SET sample_expires_at = ?,
	    updated_at = UTC_TIMESTAMP(6),
	    event_sequence = event_sequence + 1
WHERE id = ?
  AND sample_expires_at = ?
  AND sample_deleted_at IS NULL
  AND deleted_at IS NULL
  AND sample_expires_at > UTC_TIMESTAMP(6)
  AND status NOT IN ('DELETING', 'DELETED')`,
		record.SampleExpiresAt, record.TaskID, record.ExpectedSampleExpiresAt,
	)
	if err != nil {
		return View{}, fmt.Errorf("extend task sample retention: %w", err)
	}
	if err := requireExactlyOne(result, "inspect task retention extension"); err != nil {
		return View{}, err
	}
	if err := taskevent.AppendCurrentState(
		ctx,
		transaction,
		record.TaskID,
		"task.retention_changed",
		"Task sample retention changed.",
	); err != nil {
		return View{}, err
	}
	value, err := queryTaskByID(ctx, transaction, record.TaskID)
	if err != nil {
		return View{}, fmt.Errorf("read extended task retention: %w", err)
	}
	if err := transaction.Commit(); err != nil {
		return View{}, fmt.Errorf("commit task retention extension: %w", err)
	}
	return value, nil
}

func lockTaskState(
	ctx context.Context,
	transaction *sql.Tx,
	taskID string,
) (lockedTaskState, error) {
	var state lockedTaskState
	err := transaction.QueryRowContext(ctx, `
SELECT created_by, status, sample_expires_at, sample_deleted_at, deleted_at,
       UTC_TIMESTAMP(6)
FROM tasks
WHERE id = ?
LIMIT 1
FOR UPDATE`, taskID).Scan(
		&state.CreatedBy, &state.Status, &state.SampleExpiresAt,
		&state.SampleDeletedAt, &state.DeletedAt, &state.DatabaseNow,
	)
	return state, err
}

func taskActionRecorded(
	ctx context.Context,
	transaction *sql.Tx,
	taskID string,
	action string,
	idempotencyKey string,
) (bool, error) {
	var exists bool
	if err := transaction.QueryRowContext(ctx, `
SELECT EXISTS (
    SELECT 1
    FROM task_action_requests
    WHERE task_id = ? AND action = ? AND idempotency_key = ?
)`, taskID, action, idempotencyKey).Scan(&exists); err != nil {
		return false, fmt.Errorf("find task action idempotency key: %w", err)
	}
	return exists, nil
}

func recordTaskAction(
	ctx context.Context,
	transaction *sql.Tx,
	taskID string,
	action string,
	idempotencyKey string,
) error {
	if _, err := transaction.ExecContext(ctx, `
INSERT INTO task_action_requests (
    task_id, action, idempotency_key, created_at
) VALUES (?, ?, ?, UTC_TIMESTAMP(6))`,
		taskID, action, idempotencyKey,
	); err != nil {
		return fmt.Errorf("record task action idempotency key: %w", err)
	}
	return nil
}

func cancelActiveJobs(
	ctx context.Context,
	transaction *sql.Tx,
	taskID string,
) (bool, error) {
	if _, err := transaction.ExecContext(ctx, `
UPDATE task_attempts attempt
JOIN jobs job
  ON job.task_id = attempt.task_id
 AND job.task_attempt_id = attempt.id
LEFT JOIN jobs active
  ON active.task_id = attempt.task_id
 AND active.task_attempt_id = attempt.id
 AND active.status IN ('running', 'cancel_requested')
SET attempt.status = 'cancelled',
    attempt.completed_at = UTC_TIMESTAMP(6),
    attempt.error_code = NULL,
    attempt.error_message = NULL
WHERE job.task_id = ?
  AND job.kind IN ('scan', 'trivy')
  AND job.status IN ('queued', 'leased')
  AND attempt.status IN ('queued', 'running')
  AND attempt.fencing_token = job.fencing_token
  AND active.id IS NULL`, taskID); err != nil {
		return false, fmt.Errorf("cancel inactive task attempts: %w", err)
	}
	for _, pool := range []string{"global", "trivy", "native"} {
		if _, err := transaction.ExecContext(ctx, `
UPDATE job_resource_slots slot
JOIN jobs job
  ON job.id = slot.job_id
 AND job.fencing_token = slot.job_fencing_token
SET slot.job_id = NULL,
    slot.job_fencing_token = NULL,
    slot.lease_owner = NULL,
    slot.acquired_at = NULL
WHERE job.task_id = ?
  AND slot.pool = ?
  AND job.status IN ('queued', 'leased')`, taskID, pool); err != nil {
			return false, fmt.Errorf(
				"release inactive task %s resource slots: %w",
				pool,
				err,
			)
		}
	}
	if _, err := transaction.ExecContext(ctx, `
UPDATE jobs
SET status = 'cancelled',
    lease_owner = NULL,
    lease_until = NULL,
    heartbeat_at = NULL,
    cancel_requested_at = COALESCE(cancel_requested_at, UTC_TIMESTAMP(6)),
    completed_at = UTC_TIMESTAMP(6),
    error_code = NULL,
    error_message = NULL
WHERE task_id = ? AND status IN ('queued', 'leased')`, taskID); err != nil {
		return false, fmt.Errorf("cancel inactive task jobs: %w", err)
	}
	result, err := transaction.ExecContext(ctx, `
UPDATE jobs
SET status = 'cancel_requested',
    cancel_requested_at = COALESCE(cancel_requested_at, UTC_TIMESTAMP(6))
WHERE task_id = ? AND status = 'running'`, taskID)
	if err != nil {
		return false, fmt.Errorf("request running task job cancellation: %w", err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("inspect running task job cancellation: %w", err)
	}
	return affected > 0, nil
}

func cancelQueuedReports(
	ctx context.Context,
	transaction *sql.Tx,
	taskID string,
) error {
	_, err := transaction.ExecContext(ctx, `
UPDATE reports
SET status = 'failed',
    error_code = 'task_deleted',
    error_message = 'Report generation stopped because the task was deleted.',
    completed_at = UTC_TIMESTAMP(6)
WHERE task_id = ?
  AND status = 'queued'`, taskID)
	if err != nil {
		return fmt.Errorf("stop queued task report generation: %w", err)
	}
	return nil
}

func requireExactlyOne(result sql.Result, operation string) error {
	affected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("%s: %w", operation, err)
	}
	if affected != 1 {
		return ErrConflict
	}
	return nil
}

func queryTaskByID(
	ctx context.Context,
	querier rowQuerier,
	id string,
) (View, error) {
	return scanTask(querier.QueryRowContext(
		ctx, taskSelectColumns+`
WHERE t.id = ?
LIMIT 1`, id,
	))
}

func queryTaskByUpload(
	ctx context.Context,
	querier rowQuerier,
	uploadID string,
) (View, error) {
	return scanTask(querier.QueryRowContext(
		ctx, taskSelectColumns+`
WHERE t.upload_id = ?
LIMIT 1`, uploadID,
	))
}

func scanTask(scanner rowScanner) (View, error) {
	var value View
	var rootFormat sql.NullString
	var stage sql.NullString
	var errorCode sql.NullString
	var errorMessage sql.NullString
	var sampleDeletedAt sql.NullTime
	var tagsJSON []byte
	var progressBasisPoints uint16
	if err := scanner.Scan(
		&value.ID, &value.Name, &rootFormat, &value.Status, &value.RiskLevel,
		&progressBasisPoints, &value.CreatorID, &value.CreatorName, &tagsJSON,
		&value.CreatedAt, &value.UpdatedAt, &value.OriginalFilename,
		&value.SizeBytes, &value.SHA256, &stage, &errorCode,
		&errorMessage, &value.SampleExpiresAt, &sampleDeletedAt,
	); err != nil {
		return View{}, err
	}
	if sampleDeletedAt.Valid {
		value.SampleDeletedAt = &sampleDeletedAt.Time
	}
	value.InputType = UnknownInput
	if rootFormat.Valid && strings.TrimSpace(rootFormat.String) != "" {
		value.InputType = rootFormat.String
	}
	value.Progress = float64(progressBasisPoints) / 100
	value.ProgressIndeterminate = taskprogress.IsIndeterminate(
		stage.String,
		progressBasisPoints,
	)
	value.Tags = []string{}
	if len(tagsJSON) > 0 {
		if err := json.Unmarshal(tagsJSON, &value.Tags); err != nil {
			return View{}, fmt.Errorf("decode task tags: %w", err)
		}
		if value.Tags == nil {
			value.Tags = []string{}
		}
	}
	value.CurrentStage = stage.String
	value.ErrorCode = errorCode.String
	value.ErrorMessage = errorMessage.String
	return value, nil
}

func taskFilters(query ListQuery) (string, []any, error) {
	conditions := make([]string, 0, 8)
	arguments := make([]any, 0, 13)
	if query.Keyword != "" {
		conditions = append(conditions,
			"(t.name LIKE ? ESCAPE '!' OR upload.display_name LIKE ? ESCAPE '!')")
		pattern := "%" + escapeLike(query.Keyword) + "%"
		arguments = append(arguments, pattern, pattern)
	}
	if query.Status != "" {
		conditions = append(conditions, "t.status = ?")
		arguments = append(arguments, query.Status)
	}
	if query.InputType != "" {
		conditions = append(conditions,
			"LOWER(COALESCE(NULLIF(t.root_format, ''), 'unknown')) = ?")
		arguments = append(arguments, query.InputType)
	}
	if query.Creator != "" {
		conditions = append(conditions,
			"(creator.display_name LIKE ? ESCAPE '!' OR creator.username LIKE ? ESCAPE '!')")
		pattern := "%" + escapeLike(query.Creator) + "%"
		arguments = append(arguments, pattern, pattern)
	}
	if query.Tag != "" {
		conditions = append(conditions,
			"JSON_CONTAINS(COALESCE(t.tags, JSON_ARRAY()), JSON_QUOTE(?), '$')")
		arguments = append(arguments, query.Tag)
	}
	if query.CreatedFrom != "" {
		createdFrom, valid := parseListDate(query.CreatedFrom)
		if !valid {
			return "", nil, ErrInvalidInput
		}
		conditions = append(conditions, "t.created_at >= ?")
		arguments = append(arguments, createdFrom)
	}
	if query.CreatedTo != "" {
		createdTo, valid := parseListDate(query.CreatedTo)
		if !valid {
			return "", nil, ErrInvalidInput
		}
		conditions = append(conditions, "t.created_at < ?")
		arguments = append(arguments, createdTo.AddDate(0, 0, 1))
	}
	if query.After != nil {
		if query.After.CreatedAt.IsZero() || !uuidPattern.MatchString(query.After.ID) {
			return "", nil, ErrInvalidInput
		}
		conditions = append(conditions,
			"(t.created_at < ? OR (t.created_at = ? AND t.id < ?))")
		arguments = append(
			arguments,
			query.After.CreatedAt,
			query.After.CreatedAt,
			query.After.ID,
		)
	}
	if len(conditions) == 0 {
		return "", arguments, nil
	}
	return "\nWHERE " + strings.Join(conditions, " AND "), arguments, nil
}

func escapeLike(value string) string {
	value = strings.ReplaceAll(value, "!", "!!")
	value = strings.ReplaceAll(value, "%", "!%")
	return strings.ReplaceAll(value, "_", "!_")
}

func isDuplicateKey(err error) bool {
	var mysqlError *mysql.MySQLError
	return errors.As(err, &mysqlError) && mysqlError.Number == 1062
}

func isRetryableTransactionError(err error) bool {
	var mysqlError *mysql.MySQLError
	if !errors.As(err, &mysqlError) {
		return false
	}
	return mysqlError.Number == 1213 || mysqlError.Number == 1205
}

func waitForCreateRetry(ctx context.Context, attempt int) error {
	delay := initialCreateRetryBackoff << attempt
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

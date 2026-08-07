package upload

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/go-sql-driver/mysql"
)

type Repository interface {
	ResolveCreate(context.Context, uint64, string, string, string) (Upload, bool, error)
	Create(context.Context, Upload, string, string, string) (Upload, bool, error)
	Get(context.Context, string) (Upload, error)
	ListParts(context.Context, string) ([]Part, error)
	InsertPart(context.Context, Part) error
	PrepareCompletion(context.Context, string, string, int64, string) error
	FinalizeCompletion(context.Context, string, string, time.Time) error
	CleanupParts(context.Context, string, func() error) (bool, error)
	Cancel(context.Context, string) error
	WithLock(context.Context, string, func(context.Context) error) error
}

const (
	maxCreateAttempts      = 3
	initialCreateRetryWait = 10 * time.Millisecond
)

type MySQLRepository struct {
	db *sql.DB
}

type lockConnectionContextKey struct{}

type sqlExecutor interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

func NewMySQLRepository(db *sql.DB) *MySQLRepository {
	return &MySQLRepository{db: db}
}

func (r *MySQLRepository) ResolveCreate(
	ctx context.Context,
	createdBy uint64,
	operation string,
	idempotencyKey string,
	requestFingerprint string,
) (Upload, bool, error) {
	return findIdempotentCreate(
		ctx,
		r.db,
		createdBy,
		operation,
		idempotencyKey,
		requestFingerprint,
		false,
	)
}

func (r *MySQLRepository) Create(
	ctx context.Context,
	value Upload,
	operation string,
	idempotencyKey string,
	requestFingerprint string,
) (Upload, bool, error) {
	for attempt := 0; attempt < maxCreateAttempts; attempt++ {
		stored, created, err := r.createOnce(
			ctx,
			value,
			operation,
			idempotencyKey,
			requestFingerprint,
		)
		if err == nil {
			return stored, created, nil
		}
		if isDuplicateCreateKey(err) {
			existing, found, resolveErr := r.ResolveCreate(
				ctx,
				value.CreatedBy,
				operation,
				idempotencyKey,
				requestFingerprint,
			)
			if resolveErr != nil {
				return Upload{}, false, resolveErr
			}
			if found {
				return existing, false, nil
			}
			return Upload{}, false, err
		}
		if !isRetryableCreateTransaction(err) ||
			attempt == maxCreateAttempts-1 {
			return Upload{}, false, err
		}
		if err := waitForCreateRetry(ctx, attempt); err != nil {
			return Upload{}, false, err
		}
	}
	return Upload{}, false, errors.New("upload creation exhausted transaction attempts")
}

func (r *MySQLRepository) createOnce(
	ctx context.Context,
	value Upload,
	operation string,
	idempotencyKey string,
	requestFingerprint string,
) (Upload, bool, error) {
	transaction, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return Upload{}, false, fmt.Errorf("begin upload creation transaction: %w", err)
	}
	defer transaction.Rollback()

	existing, found, err := findIdempotentCreate(
		ctx,
		transaction,
		value.CreatedBy,
		operation,
		idempotencyKey,
		requestFingerprint,
		true,
	)
	if err != nil {
		return Upload{}, false, err
	}
	if found {
		if err := transaction.Commit(); err != nil {
			return Upload{}, false, fmt.Errorf("commit upload creation replay: %w", err)
		}
		return existing, false, nil
	}
	_, err = transaction.ExecContext(ctx, `
INSERT INTO uploads (
    id, created_by, original_name, display_name, content_type,
    declared_size_bytes, part_size_bytes, status, expires_at,
    idempotency_key, idempotency_operation, request_fingerprint
) VALUES (?, ?, ?, ?, ?, ?, ?, 'created', ?, ?, ?, ?)`,
		value.ID, value.CreatedBy, value.OriginalName, value.DisplayName, value.ContentType,
		value.DeclaredSize, value.PartSize, value.ExpiresAt,
		idempotencyKey, operation, requestFingerprint,
	)
	if err != nil {
		return Upload{}, false, fmt.Errorf("create upload: %w", err)
	}
	if err := transaction.Commit(); err != nil {
		return Upload{}, false, fmt.Errorf("commit upload creation: %w", err)
	}
	return value, true, nil
}

func findIdempotentCreate(
	ctx context.Context,
	query rowQuerier,
	createdBy uint64,
	operation string,
	idempotencyKey string,
	requestFingerprint string,
	lock bool,
) (Upload, bool, error) {
	suffix := ""
	if lock {
		suffix = " FOR UPDATE"
	}
	var (
		value             Upload
		storedFingerprint string
	)
	err := query.QueryRowContext(ctx, `
SELECT id, created_by, original_name, display_name, content_type,
       declared_size_bytes, part_size_bytes, expires_at, created_at,
       request_fingerprint
FROM uploads
WHERE created_by = ?
  AND idempotency_operation = ?
  AND idempotency_key = ?
LIMIT 1`+suffix, createdBy, operation, idempotencyKey).Scan(
		&value.ID,
		&value.CreatedBy,
		&value.OriginalName,
		&value.DisplayName,
		&value.ContentType,
		&value.DeclaredSize,
		&value.PartSize,
		&value.ExpiresAt,
		&value.CreatedAt,
		&storedFingerprint,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return Upload{}, false, nil
	}
	if err != nil {
		return Upload{}, false, fmt.Errorf("find upload creation idempotency key: %w", err)
	}
	if storedFingerprint != requestFingerprint {
		return Upload{}, false, ErrIdempotencyConflict
	}
	value.Status = "created"
	return value, true, nil
}

type rowQuerier interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

func isDuplicateCreateKey(err error) bool {
	var mysqlError *mysql.MySQLError
	return errors.As(err, &mysqlError) && mysqlError.Number == 1062
}

func isRetryableCreateTransaction(err error) bool {
	var mysqlError *mysql.MySQLError
	if !errors.As(err, &mysqlError) {
		return false
	}
	return mysqlError.Number == 1205 || mysqlError.Number == 1213
}

func waitForCreateRetry(ctx context.Context, attempt int) error {
	timer := time.NewTimer(initialCreateRetryWait << attempt)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func (r *MySQLRepository) Get(ctx context.Context, id string) (Upload, error) {
	var value Upload
	var expectedSHA, actualSHA sql.NullString
	var blobID sql.NullInt64
	err := r.executor(ctx).QueryRowContext(ctx, `
SELECT id, created_by, original_name, display_name, content_type,
       declared_size_bytes, part_size_bytes, expected_sha256, actual_sha256,
       status, blob_id, expires_at, completed_at, parts_cleaned_at, created_at
FROM uploads
WHERE id = ?
LIMIT 1`, id).Scan(
		&value.ID, &value.CreatedBy, &value.OriginalName, &value.DisplayName, &value.ContentType,
		&value.DeclaredSize, &value.PartSize, &expectedSHA, &actualSHA,
		&value.Status, &blobID, &value.ExpiresAt, &value.CompletedAt,
		&value.PartsCleanedAt, &value.CreatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return Upload{}, ErrNotFound
		}
		return Upload{}, fmt.Errorf("get upload: %w", err)
	}
	value.ExpectedSHA256 = expectedSHA.String
	value.ActualSHA256 = actualSHA.String
	if blobID.Valid {
		id := uint64(blobID.Int64)
		value.BlobID = &id
	}
	return value, nil
}

func (r *MySQLRepository) ListParts(ctx context.Context, uploadID string) ([]Part, error) {
	rows, err := r.executor(ctx).QueryContext(ctx, `
SELECT upload_id, part_number, size_bytes, sha256, content_range, storage_key, created_at
FROM upload_parts
WHERE upload_id = ?
ORDER BY part_number ASC`, uploadID)
	if err != nil {
		return nil, fmt.Errorf("list upload parts: %w", err)
	}
	defer rows.Close()
	parts := make([]Part, 0)
	for rows.Next() {
		var part Part
		if err := rows.Scan(
			&part.UploadID, &part.Number, &part.Size, &part.SHA256,
			&part.ContentRange, &part.StorageKey, &part.CreatedAt,
		); err != nil {
			return nil, fmt.Errorf("scan upload part: %w", err)
		}
		parts = append(parts, part)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate upload parts: %w", err)
	}
	return parts, nil
}

func (r *MySQLRepository) InsertPart(ctx context.Context, part Part) error {
	transaction, err := r.beginTx(ctx)
	if err != nil {
		return fmt.Errorf("begin upload part transaction: %w", err)
	}
	defer transaction.Rollback()
	if _, err := transaction.ExecContext(ctx, `
INSERT INTO upload_parts (
    upload_id, part_number, size_bytes, sha256, content_range, storage_key
) VALUES (?, ?, ?, ?, ?, ?)`,
		part.UploadID, part.Number, part.Size, part.SHA256, part.ContentRange, part.StorageKey,
	); err != nil {
		return fmt.Errorf("insert upload part: %w", err)
	}
	if _, err := transaction.ExecContext(ctx, `
UPDATE uploads
SET status = 'uploading'
WHERE id = ? AND status = 'created'`, part.UploadID); err != nil {
		return fmt.Errorf("mark upload active: %w", err)
	}
	if err := transaction.Commit(); err != nil {
		return fmt.Errorf("commit upload part: %w", err)
	}
	return nil
}

func (r *MySQLRepository) PrepareCompletion(
	ctx context.Context,
	uploadID string,
	sha256Value string,
	size int64,
	storageKey string,
) error {
	transaction, err := r.beginTx(ctx)
	if err != nil {
		return fmt.Errorf("begin upload completion preparation: %w", err)
	}
	defer transaction.Rollback()

	var (
		status    string
		actualSHA sql.NullString
		blobID    sql.NullInt64
	)
	err = transaction.QueryRowContext(ctx, `
SELECT status, actual_sha256, blob_id
FROM uploads
WHERE id = ?
LIMIT 1
FOR UPDATE`, uploadID).Scan(&status, &actualSHA, &blobID)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return fmt.Errorf("lock upload completion preparation: %w", err)
	}
	switch status {
	case "assembling", "completed":
		if !actualSHA.Valid || actualSHA.String != sha256Value ||
			!blobID.Valid || blobID.Int64 <= 0 {
			return ErrConflict
		}
		expectedState := ""
		if status == "completed" {
			expectedState = "available"
		}
		if err := verifyPreparedBlob(
			ctx,
			transaction,
			uint64(blobID.Int64),
			sha256Value,
			size,
			storageKey,
			expectedState,
		); err != nil {
			return err
		}
		if err := transaction.Commit(); err != nil {
			return fmt.Errorf("commit idempotent upload completion preparation: %w", err)
		}
		return nil
	case "created", "uploading":
		// Continue below. The upload row lock prevents a duplicate reference on
		// a replay while the unique blob hash coordinates equal-content uploads.
	default:
		return ErrInvalidState
	}

	result, err := transaction.ExecContext(ctx, `
INSERT INTO blobs (sha256, size_bytes, storage_key, reference_count, state)
VALUES (?, ?, ?, 0, 'staging')
ON DUPLICATE KEY UPDATE
    id = LAST_INSERT_ID(id)`,
		sha256Value, size, storageKey,
	)
	if err != nil {
		return fmt.Errorf("prepare blob record: %w", err)
	}
	preparedBlobID, err := result.LastInsertId()
	if err != nil {
		return fmt.Errorf("read prepared blob ID: %w", err)
	}
	if preparedBlobID <= 0 {
		return errors.New("prepared blob ID is invalid")
	}
	// A completed retention deletion keeps the content identity as a tombstone.
	// Re-uploading the same bytes may safely reuse that row only after physical
	// deletion completed and no references remain. Rows still being deleted are
	// left untouched so the retention worker cannot race a new publication.
	if _, err := transaction.ExecContext(ctx, `
UPDATE blobs
SET state = 'staging',
    verified_at = NULL,
    deleted_at = NULL
WHERE id = ?
  AND sha256 = ?
  AND size_bytes = ?
  AND storage_key = ?
  AND state = 'deleted'
  AND reference_count = 0
  AND deleted_at IS NOT NULL`,
		preparedBlobID,
		sha256Value,
		size,
		storageKey,
	); err != nil {
		return fmt.Errorf("reactivate deleted blob record: %w", err)
	}
	if err := verifyPreparedBlob(
		ctx,
		transaction,
		uint64(preparedBlobID),
		sha256Value,
		size,
		storageKey,
		"",
	); err != nil {
		return err
	}
	referenceResult, err := transaction.ExecContext(ctx, `
UPDATE blobs
SET reference_count = reference_count + 1
WHERE id = ?
  AND state IN ('staging', 'available')
  AND deleted_at IS NULL`, preparedBlobID)
	if err != nil {
		return fmt.Errorf("reference prepared blob: %w", err)
	}
	referenced, err := referenceResult.RowsAffected()
	if err != nil {
		return fmt.Errorf("inspect prepared blob reference: %w", err)
	}
	if referenced != 1 {
		return ErrConflict
	}
	updateResult, err := transaction.ExecContext(ctx, `
UPDATE uploads
SET status = 'assembling', actual_sha256 = ?, blob_id = ?
WHERE id = ? AND status IN ('created', 'uploading')`,
		sha256Value, preparedBlobID, uploadID)
	if err != nil {
		return fmt.Errorf("prepare upload completion: %w", err)
	}
	updated, err := updateResult.RowsAffected()
	if err != nil {
		return fmt.Errorf("inspect upload completion preparation: %w", err)
	}
	if updated != 1 {
		return ErrConflict
	}
	if err := transaction.Commit(); err != nil {
		return fmt.Errorf("commit upload completion preparation: %w", err)
	}
	return nil
}

func (r *MySQLRepository) FinalizeCompletion(
	ctx context.Context,
	uploadID string,
	sha256Value string,
	completedAt time.Time,
) error {
	transaction, err := r.beginTx(ctx)
	if err != nil {
		return fmt.Errorf("begin upload completion finalization: %w", err)
	}
	defer transaction.Rollback()

	var (
		status    string
		actualSHA sql.NullString
		blobID    sql.NullInt64
	)
	err = transaction.QueryRowContext(ctx, `
SELECT status, actual_sha256, blob_id
FROM uploads
WHERE id = ?
LIMIT 1
FOR UPDATE`, uploadID).Scan(&status, &actualSHA, &blobID)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return fmt.Errorf("lock upload completion finalization: %w", err)
	}
	if !actualSHA.Valid || actualSHA.String != sha256Value ||
		!blobID.Valid || blobID.Int64 <= 0 {
		return ErrConflict
	}
	if status != "assembling" && status != "completed" {
		return ErrInvalidState
	}

	var (
		storedSHA   string
		storedState string
		deletedAt   sql.NullTime
	)
	if err := transaction.QueryRowContext(ctx, `
SELECT sha256, state, deleted_at
FROM blobs
WHERE id = ?
LIMIT 1
FOR UPDATE`, blobID.Int64).Scan(&storedSHA, &storedState, &deletedAt); err != nil {
		return fmt.Errorf("lock prepared blob finalization: %w", err)
	}
	if storedSHA != sha256Value || deletedAt.Valid {
		return ErrConflict
	}
	if status == "completed" {
		if storedState != "available" {
			return ErrConflict
		}
		if err := transaction.Commit(); err != nil {
			return fmt.Errorf("commit idempotent upload completion: %w", err)
		}
		return nil
	}
	if storedState != "staging" && storedState != "available" {
		return ErrConflict
	}
	result, err := transaction.ExecContext(ctx, `
UPDATE blobs
SET state = 'available',
    verified_at = ?
WHERE id = ?
  AND state IN ('staging', 'available')
  AND deleted_at IS NULL`, completedAt, blobID.Int64)
	if err != nil {
		return fmt.Errorf("publish prepared blob record: %w", err)
	}
	updated, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("inspect prepared blob publication: %w", err)
	}
	if updated != 1 {
		return ErrConflict
	}
	result, err = transaction.ExecContext(ctx, `
UPDATE uploads
SET status = 'completed',
    completed_at = ?
WHERE id = ?
  AND status = 'assembling'
  AND actual_sha256 = ?
  AND blob_id = ?`, completedAt, uploadID, sha256Value, blobID.Int64)
	if err != nil {
		return fmt.Errorf("finalize upload: %w", err)
	}
	updated, err = result.RowsAffected()
	if err != nil {
		return fmt.Errorf("inspect upload finalization: %w", err)
	}
	if updated != 1 {
		return ErrConflict
	}
	if err := transaction.Commit(); err != nil {
		return fmt.Errorf("commit upload completion finalization: %w", err)
	}
	return nil
}

func verifyPreparedBlob(
	ctx context.Context,
	transaction *sql.Tx,
	blobID uint64,
	sha256Value string,
	size int64,
	storageKey string,
	expectedState string,
) error {
	var (
		storedSHA   string
		storedSize  int64
		storedKey   string
		storedState string
		deletedAt   sql.NullTime
	)
	if err := transaction.QueryRowContext(ctx, `
SELECT sha256, size_bytes, storage_key, state, deleted_at
FROM blobs
WHERE id = ?
LIMIT 1
FOR UPDATE`, blobID).Scan(
		&storedSHA,
		&storedSize,
		&storedKey,
		&storedState,
		&deletedAt,
	); err != nil {
		return fmt.Errorf("verify prepared blob record: %w", err)
	}
	if storedSHA != sha256Value || storedSize != size || storedKey != storageKey ||
		deletedAt.Valid {
		return ErrConflict
	}
	if expectedState != "" {
		if storedState != expectedState {
			return ErrConflict
		}
	} else if storedState != "staging" && storedState != "available" {
		return ErrConflict
	}
	return nil
}

func (r *MySQLRepository) CleanupParts(
	ctx context.Context,
	uploadID string,
	deleteDirectory func() error,
) (bool, error) {
	if deleteDirectory == nil {
		return false, errors.New("upload part delete callback is required")
	}
	transaction, err := r.beginTx(ctx)
	if err != nil {
		return false, fmt.Errorf("begin upload part cleanup: %w", err)
	}
	defer transaction.Rollback()

	var (
		status    string
		cleanedAt sql.NullTime
	)
	err = transaction.QueryRowContext(ctx, `
SELECT status, parts_cleaned_at
FROM uploads
WHERE id = ?
LIMIT 1
FOR UPDATE`, uploadID).Scan(&status, &cleanedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return false, ErrNotFound
	}
	if err != nil {
		return false, fmt.Errorf("lock upload part cleanup: %w", err)
	}
	if cleanedAt.Valid {
		if err := transaction.Commit(); err != nil {
			return false, fmt.Errorf("commit completed upload part cleanup: %w", err)
		}
		return false, nil
	}
	switch status {
	case "completed", "failed", "expired", "cancelled":
	default:
		return false, ErrInvalidState
	}
	if err := deleteDirectory(); err != nil {
		return false, fmt.Errorf("delete upload part directory: %w", err)
	}
	if _, err := transaction.ExecContext(ctx, `
DELETE FROM upload_parts
WHERE upload_id = ?`, uploadID); err != nil {
		return false, fmt.Errorf("delete upload part records: %w", err)
	}
	result, err := transaction.ExecContext(ctx, `
UPDATE uploads
SET parts_cleaned_at = UTC_TIMESTAMP(6)
WHERE id = ?
  AND status = ?
  AND parts_cleaned_at IS NULL`, uploadID, status)
	if err != nil {
		return false, fmt.Errorf("record upload part cleanup: %w", err)
	}
	updated, err := result.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("inspect upload part cleanup: %w", err)
	}
	if updated != 1 {
		return false, ErrConflict
	}
	if err := transaction.Commit(); err != nil {
		return false, fmt.Errorf("commit upload part cleanup: %w", err)
	}
	return true, nil
}

func (r *MySQLRepository) Cancel(ctx context.Context, uploadID string) error {
	transaction, err := r.beginTx(ctx)
	if err != nil {
		return fmt.Errorf("begin upload cancellation transaction: %w", err)
	}
	defer transaction.Rollback()

	var (
		status string
		blobID sql.NullInt64
	)
	err = transaction.QueryRowContext(ctx, `
SELECT status, blob_id
FROM uploads
WHERE id = ?
LIMIT 1
FOR UPDATE`, uploadID).Scan(&status, &blobID)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return fmt.Errorf("lock upload cancellation: %w", err)
	}
	switch status {
	case "created", "uploading", "assembling", "failed", "expired":
	default:
		return ErrInvalidState
	}
	if blobID.Valid {
		if blobID.Int64 <= 0 {
			return ErrConflict
		}
		if err := releasePreparedBlobReference(
			ctx,
			transaction,
			uint64(blobID.Int64),
		); err != nil {
			return err
		}
	}
	result, err := transaction.ExecContext(ctx, `
UPDATE uploads
SET status = 'cancelled',
    blob_id = NULL
WHERE id = ?
  AND status = ?`, uploadID, status)
	if err != nil {
		return fmt.Errorf("cancel upload: %w", err)
	}
	updated, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("inspect upload cancellation: %w", err)
	}
	if updated != 1 {
		return ErrInvalidState
	}
	if err := transaction.Commit(); err != nil {
		return fmt.Errorf("commit upload cancellation: %w", err)
	}
	return nil
}

func releasePreparedBlobReference(
	ctx context.Context,
	transaction *sql.Tx,
	blobID uint64,
) error {
	var (
		referenceCount uint64
		state          string
	)
	err := transaction.QueryRowContext(ctx, `
SELECT reference_count, state
FROM blobs
WHERE id = ?
LIMIT 1
FOR UPDATE`, blobID).Scan(&referenceCount, &state)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrConflict
	}
	if err != nil {
		return fmt.Errorf("lock cancelled upload blob: %w", err)
	}
	if referenceCount == 0 ||
		(state != "staging" && state != "available") {
		return ErrConflict
	}
	nextState := state
	if referenceCount == 1 {
		nextState = "deleting"
	}
	result, err := transaction.ExecContext(ctx, `
UPDATE blobs
SET state = ?,
    reference_count = reference_count - 1
WHERE id = ?
  AND state = ?
  AND reference_count = ?`,
		nextState,
		blobID,
		state,
		referenceCount,
	)
	if err != nil {
		return fmt.Errorf("release cancelled upload blob: %w", err)
	}
	updated, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("inspect cancelled upload blob release: %w", err)
	}
	if updated != 1 {
		return ErrConflict
	}
	return nil
}

func (r *MySQLRepository) WithLock(
	ctx context.Context,
	uploadID string,
	fn func(context.Context) error,
) error {
	connection, err := r.db.Conn(ctx)
	if err != nil {
		return fmt.Errorf("reserve upload lock connection: %w", err)
	}
	defer connection.Close()
	lockName := "binaryscan_upload_" + uploadID
	var acquired sql.NullInt64
	if err := connection.QueryRowContext(ctx, "SELECT GET_LOCK(?, ?)", lockName, 30).Scan(&acquired); err != nil {
		return fmt.Errorf("acquire upload lock: %w", err)
	}
	if !acquired.Valid || acquired.Int64 != 1 {
		return ErrConflict
	}
	defer func() {
		var released sql.NullInt64
		_ = connection.QueryRowContext(
			context.Background(), "SELECT RELEASE_LOCK(?)", lockName,
		).Scan(&released)
	}()
	lockedContext := context.WithValue(ctx, lockConnectionContextKey{}, connection)
	return fn(lockedContext)
}

func (r *MySQLRepository) executor(ctx context.Context) sqlExecutor {
	if connection, ok := ctx.Value(lockConnectionContextKey{}).(*sql.Conn); ok {
		return connection
	}
	return r.db
}

func (r *MySQLRepository) beginTx(ctx context.Context) (*sql.Tx, error) {
	if connection, ok := ctx.Value(lockConnectionContextKey{}).(*sql.Conn); ok {
		return connection.BeginTx(ctx, nil)
	}
	return r.db.BeginTx(ctx, nil)
}

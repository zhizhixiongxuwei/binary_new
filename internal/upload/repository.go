package upload

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"binaryscan/internal/inputcategory"

	"github.com/go-sql-driver/mysql"
)

type Repository interface {
	ResolveCreate(context.Context, uint64, string, string, string) (Upload, bool, error)
	Create(context.Context, Upload, string, string, string) (Upload, bool, error)
	RecordValidation(context.Context, string, ValidationResult) error
	SetArchiveImportID(context.Context, string, string) error
	CreateDerivedCompleted(context.Context, DerivedCompletedRecord) (Upload, bool, error)
	Get(context.Context, string) (Upload, error)
	UploadHasTask(context.Context, string) (bool, error)
	TaskIDForUpload(context.Context, string) (string, bool, error)
	ListDirectTaskCandidates(context.Context, string, int) ([]DirectTaskCandidate, error)
	ListArchiveImportCandidates(context.Context, string, int) ([]ArchiveImportCandidate, error)
	ListParts(context.Context, string) ([]Part, error)
	InsertPart(context.Context, Part) error
	PrepareCompletion(context.Context, string, string, int64, string) error
	FinalizeCompletion(context.Context, string, string, time.Time) error
	CleanupParts(context.Context, string, func() error) (bool, error)
	Cancel(context.Context, string) error
	WithLock(context.Context, string, func(context.Context) error) error
}

const (
	maxCreateAttempts          = 3
	initialCreateRetryWait     = 10 * time.Millisecond
	MaxDirectTaskRecoveryBatch = 1000
	MaxArchiveRecoveryBatch    = 1000
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
	if value.IntakeProfile == nil ||
		value.IntakeProfile.UploadID != value.ID ||
		value.IntakeProfile.ValidationStatus != ValidationPending ||
		value.IntakeProfile.SourceKind != SourceDirect {
		return Upload{}, false, ErrInvalidInput
	}
	if _, err := transaction.ExecContext(ctx, `
INSERT INTO upload_intake_profiles (
    upload_id, input_category, validation_status, source_kind
) VALUES (?, ?, 'pending', 'direct')`,
		value.ID,
		string(value.IntakeProfile.InputCategory),
	); err != nil {
		return Upload{}, false, fmt.Errorf("create upload intake profile: %w", err)
	}
	if err := transaction.Commit(); err != nil {
		return Upload{}, false, fmt.Errorf("commit upload creation: %w", err)
	}
	return value, true, nil
}

func (r *MySQLRepository) CreateDerivedCompleted(
	ctx context.Context,
	record DerivedCompletedRecord,
) (Upload, bool, error) {
	for attempt := 0; attempt < maxCreateAttempts; attempt++ {
		stored, created, err := r.createDerivedCompletedOnce(ctx, record)
		if err == nil {
			return stored, created, nil
		}
		if isDuplicateCreateKey(err) {
			existing, found, resolveErr := r.resolveDerivedCompleted(
				ctx,
				record.Upload.CreatedBy,
				record.IdempotencyKey,
				record.RequestFingerprint,
			)
			if resolveErr != nil {
				return Upload{}, false, resolveErr
			}
			if found {
				return existing, false, nil
			}
			return Upload{}, false, err
		}
		if !isRetryableCreateTransaction(err) || attempt == maxCreateAttempts-1 {
			return Upload{}, false, err
		}
		if err := waitForCreateRetry(ctx, attempt); err != nil {
			return Upload{}, false, err
		}
	}
	return Upload{}, false, errors.New("derived upload creation exhausted transaction attempts")
}

func (r *MySQLRepository) createDerivedCompletedOnce(
	ctx context.Context,
	record DerivedCompletedRecord,
) (Upload, bool, error) {
	value := record.Upload
	profile := value.IntakeProfile
	if profile == nil {
		return Upload{}, false, ErrInvalidInput
	}
	transaction, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return Upload{}, false, fmt.Errorf("begin derived upload creation transaction: %w", err)
	}
	defer transaction.Rollback()

	existing, found, err := findIdempotentCreate(
		ctx,
		transaction,
		value.CreatedBy,
		archiveEntryCreateOperation,
		record.IdempotencyKey,
		record.RequestFingerprint,
		true,
	)
	if err != nil {
		return Upload{}, false, err
	}
	if found {
		existing, err = getUpload(ctx, transaction, existing.ID)
		if err != nil {
			return Upload{}, false, err
		}
		if err := transaction.Commit(); err != nil {
			return Upload{}, false, fmt.Errorf("commit derived upload creation replay: %w", err)
		}
		return existing, false, nil
	}

	if value.BlobID == nil || *value.BlobID == 0 || value.CompletedAt == nil ||
		value.PartsCleanedAt == nil || profile.ValidatedAt == nil {
		return Upload{}, false, ErrInvalidInput
	}
	var (
		storedSHA  string
		storedSize int64
		blobState  string
		deletedAt  sql.NullTime
	)
	err = transaction.QueryRowContext(ctx, `
SELECT sha256, size_bytes, state, deleted_at
FROM blobs
WHERE id = ?
LIMIT 1
FOR UPDATE`, *value.BlobID).Scan(
		&storedSHA,
		&storedSize,
		&blobState,
		&deletedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return Upload{}, false, ErrConflict
	}
	if err != nil {
		return Upload{}, false, fmt.Errorf("lock derived upload blob: %w", err)
	}
	if storedSHA != value.ActualSHA256 || storedSize != value.DeclaredSize ||
		blobState != "available" || deletedAt.Valid {
		return Upload{}, false, ErrConflict
	}

	result, err := transaction.ExecContext(ctx, `
UPDATE blobs
SET reference_count = reference_count + 1
WHERE id = ?
  AND state = 'available'
  AND deleted_at IS NULL`, *value.BlobID)
	if err != nil {
		return Upload{}, false, fmt.Errorf("retain derived upload blob: %w", err)
	}
	retained, err := result.RowsAffected()
	if err != nil {
		return Upload{}, false, fmt.Errorf("inspect derived upload blob retention: %w", err)
	}
	if retained != 1 {
		return Upload{}, false, ErrConflict
	}

	_, err = transaction.ExecContext(ctx, `
INSERT INTO uploads (
    id, created_by, original_name, display_name, content_type,
    declared_size_bytes, part_size_bytes, actual_sha256, status, blob_id,
    expires_at, completed_at, parts_cleaned_at,
    idempotency_key, idempotency_operation, request_fingerprint, created_at
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'completed', ?, ?, ?, ?, ?, ?, ?, ?)`,
		value.ID,
		value.CreatedBy,
		value.OriginalName,
		value.DisplayName,
		value.ContentType,
		value.DeclaredSize,
		value.PartSize,
		value.ActualSHA256,
		*value.BlobID,
		value.ExpiresAt,
		*value.CompletedAt,
		*value.PartsCleanedAt,
		record.IdempotencyKey,
		archiveEntryCreateOperation,
		record.RequestFingerprint,
		value.CreatedAt,
	)
	if err != nil {
		return Upload{}, false, fmt.Errorf("create derived upload: %w", err)
	}
	_, err = transaction.ExecContext(ctx, `
INSERT INTO upload_intake_profiles (
    upload_id, input_category, detected_category, detected_format,
    validation_status, source_kind, source_parent_upload_id,
    source_archive_name, source_entry_path, validated_at, created_at
) VALUES (?, ?, ?, ?, 'valid', 'archive_entry', ?, ?, ?, ?, ?)`,
		value.ID,
		string(profile.InputCategory),
		string(profile.DetectedCategory),
		profile.DetectedFormat,
		profile.SourceParentUploadID,
		profile.SourceArchiveName,
		profile.SourceEntryPath,
		*profile.ValidatedAt,
		profile.CreatedAt,
	)
	if err != nil {
		return Upload{}, false, fmt.Errorf("create derived upload intake profile: %w", err)
	}
	if err := transaction.Commit(); err != nil {
		return Upload{}, false, fmt.Errorf("commit derived upload creation: %w", err)
	}
	return value, true, nil
}

func (r *MySQLRepository) resolveDerivedCompleted(
	ctx context.Context,
	createdBy uint64,
	idempotencyKey string,
	requestFingerprint string,
) (Upload, bool, error) {
	existing, found, err := findIdempotentCreate(
		ctx,
		r.db,
		createdBy,
		archiveEntryCreateOperation,
		idempotencyKey,
		requestFingerprint,
		false,
	)
	if err != nil || !found {
		return existing, found, err
	}
	value, err := getUpload(ctx, r.db, existing.ID)
	if err != nil {
		return Upload{}, false, err
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
	profile, err := loadIntakeProfile(ctx, query, value.ID)
	if err != nil {
		return Upload{}, false, err
	}
	value.IntakeProfile = profile
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
	return getUpload(ctx, r.executor(ctx), id)
}

func (r *MySQLRepository) UploadHasTask(ctx context.Context, uploadID string) (bool, error) {
	var retained bool
	if err := r.executor(ctx).QueryRowContext(ctx, `
SELECT EXISTS (
    SELECT 1
    FROM tasks
    WHERE upload_id = ?
)`, uploadID).Scan(&retained); err != nil {
		return false, fmt.Errorf("check upload task dependency: %w", err)
	}
	return retained, nil
}

func (r *MySQLRepository) TaskIDForUpload(
	ctx context.Context,
	uploadID string,
) (string, bool, error) {
	// A DELETED task row is still the permanent exactly-once tombstone for its
	// upload and must remain visible to callers.
	var taskID string
	err := r.executor(ctx).QueryRowContext(ctx, `
SELECT id
FROM tasks
WHERE upload_id = ?
LIMIT 1`, uploadID).Scan(&taskID)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, fmt.Errorf("find upload task: %w", err)
	}
	return taskID, true, nil
}

func (r *MySQLRepository) ListDirectTaskCandidates(
	ctx context.Context,
	afterID string,
	limit int,
) ([]DirectTaskCandidate, error) {
	if r == nil || r.db == nil || limit < 1 || limit > MaxDirectTaskRecoveryBatch ||
		(afterID != "" && !uuidPattern.MatchString(afterID)) {
		return nil, ErrInvalidInput
	}
	// Every task status, including DELETED, permanently consumes the upload.
	rows, err := r.db.QueryContext(ctx, `
SELECT upload.id, upload.created_by, upload.display_name,
       intake.input_category, intake.detected_format
FROM uploads upload
JOIN upload_intake_profiles intake ON intake.upload_id = upload.id
JOIN blobs stored_blob ON stored_blob.id = upload.blob_id
WHERE upload.id > ?
  AND upload.status = 'completed'
  AND intake.source_kind = 'direct'
  AND intake.validation_status = 'valid'
  AND intake.input_category IN ('binary', 'container')
  AND intake.detected_category = intake.input_category
  AND intake.detected_format IS NOT NULL
  AND stored_blob.state = 'available'
  AND NOT EXISTS (
      SELECT 1
      FROM tasks
      WHERE tasks.upload_id = upload.id
  )
ORDER BY upload.id
LIMIT ?`, afterID, limit)
	if err != nil {
		return nil, fmt.Errorf("list direct task recovery candidates: %w", err)
	}
	defer rows.Close()
	result := make([]DirectTaskCandidate, 0, limit)
	for rows.Next() {
		var candidate DirectTaskCandidate
		var category string
		if err := rows.Scan(
			&candidate.UploadID,
			&candidate.CreatedBy,
			&candidate.Filename,
			&category,
			&candidate.DetectedFormat,
		); err != nil {
			return nil, fmt.Errorf("scan direct task recovery candidate: %w", err)
		}
		candidate.InputCategory = inputcategory.Category(category)
		result = append(result, candidate)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate direct task recovery candidates: %w", err)
	}
	return result, nil
}

func (r *MySQLRepository) ListArchiveImportCandidates(
	ctx context.Context,
	afterID string,
	limit int,
) ([]ArchiveImportCandidate, error) {
	if r == nil || r.db == nil || limit < 1 || limit > MaxArchiveRecoveryBatch ||
		(afterID != "" && !uuidPattern.MatchString(afterID)) {
		return nil, ErrInvalidInput
	}
	rows, err := r.db.QueryContext(ctx, `
SELECT upload.id, upload.created_by, upload.display_name,
       upload.declared_size_bytes, upload.actual_sha256, intake.detected_format
FROM uploads upload
JOIN upload_intake_profiles intake ON intake.upload_id = upload.id
JOIN blobs stored_blob ON stored_blob.id = upload.blob_id
WHERE upload.id > ?
  AND upload.status = 'completed'
  AND intake.source_kind = 'direct'
  AND intake.validation_status = 'valid'
  AND intake.input_category = 'archive'
  AND intake.detected_category = 'archive'
  AND intake.detected_format IS NOT NULL
  AND intake.archive_import_id IS NULL
  AND upload.actual_sha256 IS NOT NULL
  AND stored_blob.state = 'available'
ORDER BY upload.id
LIMIT ?`, afterID, limit)
	if err != nil {
		return nil, fmt.Errorf("list archive import recovery candidates: %w", err)
	}
	defer rows.Close()
	result := make([]ArchiveImportCandidate, 0, limit)
	for rows.Next() {
		var candidate ArchiveImportCandidate
		if err := rows.Scan(
			&candidate.UploadID,
			&candidate.CreatedBy,
			&candidate.Filename,
			&candidate.Size,
			&candidate.SHA256,
			&candidate.DetectedFormat,
		); err != nil {
			return nil, fmt.Errorf("scan archive import recovery candidate: %w", err)
		}
		result = append(result, candidate)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate archive import recovery candidates: %w", err)
	}
	return result, nil
}

func getUpload(ctx context.Context, query sqlExecutor, id string) (Upload, error) {
	var value Upload
	var expectedSHA, actualSHA sql.NullString
	var blobID sql.NullInt64
	err := query.QueryRowContext(ctx, `
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
	profile, err := loadIntakeProfile(ctx, query, id)
	if err != nil {
		return Upload{}, err
	}
	value.IntakeProfile = profile
	return value, nil
}

func (r *MySQLRepository) RecordValidation(
	ctx context.Context,
	uploadID string,
	result ValidationResult,
) error {
	transaction, err := r.beginTx(ctx)
	if err != nil {
		return fmt.Errorf("begin upload validation transaction: %w", err)
	}
	defer transaction.Rollback()

	var (
		uploadStatus           string
		inputCategory          string
		storedDetectedCategory sql.NullString
		storedDetectedFormat   sql.NullString
		storedStatus           string
		storedErrorCode        sql.NullString
		storedErrorMessage     sql.NullString
	)
	err = transaction.QueryRowContext(ctx, `
SELECT upload.status, intake.input_category, intake.detected_category,
       intake.detected_format, intake.validation_status,
       intake.validation_error_code, intake.validation_error_message
FROM uploads upload
JOIN upload_intake_profiles intake ON intake.upload_id = upload.id
WHERE upload.id = ?
LIMIT 1
FOR UPDATE`, uploadID).Scan(
		&uploadStatus,
		&inputCategory,
		&storedDetectedCategory,
		&storedDetectedFormat,
		&storedStatus,
		&storedErrorCode,
		&storedErrorMessage,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return fmt.Errorf("lock upload validation: %w", err)
	}
	if inputCategory != string(result.InputCategory) {
		return ErrConflict
	}
	if storedStatus != ValidationPending {
		if storedStatus != result.Status ||
			storedDetectedCategory.String != string(result.DetectedCategory) ||
			storedDetectedFormat.String != result.DetectedFormat ||
			storedErrorCode.String != result.ErrorCode ||
			storedErrorMessage.String != result.ErrorMessage {
			return ErrConflict
		}
		if err := transaction.Commit(); err != nil {
			return fmt.Errorf("commit idempotent upload validation: %w", err)
		}
		return nil
	}
	if uploadStatus != "created" && uploadStatus != "uploading" {
		return ErrInvalidState
	}
	if result.Status != ValidationValid &&
		result.Status != ValidationMismatch &&
		result.Status != ValidationUnsupported {
		return ErrInvalidInput
	}

	var detectedCategory any
	if result.DetectedCategory != "" {
		detectedCategory = string(result.DetectedCategory)
	}
	var errorCode any
	var errorMessage any
	if result.ErrorCode != "" {
		errorCode = result.ErrorCode
		errorMessage = result.ErrorMessage
	}
	update, err := transaction.ExecContext(ctx, `
UPDATE upload_intake_profiles
SET detected_category = ?,
    detected_format = ?,
    validation_status = ?,
    validation_error_code = ?,
    validation_error_message = ?,
    validated_at = ?
WHERE upload_id = ?
  AND validation_status = 'pending'`,
		detectedCategory,
		result.DetectedFormat,
		result.Status,
		errorCode,
		errorMessage,
		result.ValidatedAt,
		uploadID,
	)
	if err != nil {
		return fmt.Errorf("record upload validation: %w", err)
	}
	updated, err := update.RowsAffected()
	if err != nil {
		return fmt.Errorf("inspect upload validation update: %w", err)
	}
	if updated != 1 {
		return ErrConflict
	}
	if result.Status == ValidationMismatch || result.Status == ValidationUnsupported {
		update, err = transaction.ExecContext(ctx, `
UPDATE uploads
SET status = 'failed'
WHERE id = ?
  AND status = ?`, uploadID, uploadStatus)
		if err != nil {
			return fmt.Errorf("reject invalid upload completion: %w", err)
		}
		updated, err = update.RowsAffected()
		if err != nil {
			return fmt.Errorf("inspect invalid upload completion: %w", err)
		}
		if updated != 1 {
			return ErrConflict
		}
	}
	if err := transaction.Commit(); err != nil {
		return fmt.Errorf("commit upload validation: %w", err)
	}
	return nil
}

func (r *MySQLRepository) SetArchiveImportID(
	ctx context.Context,
	uploadID string,
	archiveImportID string,
) error {
	transaction, err := r.beginTx(ctx)
	if err != nil {
		return fmt.Errorf("begin archive import association: %w", err)
	}
	defer transaction.Rollback()
	var (
		status           string
		inputCategory    string
		validationStatus string
		storedID         sql.NullString
	)
	err = transaction.QueryRowContext(ctx, `
SELECT upload.status, intake.input_category, intake.validation_status,
       intake.archive_import_id
FROM uploads upload
JOIN upload_intake_profiles intake ON intake.upload_id = upload.id
WHERE upload.id = ?
LIMIT 1
FOR UPDATE`, uploadID).Scan(
		&status,
		&inputCategory,
		&validationStatus,
		&storedID,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return fmt.Errorf("lock archive import association: %w", err)
	}
	if status != "completed" || inputCategory != string(inputcategory.Archive) ||
		validationStatus != ValidationValid {
		return ErrInvalidState
	}
	if storedID.Valid {
		if storedID.String != archiveImportID {
			return ErrConflict
		}
		if err := transaction.Commit(); err != nil {
			return fmt.Errorf("commit idempotent archive import association: %w", err)
		}
		return nil
	}
	result, err := transaction.ExecContext(ctx, `
UPDATE upload_intake_profiles
SET archive_import_id = ?
WHERE upload_id = ?
  AND archive_import_id IS NULL`, archiveImportID, uploadID)
	if err != nil {
		return fmt.Errorf("associate archive import: %w", err)
	}
	updated, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("inspect archive import association: %w", err)
	}
	if updated != 1 {
		return ErrConflict
	}
	if err := transaction.Commit(); err != nil {
		return fmt.Errorf("commit archive import association: %w", err)
	}
	return nil
}

func loadIntakeProfile(
	ctx context.Context,
	query rowQuerier,
	uploadID string,
) (*IntakeProfile, error) {
	var profile IntakeProfile
	var (
		detectedCategory sql.NullString
		detectedFormat   sql.NullString
		errorCode        sql.NullString
		errorMessage     sql.NullString
		parentUploadID   sql.NullString
		archiveName      sql.NullString
		entryPath        sql.NullString
		archiveImportID  sql.NullString
		validatedAt      sql.NullTime
	)
	err := query.QueryRowContext(ctx, `
SELECT upload_id, input_category, detected_category, detected_format,
       validation_status, validation_error_code, validation_error_message,
       source_kind, source_parent_upload_id, source_archive_name,
       source_entry_path, archive_import_id, validated_at, created_at, updated_at
FROM upload_intake_profiles
WHERE upload_id = ?
LIMIT 1`, uploadID).Scan(
		&profile.UploadID,
		&profile.InputCategory,
		&detectedCategory,
		&detectedFormat,
		&profile.ValidationStatus,
		&errorCode,
		&errorMessage,
		&profile.SourceKind,
		&parentUploadID,
		&archiveName,
		&entryPath,
		&archiveImportID,
		&validatedAt,
		&profile.CreatedAt,
		&profile.UpdatedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get upload intake profile: %w", err)
	}
	profile.DetectedCategory = inputCategoryFromString(detectedCategory.String)
	profile.DetectedFormat = detectedFormat.String
	profile.ValidationErrorCode = errorCode.String
	profile.ValidationErrorMessage = errorMessage.String
	profile.SourceParentUploadID = parentUploadID.String
	profile.SourceArchiveName = archiveName.String
	profile.SourceEntryPath = entryPath.String
	profile.ArchiveImportID = archiveImportID.String
	if validatedAt.Valid {
		value := validatedAt.Time
		profile.ValidatedAt = &value
	}
	return &profile, nil
}

func inputCategoryFromString(value string) inputcategory.Category {
	category, _ := inputcategory.Parse(value)
	return category
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
	case "completed":
		var taskID string
		err := transaction.QueryRowContext(ctx, `
SELECT id
FROM tasks
WHERE upload_id = ?
LIMIT 1`, uploadID).Scan(&taskID)
		if err == nil {
			return ErrInvalidState
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("check completed upload task dependency: %w", err)
		}
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

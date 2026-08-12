package archiveimport

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"binaryscan/internal/blobfence"

	"github.com/go-sql-driver/mysql"
)

type ReleasedBlob struct {
	ID         uint64
	StorageKey string
}

type DeletionPlan struct {
	ImportID       string
	DerivedUploads []DerivedUploadDeletion
	AlreadyDeleted bool
}

type DerivedUploadDeletion struct {
	ID    string
	Owner uint64
}

type MySQLRepository struct {
	db *sql.DB
}

func NewMySQLRepository(db *sql.DB) (*MySQLRepository, error) {
	if db == nil {
		return nil, errors.New("archive import database is required")
	}
	return &MySQLRepository{db: db}, nil
}

func (r *MySQLRepository) Ensure(
	ctx context.Context,
	id string,
	input EnsureInput,
	limits []byte,
) (Import, bool, error) {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return Import{}, false, fmt.Errorf("begin archive import ensure: %w", err)
	}
	defer tx.Rollback()

	var owner uint64
	var filename, status, actualSHA, blobState, blobStorageKey, blobSHA string
	var inputCategory, detectedCategory, detectedFormat string
	var validationStatus, sourceKind string
	var associatedImportID sql.NullString
	var declaredSize, blobSize int64
	var blobID sql.NullInt64
	err = tx.QueryRowContext(ctx, `
SELECT upload.created_by, upload.display_name, upload.declared_size_bytes,
       upload.actual_sha256, upload.status, upload.blob_id, stored_blob.state,
       stored_blob.storage_key, stored_blob.sha256, stored_blob.size_bytes,
       intake.input_category, intake.detected_category,
       intake.detected_format, intake.validation_status,
       intake.source_kind, intake.archive_import_id
FROM uploads upload
JOIN upload_intake_profiles intake ON intake.upload_id = upload.id
LEFT JOIN blobs stored_blob ON stored_blob.id = upload.blob_id
WHERE upload.id = ?
FOR UPDATE`, input.UploadID).Scan(
		&owner, &filename, &declaredSize, &actualSHA, &status, &blobID, &blobState,
		&blobStorageKey, &blobSHA, &blobSize,
		&inputCategory, &detectedCategory, &detectedFormat, &validationStatus,
		&sourceKind, &associatedImportID,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return Import{}, false, ErrNotFound
	}
	if err != nil {
		return Import{}, false, fmt.Errorf("lock archive upload: %w", err)
	}
	if owner != input.CreatedBy || status != "completed" || !blobID.Valid ||
		blobID.Int64 <= 0 || blobState != "available" ||
		declaredSize != input.Size || actualSHA != input.SHA256 ||
		blobSize != input.Size || blobSHA != input.SHA256 ||
		blobStorageKey != "blobs/sha256/"+input.SHA256[:2]+"/"+input.SHA256 ||
		filename != input.Filename || inputCategory != "archive" ||
		detectedCategory != "archive" || detectedFormat != input.DetectedFormat ||
		validationStatus != "valid" || sourceKind != "direct" {
		return Import{}, false, ErrConflict
	}

	existing, found, err := findImportByUpload(ctx, tx, input.UploadID, true)
	if err != nil {
		return Import{}, false, err
	}
	if found {
		if existing.CreatedBy != input.CreatedBy ||
			existing.RootFormat != input.DetectedFormat {
			return Import{}, false, ErrConflict
		}
		if associatedImportID.Valid && associatedImportID.String != existing.ID {
			return Import{}, false, ErrConflict
		}
		var sourceBlobID uint64
		var sourceKey, sourceSHA string
		var sourceSize int64
		var sourceReleasedAt sql.NullTime
		err := tx.QueryRowContext(ctx, `
SELECT source_blob_id, source_storage_key, source_sha256, source_size_bytes,
       source_blob_reference_released_at
FROM archive_imports
WHERE id = ?
FOR UPDATE`, existing.ID).Scan(
			&sourceBlobID, &sourceKey, &sourceSHA, &sourceSize, &sourceReleasedAt,
		)
		if err != nil {
			return Import{}, false, fmt.Errorf("verify archive import source reference: %w", err)
		}
		if sourceBlobID != uint64(blobID.Int64) || sourceKey != blobStorageKey ||
			sourceSHA != blobSHA || sourceSize != blobSize ||
			(existing.Status == StatusQueued && sourceReleasedAt.Valid) {
			return Import{}, false, ErrConflict
		}
		if !associatedImportID.Valid {
			result, err := tx.ExecContext(ctx, `
UPDATE upload_intake_profiles
SET archive_import_id = ?, updated_at = UTC_TIMESTAMP(6)
WHERE upload_id = ? AND archive_import_id IS NULL`, existing.ID, input.UploadID)
			if err != nil {
				return Import{}, false, fmt.Errorf("repair archive import intake association: %w", err)
			}
			if err := requireOneRow(result, ErrConflict); err != nil {
				return Import{}, false, err
			}
		}
		if err := tx.Commit(); err != nil {
			return Import{}, false, fmt.Errorf("commit archive import replay: %w", err)
		}
		return existing, false, nil
	}
	if associatedImportID.Valid {
		return Import{}, false, ErrConflict
	}
	result, err := tx.ExecContext(ctx, `
UPDATE blobs
SET reference_count = reference_count + 1
WHERE id = ? AND sha256 = ? AND size_bytes = ? AND storage_key = ?
  AND state = 'available'`, blobID.Int64, blobSHA, blobSize, blobStorageKey)
	if err != nil {
		return Import{}, false, fmt.Errorf("retain archive import source blob: %w", err)
	}
	if err := requireOneRow(result, ErrConflict); err != nil {
		return Import{}, false, err
	}

	_, err = tx.ExecContext(ctx, `
INSERT INTO archive_imports (
    id, upload_id, created_by, root_format,
    source_blob_id, source_storage_key, source_sha256, source_size_bytes,
    status, attempt, max_attempts,
    fencing_token, available_at, limits_snapshot, created_at, updated_at
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'queued', 0, 3, 0, UTC_TIMESTAMP(6), ?,
          UTC_TIMESTAMP(6), UTC_TIMESTAMP(6))`,
		id, input.UploadID, input.CreatedBy, input.DetectedFormat,
		blobID.Int64, blobStorageKey, blobSHA, blobSize, limits,
	)
	if err != nil {
		if isDuplicateKey(err) {
			return Import{}, false, ErrConflict
		}
		return Import{}, false, fmt.Errorf("create archive import: %w", err)
	}
	association, err := tx.ExecContext(ctx, `
UPDATE upload_intake_profiles
SET archive_import_id = ?, updated_at = UTC_TIMESTAMP(6)
WHERE upload_id = ? AND archive_import_id IS NULL`, id, input.UploadID)
	if err != nil {
		return Import{}, false, fmt.Errorf("associate archive import intake profile: %w", err)
	}
	if err := requireOneRow(association, ErrConflict); err != nil {
		return Import{}, false, err
	}
	value, found, err := findImportByUpload(ctx, tx, input.UploadID, false)
	if err != nil {
		return Import{}, false, err
	}
	if !found {
		return Import{}, false, errors.New("created archive import disappeared")
	}
	if err := tx.Commit(); err != nil {
		return Import{}, false, fmt.Errorf("commit archive import ensure: %w", err)
	}
	return value, true, nil
}

func (r *MySQLRepository) Get(ctx context.Context, id string) (Import, error) {
	value, found, err := findImportByID(ctx, r.db, id, false)
	if err != nil {
		return Import{}, err
	}
	if !found {
		return Import{}, ErrNotFound
	}
	return value, nil
}

func (r *MySQLRepository) ListImports(
	ctx context.Context,
	owner *uint64,
	before time.Time,
	beforeID string,
	limit int,
) ([]Import, bool, error) {
	where := "WHERE archive_import.status <> 'deleted'"
	arguments := make([]any, 0, 5)
	if owner != nil {
		where += " AND archive_import.created_by = ?"
		arguments = append(arguments, *owner)
	}
	if !before.IsZero() {
		where += ` AND (
    archive_import.created_at < ? OR
    (archive_import.created_at = ? AND archive_import.id < ?)
)`
		arguments = append(arguments, before, before, beforeID)
	}
	arguments = append(arguments, limit+1)
	rows, err := r.db.QueryContext(ctx, `
SELECT archive_import.id, archive_import.upload_id, upload.display_name, archive_import.created_by,
       archive_import.root_format, archive_import.status, archive_import.scanned_entries,
       archive_import.total_entries, archive_import.eligible_entries, archive_import.skipped_entries,
       archive_import.created_tasks, archive_import.error_code, archive_import.error_message,
       archive_import.attempt, archive_import.max_attempts, archive_import.fencing_token,
       archive_import.completed_at, archive_import.created_at, archive_import.updated_at
FROM archive_imports archive_import
JOIN uploads upload ON upload.id = archive_import.upload_id
`+where+`
ORDER BY archive_import.created_at DESC, archive_import.id DESC
LIMIT ?`, arguments...)
	if err != nil {
		return nil, false, fmt.Errorf("list archive imports: %w", err)
	}
	defer rows.Close()
	values := make([]Import, 0, limit+1)
	for rows.Next() {
		value, found, err := scanImport(rows)
		if err != nil {
			return nil, false, err
		}
		if !found {
			return nil, false, errors.New("archive import list row disappeared")
		}
		values = append(values, value)
	}
	if err := rows.Err(); err != nil {
		return nil, false, fmt.Errorf("iterate archive imports: %w", err)
	}
	more := len(values) > limit
	if more {
		values = values[:limit]
	}
	return values, more, nil
}

func findImportByUpload(
	ctx context.Context,
	query rowQueryer,
	uploadID string,
	lock bool,
) (Import, bool, error) {
	suffix := ""
	if lock {
		suffix = " FOR UPDATE"
	}
	return scanImport(query.QueryRowContext(ctx, `
SELECT archive_import.id, archive_import.upload_id, upload.display_name, archive_import.created_by,
       archive_import.root_format, archive_import.status, archive_import.scanned_entries,
       archive_import.total_entries, archive_import.eligible_entries, archive_import.skipped_entries,
       archive_import.created_tasks, archive_import.error_code, archive_import.error_message,
       archive_import.attempt, archive_import.max_attempts, archive_import.fencing_token,
       archive_import.completed_at, archive_import.created_at, archive_import.updated_at
FROM archive_imports archive_import
JOIN uploads upload ON upload.id = archive_import.upload_id
WHERE archive_import.upload_id = ?`+suffix, uploadID))
}

func findImportByID(
	ctx context.Context,
	query rowQueryer,
	id string,
	lock bool,
) (Import, bool, error) {
	suffix := ""
	if lock {
		suffix = " FOR UPDATE"
	}
	return scanImport(query.QueryRowContext(ctx, `
SELECT archive_import.id, archive_import.upload_id, upload.display_name, archive_import.created_by,
       archive_import.root_format, archive_import.status, archive_import.scanned_entries,
       archive_import.total_entries, archive_import.eligible_entries, archive_import.skipped_entries,
       archive_import.created_tasks, archive_import.error_code, archive_import.error_message,
       archive_import.attempt, archive_import.max_attempts, archive_import.fencing_token,
       archive_import.completed_at, archive_import.created_at, archive_import.updated_at
FROM archive_imports archive_import
JOIN uploads upload ON upload.id = archive_import.upload_id
WHERE archive_import.id = ?`+suffix, id))
}

type rowQueryer interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

type rowScanner interface {
	Scan(...any) error
}

func scanImport(row rowScanner) (Import, bool, error) {
	var value Import
	var errorCode, errorMessage sql.NullString
	var completedAt sql.NullTime
	err := row.Scan(
		&value.ID, &value.UploadID, &value.Filename, &value.CreatedBy,
		&value.RootFormat, &value.Status, &value.ScannedEntries,
		&value.TotalEntries, &value.EligibleEntries, &value.SkippedEntries,
		&value.CreatedTasks, &errorCode, &errorMessage, &value.Attempt,
		&value.MaxAttempts, &value.FencingToken, &completedAt,
		&value.CreatedAt, &value.UpdatedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return Import{}, false, nil
	}
	if err != nil {
		return Import{}, false, fmt.Errorf("scan archive import: %w", err)
	}
	value.ErrorCode = errorCode.String
	value.ErrorMessage = errorMessage.String
	if completedAt.Valid {
		value.CompletedAt = &completedAt.Time
	}
	return value, true, nil
}

func (r *MySQLRepository) ListEntries(
	ctx context.Context,
	importID string,
	filter string,
	afterID uint64,
	limit int,
) ([]Entry, bool, error) {
	where := "WHERE entry.archive_import_id = ? AND entry.id > ?"
	arguments := []any{importID, afterID}
	if filter != "" && filter != "all" {
		where += " AND entry.status = ?"
		arguments = append(arguments, filter)
	}
	arguments = append(arguments, limit+1)
	rows, err := r.db.QueryContext(ctx, `
SELECT entry.id, entry.public_id, entry.archive_import_id,
       entry.logical_path, entry.size_bytes, entry.sha256,
       entry.detected_format, entry.detected_category, entry.status,
       entry.skip_reason, entry.error_code, entry.error_message,
       entry.blob_id, entry.derived_upload_id, entry.task_id
FROM archive_import_entries entry
`+where+`
ORDER BY entry.id ASC
LIMIT ?`, arguments...)
	if err != nil {
		return nil, false, fmt.Errorf("list archive import entries: %w", err)
	}
	defer rows.Close()
	items := make([]Entry, 0, limit+1)
	for rows.Next() {
		item, err := scanEntry(rows)
		if err != nil {
			return nil, false, err
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, false, fmt.Errorf("iterate archive import entries: %w", err)
	}
	hasMore := len(items) > limit
	if hasMore {
		items = items[:limit]
	}
	return items, hasMore, nil
}

func scanEntry(row rowScanner) (Entry, error) {
	var value Entry
	var sha, format, category, skipReason, errorCode, errorMessage sql.NullString
	var blobID sql.NullInt64
	var derivedUploadID, taskID sql.NullString
	err := row.Scan(
		&value.DatabaseID, &value.ID, &value.ImportID, &value.Path,
		&value.SizeBytes, &sha, &format, &category, &value.Status,
		&skipReason, &errorCode, &errorMessage, &blobID,
		&derivedUploadID, &taskID,
	)
	if err != nil {
		return Entry{}, fmt.Errorf("scan archive import entry: %w", err)
	}
	if sha.Valid {
		value.SHA256 = stringPointer(sha.String)
	}
	if format.Valid {
		value.DetectedFormat = stringPointer(format.String)
	}
	if category.Valid {
		value.DetectedCategory = stringPointer(category.String)
	}
	value.SkipReason = skipReason.String
	value.ErrorCode = errorCode.String
	value.ErrorMessage = errorMessage.String
	if blobID.Valid && blobID.Int64 > 0 {
		value.BlobID = uint64(blobID.Int64)
	}
	value.DerivedUploadID = derivedUploadID.String
	value.TaskID = taskID.String
	return value, nil
}

func stringPointer(value string) *string {
	copy := value
	return &copy
}

func (r *MySQLRepository) Claim(
	ctx context.Context,
	owner string,
	leaseDuration time.Duration,
) (Lease, bool, error) {
	// The global resource gate is shared with queue claims. READ COMMITTED makes
	// the slot/running checks below observe the transaction that just released
	// the locked job_resource_limits row; a REPEATABLE READ snapshot could miss
	// that commit after waiting on the gate and admit two heavy workers.
	tx, err := r.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return Lease{}, false, fmt.Errorf("begin archive import claim: %w", err)
	}
	defer tx.Rollback()

	var id string
	err = tx.QueryRowContext(ctx, `
SELECT archive_import.id
FROM archive_imports archive_import
JOIN uploads upload ON upload.id = archive_import.upload_id
JOIN upload_intake_profiles intake ON intake.upload_id = upload.id
JOIN blobs source_blob ON source_blob.id = archive_import.source_blob_id
WHERE archive_import.status = 'queued'
  AND archive_import.available_at <= UTC_TIMESTAMP(6)
  AND archive_import.attempt < archive_import.max_attempts
  AND upload.status = 'completed'
  AND archive_import.source_blob_reference_released_at IS NULL
  AND source_blob.state = 'available'
  AND source_blob.storage_key = archive_import.source_storage_key
  AND source_blob.sha256 = archive_import.source_sha256
  AND source_blob.size_bytes = archive_import.source_size_bytes
  AND intake.input_category = 'archive'
  AND intake.detected_category = 'archive'
  AND intake.validation_status = 'valid'
  AND intake.source_kind = 'direct'
  AND intake.detected_format = archive_import.root_format
  AND intake.archive_import_id = archive_import.id
ORDER BY archive_import.available_at ASC, archive_import.id ASC
LIMIT 1
FOR UPDATE SKIP LOCKED`).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		if err := tx.Commit(); err != nil {
			return Lease{}, false, fmt.Errorf("commit empty archive import claim: %w", err)
		}
		return Lease{}, false, nil
	}
	if err != nil {
		return Lease{}, false, fmt.Errorf("select archive import claim: %w", err)
	}
	var resourceLimitID uint8
	if err := tx.QueryRowContext(ctx, `
SELECT id
FROM job_resource_limits
WHERE id = 1
FOR UPDATE`).Scan(&resourceLimitID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return Lease{}, false, ErrConflict
		}
		return Lease{}, false, fmt.Errorf("lock archive import resource gate: %w", err)
	}
	var globalSlotBusy, otherImportRunning bool
	if err := tx.QueryRowContext(ctx, `
SELECT
    EXISTS (
        SELECT 1 FROM job_resource_slots
        WHERE pool = 'global' AND job_id IS NOT NULL
    ),
    EXISTS (
        SELECT 1 FROM archive_imports
        WHERE status = 'running'
    )`).Scan(&globalSlotBusy, &otherImportRunning); err != nil {
		return Lease{}, false, fmt.Errorf("inspect archive import resource gate: %w", err)
	}
	if globalSlotBusy || otherImportRunning {
		if err := tx.Commit(); err != nil {
			return Lease{}, false, fmt.Errorf("commit busy archive resource claim: %w", err)
		}
		return Lease{}, false, nil
	}
	microseconds := leaseDuration.Microseconds()
	result, err := tx.ExecContext(ctx, `
UPDATE archive_imports
SET status = 'running',
    attempt = attempt + 1,
    fencing_token = fencing_token + 1,
    lease_owner = ?,
    lease_until = TIMESTAMPADD(MICROSECOND, ?, UTC_TIMESTAMP(6)),
    heartbeat_at = UTC_TIMESTAMP(6),
    started_at = COALESCE(started_at, UTC_TIMESTAMP(6)),
    error_code = NULL,
    error_message = NULL,
    updated_at = UTC_TIMESTAMP(6)
WHERE id = ? AND status = 'queued' AND attempt < max_attempts`,
		owner, microseconds, id,
	)
	if err != nil {
		return Lease{}, false, fmt.Errorf("claim archive import: %w", err)
	}
	if affected, err := result.RowsAffected(); err != nil || affected != 1 {
		if err != nil {
			return Lease{}, false, fmt.Errorf("inspect archive import claim: %w", err)
		}
		return Lease{}, false, ErrConflict
	}

	var lease Lease
	var errorCode, errorMessage sql.NullString
	var completedAt sql.NullTime
	var limitsSnapshot []byte
	err = tx.QueryRowContext(ctx, `
SELECT archive_import.id, archive_import.upload_id, upload.display_name, archive_import.created_by,
       archive_import.root_format, archive_import.status, archive_import.scanned_entries,
       archive_import.total_entries, archive_import.eligible_entries, archive_import.skipped_entries,
       archive_import.created_tasks, archive_import.error_code, archive_import.error_message,
       archive_import.attempt, archive_import.max_attempts, archive_import.fencing_token,
       archive_import.completed_at, archive_import.created_at, archive_import.updated_at,
       archive_import.lease_owner, archive_import.lease_until,
       source_blob.id, archive_import.source_storage_key,
       archive_import.source_sha256, archive_import.source_size_bytes,
       archive_import.limits_snapshot
FROM archive_imports archive_import
JOIN uploads upload ON upload.id = archive_import.upload_id
JOIN blobs source_blob ON source_blob.id = archive_import.source_blob_id
JOIN upload_intake_profiles intake ON intake.upload_id = upload.id
WHERE archive_import.id = ?
  AND upload.status = 'completed'
  AND archive_import.source_blob_reference_released_at IS NULL
  AND source_blob.state = 'available'
  AND source_blob.storage_key = archive_import.source_storage_key
  AND source_blob.sha256 = archive_import.source_sha256
  AND source_blob.size_bytes = archive_import.source_size_bytes
  AND intake.input_category = 'archive'
  AND intake.detected_category = 'archive'
  AND intake.validation_status = 'valid'
  AND intake.source_kind = 'direct'
  AND intake.detected_format = archive_import.root_format
  AND intake.archive_import_id = archive_import.id
FOR UPDATE`, id).Scan(
		&lease.ID, &lease.UploadID, &lease.Filename, &lease.CreatedBy,
		&lease.RootFormat, &lease.Status, &lease.ScannedEntries,
		&lease.TotalEntries, &lease.EligibleEntries, &lease.SkippedEntries,
		&lease.CreatedTasks, &errorCode, &errorMessage, &lease.Attempt,
		&lease.MaxAttempts, &lease.FencingToken, &completedAt,
		&lease.CreatedAt, &lease.UpdatedAt, &lease.Owner, &lease.LeaseUntil,
		&lease.SourceBlobID, &lease.SourceKey, &lease.SourceSHA, &lease.SourceSize,
		&limitsSnapshot,
	)
	if err != nil {
		return Lease{}, false, fmt.Errorf("read archive import lease: %w", err)
	}
	lease.ErrorCode = errorCode.String
	lease.ErrorMessage = errorMessage.String
	if completedAt.Valid {
		lease.CompletedAt = &completedAt.Time
	}
	lease.Limits, err = decodeLimitsSnapshot(limitsSnapshot)
	if err != nil {
		return Lease{}, false, errors.New("archive import limits snapshot is invalid")
	}
	if err := tx.Commit(); err != nil {
		return Lease{}, false, fmt.Errorf("commit archive import claim: %w", err)
	}
	return lease, true, nil
}

func decodeLimitsSnapshot(snapshot []byte) (Limits, error) {
	var limits Limits
	if err := json.Unmarshal(snapshot, &limits); err != nil {
		return Limits{}, err
	}
	// Imports queued before max_depth became part of the durable snapshot keep
	// the original v1 depth rather than adopting a later process setting.
	if limits.MaxDepth == 0 {
		limits.MaxDepth = DefaultMaxDepth
	}
	if err := validateLimits(limits); err != nil {
		return Limits{}, err
	}
	return limits, nil
}

func (r *MySQLRepository) Heartbeat(
	ctx context.Context,
	lease Lease,
	duration time.Duration,
) error {
	result, err := r.db.ExecContext(ctx, `
UPDATE archive_imports
SET lease_until = TIMESTAMPADD(MICROSECOND, ?, UTC_TIMESTAMP(6)),
    heartbeat_at = UTC_TIMESTAMP(6), updated_at = UTC_TIMESTAMP(6)
WHERE id = ? AND status = 'running' AND lease_owner = ?
  AND fencing_token = ? AND lease_until > UTC_TIMESTAMP(6)`,
		duration.Microseconds(), lease.ID, lease.Owner, lease.FencingToken,
	)
	if err != nil {
		return fmt.Errorf("heartbeat archive import: %w", err)
	}
	return requireOneRow(result, ErrLeaseLost)
}

func (r *MySQLRepository) ResetForProcessing(
	ctx context.Context,
	lease Lease,
) ([]ReleasedBlob, error) {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin archive import reset: %w", err)
	}
	defer tx.Rollback()
	if err := lockLease(ctx, tx, lease); err != nil {
		return nil, err
	}
	released, err := releaseEntryBlobs(ctx, tx, lease.ID)
	if err != nil {
		return nil, err
	}
	if _, err := tx.ExecContext(ctx, `
DELETE FROM archive_import_entries WHERE archive_import_id = ?`, lease.ID); err != nil {
		return nil, fmt.Errorf("clear prior archive import entries: %w", err)
	}
	result, err := tx.ExecContext(ctx, `
UPDATE archive_imports
SET scanned_entries = 0, total_entries = 0, eligible_entries = 0,
    skipped_entries = 0, expanded_bytes = 0,
    error_code = NULL, error_message = NULL, updated_at = UTC_TIMESTAMP(6)
WHERE id = ? AND status = 'running' AND lease_owner = ? AND fencing_token = ?`,
		lease.ID, lease.Owner, lease.FencingToken,
	)
	if err != nil {
		return nil, fmt.Errorf("reset archive import counters: %w", err)
	}
	if err := requireOneRow(result, ErrLeaseLost); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit archive import reset: %w", err)
	}
	return released, nil
}

func (r *MySQLRepository) PersistEntry(
	ctx context.Context,
	lease Lease,
	entry PersistEntry,
) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin archive entry persistence: %w", err)
	}
	defer tx.Rollback()
	if err := lockLease(ctx, tx, lease); err != nil {
		return err
	}

	var blobID any
	var sha, detectedFormat, category any
	if entry.Status == EntryEligible {
		id, err := retainPublishedBlob(
			ctx, tx, entry.SHA256, entry.Size, entry.BlobStorageKey,
		)
		if err != nil {
			return err
		}
		blobID = id
		sha = entry.SHA256
		detectedFormat = entry.Format
		category = entry.Category
	} else {
		if entry.SHA256 != "" {
			sha = entry.SHA256
		}
		if entry.Format != "" {
			detectedFormat = entry.Format
		}
		if entry.Category != "" {
			category = entry.Category
		}
	}
	var skipReason, errorCode, errorMessage any
	if entry.SkipReason != "" {
		skipReason = entry.SkipReason
	}
	if entry.ErrorCode != "" {
		errorCode = entry.ErrorCode
	}
	if entry.ErrorMessage != "" {
		errorMessage = entry.ErrorMessage
	}
	_, err = tx.ExecContext(ctx, `
INSERT INTO archive_import_entries (
    public_id, archive_import_id, ordinal, logical_path, logical_path_hash,
    size_bytes, sha256, detected_format, detected_category, status,
    skip_reason, error_code, error_message, blob_id, created_at, updated_at
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
          UTC_TIMESTAMP(6), UTC_TIMESTAMP(6))`,
		entry.PublicID, lease.ID, entry.Ordinal, entry.LogicalPath,
		entry.LogicalPathHash[:], entry.Size, sha, detectedFormat, category,
		entry.Status, skipReason, errorCode, errorMessage, blobID,
	)
	if err != nil {
		return fmt.Errorf("insert archive import entry: %w", err)
	}
	eligibleIncrement := 0
	skippedIncrement := 0
	if entry.Status == EntryEligible {
		eligibleIncrement = 1
	} else {
		skippedIncrement = 1
	}
	result, err := tx.ExecContext(ctx, `
UPDATE archive_imports
SET scanned_entries = scanned_entries + 1,
    total_entries = total_entries + 1,
    eligible_entries = eligible_entries + ?,
    skipped_entries = skipped_entries + ?,
    updated_at = UTC_TIMESTAMP(6)
WHERE id = ? AND status = 'running' AND lease_owner = ? AND fencing_token = ?`,
		eligibleIncrement, skippedIncrement, lease.ID, lease.Owner, lease.FencingToken,
	)
	if err != nil {
		return fmt.Errorf("advance archive import counters: %w", err)
	}
	if err := requireOneRow(result, ErrLeaseLost); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit archive import entry: %w", err)
	}
	return nil
}

func retainPublishedBlob(
	ctx context.Context,
	tx *sql.Tx,
	sha string,
	size int64,
	storageKey string,
) (uint64, error) {
	var id uint64
	var storedSize int64
	var storedKey, state string
	var references uint64
	err := tx.QueryRowContext(ctx, `
SELECT id, size_bytes, storage_key, state, reference_count
FROM blobs
WHERE sha256 = ?
FOR UPDATE`, sha).Scan(&id, &storedSize, &storedKey, &state, &references)
	if errors.Is(err, sql.ErrNoRows) {
		result, insertErr := tx.ExecContext(ctx, `
INSERT INTO blobs (
    sha256, size_bytes, storage_key, reference_count, state, verified_at
) VALUES (?, ?, ?, 1, 'available', UTC_TIMESTAMP(6))`,
			sha, size, storageKey,
		)
		if insertErr != nil {
			return 0, fmt.Errorf("create archive entry blob: %w", insertErr)
		}
		inserted, insertErr := result.LastInsertId()
		if insertErr != nil || inserted <= 0 {
			if insertErr == nil {
				insertErr = errors.New("invalid blob ID")
			}
			return 0, fmt.Errorf("read archive entry blob ID: %w", insertErr)
		}
		return uint64(inserted), nil
	}
	if err != nil {
		return 0, fmt.Errorf("lock archive entry blob: %w", err)
	}
	if storedSize != size || storedKey != storageKey {
		return 0, ErrConflict
	}
	var result sql.Result
	switch state {
	case "available":
		result, err = tx.ExecContext(ctx, `
UPDATE blobs
SET reference_count = reference_count + 1
WHERE id = ? AND state = 'available'`, id)
	case "deleting", "deleted":
		if references != 0 {
			return 0, ErrConflict
		}
		result, err = tx.ExecContext(ctx, `
UPDATE blobs
SET reference_count = 1, state = 'available', deleted_at = NULL,
    verified_at = UTC_TIMESTAMP(6)
WHERE id = ? AND state = ? AND reference_count = 0`, id, state)
	default:
		return 0, ErrConflict
	}
	if err != nil {
		return 0, fmt.Errorf("retain archive entry blob: %w", err)
	}
	if err := requireOneRow(result, ErrConflict); err != nil {
		return 0, err
	}
	return id, nil
}

func (r *MySQLRepository) WithBlobFence(
	ctx context.Context,
	sha string,
	operation func() error,
) error {
	if ctx == nil || !isLowerHex(sha) || len(sha) != 64 || operation == nil {
		return ErrInvalidInput
	}
	if err := blobfence.With(ctx, r.db, sha, operation); err != nil {
		return fmt.Errorf("archive blob fence: %w", err)
	}
	return nil
}

func (r *MySQLRepository) BlobIsReleased(
	ctx context.Context,
	value ReleasedBlob,
) (bool, error) {
	var count int
	err := r.db.QueryRowContext(ctx, `
SELECT COUNT(*)
FROM blobs
WHERE id = ? AND storage_key = ?
  AND reference_count = 0 AND state = 'deleting'`,
		value.ID, value.StorageKey,
	).Scan(&count)
	if err != nil {
		return false, fmt.Errorf("verify released archive blob: %w", err)
	}
	return count == 1, nil
}

func (r *MySQLRepository) CompleteLease(
	ctx context.Context,
	lease Lease,
	expandedBytes int64,
) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin archive import completion: %w", err)
	}
	defer tx.Rollback()
	if err := lockLease(ctx, tx, lease); err != nil {
		return err
	}
	if _, _, err := releaseImportSource(ctx, tx, lease.ID); err != nil {
		return err
	}
	result, err := tx.ExecContext(ctx, `
UPDATE archive_imports
SET status = 'ready', expanded_bytes = ?, lease_owner = NULL,
    lease_until = NULL, heartbeat_at = NULL, completed_at = UTC_TIMESTAMP(6),
    error_code = NULL, error_message = NULL, updated_at = UTC_TIMESTAMP(6)
WHERE id = ? AND status = 'running' AND lease_owner = ? AND fencing_token = ?
  AND lease_until > UTC_TIMESTAMP(6)`,
		expandedBytes, lease.ID, lease.Owner, lease.FencingToken,
	)
	if err != nil {
		return fmt.Errorf("complete archive import: %w", err)
	}
	if err := requireOneRow(result, ErrLeaseLost); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit archive import completion: %w", err)
	}
	return nil
}

func (r *MySQLRepository) FailLease(
	ctx context.Context,
	lease Lease,
	code string,
	message string,
	retry bool,
	retryDelay time.Duration,
) error {
	status := StatusFailed
	completed := "UTC_TIMESTAMP(6)"
	available := "available_at"
	if retry && lease.Attempt < lease.MaxAttempts {
		status = StatusQueued
		completed = "NULL"
		available = "TIMESTAMPADD(MICROSECOND, ?, UTC_TIMESTAMP(6))"
	}
	query := `
UPDATE archive_imports
SET status = ?, available_at = ` + available + `,
    lease_owner = NULL, lease_until = NULL, heartbeat_at = NULL,
    error_code = ?, error_message = ?, completed_at = ` + completed + `,
    updated_at = UTC_TIMESTAMP(6)
WHERE id = ? AND status = 'running' AND lease_owner = ? AND fencing_token = ?`
	arguments := []any{status}
	if status == StatusQueued {
		arguments = append(arguments, retryDelay.Microseconds())
	}
	arguments = append(arguments, code, bounded(message, 2048), lease.ID, lease.Owner, lease.FencingToken)
	if status == StatusQueued {
		result, err := r.db.ExecContext(ctx, query, arguments...)
		if err != nil {
			return fmt.Errorf("fail archive import: %w", err)
		}
		return requireOneRow(result, ErrLeaseLost)
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin terminal archive import failure: %w", err)
	}
	defer tx.Rollback()
	if err := lockLease(ctx, tx, lease); err != nil {
		return err
	}
	if _, _, err := releaseImportSource(ctx, tx, lease.ID); err != nil {
		return err
	}
	result, err := tx.ExecContext(ctx, query, arguments...)
	if err != nil {
		return fmt.Errorf("fail archive import: %w", err)
	}
	if err := requireOneRow(result, ErrLeaseLost); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit terminal archive import failure: %w", err)
	}
	return nil
}

func lockLease(ctx context.Context, tx *sql.Tx, lease Lease) error {
	var marker int
	err := tx.QueryRowContext(ctx, `
SELECT 1
FROM archive_imports
WHERE id = ? AND status = 'running' AND lease_owner = ?
  AND fencing_token = ? AND lease_until > UTC_TIMESTAMP(6)
FOR UPDATE`, lease.ID, lease.Owner, lease.FencingToken).Scan(&marker)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrLeaseLost
	}
	if err != nil {
		return fmt.Errorf("lock archive import lease: %w", err)
	}
	return nil
}

func releaseEntryBlobs(
	ctx context.Context,
	tx *sql.Tx,
	importID string,
) ([]ReleasedBlob, error) {
	rows, err := tx.QueryContext(ctx, `
SELECT id, blob_id
FROM archive_import_entries
WHERE archive_import_id = ?
  AND blob_id IS NOT NULL
  AND blob_reference_released_at IS NULL
ORDER BY id ASC
FOR UPDATE`, importID)
	if err != nil {
		return nil, fmt.Errorf("lock archive entry blob references: %w", err)
	}
	type reference struct {
		entryID uint64
		blobID  uint64
	}
	references := make([]reference, 0)
	for rows.Next() {
		var value reference
		if err := rows.Scan(&value.entryID, &value.blobID); err != nil {
			rows.Close()
			return nil, fmt.Errorf("scan archive entry blob reference: %w", err)
		}
		references = append(references, value)
	}
	if err := rows.Close(); err != nil {
		return nil, fmt.Errorf("close archive entry blob references: %w", err)
	}
	released := make([]ReleasedBlob, 0)
	for _, reference := range references {
		candidate, deleting, err := releaseBlob(ctx, tx, reference.blobID)
		if err != nil {
			return nil, err
		}
		if deleting {
			released = append(released, candidate)
		}
		if _, err := tx.ExecContext(ctx, `
UPDATE archive_import_entries
SET blob_reference_released_at = UTC_TIMESTAMP(6)
WHERE id = ? AND blob_reference_released_at IS NULL`, reference.entryID); err != nil {
			return nil, fmt.Errorf("mark archive entry blob released: %w", err)
		}
	}
	return released, nil
}

func releaseImportSource(
	ctx context.Context,
	tx *sql.Tx,
	importID string,
) (ReleasedBlob, bool, error) {
	var blobID uint64
	var releasedAt sql.NullTime
	err := tx.QueryRowContext(ctx, `
SELECT source_blob_id, source_blob_reference_released_at
FROM archive_imports
WHERE id = ?
FOR UPDATE`, importID).Scan(&blobID, &releasedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return ReleasedBlob{}, false, ErrNotFound
	}
	if err != nil {
		return ReleasedBlob{}, false, fmt.Errorf("lock archive import source reference: %w", err)
	}
	if releasedAt.Valid {
		return ReleasedBlob{}, false, nil
	}
	candidate, deleting, err := releaseBlob(ctx, tx, blobID)
	if err != nil {
		return ReleasedBlob{}, false, err
	}
	result, err := tx.ExecContext(ctx, `
UPDATE archive_imports
SET source_blob_reference_released_at = UTC_TIMESTAMP(6),
    updated_at = UTC_TIMESTAMP(6)
WHERE id = ? AND source_blob_reference_released_at IS NULL`, importID)
	if err != nil {
		return ReleasedBlob{}, false, fmt.Errorf("mark archive import source released: %w", err)
	}
	if err := requireOneRow(result, ErrConflict); err != nil {
		return ReleasedBlob{}, false, err
	}
	return candidate, deleting, nil
}

func releaseBlob(
	ctx context.Context,
	tx *sql.Tx,
	blobID uint64,
) (ReleasedBlob, bool, error) {
	var references uint64
	var state, storageKey string
	err := tx.QueryRowContext(ctx, `
SELECT reference_count, state, storage_key
FROM blobs
WHERE id = ?
FOR UPDATE`, blobID).Scan(&references, &state, &storageKey)
	if err != nil {
		return ReleasedBlob{}, false, fmt.Errorf("lock archive entry blob release: %w", err)
	}
	if references == 0 || state != "available" {
		return ReleasedBlob{}, false, ErrConflict
	}
	nextState := "available"
	deleting := references == 1
	if deleting {
		nextState = "deleting"
	}
	result, err := tx.ExecContext(ctx, `
UPDATE blobs
SET reference_count = reference_count - 1, state = ?
WHERE id = ? AND state = 'available' AND reference_count = ?`,
		nextState, blobID, references,
	)
	if err != nil {
		return ReleasedBlob{}, false, fmt.Errorf("release archive entry blob: %w", err)
	}
	if err := requireOneRow(result, ErrConflict); err != nil {
		return ReleasedBlob{}, false, err
	}
	return ReleasedBlob{ID: blobID, StorageKey: storageKey}, deleting, nil
}

func (r *MySQLRepository) MarkBlobDeleted(
	ctx context.Context,
	blobID uint64,
) error {
	_, err := r.db.ExecContext(ctx, `
UPDATE blobs
SET state = 'deleted', deleted_at = UTC_TIMESTAMP(6)
WHERE id = ? AND state = 'deleting' AND reference_count = 0`, blobID)
	if err != nil {
		return fmt.Errorf("mark released archive blob deleted: %w", err)
	}
	return nil
}

func (r *MySQLRepository) RecoverExpired(
	ctx context.Context,
	retryDelay time.Duration,
) (int64, error) {
	const recoveryLimit = 1000
	rows, err := r.db.QueryContext(ctx, `
SELECT id
FROM archive_imports
WHERE status = 'running' AND lease_until <= UTC_TIMESTAMP(6)
ORDER BY updated_at ASC, id ASC
LIMIT ?`, recoveryLimit)
	if err != nil {
		return 0, fmt.Errorf("list expired archive import leases: %w", err)
	}
	ids := make([]string, 0)
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return 0, fmt.Errorf("scan expired archive import lease: %w", err)
		}
		ids = append(ids, id)
	}
	if err := rows.Close(); err != nil {
		return 0, fmt.Errorf("close expired archive import leases: %w", err)
	}
	var recovered int64
	var itemErrors []error
	for _, id := range ids {
		didRecover, err := r.recoverExpiredLease(ctx, id, retryDelay)
		if err != nil {
			deferErr := r.deferExpiredRecovery(ctx, id, err)
			itemErrors = append(itemErrors, errors.Join(
				fmt.Errorf("recover expired archive import %s: %w", id, err),
				deferErr,
			))
			continue
		}
		if didRecover {
			recovered++
		}
	}
	return recovered, errors.Join(itemErrors...)
}

func (r *MySQLRepository) recoverExpiredLease(
	ctx context.Context,
	id string,
	retryDelay time.Duration,
) (bool, error) {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return false, fmt.Errorf("begin expired archive import recovery: %w", err)
	}
	defer tx.Rollback()
	var attempt, maxAttempts uint32
	err = tx.QueryRowContext(ctx, `
SELECT attempt, max_attempts
FROM archive_imports
WHERE id = ? AND status = 'running' AND lease_until <= UTC_TIMESTAMP(6)
FOR UPDATE`, id).Scan(&attempt, &maxAttempts)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("lock expired archive import lease: %w", err)
	}
	if attempt >= maxAttempts {
		if _, _, err := releaseImportSource(ctx, tx, id); err != nil {
			return false, err
		}
		result, err := tx.ExecContext(ctx, `
UPDATE archive_imports
SET status = 'failed', lease_owner = NULL, lease_until = NULL,
    heartbeat_at = NULL, error_code = 'archive_import_lease_expired',
    error_message = 'Archive import lease expired after the final attempt.',
    completed_at = UTC_TIMESTAMP(6), updated_at = UTC_TIMESTAMP(6)
WHERE id = ? AND status = 'running' AND lease_until <= UTC_TIMESTAMP(6)
  AND attempt >= max_attempts`, id)
		if err != nil {
			return false, fmt.Errorf("fail exhausted archive import lease: %w", err)
		}
		if err := requireOneRow(result, ErrConflict); err != nil {
			return false, err
		}
	} else {
		result, err := tx.ExecContext(ctx, `
UPDATE archive_imports
SET status = 'queued', lease_owner = NULL, lease_until = NULL,
    heartbeat_at = NULL,
    available_at = TIMESTAMPADD(MICROSECOND, ?, UTC_TIMESTAMP(6)),
    error_code = 'archive_import_lease_expired',
    error_message = 'Archive import lease expired and was queued for retry.',
    completed_at = NULL, updated_at = UTC_TIMESTAMP(6)
WHERE id = ? AND status = 'running' AND lease_until <= UTC_TIMESTAMP(6)
  AND attempt < max_attempts`, retryDelay.Microseconds(), id)
		if err != nil {
			return false, fmt.Errorf("requeue expired archive import lease: %w", err)
		}
		if err := requireOneRow(result, ErrConflict); err != nil {
			return false, err
		}
	}
	if err := tx.Commit(); err != nil {
		return false, fmt.Errorf("commit expired archive import recovery: %w", err)
	}
	return true, nil
}

func (r *MySQLRepository) deferExpiredRecovery(
	ctx context.Context,
	id string,
	cause error,
) error {
	_, err := r.db.ExecContext(ctx, `
UPDATE archive_imports
SET error_code = 'archive_import_recovery_failed', error_message = ?,
    updated_at = UTC_TIMESTAMP(6)
WHERE id = ? AND status = 'running' AND lease_until <= UTC_TIMESTAMP(6)`,
		bounded(cause.Error(), 2048), id,
	)
	if err != nil {
		return fmt.Errorf("defer expired archive import recovery: %w", err)
	}
	return nil
}

func requireOneRow(result sql.Result, conflict error) error {
	affected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if affected != 1 {
		return conflict
	}
	return nil
}

func isDuplicateKey(err error) bool {
	var mysqlError *mysql.MySQLError
	return errors.As(err, &mysqlError) && mysqlError.Number == 1062
}

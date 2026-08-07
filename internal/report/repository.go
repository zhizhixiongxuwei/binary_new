package report

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/go-sql-driver/mysql"
)

const reportColumns = `
SELECT id, task_id, format, schema_version, status, sha256, size_bytes,
       error_code, error_message, created_at, completed_at
FROM reports`

type MySQLRepository struct {
	db *sql.DB
}

func NewMySQLRepository(db *sql.DB) *MySQLRepository {
	return &MySQLRepository{db: db}
}

func (r *MySQLRepository) List(
	ctx context.Context,
	taskID string,
) (List, error) {
	if err := ctx.Err(); err != nil {
		return List{}, err
	}
	var sampleRelation string
	err := r.db.QueryRowContext(ctx, `
SELECT CASE
           WHEN sample_deleted_at IS NOT NULL THEN 'deleted'
           WHEN sample_expires_at <= UTC_TIMESTAMP(6) THEN 'expired'
           ELSE 'retained'
       END
FROM tasks
WHERE id = ? AND deleted_at IS NULL
LIMIT 1`, taskID).Scan(&sampleRelation)
	if errors.Is(err, sql.ErrNoRows) {
		return List{}, ErrTaskNotFound
	}
	if err != nil {
		return List{}, fmt.Errorf("find report task: %w", err)
	}

	rows, err := r.db.QueryContext(ctx, reportColumns+`
WHERE task_id = ? AND schema_version = ? AND deleted_at IS NULL
ORDER BY created_at ASC, id ASC`, taskID, SchemaVersion)
	if err != nil {
		return List{}, fmt.Errorf("list task reports: %w", err)
	}
	defer rows.Close()
	items := make([]Report, 0, 2)
	for rows.Next() {
		item, err := scanReport(rows)
		if err != nil {
			return List{}, fmt.Errorf("scan task report: %w", err)
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return List{}, fmt.Errorf("iterate task reports: %w", err)
	}
	return List{Items: items, SampleRelation: sampleRelation}, nil
}

func (r *MySQLRepository) Claim(
	ctx context.Context,
	claim Claim,
) (result Report, generate bool, returnErr error) {
	if claim.LeaseOwner == "" || len(claim.LeaseOwner) > 255 ||
		claim.LeaseDuration <= 0 || claim.LeaseDuration.Microseconds() <= 0 {
		return Report{}, false, errors.New("report generation lease is invalid")
	}
	leaseMicros := claim.LeaseDuration.Microseconds()
	transaction, err := r.db.BeginTx(ctx, &sql.TxOptions{
		Isolation: sql.LevelReadCommitted,
	})
	if err != nil {
		return Report{}, false, fmt.Errorf("begin report claim: %w", err)
	}
	finished := false
	defer func() {
		if !finished {
			returnErr = joinRollbackError(
				returnErr, transaction.Rollback(), "rollback report claim",
			)
		}
	}()

	var taskStatus string
	var activeRetention uint8
	err = transaction.QueryRowContext(ctx, `
SELECT t.status,
       EXISTS (
      SELECT 1
      FROM task_sample_retention_operations operation
      WHERE operation.task_id = t.id
        AND operation.status = 'cleaning'
        AND operation.lease_until > UTC_TIMESTAMP(6)
       )
FROM tasks t
WHERE t.id = ? AND t.deleted_at IS NULL
FOR UPDATE`, claim.TaskID).Scan(&taskStatus, &activeRetention)
	if errors.Is(err, sql.ErrNoRows) {
		return Report{}, false, ErrTaskNotFound
	}
	if err != nil {
		return Report{}, false, fmt.Errorf("lock report task: %w", err)
	}
	if activeRetention != 0 {
		return Report{}, false, ErrGenerationInProgress
	}
	if !reportableTaskStatus(taskStatus) {
		return Report{}, false, ErrTaskNotTerminal
	}

	existing, err := queryReportByIdentity(
		ctx, transaction, claim.TaskID, claim.Format, claim.SchemaVersion, true,
	)
	switch {
	case err == nil && existing.Status == "complete":
		finished = true
		if err := transaction.Commit(); err != nil {
			return Report{}, false, fmt.Errorf("commit report replay: %w", err)
		}
		return existing, false, nil
	case err == nil && (existing.Status == "generating" || existing.Status == "queued"):
		return Report{}, false, ErrGenerationInProgress
	case err == nil && existing.Status == "failed":
		result, err = restartFailedReport(
			ctx, transaction, existing, claim.LeaseOwner, leaseMicros,
		)
		if err != nil {
			return Report{}, false, err
		}
	case err == nil:
		return Report{}, false, ErrReportConflict
	case !errors.Is(err, sql.ErrNoRows):
		return Report{}, false, fmt.Errorf("find existing report: %w", err)
	default:
		_, err = transaction.ExecContext(ctx, `
INSERT INTO reports (
    id, task_id, format, schema_version, status,
    generation_fence, generation_owner, generation_lease_until,
    generation_heartbeat_at, created_at
) VALUES (?, ?, ?, ?, 'generating', 1, ?,
          DATE_ADD(UTC_TIMESTAMP(6), INTERVAL ? MICROSECOND),
          UTC_TIMESTAMP(6), ?)`,
			claim.ReportID,
			claim.TaskID,
			string(claim.Format),
			claim.SchemaVersion,
			claim.LeaseOwner,
			leaseMicros,
			claim.CreatedAt,
		)
		if err != nil {
			if isDuplicateKey(err) {
				return Report{}, false, ErrGenerationInProgress
			}
			return Report{}, false, fmt.Errorf("create report record: %w", err)
		}
		result = Report{
			ID: claim.ReportID, TaskID: claim.TaskID, Format: claim.Format,
			SchemaVersion: claim.SchemaVersion, Status: "generating",
			CreatedAt: claim.CreatedAt, GenerationOwner: claim.LeaseOwner,
			GenerationFence: 1,
		}
	}

	finished = true
	if err := transaction.Commit(); err != nil {
		return Report{}, false, fmt.Errorf("commit report claim: %w", err)
	}
	return result, true, nil
}

func restartFailedReport(
	ctx context.Context,
	transaction *sql.Tx,
	existing Report,
	leaseOwner string,
	leaseMicros int64,
) (Report, error) {
	result, err := transaction.ExecContext(ctx, `
UPDATE reports
SET status = 'generating',
    generation_fence = generation_fence + 1,
    generation_owner = ?,
    generation_lease_until =
        DATE_ADD(UTC_TIMESTAMP(6), INTERVAL ? MICROSECOND),
    generation_heartbeat_at = UTC_TIMESTAMP(6),
    storage_key = NULL,
    sha256 = NULL,
    size_bytes = NULL,
    error_code = NULL,
    error_message = NULL,
    completed_at = NULL,
    deleted_at = NULL
WHERE task_id = ? AND id = ? AND status = 'failed'`,
		leaseOwner, leaseMicros, existing.TaskID, existing.ID,
	)
	if err != nil {
		return Report{}, fmt.Errorf("restart failed report: %w", err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return Report{}, fmt.Errorf("inspect restarted report: %w", err)
	}
	if affected != 1 {
		return Report{}, ErrGenerationInProgress
	}
	var fence uint64
	if err := transaction.QueryRowContext(ctx, `
SELECT generation_fence
FROM reports
WHERE task_id = ? AND id = ?
LIMIT 1`, existing.TaskID, existing.ID).Scan(&fence); err != nil {
		return Report{}, fmt.Errorf("read restarted report fence: %w", err)
	}
	existing.Status = "generating"
	existing.GenerationOwner = leaseOwner
	existing.GenerationFence = fence
	existing.SHA256 = nil
	existing.SizeBytes = nil
	existing.ErrorCode = nil
	existing.ErrorMessage = nil
	existing.CompletedAt = nil
	return existing, nil
}

func (r *MySQLRepository) Renew(
	ctx context.Context,
	taskID string,
	reportID string,
	leaseOwner string,
	fence uint64,
	leaseDuration time.Duration,
) (bool, error) {
	if leaseOwner == "" || fence == 0 || leaseDuration <= 0 ||
		leaseDuration.Microseconds() <= 0 {
		return false, errors.New("report generation renewal lease is invalid")
	}
	result, err := r.db.ExecContext(ctx, `
UPDATE reports report
JOIN tasks task ON task.id = report.task_id
SET report.generation_lease_until =
        DATE_ADD(UTC_TIMESTAMP(6), INTERVAL ? MICROSECOND),
    report.generation_heartbeat_at = UTC_TIMESTAMP(6)
WHERE report.task_id = ?
  AND report.id = ?
  AND report.status = 'generating'
  AND report.generation_owner = ?
  AND report.generation_fence = ?
  AND task.deleted_at IS NULL
  AND task.status IN ('SUCCEEDED', 'PARTIAL_SUCCEEDED', 'FAILED', 'CANCELLED')`,
		leaseDuration.Microseconds(), taskID, reportID, leaseOwner, fence,
	)
	if err != nil {
		return false, fmt.Errorf("renew report generation lease: %w", err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("inspect report generation renewal: %w", err)
	}
	return affected == 1, nil
}

func (r *MySQLRepository) AuthorizePublish(
	ctx context.Context,
	taskID string,
	reportID string,
	leaseOwner string,
	fence uint64,
) error {
	var taskStatus string
	var reportStatus string
	err := r.db.QueryRowContext(ctx, `
SELECT task.status, report.status
FROM tasks task
JOIN reports report ON report.task_id = task.id
WHERE task.id = ?
  AND report.id = ?
  AND task.deleted_at IS NULL
  AND report.deleted_at IS NULL
  AND report.generation_owner = ?
  AND report.generation_fence = ?
  AND report.generation_lease_until > UTC_TIMESTAMP(6)
LIMIT 1`, taskID, reportID, leaseOwner, fence).Scan(
		&taskStatus, &reportStatus,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrReportConflict
	}
	if err != nil {
		return fmt.Errorf("authorize report publication: %w", err)
	}
	if !reportableTaskStatus(taskStatus) {
		return ErrTaskNotTerminal
	}
	if reportStatus != "generating" {
		return ErrReportConflict
	}
	return nil
}

func (r *MySQLRepository) Complete(
	ctx context.Context,
	taskID string,
	reportID string,
	leaseOwner string,
	fence uint64,
	artifact ArtifactMetadata,
) (Report, error) {
	tx, err := r.db.BeginTx(ctx, &sql.TxOptions{
		Isolation: sql.LevelReadCommitted,
	})
	if err != nil {
		return Report{}, fmt.Errorf("begin report completion: %w", err)
	}
	defer tx.Rollback()

	var taskStatus string
	err = tx.QueryRowContext(ctx, `
SELECT status
FROM tasks
WHERE id = ? AND deleted_at IS NULL
FOR UPDATE`, taskID).Scan(&taskStatus)
	if errors.Is(err, sql.ErrNoRows) {
		return Report{}, ErrReportConflict
	}
	if err != nil {
		return Report{}, fmt.Errorf("lock report task for completion: %w", err)
	}
	if !reportableTaskStatus(taskStatus) {
		return Report{}, ErrTaskNotTerminal
	}

	result, err := tx.ExecContext(ctx, `
UPDATE reports
SET status = 'complete',
    storage_key = ?,
    sha256 = ?,
    size_bytes = ?,
    error_code = NULL,
    error_message = NULL,
    generation_owner = NULL,
    generation_lease_until = NULL,
    generation_heartbeat_at = NULL,
    completed_at = ?
WHERE task_id = ? AND id = ? AND status = 'generating'
  AND generation_owner = ?
  AND generation_fence = ?
  AND generation_lease_until > UTC_TIMESTAMP(6)`,
		artifact.StorageKey,
		artifact.SHA256,
		artifact.SizeBytes,
		artifact.CompletedAt,
		taskID,
		reportID,
		leaseOwner,
		fence,
	)
	if err != nil {
		return Report{}, fmt.Errorf("complete report record: %w", err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return Report{}, fmt.Errorf("inspect completed report: %w", err)
	}
	if affected != 1 {
		return Report{}, ErrReportConflict
	}
	value, err := queryReportByID(ctx, tx, taskID, reportID)
	if err != nil {
		return Report{}, fmt.Errorf("read completed report: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return Report{}, fmt.Errorf("commit report completion: %w", err)
	}
	return value, nil
}

func (r *MySQLRepository) Fail(
	ctx context.Context,
	taskID string,
	reportID string,
	leaseOwner string,
	fence uint64,
	errorCode string,
	errorMessage string,
	completedAt time.Time,
) error {
	result, err := r.db.ExecContext(ctx, `
UPDATE reports
SET status = 'failed',
    storage_key = NULL,
    sha256 = NULL,
    size_bytes = NULL,
    error_code = ?,
    error_message = ?,
    generation_owner = NULL,
    generation_lease_until = NULL,
    generation_heartbeat_at = NULL,
    completed_at = ?
WHERE task_id = ? AND id = ? AND status = 'generating'
  AND generation_owner = ?
  AND generation_fence = ?`,
		errorCode, errorMessage, completedAt, taskID, reportID,
		leaseOwner, fence,
	)
	if err != nil {
		return fmt.Errorf("fail report record: %w", err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("inspect failed report: %w", err)
	}
	if affected != 1 {
		return ErrReportConflict
	}
	return nil
}

func (r *MySQLRepository) Download(
	ctx context.Context,
	taskID string,
	reportID string,
) (DownloadDescriptor, error) {
	var descriptor DownloadDescriptor
	var format string
	var storageKey sql.NullString
	var digest sql.NullString
	var size sql.Null[uint64]
	err := r.db.QueryRowContext(ctx, `
SELECT report.id, report.task_id, report.format, report.status,
       report.storage_key, report.sha256, report.size_bytes
FROM reports report
JOIN tasks task ON task.id = report.task_id
WHERE report.task_id = ?
  AND report.id = ?
  AND report.deleted_at IS NULL
  AND task.deleted_at IS NULL
LIMIT 1`, taskID, reportID).Scan(
		&descriptor.ReportID,
		&descriptor.TaskID,
		&format,
		&descriptor.Status,
		&storageKey,
		&digest,
		&size,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return DownloadDescriptor{}, ErrReportNotFound
	}
	if err != nil {
		return DownloadDescriptor{}, fmt.Errorf("read report download: %w", err)
	}
	descriptor.Format = Format(format)
	if !storageKey.Valid || !digest.Valid || !size.Valid {
		return DownloadDescriptor{}, ErrArtifactUnavailable
	}
	descriptor.StorageKey = storageKey.String
	descriptor.SHA256 = digest.String
	descriptor.SizeBytes = size.V
	return descriptor, nil
}

type rowScanner interface {
	Scan(...any) error
}

type rowQuerier interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

func queryReportByIdentity(
	ctx context.Context,
	querier rowQuerier,
	taskID string,
	format Format,
	schemaVersion string,
	forUpdate bool,
) (Report, error) {
	suffix := ""
	if forUpdate {
		suffix = " FOR UPDATE"
	}
	return scanReport(querier.QueryRowContext(
		ctx,
		reportColumns+`
WHERE task_id = ? AND format = ? AND schema_version = ?
LIMIT 1`+suffix,
		taskID,
		string(format),
		schemaVersion,
	))
}

func queryReportByID(
	ctx context.Context,
	querier rowQuerier,
	taskID string,
	reportID string,
) (Report, error) {
	return scanReport(querier.QueryRowContext(
		ctx,
		reportColumns+`
WHERE task_id = ? AND id = ?
LIMIT 1`,
		taskID,
		reportID,
	))
}

func scanReport(scanner rowScanner) (Report, error) {
	var value Report
	var format string
	var digest sql.NullString
	var size sql.Null[uint64]
	var errorCode sql.NullString
	var errorMessage sql.NullString
	var completedAt sql.NullTime
	if err := scanner.Scan(
		&value.ID,
		&value.TaskID,
		&format,
		&value.SchemaVersion,
		&value.Status,
		&digest,
		&size,
		&errorCode,
		&errorMessage,
		&value.CreatedAt,
		&completedAt,
	); err != nil {
		return Report{}, err
	}
	value.Format = Format(format)
	if digest.Valid {
		value.SHA256 = &digest.String
	}
	if size.Valid {
		value.SizeBytes = &size.V
	}
	if errorCode.Valid {
		value.ErrorCode = &errorCode.String
	}
	if errorMessage.Valid {
		value.ErrorMessage = &errorMessage.String
	}
	if completedAt.Valid {
		value.CompletedAt = &completedAt.Time
	}
	return value, nil
}

func reportableTaskStatus(status string) bool {
	switch status {
	case "SUCCEEDED", "PARTIAL_SUCCEEDED", "FAILED", "CANCELLED":
		return true
	default:
		return false
	}
}

func isDuplicateKey(err error) bool {
	var mysqlError *mysql.MySQLError
	return errors.As(err, &mysqlError) && mysqlError.Number == 1062
}

func joinRollbackError(returnErr error, rollbackErr error, operation string) error {
	if rollbackErr == nil || errors.Is(rollbackErr, sql.ErrTxDone) {
		return returnErr
	}
	wrapped := fmt.Errorf("%s: %w", operation, rollbackErr)
	if returnErr == nil {
		return wrapped
	}
	return errors.Join(returnErr, wrapped)
}

var _ Repository = (*MySQLRepository)(nil)

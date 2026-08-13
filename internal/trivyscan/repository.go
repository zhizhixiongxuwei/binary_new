package trivyscan

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"time"
	"unicode"
	"unicode/utf8"

	trivyadapter "binaryscan/internal/analyzers/trivy"
	"binaryscan/internal/containerarchive"
	"binaryscan/internal/queue"
	"binaryscan/internal/trivydb"
	"binaryscan/internal/trivyhandoff"
)

const maxRepositoryArtifactBytes = int64(1 << 30)

var canonicalUUIDPattern = regexp.MustCompile(
	`^[a-f0-9]{8}-[a-f0-9]{4}-[0-9a-f]{4}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$`,
)
var ociDigestPattern = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)

type existingRun struct {
	taskID          string
	taskAttemptID   uint64
	jobID           string
	analyzerName    string
	analyzerVersion string
	parameters      []byte
	status          string
}

type artifactRecord struct {
	id         string
	storageKey string
	sha256     string
	sizeBytes  int64
	state      string
	deletedAt  sql.NullTime
}

func NewMySQLRepository(
	db *sql.DB,
	repositoryRoot string,
	taskWorkRoot string,
	maxArtifactBytes int64,
) (*MySQLRepository, error) {
	if db == nil {
		return nil, fmt.Errorf("%w: nil SQL database", ErrInvalidConfiguration)
	}
	cleanRepository, repositoryOK := cleanAbsoluteRoot(repositoryRoot)
	cleanWork, workOK := cleanAbsoluteRoot(taskWorkRoot)
	if !repositoryOK || !workOK || rootsOverlap(cleanRepository, cleanWork) ||
		maxArtifactBytes <= 0 ||
		maxArtifactBytes > maxRepositoryArtifactBytes {
		return nil, fmt.Errorf(
			"%w: repository roots or artifact limit are invalid",
			ErrInvalidConfiguration,
		)
	}
	if err := verifyDirectoryRoot(cleanRepository); err != nil {
		return nil, fmt.Errorf(
			"%w: repository root: %v",
			ErrInvalidConfiguration,
			err,
		)
	}
	if err := verifyDirectoryRoot(cleanWork); err != nil {
		return nil, fmt.Errorf(
			"%w: task-work root: %v",
			ErrInvalidConfiguration,
			err,
		)
	}
	return &MySQLRepository{
		db: db, repositoryRoot: cleanRepository, taskWorkRoot: cleanWork,
		maxArtifactBytes: maxArtifactBytes,
	}, nil
}

func (r *MySQLRepository) Publish(
	ctx context.Context,
	lease queue.Lease,
	publication Publication,
) error {
	_, err := r.PublishWithSummary(ctx, lease, publication)
	return err
}

func (r *MySQLRepository) PublishWithSummary(
	ctx context.Context,
	lease queue.Lease,
	publication Publication,
) (summary PublishSummary, returnErr error) {
	if err := validatePublication(lease, publication, r.maxArtifactBytes); err != nil {
		return PublishSummary{}, err
	}
	transaction, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return PublishSummary{}, fmt.Errorf("begin Trivy result publication: %w", err)
	}
	finished := false
	commitAttempted := false
	var created []publishedArtifact
	defer func() {
		if !finished {
			rollbackErr := transaction.Rollback()
			if rollbackErr != nil && !errors.Is(rollbackErr, sql.ErrTxDone) {
				returnErr = errors.Join(
					returnErr,
					fmt.Errorf("rollback Trivy result publication: %w", rollbackErr),
				)
			}
		}
		if returnErr != nil && !commitAttempted {
			for _, artifact := range created {
				returnErr = errors.Join(
					returnErr,
					r.removePublishedArtifact(artifact),
				)
			}
		}
	}()
	if err := lockPublishingLease(ctx, transaction, lease); err != nil {
		return PublishSummary{}, err
	}
	if err := registerDatabaseBundle(ctx, transaction, publication.Snapshot); err != nil {
		return PublishSummary{}, err
	}

	for _, run := range publication.Runs {
		parameters, err := publication.parameters(run)
		if err != nil {
			return PublishSummary{}, err
		}
		runID := stableUUID(
			"binaryscan.trivy.run.v1",
			lease.TaskID,
			strconv.FormatUint(*lease.TaskAttemptID, 10),
			lease.JobID,
			run.TargetKey,
		)
		existing, found, err := findAnalyzerRun(
			ctx,
			transaction,
			runID,
		)
		if err != nil {
			return PublishSummary{}, err
		}
		if found {
			if existing.taskID != lease.TaskID ||
				existing.taskAttemptID != *lease.TaskAttemptID ||
				existing.jobID != lease.JobID ||
				existing.analyzerName != AnalyzerName {
				return PublishSummary{}, fmt.Errorf(
					"%w: stable analyzer run identity collided",
					ErrInvalidPublication,
				)
			}
			if existing.status == "succeeded" {
				if err := r.verifyCompletedRun(
					ctx,
					transaction,
					lease,
					runID,
					publication,
					run,
					existing,
				); err != nil {
					return PublishSummary{}, err
				}
				summary.Succeeded++
				continue
			}
			if err := updateAnalyzerRun(
				ctx,
				transaction,
				runID,
				publication,
				run,
				parameters,
			); err != nil {
				return PublishSummary{}, err
			}
		} else if err := insertAnalyzerRun(
			ctx,
			transaction,
			runID,
			lease,
			publication,
			run,
			parameters,
		); err != nil {
			return PublishSummary{}, err
		}

		if run.Status != "succeeded" {
			summary.Failed++
			if retryableRunFailure(run.ErrorCode) {
				summary.TransientFailures++
			}
			continue
		}
		records, err := loadRunArtifacts(
			ctx,
			transaction,
			lease.TaskID,
			runID,
		)
		if err != nil {
			return PublishSummary{}, err
		}
		if len(records) != 0 {
			return PublishSummary{}, fmt.Errorf(
				"%w: incomplete run already has a raw artifact",
				ErrInvalidPublication,
			)
		}
		artifactID := stableUUID(
			"binaryscan.trivy.artifact.v1",
			lease.TaskID,
			strconv.FormatUint(*lease.TaskAttemptID, 10),
			runID,
		)
		artifact, err := r.publishRawArtifact(
			ctx,
			lease,
			runID,
			*run.Raw,
		)
		if err != nil {
			return PublishSummary{}, err
		}
		if artifact.created {
			created = append(created, artifact)
		}
		if err := insertArtifact(
			ctx,
			transaction,
			artifactID,
			lease,
			runID,
			artifact,
		); err != nil {
			return PublishSummary{}, err
		}
		if err := replaceFindings(
			ctx,
			transaction,
			lease.TaskID,
			runID,
			publication.Snapshot.Bundle.ID,
			run,
		); err != nil {
			return PublishSummary{}, err
		}
		summary.Succeeded++
	}
	if err := updateTaskRisk(ctx, transaction, lease.TaskID); err != nil {
		return PublishSummary{}, err
	}
	if err := revalidatePublishingLease(ctx, transaction, lease); err != nil {
		return PublishSummary{}, err
	}
	commitAttempted = true
	if err := transaction.Commit(); err != nil {
		return PublishSummary{}, fmt.Errorf("commit Trivy result publication: %w", err)
	}
	finished = true
	return summary, nil
}

func registerDatabaseBundle(
	ctx context.Context,
	transaction *sql.Tx,
	snapshot trivydb.Snapshot,
) error {
	var (
		version       string
		generatedAt   time.Time
		contentSHA256 string
		trivyVersion  string
		javaVersion   string
		manifest      []byte
	)
	err := transaction.QueryRowContext(ctx, `
SELECT version, generated_at, content_sha256, trivy_db_version,
       trivy_java_db_version, manifest_json
FROM trivy_database_bundles
WHERE id = ?
FOR UPDATE`, snapshot.Bundle.ID).Scan(
		&version,
		&generatedAt,
		&contentSHA256,
		&trivyVersion,
		&javaVersion,
		&manifest,
	)
	if errors.Is(err, sql.ErrNoRows) {
		if snapshot.Java == nil {
			return fmt.Errorf("%w: Java database is missing", ErrInvalidPublication)
		}
		_, err = transaction.ExecContext(ctx, `
INSERT INTO trivy_database_bundles (
    id, version, generated_at, content_sha256, trivy_db_version,
    trivy_java_db_version, manifest_json
) VALUES (?, ?, ?, ?, ?, ?, ?)`,
			snapshot.Bundle.ID,
			snapshot.Bundle.Version,
			snapshot.Bundle.GeneratedAt,
			snapshot.Bundle.ContentSHA256,
			snapshot.Trivy.Version,
			snapshot.Java.Version,
			snapshot.Bundle.ManifestJSON,
		)
		if err != nil {
			return fmt.Errorf("register Trivy database bundle: %w", err)
		}
		return nil
	}
	if err != nil {
		return fmt.Errorf("load Trivy database bundle: %w", err)
	}
	if snapshot.Java == nil ||
		version != snapshot.Bundle.Version ||
		!generatedAt.Equal(snapshot.Bundle.GeneratedAt) ||
		contentSHA256 != snapshot.Bundle.ContentSHA256 ||
		trivyVersion != snapshot.Trivy.Version ||
		javaVersion != snapshot.Java.Version ||
		!bytes.Equal(manifest, snapshot.Bundle.ManifestJSON) {
		return fmt.Errorf(
			"%w: database bundle identity conflicts with registered metadata",
			ErrInvalidPublication,
		)
	}
	return nil
}

func lockPublishingLease(
	ctx context.Context,
	transaction *sql.Tx,
	lease queue.Lease,
) error {
	if lease.Kind == queue.KindImage {
		return lockManualImagePublishingLease(ctx, transaction, lease)
	}
	if lease.Kind != queue.KindTrivy {
		return queue.ErrLeaseLost
	}
	var (
		attemptID    uint64
		attemptFence uint64
		taskStatus   string
	)
	err := transaction.QueryRowContext(ctx, `
SELECT job.task_attempt_id, attempt.fencing_token, task.status
FROM jobs job
JOIN task_attempts attempt
  ON attempt.task_id = job.task_id
 AND attempt.id = job.task_attempt_id
JOIN tasks task ON task.id = job.task_id
WHERE job.id = ?
  AND job.task_id = ?
  AND job.kind = 'trivy'
  AND job.status = 'running'
  AND job.lease_owner = ?
  AND job.fencing_token = ?
  AND job.lease_until > UTC_TIMESTAMP(6)
  AND job.cancel_requested_at IS NULL
  AND attempt.status = 'running'
  AND attempt.fencing_token = ?
  AND task.status = 'REPORTING'
  AND task.sample_deleted_at IS NULL
  AND task.deleted_at IS NULL
FOR UPDATE`,
		lease.JobID,
		lease.TaskID,
		lease.Owner,
		lease.FencingToken,
		lease.FencingToken,
	).Scan(&attemptID, &attemptFence, &taskStatus)
	if errors.Is(err, sql.ErrNoRows) {
		return queue.ErrLeaseLost
	}
	if err != nil {
		return fmt.Errorf("lock Trivy publishing lease: %w", err)
	}
	if lease.TaskAttemptID == nil ||
		attemptID != *lease.TaskAttemptID ||
		attemptFence != lease.FencingToken ||
		taskStatus != "REPORTING" {
		return queue.ErrLeaseLost
	}
	return nil
}

func lockManualImagePublishingLease(
	ctx context.Context,
	transaction *sql.Tx,
	lease queue.Lease,
) error {
	if lease.TaskAttemptID == nil {
		return queue.ErrLeaseLost
	}
	var attemptID uint64
	err := transaction.QueryRowContext(ctx, `
SELECT job.task_attempt_id
FROM jobs job
JOIN task_attempts attempt
  ON attempt.task_id = job.task_id
 AND attempt.id = job.task_attempt_id
JOIN tasks task ON task.id = job.task_id
WHERE job.id = ?
  AND job.task_id = ?
  AND job.task_attempt_id = ?
  AND job.kind = 'image'
  AND job.status = 'running'
  AND job.lease_owner = ?
  AND job.fencing_token = ?
  AND job.lease_until > UTC_TIMESTAMP(6)
  AND job.cancel_requested_at IS NULL
  AND (
      (task.status IN ('SUCCEEDED', 'PARTIAL_SUCCEEDED')
       AND attempt.status = 'succeeded')
      OR (task.status = 'FAILED' AND attempt.status = 'failed')
      OR (task.status = 'CANCELLED' AND attempt.status = 'cancelled')
  )
  AND task.sample_deleted_at IS NULL
  AND task.sample_expires_at > UTC_TIMESTAMP(6)
  AND task.deleted_at IS NULL
FOR UPDATE`,
		lease.JobID,
		lease.TaskID,
		*lease.TaskAttemptID,
		lease.Owner,
		lease.FencingToken,
	).Scan(&attemptID)
	if errors.Is(err, sql.ErrNoRows) {
		return queue.ErrLeaseLost
	}
	if err != nil {
		return fmt.Errorf("lock manual image publishing lease: %w", err)
	}
	if attemptID != *lease.TaskAttemptID {
		return queue.ErrLeaseLost
	}
	return nil
}

func revalidatePublishingLease(
	ctx context.Context,
	transaction *sql.Tx,
	lease queue.Lease,
) error {
	if lease.Kind == queue.KindImage {
		return revalidateManualImagePublishingLease(
			ctx,
			transaction,
			lease,
		)
	}
	if lease.Kind != queue.KindTrivy || lease.TaskAttemptID == nil {
		return queue.ErrLeaseLost
	}
	var valid int
	err := transaction.QueryRowContext(ctx, `
SELECT 1
FROM jobs job
JOIN task_attempts attempt
  ON attempt.task_id = job.task_id
 AND attempt.id = job.task_attempt_id
JOIN tasks task ON task.id = job.task_id
WHERE job.id = ?
  AND job.task_id = ?
  AND job.task_attempt_id = ?
  AND job.kind = 'trivy'
  AND job.status = 'running'
  AND job.lease_owner = ?
  AND job.fencing_token = ?
  AND job.lease_until > UTC_TIMESTAMP(6)
  AND job.cancel_requested_at IS NULL
  AND attempt.status = 'running'
  AND attempt.fencing_token = ?
  AND task.status = 'REPORTING'
  AND task.sample_deleted_at IS NULL
  AND task.deleted_at IS NULL`,
		lease.JobID,
		lease.TaskID,
		*lease.TaskAttemptID,
		lease.Owner,
		lease.FencingToken,
		lease.FencingToken,
	).Scan(&valid)
	if errors.Is(err, sql.ErrNoRows) {
		return queue.ErrLeaseLost
	}
	if err != nil {
		return fmt.Errorf("revalidate Trivy publishing lease: %w", err)
	}
	return nil
}

func revalidateManualImagePublishingLease(
	ctx context.Context,
	transaction *sql.Tx,
	lease queue.Lease,
) error {
	if lease.TaskAttemptID == nil {
		return queue.ErrLeaseLost
	}
	var valid int
	err := transaction.QueryRowContext(ctx, `
SELECT 1
FROM jobs job
JOIN task_attempts attempt
  ON attempt.task_id = job.task_id
 AND attempt.id = job.task_attempt_id
JOIN tasks task ON task.id = job.task_id
WHERE job.id = ?
  AND job.task_id = ?
  AND job.task_attempt_id = ?
  AND job.kind = 'image'
  AND job.status = 'running'
  AND job.lease_owner = ?
  AND job.fencing_token = ?
  AND job.lease_until > UTC_TIMESTAMP(6)
  AND job.cancel_requested_at IS NULL
  AND (
      (task.status IN ('SUCCEEDED', 'PARTIAL_SUCCEEDED')
       AND attempt.status = 'succeeded')
      OR (task.status = 'FAILED' AND attempt.status = 'failed')
      OR (task.status = 'CANCELLED' AND attempt.status = 'cancelled')
  )
  AND task.sample_deleted_at IS NULL
  AND task.sample_expires_at > UTC_TIMESTAMP(6)
  AND task.deleted_at IS NULL`,
		lease.JobID,
		lease.TaskID,
		*lease.TaskAttemptID,
		lease.Owner,
		lease.FencingToken,
	).Scan(&valid)
	if errors.Is(err, sql.ErrNoRows) {
		return queue.ErrLeaseLost
	}
	if err != nil {
		return fmt.Errorf(
			"revalidate manual image publishing lease: %w",
			err,
		)
	}
	return nil
}

func findAnalyzerRun(
	ctx context.Context,
	transaction *sql.Tx,
	runID string,
) (existingRun, bool, error) {
	var value existingRun
	err := transaction.QueryRowContext(ctx, `
SELECT task_id, task_attempt_id, job_id, analyzer_name, analyzer_version,
       parameters_json, status
FROM analyzer_runs
WHERE id = ?
FOR UPDATE`, runID).Scan(
		&value.taskID,
		&value.taskAttemptID,
		&value.jobID,
		&value.analyzerName,
		&value.analyzerVersion,
		&value.parameters,
		&value.status,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return existingRun{}, false, nil
	}
	if err != nil {
		return existingRun{}, false, fmt.Errorf("find Trivy analyzer run: %w", err)
	}
	return value, true, nil
}

func insertAnalyzerRun(
	ctx context.Context,
	transaction *sql.Tx,
	runID string,
	lease queue.Lease,
	publication Publication,
	run RunResult,
	parameters json.RawMessage,
) error {
	_, err := transaction.ExecContext(ctx, `
INSERT INTO analyzer_runs (
    id, task_id, task_attempt_id, job_id, file_node_id,
    analyzer_name, analyzer_version, parameters_json, status, exit_code,
    error_code, error_message, started_at, completed_at
) VALUES (?, ?, ?, ?, NULL, 'trivy', ?, ?, ?, ?, NULLIF(?, ''),
          NULLIF(?, ''), ?, ?)`,
		runID,
		lease.TaskID,
		*lease.TaskAttemptID,
		lease.JobID,
		publication.AnalyzerVersion,
		[]byte(parameters),
		run.Status,
		exitCode(run),
		run.ErrorCode,
		run.ErrorMessage,
		publication.StartedAt,
		publication.CompletedAt,
	)
	if err != nil {
		return fmt.Errorf("insert Trivy analyzer run: %w", err)
	}
	return nil
}

func updateAnalyzerRun(
	ctx context.Context,
	transaction *sql.Tx,
	runID string,
	publication Publication,
	run RunResult,
	parameters json.RawMessage,
) error {
	result, err := transaction.ExecContext(ctx, `
UPDATE analyzer_runs
SET analyzer_version = ?,
    parameters_json = ?,
    status = ?,
    exit_code = ?,
    error_code = NULLIF(?, ''),
    error_message = NULLIF(?, ''),
    started_at = ?,
    completed_at = ?
WHERE id = ? AND analyzer_name = 'trivy' AND status <> 'succeeded'`,
		publication.AnalyzerVersion,
		[]byte(parameters),
		run.Status,
		exitCode(run),
		run.ErrorCode,
		run.ErrorMessage,
		publication.StartedAt,
		publication.CompletedAt,
		runID,
	)
	if err != nil {
		return fmt.Errorf("update Trivy analyzer run: %w", err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("inspect Trivy analyzer run update: %w", err)
	}
	if affected > 1 {
		return queue.ErrInconsistentState
	}
	return nil
}

func exitCode(run RunResult) any {
	if run.Status == "succeeded" {
		return 0
	}
	return nil
}

func retryableRunFailure(code string) bool {
	switch code {
	case "trivy_timeout", "trivy_execution_failed", "trivy_internal_error":
		return true
	default:
		return false
	}
}

func loadRunArtifacts(
	ctx context.Context,
	transaction *sql.Tx,
	taskID string,
	runID string,
) ([]artifactRecord, error) {
	rows, err := transaction.QueryContext(ctx, `
SELECT id, storage_key, sha256, size_bytes, state, deleted_at
FROM artifacts
WHERE task_id = ?
  AND analyzer_run_id = ?
  AND kind = 'trivy-raw-json'
ORDER BY id
LIMIT 2
FOR UPDATE`, taskID, runID)
	if err != nil {
		return nil, fmt.Errorf("load Trivy raw artifacts: %w", err)
	}
	defer rows.Close()
	var records []artifactRecord
	for rows.Next() {
		var value artifactRecord
		if err := rows.Scan(
			&value.id,
			&value.storageKey,
			&value.sha256,
			&value.sizeBytes,
			&value.state,
			&value.deletedAt,
		); err != nil {
			return nil, fmt.Errorf("scan Trivy raw artifact: %w", err)
		}
		records = append(records, value)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate Trivy raw artifacts: %w", err)
	}
	if err := rows.Close(); err != nil {
		return nil, fmt.Errorf("close Trivy raw artifacts: %w", err)
	}
	if len(records) > 1 {
		return nil, queue.ErrInconsistentState
	}
	return records, nil
}

func (r *MySQLRepository) verifyCompletedRun(
	ctx context.Context,
	transaction *sql.Tx,
	lease queue.Lease,
	runID string,
	publication Publication,
	run RunResult,
	existing existingRun,
) error {
	records, err := loadRunArtifacts(
		ctx,
		transaction,
		lease.TaskID,
		runID,
	)
	if err != nil {
		return err
	}
	if len(records) != 1 {
		return fmt.Errorf(
			"%w: completed Trivy run has no unique raw artifact",
			ErrInvalidPublication,
		)
	}
	var persisted runParameters
	expectedSourceFormat := publication.SourceFormat
	expectedSourceSHA256 := publication.SourceSHA256
	expectedSchemaVersion := 1
	expectedSourceSize := int64(0)
	expectedLogicalPath := ""
	if run.SourceFormat != "" {
		expectedSourceFormat = run.SourceFormat
		expectedSourceSHA256 = run.SourceSHA256
		expectedSchemaVersion = 2
		expectedSourceSize = run.SourceSizeBytes
		expectedLogicalPath = run.ImageLogicalPath
	}
	if len(existing.parameters) == 0 ||
		json.Unmarshal(existing.parameters, &persisted) != nil ||
		persisted.SchemaVersion != expectedSchemaVersion ||
		persisted.Scanner != "vuln" ||
		!persisted.Offline ||
		persisted.CacheBackend != "memory" ||
		persisted.SourceFormat != expectedSourceFormat ||
		persisted.SourceSHA256 != expectedSourceSHA256 ||
		persisted.SourceSizeBytes != expectedSourceSize ||
		persisted.ImageLogicalPath != expectedLogicalPath ||
		persisted.TargetKey != run.TargetKey ||
		persisted.ManifestDigest != run.ManifestDigest ||
		persisted.Platform != run.Platform ||
		!slices.Equal(persisted.References, run.References) ||
		persisted.Analyzer.Name != AnalyzerName ||
		persisted.Analyzer.Version != existing.analyzerVersion ||
		!canonicalUUIDPattern.MatchString(persisted.DatabaseBundle.ID) ||
		persisted.DatabaseBundle.Version == "" ||
		persisted.DatabaseBundle.GeneratedAt.IsZero() ||
		!lowercaseSHA256Pattern.MatchString(
			persisted.DatabaseBundle.ContentSHA256,
		) ||
		persisted.TrivyDB.DatabaseType != trivydb.DatabaseTrivy ||
		!canonicalUUIDPattern.MatchString(persisted.TrivyDB.ID) ||
		persisted.TrivyDB.Version == "" ||
		persisted.TrivyDB.DatabaseSchemaVersion <= 0 ||
		(persisted.JavaDB != nil &&
			(persisted.JavaDB.DatabaseType != trivydb.DatabaseTrivyJava ||
				!canonicalUUIDPattern.MatchString(persisted.JavaDB.ID) ||
				persisted.JavaDB.Version == "" ||
				persisted.JavaDB.DatabaseSchemaVersion <= 0)) ||
		persisted.ResultFindingCount < 0 ||
		persisted.ResultFindingCount > maxSupportedFindings ||
		persisted.RawArtifact == nil ||
		!lowercaseSHA256Pattern.MatchString(persisted.RawArtifact.SHA256) ||
		persisted.RawArtifact.SizeBytes <= 0 ||
		persisted.RawArtifact.SizeBytes > r.maxArtifactBytes ||
		persisted.RawArtifact.SchemaVersion != 2 ||
		persisted.RawArtifact.FindingCount !=
			persisted.ResultFindingCount {
		return fmt.Errorf(
			"%w: completed Trivy run provenance is invalid",
			ErrInvalidPublication,
		)
	}
	var (
		findingCount   uint64
		matchedDBCount uint64
	)
	if err := transaction.QueryRowContext(ctx, `
SELECT COUNT(*), COALESCE(SUM(
	           CASE WHEN trivy_database_bundle_id = ? THEN 1 ELSE 0 END
       ), 0)
FROM vulnerability_findings
WHERE task_id = ? AND analyzer_run_id = ?`,
		persisted.DatabaseBundle.ID,
		lease.TaskID,
		runID,
	).Scan(&findingCount, &matchedDBCount); err != nil {
		return fmt.Errorf("verify completed Trivy findings: %w", err)
	}
	if findingCount != uint64(persisted.ResultFindingCount) ||
		matchedDBCount != findingCount {
		return fmt.Errorf(
			"%w: completed Trivy finding set is incomplete",
			ErrInvalidPublication,
		)
	}
	expectedID := stableUUID(
		"binaryscan.trivy.artifact.v1",
		lease.TaskID,
		strconv.FormatUint(*lease.TaskAttemptID, 10),
		runID,
	)
	expectedKey := rawArtifactStorageKey(
		lease.TaskID,
		*lease.TaskAttemptID,
		runID,
	)
	record := records[0]
	if record.id != expectedID || record.storageKey != expectedKey ||
		record.state != "published" || record.deletedAt.Valid ||
		!lowercaseSHA256Pattern.MatchString(record.sha256) ||
		record.sha256 != persisted.RawArtifact.SHA256 ||
		record.sizeBytes <= 0 ||
		record.sizeBytes != persisted.RawArtifact.SizeBytes ||
		record.sizeBytes > r.maxArtifactBytes {
		return fmt.Errorf(
			"%w: completed Trivy raw artifact metadata is invalid",
			ErrInvalidPublication,
		)
	}
	return r.verifyRepositoryArtifact(ctx, record)
}

func insertArtifact(
	ctx context.Context,
	transaction *sql.Tx,
	artifactID string,
	lease queue.Lease,
	runID string,
	artifact publishedArtifact,
) error {
	_, err := transaction.ExecContext(ctx, `
INSERT INTO artifacts (
    id, task_id, task_attempt_id, analyzer_run_id, kind, media_type,
    storage_key, sha256, size_bytes, state, published_at
) VALUES (?, ?, ?, ?, 'trivy-raw-json', 'application/json', ?, ?, ?,
          'published', UTC_TIMESTAMP(6))`,
		artifactID,
		lease.TaskID,
		*lease.TaskAttemptID,
		runID,
		artifact.storageKey,
		artifact.sha256,
		artifact.sizeBytes,
	)
	if err != nil {
		return fmt.Errorf("insert Trivy raw artifact: %w", err)
	}
	return nil
}

func replaceFindings(
	ctx context.Context,
	transaction *sql.Tx,
	taskID string,
	runID string,
	databaseBundleID string,
	run RunResult,
) error {
	if _, err := transaction.ExecContext(ctx, `
DELETE FROM vulnerability_findings
WHERE task_id = ? AND analyzer_run_id = ?`, taskID, runID); err != nil {
		return fmt.Errorf("replace Trivy findings: %w", err)
	}
	if len(run.Findings) == 0 {
		return nil
	}
	statement, err := transaction.PrepareContext(ctx, `
INSERT INTO vulnerability_findings (
	    task_id, analyzer_run_id, trivy_database_bundle_id,
    image_logical_path, image_platform, vulnerability_id, severity,
    package_name, installed_version, fixed_version, title,
    description_summary, evidence_json, references_json
) VALUES (?, ?, ?, ?, NULLIF(?, ''), ?, ?, ?, NULLIF(?, ''),
          NULLIF(?, ''), NULLIF(?, ''), NULLIF(?, ''), ?, ?)`)
	if err != nil {
		return fmt.Errorf("prepare Trivy finding publication: %w", err)
	}
	defer statement.Close()
	for _, finding := range run.Findings {
		var dataSource *trivyadapter.DataSource
		if finding.DataSource != (trivyadapter.DataSource{}) {
			copy := finding.DataSource
			dataSource = &copy
		}
		evidence, err := json.Marshal(findingEvidence{
			PackageName:      finding.PackageName,
			InstalledVersion: finding.InstalledVersion,
			FixedVersion:     finding.FixedVersion,
			PackagePath:      finding.PackagePath,
			Target:           finding.Target,
			Class:            finding.Class,
			Type:             finding.Type,
			ImageLogicalPath: run.ImageLogicalPath,
			ImagePlatform:    run.Platform,
			ImageReferences: append(
				[]string(nil),
				run.References[:min(len(run.References), 32)]...,
			),
			ManifestDigest: run.ManifestDigest,
			DataSource:     dataSource,
		})
		if err != nil {
			return fmt.Errorf("encode Trivy finding evidence: %w", err)
		}
		references, err := json.Marshal(finding.References)
		if err != nil {
			return fmt.Errorf("encode Trivy finding references: %w", err)
		}
		if _, err := statement.ExecContext(
			ctx,
			taskID,
			runID,
			databaseBundleID,
			run.ImageLogicalPath,
			run.Platform,
			finding.VulnerabilityID,
			finding.Severity,
			finding.PackageName,
			finding.InstalledVersion,
			finding.FixedVersion,
			finding.Title,
			finding.DescriptionSummary,
			evidence,
			references,
		); err != nil {
			return fmt.Errorf("insert Trivy finding: %w", err)
		}
	}
	return nil
}

func updateTaskRisk(
	ctx context.Context,
	transaction *sql.Tx,
	taskID string,
) error {
	_, err := transaction.ExecContext(ctx, `
UPDATE tasks
SET risk_level = (
    SELECT CASE COALESCE(MAX(
        CASE severity
            WHEN 'CRITICAL' THEN 5
            WHEN 'HIGH' THEN 4
            WHEN 'MEDIUM' THEN 3
            WHEN 'LOW' THEN 2
            WHEN 'UNKNOWN' THEN 1
            ELSE 0
        END
    ), 0)
        WHEN 5 THEN 'CRITICAL'
        WHEN 4 THEN 'HIGH'
        WHEN 3 THEN 'MEDIUM'
        WHEN 2 THEN 'LOW'
        WHEN 1 THEN 'UNKNOWN'
        ELSE 'NONE'
    END
    FROM vulnerability_findings
    WHERE task_id = ?
),
updated_at = UTC_TIMESTAMP(6)
WHERE id = ?
  AND status IN (
      'REPORTING', 'SUCCEEDED', 'PARTIAL_SUCCEEDED', 'FAILED', 'CANCELLED'
  )
  AND deleted_at IS NULL`, taskID, taskID)
	if err != nil {
		return fmt.Errorf("update task vulnerability risk: %w", err)
	}
	return nil
}

func validatePublication(
	lease queue.Lease,
	value Publication,
	maxArtifactBytes int64,
) error {
	if (lease.Kind != queue.KindTrivy && lease.Kind != queue.KindImage) ||
		lease.TaskAttemptID == nil ||
		lease.FencingToken == 0 || lease.Owner == "" ||
		!canonicalUUIDPattern.MatchString(lease.JobID) ||
		!canonicalUUIDPattern.MatchString(lease.TaskID) ||
		!analyzerVersionPattern.MatchString(value.AnalyzerVersion) ||
		(value.SourceFormat != containerarchive.FormatDocker &&
			value.SourceFormat != containerarchive.FormatOCI &&
			value.SourceFormat != trivyhandoff.FormatVMImage) ||
		!lowercaseSHA256Pattern.MatchString(value.SourceSHA256) ||
		value.SourceStorageKey != "blobs/sha256/"+
			value.SourceSHA256[:2]+"/"+value.SourceSHA256 ||
		value.StartedAt.IsZero() || value.CompletedAt.IsZero() ||
		value.CompletedAt.Before(value.StartedAt) ||
		len(value.Runs) == 0 || len(value.Runs) > 100_000 ||
		!validSnapshot(value.Snapshot) {
		return ErrInvalidPublication
	}
	targetKeys := make(map[string]struct{}, len(value.Runs))
	totalFindings := 0
	for _, run := range value.Runs {
		if _, duplicate := targetKeys[run.TargetKey]; duplicate {
			return ErrInvalidPublication
		}
		targetKeys[run.TargetKey] = struct{}{}
		if run.SourceFormat != trivyhandoff.FormatVMImage &&
			(run.Platform == "" || len(run.Platform) > 128 ||
				len(run.References) == 0 || len(run.References) > 10_000) {
			return ErrInvalidPublication
		}
		if run.SourceFormat == "" {
			if run.ImageLogicalPath != "/" {
				return ErrInvalidPublication
			}
			switch value.SourceFormat {
			case containerarchive.FormatDocker:
				if run.TargetKey != "docker:"+value.SourceSHA256 ||
					run.ManifestDigest != "" {
					return ErrInvalidPublication
				}
			case containerarchive.FormatOCI:
				if !ociDigestPattern.MatchString(run.TargetKey) ||
					run.ManifestDigest != run.TargetKey {
					return ErrInvalidPublication
				}
			}
		} else {
			if !validRunSource(run) ||
				run.TargetKey != stableTargetKey(
					HandoffSource{
						Format:           run.SourceFormat,
						SourceStorageKey: run.SourceStorageKey,
						SourceSHA256:     run.SourceSHA256,
						SourceSizeBytes:  run.SourceSizeBytes,
						ImageLogicalPath: run.ImageLogicalPath,
					},
					containerarchive.Target{
						ManifestDigest: run.ManifestDigest,
					},
				) {
				return ErrInvalidPublication
			}
			switch run.SourceFormat {
			case containerarchive.FormatDocker:
				if run.ManifestDigest != "" {
					return ErrInvalidPublication
				}
			case containerarchive.FormatOCI:
				if !ociDigestPattern.MatchString(run.ManifestDigest) {
					return ErrInvalidPublication
				}
			case trivyhandoff.FormatVMImage:
				if run.ManifestDigest != "" {
					return ErrInvalidPublication
				}
			default:
				return ErrInvalidPublication
			}
		}
		for _, reference := range run.References {
			if reference == "" || len(reference) > 512 ||
				!validMessage(reference) {
				return ErrInvalidPublication
			}
		}
		switch run.Status {
		case "succeeded":
			if run.Raw == nil || run.ErrorCode != "" ||
				run.ErrorMessage != "" ||
				!validRawMetadata(*run.Raw, maxArtifactBytes) ||
				run.Raw.FindingCount != len(run.Findings) {
				return ErrInvalidPublication
			}
		case "failed", "timed_out":
			if run.Raw != nil || len(run.Findings) != 0 ||
				!validErrorCode(run.ErrorCode) ||
				!validMessage(run.ErrorMessage) {
				return ErrInvalidPublication
			}
		default:
			return ErrInvalidPublication
		}
		totalFindings += len(run.Findings)
		if totalFindings > maxSupportedFindings {
			return ErrInvalidPublication
		}
		for _, finding := range run.Findings {
			if !validFinding(finding) {
				return ErrInvalidPublication
			}
		}
	}
	return nil
}

func validRunSource(run RunResult) bool {
	if run.SourceSizeBytes <= 0 {
		return false
	}
	return trivyhandoff.Validate(trivyhandoff.Payload{
		SchemaVersion: trivyhandoff.SchemaVersion,
		Sources: []trivyhandoff.Source{{
			Format:           run.SourceFormat,
			SourceStorageKey: run.SourceStorageKey,
			SourceSHA256:     run.SourceSHA256,
			SourceSizeBytes:  run.SourceSizeBytes,
			ImageLogicalPath: run.ImageLogicalPath,
		}},
		MaxExpandedBytes: run.SourceSizeBytes,
		MaxArchiveRatio:  1,
	}, maxSupportedSourceBytes, 1) == nil
}

func validRawMetadata(
	value trivyadapter.RawReportMetadata,
	maximum int64,
) bool {
	return value.Path != "" &&
		lowercaseSHA256Pattern.MatchString(value.SHA256) &&
		value.SizeBytes > 0 && value.SizeBytes <= maximum &&
		value.SchemaVersion == 2 &&
		value.ArtifactName != "" && value.ArtifactType != "" &&
		value.ResultCount >= 0 && value.FindingCount >= 0
}

func validFinding(value trivyadapter.Finding) bool {
	validSeverity := false
	switch value.Severity {
	case "UNKNOWN", "LOW", "MEDIUM", "HIGH", "CRITICAL":
		validSeverity = true
	}
	return validSeverity &&
		validFindingText(value.VulnerabilityID, 128, true) &&
		validFindingText(value.PackageName, 512, true) &&
		validFindingText(value.PackagePath, 2048, false) &&
		validFindingText(value.InstalledVersion, 512, true) &&
		validFindingText(value.FixedVersion, 512, false) &&
		validFindingText(value.Title, 1024, false) &&
		validFindingText(value.DescriptionSummary, 2048, false) &&
		validFindingText(value.Target, 4096, true) &&
		validFindingText(value.Class, 128, true) &&
		validFindingText(value.Type, 128, true) &&
		validFindingText(value.DataSource.ID, 128, false) &&
		validFindingText(value.DataSource.Name, 512, false) &&
		(value.DataSource.URL == "" || validFindingURL(value.DataSource.URL)) &&
		validFindingReferences(value.References)
}

func validFindingText(value string, maximum int, required bool) bool {
	if (required && value == "") || len(value) > maximum || !utf8.ValidString(value) {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return false
		}
	}
	return true
}

func validFindingReferences(values []string) bool {
	if len(values) > 128 {
		return false
	}
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if !validFindingURL(value) {
			return false
		}
		if _, duplicate := seen[value]; duplicate {
			return false
		}
		seen[value] = struct{}{}
	}
	return true
}

func validFindingURL(value string) bool {
	if !validFindingText(value, 2048, true) {
		return false
	}
	parsed, err := url.Parse(value)
	return err == nil && parsed.User == nil && parsed.Host != "" &&
		(parsed.Scheme == "http" || parsed.Scheme == "https")
}

func validSnapshot(value trivydb.Snapshot) bool {
	if !canonicalUUIDPattern.MatchString(value.Bundle.ID) ||
		value.Bundle.Version == "" || len(value.Bundle.Version) > 128 ||
		value.Bundle.GeneratedAt.IsZero() ||
		!lowercaseSHA256Pattern.MatchString(value.Bundle.ContentSHA256) ||
		len(value.Bundle.ManifestJSON) == 0 ||
		len(value.Bundle.ManifestJSON) > 1<<20 ||
		!json.Valid(value.Bundle.ManifestJSON) ||
		!validVersion(value.Trivy, trivydb.DatabaseTrivy) {
		return false
	}
	return value.Java != nil &&
		validVersion(*value.Java, trivydb.DatabaseTrivyJava)
}

func validVersion(value trivydb.Version, databaseType string) bool {
	return canonicalUUIDPattern.MatchString(value.ID) &&
		value.DatabaseType == databaseType &&
		value.Version != "" && len(value.Version) <= 128 &&
		value.DatabaseSchemaVersion > 0 && len(value.Files) > 0
}

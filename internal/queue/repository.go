package queue

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"binaryscan/internal/report"
	"binaryscan/internal/taskevent"
	"binaryscan/internal/taskprogress"
	"binaryscan/internal/trivyhandoff"
)

// The equality prefix and ordering must match idx_jobs_claim. FORCE INDEX and
// STRAIGHT_JOIN keep jobs as the ordered driving table so InnoDB can stop after
// the first candidate instead of locking later queued rows during a filesort.
const claimCandidateSQL = `
SELECT j.id, j.task_id, j.task_attempt_id, j.kind, j.payload,
       j.attempt, j.max_attempts, j.fencing_token,
       attempt.fencing_token, attempt.status
FROM jobs j FORCE INDEX (idx_jobs_claim)
STRAIGHT_JOIN tasks task ON task.id = j.task_id
LEFT JOIN task_attempts attempt
  ON attempt.task_id = j.task_id AND attempt.id = j.task_attempt_id
WHERE j.kind = ?
  AND j.status = 'queued'
  AND j.available_at <= UTC_TIMESTAMP(6)
  AND j.attempt < j.max_attempts
  AND j.cancel_requested_at IS NULL
  AND (
      (
          j.kind IN ('decompile', 'image')
          AND task.status IN (
              'SUCCEEDED', 'PARTIAL_SUCCEEDED', 'FAILED', 'CANCELLED'
          )
          AND task.sample_deleted_at IS NULL
          AND task.sample_expires_at > UTC_TIMESTAMP(6)
          AND task.deleted_at IS NULL
      )
      OR (
          j.kind = 'c_analysis'
          AND task.status IN (
              'SUCCEEDED', 'PARTIAL_SUCCEEDED', 'FAILED', 'CANCELLED'
          )
          AND task.deleted_at IS NULL
          AND EXISTS (
              SELECT 1
              FROM c_analysis_runs analysis
              JOIN decompile_source_projects project
                ON project.task_id = analysis.task_id
               AND project.id = analysis.source_project_id
              WHERE analysis.task_id = j.task_id
                AND analysis.job_id = j.id
                AND analysis.status = 'queued'
                AND project.deleted_at IS NULL
                AND project.storage_deleted_at IS NULL
                AND project.layout_version = 'project-v1'
                AND project.source_kind = 'ghidra-pseudoc'
                AND project.language = 'c'
                AND project.status IN ('complete', 'partial')
                AND project.canonical_sha256 = analysis.source_sha256
                AND project.canonical_size_bytes = analysis.source_size_bytes
          )
      )
      OR (
          j.kind = 'java_analysis'
          AND task.status IN (
              'SUCCEEDED', 'PARTIAL_SUCCEEDED', 'FAILED', 'CANCELLED'
          )
          AND task.deleted_at IS NULL
          AND EXISTS (
              SELECT 1
              FROM java_analysis_runs analysis
              JOIN decompile_source_projects project
                ON project.task_id = analysis.task_id
               AND project.id = analysis.source_project_id
              WHERE analysis.task_id = j.task_id
                AND analysis.job_id = j.id
                AND analysis.status = 'queued'
                AND project.deleted_at IS NULL
                AND project.storage_deleted_at IS NULL
                AND project.layout_version = 'project-v1'
                AND project.source_kind = 'java'
                AND project.language IN ('java', 'mixed')
                AND project.status IN ('complete', 'partial')
                AND project.manifest_sha256 = analysis.source_manifest_sha256
                AND analysis.input_sha256 REGEXP '^[0-9a-f]{64}$'
                AND analysis.source_size_bytes > 0
                AND analysis.source_file_count > 0
          )
      )
      OR (
          j.kind = 'python_analysis'
          AND task.status IN (
              'SUCCEEDED', 'PARTIAL_SUCCEEDED', 'FAILED', 'CANCELLED'
          )
          AND task.deleted_at IS NULL
          AND EXISTS (
              SELECT 1
              FROM python_analysis_runs analysis
              JOIN decompile_source_projects project
                ON project.task_id = analysis.task_id
               AND project.id = analysis.source_project_id
              WHERE analysis.task_id = j.task_id
                AND analysis.job_id = j.id
                AND analysis.status = 'queued'
                AND project.deleted_at IS NULL
                AND project.storage_deleted_at IS NULL
                AND project.layout_version = 'project-v1'
                AND project.source_kind = 'python'
                AND project.status IN ('complete', 'partial')
                AND project.manifest_sha256 = analysis.source_manifest_sha256
                AND analysis.input_sha256 REGEXP '^[0-9a-f]{64}$'
                AND analysis.source_size_bytes > 0
                AND analysis.source_file_count > 0
          )
      )
      OR (
          j.kind NOT IN (
              'decompile', 'image', 'c_analysis', 'java_analysis',
              'python_analysis'
          )
          AND task.status NOT IN (
              'SUCCEEDED', 'PARTIAL_SUCCEEDED', 'FAILED',
              'CANCEL_REQUESTED', 'CANCELLED', 'DELETING', 'DELETED'
          )
      )
  )
  AND (j.kind <> 'scan' OR task.status = 'QUEUED')
  AND (
      j.kind <> 'trivy'
      OR (
          task.status = 'SCANNING'
          AND attempt.status = 'running'
          AND attempt.fencing_token = j.fencing_token
      )
  )
ORDER BY j.priority DESC, j.available_at ASC, j.id ASC
LIMIT 1
FOR UPDATE SKIP LOCKED`

const (
	resourcePoolGlobal = "global"
	resourcePoolTrivy  = "trivy"
	resourcePoolNative = "native"
)

var errResourceSlotUnavailable = errors.New("job resource slot unavailable")

type resourceRequirement struct {
	pool  string
	limit int
}

type MySQLRepository struct {
	db *sql.DB
}

func NewMySQLRepository(db *sql.DB) *MySQLRepository {
	return &MySQLRepository{db: db}
}

func (r *MySQLRepository) ConfigureResourceLimits(
	ctx context.Context,
	heavySlots int,
	trivySlots int,
	nativeSlots int,
) error {
	if heavySlots < 1 || heavySlots > 4 ||
		trivySlots < 1 || trivySlots > heavySlots ||
		nativeSlots < 1 || nativeSlots > heavySlots {
		return ErrInvalidInput
	}
	transaction, err := beginClaimTransaction(ctx, r.db)
	if err != nil {
		return fmt.Errorf("begin resource limit configuration: %w", err)
	}
	defer transaction.Rollback()
	if err := synchronizeResourceLimits(
		ctx,
		transaction,
		heavySlots,
		trivySlots,
		nativeSlots,
	); err != nil {
		return err
	}
	if err := transaction.Commit(); err != nil {
		return fmt.Errorf("commit resource limit configuration: %w", err)
	}
	return nil
}

type transactionBeginner interface {
	BeginTx(context.Context, *sql.TxOptions) (*sql.Tx, error)
}

func beginClaimTransaction(
	ctx context.Context,
	beginner transactionBeginner,
) (*sql.Tx, error) {
	// REPEATABLE READ next-key locks can let SKIP LOCKED select a later row
	// whose queued-index entry still cannot be updated. READ COMMITTED retains
	// the locking read and CAS update while avoiding those gap locks.
	return beginner.BeginTx(ctx, &sql.TxOptions{
		Isolation: sql.LevelReadCommitted,
	})
}

func (r *MySQLRepository) Claim(
	ctx context.Context,
	request claimRequest,
) (Lease, bool, error) {
	if request.PayloadWorkerKind != "" &&
		(request.Kind != KindDecompile ||
			(request.PayloadWorkerKind != KindNative &&
				request.PayloadWorkerKind != KindBytecode)) {
		return Lease{}, false, ErrInvalidInput
	}
	transaction, err := beginClaimTransaction(ctx, r.db)
	if err != nil {
		return Lease{}, false, fmt.Errorf("begin job claim: %w", err)
	}
	defer transaction.Rollback()

	var lease Lease
	var payload []byte
	var attemptID sql.NullInt64
	var attemptToken sql.NullInt64
	var attemptStatus sql.NullString
	candidateSQL := claimCandidateSQL
	candidateArgs := []any{request.Kind}
	if request.PayloadWorkerKind != "" {
		candidateSQL = strings.Replace(
			candidateSQL,
			"ORDER BY j.priority DESC",
			`  AND JSON_UNQUOTE(JSON_EXTRACT(
	      j.payload, '$.engine.worker_kind'
	  )) = ?
ORDER BY j.priority DESC`,
			1,
		)
		candidateArgs = append(candidateArgs, request.PayloadWorkerKind)
	}
	err = transaction.QueryRowContext(
		ctx, candidateSQL, candidateArgs...,
	).Scan(
		&lease.JobID, &lease.TaskID, &attemptID, &lease.Kind, &payload,
		&lease.Attempt, &lease.MaxAttempts, &lease.FencingToken,
		&attemptToken, &attemptStatus,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return Lease{}, false, nil
	}
	if err != nil {
		return Lease{}, false, fmt.Errorf("select queued job: %w", err)
	}

	oldAttempt := lease.Attempt
	oldToken := lease.FencingToken
	result, err := transaction.ExecContext(ctx, `
UPDATE jobs
SET status = 'leased',
    attempt = attempt + 1,
    fencing_token = fencing_token + 1,
    lease_owner = ?,
    lease_until = DATE_ADD(UTC_TIMESTAMP(6), INTERVAL ? MICROSECOND),
    heartbeat_at = UTC_TIMESTAMP(6),
    error_code = NULL,
    error_message = NULL
WHERE id = ?
  AND status = 'queued'
  AND attempt = ?
  AND fencing_token = ?
  AND available_at <= UTC_TIMESTAMP(6)
  AND attempt < max_attempts
  AND cancel_requested_at IS NULL`,
		request.Owner, request.LeaseDurationMicros,
		lease.JobID, oldAttempt, oldToken,
	)
	if err != nil {
		return Lease{}, false, fmt.Errorf("lease queued job: %w", err)
	}
	if err := requireOne(result, ErrInconsistentState, "inspect queued job lease"); err != nil {
		return Lease{}, false, err
	}

	lease.Attempt++
	lease.FencingToken++
	lease.Owner = request.Owner
	lease.Payload = json.RawMessage(payload)
	requirements, err := claimResourceRequirements(request, payload)
	if err != nil {
		return Lease{}, false, err
	}
	if attemptID.Valid {
		if attemptID.Int64 <= 0 {
			return Lease{}, false, ErrInconsistentState
		}
		id := uint64(attemptID.Int64)
		lease.TaskAttemptID = &id
	}
	if lease.Kind == KindScan || lease.Kind == KindTrivy {
		expectedAttemptStatus := "queued"
		if lease.Kind == KindTrivy {
			expectedAttemptStatus = "running"
		}
		if lease.TaskAttemptID == nil ||
			!attemptToken.Valid || attemptToken.Int64 < 0 ||
			uint64(attemptToken.Int64) != oldToken ||
			!attemptStatus.Valid || attemptStatus.String != expectedAttemptStatus {
			return Lease{}, false, ErrInconsistentState
		}
		attemptSQL := `
UPDATE task_attempts
SET fencing_token = ?,
    error_code = NULL,
    error_message = NULL
WHERE id = ? AND task_id = ? AND fencing_token = ? AND status = 'queued'`
		if lease.Kind == KindTrivy {
			attemptSQL = `
UPDATE task_attempts
SET fencing_token = ?,
    error_code = NULL,
    error_message = NULL
WHERE id = ? AND task_id = ? AND fencing_token = ? AND status = 'running'`
		}
		attemptResult, err := transaction.ExecContext(ctx, attemptSQL,
			lease.FencingToken, attemptID.Int64, lease.TaskID,
			attemptToken.Int64,
		)
		if err != nil {
			return Lease{}, false, fmt.Errorf("advance task attempt fence: %w", err)
		}
		if err := requireOne(
			attemptResult, ErrInconsistentState, "inspect task attempt fence",
		); err != nil {
			return Lease{}, false, err
		}
	}

	if len(requirements) != 0 {
		if err := synchronizeResourceLimits(
			ctx,
			transaction,
			request.HeavySlotLimit,
			request.TrivySlotLimit,
			request.NativeSlotLimit,
		); err != nil {
			return Lease{}, false, err
		}
		if requiresResourcePool(requirements, resourcePoolGlobal) {
			var archiveImportRunning bool
			if err := transaction.QueryRowContext(ctx, `
SELECT EXISTS (
    SELECT 1 FROM archive_imports WHERE status = 'running'
)`).Scan(&archiveImportRunning); err != nil {
				return Lease{}, false, fmt.Errorf(
					"check archive import resource exclusion: %w", err,
				)
			}
			if archiveImportRunning {
				// Rolling back also releases the provisional job lease and task
				// attempt fence advanced earlier in this transaction.
				return Lease{}, false, nil
			}
		}
	}
	for _, requirement := range requirements {
		slot, err := acquireResourceSlot(
			ctx,
			transaction,
			lease,
			requirement,
		)
		if errors.Is(err, errResourceSlotUnavailable) {
			return Lease{}, false, nil
		} else if err != nil {
			return Lease{}, false, err
		}
		lease.ResourceSlots = append(lease.ResourceSlots, slot)
	}

	if err := transaction.QueryRowContext(ctx, `
SELECT lease_until
FROM jobs
WHERE id = ?`, lease.JobID).Scan(&lease.LeaseUntil); err != nil {
		return Lease{}, false, fmt.Errorf("read claimed job lease: %w", err)
	}
	if err := transaction.Commit(); err != nil {
		return Lease{}, false, fmt.Errorf("commit job claim: %w", err)
	}
	return lease, true, nil
}

func requiresResourcePool(
	requirements []resourceRequirement,
	pool string,
) bool {
	for _, requirement := range requirements {
		if requirement.pool == pool {
			return true
		}
	}
	return false
}

func synchronizeResourceLimits(
	ctx context.Context,
	transaction *sql.Tx,
	heavySlots int,
	trivySlots int,
	nativeSlots int,
) error {
	var currentHeavy int
	var currentTrivy int
	var currentNative int
	var generation uint64
	err := transaction.QueryRowContext(ctx, `
SELECT heavy_slots, trivy_slots, native_slots, generation
FROM job_resource_limits
WHERE id = 1
FOR UPDATE`).Scan(
		&currentHeavy,
		&currentTrivy,
		&currentNative,
		&generation,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrInconsistentState
	}
	if err != nil {
		return fmt.Errorf("lock job resource limits: %w", err)
	}
	if currentHeavy == heavySlots &&
		currentTrivy == trivySlots &&
		currentNative == nativeSlots {
		return nil
	}

	var jobsExist bool
	if err := transaction.QueryRowContext(ctx, `
SELECT EXISTS (
    SELECT 1
    FROM jobs
)`).Scan(&jobsExist); err != nil {
		return fmt.Errorf("inspect existing jobs for resource limits: %w", err)
	}
	// Claim is allowed to initialize a brand-new database exactly once.
	// Thereafter MySQL is the stable authority; capacity changes are an
	// explicit administration operation, never a per-worker race.
	if jobsExist || generation != 1 {
		return fmt.Errorf(
			"%w: database=%d/%d/%d generation=%d requested=%d/%d/%d",
			ErrResourceLimitMismatch,
			currentHeavy,
			currentTrivy,
			currentNative,
			generation,
			heavySlots,
			trivySlots,
			nativeSlots,
		)
	}
	result, err := transaction.ExecContext(ctx, `
UPDATE job_resource_limits
SET heavy_slots = ?,
    trivy_slots = ?,
    native_slots = ?,
    generation = generation + 1
WHERE id = 1
  AND heavy_slots = ?
  AND trivy_slots = ?
  AND native_slots = ?
  AND generation = ?`,
		heavySlots,
		trivySlots,
		nativeSlots,
		currentHeavy,
		currentTrivy,
		currentNative,
		generation,
	)
	if err != nil {
		return fmt.Errorf("update job resource limits: %w", err)
	}
	return requireOne(
		result,
		ErrInconsistentState,
		"inspect job resource limit update",
	)
}

func claimResourceRequirements(
	request claimRequest,
	payload []byte,
) ([]resourceRequirement, error) {
	if request.HeavySlotLimit == 0 &&
		request.TrivySlotLimit == 0 &&
		request.NativeSlotLimit == 0 {
		return nil, nil
	}
	if request.HeavySlotLimit < 1 || request.HeavySlotLimit > 4 ||
		request.TrivySlotLimit < 1 ||
		request.TrivySlotLimit > request.HeavySlotLimit ||
		request.NativeSlotLimit < 1 ||
		request.NativeSlotLimit > request.HeavySlotLimit {
		return nil, ErrInvalidInput
	}
	workerKind := request.PayloadWorkerKind
	if request.Kind == KindDecompile {
		payloadKind, err := decompilePayloadWorkerKind(payload)
		if err != nil {
			return nil, err
		}
		if workerKind != "" && workerKind != payloadKind {
			return nil, ErrInconsistentState
		}
		workerKind = payloadKind
	}
	pools, err := resourcePoolsForJob(request.Kind, workerKind)
	if err != nil {
		return nil, err
	}
	requirements := make([]resourceRequirement, 0, len(pools))
	for _, pool := range pools {
		limit := request.HeavySlotLimit
		switch pool {
		case resourcePoolTrivy:
			limit = request.TrivySlotLimit
		case resourcePoolNative:
			limit = request.NativeSlotLimit
		}
		if (request.Kind == KindCAnalysis || request.Kind == KindJavaAnalysis ||
			request.Kind == KindPythonAnalysis) &&
			pool == resourcePoolGlobal {
			limit = 1
		}
		requirements = append(requirements, resourceRequirement{
			pool:  pool,
			limit: limit,
		})
	}
	return requirements, nil
}

func heavyResourceKind(kind Kind) bool {
	switch kind {
	case KindScan, KindImage, KindNative, KindBytecode, KindTrivy,
		KindDecompile, KindCAnalysis, KindJavaAnalysis, KindPythonAnalysis:
		return true
	default:
		return false
	}
}

func acquireResourceSlot(
	ctx context.Context,
	transaction *sql.Tx,
	lease Lease,
	requirement resourceRequirement,
) (ResourceSlotLease, error) {
	var slotNumber uint8
	err := transaction.QueryRowContext(ctx, `
SELECT slot_number
FROM job_resource_slots FORCE INDEX (PRIMARY)
WHERE pool = ?
  AND slot_number <= ?
  AND job_id IS NULL
ORDER BY slot_number ASC
LIMIT 1
FOR UPDATE SKIP LOCKED`,
		requirement.pool,
		requirement.limit,
	).Scan(&slotNumber)
	if errors.Is(err, sql.ErrNoRows) {
		return ResourceSlotLease{}, errResourceSlotUnavailable
	}
	if err != nil {
		return ResourceSlotLease{}, fmt.Errorf(
			"select %s resource slot: %w",
			requirement.pool,
			err,
		)
	}
	result, err := transaction.ExecContext(ctx, `
UPDATE job_resource_slots
SET job_id = ?,
    job_fencing_token = ?,
    lease_owner = ?,
    acquired_at = UTC_TIMESTAMP(6)
WHERE pool = ?
  AND slot_number = ?
  AND job_id IS NULL`,
		lease.JobID,
		lease.FencingToken,
		lease.Owner,
		requirement.pool,
		slotNumber,
	)
	if err != nil {
		return ResourceSlotLease{}, fmt.Errorf(
			"lease %s resource slot: %w",
			requirement.pool,
			err,
		)
	}
	if err := requireOne(
		result,
		ErrInconsistentState,
		"inspect resource slot lease",
	); err != nil {
		return ResourceSlotLease{}, err
	}
	return ResourceSlotLease{
		Pool:       requirement.pool,
		SlotNumber: slotNumber,
	}, nil
}

func (r *MySQLRepository) Start(ctx context.Context, lease Lease) error {
	transaction, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin job start: %w", err)
	}
	defer transaction.Rollback()

	if lease.Kind == KindDecompile || lease.Kind == KindImage {
		var valid uint8
		err := transaction.QueryRowContext(ctx, `
	SELECT 1
	FROM tasks
	WHERE id = ?
	  AND status IN ('SUCCEEDED', 'PARTIAL_SUCCEEDED', 'FAILED', 'CANCELLED')
	  AND sample_deleted_at IS NULL
	  AND sample_expires_at > UTC_TIMESTAMP(6)
	  AND deleted_at IS NULL
	FOR UPDATE`, lease.TaskID).Scan(&valid)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrInconsistentState
		}
		if err != nil {
			return fmt.Errorf("validate post-scan job task start: %w", err)
		}
	}
	if lease.Kind == KindCAnalysis {
		var valid uint8
		err := transaction.QueryRowContext(ctx, `
SELECT 1
FROM jobs job
JOIN tasks task ON task.id = job.task_id
JOIN c_analysis_runs analysis
  ON analysis.task_id = job.task_id AND analysis.job_id = job.id
JOIN decompile_source_projects project
  ON project.task_id = analysis.task_id
 AND project.id = analysis.source_project_id
WHERE job.id = ? AND job.task_id = ? AND job.kind = 'c_analysis'
  AND job.status = 'leased' AND job.lease_owner = ?
  AND job.fencing_token = ? AND job.lease_until > UTC_TIMESTAMP(6)
  AND task.status IN ('SUCCEEDED', 'PARTIAL_SUCCEEDED', 'FAILED', 'CANCELLED')
  AND task.deleted_at IS NULL
  AND analysis.status = 'queued'
  AND project.deleted_at IS NULL AND project.storage_deleted_at IS NULL
  AND project.layout_version = 'project-v1'
  AND project.source_kind = 'ghidra-pseudoc' AND project.language = 'c'
  AND project.status IN ('complete', 'partial')
  AND project.canonical_sha256 = analysis.source_sha256
  AND project.canonical_size_bytes = analysis.source_size_bytes
FOR UPDATE`, lease.JobID, lease.TaskID, lease.Owner, lease.FencingToken).Scan(&valid)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrLeaseLost
		}
		if err != nil {
			return fmt.Errorf("validate C analysis job start: %w", err)
		}
	}
	if lease.Kind == KindJavaAnalysis {
		var valid uint8
		err := transaction.QueryRowContext(ctx, `
SELECT 1
FROM jobs job
JOIN tasks task ON task.id = job.task_id
JOIN java_analysis_runs analysis
  ON analysis.task_id = job.task_id AND analysis.job_id = job.id
JOIN decompile_source_projects project
  ON project.task_id = analysis.task_id
 AND project.id = analysis.source_project_id
WHERE job.id = ? AND job.task_id = ? AND job.kind = 'java_analysis'
  AND job.status = 'leased' AND job.lease_owner = ?
  AND job.fencing_token = ? AND job.lease_until > UTC_TIMESTAMP(6)
  AND task.status IN ('SUCCEEDED', 'PARTIAL_SUCCEEDED', 'FAILED', 'CANCELLED')
  AND task.deleted_at IS NULL AND analysis.status = 'queued'
  AND project.deleted_at IS NULL AND project.storage_deleted_at IS NULL
  AND project.layout_version = 'project-v1'
  AND project.source_kind = 'java' AND project.language IN ('java', 'mixed')
  AND project.status IN ('complete', 'partial')
  AND project.manifest_sha256 = analysis.source_manifest_sha256
  AND analysis.input_sha256 REGEXP '^[0-9a-f]{64}$'
  AND analysis.source_size_bytes > 0 AND analysis.source_file_count > 0
FOR UPDATE`, lease.JobID, lease.TaskID, lease.Owner, lease.FencingToken).Scan(&valid)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrLeaseLost
		}
		if err != nil {
			return fmt.Errorf("validate Java analysis job start: %w", err)
		}
	}
	if lease.Kind == KindPythonAnalysis {
		var valid uint8
		err := transaction.QueryRowContext(ctx, `
SELECT 1
FROM jobs job
JOIN tasks task ON task.id = job.task_id
JOIN python_analysis_runs analysis
  ON analysis.task_id = job.task_id AND analysis.job_id = job.id
JOIN decompile_source_projects project
  ON project.task_id = analysis.task_id
 AND project.id = analysis.source_project_id
WHERE job.id = ? AND job.task_id = ? AND job.kind = 'python_analysis'
  AND job.status = 'leased' AND job.lease_owner = ?
  AND job.fencing_token = ? AND job.lease_until > UTC_TIMESTAMP(6)
  AND task.status IN ('SUCCEEDED', 'PARTIAL_SUCCEEDED', 'FAILED', 'CANCELLED')
  AND task.deleted_at IS NULL AND analysis.status = 'queued'
  AND project.deleted_at IS NULL AND project.storage_deleted_at IS NULL
  AND project.layout_version = 'project-v1'
  AND project.source_kind = 'python'
  AND project.status IN ('complete', 'partial')
  AND project.manifest_sha256 = analysis.source_manifest_sha256
  AND analysis.input_sha256 REGEXP '^[0-9a-f]{64}$'
  AND analysis.source_size_bytes > 0 AND analysis.source_file_count > 0
FOR UPDATE`, lease.JobID, lease.TaskID, lease.Owner, lease.FencingToken).Scan(&valid)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrLeaseLost
		}
		if err != nil {
			return fmt.Errorf("validate Python analysis job start: %w", err)
		}
	}

	result, err := transaction.ExecContext(ctx, `
UPDATE jobs
SET status = 'running',
    started_at = COALESCE(started_at, UTC_TIMESTAMP(6)),
    heartbeat_at = UTC_TIMESTAMP(6)
WHERE id = ?
  AND task_id = ?
  AND status = 'leased'
  AND lease_owner = ?
  AND fencing_token = ?
  AND lease_until > UTC_TIMESTAMP(6)`,
		lease.JobID, lease.TaskID, lease.Owner, lease.FencingToken,
	)
	if err != nil {
		return fmt.Errorf("start leased job: %w", err)
	}
	if err := requireOne(result, ErrLeaseLost, "inspect leased job start"); err != nil {
		return err
	}
	if len(lease.ResourceSlots) != 0 {
		if err := validateResourceSlots(ctx, transaction, lease); err != nil {
			return err
		}
	}

	if lease.Kind == KindScan {
		if lease.TaskAttemptID == nil {
			return ErrInconsistentState
		}
		attemptResult, err := transaction.ExecContext(ctx, `
UPDATE task_attempts
SET status = 'running',
    started_at = COALESCE(started_at, UTC_TIMESTAMP(6)),
    completed_at = NULL,
    error_code = NULL,
    error_message = NULL
WHERE id = ? AND task_id = ? AND fencing_token = ? AND status = 'queued'`,
			*lease.TaskAttemptID, lease.TaskID, lease.FencingToken,
		)
		if err != nil {
			return fmt.Errorf("start task attempt: %w", err)
		}
		if err := requireOne(
			attemptResult, ErrInconsistentState, "inspect task attempt start",
		); err != nil {
			return err
		}
		taskResult, err := transaction.ExecContext(ctx, `
UPDATE tasks
SET status = 'VALIDATING',
    stage = 'VALIDATING',
    progress_basis_points = 0,
    error_code = NULL,
    error_message = NULL,
    event_sequence = event_sequence + 1
WHERE id = ? AND status = 'QUEUED'`, lease.TaskID)
		if err != nil {
			return fmt.Errorf("start scan task: %w", err)
		}
		if err := requireOne(taskResult, ErrInconsistentState, "inspect scan task start"); err != nil {
			return err
		}
		if err := taskevent.AppendCurrentState(
			ctx, transaction, lease.TaskID,
			"task.status_changed", "Task scan started.",
		); err != nil {
			return err
		}
	} else if lease.Kind == KindTrivy {
		if lease.TaskAttemptID == nil {
			return ErrInconsistentState
		}
		var valid int
		err := transaction.QueryRowContext(ctx, `
SELECT 1
FROM task_attempts attempt
JOIN tasks task ON task.id = attempt.task_id
WHERE attempt.id = ?
  AND attempt.task_id = ?
  AND attempt.status = 'running'
  AND attempt.fencing_token = ?
  AND task.status = 'SCANNING'
  AND task.stage = 'SCANNING'
  AND task.sample_deleted_at IS NULL
  AND task.deleted_at IS NULL
FOR UPDATE`,
			*lease.TaskAttemptID, lease.TaskID, lease.FencingToken,
		).Scan(&valid)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrInconsistentState
		}
		if err != nil {
			return fmt.Errorf("validate Trivy task start: %w", err)
		}
	}
	if err := transaction.Commit(); err != nil {
		return fmt.Errorf("commit job start: %w", err)
	}
	return nil
}

func resourcePoolsForLease(lease Lease) ([]string, error) {
	workerKind := Kind("")
	if lease.Kind == KindDecompile {
		var err error
		workerKind, err = decompilePayloadWorkerKind(lease.Payload)
		if err != nil {
			return nil, err
		}
	}
	return resourcePoolsForJob(lease.Kind, workerKind)
}

func resourcePoolsForJob(kind Kind, workerKind Kind) ([]string, error) {
	if !heavyResourceKind(kind) {
		return nil, nil
	}
	switch kind {
	case KindNative:
		return []string{resourcePoolGlobal, resourcePoolNative}, nil
	case KindTrivy, KindImage:
		return []string{resourcePoolGlobal, resourcePoolTrivy}, nil
	case KindDecompile:
		switch workerKind {
		case KindNative:
			return []string{resourcePoolGlobal, resourcePoolNative}, nil
		case KindBytecode:
			return []string{resourcePoolGlobal}, nil
		default:
			return nil, ErrInconsistentState
		}
	default:
		return []string{resourcePoolGlobal}, nil
	}
}

func decompilePayloadWorkerKind(payload []byte) (Kind, error) {
	var envelope struct {
		Engine struct {
			WorkerKind Kind `json:"worker_kind"`
		} `json:"engine"`
	}
	if len(payload) == 0 || json.Unmarshal(payload, &envelope) != nil {
		return "", ErrInconsistentState
	}
	if envelope.Engine.WorkerKind != KindNative &&
		envelope.Engine.WorkerKind != KindBytecode {
		return "", ErrInconsistentState
	}
	return envelope.Engine.WorkerKind, nil
}

func validateResourceSlots(
	ctx context.Context,
	transaction *sql.Tx,
	lease Lease,
) error {
	expectedPools, err := resourcePoolsForLease(lease)
	if err != nil {
		return err
	}
	if len(lease.ResourceSlots) != len(expectedPools) {
		return ErrLeaseLost
	}
	for index, slot := range lease.ResourceSlots {
		if slot.Pool != expectedPools[index] || slot.SlotNumber == 0 {
			return ErrLeaseLost
		}
		var valid int
		err := transaction.QueryRowContext(ctx, `
SELECT 1
FROM job_resource_slots
WHERE pool = ?
  AND slot_number = ?
  AND job_id = ?
  AND job_fencing_token = ?
  AND lease_owner = ?
FOR UPDATE`,
			slot.Pool,
			slot.SlotNumber,
			lease.JobID,
			lease.FencingToken,
			lease.Owner,
		).Scan(&valid)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrLeaseLost
		}
		if err != nil {
			return fmt.Errorf(
				"validate %s resource slot: %w",
				slot.Pool,
				err,
			)
		}
	}
	return nil
}

func (r *MySQLRepository) Heartbeat(
	ctx context.Context,
	lease Lease,
	leaseDurationMicros int64,
) (Lease, error) {
	transaction, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return Lease{}, fmt.Errorf("begin job heartbeat: %w", err)
	}
	defer transaction.Rollback()
	result, err := transaction.ExecContext(ctx, `
UPDATE jobs
SET heartbeat_at = UTC_TIMESTAMP(6),
    lease_until = DATE_ADD(UTC_TIMESTAMP(6), INTERVAL ? MICROSECOND)
WHERE id = ?
  AND task_id = ?
  AND status IN ('leased', 'running')
  AND lease_owner = ?
  AND fencing_token = ?
  AND lease_until > UTC_TIMESTAMP(6)`,
		leaseDurationMicros, lease.JobID, lease.TaskID, lease.Owner, lease.FencingToken,
	)
	if err != nil {
		return Lease{}, fmt.Errorf("heartbeat job lease: %w", err)
	}
	if err := requireOne(result, ErrLeaseLost, "inspect job heartbeat"); err != nil {
		return Lease{}, err
	}
	if len(lease.ResourceSlots) != 0 {
		if err := validateResourceSlots(ctx, transaction, lease); err != nil {
			return Lease{}, err
		}
	}
	if err := transaction.QueryRowContext(ctx, `
SELECT lease_until
FROM jobs
WHERE id = ?
  AND task_id = ?
  AND status IN ('leased', 'running')
  AND lease_owner = ?
  AND fencing_token = ?
  AND lease_until > UTC_TIMESTAMP(6)`,
		lease.JobID, lease.TaskID, lease.Owner, lease.FencingToken,
	).Scan(&lease.LeaseUntil); errors.Is(err, sql.ErrNoRows) {
		return Lease{}, ErrLeaseLost
	} else if err != nil {
		return Lease{}, fmt.Errorf("read heartbeat lease: %w", err)
	}
	if err := transaction.Commit(); err != nil {
		return Lease{}, fmt.Errorf("commit job heartbeat: %w", err)
	}
	return lease, nil
}

func (r *MySQLRepository) WorkspaceLeaseActive(
	ctx context.Context,
	request workspaceLeaseRequest,
) (bool, error) {
	var active bool
	// Do not predicate this read on lease_until or cancel_requested_at. While
	// Heartbeat holds the row lock, a plain MVCC SELECT can still observe the
	// previous version, and the current worker does not stop synchronously when
	// cancellation is requested. The exact active status and fence must remain
	// fail-closed until recovery, cancellation handling, or completion publishes
	// a newer state.
	err := r.db.QueryRowContext(ctx, `
SELECT EXISTS (
    SELECT 1
    FROM jobs job
    JOIN task_attempts attempt
      ON attempt.task_id = job.task_id
     AND attempt.id = job.task_attempt_id
	    WHERE job.id = ?
	      AND job.task_id = ?
	      AND job.task_attempt_id = ?
	      AND job.kind = ?
	      AND job.fencing_token = ?
	      AND job.status IN ('leased', 'running', 'cancel_requested')
	      AND (
	          job.kind IN (
	              'decompile', 'image', 'c_analysis', 'java_analysis',
	              'python_analysis'
	          )
	          OR attempt.fencing_token = ?
	      )
)`,
		request.JobID, request.TaskID, request.TaskAttemptID,
		request.Kind, request.FencingToken, request.FencingToken,
	).Scan(&active)
	if err != nil {
		return false, fmt.Errorf("query workspace lease activity: %w", err)
	}
	return active, nil
}

func (r *MySQLRepository) TaskActivity(
	ctx context.Context,
	request activityRequest,
) error {
	transaction, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin task activity: %w", err)
	}
	defer transaction.Rollback()

	result, err := transaction.ExecContext(ctx, `
UPDATE tasks AS task
JOIN jobs AS job ON job.task_id = task.id
SET task.event_sequence = task.event_sequence + 1
WHERE job.id = ?
  AND job.task_id = ?
  AND job.kind = ?
  AND job.status = 'running'
  AND job.lease_owner = ?
  AND job.fencing_token = ?
  AND job.lease_until > UTC_TIMESTAMP(6)
  AND task.deleted_at IS NULL`,
		request.Lease.JobID,
		request.Lease.TaskID,
		request.Lease.Kind,
		request.Lease.Owner,
		request.Lease.FencingToken,
	)
	if err != nil {
		return fmt.Errorf("advance task activity sequence: %w", err)
	}
	if err := requireOne(
		result,
		ErrLeaseLost,
		"inspect task activity lease",
	); err != nil {
		return err
	}
	if err := taskevent.AppendActivity(
		ctx,
		transaction,
		request.Lease.TaskID,
		taskevent.Activity{
			EventType: request.Input.EventType,
			Severity:  request.Input.Severity,
			Message:   request.Input.Message,
			Payload:   request.Input.Payload,
		},
	); err != nil {
		return err
	}
	if err := transaction.Commit(); err != nil {
		return fmt.Errorf("commit task activity: %w", err)
	}
	return nil
}

func (r *MySQLRepository) TaskProgress(
	ctx context.Context,
	request progressRequest,
) error {
	transaction, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin task progress: %w", err)
	}
	defer transaction.Rollback()

	leaseResult, err := transaction.ExecContext(ctx, `
UPDATE jobs
SET heartbeat_at = UTC_TIMESTAMP(6),
    lease_until = DATE_ADD(UTC_TIMESTAMP(6), INTERVAL ? MICROSECOND)
WHERE id = ?
  AND task_id = ?
  AND status = 'running'
  AND lease_owner = ?
  AND fencing_token = ?
  AND lease_until > UTC_TIMESTAMP(6)`,
		request.LeaseDurationMicros,
		request.Lease.JobID, request.Lease.TaskID,
		request.Lease.Owner, request.Lease.FencingToken,
	)
	if err != nil {
		return fmt.Errorf("validate progress lease: %w", err)
	}
	if err := requireOne(leaseResult, ErrLeaseLost, "inspect progress lease"); err != nil {
		return err
	}
	if len(request.Lease.ResourceSlots) != 0 {
		if err := validateResourceSlots(
			ctx,
			transaction,
			request.Lease,
		); err != nil {
			return err
		}
	}
	taskResult, err := transaction.ExecContext(ctx, `
UPDATE tasks
SET status = ?,
    stage = ?,
    progress_basis_points = ?,
    updated_at = UTC_TIMESTAMP(6),
    event_sequence = event_sequence + 1
WHERE id = ?
  AND status NOT IN ('SUCCEEDED', 'PARTIAL_SUCCEEDED', 'FAILED', 'CANCELLED', 'DELETED')`,
		request.Input.TaskStatus, request.Input.Stage,
		request.ProgressBasisPoints, request.Lease.TaskID,
	)
	if err != nil {
		return fmt.Errorf("update task progress: %w", err)
	}
	if err := requireOne(taskResult, ErrInconsistentState, "inspect task progress"); err != nil {
		return err
	}
	if err := taskevent.AppendCurrentState(
		ctx, transaction, request.Lease.TaskID,
		"task.progress", "Task progress changed.",
	); err != nil {
		return err
	}
	if err := transaction.Commit(); err != nil {
		return fmt.Errorf("commit task progress: %w", err)
	}
	return nil
}

func (r *MySQLRepository) Finish(ctx context.Context, request finishRequest) error {
	if request.SampleRetentionMicros <= 0 {
		return ErrInvalidInput
	}
	transaction, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin job finish: %w", err)
	}
	defer transaction.Rollback()

	var taskID string
	var kind Kind
	var attemptID sql.NullInt64
	var attempt, maxAttempts uint32
	err = transaction.QueryRowContext(ctx, `
SELECT task_id, task_attempt_id, kind, attempt, max_attempts
FROM jobs
WHERE id = ?
  AND task_id = ?
  AND status = 'running'
  AND lease_owner = ?
  AND fencing_token = ?
  AND lease_until > UTC_TIMESTAMP(6)
FOR UPDATE`,
		request.Lease.JobID, request.Lease.TaskID,
		request.Lease.Owner, request.Lease.FencingToken,
	).Scan(&taskID, &attemptID, &kind, &attempt, &maxAttempts)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrLeaseLost
	}
	if err != nil {
		return fmt.Errorf("lock finishing job: %w", err)
	}
	if taskID != request.Lease.TaskID || kind != request.Lease.Kind ||
		attempt != request.Lease.Attempt ||
		maxAttempts != request.Lease.MaxAttempts {
		return ErrInconsistentState
	}
	if len(request.Lease.ResourceSlots) != 0 {
		if err := validateResourceSlots(
			ctx,
			transaction,
			request.Lease,
		); err != nil {
			return err
		}
	}

	retry := request.Input.Outcome == OutcomeTransientFailure && attempt < maxAttempts
	jobStatus := "failed"
	taskStatus := "FAILED"
	attemptStatus := "failed"
	if retry {
		jobStatus = "queued"
		taskStatus = "QUEUED"
		attemptStatus = "queued"
	} else if request.Input.Outcome == OutcomeSucceeded {
		jobStatus = "succeeded"
		taskStatus = "SUCCEEDED"
		attemptStatus = "succeeded"
	} else if request.Input.Outcome == OutcomePartialSucceeded {
		jobStatus = "succeeded"
		taskStatus = "PARTIAL_SUCCEEDED"
		attemptStatus = "succeeded"
	}

	var jobResult sql.Result
	if retry {
		jobResult, err = transaction.ExecContext(ctx, `
UPDATE jobs
SET status = 'queued',
    available_at = DATE_ADD(UTC_TIMESTAMP(6), INTERVAL ? MICROSECOND),
    lease_owner = NULL,
    lease_until = NULL,
    heartbeat_at = NULL,
    started_at = NULL,
    completed_at = NULL,
    error_code = ?,
    error_message = ?
WHERE id = ?
  AND task_id = ?
  AND status = 'running'
  AND lease_owner = ?
  AND fencing_token = ?
  AND lease_until > UTC_TIMESTAMP(6)`,
			request.RetryDelayMicros,
			request.Input.ErrorCode, request.Input.ErrorMessage,
			request.Lease.JobID, request.Lease.TaskID,
			request.Lease.Owner, request.Lease.FencingToken,
		)
	} else {
		jobResult, err = transaction.ExecContext(ctx, `
UPDATE jobs
SET status = ?,
    lease_owner = NULL,
    lease_until = NULL,
    heartbeat_at = NULL,
    completed_at = UTC_TIMESTAMP(6),
    error_code = NULLIF(?, ''),
    error_message = NULLIF(?, '')
WHERE id = ?
  AND task_id = ?
  AND status = 'running'
  AND lease_owner = ?
  AND fencing_token = ?
  AND lease_until > UTC_TIMESTAMP(6)`,
			jobStatus, request.Input.ErrorCode, request.Input.ErrorMessage,
			request.Lease.JobID, request.Lease.TaskID,
			request.Lease.Owner, request.Lease.FencingToken,
		)
	}
	if err != nil {
		return fmt.Errorf("finish leased job: %w", err)
	}
	if err := requireOne(jobResult, ErrLeaseLost, "inspect leased job finish"); err != nil {
		return err
	}
	if len(request.Lease.ResourceSlots) != 0 {
		if err := releaseResourceSlots(
			ctx,
			transaction,
			request.Lease,
		); err != nil {
			return err
		}
	}

	if kind == KindScan {
		if !attemptID.Valid || attemptID.Int64 <= 0 ||
			request.Lease.TaskAttemptID == nil ||
			uint64(attemptID.Int64) != *request.Lease.TaskAttemptID {
			return ErrInconsistentState
		}
		handoff := false
		if !retry &&
			(request.Input.Outcome == OutcomeSucceeded ||
				request.Input.Outcome == OutcomePartialSucceeded) {
			if err := transaction.QueryRowContext(ctx, `
SELECT EXISTS (
    SELECT 1
    FROM jobs
    WHERE task_id = ?
      AND task_attempt_id = ?
      AND kind = 'trivy'
      AND status = 'queued'
)`, request.Lease.TaskID, *request.Lease.TaskAttemptID).Scan(&handoff); err != nil {
				return fmt.Errorf("check Trivy job handoff: %w", err)
			}
		}
		if err := finishScanTask(
			ctx, transaction, request, taskStatus, attemptStatus, retry, handoff,
		); err != nil {
			return err
		}
	} else if kind == KindTrivy {
		if !attemptID.Valid || attemptID.Int64 <= 0 ||
			request.Lease.TaskAttemptID == nil ||
			uint64(attemptID.Int64) != *request.Lease.TaskAttemptID {
			return ErrInconsistentState
		}
		var rawPayload []byte
		if err := transaction.QueryRowContext(ctx, `
SELECT payload FROM jobs WHERE id = ? AND task_id = ?`,
			request.Lease.JobID, request.Lease.TaskID,
		).Scan(&rawPayload); err != nil {
			return fmt.Errorf("read Trivy job payload: %w", err)
		}
		upstreamPartial, err := trivyUpstreamPartial(rawPayload)
		if err != nil {
			return err
		}
		if err := finishTrivyTask(
			ctx, transaction, request, retry, upstreamPartial,
		); err != nil {
			return err
		}
	}
	if err := transaction.Commit(); err != nil {
		return fmt.Errorf("commit job finish: %w", err)
	}
	return nil
}

func releaseResourceSlots(
	ctx context.Context,
	transaction *sql.Tx,
	lease Lease,
) error {
	if len(lease.ResourceSlots) == 0 {
		return nil
	}
	if err := validateResourceSlots(ctx, transaction, lease); err != nil {
		return err
	}
	for _, slot := range lease.ResourceSlots {
		result, err := transaction.ExecContext(ctx, `
UPDATE job_resource_slots
SET job_id = NULL,
    job_fencing_token = NULL,
    lease_owner = NULL,
    acquired_at = NULL
WHERE pool = ?
  AND slot_number = ?
  AND job_id = ?
  AND job_fencing_token = ?
  AND lease_owner = ?`,
			slot.Pool,
			slot.SlotNumber,
			lease.JobID,
			lease.FencingToken,
			lease.Owner,
		)
		if err != nil {
			return fmt.Errorf(
				"release %s resource slot: %w",
				slot.Pool,
				err,
			)
		}
		if err := requireOne(
			result,
			ErrLeaseLost,
			"inspect resource slot release",
		); err != nil {
			return err
		}
	}
	return nil
}

func finishScanTask(
	ctx context.Context,
	transaction *sql.Tx,
	request finishRequest,
	taskStatus string,
	attemptStatus string,
	retry bool,
	handoff bool,
) error {
	if request.Lease.TaskAttemptID == nil {
		return ErrInconsistentState
	}
	if retry {
		attemptResult, err := transaction.ExecContext(ctx, `
UPDATE task_attempts
SET status = 'queued',
    started_at = NULL,
    completed_at = NULL,
    error_code = ?,
    error_message = ?
WHERE id = ? AND task_id = ? AND fencing_token = ? AND status = 'running'`,
			request.Input.ErrorCode, request.Input.ErrorMessage,
			*request.Lease.TaskAttemptID, request.Lease.TaskID, request.Lease.FencingToken,
		)
		if err != nil {
			return fmt.Errorf("requeue task attempt: %w", err)
		}
		if err := requireOne(
			attemptResult, ErrInconsistentState, "inspect requeued task attempt",
		); err != nil {
			return err
		}
		taskResult, err := transaction.ExecContext(ctx, `
UPDATE tasks
SET status = 'QUEUED',
    stage = NULL,
    error_code = ?,
    error_message = ?,
    event_sequence = event_sequence + 1
WHERE id = ?
  AND status NOT IN ('SUCCEEDED', 'PARTIAL_SUCCEEDED', 'FAILED', 'CANCELLED', 'DELETED')`,
			request.Input.ErrorCode, request.Input.ErrorMessage, request.Lease.TaskID,
		)
		if err != nil {
			return fmt.Errorf("requeue scan task: %w", err)
		}
		if err := requireOne(
			taskResult, ErrInconsistentState, "inspect requeued scan task",
		); err != nil {
			return err
		}
		return taskevent.AppendCurrentState(
			ctx, transaction, request.Lease.TaskID,
			"task.status_changed", "Task requeued after a transient failure.",
		)
	}

	if handoff {
		var valid int
		err := transaction.QueryRowContext(ctx, `
SELECT 1
FROM task_attempts
WHERE id = ?
  AND task_id = ?
  AND fencing_token = ?
  AND status = 'running'
FOR UPDATE`,
			*request.Lease.TaskAttemptID, request.Lease.TaskID,
			request.Lease.FencingToken,
		).Scan(&valid)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrInconsistentState
		}
		if err != nil {
			return fmt.Errorf("validate Trivy handoff task attempt: %w", err)
		}
		taskResult, err := transaction.ExecContext(ctx, `
UPDATE tasks
SET status = 'SCANNING',
    stage = 'SCANNING',
	progress_basis_points = ?,
    error_code = NULL,
    error_message = NULL,
    completed_at = NULL,
    event_sequence = event_sequence + 1
WHERE id = ?
  AND status NOT IN (
      'SUCCEEDED', 'PARTIAL_SUCCEEDED', 'FAILED',
      'CANCEL_REQUESTED', 'CANCELLED', 'DELETING', 'DELETED'
	  )`, taskprogress.ScanningStartBasisPoints, request.Lease.TaskID)
		if err != nil {
			return fmt.Errorf("advance task to Trivy scanning: %w", err)
		}
		if err := requireOne(
			taskResult, ErrInconsistentState, "inspect Trivy task handoff",
		); err != nil {
			return err
		}
		return taskevent.AppendCurrentState(
			ctx, transaction, request.Lease.TaskID,
			"task.status_changed", "Container vulnerability scan queued.",
		)
	}

	attemptResult, err := transaction.ExecContext(ctx, `
UPDATE task_attempts
SET status = ?,
    completed_at = UTC_TIMESTAMP(6),
    error_code = NULLIF(?, ''),
    error_message = NULLIF(?, '')
WHERE id = ? AND task_id = ? AND fencing_token = ? AND status = 'running'`,
		attemptStatus, request.Input.ErrorCode, request.Input.ErrorMessage,
		*request.Lease.TaskAttemptID, request.Lease.TaskID, request.Lease.FencingToken,
	)
	if err != nil {
		return fmt.Errorf("finish task attempt: %w", err)
	}
	if err := requireOne(attemptResult, ErrInconsistentState, "inspect finished task attempt"); err != nil {
		return err
	}
	progress := uint16(0)
	if taskStatus == "SUCCEEDED" || taskStatus == "PARTIAL_SUCCEEDED" {
		progress = 10_000
	}
	taskResult, err := transaction.ExecContext(ctx, `
UPDATE tasks
SET status = ?,
    stage = NULL,
    progress_basis_points = ?,
    error_code = NULLIF(?, ''),
    error_message = NULLIF(?, ''),
    completed_at = UTC_TIMESTAMP(6),
    sample_expires_at = CASE
        WHEN sample_deleted_at IS NULL AND deleted_at IS NULL
        THEN GREATEST(
            sample_expires_at,
            DATE_ADD(UTC_TIMESTAMP(6), INTERVAL ? MICROSECOND)
        )
        ELSE sample_expires_at
    END,
    event_sequence = event_sequence + 1
WHERE id = ?
  AND status NOT IN ('SUCCEEDED', 'PARTIAL_SUCCEEDED', 'FAILED', 'CANCELLED', 'DELETED')`,
		taskStatus, progress, request.Input.ErrorCode,
		request.Input.ErrorMessage, request.SampleRetentionMicros,
		request.Lease.TaskID,
	)
	if err != nil {
		return fmt.Errorf("finish scan task: %w", err)
	}
	if err := requireOne(
		taskResult, ErrInconsistentState, "inspect finished scan task",
	); err != nil {
		return err
	}
	return taskevent.AppendCurrentState(
		ctx, transaction, request.Lease.TaskID,
		"task.status_changed", "Task scan finished.",
	)
}

func finishTrivyTask(
	ctx context.Context,
	transaction *sql.Tx,
	request finishRequest,
	retry bool,
	upstreamPartial bool,
) error {
	if request.Lease.TaskAttemptID == nil {
		return ErrInconsistentState
	}
	if retry {
		attemptResult, err := transaction.ExecContext(ctx, `
UPDATE task_attempts
SET error_code = ?,
    error_message = ?
WHERE id = ?
  AND task_id = ?
  AND fencing_token = ?
  AND status = 'running'`,
			request.Input.ErrorCode, request.Input.ErrorMessage,
			*request.Lease.TaskAttemptID, request.Lease.TaskID,
			request.Lease.FencingToken,
		)
		if err != nil {
			return fmt.Errorf("record retrying Trivy task attempt: %w", err)
		}
		if err := requireOne(
			attemptResult, ErrInconsistentState,
			"inspect retrying Trivy task attempt",
		); err != nil {
			return err
		}
		taskResult, err := transaction.ExecContext(ctx, `
UPDATE tasks
SET status = 'SCANNING',
    stage = 'SCANNING',
	progress_basis_points = ?,
    error_code = ?,
    error_message = ?,
    completed_at = NULL,
    event_sequence = event_sequence + 1
WHERE id = ? AND status IN ('SCANNING', 'REPORTING')`,
			taskprogress.ScanningStartBasisPoints,
			request.Input.ErrorCode, request.Input.ErrorMessage,
			request.Lease.TaskID,
		)
		if err != nil {
			return fmt.Errorf("requeue Trivy task: %w", err)
		}
		if err := requireOne(
			taskResult, ErrInconsistentState, "inspect requeued Trivy task",
		); err != nil {
			return err
		}
		return taskevent.AppendCurrentState(
			ctx, transaction, request.Lease.TaskID,
			"task.status_changed",
			"Container vulnerability scan requeued after a transient failure.",
		)
	}

	taskStatus := "FAILED"
	attemptStatus := "failed"
	progress := uint16(0)
	if request.Input.Outcome == OutcomeSucceeded ||
		request.Input.Outcome == OutcomePartialSucceeded {
		taskStatus = "SUCCEEDED"
		attemptStatus = "succeeded"
		progress = 10_000
		if upstreamPartial ||
			request.Input.Outcome == OutcomePartialSucceeded {
			taskStatus = "PARTIAL_SUCCEEDED"
		}
	}
	attemptResult, err := transaction.ExecContext(ctx, `
UPDATE task_attempts
SET status = ?,
    completed_at = UTC_TIMESTAMP(6),
    error_code = NULLIF(?, ''),
    error_message = NULLIF(?, '')
WHERE id = ?
  AND task_id = ?
  AND fencing_token = ?
  AND status = 'running'`,
		attemptStatus, request.Input.ErrorCode, request.Input.ErrorMessage,
		*request.Lease.TaskAttemptID, request.Lease.TaskID,
		request.Lease.FencingToken,
	)
	if err != nil {
		return fmt.Errorf("finish Trivy task attempt: %w", err)
	}
	if err := requireOne(
		attemptResult, ErrInconsistentState, "inspect finished Trivy task attempt",
	); err != nil {
		return err
	}
	taskResult, err := transaction.ExecContext(ctx, `
UPDATE tasks
SET status = ?,
    stage = NULL,
    progress_basis_points = ?,
    error_code = NULLIF(?, ''),
    error_message = NULLIF(?, ''),
    completed_at = UTC_TIMESTAMP(6),
    sample_expires_at = CASE
        WHEN sample_deleted_at IS NULL AND deleted_at IS NULL
        THEN GREATEST(
            sample_expires_at,
            DATE_ADD(UTC_TIMESTAMP(6), INTERVAL ? MICROSECOND)
        )
        ELSE sample_expires_at
    END,
    event_sequence = event_sequence + 1
WHERE id = ? AND status IN ('SCANNING', 'REPORTING')`,
		taskStatus, progress, request.Input.ErrorCode,
		request.Input.ErrorMessage, request.SampleRetentionMicros,
		request.Lease.TaskID,
	)
	if err != nil {
		return fmt.Errorf("finish Trivy task: %w", err)
	}
	if err := requireOne(
		taskResult, ErrInconsistentState, "inspect finished Trivy task",
	); err != nil {
		return err
	}
	return taskevent.AppendCurrentState(
		ctx, transaction, request.Lease.TaskID,
		"task.status_changed", "Container vulnerability scan finished.",
	)
}

func trivyUpstreamPartial(raw []byte) (bool, error) {
	payload, err := trivyhandoff.Decode(
		raw,
		10*1024*1024*1024,
		trivyhandoff.MaxSources,
	)
	if err != nil {
		return false, fmt.Errorf(
			"%w: decode Trivy job payload: %v",
			ErrInconsistentState,
			err,
		)
	}
	return payload.UpstreamPartial, nil
}

type expiredJob struct {
	ID            string
	TaskID        string
	TaskAttemptID sql.NullInt64
	Kind          Kind
	Attempt       uint32
	MaxAttempts   uint32
	FencingToken  uint64
	Status        string
}

func (r *MySQLRepository) RecoverExpired(
	ctx context.Context,
	limit int,
	retryDelayMicros int64,
	sampleRetentionMicros int64,
) (int, error) {
	if sampleRetentionMicros <= 0 {
		return 0, ErrInvalidInput
	}
	transaction, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("begin expired lease recovery: %w", err)
	}
	defer transaction.Rollback()
	rows, err := transaction.QueryContext(ctx, `
SELECT id, task_id, task_attempt_id, kind, attempt, max_attempts, fencing_token,
       status
FROM jobs
WHERE (
        status IN ('leased', 'running')
        AND lease_until <= UTC_TIMESTAMP(6)
      )
   OR (
        status = 'cancel_requested'
        AND (lease_until IS NULL OR lease_until <= UTC_TIMESTAMP(6))
      )
ORDER BY lease_until ASC, id ASC
LIMIT ?
FOR UPDATE SKIP LOCKED`, limit)
	if err != nil {
		return 0, fmt.Errorf("select expired job leases: %w", err)
	}
	jobs := make([]expiredJob, 0, limit)
	for rows.Next() {
		var job expiredJob
		if err := rows.Scan(
			&job.ID, &job.TaskID, &job.TaskAttemptID, &job.Kind,
			&job.Attempt, &job.MaxAttempts, &job.FencingToken,
			&job.Status,
		); err != nil {
			_ = rows.Close()
			return 0, fmt.Errorf("scan expired job lease: %w", err)
		}
		jobs = append(jobs, job)
	}
	if err := rows.Close(); err != nil {
		return 0, fmt.Errorf("close expired job leases: %w", err)
	}
	if err := rows.Err(); err != nil {
		return 0, fmt.Errorf("iterate expired job leases: %w", err)
	}
	for _, job := range jobs {
		useSavepoint := len(jobs) > 1
		if useSavepoint {
			if _, err := transaction.ExecContext(ctx, "SAVEPOINT recover_expired_job"); err != nil {
				return 0, fmt.Errorf("create expired job recovery savepoint: %w", err)
			}
		}
		if err := recoverExpiredJob(
			ctx, transaction, job, retryDelayMicros, sampleRetentionMicros,
		); err != nil {
			if !errors.Is(err, ErrInconsistentState) {
				return 0, err
			}
			if !useSavepoint {
				_ = transaction.Rollback()
				if quarantineErr := r.quarantineExpiredJob(
					ctx, job, sampleRetentionMicros,
				); quarantineErr != nil {
					return 0, errors.Join(err, quarantineErr)
				}
				return 1, nil
			}
			if _, rollbackErr := transaction.ExecContext(
				ctx, "ROLLBACK TO SAVEPOINT recover_expired_job",
			); rollbackErr != nil {
				return 0, errors.Join(err, rollbackErr)
			}
			if quarantineErr := quarantineExpiredJobTx(
				ctx, transaction, job, sampleRetentionMicros,
			); quarantineErr != nil {
				return 0, errors.Join(err, quarantineErr)
			}
		}
		if useSavepoint {
			if _, err := transaction.ExecContext(ctx, "RELEASE SAVEPOINT recover_expired_job"); err != nil {
				return 0, fmt.Errorf("release expired job recovery savepoint: %w", err)
			}
		}
	}
	if err := transaction.Commit(); err != nil {
		return 0, fmt.Errorf("commit expired lease recovery: %w", err)
	}
	return len(jobs), nil
}

func (r *MySQLRepository) quarantineExpiredJob(
	ctx context.Context,
	job expiredJob,
	sampleRetentionMicros int64,
) error {
	transaction, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin expired job quarantine: %w", err)
	}
	defer transaction.Rollback()
	if err := quarantineExpiredJobTx(
		ctx, transaction, job, sampleRetentionMicros,
	); err != nil {
		return err
	}
	if err := transaction.Commit(); err != nil {
		return fmt.Errorf("commit expired job quarantine: %w", err)
	}
	return nil
}

func quarantineExpiredJobTx(
	ctx context.Context,
	transaction *sql.Tx,
	job expiredJob,
	sampleRetentionMicros int64,
) error {
	result, err := transaction.ExecContext(ctx, `
UPDATE jobs
SET status = 'failed',
    lease_owner = NULL,
    lease_until = NULL,
    heartbeat_at = NULL,
    completed_at = UTC_TIMESTAMP(6),
    error_code = 'lease_recovery_inconsistent',
    error_message = 'The expired worker lease had inconsistent durable state.'
WHERE id = ?
  AND fencing_token = ?
  AND (
      (status IN ('leased', 'running') AND lease_until <= UTC_TIMESTAMP(6))
      OR (
          status = 'cancel_requested'
          AND (lease_until IS NULL OR lease_until <= UTC_TIMESTAMP(6))
      )
  )`, job.ID, job.FencingToken)
	if err != nil {
		return fmt.Errorf("quarantine inconsistent expired job: %w", err)
	}
	if err := requireOne(
		result, ErrInconsistentState, "inspect inconsistent expired job quarantine",
	); err != nil {
		return err
	}
	// The job/fence pair is authoritative even if corrupt payload or related
	// rows made the normal pool calculation impossible. Release every slot it
	// owns so one poison record cannot permanently block the global heavy gate.
	if _, err := transaction.ExecContext(ctx, `
UPDATE job_resource_slots
SET job_id = NULL,
    job_fencing_token = NULL,
    lease_owner = NULL,
    acquired_at = NULL
WHERE job_id = ? AND job_fencing_token = ?`, job.ID, job.FencingToken); err != nil {
		return fmt.Errorf("release inconsistent expired job slots: %w", err)
	}
	if job.Kind != KindScan && job.Kind != KindTrivy {
		return nil
	}
	if job.TaskAttemptID.Valid && job.TaskAttemptID.Int64 > 0 {
		if _, err := transaction.ExecContext(ctx, `
UPDATE task_attempts
SET status = 'failed', completed_at = UTC_TIMESTAMP(6),
    error_code = 'lease_recovery_inconsistent',
    error_message = 'The expired worker lease had inconsistent durable state.'
WHERE id = ? AND task_id = ? AND fencing_token = ?
  AND status IN ('queued', 'running')`,
			job.TaskAttemptID.Int64, job.TaskID, job.FencingToken,
		); err != nil {
			return fmt.Errorf("fail inconsistent expired task attempt: %w", err)
		}
	}
	if _, err := transaction.ExecContext(ctx, `
UPDATE tasks
SET status = 'FAILED', stage = NULL, completed_at = UTC_TIMESTAMP(6),
    error_code = 'lease_recovery_inconsistent',
    error_message = 'The expired worker lease had inconsistent durable state.',
    sample_expires_at = CASE
        WHEN sample_deleted_at IS NULL AND deleted_at IS NULL
        THEN GREATEST(
            sample_expires_at,
            DATE_ADD(UTC_TIMESTAMP(6), INTERVAL ? MICROSECOND)
        )
        ELSE sample_expires_at
    END,
    event_sequence = event_sequence + 1
WHERE id = ?
  AND status NOT IN ('SUCCEEDED', 'PARTIAL_SUCCEEDED', 'FAILED', 'CANCELLED', 'DELETED')`,
		sampleRetentionMicros, job.TaskID,
	); err != nil {
		return fmt.Errorf("fail inconsistent expired task: %w", err)
	}
	return nil
}

func recoverExpiredJob(
	ctx context.Context,
	transaction *sql.Tx,
	job expiredJob,
	retryDelayMicros int64,
	sampleRetentionMicros int64,
) error {
	if job.Status == "cancel_requested" {
		return recoverCancelledJob(
			ctx, transaction, job, sampleRetentionMicros,
		)
	}
	if job.Kind == KindCAnalysis {
		finalized, err := recoverTerminalCAnalysisJob(ctx, transaction, job)
		if err != nil {
			return err
		}
		if finalized {
			return nil
		}
	}
	if job.Kind == KindJavaAnalysis {
		finalized, err := recoverTerminalJavaAnalysisJob(ctx, transaction, job)
		if err != nil {
			return err
		}
		if finalized {
			return nil
		}
	}
	retry := job.Attempt < job.MaxAttempts
	status := "failed"
	if retry {
		status = "queued"
	}
	var result sql.Result
	var err error
	if retry {
		result, err = transaction.ExecContext(ctx, `
UPDATE jobs
SET status = 'queued',
    available_at = DATE_ADD(UTC_TIMESTAMP(6), INTERVAL ? MICROSECOND),
    lease_owner = NULL,
    lease_until = NULL,
    heartbeat_at = NULL,
    started_at = NULL,
    completed_at = NULL,
    error_code = 'lease_expired',
    error_message = 'The worker lease expired.'
WHERE id = ?
  AND fencing_token = ?
  AND status IN ('leased', 'running')
  AND lease_until <= UTC_TIMESTAMP(6)`,
			retryDelayMicros, job.ID, job.FencingToken,
		)
	} else {
		result, err = transaction.ExecContext(ctx, `
UPDATE jobs
SET status = 'failed',
    lease_owner = NULL,
    lease_until = NULL,
    heartbeat_at = NULL,
    completed_at = UTC_TIMESTAMP(6),
    error_code = 'lease_expired',
    error_message = 'The worker lease expired after the final attempt.'
WHERE id = ?
  AND fencing_token = ?
  AND status IN ('leased', 'running')
  AND lease_until <= UTC_TIMESTAMP(6)`,
			job.ID, job.FencingToken,
		)
	}
	if err != nil {
		return fmt.Errorf("recover expired job: %w", err)
	}
	if err := requireOne(result, ErrInconsistentState, "inspect expired job recovery"); err != nil {
		return err
	}
	if err := releaseRecoveredResourceSlots(
		ctx,
		transaction,
		job,
	); err != nil {
		return err
	}
	if job.Kind == KindCAnalysis {
		return recoverExpiredCAnalysisJob(ctx, transaction, job, retry)
	}
	if job.Kind == KindJavaAnalysis {
		return recoverExpiredJavaAnalysisJob(ctx, transaction, job, retry)
	}
	if job.Kind == KindTrivy {
		return recoverExpiredTrivyJob(
			ctx, transaction, job, retry, sampleRetentionMicros,
		)
	}
	if job.Kind != KindScan {
		return nil
	}
	if !job.TaskAttemptID.Valid || job.TaskAttemptID.Int64 <= 0 {
		return ErrInconsistentState
	}
	attemptResult, err := transaction.ExecContext(ctx, `
UPDATE task_attempts
SET status = ?,
    started_at = CASE WHEN ? = 'queued' THEN NULL ELSE started_at END,
    completed_at = CASE WHEN ? = 'failed' THEN UTC_TIMESTAMP(6) ELSE NULL END,
    error_code = 'lease_expired',
    error_message = ?
WHERE id = ? AND task_id = ? AND fencing_token = ?
  AND status IN ('queued', 'running')`,
		status, status, status,
		expiredMessage(retry),
		job.TaskAttemptID.Int64, job.TaskID, job.FencingToken,
	)
	if err != nil {
		return fmt.Errorf("recover expired task attempt: %w", err)
	}
	if err := requireOne(
		attemptResult, ErrInconsistentState, "inspect expired task attempt recovery",
	); err != nil {
		return err
	}
	taskStatus := "FAILED"
	if retry {
		taskStatus = "QUEUED"
	}
	taskResult, err := transaction.ExecContext(ctx, `
UPDATE tasks
SET status = ?,
    stage = NULL,
    error_code = 'lease_expired',
    error_message = ?,
    completed_at = CASE WHEN ? = 'FAILED' THEN UTC_TIMESTAMP(6) ELSE NULL END,
    sample_expires_at = CASE
        WHEN ? = 'FAILED'
         AND sample_deleted_at IS NULL
         AND deleted_at IS NULL
        THEN GREATEST(
            sample_expires_at,
            DATE_ADD(UTC_TIMESTAMP(6), INTERVAL ? MICROSECOND)
        )
        ELSE sample_expires_at
    END,
    event_sequence = event_sequence + 1
WHERE id = ?
  AND status NOT IN ('SUCCEEDED', 'PARTIAL_SUCCEEDED', 'FAILED', 'CANCELLED', 'DELETED')`,
		taskStatus, expiredMessage(retry), taskStatus,
		taskStatus, sampleRetentionMicros, job.TaskID,
	)
	if err != nil {
		return fmt.Errorf("recover expired scan task: %w", err)
	}
	if err := requireOne(
		taskResult, ErrInconsistentState, "inspect expired scan task recovery",
	); err != nil {
		return err
	}
	return taskevent.AppendCurrentState(
		ctx, transaction, job.TaskID,
		"task.status_changed", "Task recovered after a worker lease expired.",
	)
}

// C analysis publishes its immutable result before the generic queue finish.
// If that final queue write was interrupted, preserve the published result and
// complete the expired job instead of re-running (or stranding) the analysis.
func recoverTerminalCAnalysisJob(
	ctx context.Context,
	transaction *sql.Tx,
	job expiredJob,
) (bool, error) {
	var runStatus, analyzerStatus string
	var errorCode, errorMessage sql.NullString
	err := transaction.QueryRowContext(ctx, `
SELECT analysis.status, analyzer.status,
       analysis.error_code, analysis.error_message
FROM c_analysis_runs analysis
JOIN analyzer_runs analyzer
  ON analyzer.task_id = analysis.task_id AND analyzer.id = analysis.id
WHERE analysis.task_id = ? AND analysis.job_id = ?
FOR UPDATE`, job.TaskID, job.ID).Scan(
		&runStatus, &analyzerStatus, &errorCode, &errorMessage,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return false, ErrInconsistentState
	}
	if err != nil {
		return false, fmt.Errorf("read expired C analysis state: %w", err)
	}
	jobStatus := ""
	switch runStatus {
	case "queued", "running", "cancel_requested":
		return false, nil
	case "succeeded", "partial":
		if analyzerStatus != runStatus || errorCode.Valid || errorMessage.Valid {
			return false, ErrInconsistentState
		}
		jobStatus = "succeeded"
	case "failed":
		if analyzerStatus != "failed" || !errorCode.Valid || !errorMessage.Valid {
			return false, ErrInconsistentState
		}
		jobStatus = "failed"
	case "cancelled":
		if analyzerStatus != "cancelled" || errorCode.Valid || errorMessage.Valid {
			return false, ErrInconsistentState
		}
		jobStatus = "cancelled"
	default:
		return false, ErrInconsistentState
	}
	var storedCode, storedMessage any
	if jobStatus == "failed" {
		storedCode, storedMessage = errorCode.String, errorMessage.String
	}
	result, err := transaction.ExecContext(ctx, `
UPDATE jobs
SET status = ?,
    lease_owner = NULL,
    lease_until = NULL,
    heartbeat_at = NULL,
    completed_at = UTC_TIMESTAMP(6),
    error_code = ?,
    error_message = ?
WHERE id = ? AND task_id = ? AND kind = 'c_analysis'
  AND fencing_token = ?
  AND status IN ('leased', 'running')
  AND lease_until <= UTC_TIMESTAMP(6)`,
		jobStatus, storedCode, storedMessage,
		job.ID, job.TaskID, job.FencingToken,
	)
	if err != nil {
		return false, fmt.Errorf("finish published C analysis job: %w", err)
	}
	if err := requireOne(
		result, ErrInconsistentState,
		"inspect published C analysis job recovery",
	); err != nil {
		return false, err
	}
	if err := releaseRecoveredResourceSlots(ctx, transaction, job); err != nil {
		return false, err
	}
	return true, nil
}

// Java analysis also publishes before the generic queue finish. Recover the
// final job state without running the immutable source project a second time.
func recoverTerminalJavaAnalysisJob(
	ctx context.Context,
	transaction *sql.Tx,
	job expiredJob,
) (bool, error) {
	var runStatus, analyzerStatus string
	var errorCode, errorMessage sql.NullString
	err := transaction.QueryRowContext(ctx, `
SELECT analysis.status, analyzer.status,
       analysis.error_code, analysis.error_message
FROM java_analysis_runs analysis
JOIN analyzer_runs analyzer
  ON analyzer.task_id = analysis.task_id AND analyzer.id = analysis.id
WHERE analysis.task_id = ? AND analysis.job_id = ?
FOR UPDATE`, job.TaskID, job.ID).Scan(
		&runStatus, &analyzerStatus, &errorCode, &errorMessage,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return false, ErrInconsistentState
	}
	if err != nil {
		return false, fmt.Errorf("read expired Java analysis state: %w", err)
	}
	jobStatus := ""
	switch runStatus {
	case "queued", "running", "cancel_requested":
		return false, nil
	case "succeeded", "partial":
		if analyzerStatus != runStatus || errorCode.Valid || errorMessage.Valid {
			return false, ErrInconsistentState
		}
		jobStatus = "succeeded"
	case "failed":
		if analyzerStatus != "failed" || !errorCode.Valid || !errorMessage.Valid {
			return false, ErrInconsistentState
		}
		jobStatus = "failed"
	case "cancelled":
		if analyzerStatus != "cancelled" || errorCode.Valid || errorMessage.Valid {
			return false, ErrInconsistentState
		}
		jobStatus = "cancelled"
	default:
		return false, ErrInconsistentState
	}
	var storedCode, storedMessage any
	if jobStatus == "failed" {
		storedCode, storedMessage = errorCode.String, errorMessage.String
	}
	result, err := transaction.ExecContext(ctx, `
UPDATE jobs
SET status = ?, lease_owner = NULL, lease_until = NULL,
    heartbeat_at = NULL, completed_at = UTC_TIMESTAMP(6),
    error_code = ?, error_message = ?
WHERE id = ? AND task_id = ? AND kind = 'java_analysis'
  AND fencing_token = ? AND status IN ('leased', 'running')
  AND lease_until <= UTC_TIMESTAMP(6)`,
		jobStatus, storedCode, storedMessage,
		job.ID, job.TaskID, job.FencingToken,
	)
	if err != nil {
		return false, fmt.Errorf("finish published Java analysis job: %w", err)
	}
	if err := requireOne(
		result, ErrInconsistentState,
		"inspect published Java analysis job recovery",
	); err != nil {
		return false, err
	}
	if err := releaseRecoveredResourceSlots(ctx, transaction, job); err != nil {
		return false, err
	}
	return true, nil
}

func recoverExpiredTrivyJob(
	ctx context.Context,
	transaction *sql.Tx,
	job expiredJob,
	retry bool,
	sampleRetentionMicros int64,
) error {
	if !job.TaskAttemptID.Valid || job.TaskAttemptID.Int64 <= 0 {
		return ErrInconsistentState
	}
	if retry {
		attemptResult, err := transaction.ExecContext(ctx, `
UPDATE task_attempts
SET error_code = 'lease_expired',
    error_message = ?
WHERE id = ?
  AND task_id = ?
  AND fencing_token = ?
  AND status = 'running'`,
			expiredMessage(true), job.TaskAttemptID.Int64,
			job.TaskID, job.FencingToken,
		)
		if err != nil {
			return fmt.Errorf("recover expired Trivy task attempt: %w", err)
		}
		if err := requireOne(
			attemptResult, ErrInconsistentState,
			"inspect expired Trivy task attempt recovery",
		); err != nil {
			return err
		}
		taskResult, err := transaction.ExecContext(ctx, `
UPDATE tasks
SET status = 'SCANNING',
    stage = 'SCANNING',
	progress_basis_points = ?,
    error_code = 'lease_expired',
    error_message = ?,
    completed_at = NULL,
    event_sequence = event_sequence + 1
WHERE id = ? AND status IN ('SCANNING', 'REPORTING')`,
			taskprogress.ScanningStartBasisPoints,
			expiredMessage(true), job.TaskID,
		)
		if err != nil {
			return fmt.Errorf("recover expired Trivy task: %w", err)
		}
		if err := requireOne(
			taskResult, ErrInconsistentState,
			"inspect expired Trivy task recovery",
		); err != nil {
			return err
		}
		return taskevent.AppendCurrentState(
			ctx, transaction, job.TaskID,
			"task.status_changed",
			"Container vulnerability scan recovered after a worker lease expired.",
		)
	}

	attemptResult, err := transaction.ExecContext(ctx, `
UPDATE task_attempts
SET status = 'failed',
    completed_at = UTC_TIMESTAMP(6),
    error_code = 'lease_expired',
    error_message = ?
WHERE id = ?
  AND task_id = ?
  AND fencing_token = ?
  AND status = 'running'`,
		expiredMessage(false), job.TaskAttemptID.Int64,
		job.TaskID, job.FencingToken,
	)
	if err != nil {
		return fmt.Errorf("fail expired Trivy task attempt: %w", err)
	}
	if err := requireOne(
		attemptResult, ErrInconsistentState,
		"inspect failed expired Trivy task attempt",
	); err != nil {
		return err
	}
	taskResult, err := transaction.ExecContext(ctx, `
UPDATE tasks
SET status = 'FAILED',
    stage = NULL,
    progress_basis_points = 0,
    error_code = 'lease_expired',
    error_message = ?,
    completed_at = UTC_TIMESTAMP(6),
    sample_expires_at = CASE
        WHEN sample_deleted_at IS NULL AND deleted_at IS NULL
        THEN GREATEST(
            sample_expires_at,
            DATE_ADD(UTC_TIMESTAMP(6), INTERVAL ? MICROSECOND)
        )
        ELSE sample_expires_at
    END,
    event_sequence = event_sequence + 1
WHERE id = ? AND status IN ('SCANNING', 'REPORTING')`,
		expiredMessage(false), sampleRetentionMicros, job.TaskID,
	)
	if err != nil {
		return fmt.Errorf("fail expired Trivy task: %w", err)
	}
	if err := requireOne(
		taskResult, ErrInconsistentState,
		"inspect failed expired Trivy task",
	); err != nil {
		return err
	}
	return taskevent.AppendCurrentState(
		ctx, transaction, job.TaskID,
		"task.status_changed",
		"Container vulnerability scan failed after its final worker lease expired.",
	)
}

func recoverExpiredCAnalysisJob(
	ctx context.Context,
	transaction *sql.Tx,
	job expiredJob,
	retry bool,
) error {
	if retry {
		result, err := transaction.ExecContext(ctx, `
UPDATE c_analysis_runs analysis
JOIN analyzer_runs analyzer
  ON analyzer.task_id = analysis.task_id AND analyzer.id = analysis.id
SET analysis.status = 'queued',
    analysis.started_at = NULL,
    analysis.completed_at = NULL,
    analysis.error_code = NULL,
    analysis.error_message = NULL,
    analyzer.status = 'queued',
    analyzer.started_at = NULL,
    analyzer.completed_at = NULL,
    analyzer.error_code = NULL,
    analyzer.error_message = NULL
WHERE analysis.task_id = ? AND analysis.job_id = ?
	  AND analysis.status = analyzer.status
	  AND analysis.status IN ('queued', 'running')`,
			job.TaskID, job.ID,
		)
		if err != nil {
			return fmt.Errorf("requeue expired C analysis run: %w", err)
		}
		mutated, err := recoveredAnalysisMutation(result)
		if err != nil {
			return fmt.Errorf("inspect requeued expired C analysis run: %w", err)
		}
		if mutated {
			if err := report.InvalidateTaskSourceAnalysisReports(
				ctx, transaction, job.TaskID,
			); err != nil {
				return fmt.Errorf(
					"invalidate reports after requeuing expired C analysis: %w", err,
				)
			}
		}
		return nil
	}
	result, err := transaction.ExecContext(ctx, `
UPDATE c_analysis_runs analysis
JOIN analyzer_runs analyzer
  ON analyzer.task_id = analysis.task_id AND analyzer.id = analysis.id
SET analysis.status = 'failed',
    analysis.error_code = 'lease_expired',
    analysis.error_message = 'The worker lease expired after the final attempt.',
    analysis.completed_at = UTC_TIMESTAMP(6),
    analyzer.status = 'failed',
    analyzer.error_code = 'lease_expired',
    analyzer.error_message = 'The worker lease expired after the final attempt.',
    analyzer.completed_at = UTC_TIMESTAMP(6)
WHERE analysis.task_id = ? AND analysis.job_id = ?
	  AND analysis.status = analyzer.status
	  AND analysis.status IN ('queued', 'running')`,
		job.TaskID, job.ID,
	)
	if err != nil {
		return fmt.Errorf("fail expired C analysis run: %w", err)
	}
	if err := requireRecoveredAnalysisMutation(
		result, ErrInconsistentState,
		"inspect failed expired C analysis run",
	); err != nil {
		return err
	}
	if err := report.InvalidateTaskSourceAnalysisReports(
		ctx, transaction, job.TaskID,
	); err != nil {
		return fmt.Errorf(
			"invalidate reports after failing expired C analysis: %w", err,
		)
	}
	return nil
}

func recoverExpiredJavaAnalysisJob(
	ctx context.Context,
	transaction *sql.Tx,
	job expiredJob,
	retry bool,
) error {
	if retry {
		result, err := transaction.ExecContext(ctx, `
UPDATE java_analysis_runs analysis
JOIN analyzer_runs analyzer
  ON analyzer.task_id = analysis.task_id AND analyzer.id = analysis.id
SET analysis.status = 'queued', analysis.bundle_sha256 = NULL,
    analysis.started_at = NULL, analysis.completed_at = NULL,
    analysis.ruleset_version = NULL, analysis.analyzed_files = 0,
    analysis.parsed_files = 0, analysis.recovered_files = 0,
    analysis.failed_files = 0, analysis.finding_count = 0,
    analysis.diagnostic_count = 0, analysis.low_count = 0,
    analysis.medium_count = 0, analysis.high_count = 0,
    analysis.critical_count = 0, analysis.findings_truncated = FALSE,
    analysis.diagnostics_truncated = FALSE,
    analysis.error_code = NULL, analysis.error_message = NULL,
    analyzer.status = 'queued', analyzer.started_at = NULL,
    analyzer.completed_at = NULL, analyzer.error_code = NULL,
    analyzer.error_message = NULL
WHERE analysis.task_id = ? AND analysis.job_id = ?
  AND analysis.status = analyzer.status
  AND analysis.status IN ('queued', 'running')`,
			job.TaskID, job.ID,
		)
		if err != nil {
			return fmt.Errorf("requeue expired Java analysis run: %w", err)
		}
		mutated, err := recoveredAnalysisMutation(result)
		if err != nil {
			return fmt.Errorf("inspect requeued expired Java analysis run: %w", err)
		}
		if mutated {
			if err := report.InvalidateTaskSourceAnalysisReports(
				ctx, transaction, job.TaskID,
			); err != nil {
				return fmt.Errorf(
					"invalidate reports after requeuing expired Java analysis: %w", err,
				)
			}
		}
		return nil
	}
	result, err := transaction.ExecContext(ctx, `
UPDATE java_analysis_runs analysis
JOIN analyzer_runs analyzer
  ON analyzer.task_id = analysis.task_id AND analyzer.id = analysis.id
SET analysis.status = 'failed',
    analysis.error_code = 'lease_expired',
    analysis.error_message = 'The worker lease expired after the final attempt.',
    analysis.completed_at = UTC_TIMESTAMP(6),
    analyzer.status = 'failed', analyzer.error_code = 'lease_expired',
    analyzer.error_message = 'The worker lease expired after the final attempt.',
    analyzer.completed_at = UTC_TIMESTAMP(6)
WHERE analysis.task_id = ? AND analysis.job_id = ?
  AND analysis.status = analyzer.status
  AND analysis.status IN ('queued', 'running')`,
		job.TaskID, job.ID,
	)
	if err != nil {
		return fmt.Errorf("fail expired Java analysis run: %w", err)
	}
	if err := requireRecoveredAnalysisMutation(
		result, ErrInconsistentState,
		"inspect failed expired Java analysis run",
	); err != nil {
		return err
	}
	if err := report.InvalidateTaskSourceAnalysisReports(
		ctx, transaction, job.TaskID,
	); err != nil {
		return fmt.Errorf(
			"invalidate reports after failing expired Java analysis: %w", err,
		)
	}
	return nil
}

func recoverCancelledJob(
	ctx context.Context,
	transaction *sql.Tx,
	job expiredJob,
	sampleRetentionMicros int64,
) error {
	result, err := transaction.ExecContext(ctx, `
UPDATE jobs
SET status = 'cancelled',
    lease_owner = NULL,
    lease_until = NULL,
    heartbeat_at = NULL,
    completed_at = UTC_TIMESTAMP(6),
    error_code = NULL,
    error_message = NULL
WHERE id = ?
  AND fencing_token = ?
  AND status = 'cancel_requested'
  AND (lease_until IS NULL OR lease_until <= UTC_TIMESTAMP(6))`,
		job.ID, job.FencingToken,
	)
	if err != nil {
		return fmt.Errorf("finalize cancelled job: %w", err)
	}
	if err := requireOne(result, ErrInconsistentState, "inspect cancelled job recovery"); err != nil {
		return err
	}
	if err := releaseRecoveredResourceSlots(
		ctx,
		transaction,
		job,
	); err != nil {
		return err
	}
	if job.Kind == KindCAnalysis {
		analysisResult, err := transaction.ExecContext(ctx, `
UPDATE c_analysis_runs analysis
JOIN analyzer_runs analyzer
  ON analyzer.task_id = analysis.task_id AND analyzer.id = analysis.id
SET analysis.status = 'cancelled',
    analysis.error_code = NULL,
    analysis.error_message = NULL,
    analysis.completed_at = UTC_TIMESTAMP(6),
    analyzer.status = 'cancelled',
    analyzer.error_code = NULL,
    analyzer.error_message = NULL,
    analyzer.completed_at = UTC_TIMESTAMP(6)
WHERE analysis.task_id = ? AND analysis.job_id = ?
	  AND analysis.status IN ('queued', 'running', 'cancel_requested')
	  AND analyzer.status IN ('queued', 'running')`, job.TaskID, job.ID)
		if err != nil {
			return fmt.Errorf("finalize cancelled C analysis run: %w", err)
		}
		mutated, err := recoveredAnalysisMutation(analysisResult)
		if err != nil {
			return fmt.Errorf("inspect cancelled C analysis run: %w", err)
		}
		if mutated {
			if err := report.InvalidateTaskSourceAnalysisReports(
				ctx, transaction, job.TaskID,
			); err != nil {
				return fmt.Errorf(
					"invalidate reports after recovering cancelled C analysis: %w", err,
				)
			}
		}
		return nil
	}
	if job.Kind == KindJavaAnalysis {
		analysisResult, err := transaction.ExecContext(ctx, `
UPDATE java_analysis_runs analysis
JOIN analyzer_runs analyzer
  ON analyzer.task_id = analysis.task_id AND analyzer.id = analysis.id
SET analysis.status = 'cancelled', analysis.error_code = NULL,
    analysis.error_message = NULL,
    analysis.completed_at = UTC_TIMESTAMP(6),
    analyzer.status = 'cancelled', analyzer.error_code = NULL,
    analyzer.error_message = NULL,
    analyzer.completed_at = UTC_TIMESTAMP(6)
WHERE analysis.task_id = ? AND analysis.job_id = ?
	  AND analysis.status IN ('queued', 'running', 'cancel_requested')
	  AND analyzer.status IN ('queued', 'running')`, job.TaskID, job.ID)
		if err != nil {
			return fmt.Errorf("finalize cancelled Java analysis run: %w", err)
		}
		mutated, err := recoveredAnalysisMutation(analysisResult)
		if err != nil {
			return fmt.Errorf("inspect cancelled Java analysis run: %w", err)
		}
		if mutated {
			if err := report.InvalidateTaskSourceAnalysisReports(
				ctx, transaction, job.TaskID,
			); err != nil {
				return fmt.Errorf(
					"invalidate reports after recovering cancelled Java analysis: %w", err,
				)
			}
		}
		return nil
	}
	if job.Kind == KindScan || job.Kind == KindTrivy {
		if !job.TaskAttemptID.Valid || job.TaskAttemptID.Int64 <= 0 {
			return ErrInconsistentState
		}
		attemptResult, err := transaction.ExecContext(ctx, `
UPDATE task_attempts
SET status = 'cancelled',
    completed_at = UTC_TIMESTAMP(6),
    error_code = NULL,
    error_message = NULL
WHERE id = ? AND task_id = ? AND fencing_token = ?
  AND status IN ('queued', 'running')`,
			job.TaskAttemptID.Int64, job.TaskID, job.FencingToken,
		)
		if err != nil {
			return fmt.Errorf("finalize cancelled task attempt: %w", err)
		}
		if err := requireOne(
			attemptResult, ErrInconsistentState, "inspect cancelled task attempt recovery",
		); err != nil {
			return err
		}
	}

	var remaining bool
	if err := transaction.QueryRowContext(ctx, `
SELECT EXISTS (
    SELECT 1
    FROM jobs
    WHERE task_id = ? AND status = 'cancel_requested'
)`, job.TaskID).Scan(&remaining); err != nil {
		return fmt.Errorf("check remaining task cancellations: %w", err)
	}
	if remaining {
		return nil
	}
	var taskStatus string
	err = transaction.QueryRowContext(ctx, `
SELECT status
FROM tasks
WHERE id = ?
FOR UPDATE`, job.TaskID).Scan(&taskStatus)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrInconsistentState
	}
	if err != nil {
		return fmt.Errorf("lock cancelled task state: %w", err)
	}
	// Deletion owns the task's terminal transition. The cancelled job,
	// attempt, and resource slots still commit so retention cleanup can
	// progress without leaving capacity stranded.
	if taskStatus == "DELETING" {
		return nil
	}
	if taskStatus != "CANCEL_REQUESTED" {
		return ErrInconsistentState
	}
	taskResult, err := transaction.ExecContext(ctx, `
UPDATE tasks
SET status = 'CANCELLED',
    stage = NULL,
    completed_at = UTC_TIMESTAMP(6),
    sample_expires_at = CASE
        WHEN sample_deleted_at IS NULL AND deleted_at IS NULL
        THEN GREATEST(
            sample_expires_at,
            DATE_ADD(UTC_TIMESTAMP(6), INTERVAL ? MICROSECOND)
        )
        ELSE sample_expires_at
    END,
    error_code = NULL,
    error_message = NULL,
    event_sequence = event_sequence + 1
WHERE id = ? AND status = 'CANCEL_REQUESTED'`,
		sampleRetentionMicros, job.TaskID,
	)
	if err != nil {
		return fmt.Errorf("finalize cancelled task: %w", err)
	}
	if err := requireOne(
		taskResult, ErrInconsistentState, "inspect finalized cancelled task",
	); err != nil {
		return err
	}
	return taskevent.AppendCurrentState(
		ctx, transaction, job.TaskID,
		"task.status_changed", "Task cancellation completed.",
	)
}

func recoveredAnalysisMutation(result sql.Result) (bool, error) {
	affected, err := result.RowsAffected()
	if err != nil {
		return false, err
	}
	if affected != 0 && affected != 2 {
		return false, ErrInconsistentState
	}
	return affected == 2, nil
}

func requireRecoveredAnalysisMutation(
	result sql.Result,
	zeroError error,
	operation string,
) error {
	affected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("%s: %w", operation, err)
	}
	if affected == 0 {
		return zeroError
	}
	if affected != 2 {
		return ErrInconsistentState
	}
	return nil
}

func releaseRecoveredResourceSlots(
	ctx context.Context,
	transaction *sql.Tx,
	job expiredJob,
) error {
	workerKind := Kind("")
	if job.Kind == KindDecompile {
		var payload []byte
		if err := transaction.QueryRowContext(ctx, `
SELECT payload
FROM jobs
WHERE id = ? AND fencing_token = ?
FOR UPDATE`, job.ID, job.FencingToken).Scan(&payload); err != nil {
			return fmt.Errorf("read recovered decompile job payload: %w", err)
		}
		var err error
		workerKind, err = decompilePayloadWorkerKind(payload)
		if err != nil {
			return err
		}
	}
	pools, err := resourcePoolsForJob(job.Kind, workerKind)
	if err != nil {
		return err
	}
	for _, pool := range pools {
		result, err := transaction.ExecContext(ctx, `
UPDATE job_resource_slots
SET job_id = NULL,
    job_fencing_token = NULL,
    lease_owner = NULL,
    acquired_at = NULL
WHERE pool = ?
  AND job_id = ?
  AND job_fencing_token = ?`,
			pool,
			job.ID,
			job.FencingToken,
		)
		if err != nil {
			return fmt.Errorf(
				"release recovered %s resource slot: %w",
				pool,
				err,
			)
		}
		if err := requireOne(
			result,
			ErrInconsistentState,
			"inspect recovered resource slot release",
		); err != nil {
			return err
		}
	}
	return nil
}

func expiredMessage(retry bool) string {
	if retry {
		return "The worker lease expired; the job was requeued."
	}
	return "The worker lease expired after the final attempt."
}

func requireOne(result sql.Result, zeroError error, operation string) error {
	affected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("%s: %w", operation, err)
	}
	if affected == 0 {
		return zeroError
	}
	if affected != 1 {
		return ErrInconsistentState
	}
	return nil
}

var _ Repository = (*MySQLRepository)(nil)

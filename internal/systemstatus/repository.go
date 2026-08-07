package systemstatus

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
)

type Repository interface {
	TaskCounts(context.Context) (map[string]int64, error)
	Queue(context.Context) (QueueRecord, error)
	TrivyDatabaseBundle(context.Context) (*DatabaseBundleRecord, error)
	ObservedAnalyzers(context.Context) ([]ObservedAnalyzer, error)
	WorkerReadiness(context.Context) ([]WorkerReadinessRecord, error)
	OperationalMetrics(context.Context) (OperationalMetricsRecord, error)
}

func (r *MySQLRepository) WorkerReadiness(
	ctx context.Context,
) ([]WorkerReadinessRecord, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	rows, err := r.db.QueryContext(ctx, `
SELECT worker_owner, worker_kind, analyzer_name, analyzer_version,
       COALESCE(runtime_name, ''), COALESCE(runtime_version, ''), status,
       started_at, last_checked_at
FROM worker_readiness
ORDER BY last_checked_at DESC, worker_owner ASC
LIMIT 256`)
	if err != nil {
		return nil, fmt.Errorf("query worker readiness: %w", err)
	}
	defer rows.Close()
	records := make([]WorkerReadinessRecord, 0)
	for rows.Next() {
		var record WorkerReadinessRecord
		if err := rows.Scan(
			&record.Owner,
			&record.WorkerKind,
			&record.AnalyzerName,
			&record.AnalyzerVersion,
			&record.RuntimeName,
			&record.RuntimeVersion,
			&record.Status,
			&record.StartedAt,
			&record.LastCheckedAt,
		); err != nil {
			return nil, fmt.Errorf("scan worker readiness: %w", err)
		}
		records = append(records, record)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate worker readiness: %w", err)
	}
	return records, nil
}

type MySQLRepository struct {
	db *sql.DB
}

func NewMySQLRepository(db *sql.DB) *MySQLRepository {
	return &MySQLRepository{db: db}
}

func (r *MySQLRepository) TaskCounts(
	ctx context.Context,
) (map[string]int64, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	rows, err := r.db.QueryContext(ctx, `
SELECT status, COUNT(*)
FROM tasks
WHERE deleted_at IS NULL
GROUP BY status
ORDER BY status`)
	if err != nil {
		return nil, fmt.Errorf("query system task counts: %w", err)
	}
	defer rows.Close()

	counts := make(map[string]int64)
	for rows.Next() {
		var status string
		var count int64
		if err := rows.Scan(&status, &count); err != nil {
			return nil, fmt.Errorf("scan system task count: %w", err)
		}
		counts[status] = count
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate system task counts: %w", err)
	}
	return counts, nil
}

func (r *MySQLRepository) Queue(
	ctx context.Context,
) (QueueRecord, error) {
	if err := ctx.Err(); err != nil {
		return QueueRecord{}, err
	}
	var record QueueRecord
	var oldestHeartbeat sql.NullTime
	var latestHeartbeat sql.NullTime
	err := r.db.QueryRowContext(ctx, `
SELECT
    COALESCE(SUM(CASE WHEN job.status = 'queued' THEN 1 ELSE 0 END), 0),
    COALESCE(SUM(CASE
        WHEN job.status IN ('leased', 'running', 'cancel_requested')
         AND job.lease_owner IS NOT NULL
         AND job.lease_until > UTC_TIMESTAMP(6)
        THEN 1 ELSE 0 END), 0),
    COUNT(DISTINCT CASE
        WHEN job.status IN ('leased', 'running', 'cancel_requested')
         AND job.lease_owner IS NOT NULL
         AND job.lease_until > UTC_TIMESTAMP(6)
        THEN job.lease_owner END),
    MIN(CASE
        WHEN job.status IN ('leased', 'running', 'cancel_requested')
         AND job.lease_owner IS NOT NULL
         AND job.lease_until > UTC_TIMESTAMP(6)
        THEN job.heartbeat_at END),
    MAX(CASE
        WHEN job.status IN ('leased', 'running', 'cancel_requested')
         AND job.lease_owner IS NOT NULL
         AND job.lease_until > UTC_TIMESTAMP(6)
        THEN job.heartbeat_at END)
FROM jobs job
JOIN tasks task ON task.id = job.task_id
WHERE task.deleted_at IS NULL`).Scan(
		&record.Depth,
		&record.ObservedLeases,
		&record.ObservedOwners,
		&oldestHeartbeat,
		&latestHeartbeat,
	)
	if err != nil {
		return QueueRecord{}, fmt.Errorf("query system queue summary: %w", err)
	}
	if oldestHeartbeat.Valid {
		value := oldestHeartbeat.Time
		record.OldestHeartbeatAt = &value
	}
	if latestHeartbeat.Valid {
		value := latestHeartbeat.Time
		record.LatestHeartbeatAt = &value
	}

	rows, err := r.db.QueryContext(ctx, `
SELECT job.kind, COUNT(*)
FROM jobs job
JOIN tasks task ON task.id = job.task_id
WHERE task.deleted_at IS NULL
  AND job.status IN ('leased', 'running', 'cancel_requested')
  AND job.lease_owner IS NOT NULL
  AND job.lease_until > UTC_TIMESTAMP(6)
GROUP BY job.kind
ORDER BY job.kind`)
	if err != nil {
		return QueueRecord{}, fmt.Errorf("query system lease kinds: %w", err)
	}
	defer rows.Close()

	record.LeasesByKind = make(map[string]int64)
	for rows.Next() {
		var kind string
		var count int64
		if err := rows.Scan(&kind, &count); err != nil {
			return QueueRecord{}, fmt.Errorf("scan system lease kind: %w", err)
		}
		record.LeasesByKind[kind] = count
	}
	if err := rows.Err(); err != nil {
		return QueueRecord{}, fmt.Errorf("iterate system lease kinds: %w", err)
	}
	return record, nil
}

func (r *MySQLRepository) TrivyDatabaseBundle(
	ctx context.Context,
) (*DatabaseBundleRecord, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	var record DatabaseBundleRecord
	err := r.db.QueryRowContext(ctx, `
	SELECT id, version, generated_at, content_sha256, trivy_db_version,
	       trivy_java_db_version, registered_at
	FROM trivy_database_bundles
	ORDER BY registered_at DESC, id DESC
	LIMIT 1`).Scan(
		&record.ID,
		&record.Version,
		&record.GeneratedAt,
		&record.ContentSHA256,
		&record.TrivyDBVersion,
		&record.TrivyJavaDBVersion,
		&record.RegisteredAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("query Trivy database bundle: %w", err)
	}
	return &record, nil
}

func (r *MySQLRepository) ObservedAnalyzers(
	ctx context.Context,
) ([]ObservedAnalyzer, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	rows, err := r.db.QueryContext(ctx, `
SELECT analyzer_name, analyzer_version, created_at
FROM analyzer_runs
ORDER BY created_at DESC, id DESC
LIMIT 256`)
	if err != nil {
		return nil, fmt.Errorf("query observed analyzers: %w", err)
	}
	defer rows.Close()

	records := make([]ObservedAnalyzer, 0)
	seen := make(map[string]struct{})
	for rows.Next() {
		var record ObservedAnalyzer
		if err := rows.Scan(
			&record.Name,
			&record.Version,
			&record.LastCheckedAt,
		); err != nil {
			return nil, fmt.Errorf("scan observed analyzer: %w", err)
		}
		key := strings.ToLower(strings.TrimSpace(record.Name))
		if key == "" {
			continue
		}
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		records = append(records, record)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate observed analyzers: %w", err)
	}
	return records, nil
}

func (r *MySQLRepository) OperationalMetrics(
	ctx context.Context,
) (OperationalMetricsRecord, error) {
	if err := ctx.Err(); err != nil {
		return OperationalMetricsRecord{}, err
	}
	stageRows, err := r.db.QueryContext(ctx, `
WITH ordered_events AS (
    SELECT task_id,
           event_sequence,
           UPPER(stage) AS stage,
           created_at,
           LAG(UPPER(stage)) OVER (
               PARTITION BY task_id
               ORDER BY event_sequence
           ) AS previous_stage
    FROM task_events
    WHERE created_at >= DATE_SUB(UTC_TIMESTAMP(6), INTERVAL 168 HOUR)
      AND stage IS NOT NULL
),
stage_transitions AS (
    SELECT task_id, event_sequence, stage, created_at
    FROM ordered_events
    WHERE previous_stage IS NULL OR previous_stage <> stage
),
timed_stages AS (
    SELECT stage,
           created_at AS started_at,
           LEAD(created_at) OVER (
               PARTITION BY task_id
               ORDER BY event_sequence
           ) AS completed_at
    FROM stage_transitions
)
SELECT stage,
       COUNT(*) AS sample_count,
       CAST(ROUND(AVG(
           TIMESTAMPDIFF(MICROSECOND, started_at, completed_at)
       ) / 1000) AS UNSIGNED) AS average_duration_ms
FROM timed_stages
WHERE completed_at IS NOT NULL
  AND completed_at >= started_at
  AND stage IN (
      'VALIDATING', 'IDENTIFYING', 'EXTRACTING', 'INDEXING',
      'SCANNING', 'REPORTING'
  )
GROUP BY stage
ORDER BY FIELD(
    stage,
    'VALIDATING', 'IDENTIFYING', 'EXTRACTING', 'INDEXING',
    'SCANNING', 'REPORTING'
)`)
	if err != nil {
		return OperationalMetricsRecord{}, fmt.Errorf(
			"query task stage duration metrics: %w",
			err,
		)
	}

	record := OperationalMetricsRecord{
		StageDurations:       make([]StageDurationMetric, 0, 6),
		AnalyzerFailureRates: make([]AnalyzerFailureMetric, 0),
	}
	for stageRows.Next() {
		var metric StageDurationMetric
		if err := stageRows.Scan(
			&metric.Stage,
			&metric.SampleCount,
			&metric.AverageDurationMilliseconds,
		); err != nil {
			stageRows.Close()
			return OperationalMetricsRecord{}, fmt.Errorf(
				"scan task stage duration metric: %w",
				err,
			)
		}
		record.StageDurations = append(record.StageDurations, metric)
	}
	if err := stageRows.Err(); err != nil {
		stageRows.Close()
		return OperationalMetricsRecord{}, fmt.Errorf(
			"iterate task stage duration metrics: %w",
			err,
		)
	}
	if err := stageRows.Close(); err != nil {
		return OperationalMetricsRecord{}, fmt.Errorf(
			"close task stage duration metrics: %w",
			err,
		)
	}

	analyzerRows, err := r.db.QueryContext(ctx, `
SELECT analyzer_name,
       COUNT(*) AS total_runs,
       SUM(CASE
           WHEN status IN ('failed', 'timed_out') THEN 1
           ELSE 0
       END) AS failed_runs,
       CAST(ROUND(
           SUM(CASE
               WHEN status IN ('failed', 'timed_out') THEN 1
               ELSE 0
           END) * 10000 / COUNT(*)
       ) AS UNSIGNED) AS failure_rate_basis_points
FROM analyzer_runs
WHERE status IN (
    'succeeded', 'partial', 'failed', 'cancelled', 'timed_out'
)
  AND created_at >= DATE_SUB(UTC_TIMESTAMP(6), INTERVAL 168 HOUR)
GROUP BY analyzer_name
ORDER BY analyzer_name
LIMIT 32`)
	if err != nil {
		return OperationalMetricsRecord{}, fmt.Errorf(
			"query analyzer failure metrics: %w",
			err,
		)
	}
	defer analyzerRows.Close()
	for analyzerRows.Next() {
		var metric AnalyzerFailureMetric
		var basisPoints uint64
		if err := analyzerRows.Scan(
			&metric.Name,
			&metric.TotalRuns,
			&metric.FailedRuns,
			&basisPoints,
		); err != nil {
			return OperationalMetricsRecord{}, fmt.Errorf(
				"scan analyzer failure metric: %w",
				err,
			)
		}
		if basisPoints > 10_000 {
			return OperationalMetricsRecord{}, fmt.Errorf(
				"scan analyzer failure metric: invalid rate %d",
				basisPoints,
			)
		}
		metric.FailureRateBasisPoints = uint16(basisPoints)
		record.AnalyzerFailureRates = append(
			record.AnalyzerFailureRates,
			metric,
		)
	}
	if err := analyzerRows.Err(); err != nil {
		return OperationalMetricsRecord{}, fmt.Errorf(
			"iterate analyzer failure metrics: %w",
			err,
		)
	}
	return record, nil
}

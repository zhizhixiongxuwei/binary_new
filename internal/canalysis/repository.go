package canalysis

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"strconv"
	"strings"
	"time"

	"binaryscan/internal/report"
)

const jobPayloadSchemaVersion = "binaryscan-c-analysis-job/v1"

type RepositoryConfig struct {
	AnalyzerVersion string
	ReadyMaxAge     time.Duration
}

type MySQLRepository struct {
	db              *sql.DB
	analyzerVersion string
	readyMaxAge     time.Duration
}

func NewMySQLRepository(
	db *sql.DB,
	config RepositoryConfig,
) (*MySQLRepository, error) {
	if db == nil {
		return nil, errors.New("C analysis database is required")
	}
	if config.AnalyzerVersion == "" {
		config.AnalyzerVersion = AnalyzerVersion
	}
	if config.ReadyMaxAge == 0 {
		config.ReadyMaxAge = 30 * time.Second
	}
	if config.AnalyzerVersion != AnalyzerVersion ||
		config.ReadyMaxAge < time.Microsecond ||
		config.ReadyMaxAge > 24*time.Hour {
		return nil, errors.New("C analysis repository configuration is invalid")
	}
	return &MySQLRepository{
		db: db, analyzerVersion: config.AnalyzerVersion,
		readyMaxAge: config.ReadyMaxAge,
	}, nil
}

func (r *MySQLRepository) Create(
	ctx context.Context,
	record CreateRecord,
) (Run, bool, error) {
	if err := ctx.Err(); err != nil {
		return Run{}, false, err
	}
	if !validCreateRecord(record) {
		return Run{}, false, ErrInvalidInput
	}
	tx, err := r.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return Run{}, false, fmt.Errorf("begin C analysis creation: %w", err)
	}
	defer tx.Rollback()

	var taskStatus string
	var taskDeleted sql.NullTime
	err = tx.QueryRowContext(ctx, `
SELECT status, deleted_at
FROM tasks
WHERE id = ?
FOR UPDATE`, record.TaskID).Scan(&taskStatus, &taskDeleted)
	if errors.Is(err, sql.ErrNoRows) {
		return Run{}, false, ErrTaskNotFound
	}
	if err != nil {
		return Run{}, false, fmt.Errorf("lock C analysis task: %w", err)
	}
	if taskDeleted.Valid || !terminalTaskStatus(taskStatus) {
		return Run{}, false, ErrSourceUnavailable
	}

	var replayRunID, replayProjectID string
	err = tx.QueryRowContext(ctx, `
SELECT analysis.id, analysis.source_project_id
FROM jobs job
JOIN c_analysis_runs analysis
  ON analysis.task_id = job.task_id AND analysis.job_id = job.id
WHERE job.task_id = ?
  AND job.kind = 'c_analysis'
  AND job.idempotency_key = ?
LIMIT 1
FOR UPDATE`, record.TaskID, record.RequestKey).Scan(
		&replayRunID, &replayProjectID,
	)
	if err == nil {
		if replayProjectID != record.SourceProjectID {
			return Run{}, false, ErrIdempotencyConflict
		}
		value, err := scanRun(tx.QueryRowContext(
			ctx, runSelect+` WHERE analysis.task_id = ? AND analysis.id = ?`,
			record.TaskID, replayRunID,
		))
		if errors.Is(err, sql.ErrNoRows) {
			return Run{}, false, ErrProjectNotFound
		}
		if err != nil {
			return Run{}, false, fmt.Errorf("read replayed C analysis: %w", err)
		}
		if err := tx.Commit(); err != nil {
			return Run{}, false, fmt.Errorf("commit C analysis replay: %w", err)
		}
		return value, false, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return Run{}, false, fmt.Errorf("find C analysis replay: %w", err)
	}

	project, attemptID, fileNodeID, err := lockEligibleProject(
		ctx, tx, record.TaskID, record.SourceProjectID,
	)
	if err != nil {
		return Run{}, false, err
	}
	if project.CanonicalSizeBytes > uint64(MaxSourceBytes) ||
		len(project.Functions) == 0 || len(project.Functions) > MaxFunctions {
		return Run{}, false, ErrSourceUnavailable
	}

	var ready bool
	if err := tx.QueryRowContext(ctx, `
SELECT EXISTS (
    SELECT 1
    FROM worker_readiness
    WHERE worker_kind = 'c_analysis'
      AND analyzer_name = ?
      AND analyzer_version = ?
      AND status = 'ready'
      AND last_checked_at >= DATE_SUB(
          UTC_TIMESTAMP(6), INTERVAL ? MICROSECOND
      )
)`, AnalyzerName, r.analyzerVersion, r.readyMaxAge.Microseconds()).Scan(&ready); err != nil {
		return Run{}, false, fmt.Errorf("check C analysis readiness: %w", err)
	}
	if !ready {
		return Run{}, false, ErrNotReady
	}

	var activeID string
	err = tx.QueryRowContext(ctx, `
SELECT id
FROM c_analysis_runs
WHERE source_project_id = ?
  AND status IN ('queued', 'running', 'cancel_requested')
LIMIT 1
FOR UPDATE`, record.SourceProjectID).Scan(&activeID)
	if err == nil {
		return Run{}, false, ErrAlreadyActive
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return Run{}, false, fmt.Errorf("find active C analysis: %w", err)
	}

	payload, err := json.Marshal(map[string]any{
		"schema_version": jobPayloadSchemaVersion,
		"run_id":         record.RunID, "project_id": record.SourceProjectID,
		"source_sha256":     project.CanonicalSHA256,
		"source_size_bytes": project.CanonicalSizeBytes,
	})
	if err != nil {
		return Run{}, false, fmt.Errorf("encode C analysis job payload: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `
INSERT INTO jobs (
    id, task_id, task_attempt_id, kind, status, priority, payload,
    available_at, attempt, max_attempts, fencing_token, idempotency_key
) VALUES (
    ?, ?, ?, 'c_analysis', 'queued', 10, ?, UTC_TIMESTAMP(6),
    0, 3, 0, ?
)`, record.JobID, record.TaskID, attemptID, payload, record.RequestKey); err != nil {
		return Run{}, false, fmt.Errorf("insert C analysis job: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `
INSERT INTO analyzer_runs (
    id, task_id, task_attempt_id, job_id, file_node_id,
    analyzer_name, analyzer_version, parameters_json, status
) VALUES (
    ?, ?, ?, ?, ?, ?, ?,
    JSON_OBJECT(
        'schema_version', ?, 'source_project_id', ?,
        'source_sha256', ?, 'source_size_bytes', ?
    ),
    'queued'
)`,
		record.RunID, record.TaskID, attemptID, record.JobID, fileNodeID,
		AnalyzerName, r.analyzerVersion, RequestSchemaVersion,
		record.SourceProjectID, project.CanonicalSHA256,
		project.CanonicalSizeBytes,
	); err != nil {
		return Run{}, false, fmt.Errorf("insert C analyzer run: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `
INSERT INTO c_analysis_runs (
    id, task_id, source_project_id, job_id, created_by_user_id,
    status, source_sha256, source_size_bytes, total_functions
) VALUES (?, ?, ?, ?, ?, 'queued', ?, ?, ?)`,
		record.RunID, record.TaskID, record.SourceProjectID, record.JobID,
		record.UserID, project.CanonicalSHA256,
		project.CanonicalSizeBytes, len(project.Functions),
	); err != nil {
		return Run{}, false, fmt.Errorf("insert C analysis run: %w", err)
	}
	value, err := scanRun(tx.QueryRowContext(
		ctx, runSelect+` WHERE analysis.task_id = ? AND analysis.id = ?`,
		record.TaskID, record.RunID,
	))
	if err != nil {
		return Run{}, false, fmt.Errorf("read created C analysis: %w", err)
	}
	if err := report.InvalidateTaskSourceAnalysisReports(
		ctx, tx, record.TaskID,
	); err != nil {
		return Run{}, false, fmt.Errorf(
			"invalidate reports after C analysis creation: %w", err,
		)
	}
	if err := tx.Commit(); err != nil {
		return Run{}, false, fmt.Errorf("commit C analysis creation: %w", err)
	}
	return value, true, nil
}

func (r *MySQLRepository) List(
	ctx context.Context,
	query ListQuery,
) (RunPage, error) {
	tx, err := r.db.BeginTx(ctx, &sql.TxOptions{
		Isolation: sql.LevelRepeatableRead, ReadOnly: true,
	})
	if err != nil {
		return RunPage{}, fmt.Errorf("begin C analysis list: %w", err)
	}
	defer tx.Rollback()
	if err := requireTask(ctx, tx, query.TaskID); err != nil {
		return RunPage{}, err
	}
	statement := runSelect + ` WHERE analysis.task_id = ?`
	arguments := []any{query.TaskID}
	if query.SourceProjectID != "" {
		statement += ` AND analysis.source_project_id = ?`
		arguments = append(arguments, query.SourceProjectID)
	}
	if query.After != nil {
		statement += `
  AND (analysis.created_at < ? OR
       (analysis.created_at = ? AND analysis.id < ?))`
		arguments = append(
			arguments, query.After.CreatedAt, query.After.CreatedAt, query.After.ID,
		)
	}
	statement += ` ORDER BY analysis.created_at DESC, analysis.id DESC LIMIT ?`
	arguments = append(arguments, query.PageSize+1)
	rows, err := tx.QueryContext(ctx, statement, arguments...)
	if err != nil {
		return RunPage{}, fmt.Errorf("list C analysis runs: %w", err)
	}
	items := make([]Run, 0, query.PageSize+1)
	for rows.Next() {
		value, err := scanRun(rows)
		if err != nil {
			rows.Close()
			return RunPage{}, fmt.Errorf("scan C analysis run: %w", err)
		}
		items = append(items, value)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return RunPage{}, fmt.Errorf("iterate C analysis runs: %w", err)
	}
	if err := rows.Close(); err != nil {
		return RunPage{}, fmt.Errorf("close C analysis runs: %w", err)
	}
	page := RunPage{Items: items}
	if len(page.Items) > query.PageSize {
		page.HasMore = true
		page.Items = page.Items[:query.PageSize]
	}
	if err := tx.Commit(); err != nil {
		return RunPage{}, fmt.Errorf("commit C analysis list: %w", err)
	}
	return page, nil
}

func (r *MySQLRepository) Get(
	ctx context.Context,
	query RunQuery,
) (Run, error) {
	tx, err := r.db.BeginTx(ctx, &sql.TxOptions{
		Isolation: sql.LevelRepeatableRead, ReadOnly: true,
	})
	if err != nil {
		return Run{}, fmt.Errorf("begin C analysis read: %w", err)
	}
	defer tx.Rollback()
	if err := requireTask(ctx, tx, query.TaskID); err != nil {
		return Run{}, err
	}
	value, err := scanRun(tx.QueryRowContext(
		ctx, runSelect+` WHERE analysis.task_id = ? AND analysis.id = ?`,
		query.TaskID, query.RunID,
	))
	if errors.Is(err, sql.ErrNoRows) {
		return Run{}, ErrRunNotFound
	}
	if err != nil {
		return Run{}, fmt.Errorf("read C analysis run: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return Run{}, fmt.Errorf("commit C analysis read: %w", err)
	}
	return value, nil
}

func (r *MySQLRepository) ListFindings(
	ctx context.Context,
	query FindingsQuery,
) (FindingPage, error) {
	tx, err := r.db.BeginTx(ctx, &sql.TxOptions{
		Isolation: sql.LevelRepeatableRead, ReadOnly: true,
	})
	if err != nil {
		return FindingPage{}, fmt.Errorf("begin C finding list: %w", err)
	}
	defer tx.Rollback()
	if err := requireTask(ctx, tx, query.TaskID); err != nil {
		return FindingPage{}, err
	}
	var runExists uint8
	err = tx.QueryRowContext(ctx, `
SELECT 1
FROM c_analysis_runs analysis
JOIN decompile_source_projects project
  ON project.task_id = analysis.task_id
 AND project.id = analysis.source_project_id
 AND project.deleted_at IS NULL
 AND project.storage_deleted_at IS NULL
WHERE analysis.task_id = ? AND analysis.id = ?
  AND analysis.deletion_started_at IS NULL`,
		query.TaskID, query.RunID,
	).Scan(&runExists)
	if errors.Is(err, sql.ErrNoRows) {
		return FindingPage{}, ErrRunNotFound
	}
	if err != nil {
		return FindingPage{}, fmt.Errorf("find C analysis run for findings: %w", err)
	}
	statement := `
SELECT id, cwe, rule_id, severity, function_result_id,
       function_address, function_name, start_line, start_column,
       end_line, end_column, message, snippet, created_at
FROM c_analysis_findings
WHERE task_id = ? AND run_id = ? AND id > ?`
	arguments := []any{query.TaskID, query.RunID, query.Cursor}
	if query.CWE != "" {
		statement += ` AND cwe = ?`
		arguments = append(arguments, query.CWE)
	}
	if query.Severity != "" {
		statement += ` AND severity = ?`
		arguments = append(arguments, query.Severity)
	}
	if query.Function != "" {
		statement += ` AND LOCATE(?, function_name) > 0`
		arguments = append(arguments, query.Function)
	}
	statement += ` ORDER BY id ASC LIMIT ?`
	arguments = append(arguments, query.PageSize+1)
	rows, err := tx.QueryContext(ctx, statement, arguments...)
	if err != nil {
		return FindingPage{}, fmt.Errorf("list C analysis findings: %w", err)
	}
	items := make([]Finding, 0, query.PageSize+1)
	ids := make([]uint64, 0, query.PageSize+1)
	for rows.Next() {
		value, id, err := scanFinding(rows)
		if err != nil {
			rows.Close()
			return FindingPage{}, fmt.Errorf("scan C analysis finding: %w", err)
		}
		items = append(items, value)
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return FindingPage{}, fmt.Errorf("iterate C analysis findings: %w", err)
	}
	if err := rows.Close(); err != nil {
		return FindingPage{}, fmt.Errorf("close C analysis findings: %w", err)
	}
	page := FindingPage{Items: items}
	if len(page.Items) > query.PageSize {
		page.Items = page.Items[:query.PageSize]
		page.NextCursor = strconv.FormatUint(ids[query.PageSize-1], 10)
	}
	if err := tx.Commit(); err != nil {
		return FindingPage{}, fmt.Errorf("commit C finding list: %w", err)
	}
	return page, nil
}

func (r *MySQLRepository) Cancel(
	ctx context.Context,
	input ActionInput,
) (Run, error) {
	tx, err := r.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return Run{}, fmt.Errorf("begin C analysis cancellation: %w", err)
	}
	defer tx.Rollback()
	if err := requireTask(ctx, tx, input.TaskID); err != nil {
		return Run{}, err
	}
	var runStatus, jobID, jobStatus string
	err = tx.QueryRowContext(ctx, `
SELECT analysis.status, analysis.job_id, job.status
FROM c_analysis_runs analysis
JOIN jobs job ON job.task_id = analysis.task_id AND job.id = analysis.job_id
WHERE analysis.task_id = ? AND analysis.id = ?
FOR UPDATE`, input.TaskID, input.RunID).Scan(&runStatus, &jobID, &jobStatus)
	if errors.Is(err, sql.ErrNoRows) {
		return Run{}, ErrRunNotFound
	}
	if err != nil {
		return Run{}, fmt.Errorf("lock C analysis cancellation: %w", err)
	}
	mutated := false
	switch runStatus {
	case "cancel_requested":
		// Idempotent replay returns the current run.
	case "queued":
		if jobStatus == "queued" {
			if _, err := tx.ExecContext(ctx, `
UPDATE jobs
SET status = 'cancelled', cancel_requested_at = UTC_TIMESTAMP(6),
    completed_at = UTC_TIMESTAMP(6)
WHERE id = ? AND task_id = ? AND status = 'queued'`, jobID, input.TaskID); err != nil {
				return Run{}, fmt.Errorf("cancel queued C analysis job: %w", err)
			}
			if err := cancelRunNow(ctx, tx, input); err != nil {
				return Run{}, err
			}
			mutated = true
		} else if jobStatus == "leased" || jobStatus == "running" ||
			jobStatus == "cancel_requested" {
			if err := requestRunCancellation(ctx, tx, input, jobID); err != nil {
				return Run{}, err
			}
			mutated = true
		} else {
			return Run{}, ErrRunNotCancellable
		}
	case "running":
		if jobStatus != "running" && jobStatus != "leased" &&
			jobStatus != "cancel_requested" {
			return Run{}, ErrRunNotCancellable
		}
		if err := requestRunCancellation(ctx, tx, input, jobID); err != nil {
			return Run{}, err
		}
		mutated = true
	case "cancelled":
		// Replaying cancellation after recovery is harmless.
	default:
		return Run{}, ErrRunNotCancellable
	}
	value, err := scanRun(tx.QueryRowContext(
		ctx, runSelect+` WHERE analysis.task_id = ? AND analysis.id = ?`,
		input.TaskID, input.RunID,
	))
	if errors.Is(err, sql.ErrNoRows) {
		return Run{}, ErrRunNotFound
	}
	if err != nil {
		return Run{}, fmt.Errorf("read cancelled C analysis: %w", err)
	}
	if mutated {
		if err := report.InvalidateTaskSourceAnalysisReports(
			ctx, tx, input.TaskID,
		); err != nil {
			return Run{}, fmt.Errorf(
				"invalidate reports after C analysis cancellation: %w", err,
			)
		}
	}
	if err := tx.Commit(); err != nil {
		return Run{}, fmt.Errorf("commit C analysis cancellation: %w", err)
	}
	return value, nil
}

func requestRunCancellation(
	ctx context.Context,
	tx *sql.Tx,
	input ActionInput,
	jobID string,
) error {
	if _, err := tx.ExecContext(ctx, `
UPDATE jobs
SET status = 'cancel_requested',
    cancel_requested_at = COALESCE(cancel_requested_at, UTC_TIMESTAMP(6))
WHERE id = ? AND task_id = ?
  AND status IN ('leased', 'running', 'cancel_requested')`,
		jobID, input.TaskID,
	); err != nil {
		return fmt.Errorf("request C analysis job cancellation: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `
UPDATE c_analysis_runs
SET status = 'cancel_requested',
    started_at = COALESCE(started_at, UTC_TIMESTAMP(6))
WHERE task_id = ? AND id = ? AND status IN ('queued', 'running', 'cancel_requested')`,
		input.TaskID, input.RunID,
	); err != nil {
		return fmt.Errorf("request C analysis run cancellation: %w", err)
	}
	return nil
}

func cancelRunNow(ctx context.Context, tx *sql.Tx, input ActionInput) error {
	if _, err := tx.ExecContext(ctx, `
UPDATE c_analysis_runs
SET status = 'cancelled', completed_at = UTC_TIMESTAMP(6),
    error_code = NULL, error_message = NULL
WHERE task_id = ? AND id = ? AND status = 'queued'`,
		input.TaskID, input.RunID,
	); err != nil {
		return fmt.Errorf("cancel C analysis run: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `
UPDATE analyzer_runs
SET status = 'cancelled', completed_at = UTC_TIMESTAMP(6),
    error_code = NULL, error_message = NULL
WHERE task_id = ? AND id = ? AND status = 'queued'`,
		input.TaskID, input.RunID,
	); err != nil {
		return fmt.Errorf("cancel C analyzer run: %w", err)
	}
	return nil
}

const runSelect = `
SELECT analysis.id, analysis.task_id, analysis.source_project_id,
       analysis.job_id, analysis.status, analyzer.analyzer_name,
       analyzer.analyzer_version, analysis.source_sha256,
       analysis.source_size_bytes, analysis.ruleset_version,
       analysis.total_functions, analysis.parsed_functions,
       analysis.failed_functions, analysis.finding_count,
       analysis.diagnostic_count, analysis.low_count,
       analysis.medium_count, analysis.high_count, analysis.critical_count,
       analysis.findings_truncated, analysis.diagnostics_truncated,
       analysis.error_code, analysis.error_message, analysis.started_at,
       analysis.completed_at, analysis.created_at, analysis.updated_at,
       node.logical_path, project.status, project.engine_name,
       project.engine_version
FROM c_analysis_runs analysis
JOIN analyzer_runs analyzer
  ON analyzer.task_id = analysis.task_id AND analyzer.id = analysis.id
 AND analysis.deletion_started_at IS NULL
JOIN decompile_source_projects project
  ON project.task_id = analysis.task_id
 AND project.id = analysis.source_project_id
 AND project.deleted_at IS NULL
 AND project.storage_deleted_at IS NULL
JOIN file_nodes node
  ON node.task_id = project.task_id AND node.id = project.file_node_id`

type rowScanner interface {
	Scan(...any) error
}

func scanRun(scanner rowScanner) (Run, error) {
	var value Run
	var ruleset, errorCode, errorMessage sql.NullString
	var startedAt, completedAt sql.NullTime
	if err := scanner.Scan(
		&value.ID, &value.TaskID, &value.SourceProjectID, &value.JobID,
		&value.Status, &value.AnalyzerName, &value.AnalyzerVersion,
		&value.SourceSHA256, &value.SourceSizeBytes, &ruleset,
		&value.Coverage.TotalFunctions, &value.Coverage.ParsedFunctions,
		&value.Coverage.FailedFunctions, &value.FindingCount,
		&value.DiagnosticCount, &value.SeverityCounts.Low,
		&value.SeverityCounts.Medium, &value.SeverityCounts.High,
		&value.SeverityCounts.Critical, &value.FindingsTruncated,
		&value.DiagnosticsTruncated, &errorCode, &errorMessage,
		&startedAt, &completedAt, &value.CreatedAt, &value.UpdatedAt,
		&value.SourceProject.TargetPath, &value.SourceProject.Status,
		&value.SourceProject.EngineName, &value.SourceProject.EngineVersion,
	); err != nil {
		return Run{}, err
	}
	value.SourceProject.ID = value.SourceProjectID
	value.RulesetVersion = ruleset.String
	if errorCode.Valid {
		code := errorCode.String
		value.ErrorCode = &code
	}
	if errorMessage.Valid {
		message := errorMessage.String
		value.ErrorMessage = &message
	}
	if startedAt.Valid {
		started := startedAt.Time
		value.StartedAt = &started
	}
	if completedAt.Valid {
		completed := completedAt.Time
		value.CompletedAt = &completed
	}
	return value, nil
}

func scanFinding(scanner rowScanner) (Finding, uint64, error) {
	var value Finding
	var id uint64
	var snippet sql.NullString
	if err := scanner.Scan(
		&id, &value.CWE, &value.RuleID, &value.Severity,
		&value.Function.ResultID, &value.Function.Address,
		&value.Function.Name, &value.Location.StartLine,
		&value.Location.StartColumn, &value.Location.EndLine,
		&value.Location.EndColumn, &value.Message, &snippet,
		&value.CreatedAt,
	); err != nil {
		return Finding{}, 0, err
	}
	value.ID = strconv.FormatUint(id, 10)
	value.Snippet = snippet.String
	return value, id, nil
}

func lockEligibleProject(
	ctx context.Context,
	tx *sql.Tx,
	taskID string,
	projectID string,
) (ProjectSnapshot, uint64, uint64, error) {
	var project ProjectSnapshot
	var attemptID sql.Null[uint64]
	var fileNodeID uint64
	var sourceFileCount, symbolCount uint64
	var rootKey, canonicalKey, canonicalSHA sql.NullString
	var canonicalSize sql.Null[uint64]
	err := tx.QueryRowContext(ctx, `
SELECT project.status, project.engine_name, project.engine_version,
       project.root_storage_key, project.canonical_storage_key,
       project.canonical_sha256, project.canonical_size_bytes,
       project.source_file_count, project.symbol_count,
       source_run.task_attempt_id, project.file_node_id, node.logical_path
FROM decompile_source_projects project
JOIN analyzer_runs source_run
  ON source_run.task_id = project.task_id AND source_run.id = project.id
JOIN file_nodes node
  ON node.task_id = project.task_id AND node.id = project.file_node_id
WHERE project.task_id = ? AND project.id = ?
  AND project.layout_version = 'project-v1'
  AND project.source_kind = 'ghidra-pseudoc'
  AND project.language = 'c'
  AND project.status IN ('complete', 'partial')
  AND project.deleted_at IS NULL
  AND project.storage_deleted_at IS NULL
FOR UPDATE`, taskID, projectID).Scan(
		&project.Status, &project.EngineName, &project.EngineVersion,
		&rootKey, &canonicalKey, &canonicalSHA, &canonicalSize,
		&sourceFileCount, &symbolCount, &attemptID, &fileNodeID,
		&project.TargetPath,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return ProjectSnapshot{}, 0, 0, ErrProjectNotFound
	}
	if err != nil {
		return ProjectSnapshot{}, 0, 0, fmt.Errorf("lock C source project: %w", err)
	}
	project.TaskID = taskID
	project.ProjectID = projectID
	project.RootStorageKey = rootKey.String
	project.CanonicalStorageKey = canonicalKey.String
	project.CanonicalSHA256 = canonicalSHA.String
	project.CanonicalSizeBytes = canonicalSize.V
	expectedRoot := path.Join("source-projects", projectID)
	if !attemptID.Valid || attemptID.V == 0 || fileNodeID == 0 ||
		project.EngineName != "ghidra" ||
		!validSafeASCII(project.EngineVersion, 128) ||
		!rootKey.Valid || rootKey.String != expectedRoot ||
		!canonicalKey.Valid ||
		canonicalKey.String != path.Join(expectedRoot, "src", "decompiled.c") ||
		!canonicalSHA.Valid || !sha256Pattern.MatchString(canonicalSHA.String) ||
		!canonicalSize.Valid || canonicalSize.V == 0 ||
		canonicalSize.V > uint64(MaxSourceBytes) || sourceFileCount != 1 ||
		symbolCount == 0 || symbolCount > MaxFunctions {
		return ProjectSnapshot{}, 0, 0, ErrSourceUnavailable
	}
	rows, err := tx.QueryContext(ctx, `
SELECT result.id, result.symbol_key,
       JSON_UNQUOTE(JSON_EXTRACT(result.diagnostics_json, '$.display_name')),
       result.content_sha256, result.source_offset_bytes,
       result.source_length_bytes, result.source_start_line,
       result.source_end_line
FROM decompile_results result
WHERE result.task_id = ? AND result.analyzer_run_id = ?
  AND result.status = 'complete' AND result.deleted_at IS NULL
  AND result.storage_key = ?
ORDER BY result.source_offset_bytes ASC, result.id ASC`,
		taskID, projectID, canonicalKey.String,
	)
	if err != nil {
		return ProjectSnapshot{}, 0, 0, fmt.Errorf("list C source functions: %w", err)
	}
	var previousEndOffset, previousEndLine uint64
	for rows.Next() {
		var function Function
		var name, digest sql.NullString
		var offset, length, startLine, endLine sql.Null[uint64]
		if err := rows.Scan(
			&function.ResultID, &function.Address, &name, &digest,
			&offset, &length, &startLine, &endLine,
		); err != nil {
			rows.Close()
			return ProjectSnapshot{}, 0, 0, fmt.Errorf("scan C source function: %w", err)
		}
		if !uuidPattern.MatchString(function.ResultID) ||
			!validText(function.Address, 128, false) ||
			!name.Valid || !validText(name.String, 512, false) || !digest.Valid ||
			!sha256Pattern.MatchString(digest.String) || !offset.Valid ||
			!length.Valid || length.V == 0 || !startLine.Valid ||
			startLine.V == 0 || !endLine.Valid || endLine.V < startLine.V ||
			startLine.V > uint64(^uint32(0)) || endLine.V > uint64(^uint32(0)) ||
			offset.V > canonicalSize.V || length.V > canonicalSize.V-offset.V ||
			(len(project.Functions) > 0 &&
				(offset.V < previousEndOffset || startLine.V <= previousEndLine)) {
			rows.Close()
			return ProjectSnapshot{}, 0, 0, ErrSourceUnavailable
		}
		function.Name = name.String
		function.SHA256 = digest.String
		function.OffsetBytes = offset.V
		function.LengthBytes = length.V
		function.StartLine = uint32(startLine.V)
		function.EndLine = uint32(endLine.V)
		project.Functions = append(project.Functions, function)
		previousEndOffset = offset.V + length.V
		previousEndLine = endLine.V
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return ProjectSnapshot{}, 0, 0, fmt.Errorf("iterate C source functions: %w", err)
	}
	if err := rows.Close(); err != nil {
		return ProjectSnapshot{}, 0, 0, fmt.Errorf("close C source functions: %w", err)
	}
	if uint64(len(project.Functions)) != symbolCount {
		return ProjectSnapshot{}, 0, 0, ErrSourceUnavailable
	}
	return project, attemptID.V, fileNodeID, nil
}

func requireTask(ctx context.Context, tx *sql.Tx, taskID string) error {
	var marker uint8
	err := tx.QueryRowContext(ctx, `
SELECT 1 FROM tasks WHERE id = ? AND deleted_at IS NULL`, taskID).Scan(&marker)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrTaskNotFound
	}
	if err != nil {
		return fmt.Errorf("find C analysis task: %w", err)
	}
	return nil
}

func validCreateRecord(record CreateRecord) bool {
	return uuidPattern.MatchString(record.RunID) &&
		uuidPattern.MatchString(record.JobID) && record.RunID != record.JobID &&
		uuidPattern.MatchString(record.TaskID) &&
		uuidPattern.MatchString(record.SourceProjectID) && record.UserID > 0 &&
		strings.HasPrefix(record.RequestKey, "c_analysis:") &&
		len(record.RequestKey) == len("c_analysis:")+64 &&
		sha256Pattern.MatchString(strings.TrimPrefix(record.RequestKey, "c_analysis:"))
}

func terminalTaskStatus(status string) bool {
	switch status {
	case "SUCCEEDED", "PARTIAL_SUCCEEDED", "FAILED", "CANCELLED":
		return true
	default:
		return false
	}
}

func requireOne(result sql.Result, zero error) error {
	affected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if affected == 0 {
		return zero
	}
	if affected != 1 {
		return errors.New("C analysis database mutation affected multiple rows")
	}
	return nil
}

func validSafeASCII(value string, maximum int) bool {
	if len(value) == 0 || len(value) > maximum || strings.TrimSpace(value) != value {
		return false
	}
	for index := range len(value) {
		if value[index] < 0x21 || value[index] > 0x7e {
			return false
		}
	}
	return true
}

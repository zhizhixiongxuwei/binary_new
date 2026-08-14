package pythonanalysis

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"binaryscan/internal/report"
)

type RepositoryConfig struct {
	AnalyzerVersion   string
	ReadyMaxAge       time.Duration
	InvalidateReports func(context.Context, *sql.Tx, string) error
}

type MySQLRepository struct {
	db                *sql.DB
	analyzerVersion   string
	readyMaxAge       time.Duration
	invalidateReports func(context.Context, *sql.Tx, string) error
}

func NewMySQLRepository(
	db *sql.DB,
	config RepositoryConfig,
) (*MySQLRepository, error) {
	if db == nil {
		return nil, errors.New("Python analysis database is required")
	}
	if config.AnalyzerVersion == "" {
		config.AnalyzerVersion = AnalyzerVersion
	}
	if config.ReadyMaxAge == 0 {
		config.ReadyMaxAge = 30 * time.Second
	}
	if config.InvalidateReports == nil {
		config.InvalidateReports = func(
			ctx context.Context,
			tx *sql.Tx,
			taskID string,
		) error {
			return report.InvalidateTaskSourceAnalysisReports(ctx, tx, taskID)
		}
	}
	if config.AnalyzerVersion != AnalyzerVersion ||
		config.ReadyMaxAge < time.Microsecond ||
		config.ReadyMaxAge > 24*time.Hour {
		return nil, errors.New("Python analysis repository configuration is invalid")
	}
	return &MySQLRepository{
		db: db, analyzerVersion: config.AnalyzerVersion,
		readyMaxAge:       config.ReadyMaxAge,
		invalidateReports: config.InvalidateReports,
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
		return Run{}, false, fmt.Errorf("begin Python analysis creation: %w", err)
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
		return Run{}, false, fmt.Errorf("lock Python analysis task: %w", err)
	}
	if taskDeleted.Valid || !terminalTaskStatus(taskStatus) {
		return Run{}, false, ErrSourceUnavailable
	}

	var replayRunID, replayProjectID string
	err = tx.QueryRowContext(ctx, `
SELECT analysis.id, analysis.source_project_id
FROM jobs job
JOIN python_analysis_runs analysis
  ON analysis.task_id = job.task_id AND analysis.job_id = job.id
WHERE job.task_id = ?
  AND job.kind = 'python_analysis'
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
			return Run{}, false, fmt.Errorf("read replayed Python analysis: %w", err)
		}
		if err := tx.Commit(); err != nil {
			return Run{}, false, fmt.Errorf("commit Python analysis replay: %w", err)
		}
		return value, false, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return Run{}, false, fmt.Errorf("find Python analysis replay: %w", err)
	}

	project, attemptID, err := r.lockEligibleProject(
		ctx, tx, record.TaskID, record.SourceProjectID,
	)
	if err != nil {
		return Run{}, false, err
	}
	if project.SourceSizeBytes > uint64(MaxSourceBytes) ||
		len(project.Files) == 0 || len(project.Files) > MaxFiles ||
		!sha256Pattern.MatchString(project.InputSHA256) {
		return Run{}, false, ErrSourceUnavailable
	}

	var ready bool
	if err := tx.QueryRowContext(ctx, `
SELECT EXISTS (
    SELECT 1
    FROM worker_readiness
    WHERE worker_kind = 'python_analysis'
      AND analyzer_name = ?
      AND analyzer_version = ?
      AND status = 'ready'
      AND last_checked_at >= DATE_SUB(
          UTC_TIMESTAMP(6), INTERVAL ? MICROSECOND
      )
)`, AnalyzerName, r.analyzerVersion, r.readyMaxAge.Microseconds()).Scan(&ready); err != nil {
		return Run{}, false, fmt.Errorf("check Python analysis readiness: %w", err)
	}
	if !ready {
		return Run{}, false, ErrNotReady
	}

	var activeID string
	err = tx.QueryRowContext(ctx, `
SELECT id
FROM python_analysis_runs
WHERE source_project_id = ?
  AND status IN ('queued', 'running', 'cancel_requested')
LIMIT 1
FOR UPDATE`, record.SourceProjectID).Scan(&activeID)
	if err == nil {
		return Run{}, false, ErrAlreadyActive
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return Run{}, false, fmt.Errorf("find active Python analysis: %w", err)
	}

	payload, err := json.Marshal(map[string]any{
		"schema_version": jobPayloadSchemaVersion,
		"run_id":         record.RunID, "project_id": record.SourceProjectID,
		"source_manifest_sha256": project.ManifestSHA256,
		"input_sha256":           project.InputSHA256,
		"source_size_bytes":      project.SourceSizeBytes,
		"source_file_count":      len(project.Files),
	})
	if err != nil {
		return Run{}, false, fmt.Errorf("encode Python analysis job payload: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `
INSERT INTO jobs (
    id, task_id, task_attempt_id, kind, status, priority, payload,
    available_at, attempt, max_attempts, fencing_token, idempotency_key
) VALUES (
    ?, ?, ?, 'python_analysis', 'queued', 10, ?, UTC_TIMESTAMP(6),
    0, 3, 0, ?
)`, record.JobID, record.TaskID, attemptID, payload, record.RequestKey); err != nil {
		return Run{}, false, fmt.Errorf("insert Python analysis job: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `
INSERT INTO analyzer_runs (
    id, task_id, task_attempt_id, job_id, file_node_id,
    analyzer_name, analyzer_version, parameters_json, status
) VALUES (
    ?, ?, ?, ?, ?, ?, ?,
    JSON_OBJECT(
        'schema_version', ?, 'source_project_id', ?,
        'source_manifest_sha256', ?, 'input_sha256', ?,
        'source_size_bytes', ?, 'source_file_count', ?
    ),
    'queued'
)`,
		record.RunID, record.TaskID, attemptID, record.JobID, nil,
		AnalyzerName, r.analyzerVersion, RequestSchemaVersion,
		record.SourceProjectID, project.ManifestSHA256, project.InputSHA256,
		project.SourceSizeBytes, len(project.Files),
	); err != nil {
		return Run{}, false, fmt.Errorf("insert Java analyzer run: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `
INSERT INTO python_analysis_runs (
    id, task_id, source_project_id, job_id, created_by_user_id,
    status, source_manifest_sha256, input_sha256, source_size_bytes,
    source_file_count
) VALUES (?, ?, ?, ?, ?, 'queued', ?, ?, ?, ?)`,
		record.RunID, record.TaskID, record.SourceProjectID, record.JobID,
		record.UserID, project.ManifestSHA256, project.InputSHA256,
		project.SourceSizeBytes, len(project.Files),
	); err != nil {
		return Run{}, false, fmt.Errorf("insert Python analysis run: %w", err)
	}
	value, err := scanRun(tx.QueryRowContext(
		ctx, runSelect+` WHERE analysis.task_id = ? AND analysis.id = ?`,
		record.TaskID, record.RunID,
	))
	if err != nil {
		return Run{}, false, fmt.Errorf("read created Python analysis: %w", err)
	}
	if err := r.invalidateReports(ctx, tx, record.TaskID); err != nil {
		return Run{}, false, fmt.Errorf(
			"invalidate reports after Python analysis creation: %w", err,
		)
	}
	if err := tx.Commit(); err != nil {
		return Run{}, false, fmt.Errorf("commit Python analysis creation: %w", err)
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
		return RunPage{}, fmt.Errorf("begin Python analysis list: %w", err)
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
		return RunPage{}, fmt.Errorf("list Python analysis runs: %w", err)
	}
	items := make([]Run, 0, query.PageSize+1)
	for rows.Next() {
		value, err := scanRun(rows)
		if err != nil {
			rows.Close()
			return RunPage{}, fmt.Errorf("scan Python analysis run: %w", err)
		}
		items = append(items, value)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return RunPage{}, fmt.Errorf("iterate Python analysis runs: %w", err)
	}
	if err := rows.Close(); err != nil {
		return RunPage{}, fmt.Errorf("close Python analysis runs: %w", err)
	}
	page := RunPage{Items: items}
	if len(page.Items) > query.PageSize {
		page.HasMore = true
		page.Items = page.Items[:query.PageSize]
	}
	if err := tx.Commit(); err != nil {
		return RunPage{}, fmt.Errorf("commit Python analysis list: %w", err)
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
		return Run{}, fmt.Errorf("begin Python analysis read: %w", err)
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
		return Run{}, fmt.Errorf("read Python analysis run: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return Run{}, fmt.Errorf("commit Python analysis read: %w", err)
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
		return FindingPage{}, fmt.Errorf("begin Java finding list: %w", err)
	}
	defer tx.Rollback()
	if err := requireTask(ctx, tx, query.TaskID); err != nil {
		return FindingPage{}, err
	}
	var runExists uint8
	err = tx.QueryRowContext(ctx, `
SELECT 1
FROM python_analysis_runs analysis
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
		return FindingPage{}, fmt.Errorf("find Python analysis run for findings: %w", err)
	}
	statement := `
SELECT id, cwe, rule_id, severity, file_result_id, logical_path,
       binary_name, callable_kind, type_name, callable_name,
       callable_signature, start_line, start_column, end_line, end_column,
       message, snippet, snippet_start_line, created_at
FROM python_analysis_findings
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
	if query.File != "" {
		statement += ` AND LOCATE(?, logical_path) > 0`
		arguments = append(arguments, query.File)
	}
	if query.Callable != "" {
		statement += ` AND (LOCATE(?, callable_name) > 0 OR LOCATE(?, type_name) > 0)`
		arguments = append(arguments, query.Callable, query.Callable)
	}
	statement += ` ORDER BY id ASC LIMIT ?`
	arguments = append(arguments, query.PageSize+1)
	rows, err := tx.QueryContext(ctx, statement, arguments...)
	if err != nil {
		return FindingPage{}, fmt.Errorf("list Python analysis findings: %w", err)
	}
	items := make([]Finding, 0, query.PageSize+1)
	ids := make([]uint64, 0, query.PageSize+1)
	for rows.Next() {
		value, id, err := scanFinding(rows)
		if err != nil {
			rows.Close()
			return FindingPage{}, fmt.Errorf("scan Python analysis finding: %w", err)
		}
		items = append(items, value)
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return FindingPage{}, fmt.Errorf("iterate Python analysis findings: %w", err)
	}
	if err := rows.Close(); err != nil {
		return FindingPage{}, fmt.Errorf("close Python analysis findings: %w", err)
	}
	page := FindingPage{Items: items}
	if len(page.Items) > query.PageSize {
		page.Items = page.Items[:query.PageSize]
		page.NextCursor = strconv.FormatUint(ids[query.PageSize-1], 10)
	}
	if err := tx.Commit(); err != nil {
		return FindingPage{}, fmt.Errorf("commit Java finding list: %w", err)
	}
	return page, nil
}

func (r *MySQLRepository) Cancel(
	ctx context.Context,
	input ActionInput,
) (Run, error) {
	tx, err := r.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return Run{}, fmt.Errorf("begin Python analysis cancellation: %w", err)
	}
	defer tx.Rollback()
	if err := requireTask(ctx, tx, input.TaskID); err != nil {
		return Run{}, err
	}
	var runStatus, jobID, jobStatus string
	err = tx.QueryRowContext(ctx, `
SELECT analysis.status, analysis.job_id, job.status
FROM python_analysis_runs analysis
JOIN jobs job ON job.task_id = analysis.task_id AND job.id = analysis.job_id
WHERE analysis.task_id = ? AND analysis.id = ?
FOR UPDATE`, input.TaskID, input.RunID).Scan(&runStatus, &jobID, &jobStatus)
	if errors.Is(err, sql.ErrNoRows) {
		return Run{}, ErrRunNotFound
	}
	if err != nil {
		return Run{}, fmt.Errorf("lock Python analysis cancellation: %w", err)
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
				return Run{}, fmt.Errorf("cancel queued Python analysis job: %w", err)
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
		return Run{}, fmt.Errorf("read cancelled Python analysis: %w", err)
	}
	if mutated {
		if err := r.invalidateReports(ctx, tx, input.TaskID); err != nil {
			return Run{}, fmt.Errorf(
				"invalidate reports after Python analysis cancellation: %w", err,
			)
		}
	}
	if err := tx.Commit(); err != nil {
		return Run{}, fmt.Errorf("commit Python analysis cancellation: %w", err)
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
		return fmt.Errorf("request Python analysis job cancellation: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `
UPDATE python_analysis_runs
SET status = 'cancel_requested',
    started_at = COALESCE(started_at, UTC_TIMESTAMP(6))
WHERE task_id = ? AND id = ? AND status IN ('queued', 'running', 'cancel_requested')`,
		input.TaskID, input.RunID,
	); err != nil {
		return fmt.Errorf("request Python analysis run cancellation: %w", err)
	}
	return nil
}

func cancelRunNow(ctx context.Context, tx *sql.Tx, input ActionInput) error {
	if _, err := tx.ExecContext(ctx, `
UPDATE python_analysis_runs
SET status = 'cancelled', completed_at = UTC_TIMESTAMP(6),
    error_code = NULL, error_message = NULL
WHERE task_id = ? AND id = ? AND status = 'queued'`,
		input.TaskID, input.RunID,
	); err != nil {
		return fmt.Errorf("cancel Python analysis run: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `
UPDATE analyzer_runs
SET status = 'cancelled', completed_at = UTC_TIMESTAMP(6),
    error_code = NULL, error_message = NULL
WHERE task_id = ? AND id = ? AND status = 'queued'`,
		input.TaskID, input.RunID,
	); err != nil {
		return fmt.Errorf("cancel Java analyzer run: %w", err)
	}
	return nil
}

const runSelect = `
SELECT analysis.id, analysis.task_id, analysis.source_project_id,
       analysis.job_id, analysis.status, analyzer.analyzer_name,
       analyzer.analyzer_version, analysis.source_manifest_sha256,
       analysis.input_sha256, analysis.bundle_sha256,
       analysis.source_size_bytes, analysis.source_file_count,
       analysis.ruleset_version, analysis.analyzed_files,
       analysis.parsed_files, analysis.recovered_files,
       analysis.failed_files, analysis.finding_count,
       analysis.diagnostic_count, analysis.low_count,
       analysis.medium_count, analysis.high_count, analysis.critical_count,
       analysis.findings_truncated, analysis.diagnostics_truncated,
       analysis.error_code, analysis.error_message, analysis.started_at,
       analysis.completed_at, analysis.created_at, analysis.updated_at,
       node.logical_path, project.status, project.engine_name,
       project.engine_version
FROM python_analysis_runs analysis
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
	var ruleset, bundle, errorCode, errorMessage sql.NullString
	var startedAt, completedAt sql.NullTime
	if err := scanner.Scan(
		&value.ID, &value.TaskID, &value.SourceProjectID, &value.JobID,
		&value.Status, &value.AnalyzerName, &value.AnalyzerVersion,
		&value.SourceManifestSHA256, &value.InputSHA256, &bundle,
		&value.SourceSizeBytes, &value.SourceFileCount, &ruleset,
		&value.Coverage.AnalyzedFiles, &value.Coverage.ParsedFiles,
		&value.Coverage.RecoveredFiles, &value.Coverage.FailedFiles,
		&value.FindingCount,
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
	value.BundleSHA256 = bundle.String
	value.Coverage.TotalFiles = value.SourceFileCount
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
	var snippetStart sql.Null[uint32]
	if err := scanner.Scan(
		&id, &value.CWE, &value.RuleID, &value.Severity,
		&value.File.ResultID, &value.File.LogicalPath, &value.File.BinaryName,
		&value.Callable.Kind, &value.Callable.TypeName, &value.Callable.Name,
		&value.Callable.Signature, &value.Location.StartLine,
		&value.Location.StartColumn, &value.Location.EndLine,
		&value.Location.EndColumn, &value.Message, &snippet, &snippetStart,
		&value.CreatedAt,
	); err != nil {
		return Finding{}, 0, err
	}
	value.ID = strconv.FormatUint(id, 10)
	value.Snippet = snippet.String
	if snippetStart.Valid {
		value.SnippetStartLine = snippetStart.V
	}
	return value, id, nil
}

func checkerProjectStatus(projectStatus string, language string) string {
	if projectStatus == "partial" || language == "mixed" {
		return "partial"
	}
	return "complete"
}

func requireTask(ctx context.Context, tx *sql.Tx, taskID string) error {
	var marker uint8
	err := tx.QueryRowContext(ctx, `
SELECT 1 FROM tasks WHERE id = ? AND deleted_at IS NULL`, taskID).Scan(&marker)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrTaskNotFound
	}
	if err != nil {
		return fmt.Errorf("find Python analysis task: %w", err)
	}
	return nil
}

func validCreateRecord(record CreateRecord) bool {
	return uuidPattern.MatchString(record.RunID) &&
		uuidPattern.MatchString(record.JobID) && record.RunID != record.JobID &&
		uuidPattern.MatchString(record.TaskID) &&
		uuidPattern.MatchString(record.SourceProjectID) && record.UserID > 0 &&
		strings.HasPrefix(record.RequestKey, "python_analysis:") &&
		len(record.RequestKey) == len("python_analysis:")+64 &&
		sha256Pattern.MatchString(strings.TrimPrefix(record.RequestKey, "python_analysis:"))
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
		return errors.New("Python analysis database mutation affected multiple rows")
	}
	return nil
}


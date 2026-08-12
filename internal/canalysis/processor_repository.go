package canalysis

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"binaryscan/internal/queue"
	"binaryscan/internal/report"
)

type jobPayload struct {
	SchemaVersion   string `json:"schema_version"`
	RunID           string `json:"run_id"`
	ProjectID       string `json:"project_id"`
	SourceSHA256    string `json:"source_sha256"`
	SourceSizeBytes uint64 `json:"source_size_bytes"`
}

func (r *MySQLRepository) Begin(
	ctx context.Context,
	lease queue.Lease,
) (ProjectSnapshot, error) {
	payload, err := decodeJobPayload(lease.Payload)
	if err != nil || !validCAnalysisLease(lease) || payload.RunID == "" {
		return ProjectSnapshot{}, ErrInvalidInput
	}
	tx, err := r.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return ProjectSnapshot{}, fmt.Errorf("begin C worker run: %w", err)
	}
	defer tx.Rollback()
	var runStatus, analyzerStatus, analyzerVersion string
	var runErrorCode sql.NullString
	var sourceProjectID, sourceSHA string
	var sourceSize uint64
	var totalFunctions uint32
	err = tx.QueryRowContext(ctx, `
	SELECT analysis.status, analysis.source_project_id,
	       analysis.source_sha256, analysis.source_size_bytes,
	       analysis.total_functions, analysis.error_code,
	       analyzer.status, analyzer.analyzer_version
FROM jobs job
JOIN c_analysis_runs analysis
  ON analysis.task_id = job.task_id AND analysis.job_id = job.id
JOIN analyzer_runs analyzer
  ON analyzer.task_id = analysis.task_id AND analyzer.id = analysis.id
WHERE job.id = ? AND job.task_id = ? AND job.kind = 'c_analysis'
  AND job.status = 'running' AND job.lease_owner = ?
  AND job.fencing_token = ? AND job.lease_until > UTC_TIMESTAMP(6)
  AND analysis.id = ?
FOR UPDATE`,
		lease.JobID, lease.TaskID, lease.Owner, lease.FencingToken,
		payload.RunID,
	).Scan(
		&runStatus, &sourceProjectID, &sourceSHA, &sourceSize,
		&totalFunctions, &runErrorCode, &analyzerStatus, &analyzerVersion,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return ProjectSnapshot{}, ErrLeaseLost
	}
	if err != nil {
		return ProjectSnapshot{}, fmt.Errorf("lock C worker run: %w", err)
	}
	if sourceProjectID != payload.ProjectID || sourceSHA != payload.SourceSHA256 ||
		sourceSize != payload.SourceSizeBytes || analyzerVersion != r.analyzerVersion {
		return ProjectSnapshot{}, ErrSourceUnavailable
	}
	switch runStatus {
	case "succeeded", "partial":
		return ProjectSnapshot{}, ErrAlreadyPublished
	case "failed":
		if runErrorCode.Valid && runErrorCode.String == "c_checker_failed" {
			return ProjectSnapshot{}, ErrFailedResultPublished
		}
		return ProjectSnapshot{}, ErrAlreadyTerminal
	case "cancelled":
		return ProjectSnapshot{}, ErrAlreadyTerminal
	case "cancel_requested":
		return ProjectSnapshot{}, context.Canceled
	case "queued", "running":
	default:
		return ProjectSnapshot{}, ErrSourceUnavailable
	}
	project, attemptID, _, err := lockEligibleProject(
		ctx, tx, lease.TaskID, sourceProjectID,
	)
	if err != nil {
		return ProjectSnapshot{}, err
	}
	if lease.TaskAttemptID == nil || *lease.TaskAttemptID != attemptID ||
		project.CanonicalSHA256 != sourceSHA ||
		project.CanonicalSizeBytes != sourceSize ||
		payload.ProjectID != project.ProjectID ||
		totalFunctions != uint32(len(project.Functions)) {
		return ProjectSnapshot{}, ErrSourceUnavailable
	}
	if analyzerStatus != "queued" && analyzerStatus != "running" {
		return ProjectSnapshot{}, ErrSourceUnavailable
	}
	if runStatus == "running" && analyzerStatus == "running" {
		if err := tx.Commit(); err != nil {
			return ProjectSnapshot{}, fmt.Errorf("commit C worker replay: %w", err)
		}
		return project, nil
	}
	result, err := tx.ExecContext(ctx, `
UPDATE c_analysis_runs
SET status = 'running', started_at = COALESCE(started_at, UTC_TIMESTAMP(6)),
    completed_at = NULL, error_code = NULL, error_message = NULL
WHERE task_id = ? AND id = ? AND status IN ('queued', 'running')`,
		lease.TaskID, payload.RunID,
	)
	if err != nil {
		return ProjectSnapshot{}, fmt.Errorf("start C analysis run: %w", err)
	}
	if err := requireOne(result, ErrLeaseLost); err != nil {
		return ProjectSnapshot{}, err
	}
	result, err = tx.ExecContext(ctx, `
UPDATE analyzer_runs
SET status = 'running', started_at = COALESCE(started_at, UTC_TIMESTAMP(6)),
    completed_at = NULL, error_code = NULL, error_message = NULL
WHERE task_id = ? AND id = ? AND status IN ('queued', 'running')`,
		lease.TaskID, payload.RunID,
	)
	if err != nil {
		return ProjectSnapshot{}, fmt.Errorf("start C analyzer run: %w", err)
	}
	if err := requireOne(result, ErrLeaseLost); err != nil {
		return ProjectSnapshot{}, err
	}
	if err := report.InvalidateTaskSourceAnalysisReports(
		ctx, tx, lease.TaskID,
	); err != nil {
		return ProjectSnapshot{}, fmt.Errorf(
			"invalidate reports after C analysis start: %w", err,
		)
	}
	if err := tx.Commit(); err != nil {
		return ProjectSnapshot{}, fmt.Errorf("commit C worker run: %w", err)
	}
	return project, nil
}

func (r *MySQLRepository) Publish(
	ctx context.Context,
	lease queue.Lease,
	result Result,
) error {
	payload, err := decodeJobPayload(lease.Payload)
	if err != nil || !validCAnalysisLease(lease) ||
		(result.Status != "succeeded" && result.Status != "partial") ||
		result.AnalysisID != payload.RunID ||
		result.SchemaVersion != ResponseSchemaVersion ||
		result.Checker.Name != AnalyzerName ||
		result.Checker.Version != r.analyzerVersion ||
		result.Checker.RulesetVersion != DefaultRulesetVersion {
		return ErrInvalidInput
	}
	tx, err := r.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return fmt.Errorf("begin C result publication: %w", err)
	}
	defer tx.Rollback()
	project, functions, err := r.lockPublication(
		ctx, tx, lease, payload,
	)
	if err != nil {
		return err
	}
	if project.CanonicalSHA256 != payload.SourceSHA256 ||
		project.CanonicalSizeBytes != payload.SourceSizeBytes ||
		result.Coverage.TotalFunctions != uint32(len(functions)) ||
		result.Coverage.ParsedFunctions > result.Coverage.TotalFunctions ||
		result.Coverage.FailedFunctions > result.Coverage.TotalFunctions ||
		result.Coverage.ParsedFunctions+result.Coverage.FailedFunctions >
			result.Coverage.TotalFunctions ||
		result.Summary.FindingCount != uint32(len(result.Findings)) ||
		result.Summary.DiagnosticCount != uint32(len(result.Diagnostics)) ||
		len(result.Findings) > MaxFindings ||
		len(result.Diagnostics) > MaxDiagnostics {
		return ErrInvalidInput
	}
	if _, err := tx.ExecContext(ctx, `
DELETE FROM c_analysis_findings WHERE task_id = ? AND run_id = ?`,
		lease.TaskID, payload.RunID,
	); err != nil {
		return fmt.Errorf("clear replayed C findings: %w", err)
	}
	statement, err := tx.PrepareContext(ctx, `
INSERT INTO c_analysis_findings (
    task_id, run_id, cwe, rule_id, severity,
    function_result_id, function_address, function_name,
    start_line, start_column, end_line, end_column, message, snippet
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULLIF(?, ''))`)
	if err != nil {
		return fmt.Errorf("prepare C finding publication: %w", err)
	}
	defer statement.Close()
	severity := SeverityCounts{}
	for _, finding := range result.Findings {
		function, ok := functions[finding.Function.ResultID]
		if !ok || function.Address != finding.Function.Address ||
			function.Name != finding.Function.Name ||
			!validFinding(finding, function) {
			return ErrInvalidInput
		}
		switch finding.Severity {
		case "LOW":
			severity.Low++
		case "MEDIUM":
			severity.Medium++
		case "HIGH":
			severity.High++
		case "CRITICAL":
			severity.Critical++
		}
		if _, err := statement.ExecContext(
			ctx, lease.TaskID, payload.RunID, finding.CWE, finding.RuleID,
			finding.Severity, finding.Function.ResultID,
			finding.Function.Address, finding.Function.Name,
			finding.Location.StartLine, finding.Location.StartColumn,
			finding.Location.EndLine, finding.Location.EndColumn,
			finding.Message, finding.Snippet,
		); err != nil {
			return fmt.Errorf("insert C analysis finding: %w", err)
		}
	}
	for _, diagnostic := range result.Diagnostics {
		if !validDiagnostic(diagnostic, functions) {
			return ErrInvalidInput
		}
	}
	runStatus := result.Status
	analyzerStatus := result.Status
	update, err := tx.ExecContext(ctx, `
UPDATE c_analysis_runs
SET status = ?, ruleset_version = ?,
    total_functions = ?, parsed_functions = ?, failed_functions = ?,
    finding_count = ?, diagnostic_count = ?,
    low_count = ?, medium_count = ?, high_count = ?, critical_count = ?,
    findings_truncated = ?, diagnostics_truncated = ?,
    error_code = NULL, error_message = NULL,
    completed_at = UTC_TIMESTAMP(6)
WHERE task_id = ? AND id = ? AND status = 'running'`,
		runStatus, result.Checker.RulesetVersion,
		result.Coverage.TotalFunctions, result.Coverage.ParsedFunctions,
		result.Coverage.FailedFunctions, result.Summary.FindingCount,
		result.Summary.DiagnosticCount, severity.Low, severity.Medium,
		severity.High, severity.Critical, result.Summary.FindingsTruncated,
		result.Summary.DiagnosticsTruncated, lease.TaskID, payload.RunID,
	)
	if err != nil {
		return fmt.Errorf("complete C analysis run: %w", err)
	}
	if err := requireOne(update, ErrLeaseLost); err != nil {
		return err
	}
	update, err = tx.ExecContext(ctx, `
UPDATE analyzer_runs
SET status = ?, exit_code = 0, error_code = NULL, error_message = NULL,
    completed_at = UTC_TIMESTAMP(6)
WHERE task_id = ? AND id = ? AND status = 'running'`,
		analyzerStatus, lease.TaskID, payload.RunID,
	)
	if err != nil {
		return fmt.Errorf("complete C analyzer run: %w", err)
	}
	if err := requireOne(update, ErrLeaseLost); err != nil {
		return err
	}
	if err := r.revalidatePublication(ctx, tx, lease, payload, runStatus); err != nil {
		return err
	}
	if err := report.InvalidateTaskCAnalysisReports(ctx, tx, lease.TaskID); err != nil {
		return fmt.Errorf("invalidate reports after C analysis publication: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit C result publication: %w", err)
	}
	return nil
}

// PublishFailed preserves the bounded coverage and diagnostic summary returned
// by a checker that completed its request but could not analyze the input. It
// intentionally stores no findings or diagnostic detail.
func (r *MySQLRepository) PublishFailed(
	ctx context.Context,
	lease queue.Lease,
	result Result,
) error {
	payload, err := decodeJobPayload(lease.Payload)
	if err != nil || !validCAnalysisLease(lease) || result.Status != "failed" ||
		result.AnalysisID != payload.RunID ||
		result.SchemaVersion != ResponseSchemaVersion ||
		result.Checker.Name != AnalyzerName ||
		result.Checker.Version != r.analyzerVersion ||
		result.Checker.RulesetVersion != DefaultRulesetVersion ||
		result.Findings == nil || result.Diagnostics == nil ||
		len(result.Findings) != 0 || result.Summary.FindingCount != 0 ||
		result.Summary.DiagnosticCount != uint32(len(result.Diagnostics)) ||
		len(result.Diagnostics) > MaxDiagnostics {
		return ErrInvalidInput
	}
	tx, err := r.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return fmt.Errorf("begin C failed result publication: %w", err)
	}
	defer tx.Rollback()
	project, functions, err := r.lockPublication(ctx, tx, lease, payload)
	if err != nil {
		return err
	}
	if project.CanonicalSHA256 != payload.SourceSHA256 ||
		project.CanonicalSizeBytes != payload.SourceSizeBytes ||
		result.Coverage.TotalFunctions != uint32(len(functions)) ||
		result.Coverage.ParsedFunctions > result.Coverage.TotalFunctions ||
		result.Coverage.FailedFunctions > result.Coverage.TotalFunctions ||
		result.Coverage.ParsedFunctions+result.Coverage.FailedFunctions >
			result.Coverage.TotalFunctions {
		return ErrInvalidInput
	}
	for _, diagnostic := range result.Diagnostics {
		if !validDiagnostic(diagnostic, functions) {
			return ErrInvalidInput
		}
	}
	errorMessage := "C checker could not analyze the source project."
	if len(result.Diagnostics) > 0 {
		errorMessage = result.Diagnostics[0].Message
	}
	if _, err := tx.ExecContext(ctx, `
DELETE FROM c_analysis_findings WHERE task_id = ? AND run_id = ?`,
		lease.TaskID, payload.RunID,
	); err != nil {
		return fmt.Errorf("clear failed C analysis findings: %w", err)
	}
	update, err := tx.ExecContext(ctx, `
UPDATE c_analysis_runs
SET status = 'failed', ruleset_version = NULL,
    total_functions = ?, parsed_functions = ?, failed_functions = ?,
    finding_count = 0, diagnostic_count = ?,
    low_count = 0, medium_count = 0, high_count = 0, critical_count = 0,
    findings_truncated = ?, diagnostics_truncated = ?,
    error_code = 'c_checker_failed', error_message = ?,
    completed_at = UTC_TIMESTAMP(6)
WHERE task_id = ? AND id = ? AND status = 'running'`,
		result.Coverage.TotalFunctions, result.Coverage.ParsedFunctions,
		result.Coverage.FailedFunctions, result.Summary.DiagnosticCount,
		result.Summary.FindingsTruncated, result.Summary.DiagnosticsTruncated,
		errorMessage, lease.TaskID, payload.RunID,
	)
	if err != nil {
		return fmt.Errorf("complete failed C analysis run: %w", err)
	}
	if err := requireOne(update, ErrLeaseLost); err != nil {
		return err
	}
	update, err = tx.ExecContext(ctx, `
UPDATE analyzer_runs
SET status = 'failed', error_code = 'c_checker_failed', error_message = ?,
    completed_at = UTC_TIMESTAMP(6)
WHERE task_id = ? AND id = ? AND status = 'running'`,
		errorMessage, lease.TaskID, payload.RunID,
	)
	if err != nil {
		return fmt.Errorf("complete failed C analyzer run: %w", err)
	}
	if err := requireOne(update, ErrLeaseLost); err != nil {
		return err
	}
	if err := r.revalidatePublication(ctx, tx, lease, payload, "failed"); err != nil {
		return err
	}
	if err := report.InvalidateTaskSourceAnalysisReports(
		ctx, tx, lease.TaskID,
	); err != nil {
		return fmt.Errorf(
			"invalidate reports after failed C analysis publication: %w", err,
		)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit C failed result publication: %w", err)
	}
	return nil
}

func (r *MySQLRepository) Retry(
	ctx context.Context,
	lease queue.Lease,
	code string,
	message string,
) error {
	return r.finishAttempt(ctx, lease, "queued", code, message)
}

func (r *MySQLRepository) Fail(
	ctx context.Context,
	lease queue.Lease,
	code string,
	message string,
) error {
	return r.finishAttempt(ctx, lease, "failed", code, message)
}

func (r *MySQLRepository) CancelRun(
	ctx context.Context,
	lease queue.Lease,
) error {
	return r.finishAttempt(
		ctx, lease, "cancelled", "", "",
	)
}

func (r *MySQLRepository) finishAttempt(
	ctx context.Context,
	lease queue.Lease,
	status string,
	code string,
	message string,
) error {
	payload, err := decodeJobPayload(lease.Payload)
	if err != nil || !validCAnalysisLease(lease) ||
		(status != "queued" && status != "failed" && status != "cancelled") ||
		(status == "failed" &&
			(!validSafeASCII(code, 128) || !validText(message, 2048, false))) ||
		(status != "failed" && (code != "" || message != "")) {
		return ErrInvalidInput
	}
	tx, err := r.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return fmt.Errorf("begin C attempt completion: %w", err)
	}
	defer tx.Rollback()
	var runStatus, analyzerStatus string
	err = tx.QueryRowContext(ctx, `
SELECT analysis.status, analyzer.status
FROM jobs job
JOIN c_analysis_runs analysis
  ON analysis.task_id = job.task_id AND analysis.job_id = job.id
JOIN analyzer_runs analyzer
  ON analyzer.task_id = analysis.task_id AND analyzer.id = analysis.id
WHERE job.id = ? AND job.task_id = ? AND job.kind = 'c_analysis'
  AND job.status = 'running' AND job.lease_owner = ?
  AND job.fencing_token = ? AND job.lease_until > UTC_TIMESTAMP(6)
  AND analysis.id = ?
FOR UPDATE`, lease.JobID, lease.TaskID, lease.Owner,
		lease.FencingToken, payload.RunID,
	).Scan(&runStatus, &analyzerStatus)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrLeaseLost
	}
	if err != nil {
		return fmt.Errorf("lock C attempt completion: %w", err)
	}
	if runStatus != analyzerStatus ||
		(runStatus != "queued" && runStatus != "running") {
		return ErrLeaseLost
	}
	if status == "queued" {
		result, err := tx.ExecContext(ctx, `
UPDATE c_analysis_runs
SET status = 'queued', started_at = NULL, completed_at = NULL,
    error_code = NULL, error_message = NULL
WHERE task_id = ? AND id = ? AND status IN ('queued', 'running')`,
			lease.TaskID, payload.RunID,
		)
		if err != nil {
			return fmt.Errorf("requeue C analysis run: %w", err)
		}
		if err := requireOne(result, ErrLeaseLost); err != nil {
			return err
		}
		result, err = tx.ExecContext(ctx, `
UPDATE analyzer_runs
SET status = 'queued', started_at = NULL, completed_at = NULL,
    error_code = NULL, error_message = NULL
WHERE task_id = ? AND id = ? AND status IN ('queued', 'running')`,
			lease.TaskID, payload.RunID,
		)
		if err != nil {
			return fmt.Errorf("requeue C analyzer run: %w", err)
		}
		if err := requireOne(result, ErrLeaseLost); err != nil {
			return err
		}
	} else {
		analysisCode, analysisMessage := any(nil), any(nil)
		analyzerCode, analyzerMessage := any(nil), any(nil)
		if status == "failed" {
			analysisCode, analysisMessage = code, message
			analyzerCode, analyzerMessage = code, message
		}
		result, err := tx.ExecContext(ctx, `
UPDATE c_analysis_runs
SET status = ?, error_code = ?, error_message = ?,
    completed_at = UTC_TIMESTAMP(6)
WHERE task_id = ? AND id = ? AND status IN ('queued', 'running')`,
			status, analysisCode, analysisMessage, lease.TaskID, payload.RunID,
		)
		if err != nil {
			return fmt.Errorf("finish C analysis run: %w", err)
		}
		if err := requireOne(result, ErrLeaseLost); err != nil {
			return err
		}
		result, err = tx.ExecContext(ctx, `
UPDATE analyzer_runs
SET status = ?, error_code = ?, error_message = ?,
    completed_at = UTC_TIMESTAMP(6)
WHERE task_id = ? AND id = ? AND status IN ('queued', 'running')`,
			status, analyzerCode, analyzerMessage, lease.TaskID, payload.RunID,
		)
		if err != nil {
			return fmt.Errorf("finish C analyzer run: %w", err)
		}
		if err := requireOne(result, ErrLeaseLost); err != nil {
			return err
		}
	}
	if runStatus != status {
		if err := report.InvalidateTaskSourceAnalysisReports(
			ctx, tx, lease.TaskID,
		); err != nil {
			return fmt.Errorf(
				"invalidate reports after C analysis attempt completion: %w", err,
			)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit C attempt completion: %w", err)
	}
	return nil
}

func (r *MySQLRepository) lockPublication(
	ctx context.Context,
	tx *sql.Tx,
	lease queue.Lease,
	payload jobPayload,
) (ProjectSnapshot, map[string]Function, error) {
	var sourceProjectID, sourceSHA, analyzerVersion string
	var sourceSize uint64
	var totalFunctions uint32
	err := tx.QueryRowContext(ctx, `
SELECT analysis.source_project_id, analysis.source_sha256,
       analysis.source_size_bytes, analysis.total_functions,
       analyzer.analyzer_version
FROM jobs job
JOIN tasks task ON task.id = job.task_id
JOIN c_analysis_runs analysis
  ON analysis.task_id = job.task_id AND analysis.job_id = job.id
JOIN analyzer_runs analyzer
  ON analyzer.task_id = analysis.task_id AND analyzer.id = analysis.id
WHERE job.id = ? AND job.task_id = ? AND job.kind = 'c_analysis'
  AND job.status = 'running' AND job.lease_owner = ?
  AND job.fencing_token = ? AND job.lease_until > UTC_TIMESTAMP(6)
  AND task.deleted_at IS NULL
  AND analysis.id = ? AND analysis.status = 'running'
  AND analyzer.status = 'running'
FOR UPDATE`, lease.JobID, lease.TaskID, lease.Owner,
		lease.FencingToken, payload.RunID,
	).Scan(
		&sourceProjectID, &sourceSHA, &sourceSize,
		&totalFunctions, &analyzerVersion,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return ProjectSnapshot{}, nil, ErrLeaseLost
	}
	if err != nil {
		return ProjectSnapshot{}, nil, fmt.Errorf("lock C result publication: %w", err)
	}
	if sourceProjectID != payload.ProjectID || sourceSHA != payload.SourceSHA256 ||
		sourceSize != payload.SourceSizeBytes || analyzerVersion != r.analyzerVersion {
		return ProjectSnapshot{}, nil, ErrSourceUnavailable
	}
	project, attemptID, _, err := lockEligibleProject(
		ctx, tx, lease.TaskID, payload.ProjectID,
	)
	if err != nil {
		return ProjectSnapshot{}, nil, err
	}
	if lease.TaskAttemptID == nil || *lease.TaskAttemptID != attemptID ||
		project.CanonicalSHA256 != payload.SourceSHA256 ||
		project.CanonicalSizeBytes != payload.SourceSizeBytes ||
		totalFunctions != uint32(len(project.Functions)) {
		return ProjectSnapshot{}, nil, ErrSourceUnavailable
	}
	functions := make(map[string]Function, len(project.Functions))
	for _, function := range project.Functions {
		functions[function.ResultID] = function
	}
	return project, functions, nil
}

func (r *MySQLRepository) revalidatePublication(
	ctx context.Context,
	tx *sql.Tx,
	lease queue.Lease,
	payload jobPayload,
	runStatus string,
) error {
	var marker uint8
	err := tx.QueryRowContext(ctx, `
SELECT 1
FROM jobs job
JOIN tasks task ON task.id = job.task_id
JOIN c_analysis_runs analysis
  ON analysis.task_id = job.task_id AND analysis.job_id = job.id
JOIN decompile_source_projects project
  ON project.task_id = analysis.task_id
 AND project.id = analysis.source_project_id
WHERE job.id = ? AND job.task_id = ? AND job.kind = 'c_analysis'
  AND job.status = 'running' AND job.lease_owner = ?
  AND job.fencing_token = ? AND job.lease_until > UTC_TIMESTAMP(6)
  AND task.deleted_at IS NULL
  AND analysis.id = ? AND analysis.status = ?
  AND analysis.source_sha256 = ? AND analysis.source_size_bytes = ?
  AND project.deleted_at IS NULL AND project.storage_deleted_at IS NULL
  AND project.canonical_sha256 = analysis.source_sha256
  AND project.canonical_size_bytes = analysis.source_size_bytes`,
		lease.JobID, lease.TaskID, lease.Owner, lease.FencingToken,
		payload.RunID, runStatus, payload.SourceSHA256, payload.SourceSizeBytes,
	).Scan(&marker)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrLeaseLost
	}
	if err != nil {
		return fmt.Errorf("revalidate C result publication: %w", err)
	}
	return nil
}

func decodeJobPayload(raw json.RawMessage) (jobPayload, error) {
	if len(raw) == 0 || len(raw) > 4096 {
		return jobPayload{}, ErrInvalidInput
	}
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.DisallowUnknownFields()
	var payload jobPayload
	if decoder.Decode(&payload) != nil || requireJSONEnd(decoder) != nil ||
		payload.SchemaVersion != jobPayloadSchemaVersion ||
		!uuidPattern.MatchString(payload.RunID) ||
		!uuidPattern.MatchString(payload.ProjectID) ||
		!sha256Pattern.MatchString(payload.SourceSHA256) ||
		payload.SourceSizeBytes == 0 || payload.SourceSizeBytes > uint64(MaxSourceBytes) {
		return jobPayload{}, ErrInvalidInput
	}
	return payload, nil
}

func validCAnalysisLease(lease queue.Lease) bool {
	return lease.Kind == queue.KindCAnalysis &&
		uuidPattern.MatchString(lease.JobID) && uuidPattern.MatchString(lease.TaskID) &&
		lease.TaskAttemptID != nil && *lease.TaskAttemptID > 0 &&
		lease.Attempt > 0 && lease.MaxAttempts > 0 &&
		lease.Attempt <= lease.MaxAttempts && lease.FencingToken > 0 &&
		validText(lease.Owner, 255, false)
}

func deterministicFailure(code string) queue.FinishInput {
	return queue.FinishInput{
		Outcome:   queue.OutcomeDeterministicFailure,
		ErrorCode: code, ErrorMessage: "C analysis could not be completed.",
	}
}

func transientFailure(code string) queue.FinishInput {
	return queue.FinishInput{
		Outcome:   queue.OutcomeTransientFailure,
		ErrorCode: code, ErrorMessage: "C analysis will be retried.",
	}
}

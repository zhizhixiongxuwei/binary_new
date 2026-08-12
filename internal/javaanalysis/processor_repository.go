package javaanalysis

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"binaryscan/internal/queue"
)

type jobPayload struct {
	SchemaVersion        string `json:"schema_version"`
	RunID                string `json:"run_id"`
	ProjectID            string `json:"project_id"`
	SourceManifestSHA256 string `json:"source_manifest_sha256"`
	InputSHA256          string `json:"input_sha256"`
	SourceSizeBytes      uint64 `json:"source_size_bytes"`
	SourceFileCount      uint32 `json:"source_file_count"`
}

func (r *MySQLRepository) Begin(
	ctx context.Context,
	lease queue.Lease,
) (ProjectSnapshot, error) {
	payload, err := decodeJobPayload(lease.Payload)
	if err != nil || !validJavaAnalysisLease(lease) {
		return ProjectSnapshot{}, ErrInvalidInput
	}
	tx, err := r.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return ProjectSnapshot{}, fmt.Errorf("begin Java worker run: %w", err)
	}
	defer tx.Rollback()
	var runStatus, analyzerStatus, analyzerVersion string
	var runErrorCode sql.NullString
	var sourceProjectID, manifestSHA, inputSHA string
	var sourceSize uint64
	var sourceCount uint32
	err = tx.QueryRowContext(ctx, `
SELECT analysis.status, analysis.source_project_id,
       analysis.source_manifest_sha256, analysis.input_sha256,
       analysis.source_size_bytes, analysis.source_file_count,
       analysis.error_code, analyzer.status, analyzer.analyzer_version
FROM jobs job
JOIN java_analysis_runs analysis
  ON analysis.task_id = job.task_id AND analysis.job_id = job.id
JOIN analyzer_runs analyzer
  ON analyzer.task_id = analysis.task_id AND analyzer.id = analysis.id
WHERE job.id = ? AND job.task_id = ? AND job.kind = 'java_analysis'
  AND job.status = 'running' AND job.lease_owner = ?
  AND job.fencing_token = ? AND job.lease_until > UTC_TIMESTAMP(6)
  AND analysis.id = ?
FOR UPDATE`, lease.JobID, lease.TaskID, lease.Owner, lease.FencingToken,
		payload.RunID,
	).Scan(
		&runStatus, &sourceProjectID, &manifestSHA, &inputSHA,
		&sourceSize, &sourceCount, &runErrorCode, &analyzerStatus,
		&analyzerVersion,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return ProjectSnapshot{}, ErrLeaseLost
	}
	if err != nil {
		return ProjectSnapshot{}, fmt.Errorf("lock Java worker run: %w", err)
	}
	if sourceProjectID != payload.ProjectID ||
		manifestSHA != payload.SourceManifestSHA256 ||
		inputSHA != payload.InputSHA256 || sourceSize != payload.SourceSizeBytes ||
		sourceCount != payload.SourceFileCount ||
		analyzerVersion != r.analyzerVersion {
		return ProjectSnapshot{}, ErrSourceUnavailable
	}
	switch runStatus {
	case "succeeded", "partial":
		return ProjectSnapshot{}, ErrAlreadyPublished
	case "failed":
		if runErrorCode.Valid && runErrorCode.String == "java_checker_failed" {
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
		!payloadMatchesProject(payload, project) ||
		analyzerStatus != "queued" && analyzerStatus != "running" {
		return ProjectSnapshot{}, ErrSourceUnavailable
	}
	if runStatus == "running" && analyzerStatus == "running" {
		if err := tx.Commit(); err != nil {
			return ProjectSnapshot{}, fmt.Errorf("commit Java worker replay: %w", err)
		}
		return project, nil
	}
	update, err := tx.ExecContext(ctx, `
UPDATE java_analysis_runs
SET status = 'running', started_at = COALESCE(started_at, UTC_TIMESTAMP(6)),
    completed_at = NULL, error_code = NULL, error_message = NULL
WHERE task_id = ? AND id = ? AND status IN ('queued', 'running')`,
		lease.TaskID, payload.RunID,
	)
	if err != nil {
		return ProjectSnapshot{}, fmt.Errorf("start Java analysis run: %w", err)
	}
	if err := requireOne(update, ErrLeaseLost); err != nil {
		return ProjectSnapshot{}, err
	}
	update, err = tx.ExecContext(ctx, `
UPDATE analyzer_runs
SET status = 'running', started_at = COALESCE(started_at, UTC_TIMESTAMP(6)),
    completed_at = NULL, error_code = NULL, error_message = NULL
WHERE task_id = ? AND id = ? AND status IN ('queued', 'running')`,
		lease.TaskID, payload.RunID,
	)
	if err != nil {
		return ProjectSnapshot{}, fmt.Errorf("start Java analyzer run: %w", err)
	}
	if err := requireOne(update, ErrLeaseLost); err != nil {
		return ProjectSnapshot{}, err
	}
	if err := r.invalidateReports(ctx, tx, lease.TaskID); err != nil {
		return ProjectSnapshot{}, fmt.Errorf(
			"invalidate reports after Java analysis start: %w", err,
		)
	}
	if err := tx.Commit(); err != nil {
		return ProjectSnapshot{}, fmt.Errorf("commit Java worker run: %w", err)
	}
	return project, nil
}

func (r *MySQLRepository) SetBundleIdentity(
	ctx context.Context,
	lease queue.Lease,
	bundleSHA256 string,
) error {
	payload, err := decodeJobPayload(lease.Payload)
	if err != nil || !validJavaAnalysisLease(lease) ||
		!sha256Pattern.MatchString(bundleSHA256) {
		return ErrInvalidInput
	}
	tx, err := r.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return fmt.Errorf("begin Java bundle publication: %w", err)
	}
	defer tx.Rollback()
	update, err := tx.ExecContext(ctx, `
UPDATE java_analysis_runs analysis
JOIN jobs job ON job.task_id = analysis.task_id AND job.id = analysis.job_id
SET analysis.bundle_sha256 = ?
WHERE job.id = ? AND job.task_id = ? AND job.kind = 'java_analysis'
  AND job.status = 'running' AND job.lease_owner = ?
  AND job.fencing_token = ? AND job.lease_until > UTC_TIMESTAMP(6)
  AND analysis.id = ? AND analysis.status = 'running'
  AND analysis.source_manifest_sha256 = ? AND analysis.input_sha256 = ?
  AND (analysis.bundle_sha256 IS NULL OR analysis.bundle_sha256 = ?)`,
		bundleSHA256, lease.JobID, lease.TaskID, lease.Owner,
		lease.FencingToken, payload.RunID, payload.SourceManifestSHA256,
		payload.InputSHA256, bundleSHA256,
	)
	if err != nil {
		return fmt.Errorf("publish Java bundle identity: %w", err)
	}
	if err := requireOne(update, ErrLeaseLost); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit Java bundle identity: %w", err)
	}
	return nil
}

func (r *MySQLRepository) Publish(
	ctx context.Context,
	lease queue.Lease,
	metadata RequestMetadata,
	result Result,
) error {
	payload, err := decodeJobPayload(lease.Payload)
	if err != nil || !validJavaAnalysisLease(lease) ||
		(result.Status != "complete" && result.Status != "partial") {
		return ErrInvalidInput
	}
	tx, err := r.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return fmt.Errorf("begin Java result publication: %w", err)
	}
	defer tx.Rollback()
	project, bundleSHA, err := r.lockPublication(ctx, tx, lease, payload)
	if err != nil {
		return err
	}
	expectedAnalysisID := javaCheckerAnalysisID(
		payload.RunID, lease.JobID, lease.FencingToken,
	)
	if !metadataMatchesProject(metadata, expectedAnalysisID, project, bundleSHA) {
		return ErrSourceUnavailable
	}
	if err := validateResult(result, metadata, MaxFindings, MaxDiagnostics); err != nil {
		return ErrInvalidInput
	}
	if _, err := tx.ExecContext(ctx, `
DELETE FROM java_analysis_findings WHERE task_id = ? AND run_id = ?`,
		lease.TaskID, payload.RunID,
	); err != nil {
		return fmt.Errorf("clear replayed Java findings: %w", err)
	}
	statement, err := tx.PrepareContext(ctx, `
INSERT INTO java_analysis_findings (
    task_id, run_id, cwe, rule_id, severity,
    file_result_id, logical_path, binary_name,
    callable_kind, type_name, callable_name, callable_signature,
    start_line, start_column, end_line, end_column,
    message, snippet, snippet_start_line
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
          ?, ?, ?, ?, ?, NULLIF(?, ''), NULLIF(?, 0))`)
	if err != nil {
		return fmt.Errorf("prepare Java finding publication: %w", err)
	}
	defer statement.Close()
	severity := SeverityCounts{}
	for _, finding := range result.Findings {
		switch finding.Severity {
		case "LOW":
			severity.Low++
		case "MEDIUM":
			severity.Medium++
		case "HIGH":
			severity.High++
		case "CRITICAL":
			severity.Critical++
		default:
			return ErrInvalidInput
		}
		if _, err := statement.ExecContext(
			ctx, lease.TaskID, payload.RunID, finding.CWE, finding.RuleID,
			finding.Severity, finding.File.ResultID, finding.File.LogicalPath,
			finding.File.BinaryName, finding.Callable.Kind,
			finding.Callable.TypeName, finding.Callable.Name,
			finding.Callable.Signature, finding.Location.StartLine,
			finding.Location.StartColumn, finding.Location.EndLine,
			finding.Location.EndColumn, finding.Message, finding.Snippet,
			finding.SnippetStartLine,
		); err != nil {
			return fmt.Errorf("insert Java analysis finding: %w", err)
		}
	}
	runStatus := "succeeded"
	analyzerStatus := "succeeded"
	if result.Status == "partial" {
		runStatus = "partial"
		analyzerStatus = "partial"
	}
	update, err := tx.ExecContext(ctx, `
UPDATE java_analysis_runs
SET status = ?, ruleset_version = ?, analyzed_files = ?, parsed_files = ?,
    recovered_files = ?, failed_files = ?, finding_count = ?,
    diagnostic_count = ?, low_count = ?, medium_count = ?, high_count = ?,
    critical_count = ?, findings_truncated = ?, diagnostics_truncated = ?,
    error_code = NULL, error_message = NULL, completed_at = UTC_TIMESTAMP(6)
WHERE task_id = ? AND id = ? AND status = 'running'`,
		runStatus, result.Identity.Ruleset, result.Coverage.FilesAnalyzed,
		result.Coverage.FilesParsed, result.Coverage.FilesRecovered,
		result.Coverage.FilesFailed,
		result.Summary.FindingCount, result.Summary.DiagnosticCount,
		severity.Low, severity.Medium, severity.High, severity.Critical,
		result.Summary.FindingsTruncated, result.Summary.DiagnosticsTruncated,
		lease.TaskID, payload.RunID,
	)
	if err != nil {
		return fmt.Errorf("complete Java analysis run: %w", err)
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
		return fmt.Errorf("complete Java analyzer run: %w", err)
	}
	if err := requireOne(update, ErrLeaseLost); err != nil {
		return err
	}
	if err := r.revalidatePublication(ctx, tx, lease, payload, runStatus); err != nil {
		return err
	}
	if err := r.invalidateReports(ctx, tx, lease.TaskID); err != nil {
		return fmt.Errorf("invalidate reports after Java analysis publication: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit Java result publication: %w", err)
	}
	return nil
}

func (r *MySQLRepository) PublishFailed(
	ctx context.Context,
	lease queue.Lease,
	metadata RequestMetadata,
	result Result,
) error {
	payload, err := decodeJobPayload(lease.Payload)
	if err != nil || !validJavaAnalysisLease(lease) || result.Status != "failed" {
		return ErrInvalidInput
	}
	tx, err := r.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return fmt.Errorf("begin Java failed result publication: %w", err)
	}
	defer tx.Rollback()
	project, bundleSHA, err := r.lockPublication(ctx, tx, lease, payload)
	if err != nil {
		return err
	}
	expectedAnalysisID := javaCheckerAnalysisID(
		payload.RunID, lease.JobID, lease.FencingToken,
	)
	if !metadataMatchesProject(metadata, expectedAnalysisID, project, bundleSHA) {
		return ErrSourceUnavailable
	}
	if err := validateResult(result, metadata, MaxFindings, MaxDiagnostics); err != nil ||
		len(result.Findings) != 0 {
		return ErrInvalidInput
	}
	errorMessage := "Java checker could not analyze the source project."
	if len(result.Diagnostics) > 0 {
		errorMessage = result.Diagnostics[0].Message
	}
	if _, err := tx.ExecContext(ctx, `
DELETE FROM java_analysis_findings WHERE task_id = ? AND run_id = ?`,
		lease.TaskID, payload.RunID,
	); err != nil {
		return fmt.Errorf("clear failed Java analysis findings: %w", err)
	}
	update, err := tx.ExecContext(ctx, `
UPDATE java_analysis_runs
SET status = 'failed', ruleset_version = NULL,
    analyzed_files = ?, parsed_files = ?, recovered_files = ?, failed_files = ?,
    finding_count = 0, diagnostic_count = ?, low_count = 0, medium_count = 0,
    high_count = 0, critical_count = 0, findings_truncated = ?,
    diagnostics_truncated = ?, error_code = 'java_checker_failed',
    error_message = ?, completed_at = UTC_TIMESTAMP(6)
WHERE task_id = ? AND id = ? AND status = 'running'`,
		result.Coverage.FilesAnalyzed, result.Coverage.FilesParsed,
		result.Coverage.FilesRecovered, result.Coverage.FilesFailed,
		result.Summary.DiagnosticCount,
		result.Summary.FindingsTruncated, result.Summary.DiagnosticsTruncated,
		errorMessage, lease.TaskID, payload.RunID,
	)
	if err != nil {
		return fmt.Errorf("complete failed Java analysis run: %w", err)
	}
	if err := requireOne(update, ErrLeaseLost); err != nil {
		return err
	}
	update, err = tx.ExecContext(ctx, `
UPDATE analyzer_runs
SET status = 'failed', error_code = 'java_checker_failed', error_message = ?,
    completed_at = UTC_TIMESTAMP(6)
WHERE task_id = ? AND id = ? AND status = 'running'`,
		errorMessage, lease.TaskID, payload.RunID,
	)
	if err != nil {
		return fmt.Errorf("complete failed Java analyzer run: %w", err)
	}
	if err := requireOne(update, ErrLeaseLost); err != nil {
		return err
	}
	if err := r.revalidatePublication(ctx, tx, lease, payload, "failed"); err != nil {
		return err
	}
	if err := r.invalidateReports(ctx, tx, lease.TaskID); err != nil {
		return fmt.Errorf(
			"invalidate reports after failed Java analysis publication: %w", err,
		)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit Java failed result publication: %w", err)
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
	return r.finishAttempt(ctx, lease, "cancelled", "", "")
}

func (r *MySQLRepository) finishAttempt(
	ctx context.Context,
	lease queue.Lease,
	status string,
	code string,
	message string,
) error {
	payload, err := decodeJobPayload(lease.Payload)
	if err != nil || !validJavaAnalysisLease(lease) ||
		(status != "queued" && status != "failed" && status != "cancelled") ||
		(status == "failed" &&
			(!validSafeASCII(code, 128) || !validText(message, 2048, false))) ||
		(status != "failed" && status != "queued" && (code != "" || message != "")) {
		return ErrInvalidInput
	}
	tx, err := r.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return fmt.Errorf("begin Java attempt completion: %w", err)
	}
	defer tx.Rollback()
	var runStatus, analyzerStatus string
	err = tx.QueryRowContext(ctx, `
SELECT analysis.status, analyzer.status
FROM jobs job
JOIN java_analysis_runs analysis
  ON analysis.task_id = job.task_id AND analysis.job_id = job.id
JOIN analyzer_runs analyzer
  ON analyzer.task_id = analysis.task_id AND analyzer.id = analysis.id
WHERE job.id = ? AND job.task_id = ? AND job.kind = 'java_analysis'
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
		return fmt.Errorf("lock Java attempt completion: %w", err)
	}
	if runStatus != analyzerStatus ||
		(runStatus != "queued" && runStatus != "running") {
		return ErrLeaseLost
	}
	if status == "queued" {
		update, err := tx.ExecContext(ctx, `
UPDATE java_analysis_runs
SET status = 'queued', bundle_sha256 = NULL, started_at = NULL,
    completed_at = NULL, ruleset_version = NULL,
    analyzed_files = 0, parsed_files = 0, recovered_files = 0,
    failed_files = 0, finding_count = 0, diagnostic_count = 0,
    low_count = 0, medium_count = 0, high_count = 0, critical_count = 0,
    findings_truncated = FALSE, diagnostics_truncated = FALSE,
    error_code = NULL, error_message = NULL
WHERE task_id = ? AND id = ? AND status IN ('queued', 'running')`,
			lease.TaskID, payload.RunID,
		)
		if err != nil {
			return fmt.Errorf("requeue Java analysis run: %w", err)
		}
		if err := requireOne(update, ErrLeaseLost); err != nil {
			return err
		}
		update, err = tx.ExecContext(ctx, `
UPDATE analyzer_runs
SET status = 'queued', started_at = NULL, completed_at = NULL,
    error_code = NULL, error_message = NULL
WHERE task_id = ? AND id = ? AND status IN ('queued', 'running')`,
			lease.TaskID, payload.RunID,
		)
		if err != nil {
			return fmt.Errorf("requeue Java analyzer run: %w", err)
		}
		if err := requireOne(update, ErrLeaseLost); err != nil {
			return err
		}
	} else {
		analysisCode, analysisMessage := any(nil), any(nil)
		if status == "failed" {
			analysisCode, analysisMessage = code, message
		}
		update, err := tx.ExecContext(ctx, `
UPDATE java_analysis_runs
SET status = ?, error_code = ?, error_message = ?,
    completed_at = UTC_TIMESTAMP(6)
WHERE task_id = ? AND id = ? AND status IN ('queued', 'running')`,
			status, analysisCode, analysisMessage, lease.TaskID, payload.RunID,
		)
		if err != nil {
			return fmt.Errorf("finish Java analysis run: %w", err)
		}
		if err := requireOne(update, ErrLeaseLost); err != nil {
			return err
		}
		update, err = tx.ExecContext(ctx, `
UPDATE analyzer_runs
SET status = ?, error_code = ?, error_message = ?,
    completed_at = UTC_TIMESTAMP(6)
WHERE task_id = ? AND id = ? AND status IN ('queued', 'running')`,
			status, analysisCode, analysisMessage, lease.TaskID, payload.RunID,
		)
		if err != nil {
			return fmt.Errorf("finish Java analyzer run: %w", err)
		}
		if err := requireOne(update, ErrLeaseLost); err != nil {
			return err
		}
	}
	if runStatus != status {
		if err := r.invalidateReports(ctx, tx, lease.TaskID); err != nil {
			return fmt.Errorf(
				"invalidate reports after Java analysis attempt completion: %w", err,
			)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit Java attempt completion: %w", err)
	}
	return nil
}

func (r *MySQLRepository) lockPublication(
	ctx context.Context,
	tx *sql.Tx,
	lease queue.Lease,
	payload jobPayload,
) (ProjectSnapshot, string, error) {
	var sourceProjectID, manifestSHA, inputSHA, bundleSHA, analyzerVersion string
	var sourceSize uint64
	var sourceCount uint32
	err := tx.QueryRowContext(ctx, `
SELECT analysis.source_project_id, analysis.source_manifest_sha256,
       analysis.input_sha256, analysis.bundle_sha256,
       analysis.source_size_bytes, analysis.source_file_count,
       analyzer.analyzer_version
FROM jobs job
JOIN tasks task ON task.id = job.task_id
JOIN java_analysis_runs analysis
  ON analysis.task_id = job.task_id AND analysis.job_id = job.id
JOIN analyzer_runs analyzer
  ON analyzer.task_id = analysis.task_id AND analyzer.id = analysis.id
WHERE job.id = ? AND job.task_id = ? AND job.kind = 'java_analysis'
  AND job.status = 'running' AND job.lease_owner = ?
  AND job.fencing_token = ? AND job.lease_until > UTC_TIMESTAMP(6)
  AND task.deleted_at IS NULL AND analysis.id = ?
  AND analysis.status = 'running' AND analyzer.status = 'running'
  AND analysis.bundle_sha256 IS NOT NULL
FOR UPDATE`, lease.JobID, lease.TaskID, lease.Owner,
		lease.FencingToken, payload.RunID,
	).Scan(
		&sourceProjectID, &manifestSHA, &inputSHA, &bundleSHA,
		&sourceSize, &sourceCount, &analyzerVersion,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return ProjectSnapshot{}, "", ErrLeaseLost
	}
	if err != nil {
		return ProjectSnapshot{}, "", fmt.Errorf("lock Java result publication: %w", err)
	}
	if sourceProjectID != payload.ProjectID ||
		manifestSHA != payload.SourceManifestSHA256 || inputSHA != payload.InputSHA256 ||
		sourceSize != payload.SourceSizeBytes || sourceCount != payload.SourceFileCount ||
		analyzerVersion != r.analyzerVersion || !sha256Pattern.MatchString(bundleSHA) {
		return ProjectSnapshot{}, "", ErrSourceUnavailable
	}
	project, attemptID, _, err := lockEligibleProject(
		ctx, tx, lease.TaskID, payload.ProjectID,
	)
	if err != nil {
		return ProjectSnapshot{}, "", err
	}
	if lease.TaskAttemptID == nil || *lease.TaskAttemptID != attemptID ||
		!payloadMatchesProject(payload, project) {
		return ProjectSnapshot{}, "", ErrSourceUnavailable
	}
	return project, bundleSHA, nil
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
JOIN java_analysis_runs analysis
  ON analysis.task_id = job.task_id AND analysis.job_id = job.id
JOIN decompile_source_projects project
  ON project.task_id = analysis.task_id
 AND project.id = analysis.source_project_id
WHERE job.id = ? AND job.task_id = ? AND job.kind = 'java_analysis'
  AND job.status = 'running' AND job.lease_owner = ?
  AND job.fencing_token = ? AND job.lease_until > UTC_TIMESTAMP(6)
  AND task.deleted_at IS NULL AND analysis.id = ? AND analysis.status = ?
  AND analysis.source_manifest_sha256 = ? AND analysis.input_sha256 = ?
  AND analysis.source_size_bytes = ? AND analysis.source_file_count = ?
  AND project.deleted_at IS NULL AND project.storage_deleted_at IS NULL
  AND project.manifest_sha256 = analysis.source_manifest_sha256`,
		lease.JobID, lease.TaskID, lease.Owner, lease.FencingToken,
		payload.RunID, runStatus, payload.SourceManifestSHA256,
		payload.InputSHA256, payload.SourceSizeBytes, payload.SourceFileCount,
	).Scan(&marker)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrLeaseLost
	}
	if err != nil {
		return fmt.Errorf("revalidate Java result publication: %w", err)
	}
	return nil
}

func metadataMatchesProject(
	metadata RequestMetadata,
	analysisID string,
	project ProjectSnapshot,
	bundleSHA string,
) bool {
	if !validRequestMetadata(metadata) || metadata.AnalysisID != analysisID ||
		metadata.InputSHA256 != project.InputSHA256 ||
		metadata.BundleSHA256 != bundleSHA ||
		metadata.SourceManifestSHA256 != project.ManifestSHA256 ||
		metadata.ProjectID != project.ProjectID ||
		metadata.Language != project.Language ||
		metadata.ProjectStatus != project.AnalysisProjectStatus ||
		len(metadata.Files) != len(project.Files) {
		return false
	}
	for index, actual := range metadata.Files {
		expected := project.Files[index]
		if actual.ResultID != expected.ResultID ||
			actual.LogicalPath != expected.LogicalPath ||
			actual.BinaryName != expected.BinaryName ||
			actual.SHA256 != expected.SHA256 ||
			actual.SizeBytes != expected.SizeBytes {
			return false
		}
	}
	return true
}

func payloadMatchesProject(payload jobPayload, project ProjectSnapshot) bool {
	return project.ProjectID == payload.ProjectID &&
		project.ManifestSHA256 == payload.SourceManifestSHA256 &&
		project.InputSHA256 == payload.InputSHA256 &&
		project.SourceSizeBytes == payload.SourceSizeBytes &&
		uint32(len(project.Files)) == payload.SourceFileCount
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
		!sha256Pattern.MatchString(payload.SourceManifestSHA256) ||
		!sha256Pattern.MatchString(payload.InputSHA256) ||
		payload.SourceSizeBytes == 0 || payload.SourceSizeBytes > uint64(MaxSourceBytes) ||
		payload.SourceFileCount == 0 || payload.SourceFileCount > MaxFiles {
		return jobPayload{}, ErrInvalidInput
	}
	return payload, nil
}

func validJavaAnalysisLease(lease queue.Lease) bool {
	return lease.Kind == queue.KindJavaAnalysis &&
		uuidPattern.MatchString(lease.JobID) && uuidPattern.MatchString(lease.TaskID) &&
		lease.TaskAttemptID != nil && *lease.TaskAttemptID > 0 &&
		lease.Attempt > 0 && lease.MaxAttempts > 0 &&
		lease.Attempt <= lease.MaxAttempts && lease.FencingToken > 0 &&
		validText(lease.Owner, 255, false)
}

func deterministicFailure(code string) queue.FinishInput {
	return queue.FinishInput{
		Outcome: queue.OutcomeDeterministicFailure, ErrorCode: code,
		ErrorMessage: "Java analysis could not be completed.",
	}
}

func transientFailure(code string) queue.FinishInput {
	return queue.FinishInput{
		Outcome: queue.OutcomeTransientFailure, ErrorCode: code,
		ErrorMessage: "Java analysis will be retried.",
	}
}

package pythonanalysis

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"sort"
	"regexp"
	"strconv"
	"strings"
	"time"

	"binaryscan/internal/queue"
)

const (
	jobPayloadSchemaVersion = "binaryscan-python-analysis-job/v1"
	manifestSchemaVersion   = "binaryscan-source-project/v1"
)

var (
	uuidPattern  = regexp.MustCompile(`^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$`)
	ErrLeaseLost = errors.New("python analysis lease is lost")
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
		payload.SourceSizeBytes == 0 ||
		payload.SourceSizeBytes > uint64(MaxSourceBytes) ||
		payload.SourceFileCount == 0 ||
		payload.SourceFileCount > MaxFileCount {
		return jobPayload{}, ErrInvalidInput
	}
	return payload, nil
}

func requireJSONEnd(decoder *json.Decoder) error {
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return errors.New("multiple JSON values")
		}
		return err
	}
	return nil
}

func validPythonAnalysisLease(lease queue.Lease) bool {
	return lease.Kind == queue.KindPythonAnalysis &&
		uuidPattern.MatchString(lease.JobID) &&
		uuidPattern.MatchString(lease.TaskID) &&
		lease.TaskAttemptID != nil && *lease.TaskAttemptID > 0 &&
		lease.Attempt > 0 && lease.MaxAttempts > 0 &&
		lease.Attempt <= lease.MaxAttempts && lease.FencingToken > 0 &&
		lease.Owner != ""
}

// Begin locks the run and analyzer rows, validates the payload snapshot, and
// loads the manifest-verified Python source project.
func (r *MySQLRepository) Begin(
	ctx context.Context,
	lease queue.Lease,
) (ProjectSnapshot, error) {
	payload, err := decodeJobPayload(lease.Payload)
	if err != nil || !validPythonAnalysisLease(lease) {
		return ProjectSnapshot{}, ErrInvalidInput
	}
	tx, err := r.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return ProjectSnapshot{}, fmt.Errorf("begin python worker run: %w", err)
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
JOIN python_analysis_runs analysis
  ON analysis.task_id = job.task_id AND analysis.job_id = job.id
JOIN analyzer_runs analyzer
  ON analyzer.task_id = analysis.task_id AND analyzer.id = analysis.id
WHERE job.id = ? AND job.task_id = ? AND job.kind = 'python_analysis'
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
		return ProjectSnapshot{}, fmt.Errorf("lock python worker run: %w", err)
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
		if runErrorCode.Valid && runErrorCode.String == "python_checker_failed" {
			return ProjectSnapshot{}, ErrFailedResultPublished
		}
		return ProjectSnapshot{}, ErrAlreadyTerminal
	case "cancelled":
		return ProjectSnapshot{}, ErrAlreadyTerminal
	case "queued", "running":
	default:
		return ProjectSnapshot{}, ErrSourceUnavailable
	}
	project, attemptID, err := r.lockEligibleProject(ctx, tx, lease.TaskID, sourceProjectID)
	if err != nil {
		return ProjectSnapshot{}, err
	}
	if lease.TaskAttemptID == nil || *lease.TaskAttemptID != attemptID ||
		analyzerStatus != "queued" && analyzerStatus != "running" {
		return ProjectSnapshot{}, ErrSourceUnavailable
	}
	if runStatus == "running" && analyzerStatus == "running" {
		if err := tx.Commit(); err != nil {
			return ProjectSnapshot{}, fmt.Errorf("commit python worker replay: %w", err)
		}
		return project, nil
	}
	for _, statement := range []string{
		`UPDATE python_analysis_runs
SET status = 'running', started_at = COALESCE(started_at, UTC_TIMESTAMP(6)),
    completed_at = NULL, error_code = NULL, error_message = NULL
WHERE task_id = ? AND id = ? AND status IN ('queued', 'running')`,
		`UPDATE analyzer_runs
SET status = 'running', started_at = COALESCE(started_at, UTC_TIMESTAMP(6)),
    completed_at = NULL, error_code = NULL, error_message = NULL
WHERE task_id = ? AND id = ? AND status IN ('queued', 'running')`,
	} {
		update, updateErr := tx.ExecContext(ctx, statement, lease.TaskID, payload.RunID)
		if updateErr != nil {
			return ProjectSnapshot{}, fmt.Errorf("start python analysis run: %w", updateErr)
		}
		if affected, _ := update.RowsAffected(); affected != 1 {
			return ProjectSnapshot{}, ErrLeaseLost
		}
	}
	if r.invalidateReports != nil {
		if err := r.invalidateReports(ctx, tx, lease.TaskID); err != nil {
			return ProjectSnapshot{}, fmt.Errorf(
				"invalidate reports after python analysis start: %w", err,
			)
		}
	}
	if err := tx.Commit(); err != nil {
		return ProjectSnapshot{}, fmt.Errorf("commit python worker run: %w", err)
	}
	return project, nil
}

// lockEligibleProject loads the decompiled Python project and its source
// files, verifying every manifest binding.
func (r *MySQLRepository) lockEligibleProject(
	ctx context.Context,
	tx *sql.Tx,
	taskID string,
	projectID string,
) (ProjectSnapshot, uint64, error) {
	var project ProjectSnapshot
	var attemptID sql.Null[uint64]
	var sourceFileCount, projectSourceSize uint64
	var rootKey, manifestKey, manifestSHA sql.NullString
	var manifestSize sql.Null[uint64]
	err := tx.QueryRowContext(ctx, `
SELECT project.status, project.engine_name, project.engine_version,
       project.root_storage_key, project.manifest_storage_key,
       project.manifest_sha256, project.manifest_size_bytes,
       project.source_file_count, project.source_size_bytes,
       source_run.task_attempt_id
FROM decompile_source_projects project
JOIN analyzer_runs source_run
  ON source_run.task_id = project.task_id AND source_run.id = project.id
WHERE project.task_id = ? AND project.id = ?
  AND project.layout_version = 'project-v1'
  AND project.source_kind = 'python'
  AND project.status IN ('complete', 'partial')
  AND project.deleted_at IS NULL
  AND project.storage_deleted_at IS NULL
FOR UPDATE`, taskID, projectID).Scan(
		&project.ProjectStatus, &project.EngineName, &project.EngineVersion,
		&rootKey, &manifestKey, &manifestSHA, &manifestSize,
		&sourceFileCount, &projectSourceSize, &attemptID,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return ProjectSnapshot{}, 0, ErrProjectNotFound
	}
	if err != nil {
		return ProjectSnapshot{}, 0, fmt.Errorf("lock python source project: %w", err)
	}
	project.TaskID = taskID
	project.ProjectID = projectID
	project.RootStorageKey = rootKey.String
	project.ManifestStorageKey = manifestKey.String
	project.ManifestSHA256 = manifestSHA.String
	project.ManifestSizeBytes = manifestSize.V
	project.ProjectSourceFileCount = sourceFileCount
	project.ProjectSourceSizeBytes = projectSourceSize
	expectedRoot := path.Join("source-projects", projectID)
	if !attemptID.Valid || attemptID.V == 0 ||
		!validSafeASCII(project.EngineName, 128) ||
		!validSafeASCII(project.EngineVersion, 128) ||
		rootKey.String != expectedRoot ||
		manifestKey.String != path.Join(expectedRoot, "manifest.json") ||
		!sha256Pattern.MatchString(manifestSHA.String) ||
		manifestSize.V == 0 || manifestSize.V > uint64(MaxSourceBytes) ||
		sourceFileCount == 0 || projectSourceSize == 0 {
		return ProjectSnapshot{}, 0, ErrSourceUnavailable
	}
	files, err := r.loadProjectFiles(ctx, tx, expectedRoot, taskID, projectID)
	if err != nil {
		return ProjectSnapshot{}, 0, err
	}
	if len(files) == 0 || len(files) > MaxFileCount {
		return ProjectSnapshot{}, 0, ErrSourceUnavailable
	}
	project.Files = files
	var totalSourceBytes uint64
	for _, file := range files {
		if totalSourceBytes > ^uint64(0)-file.SizeBytes {
			return ProjectSnapshot{}, 0, ErrSourceUnavailable
		}
		totalSourceBytes += file.SizeBytes
	}
	if totalSourceBytes == 0 || totalSourceBytes > uint64(MaxSourceBytes) {
		return ProjectSnapshot{}, 0, ErrSourceUnavailable
	}
	project.SourceSizeBytes = totalSourceBytes
	inputSHA, err := canonicalInputSHA256(files)
	if err != nil || !sha256Pattern.MatchString(inputSHA) {
		return ProjectSnapshot{}, 0, ErrSourceUnavailable
	}
	project.InputSHA256 = inputSHA
	return project, attemptID.V, nil
}

// canonicalInputSHA256 derives the stable input identity from the sorted
// manifest-verified file listing.
func canonicalInputSHA256(files []ManifestFile) (string, error) {
	if len(files) == 0 || len(files) > MaxFileCount {
		return "", ErrSourceUnavailable
	}
	copied := append([]ManifestFile(nil), files...)
	sort.Slice(copied, func(i, j int) bool {
		return copied[i].LogicalPath < copied[j].LogicalPath
	})
	hasher := sha256.New()
	_, _ = io.WriteString(hasher, manifestSchemaVersion+"\n")
	previous := ""
	for _, file := range copied {
		if !validRelativePath(file.LogicalPath) ||
			file.LogicalPath == previous ||
			!sha256Pattern.MatchString(file.SHA256) || file.SizeBytes == 0 {
			return "", ErrSourceUnavailable
		}
		previous = file.LogicalPath
		values := []string{
			file.LogicalPath, strconv.FormatUint(file.SizeBytes, 10), file.SHA256,
		}
		for index, value := range values {
			_, _ = io.WriteString(hasher, value)
			if index < len(values)-1 {
				_, _ = hasher.Write([]byte{0})
			}
		}
		_, _ = hasher.Write([]byte{0})
	}
	return hex.EncodeToString(hasher.Sum(nil)), nil
}

func (r *MySQLRepository) loadProjectFiles(
	ctx context.Context,
	tx *sql.Tx,
	expectedRoot string,
	taskID string,
	projectID string,
) ([]ManifestFile, error) {
	rows, err := tx.QueryContext(ctx, `
SELECT result.id,
       SUBSTRING(result.storage_key, CHAR_LENGTH(?) + 2),
       result.content_sha256, result.size_bytes
FROM decompile_results result
WHERE result.task_id = ? AND result.analyzer_run_id = ?
      AND result.status = 'complete' AND result.language = 'python'
      AND result.deleted_at IS NULL AND result.storage_key IS NOT NULL
      AND result.storage_key LIKE CONCAT(?, '/src/main/python/%')
      AND result.size_bytes > 0
ORDER BY result.storage_key ASC, result.id ASC`,
		expectedRoot, taskID, projectID, expectedRoot,
	)
	if err != nil {
		return nil, fmt.Errorf("list python source files: %w", err)
	}
	defer rows.Close()
	var files []ManifestFile
	var previousPath string
	for rows.Next() {
		var file ManifestFile
		var logicalPath, digest sql.NullString
		var size sql.Null[uint64]
		var resultID string
		if err := rows.Scan(
			&resultID, &logicalPath, &digest, &size,
		); err != nil {
			return nil, fmt.Errorf("scan python source file: %w", err)
		}
		if !logicalPath.Valid || logicalPath.String == "" ||
			!validRelativePath(logicalPath.String) ||
			logicalPath.String == previousPath ||
			!digest.Valid || !sha256Pattern.MatchString(digest.String) ||
			!size.Valid || size.V == 0 || size.V > uint64(MaxSourceBytes) {
			return nil, ErrSourceUnavailable
		}
		previousPath = logicalPath.String
		file.ResultID = resultID
		file.LogicalPath = logicalPath.String
		file.SHA256 = digest.String
		file.SizeBytes = size.V
		files = append(files, file)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate python source files: %w", err)
	}
	return files, nil
}

// Publish stores the checker result and completes the run and analyzer rows.
func (r *MySQLRepository) Publish(
	ctx context.Context,
	lease queue.Lease,
	metadata RequestMetadata,
	result Result,
) error {
	tx, err := r.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return fmt.Errorf("begin python publish: %w", err)
	}
	defer tx.Rollback()
	if err := r.lockPublication(ctx, tx, lease, metadata); err != nil {
		return err
	}
	low, medium, high, critical := result.SeverityCounts()
	status := "succeeded"
	if len(result.Diagnostics) > 0 || result.FindingsTruncated ||
		result.DiagnosticsTruncated {
		status = "partial"
	}
	ruleset := RulesetVersion
	bundleSHA := hex.EncodeToString(metadata.Manifest[:])
	update, err := tx.ExecContext(ctx, `
UPDATE python_analysis_runs
SET status = ?, completed_at = UTC_TIMESTAMP(6),
    bundle_sha256 = ?, ruleset_version = ?, analyzed_files = ?, parsed_files = ?,
    recovered_files = ?, failed_files = ?, finding_count = ?,
    diagnostic_count = ?, low_count = ?, medium_count = ?,
    high_count = ?, critical_count = ?, findings_truncated = ?,
    diagnostics_truncated = ?, error_code = NULL, error_message = NULL
WHERE task_id = ? AND id = ? AND status = 'running'`,
		status, bundleSHA, ruleset, result.AnalyzedFiles, result.ParsedFiles,
		result.RecoveredFiles, result.FailedFiles, len(result.Findings),
		len(result.Diagnostics), low, medium, high, critical,
		result.FindingsTruncated, result.DiagnosticsTruncated,
		lease.TaskID, metadata.RunID,
	)
	if err != nil {
		return fmt.Errorf("complete python analysis run: %w", err)
	}
	if affected, _ := update.RowsAffected(); affected != 1 {
		return ErrLeaseLost
	}
	if _, err := tx.ExecContext(ctx, `
UPDATE analyzer_runs
SET status = ?, completed_at = UTC_TIMESTAMP(6),
    error_code = NULL, error_message = NULL
WHERE task_id = ? AND id = ? AND status = 'running'`,
		status, lease.TaskID, metadata.RunID,
	); err != nil {
		return fmt.Errorf("complete python analyzer run: %w", err)
	}
	for _, finding := range result.Findings {
		if err := r.insertFinding(ctx, tx, lease, metadata, finding); err != nil {
			return err
		}
	}
	if r.invalidateReports != nil {
		if err := r.invalidateReports(ctx, tx, lease.TaskID); err != nil {
			return fmt.Errorf("invalidate reports after python analysis: %w", err)
		}
	}
	return tx.Commit()
}

func (r *MySQLRepository) insertFinding(
	ctx context.Context,
	tx *sql.Tx,
	lease queue.Lease,
	metadata RequestMetadata,
	finding Finding,
) error {
	fileResultID := finding.File.ResultID
	if fileResultID == "" {
		fileResultID = finding.File.LogicalPath
	}
	snippet := sql.NullString{}
	if finding.Snippet != "" {
		snippet = sql.NullString{String: finding.Snippet, Valid: true}
	}
	snippetLine := sql.NullInt64{}
	if finding.SnippetStartLine > 0 {
		snippetLine = sql.NullInt64{Int64: int64(finding.SnippetStartLine), Valid: true}
	}
	_, err := tx.ExecContext(ctx, `
INSERT INTO python_analysis_findings (
    task_id, run_id, cwe, rule_id, severity, file_result_id,
    logical_path, binary_name, callable_kind, type_name, callable_name,
    callable_signature, start_line, start_column, end_line, end_column,
    message, snippet, snippet_start_line, created_at
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
    ?, ?, ?, ?, ?, ?, ?, UTC_TIMESTAMP(6))`,
		lease.TaskID, metadata.RunID, finding.CWE, finding.RuleID,
		finding.Severity, fileResultID, finding.File.LogicalPath,
		finding.File.BinaryName, finding.Callable.Kind,
		finding.Callable.TypeName, finding.Callable.Name,
		finding.Callable.Signature, finding.Location.StartLine,
		finding.Location.StartColumn, finding.Location.EndLine,
		finding.Location.EndColumn, finding.Message,
		snippet, snippetLine,
	)
	if err != nil {
		return fmt.Errorf("insert python finding: %w", err)
	}
	return nil
}

// PublishFailed records a checker failure as the terminal run state.
func (r *MySQLRepository) PublishFailed(
	ctx context.Context,
	lease queue.Lease,
	metadata RequestMetadata,
	result Result,
) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `
UPDATE python_analysis_runs
SET status = 'failed', completed_at = UTC_TIMESTAMP(6),
    error_code = 'python_checker_failed',
    error_message = 'The Python checker rejected the analysis.',
    finding_count = ?, diagnostic_count = ?
WHERE task_id = ? AND id = ? AND status = 'running'`,
		len(result.Findings), len(result.Diagnostics),
		lease.TaskID, metadata.RunID,
	); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `
UPDATE analyzer_runs
SET status = 'failed', completed_at = UTC_TIMESTAMP(6),
    error_code = 'python_checker_failed',
    error_message = 'The Python checker rejected the analysis.'
WHERE task_id = ? AND id = ? AND status = 'running'`,
		lease.TaskID, metadata.RunID,
	); err != nil {
		return err
	}
	return tx.Commit()
}

// Retry requeues the run and analyzer rows after a transient failure so the
// queued job can be claimed again (the claim eligibility requires the run to
// be queued).
func (r *MySQLRepository) Retry(
	ctx context.Context,
	lease queue.Lease,
	code string,
	message string,
) error {
	tx, err := r.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return fmt.Errorf("begin python attempt requeue: %w", err)
	}
	defer tx.Rollback()
	update, err := tx.ExecContext(ctx, `
UPDATE python_analysis_runs
SET status = 'queued', bundle_sha256 = NULL, started_at = NULL,
    completed_at = NULL, ruleset_version = NULL,
    analyzed_files = 0, parsed_files = 0, recovered_files = 0,
    failed_files = 0, finding_count = 0, diagnostic_count = 0,
    low_count = 0, medium_count = 0, high_count = 0, critical_count = 0,
    findings_truncated = FALSE, diagnostics_truncated = FALSE,
    error_code = NULL, error_message = NULL
WHERE task_id = ? AND id = ? AND status IN ('queued', 'running')`,
		lease.TaskID, lease.JobID,
	)
	if err != nil {
		return fmt.Errorf("requeue Python analysis run: %w", err)
	}
	if affected, _ := update.RowsAffected(); affected != 1 {
		return ErrLeaseLost
	}
	update, err = tx.ExecContext(ctx, `
UPDATE analyzer_runs
SET status = 'queued', started_at = NULL, completed_at = NULL,
    error_code = NULL, error_message = NULL
WHERE task_id = ? AND id = ? AND status IN ('queued', 'running')`,
		lease.TaskID, lease.JobID,
	)
	if err != nil {
		return fmt.Errorf("requeue Python analyzer run: %w", err)
	}
	if affected, _ := update.RowsAffected(); affected != 1 {
		return ErrLeaseLost
	}
	return tx.Commit()
}

// Fail records a deterministic terminal failure on both rows.
func (r *MySQLRepository) Fail(
	ctx context.Context,
	lease queue.Lease,
	code string,
	message string,
) error {
	tx, err := r.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return fmt.Errorf("begin python attempt failure: %w", err)
	}
	defer tx.Rollback()
	for _, statement := range []string{
		`UPDATE python_analysis_runs
SET status = 'failed', completed_at = UTC_TIMESTAMP(6),
    error_code = ?, error_message = ?
WHERE task_id = ? AND id = ? AND status IN ('queued', 'running')`,
		`UPDATE analyzer_runs
SET status = 'failed', completed_at = UTC_TIMESTAMP(6),
    error_code = ?, error_message = ?
WHERE task_id = ? AND id = ? AND status IN ('queued', 'running')`,
	} {
		update, updateErr := tx.ExecContext(ctx, statement, code, message, lease.TaskID, lease.JobID)
		if updateErr != nil {
			return fmt.Errorf("fail Python analysis run: %w", updateErr)
		}
		if affected, _ := update.RowsAffected(); affected != 1 {
			return ErrLeaseLost
		}
	}
	return tx.Commit()
}

func (r *MySQLRepository) lockPublication(
	ctx context.Context,
	tx *sql.Tx,
	lease queue.Lease,
	metadata RequestMetadata,
) error {
	var jobKind, jobStatus string
	err := tx.QueryRowContext(ctx, `
SELECT kind, status FROM jobs
WHERE id = ? AND task_id = ? FOR UPDATE`,
		lease.JobID, lease.TaskID,
	).Scan(&jobKind, &jobStatus)
	if err != nil || jobKind != string(queue.KindPythonAnalysis) ||
		jobStatus != "running" {
		return ErrLeaseLost
	}
	_ = metadata
	return nil
}

func validRelativePath(value string) bool {
	if value == "" || path.IsAbs(value) || strings.Contains(value, `\`) ||
		path.Clean(value) != value {
		return false
	}
	if value == ".." || strings.HasPrefix(value, "../") {
		return false
	}
	return true
}

func validSafeASCII(value string, maximum int) bool {
	if value == "" || len(value) > maximum {
		return false
	}
	for _, character := range value {
		if character < 0x20 || character > 0x7e {
			return false
		}
	}
	return true
}

var _ = sha256.Sum256
var _ = hex.EncodeToString
var _ = os.OpenRoot
var _ = time.Now

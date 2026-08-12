package report

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"
)

type taskSnapshot struct {
	ID                  string               `json:"id"`
	Name                string               `json:"name"`
	Status              string               `json:"status"`
	Stage               *string              `json:"stage"`
	ProgressBasisPoints uint16               `json:"progressBasisPoints"`
	RiskLevel           string               `json:"riskLevel"`
	RootFormat          *string              `json:"rootFormat"`
	ErrorCode           *string              `json:"errorCode"`
	ErrorMessage        *string              `json:"errorMessage"`
	CreatedAt           time.Time            `json:"createdAt"`
	CompletedAt         *time.Time           `json:"completedAt"`
	SampleExpiresAt     time.Time            `json:"sampleExpiresAt"`
	SampleDeletedAt     *time.Time           `json:"sampleDeletedAt"`
	LimitsSnapshot      reportLimitsSnapshot `json:"-"`
	Input               inputSnapshot        `json:"-"`
}

type reportLimitsSnapshot struct {
	MaxUploadBytes   int64 `json:"maxUploadBytes"`
	MaxExpandedBytes int64 `json:"maxExpandedBytes"`
	MaxArchiveRatio  int   `json:"maxArchiveRatio"`
	MaxDepth         int   `json:"maxDepth"`
	MaxFileNodes     int   `json:"maxFileNodes"`
	MaxNestedImages  int   `json:"maxNestedImages"`
}

type inputSnapshot struct {
	Filename  string `json:"filename"`
	SizeBytes uint64 `json:"sizeBytes"`
	SHA256    string `json:"sha256"`
}

type executionSnapshot struct {
	Status              *string         `json:"status"`
	Stage               *string         `json:"stage"`
	ProgressBasisPoints uint16          `json:"progressBasisPoints"`
	Statistics          json.RawMessage `json:"statistics"`
	AttemptNumber       *uint32         `json:"-"`
	AttemptStatus       *string         `json:"-"`
	ErrorCode           *string         `json:"-"`
	ErrorMessage        *string         `json:"-"`
	StartedAt           *time.Time      `json:"-"`
	CompletedAt         *time.Time      `json:"-"`
}

type fileNodeSnapshot struct {
	ID               string          `json:"id"`
	ParentID         *string         `json:"parentId"`
	LogicalPath      string          `json:"path"`
	DisplayName      string          `json:"name"`
	NodeType         string          `json:"type"`
	Depth            uint16          `json:"depth"`
	Format           *string         `json:"format"`
	MIMEType         *string         `json:"mimeType"`
	Architecture     *string         `json:"architecture"`
	SizeBytes        *uint64         `json:"sizeBytes"`
	SHA256           *string         `json:"sha256"`
	ExtractionStatus string          `json:"extractionStatus"`
	Metadata         json.RawMessage `json:"metadata"`
	ErrorCode        *string         `json:"errorCode"`
	ErrorMessage     *string         `json:"errorMessage"`
	CreatedAt        time.Time       `json:"createdAt"`
}

type analyzerRunSnapshot struct {
	ID              string          `json:"id"`
	TaskAttemptID   *string         `json:"taskAttemptId"`
	JobID           *string         `json:"jobId"`
	FileNodeID      *string         `json:"fileNodeId"`
	AnalyzerName    string          `json:"analyzerName"`
	AnalyzerVersion string          `json:"analyzerVersion"`
	Parameters      json.RawMessage `json:"parameters"`
	Status          string          `json:"status"`
	ExitCode        *int            `json:"exitCode"`
	ErrorCode       *string         `json:"errorCode"`
	ErrorMessage    *string         `json:"errorMessage"`
	StartedAt       *time.Time      `json:"startedAt"`
	CompletedAt     *time.Time      `json:"completedAt"`
	CreatedAt       time.Time       `json:"createdAt"`
}

type decompileSnapshot struct {
	ID            string          `json:"id"`
	FileNodeID    string          `json:"fileNodeId"`
	AnalyzerRunID *string         `json:"analyzerRunId"`
	SymbolKey     string          `json:"symbolKey"`
	Language      string          `json:"language"`
	EngineName    string          `json:"engineName"`
	EngineVersion string          `json:"engineVersion"`
	Status        string          `json:"status"`
	ContentSHA256 *string         `json:"contentSha256"`
	SizeBytes     *uint64         `json:"sizeBytes"`
	Diagnostics   json.RawMessage `json:"diagnostics"`
	CreatedAt     time.Time       `json:"createdAt"`
	CompletedAt   *time.Time      `json:"completedAt"`
}

type vulnerabilitySnapshot struct {
	ID                 string          `json:"id"`
	AnalyzerRunID      *string         `json:"analyzerRunId"`
	DatabaseBundleID   *string         `json:"databaseBundleId"`
	ImageLogicalPath   string          `json:"imageLogicalPath"`
	ImagePlatform      *string         `json:"imagePlatform"`
	VulnerabilityID    string          `json:"vulnerabilityId"`
	Severity           string          `json:"severity"`
	PackageName        string          `json:"packageName"`
	InstalledVersion   *string         `json:"installedVersion"`
	FixedVersion       *string         `json:"fixedVersion"`
	Title              *string         `json:"title"`
	DescriptionSummary *string         `json:"descriptionSummary"`
	Evidence           json.RawMessage `json:"evidence"`
	References         json.RawMessage `json:"references"`
	CreatedAt          time.Time       `json:"createdAt"`
}

type databaseBundleSnapshot struct {
	ID                 string          `json:"id"`
	Version            string          `json:"version"`
	GeneratedAt        time.Time       `json:"generatedAt"`
	ContentSHA256      string          `json:"contentSha256"`
	TrivyDBVersion     string          `json:"trivyDbVersion"`
	TrivyJavaDBVersion string          `json:"trivyJavaDbVersion"`
	Manifest           json.RawMessage `json:"manifest"`
	RegisteredAt       time.Time       `json:"registeredAt"`
}

type issueSnapshot struct {
	Code        string  `json:"code"`
	Message     string  `json:"message"`
	Source      *string `json:"source"`
	LogicalPath *string `json:"logicalPath"`
}

const (
	maxReportRecords     = 20000
	maxDatabaseBundles   = 100
	maxReportDiagnostics = 3000
	maxReportJSONBytes   = 1 << 20
)

func (r *MySQLRepository) WriteJSONSnapshot(
	ctx context.Context,
	request SnapshotRequest,
	writer io.Writer,
) error {
	return r.withReadSnapshot(ctx, func(transaction *sql.Tx) error {
		task, err := loadTaskSnapshot(ctx, transaction, request.TaskID)
		if err != nil {
			return err
		}
		execution, err := loadExecutionSnapshot(ctx, transaction, task)
		if err != nil {
			return err
		}

		stream := newJSONStream(writer)
		stream.raw("{")
		stream.field("schemaVersion", SchemaVersion)
		stream.field("reportId", request.ReportID)
		stream.field("generatedAt", request.GeneratedAt)
		stream.field("task", task)
		stream.field("input", task.Input)
		stream.field("limitsSnapshot", task.LimitsSnapshot)
		stream.field("execution", execution)
		if err := streamFileNodes(ctx, transaction, request.TaskID, stream); err != nil {
			return err
		}
		if err := streamAnalyzerRuns(ctx, transaction, request.TaskID, stream); err != nil {
			return err
		}
		if err := streamDecompileResults(ctx, transaction, request.TaskID, stream); err != nil {
			return err
		}
		if err := streamVulnerabilities(ctx, transaction, request.TaskID, stream); err != nil {
			return err
		}
		cAnalysisRuns, dependencies, err := loadLatestCAnalysisRuns(
			ctx, transaction, request.TaskID,
		)
		if err != nil {
			return err
		}
		stream.field("cAnalysisRuns", cAnalysisRuns)
		if stream.err != nil {
			return fmt.Errorf("write report C-analysis runs: %w", stream.err)
		}
		if err := streamLatestCAnalysisFindings(
			ctx, transaction, request.TaskID, stream,
		); err != nil {
			return err
		}
		javaAnalysisRuns, javaDependencies, err := loadLatestJavaAnalysisRuns(
			ctx, transaction, request.TaskID,
		)
		if err != nil {
			return err
		}
		stream.field("javaAnalysisRuns", javaAnalysisRuns)
		if stream.err != nil {
			return fmt.Errorf("write report Java-analysis runs: %w", stream.err)
		}
		if err := streamLatestJavaAnalysisFindings(
			ctx, transaction, request.TaskID, stream,
		); err != nil {
			return err
		}
		if err := streamDatabaseBundles(ctx, transaction, request.TaskID, stream); err != nil {
			return err
		}
		if err := streamIssues(ctx, transaction, request.TaskID, "warnings", `
SELECT 'task_event', NULL, 'task_warning',
       COALESCE(NULLIF(message, ''), 'Task warning.')
FROM task_events
WHERE task_id = ? AND severity = 'warning'
ORDER BY id ASC`, stream); err != nil {
			return err
		}
		if err := streamIssues(ctx, transaction, request.TaskID, "unsupported", `
SELECT 'file_node', logical_path,
       COALESCE(NULLIF(error_code, ''), 'file_unsupported'),
       COALESCE(NULLIF(error_message, ''), 'File format is unsupported.')
FROM file_nodes
WHERE task_id = ? AND extraction_status = 'unsupported'
UNION ALL
SELECT 'decompile_result', NULL, 'decompile_unsupported',
       'Decompilation is unsupported for this result.'
FROM decompile_results
WHERE task_id = ? AND status = 'unsupported' AND deleted_at IS NULL
`, stream, request.TaskID); err != nil {
			return err
		}
		if err := streamIssues(ctx, transaction, request.TaskID, "failed", `
SELECT 'file_node', logical_path,
       COALESCE(NULLIF(error_code, ''),
                CASE WHEN extraction_status = 'limit_reached'
                     THEN 'extraction_limit_reached' ELSE 'file_failed' END),
       COALESCE(NULLIF(error_message, ''),
                CASE WHEN extraction_status = 'limit_reached'
                     THEN 'Extraction stopped at a configured limit.'
                     ELSE 'File processing failed.' END)
FROM file_nodes
WHERE task_id = ? AND extraction_status IN ('failed', 'limit_reached')
UNION ALL
SELECT 'analyzer_run', NULL,
       COALESCE(NULLIF(error_code, ''), 'analyzer_failed'),
       COALESCE(NULLIF(error_message, ''), 'Analyzer execution failed.')
FROM analyzer_runs
WHERE task_id = ? AND status IN ('failed', 'timed_out')
UNION ALL
SELECT 'decompile_result', NULL,
       CASE WHEN status = 'cancelled'
            THEN 'decompile_cancelled' ELSE 'decompile_failed' END,
       CASE WHEN status = 'cancelled'
            THEN 'Decompilation was cancelled.' ELSE 'Decompilation failed.' END
FROM decompile_results
WHERE task_id = ? AND status IN ('failed', 'cancelled')
  AND deleted_at IS NULL
UNION ALL
SELECT 'task', NULL,
       COALESCE(NULLIF(error_code, ''), 'task_failed'),
       COALESCE(NULLIF(error_message, ''), 'Task execution failed.')
FROM tasks
WHERE id = ? AND status = 'FAILED'
`, stream, request.TaskID, request.TaskID, request.TaskID); err != nil {
			return err
		}
		stream.raw("}\n")
		recordSnapshotDependencies(request, dependencies)
		recordJavaSnapshotDependencies(request, javaDependencies)
		return stream.err
	})
}

func (r *MySQLRepository) withReadSnapshot(
	ctx context.Context,
	callback func(*sql.Tx) error,
) (returnErr error) {
	transaction, err := r.db.BeginTx(ctx, &sql.TxOptions{
		Isolation: sql.LevelRepeatableRead,
		ReadOnly:  true,
	})
	if err != nil {
		return fmt.Errorf("begin report snapshot: %w", err)
	}
	finished := false
	defer func() {
		if !finished {
			returnErr = joinRollbackError(
				returnErr, transaction.Rollback(), "rollback report snapshot",
			)
		}
	}()
	if err := callback(transaction); err != nil {
		return err
	}
	finished = true
	if err := transaction.Commit(); err != nil {
		return fmt.Errorf("commit report snapshot: %w", err)
	}
	return nil
}

func loadTaskSnapshot(
	ctx context.Context,
	transaction *sql.Tx,
	taskID string,
) (taskSnapshot, error) {
	var value taskSnapshot
	var stage sql.NullString
	var rootFormat sql.NullString
	var errorCode sql.NullString
	var errorMessage sql.NullString
	var completedAt sql.NullTime
	var sampleDeletedAt sql.NullTime
	var limits []byte
	err := transaction.QueryRowContext(ctx, `
SELECT task.id, task.name, task.status, task.stage,
       task.progress_basis_points, task.risk_level, task.root_format,
       task.error_code, task.error_message, task.created_at, task.completed_at,
       task.sample_expires_at, task.sample_deleted_at, task.limits_snapshot,
       upload.display_name, input_blob.size_bytes, input_blob.sha256
FROM tasks task
JOIN uploads upload ON upload.id = task.upload_id
JOIN blobs input_blob ON input_blob.id = task.blob_id
WHERE task.id = ?
LIMIT 1`, taskID).Scan(
		&value.ID,
		&value.Name,
		&value.Status,
		&stage,
		&value.ProgressBasisPoints,
		&value.RiskLevel,
		&rootFormat,
		&errorCode,
		&errorMessage,
		&value.CreatedAt,
		&completedAt,
		&value.SampleExpiresAt,
		&sampleDeletedAt,
		&limits,
		&value.Input.Filename,
		&value.Input.SizeBytes,
		&value.Input.SHA256,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return taskSnapshot{}, ErrTaskNotFound
	}
	if err != nil {
		return taskSnapshot{}, fmt.Errorf("read report task snapshot: %w", err)
	}
	value.Stage = nullableString(stage)
	value.RootFormat = nullableString(rootFormat)
	value.ErrorCode = nullableString(errorCode)
	value.ErrorMessage = nullableString(errorMessage)
	value.CompletedAt = nullableTime(completedAt)
	value.SampleDeletedAt = nullableTime(sampleDeletedAt)
	var storedLimits struct {
		MaxUploadBytes   int64 `json:"max_upload_bytes"`
		MaxExpandedBytes int64 `json:"max_expanded_bytes"`
		MaxArchiveRatio  int   `json:"max_archive_ratio"`
		MaxDepth         int   `json:"max_depth"`
		MaxFileNodes     int   `json:"max_file_nodes"`
		MaxNestedImages  int   `json:"max_nested_images"`
	}
	if err := json.Unmarshal(limits, &storedLimits); err != nil {
		return taskSnapshot{}, fmt.Errorf("decode report limits snapshot: %w", err)
	}
	value.LimitsSnapshot = reportLimitsSnapshot(storedLimits)
	if !reportableTaskStatus(value.Status) {
		return taskSnapshot{}, ErrTaskNotTerminal
	}
	return value, nil
}

func loadExecutionSnapshot(
	ctx context.Context,
	transaction *sql.Tx,
	task taskSnapshot,
) (executionSnapshot, error) {
	value := executionSnapshot{
		Stage:               task.Stage,
		ProgressBasisPoints: task.ProgressBasisPoints,
		Statistics:          json.RawMessage(`null`),
		ErrorCode:           task.ErrorCode,
		ErrorMessage:        task.ErrorMessage,
		CompletedAt:         task.CompletedAt,
	}
	var attemptNumber uint32
	var attemptStatus string
	var statistics []byte
	var errorCode sql.NullString
	var errorMessage sql.NullString
	var startedAt sql.NullTime
	var completedAt sql.NullTime
	err := transaction.QueryRowContext(ctx, `
SELECT attempt_number, status, statistics, error_code, error_message,
       started_at, completed_at
FROM task_attempts
WHERE task_id = ?
ORDER BY attempt_number DESC
LIMIT 1`, task.ID).Scan(
		&attemptNumber,
		&attemptStatus,
		&statistics,
		&errorCode,
		&errorMessage,
		&startedAt,
		&completedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return value, nil
	}
	if err != nil {
		return executionSnapshot{}, fmt.Errorf("read task execution snapshot: %w", err)
	}
	value.AttemptNumber = &attemptNumber
	value.AttemptStatus = &attemptStatus
	value.Status = &attemptStatus
	value.Statistics = safeRawJSON(statistics, `null`)
	value.ErrorCode = nullableString(errorCode)
	value.ErrorMessage = nullableString(errorMessage)
	value.StartedAt = nullableTime(startedAt)
	value.CompletedAt = nullableTime(completedAt)
	return value, nil
}

type jsonStream struct {
	writer  io.Writer
	encoder *json.Encoder
	err     error
	fields  int
}

func newJSONStream(writer io.Writer) *jsonStream {
	encoder := json.NewEncoder(writer)
	encoder.SetEscapeHTML(true)
	return &jsonStream{writer: writer, encoder: encoder}
}

func (s *jsonStream) raw(value string) {
	if s.err != nil {
		return
	}
	_, s.err = io.WriteString(s.writer, value)
}

func (s *jsonStream) field(name string, value any) {
	if s.fields > 0 {
		s.raw(",")
	}
	s.fields++
	s.raw(strconv.Quote(name))
	s.raw(":")
	if s.err == nil {
		s.err = s.encoder.Encode(value)
	}
}

func (s *jsonStream) beginArray(name string) {
	if s.fields > 0 {
		s.raw(",")
	}
	s.fields++
	s.raw(strconv.Quote(name))
	s.raw(":[")
}

func (s *jsonStream) arrayValue(value any, first *bool) {
	if !*first {
		s.raw(",")
	}
	*first = false
	if s.err == nil {
		s.err = s.encoder.Encode(value)
	}
}

func (s *jsonStream) endArray() {
	s.raw("]")
}

func streamFileNodes(
	ctx context.Context,
	transaction *sql.Tx,
	taskID string,
	stream *jsonStream,
) error {
	rows, err := transaction.QueryContext(ctx, `
SELECT id, parent_id, logical_path, display_name, node_type, depth, format,
       mime_type, architecture, size_bytes, sha256, extraction_status,
       metadata_json, error_code, error_message, created_at
FROM file_nodes
WHERE task_id = ?
ORDER BY id ASC`, taskID)
	if err != nil {
		return fmt.Errorf("query report file nodes: %w", err)
	}
	defer rows.Close()
	stream.beginArray("fileNodes")
	first := true
	count := 0
	for rows.Next() {
		if count >= maxReportRecords {
			return errors.New("report file node limit exceeded")
		}
		count++
		if err := ctx.Err(); err != nil {
			return err
		}
		value, err := scanFileNodeSnapshot(rows)
		if err != nil {
			return fmt.Errorf("scan report file node: %w", err)
		}
		stream.arrayValue(value, &first)
		if stream.err != nil {
			return fmt.Errorf("write report file nodes: %w", stream.err)
		}
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate report file nodes: %w", err)
	}
	stream.endArray()
	return stream.err
}

func scanFileNodeSnapshot(scanner rowScanner) (fileNodeSnapshot, error) {
	var value fileNodeSnapshot
	var id uint64
	var parentID sql.Null[uint64]
	var format sql.NullString
	var mimeType sql.NullString
	var architecture sql.NullString
	var size sql.Null[uint64]
	var digest sql.NullString
	var metadata []byte
	var errorCode sql.NullString
	var errorMessage sql.NullString
	err := scanner.Scan(
		&id, &parentID, &value.LogicalPath, &value.DisplayName, &value.NodeType,
		&value.Depth, &format, &mimeType, &architecture, &size, &digest,
		&value.ExtractionStatus, &metadata, &errorCode, &errorMessage,
		&value.CreatedAt,
	)
	if err != nil {
		return fileNodeSnapshot{}, err
	}
	value.ID = strconv.FormatUint(id, 10)
	if parentID.Valid {
		parent := strconv.FormatUint(parentID.V, 10)
		value.ParentID = &parent
	}
	value.Format = nullableString(format)
	value.MIMEType = nullableString(mimeType)
	value.Architecture = nullableString(architecture)
	value.SizeBytes = nullableUint64(size)
	value.SHA256 = nullableString(digest)
	value.Metadata = safeRawJSON(metadata, `null`)
	value.ErrorCode = nullableString(errorCode)
	value.ErrorMessage = nullableString(errorMessage)
	return value, nil
}

func streamAnalyzerRuns(
	ctx context.Context,
	transaction *sql.Tx,
	taskID string,
	stream *jsonStream,
) error {
	rows, err := transaction.QueryContext(ctx, `
SELECT id, task_attempt_id, job_id, file_node_id, analyzer_name,
       analyzer_version, parameters_json, status, exit_code, error_code,
       error_message, started_at, completed_at, created_at
FROM analyzer_runs
WHERE task_id = ?
ORDER BY created_at ASC, id ASC`, taskID)
	if err != nil {
		return fmt.Errorf("query report analyzer runs: %w", err)
	}
	defer rows.Close()
	stream.beginArray("analyzerRuns")
	first := true
	count := 0
	for rows.Next() {
		if count >= maxReportRecords {
			return errors.New("report analyzer run limit exceeded")
		}
		count++
		if err := ctx.Err(); err != nil {
			return err
		}
		var value analyzerRunSnapshot
		var attemptID sql.Null[uint64]
		var jobID sql.NullString
		var fileNodeID sql.Null[uint64]
		var parameters []byte
		var exitCode sql.NullInt32
		var errorCode sql.NullString
		var errorMessage sql.NullString
		var startedAt sql.NullTime
		var completedAt sql.NullTime
		if err := rows.Scan(
			&value.ID, &attemptID, &jobID, &fileNodeID, &value.AnalyzerName,
			&value.AnalyzerVersion, &parameters, &value.Status, &exitCode,
			&errorCode, &errorMessage, &startedAt, &completedAt,
			&value.CreatedAt,
		); err != nil {
			return fmt.Errorf("scan report analyzer run: %w", err)
		}
		value.TaskAttemptID = nullableUint64String(attemptID)
		value.JobID = nullableString(jobID)
		value.FileNodeID = nullableUint64String(fileNodeID)
		value.Parameters = safeRawJSON(parameters, `null`)
		if exitCode.Valid {
			exit := int(exitCode.Int32)
			value.ExitCode = &exit
		}
		value.ErrorCode = nullableString(errorCode)
		value.ErrorMessage = nullableString(errorMessage)
		value.StartedAt = nullableTime(startedAt)
		value.CompletedAt = nullableTime(completedAt)
		stream.arrayValue(value, &first)
		if stream.err != nil {
			return fmt.Errorf("write report analyzer runs: %w", stream.err)
		}
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate report analyzer runs: %w", err)
	}
	stream.endArray()
	return stream.err
}

func streamDecompileResults(
	ctx context.Context,
	transaction *sql.Tx,
	taskID string,
	stream *jsonStream,
) error {
	rows, err := transaction.QueryContext(ctx, `
SELECT id, file_node_id, analyzer_run_id, symbol_key, language, engine_name,
       engine_version, status, content_sha256, size_bytes, diagnostics_json,
       created_at, completed_at
FROM decompile_results
WHERE task_id = ? AND deleted_at IS NULL
ORDER BY created_at ASC, id ASC`, taskID)
	if err != nil {
		return fmt.Errorf("query report decompile results: %w", err)
	}
	defer rows.Close()
	stream.beginArray("decompileResults")
	first := true
	count := 0
	for rows.Next() {
		if count >= maxReportRecords {
			return errors.New("report decompile result limit exceeded")
		}
		count++
		if err := ctx.Err(); err != nil {
			return err
		}
		var value decompileSnapshot
		var fileNodeID uint64
		var analyzerRunID sql.NullString
		var digest sql.NullString
		var size sql.Null[uint64]
		var diagnostics []byte
		var completedAt sql.NullTime
		if err := rows.Scan(
			&value.ID, &fileNodeID, &analyzerRunID, &value.SymbolKey,
			&value.Language, &value.EngineName, &value.EngineVersion,
			&value.Status, &digest, &size, &diagnostics, &value.CreatedAt,
			&completedAt,
		); err != nil {
			return fmt.Errorf("scan report decompile result: %w", err)
		}
		value.FileNodeID = strconv.FormatUint(fileNodeID, 10)
		value.AnalyzerRunID = nullableString(analyzerRunID)
		value.ContentSHA256 = nullableString(digest)
		value.SizeBytes = nullableUint64(size)
		value.Diagnostics = safeRawJSON(diagnostics, `null`)
		value.CompletedAt = nullableTime(completedAt)
		stream.arrayValue(value, &first)
		if stream.err != nil {
			return fmt.Errorf("write report decompile results: %w", stream.err)
		}
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate report decompile results: %w", err)
	}
	stream.endArray()
	return stream.err
}

func streamVulnerabilities(
	ctx context.Context,
	transaction *sql.Tx,
	taskID string,
	stream *jsonStream,
) error {
	rows, err := transaction.QueryContext(ctx, `
	SELECT id, analyzer_run_id, trivy_database_bundle_id, image_logical_path,
       image_platform, vulnerability_id, severity, package_name,
       installed_version, fixed_version, title, description_summary,
       evidence_json, references_json, created_at
FROM vulnerability_findings
WHERE task_id = ?
ORDER BY id ASC`, taskID)
	if err != nil {
		return fmt.Errorf("query report vulnerabilities: %w", err)
	}
	defer rows.Close()
	stream.beginArray("vulnerabilityFindings")
	first := true
	count := 0
	for rows.Next() {
		if count >= maxReportRecords {
			return errors.New("report vulnerability finding limit exceeded")
		}
		count++
		if err := ctx.Err(); err != nil {
			return err
		}
		var value vulnerabilitySnapshot
		var id uint64
		var analyzerRunID sql.NullString
		var databaseID sql.NullString
		var imagePlatform sql.NullString
		var installedVersion sql.NullString
		var fixedVersion sql.NullString
		var title sql.NullString
		var description sql.NullString
		var evidence []byte
		var references []byte
		if err := rows.Scan(
			&id, &analyzerRunID, &databaseID, &value.ImageLogicalPath,
			&imagePlatform, &value.VulnerabilityID, &value.Severity,
			&value.PackageName, &installedVersion, &fixedVersion, &title,
			&description, &evidence, &references, &value.CreatedAt,
		); err != nil {
			return fmt.Errorf("scan report vulnerability: %w", err)
		}
		value.ID = strconv.FormatUint(id, 10)
		value.AnalyzerRunID = nullableString(analyzerRunID)
		value.DatabaseBundleID = nullableString(databaseID)
		value.ImagePlatform = nullableString(imagePlatform)
		value.InstalledVersion = nullableString(installedVersion)
		value.FixedVersion = nullableString(fixedVersion)
		value.Title = nullableString(title)
		value.DescriptionSummary = nullableString(description)
		value.Evidence = safeRawJSON(evidence, `null`)
		value.References = safeRawJSON(references, `null`)
		stream.arrayValue(value, &first)
		if stream.err != nil {
			return fmt.Errorf("write report vulnerabilities: %w", stream.err)
		}
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate report vulnerabilities: %w", err)
	}
	stream.endArray()
	return stream.err
}

func streamDatabaseBundles(
	ctx context.Context,
	transaction *sql.Tx,
	taskID string,
	stream *jsonStream,
) error {
	rows, err := transaction.QueryContext(ctx, `
	SELECT database_bundle.id, database_bundle.version,
	       database_bundle.generated_at, database_bundle.content_sha256,
	       database_bundle.trivy_db_version,
	       database_bundle.trivy_java_db_version,
	       database_bundle.manifest_json, database_bundle.registered_at
	FROM trivy_database_bundles database_bundle
	WHERE EXISTS (
    SELECT 1
    FROM vulnerability_findings finding
    WHERE finding.task_id = ?
	      AND finding.trivy_database_bundle_id = database_bundle.id
)
OR EXISTS (
    SELECT 1
    FROM analyzer_runs analyzer
    WHERE analyzer.task_id = ?
      AND analyzer.analyzer_name = 'trivy'
	      AND JSON_UNQUOTE(JSON_EXTRACT(
	          analyzer.parameters_json, '$.database_bundle.id'
	      )) = database_bundle.id
	)
	ORDER BY database_bundle.generated_at DESC, database_bundle.id ASC`,
		taskID,
		taskID,
	)
	if err != nil {
		return fmt.Errorf("query report Trivy database bundles: %w", err)
	}
	defer rows.Close()
	stream.beginArray("trivyDatabaseBundles")
	first := true
	count := 0
	for rows.Next() {
		if count >= maxDatabaseBundles {
			return errors.New("report Trivy database bundle limit exceeded")
		}
		count++
		if err := ctx.Err(); err != nil {
			return err
		}
		var value databaseBundleSnapshot
		var manifest []byte
		if err := rows.Scan(
			&value.ID, &value.Version, &value.GeneratedAt,
			&value.ContentSHA256, &value.TrivyDBVersion,
			&value.TrivyJavaDBVersion, &manifest, &value.RegisteredAt,
		); err != nil {
			return fmt.Errorf("scan report Trivy database bundle: %w", err)
		}
		value.Manifest = safeRawJSON(manifest, `{}`)
		stream.arrayValue(value, &first)
		if stream.err != nil {
			return fmt.Errorf("write report Trivy database bundles: %w", stream.err)
		}
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate report Trivy database bundles: %w", err)
	}
	stream.endArray()
	return stream.err
}

func streamIssues(
	ctx context.Context,
	transaction *sql.Tx,
	taskID string,
	name string,
	query string,
	stream *jsonStream,
	extraArguments ...any,
) error {
	arguments := []any{taskID}
	arguments = append(arguments, extraArguments...)
	rows, err := transaction.QueryContext(ctx, query, arguments...)
	if err != nil {
		return fmt.Errorf("query report %s: %w", name, err)
	}
	defer rows.Close()
	stream.beginArray(name)
	first := true
	count := 0
	for rows.Next() {
		if count >= maxReportDiagnostics {
			return fmt.Errorf("report %s limit exceeded", name)
		}
		count++
		if err := ctx.Err(); err != nil {
			return err
		}
		var value issueSnapshot
		var source sql.NullString
		var logicalPath sql.NullString
		if err := rows.Scan(
			&source, &logicalPath, &value.Code, &value.Message,
		); err != nil {
			return fmt.Errorf("scan report %s: %w", name, err)
		}
		value.Source = nullableString(source)
		value.LogicalPath = nullableString(logicalPath)
		stream.arrayValue(value, &first)
		if stream.err != nil {
			return fmt.Errorf("write report %s: %w", name, stream.err)
		}
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate report %s: %w", name, err)
	}
	stream.endArray()
	return stream.err
}

func nullableString(value sql.NullString) *string {
	if !value.Valid || value.String == "" {
		return nil
	}
	copy := value.String
	return &copy
}

func nullableUint64(value sql.Null[uint64]) *uint64 {
	if !value.Valid {
		return nil
	}
	copy := value.V
	return &copy
}

func nullableUint64String(value sql.Null[uint64]) *string {
	if !value.Valid {
		return nil
	}
	copy := strconv.FormatUint(value.V, 10)
	return &copy
}

func nullableTime(value sql.NullTime) *time.Time {
	if !value.Valid {
		return nil
	}
	copy := value.Time
	return &copy
}

func safeRawJSON(value []byte, fallback string) json.RawMessage {
	if len(value) == 0 || len(value) > maxReportJSONBytes {
		return json.RawMessage(fallback)
	}
	decoder := json.NewDecoder(bytes.NewReader(value))
	decoder.UseNumber()
	var decoded any
	if err := decoder.Decode(&decoded); err != nil {
		return json.RawMessage(fallback)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return json.RawMessage(fallback)
	}
	sanitized, ok := sanitizeReportJSON(decoded, 0)
	if !ok {
		return json.RawMessage(fallback)
	}
	encoded, err := json.Marshal(sanitized)
	if err != nil {
		return json.RawMessage(fallback)
	}
	return encoded
}

func sanitizeReportJSON(value any, depth int) (any, bool) {
	if depth > 32 {
		return nil, false
	}
	switch typed := value.(type) {
	case map[string]any:
		if len(typed) > 1000 {
			return nil, false
		}
		clean := make(map[string]any, len(typed))
		for key, child := range typed {
			if len(key) > 1024 {
				return nil, false
			}
			if forbiddenReportJSONKey(key) {
				continue
			}
			sanitized, ok := sanitizeReportJSON(child, depth+1)
			if !ok {
				return nil, false
			}
			clean[key] = sanitized
		}
		return clean, true
	case []any:
		if len(typed) > 10000 {
			return nil, false
		}
		clean := make([]any, len(typed))
		for index, child := range typed {
			sanitized, ok := sanitizeReportJSON(child, depth+1)
			if !ok {
				return nil, false
			}
			clean[index] = sanitized
		}
		return clean, true
	case string:
		if len(typed) > 65536 {
			return nil, false
		}
		return typed, true
	case nil, bool, json.Number:
		return typed, true
	default:
		return nil, false
	}
}

func forbiddenReportJSONKey(key string) bool {
	normalized := strings.ToLower(key)
	normalized = strings.NewReplacer("_", "", "-", "", " ", "").Replace(normalized)
	switch normalized {
	case "storagekey", "storagepath", "sourcecontent", "sourcecode",
		"decompiledsource", "pseudoc", "cachekey", "password", "passphrase",
		"privatekey", "secret", "apikey", "accesskey", "encryptionkey",
		"signingkey":
		return true
	default:
		return false
	}
}

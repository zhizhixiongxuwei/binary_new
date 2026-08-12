package report

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

type javaAnalysisRunSnapshot struct {
	ID                   string     `json:"id"`
	SourceProjectID      string     `json:"sourceProjectId"`
	AnalyzerName         string     `json:"analyzerName"`
	AnalyzerVersion      string     `json:"analyzerVersion"`
	RulesetVersion       string     `json:"rulesetVersion"`
	Status               string     `json:"status"`
	SourceManifestSHA256 string     `json:"sourceManifestSha256"`
	InputSHA256          string     `json:"inputSha256"`
	BundleSHA256         string     `json:"bundleSha256"`
	SourceSizeBytes      uint64     `json:"sourceSizeBytes"`
	SourceFileCount      uint64     `json:"sourceFileCount"`
	AnalyzedFiles        uint64     `json:"analyzedFiles"`
	ParsedFiles          uint64     `json:"parsedFiles"`
	RecoveredFiles       uint64     `json:"recoveredFiles"`
	FailedFiles          uint64     `json:"failedFiles"`
	FindingCount         uint64     `json:"findingCount"`
	DiagnosticCount      uint64     `json:"diagnosticCount"`
	LowCount             uint64     `json:"lowCount"`
	MediumCount          uint64     `json:"mediumCount"`
	HighCount            uint64     `json:"highCount"`
	CriticalCount        uint64     `json:"criticalCount"`
	FindingsTruncated    bool       `json:"findingsTruncated"`
	DiagnosticsTruncated bool       `json:"diagnosticsTruncated"`
	CreatedAt            time.Time  `json:"createdAt"`
	CompletedAt          *time.Time `json:"completedAt"`
}

type javaAnalysisFindingSnapshot struct {
	ID                string    `json:"id"`
	RunID             string    `json:"runId"`
	SourceProjectID   string    `json:"sourceProjectId"`
	CWE               string    `json:"cwe"`
	RuleID            string    `json:"ruleId"`
	Severity          string    `json:"severity"`
	FileResultID      string    `json:"fileResultId"`
	LogicalPath       string    `json:"logicalPath"`
	BinaryName        string    `json:"binaryName"`
	CallableKind      string    `json:"callableKind"`
	TypeName          string    `json:"typeName"`
	CallableName      string    `json:"callableName"`
	CallableSignature *string   `json:"callableSignature"`
	StartLine         uint64    `json:"startLine"`
	StartColumn       uint64    `json:"startColumn"`
	EndLine           uint64    `json:"endLine"`
	EndColumn         uint64    `json:"endColumn"`
	Message           string    `json:"message"`
	Snippet           *string   `json:"snippet"`
	SnippetStartLine  *uint64   `json:"snippetStartLine"`
	CreatedAt         time.Time `json:"createdAt"`
}

const latestJavaAnalysisRunsCTE = `
WITH ranked_java_analysis_runs AS (
    SELECT run.id, run.source_project_id, run.status,
           run.source_manifest_sha256, run.input_sha256, run.bundle_sha256,
           run.source_size_bytes, run.source_file_count,
           run.ruleset_version, run.analyzed_files, run.parsed_files,
           run.recovered_files, run.failed_files, run.finding_count,
           run.diagnostic_count, run.low_count, run.medium_count,
           run.high_count, run.critical_count, run.findings_truncated,
           run.diagnostics_truncated, run.created_at, run.completed_at,
           analyzer.analyzer_name, analyzer.analyzer_version,
           ROW_NUMBER() OVER (
               PARTITION BY run.source_project_id
               ORDER BY run.completed_at DESC, run.id DESC
           ) AS project_rank
    FROM java_analysis_runs run
    JOIN decompile_source_projects project
      ON project.task_id = run.task_id AND project.id = run.source_project_id
    JOIN analyzer_runs analyzer
      ON analyzer.task_id = run.task_id AND analyzer.id = run.id
    WHERE run.task_id = ?
      AND run.status IN ('succeeded', 'partial')
      AND run.completed_at IS NOT NULL
      AND run.deletion_started_at IS NULL
      AND project.deleted_at IS NULL
      AND project.storage_deleted_at IS NULL
)`

func loadLatestJavaAnalysisRuns(
	ctx context.Context,
	transaction *sql.Tx,
	taskID string,
) ([]javaAnalysisRunSnapshot, []JavaAnalysisDependency, error) {
	rows, err := transaction.QueryContext(ctx, latestJavaAnalysisRunsCTE+`
SELECT id, source_project_id, analyzer_name, analyzer_version,
       ruleset_version, status, source_manifest_sha256, input_sha256,
       bundle_sha256, source_size_bytes, source_file_count, analyzed_files,
       parsed_files, recovered_files, failed_files, finding_count,
       diagnostic_count, low_count, medium_count, high_count, critical_count,
       findings_truncated, diagnostics_truncated, created_at, completed_at
FROM ranked_java_analysis_runs
WHERE project_rank = 1
ORDER BY source_project_id ASC, id ASC`, taskID)
	if err != nil {
		return nil, nil, fmt.Errorf("query report Java-analysis runs: %w", err)
	}
	defer rows.Close()
	runs := make([]javaAnalysisRunSnapshot, 0)
	dependencies := make([]JavaAnalysisDependency, 0)
	for rows.Next() {
		if err := ctx.Err(); err != nil {
			return nil, nil, err
		}
		var value javaAnalysisRunSnapshot
		var completedAt sql.NullTime
		if err := rows.Scan(
			&value.ID, &value.SourceProjectID, &value.AnalyzerName,
			&value.AnalyzerVersion, &value.RulesetVersion, &value.Status,
			&value.SourceManifestSHA256, &value.InputSHA256,
			&value.BundleSHA256, &value.SourceSizeBytes,
			&value.SourceFileCount, &value.AnalyzedFiles, &value.ParsedFiles,
			&value.RecoveredFiles, &value.FailedFiles, &value.FindingCount,
			&value.DiagnosticCount, &value.LowCount, &value.MediumCount,
			&value.HighCount, &value.CriticalCount, &value.FindingsTruncated,
			&value.DiagnosticsTruncated, &value.CreatedAt, &completedAt,
		); err != nil {
			return nil, nil, fmt.Errorf("scan report Java-analysis run: %w", err)
		}
		if !completedAt.Valid {
			return nil, nil, errors.New(
				"terminal report Java-analysis run has no completion time",
			)
		}
		completed := completedAt.Time
		value.CompletedAt = &completed
		runs = append(runs, value)
		dependencies = append(dependencies, JavaAnalysisDependency{
			RunID: value.ID, ProjectID: value.SourceProjectID,
			CompletedAt:          completed,
			SourceManifestSHA256: value.SourceManifestSHA256,
			InputSHA256:          value.InputSHA256,
		})
	}
	if err := rows.Err(); err != nil {
		return nil, nil, fmt.Errorf("iterate report Java-analysis runs: %w", err)
	}
	return runs, dependencies, nil
}

func streamLatestJavaAnalysisFindings(
	ctx context.Context,
	transaction *sql.Tx,
	taskID string,
	stream *jsonStream,
) error {
	rows, err := transaction.QueryContext(ctx, latestJavaAnalysisRunsCTE+`
SELECT finding.id, finding.run_id, latest.source_project_id,
       finding.cwe, finding.rule_id, finding.severity,
       finding.file_result_id, finding.logical_path, finding.binary_name,
       finding.callable_kind, finding.type_name, finding.callable_name,
       finding.callable_signature, finding.start_line, finding.start_column,
       finding.end_line, finding.end_column, finding.message,
       finding.snippet, finding.snippet_start_line, finding.created_at
FROM ranked_java_analysis_runs latest
JOIN java_analysis_findings finding
  ON finding.task_id = ? AND finding.run_id = latest.id
WHERE latest.project_rank = 1
ORDER BY latest.source_project_id ASC,
         FIELD(finding.severity, 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'),
         finding.id ASC
LIMIT ?`, taskID, taskID, maxReportRecords+1)
	if err != nil {
		return fmt.Errorf("query report Java-analysis findings: %w", err)
	}
	defer rows.Close()
	stream.beginArray("javaAnalysisFindings")
	first := true
	count := 0
	truncated := false
	for rows.Next() {
		if count == maxReportRecords {
			truncated = true
			break
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		value, err := scanJavaAnalysisFinding(rows)
		if err != nil {
			return fmt.Errorf("scan report Java-analysis finding: %w", err)
		}
		stream.arrayValue(value, &first)
		if stream.err != nil {
			return fmt.Errorf("write report Java-analysis findings: %w", stream.err)
		}
		count++
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate report Java-analysis findings: %w", err)
	}
	stream.endArray()
	stream.field("javaAnalysisFindingsTruncated", truncated)
	return stream.err
}

func loadHTMLJavaAnalysisFindings(
	ctx context.Context,
	transaction *sql.Tx,
	taskID string,
) ([]javaAnalysisFindingSnapshot, bool, error) {
	rows, err := transaction.QueryContext(ctx, latestJavaAnalysisRunsCTE+`
SELECT finding.id, finding.run_id, latest.source_project_id,
       finding.cwe, finding.rule_id, finding.severity,
       finding.file_result_id, finding.logical_path, finding.binary_name,
       finding.callable_kind, finding.type_name, finding.callable_name,
       finding.callable_signature, finding.start_line, finding.start_column,
       finding.end_line, finding.end_column, finding.message,
       finding.snippet, finding.snippet_start_line, finding.created_at
FROM ranked_java_analysis_runs latest
JOIN java_analysis_findings finding
  ON finding.task_id = ? AND finding.run_id = latest.id
WHERE latest.project_rank = 1
ORDER BY FIELD(finding.severity, 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'),
         latest.source_project_id ASC, finding.id ASC
LIMIT ?`, taskID, taskID, htmlJavaAnalysisFindingLimit+1)
	if err != nil {
		return nil, false, fmt.Errorf("query HTML Java-analysis findings: %w", err)
	}
	defer rows.Close()
	values := make([]javaAnalysisFindingSnapshot, 0, htmlJavaAnalysisFindingLimit)
	truncated := false
	for rows.Next() {
		if len(values) == htmlJavaAnalysisFindingLimit {
			truncated = true
			break
		}
		value, err := scanJavaAnalysisFinding(rows)
		if err != nil {
			return nil, false, fmt.Errorf("scan HTML Java-analysis finding: %w", err)
		}
		values = append(values, value)
	}
	if err := rows.Err(); err != nil {
		return nil, false, fmt.Errorf("iterate HTML Java-analysis findings: %w", err)
	}
	return values, truncated, nil
}

func scanJavaAnalysisFinding(scanner rowScanner) (javaAnalysisFindingSnapshot, error) {
	var value javaAnalysisFindingSnapshot
	var id uint64
	var signature, snippet sql.NullString
	var snippetStartLine sql.Null[uint64]
	if err := scanner.Scan(
		&id, &value.RunID, &value.SourceProjectID, &value.CWE,
		&value.RuleID, &value.Severity, &value.FileResultID,
		&value.LogicalPath, &value.BinaryName, &value.CallableKind,
		&value.TypeName, &value.CallableName, &signature, &value.StartLine,
		&value.StartColumn, &value.EndLine, &value.EndColumn, &value.Message,
		&snippet, &snippetStartLine, &value.CreatedAt,
	); err != nil {
		return javaAnalysisFindingSnapshot{}, err
	}
	value.ID = fmt.Sprint(id)
	value.CallableSignature = nullableString(signature)
	value.Snippet = nullableString(snippet)
	if snippetStartLine.Valid {
		line := snippetStartLine.V
		value.SnippetStartLine = &line
	}
	return value, nil
}

func recordJavaSnapshotDependencies(
	request SnapshotRequest,
	dependencies []JavaAnalysisDependency,
) {
	if request.JavaDependencies == nil {
		return
	}
	*request.JavaDependencies = append(
		(*request.JavaDependencies)[:0], dependencies...,
	)
}

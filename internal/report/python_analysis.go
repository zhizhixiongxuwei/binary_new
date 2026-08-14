package report

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

// pythonAnalysisRunSnapshot mirrors one completed python_analysis_runs row
// joined with its analyzer identity.
type pythonAnalysisRunSnapshot struct {
	ID                   string    `json:"id"`
	SourceProjectID      string    `json:"sourceProjectId"`
	AnalyzerName         string    `json:"analyzerName"`
	AnalyzerVersion      string    `json:"analyzerVersion"`
	RulesetVersion       string    `json:"rulesetVersion"`
	Status               string    `json:"status"`
	SourceManifestSHA256 string    `json:"sourceManifestSha256"`
	InputSHA256          string    `json:"inputSha256"`
	SourceSizeBytes      uint64    `json:"sourceSizeBytes"`
	SourceFileCount      uint64    `json:"sourceFileCount"`
	AnalyzedFiles        uint64    `json:"analyzedFiles"`
	ParsedFiles          uint64    `json:"parsedFiles"`
	RecoveredFiles       uint64    `json:"recoveredFiles"`
	FailedFiles          uint64    `json:"failedFiles"`
	FindingCount         uint64    `json:"findingCount"`
	DiagnosticCount      uint64    `json:"diagnosticCount"`
	LowCount             uint64    `json:"lowCount"`
	MediumCount          uint64    `json:"mediumCount"`
	HighCount            uint64    `json:"highCount"`
	CriticalCount        uint64    `json:"criticalCount"`
	FindingsTruncated    bool      `json:"findingsTruncated"`
	DiagnosticsTruncated bool      `json:"diagnosticsTruncated"`
	CompletedAt          time.Time `json:"completedAt"`
	CreatedAt            time.Time `json:"createdAt"`
}

// pythonAnalysisFindingSnapshot is one normalized python_analysis_findings row.
type pythonAnalysisFindingSnapshot struct {
	ID              string  `json:"id"`
	RunID           string  `json:"runId"`
	SourceProjectID string  `json:"sourceProjectId"`
	CWE             string  `json:"cwe"`
	RuleID          string  `json:"ruleId"`
	Severity        string  `json:"severity"`
	FileResultID    string  `json:"fileResultId"`
	LogicalPath     string  `json:"logicalPath"`
	BinaryName      string  `json:"binaryName"`
	CallableName    string  `json:"callableName"`
	StartLine       uint64  `json:"startLine"`
	StartColumn     uint64  `json:"startColumn"`
	EndLine         uint64  `json:"endLine"`
	EndColumn       uint64  `json:"endColumn"`
	Message         string  `json:"message"`
	Snippet         *string `json:"snippet"`
	SnippetStartLine *uint64 `json:"snippetStartLine"`
}

const latestPythonAnalysisRunsCTE = `
WITH ranked_python_analysis_runs AS (
    SELECT run.id, run.source_project_id, run.status,
           run.source_manifest_sha256, run.input_sha256,
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
    FROM python_analysis_runs run
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

// PythonAnalysisDependency records the analysis inputs the snapshot depends on.
type PythonAnalysisDependency struct {
	RunID                string
	ProjectID            string
	CompletedAt          time.Time
	SourceManifestSHA256 string
	InputSHA256          string
}

func loadLatestPythonAnalysisRuns(
	ctx context.Context,
	transaction *sql.Tx,
	taskID string,
) ([]pythonAnalysisRunSnapshot, []PythonAnalysisDependency, error) {
	rows, err := transaction.QueryContext(ctx, latestPythonAnalysisRunsCTE+`
SELECT id, source_project_id, analyzer_name, analyzer_version,
       ruleset_version, status, source_manifest_sha256, input_sha256,
       source_size_bytes, source_file_count, analyzed_files,
       parsed_files, recovered_files, failed_files, finding_count,
       diagnostic_count, low_count, medium_count, high_count, critical_count,
       findings_truncated, diagnostics_truncated, created_at, completed_at
FROM ranked_python_analysis_runs
WHERE project_rank = 1
ORDER BY source_project_id ASC, id ASC`, taskID)
	if err != nil {
		return nil, nil, fmt.Errorf("query report Python-analysis runs: %w", err)
	}
	defer rows.Close()
	runs := make([]pythonAnalysisRunSnapshot, 0)
	dependencies := make([]PythonAnalysisDependency, 0)
	for rows.Next() {
		if err := ctx.Err(); err != nil {
			return nil, nil, err
		}
		var value pythonAnalysisRunSnapshot
		var completedAt sql.NullTime
		if err := rows.Scan(
			&value.ID, &value.SourceProjectID, &value.AnalyzerName,
			&value.AnalyzerVersion, &value.RulesetVersion, &value.Status,
			&value.SourceManifestSHA256, &value.InputSHA256,
			&value.SourceSizeBytes, &value.SourceFileCount, &value.AnalyzedFiles,
			&value.ParsedFiles, &value.RecoveredFiles, &value.FailedFiles,
			&value.FindingCount, &value.DiagnosticCount, &value.LowCount,
			&value.MediumCount, &value.HighCount, &value.CriticalCount,
			&value.FindingsTruncated, &value.DiagnosticsTruncated,
			&value.CreatedAt, &completedAt,
		); err != nil {
			return nil, nil, fmt.Errorf("scan report Python-analysis run: %w", err)
		}
		if !completedAt.Valid || completedAt.Time.IsZero() {
			return nil, nil, fmt.Errorf(
				"report Python-analysis run completed_at is invalid",
			)
		}
		value.CompletedAt = completedAt.Time
		runs = append(runs, value)
		dependencies = append(dependencies, PythonAnalysisDependency{
			RunID: value.ID, ProjectID: value.SourceProjectID,
			CompletedAt: value.CompletedAt,
			SourceManifestSHA256: value.SourceManifestSHA256,
			InputSHA256:          value.InputSHA256,
		})
	}
	if err := rows.Err(); err != nil {
		return nil, nil, fmt.Errorf("iterate report Python-analysis runs: %w", err)
	}
	return runs, dependencies, nil
}

func loadHTMLPythonAnalysisFindings(
	ctx context.Context,
	transaction *sql.Tx,
	taskID string,
) ([]pythonAnalysisFindingSnapshot, bool, error) {
	rows, err := transaction.QueryContext(ctx, latestPythonAnalysisRunsCTE+`
SELECT finding.id, finding.run_id, latest.source_project_id,
       finding.cwe, finding.rule_id, finding.severity,
       finding.file_result_id, finding.logical_path, finding.binary_name,
       finding.callable_name, finding.start_line, finding.start_column,
       finding.end_line, finding.end_column, finding.message,
       finding.snippet, finding.snippet_start_line
FROM ranked_python_analysis_runs latest
JOIN python_analysis_findings finding
  ON finding.task_id = ? AND finding.run_id = latest.id
WHERE latest.project_rank = 1
ORDER BY FIELD(finding.severity, 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'),
         latest.source_project_id ASC, finding.id ASC
LIMIT ?`, taskID, taskID, htmlPythonAnalysisFindingLimit+1)
	if err != nil {
		return nil, false, fmt.Errorf("query HTML Python-analysis findings: %w", err)
	}
	defer rows.Close()
	values := make([]pythonAnalysisFindingSnapshot, 0, htmlPythonAnalysisFindingLimit)
	truncated := false
	for rows.Next() {
		if len(values) == htmlPythonAnalysisFindingLimit {
			truncated = true
			break
		}
		if err := ctx.Err(); err != nil {
			return nil, false, err
		}
		var value pythonAnalysisFindingSnapshot
		var snippet, snippetStartLine sql.NullString
		var startLine sql.NullInt64
		if err := rows.Scan(
			&value.ID, &value.RunID, &value.SourceProjectID,
			&value.CWE, &value.RuleID, &value.Severity,
			&value.FileResultID, &value.LogicalPath, &value.BinaryName,
			&value.CallableName, &value.StartLine, &value.StartColumn,
			&value.EndLine, &value.EndColumn, &value.Message,
			&snippet, &startLine,
		); err != nil {
			return nil, false, fmt.Errorf("scan HTML Python-analysis finding: %w", err)
		}
		_ = snippetStartLine
		if snippet.Valid {
			copy := snippet.String
			value.Snippet = &copy
		}
		if startLine.Valid && startLine.Int64 > 0 {
			line := uint64(startLine.Int64)
			value.SnippetStartLine = &line
		}
		values = append(values, value)
	}
	if err := rows.Err(); err != nil {
		return nil, false, fmt.Errorf("iterate HTML Python-analysis findings: %w", err)
	}
	return values, truncated, nil
}

func recordPythonSnapshotDependencies(
	request SnapshotRequest,
	dependencies []PythonAnalysisDependency,
) {
	if request.PythonDependencies == nil {
		return
	}
	*request.PythonDependencies = append(
		(*request.PythonDependencies)[:0], dependencies...,
	)
}

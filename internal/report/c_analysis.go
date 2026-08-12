package report

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

type cAnalysisRunSnapshot struct {
	ID                   string     `json:"id"`
	SourceProjectID      string     `json:"sourceProjectId"`
	AnalyzerName         string     `json:"analyzerName"`
	AnalyzerVersion      string     `json:"analyzerVersion"`
	Status               string     `json:"status"`
	SourceSHA256         string     `json:"sourceSha256"`
	SourceSizeBytes      uint64     `json:"sourceSizeBytes"`
	FindingCount         uint64     `json:"findingCount"`
	DiagnosticCount      uint64     `json:"diagnosticCount"`
	FindingsTruncated    bool       `json:"findingsTruncated"`
	DiagnosticsTruncated bool       `json:"diagnosticsTruncated"`
	CreatedAt            time.Time  `json:"createdAt"`
	CompletedAt          *time.Time `json:"completedAt"`
}

type cAnalysisFindingSnapshot struct {
	ID               string    `json:"id"`
	RunID            string    `json:"runId"`
	SourceProjectID  string    `json:"sourceProjectId"`
	CWE              string    `json:"cwe"`
	RuleID           string    `json:"ruleId"`
	Severity         string    `json:"severity"`
	FunctionResultID string    `json:"functionResultId"`
	FunctionAddress  string    `json:"functionAddress"`
	FunctionName     string    `json:"functionName"`
	StartLine        uint64    `json:"startLine"`
	StartColumn      uint64    `json:"startColumn"`
	EndLine          uint64    `json:"endLine"`
	EndColumn        uint64    `json:"endColumn"`
	Message          string    `json:"message"`
	Snippet          *string   `json:"snippet"`
	CreatedAt        time.Time `json:"createdAt"`
}

const latestCAnalysisRunsCTE = `
WITH ranked_c_analysis_runs AS (
    SELECT run.id, run.source_project_id, run.status, run.source_sha256,
           run.source_size_bytes, run.finding_count, run.diagnostic_count,
           run.findings_truncated, run.diagnostics_truncated,
           run.created_at, run.completed_at,
           analyzer.analyzer_name, analyzer.analyzer_version,
           ROW_NUMBER() OVER (
               PARTITION BY run.source_project_id
               ORDER BY run.completed_at DESC, run.id DESC
           ) AS project_rank
    FROM c_analysis_runs run
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

func loadLatestCAnalysisRuns(
	ctx context.Context,
	transaction *sql.Tx,
	taskID string,
) ([]cAnalysisRunSnapshot, []CAnalysisDependency, error) {
	rows, err := transaction.QueryContext(ctx, latestCAnalysisRunsCTE+`
SELECT id, source_project_id, analyzer_name, analyzer_version, status,
       source_sha256, source_size_bytes, finding_count, diagnostic_count,
       findings_truncated, diagnostics_truncated, created_at, completed_at
FROM ranked_c_analysis_runs
WHERE project_rank = 1
ORDER BY source_project_id ASC, id ASC`, taskID)
	if err != nil {
		return nil, nil, fmt.Errorf("query report C-analysis runs: %w", err)
	}
	defer rows.Close()
	runs := make([]cAnalysisRunSnapshot, 0)
	dependencies := make([]CAnalysisDependency, 0)
	for rows.Next() {
		if err := ctx.Err(); err != nil {
			return nil, nil, err
		}
		var value cAnalysisRunSnapshot
		var completedAt sql.NullTime
		if err := rows.Scan(
			&value.ID, &value.SourceProjectID, &value.AnalyzerName,
			&value.AnalyzerVersion, &value.Status, &value.SourceSHA256,
			&value.SourceSizeBytes, &value.FindingCount,
			&value.DiagnosticCount, &value.FindingsTruncated,
			&value.DiagnosticsTruncated, &value.CreatedAt, &completedAt,
		); err != nil {
			return nil, nil, fmt.Errorf("scan report C-analysis run: %w", err)
		}
		if !completedAt.Valid {
			return nil, nil, errors.New("terminal report C-analysis run has no completion time")
		}
		completed := completedAt.Time
		value.CompletedAt = &completed
		runs = append(runs, value)
		dependencies = append(dependencies, CAnalysisDependency{
			RunID: value.ID, ProjectID: value.SourceProjectID,
			CompletedAt: completed, SourceSHA256: value.SourceSHA256,
		})
	}
	if err := rows.Err(); err != nil {
		return nil, nil, fmt.Errorf("iterate report C-analysis runs: %w", err)
	}
	return runs, dependencies, nil
}

func streamLatestCAnalysisFindings(
	ctx context.Context,
	transaction *sql.Tx,
	taskID string,
	stream *jsonStream,
) error {
	rows, err := transaction.QueryContext(ctx, latestCAnalysisRunsCTE+`
SELECT finding.id, finding.run_id, latest.source_project_id,
       finding.cwe, finding.rule_id, finding.severity,
       finding.function_result_id, finding.function_address,
       finding.function_name, finding.start_line, finding.start_column,
       finding.end_line, finding.end_column, finding.message,
       finding.snippet, finding.created_at
FROM ranked_c_analysis_runs latest
JOIN c_analysis_findings finding
  ON finding.task_id = ? AND finding.run_id = latest.id
WHERE latest.project_rank = 1
ORDER BY latest.source_project_id ASC,
         FIELD(finding.severity, 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'),
         finding.id ASC`, taskID, taskID)
	if err != nil {
		return fmt.Errorf("query report C-analysis findings: %w", err)
	}
	defer rows.Close()
	stream.beginArray("cAnalysisFindings")
	first := true
	for rows.Next() {
		if err := ctx.Err(); err != nil {
			return err
		}
		value, err := scanCAnalysisFinding(rows)
		if err != nil {
			return fmt.Errorf("scan report C-analysis finding: %w", err)
		}
		stream.arrayValue(value, &first)
		if stream.err != nil {
			return fmt.Errorf("write report C-analysis findings: %w", stream.err)
		}
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate report C-analysis findings: %w", err)
	}
	stream.endArray()
	return stream.err
}

func loadHTMLCAnalysisFindings(
	ctx context.Context,
	transaction *sql.Tx,
	taskID string,
) ([]cAnalysisFindingSnapshot, bool, error) {
	rows, err := transaction.QueryContext(ctx, latestCAnalysisRunsCTE+`
SELECT finding.id, finding.run_id, latest.source_project_id,
       finding.cwe, finding.rule_id, finding.severity,
       finding.function_result_id, finding.function_address,
       finding.function_name, finding.start_line, finding.start_column,
       finding.end_line, finding.end_column, finding.message,
       finding.snippet, finding.created_at
FROM ranked_c_analysis_runs latest
JOIN c_analysis_findings finding
  ON finding.task_id = ? AND finding.run_id = latest.id
WHERE latest.project_rank = 1
ORDER BY FIELD(finding.severity, 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'),
         latest.source_project_id ASC, finding.id ASC
LIMIT ?`, taskID, taskID, htmlCAnalysisFindingLimit+1)
	if err != nil {
		return nil, false, fmt.Errorf("query HTML C-analysis findings: %w", err)
	}
	defer rows.Close()
	values := make([]cAnalysisFindingSnapshot, 0, htmlCAnalysisFindingLimit)
	truncated := false
	for rows.Next() {
		if len(values) == htmlCAnalysisFindingLimit {
			truncated = true
			break
		}
		value, err := scanCAnalysisFinding(rows)
		if err != nil {
			return nil, false, fmt.Errorf("scan HTML C-analysis finding: %w", err)
		}
		values = append(values, value)
	}
	if err := rows.Err(); err != nil {
		return nil, false, fmt.Errorf("iterate HTML C-analysis findings: %w", err)
	}
	return values, truncated, nil
}

func scanCAnalysisFinding(scanner rowScanner) (cAnalysisFindingSnapshot, error) {
	var value cAnalysisFindingSnapshot
	var id uint64
	var snippet sql.NullString
	if err := scanner.Scan(
		&id, &value.RunID, &value.SourceProjectID, &value.CWE,
		&value.RuleID, &value.Severity, &value.FunctionResultID,
		&value.FunctionAddress, &value.FunctionName, &value.StartLine,
		&value.StartColumn, &value.EndLine, &value.EndColumn, &value.Message,
		&snippet, &value.CreatedAt,
	); err != nil {
		return cAnalysisFindingSnapshot{}, err
	}
	value.ID = fmt.Sprint(id)
	value.Snippet = nullableString(snippet)
	return value, nil
}

func recordSnapshotDependencies(
	request SnapshotRequest,
	dependencies []CAnalysisDependency,
) {
	if request.Dependencies == nil {
		return
	}
	*request.Dependencies = append((*request.Dependencies)[:0], dependencies...)
}

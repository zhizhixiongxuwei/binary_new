package javaanalysis

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"regexp"
	"testing"
	"time"

	"binaryscan/internal/queue"

	"github.com/DATA-DOG/go-sqlmock"
)

func TestSetBundleIdentityRequiresExactLiveFence(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	repository, err := NewMySQLRepository(db, RepositoryConfig{})
	if err != nil {
		t.Fatal(err)
	}
	lease := javaRepositoryLease(t)
	bundleSHA := stringsOf("b", 64)
	mock.ExpectBegin()
	mock.ExpectExec(regexp.QuoteMeta("UPDATE java_analysis_runs analysis")+
		`(?s).*job[.]lease_owner = [?].*job[.]fencing_token = [?].*analysis[.]bundle_sha256 IS NULL`).
		WithArgs(
			bundleSHA, lease.JobID, lease.TaskID, lease.Owner,
			lease.FencingToken, testRunID, stringsOf("a", 64),
			stringsOf("c", 64), bundleSHA,
		).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()
	if err := repository.SetBundleIdentity(t.Context(), lease, bundleSHA); err != nil {
		t.Fatal(err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestSetBundleIdentityRejectsStaleFence(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	repository, err := NewMySQLRepository(db, RepositoryConfig{})
	if err != nil {
		t.Fatal(err)
	}
	lease := javaRepositoryLease(t)
	bundleSHA := stringsOf("b", 64)
	mock.ExpectBegin()
	mock.ExpectExec(`(?s)UPDATE java_analysis_runs analysis.*job[.]fencing_token = [?]`).
		WithArgs(
			bundleSHA, lease.JobID, lease.TaskID, lease.Owner,
			lease.FencingToken, testRunID, stringsOf("a", 64),
			stringsOf("c", 64), bundleSHA,
		).
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectRollback()
	err = repository.SetBundleIdentity(context.Background(), lease, bundleSHA)
	if !errors.Is(err, ErrLeaseLost) {
		t.Fatalf("SetBundleIdentity error = %v, want lease lost", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestCheckerProjectStatusPropagatesIncompleteSourceBoundaries(t *testing.T) {
	tests := []struct {
		projectStatus string
		language      string
		want          string
	}{
		{projectStatus: "complete", language: "java", want: "complete"},
		{projectStatus: "partial", language: "java", want: "partial"},
		{projectStatus: "complete", language: "mixed", want: "partial"},
		{projectStatus: "partial", language: "mixed", want: "partial"},
	}
	for _, test := range tests {
		if got := checkerProjectStatus(test.projectStatus, test.language); got != test.want {
			t.Errorf(
				"checker project status for %s/%s = %s, want %s",
				test.projectStatus, test.language, got, test.want,
			)
		}
	}
}

func TestCreateInvalidatesReportsInJavaCreationTransaction(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	invalidations := 0
	repository, err := NewMySQLRepository(db, RepositoryConfig{
		InvalidateReports: func(_ context.Context, tx *sql.Tx, taskID string) error {
			if tx == nil || taskID != testTaskID {
				t.Fatalf("invalidation transaction/task = %p/%q", tx, taskID)
			}
			invalidations++
			return nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	lease, file, inputSHA := javaLifecycleFixture(t)
	record := CreateRecord{
		RunID: testRunID, JobID: testJobID, TaskID: testTaskID,
		SourceProjectID: testProjectID, UserID: 7,
		RequestKey: "java_analysis:" + stringsOf("d", 64),
	}
	createdAt := time.Date(2026, 8, 10, 1, 2, 3, 0, time.UTC)

	mock.ExpectBegin()
	mock.ExpectQuery(`(?s)SELECT status, deleted_at.*FROM tasks.*FOR UPDATE`).
		WithArgs(testTaskID).
		WillReturnRows(sqlmock.NewRows([]string{"status", "deleted_at"}).
			AddRow("SUCCEEDED", nil))
	mock.ExpectQuery(`(?s)SELECT analysis.id, analysis.source_project_id.*idempotency_key = \?.*FOR UPDATE`).
		WithArgs(testTaskID, record.RequestKey).
		WillReturnError(sql.ErrNoRows)
	expectEligibleJavaProject(mock, lease, file)
	mock.ExpectQuery(`(?s)SELECT EXISTS.*FROM worker_readiness.*worker_kind = 'java_analysis'`).
		WithArgs(AnalyzerName, AnalyzerVersion, int64(30*time.Second/time.Microsecond)).
		WillReturnRows(sqlmock.NewRows([]string{"ready"}).AddRow(true))
	mock.ExpectQuery(`(?s)SELECT id.*FROM java_analysis_runs.*status IN \('queued', 'running', 'cancel_requested'\).*FOR UPDATE`).
		WithArgs(testProjectID).
		WillReturnError(sql.ErrNoRows)
	mock.ExpectExec(`(?s)INSERT INTO jobs.*'java_analysis'.*'queued'`).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`(?s)INSERT INTO analyzer_runs.*'queued'`).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`(?s)INSERT INTO java_analysis_runs.*'queued'`).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectQuery(`(?s)SELECT analysis.id.*FROM java_analysis_runs analysis.*WHERE analysis.task_id = \? AND analysis.id = \?`).
		WithArgs(testTaskID, testRunID).
		WillReturnRows(javaRunRows(createdAt, "queued", file, inputSHA))
	mock.ExpectCommit()

	value, created, err := repository.Create(t.Context(), record)
	if err != nil || !created || value.ID != testRunID {
		t.Fatalf("Create() = (%#v, %v, %v)", value, created, err)
	}
	if invalidations != 1 {
		t.Fatalf("report invalidations = %d, want 1", invalidations)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestBeginInvalidatesOnlyWhenJavaRunBecomesRunning(t *testing.T) {
	tests := []struct {
		name        string
		status      string
		invalidates int
	}{
		{name: "queued transition", status: "queued", invalidates: 1},
		{name: "running replay", status: "running", invalidates: 0},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			db, mock, err := sqlmock.New()
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			invalidations := 0
			repository, err := NewMySQLRepository(db, RepositoryConfig{
				InvalidateReports: func(_ context.Context, tx *sql.Tx, taskID string) error {
					if tx == nil || taskID != testTaskID {
						t.Fatalf("invalidation transaction/task = %p/%q", tx, taskID)
					}
					invalidations++
					return nil
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			lease, file, inputSHA := javaLifecycleFixture(t)

			mock.ExpectBegin()
			mock.ExpectQuery(`(?s)SELECT analysis.status, analysis.source_project_id.*analysis.error_code, analyzer.status.*FOR UPDATE`).
				WithArgs(lease.JobID, lease.TaskID, lease.Owner, lease.FencingToken, testRunID).
				WillReturnRows(sqlmock.NewRows([]string{
					"analysis_status", "source_project_id", "manifest_sha", "input_sha",
					"source_size", "source_count", "error_code", "analyzer_status",
					"analyzer_version",
				}).AddRow(
					test.status, testProjectID, stringsOf("a", 64), inputSHA,
					file.SizeBytes, uint32(1), nil, test.status, AnalyzerVersion,
				))
			expectEligibleJavaProject(mock, lease, file)
			if test.invalidates != 0 {
				mock.ExpectExec(`(?s)UPDATE java_analysis_runs.*SET status = 'running'.*status IN \('queued', 'running'\)`).
					WithArgs(lease.TaskID, testRunID).
					WillReturnResult(sqlmock.NewResult(0, 1))
				mock.ExpectExec(`(?s)UPDATE analyzer_runs.*SET status = 'running'.*status IN \('queued', 'running'\)`).
					WithArgs(lease.TaskID, testRunID).
					WillReturnResult(sqlmock.NewResult(0, 1))
			}
			mock.ExpectCommit()

			if _, err := repository.Begin(t.Context(), lease); err != nil {
				t.Fatal(err)
			}
			if invalidations != test.invalidates {
				t.Fatalf("report invalidations = %d, want %d", invalidations, test.invalidates)
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestPublishFailedInvalidatesReportsInsideFencedTransaction(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	invalidations := 0
	repository, err := NewMySQLRepository(db, RepositoryConfig{
		InvalidateReports: func(_ context.Context, tx *sql.Tx, taskID string) error {
			if tx == nil || taskID != testTaskID {
				t.Fatalf("invalidation transaction/task = %p/%q", tx, taskID)
			}
			invalidations++
			return nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	lease, file, inputSHA := javaLifecycleFixture(t)
	bundleSHA := stringsOf("b", 64)
	checkerAnalysisID := javaCheckerAnalysisID(
		testRunID, lease.JobID, lease.FencingToken,
	)
	metadata := RequestMetadata{
		SchemaVersion: RequestSchemaVersion, AnalysisID: checkerAnalysisID,
		InputSHA256: inputSHA, BundleSHA256: bundleSHA,
		SourceManifestSHA256: stringsOf("a", 64),
		ProjectID:            testProjectID, Language: "java", ProjectStatus: "complete",
		Files: []SourceFile{file},
	}
	result := Result{
		SchemaVersion: ResponseSchemaVersion, AnalysisID: checkerAnalysisID,
		Status: "failed", Identity: CheckerIdentity{
			Product: AnalyzerName, Version: AnalyzerVersion,
			Ruleset: DefaultRulesetVersion,
		},
		InputSHA256: inputSHA, BundleSHA256: bundleSHA,
		Coverage: ResultCoverage{FilesTotal: 1, FilesFailed: 1},
		Summary:  ResultSummary{DiagnosticCount: 1},
		Findings: []Finding{},
		Diagnostics: []Diagnostic{{
			Code: "parse-error", Message: "Parser rejected the source file.",
		}},
	}

	mock.ExpectBegin()
	mock.ExpectQuery(`(?s)SELECT analysis.source_project_id.*analysis.bundle_sha256.*FROM jobs job.*FOR UPDATE`).
		WithArgs(lease.JobID, lease.TaskID, lease.Owner, lease.FencingToken, testRunID).
		WillReturnRows(sqlmock.NewRows([]string{
			"source_project_id", "manifest_sha", "input_sha", "bundle_sha",
			"source_size", "source_count", "analyzer_version",
		}).AddRow(
			testProjectID, stringsOf("a", 64), inputSHA, bundleSHA,
			file.SizeBytes, 1, AnalyzerVersion,
		))
	expectEligibleJavaProject(mock, lease, file)
	mock.ExpectExec(`DELETE FROM java_analysis_findings`).
		WithArgs(lease.TaskID, testRunID).
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec(`(?s)UPDATE java_analysis_runs.*status = 'failed'.*error_code = 'java_checker_failed'`).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`(?s)UPDATE analyzer_runs.*status = 'failed'.*error_code = 'java_checker_failed'`).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectQuery(`(?s)SELECT 1.*FROM jobs job.*JOIN decompile_source_projects project.*analysis.status = \?`).
		WillReturnRows(sqlmock.NewRows([]string{"marker"}).AddRow(1))
	mock.ExpectCommit()

	if err := repository.PublishFailed(t.Context(), lease, metadata, result); err != nil {
		t.Fatal(err)
	}
	if invalidations != 1 {
		t.Fatalf("report invalidations = %d, want 1", invalidations)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestPublishInvalidatesReportsInsideFencedTransaction(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	invalidated := false
	repository, err := NewMySQLRepository(db, RepositoryConfig{
		InvalidateReports: func(_ context.Context, tx *sql.Tx, taskID string) error {
			if tx == nil || taskID != "723e4567-e89b-42d3-a456-426614174006" {
				t.Fatalf("report invalidation transaction/task = %p/%q", tx, taskID)
			}
			invalidated = true
			return nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	content := "class A {}"
	file := javaTestFile(testResultA, "src/main/java/a/A.java", "a.A", content)
	file.OffsetBytes = 0
	file.LengthBytes = file.SizeBytes
	inputSHA, err := canonicalInputSHA256([]SourceFile{file})
	if err != nil {
		t.Fatal(err)
	}
	lease := javaRepositoryLease(t)
	payload := jobPayload{
		SchemaVersion: jobPayloadSchemaVersion, RunID: testRunID,
		ProjectID: testProjectID, SourceManifestSHA256: stringsOf("a", 64),
		InputSHA256: inputSHA, SourceSizeBytes: file.SizeBytes,
		SourceFileCount: 1,
	}
	lease.Payload, err = json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	bundleSHA := stringsOf("b", 64)
	checkerAnalysisID := javaCheckerAnalysisID(
		payload.RunID, lease.JobID, lease.FencingToken,
	)
	metadata := RequestMetadata{
		SchemaVersion: RequestSchemaVersion, AnalysisID: checkerAnalysisID,
		InputSHA256: inputSHA, BundleSHA256: bundleSHA,
		SourceManifestSHA256: payload.SourceManifestSHA256,
		ProjectID:            testProjectID, Language: "java", ProjectStatus: "complete",
		Files: []SourceFile{file},
	}
	result := Result{
		SchemaVersion: ResponseSchemaVersion, AnalysisID: checkerAnalysisID,
		Status: "complete", Identity: CheckerIdentity{
			Product: AnalyzerName, Version: AnalyzerVersion,
			Ruleset: DefaultRulesetVersion,
		},
		InputSHA256: inputSHA, BundleSHA256: bundleSHA,
		Coverage: ResultCoverage{
			FilesTotal: 1, FilesAnalyzed: 1, FilesParsed: 1,
		},
		Findings: []Finding{}, Diagnostics: []Diagnostic{},
	}
	expectedRoot := "source-projects/" + testProjectID
	mock.ExpectBegin()
	mock.ExpectQuery(`(?s)SELECT analysis.source_project_id.*analysis.bundle_sha256.*FROM jobs job.*FOR UPDATE`).
		WithArgs(lease.JobID, lease.TaskID, lease.Owner, lease.FencingToken, testRunID).
		WillReturnRows(sqlmock.NewRows([]string{
			"source_project_id", "manifest_sha", "input_sha", "bundle_sha",
			"source_size", "source_count", "analyzer_version",
		}).AddRow(
			testProjectID, payload.SourceManifestSHA256, inputSHA, bundleSHA,
			file.SizeBytes, 1, AnalyzerVersion,
		))
	mock.ExpectQuery(`(?s)SELECT project.status.*FROM decompile_source_projects project.*FOR UPDATE`).
		WithArgs(lease.TaskID, testProjectID).
		WillReturnRows(sqlmock.NewRows([]string{
			"status", "source_kind", "language", "engine_name", "engine_version",
			"root_storage_key", "manifest_storage_key", "manifest_sha256",
			"manifest_size_bytes", "source_file_count", "symbol_count",
			"source_size_bytes", "task_attempt_id", "file_node_id", "logical_path",
		}).AddRow(
			"complete", "java", "java", "fixture", "1", expectedRoot,
			expectedRoot+"/manifest.json", payload.SourceManifestSHA256,
			100, 1, 1, file.SizeBytes, *lease.TaskAttemptID, 9, "/sample.jar",
		))
	mock.ExpectQuery(`(?s)SELECT result.id.*FROM decompile_results result.*ORDER BY result.storage_key`).
		WithArgs(expectedRoot, lease.TaskID, testProjectID, expectedRoot).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "logical_path", "binary_name", "content_sha256", "size_bytes",
		}).AddRow(
			file.ResultID, file.LogicalPath, file.BinaryName, file.SHA256, file.SizeBytes,
		))
	mock.ExpectExec(`DELETE FROM java_analysis_findings`).
		WithArgs(lease.TaskID, testRunID).
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectPrepare(`INSERT INTO java_analysis_findings`)
	mock.ExpectExec(`(?s)UPDATE java_analysis_runs.*SET status = \?.*completed_at = UTC_TIMESTAMP`).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`(?s)UPDATE analyzer_runs.*SET status = \?.*completed_at = UTC_TIMESTAMP`).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectQuery(`(?s)SELECT 1.*FROM jobs job.*JOIN decompile_source_projects project.*analysis.status = \?`).
		WillReturnRows(sqlmock.NewRows([]string{"marker"}).AddRow(1))
	mock.ExpectCommit()

	if err := repository.Publish(t.Context(), lease, metadata, result); err != nil {
		t.Fatal(err)
	}
	if !invalidated {
		t.Fatal("successful Java publication did not invalidate reports")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func javaLifecycleFixture(t *testing.T) (queue.Lease, SourceFile, string) {
	t.Helper()
	file := javaTestFile(
		testResultA, "src/main/java/a/A.java", "a.A", "class A {}",
	)
	file.OffsetBytes = 0
	file.LengthBytes = file.SizeBytes
	inputSHA, err := canonicalInputSHA256([]SourceFile{file})
	if err != nil {
		t.Fatal(err)
	}
	lease := javaRepositoryLease(t)
	lease.Payload, err = json.Marshal(jobPayload{
		SchemaVersion: jobPayloadSchemaVersion, RunID: testRunID,
		ProjectID: testProjectID, SourceManifestSHA256: stringsOf("a", 64),
		InputSHA256: inputSHA, SourceSizeBytes: file.SizeBytes,
		SourceFileCount: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	return lease, file, inputSHA
}

func expectEligibleJavaProject(
	mock sqlmock.Sqlmock,
	lease queue.Lease,
	file SourceFile,
) {
	expectedRoot := "source-projects/" + testProjectID
	mock.ExpectQuery(`(?s)SELECT project.status.*FROM decompile_source_projects project.*FOR UPDATE`).
		WithArgs(lease.TaskID, testProjectID).
		WillReturnRows(sqlmock.NewRows([]string{
			"status", "source_kind", "language", "engine_name", "engine_version",
			"root_storage_key", "manifest_storage_key", "manifest_sha256",
			"manifest_size_bytes", "source_file_count", "symbol_count",
			"source_size_bytes", "task_attempt_id", "file_node_id", "logical_path",
		}).AddRow(
			"complete", "java", "java", "fixture", "1", expectedRoot,
			expectedRoot+"/manifest.json", stringsOf("a", 64),
			100, 1, 1, file.SizeBytes, *lease.TaskAttemptID, 9, "/sample.jar",
		))
	mock.ExpectQuery(`(?s)SELECT result.id.*FROM decompile_results result.*ORDER BY result.storage_key`).
		WithArgs(expectedRoot, lease.TaskID, testProjectID, expectedRoot).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "logical_path", "binary_name", "content_sha256", "size_bytes",
		}).AddRow(
			file.ResultID, file.LogicalPath, file.BinaryName, file.SHA256, file.SizeBytes,
		))
}

func javaRunRows(
	createdAt time.Time,
	status string,
	file SourceFile,
	inputSHA string,
) *sqlmock.Rows {
	columns := []string{
		"id", "task_id", "source_project_id", "job_id", "status",
		"analyzer_name", "analyzer_version", "source_manifest_sha256",
		"input_sha256", "bundle_sha256", "source_size_bytes",
		"source_file_count", "ruleset_version", "analyzed_files",
		"parsed_files", "recovered_files", "failed_files", "finding_count",
		"diagnostic_count", "low_count", "medium_count", "high_count",
		"critical_count", "findings_truncated", "diagnostics_truncated",
		"error_code", "error_message", "started_at", "completed_at",
		"created_at", "updated_at", "logical_path", "project_status",
		"engine_name", "engine_version",
	}
	return sqlmock.NewRows(columns).AddRow(
		testRunID, testTaskID, testProjectID, testJobID, status,
		AnalyzerName, AnalyzerVersion, stringsOf("a", 64), inputSHA, nil,
		file.SizeBytes, uint32(1), nil, uint32(0), uint32(0), uint32(0),
		uint32(0), uint32(0), uint32(0), uint32(0), uint32(0), uint32(0),
		uint32(0), false, false, nil, nil, nil, nil, createdAt, createdAt,
		"/sample.jar", "complete", "fixture", "1",
	)
}

func javaRepositoryLease(t *testing.T) queue.Lease {
	t.Helper()
	payload, err := json.Marshal(jobPayload{
		SchemaVersion: jobPayloadSchemaVersion, RunID: testRunID,
		ProjectID: testProjectID, SourceManifestSHA256: stringsOf("a", 64),
		InputSHA256: stringsOf("c", 64), SourceSizeBytes: 10,
		SourceFileCount: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	attemptID := uint64(9)
	return queue.Lease{
		JobID:         "623e4567-e89b-42d3-a456-426614174005",
		TaskID:        "723e4567-e89b-42d3-a456-426614174006",
		TaskAttemptID: &attemptID, Kind: queue.KindJavaAnalysis,
		Payload: payload, Attempt: 1, MaxAttempts: 3, FencingToken: 7,
		Owner: "java-analysis:test", LeaseUntil: time.Now().Add(time.Minute),
	}
}

func stringsOf(value string, count int) string {
	result := ""
	for range count {
		result += value
	}
	return result
}

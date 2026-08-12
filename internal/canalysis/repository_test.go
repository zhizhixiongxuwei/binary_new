package canalysis

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
)

func TestRepositoryCreateReplaysExactIdempotentRunBeforeReadiness(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	repository, err := NewMySQLRepository(db, RepositoryConfig{
		AnalyzerVersion: AnalyzerVersion, ReadyMaxAge: time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	record := validRepositoryCreateRecord()
	createdAt := time.Date(2026, 8, 10, 1, 2, 3, 0, time.UTC)
	mock.ExpectBegin()
	mock.ExpectQuery(`(?s)SELECT status, deleted_at.*FROM tasks.*FOR UPDATE`).
		WithArgs(testTaskID).
		WillReturnRows(sqlmock.NewRows([]string{"status", "deleted_at"}).
			AddRow("SUCCEEDED", nil))
	mock.ExpectQuery(`(?s)SELECT analysis.id, analysis.source_project_id.*idempotency_key = \?.*FOR UPDATE`).
		WithArgs(testTaskID, record.RequestKey).
		WillReturnRows(sqlmock.NewRows([]string{"id", "source_project_id"}).
			AddRow(testRunID, testProjectID))
	mock.ExpectQuery(`(?s)SELECT analysis.id.*FROM c_analysis_runs analysis.*analysis.deletion_started_at IS NULL.*WHERE analysis.task_id = \? AND analysis.id = \?`).
		WithArgs(testTaskID, testRunID).
		WillReturnRows(runRows(createdAt))
	mock.ExpectCommit()
	value, created, err := repository.Create(context.Background(), record)
	if err != nil || created || value.ID != testRunID ||
		value.SourceProject.TargetPath != "bin/sample" {
		t.Fatalf("Create() = %#v, %v, %v", value, created, err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestRepositoryCreateInvalidatesReportsInCreationTransaction(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	repository, err := NewMySQLRepository(db, RepositoryConfig{})
	if err != nil {
		t.Fatal(err)
	}
	record := validRepositoryCreateRecord()
	createdAt := time.Date(2026, 8, 10, 1, 2, 3, 0, time.UTC)

	mock.ExpectBegin()
	mock.ExpectQuery(`(?s)SELECT status, deleted_at.*FROM tasks.*FOR UPDATE`).
		WithArgs(testTaskID).
		WillReturnRows(sqlmock.NewRows([]string{"status", "deleted_at"}).
			AddRow("SUCCEEDED", nil))
	mock.ExpectQuery(`(?s)SELECT analysis.id, analysis.source_project_id.*idempotency_key = \?.*FOR UPDATE`).
		WithArgs(testTaskID, record.RequestKey).
		WillReturnError(sql.ErrNoRows)
	expectEligibleCProject(mock)
	mock.ExpectQuery(`(?s)SELECT EXISTS.*FROM worker_readiness.*worker_kind = 'c_analysis'`).
		WithArgs(AnalyzerName, AnalyzerVersion, int64(30*time.Second/time.Microsecond)).
		WillReturnRows(sqlmock.NewRows([]string{"ready"}).AddRow(true))
	mock.ExpectQuery(`(?s)SELECT id.*FROM c_analysis_runs.*status IN \('queued', 'running', 'cancel_requested'\).*FOR UPDATE`).
		WithArgs(testProjectID).
		WillReturnError(sql.ErrNoRows)
	mock.ExpectExec(`(?s)INSERT INTO jobs.*'c_analysis'.*'queued'`).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`(?s)INSERT INTO analyzer_runs.*'queued'`).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`(?s)INSERT INTO c_analysis_runs.*'queued'`).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectQuery(`(?s)SELECT analysis.id.*FROM c_analysis_runs analysis.*WHERE analysis.task_id = \? AND analysis.id = \?`).
		WithArgs(testTaskID, testRunID).
		WillReturnRows(runRows(createdAt))
	expectSourceAnalysisReportInvalidation(mock, testTaskID)
	mock.ExpectCommit()

	value, created, err := repository.Create(t.Context(), record)
	if err != nil || !created || value.ID != testRunID {
		t.Fatalf("Create() = (%#v, %v, %v)", value, created, err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestRepositoryBeginInvalidatesOnlyWhenRunBecomesRunning(t *testing.T) {
	tests := []struct {
		name        string
		status      string
		invalidates bool
	}{
		{name: "queued transition", status: "queued", invalidates: true},
		{name: "running replay", status: "running", invalidates: false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			db, mock, err := sqlmock.New()
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			repository, err := NewMySQLRepository(db, RepositoryConfig{})
			if err != nil {
				t.Fatal(err)
			}
			lease := processorLease(t, ProjectSnapshot{
				CanonicalSHA256: testSHA, CanonicalSizeBytes: 128,
			})

			mock.ExpectBegin()
			mock.ExpectQuery(`(?s)SELECT analysis.status, analysis.source_project_id.*analyzer.status.*FOR UPDATE`).
				WithArgs(testJobID, testTaskID, lease.Owner, uint64(2), testRunID).
				WillReturnRows(sqlmock.NewRows([]string{
					"analysis_status", "source_project_id", "source_sha256",
					"source_size_bytes", "total_functions", "error_code",
					"analyzer_status", "analyzer_version",
				}).AddRow(
					test.status, testProjectID, testSHA, uint64(128), uint32(1),
					nil, test.status, AnalyzerVersion,
				))
			expectEligibleCProject(mock)
			if test.invalidates {
				mock.ExpectExec(`(?s)UPDATE c_analysis_runs.*SET status = 'running'.*status IN \('queued', 'running'\)`).
					WithArgs(testTaskID, testRunID).
					WillReturnResult(sqlmock.NewResult(0, 1))
				mock.ExpectExec(`(?s)UPDATE analyzer_runs.*SET status = 'running'.*status IN \('queued', 'running'\)`).
					WithArgs(testTaskID, testRunID).
					WillReturnResult(sqlmock.NewResult(0, 1))
				expectSourceAnalysisReportInvalidation(mock, testTaskID)
			}
			mock.ExpectCommit()

			if _, err := repository.Begin(t.Context(), lease); err != nil {
				t.Fatal(err)
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestRepositoryCreateRejectsIdempotencyKeyReusedForAnotherProject(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	repository, err := NewMySQLRepository(db, RepositoryConfig{})
	if err != nil {
		t.Fatal(err)
	}
	record := validRepositoryCreateRecord()
	mock.ExpectBegin()
	mock.ExpectQuery(`(?s)SELECT status, deleted_at.*FROM tasks.*FOR UPDATE`).
		WithArgs(testTaskID).
		WillReturnRows(sqlmock.NewRows([]string{"status", "deleted_at"}).
			AddRow("SUCCEEDED", nil))
	mock.ExpectQuery(`(?s)SELECT analysis.id, analysis.source_project_id.*idempotency_key = \?.*FOR UPDATE`).
		WithArgs(testTaskID, record.RequestKey).
		WillReturnRows(sqlmock.NewRows([]string{"id", "source_project_id"}).
			AddRow(testRunID, "66666666-6666-4666-8666-666666666666"))
	mock.ExpectRollback()
	_, _, err = repository.Create(context.Background(), record)
	if !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("Create() error = %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestRepositoryCancelInvalidatesOnlyOnMutation(t *testing.T) {
	tests := []struct {
		name       string
		runStatus  string
		jobStatus  string
		wantStatus string
		mutated    bool
	}{
		{
			name: "queued cancellation", runStatus: "queued", jobStatus: "queued",
			wantStatus: "cancelled", mutated: true,
		},
		{
			name: "running cancellation request", runStatus: "running",
			jobStatus: "running", wantStatus: "cancel_requested", mutated: true,
		},
		{
			name: "cancellation request replay", runStatus: "cancel_requested",
			jobStatus: "cancel_requested", wantStatus: "cancel_requested", mutated: false,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			db, mock, err := sqlmock.New()
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			repository, err := NewMySQLRepository(db, RepositoryConfig{})
			if err != nil {
				t.Fatal(err)
			}
			createdAt := time.Date(2026, 8, 10, 1, 2, 3, 0, time.UTC)

			mock.ExpectBegin()
			mock.ExpectQuery(`SELECT 1 FROM tasks WHERE id = \? AND deleted_at IS NULL`).
				WithArgs(testTaskID).
				WillReturnRows(sqlmock.NewRows([]string{"present"}).AddRow(1))
			mock.ExpectQuery(`(?s)SELECT analysis.status, analysis.job_id, job.status.*FOR UPDATE`).
				WithArgs(testTaskID, testRunID).
				WillReturnRows(sqlmock.NewRows([]string{
					"analysis_status", "job_id", "job_status",
				}).AddRow(test.runStatus, testJobID, test.jobStatus))
			if test.mutated && test.jobStatus == "queued" {
				mock.ExpectExec(`(?s)UPDATE jobs.*status = 'cancelled'.*status = 'queued'`).
					WithArgs(testJobID, testTaskID).
					WillReturnResult(sqlmock.NewResult(0, 1))
				mock.ExpectExec(`(?s)UPDATE c_analysis_runs.*status = 'cancelled'.*status = 'queued'`).
					WithArgs(testTaskID, testRunID).
					WillReturnResult(sqlmock.NewResult(0, 1))
				mock.ExpectExec(`(?s)UPDATE analyzer_runs.*status = 'cancelled'.*status = 'queued'`).
					WithArgs(testTaskID, testRunID).
					WillReturnResult(sqlmock.NewResult(0, 1))
			} else if test.mutated {
				mock.ExpectExec(`(?s)UPDATE jobs.*status = 'cancel_requested'.*status IN \('leased', 'running', 'cancel_requested'\)`).
					WithArgs(testJobID, testTaskID).
					WillReturnResult(sqlmock.NewResult(0, 1))
				mock.ExpectExec(`(?s)UPDATE c_analysis_runs.*status = 'cancel_requested'.*status IN \('queued', 'running', 'cancel_requested'\)`).
					WithArgs(testTaskID, testRunID).
					WillReturnResult(sqlmock.NewResult(0, 1))
			}
			mock.ExpectQuery(`(?s)SELECT analysis.id.*FROM c_analysis_runs analysis.*WHERE analysis.task_id = \? AND analysis.id = \?`).
				WithArgs(testTaskID, testRunID).
				WillReturnRows(runRowsWithStatus(createdAt, test.wantStatus))
			if test.mutated {
				expectSourceAnalysisReportInvalidation(mock, testTaskID)
			}
			mock.ExpectCommit()

			value, err := repository.Cancel(t.Context(), ActionInput{
				TaskID: testTaskID, RunID: testRunID,
			})
			if err != nil || value.Status != test.wantStatus {
				t.Fatalf("Cancel() = (%#v, %v)", value, err)
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestRepositoryCanFailQueuedRunAfterSourceFenceRejectsBegin(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	repository, err := NewMySQLRepository(db, RepositoryConfig{})
	if err != nil {
		t.Fatal(err)
	}
	lease := processorLease(t, ProjectSnapshot{
		CanonicalSHA256: testSHA, CanonicalSizeBytes: 128,
	})
	mock.ExpectBegin()
	mock.ExpectQuery(`(?s)SELECT analysis.status, analyzer.status.*job.status = 'running'.*FOR UPDATE`).
		WithArgs(testJobID, testTaskID, lease.Owner, uint64(2), testRunID).
		WillReturnRows(sqlmock.NewRows([]string{
			"analysis_status", "analyzer_status",
		}).AddRow("queued", "queued"))
	mock.ExpectExec(`(?s)UPDATE c_analysis_runs.*SET status = \?.*status IN \('queued', 'running'\)`).
		WithArgs(
			"failed", "c_analysis_source_unavailable", "Source unavailable.",
			testTaskID, testRunID,
		).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`(?s)UPDATE analyzer_runs.*SET status = \?.*status IN \('queued', 'running'\)`).
		WithArgs(
			"failed", "c_analysis_source_unavailable", "Source unavailable.",
			testTaskID, testRunID,
		).
		WillReturnResult(sqlmock.NewResult(0, 1))
	expectSourceAnalysisReportInvalidation(mock, testTaskID)
	mock.ExpectCommit()

	err = repository.Fail(
		context.Background(), lease,
		"c_analysis_source_unavailable", "Source unavailable.",
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestRepositoryRecognizesPublishedCheckerFailureForFinishReplay(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	repository, err := NewMySQLRepository(db, RepositoryConfig{})
	if err != nil {
		t.Fatal(err)
	}
	lease := processorLease(t, ProjectSnapshot{
		CanonicalSHA256: testSHA, CanonicalSizeBytes: 128,
	})
	mock.ExpectBegin()
	mock.ExpectQuery(`(?s)SELECT analysis[.]status, analysis[.]source_project_id.*analysis[.]error_code.*FOR UPDATE`).
		WithArgs(testJobID, testTaskID, lease.Owner, uint64(2), testRunID).
		WillReturnRows(sqlmock.NewRows([]string{
			"analysis_status", "source_project_id", "source_sha256",
			"source_size_bytes", "total_functions", "error_code",
			"analyzer_status", "analyzer_version",
		}).AddRow(
			"failed", testProjectID, testSHA, uint64(128), uint32(1),
			"c_checker_failed", "failed", AnalyzerVersion,
		))
	mock.ExpectRollback()

	_, err = repository.Begin(context.Background(), lease)
	if !errors.Is(err, ErrFailedResultPublished) {
		t.Fatalf("Begin() error = %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestRepositoryPublishesFailedCheckerSummaryWithLeaseAndSourceFences(
	t *testing.T,
) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	repository, err := NewMySQLRepository(db, RepositoryConfig{})
	if err != nil {
		t.Fatal(err)
	}
	lease := processorLease(t, ProjectSnapshot{
		CanonicalSHA256: testSHA, CanonicalSizeBytes: 128,
	})
	line := uint32(4)
	result := Result{
		SchemaVersion: ResponseSchemaVersion, AnalysisID: testRunID,
		Status: "failed",
		Checker: CheckerIdentity{
			Name: AnalyzerName, Version: AnalyzerVersion,
			RulesetVersion: DefaultRulesetVersion,
		},
		Coverage: Coverage{
			TotalFunctions: 1, ParsedFunctions: 0, FailedFunctions: 1,
		},
		Summary: ResultSummary{
			DiagnosticCount: 1, DiagnosticsTruncated: true,
		},
		Findings: []Finding{},
		Diagnostics: []Diagnostic{{
			FunctionResultID: testResultID, Code: "parse-error",
			Message: "Parser stopped at an unsupported construct.", Line: &line,
		}},
	}
	canonicalKey := "source-projects/" + testProjectID + "/src/decompiled.c"

	mock.ExpectBegin()
	mock.ExpectQuery(`(?s)SELECT analysis[.]source_project_id, analysis[.]source_sha256.*analysis[.]status = 'running'.*FOR UPDATE`).
		WithArgs(testJobID, testTaskID, lease.Owner, uint64(2), testRunID).
		WillReturnRows(sqlmock.NewRows([]string{
			"source_project_id", "source_sha256", "source_size_bytes",
			"total_functions", "analyzer_version",
		}).AddRow(testProjectID, testSHA, uint64(128), uint32(1), AnalyzerVersion))
	mock.ExpectQuery(`(?s)SELECT project[.]status, project[.]engine_name.*FROM decompile_source_projects project.*FOR UPDATE`).
		WithArgs(testTaskID, testProjectID).
		WillReturnRows(sqlmock.NewRows([]string{
			"status", "engine_name", "engine_version", "root_storage_key",
			"canonical_storage_key", "canonical_sha256", "canonical_size_bytes",
			"source_file_count", "symbol_count", "task_attempt_id", "file_node_id",
			"logical_path",
		}).AddRow(
			"complete", "ghidra", "12.1.2", "source-projects/"+testProjectID,
			canonicalKey, testSHA, uint64(128), uint64(1), uint64(1), uint64(9),
			uint64(17), "bin/sample",
		))
	mock.ExpectQuery(`(?s)SELECT result[.]id, result[.]symbol_key.*FROM decompile_results result.*ORDER BY`).
		WithArgs(testTaskID, testProjectID, canonicalKey).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "symbol_key", "display_name", "content_sha256",
			"source_offset_bytes", "source_length_bytes", "source_start_line",
			"source_end_line",
		}).AddRow(
			testResultID, "00401000", "main", testSHA, uint64(0), uint64(128),
			uint64(1), uint64(10),
		))
	mock.ExpectExec(`DELETE FROM c_analysis_findings`).
		WithArgs(testTaskID, testRunID).
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec(`(?s)UPDATE c_analysis_runs.*status = 'failed'.*parsed_functions = \?.*diagnostic_count = \?.*diagnostics_truncated = \?.*error_code = 'c_checker_failed'`).
		WithArgs(
			uint32(1), uint32(0), uint32(1), uint32(1), false, true,
			"Parser stopped at an unsupported construct.", testTaskID, testRunID,
		).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`(?s)UPDATE analyzer_runs.*status = 'failed'.*error_code = 'c_checker_failed'`).
		WithArgs(
			"Parser stopped at an unsupported construct.", testTaskID, testRunID,
		).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectQuery(`(?s)SELECT 1.*FROM jobs job.*analysis[.]status = \?.*project[.]canonical_sha256 = analysis[.]source_sha256`).
		WithArgs(
			testJobID, testTaskID, lease.Owner, uint64(2), testRunID, "failed",
			testSHA, uint64(128),
		).
		WillReturnRows(sqlmock.NewRows([]string{"present"}).AddRow(1))
	expectSourceAnalysisReportInvalidation(mock, testTaskID)
	mock.ExpectCommit()

	if err := repository.PublishFailed(context.Background(), lease, result); err != nil {
		t.Fatal(err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestRepositoryFindingFunctionFilterUsesLiteralSubstring(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	repository, err := NewMySQLRepository(db, RepositoryConfig{})
	if err != nil {
		t.Fatal(err)
	}
	filter := "解析%_函数"
	mock.ExpectBegin()
	mock.ExpectQuery(`SELECT 1 FROM tasks WHERE id = \? AND deleted_at IS NULL`).
		WithArgs(testTaskID).
		WillReturnRows(sqlmock.NewRows([]string{"present"}).AddRow(1))
	mock.ExpectQuery(`(?s)SELECT 1.*FROM c_analysis_runs analysis.*project.deleted_at IS NULL.*WHERE analysis.task_id = \? AND analysis.id = \?.*analysis.deletion_started_at IS NULL`).
		WithArgs(testTaskID, testRunID).
		WillReturnRows(sqlmock.NewRows([]string{"present"}).AddRow(1))
	mock.ExpectQuery(`(?s)FROM c_analysis_findings.*LOCATE\(\?, function_name\) > 0.*ORDER BY id ASC LIMIT \?`).
		WithArgs(testTaskID, testRunID, uint64(0), filter, 51).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "cwe", "rule_id", "severity", "function_result_id",
			"function_address", "function_name", "start_line", "start_column",
			"end_line", "end_column", "message", "snippet", "created_at",
		}))
	mock.ExpectCommit()

	page, err := repository.ListFindings(context.Background(), FindingsQuery{
		TaskID: testTaskID, RunID: testRunID,
		PageSize: 50, Function: filter,
	})
	if err != nil || len(page.Items) != 0 {
		t.Fatalf("ListFindings() = %#v, %v", page, err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestRepositoryHidesRunsAndFindingsForTombstonedProject(t *testing.T) {
	t.Run("list", func(t *testing.T) {
		db, mock, err := sqlmock.New()
		if err != nil {
			t.Fatal(err)
		}
		defer db.Close()
		repository, err := NewMySQLRepository(db, RepositoryConfig{})
		if err != nil {
			t.Fatal(err)
		}
		mock.ExpectBegin()
		mock.ExpectQuery(`SELECT 1 FROM tasks WHERE id = \? AND deleted_at IS NULL`).
			WithArgs(testTaskID).
			WillReturnRows(sqlmock.NewRows([]string{"present"}).AddRow(1))
		mock.ExpectQuery(`(?s)FROM c_analysis_runs analysis.*analysis.deletion_started_at IS NULL.*project.deleted_at IS NULL.*WHERE analysis.task_id = \?.*ORDER BY analysis.created_at DESC.*LIMIT \?`).
			WithArgs(testTaskID, 51).
			WillReturnRows(sqlmock.NewRows(runColumns()))
		mock.ExpectCommit()
		page, err := repository.List(context.Background(), ListQuery{
			TaskID: testTaskID, PageSize: 50,
		})
		if err != nil || len(page.Items) != 0 {
			t.Fatalf("List() = %#v, %v", page, err)
		}
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("detail", func(t *testing.T) {
		db, mock, err := sqlmock.New()
		if err != nil {
			t.Fatal(err)
		}
		defer db.Close()
		repository, err := NewMySQLRepository(db, RepositoryConfig{})
		if err != nil {
			t.Fatal(err)
		}
		mock.ExpectBegin()
		mock.ExpectQuery(`SELECT 1 FROM tasks WHERE id = \? AND deleted_at IS NULL`).
			WithArgs(testTaskID).
			WillReturnRows(sqlmock.NewRows([]string{"present"}).AddRow(1))
		mock.ExpectQuery(`(?s)FROM c_analysis_runs analysis.*analysis.deletion_started_at IS NULL.*project.deleted_at IS NULL.*WHERE analysis.task_id = \? AND analysis.id = \?`).
			WithArgs(testTaskID, testRunID).
			WillReturnRows(sqlmock.NewRows(runColumns()))
		mock.ExpectRollback()
		_, err = repository.Get(context.Background(), RunQuery{
			TaskID: testTaskID, RunID: testRunID,
		})
		if !errors.Is(err, ErrRunNotFound) {
			t.Fatalf("Get() error = %v, want ErrRunNotFound", err)
		}
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("findings", func(t *testing.T) {
		db, mock, err := sqlmock.New()
		if err != nil {
			t.Fatal(err)
		}
		defer db.Close()
		repository, err := NewMySQLRepository(db, RepositoryConfig{})
		if err != nil {
			t.Fatal(err)
		}
		mock.ExpectBegin()
		mock.ExpectQuery(`SELECT 1 FROM tasks WHERE id = \? AND deleted_at IS NULL`).
			WithArgs(testTaskID).
			WillReturnRows(sqlmock.NewRows([]string{"present"}).AddRow(1))
		mock.ExpectQuery(`(?s)SELECT 1.*FROM c_analysis_runs analysis.*project.deleted_at IS NULL.*WHERE analysis.task_id = \? AND analysis.id = \?.*analysis.deletion_started_at IS NULL`).
			WithArgs(testTaskID, testRunID).
			WillReturnError(sql.ErrNoRows)
		mock.ExpectRollback()
		_, err = repository.ListFindings(context.Background(), FindingsQuery{
			TaskID: testTaskID, RunID: testRunID, PageSize: 50,
		})
		if !errors.Is(err, ErrRunNotFound) {
			t.Fatalf("ListFindings() error = %v, want ErrRunNotFound", err)
		}
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Fatal(err)
		}
	})
}

func validRepositoryCreateRecord() CreateRecord {
	return CreateRecord{
		RunID: testRunID, JobID: testJobID, TaskID: testTaskID,
		SourceProjectID: testProjectID, UserID: 7,
		RequestKey: "c_analysis:" +
			"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
	}
}

func expectSourceAnalysisReportInvalidation(
	mock sqlmock.Sqlmock,
	taskID string,
) {
	mock.ExpectExec(`(?s)UPDATE reports.*snapshot_state = 'stale'.*WHERE task_id = \?`).
		WithArgs(taskID).
		WillReturnResult(sqlmock.NewResult(0, 1))
}

func expectEligibleCProject(mock sqlmock.Sqlmock) {
	canonicalKey := "source-projects/" + testProjectID + "/src/decompiled.c"
	mock.ExpectQuery(`(?s)SELECT project.status, project.engine_name.*FROM decompile_source_projects project.*FOR UPDATE`).
		WithArgs(testTaskID, testProjectID).
		WillReturnRows(sqlmock.NewRows([]string{
			"status", "engine_name", "engine_version", "root_storage_key",
			"canonical_storage_key", "canonical_sha256", "canonical_size_bytes",
			"source_file_count", "symbol_count", "task_attempt_id", "file_node_id",
			"logical_path",
		}).AddRow(
			"complete", "ghidra", "12.1.2", "source-projects/"+testProjectID,
			canonicalKey, testSHA, uint64(128), uint64(1), uint64(1), uint64(9),
			uint64(17), "bin/sample",
		))
	mock.ExpectQuery(`(?s)SELECT result.id, result.symbol_key.*FROM decompile_results result.*ORDER BY`).
		WithArgs(testTaskID, testProjectID, canonicalKey).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "symbol_key", "display_name", "content_sha256",
			"source_offset_bytes", "source_length_bytes", "source_start_line",
			"source_end_line",
		}).AddRow(
			testResultID, "00401000", "main", testSHA, uint64(0), uint64(128),
			uint64(1), uint64(10),
		))
}

func runRows(createdAt time.Time) *sqlmock.Rows {
	return runRowsWithStatus(createdAt, "queued")
}

func runRowsWithStatus(createdAt time.Time, status string) *sqlmock.Rows {
	return sqlmock.NewRows(runColumns()).AddRow(
		testRunID, testTaskID, testProjectID, testJobID, status,
		AnalyzerName, AnalyzerVersion, testSHA, uint64(128), nil, uint32(1),
		uint32(0), uint32(0), uint32(0), uint32(0), uint32(0), uint32(0),
		uint32(0), uint32(0), false, false, nil, nil, nil, nil,
		createdAt, createdAt, "bin/sample", "complete", "ghidra", "12.1.2",
	)
}

func runColumns() []string {
	return []string{
		"id", "task_id", "source_project_id", "job_id", "status",
		"analyzer_name", "analyzer_version", "source_sha256",
		"source_size_bytes", "ruleset_version", "total_functions",
		"parsed_functions", "failed_functions", "finding_count",
		"diagnostic_count", "low_count", "medium_count", "high_count",
		"critical_count", "findings_truncated", "diagnostics_truncated",
		"error_code", "error_message", "started_at", "completed_at",
		"created_at", "updated_at", "logical_path", "project_status",
		"engine_name", "engine_version",
	}
}

package decompile

import (
	"context"
	"strings"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
)

func TestSourceProjectDeletionCollectsStaleTaskReportsWithoutAnalysisDependency(
	t *testing.T,
) {
	database, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	mock.ExpectBegin()
	mock.ExpectQuery(`(?s)SELECT layout_version, root_storage_key, storage_deleted_at.*FROM decompile_source_projects`).
		WithArgs(testTaskID, testSourceProjectID).
		WillReturnRows(sqlmock.NewRows([]string{
			"layout_version", "root_storage_key", "storage_deleted_at",
		}).AddRow(
			SourceProjectLayoutV1, sourceProjectRoot(testSourceProjectID), nil,
		))
	mock.ExpectQuery(`(?s)SELECT DISTINCT report[.]id.*WHERE report[.]task_id = \?\s+ORDER BY report[.]id`).
		WithArgs(testTaskID).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "format", "storage_key", "sha256", "size_bytes", "artifact_id",
		}).AddRow(
			"923e4567-e89b-42d3-a456-426614174009", "json",
			"reports/"+testTaskID+"/923e4567-e89b-42d3-a456-426614174009.json",
			strings.Repeat("a", 64), uint64(42), nil,
		))
	mock.ExpectQuery(`(?s)SELECT id, job_id.*FROM c_analysis_runs`).
		WithArgs(testTaskID, testSourceProjectID).
		WillReturnRows(sqlmock.NewRows([]string{"id", "job_id"}))
	mock.ExpectQuery(`(?s)SELECT id, job_id.*FROM java_analysis_runs`).
		WithArgs(testTaskID, testSourceProjectID).
		WillReturnRows(sqlmock.NewRows([]string{"id", "job_id"}))
	mock.ExpectRollback()

	tx, err := database.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	claim := SourceProjectDeletionClaim{
		TaskID: testTaskID, ProjectID: testSourceProjectID,
	}
	if err := NewMySQLRepository(database).collectSourceProjectDeletionOutputs(
		context.Background(), tx, &claim,
	); err != nil {
		t.Fatal(err)
	}
	if len(claim.ReportIDs) != 1 || len(claim.Files) != 1 ||
		claim.ReportIDs[0] != "923e4567-e89b-42d3-a456-426614174009" {
		t.Fatalf("collected deletion evidence = %#v", claim)
	}
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestListReadySourceProjectDeletionsPurgesExpiredAndUsedTokens(t *testing.T) {
	database, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	mock.ExpectExec(`(?s)DELETE FROM source_project_deletion_tokens.*expires_at.*used_at.*LIMIT 1000`).
		WillReturnResult(sqlmock.NewResult(0, 3))
	mock.ExpectQuery(`(?s)SELECT id.*FROM source_project_deletion_operations.*LIMIT \?`).
		WithArgs(10).
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(
			"a23e4567-e89b-42d3-a456-42661417400a",
		))

	values, err := NewMySQLRepository(database).
		ListReadySourceProjectDeletions(context.Background(), 10)
	if err != nil || len(values) != 1 {
		t.Fatalf("ListReadySourceProjectDeletions() = (%v, %v)", values, err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestCancelSourceProjectCAnalysisJobsKeepsPrecancelledRunActive(t *testing.T) {
	database, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	mock.ExpectBegin()
	for _, pool := range []string{"global", "trivy", "native"} {
		mock.ExpectExec(`(?s)UPDATE job_resource_slots slot.*job.status IN \('queued', 'leased'\)`).
			WithArgs(testTaskID, testSourceProjectID, pool).
			WillReturnResult(sqlmock.NewResult(0, 0))
	}
	mock.ExpectExec(`(?s)UPDATE jobs job.*job.status IN \('queued', 'leased'\)`).
		WithArgs(testTaskID, testSourceProjectID).
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec(`(?s)UPDATE c_analysis_runs run.*run.status = 'queued'.*job.status = 'cancelled'`).
		WithArgs(testTaskID, testSourceProjectID).
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec(`(?s)UPDATE jobs job.*job.status IN \('running', 'cancel_requested'\).*run.status IN \('running', 'cancel_requested'\)`).
		WithArgs(testTaskID, testSourceProjectID).
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(`(?s)SELECT EXISTS.*job.status IN \('queued', 'leased', 'running', 'cancel_requested'\).*OR.*run.status IN \('queued', 'running', 'cancel_requested'\)`).
		WithArgs(testTaskID, testSourceProjectID).
		WillReturnRows(sqlmock.NewRows([]string{"active"}).AddRow(1))
	mock.ExpectRollback()

	tx, err := database.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	active, err := cancelSourceProjectCAnalysisJobs(
		context.Background(), tx, testTaskID, testSourceProjectID,
	)
	if err != nil {
		t.Fatal(err)
	}
	if !active {
		t.Fatal("pre-cancelled C-analysis run was treated as terminal")
	}
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestCancelSourceProjectJavaAnalysisJobsKeepsPrecancelledRunActive(t *testing.T) {
	database, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	mock.ExpectBegin()
	for _, pool := range []string{"global", "trivy", "native"} {
		mock.ExpectExec(`(?s)UPDATE job_resource_slots slot.*JOIN java_analysis_runs run.*job.status IN \('queued', 'leased'\)`).
			WithArgs(testTaskID, testSourceProjectID, pool).
			WillReturnResult(sqlmock.NewResult(0, 0))
	}
	mock.ExpectExec(`(?s)UPDATE jobs job.*JOIN java_analysis_runs run.*job.status IN \('queued', 'leased'\)`).
		WithArgs(testTaskID, testSourceProjectID).
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec(`(?s)UPDATE java_analysis_runs run.*run.status = 'queued'.*job.status = 'cancelled'`).
		WithArgs(testTaskID, testSourceProjectID).
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec(`(?s)UPDATE jobs job.*JOIN java_analysis_runs run.*job.status IN \('running', 'cancel_requested'\).*run.status IN \('running', 'cancel_requested'\)`).
		WithArgs(testTaskID, testSourceProjectID).
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(`(?s)SELECT EXISTS.*FROM java_analysis_runs run.*job.status IN \('queued', 'leased', 'running', 'cancel_requested'\)`).
		WithArgs(testTaskID, testSourceProjectID).
		WillReturnRows(sqlmock.NewRows([]string{"active"}).AddRow(1))
	mock.ExpectRollback()

	tx, err := database.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	active, err := cancelSourceProjectJavaAnalysisJobs(
		context.Background(), tx, testTaskID, testSourceProjectID,
	)
	if err != nil {
		t.Fatal(err)
	}
	if !active {
		t.Fatal("pre-cancelled Java-analysis run was treated as terminal")
	}
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestSourceProjectDeletionPreviewCountsAllTaskReportEvidence(t *testing.T) {
	database, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	mock.ExpectBegin()
	mock.ExpectQuery(`(?s)SELECT.*COUNT\(DISTINCT artifact_id\).*FROM decompile_results`).
		WithArgs(
			testTaskID, testSourceProjectID,
			testTaskID, testSourceProjectID,
			testTaskID, testSourceProjectID,
			testTaskID, testSourceProjectID,
			testTaskID, testTaskID, testTaskID,
			testTaskID, testSourceProjectID,
		).
		WillReturnRows(sqlmock.NewRows([]string{
			"c_runs", "c_findings", "java_runs", "java_findings", "reports",
			"report_files", "artifacts", "results",
		}).AddRow(2, 3, 4, 5, 6, 6, 1, 7))
	mock.ExpectRollback()

	tx, err := database.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	counts, err := loadSourceProjectDeletionCounts(
		context.Background(), tx, testTaskID, testSourceProjectID, 1,
	)
	if err != nil {
		t.Fatal(err)
	}
	if counts.Artifacts != 1 || counts.SourceFiles != 1 ||
		counts.JavaAnalysisRuns != 4 || counts.JavaAnalysisFindings != 5 {
		t.Fatalf("deletion counts = %+v, want all task report evidence and source file", counts)
	}
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

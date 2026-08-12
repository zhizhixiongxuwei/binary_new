package report

import (
	"context"
	"errors"
	"regexp"
	"strings"
	"testing"
	"time"

	"binaryscan/internal/taskcleanup"

	"github.com/DATA-DOG/go-sqlmock"
)

const (
	testCAnalysisRunID   = "323e4567-e89b-42d3-a456-426614174002"
	testCAnalysisJobID   = "423e4567-e89b-42d3-a456-426614174003"
	testReportArtifactID = "523e4567-e89b-42d3-a456-426614174004"
)

type cascadeFileDeleterStub struct {
	files []taskcleanup.StoredFile
	err   error
}

func (s *cascadeFileDeleterStub) DeleteFile(
	_ context.Context,
	file taskcleanup.StoredFile,
) (bool, error) {
	s.files = append(s.files, file)
	return false, s.err
}

func (*cascadeFileDeleterStub) DeleteScope(
	context.Context,
	taskcleanup.Scope,
) error {
	return nil
}

func TestCAnalysisRunCascadeDeleteIncludesStaleTaskReports(t *testing.T) {
	database, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	fileDeleter := &cascadeFileDeleterStub{}
	deleter := &CAnalysisRunCascadeDeleter{db: database, deleter: fileDeleter}
	reportKey := "reports/" + testTaskID + "/" + testReportID + ".json"
	artifactKey := "artifacts/" + testTaskID + "/c-analysis/summary.json"

	mock.ExpectBegin()
	expectCascadeTaskAndTerminalRun(mock, "succeeded", "succeeded")
	mock.ExpectQuery(`(?s)SELECT report[.]id, report[.]format.*WHERE report[.]task_id = \?\s+ORDER BY report[.]id\s+FOR UPDATE`).
		WithArgs(testTaskID).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "format", "storage_key", "sha256", "size_bytes", "artifact_id",
		}).AddRow(
			testReportID, "json", reportKey, strings.Repeat("a", 64), uint64(12),
			testReportArtifactID,
		))
	mock.ExpectQuery(`(?s)SELECT artifact[.]storage_key.*FOR UPDATE`).
		WithArgs(testTaskID, testReportArtifactID).
		WillReturnRows(sqlmock.NewRows(
			[]string{"storage_key", "sha256", "size_bytes"},
		).AddRow(artifactKey, strings.Repeat("b", 64), uint64(24)))
	expectCascadeTombstone(mock, true)
	mock.ExpectCommit()

	mock.ExpectBegin()
	expectCascadeFinalizationLock(mock, "succeeded", "succeeded")
	mock.ExpectExec(regexp.QuoteMeta(
		"DELETE FROM reports WHERE task_id = ? AND id IN (?)",
	)).WithArgs(testTaskID, testReportID).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(regexp.QuoteMeta(
		"DELETE FROM artifacts WHERE task_id = ? AND id IN (?)",
	)).WithArgs(testTaskID, testReportArtifactID).
		WillReturnResult(sqlmock.NewResult(0, 1))
	expectCascadeTerminalRows(mock)
	mock.ExpectCommit()

	if err := deleter.Delete(
		context.Background(), testTaskID, testCAnalysisRunID,
	); err != nil {
		t.Fatalf("Delete() error = %v", err)
	}
	if len(fileDeleter.files) != 2 ||
		fileDeleter.files[0].StorageKey != reportKey ||
		fileDeleter.files[1].StorageKey != artifactKey {
		t.Fatalf("safely deleted files = %#v", fileDeleter.files)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestCAnalysisRunDeletionMaintenanceRecoversAfterPreparedProcessCrash(
	t *testing.T,
) {
	database, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	fileDeleter := &cascadeFileDeleterStub{}
	deleter := &CAnalysisRunCascadeDeleter{db: database, deleter: fileDeleter}
	reportKey := "reports/" + testTaskID + "/" + testReportID + ".json"

	mock.ExpectBegin()
	expectCascadeTaskAndTerminalRun(mock, "succeeded", "succeeded")
	mock.ExpectQuery(`(?s)SELECT report[.]id, report[.]format.*FOR UPDATE`).
		WithArgs(testTaskID).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "format", "storage_key", "sha256", "size_bytes", "artifact_id",
		}).AddRow(
			testReportID, "json", reportKey, strings.Repeat("e", 64), uint64(14), nil,
		))
	expectCascadeTombstone(mock, false)
	mock.ExpectCommit()
	plan, err := deleter.prepare(
		context.Background(), testTaskID, testCAnalysisRunID,
	)
	if err != nil || len(plan.files) != 1 || len(fileDeleter.files) != 0 {
		t.Fatalf(
			"prepared crash state = plan %#v, files %#v, error %v",
			plan, fileDeleter.files, err,
		)
	}

	mock.ExpectQuery(`(?s)SELECT run[.]task_id, run[.]id.*run[.]deletion_started_at IS NOT NULL.*active_project_id.*LIMIT \?`).
		WithArgs(10).
		WillReturnRows(sqlmock.NewRows([]string{"task_id", "run_id"}).
			AddRow(testTaskID, testCAnalysisRunID))
	mock.ExpectBegin()
	expectCascadeTaskAndTerminalRun(mock, "succeeded", "succeeded")
	mock.ExpectQuery(`(?s)SELECT report[.]id, report[.]format.*FOR UPDATE`).
		WithArgs(testTaskID).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "format", "storage_key", "sha256", "size_bytes", "artifact_id",
		}).AddRow(
			testReportID, "json", reportKey, strings.Repeat("e", 64), uint64(14), nil,
		))
	expectCascadeTombstone(mock, false)
	mock.ExpectCommit()
	mock.ExpectBegin()
	expectCascadeFinalizationLock(mock, "succeeded", "succeeded")
	mock.ExpectExec(regexp.QuoteMeta(
		"DELETE FROM reports WHERE task_id = ? AND id IN (?)",
	)).WithArgs(testTaskID, testReportID).
		WillReturnResult(sqlmock.NewResult(0, 1))
	expectCascadeTerminalRows(mock)
	mock.ExpectCommit()

	completed, err := deleter.RecoverPending(context.Background(), 10)
	if err != nil || completed != 1 || len(fileDeleter.files) != 1 ||
		fileDeleter.files[0].StorageKey != reportKey {
		t.Fatalf(
			"RecoverPending() = %d, %v; files %#v",
			completed, err, fileDeleter.files,
		)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestCAnalysisRunCascadeDeleteLeavesDurableRetryableTombstoneWhenFileCleanupFails(
	t *testing.T,
) {
	database, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	fileDeleter := &cascadeFileDeleterStub{err: errors.New("unsafe file")}
	deleter := &CAnalysisRunCascadeDeleter{db: database, deleter: fileDeleter}

	mock.ExpectBegin()
	expectCascadeTaskAndTerminalRun(mock, "partial", "succeeded")
	mock.ExpectQuery(`(?s)SELECT report[.]id, report[.]format.*FOR UPDATE`).
		WithArgs(testTaskID).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "format", "storage_key", "sha256", "size_bytes", "artifact_id",
		}).AddRow(
			testReportID, "html",
			"reports/"+testTaskID+"/"+testReportID+".html",
			strings.Repeat("c", 64), uint64(10), nil,
		))
	expectCascadeTombstone(mock, false)
	mock.ExpectCommit()

	err = deleter.Delete(context.Background(), testTaskID, testCAnalysisRunID)
	if err == nil || !strings.Contains(err.Error(), "unsafe file") {
		t.Fatalf("Delete() error = %v", err)
	}
	if len(fileDeleter.files) != 1 {
		t.Fatalf("file cleanup attempts = %#v", fileDeleter.files)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}

	fileDeleter.err = nil
	mock.ExpectBegin()
	expectCascadeTaskAndTerminalRun(mock, "partial", "succeeded")
	mock.ExpectQuery(`(?s)SELECT report[.]id, report[.]format.*FOR UPDATE`).
		WithArgs(testTaskID).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "format", "storage_key", "sha256", "size_bytes", "artifact_id",
		}).AddRow(
			testReportID, "html",
			"reports/"+testTaskID+"/"+testReportID+".html",
			strings.Repeat("c", 64), uint64(10), nil,
		))
	expectCascadeTombstone(mock, false)
	mock.ExpectCommit()
	mock.ExpectBegin()
	expectCascadeFinalizationLock(mock, "partial", "succeeded")
	mock.ExpectExec(regexp.QuoteMeta(
		"DELETE FROM reports WHERE task_id = ? AND id IN (?)",
	)).WithArgs(testTaskID, testReportID).
		WillReturnResult(sqlmock.NewResult(0, 1))
	expectCascadeTerminalRows(mock)
	mock.ExpectCommit()
	if err := deleter.Delete(
		context.Background(), testTaskID, testCAnalysisRunID,
	); err != nil {
		t.Fatalf("retry Delete() error = %v", err)
	}
	if len(fileDeleter.files) != 2 {
		t.Fatalf("retry file cleanup attempts = %#v", fileDeleter.files)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestCAnalysisRunCascadeDeleteDoesNotRemoveFilesWhenTombstoneCommitFails(
	t *testing.T,
) {
	database, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	fileDeleter := &cascadeFileDeleterStub{}
	deleter := &CAnalysisRunCascadeDeleter{db: database, deleter: fileDeleter}

	mock.ExpectBegin()
	expectCascadeTaskAndTerminalRun(mock, "failed", "failed")
	mock.ExpectQuery(`(?s)SELECT report[.]id, report[.]format.*FOR UPDATE`).
		WithArgs(testTaskID).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "format", "storage_key", "sha256", "size_bytes", "artifact_id",
		}).AddRow(
			testReportID, "json",
			"reports/"+testTaskID+"/"+testReportID+".json",
			strings.Repeat("d", 64), uint64(10), nil,
		))
	expectCascadeTombstone(mock, false)
	mock.ExpectCommit().WillReturnError(errors.New("commit failed"))

	err = deleter.Delete(context.Background(), testTaskID, testCAnalysisRunID)
	if err == nil || !strings.Contains(err.Error(), "commit failed") {
		t.Fatalf("Delete() error = %v", err)
	}
	if len(fileDeleter.files) != 0 {
		t.Fatalf("files removed before durable tombstone: %#v", fileDeleter.files)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestCAnalysisRunCascadeDeleteRejectsNonTerminalRunBeforeFileCleanup(t *testing.T) {
	database, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	fileDeleter := &cascadeFileDeleterStub{}
	deleter := &CAnalysisRunCascadeDeleter{db: database, deleter: fileDeleter}

	mock.ExpectBegin()
	expectCascadeTaskAndTerminalRun(mock, "cancel_requested", "cancel_requested")
	mock.ExpectRollback()

	err = deleter.Delete(context.Background(), testTaskID, testCAnalysisRunID)
	if !errors.Is(err, ErrCAnalysisRunNotTerminal) {
		t.Fatalf("Delete() error = %v, want non-terminal", err)
	}
	if len(fileDeleter.files) != 0 {
		t.Fatalf("non-terminal deletion touched files: %#v", fileDeleter.files)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func expectCascadeTaskAndTerminalRun(
	mock sqlmock.Sqlmock,
	runStatus string,
	jobStatus string,
) {
	mock.ExpectQuery(`(?s)SELECT 1.*FROM tasks.*FOR UPDATE`).
		WithArgs(testTaskID).
		WillReturnRows(sqlmock.NewRows([]string{"marker"}).AddRow(1))
	mock.ExpectQuery(`(?s)SELECT run[.]status, run[.]job_id, job[.]status.*FOR UPDATE`).
		WithArgs(testTaskID, testCAnalysisRunID).
		WillReturnRows(sqlmock.NewRows(
			[]string{"run_status", "job_id", "job_status"},
		).AddRow(runStatus, testCAnalysisJobID, jobStatus))
}

func expectCascadeTombstone(mock sqlmock.Sqlmock, withArtifact bool) {
	mock.ExpectExec(`(?s)UPDATE c_analysis_runs.*deletion_started_at = COALESCE.*status IN`).
		WithArgs(testTaskID, testCAnalysisRunID).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`(?s)UPDATE reports.*snapshot_state = 'stale'.*deleted_at = COALESCE.*WHERE task_id = \? AND id IN \(\?\)`).
		WithArgs(testTaskID, testReportID).
		WillReturnResult(sqlmock.NewResult(0, 1))
	if withArtifact {
		mock.ExpectExec(`(?s)UPDATE artifacts.*state = 'deleting'.*deleted_at = COALESCE.*WHERE task_id = \? AND id IN \(\?\)`).
			WithArgs(testTaskID, testReportArtifactID).
			WillReturnResult(sqlmock.NewResult(0, 1))
	}
}

func expectCascadeFinalizationLock(
	mock sqlmock.Sqlmock,
	runStatus string,
	jobStatus string,
) {
	mock.ExpectQuery(`(?s)SELECT 1.*FROM tasks.*FOR UPDATE`).
		WithArgs(testTaskID).
		WillReturnRows(sqlmock.NewRows([]string{"marker"}).AddRow(1))
	mock.ExpectQuery(`(?s)SELECT run[.]status, run[.]job_id, job[.]status, run[.]deletion_started_at.*FOR UPDATE`).
		WithArgs(testTaskID, testCAnalysisRunID).
		WillReturnRows(sqlmock.NewRows([]string{
			"run_status", "job_id", "job_status", "deletion_started_at",
		}).AddRow(runStatus, testCAnalysisJobID, jobStatus, time.Now().UTC()))
}

func expectCascadeTerminalRows(mock sqlmock.Sqlmock) {
	mock.ExpectExec(`(?s)DELETE FROM task_events.*event_type LIKE 'c_analysis[.]%'.*JSON_EXTRACT`).
		WithArgs(testTaskID, testCAnalysisRunID).
		WillReturnResult(sqlmock.NewResult(0, 2))
	mock.ExpectExec(`DELETE FROM c_analysis_findings`).
		WithArgs(testTaskID, testCAnalysisRunID).
		WillReturnResult(sqlmock.NewResult(0, 4))
	mock.ExpectExec(`(?s)DELETE FROM c_analysis_runs.*deletion_started_at IS NOT NULL.*status IN`).
		WithArgs(testTaskID, testCAnalysisRunID).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`DELETE FROM analyzer_runs`).
		WithArgs(testTaskID, testCAnalysisRunID).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`(?s)UPDATE job_resource_slots.*WHERE job_id = \?`).
		WithArgs(testCAnalysisJobID).
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec(`(?s)DELETE FROM jobs.*status IN`).
		WithArgs(testTaskID, testCAnalysisJobID).
		WillReturnResult(sqlmock.NewResult(0, 1))
}

var _ taskcleanup.FileDeleter = (*cascadeFileDeleterStub)(nil)

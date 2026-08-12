package report

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
)

var reportTestTime = time.Date(2026, 7, 30, 12, 0, 0, 0, time.UTC)

const reportTestOwner = "report-test-owner"

func newReportRepositoryMock(
	t *testing.T,
) (*MySQLRepository, sqlmock.Sqlmock, func()) {
	t.Helper()
	database, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	return NewMySQLRepository(database), mock, func() {
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Error(err)
		}
		database.Close()
	}
}

func TestRepositoryClaimCreatesGeneratingReportForTerminalTask(t *testing.T) {
	repository, mock, cleanup := newReportRepositoryMock(t)
	defer cleanup()
	mock.ExpectBegin()
	mock.ExpectQuery(`(?s)SELECT t[.]status,.*task_sample_retention_operations.*FROM tasks t.*WHERE t[.]id = \?.*FOR UPDATE`).
		WithArgs(testTaskID).
		WillReturnRows(sqlmock.NewRows(
			[]string{"status", "active_retention", "active_evidence_deletion"},
		).AddRow("SUCCEEDED", 0, 0))
	mock.ExpectQuery("SELECT id, task_id, format, schema_version, status").
		WithArgs(testTaskID, "json", SchemaVersion).
		WillReturnError(sql.ErrNoRows)
	mock.ExpectQuery(`(?s)SELECT EXISTS.*snapshot_state = 'staged'`).
		WithArgs(testTaskID, "json", SchemaVersion).
		WillReturnRows(sqlmock.NewRows([]string{"active"}).AddRow(0))
	mock.ExpectQuery(`SELECT COALESCE\(MAX\(generation\), 0\) \+ 1`).
		WithArgs(testTaskID, "json", SchemaVersion).
		WillReturnRows(sqlmock.NewRows([]string{"generation"}).AddRow(1))
	mock.ExpectExec(regexp.QuoteMeta(`
INSERT INTO reports (
    id, task_id, format, schema_version, status, snapshot_state, generation,
    generation_fence, generation_owner, generation_lease_until,
    generation_heartbeat_at, created_at
) VALUES (?, ?, ?, ?, 'generating', 'staged', ?, 1, ?,
          DATE_ADD(UTC_TIMESTAMP(6), INTERVAL ? MICROSECOND),
          UTC_TIMESTAMP(6), ?)`)).
		WithArgs(
			testReportID, testTaskID, "json", SchemaVersion,
			uint64(1),
			reportTestOwner, int64(time.Minute/time.Microsecond),
			reportTestTime,
		).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

	value, generate, err := repository.Claim(context.Background(), Claim{
		TaskID: testTaskID, ReportID: testReportID, Format: FormatJSON,
		SchemaVersion: SchemaVersion, CreatedAt: reportTestTime,
		LeaseOwner: reportTestOwner, LeaseDuration: time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !generate || value.ID != testReportID ||
		value.Status != "generating" || value.SnapshotState != "staged" ||
		value.Generation != 1 {
		t.Fatalf("claimed report = %#v, generate=%v", value, generate)
	}
}

func TestRepositoryListIsCurrentSchemaTaskScopedAndExcludesDeleted(t *testing.T) {
	repository, mock, cleanup := newReportRepositoryMock(t)
	defer cleanup()
	mock.ExpectQuery("(?s)SELECT CASE.*sample_deleted_at.*sample_expires_at.*FROM tasks").
		WithArgs(testTaskID).
		WillReturnRows(sqlmock.NewRows([]string{"sample_relation"}).AddRow("expired"))
	mock.ExpectQuery(
		`(?s)WHERE task_id = \? AND schema_version = \? AND deleted_at IS NULL.*`+
			`snapshot_state = 'current'.*snapshot_state = 'staged'`,
	).WithArgs(testTaskID, SchemaVersion).WillReturnRows(
		sqlmock.NewRows([]string{
			"id", "task_id", "format", "schema_version", "status",
			"snapshot_state", "generation",
			"sha256", "size_bytes", "error_code", "error_message",
			"created_at", "completed_at",
		}),
	)

	value, err := repository.List(context.Background(), testTaskID)
	if err != nil {
		t.Fatal(err)
	}
	if value.Items == nil || len(value.Items) != 0 ||
		value.SampleRelation != "expired" {
		t.Fatalf("report list = %#v", value)
	}
}

func TestRepositoryInvalidationReplacementVisibility(t *testing.T) {
	repository, mock, cleanup := newReportRepositoryMock(t)
	defer cleanup()
	ctx := context.Background()
	replacementID := "323e4567-e89b-42d3-a456-426614174002"
	completedAt := reportTestTime.Add(time.Minute)
	digest := strings.Repeat("a", 64)
	artifact := ArtifactMetadata{
		StorageKey:  "reports/" + testTaskID + "/" + replacementID + ".json",
		SHA256:      digest,
		SizeBytes:   42,
		CompletedAt: completedAt,
	}

	// MySQL evaluates UPDATE assignments from left to right. The fencing fields
	// must therefore observe the original generating status before status/state
	// are transitioned at the end of the SET list.
	mock.ExpectExec(`(?s)UPDATE reports.*SET generation_fence = CASE.*` +
		`generation_owner = CASE.*completed_at = CASE.*` +
		`status = CASE.*snapshot_state = 'stale'.*WHERE task_id = \?`).
		WithArgs(testTaskID).
		WillReturnResult(sqlmock.NewResult(0, 2))
	if err := InvalidateTaskCAnalysisReports(ctx, repository.db, testTaskID); err != nil {
		t.Fatalf("InvalidateTaskCAnalysisReports() error = %v", err)
	}

	expectReportTaskRelation(mock, "retained")
	mock.ExpectQuery(`(?s)WHERE task_id = \? AND schema_version = \?.*`+
		`snapshot_state = 'current'.*snapshot_state = 'staged'`).
		WithArgs(testTaskID, SchemaVersion).
		WillReturnRows(emptyReportRows())
	listed, err := repository.List(ctx, testTaskID)
	if err != nil || len(listed.Items) != 0 {
		t.Fatalf("List() after invalidation = (%#v, %v), want empty", listed, err)
	}

	mock.ExpectBegin()
	mock.ExpectQuery(`(?s)SELECT t[.]status,.*FROM tasks t.*FOR UPDATE`).
		WithArgs(testTaskID).
		WillReturnRows(sqlmock.NewRows(
			[]string{"status", "active_retention", "active_evidence_deletion"},
		).AddRow("SUCCEEDED", 0, 0))
	mock.ExpectQuery("SELECT id, task_id, format, schema_version, status").
		WithArgs(testTaskID, "json", SchemaVersion).
		WillReturnError(sql.ErrNoRows)
	mock.ExpectQuery(`(?s)SELECT EXISTS.*snapshot_state = 'staged'`).
		WithArgs(testTaskID, "json", SchemaVersion).
		WillReturnRows(sqlmock.NewRows([]string{"active"}).AddRow(0))
	mock.ExpectQuery(`SELECT COALESCE\(MAX\(generation\), 0\) \+ 1`).
		WithArgs(testTaskID, "json", SchemaVersion).
		WillReturnRows(sqlmock.NewRows([]string{"generation"}).AddRow(2))
	mock.ExpectExec(`(?s)INSERT INTO reports.*snapshot_state, generation`).
		WithArgs(
			replacementID, testTaskID, "json", SchemaVersion, uint64(2),
			reportTestOwner, int64(time.Minute/time.Microsecond), reportTestTime,
		).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()
	claimed, generate, err := repository.Claim(ctx, Claim{
		TaskID: testTaskID, ReportID: replacementID, Format: FormatJSON,
		SchemaVersion: SchemaVersion, CreatedAt: reportTestTime,
		LeaseOwner: reportTestOwner, LeaseDuration: time.Minute,
	})
	if err != nil || !generate || claimed.Generation != 2 {
		t.Fatalf("Claim() replacement = (%#v, %v, %v)", claimed, generate, err)
	}

	mock.ExpectBegin()
	mock.ExpectQuery(`(?s)SELECT status.*FROM tasks.*FOR UPDATE`).
		WithArgs(testTaskID).
		WillReturnRows(sqlmock.NewRows([]string{"status"}).AddRow("SUCCEEDED"))
	mock.ExpectQuery(`(?s)SELECT format, schema_version, generation, status, snapshot_state.*FOR UPDATE`).
		WithArgs(testTaskID, replacementID, reportTestOwner, uint64(1)).
		WillReturnRows(sqlmock.NewRows([]string{
			"format", "schema_version", "generation", "status", "snapshot_state",
		}).AddRow("json", SchemaVersion, uint64(2), "generating", "staged"))
	mock.ExpectExec(`(?s)UPDATE reports.*snapshot_state = 'stale'`).
		WithArgs(testTaskID, "json", SchemaVersion).
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec(`(?s)UPDATE reports.*status = 'complete'.*snapshot_state = 'current'`).
		WithArgs(
			artifact.StorageKey, artifact.SHA256, artifact.SizeBytes,
			artifact.CompletedAt, testTaskID, replacementID,
			reportTestOwner, uint64(1),
		).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectQuery("SELECT id, task_id, format, schema_version, status").
		WithArgs(testTaskID, replacementID).
		WillReturnRows(emptyReportRows().AddRow(
			replacementID, testTaskID, "json", SchemaVersion, "complete",
			"current", uint64(2), digest, uint64(42), nil, nil,
			reportTestTime, completedAt,
		))
	mock.ExpectCommit()
	completed, err := repository.Complete(
		ctx, testTaskID, replacementID, reportTestOwner, 1, artifact,
	)
	if err != nil || completed.SnapshotState != "current" {
		t.Fatalf("Complete() replacement = (%#v, %v)", completed, err)
	}

	expectReportTaskRelation(mock, "retained")
	mock.ExpectQuery(`(?s)WHERE task_id = \? AND schema_version = \?.*`+
		`snapshot_state = 'current'.*snapshot_state = 'staged'`).
		WithArgs(testTaskID, SchemaVersion).
		WillReturnRows(emptyReportRows().AddRow(
			replacementID, testTaskID, "json", SchemaVersion, "complete",
			"current", uint64(2), digest, uint64(42), nil, nil,
			reportTestTime, completedAt,
		))
	listed, err = repository.List(ctx, testTaskID)
	if err != nil || len(listed.Items) != 1 || listed.Items[0].ID != replacementID {
		t.Fatalf("List() replacement = (%#v, %v)", listed, err)
	}

	mock.ExpectQuery(`(?s)SELECT report[.]id.*report[.]status = 'complete'.*`+
		`report[.]snapshot_state = 'current'`).
		WithArgs(testTaskID, testReportID).
		WillReturnError(sql.ErrNoRows)
	_, err = repository.Download(ctx, testTaskID, testReportID)
	if !errors.Is(err, ErrReportNotFound) {
		t.Fatalf("Download() stale report error = %v, want not found", err)
	}
}

func expectReportTaskRelation(mock sqlmock.Sqlmock, relation string) {
	mock.ExpectQuery("(?s)SELECT CASE.*sample_deleted_at.*sample_expires_at.*FROM tasks").
		WithArgs(testTaskID).
		WillReturnRows(sqlmock.NewRows([]string{"sample_relation"}).AddRow(relation))
}

func emptyReportRows() *sqlmock.Rows {
	return sqlmock.NewRows([]string{
		"id", "task_id", "format", "schema_version", "status",
		"snapshot_state", "generation", "sha256", "size_bytes",
		"error_code", "error_message", "created_at", "completed_at",
	})
}

func TestRepositoryClaimRejectsActiveTask(t *testing.T) {
	repository, mock, cleanup := newReportRepositoryMock(t)
	defer cleanup()
	mock.ExpectBegin()
	mock.ExpectQuery(`(?s)SELECT t[.]status,.*task_sample_retention_operations.*FROM tasks t`).
		WithArgs(testTaskID).
		WillReturnRows(sqlmock.NewRows(
			[]string{"status", "active_retention", "active_evidence_deletion"},
		).AddRow("SCANNING", 0, 0))
	mock.ExpectRollback()

	_, _, err := repository.Claim(context.Background(), Claim{
		TaskID: testTaskID, ReportID: testReportID, Format: FormatJSON,
		SchemaVersion: SchemaVersion, CreatedAt: reportTestTime,
		LeaseOwner: reportTestOwner, LeaseDuration: time.Minute,
	})
	if !errors.Is(err, ErrTaskNotTerminal) {
		t.Fatalf("claim error = %v", err)
	}
}

func TestRepositoryClaimConflictsWithActiveSampleRetention(t *testing.T) {
	repository, mock, cleanup := newReportRepositoryMock(t)
	defer cleanup()
	mock.ExpectBegin()
	mock.ExpectQuery(`(?s)SELECT t[.]status,.*task_sample_retention_operations.*FROM tasks t`).
		WithArgs(testTaskID).
		WillReturnRows(sqlmock.NewRows(
			[]string{"status", "active_retention", "active_evidence_deletion"},
		).AddRow("SUCCEEDED", 1, 0))
	mock.ExpectRollback()

	_, _, err := repository.Claim(context.Background(), Claim{
		TaskID: testTaskID, ReportID: testReportID, Format: FormatJSON,
		SchemaVersion: SchemaVersion, CreatedAt: reportTestTime,
		LeaseOwner: reportTestOwner, LeaseDuration: time.Minute,
	})
	if !errors.Is(err, ErrGenerationInProgress) {
		t.Fatalf("Claim() error = %v, want generation conflict", err)
	}
}

func TestRepositoryClaimConflictsWithEvidenceDeletionFence(t *testing.T) {
	repository, mock, cleanup := newReportRepositoryMock(t)
	defer cleanup()
	mock.ExpectBegin()
	mock.ExpectQuery(`(?s)SELECT t[.]status,.*source_project_deletion_operations.*c_analysis_runs.*java_analysis_runs.*FROM tasks t`).
		WithArgs(testTaskID).
		WillReturnRows(sqlmock.NewRows(
			[]string{"status", "active_retention", "active_evidence_deletion"},
		).AddRow("SUCCEEDED", 0, 1))
	mock.ExpectRollback()

	_, _, err := repository.Claim(context.Background(), Claim{
		TaskID: testTaskID, ReportID: testReportID, Format: FormatJSON,
		SchemaVersion: SchemaVersion, CreatedAt: reportTestTime,
		LeaseOwner: reportTestOwner, LeaseDuration: time.Minute,
	})
	if !errors.Is(err, ErrGenerationInProgress) {
		t.Fatalf("Claim() error = %v, want evidence deletion conflict", err)
	}
}

func TestRepositoryClaimReplaysCurrentComplete(t *testing.T) {
	repository, mock, cleanup := newReportRepositoryMock(t)
	defer cleanup()
	mock.ExpectBegin()
	mock.ExpectQuery(`(?s)SELECT t[.]status,.*task_sample_retention_operations.*FROM tasks t`).
		WithArgs(testTaskID).
		WillReturnRows(sqlmock.NewRows(
			[]string{"status", "active_retention", "active_evidence_deletion"},
		).AddRow("CANCELLED", 0, 0))
	rows := sqlmock.NewRows([]string{
		"id", "task_id", "format", "schema_version", "status",
		"snapshot_state", "generation", "sha256", "size_bytes",
		"error_code", "error_message", "created_at", "completed_at",
	}).AddRow(
		testReportID, testTaskID, "json", SchemaVersion, "complete",
		"current", uint64(1), nil, nil, nil, nil, reportTestTime, reportTestTime,
	)
	mock.ExpectQuery(
		"SELECT id, task_id, format, schema_version, status",
	).WithArgs(testTaskID, "json", SchemaVersion).WillReturnRows(rows)
	mock.ExpectCommit()

	value, generate, err := repository.Claim(context.Background(), Claim{
		TaskID: testTaskID, ReportID: testReportID,
		Format: FormatJSON, SchemaVersion: SchemaVersion,
		CreatedAt: reportTestTime, LeaseOwner: reportTestOwner,
		LeaseDuration: time.Minute,
	})
	if err != nil || generate || value.Status != "complete" ||
		value.SnapshotState != "current" {
		t.Fatalf("replayed report = %#v, generate=%v, error=%v", value, generate, err)
	}
}

func TestRepositoryClaimCreatesReplacementAfterFailedReport(t *testing.T) {
	repository, mock, cleanup := newReportRepositoryMock(t)
	defer cleanup()
	mock.ExpectBegin()
	mock.ExpectQuery(`(?s)SELECT t[.]status,.*task_sample_retention_operations.*FROM tasks t`).
		WithArgs(testTaskID).
		WillReturnRows(sqlmock.NewRows(
			[]string{"status", "active_retention", "active_evidence_deletion"},
		).AddRow("FAILED", 0, 0))
	mock.ExpectQuery(
		"SELECT id, task_id, format, schema_version, status",
	).WithArgs(testTaskID, "html", SchemaVersion).WillReturnError(sql.ErrNoRows)
	mock.ExpectQuery(`(?s)SELECT EXISTS.*snapshot_state = 'staged'`).
		WithArgs(testTaskID, "html", SchemaVersion).
		WillReturnRows(sqlmock.NewRows([]string{"active"}).AddRow(0))
	mock.ExpectQuery(`SELECT COALESCE\(MAX\(generation\), 0\) \+ 1`).
		WithArgs(testTaskID, "html", SchemaVersion).
		WillReturnRows(sqlmock.NewRows([]string{"generation"}).AddRow(2))
	mock.ExpectExec(`(?s)INSERT INTO reports.*snapshot_state, generation`).
		WithArgs(
			"323e4567-e89b-42d3-a456-426614174002", testTaskID, "html",
			SchemaVersion, uint64(2), reportTestOwner,
			int64(time.Minute/time.Microsecond), reportTestTime.Add(time.Hour),
		).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

	value, generate, err := repository.Claim(context.Background(), Claim{
		TaskID: testTaskID, ReportID: "323e4567-e89b-42d3-a456-426614174002",
		Format: FormatHTML, SchemaVersion: SchemaVersion,
		CreatedAt:  reportTestTime.Add(time.Hour),
		LeaseOwner: reportTestOwner, LeaseDuration: time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !generate || value.ID != "323e4567-e89b-42d3-a456-426614174002" ||
		value.Status != "generating" || value.Generation != 2 {
		t.Fatalf("replacement report = %#v, generate=%v", value, generate)
	}
}

func TestRepositoryAuthorizePublishRejectsDeletingTask(t *testing.T) {
	repository, mock, cleanup := newReportRepositoryMock(t)
	defer cleanup()
	mock.ExpectQuery(`(?s)SELECT task[.]status, report[.]status.*JOIN reports.*task[.]deleted_at IS NULL.*report[.]deleted_at IS NULL`).
		WithArgs(testTaskID, testReportID, reportTestOwner, uint64(1)).
		WillReturnRows(sqlmock.NewRows(
			[]string{"task_status", "report_status", "snapshot_state"},
		).AddRow("DELETING", "generating", "staged"))

	err := repository.AuthorizePublish(
		context.Background(),
		testTaskID,
		testReportID,
		reportTestOwner,
		1,
	)
	if !errors.Is(err, ErrTaskNotTerminal) {
		t.Fatalf("AuthorizePublish() error = %v", err)
	}
}

func TestRepositoryCompleteSerializesWithTaskDeletion(t *testing.T) {
	artifact := ArtifactMetadata{
		StorageKey:  "reports/" + testTaskID + "/" + testReportID + ".json",
		SHA256:      strings.Repeat("a", 64),
		SizeBytes:   42,
		CompletedAt: reportTestTime.Add(time.Minute),
	}
	t.Run("terminal task", func(t *testing.T) {
		repository, mock, cleanup := newReportRepositoryMock(t)
		defer cleanup()
		mock.ExpectBegin()
		mock.ExpectQuery(`(?s)SELECT status.*FROM tasks.*deleted_at IS NULL.*FOR UPDATE`).
			WithArgs(testTaskID).
			WillReturnRows(
				sqlmock.NewRows([]string{"status"}).AddRow("SUCCEEDED"),
			)
		mock.ExpectQuery(`(?s)SELECT format, schema_version, generation, status, snapshot_state.*FROM reports.*FOR UPDATE`).
			WithArgs(testTaskID, testReportID, reportTestOwner, uint64(1)).
			WillReturnRows(sqlmock.NewRows([]string{
				"format", "schema_version", "generation", "status", "snapshot_state",
			}).AddRow("json", SchemaVersion, uint64(2), "generating", "staged"))
		mock.ExpectExec(`(?s)UPDATE reports.*snapshot_state = 'stale'.*snapshot_state = 'current'`).
			WithArgs(testTaskID, "json", SchemaVersion).
			WillReturnResult(sqlmock.NewResult(0, 1))
		mock.ExpectExec(`(?s)UPDATE reports.*status = 'complete'.*status = 'generating'`).
			WithArgs(
				artifact.StorageKey,
				artifact.SHA256,
				artifact.SizeBytes,
				artifact.CompletedAt,
				testTaskID,
				testReportID,
				reportTestOwner,
				uint64(1),
			).
			WillReturnResult(sqlmock.NewResult(0, 1))
		mock.ExpectQuery(
			"SELECT id, task_id, format, schema_version, status",
		).WithArgs(testTaskID, testReportID).WillReturnRows(
			sqlmock.NewRows([]string{
				"id", "task_id", "format", "schema_version", "status",
				"snapshot_state", "generation",
				"sha256", "size_bytes", "error_code", "error_message",
				"created_at", "completed_at",
			}).AddRow(
				testReportID,
				testTaskID,
				"json",
				SchemaVersion,
				"complete",
				"current",
				uint64(2),
				artifact.SHA256,
				artifact.SizeBytes,
				nil,
				nil,
				reportTestTime,
				artifact.CompletedAt,
			),
		)
		mock.ExpectCommit()

		value, err := repository.Complete(
			context.Background(),
			testTaskID,
			testReportID,
			reportTestOwner,
			1,
			artifact,
		)
		if err != nil || value.Status != "complete" {
			t.Fatalf("Complete() = (%+v, %v)", value, err)
		}
	})

	t.Run("deleting task", func(t *testing.T) {
		repository, mock, cleanup := newReportRepositoryMock(t)
		defer cleanup()
		mock.ExpectBegin()
		mock.ExpectQuery(`(?s)SELECT status.*FROM tasks.*FOR UPDATE`).
			WithArgs(testTaskID).
			WillReturnRows(
				sqlmock.NewRows([]string{"status"}).AddRow("DELETING"),
			)
		mock.ExpectRollback()

		_, err := repository.Complete(
			context.Background(),
			testTaskID,
			testReportID,
			reportTestOwner,
			1,
			artifact,
		)
		if !errors.Is(err, ErrTaskNotTerminal) {
			t.Fatalf("Complete() error = %v", err)
		}
	})
}

func TestInsertJavaAnalysisDependenciesFencesImmutableIdentity(t *testing.T) {
	database, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	completedAt := reportTestTime.Add(time.Minute)
	manifestDigest := strings.Repeat("a", 64)
	inputDigest := strings.Repeat("b", 64)
	projectID := "923e4567-e89b-42d3-a456-426614174009"

	mock.ExpectBegin()
	mock.ExpectExec(`(?s)INSERT INTO report_java_analysis_runs.*FROM java_analysis_runs run.*run[.]source_manifest_sha256 = \?.*run[.]input_sha256 = \?`).
		WithArgs(
			testReportID, uint64(3), testTaskID, testJavaAnalysisRunID,
			projectID, completedAt, manifestDigest, inputDigest,
		).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectRollback()
	tx, err := database.Begin()
	if err != nil {
		t.Fatal(err)
	}
	err = insertJavaAnalysisDependencies(
		context.Background(), tx, testTaskID, testReportID, 3,
		[]JavaAnalysisDependency{{
			RunID: testJavaAnalysisRunID, ProjectID: projectID,
			CompletedAt: completedAt, SourceManifestSHA256: manifestDigest,
			InputSHA256: inputDigest,
		}},
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestRepositoryFailReleasesGeneratingReportDeletionBarrier(t *testing.T) {
	repository, mock, cleanup := newReportRepositoryMock(t)
	defer cleanup()
	completedAt := reportTestTime.Add(time.Minute)

	mock.ExpectExec(
		`(?s)UPDATE reports.*status = 'failed'.*WHERE task_id = \? AND id = \? AND status = 'generating'`,
	).WithArgs(
		"task_deleted",
		"Report generation stopped because the task was deleted.",
		completedAt,
		testTaskID,
		testReportID,
		reportTestOwner,
		uint64(1),
	).WillReturnResult(sqlmock.NewResult(0, 1))

	err := repository.Fail(
		context.Background(),
		testTaskID,
		testReportID,
		reportTestOwner,
		1,
		"task_deleted",
		"Report generation stopped because the task was deleted.",
		completedAt,
	)
	if err != nil {
		t.Fatalf("Fail() error = %v", err)
	}
}

func TestReportResponseNeverSerializesStorageKey(t *testing.T) {
	digest := strings.Repeat("a", 64)
	size := uint64(12)
	value := Report{
		ID: testReportID, TaskID: testTaskID, Format: FormatJSON,
		SchemaVersion: SchemaVersion, Status: "complete", SHA256: &digest,
		SizeBytes: &size, CreatedAt: reportTestTime,
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(strings.ToLower(string(encoded)), "storage") {
		t.Fatalf("report response leaks storage metadata: %s", encoded)
	}
	for _, field := range []string{
		`"sha256"`, `"size_bytes"`, `"error_code":null`,
		`"error_message":null`, `"completed_at":null`,
	} {
		if !strings.Contains(string(encoded), field) {
			t.Errorf("report response omits %s: %s", field, encoded)
		}
	}
}

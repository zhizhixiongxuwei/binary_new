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
			[]string{"status", "active_retention"},
		).AddRow("SUCCEEDED", 0))
	mock.ExpectQuery("SELECT id, task_id, format, schema_version, status").
		WithArgs(testTaskID, "json", SchemaVersion).
		WillReturnError(sql.ErrNoRows)
	mock.ExpectExec(regexp.QuoteMeta(`
INSERT INTO reports (
    id, task_id, format, schema_version, status,
    generation_fence, generation_owner, generation_lease_until,
    generation_heartbeat_at, created_at
) VALUES (?, ?, ?, ?, 'generating', 1, ?,
          DATE_ADD(UTC_TIMESTAMP(6), INTERVAL ? MICROSECOND),
          UTC_TIMESTAMP(6), ?)`)).
		WithArgs(
			testReportID, testTaskID, "json", SchemaVersion,
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
		value.Status != "generating" {
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
		"WHERE task_id = \\? AND schema_version = \\? AND deleted_at IS NULL",
	).WithArgs(testTaskID, SchemaVersion).WillReturnRows(
		sqlmock.NewRows([]string{
			"id", "task_id", "format", "schema_version", "status",
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

func TestRepositoryClaimRejectsActiveTask(t *testing.T) {
	repository, mock, cleanup := newReportRepositoryMock(t)
	defer cleanup()
	mock.ExpectBegin()
	mock.ExpectQuery(`(?s)SELECT t[.]status,.*task_sample_retention_operations.*FROM tasks t`).
		WithArgs(testTaskID).
		WillReturnRows(sqlmock.NewRows(
			[]string{"status", "active_retention"},
		).AddRow("SCANNING", 0))
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
			[]string{"status", "active_retention"},
		).AddRow("SUCCEEDED", 1))
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

func TestRepositoryClaimReplaysCompleteAndConflictsGenerating(t *testing.T) {
	for _, test := range []struct {
		status       string
		wantGenerate bool
		wantErr      error
	}{
		{status: "complete", wantGenerate: false},
		{status: "generating", wantErr: ErrGenerationInProgress},
	} {
		t.Run(test.status, func(t *testing.T) {
			repository, mock, cleanup := newReportRepositoryMock(t)
			defer cleanup()
			mock.ExpectBegin()
			mock.ExpectQuery(`(?s)SELECT t[.]status,.*task_sample_retention_operations.*FROM tasks t`).
				WithArgs(testTaskID).
				WillReturnRows(
					sqlmock.NewRows(
						[]string{"status", "active_retention"},
					).AddRow("CANCELLED", 0),
				)
			rows := sqlmock.NewRows([]string{
				"id", "task_id", "format", "schema_version", "status",
				"sha256", "size_bytes", "error_code", "error_message",
				"created_at", "completed_at",
			}).AddRow(
				testReportID, testTaskID, "json", SchemaVersion, test.status,
				nil, nil, nil, nil, reportTestTime, nil,
			)
			mock.ExpectQuery(
				"SELECT id, task_id, format, schema_version, status",
			).WithArgs(testTaskID, "json", SchemaVersion).WillReturnRows(rows)
			if test.wantErr == nil {
				mock.ExpectCommit()
			} else {
				mock.ExpectRollback()
			}

			value, generate, err := repository.Claim(
				context.Background(),
				Claim{
					TaskID: testTaskID, ReportID: testReportID,
					Format: FormatJSON, SchemaVersion: SchemaVersion,
					CreatedAt:  reportTestTime,
					LeaseOwner: reportTestOwner, LeaseDuration: time.Minute,
				},
			)
			if !errors.Is(err, test.wantErr) {
				t.Fatalf("claim error = %v, want %v", err, test.wantErr)
			}
			if generate != test.wantGenerate {
				t.Fatalf("generate = %v", generate)
			}
			if test.wantErr == nil && value.Status != "complete" {
				t.Fatalf("replayed report = %#v", value)
			}
		})
	}
}

func TestRepositoryClaimRestartsFailedReport(t *testing.T) {
	repository, mock, cleanup := newReportRepositoryMock(t)
	defer cleanup()
	mock.ExpectBegin()
	mock.ExpectQuery(`(?s)SELECT t[.]status,.*task_sample_retention_operations.*FROM tasks t`).
		WithArgs(testTaskID).
		WillReturnRows(sqlmock.NewRows(
			[]string{"status", "active_retention"},
		).AddRow("FAILED", 0))
	mock.ExpectQuery(
		"SELECT id, task_id, format, schema_version, status",
	).WithArgs(testTaskID, "html", SchemaVersion).WillReturnRows(
		sqlmock.NewRows([]string{
			"id", "task_id", "format", "schema_version", "status",
			"sha256", "size_bytes", "error_code", "error_message",
			"created_at", "completed_at",
		}).AddRow(
			testReportID, testTaskID, "html", SchemaVersion, "failed",
			nil, nil, "failed", "old", reportTestTime, reportTestTime,
		),
	)
	mock.ExpectExec("UPDATE reports").
		WithArgs(
			reportTestOwner, int64(time.Minute/time.Microsecond),
			testTaskID, testReportID,
		).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectQuery("SELECT generation_fence").
		WithArgs(testTaskID, testReportID).
		WillReturnRows(
			sqlmock.NewRows([]string{"generation_fence"}).AddRow(2),
		)
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
	if !generate || value.ID != testReportID ||
		value.Status != "generating" || value.ErrorCode != nil {
		t.Fatalf("restarted report = %#v, generate=%v", value, generate)
	}
}

func TestRepositoryAuthorizePublishRejectsDeletingTask(t *testing.T) {
	repository, mock, cleanup := newReportRepositoryMock(t)
	defer cleanup()
	mock.ExpectQuery(`(?s)SELECT task[.]status, report[.]status.*JOIN reports.*task[.]deleted_at IS NULL.*report[.]deleted_at IS NULL`).
		WithArgs(testTaskID, testReportID, reportTestOwner, uint64(1)).
		WillReturnRows(sqlmock.NewRows(
			[]string{"task_status", "report_status"},
		).AddRow("DELETING", "generating"))

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
				"sha256", "size_bytes", "error_code", "error_message",
				"created_at", "completed_at",
			}).AddRow(
				testReportID,
				testTaskID,
				"json",
				SchemaVersion,
				"complete",
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

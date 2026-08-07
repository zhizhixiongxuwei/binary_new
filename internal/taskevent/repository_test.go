package taskevent

import (
	"context"
	"database/sql"
	"errors"
	"regexp"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
)

func TestMySQLRepositoryListsEventsInResumeOrder(t *testing.T) {
	database, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()

	mock.ExpectBegin()
	mock.ExpectQuery(regexp.QuoteMeta(`
SELECT 1
FROM tasks
WHERE id = ?
LIMIT 1`)).
		WithArgs(testTaskID).
		WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(1))
	createdAt := time.Date(2026, 7, 30, 1, 2, 3, 0, time.UTC)
	mock.ExpectQuery(regexp.QuoteMeta(`
SELECT event_sequence, event_type, stage, progress_basis_points,
       severity, message, payload, created_at
FROM task_events
WHERE task_id = ? AND event_sequence > ?
ORDER BY event_sequence ASC
LIMIT ?`)).
		WithArgs(testTaskID, uint64(7), 2).
		WillReturnRows(sqlmock.NewRows([]string{
			"event_sequence", "event_type", "stage",
			"progress_basis_points", "severity", "message", "payload",
			"created_at",
		}).
			AddRow(
				uint64(8), "task.status_changed", "SCANNING", 7000,
				"info", "Task status changed.", []byte(`{"status":"SCANNING"}`),
				createdAt,
			).
			AddRow(
				uint64(9), "task.progress", nil, nil,
				"debug", nil, nil, createdAt.Add(time.Second),
			))
	mock.ExpectCommit()

	repository := NewMySQLRepository(database)
	events, err := repository.List(context.Background(), Query{
		TaskID: testTaskID, AfterSequence: 7, Limit: 2,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 2 || events[0].Sequence != 8 ||
		events[0].Progress == nil || *events[0].Progress != 70 ||
		!events[0].ProgressIndeterminate ||
		events[0].Stage == nil || *events[0].Stage != "SCANNING" ||
		events[1].Sequence != 9 || events[1].Progress != nil ||
		events[1].Message != nil {
		t.Fatalf("events = %#v", events)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestMySQLRepositoryDistinguishesMissingTask(t *testing.T) {
	database, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()

	mock.ExpectBegin()
	mock.ExpectQuery("SELECT 1").
		WithArgs(testTaskID).
		WillReturnError(sql.ErrNoRows)
	mock.ExpectRollback()

	repository := NewMySQLRepository(database)
	_, err = repository.List(context.Background(), Query{
		TaskID: testTaskID, Limit: 10,
	})
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("List() error = %v, want ErrNotFound", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestMySQLRepositoryRejectsOutOfRangeStoredProgress(t *testing.T) {
	database, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()

	mock.ExpectBegin()
	mock.ExpectQuery("SELECT 1").
		WithArgs(testTaskID).
		WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(1))
	mock.ExpectQuery("SELECT event_sequence").
		WithArgs(testTaskID, uint64(0), 1).
		WillReturnRows(sqlmock.NewRows([]string{
			"event_sequence", "event_type", "stage",
			"progress_basis_points", "severity", "message", "payload",
			"created_at",
		}).AddRow(
			uint64(1), "task.progress", nil, 10_001, "info", nil,
			[]byte(`{}`), time.Now().UTC(),
		))
	mock.ExpectRollback()

	repository := NewMySQLRepository(database)
	if _, err := repository.List(context.Background(), Query{
		TaskID: testTaskID, Limit: 1,
	}); err == nil {
		t.Fatal("List() error = nil, want progress range error")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

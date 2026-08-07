package taskevent

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
)

func TestAppendActivityPersistsSafePayload(t *testing.T) {
	database, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()

	payload := json.RawMessage(`{"analyzer":"ghidra","phase":"running","current":3,"total":10}`)
	mock.ExpectBegin()
	mock.ExpectExec(`(?s)INSERT INTO task_events.*event_sequence.*SELECT.*stage.*progress_basis_points.*FROM tasks.*WHERE id = \?`).
		WithArgs(
			"decompile.progress",
			"info",
			"Ghidra decompilation is running.",
			[]byte(payload),
			testTaskID,
		).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectRollback()

	transaction, err := database.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	err = AppendActivity(
		context.Background(),
		transaction,
		testTaskID,
		Activity{
			EventType: "decompile.progress",
			Severity:  "info",
			Message:   "Ghidra decompilation is running.",
			Payload:   payload,
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := transaction.Rollback(); err != nil {
		t.Fatal(err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestAppendCurrentStatePersistsAdvancedSequence(t *testing.T) {
	database, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()

	mock.ExpectBegin()
	mock.ExpectExec(`(?s)INSERT INTO task_events.*event_sequence.*SELECT.*JSON_OBJECT.*sample_expires_at.*sample_deleted_at.*FROM tasks.*WHERE id = \?`).
		WithArgs("task.progress", "Task progress changed.", testTaskID).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectRollback()

	transaction, err := database.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	err = AppendCurrentState(
		context.Background(), transaction, testTaskID,
		"task.progress", "Task progress changed.",
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := transaction.Rollback(); err != nil {
		t.Fatal(err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestAppendCurrentStateRejectsMissingTask(t *testing.T) {
	database, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()

	mock.ExpectBegin()
	mock.ExpectExec(`(?s)INSERT INTO task_events.*FROM tasks.*WHERE id = \?`).
		WithArgs("task.progress", "Task progress changed.", testTaskID).
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectRollback()

	transaction, err := database.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	err = AppendCurrentState(
		context.Background(), transaction, testTaskID,
		"task.progress", "Task progress changed.",
	)
	if err == nil || !strings.Contains(err.Error(), "expected one task row") {
		t.Fatalf("AppendCurrentState() error = %v", err)
	}
	if err := transaction.Rollback(); err != nil {
		t.Fatal(err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

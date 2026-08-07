package workerreadiness

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
)

func TestMySQLRepositoryRegistersHeartbeatsAndRemovesReadiness(t *testing.T) {
	database, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	repository, err := NewMySQLRepository(database)
	if err != nil {
		t.Fatal(err)
	}
	registration := Registration{
		Owner: "native:fixture", WorkerKind: "native",
		AnalyzerName: "ghidra", AnalyzerVersion: "12.1.2",
		RuntimeName: "jdk", RuntimeVersion: `openjdk version "21.0.4"`,
	}

	mock.ExpectExec(`(?s)INSERT INTO worker_readiness.*ON DUPLICATE KEY UPDATE`).
		WithArgs(
			registration.Owner, registration.WorkerKind,
			registration.AnalyzerName, registration.AnalyzerVersion,
			registration.RuntimeName, registration.RuntimeVersion,
		).
		WillReturnResult(sqlmock.NewResult(0, 1))
	if err := repository.Register(context.Background(), registration); err != nil {
		t.Fatal(err)
	}

	mock.ExpectExec(`(?s)UPDATE worker_readiness.*last_checked_at.*worker_owner = \?`).
		WithArgs(registration.Owner).
		WillReturnResult(sqlmock.NewResult(0, 1))
	if err := repository.Heartbeat(context.Background(), registration.Owner); err != nil {
		t.Fatal(err)
	}

	before := time.Now().UTC().Add(-24 * time.Hour)
	mock.ExpectExec(`(?s)DELETE FROM worker_readiness.*last_checked_at < \?`).
		WithArgs(before).
		WillReturnResult(sqlmock.NewResult(0, 2))
	if err := repository.Prune(context.Background(), before); err != nil {
		t.Fatal(err)
	}

	mock.ExpectExec(`DELETE FROM worker_readiness WHERE worker_owner = \?`).
		WithArgs(registration.Owner).
		WillReturnResult(sqlmock.NewResult(0, 1))
	if err := repository.Remove(context.Background(), registration.Owner); err != nil {
		t.Fatal(err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestMySQLRepositoryRejectsLostAndInvalidReadiness(t *testing.T) {
	database, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	repository, err := NewMySQLRepository(database)
	if err != nil {
		t.Fatal(err)
	}
	mock.ExpectExec(`UPDATE worker_readiness`).
		WithArgs("native:missing").
		WillReturnResult(sqlmock.NewResult(0, 0))
	if err := repository.Heartbeat(
		context.Background(), "native:missing",
	); err == nil || !strings.Contains(err.Error(), "lost") {
		t.Fatalf("Heartbeat() error = %v", err)
	}
	if err := repository.Register(context.Background(), Registration{
		Owner: "native:bad", WorkerKind: "native",
		AnalyzerName: "trivy", AnalyzerVersion: "0.72.0",
	}); err == nil {
		t.Fatal("Register() accepted a mismatched analyzer kind")
	}
	if _, err := NewMySQLRepository(nil); err == nil {
		t.Fatal("NewMySQLRepository(nil) error = nil")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestValidateRegistrationAcceptsBytecodeSourceToolchain(t *testing.T) {
	err := validateRegistration(Registration{
		Owner: "bytecode:fixture", WorkerKind: "bytecode",
		AnalyzerName: "vineflower-cfr-jadx", AnalyzerVersion: "1.12.0+0.152+1.5.6",
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestMySQLRepositoryWrapsDatabaseFailure(t *testing.T) {
	database, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	repository, err := NewMySQLRepository(database)
	if err != nil {
		t.Fatal(err)
	}
	mock.ExpectExec(`DELETE FROM worker_readiness`).
		WillReturnError(sql.ErrConnDone)
	err = repository.Remove(context.Background(), "native:fixture")
	if !errors.Is(err, sql.ErrConnDone) {
		t.Fatalf("Remove() error = %v", err)
	}
}

package blobfence

import (
	"context"
	"errors"
	"regexp"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
)

const testSHA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func TestWithDoesNotRunOperationWhenFenceIsBusy(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	mock.ExpectQuery(regexp.QuoteMeta("SELECT GET_LOCK(?, ?)")).
		WithArgs(LockName(testSHA), lockWaitSeconds).
		WillReturnRows(sqlmock.NewRows([]string{"acquired"}).AddRow(0))
	called := false
	if err := With(context.Background(), db, testSHA, func() error {
		called = true
		return nil
	}); err == nil || called {
		t.Fatalf("With() error=%v called=%v", err, called)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestWithDoesNotReverseSuccessfulOperationOnUnlockFailure(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	mock.ExpectQuery(regexp.QuoteMeta("SELECT GET_LOCK(?, ?)")).
		WithArgs(LockName(testSHA), lockWaitSeconds).
		WillReturnRows(sqlmock.NewRows([]string{"acquired"}).AddRow(1))
	mock.ExpectExec(regexp.QuoteMeta("SELECT RELEASE_LOCK(?)")).
		WithArgs(LockName(testSHA)).
		WillReturnError(errors.New("connection interrupted"))
	if err := With(context.Background(), db, testSHA, func() error { return nil }); err != nil {
		t.Fatalf("With() error = %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

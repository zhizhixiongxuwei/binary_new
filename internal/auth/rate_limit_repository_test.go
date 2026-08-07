package auth

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
)

func TestBeginLoginAttemptKeepsActiveBlockAfterWindowExpiry(
	t *testing.T,
) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	repository := NewMySQLRepository(db)
	policy := LoginRateLimitPolicy{
		Threshold: 5, Window: time.Minute,
		BlockDuration: 5 * time.Minute,
	}
	key := normalizeLoginClientKey([]byte{192, 0, 2, 1})
	now := time.Date(2026, time.July, 31, 8, 0, 0, 0, time.UTC)
	blockedUntil := now.Add(4 * time.Minute)

	mock.ExpectExec("DELETE FROM login_rate_limits").
		WithArgs(
			-loginRateLimitRetention(policy).Microseconds(),
			loginRateLimitCleanupBatch,
		).
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectBegin()
	mock.ExpectExec("INSERT INTO login_rate_limits").
		WithArgs(key[:], policy.Window.Microseconds()).
		WillReturnResult(sqlmock.NewResult(0, 0))
	expectLoginRateLimitState(
		mock, key, now.Add(-2*time.Minute), now.Add(-time.Minute),
		5, 0, blockedUntil, now,
	)
	mock.ExpectCommit()

	attempt, err := repository.BeginLoginAttempt(
		context.Background(), key, policy,
	)
	if err != nil {
		t.Fatal(err)
	}
	if !attempt.Limited || attempt.RetryAfter != 4*time.Minute {
		t.Fatalf("attempt = %#v", attempt)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestBeginLoginAttemptResetsExpiredWindowAndReserves(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	repository := NewMySQLRepository(db)
	policy := LoginRateLimitPolicy{
		Threshold: 5, Window: time.Minute,
		BlockDuration: 5 * time.Minute,
	}
	key := normalizeLoginClientKey([]byte{192, 0, 2, 2})
	now := time.Date(2026, time.July, 31, 8, 0, 0, 0, time.UTC)
	newWindow := now.Add(time.Microsecond)

	mock.ExpectExec("DELETE FROM login_rate_limits").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectBegin()
	mock.ExpectExec("INSERT INTO login_rate_limits").
		WillReturnResult(sqlmock.NewResult(0, 0))
	expectLoginRateLimitState(
		mock, key, now.Add(-2*time.Minute), now,
		3, 0, nil, now,
	)
	mock.ExpectExec("UPDATE login_rate_limits[[:space:]]+SET window_started_at").
		WithArgs(policy.Window.Microseconds(), key[:]).
		WillReturnResult(sqlmock.NewResult(0, 1))
	expectLoginRateLimitState(
		mock, key, newWindow, newWindow.Add(policy.Window),
		0, 0, nil, newWindow,
	)
	mock.ExpectExec("SET in_flight_count = in_flight_count \\+ 1").
		WithArgs(key[:], newWindow, uint32(0), uint32(0)).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

	attempt, err := repository.BeginLoginAttempt(
		context.Background(), key, policy,
	)
	if err != nil {
		t.Fatal(err)
	}
	if attempt.Limited ||
		!attempt.WindowStartedAt.Equal(newWindow) {
		t.Fatalf("attempt = %#v", attempt)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestFinishLoginAttemptFailureSetsBlockAtThreshold(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	repository := NewMySQLRepository(db)
	policy := LoginRateLimitPolicy{
		Threshold: 5, Window: time.Minute,
		BlockDuration: 5 * time.Minute,
	}
	key := normalizeLoginClientKey([]byte{192, 0, 2, 3})
	now := time.Date(2026, time.July, 31, 8, 0, 0, 0, time.UTC)
	windowStart := now.Add(-30 * time.Second)
	attempt := LoginAttempt{
		ClientKey: key, WindowStartedAt: windowStart,
	}

	mock.ExpectBegin()
	expectLoginRateLimitState(
		mock, key, windowStart, windowStart.Add(policy.Window),
		4, 1, nil, now,
	)
	mock.ExpectExec("SET failure_count = failure_count \\+ 1").
		WithArgs(
			policy.Threshold,
			policy.BlockDuration.Microseconds(),
			key[:],
			windowStart,
			uint32(1),
		).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

	if err := repository.FinishLoginAttempt(
		context.Background(), attempt, true, policy,
	); err != nil {
		t.Fatal(err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestFinishLoginAttemptIgnoresStaleWindow(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	repository := NewMySQLRepository(db)
	policy := LoginRateLimitPolicy{
		Threshold: 5, Window: time.Minute,
		BlockDuration: 5 * time.Minute,
	}
	key := normalizeLoginClientKey([]byte{192, 0, 2, 4})
	now := time.Date(2026, time.July, 31, 8, 0, 0, 0, time.UTC)
	staleWindow := now.Add(-2 * time.Minute)

	mock.ExpectBegin()
	expectLoginRateLimitState(
		mock, key, now, now.Add(policy.Window),
		0, 0, nil, now,
	)
	mock.ExpectCommit()

	if err := repository.FinishLoginAttempt(
		context.Background(),
		LoginAttempt{
			ClientKey: key, WindowStartedAt: staleWindow,
		},
		true,
		policy,
	); err != nil {
		t.Fatal(err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestBeginLoginAttemptFailsClosedWhenCleanupFails(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	repository := NewMySQLRepository(db)
	policy := LoginRateLimitPolicy{
		Threshold: 5, Window: time.Minute,
		BlockDuration: 5 * time.Minute,
	}
	mock.ExpectExec("DELETE FROM login_rate_limits").
		WillReturnError(errors.New("database unavailable"))

	_, err = repository.BeginLoginAttempt(
		context.Background(),
		normalizeLoginClientKey(nil),
		policy,
	)
	if err == nil {
		t.Fatal("BeginLoginAttempt() error = nil")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func expectLoginRateLimitState(
	mock sqlmock.Sqlmock,
	key [32]byte,
	windowStartedAt time.Time,
	windowExpiresAt time.Time,
	failureCount uint32,
	inFlightCount uint32,
	blockedUntil any,
	databaseNow time.Time,
) {
	mock.ExpectQuery("SELECT window_started_at, window_expires_at").
		WithArgs(key[:]).
		WillReturnRows(sqlmock.NewRows([]string{
			"window_started_at",
			"window_expires_at",
			"failure_count",
			"in_flight_count",
			"blocked_until",
			"database_now",
		}).AddRow(
			windowStartedAt,
			windowExpiresAt,
			failureCount,
			inFlightCount,
			blockedUntil,
			databaseNow,
		))
}

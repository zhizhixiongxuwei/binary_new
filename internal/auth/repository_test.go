package auth

import (
	"context"
	"errors"
	"regexp"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
)

func TestUpdatePasswordUsesOldHashCAS(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	repository := NewMySQLRepository(db)

	mock.ExpectBegin()
	mock.ExpectExec(regexp.QuoteMeta(`
UPDATE users
SET password_hash = ?, force_password_change = FALSE,
    failed_login_count = 0, locked_until = NULL
WHERE id = ? AND password_hash = ? AND status = 'active'`)).
		WithArgs("new-hash", uint64(7), "expected-old-hash").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectRollback()

	err = repository.UpdatePassword(
		context.Background(), 7, "current-session", "new-hash", "expected-old-hash", time.Now(),
	)
	if err != ErrInvalidCredentials {
		t.Fatalf("UpdatePassword() error = %v, want ErrInvalidCredentials", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestCompleteLoginRejectsChangedPasswordHash(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	repository := NewMySQLRepository(db)
	now := time.Now().UTC()

	mock.ExpectBegin()
	mock.ExpectQuery(regexp.QuoteMeta(`
SELECT status, locked_until, password_hash
FROM users
WHERE id = ?
FOR UPDATE`)).
		WithArgs(uint64(7)).
		WillReturnRows(sqlmock.NewRows([]string{"status", "locked_until", "password_hash"}).
			AddRow("active", nil, "new-password-hash"))
	mock.ExpectRollback()

	err = repository.CompleteLogin(
		context.Background(), 7, "old-password-hash",
		NewSession{ID: "session"}, now,
	)
	if err != ErrInvalidCredentials {
		t.Fatalf("CompleteLogin() error = %v, want ErrInvalidCredentials", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestRenewSessionExtendsNearExpiryUnderRowLock(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	repository := NewMySQLRepository(db)
	now := time.Date(2026, time.July, 31, 6, 0, 0, 0, time.UTC)
	currentExpiry := now.Add(10 * time.Minute)
	renewBefore := now.Add(30 * time.Minute)
	newExpiry := now.Add(time.Hour)

	mock.ExpectBegin()
	mock.ExpectQuery(regexp.QuoteMeta(`
SELECT session.expires_at, session.revoked_at, user.status
FROM sessions session
JOIN users user ON user.id = session.user_id
WHERE session.id = ?
FOR UPDATE`)).
		WithArgs("session").
		WillReturnRows(sqlmock.NewRows(
			[]string{"expires_at", "revoked_at", "status"},
		).AddRow(currentExpiry, nil, "active"))
	mock.ExpectExec(regexp.QuoteMeta(`
UPDATE sessions
SET expires_at = ?,
    last_seen_at = ?
WHERE id = ?
  AND revoked_at IS NULL
  AND expires_at > ?`)).
		WithArgs(newExpiry, now, "session", now).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

	expiresAt, err := repository.RenewSession(
		context.Background(),
		"session",
		now,
		renewBefore,
		newExpiry,
	)
	if err != nil {
		t.Fatal(err)
	}
	if !expiresAt.Equal(newExpiry) {
		t.Fatalf("expiresAt = %v, want %v", expiresAt, newExpiry)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestRenewSessionRejectsRevokedSession(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	repository := NewMySQLRepository(db)
	now := time.Date(2026, time.July, 31, 6, 0, 0, 0, time.UTC)

	mock.ExpectBegin()
	mock.ExpectQuery(regexp.QuoteMeta(`
SELECT session.expires_at, session.revoked_at, user.status
FROM sessions session
JOIN users user ON user.id = session.user_id
WHERE session.id = ?
FOR UPDATE`)).
		WithArgs("session").
		WillReturnRows(sqlmock.NewRows(
			[]string{"expires_at", "revoked_at", "status"},
		).AddRow(now.Add(time.Hour), now.Add(-time.Minute), "active"))
	mock.ExpectRollback()

	_, err = repository.RenewSession(
		context.Background(),
		"session",
		now,
		now.Add(30*time.Minute),
		now.Add(time.Hour),
	)
	if !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("RenewSession() error = %v, want ErrUnauthenticated", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

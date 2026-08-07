package useradmin

import (
	"context"
	"regexp"
	"testing"
	"time"

	"binaryscan/internal/audit"
	"binaryscan/internal/auth"

	"github.com/DATA-DOG/go-sqlmock"
)

func userRows(now time.Time, internalID uint64, role, status string) *sqlmock.Rows {
	return userRowsWithLock(now, internalID, role, status, 0, nil)
}

func userRowsWithLock(
	now time.Time,
	internalID uint64,
	role string,
	status string,
	failedLoginCount uint32,
	lockedUntil *time.Time,
) *sqlmock.Rows {
	return sqlmock.NewRows([]string{
		"id", "public_id", "username", "display_name", "role", "status",
		"force_password_change", "failed_login_count", "locked_until",
		"last_login_at", "created_at", "updated_at",
	}).AddRow(
		internalID, testPublicID, "admin", "Administrator", role, status,
		false, failedLoginCount, lockedUntil, nil, now.Add(-time.Hour), now,
	)
}

func userLockQuery() string {
	return regexp.QuoteMeta(userSelectColumns + `
WHERE u.public_id = ?
LIMIT 1
FOR UPDATE`)
}

func TestUpdateRejectsCurrentAdministratorDemotionInsideTransaction(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	now := time.Date(2026, 7, 30, 12, 0, 0, 0, time.UTC)
	mock.ExpectBegin()
	mock.ExpectQuery(userLockQuery()).
		WithArgs(testPublicID).
		WillReturnRows(userRows(now, 7, "administrator", "active"))
	mock.ExpectRollback()

	role := auth.RoleReader
	_, err = NewMySQLRepository(db).Update(context.Background(), UpdateRecord{
		ActorUserID: 7, PublicID: testPublicID, Role: &role,
		ExpectedUpdatedAt: now, UpdatedAt: now.Add(time.Minute),
	})
	if err != ErrCurrentUserGuard {
		t.Fatalf("Update() error = %v, want ErrCurrentUserGuard", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestUpdatePreservesLastActiveAdministratorInsideTransaction(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	now := time.Date(2026, 7, 30, 12, 0, 0, 0, time.UTC)
	mock.ExpectBegin()
	mock.ExpectQuery(userLockQuery()).
		WithArgs(testPublicID).
		WillReturnRows(userRows(now, 7, "administrator", "active"))
	mock.ExpectQuery(regexp.QuoteMeta(`
SELECT id
FROM users
WHERE status = 'active' AND role = 'administrator'
ORDER BY id
FOR UPDATE`)).
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(7))
	mock.ExpectRollback()

	role := auth.RoleReader
	_, err = NewMySQLRepository(db).Update(context.Background(), UpdateRecord{
		ActorUserID: 99, PublicID: testPublicID, Role: &role,
		ExpectedUpdatedAt: now, UpdatedAt: now.Add(time.Minute),
	})
	if err != ErrLastAdministrator {
		t.Fatalf("Update() error = %v, want ErrLastAdministrator", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestResetPasswordRevokesEverySessionAndAppendsAuditAtomically(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	now := time.Date(2026, 7, 30, 12, 0, 0, 0, time.UTC)
	updatedAt := now.Add(time.Minute)
	actorID := uint64(99)

	mock.ExpectBegin()
	mock.ExpectQuery(userLockQuery()).
		WithArgs(testPublicID).
		WillReturnRows(userRows(now, 7, "reader", "active"))
	mock.ExpectExec(regexp.QuoteMeta(`
UPDATE users
SET password_hash = ?, force_password_change = TRUE,
    failed_login_count = 0, locked_until = NULL, updated_at = ?
WHERE id = ?`)).
		WithArgs("argon-hash", updatedAt, uint64(7)).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(regexp.QuoteMeta(`
UPDATE sessions
SET revoked_at = COALESCE(revoked_at, ?)
WHERE user_id = ? AND revoked_at IS NULL`)).
		WithArgs(updatedAt, uint64(7)).
		WillReturnResult(sqlmock.NewResult(0, 3))
	mock.ExpectExec("INSERT INTO audit_logs").
		WithArgs(
			sqlmock.AnyArg(), "request-99", "user.password_reset", "user",
			testPublicID, audit.OutcomeSuccess, nil, nil, sqlmock.AnyArg(),
		).
		WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectQuery(regexp.QuoteMeta(userSelectColumns + `
WHERE u.id = ?
LIMIT 1`)).
		WithArgs(uint64(7)).
		WillReturnRows(userRows(updatedAt, 7, "reader", "active"))
	mock.ExpectCommit()

	user, err := NewMySQLRepository(db).ResetPassword(
		context.Background(),
		ResetPasswordRecord{
			PublicID: testPublicID, PasswordHash: "argon-hash",
			ExpectedUpdatedAt: now, UpdatedAt: updatedAt,
			Audit: audit.Event{
				ActorUserID: &actorID, RequestID: "request-99",
				Action: "user.password_reset", ObjectType: "user",
				ObjectID: testPublicID, Outcome: audit.OutcomeSuccess,
				Metadata: map[string]any{"must_change_password": true},
			},
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if user.ID != testPublicID {
		t.Fatalf("user = %#v", user)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestUpdateRoleDoesNotSilentlyUnlockAccount(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	now := time.Now().UTC().Truncate(time.Microsecond)
	updatedAt := now.Add(time.Minute)
	lockedUntil := now.Add(15 * time.Minute)
	actorID := uint64(99)
	role := auth.RoleOperator

	mock.ExpectBegin()
	mock.ExpectQuery(userLockQuery()).
		WithArgs(testPublicID).
		WillReturnRows(userRowsWithLock(
			now, 7, "reader", "active", 5, &lockedUntil,
		))
	mock.ExpectExec(regexp.QuoteMeta(`
UPDATE users
SET role = ?, status = ?,
    failed_login_count = CASE WHEN ? THEN 0 ELSE failed_login_count END,
    locked_until = CASE WHEN ? THEN NULL ELSE locked_until END,
    updated_at = ?
WHERE id = ?`)).
		WithArgs(role, "active", false, false, updatedAt, uint64(7)).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(regexp.QuoteMeta(`
UPDATE sessions
SET revoked_at = COALESCE(revoked_at, ?)
WHERE user_id = ? AND revoked_at IS NULL`)).
		WithArgs(updatedAt, uint64(7)).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec("INSERT INTO audit_logs").
		WithArgs(
			sqlmock.AnyArg(), "request-99", "user.update", "user",
			testPublicID, audit.OutcomeSuccess, nil, nil, sqlmock.AnyArg(),
		).
		WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectQuery(regexp.QuoteMeta(userSelectColumns + `
WHERE u.id = ?
LIMIT 1`)).
		WithArgs(uint64(7)).
		WillReturnRows(userRowsWithLock(
			updatedAt, 7, "operator", "active", 5, &lockedUntil,
		))
	mock.ExpectCommit()

	user, err := NewMySQLRepository(db).Update(
		context.Background(),
		UpdateRecord{
			ActorUserID: 99, PublicID: testPublicID, Role: &role,
			ExpectedUpdatedAt: now, UpdatedAt: updatedAt,
			Audit: audit.Event{
				ActorUserID: &actorID, RequestID: "request-99",
				Action: "user.update", ObjectType: "user",
				ObjectID: testPublicID, Outcome: audit.OutcomeSuccess,
			},
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if user.Status != "locked" || user.FailedLoginCount != 5 ||
		user.LockedUntil == nil {
		t.Fatalf("locked account was changed unexpectedly: %#v", user)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

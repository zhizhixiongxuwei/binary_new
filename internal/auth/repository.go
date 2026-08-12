package auth

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"errors"
	"fmt"
	"net"
	"time"
)

var ErrAlreadyInitialized = errors.New("installation already contains a user; initial administrator creation is disabled")

type Repository interface {
	BeginLoginAttempt(
		context.Context,
		[sha256.Size]byte,
		LoginRateLimitPolicy,
	) (LoginAttempt, error)
	FinishLoginAttempt(
		context.Context,
		LoginAttempt,
		bool,
		LoginRateLimitPolicy,
	) error
	FindUserByUsername(context.Context, string) (User, error)
	FindUserByID(context.Context, uint64) (User, error)
	RecordLoginFailure(context.Context, uint64, uint32, time.Time, time.Time) error
	CompleteLogin(context.Context, uint64, string, NewSession, time.Time) error
	FindSessionByTokenHash(context.Context, [sha256.Size]byte) (Session, error)
	TouchSession(context.Context, string, time.Time) error
	RenewSession(
		context.Context,
		string,
		time.Time,
		time.Time,
		time.Time,
	) (time.Time, error)
	RevokeSession(context.Context, string, time.Time) error
	UpdatePassword(context.Context, uint64, string, string, string, time.Time) error
	CreateInitialAdministrator(context.Context, User) error
}

func (r *MySQLRepository) FindUserByID(ctx context.Context, userID uint64) (User, error) {
	var user User
	var role string
	err := r.db.QueryRowContext(ctx, `
SELECT id, public_id, username, display_name, password_hash, role, status,
       force_password_change, failed_login_count, locked_until
FROM users
WHERE id = ?
LIMIT 1`, userID).Scan(
		&user.ID, &user.PublicID, &user.Username, &user.DisplayName, &user.PasswordHash,
		&role, &user.Status, &user.ForcePasswordChange, &user.FailedLoginCount, &user.LockedUntil,
	)
	user.Role = Role(role)
	return user, err
}

type MySQLRepository struct {
	db *sql.DB
}

func NewMySQLRepository(db *sql.DB) *MySQLRepository {
	return &MySQLRepository{db: db}
}

func (r *MySQLRepository) FindUserByUsername(ctx context.Context, username string) (User, error) {
	var user User
	var role string
	err := r.db.QueryRowContext(ctx, `
SELECT id, public_id, username, display_name, password_hash, role, status,
       force_password_change, failed_login_count, locked_until
FROM users
WHERE username = ?
LIMIT 1`, username).Scan(
		&user.ID, &user.PublicID, &user.Username, &user.DisplayName, &user.PasswordHash,
		&role, &user.Status, &user.ForcePasswordChange, &user.FailedLoginCount, &user.LockedUntil,
	)
	user.Role = Role(role)
	return user, err
}

func (r *MySQLRepository) RecordLoginFailure(
	ctx context.Context,
	userID uint64,
	threshold uint32,
	now time.Time,
	lockUntil time.Time,
) error {
	_, err := r.db.ExecContext(ctx, `
UPDATE users
SET failed_login_count =
        CASE WHEN locked_until IS NOT NULL AND locked_until <= ? THEN 1
             ELSE failed_login_count + 1 END,
    locked_until =
        CASE WHEN
            (CASE WHEN locked_until IS NOT NULL AND locked_until <= ? THEN 1
                  ELSE failed_login_count + 1 END) >= ?
             THEN ?
             WHEN locked_until IS NOT NULL AND locked_until <= ? THEN NULL
             ELSE locked_until END
WHERE id = ?`, now, now, threshold, lockUntil, now, userID)
	if err != nil {
		return fmt.Errorf("record login failure: %w", err)
	}
	return nil
}

func (r *MySQLRepository) CompleteLogin(
	ctx context.Context,
	userID uint64,
	expectedPasswordHash string,
	session NewSession,
	now time.Time,
) error {
	transaction, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin login transaction: %w", err)
	}
	defer transaction.Rollback()

	var status string
	var lockedUntil *time.Time
	var storedPasswordHash string
	if err := transaction.QueryRowContext(ctx, `
SELECT status, locked_until, password_hash
FROM users
WHERE id = ?
FOR UPDATE`, userID).Scan(&status, &lockedUntil, &storedPasswordHash); err != nil {
		return fmt.Errorf("lock login user: %w", err)
	}
	if status != "active" || (lockedUntil != nil && lockedUntil.After(now)) ||
		subtle.ConstantTimeCompare([]byte(storedPasswordHash), []byte(expectedPasswordHash)) != 1 {
		return ErrInvalidCredentials
	}
	if _, err := transaction.ExecContext(ctx, `
UPDATE users
SET failed_login_count = 0, locked_until = NULL, last_login_at = ?
WHERE id = ?`, now, userID); err != nil {
		return fmt.Errorf("reset login failures: %w", err)
	}
	if _, err := transaction.ExecContext(ctx, `
INSERT INTO sessions (
    id, user_id, token_hash, csrf_token_hash, client_ip, user_agent,
    expires_at, last_seen_at
) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		session.ID, userID, session.TokenHash[:], session.CSRFTokenHash[:],
		session.ClientIP, session.UserAgent, session.ExpiresAt, now,
	); err != nil {
		return fmt.Errorf("create session: %w", err)
	}
	if err := transaction.Commit(); err != nil {
		return fmt.Errorf("commit login transaction: %w", err)
	}
	return nil
}

func (r *MySQLRepository) FindSessionByTokenHash(ctx context.Context, tokenHash [sha256.Size]byte) (Session, error) {
	var session Session
	var role string
	var csrfHash []byte
	err := r.db.QueryRowContext(ctx, `
SELECT s.id, s.csrf_token_hash, s.expires_at, s.revoked_at, s.last_seen_at,
       u.id, u.public_id, u.username, u.display_name, u.role, u.force_password_change
FROM sessions s
JOIN users u ON u.id = s.user_id
WHERE s.token_hash = ? AND u.status = 'active'
LIMIT 1`, tokenHash[:]).Scan(
		&session.ID, &csrfHash, &session.ExpiresAt, &session.RevokedAt, &session.LastSeenAt,
		&session.User.UserID, &session.User.PublicID, &session.User.Username,
		&session.User.DisplayName, &role, &session.User.ForcePasswordChange,
	)
	if err != nil {
		return Session{}, err
	}
	if len(csrfHash) != sha256.Size {
		return Session{}, errors.New("stored CSRF token hash has invalid length")
	}
	copy(session.CSRFTokenHash[:], csrfHash)
	session.User.Role = Role(role)
	return session, nil
}

func (r *MySQLRepository) TouchSession(ctx context.Context, sessionID string, now time.Time) error {
	_, err := r.db.ExecContext(ctx, `
UPDATE sessions
SET last_seen_at = ?
WHERE id = ? AND last_seen_at < ?`, now, sessionID, now.Add(-5*time.Minute))
	if err != nil {
		return fmt.Errorf("touch session: %w", err)
	}
	return nil
}

func (r *MySQLRepository) RenewSession(
	ctx context.Context,
	sessionID string,
	now time.Time,
	renewBefore time.Time,
	newExpiresAt time.Time,
) (expiresAt time.Time, returnErr error) {
	if sessionID == "" || !renewBefore.After(now) ||
		!newExpiresAt.After(renewBefore) {
		return time.Time{}, errors.New("session renewal input is invalid")
	}
	transaction, err := r.db.BeginTx(
		ctx,
		&sql.TxOptions{Isolation: sql.LevelReadCommitted},
	)
	if err != nil {
		return time.Time{}, fmt.Errorf("begin session renewal: %w", err)
	}
	finished := false
	defer func() {
		if !finished {
			returnErr = errors.Join(
				returnErr,
				transaction.Rollback(),
			)
		}
	}()

	var (
		revokedAt  *time.Time
		userStatus string
	)
	err = transaction.QueryRowContext(ctx, `
SELECT session.expires_at, session.revoked_at, user.status
FROM sessions session
JOIN users user ON user.id = session.user_id
WHERE session.id = ?
FOR UPDATE`, sessionID).Scan(&expiresAt, &revokedAt, &userStatus)
	if errors.Is(err, sql.ErrNoRows) {
		return time.Time{}, ErrUnauthenticated
	}
	if err != nil {
		return time.Time{}, fmt.Errorf("lock session renewal: %w", err)
	}
	if revokedAt != nil || userStatus != "active" || !expiresAt.After(now) {
		return time.Time{}, ErrUnauthenticated
	}

	if !expiresAt.After(renewBefore) {
		result, err := transaction.ExecContext(ctx, `
UPDATE sessions
SET expires_at = ?,
    last_seen_at = ?
WHERE id = ?
  AND revoked_at IS NULL
  AND expires_at > ?`, newExpiresAt, now, sessionID, now)
		if err != nil {
			return time.Time{}, fmt.Errorf("renew session: %w", err)
		}
		affected, err := result.RowsAffected()
		if err != nil {
			return time.Time{}, fmt.Errorf("inspect session renewal: %w", err)
		}
		if affected != 1 {
			return time.Time{}, ErrUnauthenticated
		}
		expiresAt = newExpiresAt
	} else if _, err := transaction.ExecContext(ctx, `
UPDATE sessions
SET last_seen_at = ?
WHERE id = ? AND last_seen_at < ?`,
		now, sessionID, now.Add(-5*time.Minute),
	); err != nil {
		return time.Time{}, fmt.Errorf("touch renewed session: %w", err)
	}
	if err := transaction.Commit(); err != nil {
		return time.Time{}, fmt.Errorf("commit session renewal: %w", err)
	}
	finished = true
	return expiresAt, nil
}

func (r *MySQLRepository) RevokeSession(ctx context.Context, sessionID string, now time.Time) error {
	_, err := r.db.ExecContext(ctx, `
UPDATE sessions
SET revoked_at = COALESCE(revoked_at, ?)
WHERE id = ?`, now, sessionID)
	if err != nil {
		return fmt.Errorf("revoke session: %w", err)
	}
	return nil
}

func (r *MySQLRepository) UpdatePassword(
	ctx context.Context,
	userID uint64,
	currentSessionID string,
	passwordHash string,
	expectedPasswordHash string,
	now time.Time,
) error {
	transaction, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin password update transaction: %w", err)
	}
	defer transaction.Rollback()
	result, err := transaction.ExecContext(ctx, `
UPDATE users
SET password_hash = ?, force_password_change = FALSE,
    failed_login_count = 0, locked_until = NULL
WHERE id = ? AND password_hash = ? AND status = 'active'`,
		passwordHash, userID, expectedPasswordHash,
	)
	if err != nil {
		return fmt.Errorf("update password: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("inspect password update: %w", err)
	}
	if rows != 1 {
		return ErrInvalidCredentials
	}
	if _, err := transaction.ExecContext(ctx, `
UPDATE sessions
SET revoked_at = COALESCE(revoked_at, ?)
WHERE user_id = ? AND id <> ? AND revoked_at IS NULL`, now, userID, currentSessionID); err != nil {
		return fmt.Errorf("revoke other sessions after password update: %w", err)
	}
	if err := transaction.Commit(); err != nil {
		return fmt.Errorf("commit password update: %w", err)
	}
	return nil
}

func (r *MySQLRepository) CreateInitialAdministrator(ctx context.Context, user User) error {
	connection, err := r.db.Conn(ctx)
	if err != nil {
		return fmt.Errorf("reserve administrator initialization connection: %w", err)
	}
	defer connection.Close()
	var acquired sql.NullInt64
	if err := connection.QueryRowContext(ctx, "SELECT GET_LOCK(?, ?)", "binaryscan_initial_administrator", 30).Scan(&acquired); err != nil {
		return fmt.Errorf("acquire administrator initialization lock: %w", err)
	}
	if !acquired.Valid || acquired.Int64 != 1 {
		return errors.New("administrator initialization lock was not acquired within 30 seconds")
	}
	defer func() {
		_, _ = connection.ExecContext(context.Background(), "SELECT RELEASE_LOCK(?)", "binaryscan_initial_administrator")
	}()

	result, err := connection.ExecContext(ctx, `
INSERT INTO users (
    public_id, username, display_name, password_hash, role, status, force_password_change
)
SELECT ?, ?, ?, ?, 'administrator', 'active', ?
WHERE NOT EXISTS (SELECT 1 FROM users LIMIT 1)`,
		user.PublicID, user.Username, user.DisplayName, user.PasswordHash,
		user.ForcePasswordChange,
	)
	if err != nil {
		return fmt.Errorf("create initial administrator: %w", err)
	}
	count, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("inspect initial administrator result: %w", err)
	}
	if count != 1 {
		return ErrAlreadyInitialized
	}
	return nil
}

func ParseClientIP(value string) []byte {
	ip := net.ParseIP(value)
	if ip == nil {
		return nil
	}
	if v4 := ip.To4(); v4 != nil {
		return append([]byte(nil), v4...)
	}
	return append([]byte(nil), ip.To16()...)
}

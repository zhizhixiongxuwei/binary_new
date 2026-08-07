package auth

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

const loginRateLimitCleanupBatch = 64

type loginRateLimitState struct {
	windowStartedAt time.Time
	windowExpiresAt time.Time
	failureCount    uint32
	inFlightCount   uint32
	blockedUntil    *time.Time
	databaseNow     time.Time
}

func (r *MySQLRepository) BeginLoginAttempt(
	ctx context.Context,
	clientKey [32]byte,
	policy LoginRateLimitPolicy,
) (LoginAttempt, error) {
	if r == nil || r.db == nil || !policy.valid() {
		return LoginAttempt{}, errors.New(
			"login rate limit repository input is invalid",
		)
	}
	if _, err := r.db.ExecContext(ctx, `
DELETE FROM login_rate_limits
WHERE updated_at < TIMESTAMPADD(MICROSECOND, ?, UTC_TIMESTAMP(6))
ORDER BY updated_at, client_key
LIMIT ?`,
		-loginRateLimitRetention(policy).Microseconds(),
		loginRateLimitCleanupBatch,
	); err != nil {
		return LoginAttempt{}, fmt.Errorf(
			"prune stale login rate limits: %w",
			err,
		)
	}

	tx, err := r.db.BeginTx(
		ctx,
		&sql.TxOptions{Isolation: sql.LevelReadCommitted},
	)
	if err != nil {
		return LoginAttempt{}, fmt.Errorf(
			"begin login rate limit transaction: %w",
			err,
		)
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `
INSERT INTO login_rate_limits (
    client_key, window_started_at, window_expires_at,
    failure_count, in_flight_count, blocked_until
) VALUES (
    ?, UTC_TIMESTAMP(6),
    TIMESTAMPADD(MICROSECOND, ?, UTC_TIMESTAMP(6)),
    0, 0, NULL
)
ON DUPLICATE KEY UPDATE client_key = VALUES(client_key)`,
		clientKey[:],
		policy.Window.Microseconds(),
	); err != nil {
		return LoginAttempt{}, fmt.Errorf(
			"initialize login rate limit: %w",
			err,
		)
	}
	state, err := readLoginRateLimitState(ctx, tx, clientKey)
	if err != nil {
		return LoginAttempt{}, err
	}
	if state.blockedUntil != nil &&
		state.blockedUntil.After(state.databaseNow) {
		if err := tx.Commit(); err != nil {
			return LoginAttempt{}, fmt.Errorf(
				"commit blocked login rate limit: %w",
				err,
			)
		}
		return LoginAttempt{
			ClientKey: clientKey, Limited: true,
			RetryAfter: retryAfterDuration(
				*state.blockedUntil,
				state.databaseNow,
			),
		}, nil
	}
	if !state.windowExpiresAt.After(state.databaseNow) ||
		state.blockedUntil != nil {
		if err := resetLoginRateLimit(
			ctx,
			tx,
			clientKey,
			policy.Window,
		); err != nil {
			return LoginAttempt{}, err
		}
		state, err = readLoginRateLimitState(ctx, tx, clientKey)
		if err != nil {
			return LoginAttempt{}, err
		}
	}
	if state.failureCount >= policy.Threshold {
		result, err := tx.ExecContext(ctx, `
UPDATE login_rate_limits
SET blocked_until =
        TIMESTAMPADD(MICROSECOND, ?, UTC_TIMESTAMP(6))
WHERE client_key = ?
  AND window_started_at = ?`,
			policy.BlockDuration.Microseconds(),
			clientKey[:],
			state.windowStartedAt,
		)
		if err != nil {
			return LoginAttempt{}, fmt.Errorf(
				"block login rate limit: %w",
				err,
			)
		}
		if err := requireRateLimitRow(result, "block login rate limit"); err != nil {
			return LoginAttempt{}, err
		}
		state, err = readLoginRateLimitState(ctx, tx, clientKey)
		if err != nil {
			return LoginAttempt{}, err
		}
		if state.blockedUntil == nil {
			return LoginAttempt{}, errors.New(
				"blocked login rate limit has no expiry",
			)
		}
		if err := tx.Commit(); err != nil {
			return LoginAttempt{}, fmt.Errorf(
				"commit new login rate limit block: %w",
				err,
			)
		}
		return LoginAttempt{
			ClientKey: clientKey, Limited: true,
			RetryAfter: retryAfterDuration(
				*state.blockedUntil,
				state.databaseNow,
			),
		}, nil
	}
	if uint64(state.failureCount)+uint64(state.inFlightCount) >=
		uint64(policy.Threshold) {
		if err := tx.Commit(); err != nil {
			return LoginAttempt{}, fmt.Errorf(
				"commit saturated login rate limit: %w",
				err,
			)
		}
		return LoginAttempt{
			ClientKey: clientKey, Limited: true,
			RetryAfter: time.Second,
		}, nil
	}
	result, err := tx.ExecContext(ctx, `
UPDATE login_rate_limits
SET in_flight_count = in_flight_count + 1
WHERE client_key = ?
  AND window_started_at = ?
  AND failure_count = ?
  AND in_flight_count = ?`,
		clientKey[:],
		state.windowStartedAt,
		state.failureCount,
		state.inFlightCount,
	)
	if err != nil {
		return LoginAttempt{}, fmt.Errorf(
			"reserve login rate limit attempt: %w",
			err,
		)
	}
	if err := requireRateLimitRow(result, "reserve login rate limit attempt"); err != nil {
		return LoginAttempt{}, err
	}
	if err := tx.Commit(); err != nil {
		return LoginAttempt{}, fmt.Errorf(
			"commit login rate limit reservation: %w",
			err,
		)
	}
	return LoginAttempt{
		ClientKey:       clientKey,
		WindowStartedAt: state.windowStartedAt,
	}, nil
}

func (r *MySQLRepository) FinishLoginAttempt(
	ctx context.Context,
	attempt LoginAttempt,
	failed bool,
	policy LoginRateLimitPolicy,
) error {
	if r == nil || r.db == nil ||
		attempt.Limited ||
		attempt.WindowStartedAt.IsZero() ||
		!policy.valid() {
		return errors.New("login rate limit completion input is invalid")
	}
	tx, err := r.db.BeginTx(
		ctx,
		&sql.TxOptions{Isolation: sql.LevelReadCommitted},
	)
	if err != nil {
		return fmt.Errorf(
			"begin login rate limit completion: %w",
			err,
		)
	}
	defer tx.Rollback()
	state, err := readLoginRateLimitState(
		ctx,
		tx,
		attempt.ClientKey,
	)
	if err != nil {
		return err
	}
	if !state.windowStartedAt.Equal(attempt.WindowStartedAt) {
		if err := tx.Commit(); err != nil {
			return fmt.Errorf(
				"commit stale login rate limit completion: %w",
				err,
			)
		}
		return nil
	}
	if !state.windowExpiresAt.After(state.databaseNow) {
		if err := resetLoginRateLimit(
			ctx,
			tx,
			attempt.ClientKey,
			policy.Window,
		); err != nil {
			return err
		}
		if err := tx.Commit(); err != nil {
			return fmt.Errorf(
				"commit expired login rate limit completion: %w",
				err,
			)
		}
		return nil
	}
	if state.inFlightCount == 0 {
		return errors.New(
			"login rate limit reservation is not active",
		)
	}
	var result sql.Result
	if failed {
		result, err = tx.ExecContext(ctx, `
UPDATE login_rate_limits
SET failure_count = failure_count + 1,
    in_flight_count = in_flight_count - 1,
    blocked_until =
        CASE WHEN failure_count + 1 >= ?
             THEN TIMESTAMPADD(
                 MICROSECOND, ?, UTC_TIMESTAMP(6)
             )
             ELSE blocked_until
        END
WHERE client_key = ?
  AND window_started_at = ?
  AND in_flight_count = ?`,
			policy.Threshold,
			policy.BlockDuration.Microseconds(),
			attempt.ClientKey[:],
			attempt.WindowStartedAt,
			state.inFlightCount,
		)
	} else {
		result, err = tx.ExecContext(ctx, `
UPDATE login_rate_limits
SET in_flight_count = in_flight_count - 1
WHERE client_key = ?
  AND window_started_at = ?
  AND in_flight_count = ?`,
			attempt.ClientKey[:],
			attempt.WindowStartedAt,
			state.inFlightCount,
		)
	}
	if err != nil {
		return fmt.Errorf(
			"complete login rate limit attempt: %w",
			err,
		)
	}
	if err := requireRateLimitRow(
		result,
		"complete login rate limit attempt",
	); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf(
			"commit login rate limit completion: %w",
			err,
		)
	}
	return nil
}

func readLoginRateLimitState(
	ctx context.Context,
	tx *sql.Tx,
	clientKey [32]byte,
) (loginRateLimitState, error) {
	var value loginRateLimitState
	err := tx.QueryRowContext(ctx, `
SELECT window_started_at, window_expires_at,
       failure_count, in_flight_count, blocked_until,
       UTC_TIMESTAMP(6)
FROM login_rate_limits
WHERE client_key = ?
FOR UPDATE`,
		clientKey[:],
	).Scan(
		&value.windowStartedAt,
		&value.windowExpiresAt,
		&value.failureCount,
		&value.inFlightCount,
		&value.blockedUntil,
		&value.databaseNow,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return loginRateLimitState{}, errors.New(
			"login rate limit state is missing",
		)
	}
	if err != nil {
		return loginRateLimitState{}, fmt.Errorf(
			"read login rate limit state: %w",
			err,
		)
	}
	return value, nil
}

func resetLoginRateLimit(
	ctx context.Context,
	tx *sql.Tx,
	clientKey [32]byte,
	window time.Duration,
) error {
	result, err := tx.ExecContext(ctx, `
UPDATE login_rate_limits
SET window_started_at = UTC_TIMESTAMP(6),
    window_expires_at =
        TIMESTAMPADD(MICROSECOND, ?, UTC_TIMESTAMP(6)),
    failure_count = 0,
    in_flight_count = 0,
    blocked_until = NULL
WHERE client_key = ?`,
		window.Microseconds(),
		clientKey[:],
	)
	if err != nil {
		return fmt.Errorf("reset login rate limit window: %w", err)
	}
	return requireRateLimitRow(result, "reset login rate limit window")
}

func requireRateLimitRow(result sql.Result, action string) error {
	affected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("inspect %s: %w", action, err)
	}
	if affected != 1 {
		return fmt.Errorf("%s affected %d rows, want 1", action, affected)
	}
	return nil
}

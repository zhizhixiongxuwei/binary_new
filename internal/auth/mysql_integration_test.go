package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-sql-driver/mysql"
)

const authIntegrationDSNFile = "BINARYSCAN_AUTH_INTEGRATION_DSN_FILE"

func TestMySQLLoginFailureLimitIntegration(t *testing.T) {
	dsnPath := strings.TrimSpace(os.Getenv(authIntegrationDSNFile))
	if dsnPath == "" {
		t.Skip(authIntegrationDSNFile + " is not set")
	}
	rawDSN, err := os.ReadFile(dsnPath)
	if err != nil {
		t.Fatalf("read integration DSN: %v", err)
	}
	driverConfig, err := mysql.ParseDSN(strings.TrimSpace(string(rawDSN)))
	if err != nil {
		t.Fatalf("parse integration DSN: %v", err)
	}
	driverConfig.ParseTime = true
	driverConfig.Loc = time.UTC
	database, err := sql.Open("mysql", driverConfig.FormatDSN())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := database.Close(); err != nil {
			t.Logf("close integration database: %v", err)
		}
	})

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	publicID := authIntegrationUUID(t)
	username := "auth-limit-" + strings.ReplaceAll(publicID[:13], "-", "")
	result, err := database.ExecContext(ctx, `
INSERT INTO users (
    public_id, username, display_name, password_hash, role, status,
    force_password_change
) VALUES (?, ?, 'Auth rate-limit fixture', 'not-used', 'reader', 'active', FALSE)`,
		publicID,
		username,
	)
	if err != nil {
		t.Fatal(err)
	}
	userID, err := result.LastInsertId()
	if err != nil || userID <= 0 {
		t.Fatalf("fixture user ID = %d, error = %v", userID, err)
	}
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(
			context.Background(),
			5*time.Second,
		)
		defer cleanupCancel()
		if _, err := database.ExecContext(
			cleanupCtx,
			"DELETE FROM users WHERE id = ?",
			userID,
		); err != nil {
			t.Logf("delete auth integration fixture: %v", err)
		}
	})

	repository := NewMySQLRepository(database)
	now := time.Date(2026, time.July, 31, 6, 0, 0, 0, time.UTC)
	lockUntil := now.Add(15 * time.Minute)
	for attempt := 0; attempt < 2; attempt++ {
		if err := repository.RecordLoginFailure(
			ctx,
			uint64(userID),
			2,
			now.Add(time.Duration(attempt)*time.Second),
			lockUntil,
		); err != nil {
			t.Fatal(err)
		}
	}

	var (
		failureCount uint32
		lockedUntil  *time.Time
	)
	if err := database.QueryRowContext(ctx, `
SELECT failed_login_count, locked_until
FROM users
WHERE id = ?`, userID).Scan(&failureCount, &lockedUntil); err != nil {
		t.Fatal(err)
	}
	if failureCount != 2 || lockedUntil == nil ||
		!lockedUntil.Equal(lockUntil) {
		t.Fatalf(
			"failure count/lock = %d/%v, want 2/%v",
			failureCount,
			lockedUntil,
			lockUntil,
		)
	}

	afterLock := lockUntil.Add(time.Second)
	if err := repository.RecordLoginFailure(
		ctx,
		uint64(userID),
		2,
		afterLock,
		afterLock.Add(15*time.Minute),
	); err != nil {
		t.Fatal(err)
	}
	if err := database.QueryRowContext(ctx, `
SELECT failed_login_count, locked_until
FROM users
WHERE id = ?`, userID).Scan(&failureCount, &lockedUntil); err != nil {
		t.Fatal(err)
	}
	if failureCount != 1 || lockedUntil != nil {
		t.Fatalf(
			"post-lock failure count/lock = %d/%v, want 1/nil",
			failureCount,
			lockedUntil,
		)
	}

	sessionID := authIntegrationUUID(t)
	currentExpiry := afterLock.Add(5 * time.Minute)
	tokenHash := make([]byte, 32)
	csrfHash := make([]byte, 32)
	if _, err := rand.Read(tokenHash); err != nil {
		t.Fatal(err)
	}
	if _, err := rand.Read(csrfHash); err != nil {
		t.Fatal(err)
	}
	if _, err := database.ExecContext(ctx, `
INSERT INTO sessions (
    id, user_id, token_hash, csrf_token_hash, expires_at, last_seen_at
) VALUES (?, ?, ?, ?, ?, ?)`,
		sessionID,
		userID,
		tokenHash,
		csrfHash,
		currentExpiry,
		afterLock,
	); err != nil {
		t.Fatal(err)
	}
	newExpiry := afterLock.Add(time.Hour)
	expiresAt, err := repository.RenewSession(
		ctx,
		sessionID,
		afterLock,
		afterLock.Add(30*time.Minute),
		newExpiry,
	)
	if err != nil {
		t.Fatal(err)
	}
	if !expiresAt.Equal(newExpiry) {
		t.Fatalf("renewed expiry = %v, want %v", expiresAt, newExpiry)
	}
	var storedExpiry time.Time
	if err := database.QueryRowContext(ctx, `
SELECT expires_at
FROM sessions
WHERE id = ?`, sessionID).Scan(&storedExpiry); err != nil {
		t.Fatal(err)
	}
	if !storedExpiry.Equal(newExpiry) {
		t.Fatalf("stored expiry = %v, want %v", storedExpiry, newExpiry)
	}

	policy := LoginRateLimitPolicy{
		Threshold:     4,
		Window:        30 * time.Second,
		BlockDuration: 5 * time.Minute,
	}
	var rateLimitKeys [][sha256.Size]byte
	registerRateLimitKey := func(key [sha256.Size]byte) {
		rateLimitKeys = append(rateLimitKeys, key)
	}
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(
			context.Background(),
			5*time.Second,
		)
		defer cleanupCancel()
		for _, key := range rateLimitKeys {
			if _, err := database.ExecContext(
				cleanupCtx,
				"DELETE FROM login_rate_limits WHERE client_key = ?",
				key[:],
			); err != nil {
				t.Logf("delete login limiter fixture: %v", err)
			}
		}
	})

	concurrentKey := authIntegrationClientKey(t)
	registerRateLimitKey(concurrentKey)
	type beginResult struct {
		attempt LoginAttempt
		err     error
	}
	beginResults := make(chan beginResult, 16)
	var begins sync.WaitGroup
	for index := 0; index < cap(beginResults); index++ {
		begins.Add(1)
		go func() {
			defer begins.Done()
			attempt, err := repository.BeginLoginAttempt(
				ctx,
				concurrentKey,
				policy,
			)
			beginResults <- beginResult{attempt: attempt, err: err}
		}()
	}
	begins.Wait()
	close(beginResults)
	var allowed []LoginAttempt
	limitedCount := 0
	for result := range beginResults {
		if result.err != nil {
			t.Fatal(result.err)
		}
		if result.attempt.Limited {
			limitedCount++
		} else {
			allowed = append(allowed, result.attempt)
		}
	}
	if len(allowed) != int(policy.Threshold) ||
		limitedCount != cap(beginResults)-int(policy.Threshold) {
		t.Fatalf(
			"concurrent allowed/limited = %d/%d, want %d/%d",
			len(allowed),
			limitedCount,
			policy.Threshold,
			cap(beginResults)-int(policy.Threshold),
		)
	}

	finishErrors := make(chan error, len(allowed))
	var finishes sync.WaitGroup
	for _, attempt := range allowed {
		attempt := attempt
		finishes.Add(1)
		go func() {
			defer finishes.Done()
			finishErrors <- repository.FinishLoginAttempt(
				ctx,
				attempt,
				true,
				policy,
			)
		}()
	}
	finishes.Wait()
	close(finishErrors)
	for finishErr := range finishErrors {
		if finishErr != nil {
			t.Fatal(finishErr)
		}
	}
	var (
		rateFailures    uint32
		rateInFlight    uint32
		blockMicrosLeft int64
	)
	if err := database.QueryRowContext(ctx, `
SELECT failure_count, in_flight_count,
       TIMESTAMPDIFF(
           MICROSECOND, UTC_TIMESTAMP(6), blocked_until
       )
FROM login_rate_limits
WHERE client_key = ?`,
		concurrentKey[:],
	).Scan(
		&rateFailures,
		&rateInFlight,
		&blockMicrosLeft,
	); err != nil {
		t.Fatal(err)
	}
	if rateFailures != policy.Threshold ||
		rateInFlight != 0 ||
		blockMicrosLeft <= 0 ||
		blockMicrosLeft > policy.BlockDuration.Microseconds() {
		t.Fatalf(
			"concurrent state failures/inflight/block = %d/%d/%d",
			rateFailures,
			rateInFlight,
			blockMicrosLeft,
		)
	}
	blockedAttempt, err := repository.BeginLoginAttempt(
		ctx,
		concurrentKey,
		policy,
	)
	if err != nil || !blockedAttempt.Limited ||
		blockedAttempt.RetryAfter <= 0 ||
		blockedAttempt.RetryAfter > policy.BlockDuration {
		t.Fatalf(
			"blocked attempt/error = %#v / %v",
			blockedAttempt,
			err,
		)
	}

	boundaryKey := authIntegrationClientKey(t)
	registerRateLimitKey(boundaryKey)
	if _, err := database.ExecContext(ctx, `
INSERT INTO login_rate_limits (
    client_key, window_started_at, window_expires_at,
    failure_count, in_flight_count, blocked_until
) VALUES (
    ?, TIMESTAMPADD(SECOND, -60, UTC_TIMESTAMP(6)),
    TIMESTAMPADD(MICROSECOND, 1, UTC_TIMESTAMP(6)),
    3, 0, NULL
)`, boundaryKey[:]); err != nil {
		t.Fatal(err)
	}
	if _, err := database.ExecContext(ctx, `
UPDATE login_rate_limits
SET window_expires_at = UTC_TIMESTAMP(6)
WHERE client_key = ?`, boundaryKey[:]); err != nil {
		t.Fatal(err)
	}
	boundaryAttempt, err := repository.BeginLoginAttempt(
		ctx,
		boundaryKey,
		policy,
	)
	if err != nil || boundaryAttempt.Limited {
		t.Fatalf(
			"boundary attempt/error = %#v / %v",
			boundaryAttempt,
			err,
		)
	}
	if err := database.QueryRowContext(ctx, `
SELECT failure_count, in_flight_count
FROM login_rate_limits
WHERE client_key = ?`, boundaryKey[:]).Scan(
		&rateFailures,
		&rateInFlight,
	); err != nil {
		t.Fatal(err)
	}
	if rateFailures != 0 || rateInFlight != 1 {
		t.Fatalf(
			"boundary failures/inflight = %d/%d, want 0/1",
			rateFailures,
			rateInFlight,
		)
	}
	if err := repository.FinishLoginAttempt(
		ctx,
		boundaryAttempt,
		false,
		policy,
	); err != nil {
		t.Fatal(err)
	}

	longBlockKey := authIntegrationClientKey(t)
	registerRateLimitKey(longBlockKey)
	if _, err := database.ExecContext(ctx, `
INSERT INTO login_rate_limits (
    client_key, window_started_at, window_expires_at,
    failure_count, in_flight_count, blocked_until
) VALUES (
    ?, TIMESTAMPADD(SECOND, -120, UTC_TIMESTAMP(6)),
    TIMESTAMPADD(SECOND, -60, UTC_TIMESTAMP(6)),
    4, 0, TIMESTAMPADD(SECOND, 30, UTC_TIMESTAMP(6))
)`, longBlockKey[:]); err != nil {
		t.Fatal(err)
	}
	longBlockedAttempt, err := repository.BeginLoginAttempt(
		ctx,
		longBlockKey,
		policy,
	)
	if err != nil || !longBlockedAttempt.Limited ||
		longBlockedAttempt.RetryAfter <= 0 {
		t.Fatalf(
			"long block attempt/error = %#v / %v",
			longBlockedAttempt,
			err,
		)
	}
	var (
		windowExpired bool
		blockActive   bool
	)
	if err := database.QueryRowContext(ctx, `
SELECT failure_count,
       window_expires_at <= UTC_TIMESTAMP(6),
       blocked_until > UTC_TIMESTAMP(6)
FROM login_rate_limits
WHERE client_key = ?`, longBlockKey[:]).Scan(
		&rateFailures,
		&windowExpired,
		&blockActive,
	); err != nil {
		t.Fatal(err)
	}
	if rateFailures != policy.Threshold ||
		!windowExpired ||
		!blockActive {
		t.Fatalf(
			"active block failures/window-expired/block-active = %d/%v/%v",
			rateFailures,
			windowExpired,
			blockActive,
		)
	}

	staleKey := authIntegrationClientKey(t)
	registerRateLimitKey(staleKey)
	if _, err := database.ExecContext(ctx, `
INSERT INTO login_rate_limits (
    client_key, window_started_at, window_expires_at,
    failure_count, in_flight_count, blocked_until,
    created_at, updated_at
) VALUES (
    ?, TIMESTAMPADD(DAY, -2, UTC_TIMESTAMP(6)),
    TIMESTAMPADD(DAY, -2, TIMESTAMPADD(SECOND, 1, UTC_TIMESTAMP(6))),
    0, 0, NULL,
    TIMESTAMPADD(DAY, -2, UTC_TIMESTAMP(6)),
    TIMESTAMPADD(DAY, -2, UTC_TIMESTAMP(6))
)`, staleKey[:]); err != nil {
		t.Fatal(err)
	}
	cleanupTriggerKey := authIntegrationClientKey(t)
	registerRateLimitKey(cleanupTriggerKey)
	cleanupAttempt, err := repository.BeginLoginAttempt(
		ctx,
		cleanupTriggerKey,
		policy,
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := repository.FinishLoginAttempt(
		ctx,
		cleanupAttempt,
		false,
		policy,
	); err != nil {
		t.Fatal(err)
	}
	var staleCount int
	if err := database.QueryRowContext(ctx, `
SELECT COUNT(*)
FROM login_rate_limits
WHERE client_key = ?`, staleKey[:]).Scan(&staleCount); err != nil {
		t.Fatal(err)
	}
	if staleCount != 0 {
		t.Fatalf("stale login limiter rows = %d, want 0", staleCount)
	}
}

func authIntegrationUUID(t *testing.T) string {
	t.Helper()
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		t.Fatal(err)
	}
	value[6] = (value[6] & 0x0f) | 0x40
	value[8] = (value[8] & 0x3f) | 0x80
	text := hex.EncodeToString(value[:])
	return text[0:8] + "-" + text[8:12] + "-" + text[12:16] + "-" +
		text[16:20] + "-" + text[20:32]
}

func authIntegrationClientKey(t *testing.T) [sha256.Size]byte {
	t.Helper()
	var value [sha256.Size]byte
	if _, err := rand.Read(value[:]); err != nil {
		t.Fatal(err)
	}
	return value
}

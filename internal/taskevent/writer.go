package taskevent

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
)

// AppendCurrentState persists the task row's already-advanced event sequence
// and current state. Callers must update the task and increment event_sequence
// in the same transaction before calling this function.
func AppendCurrentState(
	ctx context.Context,
	transaction *sql.Tx,
	taskID string,
	eventType string,
	message string,
) error {
	result, err := transaction.ExecContext(ctx, `
INSERT INTO task_events (
    task_id,
    event_sequence,
    event_type,
    stage,
    progress_basis_points,
    severity,
    message,
    payload,
    created_at
)
SELECT
    id,
    event_sequence,
    ?,
    stage,
    progress_basis_points,
    CASE
        WHEN status = 'FAILED' OR error_code IS NOT NULL THEN 'error'
        WHEN status IN ('PARTIAL_SUCCEEDED', 'CANCEL_REQUESTED')
            OR risk_level IN ('HIGH', 'CRITICAL') THEN 'warning'
        ELSE 'info'
    END,
    ?,
    JSON_OBJECT(
        'status', status,
        'stage', stage,
        'progress_basis_points', progress_basis_points,
        'risk_level', risk_level,
        'error_code', error_code,
        'error_message', error_message,
        'sample_expires_at', sample_expires_at,
        'sample_deleted_at', sample_deleted_at,
        'deleted_at', deleted_at
    ),
    UTC_TIMESTAMP(6)
FROM tasks
WHERE id = ?`, eventType, message, taskID)
	if err != nil {
		return fmt.Errorf("append task event: %w", err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("inspect appended task event: %w", err)
	}
	if affected != 1 {
		return fmt.Errorf("append task event: expected one task row, got %d", affected)
	}
	return nil
}

// AppendActivity persists a user-visible analyzer milestone against the task's
// already-advanced event sequence. The task snapshot fields remain in their
// normal columns; payload contains only the analyzer-specific safe metadata.
func AppendActivity(
	ctx context.Context,
	transaction *sql.Tx,
	taskID string,
	activity Activity,
) error {
	payload := activity.Payload
	if len(payload) == 0 {
		payload = json.RawMessage(`{}`)
	}
	result, err := transaction.ExecContext(ctx, `
INSERT INTO task_events (
    task_id,
    event_sequence,
    event_type,
    stage,
    progress_basis_points,
    severity,
    message,
    payload,
    created_at
)
SELECT
    id,
    event_sequence,
    ?,
    stage,
    progress_basis_points,
    ?,
    ?,
    ?,
    UTC_TIMESTAMP(6)
FROM tasks
WHERE id = ?`,
		activity.EventType,
		activity.Severity,
		activity.Message,
		[]byte(payload),
		taskID,
	)
	if err != nil {
		return fmt.Errorf("append task activity: %w", err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("inspect appended task activity: %w", err)
	}
	if affected != 1 {
		return fmt.Errorf(
			"append task activity: expected one task row, got %d",
			affected,
		)
	}
	return nil
}

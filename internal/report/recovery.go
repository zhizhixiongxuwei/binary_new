package report

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"binaryscan/internal/audit"
)

const MaxRecoveryBatch = 100

// RecoverExpired fences report generators that stopped heartbeating. A live
// generator can either renew first or be fenced first; it can never publish
// after this transaction changes the row to failed.
func (r *MySQLRepository) RecoverExpired(
	ctx context.Context,
	limit int,
) (int, error) {
	if limit < 1 || limit > MaxRecoveryBatch {
		return 0, errors.New(
			"report generation recovery limit must be between 1 and 100",
		)
	}
	tx, err := r.db.BeginTx(ctx, &sql.TxOptions{
		Isolation: sql.LevelReadCommitted,
	})
	if err != nil {
		return 0, fmt.Errorf("begin report generation recovery: %w", err)
	}
	defer tx.Rollback()

	rows, err := tx.QueryContext(ctx, `
SELECT id, task_id, generation_fence
FROM reports
WHERE status = 'generating'
  AND generation_lease_until <= UTC_TIMESTAMP(6)
ORDER BY generation_lease_until, id
LIMIT ?
FOR UPDATE SKIP LOCKED`, limit)
	if err != nil {
		return 0, fmt.Errorf("lock expired report generations: %w", err)
	}
	type expired struct {
		id, taskID string
		fence      uint64
	}
	values := make([]expired, 0, limit)
	for rows.Next() {
		var value expired
		if err := rows.Scan(&value.id, &value.taskID, &value.fence); err != nil {
			rows.Close()
			return 0, fmt.Errorf("scan expired report generation: %w", err)
		}
		values = append(values, value)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return 0, fmt.Errorf("iterate expired report generations: %w", err)
	}
	if err := rows.Close(); err != nil {
		return 0, fmt.Errorf("close expired report generations: %w", err)
	}
	for _, value := range values {
		result, err := tx.ExecContext(ctx, `
UPDATE reports
SET status = 'failed',
	    snapshot_state = 'stale',
    generation_fence = generation_fence + 1,
    generation_owner = NULL,
    generation_lease_until = NULL,
    generation_heartbeat_at = NULL,
    storage_key = NULL,
    sha256 = NULL,
    size_bytes = NULL,
    error_code = 'report_generator_lost',
    error_message = 'Report generation stopped before completion.',
    completed_at = UTC_TIMESTAMP(6)
WHERE id = ?
  AND task_id = ?
  AND status = 'generating'
	  AND snapshot_state = 'staged'
  AND generation_fence = ?
  AND generation_lease_until <= UTC_TIMESTAMP(6)`,
			value.id, value.taskID, value.fence,
		)
		if err != nil {
			return 0, fmt.Errorf("fence expired report generation: %w", err)
		}
		affected, err := result.RowsAffected()
		if err != nil {
			return 0, fmt.Errorf(
				"inspect expired report generation recovery: %w", err,
			)
		}
		if affected != 1 {
			return 0, errors.New(
				"expired report generation changed while locked",
			)
		}
		if err := audit.Append(ctx, tx, audit.Event{
			Action:     "report.generation_recovered",
			ObjectType: "report",
			ObjectID:   value.id,
			Outcome:    audit.OutcomeSuccess,
			Metadata: map[string]any{
				"task_id":       value.taskID,
				"expired_fence": value.fence,
			},
		}); err != nil {
			return 0, fmt.Errorf(
				"append report generation recovery audit: %w", err,
			)
		}
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("commit report generation recovery: %w", err)
	}
	return len(values), nil
}

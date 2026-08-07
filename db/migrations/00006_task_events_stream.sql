-- +goose NO TRANSACTION
-- +goose Up

-- MySQL does not support ADD COLUMN IF NOT EXISTS. Use a prepared statement
-- so a retry after partially committed DDL is safe without a stored procedure.
SET @event_sequence_exists = (
    SELECT COUNT(*)
    FROM information_schema.columns
    WHERE table_schema = DATABASE()
      AND table_name = 'tasks'
      AND column_name = 'event_sequence'
);
SET @event_sequence_ddl = IF(
    @event_sequence_exists = 0,
    'ALTER TABLE tasks ADD COLUMN event_sequence BIGINT UNSIGNED NOT NULL DEFAULT 0 AFTER deleted_at',
    'SELECT 1'
);
PREPARE event_sequence_statement FROM @event_sequence_ddl;
EXECUTE event_sequence_statement;
DEALLOCATE PREPARE event_sequence_statement;

-- Preserve any event history written before this migration, then append one
-- complete snapshot so every existing task has a resumable stream position.
-- Runtime writers advance this counter and insert the matching event in the
-- same transaction; no trigger or elevated MySQL privilege is required.
UPDATE tasks AS task
LEFT JOIN (
    SELECT task_id, MAX(event_sequence) AS max_sequence
    FROM task_events
    GROUP BY task_id
) AS existing ON existing.task_id = task.id
SET task.event_sequence = COALESCE(existing.max_sequence, 0) + 1;

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
    task.id,
    task.event_sequence,
    'task.snapshot',
    task.stage,
    task.progress_basis_points,
    CASE
        WHEN task.status = 'FAILED' OR task.error_code IS NOT NULL THEN 'error'
        WHEN task.status IN ('PARTIAL_SUCCEEDED', 'CANCEL_REQUESTED')
            OR task.risk_level IN ('HIGH', 'CRITICAL') THEN 'warning'
        ELSE 'info'
    END,
    'Existing task state captured.',
    JSON_OBJECT(
        'status', task.status,
        'stage', task.stage,
        'progress_basis_points', task.progress_basis_points,
        'risk_level', task.risk_level,
        'error_code', task.error_code,
        'error_message', task.error_message,
        'sample_expires_at', task.sample_expires_at,
        'sample_deleted_at', task.sample_deleted_at,
        'deleted_at', task.deleted_at
    ),
    CURRENT_TIMESTAMP(6)
FROM tasks AS task;

-- +goose Down

SET @event_sequence_exists = (
    SELECT COUNT(*)
    FROM information_schema.columns
    WHERE table_schema = DATABASE()
      AND table_name = 'tasks'
      AND column_name = 'event_sequence'
);
SET @event_sequence_ddl = IF(
    @event_sequence_exists = 1,
    'ALTER TABLE tasks DROP COLUMN event_sequence',
    'SELECT 1'
);
PREPARE event_sequence_statement FROM @event_sequence_ddl;
EXECUTE event_sequence_statement;
DEALLOCATE PREPARE event_sequence_statement;

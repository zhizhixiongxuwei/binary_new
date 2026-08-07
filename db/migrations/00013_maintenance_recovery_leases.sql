-- +goose Up

ALTER TABLE reports
    ADD COLUMN generation_fence BIGINT UNSIGNED NOT NULL DEFAULT 0
        AFTER status,
    ADD COLUMN generation_owner VARCHAR(255) CHARACTER SET ascii
        COLLATE ascii_bin NULL AFTER generation_fence,
    ADD COLUMN generation_lease_until TIMESTAMP(6) NULL
        AFTER generation_owner,
    ADD COLUMN generation_heartbeat_at TIMESTAMP(6) NULL
        AFTER generation_lease_until,
    ADD KEY idx_reports_generation_lease (
        status, generation_lease_until, id
    );

UPDATE reports
SET status = 'failed',
    generation_fence = 1,
    error_code = 'report_generator_lost',
    error_message = 'Report generation stopped before lease tracking was enabled.',
    completed_at = COALESCE(completed_at, UTC_TIMESTAMP(6))
WHERE status = 'generating';

CREATE TABLE IF NOT EXISTS task_sample_retention_operations (
    task_id CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    status VARCHAR(24) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    fencing_token BIGINT UNSIGNED NOT NULL DEFAULT 0,
    attempt_count INT UNSIGNED NOT NULL DEFAULT 0,
    lease_owner VARCHAR(255) CHARACTER SET ascii COLLATE ascii_bin NULL,
    lease_until TIMESTAMP(6) NULL,
    last_error_code VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NULL,
    started_at TIMESTAMP(6) NULL,
    completed_at TIMESTAMP(6) NULL,
    created_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6)
        ON UPDATE CURRENT_TIMESTAMP(6),
    PRIMARY KEY (task_id),
    KEY idx_task_sample_retention_ready (status, lease_until, updated_at),
    CONSTRAINT fk_task_sample_retention_task
        FOREIGN KEY (task_id) REFERENCES tasks (id) ON DELETE RESTRICT,
    CONSTRAINT chk_task_sample_retention_status CHECK (
        status IN ('cleaning', 'failed', 'completed')
    ),
    CONSTRAINT chk_task_sample_retention_fence CHECK (fencing_token > 0),
    CONSTRAINT chk_task_sample_retention_attempt CHECK (attempt_count > 0),
    CONSTRAINT chk_task_sample_retention_lease CHECK (
        (
            status = 'cleaning' AND lease_owner IS NOT NULL AND
            lease_until IS NOT NULL AND completed_at IS NULL
        ) OR (
            status = 'failed' AND lease_owner IS NULL AND
            lease_until IS NULL AND completed_at IS NULL
        ) OR (
            status = 'completed' AND lease_owner IS NULL AND
            lease_until IS NULL AND completed_at IS NOT NULL
        )
    )
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- +goose Down

DROP TABLE IF EXISTS task_sample_retention_operations;

ALTER TABLE reports
    DROP INDEX idx_reports_generation_lease,
    DROP COLUMN generation_heartbeat_at,
    DROP COLUMN generation_lease_until,
    DROP COLUMN generation_owner,
    DROP COLUMN generation_fence;

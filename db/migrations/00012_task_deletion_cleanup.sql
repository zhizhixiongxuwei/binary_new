-- +goose Up

CREATE TABLE IF NOT EXISTS task_deletion_operations (
    task_id CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    status VARCHAR(24) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    fencing_token BIGINT UNSIGNED NOT NULL DEFAULT 0,
    attempt_count INT UNSIGNED NOT NULL DEFAULT 0,
    lease_owner VARCHAR(255) CHARACTER SET ascii COLLATE ascii_bin NULL,
    lease_until TIMESTAMP(6) NULL,
    last_error_code VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NULL,
    last_error_message VARCHAR(2048) NULL,
    started_at TIMESTAMP(6) NULL,
    completed_at TIMESTAMP(6) NULL,
    created_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6)
        ON UPDATE CURRENT_TIMESTAMP(6),
    PRIMARY KEY (task_id),
    KEY idx_task_deletion_operations_ready (status, lease_until, updated_at),
    CONSTRAINT fk_task_deletion_operations_task
        FOREIGN KEY (task_id) REFERENCES tasks (id) ON DELETE RESTRICT,
    CONSTRAINT chk_task_deletion_operations_status CHECK (
        status IN ('cleaning', 'failed', 'completed')
    ),
    CONSTRAINT chk_task_deletion_operations_fence CHECK (
        fencing_token > 0
    ),
    CONSTRAINT chk_task_deletion_operations_attempts CHECK (
        attempt_count > 0
    ),
    CONSTRAINT chk_task_deletion_operations_lease CHECK (
        (
            status = 'cleaning' AND
            lease_owner IS NOT NULL AND
            lease_until IS NOT NULL AND
            completed_at IS NULL
        ) OR (
            status = 'failed' AND
            lease_owner IS NULL AND
            lease_until IS NULL AND
            completed_at IS NULL
        ) OR (
            status = 'completed' AND
            lease_owner IS NULL AND
            lease_until IS NULL AND
            completed_at IS NOT NULL
        )
    )
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- +goose Down

DROP TABLE IF EXISTS task_deletion_operations;

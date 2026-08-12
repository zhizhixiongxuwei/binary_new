-- +goose NO TRANSACTION
-- +goose Up

ALTER TABLE decompile_source_projects
    ADD COLUMN deletion_generation BIGINT UNSIGNED NOT NULL DEFAULT 0
        AFTER storage_deleted_at;

CREATE TABLE IF NOT EXISTS source_project_deletion_tokens (
    token_hash CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    user_id BIGINT UNSIGNED NOT NULL,
    project_id CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    project_generation BIGINT UNSIGNED NOT NULL,
    impact_counts_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    expires_at TIMESTAMP(6) NOT NULL,
    used_at TIMESTAMP(6) NULL,
    created_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    PRIMARY KEY (token_hash),
    KEY idx_source_project_deletion_tokens_expiry (expires_at, token_hash),
    KEY idx_source_project_deletion_tokens_used (used_at, token_hash),
    KEY idx_source_project_deletion_tokens_project (
        project_id, project_generation, expires_at
    ),
    CONSTRAINT fk_source_project_deletion_token_user
        FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
    CONSTRAINT fk_source_project_deletion_token_project
        FOREIGN KEY (project_id)
        REFERENCES decompile_source_projects (id) ON DELETE CASCADE,
    CONSTRAINT chk_source_project_deletion_token_hash CHECK (
        token_hash REGEXP '^[0-9a-f]{64}$' AND
        impact_counts_sha256 REGEXP '^[0-9a-f]{64}$'
    ),
    CONSTRAINT chk_source_project_deletion_token_expiry CHECK (
        expires_at > created_at AND (used_at IS NULL OR used_at >= created_at)
    )
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE IF NOT EXISTS source_project_deletion_operations (
    id CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    project_id CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    task_id CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    requested_by_user_id BIGINT UNSIGNED NULL,
    project_generation BIGINT UNSIGNED NOT NULL,
    status VARCHAR(24) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    impact_counts_json JSON NOT NULL,
    impact_counts_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    storage_scope VARCHAR(1024) CHARACTER SET ascii COLLATE ascii_bin NULL,
    attempt_count INT UNSIGNED NOT NULL DEFAULT 0,
    fencing_token BIGINT UNSIGNED NOT NULL DEFAULT 0,
    lease_owner VARCHAR(255) CHARACTER SET ascii COLLATE ascii_bin NULL,
    lease_until TIMESTAMP(6) NULL,
    available_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    last_error_code VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NULL,
    last_error_message VARCHAR(2048) NULL,
    created_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6)
        ON UPDATE CURRENT_TIMESTAMP(6),
    completed_at TIMESTAMP(6) NULL,
    active_project_id CHAR(36) CHARACTER SET ascii COLLATE ascii_bin
        GENERATED ALWAYS AS (
            CASE
                WHEN status IN ('pending', 'cancelling', 'deleting', 'failed')
                THEN project_id
                ELSE NULL
            END
        ) STORED,
    PRIMARY KEY (id),
    UNIQUE KEY uq_source_project_deletion_active (active_project_id),
    KEY idx_source_project_deletion_ready (
        status, available_at, lease_until, id
    ),
    KEY idx_source_project_deletion_task (task_id, created_at, id),
    KEY idx_source_project_deletion_requester (
        requested_by_user_id, created_at, id
    ),
    CONSTRAINT fk_source_project_deletion_operation_project
        FOREIGN KEY (task_id, project_id)
        REFERENCES decompile_source_projects (task_id, id) ON DELETE RESTRICT,
    CONSTRAINT fk_source_project_deletion_operation_task
        FOREIGN KEY (task_id) REFERENCES tasks (id) ON DELETE RESTRICT,
    CONSTRAINT fk_source_project_deletion_operation_requester
        FOREIGN KEY (requested_by_user_id)
        REFERENCES users (id) ON DELETE SET NULL,
    CONSTRAINT chk_source_project_deletion_operation_status CHECK (
        status IN ('pending', 'cancelling', 'deleting', 'complete', 'failed')
    ),
    CONSTRAINT chk_source_project_deletion_operation_digest CHECK (
        impact_counts_sha256 REGEXP '^[0-9a-f]{64}$'
    ),
    CONSTRAINT chk_source_project_deletion_operation_counts CHECK (
        JSON_TYPE(impact_counts_json) = 'OBJECT' AND
        OCTET_LENGTH(impact_counts_json) <= 4096
    ),
    CONSTRAINT chk_source_project_deletion_operation_scope CHECK (
        storage_scope IS NULL OR storage_scope REGEXP
            '^source-projects/[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
    ),
    CONSTRAINT chk_source_project_deletion_operation_lease CHECK (
        (status = 'deleting' AND attempt_count > 0 AND fencing_token > 0 AND
            lease_owner IS NOT NULL AND lease_until IS NOT NULL AND
            completed_at IS NULL) OR
        (status IN ('pending', 'cancelling', 'failed') AND
            lease_owner IS NULL AND lease_until IS NULL AND
            completed_at IS NULL) OR
        (status = 'complete' AND lease_owner IS NULL AND lease_until IS NULL AND
            completed_at IS NOT NULL)
    ),
    CONSTRAINT chk_source_project_deletion_operation_error CHECK (
        (status = 'failed' AND last_error_code IS NOT NULL AND
            last_error_message IS NOT NULL) OR
        (status <> 'failed' AND last_error_code IS NULL AND
            last_error_message IS NULL)
    )
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- +goose Down

DROP TABLE IF EXISTS source_project_deletion_operations;
DROP TABLE IF EXISTS source_project_deletion_tokens;

ALTER TABLE decompile_source_projects
    DROP COLUMN deletion_generation;

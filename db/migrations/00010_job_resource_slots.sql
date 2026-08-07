-- +goose NO TRANSACTION
-- +goose Up

CREATE TABLE IF NOT EXISTS job_resource_slots (
    pool VARCHAR(16) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    slot_number TINYINT UNSIGNED NOT NULL,
    job_id CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NULL,
    job_fencing_token BIGINT UNSIGNED NULL,
    lease_owner VARCHAR(255) CHARACTER SET ascii COLLATE ascii_bin NULL,
    acquired_at TIMESTAMP(6) NULL,
    updated_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6)
        ON UPDATE CURRENT_TIMESTAMP(6),
    PRIMARY KEY (pool, slot_number),
    UNIQUE KEY uq_job_resource_slots_job_pool (job_id, pool),
    KEY idx_job_resource_slots_job_fence (job_id, job_fencing_token),
    CONSTRAINT fk_job_resource_slots_job FOREIGN KEY (job_id)
        REFERENCES jobs (id) ON DELETE RESTRICT,
    CONSTRAINT chk_job_resource_slots_pool CHECK (
        pool IN ('global', 'trivy')
    ),
    CONSTRAINT chk_job_resource_slots_number CHECK (
        slot_number BETWEEN 1 AND 4
    ),
    CONSTRAINT chk_job_resource_slots_holder CHECK (
        (
            job_id IS NULL AND
            job_fencing_token IS NULL AND
            lease_owner IS NULL AND
            acquired_at IS NULL
        ) OR (
            job_id IS NOT NULL AND
            job_fencing_token IS NOT NULL AND
            job_fencing_token > 0 AND
            lease_owner IS NOT NULL AND
            acquired_at IS NOT NULL
        )
    )
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

INSERT IGNORE INTO job_resource_slots (
    pool,
    slot_number
) VALUES
    ('global', 1),
    ('global', 2),
    ('global', 3),
    ('global', 4),
    ('trivy', 1),
    ('trivy', 2),
    ('trivy', 3),
    ('trivy', 4);

CREATE TABLE IF NOT EXISTS job_resource_limits (
    id TINYINT UNSIGNED NOT NULL,
    heavy_slots TINYINT UNSIGNED NOT NULL,
    trivy_slots TINYINT UNSIGNED NOT NULL,
    generation BIGINT UNSIGNED NOT NULL DEFAULT 1,
    updated_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6)
        ON UPDATE CURRENT_TIMESTAMP(6),
    PRIMARY KEY (id),
    CONSTRAINT chk_job_resource_limits_singleton CHECK (id = 1),
    CONSTRAINT chk_job_resource_limits_heavy CHECK (
        heavy_slots BETWEEN 2 AND 4
    ),
    CONSTRAINT chk_job_resource_limits_trivy CHECK (
        trivy_slots BETWEEN 1 AND heavy_slots
    )
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

INSERT IGNORE INTO job_resource_limits (
    id,
    heavy_slots,
    trivy_slots
) VALUES (1, 2, 1);

-- +goose Down

DROP TABLE IF EXISTS job_resource_limits;
DROP TABLE IF EXISTS job_resource_slots;

-- +goose NO TRANSACTION
-- +goose Up

ALTER TABLE job_resource_slots
    DROP CHECK chk_job_resource_slots_pool,
    ADD CONSTRAINT chk_job_resource_slots_pool CHECK (
        pool IN ('global', 'trivy', 'native')
    );

INSERT IGNORE INTO job_resource_slots (
    pool,
    slot_number
) VALUES
    ('native', 1),
    ('native', 2),
    ('native', 3),
    ('native', 4);

ALTER TABLE job_resource_limits
    ADD COLUMN native_slots TINYINT UNSIGNED NOT NULL DEFAULT 1
        AFTER trivy_slots,
    ADD CONSTRAINT chk_job_resource_limits_native CHECK (
        native_slots BETWEEN 1 AND heavy_slots
    );

-- +goose Down

ALTER TABLE job_resource_limits
    DROP CHECK chk_job_resource_limits_native,
    DROP COLUMN native_slots;

DELETE FROM job_resource_slots
WHERE pool = 'native';

ALTER TABLE job_resource_slots
    DROP CHECK chk_job_resource_slots_pool,
    ADD CONSTRAINT chk_job_resource_slots_pool CHECK (
        pool IN ('global', 'trivy')
    );

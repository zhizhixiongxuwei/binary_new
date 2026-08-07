-- +goose NO TRANSACTION
-- +goose Up

ALTER TABLE uploads
    DROP CHECK chk_uploads_declared_size,
    ADD CONSTRAINT chk_uploads_declared_size CHECK (
        declared_size_bytes <= 2147483648 OR
        status IN ('completed', 'failed', 'expired', 'cancelled')
    );

ALTER TABLE job_resource_limits
    DROP CHECK chk_job_resource_limits_heavy;

UPDATE job_resource_limits
SET heavy_slots = 1,
    trivy_slots = 1,
    native_slots = 1,
    generation = generation + 1,
    updated_at = UTC_TIMESTAMP(6)
WHERE id = 1;

ALTER TABLE job_resource_limits
    ADD CONSTRAINT chk_job_resource_limits_heavy CHECK (
        heavy_slots BETWEEN 1 AND 2
    );

-- +goose Down

UPDATE job_resource_limits
SET heavy_slots = 2,
    trivy_slots = 1,
    native_slots = 1,
    generation = generation + 1,
    updated_at = UTC_TIMESTAMP(6)
WHERE id = 1;

ALTER TABLE job_resource_limits
    DROP CHECK chk_job_resource_limits_heavy,
    ADD CONSTRAINT chk_job_resource_limits_heavy CHECK (
        heavy_slots BETWEEN 2 AND 4
    );

ALTER TABLE uploads
    DROP CHECK chk_uploads_declared_size,
    ADD CONSTRAINT chk_uploads_declared_size CHECK (
        declared_size_bytes <= 10737418240
    );

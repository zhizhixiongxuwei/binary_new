-- +goose NO TRANSACTION
-- +goose Up

ALTER TABLE jobs
    DROP INDEX idx_jobs_claim,
    ADD INDEX idx_jobs_claim (
        kind,
        status,
        priority DESC,
        available_at,
        id
    );

-- +goose Down

ALTER TABLE jobs
    DROP INDEX idx_jobs_claim,
    ADD INDEX idx_jobs_claim (
        kind,
        status,
        priority DESC,
        available_at,
        lease_until,
        id
    );

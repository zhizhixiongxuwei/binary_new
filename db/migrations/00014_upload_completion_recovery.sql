-- +goose Up

ALTER TABLE uploads
    ADD COLUMN parts_cleaned_at TIMESTAMP(6) NULL AFTER completed_at,
    ADD KEY idx_uploads_parts_cleanup (
        status, parts_cleaned_at, updated_at, id
    );

-- Existing terminal rows are intentionally left pending. The maintenance
-- worker will run the same path-confined, idempotent cleanup used for new
-- uploads before recording parts_cleaned_at.

-- +goose Down

ALTER TABLE uploads
    DROP INDEX idx_uploads_parts_cleanup,
    DROP COLUMN parts_cleaned_at;

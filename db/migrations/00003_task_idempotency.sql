-- +goose NO TRANSACTION
-- +goose Up

ALTER TABLE tasks
    ADD COLUMN idempotency_key VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NULL
        AFTER upload_id,
    ADD UNIQUE KEY uq_tasks_creator_idempotency (created_by, idempotency_key);

-- +goose Down

ALTER TABLE tasks
    DROP INDEX uq_tasks_creator_idempotency,
    DROP COLUMN idempotency_key;

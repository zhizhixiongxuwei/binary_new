-- +goose NO TRANSACTION
-- +goose Up

ALTER TABLE tasks
    ADD INDEX idx_tasks_created_id (created_at DESC, id DESC);

-- +goose Down

ALTER TABLE tasks
    DROP INDEX idx_tasks_created_id;

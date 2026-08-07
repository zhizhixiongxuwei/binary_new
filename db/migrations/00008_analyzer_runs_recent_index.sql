-- +goose NO TRANSACTION
-- +goose Up

ALTER TABLE analyzer_runs
    ADD INDEX idx_analyzer_runs_recent (created_at DESC, id DESC);

-- +goose Down

ALTER TABLE analyzer_runs
    DROP INDEX idx_analyzer_runs_recent;

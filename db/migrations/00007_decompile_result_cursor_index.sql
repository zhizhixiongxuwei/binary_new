-- +goose NO TRANSACTION
-- +goose Up

ALTER TABLE decompile_results
    ADD INDEX idx_decompile_results_task_created_id (
        task_id,
        created_at,
        id
    );

-- +goose Down

ALTER TABLE decompile_results
    DROP INDEX idx_decompile_results_task_created_id;

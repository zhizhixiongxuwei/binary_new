-- +goose NO TRANSACTION
-- +goose Up

ALTER TABLE analyzer_runs
    ADD COLUMN cache_identity CHAR(64)
        CHARACTER SET ascii COLLATE ascii_bin NULL
        AFTER parameters_json,
    ADD INDEX idx_analyzer_runs_bytecode_cache (
        cache_identity,
        status,
        completed_at,
        id
    );

-- +goose Down

ALTER TABLE analyzer_runs
    DROP INDEX idx_analyzer_runs_bytecode_cache,
    DROP COLUMN cache_identity;

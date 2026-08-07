-- +goose NO TRANSACTION
-- +goose Up

ALTER TABLE reports
    ADD KEY idx_reports_storage_key (storage_key);

ALTER TABLE decompile_results
    ADD KEY idx_decompile_results_storage_key (storage_key);

-- +goose Down

ALTER TABLE decompile_results
    DROP INDEX idx_decompile_results_storage_key;

ALTER TABLE reports
    DROP INDEX idx_reports_storage_key;

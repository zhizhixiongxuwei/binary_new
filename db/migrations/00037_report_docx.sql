-- +goose NO TRANSACTION
-- +goose Up
ALTER TABLE reports
    DROP CHECK chk_reports_format,
    ADD CONSTRAINT chk_reports_format CHECK (format IN ('json', 'html', 'docx'));

-- +goose Down
ALTER TABLE reports
    DROP CHECK chk_reports_format,
    ADD CONSTRAINT chk_reports_format CHECK (format IN ('json', 'html'));

-- +goose NO TRANSACTION
-- +goose Up
ALTER TABLE uploads
    ADD COLUMN content_type VARCHAR(255) CHARACTER SET ascii COLLATE ascii_bin
        NOT NULL DEFAULT 'application/octet-stream'
    AFTER display_name;

-- +goose Down
ALTER TABLE uploads DROP COLUMN content_type;

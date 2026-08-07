-- +goose Up

ALTER TABLE file_nodes
    ADD COLUMN archive_name_id VARCHAR(2740)
        CHARACTER SET ascii COLLATE ascii_bin NULL
        AFTER display_name;

-- archive_name_id is either b64:<RFC4648 bytes> for archive names up to the
-- accepted 2048-byte path ceiling, or sha256:<lowercase digest> for an
-- overlong rejected name. Existing root and synthetic nodes remain NULL.

-- +goose Down

ALTER TABLE file_nodes
    DROP COLUMN archive_name_id;

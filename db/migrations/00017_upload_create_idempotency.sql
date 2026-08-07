-- +goose Up

ALTER TABLE uploads
    DROP INDEX uq_uploads_creator_idempotency,
    ADD COLUMN idempotency_operation VARCHAR(32) CHARACTER SET ascii
        COLLATE ascii_bin NULL AFTER idempotency_key,
    ADD COLUMN request_fingerprint CHAR(64) CHARACTER SET ascii
        COLLATE ascii_bin NULL AFTER idempotency_operation,
    ADD UNIQUE KEY uq_uploads_creator_operation_idempotency (
        created_by, idempotency_operation, idempotency_key
    );

-- Legacy rows may contain an idempotency_key written before request
-- fingerprints were introduced. New upload creation always writes all three
-- fields; legacy NULL operation values remain isolated from the new scope.

-- +goose Down

ALTER TABLE uploads
    DROP INDEX uq_uploads_creator_operation_idempotency,
    DROP COLUMN request_fingerprint,
    DROP COLUMN idempotency_operation,
    ADD UNIQUE KEY uq_uploads_creator_idempotency (
        created_by, idempotency_key
    );

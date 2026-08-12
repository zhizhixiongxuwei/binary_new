-- +goose NO TRANSACTION
-- +goose Up

CREATE TABLE IF NOT EXISTS upload_intake_profiles (
    upload_id CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    input_category VARCHAR(16) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    detected_category VARCHAR(16) CHARACTER SET ascii COLLATE ascii_bin NULL,
    detected_format VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NULL,
    validation_status VARCHAR(24) CHARACTER SET ascii COLLATE ascii_bin
        NOT NULL DEFAULT 'pending',
    validation_error_code VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NULL,
    validation_error_message VARCHAR(2048) NULL,
    source_kind VARCHAR(24) CHARACTER SET ascii COLLATE ascii_bin
        NOT NULL DEFAULT 'direct',
    source_parent_upload_id CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NULL,
    source_archive_name VARCHAR(512) NULL,
    source_entry_path VARCHAR(2048) NULL,
    archive_import_id CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NULL,
    validated_at TIMESTAMP(6) NULL,
    created_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6)
        ON UPDATE CURRENT_TIMESTAMP(6),
    PRIMARY KEY (upload_id),
    UNIQUE KEY uq_upload_intake_archive_import (archive_import_id),
    KEY idx_upload_intake_validation (
        validation_status, updated_at, upload_id
    ),
    KEY idx_upload_intake_source_parent (
        source_parent_upload_id, upload_id
    ),
    CONSTRAINT fk_upload_intake_upload
        FOREIGN KEY (upload_id) REFERENCES uploads (id) ON DELETE CASCADE,
    CONSTRAINT chk_upload_intake_input_category CHECK (
        input_category IN ('binary', 'archive', 'container')
    ),
    CONSTRAINT chk_upload_intake_detected_category CHECK (
        detected_category IS NULL OR
        detected_category IN ('binary', 'archive', 'container')
    ),
    CONSTRAINT chk_upload_intake_validation_status CHECK (
        validation_status IN ('pending', 'valid', 'mismatch', 'unsupported')
    ),
    CONSTRAINT chk_upload_intake_source_kind CHECK (
        source_kind IN ('direct', 'archive_entry')
    ),
    CONSTRAINT chk_upload_intake_source_fields CHECK (
        (
            source_kind = 'direct' AND
            source_parent_upload_id IS NULL AND
            source_archive_name IS NULL AND
            source_entry_path IS NULL
        ) OR (
            source_kind = 'archive_entry' AND
            input_category IN ('binary', 'container') AND
            source_parent_upload_id IS NOT NULL AND
            source_archive_name IS NOT NULL AND
            source_entry_path IS NOT NULL
        )
    ),
    CONSTRAINT chk_upload_intake_validation_fields CHECK (
        (
            validation_status = 'pending' AND
            detected_category IS NULL AND
            detected_format IS NULL AND
            validation_error_code IS NULL AND
            validation_error_message IS NULL AND
            validated_at IS NULL
        ) OR (
            validation_status = 'valid' AND
            detected_category IS NOT NULL AND
            detected_category = input_category AND
            detected_format IS NOT NULL AND
            validation_error_code IS NULL AND
            validation_error_message IS NULL AND
            validated_at IS NOT NULL
        ) OR (
            validation_status = 'mismatch' AND
            detected_category IS NOT NULL AND
            detected_category <> input_category AND
            detected_format IS NOT NULL AND
            validation_error_code IS NOT NULL AND
            validation_error_message IS NOT NULL AND
            validated_at IS NOT NULL
        ) OR (
            validation_status = 'unsupported' AND
            detected_category IS NULL AND
            detected_format IS NOT NULL AND
            validation_error_code IS NOT NULL AND
            validation_error_message IS NOT NULL AND
            validated_at IS NOT NULL
        )
    )
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- +goose Down

-- Intake profiles are the only durable record of the user's immutable input
-- category and archive-entry provenance. Refuse a lossy rollback after any
-- profile has been created.
DROP TABLE IF EXISTS binaryscan_migration_34_rollback_guard;
CREATE TABLE binaryscan_migration_34_rollback_guard (
    allowed TINYINT NOT NULL,
    CONSTRAINT chk_no_upload_intake_before_rollback CHECK (allowed = 1)
) ENGINE=InnoDB;
INSERT INTO binaryscan_migration_34_rollback_guard (allowed)
SELECT 0
FROM upload_intake_profiles
LIMIT 1;
DROP TABLE binaryscan_migration_34_rollback_guard;

DROP TABLE IF EXISTS upload_intake_profiles;

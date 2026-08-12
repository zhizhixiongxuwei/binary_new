-- +goose NO TRANSACTION
-- +goose Up

CREATE TABLE IF NOT EXISTS archive_imports (
    id CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    upload_id CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    created_by BIGINT UNSIGNED NOT NULL,
    root_format VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    source_blob_id BIGINT UNSIGNED NOT NULL,
    source_storage_key VARCHAR(512) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    source_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    source_size_bytes BIGINT UNSIGNED NOT NULL,
    source_blob_reference_released_at TIMESTAMP(6) NULL,
    status VARCHAR(24) CHARACTER SET ascii COLLATE ascii_bin NOT NULL DEFAULT 'queued',
    attempt INT UNSIGNED NOT NULL DEFAULT 0,
    max_attempts INT UNSIGNED NOT NULL DEFAULT 3,
    fencing_token BIGINT UNSIGNED NOT NULL DEFAULT 0,
    available_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    lease_owner VARCHAR(255) CHARACTER SET ascii COLLATE ascii_bin NULL,
    lease_until TIMESTAMP(6) NULL,
    heartbeat_at TIMESTAMP(6) NULL,
    limits_snapshot JSON NOT NULL,
    scanned_entries INT UNSIGNED NOT NULL DEFAULT 0,
    total_entries INT UNSIGNED NOT NULL DEFAULT 0,
    eligible_entries INT UNSIGNED NOT NULL DEFAULT 0,
    skipped_entries INT UNSIGNED NOT NULL DEFAULT 0,
    created_tasks INT UNSIGNED NOT NULL DEFAULT 0,
    expanded_bytes BIGINT UNSIGNED NOT NULL DEFAULT 0,
    error_code VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NULL,
    error_message VARCHAR(2048) NULL,
    started_at TIMESTAMP(6) NULL,
    completed_at TIMESTAMP(6) NULL,
    deleted_at TIMESTAMP(6) NULL,
    created_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
    PRIMARY KEY (id),
    UNIQUE KEY uq_archive_imports_upload (upload_id),
    KEY idx_archive_imports_claim (status, available_at, lease_until, id),
    KEY idx_archive_imports_owner_created (created_by, created_at, id),
    KEY idx_archive_imports_lease (status, lease_until),
    KEY idx_archive_imports_source_blob (source_blob_id, source_blob_reference_released_at),
    CONSTRAINT fk_archive_imports_upload FOREIGN KEY (upload_id) REFERENCES uploads (id) ON DELETE RESTRICT,
    CONSTRAINT fk_archive_imports_creator FOREIGN KEY (created_by) REFERENCES users (id),
    CONSTRAINT fk_archive_imports_source_blob FOREIGN KEY (source_blob_id) REFERENCES blobs (id),
    CONSTRAINT chk_archive_imports_root_format CHECK (root_format IN (
        'zip', '7z', 'rar', 'tar', 'gzip', 'bzip2', 'xz', 'zstd',
        'cab', 'cpio', 'ar', 'deb', 'rpm'
    )),
    CONSTRAINT chk_archive_imports_status CHECK (status IN (
        'queued', 'running', 'ready', 'failed', 'deleting', 'deleted'
    )),
    CONSTRAINT chk_archive_imports_attempts CHECK (attempt <= max_attempts),
    CONSTRAINT chk_archive_imports_source_key CHECK (
        source_storage_key = CONCAT(
            'blobs/sha256/', LEFT(source_sha256, 2), '/', source_sha256
        )
    ),
    CONSTRAINT chk_archive_imports_lease_state CHECK (
        (status = 'running' AND lease_owner IS NOT NULL AND lease_until IS NOT NULL) OR
        (status <> 'running' AND lease_owner IS NULL AND lease_until IS NULL)
    )
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- DDL is implicitly committed by MySQL. A process can therefore stop after
-- creating archive_imports but before adding this cross-migration foreign key.
-- Make the ALTER retryable without weakening the final schema contract.
SET @archive_profile_fk_exists = (
    SELECT COUNT(*)
    FROM information_schema.referential_constraints
    WHERE constraint_schema = DATABASE()
      AND table_name = 'upload_intake_profiles'
      AND constraint_name = 'fk_upload_intake_profiles_archive_import'
);
SET @archive_profile_fk_ddl = IF(
    @archive_profile_fk_exists = 0,
    'ALTER TABLE upload_intake_profiles ADD CONSTRAINT fk_upload_intake_profiles_archive_import FOREIGN KEY (archive_import_id) REFERENCES archive_imports (id) ON DELETE SET NULL',
    'SELECT 1'
);
PREPARE archive_profile_fk_statement FROM @archive_profile_fk_ddl;
EXECUTE archive_profile_fk_statement;
DEALLOCATE PREPARE archive_profile_fk_statement;

CREATE TABLE IF NOT EXISTS archive_import_entries (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    public_id CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    archive_import_id CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    ordinal INT UNSIGNED NOT NULL,
    logical_path VARCHAR(2048) COLLATE utf8mb4_bin NOT NULL,
    logical_path_hash BINARY(32) NOT NULL,
    size_bytes BIGINT UNSIGNED NOT NULL DEFAULT 0,
    sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NULL,
    detected_format VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NULL,
    detected_category VARCHAR(24) CHARACTER SET ascii COLLATE ascii_bin NULL,
    status VARCHAR(24) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    skip_reason VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NULL,
    error_code VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NULL,
    error_message VARCHAR(2048) NULL,
    blob_id BIGINT UNSIGNED NULL,
    blob_reference_released_at TIMESTAMP(6) NULL,
    derived_upload_id CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NULL,
    task_id CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NULL,
    created_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
    PRIMARY KEY (id),
    UNIQUE KEY uq_archive_import_entries_public_id (public_id),
    UNIQUE KEY uq_archive_import_entries_ordinal (archive_import_id, ordinal),
    UNIQUE KEY uq_archive_import_entries_path (archive_import_id, logical_path_hash),
    UNIQUE KEY uq_archive_import_entries_task (task_id),
    KEY idx_archive_import_entries_page (archive_import_id, status, id),
    KEY idx_archive_import_entries_blob (blob_id, blob_reference_released_at),
    KEY idx_archive_import_entries_derived_upload (derived_upload_id),
    CONSTRAINT fk_archive_import_entries_import FOREIGN KEY (archive_import_id) REFERENCES archive_imports (id) ON DELETE CASCADE,
    CONSTRAINT fk_archive_import_entries_blob FOREIGN KEY (blob_id) REFERENCES blobs (id),
    CONSTRAINT fk_archive_import_entries_upload FOREIGN KEY (derived_upload_id) REFERENCES uploads (id) ON DELETE SET NULL,
    CONSTRAINT fk_archive_import_entries_task FOREIGN KEY (task_id) REFERENCES tasks (id) ON DELETE SET NULL,
    CONSTRAINT chk_archive_import_entries_category CHECK (
        detected_category IS NULL OR detected_category IN ('binary', 'container')
    ),
    CONSTRAINT chk_archive_import_entries_status CHECK (status IN (
        'eligible', 'skipped', 'created', 'failed'
    )),
    CONSTRAINT chk_archive_import_entries_blob CHECK (
        (status IN ('eligible', 'created', 'failed') AND
         blob_id IS NOT NULL AND sha256 IS NOT NULL AND
         detected_format IS NOT NULL AND detected_category IS NOT NULL) OR
        (status = 'skipped' AND blob_id IS NULL)
    )
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE IF NOT EXISTS archive_import_task_batches (
    id CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    archive_import_id CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    created_by BIGINT UNSIGNED NOT NULL,
    created_by_role VARCHAR(24) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    idempotency_key VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    request_fingerprint CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    status VARCHAR(24) CHARACTER SET ascii COLLATE ascii_bin NOT NULL DEFAULT 'processing',
    error_code VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NULL,
    created_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
    completed_at TIMESTAMP(6) NULL,
    PRIMARY KEY (id),
    UNIQUE KEY uq_archive_import_batches_idempotency (archive_import_id, created_by, idempotency_key),
    KEY idx_archive_import_batches_recovery (status, updated_at, id),
    KEY idx_archive_import_batches_creator (created_by),
    CONSTRAINT fk_archive_import_batches_import FOREIGN KEY (archive_import_id) REFERENCES archive_imports (id) ON DELETE CASCADE,
    CONSTRAINT fk_archive_import_batches_creator FOREIGN KEY (created_by) REFERENCES users (id),
    CONSTRAINT chk_archive_import_batches_status CHECK (status IN ('processing', 'completed')),
    CONSTRAINT chk_archive_import_batches_role CHECK (
        created_by_role IN ('administrator', 'operator')
    )
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE IF NOT EXISTS archive_import_task_batch_items (
    batch_id CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    entry_id BIGINT UNSIGNED NOT NULL,
    ordinal TINYINT UNSIGNED NOT NULL,
    outcome VARCHAR(24) CHARACTER SET ascii COLLATE ascii_bin NOT NULL DEFAULT 'pending',
    attempt INT UNSIGNED NOT NULL DEFAULT 0,
    max_attempts INT UNSIGNED NOT NULL DEFAULT 3,
    fencing_token BIGINT UNSIGNED NOT NULL DEFAULT 0,
    lease_owner VARCHAR(255) CHARACTER SET ascii COLLATE ascii_bin NULL,
    lease_until TIMESTAMP(6) NULL,
    heartbeat_at TIMESTAMP(6) NULL,
    task_id CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NULL,
    error_code VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NULL,
    error_message VARCHAR(2048) NULL,
    created_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
    PRIMARY KEY (batch_id, entry_id),
    UNIQUE KEY uq_archive_import_batch_items_ordinal (batch_id, ordinal),
    KEY idx_archive_import_batch_items_entry (entry_id),
    KEY idx_archive_import_batch_items_task (task_id),
    CONSTRAINT fk_archive_import_batch_items_batch FOREIGN KEY (batch_id) REFERENCES archive_import_task_batches (id) ON DELETE CASCADE,
    CONSTRAINT fk_archive_import_batch_items_entry FOREIGN KEY (entry_id) REFERENCES archive_import_entries (id) ON DELETE CASCADE,
    CONSTRAINT fk_archive_import_batch_items_task FOREIGN KEY (task_id) REFERENCES tasks (id) ON DELETE SET NULL,
    CONSTRAINT chk_archive_import_batch_items_ordinal CHECK (ordinal < 20),
    CONSTRAINT chk_archive_import_batch_items_attempts CHECK (attempt <= max_attempts),
    CONSTRAINT chk_archive_import_batch_items_outcome CHECK (outcome IN (
        'pending', 'processing', 'created', 'existing', 'failed'
    )),
    CONSTRAINT chk_archive_import_batch_items_lease CHECK (
        (outcome = 'processing' AND lease_owner IS NOT NULL AND lease_until IS NOT NULL) OR
        (outcome <> 'processing' AND lease_owner IS NULL AND lease_until IS NULL)
    )
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- +goose Down

-- Do not silently discard imports, entry provenance, or idempotency outcomes.
DROP TABLE IF EXISTS binaryscan_migration_35_rollback_guard;
CREATE TABLE binaryscan_migration_35_rollback_guard (
    allowed TINYINT NOT NULL,
    CONSTRAINT chk_no_archive_import_before_rollback CHECK (allowed = 1)
) ENGINE=InnoDB;
INSERT INTO binaryscan_migration_35_rollback_guard (allowed)
SELECT 0 FROM archive_imports LIMIT 1;
INSERT INTO binaryscan_migration_35_rollback_guard (allowed)
SELECT 0 FROM archive_import_entries LIMIT 1;
INSERT INTO binaryscan_migration_35_rollback_guard (allowed)
SELECT 0 FROM archive_import_task_batches LIMIT 1;
INSERT INTO binaryscan_migration_35_rollback_guard (allowed)
SELECT 0 FROM archive_import_task_batch_items LIMIT 1;
INSERT INTO binaryscan_migration_35_rollback_guard (allowed)
SELECT 0
FROM upload_intake_profiles
WHERE archive_import_id IS NOT NULL
LIMIT 1;
DROP TABLE binaryscan_migration_35_rollback_guard;

SET @archive_profile_fk_exists = (
    SELECT COUNT(*)
    FROM information_schema.referential_constraints
    WHERE constraint_schema = DATABASE()
      AND table_name = 'upload_intake_profiles'
      AND constraint_name = 'fk_upload_intake_profiles_archive_import'
);
SET @archive_profile_fk_ddl = IF(
    @archive_profile_fk_exists = 1,
    'ALTER TABLE upload_intake_profiles DROP FOREIGN KEY fk_upload_intake_profiles_archive_import',
    'SELECT 1'
);
PREPARE archive_profile_fk_statement FROM @archive_profile_fk_ddl;
EXECUTE archive_profile_fk_statement;
DEALLOCATE PREPARE archive_profile_fk_statement;
DROP TABLE IF EXISTS archive_import_task_batch_items;
DROP TABLE IF EXISTS archive_import_task_batches;
DROP TABLE IF EXISTS archive_import_entries;
DROP TABLE IF EXISTS archive_imports;

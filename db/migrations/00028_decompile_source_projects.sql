-- +goose NO TRANSACTION
-- +goose Up

CREATE TABLE IF NOT EXISTS decompile_source_projects (
    id CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    task_id CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    file_node_id BIGINT UNSIGNED NOT NULL,
    job_id CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NULL,
    layout_version VARCHAR(24) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    source_kind VARCHAR(32) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    language VARCHAR(32) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    engine_name VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    engine_version VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    status VARCHAR(24) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    root_storage_key VARCHAR(1024) CHARACTER SET ascii COLLATE ascii_bin NULL,
    canonical_storage_key VARCHAR(1024) CHARACTER SET ascii COLLATE ascii_bin NULL,
    canonical_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NULL,
    canonical_size_bytes BIGINT UNSIGNED NULL,
    manifest_storage_key VARCHAR(1024) CHARACTER SET ascii COLLATE ascii_bin NULL,
    manifest_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NULL,
    manifest_size_bytes BIGINT UNSIGNED NULL,
    source_file_count BIGINT UNSIGNED NOT NULL,
    symbol_count BIGINT UNSIGNED NOT NULL,
    source_size_bytes BIGINT UNSIGNED NOT NULL,
    created_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    completed_at TIMESTAMP(6) NULL,
    deleted_at TIMESTAMP(6) NULL,
    storage_deleted_at TIMESTAMP(6) NULL,
    PRIMARY KEY (id),
    UNIQUE KEY uq_decompile_source_projects_task_id_id (task_id, id),
    UNIQUE KEY uq_decompile_source_projects_root (root_storage_key),
    UNIQUE KEY uq_decompile_source_projects_canonical (canonical_storage_key),
    UNIQUE KEY uq_decompile_source_projects_manifest (manifest_storage_key),
    KEY idx_decompile_source_projects_task_created (
        task_id, deleted_at, created_at DESC, id DESC
    ),
    KEY idx_decompile_source_projects_node (
        task_id, file_node_id, created_at DESC, id DESC
    ),
    KEY idx_decompile_source_projects_storage_cleanup (
        deleted_at, storage_deleted_at, id
    ),
    CONSTRAINT fk_decompile_source_projects_run
        FOREIGN KEY (task_id, id)
        REFERENCES analyzer_runs (task_id, id) ON DELETE CASCADE,
    CONSTRAINT fk_decompile_source_projects_task
        FOREIGN KEY (task_id)
        REFERENCES tasks (id) ON DELETE CASCADE,
    CONSTRAINT fk_decompile_source_projects_file_node
        FOREIGN KEY (task_id, file_node_id)
        REFERENCES file_nodes (task_id, id) ON DELETE CASCADE,
    CONSTRAINT fk_decompile_source_projects_job
        FOREIGN KEY (task_id, job_id)
        REFERENCES jobs (task_id, id) ON DELETE CASCADE,
    CONSTRAINT chk_decompile_source_projects_layout
        CHECK (layout_version IN ('project-v1', 'legacy-v1')),
    CONSTRAINT chk_decompile_source_projects_kind
        CHECK (source_kind IN (
            'ghidra-pseudoc', 'java', 'kotlin', 'python', 'bytecode'
        )),
    CONSTRAINT chk_decompile_source_projects_status
        CHECK (status IN ('complete', 'partial', 'bytecode_only')),
    CONSTRAINT chk_decompile_source_projects_counts
        CHECK (source_file_count > 0 AND symbol_count > 0),
    CONSTRAINT chk_decompile_source_projects_canonical
        CHECK (
            (canonical_storage_key IS NULL AND canonical_sha256 IS NULL AND
             canonical_size_bytes IS NULL) OR
            (canonical_storage_key IS NOT NULL AND canonical_sha256 IS NOT NULL AND
             canonical_size_bytes IS NOT NULL)
        ),
    CONSTRAINT chk_decompile_source_projects_manifest
        CHECK (
            (manifest_storage_key IS NULL AND manifest_sha256 IS NULL AND
             manifest_size_bytes IS NULL) OR
            (manifest_storage_key IS NOT NULL AND manifest_sha256 IS NOT NULL AND
             manifest_size_bytes IS NOT NULL)
        ),
    CONSTRAINT chk_decompile_source_projects_storage
        CHECK (
            (layout_version = 'legacy-v1' AND root_storage_key IS NULL AND
             canonical_storage_key IS NULL AND manifest_storage_key IS NULL) OR
            (layout_version = 'project-v1' AND (
                root_storage_key IS NOT NULL OR storage_deleted_at IS NOT NULL
            ))
        ),
    CONSTRAINT chk_decompile_source_projects_storage_deleted
        CHECK (storage_deleted_at IS NULL OR deleted_at IS NOT NULL)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

ALTER TABLE decompile_results
    ADD COLUMN source_offset_bytes BIGINT UNSIGNED NULL AFTER size_bytes,
    ADD COLUMN source_length_bytes BIGINT UNSIGNED NULL AFTER source_offset_bytes,
    ADD COLUMN source_start_line BIGINT UNSIGNED NULL AFTER source_length_bytes,
    ADD COLUMN source_end_line BIGINT UNSIGNED NULL AFTER source_start_line,
    ADD CONSTRAINT chk_decompile_results_source_range CHECK (
        (
            source_offset_bytes IS NULL AND source_length_bytes IS NULL AND
            source_start_line IS NULL AND source_end_line IS NULL
        ) OR (
            source_offset_bytes IS NOT NULL AND source_length_bytes IS NOT NULL AND
            source_length_bytes > 0 AND source_start_line IS NOT NULL AND
            source_start_line > 0 AND source_end_line IS NOT NULL AND
            source_end_line >= source_start_line
        )
    );

INSERT INTO decompile_source_projects (
    id, task_id, file_node_id, job_id, layout_version, source_kind, language,
    engine_name, engine_version, status, source_file_count, symbol_count,
    source_size_bytes, created_at, completed_at
)
SELECT
    run.id,
    run.task_id,
    run.file_node_id,
    run.job_id,
    'legacy-v1',
    CASE
        WHEN run.analyzer_name = 'ghidra' THEN 'ghidra-pseudoc'
        WHEN SUM(
            result.storage_key IS NOT NULL AND result.content_sha256 IS NOT NULL AND
            result.size_bytes IS NOT NULL AND
            result.status IN ('complete', 'partial', 'bytecode_only') AND
            result.language = 'java'
        ) > 0 THEN 'java'
        WHEN SUM(
            result.storage_key IS NOT NULL AND result.content_sha256 IS NOT NULL AND
            result.size_bytes IS NOT NULL AND
            result.status IN ('complete', 'partial', 'bytecode_only') AND
            result.language = 'kotlin'
        ) > 0 THEN 'kotlin'
        WHEN SUM(
            result.storage_key IS NOT NULL AND result.content_sha256 IS NOT NULL AND
            result.size_bytes IS NOT NULL AND
            result.status IN ('complete', 'partial', 'bytecode_only') AND
            result.language = 'python'
        ) > 0 THEN 'python'
        ELSE 'bytecode'
    END,
    CASE
        WHEN run.analyzer_name = 'ghidra' THEN 'c'
        WHEN COUNT(DISTINCT CASE
            WHEN result.storage_key IS NOT NULL AND
                 result.content_sha256 IS NOT NULL AND
                 result.size_bytes IS NOT NULL AND
                 result.status IN ('complete', 'partial', 'bytecode_only')
            THEN result.language
        END) = 1 THEN MIN(CASE
            WHEN result.storage_key IS NOT NULL AND
                 result.content_sha256 IS NOT NULL AND
                 result.size_bytes IS NOT NULL AND
                 result.status IN ('complete', 'partial', 'bytecode_only')
            THEN result.language
        END)
        ELSE 'mixed'
    END,
    run.analyzer_name,
    run.analyzer_version,
    CASE
        WHEN run.status = 'partial' THEN 'partial'
        WHEN SUM(result.status = 'complete') = COUNT(*) THEN 'complete'
        WHEN SUM(result.status = 'bytecode_only') = COUNT(*) THEN 'bytecode_only'
        ELSE 'partial'
    END,
    COUNT(DISTINCT CASE
        WHEN result.storage_key IS NOT NULL AND
             result.content_sha256 IS NOT NULL AND
             result.size_bytes IS NOT NULL AND
             result.status IN ('complete', 'partial', 'bytecode_only')
        THEN result.storage_key
    END),
    COUNT(*),
    COALESCE(SUM(CASE
        WHEN result.storage_key IS NOT NULL AND
             result.content_sha256 IS NOT NULL AND
             result.size_bytes IS NOT NULL AND
             result.status IN ('complete', 'partial', 'bytecode_only')
        THEN result.size_bytes
        ELSE 0
    END), 0),
    LEAST(run.created_at, MIN(result.created_at)),
    COALESCE(run.completed_at, MAX(result.completed_at))
FROM analyzer_runs run
JOIN decompile_results result
  ON result.task_id = run.task_id
 AND result.analyzer_run_id = run.id
WHERE run.file_node_id IS NOT NULL
  AND result.deleted_at IS NULL
GROUP BY
    run.id, run.task_id, run.file_node_id, run.job_id,
    run.analyzer_name, run.analyzer_version, run.created_at, run.completed_at
HAVING COUNT(DISTINCT CASE
    WHEN result.storage_key IS NOT NULL AND
         result.content_sha256 IS NOT NULL AND
         result.size_bytes IS NOT NULL AND
         result.status IN ('complete', 'partial', 'bytecode_only')
    THEN result.storage_key
END) > 0;

-- +goose Down

-- Refuse application rollback after v28 has published the new filesystem
-- layout. A normal table is intentional: goose executes non-transactional
-- statements through a connection pool, so a temporary table or prepared
-- statement would not be guaranteed to stay on one MySQL connection.
DROP TABLE IF EXISTS binaryscan_migration_28_rollback_guard;
CREATE TABLE binaryscan_migration_28_rollback_guard (
    allowed TINYINT NOT NULL,
    CONSTRAINT chk_no_project_v1_before_rollback CHECK (allowed = 1)
) ENGINE=InnoDB;
INSERT INTO binaryscan_migration_28_rollback_guard (allowed)
SELECT 0
FROM decompile_source_projects
WHERE layout_version = 'project-v1'
LIMIT 1;
DROP TABLE binaryscan_migration_28_rollback_guard;

ALTER TABLE decompile_results
    DROP CHECK chk_decompile_results_source_range,
    DROP COLUMN source_end_line,
    DROP COLUMN source_start_line,
    DROP COLUMN source_length_bytes,
    DROP COLUMN source_offset_bytes;

DROP TABLE IF EXISTS decompile_source_projects;

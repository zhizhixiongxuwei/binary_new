-- +goose NO TRANSACTION
-- +goose Up

ALTER TABLE reports
    DROP INDEX uq_reports_task_format_schema,
    ADD COLUMN snapshot_state VARCHAR(16) CHARACTER SET ascii
        COLLATE ascii_bin NOT NULL DEFAULT 'staged' AFTER status,
    ADD COLUMN generation BIGINT UNSIGNED NOT NULL DEFAULT 1
        AFTER snapshot_state,
    ADD COLUMN current_slot TINYINT
        GENERATED ALWAYS AS (
            CASE
                WHEN snapshot_state = 'current' AND deleted_at IS NULL THEN 1
                ELSE NULL
            END
        ) STORED AFTER generation;

UPDATE reports
SET snapshot_state = CASE
    WHEN status = 'complete' AND deleted_at IS NULL THEN 'current'
    WHEN status IN ('queued', 'generating') AND deleted_at IS NULL THEN 'staged'
    ELSE 'stale'
END;

ALTER TABLE reports
    ADD UNIQUE KEY uq_reports_task_id_id (task_id, id),
    ADD UNIQUE KEY uq_reports_generation (
        task_id, format, schema_version, generation
    ),
    ADD UNIQUE KEY uq_reports_current (
        task_id, format, schema_version, current_slot
    ),
    ADD KEY idx_reports_snapshot_state (
        task_id, schema_version, snapshot_state, format, generation DESC
    ),
    ADD CONSTRAINT chk_reports_snapshot_state CHECK (
        snapshot_state IN ('current', 'stale', 'staged')
    ),
    ADD CONSTRAINT chk_reports_snapshot_lifecycle CHECK (
        (snapshot_state = 'current' AND status = 'complete' AND
            deleted_at IS NULL) OR
        (snapshot_state = 'staged' AND status IN ('queued', 'generating') AND
            deleted_at IS NULL) OR
        snapshot_state = 'stale'
    );

CREATE TABLE IF NOT EXISTS report_c_analysis_runs (
    report_id CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    task_id CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    run_id CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    project_id CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    report_generation BIGINT UNSIGNED NOT NULL,
    run_completed_at TIMESTAMP(6) NOT NULL,
    source_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    created_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    PRIMARY KEY (report_id, project_id),
    UNIQUE KEY uq_report_c_analysis_report_run (report_id, run_id),
    KEY idx_report_c_analysis_run (task_id, run_id, report_id),
    KEY idx_report_c_analysis_project (task_id, project_id, report_id),
    CONSTRAINT fk_report_c_analysis_report
        FOREIGN KEY (task_id, report_id)
        REFERENCES reports (task_id, id) ON DELETE CASCADE,
    CONSTRAINT fk_report_c_analysis_run
        FOREIGN KEY (task_id, run_id)
        REFERENCES c_analysis_runs (task_id, id) ON DELETE RESTRICT,
    CONSTRAINT fk_report_c_analysis_project
        FOREIGN KEY (task_id, project_id)
        REFERENCES decompile_source_projects (task_id, id) ON DELETE RESTRICT,
    CONSTRAINT chk_report_c_analysis_generation CHECK (report_generation > 0),
    CONSTRAINT chk_report_c_analysis_digest CHECK (
        source_sha256 REGEXP '^[0-9a-f]{64}$'
    )
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- +goose Down

-- Restoring the v29 identity constraint is safe only when no replacement
-- history has been created. Refuse a lossy rollback instead of guessing which
-- immutable report should survive.
DROP TABLE IF EXISTS binaryscan_migration_30_rollback_guard;
CREATE TABLE binaryscan_migration_30_rollback_guard (
    allowed TINYINT NOT NULL,
    CONSTRAINT chk_no_report_replacements_before_rollback CHECK (allowed = 1)
) ENGINE=InnoDB;
INSERT INTO binaryscan_migration_30_rollback_guard (allowed)
SELECT 0
FROM reports
GROUP BY task_id, format, schema_version
HAVING COUNT(*) > 1
LIMIT 1;
DROP TABLE binaryscan_migration_30_rollback_guard;

DROP TABLE IF EXISTS report_c_analysis_runs;

ALTER TABLE reports
    DROP CHECK chk_reports_snapshot_lifecycle,
    DROP CHECK chk_reports_snapshot_state,
    DROP INDEX idx_reports_snapshot_state,
    DROP INDEX uq_reports_current,
    DROP INDEX uq_reports_generation,
    DROP INDEX uq_reports_task_id_id,
    ADD UNIQUE KEY uq_reports_task_format_schema (
        task_id, format, schema_version
    ),
    DROP COLUMN current_slot,
    DROP COLUMN generation,
    DROP COLUMN snapshot_state;

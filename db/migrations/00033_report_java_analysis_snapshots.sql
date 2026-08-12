-- +goose NO TRANSACTION
-- +goose Up

CREATE TABLE IF NOT EXISTS report_java_analysis_runs (
    report_id CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    task_id CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    run_id CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    project_id CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    report_generation BIGINT UNSIGNED NOT NULL,
    run_completed_at TIMESTAMP(6) NOT NULL,
    source_manifest_sha256 CHAR(64) CHARACTER SET ascii
        COLLATE ascii_bin NOT NULL,
    input_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    created_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    PRIMARY KEY (report_id, project_id),
    UNIQUE KEY uq_report_java_analysis_report_run (report_id, run_id),
    KEY idx_report_java_analysis_run (task_id, run_id, report_id),
    KEY idx_report_java_analysis_project (task_id, project_id, report_id),
    CONSTRAINT fk_report_java_analysis_report
        FOREIGN KEY (task_id, report_id)
        REFERENCES reports (task_id, id) ON DELETE CASCADE,
    CONSTRAINT fk_report_java_analysis_run
        FOREIGN KEY (task_id, run_id)
        REFERENCES java_analysis_runs (task_id, id) ON DELETE RESTRICT,
    CONSTRAINT fk_report_java_analysis_project
        FOREIGN KEY (task_id, project_id)
        REFERENCES decompile_source_projects (task_id, id) ON DELETE RESTRICT,
    CONSTRAINT chk_report_java_analysis_generation CHECK (
        report_generation > 0
    ),
    CONSTRAINT chk_report_java_analysis_manifest_digest CHECK (
        source_manifest_sha256 REGEXP '^[0-9a-f]{64}$'
    ),
    CONSTRAINT chk_report_java_analysis_input_digest CHECK (
        input_sha256 REGEXP '^[0-9a-f]{64}$'
    )
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- +goose Down

-- A report dependency is durable evidence. Refuse a lossy rollback after
-- Java-analysis snapshots have been published.
DROP TABLE IF EXISTS binaryscan_migration_33_rollback_guard;
CREATE TABLE binaryscan_migration_33_rollback_guard (
    allowed TINYINT NOT NULL,
    CONSTRAINT chk_no_java_report_dependencies_before_rollback
        CHECK (allowed = 1)
) ENGINE=InnoDB;
INSERT INTO binaryscan_migration_33_rollback_guard (allowed)
SELECT 0
FROM report_java_analysis_runs
LIMIT 1;
DROP TABLE binaryscan_migration_33_rollback_guard;

DROP TABLE IF EXISTS report_java_analysis_runs;

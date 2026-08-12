-- +goose NO TRANSACTION
-- +goose Up

ALTER TABLE jobs
    DROP CHECK chk_jobs_kind,
    ADD CONSTRAINT chk_jobs_kind CHECK (
        kind IN (
            'scan', 'image', 'native', 'bytecode', 'trivy', 'report',
            'decompile', 'c_analysis', 'java_analysis'
        )
    );

ALTER TABLE worker_readiness
    DROP CHECK chk_worker_readiness_kind,
    DROP CHECK chk_worker_readiness_analyzer,
    ADD CONSTRAINT chk_worker_readiness_kind CHECK (
        worker_kind IN (
            'image', 'native', 'trivy', 'bytecode', 'c_analysis',
            'java_analysis'
        )
    ),
    ADD CONSTRAINT chk_worker_readiness_analyzer CHECK (
        (worker_kind = 'native' AND analyzer_name = 'ghidra') OR
        (worker_kind IN ('image', 'trivy') AND analyzer_name = 'trivy') OR
        (worker_kind = 'bytecode' AND analyzer_name IN (
            'go-bytecode-router', 'vineflower-cfr-jadx'
        )) OR
        (worker_kind = 'c_analysis' AND analyzer_name = 'binaryscan-c-checker') OR
        (worker_kind = 'java_analysis' AND
            analyzer_name = 'binaryscan-java-checker')
    );

CREATE TABLE IF NOT EXISTS java_analysis_runs (
    id CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    task_id CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    source_project_id CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    job_id CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    created_by_user_id BIGINT UNSIGNED NULL,
    status VARCHAR(24) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    source_manifest_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    input_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    bundle_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NULL,
    source_size_bytes BIGINT UNSIGNED NOT NULL DEFAULT 0,
    source_file_count INT UNSIGNED NOT NULL DEFAULT 0,
    ruleset_version VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NULL,
    analyzed_files INT UNSIGNED NOT NULL DEFAULT 0,
    parsed_files INT UNSIGNED NOT NULL DEFAULT 0,
    recovered_files INT UNSIGNED NOT NULL DEFAULT 0,
    failed_files INT UNSIGNED NOT NULL DEFAULT 0,
    finding_count INT UNSIGNED NOT NULL DEFAULT 0,
    diagnostic_count INT UNSIGNED NOT NULL DEFAULT 0,
    low_count INT UNSIGNED NOT NULL DEFAULT 0,
    medium_count INT UNSIGNED NOT NULL DEFAULT 0,
    high_count INT UNSIGNED NOT NULL DEFAULT 0,
    critical_count INT UNSIGNED NOT NULL DEFAULT 0,
    findings_truncated BOOLEAN NOT NULL DEFAULT FALSE,
    diagnostics_truncated BOOLEAN NOT NULL DEFAULT FALSE,
    error_code VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NULL,
    error_message VARCHAR(2048) NULL,
    started_at TIMESTAMP(6) NULL,
    completed_at TIMESTAMP(6) NULL,
    deletion_started_at TIMESTAMP(6) NULL,
    created_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6)
        ON UPDATE CURRENT_TIMESTAMP(6),
    active_source_project_id CHAR(36) CHARACTER SET ascii COLLATE ascii_bin
        GENERATED ALWAYS AS (
            CASE
                WHEN status IN ('queued', 'running', 'cancel_requested')
                THEN source_project_id
                ELSE NULL
            END
        ) VIRTUAL,
    PRIMARY KEY (id),
    UNIQUE KEY uq_java_analysis_runs_task_id_id (task_id, id),
    UNIQUE KEY uq_java_analysis_runs_job (task_id, job_id),
    UNIQUE KEY uq_java_analysis_runs_active_project (active_source_project_id),
    KEY idx_java_analysis_runs_task_created (
        task_id, created_at DESC, id DESC
    ),
    KEY idx_java_analysis_runs_project_created (
        source_project_id, created_at DESC, id DESC
    ),
    KEY idx_java_analysis_runs_status_created (status, created_at, id),
    KEY idx_java_analysis_runs_creator (created_by_user_id, created_at),
    CONSTRAINT fk_java_analysis_runs_analyzer
        FOREIGN KEY (task_id, id)
        REFERENCES analyzer_runs (task_id, id) ON DELETE CASCADE,
    CONSTRAINT fk_java_analysis_runs_task
        FOREIGN KEY (task_id)
        REFERENCES tasks (id) ON DELETE CASCADE,
    CONSTRAINT fk_java_analysis_runs_project
        FOREIGN KEY (task_id, source_project_id)
        REFERENCES decompile_source_projects (task_id, id) ON DELETE CASCADE,
    CONSTRAINT fk_java_analysis_runs_job
        FOREIGN KEY (task_id, job_id)
        REFERENCES jobs (task_id, id) ON DELETE CASCADE,
    CONSTRAINT fk_java_analysis_runs_creator
        FOREIGN KEY (created_by_user_id)
        REFERENCES users (id) ON DELETE SET NULL,
    CONSTRAINT chk_java_analysis_runs_status CHECK (
        status IN (
            'queued', 'running', 'succeeded', 'partial', 'failed',
            'cancel_requested', 'cancelled'
        )
    ),
    CONSTRAINT chk_java_analysis_runs_source CHECK (
        source_manifest_sha256 REGEXP '^[0-9a-f]{64}$' AND
        input_sha256 REGEXP '^[0-9a-f]{64}$' AND
        source_size_bytes > 0 AND source_size_bytes <= 134217728 AND
        source_file_count > 0 AND source_file_count <= 3000 AND
        (bundle_sha256 IS NULL OR bundle_sha256 REGEXP '^[0-9a-f]{64}$') AND
        (status NOT IN ('succeeded', 'partial') OR
         bundle_sha256 IS NOT NULL)
    ),
    CONSTRAINT chk_java_analysis_runs_ruleset CHECK (
        (status IN ('succeeded', 'partial') AND
            ruleset_version IS NOT NULL AND
            ruleset_version = 'java-rules-v1') OR
        (status NOT IN ('succeeded', 'partial') AND ruleset_version IS NULL)
    ),
    CONSTRAINT chk_java_analysis_runs_counts CHECK (
        analyzed_files <= parsed_files AND
        parsed_files <= source_file_count AND
        recovered_files <= parsed_files AND
        failed_files <= source_file_count AND
        (status NOT IN ('succeeded', 'partial') OR
            parsed_files + failed_files = source_file_count) AND
        finding_count <= 10000 AND diagnostic_count <= 1000 AND
        low_count + medium_count + high_count + critical_count = finding_count
    ),
    CONSTRAINT chk_java_analysis_runs_lifecycle CHECK (
        (status = 'queued' AND started_at IS NULL AND completed_at IS NULL) OR
        (status IN ('running', 'cancel_requested') AND
            started_at IS NOT NULL AND completed_at IS NULL) OR
        (status IN ('succeeded', 'partial', 'failed', 'cancelled') AND
            completed_at IS NOT NULL)
    ),
    CONSTRAINT chk_java_analysis_runs_error CHECK (
        (status = 'failed' AND error_code IS NOT NULL AND
            error_message IS NOT NULL) OR
        (status <> 'failed' AND error_code IS NULL AND error_message IS NULL)
    ),
    CONSTRAINT chk_java_analysis_runs_deletion CHECK (
        deletion_started_at IS NULL OR
        status IN ('succeeded', 'partial', 'failed', 'cancelled')
    )
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE IF NOT EXISTS java_analysis_findings (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    task_id CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    run_id CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    cwe VARCHAR(16) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    rule_id VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    severity VARCHAR(16) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    file_result_id CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    logical_path VARCHAR(1024) CHARACTER SET utf8mb4
        COLLATE utf8mb4_0900_bin NOT NULL,
    binary_name VARCHAR(1024) NOT NULL,
    callable_kind VARCHAR(32) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    type_name VARCHAR(1024) NOT NULL,
    callable_name VARCHAR(512) NOT NULL,
    callable_signature VARCHAR(2048) NOT NULL,
    start_line INT UNSIGNED NOT NULL,
    start_column INT UNSIGNED NOT NULL,
    end_line INT UNSIGNED NOT NULL,
    end_column INT UNSIGNED NOT NULL,
    message VARCHAR(2048) NOT NULL,
    snippet VARCHAR(1024) NULL,
    snippet_start_line INT UNSIGNED NULL,
    created_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    PRIMARY KEY (id),
    KEY idx_java_analysis_findings_run (task_id, run_id, id),
    KEY idx_java_analysis_findings_cwe (task_id, run_id, cwe, id),
    KEY idx_java_analysis_findings_severity (task_id, run_id, severity, id),
    KEY idx_java_analysis_findings_file (
        task_id, run_id, logical_path(191), id
    ),
    KEY idx_java_analysis_findings_callable (
        task_id, run_id, callable_name(191), id
    ),
    CONSTRAINT fk_java_analysis_findings_run
        FOREIGN KEY (task_id, run_id)
        REFERENCES java_analysis_runs (task_id, id) ON DELETE CASCADE,
    CONSTRAINT chk_java_analysis_findings_severity CHECK (
        severity IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')
    ),
    CONSTRAINT chk_java_analysis_findings_rule CHECK (
        rule_id IN (
            'java-weak-message-digest',
            'java-weak-cipher',
            'java-legacy-tls',
            'java-hardcoded-crypto-key',
            'java-trust-all-hostname-verifier',
            'java-trust-all-x509-manager',
            'java-xxe-enabled',
            'java-unsafe-deserialization',
            'java-sql-injection',
            'java-command-injection',
            'java-dynamic-code-execution',
            'java-overly-permissive-file',
            'java-insecure-cookie'
        )
    ),
    CONSTRAINT chk_java_analysis_findings_cwe_rule CHECK (
        (rule_id = 'java-weak-message-digest' AND cwe = 'CWE-328') OR
        (rule_id = 'java-weak-cipher' AND cwe = 'CWE-327') OR
        (rule_id = 'java-legacy-tls' AND cwe = 'CWE-326') OR
        (rule_id = 'java-hardcoded-crypto-key' AND cwe = 'CWE-321') OR
        (rule_id = 'java-trust-all-hostname-verifier' AND cwe = 'CWE-295') OR
        (rule_id = 'java-trust-all-x509-manager' AND cwe = 'CWE-295') OR
        (rule_id = 'java-xxe-enabled' AND cwe = 'CWE-611') OR
        (rule_id = 'java-unsafe-deserialization' AND cwe = 'CWE-502') OR
        (rule_id = 'java-sql-injection' AND cwe = 'CWE-89') OR
        (rule_id = 'java-command-injection' AND cwe = 'CWE-78') OR
        (rule_id = 'java-dynamic-code-execution' AND cwe = 'CWE-94') OR
        (rule_id = 'java-overly-permissive-file' AND cwe = 'CWE-732') OR
        (rule_id = 'java-insecure-cookie' AND cwe = 'CWE-614')
    ),
    CONSTRAINT chk_java_analysis_findings_location CHECK (
        start_line > 0 AND start_column > 0 AND
        end_line >= start_line AND end_column > 0 AND
        (end_line > start_line OR end_column >= start_column)
    ),
    CONSTRAINT chk_java_analysis_findings_text CHECK (
        CHAR_LENGTH(message) > 0 AND
        CHAR_LENGTH(logical_path) > 0 AND CHAR_LENGTH(binary_name) > 0 AND
        CHAR_LENGTH(callable_kind) > 0 AND CHAR_LENGTH(type_name) > 0 AND
        CHAR_LENGTH(callable_name) > 0 AND
        CHAR_LENGTH(callable_signature) > 0 AND
        (snippet IS NULL OR OCTET_LENGTH(snippet) <= 1024) AND
        ((snippet IS NULL AND snippet_start_line IS NULL) OR
         (snippet IS NOT NULL AND snippet_start_line > 0))
    )
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- +goose Down

-- A rollback would otherwise silently delete Java findings, jobs, or runs.
DROP TABLE IF EXISTS binaryscan_migration_32_rollback_guard;
CREATE TABLE binaryscan_migration_32_rollback_guard (
    allowed TINYINT NOT NULL,
    CONSTRAINT chk_no_java_analysis_before_rollback CHECK (allowed = 1)
) ENGINE=InnoDB;
INSERT INTO binaryscan_migration_32_rollback_guard (allowed)
SELECT 0 FROM (
    SELECT id FROM java_analysis_runs
    UNION ALL
    SELECT id FROM jobs WHERE kind = 'java_analysis'
    UNION ALL
    SELECT id FROM analyzer_runs
    WHERE analyzer_name = 'binaryscan-java-checker'
) java_analysis_data
LIMIT 1;
DROP TABLE binaryscan_migration_32_rollback_guard;

DROP TABLE IF EXISTS java_analysis_findings;
DROP TABLE IF EXISTS java_analysis_runs;

DELETE FROM worker_readiness WHERE worker_kind = 'java_analysis';

ALTER TABLE worker_readiness
    DROP CHECK chk_worker_readiness_kind,
    DROP CHECK chk_worker_readiness_analyzer,
    ADD CONSTRAINT chk_worker_readiness_kind CHECK (
        worker_kind IN ('image', 'native', 'trivy', 'bytecode', 'c_analysis')
    ),
    ADD CONSTRAINT chk_worker_readiness_analyzer CHECK (
        (worker_kind = 'native' AND analyzer_name = 'ghidra') OR
        (worker_kind IN ('image', 'trivy') AND analyzer_name = 'trivy') OR
        (worker_kind = 'bytecode' AND analyzer_name IN (
            'go-bytecode-router', 'vineflower-cfr-jadx'
        )) OR
        (worker_kind = 'c_analysis' AND analyzer_name = 'binaryscan-c-checker')
    );

ALTER TABLE jobs
    DROP CHECK chk_jobs_kind,
    ADD CONSTRAINT chk_jobs_kind CHECK (
        kind IN (
            'scan', 'image', 'native', 'bytecode', 'trivy', 'report',
            'decompile', 'c_analysis'
        )
    );

-- +goose NO TRANSACTION
-- +goose Up

ALTER TABLE jobs
    DROP CHECK chk_jobs_kind,
    ADD CONSTRAINT chk_jobs_kind CHECK (
        kind IN (
            'scan', 'image', 'native', 'bytecode', 'trivy', 'report',
            'decompile', 'c_analysis', 'java_analysis', 'python_analysis'
        )
    );

ALTER TABLE worker_readiness
    DROP CHECK chk_worker_readiness_kind,
    DROP CHECK chk_worker_readiness_analyzer,
    ADD CONSTRAINT chk_worker_readiness_kind CHECK (
        worker_kind IN (
            'image', 'native', 'trivy', 'bytecode', 'c_analysis',
            'java_analysis', 'python_analysis'
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
            analyzer_name = 'binaryscan-java-checker') OR
        (worker_kind = 'python_analysis' AND
            analyzer_name = 'binaryscan-python-checker')
    );

CREATE TABLE IF NOT EXISTS python_analysis_runs (
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
    UNIQUE KEY uq_python_analysis_runs_task_id_id (task_id, id),
    UNIQUE KEY uq_python_analysis_runs_job (task_id, job_id),
    UNIQUE KEY uq_python_analysis_runs_active_project (active_source_project_id),
    KEY idx_python_analysis_runs_task_created (
        task_id, created_at DESC, id DESC
    ),
    KEY idx_python_analysis_runs_project_created (
        source_project_id, created_at DESC, id DESC
    ),
    KEY idx_python_analysis_runs_status_created (status, created_at, id),
    KEY idx_python_analysis_runs_creator (created_by_user_id, created_at),
    CONSTRAINT fk_python_analysis_runs_analyzer
        FOREIGN KEY (task_id, id)
        REFERENCES analyzer_runs (task_id, id) ON DELETE CASCADE,
    CONSTRAINT fk_python_analysis_runs_task
        FOREIGN KEY (task_id)
        REFERENCES tasks (id) ON DELETE CASCADE,
    CONSTRAINT fk_python_analysis_runs_project
        FOREIGN KEY (task_id, source_project_id)
        REFERENCES decompile_source_projects (task_id, id) ON DELETE CASCADE,
    CONSTRAINT fk_python_analysis_runs_job
        FOREIGN KEY (task_id, job_id)
        REFERENCES jobs (task_id, id) ON DELETE CASCADE,
    CONSTRAINT fk_python_analysis_runs_creator
        FOREIGN KEY (created_by_user_id)
        REFERENCES users (id) ON DELETE SET NULL,
    CONSTRAINT chk_python_analysis_runs_status CHECK (
        status IN (
            'queued', 'running', 'succeeded', 'partial', 'failed',
            'cancel_requested', 'cancelled'
        )
    ),
    CONSTRAINT chk_python_analysis_runs_source CHECK (
        source_manifest_sha256 REGEXP '^[0-9a-f]{64}$' AND
        input_sha256 REGEXP '^[0-9a-f]{64}$' AND
        source_size_bytes > 0 AND source_size_bytes <= 134217728 AND
        source_file_count > 0 AND source_file_count <= 3000 AND
        (bundle_sha256 IS NULL OR bundle_sha256 REGEXP '^[0-9a-f]{64}$') AND
        (status NOT IN ('succeeded', 'partial') OR
         bundle_sha256 IS NOT NULL)
    ),
    CONSTRAINT chk_python_analysis_runs_ruleset CHECK (
        (status IN ('succeeded', 'partial') AND
            ruleset_version IS NOT NULL AND
            ruleset_version = 'python-rules-v1') OR
        (status NOT IN ('succeeded', 'partial') AND ruleset_version IS NULL)
    ),
    CONSTRAINT chk_python_analysis_runs_counts CHECK (
        analyzed_files <= parsed_files AND
        parsed_files <= source_file_count AND
        recovered_files <= parsed_files AND
        failed_files <= source_file_count AND
        (status NOT IN ('succeeded', 'partial') OR
            parsed_files + failed_files = source_file_count) AND
        finding_count <= 10000 AND diagnostic_count <= 1000 AND
        low_count + medium_count + high_count + critical_count = finding_count
    ),
    CONSTRAINT chk_python_analysis_runs_lifecycle CHECK (
        (status = 'queued' AND started_at IS NULL AND completed_at IS NULL) OR
        (status IN ('running', 'cancel_requested') AND
            started_at IS NOT NULL AND completed_at IS NULL) OR
        (status IN ('succeeded', 'partial', 'failed', 'cancelled') AND
            completed_at IS NOT NULL)
    ),
    CONSTRAINT chk_python_analysis_runs_error CHECK (
        (status = 'failed' AND error_code IS NOT NULL AND
            error_message IS NOT NULL) OR
        (status <> 'failed' AND error_code IS NULL AND error_message IS NULL)
    ),
    CONSTRAINT chk_python_analysis_runs_deletion CHECK (
        deletion_started_at IS NULL OR
        status IN ('succeeded', 'partial', 'failed', 'cancelled')
    )
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE IF NOT EXISTS python_analysis_findings (
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
    KEY idx_python_analysis_findings_run (task_id, run_id, id),
    KEY idx_python_analysis_findings_cwe (task_id, run_id, cwe, id),
    KEY idx_python_analysis_findings_severity (task_id, run_id, severity, id),
    KEY idx_python_analysis_findings_file (
        task_id, run_id, logical_path(191), id
    ),
    KEY idx_python_analysis_findings_callable (
        task_id, run_id, callable_name(191), id
    ),
    CONSTRAINT fk_python_analysis_findings_run
        FOREIGN KEY (task_id, run_id)
        REFERENCES python_analysis_runs (task_id, id) ON DELETE CASCADE,
    CONSTRAINT chk_python_analysis_findings_severity CHECK (
        severity IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')
    ),
    CONSTRAINT chk_python_analysis_findings_rule CHECK (
        rule_id IN (
            'python-dynamic-code-execution',
            'python-command-injection',
            'python-unsafe-deserialization',
            'python-weak-message-digest',
            'python-insecure-request'
        )
    ),
    CONSTRAINT chk_python_analysis_findings_cwe_rule CHECK (
        (rule_id = 'python-dynamic-code-execution' AND cwe = 'CWE-95') OR
        (rule_id = 'python-command-injection' AND cwe = 'CWE-78') OR
        (rule_id = 'python-unsafe-deserialization' AND cwe = 'CWE-502') OR
        (rule_id = 'python-weak-message-digest' AND cwe = 'CWE-328') OR
        (rule_id = 'python-insecure-request' AND cwe = 'CWE-295')
    ),
    CONSTRAINT chk_python_analysis_findings_position CHECK (
        start_line > 0 AND end_line >= start_line AND
        end_column >= start_column
    )
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- +goose Down
DROP TABLE IF EXISTS python_analysis_findings;
DROP TABLE IF EXISTS python_analysis_runs;

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

ALTER TABLE jobs
    DROP CHECK chk_jobs_kind,
    ADD CONSTRAINT chk_jobs_kind CHECK (
        kind IN (
            'scan', 'image', 'native', 'bytecode', 'trivy', 'report',
            'decompile', 'c_analysis', 'java_analysis'
        )
    );

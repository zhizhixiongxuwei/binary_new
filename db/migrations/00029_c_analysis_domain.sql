-- +goose NO TRANSACTION
-- +goose Up

ALTER TABLE jobs
    DROP CHECK chk_jobs_kind,
    ADD CONSTRAINT chk_jobs_kind CHECK (
        kind IN (
            'scan', 'image', 'native', 'bytecode', 'trivy', 'report',
            'decompile', 'c_analysis'
        )
    );

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

CREATE TABLE IF NOT EXISTS c_analysis_runs (
    id CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    task_id CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    source_project_id CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    job_id CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    created_by_user_id BIGINT UNSIGNED NULL,
    status VARCHAR(24) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    source_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    source_size_bytes BIGINT UNSIGNED NOT NULL,
    ruleset_version VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NULL,
    total_functions INT UNSIGNED NOT NULL,
    parsed_functions INT UNSIGNED NOT NULL DEFAULT 0,
    failed_functions INT UNSIGNED NOT NULL DEFAULT 0,
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
    UNIQUE KEY uq_c_analysis_runs_task_id_id (task_id, id),
    UNIQUE KEY uq_c_analysis_runs_job (task_id, job_id),
    UNIQUE KEY uq_c_analysis_runs_active_project (active_source_project_id),
    KEY idx_c_analysis_runs_task_created (
        task_id, created_at DESC, id DESC
    ),
    KEY idx_c_analysis_runs_project_created (
        source_project_id, created_at DESC, id DESC
    ),
    KEY idx_c_analysis_runs_status_created (status, created_at, id),
    KEY idx_c_analysis_runs_creator (created_by_user_id, created_at),
    CONSTRAINT fk_c_analysis_runs_analyzer
        FOREIGN KEY (task_id, id)
        REFERENCES analyzer_runs (task_id, id) ON DELETE CASCADE,
    CONSTRAINT fk_c_analysis_runs_task
        FOREIGN KEY (task_id)
        REFERENCES tasks (id) ON DELETE CASCADE,
    CONSTRAINT fk_c_analysis_runs_project
        FOREIGN KEY (task_id, source_project_id)
        REFERENCES decompile_source_projects (task_id, id) ON DELETE CASCADE,
    CONSTRAINT fk_c_analysis_runs_job
        FOREIGN KEY (task_id, job_id)
        REFERENCES jobs (task_id, id) ON DELETE CASCADE,
    CONSTRAINT fk_c_analysis_runs_creator
        FOREIGN KEY (created_by_user_id)
        REFERENCES users (id) ON DELETE SET NULL,
    CONSTRAINT chk_c_analysis_runs_status CHECK (
        status IN (
            'queued', 'running', 'succeeded', 'partial', 'failed',
            'cancel_requested', 'cancelled'
        )
    ),
    CONSTRAINT chk_c_analysis_runs_source CHECK (
        source_size_bytes > 0 AND source_size_bytes <= 134217728 AND
        total_functions > 0 AND total_functions <= 3000 AND
        source_sha256 REGEXP '^[0-9a-f]{64}$'
    ),
    CONSTRAINT chk_c_analysis_runs_ruleset CHECK (
        (status IN ('succeeded', 'partial') AND
            ruleset_version = 'c-rules-v1') OR
        (status NOT IN ('succeeded', 'partial') AND ruleset_version IS NULL)
    ),
    CONSTRAINT chk_c_analysis_runs_counts CHECK (
        parsed_functions <= total_functions AND
        failed_functions <= total_functions AND
        parsed_functions + failed_functions <= total_functions AND
        finding_count <= 10000 AND diagnostic_count <= 1000 AND
        low_count + medium_count + high_count + critical_count = finding_count
    ),
    CONSTRAINT chk_c_analysis_runs_lifecycle CHECK (
        (status = 'queued' AND started_at IS NULL AND completed_at IS NULL) OR
        (status IN ('running', 'cancel_requested') AND
            started_at IS NOT NULL AND completed_at IS NULL) OR
        (status IN ('succeeded', 'partial', 'failed', 'cancelled') AND
            completed_at IS NOT NULL)
    ),
    CONSTRAINT chk_c_analysis_runs_error CHECK (
        (status = 'failed' AND error_code IS NOT NULL AND
            error_message IS NOT NULL) OR
        (status <> 'failed' AND error_code IS NULL AND error_message IS NULL)
    ),
    CONSTRAINT chk_c_analysis_runs_deletion CHECK (
        deletion_started_at IS NULL OR
        status IN ('succeeded', 'partial', 'failed', 'cancelled')
    )
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE IF NOT EXISTS c_analysis_findings (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    task_id CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    run_id CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    cwe VARCHAR(16) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    rule_id VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    severity VARCHAR(16) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    function_result_id CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    function_address VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    function_name VARCHAR(512) NOT NULL,
    start_line INT UNSIGNED NOT NULL,
    start_column INT UNSIGNED NOT NULL,
    end_line INT UNSIGNED NOT NULL,
    end_column INT UNSIGNED NOT NULL,
    message VARCHAR(2048) NOT NULL,
    snippet VARCHAR(1024) NULL,
    created_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    PRIMARY KEY (id),
    KEY idx_c_analysis_findings_run (task_id, run_id, id),
    KEY idx_c_analysis_findings_cwe (task_id, run_id, cwe, id),
    KEY idx_c_analysis_findings_severity (task_id, run_id, severity, id),
    KEY idx_c_analysis_findings_function (
        task_id, run_id, function_name(191), id
    ),
    CONSTRAINT fk_c_analysis_findings_run
        FOREIGN KEY (task_id, run_id)
        REFERENCES c_analysis_runs (task_id, id) ON DELETE CASCADE,
    CONSTRAINT chk_c_analysis_findings_severity CHECK (
        severity IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')
    ),
    CONSTRAINT chk_c_analysis_findings_rule CHECK (
        rule_id IN (
            'cwe-242-gets',
            'cwe-120-bounds',
            'cwe-134-format',
            'cwe-78-command',
            'cwe-787-oob-write',
            'cwe-125-oob-read',
            'cwe-562-stack-address',
            'cwe-590-invalid-free',
            'cwe-761-offset-free',
            'cwe-369-zero-divisor',
            'cwe-377-temp-file',
            'cwe-252-unchecked-return',
            'cwe-131-size-calculation',
            'cwe-327-328-weak-crypto',
            'cwe-732-permissions'
        )
    ),
    CONSTRAINT chk_c_analysis_findings_cwe_rule CHECK (
        (rule_id = 'cwe-242-gets' AND cwe = 'CWE-242') OR
        (rule_id = 'cwe-120-bounds' AND cwe = 'CWE-120') OR
        (rule_id = 'cwe-134-format' AND cwe = 'CWE-134') OR
        (rule_id = 'cwe-78-command' AND cwe = 'CWE-78') OR
        (rule_id = 'cwe-787-oob-write' AND cwe = 'CWE-787') OR
        (rule_id = 'cwe-125-oob-read' AND cwe = 'CWE-125') OR
        (rule_id = 'cwe-562-stack-address' AND cwe = 'CWE-562') OR
        (rule_id = 'cwe-590-invalid-free' AND cwe = 'CWE-590') OR
        (rule_id = 'cwe-761-offset-free' AND cwe = 'CWE-761') OR
        (rule_id = 'cwe-369-zero-divisor' AND cwe = 'CWE-369') OR
        (rule_id = 'cwe-377-temp-file' AND cwe = 'CWE-377') OR
        (rule_id = 'cwe-252-unchecked-return' AND cwe = 'CWE-252') OR
        (rule_id = 'cwe-131-size-calculation' AND cwe = 'CWE-131') OR
        (rule_id = 'cwe-327-328-weak-crypto' AND
            cwe IN ('CWE-327', 'CWE-328')) OR
        (rule_id = 'cwe-732-permissions' AND cwe = 'CWE-732')
    ),
    CONSTRAINT chk_c_analysis_findings_location CHECK (
        start_line > 0 AND start_column > 0 AND
        end_line >= start_line AND end_column > 0 AND
        (end_line > start_line OR end_column >= start_column)
    ),
    CONSTRAINT chk_c_analysis_findings_text CHECK (
        CHAR_LENGTH(message) > 0 AND
        (snippet IS NULL OR OCTET_LENGTH(snippet) <= 1024)
    )
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- +goose Down

DROP TABLE IF EXISTS c_analysis_findings;
DROP TABLE IF EXISTS c_analysis_runs;

DELETE FROM worker_readiness WHERE worker_kind = 'c_analysis';

ALTER TABLE worker_readiness
    DROP CHECK chk_worker_readiness_kind,
    DROP CHECK chk_worker_readiness_analyzer,
    ADD CONSTRAINT chk_worker_readiness_kind CHECK (
        worker_kind IN ('image', 'native', 'trivy', 'bytecode')
    ),
    ADD CONSTRAINT chk_worker_readiness_analyzer CHECK (
        (worker_kind = 'native' AND analyzer_name = 'ghidra') OR
        (worker_kind IN ('image', 'trivy') AND analyzer_name = 'trivy') OR
        (worker_kind = 'bytecode' AND analyzer_name IN (
            'go-bytecode-router', 'vineflower-cfr-jadx'
        ))
    );

DELETE FROM jobs WHERE kind = 'c_analysis';

ALTER TABLE jobs
    DROP CHECK chk_jobs_kind,
    ADD CONSTRAINT chk_jobs_kind CHECK (
        kind IN (
            'scan', 'image', 'native', 'bytecode', 'trivy', 'report',
            'decompile'
        )
    );

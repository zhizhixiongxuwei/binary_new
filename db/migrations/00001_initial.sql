-- +goose NO TRANSACTION
-- +goose Up

CREATE TABLE IF NOT EXISTS users (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    public_id CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    username VARCHAR(64) NOT NULL,
    display_name VARCHAR(128) NOT NULL,
    password_hash VARCHAR(255) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    role VARCHAR(24) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    status VARCHAR(24) CHARACTER SET ascii COLLATE ascii_bin NOT NULL DEFAULT 'active',
    force_password_change BOOLEAN NOT NULL DEFAULT TRUE,
    failed_login_count INT UNSIGNED NOT NULL DEFAULT 0,
    locked_until TIMESTAMP(6) NULL,
    last_login_at TIMESTAMP(6) NULL,
    created_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
    PRIMARY KEY (id),
    UNIQUE KEY uq_users_public_id (public_id),
    UNIQUE KEY uq_users_username (username),
    KEY idx_users_status_role (status, role),
    CONSTRAINT chk_users_role CHECK (role IN ('administrator', 'operator', 'reader')),
    CONSTRAINT chk_users_status CHECK (status IN ('active', 'disabled'))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE IF NOT EXISTS sessions (
    id CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    user_id BIGINT UNSIGNED NOT NULL,
    token_hash BINARY(32) NOT NULL,
    csrf_token_hash BINARY(32) NOT NULL,
    client_ip VARBINARY(16) NULL,
    user_agent VARCHAR(512) NULL,
    expires_at TIMESTAMP(6) NOT NULL,
    last_seen_at TIMESTAMP(6) NOT NULL,
    revoked_at TIMESTAMP(6) NULL,
    created_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    PRIMARY KEY (id),
    UNIQUE KEY uq_sessions_token_hash (token_hash),
    KEY idx_sessions_user_expires (user_id, expires_at),
    KEY idx_sessions_expiry_revoked (expires_at, revoked_at),
    CONSTRAINT fk_sessions_user FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE IF NOT EXISTS blobs (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    size_bytes BIGINT UNSIGNED NOT NULL,
    storage_key VARCHAR(1024) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    reference_count BIGINT UNSIGNED NOT NULL DEFAULT 0,
    state VARCHAR(24) CHARACTER SET ascii COLLATE ascii_bin NOT NULL DEFAULT 'available',
    created_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    verified_at TIMESTAMP(6) NULL,
    deleted_at TIMESTAMP(6) NULL,
    PRIMARY KEY (id),
    UNIQUE KEY uq_blobs_sha256 (sha256),
    KEY idx_blobs_state_reference_count (state, reference_count),
    CONSTRAINT chk_blobs_state CHECK (state IN ('staging', 'available', 'deleting', 'deleted'))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE IF NOT EXISTS uploads (
    id CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    created_by BIGINT UNSIGNED NOT NULL,
    original_name VARBINARY(1024) NOT NULL,
    display_name VARCHAR(512) NOT NULL,
    declared_size_bytes BIGINT UNSIGNED NOT NULL,
    part_size_bytes INT UNSIGNED NOT NULL,
    expected_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NULL,
    actual_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NULL,
    status VARCHAR(24) CHARACTER SET ascii COLLATE ascii_bin NOT NULL DEFAULT 'created',
    blob_id BIGINT UNSIGNED NULL,
    idempotency_key VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NULL,
    expires_at TIMESTAMP(6) NOT NULL,
    completed_at TIMESTAMP(6) NULL,
    created_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
    PRIMARY KEY (id),
    UNIQUE KEY uq_uploads_creator_idempotency (created_by, idempotency_key),
    KEY idx_uploads_status_expires (status, expires_at),
    KEY idx_uploads_blob_id (blob_id),
    CONSTRAINT fk_uploads_creator FOREIGN KEY (created_by) REFERENCES users (id),
    CONSTRAINT fk_uploads_blob FOREIGN KEY (blob_id) REFERENCES blobs (id),
    CONSTRAINT chk_uploads_status CHECK (status IN ('created', 'uploading', 'assembling', 'completed', 'failed', 'expired', 'cancelled')),
    CONSTRAINT chk_uploads_declared_size CHECK (declared_size_bytes <= 10737418240),
    CONSTRAINT chk_uploads_part_size CHECK (part_size_bytes > 0)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE IF NOT EXISTS upload_parts (
    upload_id CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    part_number INT UNSIGNED NOT NULL,
    size_bytes INT UNSIGNED NOT NULL,
    sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    content_range VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    storage_key VARCHAR(1024) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    created_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    PRIMARY KEY (upload_id, part_number),
    KEY idx_upload_parts_created_at (created_at),
    CONSTRAINT fk_upload_parts_upload FOREIGN KEY (upload_id) REFERENCES uploads (id) ON DELETE CASCADE,
    CONSTRAINT chk_upload_parts_size CHECK (size_bytes > 0)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE IF NOT EXISTS tasks (
    id CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    upload_id CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    blob_id BIGINT UNSIGNED NOT NULL,
    created_by BIGINT UNSIGNED NOT NULL,
    name VARCHAR(255) NOT NULL,
    tags JSON NULL,
    status VARCHAR(32) CHARACTER SET ascii COLLATE ascii_bin NOT NULL DEFAULT 'UPLOADING',
    stage VARCHAR(32) CHARACTER SET ascii COLLATE ascii_bin NULL,
    progress_basis_points SMALLINT UNSIGNED NOT NULL DEFAULT 0,
    risk_level VARCHAR(16) CHARACTER SET ascii COLLATE ascii_bin NOT NULL DEFAULT 'UNKNOWN',
    limits_snapshot JSON NOT NULL,
    root_format VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NULL,
    error_code VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NULL,
    error_message VARCHAR(2048) NULL,
    sample_expires_at TIMESTAMP(6) NOT NULL,
    sample_deleted_at TIMESTAMP(6) NULL,
    completed_at TIMESTAMP(6) NULL,
    deleted_at TIMESTAMP(6) NULL,
    created_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
    PRIMARY KEY (id),
    UNIQUE KEY uq_tasks_upload_id (upload_id),
    KEY idx_tasks_status_created (status, created_at, id),
    KEY idx_tasks_creator_created (created_by, created_at, id),
    KEY idx_tasks_risk_created (risk_level, created_at, id),
    KEY idx_tasks_sample_expiry (sample_expires_at, sample_deleted_at),
    KEY idx_tasks_deleted_created (deleted_at, created_at, id),
    CONSTRAINT fk_tasks_upload FOREIGN KEY (upload_id) REFERENCES uploads (id),
    CONSTRAINT fk_tasks_blob FOREIGN KEY (blob_id) REFERENCES blobs (id),
    CONSTRAINT fk_tasks_creator FOREIGN KEY (created_by) REFERENCES users (id),
    CONSTRAINT chk_tasks_status CHECK (status IN (
        'UPLOADING', 'QUEUED', 'VALIDATING', 'IDENTIFYING', 'EXTRACTING',
        'INDEXING', 'SCANNING', 'REPORTING', 'SUCCEEDED', 'PARTIAL_SUCCEEDED',
        'FAILED', 'CANCEL_REQUESTED', 'CANCELLED', 'DELETING', 'DELETED'
    )),
    CONSTRAINT chk_tasks_risk CHECK (risk_level IN ('UNKNOWN', 'NONE', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
    CONSTRAINT chk_tasks_progress CHECK (progress_basis_points <= 10000)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE IF NOT EXISTS task_attempts (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    task_id CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    attempt_number INT UNSIGNED NOT NULL,
    fencing_token BIGINT UNSIGNED NOT NULL,
    status VARCHAR(32) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    statistics JSON NULL,
    error_code VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NULL,
    error_message VARCHAR(2048) NULL,
    started_at TIMESTAMP(6) NULL,
    completed_at TIMESTAMP(6) NULL,
    created_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    PRIMARY KEY (id),
    UNIQUE KEY uq_task_attempts_task_id_id (task_id, id),
    UNIQUE KEY uq_task_attempts_number (task_id, attempt_number),
    UNIQUE KEY uq_task_attempts_fencing (task_id, fencing_token),
    KEY idx_task_attempts_status_created (status, created_at),
    CONSTRAINT fk_task_attempts_task FOREIGN KEY (task_id) REFERENCES tasks (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE IF NOT EXISTS jobs (
    id CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    task_id CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    task_attempt_id BIGINT UNSIGNED NULL,
    kind VARCHAR(32) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    status VARCHAR(24) CHARACTER SET ascii COLLATE ascii_bin NOT NULL DEFAULT 'queued',
    priority SMALLINT NOT NULL DEFAULT 0,
    payload JSON NULL,
    available_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    attempt INT UNSIGNED NOT NULL DEFAULT 0,
    max_attempts INT UNSIGNED NOT NULL DEFAULT 3,
    fencing_token BIGINT UNSIGNED NOT NULL DEFAULT 0,
    lease_owner VARCHAR(255) CHARACTER SET ascii COLLATE ascii_bin NULL,
    lease_until TIMESTAMP(6) NULL,
    heartbeat_at TIMESTAMP(6) NULL,
    cancel_requested_at TIMESTAMP(6) NULL,
    idempotency_key VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NULL,
    error_code VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NULL,
    error_message VARCHAR(2048) NULL,
    started_at TIMESTAMP(6) NULL,
    completed_at TIMESTAMP(6) NULL,
    created_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
    PRIMARY KEY (id),
    UNIQUE KEY uq_jobs_task_id_id (task_id, id),
    UNIQUE KEY uq_jobs_task_idempotency (task_id, idempotency_key),
    KEY idx_jobs_claim (kind, status, priority DESC, available_at, lease_until, id),
    KEY idx_jobs_lease (status, lease_until),
    KEY idx_jobs_task_status (task_id, status, created_at),
    CONSTRAINT fk_jobs_task FOREIGN KEY (task_id) REFERENCES tasks (id) ON DELETE CASCADE,
    CONSTRAINT fk_jobs_task_attempt FOREIGN KEY (task_id, task_attempt_id) REFERENCES task_attempts (task_id, id) ON DELETE CASCADE,
    CONSTRAINT chk_jobs_kind CHECK (kind IN ('scan', 'image', 'native', 'bytecode', 'trivy', 'report', 'decompile')),
    CONSTRAINT chk_jobs_status CHECK (status IN ('queued', 'leased', 'running', 'succeeded', 'failed', 'cancel_requested', 'cancelled')),
    CONSTRAINT chk_jobs_attempts CHECK (attempt <= max_attempts)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE IF NOT EXISTS task_events (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    task_id CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    event_sequence BIGINT UNSIGNED NOT NULL,
    event_type VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    stage VARCHAR(32) CHARACTER SET ascii COLLATE ascii_bin NULL,
    progress_basis_points SMALLINT UNSIGNED NULL,
    severity VARCHAR(16) CHARACTER SET ascii COLLATE ascii_bin NOT NULL DEFAULT 'info',
    message VARCHAR(2048) NULL,
    payload JSON NULL,
    created_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    PRIMARY KEY (id),
    UNIQUE KEY uq_task_events_sequence (task_id, event_sequence),
    KEY idx_task_events_created (task_id, created_at, id),
    CONSTRAINT fk_task_events_task FOREIGN KEY (task_id) REFERENCES tasks (id) ON DELETE CASCADE,
    CONSTRAINT chk_task_events_progress CHECK (progress_basis_points IS NULL OR progress_basis_points <= 10000),
    CONSTRAINT chk_task_events_severity CHECK (severity IN ('debug', 'info', 'warning', 'error'))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE IF NOT EXISTS file_nodes (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    task_id CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    parent_id BIGINT UNSIGNED NULL,
    logical_path VARCHAR(2048) NOT NULL,
    logical_path_hash BINARY(32) NOT NULL,
    display_name VARCHAR(512) NOT NULL,
    node_type VARCHAR(24) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    depth SMALLINT UNSIGNED NOT NULL,
    format VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NULL,
    mime_type VARCHAR(255) CHARACTER SET ascii COLLATE ascii_bin NULL,
    architecture VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NULL,
    size_bytes BIGINT UNSIGNED NULL,
    sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NULL,
    storage_key VARCHAR(1024) CHARACTER SET ascii COLLATE ascii_bin NULL,
    extraction_status VARCHAR(24) CHARACTER SET ascii COLLATE ascii_bin NOT NULL DEFAULT 'indexed',
    metadata_json JSON NULL,
    error_code VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NULL,
    error_message VARCHAR(2048) NULL,
    created_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    PRIMARY KEY (id),
    UNIQUE KEY uq_file_nodes_task_id_id (task_id, id),
    KEY idx_file_nodes_parent (task_id, parent_id, id),
    KEY idx_file_nodes_path_hash (task_id, logical_path_hash),
    KEY idx_file_nodes_format (task_id, format, id),
    KEY idx_file_nodes_sha256 (sha256),
    CONSTRAINT fk_file_nodes_task FOREIGN KEY (task_id) REFERENCES tasks (id) ON DELETE CASCADE,
    CONSTRAINT fk_file_nodes_parent FOREIGN KEY (task_id, parent_id) REFERENCES file_nodes (task_id, id) ON DELETE CASCADE,
    CONSTRAINT chk_file_nodes_type CHECK (node_type IN ('file', 'directory', 'symlink', 'hardlink', 'special')),
    CONSTRAINT chk_file_nodes_depth CHECK (depth <= 10),
    CONSTRAINT chk_file_nodes_extraction CHECK (extraction_status IN ('indexed', 'extracted', 'skipped', 'unsupported', 'limit_reached', 'failed'))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE IF NOT EXISTS analyzer_runs (
    id CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    task_id CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    task_attempt_id BIGINT UNSIGNED NULL,
    job_id CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NULL,
    file_node_id BIGINT UNSIGNED NULL,
    analyzer_name VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    analyzer_version VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    parameters_json JSON NULL,
    status VARCHAR(24) CHARACTER SET ascii COLLATE ascii_bin NOT NULL DEFAULT 'queued',
    exit_code INT NULL,
    error_code VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NULL,
    error_message VARCHAR(2048) NULL,
    started_at TIMESTAMP(6) NULL,
    completed_at TIMESTAMP(6) NULL,
    created_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    PRIMARY KEY (id),
    UNIQUE KEY uq_analyzer_runs_task_id_id (task_id, id),
    KEY idx_analyzer_runs_task_created (task_id, created_at, id),
    KEY idx_analyzer_runs_node (file_node_id, analyzer_name, created_at),
    KEY idx_analyzer_runs_status (status, created_at),
    CONSTRAINT fk_analyzer_runs_task FOREIGN KEY (task_id) REFERENCES tasks (id) ON DELETE CASCADE,
    CONSTRAINT fk_analyzer_runs_attempt FOREIGN KEY (task_id, task_attempt_id) REFERENCES task_attempts (task_id, id) ON DELETE CASCADE,
    CONSTRAINT fk_analyzer_runs_job FOREIGN KEY (task_id, job_id) REFERENCES jobs (task_id, id) ON DELETE CASCADE,
    CONSTRAINT fk_analyzer_runs_file_node FOREIGN KEY (task_id, file_node_id) REFERENCES file_nodes (task_id, id) ON DELETE CASCADE,
    CONSTRAINT chk_analyzer_runs_status CHECK (status IN ('queued', 'running', 'succeeded', 'partial', 'failed', 'cancelled', 'timed_out'))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE IF NOT EXISTS decompile_results (
    id CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    task_id CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    file_node_id BIGINT UNSIGNED NOT NULL,
    analyzer_run_id CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NULL,
    cache_key CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    symbol_key VARCHAR(512) NOT NULL,
    language VARCHAR(32) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    engine_name VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    engine_version VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    status VARCHAR(24) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    storage_key VARCHAR(1024) CHARACTER SET ascii COLLATE ascii_bin NULL,
    content_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NULL,
    size_bytes BIGINT UNSIGNED NULL,
    diagnostics_json JSON NULL,
    created_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    completed_at TIMESTAMP(6) NULL,
    deleted_at TIMESTAMP(6) NULL,
    PRIMARY KEY (id),
    UNIQUE KEY uq_decompile_results_cache (cache_key),
    KEY idx_decompile_results_task_status (task_id, status, created_at),
    KEY idx_decompile_results_node (file_node_id, created_at),
    CONSTRAINT fk_decompile_results_task FOREIGN KEY (task_id) REFERENCES tasks (id) ON DELETE CASCADE,
    CONSTRAINT fk_decompile_results_file_node FOREIGN KEY (task_id, file_node_id) REFERENCES file_nodes (task_id, id) ON DELETE CASCADE,
    CONSTRAINT fk_decompile_results_analyzer FOREIGN KEY (task_id, analyzer_run_id) REFERENCES analyzer_runs (task_id, id) ON DELETE CASCADE,
    CONSTRAINT chk_decompile_results_status CHECK (status IN ('queued', 'running', 'complete', 'partial', 'bytecode_only', 'unsupported', 'failed', 'cancelled'))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE IF NOT EXISTS trivy_database_bundles (
    id CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    version VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    generated_at TIMESTAMP(6) NOT NULL,
    content_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    trivy_db_version VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    trivy_java_db_version VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    manifest_json MEDIUMTEXT CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL,
    registered_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    PRIMARY KEY (id),
    UNIQUE KEY uq_trivy_database_bundle_content (content_sha256),
    KEY idx_trivy_database_bundle_generated (generated_at DESC, id DESC),
    CONSTRAINT chk_trivy_database_bundle_manifest CHECK (JSON_VALID(manifest_json))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE IF NOT EXISTS vulnerability_findings (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    task_id CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    analyzer_run_id CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NULL,
    trivy_database_bundle_id CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NULL,
    image_logical_path VARCHAR(2048) NOT NULL,
    image_platform VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NULL,
    vulnerability_id VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    severity VARCHAR(16) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    package_name VARCHAR(512) NOT NULL,
    installed_version VARCHAR(512) NULL,
    fixed_version VARCHAR(512) NULL,
    title VARCHAR(1024) NULL,
    description_summary VARCHAR(2048) NULL,
    evidence_json JSON NULL,
    references_json JSON NULL,
    created_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    PRIMARY KEY (id),
    KEY idx_vulnerability_findings_task_severity (task_id, severity, id),
    KEY idx_vulnerability_findings_cve (vulnerability_id, task_id),
    KEY idx_vulnerability_findings_package (task_id, package_name(191)),
    KEY idx_vulnerability_findings_bundle (trivy_database_bundle_id),
    CONSTRAINT fk_vulnerability_findings_task FOREIGN KEY (task_id) REFERENCES tasks (id) ON DELETE CASCADE,
    CONSTRAINT fk_vulnerability_findings_analyzer FOREIGN KEY (task_id, analyzer_run_id) REFERENCES analyzer_runs (task_id, id) ON DELETE CASCADE,
    CONSTRAINT fk_vulnerability_findings_bundle FOREIGN KEY (trivy_database_bundle_id) REFERENCES trivy_database_bundles (id) ON DELETE SET NULL,
    CONSTRAINT chk_vulnerability_findings_severity CHECK (severity IN ('UNKNOWN', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE IF NOT EXISTS artifacts (
    id CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    task_id CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    task_attempt_id BIGINT UNSIGNED NULL,
    analyzer_run_id CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NULL,
    kind VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    media_type VARCHAR(255) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    storage_key VARCHAR(1024) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    size_bytes BIGINT UNSIGNED NOT NULL,
    state VARCHAR(24) CHARACTER SET ascii COLLATE ascii_bin NOT NULL DEFAULT 'staged',
    created_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    published_at TIMESTAMP(6) NULL,
    deleted_at TIMESTAMP(6) NULL,
    PRIMARY KEY (id),
    UNIQUE KEY uq_artifacts_task_id_id (task_id, id),
    UNIQUE KEY uq_artifacts_storage_key (storage_key),
    KEY idx_artifacts_task_kind (task_id, kind, created_at),
    KEY idx_artifacts_state_created (state, created_at),
    CONSTRAINT fk_artifacts_task FOREIGN KEY (task_id) REFERENCES tasks (id) ON DELETE CASCADE,
    CONSTRAINT fk_artifacts_attempt FOREIGN KEY (task_id, task_attempt_id) REFERENCES task_attempts (task_id, id) ON DELETE CASCADE,
    CONSTRAINT fk_artifacts_analyzer FOREIGN KEY (task_id, analyzer_run_id) REFERENCES analyzer_runs (task_id, id) ON DELETE CASCADE,
    CONSTRAINT chk_artifacts_state CHECK (state IN ('staged', 'published', 'deleting', 'deleted', 'failed'))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE IF NOT EXISTS reports (
    id CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    task_id CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    artifact_id CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NULL,
    format VARCHAR(16) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    schema_version VARCHAR(32) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    status VARCHAR(24) CHARACTER SET ascii COLLATE ascii_bin NOT NULL DEFAULT 'queued',
    storage_key VARCHAR(1024) CHARACTER SET ascii COLLATE ascii_bin NULL,
    sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NULL,
    size_bytes BIGINT UNSIGNED NULL,
    error_code VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NULL,
    error_message VARCHAR(2048) NULL,
    created_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    completed_at TIMESTAMP(6) NULL,
    deleted_at TIMESTAMP(6) NULL,
    PRIMARY KEY (id),
    UNIQUE KEY uq_reports_task_format_schema (task_id, format, schema_version),
    KEY idx_reports_status_created (status, created_at),
    CONSTRAINT fk_reports_task FOREIGN KEY (task_id) REFERENCES tasks (id) ON DELETE CASCADE,
    CONSTRAINT fk_reports_artifact FOREIGN KEY (task_id, artifact_id) REFERENCES artifacts (task_id, id) ON DELETE CASCADE,
    CONSTRAINT chk_reports_format CHECK (format IN ('json', 'html')),
    CONSTRAINT chk_reports_status CHECK (status IN ('queued', 'generating', 'complete', 'failed', 'deleted'))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE IF NOT EXISTS audit_logs (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    actor_user_id BIGINT UNSIGNED NULL,
    request_id VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NULL,
    action VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    object_type VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NULL,
    object_id VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NULL,
    outcome VARCHAR(24) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    client_ip VARBINARY(16) NULL,
    user_agent VARCHAR(512) NULL,
    metadata_json JSON NULL,
    created_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    PRIMARY KEY (id),
    KEY idx_audit_logs_created (created_at, id),
    KEY idx_audit_logs_actor_created (actor_user_id, created_at, id),
    KEY idx_audit_logs_action_created (action, created_at, id),
    KEY idx_audit_logs_object (object_type, object_id, created_at),
    CONSTRAINT fk_audit_logs_actor FOREIGN KEY (actor_user_id) REFERENCES users (id) ON DELETE SET NULL,
    CONSTRAINT chk_audit_logs_outcome CHECK (outcome IN ('success', 'failure', 'denied'))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE IF NOT EXISTS system_settings (
    setting_key VARCHAR(191) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    value_json JSON NOT NULL,
    description VARCHAR(512) NULL,
    updated_by BIGINT UNSIGNED NULL,
    created_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
    PRIMARY KEY (setting_key),
    KEY idx_system_settings_updated_at (updated_at),
    CONSTRAINT fk_system_settings_user FOREIGN KEY (updated_by) REFERENCES users (id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- +goose Down

DROP TABLE IF EXISTS system_settings;
DROP TABLE IF EXISTS audit_logs;
DROP TABLE IF EXISTS reports;
DROP TABLE IF EXISTS artifacts;
DROP TABLE IF EXISTS vulnerability_findings;
DROP TABLE IF EXISTS trivy_database_bundles;
DROP TABLE IF EXISTS decompile_results;
DROP TABLE IF EXISTS analyzer_runs;
DROP TABLE IF EXISTS file_nodes;
DROP TABLE IF EXISTS task_events;
DROP TABLE IF EXISTS jobs;
DROP TABLE IF EXISTS task_attempts;
DROP TABLE IF EXISTS tasks;
DROP TABLE IF EXISTS upload_parts;
DROP TABLE IF EXISTS uploads;
DROP TABLE IF EXISTS blobs;
DROP TABLE IF EXISTS sessions;
DROP TABLE IF EXISTS users;

-- +goose NO TRANSACTION
-- +goose Up

CREATE TABLE IF NOT EXISTS worker_readiness (
    worker_owner VARCHAR(255) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    worker_kind VARCHAR(32) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    analyzer_name VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    analyzer_version VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    runtime_name VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NULL,
    runtime_version VARCHAR(256) CHARACTER SET ascii COLLATE ascii_bin NULL,
    status VARCHAR(16) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    started_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    last_checked_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6)
        ON UPDATE CURRENT_TIMESTAMP(6),
    PRIMARY KEY (worker_owner),
    KEY idx_worker_readiness_analyzer (
        analyzer_name, status, last_checked_at, worker_kind
    ),
    KEY idx_worker_readiness_checked (last_checked_at),
    CONSTRAINT chk_worker_readiness_kind CHECK (
        worker_kind IN ('image', 'native', 'trivy')
    ),
    CONSTRAINT chk_worker_readiness_analyzer CHECK (
        (worker_kind = 'native' AND analyzer_name = 'ghidra') OR
        (worker_kind IN ('image', 'trivy') AND analyzer_name = 'trivy')
    ),
    CONSTRAINT chk_worker_readiness_status CHECK (status = 'ready')
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- +goose Down

DROP TABLE IF EXISTS worker_readiness;

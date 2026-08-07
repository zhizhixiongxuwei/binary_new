-- +goose Up

CREATE TABLE IF NOT EXISTS login_rate_limits (
    client_key BINARY(32) NOT NULL,
    window_started_at TIMESTAMP(6) NOT NULL,
    window_expires_at TIMESTAMP(6) NOT NULL,
    failure_count INT UNSIGNED NOT NULL DEFAULT 0,
    in_flight_count INT UNSIGNED NOT NULL DEFAULT 0,
    blocked_until TIMESTAMP(6) NULL,
    created_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6)
        ON UPDATE CURRENT_TIMESTAMP(6),
    PRIMARY KEY (client_key),
    KEY idx_login_rate_limits_updated (updated_at, client_key),
    CONSTRAINT chk_login_rate_limit_window
        CHECK (window_expires_at > window_started_at),
    CONSTRAINT chk_login_rate_limit_counts
        CHECK (
            failure_count <= 1000000
            AND in_flight_count <= 1000000
        )
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- +goose Down

DROP TABLE IF EXISTS login_rate_limits;

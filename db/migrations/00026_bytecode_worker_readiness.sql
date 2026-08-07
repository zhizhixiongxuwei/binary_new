-- +goose NO TRANSACTION
-- +goose Up

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

-- +goose Down

DELETE FROM worker_readiness WHERE worker_kind = 'bytecode';

ALTER TABLE worker_readiness
    DROP CHECK chk_worker_readiness_kind,
    DROP CHECK chk_worker_readiness_analyzer,
    ADD CONSTRAINT chk_worker_readiness_kind CHECK (
        worker_kind IN ('image', 'native', 'trivy')
    ),
    ADD CONSTRAINT chk_worker_readiness_analyzer CHECK (
        (worker_kind = 'native' AND analyzer_name = 'ghidra') OR
        (worker_kind IN ('image', 'trivy') AND analyzer_name = 'trivy')
    );

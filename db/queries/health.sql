-- name: Ping :one
SELECT 1;

-- name: CurrentSchemaVersion :one
SELECT MAX(version_id) AS version_id
FROM goose_db_version
WHERE is_applied = TRUE;

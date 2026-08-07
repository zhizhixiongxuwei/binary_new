-- Task creation is implemented transactionally in internal/task/repository.go because
-- upload ownership, blob retention, the first attempt, and the first job must commit
-- atomically. These named reads document the stable query contract.

-- name: GetTaskByID :one
SELECT t.id, t.name, t.root_format, t.status, t.risk_level,
       t.progress_basis_points, creator.public_id, creator.display_name, t.tags,
       t.created_at, t.updated_at, upload.display_name AS original_filename,
       stored_blob.size_bytes, stored_blob.sha256, t.stage, t.error_code,
       t.error_message, t.sample_expires_at
FROM tasks t
JOIN users creator ON creator.id = t.created_by
JOIN uploads upload ON upload.id = t.upload_id
JOIN blobs stored_blob ON stored_blob.id = t.blob_id
WHERE t.id = ?
LIMIT 1;

-- name: CountTasks :one
SELECT COUNT(*)
FROM tasks;

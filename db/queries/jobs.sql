-- Reference-only sqlc prototype; the current build does not generate this
-- directory. Runtime claims use internal/queue.claimCandidateSQL.
-- name: GetQueuedJobForUpdate :one
SELECT id, task_id, kind, priority, attempt, max_attempts, fencing_token
FROM jobs FORCE INDEX (idx_jobs_claim)
WHERE kind = ?
  AND status = 'queued'
  AND available_at <= UTC_TIMESTAMP(6)
  AND attempt < max_attempts
  AND cancel_requested_at IS NULL
ORDER BY priority DESC, available_at ASC, id ASC
LIMIT 1
FOR UPDATE SKIP LOCKED;

-- name: RenewJobLease :execrows
UPDATE jobs
SET lease_until = ?, heartbeat_at = CURRENT_TIMESTAMP(6)
WHERE id = ?
  AND lease_owner = ?
  AND fencing_token = ?
  AND status IN ('leased', 'running');

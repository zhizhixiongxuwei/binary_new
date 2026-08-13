package scan

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"errors"
	"fmt"
	"strconv"

	"binaryscan/internal/queue"
	"binaryscan/internal/trivyhandoff"
)

const (
	trivyJobMaxAttempts = 3
	maxTrivySourceBytes = int64(10 * 1024 * 1024 * 1024)
)

// EnqueueTrivy creates the single Trivy handoff for a scan attempt. The
// idempotency key is derived from the logical task attempt, while the live scan
// job and task-attempt fences protect both first publication and replay.
func (r *MySQLRepository) EnqueueTrivy(
	ctx context.Context,
	lease queue.Lease,
	payload TrivyJobPayload,
) error {
	if lease.Kind != queue.KindScan || lease.TaskAttemptID == nil ||
		lease.FencingToken == 0 {
		return queue.ErrLeaseLost
	}
	encoded, err := trivyhandoff.Encode(
		payload,
		maxTrivySourceBytes,
		trivyhandoff.MaxSources,
	)
	if err != nil {
		return ErrInvalidTrivyJob
	}
	jobID, err := newJobUUID()
	if err != nil {
		return fmt.Errorf("generate Trivy job ID: %w", err)
	}
	idempotencyKey := "trivy:attempt:" + strconv.FormatUint(
		*lease.TaskAttemptID, 10,
	)

	transaction, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin Trivy job handoff: %w", err)
	}
	defer transaction.Rollback()

	if err := lockTreePublishingLease(ctx, transaction, lease); err != nil {
		return err
	}
	if err := validateTrivyHandoffSources(
		ctx, transaction, lease.TaskID, payload,
	); err != nil {
		return err
	}

	var existing struct {
		id           string
		taskAttempt  uint64
		kind         queue.Kind
		status       string
		attempt      uint32
		maxAttempts  uint32
		fencingToken uint64
		payload      []byte
	}
	err = transaction.QueryRowContext(ctx, `
SELECT id, task_attempt_id, kind, status, attempt, max_attempts,
       fencing_token, payload
FROM jobs
WHERE task_id = ? AND idempotency_key = ?
FOR UPDATE`, lease.TaskID, idempotencyKey).Scan(
		&existing.id, &existing.taskAttempt, &existing.kind, &existing.status,
		&existing.attempt, &existing.maxAttempts, &existing.fencingToken,
		&existing.payload,
	)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		if _, err := transaction.ExecContext(ctx, `
INSERT INTO jobs (
    id, task_id, task_attempt_id, kind, status, priority, payload,
    available_at, attempt, max_attempts, fencing_token, idempotency_key,
    created_at, updated_at
) VALUES (?, ?, ?, 'trivy', 'queued', 0, ?, UTC_TIMESTAMP(6),
          0, ?, ?, ?, UTC_TIMESTAMP(6), UTC_TIMESTAMP(6))`,
			jobID, lease.TaskID, *lease.TaskAttemptID, encoded,
			trivyJobMaxAttempts, lease.FencingToken, idempotencyKey,
		); err != nil {
			return fmt.Errorf("insert Trivy job handoff: %w", err)
		}
	case err != nil:
		return fmt.Errorf("lock existing Trivy job handoff: %w", err)
	default:
		persisted, decodeErr := decodeTrivyJobPayload(existing.payload)
		if decodeErr != nil ||
			existing.taskAttempt != *lease.TaskAttemptID ||
			existing.kind != queue.KindTrivy ||
			existing.status != "queued" ||
			existing.attempt != 0 ||
			existing.maxAttempts != trivyJobMaxAttempts ||
			!equalTrivyPayload(persisted, payload) {
			return queue.ErrInconsistentState
		}
		if existing.fencingToken != lease.FencingToken {
			result, err := transaction.ExecContext(ctx, `
UPDATE jobs
SET fencing_token = ?,
    updated_at = UTC_TIMESTAMP(6)
WHERE id = ?
  AND task_id = ?
  AND task_attempt_id = ?
  AND kind = 'trivy'
  AND status = 'queued'
  AND attempt = 0
  AND fencing_token = ?`,
				lease.FencingToken, existing.id, lease.TaskID,
				*lease.TaskAttemptID, existing.fencingToken,
			)
			if err != nil {
				return fmt.Errorf("refresh Trivy handoff fence: %w", err)
			}
			if err := requireOneTrivy(
				result, "inspect refreshed Trivy handoff fence",
			); err != nil {
				return err
			}
		}
	}

	if err := transaction.Commit(); err != nil {
		return fmt.Errorf("commit Trivy job handoff: %w", err)
	}
	return nil
}

func validateTrivyHandoffSources(
	ctx context.Context,
	transaction *sql.Tx,
	taskID string,
	payload TrivyJobPayload,
) error {
	for _, source := range payload.Sources {
		if err := validateTrivyHandoffSource(
			ctx,
			transaction,
			taskID,
			source,
		); err != nil {
			return err
		}
	}
	return nil
}

func validateTrivyHandoffSource(
	ctx context.Context,
	transaction *sql.Tx,
	taskID string,
	source TrivySource,
) error {
	var format, storageKey, sha256Value string
	var sizeBytes uint64
	if source.ImageLogicalPath == "/" {
		err := transaction.QueryRowContext(ctx, `
SELECT format, storage_key, sha256, size_bytes
FROM file_nodes
WHERE task_id = ?
  AND parent_id IS NULL
  AND depth = 0
  AND node_type = 'file'
FOR UPDATE`, taskID).Scan(
			&format, &storageKey, &sha256Value, &sizeBytes,
		)
		if errors.Is(err, sql.ErrNoRows) {
			return queue.ErrInconsistentState
		}
		if err != nil {
			return fmt.Errorf("lock Trivy source root node: %w", err)
		}
	} else {
		logicalPathHash := sha256.Sum256([]byte(source.ImageLogicalPath))
		var (
			blobStorageKey string
			blobSHA256     string
			blobSizeBytes  uint64
			blobReferences uint64
			blobState      string
		)
		err := transaction.QueryRowContext(ctx, `
SELECT node.format, node.storage_key, node.sha256, node.size_bytes,
       stored_blob.storage_key, stored_blob.sha256, stored_blob.size_bytes,
       stored_blob.reference_count, stored_blob.state
FROM file_nodes node
JOIN file_node_blob_refs reference
  ON reference.task_id = node.task_id
 AND reference.file_node_id = node.id
JOIN blobs stored_blob ON stored_blob.id = reference.blob_id
WHERE node.task_id = ?
  AND node.logical_path_hash = ?
  AND node.logical_path = ?
  AND node.node_type = 'file'
FOR UPDATE`,
			taskID,
			logicalPathHash[:],
			source.ImageLogicalPath,
		).Scan(
			&format,
			&storageKey,
			&sha256Value,
			&sizeBytes,
			&blobStorageKey,
			&blobSHA256,
			&blobSizeBytes,
			&blobReferences,
			&blobState,
		)
		if errors.Is(err, sql.ErrNoRows) {
			return queue.ErrInconsistentState
		}
		if err != nil {
			return fmt.Errorf("lock nested Trivy source node: %w", err)
		}
		if blobStorageKey != source.SourceStorageKey ||
			blobSHA256 != source.SourceSHA256 ||
			blobSizeBytes != sizeBytes ||
			blobReferences == 0 ||
			blobState != "available" {
			return queue.ErrInconsistentState
		}
	}
	if sizeBytes > uint64(^uint64(0)>>1) ||
		!handoffFormatMatches(format, source.Format) ||
		storageKey != source.SourceStorageKey ||
		sha256Value != source.SourceSHA256 ||
		int64(sizeBytes) != source.SourceSizeBytes {
		return queue.ErrInconsistentState
	}
	return nil
}

// handoffFormatMatches accepts the exact detector format for container
// archives, and any Trivy-supported VM image format for vm-image sources whose
// root node keeps the detected ext/partitioned format name.
func handoffFormatMatches(detected string, handoff string) bool {
	if detected == handoff {
		return true
	}
	return handoff == trivyhandoff.FormatVMImage && vmImageFormat(detected)
}

func validTrivyJobPayload(payload TrivyJobPayload) bool {
	return trivyhandoff.Validate(
		payload,
		maxTrivySourceBytes,
		trivyhandoff.MaxSources,
	) == nil
}

func decodeTrivyJobPayload(raw []byte) (TrivyJobPayload, error) {
	return trivyhandoff.Decode(
		raw,
		maxTrivySourceBytes,
		trivyhandoff.MaxSources,
	)
}

func equalTrivyPayload(left TrivyJobPayload, right TrivyJobPayload) bool {
	if left.SchemaVersion != right.SchemaVersion ||
		left.MaxExpandedBytes != right.MaxExpandedBytes ||
		left.MaxArchiveRatio != right.MaxArchiveRatio ||
		left.UpstreamPartial != right.UpstreamPartial ||
		len(left.Sources) != len(right.Sources) {
		return false
	}
	for index := range left.Sources {
		if left.Sources[index] != right.Sources[index] {
			return false
		}
	}
	return true
}

func newJobUUID() (string, error) {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", err
	}
	value[6] = (value[6] & 0x0f) | 0x40
	value[8] = (value[8] & 0x3f) | 0x80
	return fmt.Sprintf(
		"%x-%x-%x-%x-%x",
		value[0:4], value[4:6], value[6:8], value[8:10], value[10:16],
	), nil
}

func requireOneTrivy(result sql.Result, operation string) error {
	affected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("%s: %w", operation, err)
	}
	if affected != 1 {
		return queue.ErrInconsistentState
	}
	return nil
}

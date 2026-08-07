package sampleexport

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

type MySQLRepository struct {
	db *sql.DB
}

func NewMySQLRepository(db *sql.DB) *MySQLRepository {
	return &MySQLRepository{db: db}
}

func (r *MySQLRepository) ResolveRootBlob(
	ctx context.Context,
	taskID string,
) (BlobDescriptor, error) {
	if r == nil || r.db == nil {
		return BlobDescriptor{}, errors.New(
			"sample export database is not configured",
		)
	}
	var (
		value        BlobDescriptor
		uploadBlobID sql.NullInt64
	)
	err := r.db.QueryRowContext(ctx, `
SELECT sample_blob.id, task.blob_id, upload.blob_id,
       sample_blob.storage_key, sample_blob.sha256, sample_blob.size_bytes,
       sample_blob.state, sample_blob.reference_count,
       upload.status, upload.actual_sha256, upload.declared_size_bytes
FROM tasks task
JOIN uploads upload ON upload.id = task.upload_id
JOIN blobs sample_blob ON sample_blob.id = task.blob_id
WHERE task.id = ?
  AND task.deleted_at IS NULL
  AND task.status NOT IN ('DELETING', 'DELETED')
  AND task.sample_deleted_at IS NULL
  AND task.sample_expires_at > UTC_TIMESTAMP(6)
  AND upload.completed_at IS NOT NULL
  AND upload.actual_sha256 = sample_blob.sha256
  AND upload.declared_size_bytes = sample_blob.size_bytes
  AND (
      (upload.status = 'completed' AND upload.blob_id = sample_blob.id)
      OR
      (upload.status = 'expired' AND upload.blob_id IS NULL)
  )
  AND sample_blob.state = 'available'
  AND sample_blob.deleted_at IS NULL
  AND sample_blob.verified_at IS NOT NULL
  AND sample_blob.reference_count > 0
LIMIT 1`,
		taskID,
	).Scan(
		&value.ID,
		&value.TaskBlobID,
		&uploadBlobID,
		&value.StorageKey,
		&value.SHA256,
		&value.SizeBytes,
		&value.State,
		&value.ReferenceCount,
		&value.UploadStatus,
		&value.UploadSHA256,
		&value.UploadDeclaredBytes,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return BlobDescriptor{}, ErrNotFound
	}
	if err != nil {
		return BlobDescriptor{}, fmt.Errorf(
			"resolve retained root sample: %w",
			err,
		)
	}
	if uploadBlobID.Valid {
		if uploadBlobID.Int64 <= 0 {
			return BlobDescriptor{}, ErrIntegrity
		}
		converted := uint64(uploadBlobID.Int64)
		value.UploadBlobID = &converted
	}
	return value, nil
}

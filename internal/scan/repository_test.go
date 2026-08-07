package scan

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"testing"

	"binaryscan/internal/queue"

	"github.com/DATA-DOG/go-sqlmock"
)

func TestMySQLRepositoryLoadsTaskBlobAndUpload(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	repository := NewMySQLRepository(db)
	lease := scanLease()
	sha := "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
	key := "blobs/sha256/ab/" + sha

	mock.ExpectQuery(`(?s)SELECT task\.id, upload\.id, stored_blob\.id, upload\.blob_id.*FROM tasks task.*JOIN blobs stored_blob.*JOIN uploads upload.*WHERE task\.id = \?`).
		WithArgs(lease.TaskID).
		WillReturnRows(sqlmock.NewRows([]string{
			"task_id", "upload_id", "blob_id", "upload_blob_id",
			"display_name", "size_bytes", "declared_size_bytes",
			"sha256", "actual_sha256", "storage_key",
			"blob_state", "upload_status", "limits_snapshot",
			"sample_deleted_at", "task_deleted_at",
		}).AddRow(
			lease.TaskID, "123e4567-e89b-42d3-a456-426614174002",
			uint64(7), int64(7), "firmware.bin", uint64(42), uint64(42),
			sha, sha, key,
			"available", "completed", validLimitsJSON(), nil, nil,
		))

	sample, err := repository.Load(context.Background(), lease)
	if err != nil {
		t.Fatal(err)
	}
	if sample.TaskID != lease.TaskID || sample.BlobID != 7 ||
		sample.DisplayName != "firmware.bin" || sample.SizeBytes != 42 ||
		sample.SHA256 != sha || sample.StorageKey != key ||
		sample.Limits.MaxExpandedBytes != 50*1024*1024*1024 ||
		sample.Limits.MaxEntryBytes != 10*1024*1024*1024 ||
		sample.Limits.MaxRatio != 100 || sample.Limits.MaxDepth != 10 ||
		sample.Limits.MaxNodes != 99_999 {
		t.Fatalf("Load() = %+v", sample)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestDecodeExtractionLimitsCapsEntryAtExpandedLimit(t *testing.T) {
	limits, err := decodeExtractionLimits([]byte(`{
		"max_upload_bytes":10737418240,
		"max_expanded_bytes":1048576,
		"max_archive_ratio":100,
		"max_depth":10,
		"max_file_nodes":100000
	}`))
	if err != nil {
		t.Fatal(err)
	}
	if limits.MaxEntryBytes != 1048576 ||
		limits.MaxEntryBytes > limits.MaxExpandedBytes {
		t.Fatalf("limits = %+v", limits)
	}
}

func TestMySQLRepositoryClassifiesUnavailableOrInconsistentSample(t *testing.T) {
	t.Run("missing task", func(t *testing.T) {
		db, mock, err := sqlmock.New()
		if err != nil {
			t.Fatal(err)
		}
		defer db.Close()
		repository := NewMySQLRepository(db)
		lease := scanLease()
		mock.ExpectQuery(`(?s)SELECT task\.id.*WHERE task\.id = \?`).
			WithArgs(lease.TaskID).
			WillReturnError(sql.ErrNoRows)

		if _, err := repository.Load(
			context.Background(), lease,
		); !errors.Is(err, ErrSampleMissing) {
			t.Fatalf("Load() error = %v", err)
		}
	})

	t.Run("blob mismatch", func(t *testing.T) {
		db, mock, err := sqlmock.New()
		if err != nil {
			t.Fatal(err)
		}
		defer db.Close()
		repository := NewMySQLRepository(db)
		lease := scanLease()
		mock.ExpectQuery(`(?s)SELECT task\.id.*WHERE task\.id = \?`).
			WithArgs(lease.TaskID).
			WillReturnRows(sampleRow(lease.TaskID, uint64(7), int64(8), uint64(42)))

		if _, err := repository.Load(
			context.Background(), lease,
		); !errors.Is(err, ErrSampleMismatch) {
			t.Fatalf("Load() error = %v", err)
		}
	})

	t.Run("oversized database value", func(t *testing.T) {
		db, mock, err := sqlmock.New()
		if err != nil {
			t.Fatal(err)
		}
		defer db.Close()
		repository := NewMySQLRepository(db)
		lease := scanLease()
		mock.ExpectQuery(`(?s)SELECT task\.id.*WHERE task\.id = \?`).
			WithArgs(lease.TaskID).
			WillReturnRows(sampleRow(
				lease.TaskID, uint64(7), int64(7),
				fmt.Sprintf("%d", uint64(math.MaxInt64)+1),
			))

		if _, err := repository.Load(
			context.Background(), lease,
		); !errors.Is(err, ErrSampleMismatch) {
			t.Fatalf("Load() error = %v", err)
		}
	})

	t.Run("invalid limits snapshot", func(t *testing.T) {
		db, mock, err := sqlmock.New()
		if err != nil {
			t.Fatal(err)
		}
		defer db.Close()
		repository := NewMySQLRepository(db)
		lease := scanLease()
		mock.ExpectQuery(`(?s)SELECT task\.id.*WHERE task\.id = \?`).
			WithArgs(lease.TaskID).
			WillReturnRows(sqlmock.NewRows([]string{
				"task_id", "upload_id", "blob_id", "upload_blob_id",
				"display_name", "size_bytes", "declared_size_bytes",
				"sha256", "actual_sha256", "storage_key",
				"blob_state", "upload_status", "limits_snapshot",
				"sample_deleted_at", "task_deleted_at",
			}).AddRow(
				lease.TaskID, "123e4567-e89b-42d3-a456-426614174002",
				uint64(7), int64(7), "firmware.bin", uint64(42), uint64(42),
				"abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
				"abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
				"blobs/sha256/ab/abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
				"available", "completed", []byte(`{"max_depth":10}`), nil, nil,
			))

		if _, err := repository.Load(
			context.Background(), lease,
		); !errors.Is(err, ErrInvalidLimits) {
			t.Fatalf("Load() error = %v", err)
		}
	})
}

func TestMySQLRepositoryPublishesRootWithFencingTransaction(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	repository := NewMySQLRepository(db)
	lease := scanLease()
	node := testRootNode()

	expectPublishingLocks(mock, lease)
	mock.ExpectQuery(`(?s)SELECT id.*FROM file_nodes.*parent_id IS NULL.*depth = 0.*LIMIT 2.*FOR UPDATE`).
		WithArgs(lease.TaskID).
		WillReturnRows(sqlmock.NewRows([]string{"id"}))
	mock.ExpectExec(`(?s)INSERT INTO file_nodes.*parent_id.*logical_path.*logical_path_hash.*node_type.*metadata_json`).
		WithArgs(
			lease.TaskID, node.LogicalPath, node.LogicalPathHash[:],
			node.DisplayName, node.Format, node.MIMEType, node.Architecture,
			node.SizeBytes, node.SHA256, node.StorageKey, []byte(node.MetadataJSON),
		).
		WillReturnResult(sqlmock.NewResult(31, 1))
	expectLeaseRevalidation(mock, lease, nil)
	mock.ExpectExec(`(?s)UPDATE tasks.*root_format = \?.*status = 'IDENTIFYING'`).
		WithArgs(node.Format, lease.TaskID).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`(?s)INSERT INTO task_events.*SELECT.*FROM tasks.*WHERE id = \?`).
		WithArgs(
			"task.metadata_changed", "Task root format identified.", lease.TaskID,
		).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

	if err := repository.Publish(context.Background(), lease, node); err != nil {
		t.Fatal(err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestMySQLRepositoryIdempotentlyUpdatesExistingRoot(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	repository := NewMySQLRepository(db)
	lease := scanLease()
	node := testRootNode()

	expectPublishingLocks(mock, lease)
	mock.ExpectQuery(`(?s)SELECT id.*FROM file_nodes.*LIMIT 2.*FOR UPDATE`).
		WithArgs(lease.TaskID).
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(uint64(31)))
	mock.ExpectExec(`(?s)UPDATE file_nodes.*logical_path = \?.*metadata_json = \?.*WHERE id = \?.*task_id = \?.*parent_id IS NULL`).
		WithArgs(
			node.LogicalPath, node.LogicalPathHash[:], node.DisplayName,
			node.Format, node.MIMEType, node.Architecture, node.SizeBytes,
			node.SHA256, node.StorageKey, []byte(node.MetadataJSON),
			uint64(31), lease.TaskID,
		).
		WillReturnResult(sqlmock.NewResult(0, 0))
	expectLeaseRevalidation(mock, lease, nil)
	mock.ExpectExec(`(?s)UPDATE tasks.*root_format = \?.*status = 'IDENTIFYING'`).
		WithArgs(node.Format, lease.TaskID).
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectCommit()

	if err := repository.Publish(context.Background(), lease, node); err != nil {
		t.Fatal(err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestMySQLRepositoryRejectsStaleFenceBeforePublication(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	repository := NewMySQLRepository(db)
	lease := scanLease()
	mock.ExpectBegin()
	mock.ExpectQuery(`(?s)SELECT task_attempt_id.*FROM jobs.*status = 'running'.*lease_owner = \?.*fencing_token = \?.*lease_until > UTC_TIMESTAMP.*FOR UPDATE`).
		WithArgs(lease.JobID, lease.TaskID, lease.Owner, lease.FencingToken).
		WillReturnError(sql.ErrNoRows)
	mock.ExpectRollback()

	err = repository.Publish(context.Background(), lease, testRootNode())
	if !errors.Is(err, queue.ErrLeaseLost) {
		t.Fatalf("Publish() error = %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestMySQLRepositoryRejectsStaleTaskAttemptFenceBeforePublication(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	repository := NewMySQLRepository(db)
	lease := scanLease()
	mock.ExpectBegin()
	mock.ExpectQuery(`(?s)SELECT task_attempt_id.*FROM jobs.*FOR UPDATE`).
		WithArgs(lease.JobID, lease.TaskID, lease.Owner, lease.FencingToken).
		WillReturnRows(sqlmock.NewRows([]string{"task_attempt_id"}).
			AddRow(int64(*lease.TaskAttemptID)))
	mock.ExpectQuery(`(?s)SELECT fencing_token.*FROM task_attempts.*status = 'running'.*fencing_token = \?.*FOR UPDATE`).
		WithArgs(*lease.TaskAttemptID, lease.TaskID, lease.FencingToken).
		WillReturnError(sql.ErrNoRows)
	mock.ExpectRollback()

	err = repository.Publish(context.Background(), lease, testRootNode())
	if !errors.Is(err, queue.ErrLeaseLost) {
		t.Fatalf("Publish() error = %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestMySQLRepositoryRollsBackWhenLeaseExpiresBeforeCommit(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	repository := NewMySQLRepository(db)
	lease := scanLease()
	node := testRootNode()

	expectPublishingLocks(mock, lease)
	mock.ExpectQuery(`(?s)SELECT id.*FROM file_nodes.*LIMIT 2.*FOR UPDATE`).
		WithArgs(lease.TaskID).
		WillReturnRows(sqlmock.NewRows([]string{"id"}))
	mock.ExpectExec(`(?s)INSERT INTO file_nodes`).
		WithArgs(
			lease.TaskID, node.LogicalPath, node.LogicalPathHash[:],
			node.DisplayName, node.Format, node.MIMEType, node.Architecture,
			node.SizeBytes, node.SHA256, node.StorageKey, []byte(node.MetadataJSON),
		).
		WillReturnResult(sqlmock.NewResult(31, 1))
	expectLeaseRevalidation(mock, lease, sql.ErrNoRows)
	mock.ExpectRollback()

	err = repository.Publish(context.Background(), lease, node)
	if !errors.Is(err, queue.ErrLeaseLost) {
		t.Fatalf("Publish() error = %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestMySQLRepositoryRejectsDuplicateRootNodes(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	repository := NewMySQLRepository(db)
	lease := scanLease()

	expectPublishingLocks(mock, lease)
	mock.ExpectQuery(`(?s)SELECT id.*FROM file_nodes.*LIMIT 2.*FOR UPDATE`).
		WithArgs(lease.TaskID).
		WillReturnRows(sqlmock.NewRows([]string{"id"}).
			AddRow(uint64(31)).
			AddRow(uint64(32)))
	mock.ExpectRollback()

	err = repository.Publish(context.Background(), lease, testRootNode())
	if !errors.Is(err, queue.ErrInconsistentState) {
		t.Fatalf("Publish() error = %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func expectPublishingLocks(
	mock sqlmock.Sqlmock,
	lease queue.Lease,
) {
	mock.ExpectBegin()
	mock.ExpectQuery(`(?s)SELECT task_attempt_id.*FROM jobs.*kind = 'scan'.*status = 'running'.*lease_owner = \?.*fencing_token = \?.*lease_until > UTC_TIMESTAMP.*cancel_requested_at IS NULL.*FOR UPDATE`).
		WithArgs(lease.JobID, lease.TaskID, lease.Owner, lease.FencingToken).
		WillReturnRows(sqlmock.NewRows([]string{"task_attempt_id"}).
			AddRow(int64(*lease.TaskAttemptID)))
	mock.ExpectQuery(`(?s)SELECT fencing_token.*FROM task_attempts.*status = 'running'.*fencing_token = \?.*FOR UPDATE`).
		WithArgs(*lease.TaskAttemptID, lease.TaskID, lease.FencingToken).
		WillReturnRows(sqlmock.NewRows([]string{"fencing_token"}).
			AddRow(lease.FencingToken))
	mock.ExpectQuery(`(?s)SELECT status.*FROM tasks.*status = 'IDENTIFYING'.*sample_deleted_at IS NULL.*deleted_at IS NULL.*FOR UPDATE`).
		WithArgs(lease.TaskID).
		WillReturnRows(sqlmock.NewRows([]string{"status"}).AddRow("IDENTIFYING"))
}

func expectLeaseRevalidation(
	mock sqlmock.Sqlmock,
	lease queue.Lease,
	result error,
) {
	expectation := mock.ExpectQuery(`(?s)SELECT 1.*FROM jobs.*status = 'running'.*lease_owner = \?.*fencing_token = \?.*lease_until > UTC_TIMESTAMP.*cancel_requested_at IS NULL`).
		WithArgs(lease.JobID, lease.TaskID, lease.Owner, lease.FencingToken)
	if result != nil {
		expectation.WillReturnError(result)
		return
	}
	expectation.WillReturnRows(sqlmock.NewRows([]string{"valid"}).AddRow(1))
}

func testRootNode() RootNode {
	digestBytes := sha256ForTest("root")
	digest := fmt.Sprintf("%x", digestBytes[:])
	pathHash := sha256ForTest("/")
	return RootNode{
		LogicalPath: "/", LogicalPathHash: pathHash,
		DisplayName: "firmware.bin", Format: "elf64",
		MIMEType: "application/x-elf", Architecture: "x86_64",
		SizeBytes: 42, SHA256: digest,
		StorageKey:   "blobs/sha256/" + digest[:2] + "/" + digest,
		MetadataJSON: json.RawMessage(`{"bits":64}`),
	}
}

func sha256ForTest(value string) [32]byte {
	return sha256.Sum256([]byte(value))
}

func sampleRow(
	taskID string,
	blobID uint64,
	uploadBlobID any,
	size any,
) *sqlmock.Rows {
	digest := sha256ForTest("sample")
	encoded := fmt.Sprintf("%x", digest[:])
	return sqlmock.NewRows([]string{
		"task_id", "upload_id", "blob_id", "upload_blob_id",
		"display_name", "size_bytes", "declared_size_bytes",
		"sha256", "actual_sha256", "storage_key",
		"blob_state", "upload_status", "limits_snapshot",
		"sample_deleted_at", "task_deleted_at",
	}).AddRow(
		taskID, "123e4567-e89b-42d3-a456-426614174002",
		blobID, uploadBlobID, "firmware.bin", size, size, encoded, encoded,
		"blobs/sha256/"+encoded[:2]+"/"+encoded,
		"available", "completed", validLimitsJSON(), nil, nil,
	)
}

func validLimitsJSON() []byte {
	return []byte(`{
		"max_upload_bytes":10737418240,
		"max_expanded_bytes":53687091200,
		"max_archive_ratio":100,
		"max_depth":10,
		"max_file_nodes":100000,
		"max_nested_images":10
	}`)
}

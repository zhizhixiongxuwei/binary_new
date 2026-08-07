package sampleexport

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
)

func TestMySQLRepositoryResolvesCurrentRetainedRootCASAssociation(
	t *testing.T,
) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	digest := strings.Repeat("a", 64)
	storageKey := "blobs/sha256/aa/" + digest
	mock.ExpectQuery(
		`(?s)SELECT sample_blob[.]id, task[.]blob_id, upload[.]blob_id.*` +
			`FROM tasks task.*JOIN uploads upload.*JOIN blobs sample_blob.*` +
			`task[.]sample_expires_at > UTC_TIMESTAMP[(]6[)].*` +
			`upload[.]actual_sha256 = sample_blob[.]sha256.*` +
			`upload[.]declared_size_bytes = sample_blob[.]size_bytes.*` +
			`sample_blob[.]reference_count > 0`,
	).WithArgs("00000000-0000-4000-8000-000000000001").
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "task_blob_id", "upload_blob_id", "storage_key",
			"sha256", "size_bytes", "state", "reference_count",
			"upload_status", "actual_sha256", "declared_size_bytes",
		}).AddRow(
			7, 7, 7, storageKey, digest, 42, "available", 2,
			"completed", digest, 42,
		))

	value, err := NewMySQLRepository(db).ResolveRootBlob(
		context.Background(),
		"00000000-0000-4000-8000-000000000001",
	)
	if err != nil {
		t.Fatal(err)
	}
	if value.ID != 7 ||
		value.TaskBlobID != 7 ||
		value.UploadBlobID == nil ||
		*value.UploadBlobID != 7 ||
		value.StorageKey != storageKey ||
		value.SHA256 != digest ||
		value.SizeBytes != 42 ||
		value.ReferenceCount != 2 {
		t.Fatalf("resolved descriptor = %+v", value)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestMySQLRepositoryAllowsExpiredUploadAfterTaskOwnsBlob(
	t *testing.T,
) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	digest := strings.Repeat("b", 64)
	mock.ExpectQuery(`(?s)upload[.]status = 'expired'.*upload[.]blob_id IS NULL`).
		WithArgs("00000000-0000-4000-8000-000000000002").
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "task_blob_id", "upload_blob_id", "storage_key",
			"sha256", "size_bytes", "state", "reference_count",
			"upload_status", "actual_sha256", "declared_size_bytes",
		}).AddRow(
			8, 8, nil, "blobs/sha256/bb/"+digest,
			digest, 10, "available", 1, "expired", digest, 10,
		))

	value, err := NewMySQLRepository(db).ResolveRootBlob(
		context.Background(),
		"00000000-0000-4000-8000-000000000002",
	)
	if err != nil {
		t.Fatal(err)
	}
	if value.UploadBlobID != nil || value.UploadStatus != "expired" {
		t.Fatalf("expired upload descriptor = %+v", value)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestMySQLRepositoryHidesExpiredDeletedOrInconsistentAssociation(
	t *testing.T,
) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	mock.ExpectQuery(`(?s)FROM tasks task.*UTC_TIMESTAMP[(]6[)]`).
		WithArgs("00000000-0000-4000-8000-000000000003").
		WillReturnError(sql.ErrNoRows)

	_, err = NewMySQLRepository(db).ResolveRootBlob(
		context.Background(),
		"00000000-0000-4000-8000-000000000003",
	)
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("ResolveRootBlob() error = %v, want ErrNotFound", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

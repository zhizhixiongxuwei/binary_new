package archiveimport

import (
	"context"
	"regexp"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
)

func TestEnsureUsesNonReservedBlobAlias(t *testing.T) {
	database, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	repository, err := NewMySQLRepository(database)
	if err != nil {
		t.Fatal(err)
	}

	mock.ExpectBegin()
	mock.ExpectQuery(regexp.QuoteMeta(`
SELECT upload.created_by, upload.display_name, upload.declared_size_bytes,
       upload.actual_sha256, upload.status, upload.blob_id, stored_blob.state,
       stored_blob.storage_key, stored_blob.sha256, stored_blob.size_bytes,
       intake.input_category, intake.detected_category,
       intake.detected_format, intake.validation_status,
       intake.source_kind, intake.archive_import_id
FROM uploads upload
JOIN upload_intake_profiles intake ON intake.upload_id = upload.id
LEFT JOIN blobs stored_blob ON stored_blob.id = upload.blob_id
WHERE upload.id = ?
FOR UPDATE`)).
		WithArgs("123e4567-e89b-42d3-a456-426614174000").
		WillReturnError(context.Canceled)
	mock.ExpectRollback()

	_, _, err = repository.Ensure(context.Background(),
		"123e4567-e89b-42d3-a456-426614174001", EnsureInput{
			UploadID: "123e4567-e89b-42d3-a456-426614174000",
		}, []byte(`{}`))
	if err == nil {
		t.Fatal("Ensure() error = nil")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

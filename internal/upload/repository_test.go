package upload

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"testing"
	"time"

	"binaryscan/internal/inputcategory"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/go-sql-driver/mysql"
)

func TestCreatePersistsUploadAndIdempotencyRecordAtomically(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	repository := NewMySQLRepository(db)
	now := time.Date(2026, 7, 31, 1, 2, 3, 0, time.UTC)
	value := Upload{
		ID:           "123e4567-e89b-42d3-a456-426614174000",
		CreatedBy:    7,
		OriginalName: []byte("sample.bin"),
		DisplayName:  "sample.bin",
		ContentType:  "application/octet-stream",
		DeclaredSize: 42,
		PartSize:     DefaultPartSize,
		Status:       "created",
		ExpiresAt:    now.Add(time.Hour),
		CreatedAt:    now,
		IntakeProfile: &IntakeProfile{
			UploadID:         "123e4567-e89b-42d3-a456-426614174000",
			InputCategory:    inputcategory.Binary,
			ValidationStatus: ValidationPending,
			SourceKind:       SourceDirect,
		},
	}
	fingerprint := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

	mock.ExpectBegin()
	mock.ExpectQuery(
		`(?s)SELECT id, created_by, original_name.*request_fingerprint.*FROM uploads.*FOR UPDATE`,
	).
		WithArgs(uint64(7), "create", "stable-key").
		WillReturnRows(idempotentCreateRows())
	mock.ExpectExec(
		`(?s)INSERT INTO uploads.*idempotency_key, idempotency_operation, request_fingerprint`,
	).
		WithArgs(
			value.ID,
			value.CreatedBy,
			value.OriginalName,
			value.DisplayName,
			value.ContentType,
			value.DeclaredSize,
			value.PartSize,
			value.ExpiresAt,
			"stable-key",
			"create",
			fingerprint,
		).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`(?s)INSERT INTO upload_intake_profiles`).
		WithArgs(value.ID, string(inputcategory.Binary)).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

	stored, created, err := repository.Create(
		context.Background(),
		value,
		"create",
		"stable-key",
		fingerprint,
	)
	if err != nil {
		t.Fatal(err)
	}
	if !created || stored.ID != value.ID {
		t.Fatalf("Create() = %#v/%v, want newly created upload", stored, created)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestResolveCreateReturnsCreationSnapshotAndRejectsFingerprintConflict(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	repository := NewMySQLRepository(db)
	now := time.Date(2026, 7, 31, 1, 2, 3, 0, time.UTC)
	fingerprint := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	row := func() *sqlmock.Rows {
		return idempotentCreateRows().AddRow(
			"123e4567-e89b-42d3-a456-426614174000",
			7,
			[]byte("sample.bin"),
			"sample.bin",
			"application/octet-stream",
			42,
			DefaultPartSize,
			now.Add(time.Hour),
			now,
			fingerprint,
		)
	}
	mock.ExpectQuery(
		`(?s)SELECT id, created_by, original_name.*request_fingerprint.*FROM uploads.*LIMIT 1`,
	).
		WithArgs(uint64(7), "create", "stable-key").
		WillReturnRows(row())
	mock.ExpectQuery(`(?s)FROM upload_intake_profiles.*WHERE upload_id = \?`).
		WithArgs("123e4567-e89b-42d3-a456-426614174000").
		WillReturnRows(pendingIntakeProfileRows(now, "123e4567-e89b-42d3-a456-426614174000"))
	mock.ExpectQuery(
		`(?s)SELECT id, created_by, original_name.*request_fingerprint.*FROM uploads.*LIMIT 1`,
	).
		WithArgs(uint64(7), "create", "stable-key").
		WillReturnRows(row())

	stored, found, err := repository.ResolveCreate(
		context.Background(),
		7,
		"create",
		"stable-key",
		fingerprint,
	)
	if err != nil || !found {
		t.Fatalf("ResolveCreate() = %#v/%v/%v", stored, found, err)
	}
	if stored.ID != "123e4567-e89b-42d3-a456-426614174000" ||
		stored.Status != "created" ||
		stored.ActualSHA256 != "" ||
		stored.BlobID != nil ||
		stored.CompletedAt != nil {
		t.Fatalf("ResolveCreate() snapshot = %#v", stored)
	}

	conflict, found, err := repository.ResolveCreate(
		context.Background(),
		7,
		"create",
		"stable-key",
		"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
	)
	if !errors.Is(err, ErrIdempotencyConflict) || found || conflict.ID != "" {
		t.Fatalf("conflicting ResolveCreate() = %#v/%v/%v", conflict, found, err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestCreateResolvesConcurrentUniqueKeyWinner(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	repository := NewMySQLRepository(db)
	now := time.Date(2026, 7, 31, 1, 2, 3, 0, time.UTC)
	fingerprint := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	loser := Upload{
		ID:           "123e4567-e89b-42d3-a456-426614174000",
		CreatedBy:    7,
		OriginalName: []byte("sample.bin"),
		DisplayName:  "sample.bin",
		ContentType:  "application/octet-stream",
		DeclaredSize: 42,
		PartSize:     DefaultPartSize,
		Status:       "created",
		ExpiresAt:    now.Add(time.Hour),
		CreatedAt:    now,
		IntakeProfile: &IntakeProfile{
			UploadID:         "123e4567-e89b-42d3-a456-426614174000",
			InputCategory:    inputcategory.Binary,
			ValidationStatus: ValidationPending,
			SourceKind:       SourceDirect,
		},
	}
	winnerID := "223e4567-e89b-42d3-a456-426614174000"

	mock.ExpectBegin()
	mock.ExpectQuery(
		`(?s)SELECT id, created_by, original_name.*request_fingerprint.*FROM uploads.*FOR UPDATE`,
	).
		WithArgs(uint64(7), "create", "stable-key").
		WillReturnRows(idempotentCreateRows())
	mock.ExpectExec(`(?s)INSERT INTO uploads`).
		WithArgs(
			loser.ID,
			loser.CreatedBy,
			loser.OriginalName,
			loser.DisplayName,
			loser.ContentType,
			loser.DeclaredSize,
			loser.PartSize,
			loser.ExpiresAt,
			"stable-key",
			"create",
			fingerprint,
		).
		WillReturnError(&mysql.MySQLError{
			Number:  1062,
			Message: "Duplicate entry for uq_uploads_creator_operation_idempotency",
		})
	mock.ExpectRollback()
	mock.ExpectQuery(
		`(?s)SELECT id, created_by, original_name.*request_fingerprint.*FROM uploads.*LIMIT 1`,
	).
		WithArgs(uint64(7), "create", "stable-key").
		WillReturnRows(idempotentCreateRows().AddRow(
			winnerID,
			7,
			[]byte("sample.bin"),
			"sample.bin",
			"application/octet-stream",
			42,
			DefaultPartSize,
			now.Add(time.Hour),
			now,
			fingerprint,
		))
	mock.ExpectQuery(`(?s)FROM upload_intake_profiles.*WHERE upload_id = \?`).
		WithArgs(winnerID).
		WillReturnRows(pendingIntakeProfileRows(now, winnerID))

	stored, created, err := repository.Create(
		context.Background(),
		loser,
		"create",
		"stable-key",
		fingerprint,
	)
	if err != nil {
		t.Fatal(err)
	}
	if created || stored.ID != winnerID {
		t.Fatalf("Create() duplicate resolution = %#v/%v", stored, created)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestCreateDerivedCompletedRetainsBlobOnceAcrossReplay(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	repository := NewMySQLRepository(db)
	now := time.Date(2026, 8, 11, 1, 2, 3, 0, time.UTC)
	uploadID := "323e4567-e89b-42d3-a456-426614174000"
	parentID := "123e4567-e89b-42d3-a456-426614174000"
	hash := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	blobID := uint64(19)
	profile := &IntakeProfile{
		UploadID: uploadID, InputCategory: inputcategory.Binary,
		DetectedCategory: inputcategory.Binary, DetectedFormat: "pe32",
		ValidationStatus: ValidationValid, SourceKind: SourceArchiveEntry,
		SourceParentUploadID: parentID, SourceArchiveName: "bundle.zip",
		SourceEntryPath: "nested/member.bin", ValidatedAt: &now,
		CreatedAt: now, UpdatedAt: now,
	}
	value := Upload{
		ID: uploadID, CreatedBy: 7, OriginalName: []byte("member.bin"),
		DisplayName: "member.bin", ContentType: "application/octet-stream",
		DeclaredSize: 4, PartSize: DefaultPartSize, ActualSHA256: hash,
		Status: "completed", BlobID: &blobID, ExpiresAt: now.Add(time.Hour),
		CompletedAt: &now, PartsCleanedAt: &now, CreatedAt: now,
		IntakeProfile: profile,
	}
	record := DerivedCompletedRecord{
		Upload: value, IdempotencyKey: "entry-key",
		RequestFingerprint: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
	}

	mock.ExpectBegin()
	mock.ExpectQuery(`(?s)SELECT id, created_by, original_name.*FROM uploads.*FOR UPDATE`).
		WithArgs(uint64(7), archiveEntryCreateOperation, "entry-key").
		WillReturnRows(idempotentCreateRows())
	mock.ExpectQuery(`(?s)SELECT sha256, size_bytes, state, deleted_at.*FROM blobs.*FOR UPDATE`).
		WithArgs(blobID).
		WillReturnRows(sqlmock.NewRows([]string{
			"sha256", "size_bytes", "state", "deleted_at",
		}).AddRow(hash, int64(4), "available", nil))
	mock.ExpectExec(`(?s)UPDATE blobs.*reference_count = reference_count \+ 1`).
		WithArgs(blobID).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`(?s)INSERT INTO uploads.*'completed'`).
		WithArgs(
			uploadID, uint64(7), []byte("member.bin"), "member.bin",
			"application/octet-stream", int64(4), int64(DefaultPartSize), hash,
			blobID, value.ExpiresAt, now, now, "entry-key", archiveEntryCreateOperation,
			record.RequestFingerprint, now,
		).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`(?s)INSERT INTO upload_intake_profiles.*'archive_entry'`).
		WithArgs(
			uploadID, "binary", "binary", "pe32", parentID, "bundle.zip",
			"nested/member.bin", now, now,
		).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

	stored, created, err := repository.CreateDerivedCompleted(context.Background(), record)
	if err != nil || !created || stored.ID != uploadID {
		t.Fatalf("CreateDerivedCompleted() = %#v/%v/%v", stored, created, err)
	}

	mock.ExpectBegin()
	mock.ExpectQuery(`(?s)SELECT id, created_by, original_name.*FROM uploads.*FOR UPDATE`).
		WithArgs(uint64(7), archiveEntryCreateOperation, "entry-key").
		WillReturnRows(idempotentCreateRows().AddRow(
			uploadID, uint64(7), []byte("member.bin"), "member.bin",
			"application/octet-stream", int64(4), int64(DefaultPartSize),
			value.ExpiresAt, now, record.RequestFingerprint,
		))
	mock.ExpectQuery(`(?s)FROM upload_intake_profiles.*WHERE upload_id = \?`).
		WithArgs(uploadID).
		WillReturnRows(validDerivedProfileRows(now, uploadID, parentID))
	mock.ExpectQuery(`(?s)SELECT id, created_by, original_name.*FROM uploads.*WHERE id = \?`).
		WithArgs(uploadID).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "created_by", "original_name", "display_name", "content_type",
			"declared_size_bytes", "part_size_bytes", "expected_sha256", "actual_sha256",
			"status", "blob_id", "expires_at", "completed_at", "parts_cleaned_at", "created_at",
		}).AddRow(
			uploadID, uint64(7), []byte("member.bin"), "member.bin", "application/octet-stream",
			int64(4), int64(DefaultPartSize), nil, hash, "completed", blobID,
			value.ExpiresAt, now, now, now,
		))
	mock.ExpectQuery(`(?s)FROM upload_intake_profiles.*WHERE upload_id = \?`).
		WithArgs(uploadID).
		WillReturnRows(validDerivedProfileRows(now, uploadID, parentID))
	mock.ExpectCommit()

	stored, created, err = repository.CreateDerivedCompleted(context.Background(), record)
	if err != nil || created || stored.Status != "completed" || stored.BlobID == nil ||
		stored.IntakeProfile == nil || stored.IntakeProfile.SourceEntryPath != "nested/member.bin" {
		t.Fatalf("derived replay = %#v/%v/%v", stored, created, err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func idempotentCreateRows() *sqlmock.Rows {
	return sqlmock.NewRows([]string{
		"id",
		"created_by",
		"original_name",
		"display_name",
		"content_type",
		"declared_size_bytes",
		"part_size_bytes",
		"expires_at",
		"created_at",
		"request_fingerprint",
	})
}

func pendingIntakeProfileRows(now time.Time, uploadID string) *sqlmock.Rows {
	return sqlmock.NewRows([]string{
		"upload_id", "input_category", "detected_category", "detected_format",
		"validation_status", "validation_error_code", "validation_error_message",
		"source_kind", "source_parent_upload_id", "source_archive_name",
		"source_entry_path", "archive_import_id", "validated_at", "created_at", "updated_at",
	}).AddRow(
		uploadID, "binary", nil, nil, "pending", nil, nil, "direct",
		nil, nil, nil, nil, nil, now, now,
	)
}

func validDerivedProfileRows(now time.Time, uploadID string, parentID string) *sqlmock.Rows {
	return sqlmock.NewRows([]string{
		"upload_id", "input_category", "detected_category", "detected_format",
		"validation_status", "validation_error_code", "validation_error_message",
		"source_kind", "source_parent_upload_id", "source_archive_name",
		"source_entry_path", "archive_import_id", "validated_at", "created_at", "updated_at",
	}).AddRow(
		uploadID, "binary", "binary", "pe32", "valid", nil, nil, "archive_entry",
		parentID, "bundle.zip", "nested/member.bin", nil, now, now, now,
	)
}

func TestPrepareCompletionPersistsBlobReferenceBeforePublication(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	repository := NewMySQLRepository(db)
	storageKey := "blobs/sha256/ha/hash"

	mock.ExpectBegin()
	mock.ExpectQuery(`(?s)SELECT status, actual_sha256, blob_id.*FROM uploads.*FOR UPDATE`).
		WithArgs("upload").
		WillReturnRows(sqlmock.NewRows(
			[]string{"status", "actual_sha256", "blob_id"},
		).AddRow("uploading", nil, nil))
	mock.ExpectExec("INSERT INTO blobs").
		WithArgs("hash", int64(4), storageKey).
		WillReturnResult(sqlmock.NewResult(9, 1))
	mock.ExpectExec(`(?s)UPDATE blobs.*state = 'staging'.*verified_at = NULL.*deleted_at = NULL.*state = 'deleted'.*reference_count = 0`).
		WithArgs(int64(9), "hash", int64(4), storageKey).
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(`(?s)SELECT sha256, size_bytes, storage_key, state, deleted_at.*FROM blobs.*FOR UPDATE`).
		WithArgs(uint64(9)).
		WillReturnRows(sqlmock.NewRows(
			[]string{"sha256", "size_bytes", "storage_key", "state", "deleted_at"},
		).AddRow("hash", 4, storageKey, "staging", nil))
	mock.ExpectExec(`(?s)UPDATE blobs.*reference_count = reference_count \+ 1`).
		WithArgs(int64(9)).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`(?s)UPDATE uploads.*status = 'assembling'.*actual_sha256 = \?.*blob_id = \?`).
		WithArgs("hash", int64(9), "upload").
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

	err = repository.PrepareCompletion(
		context.Background(), "upload", "hash", 4, storageKey,
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestRecordValidationRejectsMismatchAtomicallyAndReplays(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	repository := NewMySQLRepository(db)
	uploadID := "123e4567-e89b-42d3-a456-426614174000"
	now := time.Date(2026, 8, 11, 2, 3, 4, 0, time.UTC)
	result := ValidationResult{
		Status: ValidationMismatch, InputCategory: inputcategory.Binary,
		DetectedCategory: inputcategory.Archive, DetectedFormat: "zip",
		ErrorCode:    "input_category_mismatch",
		ErrorMessage: "The detected format does not match the selected input category.",
		ValidatedAt:  now,
	}

	mock.ExpectBegin()
	mock.ExpectQuery(`(?s)SELECT upload.status, intake.input_category.*FOR UPDATE`).
		WithArgs(uploadID).
		WillReturnRows(sqlmock.NewRows([]string{
			"status", "input_category", "detected_category", "detected_format",
			"validation_status", "validation_error_code", "validation_error_message",
		}).AddRow("uploading", "binary", nil, nil, "pending", nil, nil))
	mock.ExpectExec(`(?s)UPDATE upload_intake_profiles.*validation_status = \?`).
		WithArgs(
			"archive", "zip", "mismatch", "input_category_mismatch",
			result.ErrorMessage, now, uploadID,
		).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`(?s)UPDATE uploads.*status = 'failed'`).
		WithArgs(uploadID, "uploading").
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()
	if err := repository.RecordValidation(context.Background(), uploadID, result); err != nil {
		t.Fatal(err)
	}

	mock.ExpectBegin()
	mock.ExpectQuery(`(?s)SELECT upload.status, intake.input_category.*FOR UPDATE`).
		WithArgs(uploadID).
		WillReturnRows(sqlmock.NewRows([]string{
			"status", "input_category", "detected_category", "detected_format",
			"validation_status", "validation_error_code", "validation_error_message",
		}).AddRow(
			"failed", "binary", "archive", "zip", "mismatch",
			"input_category_mismatch", result.ErrorMessage,
		))
	mock.ExpectCommit()
	if err := repository.RecordValidation(context.Background(), uploadID, result); err != nil {
		t.Fatalf("replayed RecordValidation() error = %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestSetArchiveImportIDIsImmutableAndIdempotent(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	repository := NewMySQLRepository(db)
	uploadID := "123e4567-e89b-42d3-a456-426614174000"
	importID := "323e4567-e89b-42d3-a456-426614174000"

	mock.ExpectBegin()
	mock.ExpectQuery(`(?s)SELECT upload.status, intake.input_category.*FOR UPDATE`).
		WithArgs(uploadID).
		WillReturnRows(sqlmock.NewRows([]string{
			"status", "input_category", "validation_status", "archive_import_id",
		}).AddRow("completed", "archive", "valid", nil))
	mock.ExpectExec(`(?s)UPDATE upload_intake_profiles.*archive_import_id = \?`).
		WithArgs(importID, uploadID).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()
	if err := repository.SetArchiveImportID(context.Background(), uploadID, importID); err != nil {
		t.Fatal(err)
	}

	mock.ExpectBegin()
	mock.ExpectQuery(`(?s)SELECT upload.status, intake.input_category.*FOR UPDATE`).
		WithArgs(uploadID).
		WillReturnRows(sqlmock.NewRows([]string{
			"status", "input_category", "validation_status", "archive_import_id",
		}).AddRow("completed", "archive", "valid", importID))
	mock.ExpectCommit()
	if err := repository.SetArchiveImportID(context.Background(), uploadID, importID); err != nil {
		t.Fatalf("replayed SetArchiveImportID() error = %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestPrepareCompletionRejectsConflictingExistingBlobMetadata(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	repository := NewMySQLRepository(db)
	storageKey := "blobs/sha256/ha/hash"

	mock.ExpectBegin()
	mock.ExpectQuery(`(?s)SELECT status, actual_sha256, blob_id.*FROM uploads.*FOR UPDATE`).
		WithArgs("upload").
		WillReturnRows(sqlmock.NewRows(
			[]string{"status", "actual_sha256", "blob_id"},
		).AddRow("created", nil, nil))
	mock.ExpectExec("INSERT INTO blobs").
		WithArgs("hash", int64(4), storageKey).
		WillReturnResult(sqlmock.NewResult(9, 0))
	mock.ExpectExec(`(?s)UPDATE blobs.*state = 'staging'.*verified_at = NULL.*deleted_at = NULL.*state = 'deleted'.*reference_count = 0`).
		WithArgs(int64(9), "hash", int64(4), storageKey).
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(`(?s)SELECT sha256, size_bytes, storage_key, state, deleted_at.*FROM blobs.*FOR UPDATE`).
		WithArgs(uint64(9)).
		WillReturnRows(sqlmock.NewRows(
			[]string{"sha256", "size_bytes", "storage_key", "state", "deleted_at"},
		).AddRow("hash", 5, storageKey, "available", nil))
	mock.ExpectRollback()

	err = repository.PrepareCompletion(
		context.Background(), "upload", "hash", 4, storageKey,
	)
	if err != ErrConflict {
		t.Fatalf("PrepareCompletion() error = %v, want ErrConflict", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestPrepareCompletionReactivatesFullyDeletedBlob(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	repository := NewMySQLRepository(db)
	storageKey := "blobs/sha256/ha/hash"

	mock.ExpectBegin()
	mock.ExpectQuery(`(?s)SELECT status, actual_sha256, blob_id.*FROM uploads.*FOR UPDATE`).
		WithArgs("upload").
		WillReturnRows(sqlmock.NewRows(
			[]string{"status", "actual_sha256", "blob_id"},
		).AddRow("uploading", nil, nil))
	mock.ExpectExec("INSERT INTO blobs").
		WithArgs("hash", int64(4), storageKey).
		WillReturnResult(sqlmock.NewResult(9, 0))
	mock.ExpectExec(`(?s)UPDATE blobs.*state = 'staging'.*verified_at = NULL.*deleted_at = NULL.*state = 'deleted'.*reference_count = 0`).
		WithArgs(int64(9), "hash", int64(4), storageKey).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectQuery(`(?s)SELECT sha256, size_bytes, storage_key, state, deleted_at.*FROM blobs.*FOR UPDATE`).
		WithArgs(uint64(9)).
		WillReturnRows(sqlmock.NewRows(
			[]string{"sha256", "size_bytes", "storage_key", "state", "deleted_at"},
		).AddRow("hash", 4, storageKey, "staging", nil))
	mock.ExpectExec(`(?s)UPDATE blobs.*reference_count = reference_count \+ 1`).
		WithArgs(int64(9)).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`(?s)UPDATE uploads.*status = 'assembling'.*actual_sha256 = \?.*blob_id = \?`).
		WithArgs("hash", int64(9), "upload").
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

	if err := repository.PrepareCompletion(
		context.Background(), "upload", "hash", 4, storageKey,
	); err != nil {
		t.Fatal(err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestPrepareCompletionReplayDoesNotAddAnotherReference(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	repository := NewMySQLRepository(db)
	storageKey := "blobs/sha256/ha/hash"

	mock.ExpectBegin()
	mock.ExpectQuery(`(?s)SELECT status, actual_sha256, blob_id.*FROM uploads.*FOR UPDATE`).
		WithArgs("upload").
		WillReturnRows(sqlmock.NewRows(
			[]string{"status", "actual_sha256", "blob_id"},
		).AddRow("assembling", "hash", 9))
	mock.ExpectQuery(`(?s)SELECT sha256, size_bytes, storage_key, state, deleted_at.*FROM blobs.*FOR UPDATE`).
		WithArgs(uint64(9)).
		WillReturnRows(sqlmock.NewRows(
			[]string{"sha256", "size_bytes", "storage_key", "state", "deleted_at"},
		).AddRow("hash", 4, storageKey, "staging", nil))
	mock.ExpectCommit()

	err = repository.PrepareCompletion(
		context.Background(), "upload", "hash", 4, storageKey,
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestFinalizeCompletionPublishesPreparedBlobAndUploadAtomically(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	repository := NewMySQLRepository(db)
	now := time.Now().UTC()

	mock.ExpectBegin()
	mock.ExpectQuery(`(?s)SELECT status, actual_sha256, blob_id.*FROM uploads.*FOR UPDATE`).
		WithArgs("upload").
		WillReturnRows(sqlmock.NewRows(
			[]string{"status", "actual_sha256", "blob_id"},
		).AddRow("assembling", "hash", 9))
	mock.ExpectQuery(`(?s)SELECT sha256, state, deleted_at.*FROM blobs.*FOR UPDATE`).
		WithArgs(int64(9)).
		WillReturnRows(sqlmock.NewRows(
			[]string{"sha256", "state", "deleted_at"},
		).AddRow("hash", "staging", nil))
	mock.ExpectExec(`(?s)UPDATE blobs.*state = 'available'.*verified_at = \?`).
		WithArgs(now, int64(9)).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`(?s)UPDATE uploads.*status = 'completed'.*completed_at = \?`).
		WithArgs(now, "upload", "hash", int64(9)).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

	if err := repository.FinalizeCompletion(
		context.Background(), "upload", "hash", now,
	); err != nil {
		t.Fatal(err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestCleanupPartsDeletesDirectoryBeforeRecordsAndCommitsMarker(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	repository := NewMySQLRepository(db)

	mock.ExpectBegin()
	mock.ExpectQuery(`(?s)SELECT status, parts_cleaned_at.*FROM uploads.*FOR UPDATE`).
		WithArgs("upload").
		WillReturnRows(sqlmock.NewRows(
			[]string{"status", "parts_cleaned_at"},
		).AddRow("completed", nil))
	mock.ExpectExec(`(?s)DELETE FROM upload_parts.*WHERE upload_id = \?`).
		WithArgs("upload").
		WillReturnResult(sqlmock.NewResult(0, 2))
	mock.ExpectExec(`(?s)UPDATE uploads.*parts_cleaned_at = UTC_TIMESTAMP.*WHERE id = \?.*status = \?.*parts_cleaned_at IS NULL`).
		WithArgs("upload", "completed").
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

	deleted := false
	changed, err := repository.CleanupParts(
		context.Background(),
		"upload",
		func() error {
			deleted = true
			return nil
		},
	)
	if err != nil || !changed || !deleted {
		t.Fatalf("CleanupParts() = (%v, %v), deleted=%v", changed, err, deleted)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestCleanupPartsReplayConvergesAfterAmbiguousCommit(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	repository := NewMySQLRepository(db)
	commitErr := context.DeadlineExceeded

	mock.ExpectBegin()
	mock.ExpectQuery(`(?s)SELECT status, parts_cleaned_at.*FROM uploads.*FOR UPDATE`).
		WithArgs("upload").
		WillReturnRows(sqlmock.NewRows(
			[]string{"status", "parts_cleaned_at"},
		).AddRow("cancelled", nil))
	mock.ExpectExec(`(?s)DELETE FROM upload_parts.*WHERE upload_id = \?`).
		WithArgs("upload").
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`(?s)UPDATE uploads.*parts_cleaned_at = UTC_TIMESTAMP`).
		WithArgs("upload", "cancelled").
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit().WillReturnError(commitErr)

	deletes := 0
	deleteDirectory := func() error {
		deletes++
		return nil
	}
	changed, err := repository.CleanupParts(
		context.Background(),
		"upload",
		deleteDirectory,
	)
	if changed || !errors.Is(err, commitErr) {
		t.Fatalf("first CleanupParts() = (%v, %v)", changed, err)
	}

	cleanedAt := time.Now().UTC()
	mock.ExpectBegin()
	mock.ExpectQuery(`(?s)SELECT status, parts_cleaned_at.*FROM uploads.*FOR UPDATE`).
		WithArgs("upload").
		WillReturnRows(sqlmock.NewRows(
			[]string{"status", "parts_cleaned_at"},
		).AddRow("cancelled", cleanedAt))
	mock.ExpectCommit()
	changed, err = repository.CleanupParts(
		context.Background(),
		"upload",
		deleteDirectory,
	)
	if err != nil || changed || deletes != 1 {
		t.Fatalf(
			"replayed CleanupParts() = (%v, %v), deletes=%d",
			changed,
			err,
			deletes,
		)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestUploadHasTaskTreatsEveryTaskStateAsRetained(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	repository := NewMySQLRepository(db)
	uploadID := "123e4567-e89b-42d3-a456-426614174000"

	mock.ExpectQuery(`(?s)SELECT EXISTS.*FROM tasks.*WHERE upload_id = \?`).
		WithArgs(uploadID).
		WillReturnRows(sqlmock.NewRows([]string{"retained"}).AddRow(true))
	retained, err := repository.UploadHasTask(context.Background(), uploadID)
	if err != nil || !retained {
		t.Fatalf("UploadHasTask() = (%v, %v)", retained, err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestTaskIDForUploadReturnsAuthoritativeTaskIncludingDeletedTombstone(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	repository := NewMySQLRepository(db)
	uploadID := "123e4567-e89b-42d3-a456-426614174000"
	taskID := "223e4567-e89b-42d3-a456-426614174000"

	// Deliberately require no task-status predicate: a soft-deleted task remains
	// the exactly-once tombstone for this upload.
	mock.ExpectQuery(`SELECT id\s+FROM tasks\s+WHERE upload_id = \?\s+LIMIT 1`).
		WithArgs(uploadID).
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(taskID))
	stored, found, err := repository.TaskIDForUpload(context.Background(), uploadID)
	if err != nil || !found || stored != taskID {
		t.Fatalf("TaskIDForUpload() = (%q, %v, %v)", stored, found, err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestListDirectTaskCandidatesUsesEligibleStableBoundedQuery(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	repository := NewMySQLRepository(db)
	afterID := "123e4567-e89b-42d3-a456-426614174000"
	uploadID := "223e4567-e89b-42d3-a456-426614174000"

	mock.ExpectQuery(`(?s)SELECT upload[.]id, upload[.]created_by, upload[.]display_name,.*FROM uploads upload.*JOIN upload_intake_profiles.*JOIN blobs.*upload[.]id > \?.*upload[.]status = 'completed'.*source_kind = 'direct'.*validation_status = 'valid'.*input_category IN \('binary', 'container'\).*detected_category = intake[.]input_category.*stored_blob[.]state = 'available'.*NOT EXISTS \(\s*SELECT 1\s*FROM tasks\s*WHERE tasks[.]upload_id = upload[.]id\s*\).*ORDER BY upload[.]id.*LIMIT \?`).
		WithArgs(afterID, 10).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "created_by", "display_name", "input_category", "detected_format",
		}).AddRow(uploadID, uint64(7), "sample.bin", "binary", "pe32"))
	candidates, err := repository.ListDirectTaskCandidates(
		context.Background(), afterID, 10,
	)
	if err != nil || len(candidates) != 1 || candidates[0].UploadID != uploadID ||
		candidates[0].InputCategory != inputcategory.Binary ||
		candidates[0].DetectedFormat != "pe32" {
		t.Fatalf("ListDirectTaskCandidates() = (%#v, %v)", candidates, err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestListArchiveImportCandidatesUsesEligibleStableBoundedQuery(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	repository := NewMySQLRepository(db)
	afterID := "123e4567-e89b-42d3-a456-426614174000"
	uploadID := "223e4567-e89b-42d3-a456-426614174000"

	mock.ExpectQuery(`(?s)SELECT upload[.]id, upload[.]created_by, upload[.]display_name,.*declared_size_bytes, upload[.]actual_sha256, intake[.]detected_format.*FROM uploads upload.*JOIN upload_intake_profiles.*JOIN blobs.*upload[.]id > \?.*upload[.]status = 'completed'.*source_kind = 'direct'.*validation_status = 'valid'.*input_category = 'archive'.*detected_category = 'archive'.*detected_format IS NOT NULL.*archive_import_id IS NULL.*actual_sha256 IS NOT NULL.*stored_blob[.]state = 'available'.*ORDER BY upload[.]id.*LIMIT \?`).
		WithArgs(afterID, 10).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "created_by", "display_name", "declared_size_bytes", "actual_sha256", "detected_format",
		}).AddRow(uploadID, uint64(7), "bundle.zip", int64(4), strings.Repeat("a", 64), "zip"))
	candidates, err := repository.ListArchiveImportCandidates(
		context.Background(), afterID, 10,
	)
	if err != nil || len(candidates) != 1 || candidates[0].UploadID != uploadID ||
		candidates[0].Size != 4 || candidates[0].DetectedFormat != "zip" {
		t.Fatalf("ListArchiveImportCandidates() = (%#v, %v)", candidates, err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestCancelTransitionsStateAndLeavesPartRowsForRecoverableCleanup(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	repository := NewMySQLRepository(db)
	uploadID := "123e4567-e89b-42d3-a456-426614174000"

	mock.ExpectBegin()
	mock.ExpectQuery(`(?s)SELECT status, blob_id.*FROM uploads.*FOR UPDATE`).
		WithArgs(uploadID).
		WillReturnRows(sqlmock.NewRows(
			[]string{"status", "blob_id"},
		).AddRow("created", nil))
	mock.ExpectExec("UPDATE uploads").
		WithArgs(uploadID, "created").
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

	if err := repository.Cancel(context.Background(), uploadID); err != nil {
		t.Fatalf("Cancel() error = %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestCancelRejectsCompletedUploadRetainedByTask(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	repository := NewMySQLRepository(db)
	uploadID := "123e4567-e89b-42d3-a456-426614174000"

	mock.ExpectBegin()
	mock.ExpectQuery(`(?s)SELECT status, blob_id.*FROM uploads.*FOR UPDATE`).
		WithArgs(uploadID).
		WillReturnRows(sqlmock.NewRows(
			[]string{"status", "blob_id"},
		).AddRow("completed", 9))
	mock.ExpectQuery(`(?s)SELECT id.*FROM tasks.*WHERE upload_id = \?`).
		WithArgs(uploadID).
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow("task-id"))
	mock.ExpectRollback()

	if err := repository.Cancel(context.Background(), uploadID); err != ErrInvalidState {
		t.Fatalf("Cancel() error = %v, want ErrInvalidState", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestCancelReleasesPreparedBlobReferenceAtomically(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	repository := NewMySQLRepository(db)
	uploadID := "123e4567-e89b-42d3-a456-426614174000"

	mock.ExpectBegin()
	mock.ExpectQuery(`(?s)SELECT status, blob_id.*FROM uploads.*FOR UPDATE`).
		WithArgs(uploadID).
		WillReturnRows(sqlmock.NewRows(
			[]string{"status", "blob_id"},
		).AddRow("assembling", 9))
	mock.ExpectQuery(`(?s)SELECT reference_count, state.*FROM blobs.*FOR UPDATE`).
		WithArgs(uint64(9)).
		WillReturnRows(sqlmock.NewRows(
			[]string{"reference_count", "state"},
		).AddRow(2, "staging"))
	mock.ExpectExec(`(?s)UPDATE blobs.*state = \?.*reference_count = reference_count - 1`).
		WithArgs("staging", uint64(9), "staging", uint64(2)).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`(?s)UPDATE uploads.*status = 'cancelled'.*blob_id = NULL`).
		WithArgs(uploadID, "assembling").
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

	if err := repository.Cancel(context.Background(), uploadID); err != nil {
		t.Fatal(err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestCancelReleasesCompletedUnusedBlobReferenceAtomically(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	repository := NewMySQLRepository(db)
	uploadID := "123e4567-e89b-42d3-a456-426614174000"

	mock.ExpectBegin()
	mock.ExpectQuery(`(?s)SELECT status, blob_id.*FROM uploads.*FOR UPDATE`).
		WithArgs(uploadID).
		WillReturnRows(sqlmock.NewRows([]string{"status", "blob_id"}).AddRow("completed", 9))
	mock.ExpectQuery(`(?s)SELECT id.*FROM tasks.*WHERE upload_id = \?`).
		WithArgs(uploadID).
		WillReturnError(sql.ErrNoRows)
	mock.ExpectQuery(`(?s)SELECT reference_count, state.*FROM blobs.*FOR UPDATE`).
		WithArgs(uint64(9)).
		WillReturnRows(sqlmock.NewRows([]string{"reference_count", "state"}).AddRow(1, "available"))
	mock.ExpectExec(`(?s)UPDATE blobs.*state = \?.*reference_count = reference_count - 1`).
		WithArgs("deleting", uint64(9), "available", uint64(1)).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`(?s)UPDATE uploads.*status = 'cancelled'.*blob_id = NULL`).
		WithArgs(uploadID, "completed").
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

	if err := repository.Cancel(context.Background(), uploadID); err != nil {
		t.Fatal(err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestWithLockUsesReservedConnectionForRepositoryCalls(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	repository := NewMySQLRepository(db)
	uploadID := "123e4567-e89b-42d3-a456-426614174000"
	now := time.Now().UTC()

	mock.ExpectQuery("SELECT GET_LOCK").
		WithArgs("binaryscan_upload_"+uploadID, 30).
		WillReturnRows(sqlmock.NewRows([]string{"acquired"}).AddRow(1))
	mock.ExpectQuery("SELECT id, created_by").
		WithArgs(uploadID).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "created_by", "original_name", "display_name", "content_type",
			"declared_size_bytes", "part_size_bytes", "expected_sha256", "actual_sha256",
			"status", "blob_id", "expires_at", "completed_at", "parts_cleaned_at",
			"created_at",
		}).AddRow(
			uploadID, 7, []byte("sample.bin"), "sample.bin", "application/octet-stream",
			4, DefaultPartSize, nil, nil, "created", nil, now.Add(time.Hour), nil, nil,
			now,
		))
	mock.ExpectQuery(`(?s)FROM upload_intake_profiles.*WHERE upload_id = \?`).
		WithArgs(uploadID).
		WillReturnRows(sqlmock.NewRows([]string{
			"upload_id", "input_category", "detected_category", "detected_format",
			"validation_status", "validation_error_code", "validation_error_message",
			"source_kind", "source_parent_upload_id", "source_archive_name",
			"source_entry_path", "archive_import_id", "validated_at", "created_at", "updated_at",
		}))
	mock.ExpectQuery("SELECT RELEASE_LOCK").
		WithArgs("binaryscan_upload_" + uploadID).
		WillReturnRows(sqlmock.NewRows([]string{"released"}).AddRow(1))

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	err = repository.WithLock(ctx, uploadID, func(lockCtx context.Context) error {
		_, getErr := repository.Get(lockCtx, uploadID)
		return getErr
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

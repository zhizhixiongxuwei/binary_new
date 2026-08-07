package upload

import (
	"context"
	"errors"
	"testing"
	"time"

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
	for range 2 {
		mock.ExpectQuery(
			`(?s)SELECT id, created_by, original_name.*request_fingerprint.*FROM uploads.*LIMIT 1`,
		).
			WithArgs(uint64(7), "create", "stable-key").
			WillReturnRows(row())
	}

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

func TestCancelRejectsUploadWhoseStateChanged(t *testing.T) {
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

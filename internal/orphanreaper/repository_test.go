package orphanreaper

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
)

func TestMySQLRepositoryTreatsEveryDatabaseRecordAsReferenced(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	repository := NewMySQLRepository(db)
	blob := BlobCandidate{
		SHA256:     "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
		StorageKey: "blobs/sha256/dd/dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
		SizeBytes:  4,
	}
	upload := UploadCandidate{ID: "123e4567-e89b-42d3-a456-426614174001"}

	// There is deliberately no state, reference-count, task-status, or lease
	// predicate: staging and actively used records must protect their files.
	mock.ExpectQuery(`SELECT EXISTS \(\s*SELECT 1\s*FROM blobs\s*WHERE sha256 = \? OR storage_key = \?`).
		WithArgs(blob.SHA256, blob.StorageKey).
		WillReturnRows(sqlmock.NewRows([]string{"referenced"}).AddRow(true))
	referenced, err := repository.BlobReferenced(context.Background(), blob)
	if err != nil || !referenced {
		t.Fatalf("BlobReferenced() = (%v, %v)", referenced, err)
	}

	mock.ExpectQuery(`SELECT EXISTS \(\s*SELECT 1\s*FROM uploads\s*WHERE id = \?`).
		WithArgs(upload.ID).
		WillReturnRows(sqlmock.NewRows([]string{"referenced"}).AddRow(true))
	referenced, err = repository.UploadReferenced(context.Background(), upload)
	if err != nil || !referenced {
		t.Fatalf("UploadReferenced() = (%v, %v)", referenced, err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestMySQLRepositoryRechecksAndFencesBlobDeletion(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	repository := NewMySQLRepository(db)
	candidate := BlobCandidate{
		SHA256:     "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		StorageKey: "blobs/sha256/aa/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		SizeBytes:  7, ModifiedAt: time.Now().Add(-48 * time.Hour),
	}

	mock.ExpectBegin()
	mock.ExpectQuery(`SELECT id\s+FROM blobs FORCE INDEX \(uq_blobs_sha256\).*FOR UPDATE`).
		WithArgs(candidate.SHA256).
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(uint64(9)))
	mock.ExpectCommit()
	called := false
	removed, err := repository.DeleteOrphanBlob(
		context.Background(), candidate,
		func(context.Context) error {
			called = true
			return nil
		},
	)
	if err != nil || removed || called {
		t.Fatalf("protected DeleteOrphanBlob() = (%v, %v), callback=%v", removed, err, called)
	}

	mock.ExpectBegin()
	mock.ExpectQuery(`SELECT id\s+FROM blobs FORCE INDEX \(uq_blobs_sha256\).*FOR UPDATE`).
		WithArgs(candidate.SHA256).
		WillReturnError(sqlmock.ErrCancelled)
	removed, err = repository.DeleteOrphanBlob(
		context.Background(), candidate,
		func(context.Context) error { return nil },
	)
	if err == nil || removed {
		t.Fatalf("failed lock DeleteOrphanBlob() = (%v, %v)", removed, err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestMySQLRepositoryDeletesAndAuditsOrphanBlob(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	repository := NewMySQLRepository(db)
	candidate := BlobCandidate{
		SHA256:     "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		StorageKey: "blobs/sha256/bb/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		SizeBytes:  6,
	}

	mock.ExpectBegin()
	mock.ExpectQuery(`SELECT id\s+FROM blobs FORCE INDEX \(uq_blobs_sha256\).*FOR UPDATE`).
		WithArgs(candidate.SHA256).
		WillReturnRows(sqlmock.NewRows([]string{"id"}))
	mock.ExpectQuery(`SELECT EXISTS \(\s*SELECT 1\s*FROM blobs\s*WHERE storage_key = \?`).
		WithArgs(candidate.StorageKey).
		WillReturnRows(sqlmock.NewRows([]string{"referenced"}).AddRow(false))
	mock.ExpectExec(`INSERT INTO audit_logs`).
		WithArgs(
			nil, nil, "maintenance.orphan_blob_removed", "blob",
			candidate.SHA256, "success", nil, nil, sqlmock.AnyArg(),
		).
		WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectCommit()
	called := 0
	removed, err := repository.DeleteOrphanBlob(
		context.Background(), candidate,
		func(context.Context) error {
			called++
			return nil
		},
	)
	if err != nil || !removed || called != 1 {
		t.Fatalf("DeleteOrphanBlob() = (%v, %v), callbacks=%d", removed, err, called)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestMySQLRepositoryReportsAuditFailureAfterFilesystemDeletion(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	repository := NewMySQLRepository(db)
	candidate := BlobCandidate{
		SHA256:     "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
		StorageKey: "blobs/sha256/cc/cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
		SizeBytes:  3,
	}
	auditErr := errors.New("audit unavailable")
	mock.ExpectBegin()
	mock.ExpectQuery(`SELECT id\s+FROM blobs FORCE INDEX \(uq_blobs_sha256\).*FOR UPDATE`).
		WithArgs(candidate.SHA256).
		WillReturnRows(sqlmock.NewRows([]string{"id"}))
	mock.ExpectQuery(`SELECT EXISTS`).WithArgs(candidate.StorageKey).
		WillReturnRows(sqlmock.NewRows([]string{"referenced"}).AddRow(false))
	mock.ExpectExec(`INSERT INTO audit_logs`).WillReturnError(auditErr)
	mock.ExpectRollback()
	deleted := false
	removed, err := repository.DeleteOrphanBlob(
		context.Background(), candidate,
		func(context.Context) error {
			deleted = true
			return nil
		},
	)
	if !deleted || removed || !errors.Is(err, auditErr) {
		t.Fatalf("audit failure = (%v, %v), deleted=%v", removed, err, deleted)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestMySQLRepositoryFencesUploadDeletion(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	repository := NewMySQLRepository(db)
	candidate := UploadCandidate{ID: "123e4567-e89b-42d3-a456-426614174000"}

	mock.ExpectBegin()
	mock.ExpectQuery(`SELECT id\s+FROM uploads.*FOR UPDATE`).
		WithArgs(candidate.ID).
		WillReturnRows(sqlmock.NewRows([]string{"id"}))
	mock.ExpectExec(`INSERT INTO audit_logs`).
		WithArgs(
			nil, nil, "maintenance.orphan_upload_removed", "upload",
			candidate.ID, "success", nil, nil, sqlmock.AnyArg(),
		).
		WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectCommit()
	called := 0
	removed, err := repository.DeleteOrphanUpload(
		context.Background(), candidate,
		func(context.Context) error {
			called++
			return nil
		},
	)
	if err != nil || !removed || called != 1 {
		t.Fatalf("DeleteOrphanUpload() = (%v, %v), callbacks=%d", removed, err, called)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestMySQLRepositoryReconcilesBlobReferenceCount(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	repository := NewMySQLRepository(db)
	candidate := BlobReferenceCandidate{ID: 42}
	createdAt := time.Now().Add(-48 * time.Hour)

	mock.ExpectQuery(`SELECT id\s+FROM blobs\s+WHERE id > \? AND state <> 'deleted'`).
		WithArgs(uint64(0), 10).
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(uint64(42)))
	candidates, err := repository.ListBlobReferenceCandidates(
		context.Background(), 0, 10,
	)
	if err != nil || len(candidates) != 1 || candidates[0] != candidate {
		t.Fatalf("ListBlobReferenceCandidates() = (%v, %v)", candidates, err)
	}

	mock.ExpectBegin()
	mock.ExpectQuery(`SELECT reference_count, state, created_at\s+FROM blobs.*FOR UPDATE`).
		WithArgs(candidate.ID).
		WillReturnRows(sqlmock.NewRows(
			[]string{"reference_count", "state", "created_at"},
		).AddRow(uint64(9), "available", createdAt))
	mock.ExpectQuery(`SELECT\s+\(SELECT COUNT\(\*\) FROM uploads.*file_node_blob_refs`).
		WithArgs(candidate.ID, candidate.ID, candidate.ID).
		WillReturnRows(sqlmock.NewRows([]string{"actual_count"}).AddRow(uint64(2)))
	mock.ExpectExec(`UPDATE blobs\s+SET reference_count = \?.*state = \?`).
		WithArgs(uint64(2), "available", "available", candidate.ID, "available", uint64(9)).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`INSERT INTO audit_logs`).
		WithArgs(
			nil, nil, "maintenance.blob_reference_reconciled", "blob",
			"42", "success", nil, nil, sqlmock.AnyArg(),
		).
		WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectCommit()
	result, err := repository.ReconcileBlobReference(
		context.Background(), candidate, time.Now().Add(-24*time.Hour), false,
	)
	if err != nil || !result.Drifted || !result.Corrected ||
		result.PreviousCount != 9 || result.ActualCount != 2 ||
		result.CurrentState != "available" {
		t.Fatalf("ReconcileBlobReference() = (%+v, %v)", result, err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestMySQLRepositoryRechecksAndAuditsStoredFileDeletion(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	repository := NewMySQLRepository(db)
	candidate := StoredFileCandidate{
		Kind: StoredFileReport,
		StorageKey: "reports/123e4567-e89b-42d3-a456-426614174000/" +
			"223e4567-e89b-42d3-a456-426614174000.json",
		SHA256: strings.Repeat("a", 64), SizeBytes: 12,
	}

	mock.ExpectQuery(`SELECT EXISTS \(\s*SELECT id\s+FROM reports FORCE INDEX`).
		WithArgs(candidate.StorageKey).
		WillReturnRows(sqlmock.NewRows([]string{"referenced"}).AddRow(false))
	referenced, err := repository.StoredFileReferenced(context.Background(), candidate)
	if err != nil || referenced {
		t.Fatalf("StoredFileReferenced() = (%v, %v)", referenced, err)
	}

	mock.ExpectBegin()
	mock.ExpectQuery(`SELECT id\s+FROM reports FORCE INDEX.*FOR UPDATE`).
		WithArgs(candidate.StorageKey).
		WillReturnRows(sqlmock.NewRows([]string{"id"}))
	mock.ExpectExec(`INSERT INTO audit_logs`).
		WithArgs(
			nil, nil, "maintenance.orphan_stored_file_removed", "report",
			candidate.SHA256, "success", nil, nil, sqlmock.AnyArg(),
		).
		WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectCommit()
	called := 0
	removed, err := repository.DeleteOrphanStoredFile(
		context.Background(), candidate,
		func(context.Context) error {
			called++
			return nil
		},
	)
	if err != nil || !removed || called != 1 {
		t.Fatalf(
			"DeleteOrphanStoredFile() = (%v, %v), callbacks=%d",
			removed, err, called,
		)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

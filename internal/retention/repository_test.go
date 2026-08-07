package retention

import (
	"context"
	"database/sql"
	"errors"
	"regexp"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
)

func TestClaimExpiredTaskSamplePersistsRecoverableFence(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	repository := NewMySQLRepository(db)
	now := time.Date(2026, 7, 31, 8, 0, 0, 0, time.UTC)

	mock.ExpectBegin()
	mock.ExpectQuery(`(?s)SELECT UTC_TIMESTAMP\(6\).*FROM tasks t.*t\.id = \?.*reports report.*decompile_results result.*FOR UPDATE SKIP LOCKED`).
		WithArgs("task-id").
		WillReturnRows(sqlmock.NewRows([]string{"now"}).AddRow(now))
	mock.ExpectQuery(`(?s)SELECT status, fencing_token, attempt_count, lease_until.*task_sample_retention_operations.*FOR UPDATE`).
		WithArgs("task-id").
		WillReturnError(sql.ErrNoRows)
	mock.ExpectExec(`(?s)INSERT INTO task_sample_retention_operations.*'cleaning'.*DATE_ADD\(UTC_TIMESTAMP\(6\), INTERVAL \? MICROSECOND\)`).
		WithArgs("task-id", "retention-owner", int64(60_000_000)).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectQuery(`(?s)SELECT id, storage_key, content_sha256, size_bytes.*FROM decompile_results.*storage_key IS NOT NULL`).
		WithArgs("task-id").
		WillReturnRows(sqlmock.NewRows(
			[]string{"id", "storage_key", "content_sha256", "size_bytes"},
		))
	expectSystemAudit(
		mock, "retention.task_sample_cleanup_started", "task", "task-id",
	)
	mock.ExpectCommit()

	claim, claimed, err := repository.ClaimExpiredTaskSample(
		context.Background(), "task-id", "retention-owner", time.Minute,
	)
	if err != nil {
		t.Fatal(err)
	}
	if !claimed || claim.FencingToken != 1 || claim.Attempt != 1 ||
		claim.LeaseOwner != "retention-owner" ||
		!claim.LeaseUntil.Equal(now.Add(time.Minute)) {
		t.Fatalf("claim = %#v, claimed=%v", claim, claimed)
	}
}

func TestReleaseExpiredTaskSampleAtomicallyReleasesLastReferenceAndAudits(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	repository := NewMySQLRepository(db)

	mock.ExpectBegin()
	mock.ExpectQuery(`(?s)SELECT t\.blob_id.*FROM tasks t.*t\.id = \?.*sample_expires_at <= UTC_TIMESTAMP.*status IN .*NOT EXISTS.*jobs.*FOR UPDATE SKIP LOCKED`).
		WithArgs("task-id").
		WillReturnRows(sqlmock.NewRows([]string{"blob_id"}).AddRow(42))
	mock.ExpectExec(`(?s)UPDATE jobs.*status = 'cancelled'.*kind = 'decompile'.*status = 'queued'`).
		WithArgs("task-id").
		WillReturnResult(sqlmock.NewResult(0, 2))
	expectNoDerivedBlobReferences(mock, "task-id")
	expectBlobReferenceRelease(mock, 42, 1, "deleting")
	mock.ExpectExec(`(?s)UPDATE tasks.*sample_deleted_at = UTC_TIMESTAMP.*event_sequence = event_sequence \+ 1.*WHERE id = \?.*blob_id = \?.*sample_expires_at <= UTC_TIMESTAMP`).
		WithArgs("task-id", uint64(42)).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`(?s)INSERT INTO task_events.*SELECT.*FROM tasks.*WHERE id = \?`).
		WithArgs(
			"task.sample_deleted",
			"Task sample retention expired.",
			"task-id",
		).
		WillReturnResult(sqlmock.NewResult(1, 1))
	expectSystemAudit(
		mock,
		"retention.task_sample_deleted",
		"task",
		"task-id",
	)
	mock.ExpectCommit()

	changed, err := repository.ReleaseExpiredTaskSample(
		context.Background(),
		"task-id",
	)
	if err != nil || !changed {
		t.Fatalf("ReleaseExpiredTaskSample() = (%v, %v)", changed, err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestReleaseExpiredTaskSampleSkipsChangedOrLockedTask(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	repository := NewMySQLRepository(db)

	mock.ExpectBegin()
	mock.ExpectQuery(`(?s)SELECT t\.blob_id.*FOR UPDATE SKIP LOCKED`).
		WithArgs("task-id").
		WillReturnError(sql.ErrNoRows)
	mock.ExpectCommit()

	changed, err := repository.ReleaseExpiredTaskSample(
		context.Background(),
		"task-id",
	)
	if err != nil || changed {
		t.Fatalf("ReleaseExpiredTaskSample() = (%v, %v)", changed, err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestExpireUploadReleasesSharedReferenceAndClearsBlob(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	repository := NewMySQLRepository(db)

	expectUploadLock(mock, "upload-id")
	mock.ExpectBegin()
	mock.ExpectQuery(`(?s)SELECT u\.blob_id.*FROM uploads u.*u\.id = \?.*expires_at <= UTC_TIMESTAMP.*FOR UPDATE SKIP LOCKED`).
		WithArgs("upload-id").
		WillReturnRows(sqlmock.NewRows([]string{"blob_id"}).AddRow(42))
	expectBlobReferenceRelease(mock, 42, 2, "available")
	mock.ExpectExec(`(?s)DELETE FROM upload_parts.*WHERE upload_id = \?`).
		WithArgs("upload-id").
		WillReturnResult(sqlmock.NewResult(0, 3))
	mock.ExpectExec(`(?s)UPDATE uploads.*status = 'expired'.*blob_id = NULL.*WHERE id = \?.*expires_at <= UTC_TIMESTAMP`).
		WithArgs("upload-id").
		WillReturnResult(sqlmock.NewResult(0, 1))
	expectSystemAudit(
		mock,
		"retention.upload_expired",
		"upload",
		"upload-id",
	)
	mock.ExpectCommit()
	expectUploadUnlock(mock, "upload-id")

	deleted := false
	changed, err := repository.ExpireUpload(
		context.Background(),
		"upload-id",
		func() error {
			deleted = true
			return nil
		},
	)
	if err != nil || !changed || !deleted {
		t.Fatalf("ExpireUpload() = (%v, %v)", changed, err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestExpireUploadSkipsBusyAdvisoryLockWithoutWaiting(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	repository := NewMySQLRepository(db)
	mock.ExpectQuery(regexp.QuoteMeta("SELECT GET_LOCK(?, ?)")).
		WithArgs("binaryscan_upload_upload-id", uploadRetentionLockWaitSeconds).
		WillReturnRows(sqlmock.NewRows([]string{"acquired"}).AddRow(0))

	deleted := false
	changed, err := repository.ExpireUpload(
		context.Background(),
		"upload-id",
		func() error {
			deleted = true
			return nil
		},
	)
	if err != nil || changed || deleted {
		t.Fatalf(
			"ExpireUpload() = (%v, %v), delete callback=%v",
			changed,
			err,
			deleted,
		)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestCleanupUploadPartsDeletesFilesBeforeRecordsAndMarksCompletion(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	repository := NewMySQLRepository(db)

	expectUploadLock(mock, "upload-id")
	mock.ExpectBegin()
	mock.ExpectQuery(`(?s)SELECT u\.status.*FROM uploads u.*u\.id = \?.*parts_cleaned_at IS NULL.*status IN.*FOR UPDATE SKIP LOCKED`).
		WithArgs("upload-id").
		WillReturnRows(sqlmock.NewRows([]string{"status"}).AddRow("completed"))
	mock.ExpectExec(`(?s)DELETE FROM upload_parts.*WHERE upload_id = \?`).
		WithArgs("upload-id").
		WillReturnResult(sqlmock.NewResult(0, 2))
	mock.ExpectExec(`(?s)UPDATE uploads.*parts_cleaned_at = UTC_TIMESTAMP.*WHERE id = \?.*status = \?.*parts_cleaned_at IS NULL`).
		WithArgs("upload-id", "completed").
		WillReturnResult(sqlmock.NewResult(0, 1))
	expectSystemAudit(
		mock,
		"maintenance.upload_parts_cleaned",
		"upload",
		"upload-id",
	)
	mock.ExpectCommit()
	expectUploadUnlock(mock, "upload-id")

	deleted := false
	changed, err := repository.CleanupUploadParts(
		context.Background(),
		"upload-id",
		func() error {
			deleted = true
			return nil
		},
	)
	if err != nil || !changed || !deleted {
		t.Fatalf("CleanupUploadParts() = (%v, %v), deleted=%v", changed, err, deleted)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestCleanupUploadPartsFilesystemFailureKeepsDurablePendingState(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	repository := NewMySQLRepository(db)
	sentinel := errors.New("filesystem unavailable")

	expectUploadLock(mock, "upload-id")
	mock.ExpectBegin()
	mock.ExpectQuery(`(?s)SELECT u\.status.*FOR UPDATE SKIP LOCKED`).
		WithArgs("upload-id").
		WillReturnRows(sqlmock.NewRows([]string{"status"}).AddRow("failed"))
	mock.ExpectRollback()
	expectUploadUnlock(mock, "upload-id")

	changed, err := repository.CleanupUploadParts(
		context.Background(),
		"upload-id",
		func() error { return sentinel },
	)
	if changed || !errors.Is(err, sentinel) {
		t.Fatalf("CleanupUploadParts() = (%v, %v)", changed, err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestExpireUploadReleasesPreparedStagingReferences(t *testing.T) {
	tests := []struct {
		name           string
		referenceCount uint64
		nextState      string
	}{
		{name: "last prepared reference becomes deleting", referenceCount: 1, nextState: "deleting"},
		{name: "shared prepared reference remains staging", referenceCount: 2, nextState: "staging"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			db, mock, err := sqlmock.New()
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			repository := NewMySQLRepository(db)

			expectUploadLock(mock, "upload-id")
			mock.ExpectBegin()
			mock.ExpectQuery(`(?s)SELECT u\.blob_id.*FROM uploads u.*u\.id = \?.*FOR UPDATE SKIP LOCKED`).
				WithArgs("upload-id").
				WillReturnRows(sqlmock.NewRows([]string{"blob_id"}).AddRow(42))
			expectBlobReferenceReleaseFromState(
				mock,
				42,
				test.referenceCount,
				"staging",
				test.nextState,
			)
			mock.ExpectExec(`(?s)DELETE FROM upload_parts.*WHERE upload_id = \?`).
				WithArgs("upload-id").
				WillReturnResult(sqlmock.NewResult(0, 1))
			mock.ExpectExec(`(?s)UPDATE uploads.*status = 'expired'.*blob_id = NULL.*parts_cleaned_at = UTC_TIMESTAMP.*WHERE id = \?.*expires_at <= UTC_TIMESTAMP`).
				WithArgs("upload-id").
				WillReturnResult(sqlmock.NewResult(0, 1))
			expectSystemAudit(
				mock,
				"retention.upload_expired",
				"upload",
				"upload-id",
			)
			mock.ExpectCommit()
			expectUploadUnlock(mock, "upload-id")

			changed, err := repository.ExpireUpload(
				context.Background(),
				"upload-id",
				func() error { return nil },
			)
			if err != nil || !changed {
				t.Fatalf("ExpireUpload() = (%v, %v)", changed, err)
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestExpireUploadFilesystemFailureRollsBackBeforeDatabaseCleanup(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	repository := NewMySQLRepository(db)
	sentinel := errors.New("unsafe upload directory")

	expectUploadLock(mock, "upload-id")
	mock.ExpectBegin()
	mock.ExpectQuery(`(?s)SELECT u\.blob_id.*FOR UPDATE SKIP LOCKED`).
		WithArgs("upload-id").
		WillReturnRows(sqlmock.NewRows([]string{"blob_id"}).AddRow(nil))
	mock.ExpectRollback()
	expectUploadUnlock(mock, "upload-id")

	changed, err := repository.ExpireUpload(
		context.Background(),
		"upload-id",
		func() error { return sentinel },
	)
	if changed || !errors.Is(err, sentinel) {
		t.Fatalf("ExpireUpload() = (%v, %v)", changed, err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestExpireUploadReplayConvergesAfterAmbiguousCommit(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	repository := NewMySQLRepository(db)
	commitErr := errors.New("commit result unavailable")

	expectUploadExpirationWithoutBlob(mock, "upload-id", commitErr)
	expectUploadExpirationWithoutBlob(mock, "upload-id", nil)

	directoryMissing := false
	deleteDirectory := func() error {
		if !directoryMissing {
			directoryMissing = true
		}
		return nil
	}
	changed, err := repository.ExpireUpload(
		context.Background(),
		"upload-id",
		deleteDirectory,
	)
	if changed || !errors.Is(err, commitErr) || !directoryMissing {
		t.Fatalf("first ExpireUpload() = (%v, %v)", changed, err)
	}
	changed, err = repository.ExpireUpload(
		context.Background(),
		"upload-id",
		deleteDirectory,
	)
	if err != nil || !changed {
		t.Fatalf("replayed ExpireUpload() = (%v, %v)", changed, err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestFinalizeDeletingBlobMarksDeletedOnlyAfterCallbackSucceeds(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	repository := NewMySQLRepository(db)
	blob := Blob{
		ID: 42, SHA256: testSHA256, SizeBytes: 8,
		StorageKey: "blobs/sha256/aa/" + testSHA256,
	}

	mock.ExpectBegin()
	expectDeletingBlobLock(mock, blob)
	called := false
	mock.ExpectExec(`(?s)UPDATE blobs.*state = 'deleted'.*deleted_at = UTC_TIMESTAMP.*WHERE id = \?.*sha256 = \?.*size_bytes = \?.*storage_key = \?.*state = 'deleting'.*reference_count = 0`).
		WithArgs(blob.ID, blob.SHA256, blob.SizeBytes, blob.StorageKey).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

	changed, err := repository.FinalizeDeletingBlob(
		context.Background(),
		blob.ID,
		func(actual Blob) error {
			called = true
			if actual != blob {
				t.Fatalf("callback blob = %+v, want %+v", actual, blob)
			}
			return nil
		},
	)
	if err != nil || !changed || !called {
		t.Fatalf("FinalizeDeletingBlob() = (%v, %v), called=%v", changed, err, called)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestFinalizeDeletingBlobFailureKeepsDatabaseDeleting(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	repository := NewMySQLRepository(db)
	blob := Blob{
		ID: 42, SHA256: testSHA256, SizeBytes: 8,
		StorageKey: "blobs/sha256/aa/" + testSHA256,
	}
	sentinel := errors.New("filesystem unavailable")

	mock.ExpectBegin()
	expectDeletingBlobLock(mock, blob)
	mock.ExpectRollback()
	changed, err := repository.FinalizeDeletingBlob(
		context.Background(),
		blob.ID,
		func(Blob) error { return sentinel },
	)
	if changed || !errors.Is(err, sentinel) {
		t.Fatalf("FinalizeDeletingBlob() = (%v, %v)", changed, err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestCandidateQueriesAreBoundedAndProtectActiveStates(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	repository := NewMySQLRepository(db)

	mock.ExpectQuery(`(?s)SELECT t\.id.*sample_expires_at <= UTC_TIMESTAMP.*sample_deleted_at IS NULL.*deleted_at IS NULL.*status IN \('SUCCEEDED', 'PARTIAL_SUCCEEDED', 'FAILED', 'CANCELLED'\).*jobs.*leased.*running.*cancel_requested.*queued.*kind <> 'decompile'.*ORDER BY.*LIMIT \?`).
		WithArgs(7).
		WillReturnRows(sqlmock.NewRows([]string{"id"}).
			AddRow("task-a").
			AddRow("task-b"))
	tasks, err := repository.ListExpiredTaskIDs(context.Background(), 7)
	if err != nil || len(tasks) != 2 {
		t.Fatalf("ListExpiredTaskIDs() = (%v, %v)", tasks, err)
	}

	mock.ExpectQuery(`(?s)SELECT u\.id.*expires_at <= UTC_TIMESTAMP.*status <> 'expired'.*blob_id IS NOT NULL.*upload_parts.*ORDER BY.*LIMIT \?`).
		WithArgs(5).
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow("upload-a"))
	uploads, err := repository.ListExpiredUploadIDs(context.Background(), 5)
	if err != nil || len(uploads) != 1 {
		t.Fatalf("ListExpiredUploadIDs() = (%v, %v)", uploads, err)
	}

	mock.ExpectQuery(`(?s)SELECT id.*FROM blobs.*state = 'deleting'.*reference_count = 0.*ORDER BY id.*LIMIT \?`).
		WithArgs(3).
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(9))
	blobs, err := repository.ListDeletingBlobIDs(context.Background(), 3)
	if err != nil || len(blobs) != 1 || blobs[0] != 9 {
		t.Fatalf("ListDeletingBlobIDs() = (%v, %v)", blobs, err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestBlobReferenceInconsistencyRollsBackOwnerMutation(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	repository := NewMySQLRepository(db)

	mock.ExpectBegin()
	mock.ExpectQuery(`(?s)SELECT t\.blob_id.*FOR UPDATE SKIP LOCKED`).
		WithArgs("task-id").
		WillReturnRows(sqlmock.NewRows([]string{"blob_id"}).AddRow(42))
	mock.ExpectExec(`(?s)UPDATE jobs.*kind = 'decompile'.*status = 'queued'`).
		WithArgs("task-id").
		WillReturnResult(sqlmock.NewResult(0, 0))
	expectNoDerivedBlobReferences(mock, "task-id")
	mock.ExpectQuery(`(?s)SELECT reference_count, state.*FROM blobs.*FOR UPDATE`).
		WithArgs(uint64(42)).
		WillReturnRows(sqlmock.NewRows([]string{"reference_count", "state"}).
			AddRow(0, "available"))
	mock.ExpectRollback()

	changed, err := repository.ReleaseExpiredTaskSample(
		context.Background(),
		"task-id",
	)
	if changed || err == nil {
		t.Fatalf("ReleaseExpiredTaskSample() = (%v, %v)", changed, err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func expectNoDerivedBlobReferences(mock sqlmock.Sqlmock, taskID string) {
	mock.ExpectQuery(`(?s)SELECT file_node_id, blob_id.*FROM file_node_blob_refs.*WHERE task_id = \?.*ORDER BY file_node_id.*FOR UPDATE`).
		WithArgs(taskID).
		WillReturnRows(sqlmock.NewRows([]string{"file_node_id", "blob_id"}))
}

const testSHA256 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func expectBlobReferenceRelease(
	mock sqlmock.Sqlmock,
	blobID uint64,
	referenceCount uint64,
	nextState string,
) {
	expectBlobReferenceReleaseFromState(
		mock,
		blobID,
		referenceCount,
		"available",
		nextState,
	)
}

func expectBlobReferenceReleaseFromState(
	mock sqlmock.Sqlmock,
	blobID uint64,
	referenceCount uint64,
	currentState string,
	nextState string,
) {
	mock.ExpectQuery(`(?s)SELECT reference_count, state.*FROM blobs.*WHERE id = \?.*FOR UPDATE`).
		WithArgs(blobID).
		WillReturnRows(sqlmock.NewRows([]string{"reference_count", "state"}).
			AddRow(referenceCount, currentState))
	mock.ExpectExec(`(?s)UPDATE blobs.*SET state = \?.*reference_count = reference_count - 1.*WHERE id = \?.*state = \?.*reference_count = \?`).
		WithArgs(nextState, blobID, currentState, referenceCount).
		WillReturnResult(sqlmock.NewResult(0, 1))
}

func expectSystemAudit(
	mock sqlmock.Sqlmock,
	action string,
	objectType string,
	objectID string,
) {
	mock.ExpectExec(regexp.QuoteMeta(`
INSERT INTO audit_logs (
    actor_user_id, request_id, action, object_type, object_id, outcome,
    client_ip, user_agent, metadata_json
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`)).
		WithArgs(
			nil,
			nil,
			action,
			objectType,
			objectID,
			"success",
			nil,
			nil,
			sqlmock.AnyArg(),
		).
		WillReturnResult(sqlmock.NewResult(1, 1))
}

func expectDeletingBlobLock(mock sqlmock.Sqlmock, blob Blob) {
	mock.ExpectQuery(`(?s)SELECT id, sha256, size_bytes, storage_key.*FROM blobs.*id = \?.*state = 'deleting'.*reference_count = 0.*FOR UPDATE SKIP LOCKED`).
		WithArgs(blob.ID).
		WillReturnRows(sqlmock.NewRows(
			[]string{"id", "sha256", "size_bytes", "storage_key"},
		).AddRow(blob.ID, blob.SHA256, blob.SizeBytes, blob.StorageKey))
}

func expectUploadLock(mock sqlmock.Sqlmock, uploadID string) {
	mock.ExpectQuery(regexp.QuoteMeta("SELECT GET_LOCK(?, ?)")).
		WithArgs(
			"binaryscan_upload_"+uploadID,
			uploadRetentionLockWaitSeconds,
		).
		WillReturnRows(sqlmock.NewRows([]string{"acquired"}).AddRow(1))
}

func expectUploadUnlock(mock sqlmock.Sqlmock, uploadID string) {
	mock.ExpectQuery(regexp.QuoteMeta("SELECT RELEASE_LOCK(?)")).
		WithArgs("binaryscan_upload_" + uploadID).
		WillReturnRows(sqlmock.NewRows([]string{"released"}).AddRow(1))
}

func expectUploadExpirationWithoutBlob(
	mock sqlmock.Sqlmock,
	uploadID string,
	commitErr error,
) {
	expectUploadLock(mock, uploadID)
	mock.ExpectBegin()
	mock.ExpectQuery(`(?s)SELECT u\.blob_id.*FOR UPDATE SKIP LOCKED`).
		WithArgs(uploadID).
		WillReturnRows(sqlmock.NewRows([]string{"blob_id"}).AddRow(nil))
	mock.ExpectExec(`(?s)DELETE FROM upload_parts.*WHERE upload_id = \?`).
		WithArgs(uploadID).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`(?s)UPDATE uploads.*status = 'expired'.*blob_id = NULL.*WHERE id = \?.*expires_at <= UTC_TIMESTAMP`).
		WithArgs(uploadID).
		WillReturnResult(sqlmock.NewResult(0, 1))
	expectSystemAudit(mock, "retention.upload_expired", "upload", uploadID)
	commit := mock.ExpectCommit()
	if commitErr != nil {
		commit.WillReturnError(commitErr)
	}
	expectUploadUnlock(mock, uploadID)
}

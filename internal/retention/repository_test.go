package retention

import (
	"context"
	"database/sql"
	"errors"
	"regexp"
	"strings"
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

func TestCompleteExpiredTaskSamplePreservesDecompileSources(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	claim := TaskSampleClaim{
		TaskID: "task-id", LeaseOwner: "retention-owner",
		FencingToken: 3, Attempt: 2,
	}
	const blobID uint64 = 42

	mock.ExpectBegin()
	mock.ExpectQuery(`(?s)SELECT t[.]blob_id.*FROM tasks t.*FOR UPDATE`).
		WithArgs(claim.TaskID).
		WillReturnRows(sqlmock.NewRows([]string{"blob_id"}).AddRow(blobID))
	mock.ExpectQuery(`(?s)SELECT status.*task_sample_retention_operations.*FOR UPDATE`).
		WithArgs(claim.TaskID, claim.FencingToken, claim.LeaseOwner).
		WillReturnRows(sqlmock.NewRows([]string{"status"}).AddRow("cleaning"))
	mock.ExpectExec(`(?s)UPDATE jobs.*kind = 'decompile'.*status = 'queued'`).
		WithArgs(claim.TaskID).
		WillReturnResult(sqlmock.NewResult(0, 0))
	expectNoDerivedBlobReferences(mock, claim.TaskID)
	expectBlobReferenceRelease(mock, blobID, 1, "deleting")
	mock.ExpectExec(`(?s)UPDATE tasks.*sample_deleted_at = UTC_TIMESTAMP`).
		WithArgs(claim.TaskID, blobID).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`(?s)INSERT INTO task_events.*SELECT.*FROM tasks`).
		WithArgs(
			"task.sample_deleted", "Task sample retention expired.", claim.TaskID,
		).
		WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectExec(`(?s)UPDATE task_sample_retention_operations.*status = 'completed'`).
		WithArgs(claim.TaskID, claim.FencingToken, claim.LeaseOwner).
		WillReturnResult(sqlmock.NewResult(0, 1))
	expectSystemAudit(
		mock, "retention.task_sample_deleted", "task", claim.TaskID,
	)
	mock.ExpectCommit()

	completed, err := NewMySQLRepository(db).CompleteExpiredTaskSample(
		context.Background(), claim,
	)
	if err != nil || !completed {
		t.Fatalf("CompleteExpiredTaskSample() = (%v, %v)", completed, err)
	}
	// An unexpected UPDATE decompile_results would fail sqlmock. This protects
	// the independently retained source-project contract.
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
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
	mock.ExpectQuery(`(?s)SELECT u\.blob_id.*FROM uploads u.*u\.id = \?.*expires_at <= UTC_TIMESTAMP.*upload_intake_profiles intake.*candidate_blob.*source_kind = 'direct'.*validation_status = 'valid'.*input_category IN \('binary', 'container'\).*NOT EXISTS \(.*FROM tasks claimed_task.*WHERE claimed_task\.upload_id = u\.id.*upload_intake_profiles archive_intake.*input_category = 'archive'.*archive_blob\.state = 'available'.*archive_import_id IS NULL.*archive_imports active_import.*active_import\.status IN \('queued', 'running'\).*archive_import_entries pending_entry.*derived_intake\.source_kind = 'archive_entry'.*pending_entry\.status IN \('eligible', 'failed'\).*FOR UPDATE SKIP LOCKED`).
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

	expectDeletingBlobFenceStart(mock, blob)
	mock.ExpectBegin()
	expectDeletingBlobLock(mock, blob)
	called := false
	mock.ExpectExec(`(?s)UPDATE blobs.*state = 'deleted'.*deleted_at = UTC_TIMESTAMP.*WHERE id = \?.*sha256 = \?.*size_bytes = \?.*storage_key = \?.*state = 'deleting'.*reference_count = 0`).
		WithArgs(blob.ID, blob.SHA256, blob.SizeBytes, blob.StorageKey).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()
	expectDeletingBlobFenceEnd(mock, blob)

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

	expectDeletingBlobFenceStart(mock, blob)
	mock.ExpectBegin()
	expectDeletingBlobLock(mock, blob)
	mock.ExpectRollback()
	expectDeletingBlobFenceEnd(mock, blob)
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

	mock.ExpectQuery(`(?s)SELECT u\.id.*expires_at <= UTC_TIMESTAMP.*status <> 'expired'.*blob_id IS NOT NULL.*upload_parts.*upload_intake_profiles intake.*candidate_blob.*source_kind = 'direct'.*validation_status = 'valid'.*input_category IN \('binary', 'container'\).*detected_category = intake\.input_category.*candidate_blob\.state = 'available'.*NOT EXISTS \(.*FROM tasks claimed_task.*WHERE claimed_task\.upload_id = u\.id.*upload_intake_profiles archive_intake.*input_category = 'archive'.*archive_blob\.state = 'available'.*archive_import_id IS NULL.*archive_imports active_import.*active_import\.status IN \('queued', 'running'\).*archive_import_entries pending_entry.*derived_intake\.source_kind = 'archive_entry'.*pending_entry\.status IN \('eligible', 'failed'\).*ORDER BY.*LIMIT \?`).
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

func TestExpiredUploadPredicateProtectsUnrecoveredIntakeWork(t *testing.T) {
	required := []string{
		"u.status = 'completed'",
		"intake.source_kind = 'direct'",
		"intake.validation_status = 'valid'",
		"intake.input_category IN ('binary', 'container')",
		"intake.detected_category = intake.input_category",
		"candidate_blob.state = 'available'",
		"FROM tasks claimed_task",
		"WHERE claimed_task.upload_id = u.id",
		"FROM upload_intake_profiles archive_intake",
		"archive_intake.input_category = 'archive'",
		"archive_intake.detected_category = 'archive'",
		"archive_intake.archive_import_id IS NULL",
		"archive_blob.state = 'available'",
		"FROM archive_imports active_import",
		"active_import.upload_id = u.id",
		"active_import.status IN ('queued', 'running')",
		"FROM archive_import_entries pending_entry",
		"derived_intake.source_kind = 'archive_entry'",
		"pending_entry.status IN ('eligible', 'failed')",
		"FROM upload_intake_profiles derived_provenance",
		"pending_provenance.status IN ('eligible', 'failed')",
		"pending_provenance.derived_upload_id IS NULL",
		"pending_provenance.sha256 = u.actual_sha256",
		"pending_provenance.blob_id = u.blob_id",
	}
	for _, fragment := range required {
		if !strings.Contains(expiredUploadPredicate, fragment) {
			t.Fatalf("expiredUploadPredicate does not contain %q", fragment)
		}
	}
	if strings.Contains(expiredUploadPredicate, "claimed_task.status") {
		t.Fatal("soft-deleted tasks must count as durable claims for upload retention")
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

func expectDeletingBlobFenceStart(mock sqlmock.Sqlmock, blob Blob) {
	mock.ExpectQuery(`(?s)SELECT sha256.*FROM blobs.*WHERE id = \?`).
		WithArgs(blob.ID).
		WillReturnRows(sqlmock.NewRows([]string{"sha256"}).AddRow(blob.SHA256))
	mock.ExpectQuery(regexp.QuoteMeta("SELECT GET_LOCK(?, ?)")).
		WithArgs("binaryscan_blob_sha256_"+blob.SHA256[:40], 30).
		WillReturnRows(sqlmock.NewRows([]string{"acquired"}).AddRow(1))
}

func expectDeletingBlobFenceEnd(mock sqlmock.Sqlmock, blob Blob) {
	mock.ExpectExec(regexp.QuoteMeta("SELECT RELEASE_LOCK(?)")).
		WithArgs("binaryscan_blob_sha256_" + blob.SHA256[:40]).
		WillReturnResult(sqlmock.NewResult(0, 1))
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

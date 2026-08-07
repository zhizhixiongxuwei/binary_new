package taskcleanup

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
)

func TestMySQLRepositoryListReadyExcludesActiveReportGeneration(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	mock.ExpectQuery(`(?s)SELECT task[.]id.*FROM reports report.*report[.]status IN \('queued', 'generating'\).*ORDER BY`).
		WithArgs(10).
		WillReturnRows(sqlmock.NewRows([]string{"id"}))

	ids, err := NewMySQLRepository(db).ListReady(context.Background(), 10)
	if err != nil || len(ids) != 0 {
		t.Fatalf("ListReady() = (%v, %v)", ids, err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestMySQLRepositoryClaimCreatesFencedOperationAndCollectsOutputs(
	t *testing.T,
) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	now := time.Date(2026, 7, 31, 1, 2, 3, 0, time.UTC)
	reportContent := []byte(`{"ok":true}`)
	reportSHA := cleanupSHA(reportContent)
	reportKey := "reports/" + testTaskID + "/" + testReportID + ".json"

	mock.ExpectBegin()
	mock.ExpectQuery(`(?s)SELECT UTC_TIMESTAMP\(6\).*FROM tasks task.*FOR UPDATE SKIP LOCKED`).
		WithArgs(testTaskID).
		WillReturnRows(sqlmock.NewRows([]string{"now"}).AddRow(now))
	mock.ExpectQuery(`(?s)SELECT status, fencing_token, attempt_count, lease_until.*task_deletion_operations.*FOR UPDATE`).
		WithArgs(testTaskID).
		WillReturnError(sql.ErrNoRows)
	mock.ExpectExec(`(?s)INSERT INTO task_deletion_operations`).
		WithArgs(testTaskID, "owner", int64(time.Minute/time.Microsecond)).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectQuery(`(?s)SELECT id, format, storage_key, sha256, size_bytes.*FROM reports`).
		WithArgs(testTaskID).
		WillReturnRows(sqlmock.NewRows(
			[]string{"id", "format", "storage_key", "sha256", "size_bytes"},
		).AddRow(
			testReportID, "json", reportKey, reportSHA, len(reportContent),
		))
	mock.ExpectQuery(`(?s)SELECT id, storage_key, sha256, size_bytes.*FROM artifacts`).
		WithArgs(testTaskID).
		WillReturnRows(sqlmock.NewRows(
			[]string{"id", "storage_key", "sha256", "size_bytes"},
		))
	mock.ExpectQuery(`(?s)SELECT id, storage_key, content_sha256, size_bytes.*FROM decompile_results`).
		WithArgs(testTaskID).
		WillReturnRows(sqlmock.NewRows(
			[]string{"id", "storage_key", "content_sha256", "size_bytes"},
		).AddRow(testResultID, nil, nil, nil))
	expectCleanupAudit(
		mock, "task.deletion_cleanup_started", "success", testTaskID,
	)
	mock.ExpectCommit()

	claim, claimed, err := NewMySQLRepository(db).Claim(
		context.Background(), testTaskID, "owner", time.Minute,
	)
	if err != nil || !claimed || claim.FencingToken != 1 ||
		claim.Attempt != 1 || len(claim.Files) != 1 ||
		claim.Files[0].StorageKey != reportKey ||
		len(claim.Scopes) != 3 {
		t.Fatalf("Claim() = (%+v, %v, %v)", claim, claimed, err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestMySQLRepositoryClaimDoesNotTakeTaskWithEffectiveWork(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	mock.ExpectBegin()
	mock.ExpectQuery(`(?s)SELECT UTC_TIMESTAMP\(6\).*FROM tasks task.*job.status IN \('queued', 'leased', 'running', 'cancel_requested'\).*FROM reports report.*report.status IN \('queued', 'generating'\).*FOR UPDATE SKIP LOCKED`).
		WithArgs(testTaskID).
		WillReturnError(sql.ErrNoRows)
	mock.ExpectCommit()
	_, claimed, err := NewMySQLRepository(db).Claim(
		context.Background(), testTaskID, "owner", time.Minute,
	)
	if err != nil || claimed {
		t.Fatalf("Claim() = (%v, %v), want skipped", claimed, err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestMySQLRepositoryRenewRequiresNoActiveReportGeneration(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	claim := Claim{
		TaskID:       testTaskID,
		LeaseOwner:   "owner",
		FencingToken: 3,
		Attempt:      2,
	}
	mock.ExpectExec(`(?s)UPDATE task_deletion_operations operation.*FROM reports report.*report[.]status IN \('queued', 'generating'\)`).
		WithArgs(
			int64(time.Minute/time.Microsecond),
			testTaskID,
			claim.FencingToken,
			claim.LeaseOwner,
		).
		WillReturnResult(sqlmock.NewResult(0, 0))

	renewed, err := NewMySQLRepository(db).Renew(
		context.Background(), claim, time.Minute,
	)
	if err != nil || renewed {
		t.Fatalf("Renew() = (%v, %v), want skipped", renewed, err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestMySQLRepositoryCompleteReleasesCASAndDeletesResultsButNotAudit(
	t *testing.T,
) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	claim := Claim{
		TaskID: testTaskID, LeaseOwner: "owner",
		FencingToken: 3, Attempt: 2,
	}
	const rootBlobID uint64 = 41
	const nestedBlobID uint64 = 42

	mock.ExpectBegin()
	mock.ExpectQuery(`(?s)SELECT blob_id, sample_deleted_at.*FROM tasks task.*FROM reports report.*report[.]status IN \('queued', 'generating'\).*FOR UPDATE`).
		WithArgs(testTaskID).
		WillReturnRows(sqlmock.NewRows(
			[]string{"blob_id", "sample_deleted_at"},
		).AddRow(rootBlobID, nil))
	mock.ExpectQuery(`(?s)SELECT status.*FROM task_deletion_operations.*fencing_token = \?.*lease_owner = \?.*FOR UPDATE`).
		WithArgs(testTaskID, claim.FencingToken, claim.LeaseOwner).
		WillReturnRows(sqlmock.NewRows([]string{"status"}).AddRow("cleaning"))
	mock.ExpectQuery(`(?s)SELECT file_node_id, blob_id.*file_node_blob_refs.*FOR UPDATE`).
		WithArgs(testTaskID).
		WillReturnRows(sqlmock.NewRows(
			[]string{"file_node_id", "blob_id"},
		).AddRow(7, nestedBlobID))
	expectBlobRelease(mock, nestedBlobID, 1, "deleting")
	mock.ExpectExec(`DELETE FROM file_node_blob_refs`).
		WithArgs(testTaskID).
		WillReturnResult(sqlmock.NewResult(0, 1))
	expectBlobRelease(mock, rootBlobID, 2, "available")
	for _, table := range []string{
		"reports", "vulnerability_findings", "decompile_results",
		"artifacts", "analyzer_runs", "file_nodes",
	} {
		mock.ExpectExec(`DELETE FROM ` + table + ` WHERE task_id = \?`).
			WithArgs(testTaskID).
			WillReturnResult(sqlmock.NewResult(0, 1))
	}
	mock.ExpectExec(`(?s)UPDATE task_attempts.*status = 'cancelled'`).
		WithArgs(testTaskID).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`(?s)UPDATE jobs.*payload = NULL`).
		WithArgs(testTaskID).
		WillReturnResult(sqlmock.NewResult(0, 2))
	mock.ExpectExec(`(?s)UPDATE tasks.*status = 'DELETED'.*deleted_at = UTC_TIMESTAMP\(6\)`).
		WithArgs(testTaskID).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`(?s)INSERT INTO task_events.*SELECT.*FROM tasks`).
		WithArgs(
			"task.status_changed", "Task deletion completed.", testTaskID,
		).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`(?s)UPDATE task_deletion_operations.*status = 'completed'`).
		WithArgs(testTaskID, claim.FencingToken, claim.LeaseOwner).
		WillReturnResult(sqlmock.NewResult(0, 1))
	expectCleanupAudit(
		mock, "task.deletion_cleanup_completed", "success", testTaskID,
	)
	mock.ExpectCommit()

	completed, err := NewMySQLRepository(db).Complete(
		context.Background(), claim,
	)
	if err != nil || !completed {
		t.Fatalf("Complete() = (%v, %v)", completed, err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestMySQLRepositoryFailUsesExactFenceAndWritesAudit(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	claim := Claim{
		TaskID: testTaskID, LeaseOwner: "owner",
		FencingToken: 4, Attempt: 3,
	}
	mock.ExpectBegin()
	mock.ExpectExec(`(?s)UPDATE task_deletion_operations operation.*status = 'failed'.*fencing_token = \?.*lease_owner = \?`).
		WithArgs(
			"task_deletion_file_cleanup_failed", testTaskID,
			claim.FencingToken, claim.LeaseOwner,
		).
		WillReturnResult(sqlmock.NewResult(0, 1))
	expectCleanupAudit(
		mock, "task.deletion_cleanup_failed", "failure", testTaskID,
	)
	mock.ExpectCommit()
	changed, err := NewMySQLRepository(db).Fail(
		context.Background(), claim,
		Failure{Code: "task_deletion_file_cleanup_failed"},
	)
	if err != nil || !changed {
		t.Fatalf("Fail() = (%v, %v)", changed, err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestMySQLRepositoryCompleteRejectsExpiredOrStolenLease(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	claim := Claim{
		TaskID: testTaskID, LeaseOwner: "owner",
		FencingToken: 5, Attempt: 4,
	}
	mock.ExpectBegin()
	mock.ExpectQuery(`(?s)SELECT blob_id, sample_deleted_at.*FROM tasks task.*FROM reports report.*report[.]status IN \('queued', 'generating'\).*FOR UPDATE`).
		WithArgs(testTaskID).
		WillReturnRows(sqlmock.NewRows(
			[]string{"blob_id", "sample_deleted_at"},
		).AddRow(41, nil))
	mock.ExpectQuery(`(?s)SELECT status.*task_deletion_operations.*lease_until > UTC_TIMESTAMP\(6\).*FOR UPDATE`).
		WithArgs(testTaskID, claim.FencingToken, claim.LeaseOwner).
		WillReturnError(sql.ErrNoRows)
	mock.ExpectCommit()
	completed, err := NewMySQLRepository(db).Complete(
		context.Background(), claim,
	)
	if err != nil || completed {
		t.Fatalf("Complete() = (%v, %v), want stale claim", completed, err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestMySQLRepositoryCompleteWaitsForGeneratingReportBarrier(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	claim := Claim{
		TaskID:       testTaskID,
		LeaseOwner:   "owner",
		FencingToken: 6,
		Attempt:      5,
	}

	mock.ExpectBegin()
	mock.ExpectQuery(
		`(?s)SELECT blob_id, sample_deleted_at.*FROM tasks task.*FROM reports report.*report[.]status IN \('queued', 'generating'\).*FOR UPDATE`,
	).WithArgs(testTaskID).WillReturnError(sql.ErrNoRows)
	mock.ExpectCommit()

	completed, err := NewMySQLRepository(db).Complete(
		context.Background(),
		claim,
	)
	if err != nil || completed {
		t.Fatalf("Complete() = (%v, %v), want active report barrier", completed, err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func expectBlobRelease(
	mock sqlmock.Sqlmock,
	blobID uint64,
	referenceCount uint64,
	nextState string,
) {
	mock.ExpectQuery(`(?s)SELECT reference_count, state.*FROM blobs.*FOR UPDATE`).
		WithArgs(blobID).
		WillReturnRows(sqlmock.NewRows(
			[]string{"reference_count", "state"},
		).AddRow(referenceCount, "available"))
	mock.ExpectExec(`(?s)UPDATE blobs.*SET state = \?.*reference_count = reference_count - 1`).
		WithArgs(nextState, blobID, referenceCount).
		WillReturnResult(sqlmock.NewResult(0, 1))
}

func expectCleanupAudit(
	mock sqlmock.Sqlmock,
	action string,
	outcome string,
	taskID string,
) {
	mock.ExpectExec(`(?s)INSERT INTO audit_logs`).
		WithArgs(
			nil, nil, action, "task", taskID, outcome,
			nil, nil, sqlmock.AnyArg(),
		).
		WillReturnResult(sqlmock.NewResult(1, 1))
}

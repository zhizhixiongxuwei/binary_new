package archiveimport

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
)

func TestRecoverDeletingReservesOldestCandidates(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	repository, err := NewMySQLRepository(db)
	if err != nil {
		t.Fatal(err)
	}

	mock.ExpectQuery(`(?s)SELECT id, upload_id.*status = 'deleting'.*updated_at <= TIMESTAMPADD.*ORDER BY updated_at ASC, id ASC.*LIMIT [?]`).
		WithArgs(-int64(time.Minute/time.Microsecond), 2).
		WillReturnRows(sqlmock.NewRows([]string{"id", "upload_id"}).
			AddRow("import-poison", "upload-poison").
			AddRow("import-next", "upload-next"))
	mock.ExpectExec(`(?s)UPDATE archive_imports.*updated_at = UTC_TIMESTAMP.*id = [?].*status = 'deleting'.*updated_at <= TIMESTAMPADD`).
		WithArgs("import-poison", -int64(time.Minute/time.Microsecond)).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`(?s)UPDATE archive_imports.*updated_at = UTC_TIMESTAMP.*id = [?].*status = 'deleting'.*updated_at <= TIMESTAMPADD`).
		WithArgs("import-next", -int64(time.Minute/time.Microsecond)).
		WillReturnResult(sqlmock.NewResult(0, 1))

	ids, err := repository.RecoverDeleting(context.Background(), time.Minute, 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(ids) != 2 || ids[0] != "upload-poison" || ids[1] != "upload-next" {
		t.Fatalf("RecoverDeleting() = %v", ids)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestRecoverExpiredIsBoundedAndRequeuesWithFenceCleared(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	repository, err := NewMySQLRepository(db)
	if err != nil {
		t.Fatal(err)
	}

	mock.ExpectQuery(`(?s)SELECT id.*lease_until <= UTC_TIMESTAMP.*ORDER BY updated_at ASC, id ASC.*LIMIT [?]`).
		WithArgs(1000).
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow("import-retry"))
	mock.ExpectBegin()
	mock.ExpectQuery(`(?s)SELECT attempt, max_attempts.*id = [?].*lease_until <= UTC_TIMESTAMP.*FOR UPDATE`).
		WithArgs("import-retry").
		WillReturnRows(sqlmock.NewRows([]string{"attempt", "max_attempts"}).AddRow(1, 3))
	mock.ExpectExec(`(?s)UPDATE archive_imports.*status = 'queued'.*lease_owner = NULL.*lease_until = NULL.*available_at = TIMESTAMPADD.*WHERE id = [?].*attempt < max_attempts`).
		WithArgs(int64(time.Second/time.Microsecond), "import-retry").
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

	count, err := repository.RecoverExpired(context.Background(), time.Second)
	if err != nil || count != 1 {
		t.Fatalf("RecoverExpired() = (%d, %v)", count, err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestRecoverExpiredPoisonDoesNotBlockLaterLease(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	repository, err := NewMySQLRepository(db)
	if err != nil {
		t.Fatal(err)
	}

	mock.ExpectQuery(`(?s)SELECT id.*ORDER BY updated_at ASC, id ASC.*LIMIT [?]`).
		WithArgs(1000).
		WillReturnRows(sqlmock.NewRows([]string{"id"}).
			AddRow("import-poison").AddRow("import-next"))
	mock.ExpectBegin()
	mock.ExpectQuery(`(?s)SELECT attempt, max_attempts.*FOR UPDATE`).
		WithArgs("import-poison").WillReturnError(errors.New("poison row"))
	mock.ExpectRollback()
	mock.ExpectExec(`(?s)UPDATE archive_imports.*archive_import_recovery_failed.*updated_at = UTC_TIMESTAMP.*id = [?]`).
		WithArgs("lock expired archive import lease: poison row", "import-poison").
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectBegin()
	mock.ExpectQuery(`(?s)SELECT attempt, max_attempts.*FOR UPDATE`).
		WithArgs("import-next").
		WillReturnRows(sqlmock.NewRows([]string{"attempt", "max_attempts"}).AddRow(1, 3))
	mock.ExpectExec(`(?s)UPDATE archive_imports.*status = 'queued'.*id = [?].*attempt < max_attempts`).
		WithArgs(int64(time.Second/time.Microsecond), "import-next").
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

	count, err := repository.RecoverExpired(context.Background(), time.Second)
	if count != 1 || err == nil {
		t.Fatalf("RecoverExpired() = (%d, %v), want one recovery plus poison error", count, err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestListRecoverableBatchesReservesPoisonSoItYields(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	repository, err := NewMySQLRepository(db)
	if err != nil {
		t.Fatal(err)
	}

	mock.ExpectQuery(`(?s)SELECT batch[.]id.*status = 'processing'.*updated_at <= TIMESTAMPADD.*ORDER BY batch[.]updated_at ASC, batch[.]id ASC.*LIMIT [?]`).
		WithArgs(-int64(time.Minute/time.Microsecond), 1).
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow("batch-poison"))
	mock.ExpectExec(`(?s)UPDATE archive_import_task_batches.*updated_at = UTC_TIMESTAMP.*id = [?].*status = 'processing'.*updated_at <= TIMESTAMPADD`).
		WithArgs("batch-poison", -int64(time.Minute/time.Microsecond)).
		WillReturnResult(sqlmock.NewResult(0, 1))

	ids, err := repository.ListRecoverableBatches(context.Background(), time.Minute, 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(ids) != 1 || ids[0] != "batch-poison" {
		t.Fatalf("ListRecoverableBatches() = %v", ids)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestCompleteTerminalBatchesRepairsInterruptedCompletion(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	repository, err := NewMySQLRepository(db)
	if err != nil {
		t.Fatal(err)
	}

	mock.ExpectExec(`(?s)UPDATE archive_import_task_batches batch.*status = 'completed'.*NOT EXISTS.*outcome IN \('pending', 'processing'\).*ORDER BY.*LIMIT [?]`).
		WithArgs(-int64(time.Minute/time.Microsecond), 20).
		WillReturnResult(sqlmock.NewResult(0, 2))

	count, err := repository.CompleteTerminalBatches(
		context.Background(), time.Minute, 20,
	)
	if err != nil || count != 2 {
		t.Fatalf("CompleteTerminalBatches() = (%d, %v)", count, err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestHeartbeatRejectsStaleLeaseFence(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	repository, err := NewMySQLRepository(db)
	if err != nil {
		t.Fatal(err)
	}
	lease := Lease{Import: Import{ID: "import-id", FencingToken: 7}, Owner: "worker-old"}
	mock.ExpectExec(`(?s)UPDATE archive_imports.*lease_owner = [?].*fencing_token = [?].*lease_until > UTC_TIMESTAMP`).
		WithArgs(int64(time.Minute/time.Microsecond), "import-id", "worker-old", uint64(7)).
		WillReturnResult(sqlmock.NewResult(0, 0))

	err = repository.Heartbeat(context.Background(), lease, time.Minute)
	if !errors.Is(err, ErrLeaseLost) {
		t.Fatalf("Heartbeat() error = %v, want ErrLeaseLost", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestLockBatchItemRejectsExpiredLeaseBeforeMutation(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	repository, err := NewMySQLRepository(db)
	if err != nil {
		t.Fatal(err)
	}
	work := BatchWorkItem{
		BatchID: "batch-id", EntryDatabaseID: 9,
		LeaseOwner: "worker-old", FencingToken: 4,
	}
	mock.ExpectBegin()
	mock.ExpectQuery(`(?s)SELECT 1.*archive_import_task_batch_items.*lease_owner = [?].*fencing_token = [?].*lease_until > UTC_TIMESTAMP.*FOR UPDATE`).
		WithArgs("batch-id", uint64(9), "worker-old", uint64(4)).
		WillReturnError(sql.ErrNoRows)
	mock.ExpectRollback()

	_, err = repository.RetryOrFailBatchItem(
		context.Background(), work, "failed", "failed",
	)
	if !errors.Is(err, ErrLeaseLost) {
		t.Fatalf("RetryOrFailBatchItem() error = %v, want ErrLeaseLost", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestReconcileEntryFactRejectsExpiredLinkedDerivedUpload(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	repository, err := NewMySQLRepository(db)
	if err != nil {
		t.Fatal(err)
	}
	derivedID := "73333333-3333-4333-8333-333333333333"
	mock.ExpectBegin()
	mock.ExpectQuery(`(?s)SELECT entry[.]archive_import_id.*FROM archive_import_entries.*FOR UPDATE`).
		WithArgs(uint64(9)).
		WillReturnRows(sqlmock.NewRows([]string{
			"archive_import_id", "upload_id", "display_name", "created_by",
			"logical_path", "detected_category", "detected_format", "status",
			"size_bytes", "sha256", "blob_id", "released_at",
			"derived_upload_id", "task_id",
		}).AddRow(
			"71111111-1111-4111-8111-111111111111",
			"72222222-2222-4222-8222-222222222222", "outer.zip", uint64(17),
			"bin/tool", "binary", "elf64", EntryFailed,
			int64(4), "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			uint64(12), nil, derivedID, nil,
		))
	mock.ExpectQuery(`(?s)SELECT derived[.]id, task[.]id, derived[.]status.*derived[.]actual_sha256 = [?].*derived[.]blob_id = [?].*FOR UPDATE`).
		WithArgs(
			"72222222-2222-4222-8222-222222222222", "outer.zip", "bin/tool",
			"binary", "binary", "elf64", uint64(17), int64(4),
			"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			uint64(12),
		).
		WillReturnRows(sqlmock.NewRows([]string{"id", "task_id", "status"}).
			AddRow(derivedID, nil, "expired"))
	mock.ExpectRollback()

	_, err = repository.ReconcileEntryFact(context.Background(), 9)
	if !errors.Is(err, ErrConflict) {
		t.Fatalf("ReconcileEntryFact() error = %v, want ErrConflict", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

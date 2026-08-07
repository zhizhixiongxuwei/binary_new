package task

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/go-sql-driver/mysql"
)

const testCreatorPublicID = "40000000-0000-4000-8000-000000000004"

func TestMySQLRepositoryCreateAtomicallyRetainsBlobAndQueuesScan(t *testing.T) {
	database, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New() error = %v", err)
	}
	defer database.Close()
	repository := NewMySQLRepository(database)
	now := time.Date(2026, 7, 29, 1, 2, 3, 0, time.UTC)
	expires := now.Add(DefaultSampleRetention)
	limits := []byte(`{"max_depth":10}`)
	record := CreateRecord{
		TaskID: testTaskID, JobID: testJobID, UserID: 42,
		UploadID: testUploadID, Name: "firmware.img",
		IdempotencyKey: "request-123", LimitsSnapshot: limits,
		SampleExpiresAt: expires, CreatedAt: now,
	}

	mock.ExpectBegin()
	mock.ExpectQuery(`(?s)SELECT id, upload_id, name.*idempotency_key = \?.*FOR UPDATE`).
		WithArgs(uint64(42), "request-123").
		WillReturnError(sql.ErrNoRows)
	mock.ExpectQuery(`(?s)SELECT upload\.created_by.*FOR UPDATE`).
		WithArgs(testUploadID).
		WillReturnRows(sqlmock.NewRows(
			[]string{"created_by", "status", "blob_id", "state"},
		).AddRow(uint64(42), "completed", int64(9), "available"))
	mock.ExpectQuery(`(?s)FROM tasks t.*WHERE t\.upload_id = \?`).
		WithArgs(testUploadID).
		WillReturnError(sql.ErrNoRows)
	mock.ExpectExec(`(?s)UPDATE blobs.*reference_count = reference_count \+ 1`).
		WithArgs(int64(9)).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`(?s)INSERT INTO tasks`).
		WithArgs(
			testTaskID, testUploadID, "request-123", int64(9), uint64(42), "firmware.img",
			limits, expires, now, now,
		).
		WillReturnResult(sqlmock.NewResult(0, 1))
	expectTaskEvent(mock, testTaskID, "task.created", "Task created.")
	mock.ExpectExec(`(?s)INSERT INTO task_attempts`).
		WithArgs(testTaskID, now).
		WillReturnResult(sqlmock.NewResult(17, 1))
	payload, _ := json.Marshal(map[string]any{
		"attempt_number": 1,
		"task_id":        testTaskID,
	})
	mock.ExpectExec(`(?s)INSERT INTO jobs`).
		WithArgs(
			testJobID, testTaskID, int64(17), payload, now,
			"request-123", now, now,
		).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectQuery(`(?s)FROM tasks t.*WHERE t\.id = \?`).
		WithArgs(testTaskID).
		WillReturnRows(taskRow(now, expires, nil, 0))
	mock.ExpectCommit()

	result, created, err := repository.Create(context.Background(), record)
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	if !created || result.ID != testTaskID || result.CreatorID != testCreatorPublicID ||
		result.InputType != UnknownInput ||
		result.Progress != 0 || result.Tags == nil {
		t.Fatalf("Create() = (%+v, %v)", result, created)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet SQL expectations: %v", err)
	}
}

func TestMySQLRepositoryCreateReturnsExistingWithoutSecondBlobReference(t *testing.T) {
	database, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New() error = %v", err)
	}
	defer database.Close()
	repository := NewMySQLRepository(database)
	now := time.Date(2026, 7, 29, 1, 2, 3, 0, time.UTC)
	expires := now.Add(DefaultSampleRetention)

	mock.ExpectBegin()
	mock.ExpectQuery(`(?s)SELECT id, upload_id, name.*idempotency_key = \?.*FOR UPDATE`).
		WithArgs(uint64(42), "retry").
		WillReturnError(sql.ErrNoRows)
	mock.ExpectQuery(`(?s)SELECT upload\.created_by.*FOR UPDATE`).
		WithArgs(testUploadID).
		WillReturnRows(sqlmock.NewRows(
			[]string{"created_by", "status", "blob_id", "state"},
		).AddRow(uint64(42), "completed", int64(9), "deleting"))
	mock.ExpectQuery(`(?s)FROM tasks t.*WHERE t\.upload_id = \?`).
		WithArgs(testUploadID).
		WillReturnRows(taskRow(now, expires, "oci", 10_000))
	mock.ExpectRollback()

	result, created, err := repository.Create(context.Background(), CreateRecord{
		TaskID: testTaskID, JobID: testJobID, UserID: 42,
		UploadID: testUploadID, Name: "ignored", IdempotencyKey: "retry",
		LimitsSnapshot: []byte(`{}`), SampleExpiresAt: expires, CreatedAt: now,
	})
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	if created || result.InputType != "oci" || result.Progress != 100 {
		t.Fatalf("Create() replay = (%+v, %v)", result, created)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet SQL expectations: %v", err)
	}
}

func TestMySQLRepositoryCreateChecksOwnershipAndCompletion(t *testing.T) {
	tests := []struct {
		name          string
		administrator bool
		owner         uint64
		status        string
		blobID        any
		blobState     any
		want          error
	}{
		{
			name: "other owner", owner: 7, status: "completed",
			blobID: int64(9), blobState: "available", want: ErrForbidden,
		},
		{
			name: "not complete", owner: 42, status: "uploading",
			blobID: nil, blobState: nil, want: ErrUploadNotCompleted,
		},
		{
			name: "missing blob", owner: 42, status: "completed",
			blobID: nil, blobState: nil, want: ErrConflict,
		},
		{
			name:          "administrator can use other owner but unavailable blob",
			administrator: true, owner: 7, status: "completed",
			blobID: int64(9), blobState: "deleting", want: ErrConflict,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			database, mock, err := sqlmock.New()
			if err != nil {
				t.Fatalf("sqlmock.New() error = %v", err)
			}
			defer database.Close()
			repository := NewMySQLRepository(database)
			mock.ExpectBegin()
			mock.ExpectQuery(`(?s)SELECT id, upload_id, name.*idempotency_key = \?.*FOR UPDATE`).
				WithArgs(uint64(42), "").
				WillReturnError(sql.ErrNoRows)
			mock.ExpectQuery(`(?s)SELECT upload\.created_by.*FOR UPDATE`).
				WithArgs(testUploadID).
				WillReturnRows(sqlmock.NewRows(
					[]string{"created_by", "status", "blob_id", "state"},
				).AddRow(test.owner, test.status, test.blobID, test.blobState))
			if test.status == "completed" &&
				(test.administrator || test.owner == uint64(42)) {
				mock.ExpectQuery(`(?s)FROM tasks t.*WHERE t\.upload_id = \?`).
					WithArgs(testUploadID).
					WillReturnError(sql.ErrNoRows)
			}
			mock.ExpectRollback()
			_, _, err = repository.Create(context.Background(), CreateRecord{
				UserID: 42, Administrator: test.administrator, UploadID: testUploadID,
			})
			if !errors.Is(err, test.want) {
				t.Fatalf("Create() error = %v, want %v", err, test.want)
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Fatalf("unmet SQL expectations: %v", err)
			}
		})
	}
}

func TestMySQLRepositoryCreateReplaysMatchingIdempotencyKey(t *testing.T) {
	database, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New() error = %v", err)
	}
	defer database.Close()
	repository := NewMySQLRepository(database)
	now := time.Date(2026, 7, 29, 1, 2, 3, 0, time.UTC)
	expires := now.Add(DefaultSampleRetention)

	mock.ExpectBegin()
	mock.ExpectQuery(`(?s)SELECT id, upload_id, name.*idempotency_key = \?.*FOR UPDATE`).
		WithArgs(uint64(42), "request-123").
		WillReturnRows(sqlmock.NewRows(
			[]string{"id", "upload_id", "name"},
		).AddRow(testTaskID, testUploadID, "firmware.img"))
	mock.ExpectQuery(`(?s)FROM tasks t.*WHERE t\.id = \?`).
		WithArgs(testTaskID).
		WillReturnRows(taskRow(now, expires, nil, 0))
	mock.ExpectRollback()

	result, created, err := repository.Create(context.Background(), CreateRecord{
		UserID: 42, UploadID: testUploadID, Name: "firmware.img",
		IdempotencyKey: "request-123",
	})
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	if created || result.ID != testTaskID {
		t.Fatalf("Create() replay = (%+v, %v)", result, created)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet SQL expectations: %v", err)
	}
}

func TestMySQLRepositoryCreateRetriesDeadlockThenReplays(t *testing.T) {
	database, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New() error = %v", err)
	}
	defer database.Close()
	repository := NewMySQLRepository(database)
	now := time.Date(2026, 7, 29, 1, 2, 3, 0, time.UTC)
	expires := now.Add(DefaultSampleRetention)

	mock.ExpectBegin()
	mock.ExpectQuery(`(?s)SELECT id, upload_id, name.*idempotency_key = \?.*FOR UPDATE`).
		WithArgs(uint64(42), "request-123").
		WillReturnError(sql.ErrNoRows)
	mock.ExpectQuery(`(?s)SELECT upload\.created_by.*FOR UPDATE`).
		WithArgs(testUploadID).
		WillReturnError(&mysql.MySQLError{Number: 1213, Message: "deadlock"})
	mock.ExpectRollback()

	mock.ExpectBegin()
	mock.ExpectQuery(`(?s)SELECT id, upload_id, name.*idempotency_key = \?.*FOR UPDATE`).
		WithArgs(uint64(42), "request-123").
		WillReturnRows(sqlmock.NewRows(
			[]string{"id", "upload_id", "name"},
		).AddRow(testTaskID, testUploadID, "firmware.img"))
	mock.ExpectQuery(`(?s)FROM tasks t.*WHERE t\.id = \?`).
		WithArgs(testTaskID).
		WillReturnRows(taskRow(now, expires, nil, 0))
	mock.ExpectRollback()

	result, created, err := repository.Create(context.Background(), CreateRecord{
		UserID: 42, UploadID: testUploadID, Name: "firmware.img",
		IdempotencyKey: "request-123",
	})
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	if created || result.ID != testTaskID {
		t.Fatalf("Create() after deadlock = (%+v, %v)", result, created)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet SQL expectations: %v", err)
	}
}

func TestMySQLRepositoryCreateBoundsLockTimeoutRetries(t *testing.T) {
	database, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New() error = %v", err)
	}
	defer database.Close()
	repository := NewMySQLRepository(database)

	for attempt := 0; attempt < maxCreateTransactionAttempts; attempt++ {
		mock.ExpectBegin()
		mock.ExpectQuery(`(?s)SELECT id, upload_id, name.*idempotency_key = \?.*FOR UPDATE`).
			WithArgs(uint64(42), "request-123").
			WillReturnError(&mysql.MySQLError{Number: 1205, Message: "lock wait timeout"})
		mock.ExpectRollback()
	}
	_, _, err = repository.Create(context.Background(), CreateRecord{
		UserID: 42, UploadID: testUploadID, Name: "firmware.img",
		IdempotencyKey: "request-123",
	})
	var mysqlError *mysql.MySQLError
	if !errors.As(err, &mysqlError) || mysqlError.Number != 1205 {
		t.Fatalf("Create() error = %v, want MySQL 1205", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet SQL expectations: %v", err)
	}
}

func TestWaitForCreateRetryHonorsContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := waitForCreateRetry(ctx, 0); !errors.Is(err, context.Canceled) {
		t.Fatalf("waitForCreateRetry() error = %v, want context.Canceled", err)
	}
}

func TestMySQLRepositoryCreateResolvesDuplicateInNewTransaction(t *testing.T) {
	database, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New() error = %v", err)
	}
	defer database.Close()
	repository := NewMySQLRepository(database)
	now := time.Date(2026, 7, 29, 1, 2, 3, 0, time.UTC)
	expires := now.Add(DefaultSampleRetention)
	limits := []byte(`{"max_depth":10}`)

	mock.ExpectBegin()
	mock.ExpectQuery(`(?s)SELECT id, upload_id, name.*idempotency_key = \?.*FOR UPDATE`).
		WithArgs(uint64(42), "request-123").
		WillReturnError(sql.ErrNoRows)
	mock.ExpectQuery(`(?s)SELECT upload\.created_by.*FOR UPDATE`).
		WithArgs(testUploadID).
		WillReturnRows(sqlmock.NewRows(
			[]string{"created_by", "status", "blob_id", "state"},
		).AddRow(uint64(42), "completed", int64(9), "available"))
	mock.ExpectQuery(`(?s)FROM tasks t.*WHERE t\.upload_id = \?`).
		WithArgs(testUploadID).
		WillReturnError(sql.ErrNoRows)
	mock.ExpectExec(`(?s)UPDATE blobs.*reference_count = reference_count \+ 1`).
		WithArgs(int64(9)).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`(?s)INSERT INTO tasks`).
		WithArgs(
			testTaskID, testUploadID, "request-123", int64(9), uint64(42), "firmware.img",
			limits, expires, now, now,
		).
		WillReturnError(&mysql.MySQLError{Number: 1062, Message: "duplicate"})
	mock.ExpectRollback()

	mock.ExpectBegin()
	mock.ExpectQuery(`(?s)SELECT id, upload_id, name.*idempotency_key = \?.*LIMIT 1`).
		WithArgs(uint64(42), "request-123").
		WillReturnRows(sqlmock.NewRows(
			[]string{"id", "upload_id", "name"},
		).AddRow(testTaskID, testUploadID, "firmware.img"))
	mock.ExpectQuery(`(?s)FROM tasks t.*WHERE t\.id = \?`).
		WithArgs(testTaskID).
		WillReturnRows(taskRow(now, expires, nil, 0))
	mock.ExpectCommit()

	result, created, err := repository.Create(context.Background(), CreateRecord{
		TaskID: testTaskID, JobID: testJobID, UserID: 42,
		UploadID: testUploadID, Name: "firmware.img",
		IdempotencyKey: "request-123", LimitsSnapshot: limits,
		SampleExpiresAt: expires, CreatedAt: now,
	})
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	if created || result.ID != testTaskID {
		t.Fatalf("Create() duplicate resolution = (%+v, %v)", result, created)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet SQL expectations: %v", err)
	}
}

func TestMySQLRepositoryCreateDuplicatePayloadConflict(t *testing.T) {
	database, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New() error = %v", err)
	}
	defer database.Close()
	repository := NewMySQLRepository(database)

	mock.ExpectBegin()
	mock.ExpectQuery(`(?s)SELECT id, upload_id, name.*idempotency_key = \?.*FOR UPDATE`).
		WillReturnError(&mysql.MySQLError{Number: 1062, Message: "duplicate"})
	mock.ExpectRollback()
	mock.ExpectBegin()
	mock.ExpectQuery(`(?s)SELECT id, upload_id, name.*idempotency_key = \?.*LIMIT 1`).
		WithArgs(uint64(42), "request-123").
		WillReturnRows(sqlmock.NewRows(
			[]string{"id", "upload_id", "name"},
		).AddRow(testTaskID, "40000000-0000-4000-8000-000000000004", "other"))
	mock.ExpectCommit()

	_, _, err = repository.Create(context.Background(), CreateRecord{
		UserID: 42, UploadID: testUploadID, Name: "firmware.img",
		IdempotencyKey: "request-123",
	})
	if !errors.Is(err, ErrConflict) {
		t.Fatalf("Create() error = %v, want ErrConflict", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet SQL expectations: %v", err)
	}
}

func TestMySQLRepositoryCreateDuplicateFallsBackToUpload(t *testing.T) {
	database, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New() error = %v", err)
	}
	defer database.Close()
	repository := NewMySQLRepository(database)
	now := time.Date(2026, 7, 29, 1, 2, 3, 0, time.UTC)
	expires := now.Add(DefaultSampleRetention)

	mock.ExpectBegin()
	mock.ExpectQuery(`(?s)SELECT id, upload_id, name.*idempotency_key = \?.*FOR UPDATE`).
		WillReturnError(&mysql.MySQLError{Number: 1062, Message: "duplicate"})
	mock.ExpectRollback()
	mock.ExpectBegin()
	mock.ExpectQuery(`(?s)SELECT id, upload_id, name.*idempotency_key = \?.*LIMIT 1`).
		WithArgs(uint64(42), "new-key").
		WillReturnError(sql.ErrNoRows)
	mock.ExpectQuery(`(?s)FROM tasks t.*WHERE t\.upload_id = \?`).
		WithArgs(testUploadID).
		WillReturnRows(taskRow(now, expires, nil, 0))
	mock.ExpectCommit()

	result, created, err := repository.Create(context.Background(), CreateRecord{
		UserID: 42, UploadID: testUploadID, Name: "firmware.img",
		IdempotencyKey: "new-key",
	})
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	if created || result.ID != testTaskID {
		t.Fatalf("Create() upload duplicate = (%+v, %v)", result, created)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet SQL expectations: %v", err)
	}
}

func TestMySQLRepositoryListFiltersEscapesAndOrders(t *testing.T) {
	database, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New() error = %v", err)
	}
	defer database.Close()
	repository := NewMySQLRepository(database)
	cursorCreatedAt := time.Date(2026, 7, 30, 1, 2, 3, 0, time.UTC)
	query := ListQuery{
		PageSize: 1, Keyword: "100%_ready!",
		Status: "QUEUED", InputType: "unknown",
		Creator: "analyst%_!", Tag: "release candidate",
		CreatedFrom: "2026-07-01", CreatedTo: "2026-07-29",
		After: &ListCursor{CreatedAt: cursorCreatedAt, ID: testTaskID},
	}
	pattern := "%100!%!_ready!!%"
	creatorPattern := "%analyst!%!_!!%"
	createdFrom := time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)
	createdToExclusive := time.Date(2026, 7, 30, 0, 0, 0, 0, time.UTC)
	filterPattern := `WHERE \(t\.name LIKE \? ESCAPE '!' OR upload\.display_name LIKE \? ESCAPE '!'\).*` +
		`t\.status = \?.*LOWER.*` +
		`\(creator\.display_name LIKE \? ESCAPE '!' OR creator\.username LIKE \? ESCAPE '!'\).*` +
		`JSON_CONTAINS.*t\.created_at >= \?.*t\.created_at < \?`
	now := time.Date(2026, 7, 29, 1, 2, 3, 0, time.UTC)
	deletedAt := now.Add(DefaultSampleRetention + time.Minute)
	mock.ExpectQuery(`(?s)SELECT t\.id.*FROM tasks t.*`+
		filterPattern+`.*t\.created_at < \?.*t\.created_at = \?.*t\.id < \?.*`+
		`ORDER BY t\.created_at DESC, t\.id DESC.*LIMIT \?`).
		WithArgs(
			pattern, pattern, "QUEUED", "unknown",
			creatorPattern, creatorPattern, "release candidate",
			createdFrom, createdToExclusive,
			cursorCreatedAt, cursorCreatedAt, testTaskID, 2,
		).
		WillReturnRows(taskRowStatusWithDeleted(
			now,
			now.Add(DefaultSampleRetention),
			nil,
			1250,
			StatusQueued,
			deletedAt,
		).AddRow(
			testTaskID, "older.img", nil, StatusQueued, "UNKNOWN",
			uint16(0), testCreatorPublicID, "Operator", []byte(`[]`), now.Add(-time.Second),
			now, "older.img", uint64(2048),
			"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
			nil, nil, nil, now.Add(DefaultSampleRetention), nil,
		))

	page, err := repository.List(context.Background(), query)
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}
	if len(page.Items) != 1 || !page.HasMore ||
		page.Items[0].Progress != 12.5 || page.Items[0].InputType != UnknownInput ||
		page.Items[0].SampleDeletedAt == nil ||
		!page.Items[0].SampleDeletedAt.Equal(deletedAt) {
		t.Fatalf("List() page = %+v", page)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet SQL expectations: %v", err)
	}
}

func TestMySQLRepositoryListRejectsInvalidDateBeforeQuery(t *testing.T) {
	database, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New() error = %v", err)
	}
	defer database.Close()
	repository := NewMySQLRepository(database)

	_, err = repository.List(context.Background(), ListQuery{
		PageSize: 20, CreatedFrom: "2026-02-30",
	})
	if !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("List() error = %v, want ErrInvalidInput", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unexpected SQL for invalid date: %v", err)
	}
}

func TestMySQLRepositoryGetMapsMissingTask(t *testing.T) {
	database, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New() error = %v", err)
	}
	defer database.Close()
	repository := NewMySQLRepository(database)
	mock.ExpectQuery(`(?s)FROM tasks t.*WHERE t\.id = \?`).
		WithArgs(testTaskID).
		WillReturnError(sql.ErrNoRows)
	if _, err := repository.Get(context.Background(), testTaskID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Get() error = %v, want ErrNotFound", err)
	}
}

func TestMySQLRepositoryGetReturnsActualSampleDeletionTime(t *testing.T) {
	database, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	repository := NewMySQLRepository(database)
	now := time.Date(2026, 7, 29, 1, 2, 3, 0, time.UTC)
	deletedAt := now.Add(DefaultSampleRetention + time.Minute)
	mock.ExpectQuery(`(?s)FROM tasks t.*WHERE t\.id = \?`).
		WithArgs(testTaskID).
		WillReturnRows(taskRowStatusWithDeleted(
			now,
			now.Add(DefaultSampleRetention),
			"pe",
			10_000,
			"SUCCEEDED",
			deletedAt,
		))

	value, err := repository.Get(context.Background(), testTaskID)
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if value.SampleDeletedAt == nil || !value.SampleDeletedAt.Equal(deletedAt) {
		t.Fatalf("Get() sample_deleted_at = %v, want %v", value.SampleDeletedAt, deletedAt)
	}
}

func TestMySQLRepositoryCancelQueuedTaskAtomically(t *testing.T) {
	database, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	repository := NewMySQLRepository(database)
	now := time.Date(2026, 7, 29, 1, 2, 3, 0, time.UTC)
	expires := now.Add(DefaultSampleRetention)
	terminalExpiry := expires.Add(time.Minute)

	mock.ExpectBegin()
	expectTaskStateLock(mock, testTaskID, 42, StatusQueued, expires, nil, now)
	expectTaskActionReplay(mock, testTaskID, "cancel", "cancel-key", false)
	mock.ExpectExec(`(?s)UPDATE task_attempts attempt.*job\.status IN \('queued', 'leased'\)`).
		WithArgs(testTaskID).
		WillReturnResult(sqlmock.NewResult(0, 1))
	expectInactiveResourceSlotRelease(mock, testTaskID, 1)
	mock.ExpectExec(`(?s)UPDATE jobs.*status = 'cancelled'.*status IN \('queued', 'leased'\)`).
		WithArgs(testTaskID).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`(?s)UPDATE jobs.*status = 'cancel_requested'.*status = 'running'`).
		WithArgs(testTaskID).
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec(`(?s)UPDATE tasks.*SET status = \?.*completed_at.*`+
		`sample_expires_at = CASE.*WHEN \? = 'CANCELLED'.*`+
		`sample_deleted_at IS NULL.*deleted_at IS NULL.*GREATEST.*`+
		`INTERVAL \? MICROSECOND.*WHERE id = \? AND status = \?`).
		WithArgs(
			StatusCancelled, StatusCancelled, StatusCancelled, StatusCancelled,
			DefaultSampleRetention.Microseconds(), testTaskID, StatusQueued,
		).
		WillReturnResult(sqlmock.NewResult(0, 1))
	expectTaskEvent(
		mock, testTaskID, "task.status_changed",
		"Task cancellation state changed.",
	)
	expectTaskActionInsert(mock, testTaskID, "cancel", "cancel-key")
	mock.ExpectQuery(`(?s)FROM tasks t.*WHERE t\.id = \?`).
		WithArgs(testTaskID).
		WillReturnRows(taskRowStatus(now, terminalExpiry, nil, 0, StatusCancelled))
	mock.ExpectCommit()

	value, err := repository.Cancel(context.Background(), MutationRecord{
		TaskID: testTaskID, UserID: 42, IdempotencyKey: "cancel-key",
		SampleRetention: DefaultSampleRetention,
	})
	if err != nil || value.Status != StatusCancelled {
		t.Fatalf("Cancel() = (%+v, %v)", value, err)
	}
	if !value.SampleExpiresAt.Equal(terminalExpiry) {
		t.Fatalf(
			"Cancel() sample expiry = %s, want %s",
			value.SampleExpiresAt, terminalExpiry,
		)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestMySQLRepositoryCancelRunningTaskRequestsCooperativeStop(t *testing.T) {
	database, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	repository := NewMySQLRepository(database)
	now := time.Date(2026, 7, 29, 1, 2, 3, 0, time.UTC)
	expires := now.Add(DefaultSampleRetention)

	mock.ExpectBegin()
	expectTaskStateLock(mock, testTaskID, 42, "SCANNING", expires, nil, now)
	expectTaskActionReplay(mock, testTaskID, "cancel", "cancel-key", false)
	mock.ExpectExec(`(?s)UPDATE task_attempts attempt`).
		WithArgs(testTaskID).
		WillReturnResult(sqlmock.NewResult(0, 0))
	expectInactiveResourceSlotRelease(mock, testTaskID, 0)
	mock.ExpectExec(`(?s)UPDATE jobs.*status = 'cancelled'`).
		WithArgs(testTaskID).
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec(`(?s)UPDATE jobs.*status = 'cancel_requested'`).
		WithArgs(testTaskID).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`(?s)UPDATE tasks.*SET status = \?`).
		WithArgs(
			StatusCancelRequested, StatusCancelRequested, StatusCancelRequested,
			StatusCancelRequested, DefaultSampleRetention.Microseconds(),
			testTaskID, "SCANNING",
		).
		WillReturnResult(sqlmock.NewResult(0, 1))
	expectTaskEvent(
		mock, testTaskID, "task.status_changed",
		"Task cancellation state changed.",
	)
	expectTaskActionInsert(mock, testTaskID, "cancel", "cancel-key")
	mock.ExpectQuery(`(?s)FROM tasks t.*WHERE t\.id = \?`).
		WithArgs(testTaskID).
		WillReturnRows(taskRowStatus(now, expires, nil, 5000, StatusCancelRequested))
	mock.ExpectCommit()

	value, err := repository.Cancel(context.Background(), MutationRecord{
		TaskID: testTaskID, UserID: 42, IdempotencyKey: "cancel-key",
		SampleRetention: DefaultSampleRetention,
	})
	if err != nil || value.Status != StatusCancelRequested {
		t.Fatalf("Cancel() = (%+v, %v)", value, err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestCancelActiveJobsHandlesTrivyHandoffStates(t *testing.T) {
	tests := []struct {
		name            string
		attemptRows     int64
		inactiveJobRows int64
		runningJobRows  int64
		wantRunning     bool
	}{
		{
			name: "queued Trivy handoff", attemptRows: 1,
			inactiveJobRows: 1,
		},
		{
			name: "leased Trivy handoff", attemptRows: 1,
			inactiveJobRows: 1,
		},
		{
			name: "running Trivy handoff", runningJobRows: 1,
			wantRunning: true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			database, mock, err := sqlmock.New()
			if err != nil {
				t.Fatal(err)
			}
			defer database.Close()
			mock.ExpectBegin()
			mock.ExpectExec(`(?s)UPDATE task_attempts attempt.*LEFT JOIN jobs active.*active\.status IN \('running', 'cancel_requested'\).*job\.kind IN \('scan', 'trivy'\).*job\.status IN \('queued', 'leased'\).*attempt\.fencing_token = job\.fencing_token.*active\.id IS NULL`).
				WithArgs(testTaskID).
				WillReturnResult(sqlmock.NewResult(0, test.attemptRows))
			expectInactiveResourceSlotRelease(mock, testTaskID, test.inactiveJobRows)
			mock.ExpectExec(`(?s)UPDATE jobs.*status = 'cancelled'.*status IN \('queued', 'leased'\)`).
				WithArgs(testTaskID).
				WillReturnResult(sqlmock.NewResult(0, test.inactiveJobRows))
			mock.ExpectExec(`(?s)UPDATE jobs.*status = 'cancel_requested'.*status = 'running'`).
				WithArgs(testTaskID).
				WillReturnResult(sqlmock.NewResult(0, test.runningJobRows))
			mock.ExpectCommit()

			transaction, err := database.BeginTx(context.Background(), nil)
			if err != nil {
				t.Fatal(err)
			}
			running, err := cancelActiveJobs(
				context.Background(), transaction, testTaskID,
			)
			if err != nil {
				_ = transaction.Rollback()
				t.Fatal(err)
			}
			if running != test.wantRunning {
				_ = transaction.Rollback()
				t.Fatalf("cancelActiveJobs() running = %v", running)
			}
			if err := transaction.Commit(); err != nil {
				t.Fatal(err)
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestMySQLRepositoryCancelRequestedReplayDoesNotRetouchJobs(t *testing.T) {
	database, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	repository := NewMySQLRepository(database)
	now := time.Date(2026, 7, 29, 1, 2, 3, 0, time.UTC)
	expires := now.Add(DefaultSampleRetention)

	mock.ExpectBegin()
	expectTaskStateLock(
		mock, testTaskID, 42, StatusCancelRequested, expires, nil, now,
	)
	expectTaskActionReplay(mock, testTaskID, "cancel", "cancel-replay", false)
	expectTaskActionInsert(mock, testTaskID, "cancel", "cancel-replay")
	mock.ExpectQuery(`(?s)FROM tasks t.*WHERE t\.id = \?`).
		WithArgs(testTaskID).
		WillReturnRows(taskRowStatus(
			now, expires, nil, 8000, StatusCancelRequested,
		))
	mock.ExpectCommit()

	value, err := repository.Cancel(context.Background(), MutationRecord{
		TaskID: testTaskID, UserID: 42, IdempotencyKey: "cancel-replay",
		SampleRetention: DefaultSampleRetention,
	})
	if err != nil || value.Status != StatusCancelRequested {
		t.Fatalf("Cancel() replay = (%+v, %v)", value, err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestMySQLRepositoryCancelReplayDoesNotCancelNewAttempt(t *testing.T) {
	database, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	repository := NewMySQLRepository(database)
	now := time.Date(2026, 7, 29, 1, 2, 3, 0, time.UTC)
	expires := now.Add(DefaultSampleRetention)

	mock.ExpectBegin()
	expectTaskStateLock(mock, testTaskID, 42, StatusQueued, expires, nil, now)
	expectTaskActionReplay(mock, testTaskID, "cancel", "cancel-key", true)
	mock.ExpectQuery(`(?s)FROM tasks t.*WHERE t\.id = \?`).
		WithArgs(testTaskID).
		WillReturnRows(taskRowStatus(now, expires, nil, 0, StatusQueued))
	mock.ExpectRollback()

	value, err := repository.Cancel(context.Background(), MutationRecord{
		TaskID: testTaskID, UserID: 42, IdempotencyKey: "cancel-key",
		SampleRetention: DefaultSampleRetention,
	})
	if err != nil || value.Status != StatusQueued {
		t.Fatalf("Cancel() replay after retry = (%+v, %v)", value, err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestMySQLRepositoryRetryCreatesFreshAttemptAndFencedJob(t *testing.T) {
	database, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	repository := NewMySQLRepository(database)
	now := time.Date(2026, 7, 29, 1, 2, 3, 0, time.UTC)
	expires := now.Add(DefaultSampleRetention)
	key := lifecycleIdempotencyKey("retry", "request-key")

	mock.ExpectBegin()
	expectTaskStateLock(mock, testTaskID, 42, "FAILED", expires, nil, now)
	expectTaskActionReplay(mock, testTaskID, "retry", key, false)
	mock.ExpectQuery(`(?s)SELECT COALESCE\(MAX\(attempt_number\).*MAX\(fencing_token\).*FROM task_attempts`).
		WithArgs(testTaskID).
		WillReturnRows(sqlmock.NewRows(
			[]string{"attempt_number", "fencing_token"},
		).AddRow(uint64(1), uint64(4)))
	mock.ExpectExec(`(?s)INSERT INTO task_attempts.*UTC_TIMESTAMP`).
		WithArgs(testTaskID, uint64(2), uint64(5)).
		WillReturnResult(sqlmock.NewResult(20, 1))
	payload, _ := json.Marshal(map[string]any{
		"attempt_number": uint64(2),
		"task_id":        testTaskID,
	})
	mock.ExpectExec(`(?s)INSERT INTO jobs.*'scan'.*'queued'.*UTC_TIMESTAMP`).
		WithArgs(testJobID, testTaskID, int64(20), payload, uint64(5)).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`(?s)UPDATE tasks.*status = 'QUEUED'.*completed_at = NULL`).
		WithArgs(testTaskID, "FAILED").
		WillReturnResult(sqlmock.NewResult(0, 1))
	expectTaskEvent(
		mock, testTaskID, "task.status_changed", "Task queued for retry.",
	)
	expectTaskActionInsert(mock, testTaskID, "retry", key)
	mock.ExpectQuery(`(?s)FROM tasks t.*WHERE t\.id = \?`).
		WithArgs(testTaskID).
		WillReturnRows(taskRowStatus(now, expires, nil, 0, StatusQueued))
	mock.ExpectCommit()

	value, err := repository.Retry(context.Background(), RetryRecord{
		MutationRecord: MutationRecord{TaskID: testTaskID, IdempotencyKey: key},
		JobID:          testJobID,
	})
	if err != nil || value.Status != StatusQueued {
		t.Fatalf("Retry() = (%+v, %v)", value, err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestMySQLRepositoryRetryReplaysBeforeStateValidation(t *testing.T) {
	database, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	repository := NewMySQLRepository(database)
	now := time.Date(2026, 7, 29, 1, 2, 3, 0, time.UTC)
	expires := now.Add(DefaultSampleRetention)
	key := lifecycleIdempotencyKey("retry", "request-key")

	mock.ExpectBegin()
	expectTaskStateLock(mock, testTaskID, 42, "SCANNING", expires, nil, now)
	expectTaskActionReplay(mock, testTaskID, "retry", key, true)
	mock.ExpectQuery(`(?s)FROM tasks t.*WHERE t\.id = \?`).
		WithArgs(testTaskID).
		WillReturnRows(taskRowStatus(now, expires, nil, 7000, "SCANNING"))
	mock.ExpectRollback()

	value, err := repository.Retry(context.Background(), RetryRecord{
		MutationRecord: MutationRecord{TaskID: testTaskID, IdempotencyKey: key},
		JobID:          testJobID,
	})
	if err != nil || value.Status != "SCANNING" ||
		!value.ProgressIndeterminate || value.Progress != 70 {
		t.Fatalf("Retry() replay = (%+v, %v)", value, err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestMySQLRepositoryRetryRejectsExpiredSample(t *testing.T) {
	database, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	repository := NewMySQLRepository(database)
	now := time.Date(2026, 7, 29, 1, 2, 3, 0, time.UTC)
	key := lifecycleIdempotencyKey("retry", "request-key")

	mock.ExpectBegin()
	expectTaskStateLock(mock, testTaskID, 42, "FAILED", now, nil, now)
	expectTaskActionReplay(mock, testTaskID, "retry", key, false)
	mock.ExpectRollback()

	_, err = repository.Retry(context.Background(), RetryRecord{
		MutationRecord: MutationRecord{TaskID: testTaskID, IdempotencyKey: key},
		JobID:          testJobID,
	})
	if !errors.Is(err, ErrSampleUnavailable) {
		t.Fatalf("Retry() error = %v, want ErrSampleUnavailable", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestMySQLRepositoryDeleteRequiresAdministratorOrOperatorOwner(t *testing.T) {
	database, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	repository := NewMySQLRepository(database)
	now := time.Date(2026, 7, 29, 1, 2, 3, 0, time.UTC)
	expires := now.Add(DefaultSampleRetention)

	mock.ExpectBegin()
	expectTaskStateLock(mock, testTaskID, 7, "SUCCEEDED", expires, nil, now)
	mock.ExpectRollback()
	_, err = repository.Delete(context.Background(), MutationRecord{
		TaskID: testTaskID, UserID: 42,
	})
	if !errors.Is(err, ErrForbidden) {
		t.Fatalf("Delete() error = %v, want ErrForbidden", err)
	}

	mock.ExpectBegin()
	expectTaskStateLock(mock, testTaskID, 7, "SUCCEEDED", expires, nil, now)
	mock.ExpectQuery(`(?s)SELECT EXISTS.*task_sample_retention_operations`).
		WithArgs(testTaskID).
		WillReturnRows(sqlmock.NewRows([]string{"active"}).AddRow(0))
	mock.ExpectExec(`(?s)UPDATE task_attempts attempt`).
		WithArgs(testTaskID).
		WillReturnResult(sqlmock.NewResult(0, 0))
	expectInactiveResourceSlotRelease(mock, testTaskID, 0)
	mock.ExpectExec(`(?s)UPDATE jobs.*status = 'cancelled'`).
		WithArgs(testTaskID).
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec(`(?s)UPDATE jobs.*status = 'cancel_requested'`).
		WithArgs(testTaskID).
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec(`(?s)UPDATE reports.*status = 'failed'.*status = 'queued'`).
		WithArgs(testTaskID).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`(?s)UPDATE tasks.*status = 'DELETING'.*WHERE id = \? AND status = \?`).
		WithArgs(testTaskID, "SUCCEEDED").
		WillReturnResult(sqlmock.NewResult(0, 1))
	expectTaskEvent(
		mock, testTaskID, "task.status_changed", "Task entered deletion.",
	)
	mock.ExpectQuery(`(?s)FROM tasks t.*WHERE t\.id = \?`).
		WithArgs(testTaskID).
		WillReturnRows(taskRowStatus(now, expires, nil, 10000, StatusDeleting))
	mock.ExpectCommit()
	value, err := repository.Delete(context.Background(), MutationRecord{
		TaskID: testTaskID, UserID: 42, Administrator: true,
	})
	if err != nil || value.Status != StatusDeleting {
		t.Fatalf("administrator Delete() = (%+v, %v)", value, err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestMySQLRepositoryDeleteConflictsWithActiveSampleRetention(t *testing.T) {
	database, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	repository := NewMySQLRepository(database)
	now := time.Date(2026, 7, 31, 1, 2, 3, 0, time.UTC)
	expires := now.Add(DefaultSampleRetention)

	mock.ExpectBegin()
	expectTaskStateLock(mock, testTaskID, 7, "SUCCEEDED", expires, nil, now)
	mock.ExpectQuery(`(?s)SELECT EXISTS.*task_sample_retention_operations`).
		WithArgs(testTaskID).
		WillReturnRows(sqlmock.NewRows([]string{"active"}).AddRow(1))
	mock.ExpectRollback()

	_, err = repository.Delete(context.Background(), MutationRecord{
		TaskID: testTaskID, UserID: 7,
	})
	if !errors.Is(err, ErrConflict) {
		t.Fatalf("Delete() error = %v, want ErrConflict", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestCancelQueuedReportsPreservesGeneratingReportBarrier(t *testing.T) {
	database, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()

	mock.ExpectBegin()
	transaction, err := database.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	mock.ExpectExec(
		`(?s)UPDATE reports.*WHERE task_id = \?\s+AND status = 'queued'\s*$`,
	).WithArgs(testTaskID).WillReturnResult(sqlmock.NewResult(0, 1))
	if err := cancelQueuedReports(
		context.Background(),
		transaction,
		testTaskID,
	); err != nil {
		t.Fatal(err)
	}
	mock.ExpectCommit()
	if err := transaction.Commit(); err != nil {
		t.Fatal(err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestMySQLRepositoryExtendRetentionUsesLockedCAS(t *testing.T) {
	database, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	repository := NewMySQLRepository(database)
	now := time.Date(2026, 7, 29, 1, 2, 3, 123456000, time.UTC)
	expected := now.Add(24 * time.Hour)
	requested := expected.Add(DefaultSampleRetention)
	record := RetentionRecord{
		TaskID:                  testTaskID,
		ExpectedSampleExpiresAt: expected,
		SampleExpiresAt:         requested,
	}

	mock.ExpectBegin()
	expectTaskStateLock(mock, testTaskID, 42, "SUCCEEDED", expected, nil, now)
	mock.ExpectExec(
		`(?s)UPDATE tasks.*sample_expires_at = \?.*updated_at = UTC_TIMESTAMP\(6\).*`+
			`WHERE id = \?.*sample_expires_at = \?.*sample_deleted_at IS NULL.*deleted_at IS NULL.*`+
			`sample_expires_at > UTC_TIMESTAMP\(6\).*status NOT IN`,
	).
		WithArgs(requested, testTaskID, expected).
		WillReturnResult(sqlmock.NewResult(0, 1))
	expectTaskEvent(
		mock, testTaskID, "task.retention_changed",
		"Task sample retention changed.",
	)
	mock.ExpectQuery(`(?s)FROM tasks t.*WHERE t\.id = \?`).
		WithArgs(testTaskID).
		WillReturnRows(taskRowStatus(now, requested, nil, 10000, "SUCCEEDED"))
	mock.ExpectCommit()

	value, err := repository.ExtendRetention(context.Background(), record)
	if err != nil || !value.SampleExpiresAt.Equal(requested) {
		t.Fatalf("ExtendRetention() = (%+v, %v)", value, err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestMySQLRepositoryExtendRetentionReplaysRequestedExpiry(t *testing.T) {
	database, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	repository := NewMySQLRepository(database)
	now := time.Date(2026, 7, 29, 1, 2, 3, 0, time.UTC)
	expected := now.Add(24 * time.Hour)
	requested := expected.Add(DefaultSampleRetention)

	mock.ExpectBegin()
	expectTaskStateLock(mock, testTaskID, 42, "SUCCEEDED", requested, nil, now)
	mock.ExpectQuery(`(?s)FROM tasks t.*WHERE t\.id = \?`).
		WithArgs(testTaskID).
		WillReturnRows(taskRowStatus(now, requested, nil, 10000, "SUCCEEDED"))
	mock.ExpectCommit()

	value, err := repository.ExtendRetention(context.Background(), RetentionRecord{
		TaskID: testTaskID, ExpectedSampleExpiresAt: expected, SampleExpiresAt: requested,
	})
	if err != nil || !value.SampleExpiresAt.Equal(requested) {
		t.Fatalf("ExtendRetention() replay = (%+v, %v)", value, err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestMySQLRepositoryExtendRetentionRejectsStaleCAS(t *testing.T) {
	database, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	repository := NewMySQLRepository(database)
	now := time.Date(2026, 7, 29, 1, 2, 3, 0, time.UTC)
	expected := now.Add(24 * time.Hour)
	stored := expected.Add(time.Hour)
	requested := expected.Add(DefaultSampleRetention)

	mock.ExpectBegin()
	expectTaskStateLock(mock, testTaskID, 42, "SUCCEEDED", stored, nil, now)
	mock.ExpectRollback()

	_, err = repository.ExtendRetention(context.Background(), RetentionRecord{
		TaskID: testTaskID, ExpectedSampleExpiresAt: expected, SampleExpiresAt: requested,
	})
	if !errors.Is(err, ErrConflict) {
		t.Fatalf("ExtendRetention() stale CAS error = %v, want ErrConflict", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestMySQLRepositoryExtendRetentionRejectsLostCASUpdate(t *testing.T) {
	database, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	repository := NewMySQLRepository(database)
	now := time.Date(2026, 7, 29, 1, 2, 3, 0, time.UTC)
	expected := now.Add(24 * time.Hour)
	requested := expected.Add(DefaultSampleRetention)

	mock.ExpectBegin()
	expectTaskStateLock(mock, testTaskID, 42, "SUCCEEDED", expected, nil, now)
	mock.ExpectExec(`(?s)UPDATE tasks.*sample_expires_at = \?.*WHERE id = \?`).
		WithArgs(requested, testTaskID, expected).
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectRollback()

	_, err = repository.ExtendRetention(context.Background(), RetentionRecord{
		TaskID: testTaskID, ExpectedSampleExpiresAt: expected, SampleExpiresAt: requested,
	})
	if !errors.Is(err, ErrConflict) {
		t.Fatalf("ExtendRetention() lost CAS error = %v, want ErrConflict", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestMySQLRepositoryExtendRetentionRejectsUnavailableTaskOrSample(t *testing.T) {
	now := time.Date(2026, 7, 29, 1, 2, 3, 0, time.UTC)
	tests := []struct {
		name            string
		status          string
		expires         time.Time
		sampleDeletedAt any
		taskDeletedAt   any
		want            error
	}{
		{name: "expired", status: "SUCCEEDED", expires: now, want: ErrSampleUnavailable},
		{
			name: "sample deleted", status: "SUCCEEDED",
			expires: now.Add(time.Hour), sampleDeletedAt: now, want: ErrSampleUnavailable,
		},
		{
			name: "task deletion timestamp set", status: "SUCCEEDED",
			expires: now.Add(time.Hour), taskDeletedAt: now, want: ErrInvalidState,
		},
		{
			name: "task deleting", status: StatusDeleting,
			expires: now.Add(time.Hour), want: ErrInvalidState,
		},
		{
			name: "task deleted", status: StatusDeleted,
			expires: now.Add(time.Hour), want: ErrInvalidState,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			database, mock, err := sqlmock.New()
			if err != nil {
				t.Fatal(err)
			}
			defer database.Close()
			repository := NewMySQLRepository(database)
			requested := test.expires.Add(DefaultSampleRetention)

			mock.ExpectBegin()
			expectTaskStateLockWithDeletedAt(
				mock, testTaskID, 42, test.status, test.expires,
				test.sampleDeletedAt, test.taskDeletedAt, now,
			)
			mock.ExpectRollback()

			_, err = repository.ExtendRetention(context.Background(), RetentionRecord{
				TaskID:                  testTaskID,
				ExpectedSampleExpiresAt: test.expires,
				SampleExpiresAt:         requested,
			})
			if !errors.Is(err, test.want) {
				t.Fatalf("ExtendRetention() error = %v, want %v", err, test.want)
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func expectTaskStateLock(
	mock sqlmock.Sqlmock,
	taskID string,
	createdBy uint64,
	status string,
	expires time.Time,
	deletedAt any,
	databaseNow time.Time,
) {
	expectTaskStateLockWithDeletedAt(
		mock, taskID, createdBy, status, expires, deletedAt, nil, databaseNow,
	)
}

func expectTaskStateLockWithDeletedAt(
	mock sqlmock.Sqlmock,
	taskID string,
	createdBy uint64,
	status string,
	expires time.Time,
	sampleDeletedAt any,
	taskDeletedAt any,
	databaseNow time.Time,
) {
	mock.ExpectQuery(`(?s)SELECT created_by, status, sample_expires_at, sample_deleted_at, deleted_at.*UTC_TIMESTAMP.*FOR UPDATE`).
		WithArgs(taskID).
		WillReturnRows(sqlmock.NewRows([]string{
			"created_by", "status", "sample_expires_at", "sample_deleted_at",
			"deleted_at", "database_now",
		}).AddRow(
			createdBy, status, expires, sampleDeletedAt, taskDeletedAt, databaseNow,
		))
}

func expectTaskActionReplay(
	mock sqlmock.Sqlmock,
	taskID string,
	action string,
	key string,
	exists bool,
) {
	mock.ExpectQuery(`(?s)SELECT EXISTS.*FROM task_action_requests.*idempotency_key = \?`).
		WithArgs(taskID, action, key).
		WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(exists))
}

func expectTaskActionInsert(
	mock sqlmock.Sqlmock,
	taskID string,
	action string,
	key string,
) {
	mock.ExpectExec(`(?s)INSERT INTO task_action_requests.*UTC_TIMESTAMP`).
		WithArgs(taskID, action, key).
		WillReturnResult(sqlmock.NewResult(0, 1))
}

func expectTaskEvent(
	mock sqlmock.Sqlmock,
	taskID string,
	eventType string,
	message string,
) {
	mock.ExpectExec(`(?s)INSERT INTO task_events.*SELECT.*FROM tasks.*WHERE id = \?`).
		WithArgs(eventType, message, taskID).
		WillReturnResult(sqlmock.NewResult(0, 1))
}

func expectInactiveResourceSlotRelease(
	mock sqlmock.Sqlmock,
	taskID string,
	rows int64,
) {
	for index, pool := range []string{"global", "trivy", "native"} {
		affected := int64(0)
		if index == 0 {
			affected = rows
		}
		mock.ExpectExec(`(?s)UPDATE job_resource_slots slot.*JOIN jobs job.*slot\.job_id = NULL.*job\.task_id = \?.*slot\.pool = \?.*job\.status IN \('queued', 'leased'\)`).
			WithArgs(taskID, pool).
			WillReturnResult(sqlmock.NewResult(0, affected))
	}
}

func taskRow(
	now time.Time,
	expires time.Time,
	rootFormat any,
	progress uint16,
) *sqlmock.Rows {
	return taskRowStatus(now, expires, rootFormat, progress, StatusQueued)
}

func taskRowStatus(
	now time.Time,
	expires time.Time,
	rootFormat any,
	progress uint16,
	status string,
) *sqlmock.Rows {
	return taskRowStatusWithDeleted(
		now, expires, rootFormat, progress, status, nil,
	)
}

func taskRowStatusWithDeleted(
	now time.Time,
	expires time.Time,
	rootFormat any,
	progress uint16,
	status string,
	sampleDeletedAt any,
) *sqlmock.Rows {
	var stage any
	switch status {
	case "VALIDATING", "IDENTIFYING", "EXTRACTING", "INDEXING", "SCANNING", "REPORTING":
		stage = status
	}
	return sqlmock.NewRows([]string{
		"id", "name", "root_format", "status", "risk_level",
		"progress_basis_points", "creator_id", "creator_name", "tags", "created_at",
		"updated_at", "original_filename", "size_bytes", "sha256",
		"stage", "error_code", "error_message", "sample_expires_at",
		"sample_deleted_at",
	}).AddRow(
		testTaskID, "firmware.img", rootFormat, status, "UNKNOWN",
		progress, testCreatorPublicID, "Operator", []byte(`[]`), now, now, "firmware.img",
		uint64(4096), "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		stage, nil, nil, expires, sampleDeletedAt,
	)
}

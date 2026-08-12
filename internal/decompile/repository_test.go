package decompile

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
)

const (
	testTaskID           = "123e4567-e89b-42d3-a456-426614174001"
	testResultID         = "223e4567-e89b-42d3-a456-426614174002"
	nextResultID         = "323e4567-e89b-42d3-a456-426614174003"
	testJobID            = "423e4567-e89b-42d3-a456-426614174004"
	testRequestID        = "523e4567-e89b-42d3-a456-426614174005"
	testAttemptID uint64 = 17
)

func TestDecompileTargetCapabilityRoutesMachOX8664ToGhidra(t *testing.T) {
	tests := []struct {
		name         string
		format       string
		architecture string
		class        string
		engine       string
		supported    bool
	}{
		{
			name: "existing PE path", format: "pe32+", architecture: "x86_64",
			class: TargetNative, engine: EngineGhidra, supported: true,
		},
		{
			name: "thin Mach-O x86_64", format: "macho-thin", architecture: "x86_64",
			class: TargetNative, engine: EngineGhidra, supported: true,
		},
		{
			name:   "thin Mach-O unsupported architecture",
			format: "macho-thin", architecture: "aarch64",
		},
		{
			name:   "fat Mach-O requires slice selection",
			format: "macho-fat", architecture: "universal",
		},
		{name: "non-decompilable format", format: "zip"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			class, engine, supported := decompileTargetForTarget(
				test.format,
				test.architecture,
			)
			if class != test.class || engine != test.engine || supported != test.supported {
				t.Fatalf(
					"decompileTargetForTarget(%q, %q) = (%q, %q, %v)",
					test.format,
					test.architecture,
					class,
					engine,
					supported,
				)
			}
		})
	}
}

func TestMySQLRepositoryReadsTerminalDecompileRequestStatus(t *testing.T) {
	database, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	repository := NewMySQLRepository(database)
	createdAt := time.Date(2026, 8, 3, 22, 12, 39, 0, time.UTC)
	completedAt := time.Date(2026, 8, 3, 22, 16, 43, 0, time.UTC)
	payload := decompilePayload(decompileCreateRecord())
	encoded, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	mock.ExpectQuery(`(?s)SELECT id, status, payload, error_code, error_message, created_at, completed_at.*FROM jobs.*task_id = \?.*id = \?.*kind = 'decompile'`).
		WithArgs(testTaskID, testJobID).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "status", "payload", "error_code", "error_message",
			"created_at", "completed_at",
		}).AddRow(
			testJobID, "succeeded", encoded, nil, nil, createdAt, completedAt,
		))

	value, err := repository.GetRequest(context.Background(), RequestQuery{
		TaskID: testTaskID,
		JobID:  testJobID,
	})
	if err != nil {
		t.Fatal(err)
	}
	if value.JobID != testJobID ||
		value.RequestID != testRequestID ||
		value.TaskID != testTaskID ||
		value.Status != "succeeded" ||
		value.CompletedAt == nil ||
		!value.CompletedAt.Equal(completedAt) {
		t.Fatalf("GetRequest() = %#v", value)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestMySQLRepositoryReturnsMissingDecompileRequest(t *testing.T) {
	database, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	repository := NewMySQLRepository(database)
	mock.ExpectQuery(`(?s)SELECT id, status, payload, error_code, error_message, created_at, completed_at.*FROM jobs`).
		WithArgs(testTaskID, testJobID).
		WillReturnError(sql.ErrNoRows)

	_, err = repository.GetRequest(context.Background(), RequestQuery{
		TaskID: testTaskID,
		JobID:  testJobID,
	})
	if !errors.Is(err, ErrRequestNotFound) {
		t.Fatalf("GetRequest() error = %v, want ErrRequestNotFound", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestMySQLRepositoryCreatesDecompileJobAtomically(t *testing.T) {
	database, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	repository := NewMySQLRepository(database)
	now := time.Date(2026, 7, 31, 1, 2, 3, 0, time.UTC)
	expiresAt := now.Add(time.Hour)
	record := decompileCreateRecord()
	payload := decompilePayload(record)
	encoded, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}

	mock.ExpectBegin()
	expectDecompileTaskLock(
		mock,
		"SUCCEEDED",
		nil,
		expiresAt,
		nil,
		now,
	)
	expectDecompileTarget(mock, "elf64")
	expectCompletedDecompileAttempt(mock, "succeeded")
	mock.ExpectQuery(`(?s)SELECT id, task_attempt_id, status, kind, payload, created_at.*FROM jobs.*idempotency_key = \?.*FOR UPDATE`).
		WithArgs(testTaskID, record.JobRequestKey).
		WillReturnError(sql.ErrNoRows)
	mock.ExpectQuery(`(?s)SELECT id.*FROM jobs.*kind = 'decompile'.*JSON_UNQUOTE.*file_node_id.*FOR UPDATE`).
		WithArgs(testTaskID, "42").
		WillReturnError(sql.ErrNoRows)
	mock.ExpectExec(`(?s)INSERT INTO jobs.*'decompile'.*'queued'.*UTC_TIMESTAMP`).
		WithArgs(
			testJobID, testTaskID, testAttemptID, encoded,
			record.JobRequestKey,
		).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`(?s)UPDATE tasks.*event_sequence = event_sequence \+ 1.*sample_expires_at > UTC_TIMESTAMP`).
		WithArgs(testTaskID, "SUCCEEDED").
		WillReturnResult(sqlmock.NewResult(0, 1))
	expectDecompileTaskEvent(mock)
	mock.ExpectQuery(`(?s)SELECT id, status, payload, created_at.*FROM jobs.*kind = 'decompile'`).
		WithArgs(testJobID, testTaskID).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "status", "payload", "created_at",
		}).AddRow(testJobID, "queued", encoded, now))
	mock.ExpectCommit()

	value, created, err := repository.Enqueue(
		context.Background(),
		record,
	)
	if err != nil {
		t.Fatal(err)
	}
	if !created ||
		value.JobID != testJobID ||
		value.RequestID != testRequestID ||
		value.TaskID != testTaskID ||
		value.FileNodeID != "42" ||
		value.TargetClass != TargetNative ||
		value.EngineTarget != EngineGhidra ||
		value.Status != "queued" ||
		!value.CreatedAt.Equal(now) {
		t.Fatalf("Enqueue() = (%+v, %v)", value, created)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestMySQLRepositoryReplaysDecompileJobWithoutDuplicateEvent(t *testing.T) {
	database, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	repository := NewMySQLRepository(database)
	now := time.Date(2026, 7, 31, 1, 2, 3, 0, time.UTC)
	record := decompileCreateRecord()
	record.Options = json.RawMessage(
		`{"analysis_mode":"default","nested":{"x":1,"y":2}}`,
	)
	stored := decompilePayload(record)
	stored.RequestID = "623e4567-e89b-42d3-a456-426614174006"
	compact, err := json.Marshal(stored)
	if err != nil {
		t.Fatal(err)
	}
	var mysqlNormalized bytes.Buffer
	if err := json.Indent(&mysqlNormalized, compact, "", "  "); err != nil {
		t.Fatal(err)
	}
	encoded := mysqlNormalized.Bytes()

	mock.ExpectBegin()
	expectDecompileTaskLock(
		mock,
		"SUCCEEDED",
		nil,
		now.Add(time.Hour),
		nil,
		now,
	)
	expectDecompileTarget(mock, "elf64")
	expectCompletedDecompileAttempt(mock, "succeeded")
	mock.ExpectQuery(`(?s)SELECT id, task_attempt_id, status, kind, payload, created_at.*FROM jobs.*idempotency_key = \?.*FOR UPDATE`).
		WithArgs(testTaskID, record.JobRequestKey).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "task_attempt_id", "status", "kind", "payload", "created_at",
		}).AddRow(
			testJobID, testAttemptID, "leased", "decompile", encoded, now,
		))
	mock.ExpectCommit()

	value, created, err := repository.Enqueue(
		context.Background(),
		record,
	)
	if err != nil {
		t.Fatal(err)
	}
	if created ||
		value.JobID != testJobID ||
		value.RequestID != stored.RequestID ||
		value.Status != "leased" {
		t.Fatalf("Enqueue() replay = (%+v, %v)", value, created)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestMySQLRepositoryRejectsReusedKeyForDifferentDecompileRequest(
	t *testing.T,
) {
	database, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	repository := NewMySQLRepository(database)
	now := time.Date(2026, 7, 31, 1, 2, 3, 0, time.UTC)
	record := decompileCreateRecord()
	stored := decompilePayload(record)
	stored.Options = json.RawMessage(`{"analysis_mode":"aggressive"}`)
	encoded, err := json.Marshal(stored)
	if err != nil {
		t.Fatal(err)
	}

	mock.ExpectBegin()
	expectDecompileTaskLock(
		mock,
		"SUCCEEDED",
		nil,
		now.Add(time.Hour),
		nil,
		now,
	)
	expectDecompileTarget(mock, "elf64")
	expectCompletedDecompileAttempt(mock, "succeeded")
	mock.ExpectQuery(`(?s)SELECT id, task_attempt_id, status, kind, payload, created_at.*FROM jobs.*idempotency_key = \?.*FOR UPDATE`).
		WithArgs(testTaskID, record.JobRequestKey).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "task_attempt_id", "status", "kind", "payload", "created_at",
		}).AddRow(
			testJobID, testAttemptID, "queued", "decompile", encoded, now,
		))
	mock.ExpectRollback()

	_, _, err = repository.Enqueue(context.Background(), record)
	if !errors.Is(err, ErrRequestConflict) {
		t.Fatalf("Enqueue() reused key error = %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestMySQLRepositoryRejectsExpiredOrConflictingDecompile(t *testing.T) {
	t.Run("database UTC expiration", func(t *testing.T) {
		database, mock, err := sqlmock.New()
		if err != nil {
			t.Fatal(err)
		}
		defer database.Close()
		repository := NewMySQLRepository(database)
		now := time.Date(2026, 7, 31, 1, 2, 3, 0, time.UTC)
		mock.ExpectBegin()
		expectDecompileTaskLock(mock, "SUCCEEDED", nil, now, nil, now)
		mock.ExpectRollback()
		_, _, err = repository.Enqueue(
			context.Background(),
			decompileCreateRecord(),
		)
		if !errors.Is(err, ErrSampleUnavailable) {
			t.Fatalf("Enqueue() expired error = %v", err)
		}
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("active same-node request", func(t *testing.T) {
		database, mock, err := sqlmock.New()
		if err != nil {
			t.Fatal(err)
		}
		defer database.Close()
		repository := NewMySQLRepository(database)
		now := time.Date(2026, 7, 31, 1, 2, 3, 0, time.UTC)
		record := decompileCreateRecord()
		mock.ExpectBegin()
		expectDecompileTaskLock(
			mock,
			"SUCCEEDED",
			nil,
			now.Add(time.Hour),
			nil,
			now,
		)
		expectDecompileTarget(mock, "elf64")
		expectCompletedDecompileAttempt(mock, "succeeded")
		mock.ExpectQuery(`(?s)SELECT id, task_attempt_id, status, kind, payload, created_at.*FROM jobs.*idempotency_key = \?.*FOR UPDATE`).
			WithArgs(testTaskID, record.JobRequestKey).
			WillReturnError(sql.ErrNoRows)
		mock.ExpectQuery(`(?s)SELECT id.*FROM jobs.*kind = 'decompile'.*JSON_UNQUOTE.*file_node_id.*FOR UPDATE`).
			WithArgs(testTaskID, "42").
			WillReturnRows(
				sqlmock.NewRows([]string{"id"}).AddRow(testJobID),
			)
		mock.ExpectRollback()
		_, _, err = repository.Enqueue(context.Background(), record)
		if !errors.Is(err, ErrDecompileInProgress) {
			t.Fatalf("Enqueue() conflict error = %v", err)
		}
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("missing completed task attempt", func(t *testing.T) {
		database, mock, err := sqlmock.New()
		if err != nil {
			t.Fatal(err)
		}
		defer database.Close()
		repository := NewMySQLRepository(database)
		now := time.Date(2026, 7, 31, 1, 2, 3, 0, time.UTC)
		mock.ExpectBegin()
		expectDecompileTaskLock(
			mock, "SUCCEEDED", nil, now.Add(time.Hour), nil, now,
		)
		expectDecompileTarget(mock, "elf64")
		mock.ExpectQuery(`(?s)SELECT id.*FROM task_attempts.*status = \?.*ORDER BY attempt_number DESC.*FOR UPDATE`).
			WithArgs(testTaskID, "succeeded").
			WillReturnError(sql.ErrNoRows)
		mock.ExpectRollback()
		_, _, err = repository.Enqueue(
			context.Background(), decompileCreateRecord(),
		)
		if !errors.Is(err, ErrTaskStateConflict) {
			t.Fatalf("Enqueue() missing task attempt error = %v", err)
		}
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Fatal(err)
		}
	})
}

func TestMySQLRepositoryListsResultsWithStableCursor(t *testing.T) {
	database, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	repository := NewMySQLRepository(database)
	createdAt := time.Date(2026, 7, 30, 1, 2, 3, 0, time.UTC)
	completedAt := createdAt.Add(time.Second)

	mock.ExpectBegin()
	expectTaskExists(mock, testTaskID)
	mock.ExpectQuery(`(?s)SELECT id, file_node_id, symbol_key.*FROM decompile_results.*WHERE task_id = \? AND deleted_at IS NULL.*ORDER BY created_at ASC, id ASC.*LIMIT \?`).
		WithArgs(testTaskID, 2).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "file_node_id", "symbol_key", "language", "engine_name",
			"engine_version", "status", "size_bytes", "diagnostics_json",
			"created_at", "completed_at", "storage_key", "content_sha256",
		}).
			AddRow(
				testResultID, uint64(42), "FUN_140001000", "c",
				"ghidra", "11.3", "complete", uint64(128),
				[]byte(`{
					"symbol_kind":"function",
					"display_name":"verify_header",
					"group_name":".text",
					"location":"0x140001000",
					"signature":"bool verify_header(void)",
					"detail":"128 B"
				}`),
				createdAt, completedAt, "decompile/result/source.c",
				strings.Repeat("a", 64),
			).
			AddRow(
				nextResultID, uint64(43), "bad_metadata", "c",
				"ghidra", "11.3", "failed", nil,
				[]byte(`{"symbol_kind":42,"display_name":null}`),
				createdAt.Add(time.Second), nil, nil, nil,
			))
	mock.ExpectCommit()

	page, err := repository.List(context.Background(), ListQuery{
		TaskID: testTaskID, PageSize: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Items) != 1 || !page.HasMore || page.NextCursor != "" {
		t.Fatalf("List() page = %#v", page)
	}
	item := page.Items[0]
	if item.ID != testResultID || item.FileNodeID != "42" ||
		item.SymbolKind != "function" ||
		item.DisplayName != "verify_header" ||
		item.GroupName != ".text" ||
		item.Location != "0x140001000" ||
		item.Signature != "bool verify_header(void)" ||
		item.Detail != "128 B" ||
		item.SizeBytes == nil || *item.SizeBytes != 128 ||
		item.StorageKey != "decompile/result/source.c" ||
		item.ContentSHA256 != strings.Repeat("a", 64) ||
		item.CompletedAt == nil || !item.CompletedAt.Equal(completedAt) {
		t.Fatalf("List() item = %#v", item)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestMySQLRepositoryListsSourceArchiveInOneRepeatableReadSnapshot(t *testing.T) {
	database, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	repository := NewMySQLRepository(database)
	createdAt := time.Date(2026, 8, 10, 1, 2, 3, 0, time.UTC)
	storageKey := "source-projects/223e4567-e89b-42d3-a456-426614174002/src/decompiled.c"
	hash := strings.Repeat("a", 64)

	mock.ExpectBegin()
	expectTaskExists(mock, testTaskID)
	mock.ExpectQuery(`(?s)SELECT result.id, result.file_node_id, result.symbol_key.*LEFT JOIN decompile_source_projects project.*ORDER BY result.created_at ASC, result.id ASC.*LIMIT \?`).
		WithArgs(testTaskID, 3).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "file_node_id", "symbol_key", "language", "engine_name",
			"engine_version", "status", "size_bytes", "diagnostics_json",
			"created_at", "completed_at", "storage_key", "content_sha256",
			"source_offset_bytes", "source_length_bytes",
			"canonical_storage_key", "canonical_size_bytes",
		}).
			AddRow(
				testResultID, uint64(42), "FUN_140001000", "c", "ghidra",
				"12.1.2", "complete", uint64(64),
				[]byte(`{"symbol_kind":"function","display_name":"main"}`),
				createdAt, createdAt, storageKey, hash,
				uint64(128), uint64(64), storageKey, uint64(4096),
			).
			AddRow(
				nextResultID, uint64(42), "failed", "c", "ghidra",
				"12.1.2", "failed", nil, nil,
				createdAt.Add(time.Second), createdAt.Add(time.Second),
				nil, nil, nil, nil, nil, nil,
			))
	mock.ExpectCommit()

	snapshot, err := repository.ListSourceArchiveSnapshot(
		context.Background(), testTaskID, 2,
	)
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.HasMore || len(snapshot.Items) != 2 ||
		snapshot.Items[0].Result.DisplayName != "main" ||
		!snapshot.Items[0].Descriptor.SourceRangeKnown ||
		snapshot.Items[0].Descriptor.SourceOffsetBytes != 128 ||
		!snapshot.Items[0].Descriptor.StorageSizeKnown ||
		snapshot.Items[0].Descriptor.StorageSizeBytes != 4096 {
		t.Fatalf("source archive snapshot = %#v", snapshot)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestMySQLRepositoryListCursorIncludesTimeAndIDTieBreaker(t *testing.T) {
	database, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	repository := NewMySQLRepository(database)
	createdAt := time.Date(2026, 7, 30, 1, 2, 3, 0, time.UTC)
	laterAt := createdAt.Add(time.Microsecond)
	laterLowerID := "123e4567-e89b-42d3-a456-426614174004"

	mock.ExpectBegin()
	expectTaskExists(mock, testTaskID)
	mock.ExpectQuery(`(?s)SELECT id, file_node_id, symbol_key.*FROM decompile_results.*created_at > \?.*created_at = \? AND id > \?.*ORDER BY created_at ASC, id ASC.*LIMIT \?`).
		WithArgs(
			testTaskID,
			createdAt,
			createdAt,
			testResultID,
			3,
		).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "file_node_id", "symbol_key", "language", "engine_name",
			"engine_version", "status", "size_bytes", "diagnostics_json",
			"created_at", "completed_at", "storage_key", "content_sha256",
		}).
			AddRow(
				nextResultID, uint64(43), "same-time", "c",
				"ghidra", "11.3", "complete", uint64(1), nil,
				createdAt, createdAt, nil, nil,
			).
			AddRow(
				laterLowerID, uint64(44), "inserted-later", "c",
				"ghidra", "11.3", "complete", uint64(1), nil,
				laterAt, laterAt, nil, nil,
			))
	mock.ExpectCommit()

	page, err := repository.List(context.Background(), ListQuery{
		TaskID: testTaskID,
		After: &ListCursor{
			CreatedAt: createdAt,
			ID:        testResultID,
		},
		PageSize: 2,
	})
	if err != nil {
		t.Fatal(err)
	}
	if page.HasMore || len(page.Items) != 2 ||
		page.Items[0].ID != nextResultID ||
		page.Items[1].ID != laterLowerID {
		t.Fatalf("List() page = %#v", page)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestScanResultSafelyFallsBackFromMalformedDiagnostics(t *testing.T) {
	value := Result{SymbolKey: "FUN_140001000"}
	applyDiagnostics(&value, []byte(`not-json`))
	if value.SymbolKind != "unknown" ||
		value.DisplayName != "FUN_140001000" ||
		value.GroupName != "Ungrouped" ||
		string(value.Diagnostics) != `{}` {
		t.Fatalf("applyDiagnostics() = %#v", value)
	}

	applyDiagnostics(&value, []byte(`{"symbol_kind":"field"}`))
	if value.SymbolKind != "unknown" {
		t.Fatalf("unknown symbol kind = %q, want unknown", value.SymbolKind)
	}
	applyDiagnostics(&value, []byte(`{"symbol_kind":"METHOD"}`))
	if value.SymbolKind != "method" {
		t.Fatalf("normalized symbol kind = %q, want method", value.SymbolKind)
	}
}

func TestMySQLRepositoryListDistinguishesMissingTask(t *testing.T) {
	database, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	repository := NewMySQLRepository(database)

	mock.ExpectBegin()
	mock.ExpectQuery(`(?s)SELECT 1.*FROM tasks.*deleted_at IS NULL`).
		WithArgs(testTaskID).
		WillReturnError(sql.ErrNoRows)
	mock.ExpectRollback()

	_, err = repository.List(context.Background(), ListQuery{
		TaskID: testTaskID, PageSize: DefaultPageSize,
	})
	if !errors.Is(err, ErrTaskNotFound) {
		t.Fatalf("List() error = %v, want ErrTaskNotFound", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestMySQLRepositorySourceDistinguishesMissingResult(t *testing.T) {
	database, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	repository := NewMySQLRepository(database)

	mock.ExpectBegin()
	expectTaskExists(mock, testTaskID)
	mock.ExpectQuery(`(?s)SELECT result.id, result.status, result.storage_key.*FROM decompile_results result.*result.task_id = \?.*result.id = \?`).
		WithArgs(testTaskID, testResultID).
		WillReturnError(sql.ErrNoRows)
	mock.ExpectRollback()

	_, err = repository.GetSource(context.Background(), SourceQuery{
		TaskID: testTaskID, ResultID: testResultID,
	})
	if !errors.Is(err, ErrResultNotFound) {
		t.Fatalf("GetSource() error = %v, want ErrResultNotFound", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestMySQLRepositoryReadsSourceDescriptor(t *testing.T) {
	database, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	repository := NewMySQLRepository(database)
	hash := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

	mock.ExpectBegin()
	expectTaskExists(mock, testTaskID)
	mock.ExpectQuery(`(?s)SELECT result.id, result.status, result.storage_key.*FROM decompile_results result.*LIMIT 1`).
		WithArgs(testTaskID, testResultID).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "status", "storage_key", "content_sha256", "size_bytes",
			"source_offset_bytes", "source_length_bytes",
			"canonical_storage_key", "canonical_size_bytes",
		}).AddRow(
			testResultID, "complete",
			"decompile/223e4567-e89b-42d3-a456-426614174002/source.c",
			hash, uint64(4096),
			nil, nil, nil, nil,
		))
	mock.ExpectCommit()

	value, err := repository.GetSource(context.Background(), SourceQuery{
		TaskID: testTaskID, ResultID: testResultID,
	})
	if err != nil {
		t.Fatal(err)
	}
	if value.ResultID != testResultID || value.Status != "complete" ||
		!value.SizeKnown || value.SizeBytes != 4096 || value.SHA256 != hash {
		t.Fatalf("GetSource() = %#v", value)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestMySQLRepositoryReadsCanonicalSourceRangeDescriptor(t *testing.T) {
	database, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	repository := NewMySQLRepository(database)
	hash := strings.Repeat("a", 64)
	storageKey := "source-projects/223e4567-e89b-42d3-a456-426614174002/src/decompiled.c"

	mock.ExpectBegin()
	expectTaskExists(mock, testTaskID)
	mock.ExpectQuery(`(?s)SELECT result.id, result.status, result.storage_key.*FROM decompile_results result.*LIMIT 1`).
		WithArgs(testTaskID, testResultID).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "status", "storage_key", "content_sha256", "size_bytes",
			"source_offset_bytes", "source_length_bytes",
			"canonical_storage_key", "canonical_size_bytes",
		}).AddRow(
			testResultID, "complete", storageKey, hash, uint64(512),
			uint64(1024), uint64(512), storageKey, uint64(8192),
		))
	mock.ExpectCommit()

	value, err := repository.GetSource(context.Background(), SourceQuery{
		TaskID: testTaskID, ResultID: testResultID,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !value.SourceRangeKnown || value.SourceOffsetBytes != 1024 ||
		value.SourceLengthBytes != 512 || !value.StorageSizeKnown ||
		value.StorageSizeBytes != 8192 || value.StorageKey != storageKey {
		t.Fatalf("GetSource() = %#v", value)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func expectTaskExists(mock sqlmock.Sqlmock, taskID string) {
	mock.ExpectQuery(`(?s)SELECT 1.*FROM tasks.*deleted_at IS NULL`).
		WithArgs(taskID).
		WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(1))
}

func decompileCreateRecord() CreateRecord {
	return CreateRecord{
		JobID:        testJobID,
		RequestID:    testRequestID,
		TaskID:       testTaskID,
		FileNodeID:   42,
		UserID:       7,
		EngineTarget: EngineAuto,
		Options:      json.RawMessage(`{}`),
		Limits:       defaultJobLimits,
		JobRequestKey: "decompile:" +
			"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	}
}

func decompilePayload(record CreateRecord) JobPayload {
	return JobPayload{
		SchemaVersion: JobPayloadVersion,
		RequestID:     record.RequestID,
		RequestedBy:   record.UserID,
		TaskID:        record.TaskID,
		Target: JobTarget{
			FileNodeID:   "42",
			Class:        TargetNative,
			Format:       "elf64",
			Architecture: "x86_64",
			StorageKey:   "blobs/sha256/aa/" + strings.Repeat("a", 64),
			SHA256:       strings.Repeat("a", 64),
			SizeBytes:    4096,
		},
		Engine: JobEngine{
			Target: EngineGhidra, WorkerKind: TargetNative,
		},
		Options: record.Options,
		Limits:  record.Limits,
	}
}

func expectDecompileTaskLock(
	mock sqlmock.Sqlmock,
	status string,
	sampleDeletedAt any,
	sampleExpiresAt time.Time,
	deletedAt any,
	databaseNow time.Time,
) {
	mock.ExpectQuery(`(?s)SELECT status, sample_deleted_at, sample_expires_at, deleted_at,.*UTC_TIMESTAMP.*FROM tasks.*FOR UPDATE`).
		WithArgs(testTaskID).
		WillReturnRows(sqlmock.NewRows([]string{
			"status", "sample_deleted_at", "sample_expires_at",
			"deleted_at", "database_now",
		}).AddRow(
			status,
			sampleDeletedAt,
			sampleExpiresAt,
			deletedAt,
			databaseNow,
		))
}

func expectDecompileTarget(mock sqlmock.Sqlmock, format string) {
	mock.ExpectQuery(`(?s)SELECT node_type, format, architecture, storage_key, sha256, size_bytes, extraction_status.*FROM file_nodes.*task_id = \? AND id = \?.*FOR UPDATE`).
		WithArgs(testTaskID, uint64(42)).
		WillReturnRows(sqlmock.NewRows([]string{
			"node_type", "format", "architecture", "storage_key", "sha256",
			"size_bytes", "extraction_status",
		}).AddRow(
			"file",
			format,
			"x86_64",
			"blobs/sha256/aa/"+strings.Repeat("a", 64),
			strings.Repeat("a", 64),
			uint64(4096),
			"indexed",
		))
}

func expectCompletedDecompileAttempt(
	mock sqlmock.Sqlmock,
	status string,
) {
	mock.ExpectQuery(`(?s)SELECT id.*FROM task_attempts.*task_id = \?.*status = \?.*ORDER BY attempt_number DESC.*FOR UPDATE`).
		WithArgs(testTaskID, status).
		WillReturnRows(
			sqlmock.NewRows([]string{"id"}).AddRow(testAttemptID),
		)
}

func expectDecompileTaskEvent(mock sqlmock.Sqlmock) {
	mock.ExpectExec(`(?s)INSERT INTO task_events.*SELECT.*FROM tasks.*WHERE id = \?`).
		WithArgs(
			"decompile.queued",
			"Decompile request queued.",
			testTaskID,
		).
		WillReturnResult(sqlmock.NewResult(0, 1))
}

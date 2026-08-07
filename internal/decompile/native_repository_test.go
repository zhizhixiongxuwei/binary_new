package decompile

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"testing"

	"binaryscan/internal/queue"

	"github.com/DATA-DOG/go-sqlmock"
)

const testNativeParameterKey = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

func TestBeginNativeRunRevalidatesFencedSourceIdentity(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	repository := NewMySQLRepository(db)
	payload := decompilePayload(decompileCreateRecord())
	lease := nativeTestLease(payload)
	runID := "323e4567-e89b-42d3-a456-426614174003"

	mock.ExpectBegin()
	mock.ExpectQuery(`(?s)SELECT node[.]storage_key.*FROM jobs job.*job[.]kind = 'decompile'.*job[.]fencing_token = \?.*FOR UPDATE`).
		WithArgs(
			uint64(42), lease.JobID, lease.TaskID, *lease.TaskAttemptID,
			lease.Owner, lease.FencingToken,
		).
		WillReturnRows(sqlmock.NewRows(
			[]string{
				"storage_key", "sha256", "size_bytes", "format", "architecture",
			},
		).AddRow(
			payload.Target.StorageKey, payload.Target.SHA256,
			payload.Target.SizeBytes, payload.Target.Format,
			payload.Target.Architecture,
		))
	mock.ExpectQuery(`(?s)SELECT EXISTS.*FROM analyzer_runs.*status = 'succeeded'`).
		WithArgs(
			lease.TaskID, *lease.TaskAttemptID, lease.JobID,
			uint64(42), "12.1.2",
			testNativeParameterKey, payload.Target.StorageKey,
			payload.Target.SHA256, "4096", payload.Target.Format,
			payload.Target.Architecture,
		).
		WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(0))
	mock.ExpectExec(`(?s)UPDATE analyzer_runs.*worker_replaced`).
		WithArgs(lease.TaskID, *lease.TaskAttemptID, lease.JobID).
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec(`(?s)INSERT INTO analyzer_runs.*'ghidra'.*cache_parameters_sha256.*'running'`).
		WithArgs(
			runID, lease.TaskID, *lease.TaskAttemptID, lease.JobID,
			uint64(42), "12.1.2",
			lease.Attempt, lease.FencingToken, payload.SchemaVersion,
			testNativeParameterKey,
			payload.Target.StorageKey, payload.Target.SHA256,
			payload.Target.SizeBytes, payload.Target.Format,
			payload.Target.Architecture,
		).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

	if err := repository.BeginNativeRun(
		context.Background(), lease, payload, runID, "12.1.2",
		testNativeParameterKey,
	); err != nil {
		t.Fatal(err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestBeginNativeRunReplaysOnlyExactSuccessfulResultIdentity(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	repository := NewMySQLRepository(db)
	payload := decompilePayload(decompileCreateRecord())
	lease := nativeTestLease(payload)
	runID := "323e4567-e89b-42d3-a456-426614174003"

	mock.ExpectBegin()
	mock.ExpectQuery(`(?s)SELECT node[.]storage_key.*node[.]architecture.*FROM jobs job.*FOR UPDATE`).
		WithArgs(
			uint64(42), lease.JobID, lease.TaskID, *lease.TaskAttemptID,
			lease.Owner, lease.FencingToken,
		).
		WillReturnRows(sqlmock.NewRows([]string{
			"storage_key", "sha256", "size_bytes", "format", "architecture",
		}).AddRow(
			payload.Target.StorageKey, payload.Target.SHA256,
			payload.Target.SizeBytes, payload.Target.Format,
			payload.Target.Architecture,
		))
	mock.ExpectQuery(`(?s)SELECT EXISTS.*analyzer_name = 'ghidra'.*analyzer_version = \?.*cache_parameters_sha256.*source_storage_key.*source_sha256.*source_size_bytes.*source_format.*source_architecture.*EXISTS.*FROM decompile_results.*status = 'complete'`).
		WithArgs(
			lease.TaskID, *lease.TaskAttemptID, lease.JobID, uint64(42), "12.1.2",
			testNativeParameterKey, payload.Target.StorageKey,
			payload.Target.SHA256, "4096", payload.Target.Format,
			payload.Target.Architecture,
		).
		WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(1))
	mock.ExpectRollback()

	err = repository.BeginNativeRun(
		context.Background(), lease, payload, runID, "12.1.2",
		testNativeParameterKey,
	)
	if !errors.Is(err, errNativeAlreadyPublished) {
		t.Fatalf("BeginNativeRun() error = %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestPublishNativeRunRejectsLostFenceBeforeRows(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	repository := NewMySQLRepository(db)
	payload := decompilePayload(decompileCreateRecord())
	lease := nativeTestLease(payload)
	runID := "323e4567-e89b-42d3-a456-426614174003"

	mock.ExpectBegin()
	mock.ExpectQuery(`(?s)SELECT 1.*FROM jobs job.*job[.]fencing_token = \?.*run[.]status = 'running'.*FOR UPDATE`).
		WithArgs(
			runID, lease.JobID, lease.TaskID, *lease.TaskAttemptID, lease.Owner,
			lease.FencingToken, uint64(42), "12.1.2", "1", "2",
			testNativeParameterKey, payload.Target.StorageKey,
			payload.Target.SHA256, "4096", payload.Target.Format,
			payload.Target.Architecture,
		).
		WillReturnError(sql.ErrNoRows)
	mock.ExpectRollback()

	publisherCalled := false
	err = repository.PublishNativeRun(
		context.Background(), lease, payload, runID, "12.1.2",
		testNativeParameterKey, "complete",
		func(context.Context) ([]NativePublishedResult, func(), error) {
			publisherCalled = true
			return nil, func() {}, nil
		},
	)
	if !errors.Is(err, ErrRequestConflict) {
		t.Fatalf("PublishNativeRun() error = %v", err)
	}
	if publisherCalled {
		t.Fatal("stale lease invoked filesystem publisher")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestPublishNativeRunRejectsZeroResultSuccess(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	repository := NewMySQLRepository(db)
	payload := decompilePayload(decompileCreateRecord())
	lease := nativeTestLease(payload)
	runID := "323e4567-e89b-42d3-a456-426614174003"

	mock.ExpectBegin()
	mock.ExpectQuery(`(?s)SELECT 1.*FROM jobs job.*run[.]file_node_id = \?.*run[.]analyzer_version = \?.*cache_parameters_sha256.*source_architecture.*FOR UPDATE`).
		WithArgs(
			runID, lease.JobID, lease.TaskID, *lease.TaskAttemptID, lease.Owner,
			lease.FencingToken, uint64(42), "12.1.2", "1", "2",
			testNativeParameterKey, payload.Target.StorageKey,
			payload.Target.SHA256, "4096", payload.Target.Format,
			payload.Target.Architecture,
		).
		WillReturnRows(sqlmock.NewRows([]string{"marker"}).AddRow(1))
	mock.ExpectRollback()

	cleanupCalls := 0
	err = repository.PublishNativeRun(
		context.Background(), lease, payload, runID, "12.1.2",
		testNativeParameterKey, "complete",
		func(context.Context) ([]NativePublishedResult, func(), error) {
			return []NativePublishedResult{}, func() { cleanupCalls++ }, nil
		},
	)
	if !errors.Is(err, ErrRequestConflict) || cleanupCalls != 1 {
		t.Fatalf("PublishNativeRun() error=%v cleanup=%d", err, cleanupCalls)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestPublishNativeRunCleansFilesWhenLeaseExpiresBeforeCommit(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	repository := NewMySQLRepository(db)
	payload := decompilePayload(decompileCreateRecord())
	lease := nativeTestLease(payload)
	runID := "323e4567-e89b-42d3-a456-426614174003"
	value := NativePublishedResult{
		SymbolKey: "00401000",
		SHA256:    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		SizeBytes: 10,
		Diagnostics: json.RawMessage(
			`{"format":"ELF","architecture":"x86:LE:64"}`,
		),
	}
	value.ID = nativeResultID(runID, value.SymbolKey)
	value.StorageKey = "decompile/" + value.ID + "/source.c"
	expectedCacheKey := nativeResultCacheKey(
		payload, lease.JobID, "12.1.2", testNativeParameterKey, value.SymbolKey,
	)

	mock.ExpectBegin()
	mock.ExpectQuery(`(?s)SELECT 1.*FROM jobs job.*job[.]fencing_token = \?.*run[.]status = 'running'.*FOR UPDATE`).
		WithArgs(
			runID, lease.JobID, lease.TaskID, *lease.TaskAttemptID, lease.Owner,
			lease.FencingToken, uint64(42), "12.1.2", "1", "2",
			testNativeParameterKey, payload.Target.StorageKey,
			payload.Target.SHA256, "4096", payload.Target.Format,
			payload.Target.Architecture,
		).
		WillReturnRows(sqlmock.NewRows([]string{"marker"}).AddRow(1))
	mock.ExpectExec(`(?s)INSERT INTO decompile_results`).
		WithArgs(
			value.ID, lease.TaskID, uint64(42), runID, expectedCacheKey,
			value.SymbolKey, "12.1.2", value.StorageKey, value.SHA256,
			value.SizeBytes, []byte(value.Diagnostics),
		).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`(?s)UPDATE analyzer_runs.*status = \?`).
		WithArgs("succeeded", runID, lease.TaskID, lease.JobID).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectQuery(`(?s)SELECT 1.*FROM jobs job.*job[.]lease_until > UTC_TIMESTAMP.*run[.]status = \?`).
		WithArgs(
			runID, lease.JobID, lease.TaskID, *lease.TaskAttemptID, lease.Owner,
			lease.FencingToken, uint64(42), "12.1.2", "succeeded", "1", "2",
			testNativeParameterKey, payload.Target.StorageKey,
			payload.Target.SHA256, "4096", payload.Target.Format,
			payload.Target.Architecture,
		).
		WillReturnError(sql.ErrNoRows)
	mock.ExpectRollback()

	publisherCalled := false
	cleanupCalls := 0
	err = repository.PublishNativeRun(
		context.Background(), lease, payload, runID, "12.1.2",
		testNativeParameterKey, "complete",
		func(context.Context) ([]NativePublishedResult, func(), error) {
			publisherCalled = true
			return []NativePublishedResult{value}, func() {
				cleanupCalls++
			}, nil
		},
	)
	if !errors.Is(err, ErrRequestConflict) {
		t.Fatalf("PublishNativeRun() error = %v", err)
	}
	if !publisherCalled || cleanupCalls != 1 {
		t.Fatalf(
			"publisher called=%v cleanup calls=%d, want true/1",
			publisherCalled, cleanupCalls,
		)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func nativeTestLease(payload JobPayload) queue.Lease {
	raw, _ := json.Marshal(payload)
	attemptID := uint64(11)
	return queue.Lease{
		JobID: testJobID, TaskID: testTaskID, TaskAttemptID: &attemptID,
		Kind:    queue.KindDecompile,
		Payload: raw, Attempt: 1, MaxAttempts: 3, FencingToken: 2,
		Owner: "native-test",
	}
}

func TestValidNativePublishedResultIsScopedToRun(t *testing.T) {
	runID := "323e4567-e89b-42d3-a456-426614174003"
	value := NativePublishedResult{
		SymbolKey: "00401000",
		SHA256:    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		SizeBytes: 10, Diagnostics: json.RawMessage(`{"ok":true}`),
	}
	value.ID = nativeResultID(runID, value.SymbolKey)
	value.StorageKey = "decompile/" + value.ID + "/source.c"
	if !validNativePublishedResult(runID, value) {
		t.Fatal("valid run-scoped result was rejected")
	}
	if validNativePublishedResult(
		"423e4567-e89b-42d3-a456-426614174004", value,
	) {
		t.Fatal("result from another run was accepted")
	}
}

func TestNativeResultCacheKeyIsRetryStableAndParameterBound(t *testing.T) {
	payload := decompilePayload(decompileCreateRecord())
	first := nativeResultCacheKey(
		payload, testJobID, "12.1.2", testNativeParameterKey, "00401000",
	)
	again := nativeResultCacheKey(
		payload, testJobID, "12.1.2", testNativeParameterKey, "00401000",
	)
	if first != again || len(first) != 64 {
		t.Fatalf("cache keys = %q / %q", first, again)
	}
	changes := []struct {
		name       string
		payload    JobPayload
		jobID      string
		version    string
		parameters string
		symbol     string
	}{
		{
			name: "engine version", payload: payload, jobID: testJobID,
			version:    "12.1.3",
			parameters: testNativeParameterKey, symbol: "00401000",
		},
		{
			name: "parameters", payload: payload, jobID: testJobID,
			version:    "12.1.2",
			parameters: "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
			symbol:     "00401000",
		},
		{
			name: "symbol", payload: payload, jobID: testJobID,
			version:    "12.1.2",
			parameters: testNativeParameterKey, symbol: "00402000",
		},
	}
	changedTask := payload
	changedTask.TaskID = "223e4567-e89b-42d3-a456-426614174002"
	changes = append(changes, struct {
		name       string
		payload    JobPayload
		jobID      string
		version    string
		parameters string
		symbol     string
	}{
		name: "task ownership", payload: changedTask, jobID: testJobID,
		version:    "12.1.2",
		parameters: testNativeParameterKey, symbol: "00401000",
	})
	changes = append(changes, struct {
		name       string
		payload    JobPayload
		jobID      string
		version    string
		parameters string
		symbol     string
	}{
		name: "separate job", payload: payload,
		jobID: "523e4567-e89b-42d3-a456-426614174005", version: "12.1.2",
		parameters: testNativeParameterKey, symbol: "00401000",
	})
	for _, change := range changes {
		t.Run(change.name, func(t *testing.T) {
			value := nativeResultCacheKey(
				change.payload, change.jobID, change.version,
				change.parameters, change.symbol,
			)
			if value == first {
				t.Fatalf("changed input retained cache key %q", value)
			}
		})
	}
}

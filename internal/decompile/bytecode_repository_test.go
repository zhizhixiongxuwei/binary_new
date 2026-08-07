package decompile

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"testing"

	"binaryscan/internal/bytecode"
	"binaryscan/internal/queue"

	"github.com/DATA-DOG/go-sqlmock"
)

const testBytecodeCacheParameterSHA = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"

func TestBeginBytecodeRunRevalidatesFenceAndRecordsIdentity(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	repository := NewMySQLRepository(db)
	payload, lease, identity, runID := bytecodeRepositoryFixture()

	mock.ExpectBegin()
	expectBytecodeSourceLock(mock, payload, lease)
	expectBytecodeReplayMiss(mock, payload, lease, identity)
	mock.ExpectExec(`(?s)UPDATE analyzer_runs.*worker_replaced.*analyzer_name = \?`).
		WithArgs(
			lease.TaskID, *lease.TaskAttemptID, lease.JobID, identity.EngineName,
		).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`(?s)INSERT INTO analyzer_runs.*cache_identity.*engine_target.*analyzer_parameters_sha256.*cache_parameters_sha256.*reuse_identity_sha256.*'running'`).
		WithArgs(
			runID, lease.TaskID, *lease.TaskAttemptID, lease.JobID, uint64(42),
			identity.EngineName, identity.EngineVersion, lease.Attempt,
			lease.FencingToken, payload.SchemaVersion, payload.Engine.Target,
			identity.AnalyzerParametersSHA, identity.CacheParametersSHA,
			bytecodeReuseContract, identity.ReuseIdentitySHA,
			payload.Target.StorageKey, payload.Target.SHA256,
			payload.Target.SizeBytes, payload.Target.Format,
			payload.Target.Architecture, identity.ReuseIdentitySHA,
		).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

	if err := repository.BeginBytecodeRun(
		context.Background(), lease, payload, runID, identity,
	); err != nil {
		t.Fatal(err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestPublishBytecodeRunRejectsLostFenceBeforeFilesystem(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	repository := NewMySQLRepository(db)
	payload, lease, identity, runID := bytecodeRepositoryFixture()

	mock.ExpectBegin()
	mock.ExpectQuery(`(?s)SELECT 1.*job[.]lease_until > UTC_TIMESTAMP.*run[.]analyzer_name = \?.*run[.]status = \?.*engine_target.*FOR UPDATE`).
		WithArgs(bytecodePublishLeaseArguments(payload, lease, identity, runID, "running")...).
		WillReturnError(sql.ErrNoRows)
	mock.ExpectRollback()
	publisherCalled := false
	err = repository.PublishBytecodeRun(
		context.Background(), lease, payload, runID, identity,
		bytecode.StatusBytecodeOnly, 0,
		func(context.Context) ([]BytecodePublishedResult, func(), error) {
			publisherCalled = true
			return nil, func() {}, nil
		},
	)
	if !errors.Is(err, ErrRequestConflict) || publisherCalled {
		t.Fatalf("PublishBytecodeRun() error=%v publisher=%v", err, publisherCalled)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestPublishBytecodeRunCleansReadableArtifactWhenLeaseExpires(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	repository := NewMySQLRepository(db)
	payload, lease, identity, runID := bytecodeRepositoryFixture()
	value := BytecodePublishedResult{
		SymbolKey: "class:A", Language: "java-bytecode", Status: "bytecode_only",
		SHA256: testBytecodeParameterSHA, SizeBytes: 32,
		Diagnostics: json.RawMessage(
			`{"symbol_kind":"class","display_name":"A","methods":[]}`,
		),
	}
	value.ID = bytecodeResultID(runID, value.SymbolKey)
	value.StorageKey = "decompile/" + value.ID + "/bytecode.json"
	expectedCache := bytecodeResultCacheKey(payload, lease.JobID, identity, value.SymbolKey)

	mock.ExpectBegin()
	mock.ExpectQuery(`(?s)SELECT 1.*run[.]status = \?.*FOR UPDATE`).
		WithArgs(bytecodePublishLeaseArguments(payload, lease, identity, runID, "running")...).
		WillReturnRows(sqlmock.NewRows([]string{"marker"}).AddRow(1))
	mock.ExpectExec(`(?s)INSERT INTO decompile_results`).
		WithArgs(
			value.ID, lease.TaskID, uint64(42), runID, expectedCache,
			value.SymbolKey, value.Language, identity.EngineName,
			identity.EngineVersion, value.Status, value.StorageKey, value.SHA256,
			value.SizeBytes, []byte(value.Diagnostics),
		).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`(?s)UPDATE analyzer_runs.*parameters_json = JSON_SET.*result_status`).
		WithArgs(
			"succeeded", 0, string(bytecode.StatusBytecodeOnly),
			1, runID, lease.TaskID, lease.JobID,
		).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectQuery(`(?s)SELECT 1.*run[.]status = \?`).
		WithArgs(bytecodePublishLeaseArguments(payload, lease, identity, runID, "succeeded")...).
		WillReturnError(sql.ErrNoRows)
	mock.ExpectRollback()
	cleanupCalls := 0
	err = repository.PublishBytecodeRun(
		context.Background(), lease, payload, runID, identity,
		bytecode.StatusBytecodeOnly, 0,
		func(context.Context) ([]BytecodePublishedResult, func(), error) {
			return []BytecodePublishedResult{value}, func() { cleanupCalls++ }, nil
		},
	)
	if !errors.Is(err, ErrRequestConflict) || cleanupCalls != 1 {
		t.Fatalf("PublishBytecodeRun() error=%v cleanup=%d", err, cleanupCalls)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestPublishBytecodeRunCommitsFencedReadableResult(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	repository := NewMySQLRepository(db)
	payload, lease, identity, runID := bytecodeRepositoryFixture()
	value := BytecodePublishedResult{
		SymbolKey: "class:A", Language: "java", Status: "complete",
		SHA256: testBytecodeParameterSHA, SizeBytes: 19,
		Diagnostics: json.RawMessage(
			`{"symbol_kind":"class","display_name":"A","methods":[]}`,
		),
	}
	value.ID = bytecodeResultID(runID, value.SymbolKey)
	value.StorageKey = "decompile/" + value.ID + "/source.java"

	mock.ExpectBegin()
	mock.ExpectQuery(`(?s)SELECT 1.*run[.]status = \?.*FOR UPDATE`).
		WithArgs(bytecodePublishLeaseArguments(payload, lease, identity, runID, "running")...).
		WillReturnRows(sqlmock.NewRows([]string{"marker"}).AddRow(1))
	mock.ExpectExec(`(?s)INSERT INTO decompile_results`).
		WithArgs(
			value.ID, lease.TaskID, uint64(42), runID,
			bytecodeResultCacheKey(payload, lease.JobID, identity, value.SymbolKey),
			value.SymbolKey, value.Language, identity.EngineName,
			identity.EngineVersion, value.Status, value.StorageKey, value.SHA256,
			value.SizeBytes, []byte(value.Diagnostics),
		).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`(?s)UPDATE analyzer_runs.*parameters_json = JSON_SET.*result_status`).
		WithArgs(
			"succeeded", 0, string(bytecode.StatusComplete),
			1, runID, lease.TaskID, lease.JobID,
		).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectQuery(`(?s)SELECT 1.*run[.]status = \?`).
		WithArgs(bytecodePublishLeaseArguments(payload, lease, identity, runID, "succeeded")...).
		WillReturnRows(sqlmock.NewRows([]string{"marker"}).AddRow(1))
	mock.ExpectCommit()
	cleanupCalls := 0
	err = repository.PublishBytecodeRun(
		context.Background(), lease, payload, runID, identity,
		bytecode.StatusComplete, 0,
		func(context.Context) ([]BytecodePublishedResult, func(), error) {
			return []BytecodePublishedResult{value}, func() { cleanupCalls++ }, nil
		},
	)
	if err != nil || cleanupCalls != 0 {
		t.Fatalf("PublishBytecodeRun() error=%v cleanup=%d", err, cleanupCalls)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestBytecodePublicationStatusPreservesPartialAndBytecodeOnly(t *testing.T) {
	runID := "723e4567-e89b-42d3-a456-426614174007"
	readable := BytecodePublishedResult{
		SymbolKey: "class:A", Language: "java-bytecode", Status: "bytecode_only",
		SHA256: testBytecodeParameterSHA, SizeBytes: 4,
		Diagnostics: json.RawMessage(`{"methods":[]}`),
	}
	readable.ID = bytecodeResultID(runID, readable.SymbolKey)
	readable.StorageKey = "decompile/" + readable.ID + "/bytecode.json"
	failed := BytecodePublishedResult{
		SymbolKey: "class:B", Language: "java", Status: "failed",
		Diagnostics: json.RawMessage(`{"class_errors":[{"code":"bad"}]}`),
	}
	failed.ID = bytecodeResultID(runID, failed.SymbolKey)
	if !validBytecodePublishedResult(runID, readable) ||
		!validBytecodePublishedResult(runID, failed) ||
		!validBytecodePublicationStatus(
			bytecode.StatusPartial, []BytecodePublishedResult{readable, failed},
		) {
		t.Fatal("valid bytecode-only partial publication was rejected")
	}
	if !validBytecodePublicationStatus(
		bytecode.StatusPartial, []BytecodePublishedResult{failed},
	) {
		t.Fatal("failure-only partial publication was rejected")
	}
}

func TestBytecodePublishedResultRejectsInvalidUTF8Metadata(t *testing.T) {
	runID := "723e4567-e89b-42d3-a456-426614174007"
	baseline := BytecodePublishedResult{
		SymbolKey: "class:A", Language: "java", Status: "complete",
		SHA256: testBytecodeParameterSHA, SizeBytes: 4,
		Diagnostics: json.RawMessage(`{"methods":[]}`),
	}
	baseline.ID = bytecodeResultID(runID, baseline.SymbolKey)
	baseline.StorageKey = "decompile/" + baseline.ID + "/source.java"
	if !validBytecodePublishedResult(runID, baseline) {
		t.Fatal("valid bytecode result was rejected")
	}
	invalidSymbol := baseline
	invalidSymbol.SymbolKey = "class:\x00A"
	invalidSymbol.ID = bytecodeResultID(runID, invalidSymbol.SymbolKey)
	invalidSymbol.StorageKey = "decompile/" + invalidSymbol.ID + "/source.java"
	if validBytecodePublishedResult(runID, invalidSymbol) {
		t.Fatal("NUL bytecode symbol was accepted")
	}
	invalidDiagnostics := baseline
	invalidDiagnostics.Diagnostics = json.RawMessage{'{', '"', 'x', '"', ':', '"', 0xff, '"', '}'}
	if validBytecodePublishedResult(runID, invalidDiagnostics) {
		t.Fatal("invalid UTF-8 bytecode diagnostics were accepted")
	}
}

func TestFailBytecodeRunRequiresUnexpiredExactLease(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	repository := NewMySQLRepository(db)
	_, lease, _, runID := bytecodeRepositoryFixture()
	mock.ExpectExec(`(?s)UPDATE analyzer_runs run.*run[.]task_attempt_id = \?.*job[.]lease_until > UTC_TIMESTAMP`).
		WithArgs(
			"bytecode_output_invalid", "Bytecode decompilation failed.",
			runID, lease.TaskID, *lease.TaskAttemptID, lease.JobID,
			lease.Owner, lease.FencingToken,
		).
		WillReturnResult(sqlmock.NewResult(0, 0))
	err = repository.FailBytecodeRun(
		context.Background(), lease, runID, "bytecode_output_invalid",
		"Bytecode decompilation failed.",
	)
	if !errors.Is(err, ErrRequestConflict) {
		t.Fatalf("FailBytecodeRun() error = %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func bytecodeRepositoryFixture() (
	JobPayload,
	queue.Lease,
	BytecodeRunIdentity,
	string,
) {
	payload := decompilePayload(decompileCreateRecord())
	payload.Target.Class = TargetBytecode
	payload.Target.Format = "java-class"
	payload.Target.Architecture = ""
	payload.Engine = JobEngine{
		Target: EngineVineflower, WorkerKind: TargetBytecode,
	}
	raw, _ := json.Marshal(payload)
	attemptID := uint64(11)
	lease := queue.Lease{
		JobID: testJobID, TaskID: testTaskID, TaskAttemptID: &attemptID,
		Kind: queue.KindDecompile, Payload: raw, Attempt: 1, MaxAttempts: 3,
		FencingToken: 2, Owner: "bytecode-test",
	}
	identity := BytecodeRunIdentity{
		EngineName: "jvm-fallback", EngineVersion: "1.0.0",
		AnalyzerParametersSHA: testBytecodeParameterSHA,
		CacheParametersSHA:    testBytecodeCacheParameterSHA,
		ReuseIdentitySHA:      "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
	}
	return payload, lease, identity, "623e4567-e89b-42d3-a456-426614174006"
}

func expectBytecodeSourceLock(
	mock sqlmock.Sqlmock,
	payload JobPayload,
	lease queue.Lease,
) {
	mock.ExpectQuery(`(?s)SELECT node[.]storage_key.*COALESCE\(node[.]architecture, ''\).*FROM jobs job.*job[.]lease_until > UTC_TIMESTAMP.*FOR UPDATE`).
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
}

func expectBytecodeReplayMiss(
	mock sqlmock.Sqlmock,
	payload JobPayload,
	lease queue.Lease,
	identity BytecodeRunIdentity,
) {
	mock.ExpectQuery(`(?s)SELECT COALESCE.*FROM analyzer_runs run.*run[.]cache_identity`).
		WithArgs(
			lease.TaskID, *lease.TaskAttemptID, lease.JobID, uint64(42),
			identity.EngineName, identity.EngineVersion,
			identity.ReuseIdentitySHA, payload.Engine.Target,
			identity.AnalyzerParametersSHA, identity.CacheParametersSHA,
			identity.ReuseIdentitySHA,
			payload.Target.SHA256, "4096", payload.Target.Format,
			payload.Target.Architecture, payload.Limits.MaxArtifacts,
		).
		WillReturnRows(sqlmock.NewRows([]string{"status"}).AddRow(""))
}

func bytecodePublishLeaseArguments(
	payload JobPayload,
	lease queue.Lease,
	identity BytecodeRunIdentity,
	runID string,
	runStatus string,
) []driver.Value {
	return []driver.Value{
		runID, lease.JobID, lease.TaskID, *lease.TaskAttemptID,
		lease.Owner, lease.FencingToken, uint64(42), identity.EngineName,
		identity.EngineVersion, identity.ReuseIdentitySHA, runStatus,
		"1", "2", payload.Engine.Target,
		identity.AnalyzerParametersSHA, identity.CacheParametersSHA,
		identity.ReuseIdentitySHA,
		payload.Target.StorageKey, payload.Target.SHA256, "4096",
		payload.Target.Format, payload.Target.Architecture,
	}
}

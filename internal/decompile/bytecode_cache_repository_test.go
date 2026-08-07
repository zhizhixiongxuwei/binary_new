package decompile

import (
	"context"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"binaryscan/internal/bytecode"

	"github.com/DATA-DOG/go-sqlmock"
)

func TestFindBytecodeCacheReturnsOnlyBoundCompleteSet(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	repository := NewMySQLRepository(db)
	payload, lease, identity, runID := bytecodeRepositoryFixture()
	candidate := bytecodeRepositoryCacheCandidate()

	mock.ExpectQuery(`(?s)SELECT source_run[.]id.*source_run[.]cache_identity = current_run[.]cache_identity.*source_task[.]sample_expires_at > UTC_TIMESTAMP.*result_count.*LIMIT 1`).
		WithArgs(
			runID, lease.JobID, lease.TaskID, *lease.TaskAttemptID,
			lease.Owner, lease.FencingToken, uint64(42), identity.EngineName,
			identity.EngineVersion, identity.ReuseIdentitySHA,
			identity.AnalyzerParametersSHA, identity.CacheParametersSHA,
			identity.ReuseIdentitySHA, bytecodeReuseContract,
			payload.Engine.Target, payload.Target.SHA256, "4096",
			payload.Target.Format, payload.Target.Architecture,
			payload.Limits.MaxArtifacts,
			maxBytecodeDiagnosticsBytes, payload.Limits.MaxOutputBytes,
			maxBytecodeCacheDiagnosticsBytes,
		).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "task_id", "result_status",
		}).AddRow(candidate.RunID, candidate.TaskID, string(candidate.ResultStatus)))
	mock.ExpectQuery(`(?s)SELECT result[.]id.*FROM decompile_results result.*ORDER BY CAST\(result[.]symbol_key AS BINARY\), result[.]id`).
		WithArgs(
			candidate.TaskID, candidate.RunID, payload.Limits.MaxOutputBytes,
			maxBytecodeDiagnosticsBytes, bytecodeCacheResultLimit(payload.Limits)+1,
		).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "symbol_key", "language", "status", "storage_key",
			"content_sha256", "size_bytes", "diagnostics_json",
		}).AddRow(
			candidate.Results[0].ID, candidate.Results[0].SymbolKey,
			candidate.Results[0].Language, candidate.Results[0].Status,
			candidate.Results[0].StorageKey, candidate.Results[0].SHA256,
			candidate.Results[0].SizeBytes, []byte(candidate.Results[0].Diagnostics),
		))

	value, found, err := repository.FindBytecodeCache(
		context.Background(), lease, payload, runID, identity,
	)
	if err != nil || !found || !sameBytecodeCacheCandidate(candidate, value) {
		t.Fatalf("FindBytecodeCache() = (%#v, %v, %v)", value, found, err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestPublishBytecodeCacheHitRejectsCandidateDeletionRace(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	repository := NewMySQLRepository(db)
	payload, lease, identity, runID := bytecodeRepositoryFixture()
	candidate := bytecodeRepositoryCacheCandidate()
	results := bytecodeRepositoryCachePublication(runID, candidate)

	mock.ExpectBegin()
	mock.ExpectQuery(`(?s)SELECT 1.*run[.]cache_identity = \?.*run[.]status = \?.*FOR UPDATE`).
		WithArgs(bytecodePublishLeaseArguments(
			payload, lease, identity, runID, "running",
		)...).
		WillReturnRows(sqlmock.NewRows([]string{"marker"}).AddRow(1))
	mock.ExpectQuery(`(?s)SELECT JSON_UNQUOTE.*FROM analyzer_runs run.*task[.]sample_expires_at > UTC_TIMESTAMP.*FOR SHARE`).
		WithArgs(bytecodeCacheLockArguments(payload, identity, candidate)...).
		WillReturnRows(bytecodeCacheLockedRows())
	mock.ExpectRollback()

	err = repository.PublishBytecodeCacheHit(
		context.Background(), lease, payload, runID, identity, candidate, results,
	)
	if !errors.Is(err, errBytecodeCacheStale) {
		t.Fatalf("PublishBytecodeCacheHit() error = %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestPublishBytecodeCacheHitCommitsPrivateVerifiedRows(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	repository := NewMySQLRepository(db)
	payload, lease, identity, runID := bytecodeRepositoryFixture()
	candidate := bytecodeRepositoryCacheCandidate()
	results := bytecodeRepositoryCachePublication(runID, candidate)

	mock.ExpectBegin()
	mock.ExpectQuery(`(?s)SELECT 1.*run[.]cache_identity = \?.*run[.]status = \?.*FOR UPDATE`).
		WithArgs(bytecodePublishLeaseArguments(
			payload, lease, identity, runID, "running",
		)...).
		WillReturnRows(sqlmock.NewRows([]string{"marker"}).AddRow(1))
	lockedRows := bytecodeCacheLockedRows().AddRow(
		string(candidate.ResultStatus), candidate.Results[0].ID,
		candidate.Results[0].SymbolKey, candidate.Results[0].Language,
		candidate.Results[0].Status, candidate.Results[0].StorageKey,
		candidate.Results[0].SHA256, candidate.Results[0].SizeBytes,
		[]byte(candidate.Results[0].Diagnostics),
	)
	mock.ExpectQuery(`(?s)SELECT JSON_UNQUOTE.*FROM analyzer_runs run.*FOR SHARE`).
		WithArgs(bytecodeCacheLockArguments(payload, identity, candidate)...).
		WillReturnRows(lockedRows)
	mock.ExpectExec(`(?s)INSERT INTO decompile_results`).
		WithArgs(
			results[0].ID, lease.TaskID, uint64(42), runID,
			bytecodeResultCacheKey(
				payload, lease.JobID, identity, results[0].SymbolKey,
			),
			results[0].SymbolKey, results[0].Language,
			identity.EngineName, identity.EngineVersion, results[0].Status,
			results[0].StorageKey, results[0].SHA256, results[0].SizeBytes,
			[]byte(results[0].Diagnostics),
		).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`(?s)UPDATE analyzer_runs.*cache_hit.*cache_source_task_id.*cache_copy_mode`).
		WithArgs(
			string(candidate.ResultStatus), 1, candidate.TaskID, candidate.RunID,
			runID, lease.TaskID, lease.JobID,
		).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectQuery(`(?s)SELECT 1.*run[.]cache_identity = \?.*run[.]status = \?`).
		WithArgs(bytecodePublishLeaseArguments(
			payload, lease, identity, runID, "succeeded",
		)...).
		WillReturnRows(sqlmock.NewRows([]string{"marker"}).AddRow(1))
	mock.ExpectCommit()

	if err := repository.PublishBytecodeCacheHit(
		context.Background(), lease, payload, runID, identity, candidate, results,
	); err != nil {
		t.Fatal(err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestBeginBytecodeRunReplaysPriorBytecodeOnlyPublication(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	repository := NewMySQLRepository(db)
	payload, lease, identity, runID := bytecodeRepositoryFixture()

	mock.ExpectBegin()
	expectBytecodeSourceLock(mock, payload, lease)
	mock.ExpectQuery(`(?s)SELECT COALESCE.*FROM analyzer_runs run.*result_status`).
		WithArgs(
			lease.TaskID, *lease.TaskAttemptID, lease.JobID, uint64(42),
			identity.EngineName, identity.EngineVersion,
			identity.ReuseIdentitySHA, payload.Engine.Target,
			identity.AnalyzerParametersSHA, identity.CacheParametersSHA,
			identity.ReuseIdentitySHA,
			payload.Target.SHA256, "4096", payload.Target.Format,
			payload.Target.Architecture, payload.Limits.MaxArtifacts,
		).
		WillReturnRows(sqlmock.NewRows([]string{"status"}).AddRow("bytecode_only"))
	mock.ExpectRollback()

	err = repository.BeginBytecodeRun(
		context.Background(), lease, payload, runID, identity,
	)
	var replay bytecodeAlreadyPublishedError
	if !errors.Is(err, errBytecodeAlreadyPublished) ||
		!errors.As(err, &replay) || replay.status != bytecode.StatusBytecodeOnly {
		t.Fatalf("BeginBytecodeRun() error = %#v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestBytecodeCacheDiagnosticsComparisonIsLosslessAndExact(t *testing.T) {
	baseline := json.RawMessage(`{"value":9007199254740992}`)
	if !jsonEqual(baseline, append(json.RawMessage(nil), baseline...)) {
		t.Fatal("identical cache diagnostics were rejected")
	}
	if jsonEqual(
		baseline,
		json.RawMessage(`{"value":9007199254740993}`),
	) {
		t.Fatal("cache diagnostics comparison lost integer precision")
	}
	if jsonEqual(
		json.RawMessage(`{"a":1,"b":2}`),
		json.RawMessage(`{"b":2,"a":1}`),
	) {
		t.Fatal("cache diagnostics comparison accepted changed source bytes")
	}
}

func bytecodeRepositoryCacheCandidate() BytecodeCacheCandidate {
	return BytecodeCacheCandidate{
		RunID: testCacheSourceRunID, TaskID: testCacheSourceTaskID,
		ResultStatus: bytecode.StatusComplete,
		Results: []BytecodeCachedResult{{
			ID: testCacheSourceResult, SymbolKey: "class:A", Language: "java",
			Status:     "complete",
			StorageKey: "decompile/" + testCacheSourceResult + "/source.java",
			SHA256:     strings.Repeat("a", 64), SizeBytes: 32,
			Diagnostics: json.RawMessage(`{"methods":[]}`),
		}},
	}
}

func bytecodeRepositoryCachePublication(
	runID string,
	candidate BytecodeCacheCandidate,
) []BytecodePublishedResult {
	cached := candidate.Results[0]
	id := bytecodeResultID(runID, cached.SymbolKey)
	return []BytecodePublishedResult{{
		ID: id, SymbolKey: cached.SymbolKey, Language: cached.Language,
		Status: cached.Status, StorageKey: "decompile/" + id + "/source.java",
		SHA256: cached.SHA256, SizeBytes: cached.SizeBytes,
		Diagnostics: append([]byte(nil), cached.Diagnostics...),
	}}
}

func bytecodeCacheLockArguments(
	payload JobPayload,
	identity BytecodeRunIdentity,
	candidate BytecodeCacheCandidate,
) []driver.Value {
	return []driver.Value{
		candidate.RunID, candidate.TaskID, identity.EngineName,
		identity.EngineVersion, identity.ReuseIdentitySHA,
		identity.AnalyzerParametersSHA, identity.CacheParametersSHA,
		identity.ReuseIdentitySHA, bytecodeReuseContract,
		payload.Engine.Target, payload.Target.SHA256, "4096",
		payload.Target.Format, payload.Target.Architecture, 1, 1,
		maxBytecodeDiagnosticsBytes, payload.Limits.MaxOutputBytes,
		maxBytecodeCacheDiagnosticsBytes, maxBytecodeDiagnosticsBytes,
	}
}

func bytecodeCacheLockedRows() *sqlmock.Rows {
	return sqlmock.NewRows([]string{
		"result_status", "id", "symbol_key", "language", "status",
		"storage_key", "content_sha256", "size_bytes", "diagnostics_json",
	})
}

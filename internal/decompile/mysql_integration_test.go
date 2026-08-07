package decompile

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"binaryscan/internal/bytecode"
	"binaryscan/internal/database"
	"binaryscan/internal/queue"
	taskdomain "binaryscan/internal/task"

	"github.com/go-sql-driver/mysql"
)

const decompileIntegrationDSNFile = "BINARYSCAN_DECOMPILE_INTEGRATION_DSN_FILE"

type decompileIntegrationFixture struct {
	userID     uint64
	blobID     uint64
	uploadID   string
	taskID     string
	attemptID  uint64
	nodeID     uint64
	jobID      string
	storageKey string
	sha256     string
	sizeBytes  uint64
}

type decompileIntegrationTarget struct {
	filename     string
	format       string
	mimeType     string
	architecture string
	payload      []byte
}

type countingBytecodeAnalyzer struct {
	delegate BytecodeAnalyzer
	calls    int
}

func (analyzer *countingBytecodeAnalyzer) Analyze(
	ctx context.Context,
	request bytecode.Request,
) (bytecode.Result, error) {
	analyzer.calls++
	return analyzer.delegate.Analyze(ctx, request)
}

func (analyzer *countingBytecodeAnalyzer) Identity() BytecodeAnalyzerIdentity {
	return analyzer.delegate.Identity()
}

func openDecompileIntegrationDatabase(t *testing.T) *sql.DB {
	t.Helper()
	dsnPath := strings.TrimSpace(os.Getenv(decompileIntegrationDSNFile))
	if dsnPath == "" {
		t.Skip(decompileIntegrationDSNFile + " is not set")
	}
	rawDSN, err := os.ReadFile(dsnPath)
	if err != nil {
		t.Fatalf("read integration DSN: %v", err)
	}
	driverConfig, err := mysql.ParseDSN(strings.TrimSpace(string(rawDSN)))
	if err != nil {
		t.Fatalf("parse integration DSN: %v", err)
	}
	driverConfig.ParseTime = true
	driverConfig.Loc = time.UTC
	db, err := sql.Open("mysql", driverConfig.FormatDSN())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Logf("close integration database: %v", err)
		}
	})
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := database.Migrate(ctx, db); err != nil {
		t.Fatalf("migrate integration database: %v", err)
	}
	return db
}

func TestMySQLDecompileRequestIntegration(t *testing.T) {
	db := openDecompileIntegrationDatabase(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	fixture := seedDecompileIntegrationFixture(t, ctx, db)
	t.Cleanup(func() {
		cleanupDecompileIntegrationFixture(t, db, fixture)
	})
	repository := NewMySQLRepository(db)
	record := CreateRecord{
		JobID:        fixture.jobID,
		RequestID:    decompileIntegrationUUID(t),
		TaskID:       fixture.taskID,
		FileNodeID:   fixture.nodeID,
		UserID:       fixture.userID,
		EngineTarget: EngineAuto,
		Options:      []byte(`{"analysis_mode":"default"}`),
		Limits:       defaultJobLimits,
		JobRequestKey: "decompile:" +
			strings.Repeat("a", 64),
	}
	created, first, err := repository.Enqueue(ctx, record)
	if err != nil {
		t.Fatal(err)
	}
	if !first ||
		created.JobID != fixture.jobID ||
		created.TargetClass != TargetNative ||
		created.EngineTarget != EngineGhidra ||
		created.Status != "queued" {
		t.Fatalf("created decompile request = (%+v, %v)", created, first)
	}

	queueService, err := queue.NewService(
		queue.NewMySQLRepository(db),
		queue.Config{
			LeaseDuration:   time.Minute,
			RetryDelay:      time.Second,
			SampleRetention: taskdomain.DefaultSampleRetention,
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := queueService.ConfigureResourceLimits(ctx); err != nil {
		t.Fatal(err)
	}
	lease, found, err := queueService.ClaimDecompileWorker(
		ctx,
		queue.KindNative,
		"decompile-integration-worker",
	)
	if err != nil || !found || lease.JobID != fixture.jobID {
		t.Fatalf("claim decompile request = (%+v, %v, %v)", lease, found, err)
	}
	if lease.TaskAttemptID == nil || *lease.TaskAttemptID != fixture.attemptID {
		t.Fatalf(
			"decompile lease task attempt = %v, want %d",
			lease.TaskAttemptID, fixture.attemptID,
		)
	}

	replayRecord := record
	replayRecord.JobID = decompileIntegrationUUID(t)
	replayRecord.RequestID = decompileIntegrationUUID(t)
	replayed, replayCreated, err := repository.Enqueue(ctx, replayRecord)
	if err != nil {
		t.Fatal(err)
	}
	if replayCreated ||
		replayed.JobID != fixture.jobID ||
		replayed.RequestID != record.RequestID ||
		replayed.Status != "leased" {
		t.Fatalf("leased decompile replay = (%+v, %v)", replayed, replayCreated)
	}
	if err := queueService.Start(ctx, lease); err != nil {
		t.Fatal(err)
	}
	if err := queueService.Finish(ctx, lease, queue.FinishInput{
		Outcome:      queue.OutcomeDeterministicFailure,
		ErrorCode:    "integration_fixture",
		ErrorMessage: "No decompiler is executed by this integration fixture.",
	}); err != nil {
		t.Fatal(err)
	}

	var jobCount int
	var eventCount int
	if err := db.QueryRowContext(ctx, `
SELECT
    (SELECT COUNT(*) FROM jobs
     WHERE task_id = ? AND kind = 'decompile'),
    (SELECT COUNT(*) FROM task_events
     WHERE task_id = ? AND event_type = 'decompile.queued')`,
		fixture.taskID,
		fixture.taskID,
	).Scan(&jobCount, &eventCount); err != nil {
		t.Fatal(err)
	}
	if jobCount != 1 || eventCount != 1 {
		t.Fatalf("decompile job/event counts = %d/%d", jobCount, eventCount)
	}

	if _, err := db.ExecContext(ctx, `
UPDATE tasks
SET sample_expires_at = UTC_TIMESTAMP(6)
WHERE id = ?`, fixture.taskID); err != nil {
		t.Fatal(err)
	}
	expiredRecord := record
	expiredRecord.JobID = decompileIntegrationUUID(t)
	expiredRecord.RequestID = decompileIntegrationUUID(t)
	expiredRecord.JobRequestKey = "decompile:" + strings.Repeat("b", 64)
	if _, _, err := repository.Enqueue(
		ctx,
		expiredRecord,
	); !errors.Is(err, ErrSampleUnavailable) {
		t.Fatalf("expired decompile request error = %v", err)
	}
}

func TestMySQLBytecodeProcessorIntegration(t *testing.T) {
	db := openDecompileIntegrationDatabase(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	classPayload := decompileIntegrationClass(t, "sample/WorkerFixture", "inspect")
	fixture := seedDecompileIntegrationTarget(t, ctx, db, decompileIntegrationTarget{
		filename: "WorkerFixture.class", format: "java-class",
		mimeType: "application/java-vm", architecture: "unknown",
		payload: classPayload,
	})
	t.Cleanup(func() {
		cleanupDecompileIntegrationFixture(t, db, fixture)
	})

	repositoryRoot := t.TempDir()
	workRoot := t.TempDir()
	sourcePath := filepath.Join(repositoryRoot, filepath.FromSlash(fixture.storageKey))
	if err := os.MkdirAll(filepath.Dir(sourcePath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(sourcePath, classPayload, 0o600); err != nil {
		t.Fatal(err)
	}

	repository := NewMySQLRepository(db)
	created, first, err := repository.Enqueue(ctx, CreateRecord{
		JobID: fixture.jobID, RequestID: decompileIntegrationUUID(t),
		TaskID: fixture.taskID, FileNodeID: fixture.nodeID,
		UserID: fixture.userID, EngineTarget: EngineAuto,
		Options: []byte(`{}`), Limits: defaultJobLimits,
		JobRequestKey: "decompile:" + strings.Repeat("c", 64),
	})
	if err != nil {
		t.Fatal(err)
	}
	if !first || created.TargetClass != TargetBytecode ||
		created.EngineTarget != EngineVineflower {
		t.Fatalf("created bytecode request = (%+v, %v)", created, first)
	}

	queueService, err := queue.NewService(
		queue.NewMySQLRepository(db),
		queue.Config{
			LeaseDuration: time.Minute, RetryDelay: time.Second,
			SampleRetention: taskdomain.DefaultSampleRetention,
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := queueService.ConfigureResourceLimits(ctx); err != nil {
		t.Fatal(err)
	}
	lease, found, err := queueService.ClaimDecompileWorker(
		ctx, queue.KindBytecode, "bytecode-integration-worker",
	)
	if err != nil || !found || lease.JobID != fixture.jobID {
		t.Fatalf("claim bytecode request = (%+v, %v, %v)", lease, found, err)
	}
	if err := queueService.Start(ctx, lease); err != nil {
		t.Fatal(err)
	}

	engine, err := bytecode.NewJVMFallbackEngine(bytecode.JVMEngineConfig{})
	if err != nil {
		t.Fatal(err)
	}
	analyzer, err := NewEngineBytecodeAnalyzer(
		engine, engine.ConfigFingerprint(), nil, []string{EngineVineflower},
	)
	if err != nil {
		t.Fatal(err)
	}
	countingAnalyzer := &countingBytecodeAnalyzer{delegate: analyzer}
	validator, err := bytecode.NewFileArtifactValidator(nil)
	if err != nil {
		t.Fatal(err)
	}
	processor, err := NewBytecodeProcessor(
		repository, countingAnalyzer, queueService,
		BytecodeProcessorConfig{
			RepositoryRoot: repositoryRoot, TaskWorkRoot: workRoot,
			EngineName:        engine.Descriptor().Name,
			EngineVersion:     engine.Descriptor().Version,
			ArtifactValidator: validator,
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	finish, err := processor.Process(ctx, lease)
	if err != nil {
		t.Fatal(err)
	}
	if finish.Outcome != queue.OutcomePartialSucceeded || finish.ErrorCode != "" {
		t.Fatalf("bytecode finish = %+v", finish)
	}
	if err := queueService.Finish(ctx, lease, finish); err != nil {
		t.Fatal(err)
	}

	var resultID, runID, runStatus, resultStatus, jobStatus, persistedStatus string
	var language, storageKey, contentSHA string
	var sizeBytes uint64
	var diagnostics []byte
	err = db.QueryRowContext(ctx, `
SELECT result.id, run.id, run.status,
       JSON_UNQUOTE(JSON_EXTRACT(run.parameters_json, '$.result_status')),
       job.status, result.status, result.language, result.storage_key,
       result.content_sha256, result.size_bytes, result.diagnostics_json
FROM analyzer_runs run
JOIN jobs job ON job.id = run.job_id
JOIN decompile_results result ON result.analyzer_run_id = run.id
WHERE run.task_id = ? AND run.job_id = ?`, fixture.taskID, fixture.jobID).Scan(
		&resultID, &runID, &runStatus, &resultStatus, &jobStatus, &persistedStatus,
		&language, &storageKey, &contentSHA, &sizeBytes, &diagnostics,
	)
	if err != nil {
		t.Fatal(err)
	}
	if runStatus != "succeeded" || resultStatus != "bytecode_only" ||
		jobStatus != "succeeded" || persistedStatus != "bytecode_only" ||
		language != "java-bytecode" || storageKey == "" ||
		!sha256Pattern.MatchString(contentSHA) || sizeBytes == 0 ||
		!json.Valid(diagnostics) {
		t.Fatalf(
			"published bytecode row = run=%q result=%q job=%q status=%q language=%q key=%q sha=%q size=%d diagnostics=%q",
			runStatus, resultStatus, jobStatus, persistedStatus, language,
			storageKey, contentSHA, sizeBytes, diagnostics,
		)
	}
	published, err := os.ReadFile(filepath.Join(
		repositoryRoot, filepath.FromSlash(storageKey),
	))
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(published)
	if uint64(len(published)) != sizeBytes ||
		hex.EncodeToString(digest[:]) != contentSHA || !json.Valid(published) ||
		!bytes.Contains(published, []byte(`"bytecode_hex":"b1"`)) {
		t.Fatalf("published bytecode artifact is invalid: %q", published)
	}
	service, err := NewService(repository, Config{RepositoryRoot: repositoryRoot})
	if err != nil {
		t.Fatal(err)
	}
	page, err := service.List(ctx, ListQuery{
		TaskID: fixture.taskID, PageSize: 10,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Items) != 1 || page.Items[0].ID != resultID ||
		page.Items[0].Status != "bytecode_only" ||
		page.Items[0].Language != "java-bytecode" ||
		page.Items[0].SymbolKind != "class" ||
		page.Items[0].DisplayName != "sample.WorkerFixture" {
		t.Fatalf("bytecode consumer page = %#v", page)
	}
	var presentation struct {
		Methods []bytecode.MethodIndex `json:"methods"`
	}
	if err := json.Unmarshal(page.Items[0].Diagnostics, &presentation); err != nil ||
		len(presentation.Methods) != 1 ||
		presentation.Methods[0].Name != "inspect" ||
		presentation.Methods[0].Descriptor != "()V" ||
		presentation.Methods[0].Bytecode == nil ||
		presentation.Methods[0].Bytecode.SizeBytes != 1 {
		t.Fatalf("bytecode consumer diagnostics = %s", page.Items[0].Diagnostics)
	}
	chunk, err := service.Source(ctx, SourceQuery{
		TaskID: fixture.taskID, ResultID: resultID, Limit: MaxSourceLimit,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !chunk.Complete || chunk.Offset != 0 || chunk.NextOffset != nil ||
		chunk.SHA256 != contentSHA || chunk.SizeBytes != sizeBytes ||
		chunk.Content != string(published) {
		t.Fatalf("bytecode consumer source = %#v", chunk)
	}

	cacheFixture := seedDecompileIntegrationCacheConsumer(
		t, ctx, db, fixture, decompileIntegrationTarget{
			filename: "WorkerFixture-copy.class", format: "java-class",
			mimeType: "application/java-vm", architecture: "unknown",
			payload: classPayload,
		},
	)
	t.Cleanup(func() {
		cleanupDecompileIntegrationCacheConsumer(t, db, cacheFixture)
	})
	cacheRequest, cacheCreated, err := repository.Enqueue(ctx, CreateRecord{
		JobID: cacheFixture.jobID, RequestID: decompileIntegrationUUID(t),
		TaskID: cacheFixture.taskID, FileNodeID: cacheFixture.nodeID,
		UserID: cacheFixture.userID, EngineTarget: EngineAuto,
		Options: []byte(`{}`), Limits: defaultJobLimits,
		JobRequestKey: "decompile:" + strings.Repeat("d", 64),
	})
	if err != nil || !cacheCreated || cacheRequest.TargetClass != TargetBytecode {
		t.Fatalf("enqueue cache consumer = (%+v, %v, %v)", cacheRequest, cacheCreated, err)
	}
	cacheLease, found, err := queueService.ClaimDecompileWorker(
		ctx, queue.KindBytecode, "bytecode-cache-integration-worker",
	)
	if err != nil || !found || cacheLease.JobID != cacheFixture.jobID {
		t.Fatalf("claim cache consumer = (%+v, %v, %v)", cacheLease, found, err)
	}
	if err := queueService.Start(ctx, cacheLease); err != nil {
		t.Fatal(err)
	}
	cacheFinish, err := processor.Process(ctx, cacheLease)
	if err != nil || cacheFinish.Outcome != queue.OutcomePartialSucceeded {
		t.Fatalf("cached bytecode finish = (%+v, %v)", cacheFinish, err)
	}
	if countingAnalyzer.calls != 1 {
		t.Fatalf("bytecode analyzer calls after cache hit = %d, want 1", countingAnalyzer.calls)
	}
	if err := queueService.Finish(ctx, cacheLease, cacheFinish); err != nil {
		t.Fatal(err)
	}
	var cachedResultID, cachedStorageKey, cachedSHA string
	var cacheHit bool
	var cacheSourceTaskID, cacheSourceRunID string
	err = db.QueryRowContext(ctx, `
SELECT result.id, result.storage_key, result.content_sha256,
       CAST(JSON_EXTRACT(run.parameters_json, '$.cache_hit') AS UNSIGNED),
       JSON_UNQUOTE(JSON_EXTRACT(
           run.parameters_json, '$.cache_source_task_id'
       )),
       JSON_UNQUOTE(JSON_EXTRACT(
           run.parameters_json, '$.cache_source_run_id'
       ))
FROM analyzer_runs run
JOIN decompile_results result ON result.analyzer_run_id = run.id
WHERE run.task_id = ? AND run.job_id = ?`,
		cacheFixture.taskID, cacheFixture.jobID,
	).Scan(
		&cachedResultID, &cachedStorageKey, &cachedSHA, &cacheHit,
		&cacheSourceTaskID, &cacheSourceRunID,
	)
	if err != nil {
		t.Fatal(err)
	}
	if !cacheHit || cacheSourceTaskID != fixture.taskID ||
		cacheSourceRunID != runID || cachedStorageKey == storageKey ||
		cachedSHA != contentSHA {
		t.Fatalf(
			"cache audit = hit=%v source=(%q,%q) result=%q key=%q sha=%q",
			cacheHit, cacheSourceTaskID, cacheSourceRunID, cachedResultID,
			cachedStorageKey, cachedSHA,
		)
	}
	if _, err := db.ExecContext(ctx, `
UPDATE tasks SET sample_deleted_at = UTC_TIMESTAMP(6) WHERE id = ?`,
		fixture.taskID,
	); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `
UPDATE decompile_results
SET storage_key = NULL, content_sha256 = NULL, size_bytes = NULL
WHERE task_id = ?`, fixture.taskID); err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(filepath.Dir(filepath.Join(
		repositoryRoot, filepath.FromSlash(storageKey),
	))); err != nil {
		t.Fatal(err)
	}
	cachedChunk, err := service.Source(ctx, SourceQuery{
		TaskID: cacheFixture.taskID, ResultID: cachedResultID,
		Limit: MaxSourceLimit,
	})
	if err != nil || !cachedChunk.Complete || cachedChunk.SHA256 != cachedSHA ||
		cachedChunk.Content != string(published) {
		t.Fatalf("cached result after source expiry = (%#v, %v)", cachedChunk, err)
	}
}

func seedDecompileIntegrationFixture(
	t *testing.T,
	ctx context.Context,
	db *sql.DB,
) decompileIntegrationFixture {
	t.Helper()
	return seedDecompileIntegrationTarget(t, ctx, db, decompileIntegrationTarget{
		filename: "fixture.elf", format: "elf64",
		mimeType: "application/x-elf", architecture: "x86_64",
		payload: bytes.Repeat([]byte{0x7f}, 4096),
	})
}

func seedDecompileIntegrationTarget(
	t *testing.T,
	ctx context.Context,
	db *sql.DB,
	target decompileIntegrationTarget,
) decompileIntegrationFixture {
	t.Helper()
	if target.filename == "" || target.format == "" || target.mimeType == "" ||
		target.architecture == "" || len(target.payload) == 0 {
		t.Fatal("decompile integration target is incomplete")
	}
	publicID := decompileIntegrationUUID(t)
	uploadID := decompileIntegrationUUID(t)
	taskID := decompileIntegrationUUID(t)
	jobID := decompileIntegrationUUID(t)
	username := "decompile-" + strings.ReplaceAll(publicID, "-", "")
	result, err := db.ExecContext(ctx, `
INSERT INTO users (
    public_id, username, display_name, password_hash, role, status,
    force_password_change
) VALUES (?, ?, 'Decompile Integration', 'integration-only',
          'operator', 'active', FALSE)`,
		publicID,
		username,
	)
	if err != nil {
		t.Fatalf("seed decompile integration user: %v", err)
	}
	userID, err := result.LastInsertId()
	if err != nil || userID <= 0 {
		t.Fatalf("read decompile integration user ID: %v", err)
	}
	digest := sha256.Sum256(target.payload)
	sha256Value := hex.EncodeToString(digest[:])
	sizeBytes := uint64(len(target.payload))
	storageKey := "blobs/sha256/" + sha256Value[:2] + "/" + sha256Value
	result, err = db.ExecContext(ctx, `
INSERT INTO blobs (
    sha256, size_bytes, storage_key, reference_count, state, verified_at
) VALUES (?, ?, ?, 2, 'available', UTC_TIMESTAMP(6))`,
		sha256Value,
		sizeBytes,
		storageKey,
	)
	if err != nil {
		t.Fatalf("seed decompile integration blob: %v", err)
	}
	blobID, err := result.LastInsertId()
	if err != nil || blobID <= 0 {
		t.Fatalf("read decompile integration blob ID: %v", err)
	}
	if _, err := db.ExecContext(ctx, `
INSERT INTO uploads (
    id, created_by, original_name, display_name, content_type,
    declared_size_bytes, part_size_bytes, expected_sha256, actual_sha256,
    status, blob_id, expires_at, completed_at
) VALUES (?, ?, ?, ?, ?,
          ?, ?, ?, ?, 'completed', ?,
          DATE_ADD(UTC_TIMESTAMP(6), INTERVAL 1 DAY), UTC_TIMESTAMP(6))`,
		uploadID,
		uint64(userID),
		target.filename,
		target.filename,
		target.mimeType,
		sizeBytes,
		sizeBytes,
		sha256Value,
		sha256Value,
		uint64(blobID),
	); err != nil {
		t.Fatalf("seed decompile integration upload: %v", err)
	}
	if _, err := db.ExecContext(ctx, `
INSERT INTO tasks (
    id, upload_id, blob_id, created_by, name, tags, status,
    progress_basis_points, risk_level, limits_snapshot, root_format,
    sample_expires_at, completed_at, event_sequence
) VALUES (?, ?, ?, ?, 'Decompile Integration', JSON_ARRAY(),
          'SUCCEEDED', 10000, 'UNKNOWN',
          JSON_OBJECT(
              'max_upload_bytes', 10737418240,
              'max_expanded_bytes', 53687091200,
              'max_archive_ratio', 100,
              'max_depth', 10,
              'max_file_nodes', 100000,
              'max_nested_images', 10
          ),
          ?, DATE_ADD(UTC_TIMESTAMP(6), INTERVAL 1 DAY),
          UTC_TIMESTAMP(6), 0)`,
		taskID,
		uploadID,
		uint64(blobID),
		uint64(userID),
		target.format,
	); err != nil {
		t.Fatalf("seed decompile integration task: %v", err)
	}
	result, err = db.ExecContext(ctx, `
INSERT INTO task_attempts (
    task_id, attempt_number, fencing_token, status, started_at, completed_at
) VALUES (?, 1, 7, 'succeeded',
          DATE_SUB(UTC_TIMESTAMP(6), INTERVAL 1 SECOND), UTC_TIMESTAMP(6))`,
		taskID,
	)
	if err != nil {
		t.Fatalf("seed decompile integration task attempt: %v", err)
	}
	attemptID, err := result.LastInsertId()
	if err != nil || attemptID <= 0 {
		t.Fatalf("read decompile integration task attempt ID: %v", err)
	}
	pathHash := sha256.Sum256([]byte("/"))
	result, err = db.ExecContext(ctx, `
INSERT INTO file_nodes (
    task_id, parent_id, logical_path, logical_path_hash, display_name,
    node_type, depth, format, mime_type, architecture, size_bytes, sha256,
    storage_key, extraction_status, metadata_json
) VALUES (?, NULL, '/', ?, ?, 'file', 0, ?,
          ?, ?, ?, ?, ?, 'indexed',
          JSON_OBJECT('fixture', TRUE))`,
		taskID,
		pathHash[:],
		target.filename,
		target.format,
		target.mimeType,
		target.architecture,
		sizeBytes,
		sha256Value,
		storageKey,
	)
	if err != nil {
		t.Fatalf("seed decompile integration file node: %v", err)
	}
	nodeID, err := result.LastInsertId()
	if err != nil || nodeID <= 0 {
		t.Fatalf("read decompile integration node ID: %v", err)
	}
	return decompileIntegrationFixture{
		userID:     uint64(userID),
		blobID:     uint64(blobID),
		uploadID:   uploadID,
		taskID:     taskID,
		attemptID:  uint64(attemptID),
		nodeID:     uint64(nodeID),
		jobID:      jobID,
		storageKey: storageKey,
		sha256:     sha256Value,
		sizeBytes:  sizeBytes,
	}
}

func seedDecompileIntegrationCacheConsumer(
	t *testing.T,
	ctx context.Context,
	db *sql.DB,
	source decompileIntegrationFixture,
	target decompileIntegrationTarget,
) decompileIntegrationFixture {
	t.Helper()
	if len(target.payload) == 0 || digestBytes(target.payload) != source.sha256 {
		t.Fatal("cache consumer must reference the identical source bytes")
	}
	uploadID := decompileIntegrationUUID(t)
	taskID := decompileIntegrationUUID(t)
	jobID := decompileIntegrationUUID(t)
	if _, err := db.ExecContext(ctx, `
INSERT INTO uploads (
    id, created_by, original_name, display_name, content_type,
    declared_size_bytes, part_size_bytes, expected_sha256, actual_sha256,
    status, blob_id, expires_at, completed_at
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'completed', ?,
          DATE_ADD(UTC_TIMESTAMP(6), INTERVAL 1 DAY), UTC_TIMESTAMP(6))`,
		uploadID, source.userID, target.filename, target.filename,
		target.mimeType, source.sizeBytes, source.sizeBytes, source.sha256,
		source.sha256, source.blobID,
	); err != nil {
		t.Fatalf("seed cache consumer upload: %v", err)
	}
	if _, err := db.ExecContext(ctx, `
INSERT INTO tasks (
    id, upload_id, blob_id, created_by, name, tags, status,
    progress_basis_points, risk_level, limits_snapshot, root_format,
    sample_expires_at, completed_at, event_sequence
) VALUES (?, ?, ?, ?, 'Bytecode Cache Integration', JSON_ARRAY(),
          'SUCCEEDED', 10000, 'UNKNOWN',
          JSON_OBJECT(
              'max_upload_bytes', 10737418240,
              'max_expanded_bytes', 53687091200,
              'max_archive_ratio', 100,
              'max_depth', 10,
              'max_file_nodes', 100000,
              'max_nested_images', 10
          ), ?, DATE_ADD(UTC_TIMESTAMP(6), INTERVAL 1 DAY),
          UTC_TIMESTAMP(6), 0)`,
		taskID, uploadID, source.blobID, source.userID, target.format,
	); err != nil {
		t.Fatalf("seed cache consumer task: %v", err)
	}
	attemptResult, err := db.ExecContext(ctx, `
INSERT INTO task_attempts (
    task_id, attempt_number, fencing_token, status, started_at, completed_at
) VALUES (?, 1, 7, 'succeeded',
          DATE_SUB(UTC_TIMESTAMP(6), INTERVAL 1 SECOND), UTC_TIMESTAMP(6))`,
		taskID,
	)
	if err != nil {
		t.Fatalf("seed cache consumer attempt: %v", err)
	}
	attemptInsertID, err := attemptResult.LastInsertId()
	if err != nil || attemptInsertID <= 0 {
		t.Fatalf("read cache consumer attempt ID: %v", err)
	}
	attemptID := uint64(attemptInsertID)
	pathHash := sha256.Sum256([]byte("/"))
	nodeResult, err := db.ExecContext(ctx, `
INSERT INTO file_nodes (
    task_id, parent_id, logical_path, logical_path_hash, display_name,
    node_type, depth, format, mime_type, architecture, size_bytes, sha256,
    storage_key, extraction_status, metadata_json
) VALUES (?, NULL, '/', ?, ?, 'file', 0, ?, ?, ?, ?, ?, ?, 'indexed',
          JSON_OBJECT('cache_fixture', TRUE))`,
		taskID, pathHash[:], target.filename, target.format, target.mimeType,
		target.architecture, source.sizeBytes, source.sha256, source.storageKey,
	)
	if err != nil {
		t.Fatalf("seed cache consumer node: %v", err)
	}
	nodeInsertID, err := nodeResult.LastInsertId()
	if err != nil || nodeInsertID <= 0 {
		t.Fatalf("read cache consumer node ID: %v", err)
	}
	nodeID := uint64(nodeInsertID)
	return decompileIntegrationFixture{
		userID: source.userID, blobID: source.blobID, uploadID: uploadID,
		taskID: taskID, attemptID: attemptID, nodeID: nodeID, jobID: jobID,
		storageKey: source.storageKey, sha256: source.sha256,
		sizeBytes: source.sizeBytes,
	}
}

func cleanupDecompileIntegrationCacheConsumer(
	t *testing.T,
	db *sql.DB,
	fixture decompileIntegrationFixture,
) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := db.ExecContext(ctx, `
UPDATE job_resource_slots
SET job_id = NULL, job_fencing_token = NULL, lease_owner = NULL,
    acquired_at = NULL
WHERE job_id IN (SELECT id FROM jobs WHERE task_id = ?)`, fixture.taskID); err != nil {
		t.Logf("cache consumer slot cleanup failed: %v", err)
	}
	if _, err := db.ExecContext(ctx, `DELETE FROM tasks WHERE id = ?`, fixture.taskID); err != nil {
		t.Logf("cache consumer task cleanup failed: %v", err)
	}
	if _, err := db.ExecContext(ctx, `DELETE FROM uploads WHERE id = ?`, fixture.uploadID); err != nil {
		t.Logf("cache consumer upload cleanup failed: %v", err)
	}
}

func decompileIntegrationClass(
	t *testing.T,
	internalName string,
	methodName string,
) []byte {
	t.Helper()
	var output bytes.Buffer
	writeU1 := func(value byte) {
		if err := output.WriteByte(value); err != nil {
			t.Fatal(err)
		}
	}
	writeU2 := func(value uint16) {
		if err := binary.Write(&output, binary.BigEndian, value); err != nil {
			t.Fatal(err)
		}
	}
	writeU4 := func(value uint32) {
		if err := binary.Write(&output, binary.BigEndian, value); err != nil {
			t.Fatal(err)
		}
	}
	writeUTF8 := func(value string) {
		writeU1(1)
		writeU2(uint16(len(value)))
		if _, err := output.WriteString(value); err != nil {
			t.Fatal(err)
		}
	}

	writeU4(0xcafebabe)
	writeU2(0)
	writeU2(61)
	writeU2(10)
	writeUTF8(internalName)
	writeU1(7)
	writeU2(1)
	writeUTF8("java/lang/Object")
	writeU1(7)
	writeU2(3)
	writeUTF8(methodName)
	writeUTF8("()V")
	writeUTF8("Code")
	writeUTF8("SourceFile")
	sourceName := internalName
	if separator := strings.LastIndexByte(sourceName, '/'); separator >= 0 {
		sourceName = sourceName[separator+1:]
	}
	writeUTF8(sourceName + ".java")
	writeU2(0x0021)
	writeU2(2)
	writeU2(4)
	writeU2(0)
	writeU2(0)
	writeU2(1)
	writeU2(0x0009)
	writeU2(5)
	writeU2(6)
	writeU2(1)
	writeU2(7)
	writeU4(13)
	writeU2(0)
	writeU2(0)
	writeU4(1)
	writeU1(0xb1)
	writeU2(0)
	writeU2(0)
	writeU2(1)
	writeU2(8)
	writeU4(2)
	writeU2(9)
	return output.Bytes()
}

func cleanupDecompileIntegrationFixture(
	t *testing.T,
	db *sql.DB,
	fixture decompileIntegrationFixture,
) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	statements := []struct {
		query string
		args  []any
	}{
		{
			query: `
UPDATE job_resource_slots
SET job_id = NULL, job_fencing_token = NULL, lease_owner = NULL,
    acquired_at = NULL
WHERE job_id IN (SELECT id FROM jobs WHERE task_id = ?)`,
			args: []any{fixture.taskID},
		},
		{query: `DELETE FROM tasks WHERE id = ?`, args: []any{fixture.taskID}},
		{query: `DELETE FROM uploads WHERE id = ?`, args: []any{fixture.uploadID}},
		{query: `DELETE FROM blobs WHERE id = ?`, args: []any{fixture.blobID}},
		{query: `DELETE FROM users WHERE id = ?`, args: []any{fixture.userID}},
	}
	for _, statement := range statements {
		if _, err := db.ExecContext(ctx, statement.query, statement.args...); err != nil {
			t.Logf("decompile integration cleanup failed: %v", err)
		}
	}
}

func decompileIntegrationUUID(t *testing.T) string {
	t.Helper()
	value, err := newUUID()
	if err != nil {
		t.Fatal(err)
	}
	return value
}

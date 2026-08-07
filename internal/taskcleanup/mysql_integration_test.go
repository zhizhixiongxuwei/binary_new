package taskcleanup

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	reportstore "binaryscan/internal/report"
	taskstore "binaryscan/internal/task"

	"github.com/go-sql-driver/mysql"
)

const (
	taskCleanupIntegrationDSNFile = "BINARYSCAN_TASK_CLEANUP_INTEGRATION_DSN_FILE"
	taskCleanupIntegrationRoot    = "BINARYSCAN_TASK_CLEANUP_INTEGRATION_REPOSITORY_ROOT"
)

type taskCleanupFixture struct {
	userID          uint64
	taskID          string
	uploadID        string
	jobID           string
	reportID        string
	barrierReportID string
	queuedReportID  string
	artifactID      string
	resultID        string
	deletedResultID string
	rootBlobID      uint64
	nestedBlobID    uint64
	rootKey         string
	nestedKey       string
	outputKeys      []string
}

func TestMySQLTaskDeletionCleanupIntegration(t *testing.T) {
	dsnPath := strings.TrimSpace(os.Getenv(taskCleanupIntegrationDSNFile))
	repositoryRoot := strings.TrimSpace(os.Getenv(taskCleanupIntegrationRoot))
	if dsnPath == "" || repositoryRoot == "" {
		t.Skip(
			taskCleanupIntegrationDSNFile + " and " +
				taskCleanupIntegrationRoot + " are not set",
		)
	}
	rawDSN, err := os.ReadFile(dsnPath)
	if err != nil {
		t.Fatal(err)
	}
	driverConfig, err := mysql.ParseDSN(strings.TrimSpace(string(rawDSN)))
	if err != nil {
		t.Fatal(err)
	}
	driverConfig.ParseTime = true
	driverConfig.Loc = time.UTC
	db, err := sql.Open("mysql", driverConfig.FormatDSN())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		t.Fatal(err)
	}

	fixture := seedTaskCleanupFixture(t, ctx, db, repositoryRoot)
	t.Cleanup(func() {
		cleanupTaskCleanupFixture(t, db, repositoryRoot, fixture)
	})
	deleter, err := NewRepositoryFileDeleter(repositoryRoot)
	if err != nil {
		t.Fatal(err)
	}
	sweeper, err := NewSweeper(
		NewMySQLRepository(db),
		deleter,
		Config{
			LeaseOwner:    "task-deletion/integration",
			LeaseDuration: time.Minute,
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	deleting, err := taskstore.NewMySQLRepository(db).Delete(
		ctx,
		taskstore.MutationRecord{
			TaskID:        fixture.taskID,
			UserID:        fixture.userID,
			Administrator: true,
		},
	)
	if err != nil || deleting.Status != taskstore.StatusDeleting {
		t.Fatalf("Delete() = (%+v, %v)", deleting, err)
	}
	var (
		barrierStatus string
		queuedStatus  string
		queuedError   sql.NullString
	)
	if err := db.QueryRowContext(ctx, `
SELECT barrier.status, queued.status, queued.error_code
FROM reports barrier
JOIN reports queued ON queued.task_id = barrier.task_id
WHERE barrier.task_id = ? AND barrier.id = ? AND queued.id = ?`,
		fixture.taskID,
		fixture.barrierReportID,
		fixture.queuedReportID,
	).Scan(&barrierStatus, &queuedStatus, &queuedError); err != nil {
		t.Fatal(err)
	}
	if barrierStatus != "generating" || queuedStatus != "failed" ||
		!queuedError.Valid || queuedError.String != "task_deleted" {
		t.Fatalf(
			"report deletion barrier = %s, queued = %s/%v",
			barrierStatus,
			queuedStatus,
			queuedError,
		)
	}
	blocked, err := sweeper.Sweep(ctx, 10)
	if err != nil || blocked != (Report{}) {
		t.Fatalf("barrier Sweep() = (%+v, %v)", blocked, err)
	}
	if _, err := db.ExecContext(ctx, `
UPDATE reports
SET generation_lease_until = DATE_SUB(UTC_TIMESTAMP(6), INTERVAL 1 SECOND)
WHERE task_id = ? AND id = ?`,
		fixture.taskID, fixture.barrierReportID,
	); err != nil {
		t.Fatal(err)
	}
	recovered, err := reportstore.NewMySQLRepository(db).RecoverExpired(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	if recovered != 1 {
		t.Fatalf("recovered report generations = %d, want 1", recovered)
	}

	first, err := sweeper.Sweep(ctx, 10)
	if err != nil || first.Claimed != 1 || first.Completed != 1 ||
		first.FilesDeleted != 4 || first.Failures != 0 {
		t.Fatalf("released Sweep() = (%+v, %v)", first, err)
	}
	assertTaskCleanupFinalState(t, ctx, db, repositoryRoot, fixture)

	second, err := sweeper.Sweep(ctx, 10)
	if err != nil || second != (Report{}) {
		t.Fatalf("replayed Sweep() = (%+v, %v)", second, err)
	}
	assertTaskCleanupFinalState(t, ctx, db, repositoryRoot, fixture)
}

func seedTaskCleanupFixture(
	t *testing.T,
	ctx context.Context,
	db *sql.DB,
	repositoryRoot string,
) taskCleanupFixture {
	t.Helper()
	fixture := taskCleanupFixture{
		taskID:          cleanupUUID(t),
		uploadID:        cleanupUUID(t),
		jobID:           cleanupUUID(t),
		reportID:        cleanupUUID(t),
		barrierReportID: cleanupUUID(t),
		queuedReportID:  cleanupUUID(t),
		artifactID:      cleanupUUID(t),
		resultID:        cleanupUUID(t),
		deletedResultID: cleanupUUID(t),
	}
	userPublicID := cleanupUUID(t)
	result, err := db.ExecContext(ctx, `
INSERT INTO users (
    public_id, username, display_name, password_hash, role, status,
    force_password_change
) VALUES (?, ?, 'Task cleanup integration', 'not-used', 'operator', 'active',
          FALSE)`,
		userPublicID,
		"cleanup-"+strings.ReplaceAll(userPublicID[:13], "-", ""),
	)
	if err != nil {
		t.Fatal(err)
	}
	fixture.userID, err = unsignedInsertID(result)
	if err != nil {
		t.Fatal(err)
	}
	rootContent := []byte("root task cleanup sample " + fixture.taskID)
	nestedContent := []byte("nested task cleanup image " + fixture.taskID)
	rootSHA := cleanupSHA(rootContent)
	nestedSHA := cleanupSHA(nestedContent)
	fixture.rootKey = "blobs/sha256/" + rootSHA[:2] + "/" + rootSHA
	fixture.nestedKey = "blobs/sha256/" + nestedSHA[:2] + "/" + nestedSHA
	fixture.rootBlobID = insertCleanupBlob(
		t, ctx, db, rootSHA, fixture.rootKey, rootContent, 2,
	)
	fixture.nestedBlobID = insertCleanupBlob(
		t, ctx, db, nestedSHA, fixture.nestedKey, nestedContent, 1,
	)
	writeCleanupFile(t, repositoryRoot, fixture.rootKey, rootContent)
	writeCleanupFile(t, repositoryRoot, fixture.nestedKey, nestedContent)

	if _, err := db.ExecContext(ctx, `
INSERT INTO uploads (
    id, created_by, original_name, display_name, declared_size_bytes,
    part_size_bytes, actual_sha256, status, blob_id, expires_at, completed_at
) VALUES (?, ?, 'sample.bin', 'sample.bin', ?, 1048576, ?, 'completed', ?,
          DATE_ADD(UTC_TIMESTAMP(6), INTERVAL 30 DAY), UTC_TIMESTAMP(6))`,
		fixture.uploadID, fixture.userID, len(rootContent), rootSHA,
		fixture.rootBlobID,
	); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `
INSERT INTO tasks (
    id, upload_id, blob_id, created_by, name, tags, status, stage,
    progress_basis_points, risk_level, limits_snapshot, root_format,
    sample_expires_at, completed_at, event_sequence
	) VALUES (?, ?, ?, ?, 'Task cleanup integration', JSON_ARRAY('integration'),
	          'SUCCEEDED', NULL, 10000, 'LOW', JSON_OBJECT(), 'docker-tar',
          DATE_ADD(UTC_TIMESTAMP(6), INTERVAL 30 DAY), UTC_TIMESTAMP(6), 0)`,
		fixture.taskID, fixture.uploadID, fixture.rootBlobID, fixture.userID,
	); err != nil {
		t.Fatal(err)
	}
	attemptResult, err := db.ExecContext(ctx, `
INSERT INTO task_attempts (
    task_id, attempt_number, fencing_token, status, completed_at
) VALUES (?, 1, 1, 'cancelled', UTC_TIMESTAMP(6))`, fixture.taskID)
	if err != nil {
		t.Fatal(err)
	}
	attemptID, err := unsignedInsertID(attemptResult)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `
INSERT INTO jobs (
    id, task_id, task_attempt_id, kind, status, payload, available_at,
    attempt, max_attempts, fencing_token, completed_at
) VALUES (?, ?, ?, 'scan', 'cancelled',
          JSON_OBJECT('source_storage_key', ?), UTC_TIMESTAMP(6),
          1, 3, 1, UTC_TIMESTAMP(6))`,
		fixture.jobID, fixture.taskID, attemptID, fixture.rootKey,
	); err != nil {
		t.Fatal(err)
	}
	rootNodeResult, err := db.ExecContext(ctx, `
INSERT INTO file_nodes (
    task_id, parent_id, logical_path, logical_path_hash, display_name,
    node_type, depth, format, size_bytes, sha256, storage_key,
    extraction_status
) VALUES (?, NULL, '/', UNHEX(SHA2('/', 256)), 'sample.bin', 'file', 0,
          'docker-tar', ?, ?, ?, 'extracted')`,
		fixture.taskID, len(rootContent), rootSHA, fixture.rootKey,
	)
	if err != nil {
		t.Fatal(err)
	}
	rootNodeID, err := unsignedInsertID(rootNodeResult)
	if err != nil {
		t.Fatal(err)
	}
	nestedNodeResult, err := db.ExecContext(ctx, `
INSERT INTO file_nodes (
    task_id, parent_id, logical_path, logical_path_hash, display_name,
    node_type, depth, format, size_bytes, sha256, storage_key,
    extraction_status
) VALUES (?, ?, '/nested.tar', UNHEX(SHA2('/nested.tar', 256)), 'nested.tar',
          'file', 1, 'docker-tar', ?, ?, ?, 'extracted')`,
		fixture.taskID, rootNodeID, len(nestedContent), nestedSHA,
		fixture.nestedKey,
	)
	if err != nil {
		t.Fatal(err)
	}
	nestedNodeID, err := unsignedInsertID(nestedNodeResult)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `
INSERT INTO file_node_blob_refs (task_id, file_node_id, blob_id)
VALUES (?, ?, ?)`, fixture.taskID, nestedNodeID, fixture.nestedBlobID); err != nil {
		t.Fatal(err)
	}

	reportContent := []byte(`{"task":"deleted"}`)
	reportKey := "reports/" + fixture.taskID + "/" + fixture.reportID + ".json"
	artifactContent := []byte(`{"Results":[]}`)
	artifactKey := "artifacts/" + fixture.taskID + "/trivy/1/" +
		fixture.artifactID + ".json"
	decompileContent := []byte("public class Deleted {}")
	decompileKey := "decompile/" + fixture.resultID + "/source.java"
	softDeletedContent := []byte("public class SoftDeleted {}")
	softDeletedKey := "decompile/" + fixture.deletedResultID + "/source.java"
	fixture.outputKeys = []string{
		reportKey,
		artifactKey,
		decompileKey,
		softDeletedKey,
	}
	for index, output := range []struct {
		key     string
		content []byte
	}{
		{reportKey, reportContent},
		{artifactKey, artifactContent},
		{decompileKey, decompileContent},
		{softDeletedKey, softDeletedContent},
	} {
		writeCleanupFile(t, repositoryRoot, output.key, output.content)
		if index == 0 {
			staging := filepath.Join(
				repositoryRoot, "reports", fixture.taskID, ".staging",
			)
			if err := os.WriteFile(staging, []byte("orphan"), 0o600); err != nil {
				t.Fatal(err)
			}
		}
	}
	if _, err := db.ExecContext(ctx, `
INSERT INTO reports (
    id, task_id, format, schema_version, status, storage_key, sha256,
    size_bytes, completed_at
) VALUES (?, ?, 'json', '1.0.0', 'complete', ?, ?, ?, UTC_TIMESTAMP(6))`,
		fixture.reportID, fixture.taskID, reportKey, cleanupSHA(reportContent),
		len(reportContent),
	); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `
INSERT INTO reports (
    id, task_id, format, schema_version, status, generation_fence,
    generation_owner, generation_lease_until, generation_heartbeat_at
) VALUES (
    ?, ?, 'html', '1.0.0', 'generating', 1,
    'task-cleanup-report-fixture', DATE_ADD(UTC_TIMESTAMP(6), INTERVAL 1 HOUR),
    UTC_TIMESTAMP(6)
)`,
		fixture.barrierReportID,
		fixture.taskID,
	); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `
INSERT INTO reports (
    id, task_id, format, schema_version, status
) VALUES (?, ?, 'json', 'queued-delete-fixture', 'queued')`,
		fixture.queuedReportID,
		fixture.taskID,
	); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `
INSERT INTO artifacts (
    id, task_id, task_attempt_id, analyzer_run_id, kind, media_type,
    storage_key, sha256, size_bytes, state, published_at
) VALUES (?, ?, ?, NULL, 'trivy-raw-json', 'application/json', ?, ?, ?,
          'published', UTC_TIMESTAMP(6))`,
		fixture.artifactID, fixture.taskID, attemptID, artifactKey,
		cleanupSHA(artifactContent), len(artifactContent),
	); err != nil {
		t.Fatal(err)
	}
	cacheKey := sha256.Sum256([]byte(fixture.resultID))
	if _, err := db.ExecContext(ctx, `
INSERT INTO decompile_results (
    id, task_id, file_node_id, analyzer_run_id, cache_key, symbol_key,
    language, engine_name, engine_version, status, storage_key,
    content_sha256, size_bytes, diagnostics_json, completed_at
) VALUES (?, ?, ?, NULL, ?, 'Deleted', 'java', 'ghidra', 'integration',
          'complete', ?, ?, ?, JSON_OBJECT(), UTC_TIMESTAMP(6))`,
		fixture.resultID, fixture.taskID, rootNodeID,
		hex.EncodeToString(cacheKey[:]), decompileKey,
		cleanupSHA(decompileContent), len(decompileContent),
	); err != nil {
		t.Fatal(err)
	}
	deletedCacheKey := sha256.Sum256([]byte(fixture.deletedResultID))
	if _, err := db.ExecContext(ctx, `
INSERT INTO decompile_results (
    id, task_id, file_node_id, analyzer_run_id, cache_key, symbol_key,
    language, engine_name, engine_version, status, storage_key,
    content_sha256, size_bytes, diagnostics_json, completed_at, deleted_at
) VALUES (?, ?, ?, NULL, ?, 'SoftDeleted', 'java', 'ghidra', 'integration',
          'complete', ?, ?, ?, JSON_OBJECT(), UTC_TIMESTAMP(6),
          UTC_TIMESTAMP(6))`,
		fixture.deletedResultID,
		fixture.taskID,
		rootNodeID,
		hex.EncodeToString(deletedCacheKey[:]),
		softDeletedKey,
		cleanupSHA(softDeletedContent),
		len(softDeletedContent),
	); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `
INSERT INTO vulnerability_findings (
    task_id, analyzer_run_id, image_logical_path, vulnerability_id, severity,
    package_name
) VALUES (?, NULL, '/', 'CVE-INTEGRATION', 'LOW', 'deleted-package')`,
		fixture.taskID,
	); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `
INSERT INTO audit_logs (
    action, object_type, object_id, outcome, metadata_json
) VALUES ('task.delete', 'task', ?, 'success',
          JSON_OBJECT('reason', 'user_requested'))`, fixture.taskID); err != nil {
		t.Fatal(err)
	}
	return fixture
}

func assertTaskCleanupFinalState(
	t *testing.T,
	ctx context.Context,
	db *sql.DB,
	repositoryRoot string,
	fixture taskCleanupFixture,
) {
	t.Helper()
	var (
		status                 string
		deletedAt, sampleAt    sql.NullTime
		operationStatus        string
		operationCompletedAt   sql.NullTime
		jobPayload             []byte
		rootReferences         uint64
		rootState, nestedState string
		nestedReferences       uint64
		resultCount            uint64
		auditCount             uint64
	)
	err := db.QueryRowContext(ctx, `
SELECT task.status, task.deleted_at, task.sample_deleted_at,
       operation.status, operation.completed_at,
       job.payload,
       root_blob.reference_count, root_blob.state,
       nested_blob.reference_count, nested_blob.state,
       (
           (SELECT COUNT(*) FROM reports WHERE task_id = task.id) +
           (SELECT COUNT(*) FROM artifacts WHERE task_id = task.id) +
           (SELECT COUNT(*) FROM decompile_results WHERE task_id = task.id) +
           (SELECT COUNT(*) FROM vulnerability_findings WHERE task_id = task.id) +
           (SELECT COUNT(*) FROM analyzer_runs WHERE task_id = task.id) +
           (SELECT COUNT(*) FROM file_nodes WHERE task_id = task.id) +
           (SELECT COUNT(*) FROM file_node_blob_refs WHERE task_id = task.id)
       ),
       (
           SELECT COUNT(*)
           FROM audit_logs
           WHERE object_type = 'task' AND object_id = task.id
             AND action IN (
                 'task.delete',
                 'task.deletion_cleanup_started',
                 'task.deletion_cleanup_completed'
             )
       )
FROM tasks task
JOIN task_deletion_operations operation ON operation.task_id = task.id
JOIN jobs job ON job.task_id = task.id AND job.id = ?
JOIN blobs root_blob ON root_blob.id = ?
JOIN blobs nested_blob ON nested_blob.id = ?
WHERE task.id = ?`,
		fixture.jobID, fixture.rootBlobID, fixture.nestedBlobID, fixture.taskID,
	).Scan(
		&status, &deletedAt, &sampleAt, &operationStatus,
		&operationCompletedAt, &jobPayload, &rootReferences, &rootState,
		&nestedReferences, &nestedState, &resultCount, &auditCount,
	)
	if err != nil {
		t.Fatal(err)
	}
	if status != "DELETED" || !deletedAt.Valid || !sampleAt.Valid ||
		operationStatus != "completed" || !operationCompletedAt.Valid ||
		jobPayload != nil || rootReferences != 1 || rootState != "available" ||
		nestedReferences != 0 || nestedState != "deleting" ||
		resultCount != 0 || auditCount != 3 {
		t.Fatalf(
			"cleanup state status=%s deleted=%v sample=%v operation=%s/%v "+
				"payload=%q root=%d/%s nested=%d/%s results=%d audits=%d",
			status, deletedAt.Valid, sampleAt.Valid,
			operationStatus, operationCompletedAt.Valid, jobPayload,
			rootReferences, rootState, nestedReferences, nestedState,
			resultCount, auditCount,
		)
	}
	for _, key := range fixture.outputKeys {
		if _, err := os.Lstat(filepath.Join(repositoryRoot, key)); !os.IsNotExist(err) {
			t.Fatalf("task output %q still exists: %v", key, err)
		}
	}
	for _, scope := range []string{
		filepath.Join("reports", fixture.taskID),
		filepath.Join("artifacts", fixture.taskID),
		filepath.Join("decompile", fixture.resultID),
		filepath.Join("decompile", fixture.deletedResultID),
	} {
		if _, err := os.Lstat(filepath.Join(repositoryRoot, scope)); !os.IsNotExist(err) {
			t.Fatalf("task output scope %q still exists: %v", scope, err)
		}
	}
	for _, key := range []string{fixture.rootKey, fixture.nestedKey} {
		if _, err := os.Stat(filepath.Join(repositoryRoot, key)); err != nil {
			t.Fatalf("CAS object %q was physically deleted: %v", key, err)
		}
	}
}

func cleanupTaskCleanupFixture(
	t *testing.T,
	db *sql.DB,
	repositoryRoot string,
	fixture taskCleanupFixture,
) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	statements := []struct {
		query string
		args  []any
	}{
		{"DELETE FROM audit_logs WHERE object_type = 'task' AND object_id = ?", []any{fixture.taskID}},
		{"DELETE FROM task_deletion_operations WHERE task_id = ?", []any{fixture.taskID}},
		{"DELETE FROM tasks WHERE id = ?", []any{fixture.taskID}},
		{"DELETE FROM uploads WHERE id = ?", []any{fixture.uploadID}},
		{"DELETE FROM blobs WHERE id IN (?, ?)", []any{fixture.rootBlobID, fixture.nestedBlobID}},
		{"DELETE FROM users WHERE id = ?", []any{fixture.userID}},
	}
	for _, statement := range statements {
		if _, err := db.ExecContext(
			ctx, statement.query, statement.args...,
		); err != nil {
			t.Errorf("cleanup integration fixture: %v", err)
		}
	}
	for _, key := range append(
		append([]string(nil), fixture.outputKeys...),
		fixture.rootKey, fixture.nestedKey,
	) {
		_ = os.Remove(filepath.Join(repositoryRoot, key))
	}
	for _, scope := range []string{
		filepath.Join(repositoryRoot, "reports", fixture.taskID),
		filepath.Join(repositoryRoot, "artifacts", fixture.taskID),
		filepath.Join(repositoryRoot, "decompile", fixture.resultID),
		filepath.Join(repositoryRoot, "decompile", fixture.deletedResultID),
	} {
		_ = os.RemoveAll(scope)
	}
}

func insertCleanupBlob(
	t *testing.T,
	ctx context.Context,
	db *sql.DB,
	sha string,
	key string,
	content []byte,
	references uint64,
) uint64 {
	t.Helper()
	result, err := db.ExecContext(ctx, `
INSERT INTO blobs (
    sha256, size_bytes, storage_key, reference_count, state, verified_at
) VALUES (?, ?, ?, ?, 'available', UTC_TIMESTAMP(6))`,
		sha, len(content), key, references,
	)
	if err != nil {
		t.Fatal(err)
	}
	id, err := unsignedInsertID(result)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func unsignedInsertID(result sql.Result) (uint64, error) {
	id, err := result.LastInsertId()
	if err != nil {
		return 0, err
	}
	if id <= 0 {
		return 0, fmt.Errorf("insert ID %d is invalid", id)
	}
	return uint64(id), nil
}

func cleanupUUID(t *testing.T) string {
	t.Helper()
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		t.Fatal(err)
	}
	raw[6] = (raw[6] & 0x0f) | 0x40
	raw[8] = (raw[8] & 0x3f) | 0x80
	encoded := hex.EncodeToString(raw[:])
	return encoded[0:8] + "-" + encoded[8:12] + "-" +
		encoded[12:16] + "-" + encoded[16:20] + "-" + encoded[20:32]
}

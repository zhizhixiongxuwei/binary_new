package database

import (
	"context"
	"database/sql"
	"os"
	"strings"
	"testing"
	"time"

	"binaryscan/db/migrations"

	"github.com/go-sql-driver/mysql"
	"github.com/pressly/goose/v3"
)

func TestMigrationsAreEmbedded(t *testing.T) {
	files, err := MigrationFiles()
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 25 {
		t.Fatalf("embedded migration count = %d, want 25: %v", len(files), files)
	}
	if files[0] != "00001_initial.sql" {
		t.Fatalf("first migration = %q, want 00001_initial.sql", files[0])
	}
	if files[1] != "00002_upload_content_type.sql" ||
		files[7] != "00008_analyzer_runs_recent_index.sql" ||
		files[8] != "00010_job_resource_slots.sql" ||
		files[22] != "00024_worker_readiness.sql" ||
		files[23] != "00026_bytecode_worker_readiness.sql" ||
		files[24] != "00027_lower_performance_baseline.sql" {
		t.Fatalf("embedded migration order = %v", files)
	}
	version, err := LatestMigrationVersion()
	if err != nil {
		t.Fatal(err)
	}
	if version != 27 {
		t.Fatalf("latest migration version = %d, want 27", version)
	}
}

func TestBytecodeWorkerReadinessMigrationIsStrictAndReversible(t *testing.T) {
	raw, err := migrations.FS.ReadFile("00026_bytecode_worker_readiness.sql")
	if err != nil {
		t.Fatal(err)
	}
	sections := strings.Split(string(raw), "-- +goose Down")
	if len(sections) != 2 {
		t.Fatalf("bytecode readiness migration sections = %d, want 2", len(sections))
	}
	up, down := sections[0], sections[1]
	for _, fragment := range []string{
		"DROP CHECK chk_worker_readiness_kind",
		"worker_kind IN ('image', 'native', 'trivy', 'bytecode')",
		"'go-bytecode-router', 'vineflower-cfr-jadx'",
	} {
		if !strings.Contains(up, fragment) {
			t.Fatalf("bytecode readiness up migration lacks %q", fragment)
		}
	}
	for _, fragment := range []string{
		"DELETE FROM worker_readiness WHERE worker_kind = 'bytecode'",
		"worker_kind IN ('image', 'native', 'trivy')",
	} {
		if !strings.Contains(down, fragment) {
			t.Fatalf("bytecode readiness down migration lacks %q", fragment)
		}
	}
}

func TestLowerPerformanceBaselineMigrationIsBoundedAndReversible(t *testing.T) {
	raw, err := migrations.FS.ReadFile("00027_lower_performance_baseline.sql")
	if err != nil {
		t.Fatal(err)
	}
	sections := strings.Split(string(raw), "-- +goose Down")
	if len(sections) != 2 {
		t.Fatalf("performance baseline migration sections = %d, want 2", len(sections))
	}
	up, down := sections[0], sections[1]
	for _, fragment := range []string{
		"declared_size_bytes <= 2147483648",
		"heavy_slots BETWEEN 1 AND 2",
		"SET heavy_slots = 1",
	} {
		if !strings.Contains(up, fragment) {
			t.Fatalf("performance baseline up migration lacks %q", fragment)
		}
	}
	for _, fragment := range []string{
		"heavy_slots BETWEEN 2 AND 4",
		"declared_size_bytes <= 10737418240",
		"SET heavy_slots = 2",
	} {
		if !strings.Contains(down, fragment) {
			t.Fatalf("performance baseline down migration lacks %q", fragment)
		}
	}
}

func TestWorkerReadinessMigrationIsStrictIndexedAndReversible(t *testing.T) {
	raw, err := migrations.FS.ReadFile("00024_worker_readiness.sql")
	if err != nil {
		t.Fatal(err)
	}
	sections := strings.Split(string(raw), "-- +goose Down")
	if len(sections) != 2 {
		t.Fatalf("worker readiness migration sections = %d, want 2", len(sections))
	}
	up, down := sections[0], sections[1]
	for _, fragment := range []string{
		"CREATE TABLE IF NOT EXISTS worker_readiness",
		"PRIMARY KEY (worker_owner)",
		"idx_worker_readiness_analyzer",
		"idx_worker_readiness_checked",
		"chk_worker_readiness_analyzer",
		"chk_worker_readiness_status",
	} {
		if !strings.Contains(up, fragment) {
			t.Fatalf("worker readiness up migration lacks %q", fragment)
		}
	}
	if !strings.Contains(down, "DROP TABLE IF EXISTS worker_readiness") {
		t.Fatal("worker readiness down migration does not drop its table")
	}
}

func TestStorageReconciliationMigrationIsIndexedAndReversible(t *testing.T) {
	raw, err := migrations.FS.ReadFile("00023_storage_reconciliation_indexes.sql")
	if err != nil {
		t.Fatal(err)
	}
	sections := strings.Split(string(raw), "-- +goose Down")
	if len(sections) != 2 {
		t.Fatalf("storage reconciliation migration sections = %d, want 2", len(sections))
	}
	up, down := sections[0], sections[1]
	for _, index := range []string{
		"idx_reports_storage_key", "idx_decompile_results_storage_key",
	} {
		if !strings.Contains(up, "ADD KEY "+index+" (storage_key)") {
			t.Fatalf("storage reconciliation up migration lacks %s", index)
		}
		if !strings.Contains(down, "DROP INDEX "+index) {
			t.Fatalf("storage reconciliation down migration lacks %s", index)
		}
	}
}

func TestTaskListCursorMigrationIsOrderedAndReversible(t *testing.T) {
	raw, err := migrations.FS.ReadFile("00022_task_list_cursor_index.sql")
	if err != nil {
		t.Fatal(err)
	}
	sections := strings.Split(string(raw), "-- +goose Down")
	if len(sections) != 2 {
		t.Fatalf("task cursor migration sections = %d, want 2", len(sections))
	}
	up, down := sections[0], sections[1]
	for _, fragment := range []string{
		"-- +goose NO TRANSACTION",
		"ADD INDEX idx_tasks_created_id (created_at DESC, id DESC)",
	} {
		if !strings.Contains(up, fragment) {
			t.Fatalf("task cursor up migration lacks %q", fragment)
		}
	}
	if !strings.Contains(down, "DROP INDEX idx_tasks_created_id") {
		t.Fatal("task cursor down migration does not drop its index")
	}
}

func TestBytecodeCacheIdentityMigrationIsIndexedAndReversible(t *testing.T) {
	raw, err := migrations.FS.ReadFile("00021_bytecode_cache_identity.sql")
	if err != nil {
		t.Fatal(err)
	}
	sections := strings.Split(string(raw), "-- +goose Down")
	if len(sections) != 2 {
		t.Fatalf("bytecode cache migration sections = %d, want 2", len(sections))
	}
	up, down := sections[0], sections[1]
	for _, fragment := range []string{
		"-- +goose NO TRANSACTION",
		"cache_identity CHAR(64)",
		"CHARACTER SET ascii COLLATE ascii_bin NULL",
		"idx_analyzer_runs_bytecode_cache",
		"cache_identity,\n        status,\n        completed_at,\n        id",
	} {
		if !strings.Contains(up, fragment) {
			t.Fatalf("bytecode cache identity up migration lacks %q", fragment)
		}
	}
	for _, fragment := range []string{
		"DROP INDEX idx_analyzer_runs_bytecode_cache",
		"DROP COLUMN cache_identity",
	} {
		if !strings.Contains(down, fragment) {
			t.Fatalf("bytecode cache identity down migration lacks %q", fragment)
		}
	}
}

func TestMySQLBytecodeCacheMigrationRoundTrip(t *testing.T) {
	rawDSN := os.Getenv("BINARYSCAN_MYSQL_MIGRATION_ROUNDTRIP_DSN")
	if rawDSN == "" {
		t.Skip("BINARYSCAN_MYSQL_MIGRATION_ROUNDTRIP_DSN is not set")
	}
	configuration, err := mysql.ParseDSN(rawDSN)
	if err != nil {
		t.Fatal(err)
	}
	configuration.ParseTime = true
	configuration.Loc = time.UTC
	db, err := sql.Open("mysql", configuration.FormatDSN())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	if err := Migrate(ctx, db); err != nil {
		t.Fatalf("migrate dedicated database to latest: %v", err)
	}
	restoreLatest := true
	t.Cleanup(func() {
		defer db.Close()
		if !restoreLatest {
			return
		}
		restoreCtx, restoreCancel := context.WithTimeout(
			context.Background(), 90*time.Second,
		)
		defer restoreCancel()
		if err := Migrate(restoreCtx, db); err != nil {
			t.Errorf("restore latest migration after round trip: %v", err)
		}
	})
	goose.SetBaseFS(migrations.FS)
	if err := goose.SetDialect("mysql"); err != nil {
		t.Fatal(err)
	}
	if err := goose.DownToContext(ctx, db, ".", 20); err != nil {
		t.Fatalf("migrate bytecode cache identity down: %v", err)
	}
	assertBytecodeCacheMigrationState(t, ctx, db, 20, 0, 0)
	if err := goose.UpToContext(ctx, db, ".", 21); err != nil {
		t.Fatalf("migrate bytecode cache identity up: %v", err)
	}
	assertBytecodeCacheMigrationState(t, ctx, db, 21, 1, 1)
	if err := Migrate(ctx, db); err != nil {
		t.Fatalf("restore latest migration after bytecode round trip: %v", err)
	}
	restoreLatest = false
}

func assertBytecodeCacheMigrationState(
	t *testing.T,
	ctx context.Context,
	db *sql.DB,
	wantVersion int64,
	wantColumn int,
	wantIndex int,
) {
	t.Helper()
	version, err := goose.GetDBVersionContext(ctx, db)
	if err != nil || version != wantVersion {
		t.Fatalf("migration version = %d, %v; want %d", version, err, wantVersion)
	}
	var columnCount, indexCount int
	if err := db.QueryRowContext(ctx, `
SELECT COUNT(*)
FROM information_schema.columns
WHERE table_schema = DATABASE()
  AND table_name = 'analyzer_runs'
  AND column_name = 'cache_identity'`).Scan(&columnCount); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRowContext(ctx, `
SELECT COUNT(DISTINCT index_name)
FROM information_schema.statistics
WHERE table_schema = DATABASE()
  AND table_name = 'analyzer_runs'
  AND index_name = 'idx_analyzer_runs_bytecode_cache'`).Scan(&indexCount); err != nil {
		t.Fatal(err)
	}
	if columnCount != wantColumn || indexCount != wantIndex {
		t.Fatalf(
			"bytecode cache migration state = column:%d index:%d; want %d/%d",
			columnCount, indexCount, wantColumn, wantIndex,
		)
	}
}

func TestNativeResourceSlotsMigrationIsBoundedAndReversible(t *testing.T) {
	raw, err := migrations.FS.ReadFile("00020_native_resource_slots.sql")
	if err != nil {
		t.Fatal(err)
	}
	sql := string(raw)
	for _, fragment := range []string{
		"pool IN ('global', 'trivy', 'native')",
		"('native', 1)",
		"('native', 4)",
		"native_slots TINYINT UNSIGNED NOT NULL DEFAULT 1",
		"native_slots BETWEEN 1 AND heavy_slots",
		"DROP CHECK chk_job_resource_limits_native",
		"DROP COLUMN native_slots",
		"DELETE FROM job_resource_slots",
		"pool IN ('global', 'trivy')",
	} {
		if !strings.Contains(sql, fragment) {
			t.Fatalf("native resource slot migration lacks %q", fragment)
		}
	}
}

func TestFileNodeSourceContainerMigrationIsTaskScopedAndReversible(
	t *testing.T,
) {
	raw, err := migrations.FS.ReadFile(
		"00018_file_node_source_container.sql",
	)
	if err != nil {
		t.Fatal(err)
	}
	sql := string(raw)
	for _, fragment := range []string{
		"source_container_id BIGINT UNSIGNED",
		"idx_file_nodes_source_container",
		"FOREIGN KEY (task_id, source_container_id)",
		"REFERENCES file_nodes (task_id, id)",
		"DROP FOREIGN KEY fk_file_nodes_source_container",
		"DROP INDEX idx_file_nodes_source_container",
		"DROP COLUMN source_container_id",
	} {
		if !strings.Contains(sql, fragment) {
			t.Fatalf("source container migration lacks %q", fragment)
		}
	}
	if strings.Contains(sql, "FOREIGN KEY (source_container_id)") {
		t.Fatal("source container foreign key must include task_id")
	}
}

func TestLoginRateLimitMigrationIsPersistentBoundedAndReversible(
	t *testing.T,
) {
	raw, err := migrations.FS.ReadFile("00019_login_rate_limits.sql")
	if err != nil {
		t.Fatal(err)
	}
	sql := string(raw)
	for _, fragment := range []string{
		"CREATE TABLE IF NOT EXISTS login_rate_limits",
		"client_key BINARY(32) NOT NULL",
		"failure_count INT UNSIGNED",
		"in_flight_count INT UNSIGNED",
		"blocked_until TIMESTAMP(6)",
		"KEY idx_login_rate_limits_updated (updated_at, client_key)",
		"CHECK (window_expires_at > window_started_at)",
		"DROP TABLE IF EXISTS login_rate_limits",
	} {
		if !strings.Contains(sql, fragment) {
			t.Fatalf("login rate limit migration lacks %q", fragment)
		}
	}
}

func TestFileNodeArchiveNameMigrationIsBoundedAndReversible(t *testing.T) {
	raw, err := migrations.FS.ReadFile("00015_file_node_archive_name.sql")
	if err != nil {
		t.Fatal(err)
	}
	sql := string(raw)
	for _, fragment := range []string{
		"archive_name_id VARCHAR(2740)",
		"CHARACTER SET ascii COLLATE ascii_bin",
		"AFTER display_name",
		"DROP COLUMN archive_name_id",
	} {
		if !strings.Contains(sql, fragment) {
			t.Fatalf("archive name migration lacks %q", fragment)
		}
	}
}

func TestMaintenanceRecoveryMigrationFencesReportsAndRetention(t *testing.T) {
	raw, err := migrations.FS.ReadFile("00013_maintenance_recovery_leases.sql")
	if err != nil {
		t.Fatal(err)
	}
	sql := string(raw)
	for _, fragment := range []string{
		"generation_fence BIGINT UNSIGNED",
		"generation_owner VARCHAR(255)",
		"generation_lease_until TIMESTAMP(6)",
		"CREATE TABLE IF NOT EXISTS task_sample_retention_operations",
		"status IN ('cleaning', 'failed', 'completed')",
		"DROP TABLE IF EXISTS task_sample_retention_operations",
		"DROP COLUMN generation_fence",
	} {
		if !strings.Contains(sql, fragment) {
			t.Fatalf("maintenance recovery migration lacks %q", fragment)
		}
	}
}

func TestTaskDeletionCleanupMigrationIsFencedAndKeepsTask(t *testing.T) {
	raw, err := migrations.FS.ReadFile("00012_task_deletion_cleanup.sql")
	if err != nil {
		t.Fatal(err)
	}
	sql := string(raw)
	for _, fragment := range []string{
		"CREATE TABLE IF NOT EXISTS task_deletion_operations",
		"PRIMARY KEY (task_id)",
		"fencing_token BIGINT UNSIGNED",
		"attempt_count INT UNSIGNED",
		"lease_owner VARCHAR(255)",
		"lease_until TIMESTAMP(6)",
		"status IN ('cleaning', 'failed', 'completed')",
		"FOREIGN KEY (task_id) REFERENCES tasks (id) ON DELETE RESTRICT",
		"DROP TABLE IF EXISTS task_deletion_operations",
	} {
		if !strings.Contains(sql, fragment) {
			t.Fatalf("task deletion cleanup migration lacks %q", fragment)
		}
	}
}

func TestJobResourceSlotsMigrationIsBoundedAndFenced(t *testing.T) {
	raw, err := migrations.FS.ReadFile("00010_job_resource_slots.sql")
	if err != nil {
		t.Fatal(err)
	}
	sql := string(raw)
	for _, fragment := range []string{
		"CREATE TABLE IF NOT EXISTS job_resource_slots",
		"CREATE TABLE IF NOT EXISTS job_resource_limits",
		"PRIMARY KEY (pool, slot_number)",
		"UNIQUE KEY uq_job_resource_slots_job_pool",
		"job_fencing_token BIGINT UNSIGNED",
		"lease_owner VARCHAR(255)",
		"acquired_at TIMESTAMP(6)",
		"FOREIGN KEY (job_id)",
		"pool IN ('global', 'trivy')",
		"slot_number BETWEEN 1 AND 4",
		"heavy_slots BETWEEN 2 AND 4",
		"trivy_slots BETWEEN 1 AND heavy_slots",
		"('global', 4)",
		"('trivy', 4)",
		"VALUES (1, 2, 1)",
		"DROP TABLE IF EXISTS job_resource_limits",
		"DROP TABLE IF EXISTS job_resource_slots",
	} {
		if !strings.Contains(sql, fragment) {
			t.Fatalf("job resource slot migration lacks %q", fragment)
		}
	}
}

func TestNestedContainerBlobReferenceMigrationOwnsDerivedCASReferences(
	t *testing.T,
) {
	raw, err := migrations.FS.ReadFile(
		"00011_nested_container_blob_refs.sql",
	)
	if err != nil {
		t.Fatal(err)
	}
	sql := string(raw)
	for _, fragment := range []string{
		"CREATE TABLE IF NOT EXISTS file_node_blob_refs",
		"PRIMARY KEY (file_node_id)",
		"FOREIGN KEY (task_id, file_node_id)",
		"REFERENCES file_nodes (task_id, id)",
		"FOREIGN KEY (blob_id)",
		"REFERENCES blobs (id)",
		"DROP TABLE IF EXISTS file_node_blob_refs",
	} {
		if !strings.Contains(sql, fragment) {
			t.Fatalf("nested container blob migration lacks %q", fragment)
		}
	}
}

func TestAnalyzerRunsRecentIndexMigrationIsBoundedQuerySupport(t *testing.T) {
	raw, err := migrations.FS.ReadFile(
		"00008_analyzer_runs_recent_index.sql",
	)
	if err != nil {
		t.Fatal(err)
	}
	sql := string(raw)
	for _, fragment := range []string{
		"ADD INDEX idx_analyzer_runs_recent (created_at DESC, id DESC)",
		"DROP INDEX idx_analyzer_runs_recent",
	} {
		if !strings.Contains(sql, fragment) {
			t.Fatalf("analyzer-run index migration lacks %q", fragment)
		}
	}
}

func TestTaskEventStreamMigrationBackfillsWithoutElevatedPrivileges(t *testing.T) {
	raw, err := migrations.FS.ReadFile("00006_task_events_stream.sql")
	if err != nil {
		t.Fatal(err)
	}
	sql := string(raw)
	for _, fragment := range []string{
		"ADD COLUMN event_sequence BIGINT UNSIGNED NOT NULL DEFAULT 0",
		"information_schema.columns",
		"MAX(event_sequence) AS max_sequence",
		"'task.snapshot'",
		"DROP COLUMN event_sequence",
	} {
		if !strings.Contains(sql, fragment) {
			t.Fatalf("task event stream migration lacks %q", fragment)
		}
	}
	for _, forbidden := range []string{
		"CREATE TRIGGER", "CREATE FUNCTION", "CREATE PROCEDURE",
		"log_bin_trust_function_creators",
	} {
		if strings.Contains(sql, forbidden) {
			t.Fatalf(
				"task event migration requires elevated MySQL privilege via %q",
				forbidden,
			)
		}
	}
}

func TestInitialMigrationContainsPlannedTables(t *testing.T) {
	raw, err := migrations.FS.ReadFile("00001_initial.sql")
	if err != nil {
		t.Fatal(err)
	}
	sql := string(raw)
	tables := []string{
		"users", "sessions", "uploads", "upload_parts", "blobs", "tasks",
		"task_attempts", "jobs", "task_events", "file_nodes", "analyzer_runs",
		"decompile_results", "vulnerability_findings", "artifacts", "reports",
		"audit_logs", "trivy_database_bundles", "system_settings",
	}
	for _, table := range tables {
		if !strings.Contains(sql, "CREATE TABLE IF NOT EXISTS "+table+" (") {
			t.Errorf("initial migration does not create %s", table)
		}
		if !strings.Contains(sql, "DROP TABLE IF EXISTS "+table+";") {
			t.Errorf("initial migration does not drop %s", table)
		}
	}
}

func TestDecompileResultCacheIdentityIsGloballyUnique(t *testing.T) {
	raw, err := migrations.FS.ReadFile("00001_initial.sql")
	if err != nil {
		t.Fatal(err)
	}
	block := createTableBlock(t, string(raw), "decompile_results")
	if !strings.Contains(
		block,
		"UNIQUE KEY uq_decompile_results_cache (cache_key)",
	) {
		t.Fatal("decompile result cache_key is not globally unique")
	}
	if strings.Contains(block, "(task_id, cache_key)") {
		t.Fatal("decompile result cache_key uniqueness was weakened to task scope")
	}
}

func TestUploadContentTypeMigrationSupportsExistingRows(t *testing.T) {
	raw, err := migrations.FS.ReadFile("00002_upload_content_type.sql")
	if err != nil {
		t.Fatal(err)
	}
	sql := string(raw)
	if !strings.Contains(sql, "NOT NULL DEFAULT 'application/octet-stream'") {
		t.Fatal("content_type migration must provide a default for existing upload rows")
	}
}

func TestTaskIdempotencyMigrationIsReversible(t *testing.T) {
	raw, err := migrations.FS.ReadFile("00003_task_idempotency.sql")
	if err != nil {
		t.Fatal(err)
	}
	sql := string(raw)
	for _, fragment := range []string{
		"ADD COLUMN idempotency_key VARCHAR(128)",
		"UNIQUE KEY uq_tasks_creator_idempotency (created_by, idempotency_key)",
		"DROP INDEX uq_tasks_creator_idempotency",
		"DROP COLUMN idempotency_key",
	} {
		if !strings.Contains(sql, fragment) {
			t.Fatalf("task idempotency migration lacks %q", fragment)
		}
	}
}

func TestJobsClaimIndexMigrationMatchesClaimOrderingAndIsReversible(t *testing.T) {
	raw, err := migrations.FS.ReadFile("00004_jobs_claim_index.sql")
	if err != nil {
		t.Fatal(err)
	}
	sections := strings.Split(string(raw), "-- +goose Down")
	if len(sections) != 2 {
		t.Fatalf("jobs claim index migration sections = %d, want 2", len(sections))
	}
	up := sections[0]
	down := sections[1]
	for _, fragment := range []string{
		"DROP INDEX idx_jobs_claim",
		"kind,\n        status,\n        priority DESC,\n        available_at,\n        id",
	} {
		if !strings.Contains(up, fragment) {
			t.Fatalf("jobs claim index up migration lacks %q", fragment)
		}
	}
	if strings.Contains(up, "lease_until") {
		t.Fatal("jobs claim index must not put lease_until between the claim ordering columns")
	}
	for _, fragment := range []string{
		"DROP INDEX idx_jobs_claim",
		"kind,\n        status,\n        priority DESC,\n        available_at,\n        lease_until,\n        id",
	} {
		if !strings.Contains(down, fragment) {
			t.Fatalf("jobs claim index down migration lacks %q", fragment)
		}
	}
}

func TestTaskActionIdempotencyMigrationIsTaskScopedAndReversible(t *testing.T) {
	raw, err := migrations.FS.ReadFile("00005_task_action_idempotency.sql")
	if err != nil {
		t.Fatal(err)
	}
	sql := string(raw)
	for _, fragment := range []string{
		"CREATE TABLE IF NOT EXISTS task_action_requests",
		"PRIMARY KEY (task_id, action, idempotency_key)",
		"CHECK (action IN ('cancel', 'retry'))",
		"FOREIGN KEY (task_id) REFERENCES tasks (id) ON DELETE CASCADE",
		"DROP TABLE IF EXISTS task_action_requests",
	} {
		if !strings.Contains(sql, fragment) {
			t.Fatalf("task action idempotency migration lacks %q", fragment)
		}
	}
}

func TestDecompileResultCursorIndexMatchesStableOrdering(t *testing.T) {
	raw, err := migrations.FS.ReadFile(
		"00007_decompile_result_cursor_index.sql",
	)
	if err != nil {
		t.Fatal(err)
	}
	sections := strings.Split(string(raw), "-- +goose Down")
	if len(sections) != 2 {
		t.Fatalf(
			"decompile cursor index migration sections = %d, want 2",
			len(sections),
		)
	}
	if !strings.Contains(
		sections[0],
		"task_id,\n        created_at,\n        id",
	) {
		t.Fatal("decompile cursor index does not match list ordering")
	}
	if !strings.Contains(
		sections[1],
		"DROP INDEX idx_decompile_results_task_created_id",
	) {
		t.Fatal("decompile cursor index migration is not reversible")
	}
}

func TestInitialMigrationKeepsChildReferencesWithinTask(t *testing.T) {
	raw, err := migrations.FS.ReadFile("00001_initial.sql")
	if err != nil {
		t.Fatal(err)
	}
	sql := string(raw)
	constraints := []string{
		"FOREIGN KEY (task_id, parent_id) REFERENCES file_nodes (task_id, id)",
		"FOREIGN KEY (task_id, task_attempt_id) REFERENCES task_attempts (task_id, id)",
		"FOREIGN KEY (task_id, job_id) REFERENCES jobs (task_id, id)",
		"FOREIGN KEY (task_id, file_node_id) REFERENCES file_nodes (task_id, id)",
		"FOREIGN KEY (task_id, analyzer_run_id) REFERENCES analyzer_runs (task_id, id)",
		"FOREIGN KEY (task_id, artifact_id) REFERENCES artifacts (task_id, id)",
	}
	for _, constraint := range constraints {
		if !strings.Contains(sql, constraint) {
			t.Errorf("initial migration is missing task-domain constraint %q", constraint)
		}
	}

	referencedKeys := map[string]string{
		"task_attempts": "UNIQUE KEY uq_task_attempts_task_id_id (task_id, id)",
		"jobs":          "UNIQUE KEY uq_jobs_task_id_id (task_id, id)",
		"file_nodes":    "UNIQUE KEY uq_file_nodes_task_id_id (task_id, id)",
		"analyzer_runs": "UNIQUE KEY uq_analyzer_runs_task_id_id (task_id, id)",
		"artifacts":     "UNIQUE KEY uq_artifacts_task_id_id (task_id, id)",
	}
	for table, key := range referencedKeys {
		block := createTableBlock(t, sql, table)
		if !strings.Contains(block, key) {
			t.Errorf("%s does not contain referenced composite key %q", table, key)
		}
	}
	if strings.Contains(createTableBlock(t, sql, "task_events"), "uq_file_nodes_task_id_id") {
		t.Error("file_nodes composite key was placed in task_events")
	}
}

func createTableBlock(t *testing.T, migrationSQL, table string) string {
	t.Helper()
	startMarker := "CREATE TABLE IF NOT EXISTS " + table + " ("
	start := strings.Index(migrationSQL, startMarker)
	if start < 0 {
		t.Fatalf("table %s was not found", table)
	}
	end := strings.Index(migrationSQL[start:], ") ENGINE=InnoDB")
	if end < 0 {
		t.Fatalf("table %s has no ENGINE terminator", table)
	}
	return migrationSQL[start : start+end]
}

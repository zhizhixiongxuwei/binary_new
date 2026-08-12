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

func TestJavaAnalysisMigrationIsFencedAndRejectsLossyRollback(t *testing.T) {
	raw, err := migrations.FS.ReadFile("00032_java_analysis_domain.sql")
	if err != nil {
		t.Fatal(err)
	}
	sections := strings.Split(string(raw), "-- +goose Down")
	if len(sections) != 2 {
		t.Fatalf("migration sections = %d, want 2", len(sections))
	}
	up, down := sections[0], sections[1]
	for _, fragment := range []string{
		"CREATE TABLE IF NOT EXISTS java_analysis_runs",
		"CREATE TABLE IF NOT EXISTS java_analysis_findings",
		"uq_java_analysis_runs_active_project",
		"source_manifest_sha256",
		"input_sha256",
		"bundle_sha256",
		"status NOT IN ('succeeded', 'partial')",
		"analyzed_files <= parsed_files",
		"recovered_files <= parsed_files",
		"parsed_files + failed_files = source_file_count",
		"callable_signature VARCHAR(2048) NOT NULL",
		"logical_path VARCHAR(1024) CHARACTER SET utf8mb4",
		"COLLATE utf8mb4_0900_bin NOT NULL",
		"CHAR_LENGTH(callable_signature) > 0",
		"worker_kind = 'java_analysis'",
		"binaryscan-java-checker",
		"java-rules-v1",
		"ruleset_version IS NOT NULL",
	} {
		if !strings.Contains(up, fragment) {
			t.Errorf("up migration lacks %q", fragment)
		}
	}
	guard := strings.Index(down, "binaryscan_migration_32_rollback_guard")
	drop := strings.Index(down, "DROP TABLE IF EXISTS java_analysis_findings")
	if guard < 0 || drop < 0 || guard > drop ||
		!strings.Contains(down, "SELECT id FROM java_analysis_runs") ||
		!strings.Contains(down, "SELECT id FROM jobs WHERE kind = 'java_analysis'") ||
		!strings.Contains(down, "WHERE analyzer_name = 'binaryscan-java-checker'") {
		t.Fatal("down migration must reject data loss before dropping Java analysis tables")
	}
}

func TestMySQLJavaAnalysisMigrationRoundTripAndRollbackGuard(t *testing.T) {
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
	defer db.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	if err := Migrate(ctx, db); err != nil {
		t.Fatalf("migrate dedicated database to latest: %v", err)
	}
	assertMigrationVersion(t, ctx, db, 33)
	assertJavaAnalysisMigrationState(t, ctx, db, true)
	assertJavaAnalysisRunningTransitionAndUnicodePath(t, ctx, db)

	var javaData int
	if err := db.QueryRowContext(ctx, `
SELECT
    (SELECT COUNT(*) FROM java_analysis_runs) +
    (SELECT COUNT(*) FROM jobs WHERE kind = 'java_analysis') +
    (SELECT COUNT(*) FROM analyzer_runs
     WHERE analyzer_name = 'binaryscan-java-checker')`).Scan(&javaData); err != nil {
		t.Fatal(err)
	}
	if javaData != 0 {
		t.Fatalf("migration round-trip database contains %d Java-analysis rows", javaData)
	}

	goose.SetBaseFS(migrations.FS)
	if err := goose.SetDialect("mysql"); err != nil {
		t.Fatal(err)
	}
	assertJavaReportRollbackGuard(t, ctx, db)
	restoreLatest := true
	t.Cleanup(func() {
		if !restoreLatest {
			return
		}
		restoreCtx, restoreCancel := context.WithTimeout(
			context.Background(), 90*time.Second,
		)
		defer restoreCancel()
		_, _ = db.ExecContext(restoreCtx, `
DELETE FROM analyzer_runs
WHERE id = '00000000-0000-4000-8000-000000000032'`)
		if err := Migrate(restoreCtx, db); err != nil {
			t.Errorf("restore latest migration after Java round trip: %v", err)
		}
	})

	if err := goose.DownToContext(ctx, db, ".", 31); err != nil {
		t.Fatalf("migrate Java analysis domain down: %v", err)
	}
	assertMigrationVersion(t, ctx, db, 31)
	assertJavaAnalysisMigrationState(t, ctx, db, false)
	if err := goose.UpToContext(ctx, db, ".", 33); err != nil {
		t.Fatalf("migrate Java analysis domain up: %v", err)
	}
	assertJavaAnalysisMigrationState(t, ctx, db, true)

	connection, err := db.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := connection.ExecContext(ctx, "SET FOREIGN_KEY_CHECKS = 0"); err != nil {
		connection.Close()
		t.Fatal(err)
	}
	_, insertErr := connection.ExecContext(ctx, `
INSERT INTO analyzer_runs (
    id, task_id, analyzer_name, analyzer_version, status
)
VALUES (
    '00000000-0000-4000-8000-000000000032',
    '00000000-0000-4000-8000-000000000001',
    'binaryscan-java-checker', '0.1.0', 'queued'
)`)
	_, restoreForeignKeyErr := connection.ExecContext(
		ctx, "SET FOREIGN_KEY_CHECKS = 1",
	)
	closeErr := connection.Close()
	if insertErr != nil {
		t.Fatalf("insert Java rollback guard fixture: %v", insertErr)
	}
	if restoreForeignKeyErr != nil {
		t.Fatalf("restore foreign key checks: %v", restoreForeignKeyErr)
	}
	if closeErr != nil {
		t.Fatalf("close Java rollback guard connection: %v", closeErr)
	}
	guardErr := goose.DownToContext(ctx, db, ".", 31)
	if guardErr == nil || !strings.Contains(
		guardErr.Error(), "chk_no_java_analysis_before_rollback",
	) {
		t.Fatalf("migration 32 rollback guard error = %v", guardErr)
	}
	assertMigrationVersion(t, ctx, db, 32)
	if _, err := db.ExecContext(ctx, `
DELETE FROM analyzer_runs
WHERE id = '00000000-0000-4000-8000-000000000032'`); err != nil {
		t.Fatalf("delete Java rollback guard fixture: %v", err)
	}
	if err := Migrate(ctx, db); err != nil {
		t.Fatalf("restore latest migration after Java guard check: %v", err)
	}
	assertMigrationVersion(t, ctx, db, 33)
	restoreLatest = false
}

func assertJavaReportRollbackGuard(t *testing.T, ctx context.Context, db *sql.DB) {
	t.Helper()
	connection, err := db.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := connection.ExecContext(ctx, "SET FOREIGN_KEY_CHECKS = 0"); err != nil {
		connection.Close()
		t.Fatal(err)
	}
	const reportID = "00000000-0000-4000-8000-000000000333"
	const taskID = "00000000-0000-4000-8000-000000000001"
	const runID = "00000000-0000-4000-8000-000000000032"
	const projectID = "00000000-0000-4000-8000-000000000002"
	const digest = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	_, insertErr := connection.ExecContext(ctx, `
INSERT INTO report_java_analysis_runs (
    report_id, task_id, run_id, project_id, report_generation,
    run_completed_at, source_manifest_sha256, input_sha256
)
VALUES (?, ?, ?, ?, 1, UTC_TIMESTAMP(6), ?, ?)`,
		reportID, taskID, runID, projectID, digest, digest,
	)
	_, restoreErr := connection.ExecContext(ctx, "SET FOREIGN_KEY_CHECKS = 1")
	closeErr := connection.Close()
	if insertErr != nil {
		t.Fatalf("insert Java report rollback fixture: %v", insertErr)
	}
	if restoreErr != nil || closeErr != nil {
		t.Fatalf("restore Java report rollback fixture connection: restore=%v close=%v", restoreErr, closeErr)
	}

	guardErr := goose.DownToContext(ctx, db, ".", 32)
	if guardErr == nil || !strings.Contains(
		guardErr.Error(), "chk_no_java_report_dependencies_before_rollback",
	) {
		t.Fatalf("migration 33 rollback guard error = %v", guardErr)
	}
	assertMigrationVersion(t, ctx, db, 33)
	if _, err := db.ExecContext(ctx, `
DELETE FROM report_java_analysis_runs WHERE report_id = ?`, reportID); err != nil {
		t.Fatalf("delete Java report rollback fixture: %v", err)
	}
}

func assertJavaAnalysisRunningTransitionAndUnicodePath(
	t *testing.T,
	ctx context.Context,
	db *sql.DB,
) {
	t.Helper()
	connection, err := db.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	if _, err := connection.ExecContext(ctx, "SET FOREIGN_KEY_CHECKS = 0"); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_, _ = connection.ExecContext(context.Background(), "SET FOREIGN_KEY_CHECKS = 1")
	}()

	const runID = "00000000-0000-4000-8000-000000000332"
	const taskID = "00000000-0000-4000-8000-000000000001"
	const projectID = "00000000-0000-4000-8000-000000000002"
	const jobID = "00000000-0000-4000-8000-000000000003"
	const digest = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	if _, err := connection.ExecContext(ctx, `
INSERT INTO java_analysis_runs (
    id, task_id, source_project_id, job_id, status,
    source_manifest_sha256, input_sha256, source_size_bytes, source_file_count
)
VALUES (?, ?, ?, ?, 'queued', ?, ?, 16, 1)`,
		runID, taskID, projectID, jobID, digest, digest,
	); err != nil {
		t.Fatalf("insert queued Java analysis fixture: %v", err)
	}
	defer connection.ExecContext(
		context.Background(), "DELETE FROM java_analysis_runs WHERE id = ?", runID,
	)
	if _, err := connection.ExecContext(ctx, `
UPDATE java_analysis_runs
SET status = 'running', started_at = UTC_TIMESTAMP(6)
WHERE id = ?`, runID); err != nil {
		t.Fatalf("transition Java analysis to running before bundle publication: %v", err)
	}
	if _, err := connection.ExecContext(ctx, `
UPDATE java_analysis_runs
SET status = 'succeeded', bundle_sha256 = ?,
    analyzed_files = 1, parsed_files = 1,
    completed_at = UTC_TIMESTAMP(6)
WHERE id = ?`, digest, runID); err == nil {
		t.Fatal("terminal Java analysis accepted a NULL ruleset_version")
	}

	const unicodePath = "src/main/java/示例/入口.java"
	if _, err := connection.ExecContext(ctx, `
INSERT INTO java_analysis_findings (
    task_id, run_id, cwe, rule_id, severity,
    file_result_id, logical_path, binary_name,
    callable_kind, type_name, callable_name, callable_signature,
    start_line, start_column, end_line, end_column, message
)
VALUES (
    ?, ?, 'CWE-328', 'java-weak-message-digest', 'MEDIUM',
    '00000000-0000-4000-8000-000000000004', ?, '示例.入口',
    'method', '入口', '检查', '检查()', 1, 1, 1, 2, 'weak digest'
)`, taskID, runID, unicodePath); err != nil {
		t.Fatalf("insert Java finding with Unicode logical path: %v", err)
	}
	defer connection.ExecContext(
		context.Background(), "DELETE FROM java_analysis_findings WHERE run_id = ?", runID,
	)
	var storedPath string
	if err := connection.QueryRowContext(ctx, `
SELECT logical_path FROM java_analysis_findings WHERE run_id = ?`, runID).Scan(&storedPath); err != nil {
		t.Fatalf("read Unicode Java finding path: %v", err)
	}
	if storedPath != unicodePath {
		t.Fatalf("stored Java finding path = %q, want %q", storedPath, unicodePath)
	}
}

func assertJavaAnalysisMigrationState(
	t *testing.T,
	ctx context.Context,
	db *sql.DB,
	present bool,
) {
	t.Helper()
	want := 0
	if present {
		want = 1
	}
	var runs, findings, reports, javaJobConstraint, javaReadinessConstraint int
	if err := db.QueryRowContext(ctx, `
SELECT COUNT(*) FROM information_schema.tables
WHERE table_schema = DATABASE() AND table_name = 'java_analysis_runs'`).Scan(&runs); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRowContext(ctx, `
SELECT COUNT(*) FROM information_schema.tables
WHERE table_schema = DATABASE() AND table_name = 'java_analysis_findings'`).Scan(&findings); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRowContext(ctx, `
SELECT COUNT(*) FROM information_schema.tables
WHERE table_schema = DATABASE() AND table_name = 'report_java_analysis_runs'`).Scan(&reports); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRowContext(ctx, `
SELECT COUNT(*)
FROM information_schema.check_constraints
WHERE constraint_schema = DATABASE() AND constraint_name = 'chk_jobs_kind'
  AND check_clause LIKE '%java_analysis%'`).Scan(&javaJobConstraint); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRowContext(ctx, `
SELECT COUNT(*)
FROM information_schema.check_constraints
WHERE constraint_schema = DATABASE()
  AND constraint_name = 'chk_worker_readiness_kind'
  AND check_clause LIKE '%java_analysis%'`).Scan(&javaReadinessConstraint); err != nil {
		t.Fatal(err)
	}
	if runs != want || findings != want || reports != want ||
		javaJobConstraint != want || javaReadinessConstraint != want {
		t.Fatalf(
			"Java migration state = runs:%d findings:%d reports:%d jobs:%d readiness:%d; want %d",
			runs, findings, reports, javaJobConstraint, javaReadinessConstraint, want,
		)
	}
}

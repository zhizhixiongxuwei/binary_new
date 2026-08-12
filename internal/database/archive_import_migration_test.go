package database

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"sort"
	"strings"
	"testing"
	"time"

	"binaryscan/db/migrations"

	"github.com/go-sql-driver/mysql"
	"github.com/pressly/goose/v3"
)

func TestArchiveImportMigrationIsRetryableAndFenced(t *testing.T) {
	raw, err := migrations.FS.ReadFile("00035_archive_imports.sql")
	if err != nil {
		t.Fatal(err)
	}
	sections := strings.Split(string(raw), "-- +goose Down")
	if len(sections) != 2 {
		t.Fatalf("migration sections = %d, want 2", len(sections))
	}
	up, down := sections[0], sections[1]
	for _, fragment := range []string{
		"-- +goose NO TRANSACTION",
		"CREATE TABLE IF NOT EXISTS archive_imports",
		"CREATE TABLE IF NOT EXISTS archive_import_entries",
		"CREATE TABLE IF NOT EXISTS archive_import_task_batches",
		"CREATE TABLE IF NOT EXISTS archive_import_task_batch_items",
		"information_schema.referential_constraints",
		"fk_upload_intake_profiles_archive_import",
		"PREPARE archive_profile_fk_statement",
		"ON DELETE SET NULL",
		"detected_format IS NOT NULL AND detected_category IS NOT NULL",
		"KEY idx_archive_import_batches_creator (created_by)",
	} {
		if !strings.Contains(up, fragment) {
			t.Errorf("up migration lacks %q", fragment)
		}
	}
	if strings.Count(up, "CREATE TABLE IF NOT EXISTS archive_import") != 4 {
		t.Fatalf("archive migration does not define four retryable tables")
	}
	guard := strings.Index(down, "binaryscan_migration_35_rollback_guard")
	drop := strings.LastIndex(down, "DROP TABLE IF EXISTS archive_imports")
	if guard < 0 || drop < 0 || guard > drop {
		t.Fatal("down migration must reject data loss before dropping archive tables")
	}
	for _, durableTable := range []string{
		"archive_imports",
		"archive_import_entries",
		"archive_import_task_batches",
		"archive_import_task_batch_items",
		"upload_intake_profiles",
	} {
		if !strings.Contains(down, "FROM "+durableTable) {
			t.Errorf("down rollback guard does not inspect %s", durableTable)
		}
	}
	if !strings.Contains(down, "information_schema.referential_constraints") ||
		!strings.Contains(down, "DROP FOREIGN KEY fk_upload_intake_profiles_archive_import") {
		t.Fatal("down migration must remove the cross-migration foreign key conditionally")
	}
}

// This test intentionally owns and rewinds the database named by the DSN. The
// environment variable must therefore point at a dedicated migration-test DB.
func TestMySQLArchiveImportMigrationRecoveryAndRoundTrip(t *testing.T) {
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
	db.SetMaxOpenConns(4)
	db.SetMaxIdleConns(4)
	defer db.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	goose.SetBaseFS(migrations.FS)
	if err := goose.SetDialect("mysql"); err != nil {
		t.Fatal(err)
	}

	// Normalize a previously interrupted test database, then exercise a true
	// empty-schema migration through every embedded version.
	if err := Migrate(ctx, db); err != nil {
		t.Fatalf("normalize dedicated migration database: %v", err)
	}
	assertArchiveDomainEmpty(t, ctx, db)
	if err := goose.DownToContext(ctx, db, ".", 0); err != nil {
		t.Fatalf("reset dedicated migration database: %v", err)
	}
	if err := goose.UpToContext(ctx, db, ".", 35); err != nil {
		t.Fatalf("fresh migration 1 -> 35: %v", err)
	}
	assertMigrationVersion(t, ctx, db, 35)
	assertArchiveMigrationSchema(t, ctx, db)

	// This is both the supported 33 -> 35 upgrade and a full 35 -> 33 -> 35
	// round trip. Migration 35 must leave migration 34 independently usable.
	if err := goose.DownToContext(ctx, db, ".", 33); err != nil {
		t.Fatalf("round trip 35 -> 33: %v", err)
	}
	assertMigrationVersion(t, ctx, db, 33)
	assertArchiveMigrationAbsent(t, ctx, db, true)
	if err := goose.UpToContext(ctx, db, ".", 35); err != nil {
		t.Fatalf("upgrade 33 -> 35: %v", err)
	}
	assertArchiveMigrationSchema(t, ctx, db)

	// Simulate a process death after each implicitly committed DDL in Up. Goose
	// has not recorded version 35 at these points, so the complete Up script is
	// replayed and must converge without manual repair.
	if err := goose.DownToContext(ctx, db, ".", 34); err != nil {
		t.Fatalf("prepare crash recovery tests at version 34: %v", err)
	}
	crashPoints := archiveMigrationCrashPoints(t)
	for crashPoint := 1; crashPoint <= len(crashPoints); crashPoint++ {
		name := crashPoints[crashPoint-1]
		t.Run("recover_after_"+name, func(t *testing.T) {
			executeArchiveMigrationUntilDDL(t, ctx, db, crashPoint)
			assertMigrationVersion(t, ctx, db, 34)
			if err := goose.UpToContext(ctx, db, ".", 35); err != nil {
				t.Fatalf("replay migration 35 after %s: %v", name, err)
			}
			assertArchiveMigrationSchema(t, ctx, db)
			if err := goose.DownToContext(ctx, db, ".", 34); err != nil {
				t.Fatalf("reset after %s: %v", name, err)
			}
			assertArchiveMigrationAbsent(t, ctx, db, false)
		})
	}

	if err := goose.UpToContext(ctx, db, ".", 35); err != nil {
		t.Fatalf("restore migration 35 for constraint tests: %v", err)
	}
	assertArchiveProfileSetNull(t, ctx, db)
	assertArchiveRollbackGuard(t, ctx, db)
	if err := goose.UpToContext(ctx, db, ".", 35); err != nil {
		t.Fatalf("restore latest after archive rollback tests: %v", err)
	}
	assertArchiveMigrationSchema(t, ctx, db)
}

func archiveMigrationCrashPoints(t *testing.T) []string {
	t.Helper()
	statements := archiveMigrationUpStatements(t)
	var points []string
	for _, statement := range statements {
		compact := archiveCompactSQL(statement)
		switch {
		case strings.HasPrefix(compact, "CREATE TABLE IF NOT EXISTS archive_imports ("):
			points = append(points, "archive_imports_table")
		case compact == "EXECUTE archive_profile_fk_statement":
			points = append(points, "profile_foreign_key")
		case strings.HasPrefix(compact, "CREATE TABLE IF NOT EXISTS archive_import_entries ("):
			points = append(points, "entries_table")
		case strings.HasPrefix(compact, "CREATE TABLE IF NOT EXISTS archive_import_task_batches ("):
			points = append(points, "task_batches_table")
		case strings.HasPrefix(compact, "CREATE TABLE IF NOT EXISTS archive_import_task_batch_items ("):
			points = append(points, "batch_items_table")
		}
	}
	if len(points) != 5 {
		t.Fatalf("migration DDL crash points = %v, want 5", points)
	}
	return points
}

func executeArchiveMigrationUntilDDL(
	t *testing.T,
	ctx context.Context,
	db *sql.DB,
	wantDDL int,
) {
	t.Helper()
	connection, err := db.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	seenDDL := 0
	for _, statement := range archiveMigrationUpStatements(t) {
		if _, err := connection.ExecContext(ctx, statement); err != nil {
			t.Fatalf("execute crash prefix statement %q: %v", archiveCompactSQL(statement), err)
		}
		compact := archiveCompactSQL(statement)
		if strings.HasPrefix(compact, "CREATE TABLE IF NOT EXISTS archive_import") ||
			compact == "EXECUTE archive_profile_fk_statement" {
			seenDDL++
			if seenDDL == wantDDL {
				return
			}
		}
	}
	t.Fatalf("migration contains only %d DDL crash points, want %d", seenDDL, wantDDL)
}

func archiveMigrationUpStatements(t *testing.T) []string {
	t.Helper()
	raw, err := migrations.FS.ReadFile("00035_archive_imports.sql")
	if err != nil {
		t.Fatal(err)
	}
	up := strings.Split(string(raw), "-- +goose Down")[0]
	parts := strings.Split(up, ";")
	statements := make([]string, 0, len(parts))
	for _, part := range parts {
		if strings.TrimSpace(archiveCompactSQL(part)) != "" {
			statements = append(statements, strings.TrimSpace(part))
		}
	}
	return statements
}

func archiveCompactSQL(statement string) string {
	lines := strings.Split(statement, "\n")
	kept := lines[:0]
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "--") {
			continue
		}
		kept = append(kept, trimmed)
	}
	return strings.Join(kept, " ")
}

func assertArchiveMigrationSchema(t *testing.T, ctx context.Context, db *sql.DB) {
	t.Helper()
	expectedTables := []string{
		"archive_import_entries",
		"archive_import_task_batch_items",
		"archive_import_task_batches",
		"archive_imports",
	}
	rows, err := db.QueryContext(ctx, `
SELECT table_name
FROM information_schema.tables
WHERE table_schema = DATABASE()
  AND table_name LIKE 'archive_import%'
ORDER BY table_name`)
	if err != nil {
		t.Fatal(err)
	}
	var tables []string
	for rows.Next() {
		var table string
		if err := rows.Scan(&table); err != nil {
			rows.Close()
			t.Fatal(err)
		}
		tables = append(tables, table)
	}
	if err := rows.Close(); err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(tables) != fmt.Sprint(expectedTables) {
		t.Fatalf("archive tables = %v, want %v", tables, expectedTables)
	}

	expectedIndexes := map[string]string{
		"archive_imports/PRIMARY":                                               "0:id",
		"archive_imports/uq_archive_imports_upload":                             "0:upload_id",
		"archive_imports/idx_archive_imports_claim":                             "1:status,available_at,lease_until,id",
		"archive_imports/idx_archive_imports_owner_created":                     "1:created_by,created_at,id",
		"archive_imports/idx_archive_imports_lease":                             "1:status,lease_until",
		"archive_imports/idx_archive_imports_source_blob":                       "1:source_blob_id,source_blob_reference_released_at",
		"archive_import_entries/PRIMARY":                                        "0:id",
		"archive_import_entries/uq_archive_import_entries_public_id":            "0:public_id",
		"archive_import_entries/uq_archive_import_entries_ordinal":              "0:archive_import_id,ordinal",
		"archive_import_entries/uq_archive_import_entries_path":                 "0:archive_import_id,logical_path_hash",
		"archive_import_entries/uq_archive_import_entries_task":                 "0:task_id",
		"archive_import_entries/idx_archive_import_entries_page":                "1:archive_import_id,status,id",
		"archive_import_entries/idx_archive_import_entries_blob":                "1:blob_id,blob_reference_released_at",
		"archive_import_entries/idx_archive_import_entries_derived_upload":      "1:derived_upload_id",
		"archive_import_task_batches/PRIMARY":                                   "0:id",
		"archive_import_task_batches/uq_archive_import_batches_idempotency":     "0:archive_import_id,created_by,idempotency_key",
		"archive_import_task_batches/idx_archive_import_batches_recovery":       "1:status,updated_at,id",
		"archive_import_task_batches/idx_archive_import_batches_creator":        "1:created_by",
		"archive_import_task_batch_items/PRIMARY":                               "0:batch_id,entry_id",
		"archive_import_task_batch_items/uq_archive_import_batch_items_ordinal": "0:batch_id,ordinal",
		"archive_import_task_batch_items/idx_archive_import_batch_items_entry":  "1:entry_id",
		"archive_import_task_batch_items/idx_archive_import_batch_items_task":   "1:task_id",
	}
	actualIndexes := readArchiveIndexes(t, ctx, db)
	assertStringMap(t, "archive indexes", actualIndexes, expectedIndexes)

	expectedChecks := []string{
		"archive_import_entries/chk_archive_import_entries_blob",
		"archive_import_entries/chk_archive_import_entries_category",
		"archive_import_entries/chk_archive_import_entries_status",
		"archive_import_task_batch_items/chk_archive_import_batch_items_attempts",
		"archive_import_task_batch_items/chk_archive_import_batch_items_lease",
		"archive_import_task_batch_items/chk_archive_import_batch_items_ordinal",
		"archive_import_task_batch_items/chk_archive_import_batch_items_outcome",
		"archive_import_task_batches/chk_archive_import_batches_role",
		"archive_import_task_batches/chk_archive_import_batches_status",
		"archive_imports/chk_archive_imports_attempts",
		"archive_imports/chk_archive_imports_lease_state",
		"archive_imports/chk_archive_imports_root_format",
		"archive_imports/chk_archive_imports_source_key",
		"archive_imports/chk_archive_imports_status",
	}
	actualChecks := readArchiveChecks(t, ctx, db)
	if fmt.Sprint(actualChecks) != fmt.Sprint(expectedChecks) {
		t.Fatalf("archive CHECK constraints = %v, want %v", actualChecks, expectedChecks)
	}

	expectedForeignKeys := map[string]string{
		"archive_imports/fk_archive_imports_upload":                           "upload_id->uploads.id;NO ACTION;RESTRICT",
		"archive_imports/fk_archive_imports_creator":                          "created_by->users.id;NO ACTION;NO ACTION",
		"archive_imports/fk_archive_imports_source_blob":                      "source_blob_id->blobs.id;NO ACTION;NO ACTION",
		"archive_import_entries/fk_archive_import_entries_import":             "archive_import_id->archive_imports.id;NO ACTION;CASCADE",
		"archive_import_entries/fk_archive_import_entries_blob":               "blob_id->blobs.id;NO ACTION;NO ACTION",
		"archive_import_entries/fk_archive_import_entries_upload":             "derived_upload_id->uploads.id;NO ACTION;SET NULL",
		"archive_import_entries/fk_archive_import_entries_task":               "task_id->tasks.id;NO ACTION;SET NULL",
		"archive_import_task_batches/fk_archive_import_batches_import":        "archive_import_id->archive_imports.id;NO ACTION;CASCADE",
		"archive_import_task_batches/fk_archive_import_batches_creator":       "created_by->users.id;NO ACTION;NO ACTION",
		"archive_import_task_batch_items/fk_archive_import_batch_items_batch": "batch_id->archive_import_task_batches.id;NO ACTION;CASCADE",
		"archive_import_task_batch_items/fk_archive_import_batch_items_entry": "entry_id->archive_import_entries.id;NO ACTION;CASCADE",
		"archive_import_task_batch_items/fk_archive_import_batch_items_task":  "task_id->tasks.id;NO ACTION;SET NULL",
		"upload_intake_profiles/fk_upload_intake_profiles_archive_import":     "archive_import_id->archive_imports.id;NO ACTION;SET NULL",
	}
	actualForeignKeys := readArchiveForeignKeys(t, ctx, db)
	assertStringMap(t, "archive foreign keys", actualForeignKeys, expectedForeignKeys)
}

func readArchiveIndexes(t *testing.T, ctx context.Context, db *sql.DB) map[string]string {
	t.Helper()
	rows, err := db.QueryContext(ctx, `
SELECT table_name, index_name, MIN(non_unique),
       GROUP_CONCAT(column_name ORDER BY seq_in_index SEPARATOR ',')
FROM information_schema.statistics
WHERE table_schema = DATABASE()
  AND table_name IN (
      'archive_imports', 'archive_import_entries',
      'archive_import_task_batches', 'archive_import_task_batch_items'
  )
GROUP BY table_name, index_name`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	result := make(map[string]string)
	for rows.Next() {
		var table, index, columns string
		var nonUnique int
		if err := rows.Scan(&table, &index, &nonUnique, &columns); err != nil {
			t.Fatal(err)
		}
		result[table+"/"+index] = fmt.Sprintf("%d:%s", nonUnique, columns)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return result
}

func readArchiveChecks(t *testing.T, ctx context.Context, db *sql.DB) []string {
	t.Helper()
	rows, err := db.QueryContext(ctx, `
SELECT table_name, constraint_name
FROM information_schema.table_constraints
WHERE constraint_schema = DATABASE()
  AND constraint_type = 'CHECK'
  AND table_name IN (
      'archive_imports', 'archive_import_entries',
      'archive_import_task_batches', 'archive_import_task_batch_items'
  )
ORDER BY table_name, constraint_name`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var result []string
	for rows.Next() {
		var table, constraint string
		if err := rows.Scan(&table, &constraint); err != nil {
			t.Fatal(err)
		}
		result = append(result, table+"/"+constraint)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return result
}

func readArchiveForeignKeys(t *testing.T, ctx context.Context, db *sql.DB) map[string]string {
	t.Helper()
	rows, err := db.QueryContext(ctx, `
SELECT k.table_name, k.constraint_name, k.column_name,
       k.referenced_table_name, k.referenced_column_name,
       r.update_rule, r.delete_rule
FROM information_schema.key_column_usage AS k
JOIN information_schema.referential_constraints AS r
  ON r.constraint_schema = k.constraint_schema
 AND r.table_name = k.table_name
 AND r.constraint_name = k.constraint_name
WHERE k.constraint_schema = DATABASE()
  AND (
      k.table_name IN (
          'archive_imports', 'archive_import_entries',
          'archive_import_task_batches', 'archive_import_task_batch_items'
      ) OR (
          k.table_name = 'upload_intake_profiles' AND
          k.constraint_name = 'fk_upload_intake_profiles_archive_import'
      )
  )`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	result := make(map[string]string)
	for rows.Next() {
		var table, constraint, column, refTable, refColumn, updateRule, deleteRule string
		if err := rows.Scan(
			&table, &constraint, &column, &refTable, &refColumn, &updateRule, &deleteRule,
		); err != nil {
			t.Fatal(err)
		}
		result[table+"/"+constraint] = fmt.Sprintf(
			"%s->%s.%s;%s;%s", column, refTable, refColumn, updateRule, deleteRule,
		)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return result
}

func assertStringMap(t *testing.T, label string, got, want map[string]string) {
	t.Helper()
	if len(got) == len(want) {
		match := true
		for key, wantValue := range want {
			if got[key] != wantValue {
				match = false
				break
			}
		}
		if match {
			return
		}
	}
	keys := make([]string, 0, len(got)+len(want))
	seen := make(map[string]bool)
	for key := range got {
		seen[key] = true
		keys = append(keys, key)
	}
	for key := range want {
		if !seen[key] {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	var differences []string
	for _, key := range keys {
		if got[key] != want[key] {
			differences = append(differences, fmt.Sprintf("%s: got %q want %q", key, got[key], want[key]))
		}
	}
	t.Fatalf("%s differ:\n%s", label, strings.Join(differences, "\n"))
}

func assertArchiveMigrationAbsent(
	t *testing.T,
	ctx context.Context,
	db *sql.DB,
	expectProfileAbsent bool,
) {
	t.Helper()
	var archiveTables, profileFK, profileTables int
	if err := db.QueryRowContext(ctx, `
SELECT COUNT(*)
FROM information_schema.tables
WHERE table_schema = DATABASE()
  AND table_name IN (
      'archive_imports', 'archive_import_entries',
      'archive_import_task_batches', 'archive_import_task_batch_items'
  )`).Scan(&archiveTables); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRowContext(ctx, `
SELECT COUNT(*)
FROM information_schema.referential_constraints
WHERE constraint_schema = DATABASE()
  AND table_name = 'upload_intake_profiles'
  AND constraint_name = 'fk_upload_intake_profiles_archive_import'`).Scan(&profileFK); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRowContext(ctx, `
SELECT COUNT(*)
FROM information_schema.tables
WHERE table_schema = DATABASE()
  AND table_name = 'upload_intake_profiles'`).Scan(&profileTables); err != nil {
		t.Fatal(err)
	}
	wantProfileTables := 1
	if expectProfileAbsent {
		wantProfileTables = 0
	}
	if archiveTables != 0 || profileFK != 0 || profileTables != wantProfileTables {
		t.Fatalf(
			"archive migration residue = tables:%d profile_fk:%d profiles:%d; want 0/0/%d",
			archiveTables, profileFK, profileTables, wantProfileTables,
		)
	}
}

func assertArchiveDomainEmpty(t *testing.T, ctx context.Context, db *sql.DB) {
	t.Helper()
	var count int
	if err := db.QueryRowContext(ctx, `
SELECT
    (SELECT COUNT(*) FROM archive_imports) +
    (SELECT COUNT(*) FROM archive_import_entries) +
    (SELECT COUNT(*) FROM archive_import_task_batches) +
    (SELECT COUNT(*) FROM archive_import_task_batch_items)`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("dedicated migration database contains %d archive-domain rows", count)
	}
}

func assertArchiveProfileSetNull(t *testing.T, ctx context.Context, db *sql.DB) {
	t.Helper()
	const importID = "00000000-0000-4000-8000-000000000351"
	const uploadID = "00000000-0000-4000-8000-000000000352"
	insertArchiveImportFixture(t, ctx, db, importID, uploadID, true)
	if _, err := db.ExecContext(ctx, "DELETE FROM archive_imports WHERE id = ?", importID); err != nil {
		t.Fatalf("delete archive import for SET NULL test: %v", err)
	}
	var linked sql.NullString
	if err := db.QueryRowContext(ctx, `
SELECT archive_import_id
FROM upload_intake_profiles
WHERE upload_id = ?`, uploadID).Scan(&linked); err != nil {
		t.Fatalf("read intake profile after archive deletion: %v", err)
	}
	if linked.Valid {
		t.Fatalf("archive_import_id after parent deletion = %q, want NULL", linked.String)
	}
	if _, err := db.ExecContext(ctx, "DELETE FROM upload_intake_profiles WHERE upload_id = ?", uploadID); err != nil {
		t.Fatalf("delete SET NULL intake fixture: %v", err)
	}
}

func assertArchiveRollbackGuard(t *testing.T, ctx context.Context, db *sql.DB) {
	t.Helper()
	const importID = "00000000-0000-4000-8000-000000000353"
	const uploadID = "00000000-0000-4000-8000-000000000354"
	insertArchiveImportFixture(t, ctx, db, importID, uploadID, false)
	guardErr := goose.DownToContext(ctx, db, ".", 34)
	if guardErr == nil || !strings.Contains(
		guardErr.Error(), "chk_no_archive_import_before_rollback",
	) {
		t.Fatalf("migration 35 rollback guard error = %v", guardErr)
	}
	assertMigrationVersion(t, ctx, db, 35)
	assertArchiveMigrationSchema(t, ctx, db)
	if _, err := db.ExecContext(ctx, "DELETE FROM archive_imports WHERE id = ?", importID); err != nil {
		t.Fatalf("delete archive rollback fixture: %v", err)
	}
	if err := goose.DownToContext(ctx, db, ".", 34); err != nil {
		t.Fatalf("rollback empty archive domain: %v", err)
	}
	assertMigrationVersion(t, ctx, db, 34)
	assertArchiveMigrationAbsent(t, ctx, db, false)
}

func insertArchiveImportFixture(
	t *testing.T,
	ctx context.Context,
	db *sql.DB,
	importID string,
	uploadID string,
	withProfile bool,
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
	restored := false
	defer func() {
		if !restored {
			_, _ = connection.ExecContext(context.Background(), "SET FOREIGN_KEY_CHECKS = 1")
		}
	}()
	digest := strings.Repeat("a", 64)
	_, insertErr := connection.ExecContext(ctx, `
INSERT INTO archive_imports (
    id, upload_id, created_by, root_format,
    source_blob_id, source_storage_key, source_sha256, source_size_bytes,
    limits_snapshot
) VALUES (?, ?, 999999, 'zip', 999999, ?, ?, 1, JSON_OBJECT())`,
		importID, uploadID, "blobs/sha256/aa/"+digest, digest,
	)
	if insertErr == nil && withProfile {
		_, insertErr = connection.ExecContext(ctx, `
INSERT INTO upload_intake_profiles (
    upload_id, input_category, detected_category, detected_format,
    validation_status, source_kind, archive_import_id, validated_at
) VALUES (?, 'archive', 'archive', 'zip', 'valid', 'direct', ?, UTC_TIMESTAMP(6))`,
			uploadID, importID,
		)
	}
	_, restoreErr := connection.ExecContext(ctx, "SET FOREIGN_KEY_CHECKS = 1")
	restored = true
	if insertErr != nil {
		t.Fatalf("insert archive migration fixture: %v", insertErr)
	}
	if restoreErr != nil {
		t.Fatalf("restore foreign key checks: %v", restoreErr)
	}
}

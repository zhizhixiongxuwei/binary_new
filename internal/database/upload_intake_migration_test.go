package database

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"binaryscan/db/migrations"

	"github.com/go-sql-driver/mysql"
	"github.com/pressly/goose/v3"
)

func TestUploadIntakeProfileMigrationPreservesFrozenContract(t *testing.T) {
	raw, err := migrations.FS.ReadFile("00034_upload_intake_profiles.sql")
	if err != nil {
		t.Fatal(err)
	}
	sections := strings.Split(string(raw), "-- +goose Down")
	if len(sections) != 2 {
		t.Fatalf("migration sections = %d, want 2", len(sections))
	}
	up, down := sections[0], sections[1]
	for _, fragment := range []string{
		"CREATE TABLE IF NOT EXISTS upload_intake_profiles",
		"PRIMARY KEY (upload_id)",
		"input_category IN ('binary', 'archive', 'container')",
		"validation_status IN ('pending', 'valid', 'mismatch', 'unsupported')",
		"source_kind IN ('direct', 'archive_entry')",
		"source_parent_upload_id",
		"source_archive_name",
		"source_entry_path",
		"archive_import_id",
		"fk_upload_intake_upload",
		"validation_status = 'valid' AND\n            detected_category IS NOT NULL",
		"detected_format IS NOT NULL",
	} {
		if !strings.Contains(up, fragment) {
			t.Errorf("up migration lacks %q", fragment)
		}
	}
	guard := strings.Index(down, "binaryscan_migration_34_rollback_guard")
	drop := strings.LastIndex(down, "DROP TABLE IF EXISTS upload_intake_profiles")
	if guard < 0 || drop < 0 || guard > drop {
		t.Fatal("down migration must guard durable intake data before dropping the profile table")
	}
}

func TestMySQLUploadIntakeMigrationRoundTripAndRollbackGuard(t *testing.T) {
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
		if restoreLatest {
			_ = Migrate(context.Background(), db)
		}
	})

	const uploadID = "00000000-0000-4000-8000-000000000034"
	connection, err := db.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := connection.ExecContext(ctx, "SET FOREIGN_KEY_CHECKS = 0"); err != nil {
		connection.Close()
		t.Fatal(err)
	}
	_, insertUploadErr := connection.ExecContext(ctx, `
INSERT INTO uploads (
    id, created_by, original_name, display_name, content_type,
    declared_size_bytes, part_size_bytes, status, expires_at
) VALUES (?, 999999, ?, ?, 'application/octet-stream', 1, 1, 'created', ?)`,
		uploadID, []byte("migration.bin"), "migration.bin", time.Now().UTC().Add(time.Hour),
	)
	_, restoreForeignKeysErr := connection.ExecContext(ctx, "SET FOREIGN_KEY_CHECKS = 1")
	closeErr := connection.Close()
	if insertUploadErr != nil {
		t.Fatalf("insert intake rollback upload fixture: %v", insertUploadErr)
	}
	if restoreForeignKeysErr != nil || closeErr != nil {
		t.Fatalf("restore foreign keys/close connection = %v/%v", restoreForeignKeysErr, closeErr)
	}
	_, err = db.ExecContext(ctx, `
INSERT INTO upload_intake_profiles (
    upload_id, input_category, detected_format, validation_status,
    source_kind, validated_at
) VALUES (?, 'binary', 'pe32', 'valid', 'direct', UTC_TIMESTAMP(6))`, uploadID)
	assertMySQLCheckConstraint(
		t, err, "chk_upload_intake_validation_fields", "valid profile without detected_category",
	)
	_, err = db.ExecContext(ctx, `
INSERT INTO upload_intake_profiles (
    upload_id, input_category, detected_category, validation_status,
    source_kind, validated_at
) VALUES (?, 'binary', 'binary', 'valid', 'direct', UTC_TIMESTAMP(6))`, uploadID)
	assertMySQLCheckConstraint(
		t, err, "chk_upload_intake_validation_fields", "valid profile without detected_format",
	)
	if _, err := db.ExecContext(ctx, `
INSERT INTO upload_intake_profiles (
    upload_id, input_category, validation_status, source_kind
) VALUES (?, 'binary', 'pending', 'direct')`, uploadID); err != nil {
		t.Fatalf("insert intake rollback profile fixture: %v", err)
	}

	guardErr := goose.DownToContext(ctx, db, ".", 33)
	if guardErr == nil || !strings.Contains(guardErr.Error(), "chk_no_upload_intake_before_rollback") {
		t.Fatalf("migration 34 rollback guard error = %v", guardErr)
	}
	assertMigrationVersion(t, ctx, db, 34)
	if _, err := db.ExecContext(ctx, "DELETE FROM upload_intake_profiles WHERE upload_id = ?", uploadID); err != nil {
		t.Fatalf("delete intake rollback profile fixture: %v", err)
	}
	if _, err := db.ExecContext(ctx, "DELETE FROM uploads WHERE id = ?", uploadID); err != nil {
		t.Fatalf("delete intake rollback upload fixture: %v", err)
	}
	if err := goose.DownToContext(ctx, db, ".", 33); err != nil {
		t.Fatalf("rollback empty intake migration: %v", err)
	}
	assertMigrationVersion(t, ctx, db, 33)
	if err := Migrate(ctx, db); err != nil {
		t.Fatalf("restore latest migrations: %v", err)
	}
	restoreLatest = false
}

func assertMySQLCheckConstraint(
	t *testing.T,
	err error,
	constraint string,
	action string,
) {
	t.Helper()
	if err == nil {
		t.Fatalf("%s unexpectedly succeeded", action)
	}
	var mysqlErr *mysql.MySQLError
	if !errors.As(err, &mysqlErr) ||
		(mysqlErr.Number != 3819 && mysqlErr.Number != 4025) ||
		!strings.Contains(mysqlErr.Message, constraint) {
		t.Fatalf("%s error = %v, want %s CHECK violation", action, err, constraint)
	}
}

package sampleexport

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"binaryscan/internal/database"

	"github.com/go-sql-driver/mysql"
)

const (
	sampleExportIntegrationDSNFile = "BINARYSCAN_SAMPLE_EXPORT_INTEGRATION_DSN_FILE"
	sampleExportIntegrationRoot    = "BINARYSCAN_SAMPLE_EXPORT_INTEGRATION_REPOSITORY_ROOT"
)

func TestMySQLSampleExportRetentionAndIntegrityIntegration(t *testing.T) {
	dsnPath := strings.TrimSpace(os.Getenv(sampleExportIntegrationDSNFile))
	repositoryRoot := strings.TrimSpace(os.Getenv(sampleExportIntegrationRoot))
	if dsnPath == "" || repositoryRoot == "" {
		t.Skip(
			sampleExportIntegrationDSNFile + " and " +
				sampleExportIntegrationRoot + " are not set",
		)
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

	taskID := sampleExportIntegrationUUID(t)
	uploadID := sampleExportIntegrationUUID(t)
	publicID := sampleExportIntegrationUUID(t)
	content := []byte("sample export MySQL integration fixture")
	sum := sha256.Sum256(content)
	digest := hex.EncodeToString(sum[:])
	storageKey := "blobs/sha256/" + digest[:2] + "/" + digest
	blobPath := filepath.Join(
		repositoryRoot,
		filepath.FromSlash(storageKey),
	)

	result, err := db.ExecContext(ctx, `
INSERT INTO users (
    public_id, username, display_name, password_hash, role, status,
    force_password_change
) VALUES (?, ?, 'Sample Export Integration', 'not-used',
          'administrator', 'active', FALSE)`,
		publicID,
		"sample-export-"+strings.ReplaceAll(publicID[:13], "-", ""),
	)
	if err != nil {
		t.Fatalf("seed integration user: %v", err)
	}
	userID, err := result.LastInsertId()
	if err != nil || userID <= 0 {
		t.Fatalf("integration user ID = %d, %v", userID, err)
	}
	result, err = db.ExecContext(ctx, `
INSERT INTO blobs (
    sha256, size_bytes, storage_key, reference_count, state, verified_at
) VALUES (?, ?, ?, 2, 'available', UTC_TIMESTAMP(6))`,
		digest,
		len(content),
		storageKey,
	)
	if err != nil {
		t.Fatalf("seed integration blob: %v", err)
	}
	blobID, err := result.LastInsertId()
	if err != nil || blobID <= 0 {
		t.Fatalf("integration blob ID = %d, %v", blobID, err)
	}
	if _, err := db.ExecContext(ctx, `
INSERT INTO uploads (
    id, created_by, original_name, display_name, content_type,
    declared_size_bytes, part_size_bytes, actual_sha256, status, blob_id,
    expires_at, completed_at
) VALUES (?, ?, ?, 'private-original.bin', 'application/octet-stream',
          ?, ?, ?, 'completed', ?,
          DATE_ADD(UTC_TIMESTAMP(6), INTERVAL 1 DAY), UTC_TIMESTAMP(6))`,
		uploadID,
		userID,
		[]byte("private-original.bin"),
		len(content),
		len(content),
		digest,
		blobID,
	); err != nil {
		t.Fatalf("seed integration upload: %v", err)
	}
	if _, err := db.ExecContext(ctx, `
INSERT INTO tasks (
    id, upload_id, blob_id, created_by, name, tags, status,
    progress_basis_points, risk_level, limits_snapshot,
    sample_expires_at
) VALUES (?, ?, ?, ?, 'Sample export integration', JSON_ARRAY(),
          'SUCCEEDED', 10000, 'NONE', JSON_OBJECT(),
          DATE_ADD(UTC_TIMESTAMP(6), INTERVAL 1 DAY))`,
		taskID,
		uploadID,
		blobID,
		userID,
	); err != nil {
		t.Fatalf("seed integration task: %v", err)
	}
	if err := os.MkdirAll(filepath.Dir(blobPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(blobPath, content, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(
			context.Background(),
			10*time.Second,
		)
		defer cleanupCancel()
		_, _ = db.ExecContext(
			cleanupCtx,
			"DELETE FROM audit_logs WHERE object_type = 'task' AND object_id = ?",
			taskID,
		)
		_, _ = db.ExecContext(
			cleanupCtx,
			"DELETE FROM tasks WHERE id = ?",
			taskID,
		)
		_, _ = db.ExecContext(
			cleanupCtx,
			"DELETE FROM uploads WHERE id = ?",
			uploadID,
		)
		_, _ = db.ExecContext(
			cleanupCtx,
			"DELETE FROM blobs WHERE id = ?",
			blobID,
		)
		_, _ = db.ExecContext(
			cleanupCtx,
			"DELETE FROM users WHERE id = ?",
			userID,
		)
		_ = os.Remove(blobPath)
	})

	service, err := NewService(
		NewMySQLRepository(db),
		Config{RepositoryRoot: repositoryRoot},
	)
	if err != nil {
		t.Fatal(err)
	}
	assertSampleExportContent(t, ctx, service, taskID, content)

	if _, err := db.ExecContext(ctx, `
UPDATE uploads
SET status = 'expired', blob_id = NULL
WHERE id = ?`, uploadID); err != nil {
		t.Fatal(err)
	}
	assertSampleExportContent(t, ctx, service, taskID, content)

	if _, err := db.ExecContext(ctx, `
UPDATE tasks
SET sample_expires_at = UTC_TIMESTAMP(6)
WHERE id = ?`, taskID); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Open(ctx, taskID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expired sample Open() error = %v", err)
	}
	if _, err := db.ExecContext(ctx, `
UPDATE tasks
SET sample_expires_at = DATE_ADD(UTC_TIMESTAMP(6), INTERVAL 1 DAY),
    sample_deleted_at = UTC_TIMESTAMP(6)
WHERE id = ?`, taskID); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Open(ctx, taskID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("deleted sample Open() error = %v", err)
	}
}

func assertSampleExportContent(
	t *testing.T,
	ctx context.Context,
	service *Service,
	taskID string,
	expected []byte,
) {
	t.Helper()
	value, err := service.Open(ctx, taskID)
	if err != nil {
		t.Fatal(err)
	}
	actual, readErr := io.ReadAll(value.Content)
	closeErr := value.Content.Close()
	if readErr != nil || closeErr != nil {
		t.Fatalf("read/close sample export: %v / %v", readErr, closeErr)
	}
	if string(actual) != string(expected) ||
		value.Filename != DownloadFilename {
		t.Fatalf(
			"sample export content/filename = %q/%q",
			actual,
			value.Filename,
		)
	}
}

func sampleExportIntegrationUUID(t *testing.T) string {
	t.Helper()
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		t.Fatal(err)
	}
	value[6] = (value[6] & 0x0f) | 0x40
	value[8] = (value[8] & 0x3f) | 0x80
	return strings.ToLower(
		hex.EncodeToString(value[0:4]) + "-" +
			hex.EncodeToString(value[4:6]) + "-" +
			hex.EncodeToString(value[6:8]) + "-" +
			hex.EncodeToString(value[8:10]) + "-" +
			hex.EncodeToString(value[10:16]),
	)
}

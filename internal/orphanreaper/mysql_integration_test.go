package orphanreaper

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"binaryscan/internal/retention"

	"github.com/go-sql-driver/mysql"
)

const orphanCleanupIntegrationDSNFile = "BINARYSCAN_ORPHAN_CLEANUP_INTEGRATION_DSN_FILE"

func TestMySQLOrphanCleanupIntegration(t *testing.T) {
	dsnPath := strings.TrimSpace(os.Getenv(orphanCleanupIntegrationDSNFile))
	if dsnPath == "" {
		t.Skip(orphanCleanupIntegrationDSNFile + " is not set")
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
	t.Cleanup(func() { _ = db.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		t.Fatalf("ping integration database: %v", err)
	}

	repositoryRoot := filepath.Join(t.TempDir(), "repository")
	uploadsRoot := filepath.Join(t.TempDir(), "uploads")
	if err := os.MkdirAll(repositoryRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(uploadsRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	old := now.Add(-48 * time.Hour)
	orphanSHA, orphanPath := writeOrphanIntegrationBlob(
		t, repositoryRoot, []byte("unreferenced orphan blob"), old,
	)
	referencedSHA, referencedPath := writeOrphanIntegrationBlob(
		t, repositoryRoot, []byte("database referenced blob"), old,
	)
	referencedKey := storageKeyForSHA(referencedSHA)
	referencedBlobResult, err := db.ExecContext(ctx, `
INSERT INTO blobs (
    sha256, size_bytes, storage_key, reference_count, state, verified_at
) VALUES (?, ?, ?, 0, 'available', UTC_TIMESTAMP(6))`,
		referencedSHA, len("database referenced blob"), referencedKey,
	)
	if err != nil {
		t.Fatalf("seed referenced blob: %v", err)
	}
	referencedBlobID, err := referencedBlobResult.LastInsertId()
	if err != nil || referencedBlobID <= 0 {
		t.Fatalf("referenced blob ID = %d, %v", referencedBlobID, err)
	}

	// A database record whose file is missing is data-loss evidence, not a
	// safely deletable orphan. The filesystem-led reaper intentionally leaves
	// this record for a separate repair/health workflow.
	missingSHA := integrationSHA([]byte("intentionally missing blob file"))
	missingKey := storageKeyForSHA(missingSHA)
	if _, err := db.ExecContext(ctx, `
INSERT INTO blobs (
    sha256, size_bytes, storage_key, reference_count, state, verified_at
) VALUES (?, 31, ?, 0, 'available', UTC_TIMESTAMP(6))`, missingSHA, missingKey); err != nil {
		t.Fatalf("seed missing-file blob record: %v", err)
	}

	userPublicID := orphanIntegrationUUID(t)
	username := "orphan-" + strings.ReplaceAll(userPublicID[:13], "-", "")
	result, err := db.ExecContext(ctx, `
INSERT INTO users (
    public_id, username, display_name, password_hash, role, status,
    force_password_change
) VALUES (?, ?, 'Orphan cleanup integration', 'not-used', 'operator',
          'active', FALSE)`, userPublicID, username)
	if err != nil {
		t.Fatalf("seed integration user: %v", err)
	}
	userID, err := result.LastInsertId()
	if err != nil || userID <= 0 {
		t.Fatalf("integration user ID = %d, %v", userID, err)
	}
	orphanUploadID := orphanIntegrationUUID(t)
	referencedUploadID := orphanIntegrationUUID(t)
	writeOrphanIntegrationUpload(t, uploadsRoot, orphanUploadID, old)
	writeOrphanIntegrationUpload(t, uploadsRoot, referencedUploadID, old)
	if _, err := db.ExecContext(ctx, `
INSERT INTO uploads (
    id, created_by, original_name, display_name, declared_size_bytes,
    part_size_bytes, status, blob_id, expires_at
) VALUES (?, ?, 'active.bin', 'active.bin', 4, 1048576, 'uploading',
	          ?, DATE_ADD(UTC_TIMESTAMP(6), INTERVAL 1 DAY))`,
		referencedUploadID, userID, referencedBlobID,
	); err != nil {
		t.Fatalf("seed referenced upload: %v", err)
	}

	storedTaskID := orphanIntegrationUUID(t)
	storedReportID := orphanIntegrationUUID(t)
	storedResultID := orphanIntegrationUUID(t)
	storedKeys := []string{
		"reports/" + storedTaskID + "/" + storedReportID + ".json",
		"artifacts/" + storedTaskID + "/trivy/raw.json",
		"decompile/" + storedResultID + "/source.c",
	}
	storedDigests := make([]string, 0, len(storedKeys))
	for index, storageKey := range storedKeys {
		content := []byte(fmt.Sprintf("orphan stored output %d", index))
		writeStoredFileFixture(t, repositoryRoot, storageKey, content, old)
		storedDigests = append(storedDigests, integrationSHA(content))
	}

	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cleanupCancel()
		_, _ = db.ExecContext(cleanupCtx, `
DELETE FROM audit_logs
WHERE (action = 'maintenance.orphan_blob_removed' AND object_id = ?)
	   OR (action = 'maintenance.orphan_upload_removed' AND object_id = ?)
	   OR action = 'maintenance.blob_reference_reconciled'
	   OR (action = 'maintenance.orphan_stored_file_removed' AND object_id IN (?, ?, ?))`,
			orphanSHA, orphanUploadID,
			storedDigests[0], storedDigests[1], storedDigests[2],
		)
		_, _ = db.ExecContext(cleanupCtx, "DELETE FROM uploads WHERE id = ?", referencedUploadID)
		_, _ = db.ExecContext(cleanupCtx, "DELETE FROM users WHERE id = ?", userID)
		_, _ = db.ExecContext(
			cleanupCtx,
			"DELETE FROM blobs WHERE sha256 IN (?, ?)",
			referencedSHA,
			missingSHA,
		)
	})

	blobDeleter, err := retention.NewRepositoryBlobDeleter(repositoryRoot)
	if err != nil {
		t.Fatal(err)
	}
	uploadDeleter, err := retention.NewRepositoryUploadDirectoryDeleter(uploadsRoot)
	if err != nil {
		t.Fatal(err)
	}
	sweeper, err := NewSweeper(NewMySQLRepository(db), Config{
		RepositoryRoot: repositoryRoot,
		UploadsRoot:    uploadsRoot,
		GracePeriod:    DefaultGracePeriod,
		Now:            func() time.Time { return now },
		BlobDeleter:    blobDeleter,
		UploadDeleter:  uploadDeleter,
	})
	if err != nil {
		t.Fatal(err)
	}

	first, err := sweeper.Sweep(ctx, MaxSweepBatch)
	if err != nil {
		t.Fatalf("first Sweep(): %v", err)
	}
	if first.RemovedBlobs != 1 || first.RemovedUploads != 1 ||
		first.ReferencedBlobs != 1 || first.ReferencedUploads != 1 ||
		first.RemovedStoredFiles != 3 || first.CorrectedBlobReferences < 2 ||
		first.Failures != 0 {
		t.Fatalf("first Sweep() report = %+v", first)
	}
	assertIntegrationMissing(t, orphanPath)
	assertIntegrationMissing(t, filepath.Join(uploadsRoot, orphanUploadID))
	assertPresent(t, referencedPath)
	assertPresent(t, filepath.Join(uploadsRoot, referencedUploadID))
	for _, storageKey := range storedKeys {
		assertIntegrationMissing(
			t, filepath.Join(repositoryRoot, filepath.FromSlash(storageKey)),
		)
	}
	assertOrphanAuditCount(t, ctx, db, "maintenance.orphan_blob_removed", orphanSHA, 1)
	assertOrphanAuditCount(
		t, ctx, db, "maintenance.orphan_upload_removed", orphanUploadID, 1,
	)
	for _, digest := range storedDigests {
		assertOrphanAuditCount(
			t, ctx, db, "maintenance.orphan_stored_file_removed", digest, 1,
		)
	}
	var referencedCount uint64
	var referencedState string
	if err := db.QueryRowContext(ctx, `
SELECT reference_count, state FROM blobs WHERE id = ?`, referencedBlobID).Scan(
		&referencedCount, &referencedState,
	); err != nil {
		t.Fatal(err)
	}
	if referencedCount != 1 || referencedState != "available" {
		t.Fatalf(
			"reconciled referenced blob = count %d, state %s",
			referencedCount, referencedState,
		)
	}

	second, err := sweeper.Sweep(ctx, MaxSweepBatch)
	if err != nil || second.RemovedBlobs != 0 || second.RemovedUploads != 0 ||
		second.RemovedStoredFiles != 0 {
		t.Fatalf("repeated Sweep() = (%+v, %v)", second, err)
	}
	assertOrphanAuditCount(t, ctx, db, "maintenance.orphan_blob_removed", orphanSHA, 1)
	assertOrphanAuditCount(
		t, ctx, db, "maintenance.orphan_upload_removed", orphanUploadID, 1,
	)
	var missingRecordCount int
	if err := db.QueryRowContext(
		ctx,
		"SELECT COUNT(*) FROM blobs WHERE sha256 = ?",
		missingSHA,
	).Scan(&missingRecordCount); err != nil {
		t.Fatal(err)
	}
	if missingRecordCount != 1 {
		t.Fatalf("missing-file blob records = %d, want 1", missingRecordCount)
	}
	var missingState string
	if err := db.QueryRowContext(
		ctx, "SELECT state FROM blobs WHERE sha256 = ?", missingSHA,
	).Scan(&missingState); err != nil {
		t.Fatal(err)
	}
	if missingState != "deleting" {
		t.Fatalf("unreferenced missing-file blob state = %s, want deleting", missingState)
	}
}

func writeOrphanIntegrationBlob(
	t *testing.T,
	root string,
	content []byte,
	modified time.Time,
) (string, string) {
	t.Helper()
	sha := integrationSHA(content)
	path := filepath.Join(root, filepath.FromSlash(storageKeyForSHA(sha)))
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(path, modified, modified); err != nil {
		t.Fatal(err)
	}
	return sha, path
}

func writeOrphanIntegrationUpload(
	t *testing.T,
	root string,
	id string,
	modified time.Time,
) {
	t.Helper()
	path := filepath.Join(root, id)
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(path, modified, modified); err != nil {
		t.Fatal(err)
	}
}

func integrationSHA(content []byte) string {
	digest := sha256.Sum256(content)
	return hex.EncodeToString(digest[:])
}

func storageKeyForSHA(sha string) string {
	return "blobs/sha256/" + sha[:2] + "/" + sha
}

func orphanIntegrationUUID(t *testing.T) string {
	t.Helper()
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		t.Fatal(err)
	}
	value[6] = (value[6] & 0x0f) | 0x40
	value[8] = (value[8] & 0x3f) | 0x80
	return fmt.Sprintf(
		"%08x-%04x-%04x-%04x-%012x",
		value[0:4], value[4:6], value[6:8], value[8:10], value[10:16],
	)
}

func assertIntegrationMissing(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expected %s to be removed, err=%v", path, err)
	}
}

func assertOrphanAuditCount(
	t *testing.T,
	ctx context.Context,
	db *sql.DB,
	action string,
	objectID string,
	want int,
) {
	t.Helper()
	var count int
	if err := db.QueryRowContext(ctx, `
SELECT COUNT(*)
FROM audit_logs
WHERE action = ? AND object_id = ? AND outcome = 'success'`,
		action, objectID,
	).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != want {
		t.Fatalf("audit rows for %s/%s = %d, want %d", action, objectID, count, want)
	}
}

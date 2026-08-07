package upload

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"binaryscan/internal/retention"

	"github.com/go-sql-driver/mysql"
)

const (
	uploadRecoveryIntegrationDSNFile = "BINARYSCAN_UPLOAD_RECOVERY_INTEGRATION_DSN_FILE"
	uploadRecoveryRepositoryRoot     = "BINARYSCAN_UPLOAD_RECOVERY_INTEGRATION_REPOSITORY_ROOT"
	uploadRecoveryUploadsRoot        = "BINARYSCAN_UPLOAD_RECOVERY_INTEGRATION_UPLOADS_ROOT"
)

func TestMySQLPreparedUploadExpiryRecoveryIntegration(t *testing.T) {
	db, repositoryRoot, uploadsRoot := openUploadIntegrationDatabase(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	firstID, err := newUUID()
	if err != nil {
		t.Fatal(err)
	}
	secondID, err := newUUID()
	if err != nil {
		t.Fatal(err)
	}
	userPublicID, err := newUUID()
	if err != nil {
		t.Fatal(err)
	}
	result, err := db.ExecContext(ctx, `
INSERT INTO users (
    public_id, username, display_name, password_hash, role, status,
    force_password_change
) VALUES (?, ?, 'Upload Recovery Integration', 'not-used', 'administrator', 'active', FALSE)`,
		userPublicID,
		"upload-recovery-"+strings.ReplaceAll(userPublicID[:13], "-", ""),
	)
	if err != nil {
		t.Fatalf("seed upload recovery user: %v", err)
	}
	userID, err := result.LastInsertId()
	if err != nil || userID <= 0 {
		t.Fatalf("upload recovery user ID = %d, %v", userID, err)
	}

	content := []byte("prepared upload crash recovery fixture")
	digest := fmt.Sprintf("%x", sha256.Sum256(content))
	storageKey := "blobs/sha256/" + digest[:2] + "/" + digest
	blobPath := filepath.Join(repositoryRoot, filepath.FromSlash(storageKey))
	uploadIDs := []string{firstID, secondID}
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cleanupCancel()
		for _, uploadID := range uploadIDs {
			_, _ = db.ExecContext(
				cleanupCtx,
				"DELETE FROM audit_logs WHERE object_type = 'upload' AND object_id = ?",
				uploadID,
			)
			_, _ = db.ExecContext(
				cleanupCtx,
				"DELETE FROM upload_parts WHERE upload_id = ?",
				uploadID,
			)
			_, _ = db.ExecContext(cleanupCtx, "DELETE FROM uploads WHERE id = ?", uploadID)
			_ = os.RemoveAll(filepath.Join(uploadsRoot, uploadID))
		}
		_, _ = db.ExecContext(cleanupCtx, "DELETE FROM blobs WHERE sha256 = ?", digest)
		_, _ = db.ExecContext(cleanupCtx, "DELETE FROM users WHERE id = ?", userID)
		_ = os.Remove(blobPath)
	})

	for _, uploadID := range uploadIDs {
		if _, err := db.ExecContext(ctx, `
INSERT INTO uploads (
    id, created_by, original_name, display_name, content_type,
    declared_size_bytes, part_size_bytes, status, expires_at
) VALUES (
    ?, ?, ?, 'prepared.bin', 'application/octet-stream',
    ?, ?, 'uploading', DATE_SUB(UTC_TIMESTAMP(6), INTERVAL 1 HOUR)
)`,
			uploadID,
			userID,
			[]byte("prepared.bin"),
			len(content),
			len(content),
		); err != nil {
			t.Fatalf("seed prepared upload: %v", err)
		}
		partsDirectory := filepath.Join(uploadsRoot, uploadID, "parts")
		if err := os.MkdirAll(partsDirectory, 0o700); err != nil {
			t.Fatal(err)
		}
		partPath := filepath.Join(partsDirectory, "00000001.part")
		if err := os.WriteFile(partPath, content, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := db.ExecContext(ctx, `
INSERT INTO upload_parts (
    upload_id, part_number, size_bytes, sha256, content_range, storage_key
) VALUES (?, 1, ?, ?, ?, ?)`,
			uploadID,
			len(content),
			digest,
			fmt.Sprintf("bytes 0-%d/%d", len(content)-1, len(content)),
			filepath.ToSlash(filepath.Join(uploadID, "parts", "00000001.part")),
		); err != nil {
			t.Fatalf("seed prepared upload part: %v", err)
		}
	}

	uploadRepository := NewMySQLRepository(db)
	for _, uploadID := range uploadIDs {
		if err := uploadRepository.PrepareCompletion(
			ctx,
			uploadID,
			digest,
			int64(len(content)),
			storageKey,
		); err != nil {
			t.Fatalf("PrepareCompletion(%s): %v", uploadID, err)
		}
	}

	var (
		blobID         uint64
		blobState      string
		referenceCount uint64
	)
	if err := db.QueryRowContext(ctx, `
SELECT id, state, reference_count
FROM blobs
WHERE sha256 = ?`, digest).Scan(&blobID, &blobState, &referenceCount); err != nil {
		t.Fatal(err)
	}
	if blobState != "staging" || referenceCount != 2 {
		t.Fatalf("prepared shared blob = state %q, references %d", blobState, referenceCount)
	}
	if err := os.MkdirAll(filepath.Dir(blobPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(blobPath, content, 0o600); err != nil {
		t.Fatal(err)
	}

	uploadDeleter, err := retention.NewRepositoryUploadDirectoryDeleter(uploadsRoot)
	if err != nil {
		t.Fatal(err)
	}
	retentionRepository := retention.NewMySQLRepository(db)
	expired, err := retentionRepository.ExpireUpload(
		ctx,
		firstID,
		func() error {
			return uploadDeleter.Delete(ctx, firstID)
		},
	)
	if err != nil || !expired {
		t.Fatalf("expire first prepared upload = (%v, %v)", expired, err)
	}
	if err := db.QueryRowContext(ctx, `
SELECT state, reference_count
FROM blobs
WHERE id = ?`, blobID).Scan(&blobState, &referenceCount); err != nil {
		t.Fatal(err)
	}
	if blobState != "staging" || referenceCount != 1 {
		t.Fatalf("shared prepared blob after first expiry = %q/%d", blobState, referenceCount)
	}
	if _, err := os.Stat(blobPath); err != nil {
		t.Fatalf("shared prepared blob was removed: %v", err)
	}

	expired, err = retentionRepository.ExpireUpload(
		ctx,
		secondID,
		func() error {
			return uploadDeleter.Delete(ctx, secondID)
		},
	)
	if err != nil || !expired {
		t.Fatalf("expire second prepared upload = (%v, %v)", expired, err)
	}
	if err := db.QueryRowContext(ctx, `
SELECT state, reference_count
FROM blobs
WHERE id = ?`, blobID).Scan(&blobState, &referenceCount); err != nil {
		t.Fatal(err)
	}
	if blobState != "deleting" || referenceCount != 0 {
		t.Fatalf("last prepared blob after expiry = %q/%d", blobState, referenceCount)
	}

	blobDeleter, err := retention.NewRepositoryBlobDeleter(repositoryRoot)
	if err != nil {
		t.Fatal(err)
	}
	deleted, err := retentionRepository.FinalizeDeletingBlob(
		ctx,
		blobID,
		func(blob retention.Blob) error {
			return blobDeleter.Delete(ctx, blob)
		},
	)
	if err != nil || !deleted {
		t.Fatalf("finalize prepared blob deletion = (%v, %v)", deleted, err)
	}
	if _, err := os.Stat(blobPath); !os.IsNotExist(err) {
		t.Fatalf("zero-reference prepared blob still exists: %v", err)
	}

	for _, uploadID := range uploadIDs {
		var (
			status    string
			blobRef   sql.NullInt64
			cleanedAt sql.NullTime
			partCount int
		)
		if err := db.QueryRowContext(ctx, `
SELECT status, blob_id, parts_cleaned_at,
       (SELECT COUNT(*) FROM upload_parts WHERE upload_id = uploads.id)
FROM uploads
WHERE id = ?`, uploadID).Scan(
			&status,
			&blobRef,
			&cleanedAt,
			&partCount,
		); err != nil {
			t.Fatal(err)
		}
		if status != "expired" || blobRef.Valid || !cleanedAt.Valid || partCount != 0 {
			t.Fatalf(
				"expired prepared upload %s = %s/%v/%v/%d",
				uploadID,
				status,
				blobRef,
				cleanedAt,
				partCount,
			)
		}
	}
}

func TestMySQLConcurrentUploadCreateIdempotencyIntegration(t *testing.T) {
	db, repositoryRoot, uploadsRoot := openUploadIntegrationDatabase(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	firstUserID := seedUploadIntegrationUser(t, ctx, db, "first")
	secondUserID := seedUploadIntegrationUser(t, ctx, db, "second")
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cleanupCancel()
		_, _ = db.ExecContext(
			cleanupCtx,
			"DELETE FROM uploads WHERE created_by IN (?, ?)",
			firstUserID,
			secondUserID,
		)
		_, _ = db.ExecContext(
			cleanupCtx,
			"DELETE FROM users WHERE id IN (?, ?)",
			firstUserID,
			secondUserID,
		)
	})

	if err := os.MkdirAll(uploadsRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(repositoryRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	partDeleter, err := retention.NewRepositoryUploadDirectoryDeleter(uploadsRoot)
	if err != nil {
		t.Fatal(err)
	}
	serviceConfig := Config{
		UploadsRoot:    uploadsRoot,
		RepositoryRoot: repositoryRoot,
		MaxUploadBytes: 10 * 1024 * 1024 * 1024,
		PartSize:       DefaultPartSize,
		Retention:      30 * 24 * time.Hour,
		PartDeleter:    partDeleter,
		Now: func() time.Time {
			return time.Date(2026, 7, 31, 2, 0, 0, 0, time.UTC)
		},
	}
	service, err := NewService(NewMySQLRepository(db), serviceConfig)
	if err != nil {
		t.Fatal(err)
	}
	input := CreateInput{
		Filename:       "concurrent.bin",
		Size:           42,
		ContentType:    "application/octet-stream",
		CreatedBy:      uint64(firstUserID),
		IdempotencyKey: "mysql-concurrent-upload-create",
	}

	start := make(chan struct{})
	views := make([]View, 2)
	createErrors := make([]error, 2)
	var wait sync.WaitGroup
	for index := range views {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			views[index], createErrors[index] = service.Create(ctx, input)
		}()
	}
	close(start)
	wait.Wait()
	for index, createErr := range createErrors {
		if createErr != nil {
			t.Fatalf("concurrent Create()[%d] error = %v", index, createErr)
		}
	}
	if views[0].ID == "" || views[0].ID != views[1].ID ||
		views[0].Status != "created" || views[1].Status != "created" {
		t.Fatalf("concurrent Create() views = %#v / %#v", views[0], views[1])
	}

	fingerprint, err := createRequestFingerprint(input)
	if err != nil {
		t.Fatal(err)
	}
	var (
		rowCount          int
		storedOperation   string
		storedFingerprint string
	)
	if err := db.QueryRowContext(ctx, `
SELECT COUNT(*), MIN(idempotency_operation), MIN(request_fingerprint)
FROM uploads
WHERE created_by = ? AND idempotency_key = ?`,
		firstUserID,
		input.IdempotencyKey,
	).Scan(&rowCount, &storedOperation, &storedFingerprint); err != nil {
		t.Fatal(err)
	}
	if rowCount != 1 ||
		storedOperation != uploadCreateOperation ||
		storedFingerprint != fingerprint {
		t.Fatalf(
			"idempotency row = %d/%q/%q",
			rowCount,
			storedOperation,
			storedFingerprint,
		)
	}

	if _, err := db.ExecContext(
		ctx,
		"UPDATE uploads SET status = 'uploading' WHERE id = ?",
		views[0].ID,
	); err != nil {
		t.Fatal(err)
	}
	restartedService, err := NewService(NewMySQLRepository(db), serviceConfig)
	if err != nil {
		t.Fatal(err)
	}
	replayed, err := restartedService.Create(ctx, input)
	if err != nil {
		t.Fatalf("restarted Create() replay error = %v", err)
	}
	if replayed.ID != views[0].ID ||
		replayed.Status != "created" ||
		replayed.SHA256 != "" ||
		len(replayed.UploadedParts) != 0 {
		t.Fatalf("restarted Create() replay = %#v", replayed)
	}

	conflicting := input
	conflicting.Filename = "different.bin"
	if _, err := restartedService.Create(ctx, conflicting); !errors.Is(
		err,
		ErrIdempotencyConflict,
	) {
		t.Fatalf("conflicting Create() error = %v", err)
	}

	otherUser := input
	otherUser.CreatedBy = uint64(secondUserID)
	otherView, err := service.Create(ctx, otherUser)
	if err != nil {
		t.Fatal(err)
	}
	if otherView.ID == views[0].ID {
		t.Fatalf("another user's idempotency key resolved upload %q", otherView.ID)
	}
}

func openUploadIntegrationDatabase(t *testing.T) (*sql.DB, string, string) {
	t.Helper()
	dsnPath := strings.TrimSpace(os.Getenv(uploadRecoveryIntegrationDSNFile))
	repositoryRoot := strings.TrimSpace(os.Getenv(uploadRecoveryRepositoryRoot))
	uploadsRoot := strings.TrimSpace(os.Getenv(uploadRecoveryUploadsRoot))
	if dsnPath == "" || repositoryRoot == "" || uploadsRoot == "" {
		t.Skip(
			uploadRecoveryIntegrationDSNFile + ", " +
				uploadRecoveryRepositoryRoot + ", and " +
				uploadRecoveryUploadsRoot + " are not set",
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
	if err := db.PingContext(ctx); err != nil {
		t.Fatalf("ping integration database: %v", err)
	}
	return db, repositoryRoot, uploadsRoot
}

func seedUploadIntegrationUser(
	t *testing.T,
	ctx context.Context,
	db *sql.DB,
	label string,
) int64 {
	t.Helper()
	publicID, err := newUUID()
	if err != nil {
		t.Fatal(err)
	}
	result, err := db.ExecContext(ctx, `
INSERT INTO users (
    public_id, username, display_name, password_hash, role, status,
    force_password_change
) VALUES (?, ?, 'Upload Idempotency Integration', 'not-used', 'operator', 'active', FALSE)`,
		publicID,
		"upload-idempotency-"+label+"-"+strings.ReplaceAll(publicID[:8], "-", ""),
	)
	if err != nil {
		t.Fatalf("seed upload idempotency user: %v", err)
	}
	userID, err := result.LastInsertId()
	if err != nil || userID <= 0 {
		t.Fatalf("upload idempotency user ID = %d, %v", userID, err)
	}
	return userID
}

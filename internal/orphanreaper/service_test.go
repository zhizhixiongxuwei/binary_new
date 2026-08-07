package orphanreaper

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"binaryscan/internal/retention"
)

type repositoryStub struct {
	blobReferenceCandidates []BlobReferenceCandidate
	blobReconcileResults    map[uint64]BlobReferenceResult
	blobReferences          map[string]bool
	uploadReferences        map[string]bool
	storedReferences        map[string]bool
	protectBlobOnDelete     map[string]bool
	protectUploadOnDelete   map[string]bool
	protectStoredOnDelete   map[string]bool
	onBlobReference         func(BlobCandidate)
	onUploadReference       func(UploadCandidate)
	blobDeleteCalls         int
	uploadDeleteCalls       int
	storedDeleteCalls       int
}

func (s *repositoryStub) ListBlobReferenceCandidates(
	_ context.Context,
	afterID uint64,
	limit int,
) ([]BlobReferenceCandidate, error) {
	result := make([]BlobReferenceCandidate, 0, limit)
	for _, candidate := range s.blobReferenceCandidates {
		if candidate.ID > afterID && len(result) < limit {
			result = append(result, candidate)
		}
	}
	return result, nil
}

func (s *repositoryStub) ReconcileBlobReference(
	_ context.Context,
	candidate BlobReferenceCandidate,
	_ time.Time,
	dryRun bool,
) (BlobReferenceResult, error) {
	result := s.blobReconcileResults[candidate.ID]
	if dryRun {
		result.Corrected = false
	}
	return result, nil
}

func (s *repositoryStub) BlobReferenced(
	_ context.Context,
	candidate BlobCandidate,
) (bool, error) {
	if s.onBlobReference != nil {
		s.onBlobReference(candidate)
	}
	return s.blobReferences[candidate.SHA256], nil
}

func (s *repositoryStub) UploadReferenced(
	_ context.Context,
	candidate UploadCandidate,
) (bool, error) {
	if s.onUploadReference != nil {
		s.onUploadReference(candidate)
	}
	return s.uploadReferences[candidate.ID], nil
}

func (s *repositoryStub) StoredFileReferenced(
	_ context.Context,
	candidate StoredFileCandidate,
) (bool, error) {
	return s.storedReferences[candidate.StorageKey], nil
}

func (s *repositoryStub) DeleteOrphanBlob(
	ctx context.Context,
	candidate BlobCandidate,
	remove func(context.Context) error,
) (bool, error) {
	s.blobDeleteCalls++
	if s.protectBlobOnDelete[candidate.SHA256] {
		return false, nil
	}
	return true, remove(ctx)
}

func (s *repositoryStub) DeleteOrphanUpload(
	ctx context.Context,
	candidate UploadCandidate,
	remove func(context.Context) error,
) (bool, error) {
	s.uploadDeleteCalls++
	if s.protectUploadOnDelete[candidate.ID] {
		return false, nil
	}
	return true, remove(ctx)
}

func (s *repositoryStub) DeleteOrphanStoredFile(
	ctx context.Context,
	candidate StoredFileCandidate,
	remove func(context.Context) error,
) (bool, error) {
	s.storedDeleteCalls++
	if s.protectStoredOnDelete[candidate.StorageKey] {
		return false, nil
	}
	return true, remove(ctx)
}

func TestSweeperRemovesOnlyOldRecheckedOrphans(t *testing.T) {
	repositoryRoot := filepath.Join(t.TempDir(), "repository")
	uploadsRoot := filepath.Join(t.TempDir(), "uploads")
	if err := os.MkdirAll(repositoryRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(uploadsRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, time.August, 1, 12, 0, 0, 0, time.UTC)
	old := now.Add(-2 * DefaultGracePeriod)
	young := now.Add(-time.Hour)

	orphanSHA := strings.Repeat("a", 64)
	referencedSHA := strings.Repeat("b", 64)
	protectedSHA := strings.Repeat("c", 64)
	youngSHA := strings.Repeat("d", 64)
	orphanBlob := writeBlobFixture(t, repositoryRoot, orphanSHA, []byte("orphan"), old)
	referencedBlob := writeBlobFixture(t, repositoryRoot, referencedSHA, []byte("referenced"), old)
	protectedBlob := writeBlobFixture(t, repositoryRoot, protectedSHA, []byte("protected"), old)
	youngBlob := writeBlobFixture(t, repositoryRoot, youngSHA, []byte("young"), young)

	outside := filepath.Join(t.TempDir(), "outside")
	if err := os.WriteFile(outside, []byte("outside"), 0o600); err != nil {
		t.Fatal(err)
	}
	symlinkSHA := strings.Repeat("e", 64)
	symlinkParent := filepath.Join(repositoryRoot, "blobs", "sha256", symlinkSHA[:2])
	if err := os.MkdirAll(symlinkParent, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(symlinkParent, symlinkSHA)); err != nil {
		t.Fatal(err)
	}

	orphanUpload := "11111111-1111-4111-8111-111111111111"
	referencedUpload := "22222222-2222-4222-8222-222222222222"
	protectedUpload := "33333333-3333-4333-8333-333333333333"
	youngUpload := "44444444-4444-4444-8444-444444444444"
	writeUploadFixture(t, uploadsRoot, orphanUpload, old)
	writeUploadFixture(t, uploadsRoot, referencedUpload, old)
	writeUploadFixture(t, uploadsRoot, protectedUpload, old)
	writeUploadFixture(t, uploadsRoot, youngUpload, young)
	symlinkUpload := "55555555-5555-4555-8555-555555555555"
	if err := os.Symlink(filepath.Dir(outside), filepath.Join(uploadsRoot, symlinkUpload)); err != nil {
		t.Fatal(err)
	}

	repository := &repositoryStub{
		blobReferences:        map[string]bool{referencedSHA: true},
		uploadReferences:      map[string]bool{referencedUpload: true},
		protectBlobOnDelete:   map[string]bool{protectedSHA: true},
		protectUploadOnDelete: map[string]bool{protectedUpload: true},
	}
	blobDeleter, err := retention.NewRepositoryBlobDeleter(repositoryRoot)
	if err != nil {
		t.Fatal(err)
	}
	uploadDeleter, err := retention.NewRepositoryUploadDirectoryDeleter(uploadsRoot)
	if err != nil {
		t.Fatal(err)
	}
	sweeper, err := NewSweeper(repository, Config{
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

	report, err := sweeper.Sweep(context.Background(), MaxSweepBatch)
	if err != nil {
		t.Fatalf("Sweep() error = %v", err)
	}
	if report.RemovedBlobs != 1 || report.RemovedUploads != 1 ||
		report.ReferencedBlobs != 1 || report.ReferencedUploads != 1 ||
		report.RecheckProtected != 2 || report.DeferredYoungBlobs != 1 ||
		report.DeferredYoungUpload != 1 || report.Failures != 2 {
		t.Fatalf("Sweep() report = %+v", report)
	}
	assertMissing(t, orphanBlob)
	assertMissing(t, filepath.Join(uploadsRoot, orphanUpload))
	for _, path := range []string{
		referencedBlob, protectedBlob, youngBlob,
		filepath.Join(uploadsRoot, referencedUpload),
		filepath.Join(uploadsRoot, protectedUpload),
		filepath.Join(uploadsRoot, youngUpload), outside,
	} {
		assertPresent(t, path)
	}

	repeated, err := sweeper.Sweep(context.Background(), MaxSweepBatch)
	if err != nil {
		t.Fatalf("repeated Sweep() error = %v", err)
	}
	if repeated.RemovedBlobs != 0 || repeated.RemovedUploads != 0 {
		t.Fatalf("repeated Sweep() removed data: %+v", repeated)
	}
}

func TestSweeperReconcilesBlobCountsAndStoredFileOrphans(t *testing.T) {
	repositoryRoot := filepath.Join(t.TempDir(), "repository")
	uploadsRoot := filepath.Join(t.TempDir(), "uploads")
	if err := os.MkdirAll(repositoryRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(uploadsRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, time.August, 2, 12, 0, 0, 0, time.UTC)
	old := now.Add(-2 * DefaultGracePeriod)
	taskID := "71111111-1111-4111-8111-111111111111"
	reportID := "72222222-2222-4222-8222-222222222222"
	referencedReportID := "73333333-3333-4333-8333-333333333333"
	resultID := "74444444-4444-4444-8444-444444444444"
	orphanReportKey := "reports/" + taskID + "/" + reportID + ".json"
	referencedReportKey := "reports/" + taskID + "/" + referencedReportID + ".html"
	orphanArtifactKey := "artifacts/" + taskID + "/trivy/result.json"
	orphanDecompileKey := "decompile/" + resultID + "/source.c"
	for storageKey, content := range map[string]string{
		orphanReportKey:     "orphan report",
		referencedReportKey: "referenced report",
		orphanArtifactKey:   "orphan artifact",
		orphanDecompileKey:  "orphan decompile",
	} {
		writeStoredFileFixture(t, repositoryRoot, storageKey, []byte(content), old)
	}

	repository := &repositoryStub{
		blobReferenceCandidates: []BlobReferenceCandidate{{ID: 41}},
		blobReconcileResults: map[uint64]BlobReferenceResult{
			41: {Drifted: true, Corrected: true, PreviousCount: 9, ActualCount: 2},
		},
		storedReferences: map[string]bool{referencedReportKey: true},
	}
	blobDeleter, _ := retention.NewRepositoryBlobDeleter(repositoryRoot)
	uploadDeleter, _ := retention.NewRepositoryUploadDirectoryDeleter(uploadsRoot)
	sweeper, err := NewSweeper(repository, Config{
		RepositoryRoot: repositoryRoot, UploadsRoot: uploadsRoot,
		GracePeriod: DefaultGracePeriod, Now: func() time.Time { return now },
		BlobDeleter: blobDeleter, UploadDeleter: uploadDeleter,
	})
	if err != nil {
		t.Fatal(err)
	}
	report, err := sweeper.Sweep(context.Background(), MaxSweepBatch)
	if err != nil {
		t.Fatalf("Sweep() error = %v", err)
	}
	if report.BlobReferencesScanned != 1 || report.DriftedBlobReferences != 1 ||
		report.CorrectedBlobReferences != 1 || report.StoredFilesScanned != 4 ||
		report.ReferencedStoredFiles != 1 || report.OrphanStoredFiles != 3 ||
		report.RemovedStoredFiles != 3 || repository.storedDeleteCalls != 3 {
		t.Fatalf("reconciliation report = %+v", report)
	}
	for _, storageKey := range []string{
		orphanReportKey, orphanArtifactKey, orphanDecompileKey,
	} {
		assertMissing(t, filepath.Join(repositoryRoot, filepath.FromSlash(storageKey)))
	}
	assertPresent(
		t,
		filepath.Join(repositoryRoot, filepath.FromSlash(referencedReportKey)),
	)
}

func TestSweeperDryRunCollectsWithoutDeleting(t *testing.T) {
	repositoryRoot := filepath.Join(t.TempDir(), "repository")
	uploadsRoot := filepath.Join(t.TempDir(), "uploads")
	if err := os.MkdirAll(repositoryRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(uploadsRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	sha := strings.Repeat("f", 64)
	path := writeBlobFixture(t, repositoryRoot, sha, []byte("dry-run"), now.Add(-48*time.Hour))
	repository := &repositoryStub{}
	blobDeleter, _ := retention.NewRepositoryBlobDeleter(repositoryRoot)
	uploadDeleter, _ := retention.NewRepositoryUploadDirectoryDeleter(uploadsRoot)
	sweeper, err := NewSweeper(repository, Config{
		RepositoryRoot: repositoryRoot, UploadsRoot: uploadsRoot,
		GracePeriod: DefaultGracePeriod, DryRun: true,
		Now:         func() time.Time { return now },
		BlobDeleter: blobDeleter, UploadDeleter: uploadDeleter,
	})
	if err != nil {
		t.Fatal(err)
	}
	report, err := sweeper.Sweep(context.Background(), 10)
	if err != nil {
		t.Fatal(err)
	}
	if !report.DryRun || report.OrphanBlobs != 1 || report.RemovedBlobs != 0 ||
		repository.blobDeleteCalls != 0 {
		t.Fatalf("dry-run report = %+v, deletes=%d", report, repository.blobDeleteCalls)
	}
	assertPresent(t, path)
}

func TestSweeperRefusesCandidateReplacedAfterInventory(t *testing.T) {
	repositoryRoot := filepath.Join(t.TempDir(), "repository")
	uploadsRoot := filepath.Join(t.TempDir(), "uploads")
	if err := os.MkdirAll(repositoryRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(uploadsRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	sha := strings.Repeat("9", 64)
	path := writeBlobFixture(t, repositoryRoot, sha, []byte("before"), now.Add(-48*time.Hour))
	repository := &repositoryStub{}
	repository.onBlobReference = func(BlobCandidate) {
		replacement := path + ".replacement"
		if err := os.WriteFile(replacement, []byte("after!"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(replacement, path); err != nil {
			t.Fatal(err)
		}
		repository.onBlobReference = nil
	}
	blobDeleter, _ := retention.NewRepositoryBlobDeleter(repositoryRoot)
	uploadDeleter, _ := retention.NewRepositoryUploadDirectoryDeleter(uploadsRoot)
	sweeper, err := NewSweeper(repository, Config{
		RepositoryRoot: repositoryRoot, UploadsRoot: uploadsRoot,
		GracePeriod: DefaultGracePeriod, Now: func() time.Time { return now },
		BlobDeleter: blobDeleter, UploadDeleter: uploadDeleter,
	})
	if err != nil {
		t.Fatal(err)
	}
	report, err := sweeper.Sweep(context.Background(), 10)
	if err == nil || !errors.Is(err, ErrUnsafeInventory) || report.RemovedBlobs != 0 ||
		report.Failures != 1 {
		t.Fatalf("replaced candidate Sweep() = (%+v, %v)", report, err)
	}
	content, readErr := os.ReadFile(path)
	if readErr != nil || string(content) != "after!" {
		t.Fatalf("replacement was removed or changed: %q, %v", content, readErr)
	}
}

func TestSweeperRefusesUploadDirectoryReplacedAfterInventory(t *testing.T) {
	repositoryRoot := filepath.Join(t.TempDir(), "repository")
	uploadsRoot := filepath.Join(t.TempDir(), "uploads")
	if err := os.MkdirAll(repositoryRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(uploadsRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	uploadID := "66666666-6666-4666-8666-666666666666"
	writeUploadFixture(t, uploadsRoot, uploadID, now.Add(-48*time.Hour))
	uploadPath := filepath.Join(uploadsRoot, uploadID)
	repository := &repositoryStub{}
	repository.onUploadReference = func(UploadCandidate) {
		moved := uploadPath + ".old"
		if err := os.Rename(uploadPath, moved); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(uploadPath, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(uploadPath, "do-not-delete"), []byte("new"), 0o600); err != nil {
			t.Fatal(err)
		}
		repository.onUploadReference = nil
	}
	blobDeleter, _ := retention.NewRepositoryBlobDeleter(repositoryRoot)
	uploadDeleter, _ := retention.NewRepositoryUploadDirectoryDeleter(uploadsRoot)
	sweeper, err := NewSweeper(repository, Config{
		RepositoryRoot: repositoryRoot, UploadsRoot: uploadsRoot,
		GracePeriod: DefaultGracePeriod, Now: func() time.Time { return now },
		BlobDeleter: blobDeleter, UploadDeleter: uploadDeleter,
	})
	if err != nil {
		t.Fatal(err)
	}

	report, err := sweeper.Sweep(context.Background(), 10)
	if err == nil || !errors.Is(err, ErrUnsafeInventory) || report.RemovedUploads != 0 ||
		report.Failures != 1 {
		t.Fatalf("replaced upload Sweep() = (%+v, %v)", report, err)
	}
	content, readErr := os.ReadFile(filepath.Join(uploadPath, "do-not-delete"))
	if readErr != nil || string(content) != "new" {
		t.Fatalf("replacement upload directory was removed or changed: %q, %v", content, readErr)
	}
}

func TestNewSweeperRejectsUnsafeRoots(t *testing.T) {
	realRoot := t.TempDir()
	symlinkRoot := filepath.Join(t.TempDir(), "repository")
	if err := os.Symlink(realRoot, symlinkRoot); err != nil {
		t.Fatal(err)
	}
	uploadsRoot := t.TempDir()
	blobDeleter, _ := retention.NewRepositoryBlobDeleter(realRoot)
	uploadDeleter, _ := retention.NewRepositoryUploadDirectoryDeleter(uploadsRoot)
	_, err := NewSweeper(&repositoryStub{}, Config{
		RepositoryRoot: symlinkRoot, UploadsRoot: uploadsRoot,
		GracePeriod: DefaultGracePeriod,
		BlobDeleter: blobDeleter, UploadDeleter: uploadDeleter,
	})
	if !errors.Is(err, ErrUnsafeInventory) {
		t.Fatalf("NewSweeper() error = %v, want ErrUnsafeInventory", err)
	}
}

func writeBlobFixture(
	t *testing.T,
	root string,
	sha string,
	content []byte,
	modified time.Time,
) string {
	t.Helper()
	parent := filepath.Join(root, "blobs", "sha256", sha[:2])
	if err := os.MkdirAll(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(parent, sha)
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(path, modified, modified); err != nil {
		t.Fatal(err)
	}
	return path
}

func writeUploadFixture(t *testing.T, root string, id string, modified time.Time) {
	t.Helper()
	parts := filepath.Join(root, id, "parts")
	if err := os.MkdirAll(parts, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(parts, "00000001.part"), []byte("part"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(filepath.Join(root, id), modified, modified); err != nil {
		t.Fatal(err)
	}
}

func writeStoredFileFixture(
	t *testing.T,
	root string,
	storageKey string,
	content []byte,
	modified time.Time,
) string {
	t.Helper()
	filePath := filepath.Join(root, filepath.FromSlash(storageKey))
	if err := os.MkdirAll(filepath.Dir(filePath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filePath, content, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(filePath, modified, modified); err != nil {
		t.Fatal(err)
	}
	return filePath
}

func assertPresent(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Lstat(path); err != nil {
		t.Fatalf("expected %s to remain: %v", path, err)
	}
}

func assertMissing(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expected %s to be removed, err=%v", path, err)
	}
}

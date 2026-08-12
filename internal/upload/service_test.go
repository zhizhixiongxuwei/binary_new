package upload

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"binaryscan/internal/auth"
	"binaryscan/internal/filetype"
	"binaryscan/internal/inputcategory"
)

type contentDetectorStub struct {
	result filetype.Result
	err    error
}

func (d contentDetectorStub) DetectContext(
	context.Context,
	io.ReaderAt,
	int64,
) (filetype.Result, error) {
	return d.result, d.err
}

type repositoryStub struct {
	mu                    sync.Mutex
	upload                Upload
	parts                 []Part
	complete              bool
	completeCalls         int
	prepareCalls          int
	cleanupCalls          int
	cancelCalls           int
	hasTaskCalls          int
	prepareErr            error
	finalizeErr           error
	cleanupErr            error
	insertErr             error
	cancelErr             error
	hasTask               bool
	hasTaskErr            error
	taskID                string
	taskIDErr             error
	taskIDCalls           int
	directCandidates      []DirectTaskCandidate
	directCandidateCalls  []string
	archiveCandidates     []ArchiveImportCandidate
	archiveCandidateCalls []string
	createKey             string
	createFingerprint     string
}

type testUploadDirectoryDeleter struct {
	root  string
	err   error
	calls int
}

func (d *testUploadDirectoryDeleter) Delete(
	_ context.Context,
	uploadID string,
) error {
	d.calls++
	if d.err != nil {
		return d.err
	}
	if !uuidPattern.MatchString(uploadID) {
		return ErrInvalidInput
	}
	return os.RemoveAll(filepath.Join(d.root, uploadID))
}

type capacityGuardStub struct {
	createCalls   int
	partCalls     int
	assemblyCalls int
	releases      int
	err           error
	onCreate      func()
}

func (g *capacityGuardStub) CheckCreate(context.Context, int64) error {
	g.createCalls++
	if g.onCreate != nil {
		g.onCreate()
	}
	return g.err
}

func (g *capacityGuardStub) ReservePart(
	context.Context,
	int64,
) (func(), error) {
	g.partCalls++
	if g.err != nil {
		return nil, g.err
	}
	return func() { g.releases++ }, nil
}

func (g *capacityGuardStub) ReserveAssembly(
	context.Context,
	int64,
) (func(), error) {
	g.assemblyCalls++
	if g.err != nil {
		return nil, g.err
	}
	return func() { g.releases++ }, nil
}

func (r *repositoryStub) ResolveCreate(
	_ context.Context,
	createdBy uint64,
	_ string,
	key string,
	fingerprint string,
) (Upload, bool, error) {
	if r.upload.ID == "" || r.upload.CreatedBy != createdBy || r.createKey != key {
		return Upload{}, false, nil
	}
	if r.createFingerprint != fingerprint {
		return Upload{}, false, ErrIdempotencyConflict
	}
	replay := r.upload
	replay.Status = "created"
	replay.ActualSHA256 = ""
	replay.BlobID = nil
	replay.CompletedAt = nil
	return replay, true, nil
}
func (r *repositoryStub) Create(
	_ context.Context,
	value Upload,
	_ string,
	key string,
	fingerprint string,
) (Upload, bool, error) {
	if r.upload.ID != "" && r.createKey == key {
		if r.createFingerprint != fingerprint {
			return Upload{}, false, ErrIdempotencyConflict
		}
		return r.upload, false, nil
	}
	r.upload = value
	r.createKey = key
	r.createFingerprint = fingerprint
	return value, true, nil
}
func (r *repositoryStub) RecordValidation(
	_ context.Context,
	_ string,
	result ValidationResult,
) error {
	if r.upload.IntakeProfile == nil {
		return ErrNotFound
	}
	r.upload.IntakeProfile.DetectedCategory = result.DetectedCategory
	r.upload.IntakeProfile.DetectedFormat = result.DetectedFormat
	r.upload.IntakeProfile.ValidationStatus = result.Status
	r.upload.IntakeProfile.ValidationErrorCode = result.ErrorCode
	r.upload.IntakeProfile.ValidationErrorMessage = result.ErrorMessage
	r.upload.IntakeProfile.ValidatedAt = &result.ValidatedAt
	if result.Status == ValidationMismatch || result.Status == ValidationUnsupported {
		r.upload.Status = "failed"
	}
	return nil
}
func (r *repositoryStub) SetArchiveImportID(_ context.Context, _ string, id string) error {
	if r.upload.IntakeProfile == nil {
		return ErrNotFound
	}
	r.upload.IntakeProfile.ArchiveImportID = id
	return nil
}
func (r *repositoryStub) CreateDerivedCompleted(
	_ context.Context,
	record DerivedCompletedRecord,
) (Upload, bool, error) {
	if r.upload.ID != "" && r.createKey == record.IdempotencyKey {
		if r.createFingerprint != record.RequestFingerprint {
			return Upload{}, false, ErrIdempotencyConflict
		}
		return r.upload, false, nil
	}
	r.upload = record.Upload
	r.createKey = record.IdempotencyKey
	r.createFingerprint = record.RequestFingerprint
	return r.upload, true, nil
}
func (r *repositoryStub) Get(context.Context, string) (Upload, error) {
	if r.upload.ID == "" {
		return Upload{}, ErrNotFound
	}
	return r.upload, nil
}
func (r *repositoryStub) UploadHasTask(context.Context, string) (bool, error) {
	r.hasTaskCalls++
	return r.hasTask, r.hasTaskErr
}
func (r *repositoryStub) TaskIDForUpload(context.Context, string) (string, bool, error) {
	r.taskIDCalls++
	if r.taskIDErr != nil {
		return "", false, r.taskIDErr
	}
	return r.taskID, r.taskID != "", nil
}
func (r *repositoryStub) ListDirectTaskCandidates(
	_ context.Context,
	afterID string,
	limit int,
) ([]DirectTaskCandidate, error) {
	r.directCandidateCalls = append(r.directCandidateCalls, afterID)
	result := make([]DirectTaskCandidate, 0, limit)
	for _, candidate := range r.directCandidates {
		if candidate.UploadID > afterID && len(result) < limit {
			result = append(result, candidate)
		}
	}
	return result, nil
}
func (r *repositoryStub) ListArchiveImportCandidates(
	_ context.Context,
	afterID string,
	limit int,
) ([]ArchiveImportCandidate, error) {
	r.archiveCandidateCalls = append(r.archiveCandidateCalls, afterID)
	result := make([]ArchiveImportCandidate, 0, limit)
	for _, candidate := range r.archiveCandidates {
		if candidate.UploadID > afterID && len(result) < limit {
			result = append(result, candidate)
		}
	}
	return result, nil
}
func (r *repositoryStub) ListParts(context.Context, string) ([]Part, error) {
	return append([]Part(nil), r.parts...), nil
}
func (r *repositoryStub) InsertPart(_ context.Context, part Part) error {
	if r.insertErr != nil {
		return r.insertErr
	}
	r.parts = append(r.parts, part)
	r.upload.Status = "uploading"
	return nil
}
func (r *repositoryStub) PrepareCompletion(
	_ context.Context,
	_ string,
	hash string,
	_ int64,
	_ string,
) error {
	r.prepareCalls++
	if r.prepareErr != nil {
		return r.prepareErr
	}
	if r.upload.Status == "created" || r.upload.Status == "uploading" {
		blobID := uint64(1)
		r.upload.Status = "assembling"
		r.upload.ActualSHA256 = hash
		r.upload.BlobID = &blobID
	}
	return nil
}
func (r *repositoryStub) FinalizeCompletion(
	_ context.Context,
	_ string,
	hash string,
	completedAt time.Time,
) error {
	r.completeCalls++
	if r.finalizeErr != nil {
		return r.finalizeErr
	}
	r.complete = true
	r.upload.Status = "completed"
	r.upload.ActualSHA256 = hash
	r.upload.CompletedAt = &completedAt
	return nil
}
func (r *repositoryStub) CleanupParts(
	_ context.Context,
	_ string,
	deleteDirectory func() error,
) (bool, error) {
	r.cleanupCalls++
	if r.cleanupErr != nil {
		return false, r.cleanupErr
	}
	if r.upload.PartsCleanedAt != nil {
		return false, nil
	}
	if err := deleteDirectory(); err != nil {
		return false, err
	}
	r.parts = nil
	now := time.Now().UTC()
	r.upload.PartsCleanedAt = &now
	return true, nil
}
func (r *repositoryStub) Cancel(_ context.Context, _ string) error {
	r.cancelCalls++
	if r.cancelErr != nil {
		return r.cancelErr
	}
	r.upload.Status = "cancelled"
	r.upload.BlobID = nil
	return nil
}
func (r *repositoryStub) WithLock(ctx context.Context, _ string, fn func(context.Context) error) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return fn(ctx)
}

func TestUploadStreamsPartsAndCompletesContentAddressedBlob(t *testing.T) {
	service, repository, uploadsRoot, repositoryRoot := newTestService(t)
	ctx := context.Background()
	view, err := service.Create(ctx, CreateInput{
		Filename: "sample.bin", Size: 6, ContentType: "application/octet-stream", CreatedBy: 7,
		IdempotencyKey: "upload-create-key", InputCategory: inputcategory.Binary,
	})
	if err != nil {
		t.Fatal(err)
	}
	principal := auth.Principal{UserID: 7, Role: auth.RoleOperator}
	first := []byte("abcd")
	second := []byte("ef")
	if err := service.PutPart(
		ctx, view.ID, principal, 1,
		Range{Start: 0, End: 3, Total: 6, Raw: "bytes 0-3/6"},
		hashBytes(first), bytes.NewReader(first),
	); err != nil {
		t.Fatal(err)
	}
	if err := service.PutPart(
		ctx, view.ID, principal, 2,
		Range{Start: 4, End: 5, Total: 6, Raw: "bytes 4-5/6"},
		hashBytes(second), bytes.NewReader(second),
	); err != nil {
		t.Fatal(err)
	}
	partPath := filepath.Join(uploadsRoot, view.ID, "parts", "00000001.part")
	info, err := os.Stat(partPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("part permission = %o, want 0600", info.Mode().Perm())
	}

	completed, err := service.Complete(ctx, view.ID, principal)
	if err != nil {
		t.Fatal(err)
	}
	expectedHash := hashBytes([]byte("abcdef"))
	if !repository.complete || completed.Status != "completed" ||
		completed.SHA256 != expectedHash || completed.SizeBytes == nil || *completed.SizeBytes != 6 {
		t.Fatalf("unexpected completion: %#v", completed)
	}
	blobPath := filepath.Join(repositoryRoot, "blobs", "sha256", expectedHash[:2], expectedHash)
	blob, err := os.ReadFile(blobPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(blob) != "abcdef" {
		t.Fatalf("blob content = %q", blob)
	}
	if _, err := os.Stat(filepath.Join(uploadsRoot, view.ID)); !os.IsNotExist(err) {
		t.Fatalf("upload parts were not cleaned: %v", err)
	}
	again, err := service.Complete(ctx, view.ID, principal)
	if err != nil {
		t.Fatal(err)
	}
	if again.SHA256 != expectedHash || repository.completeCalls != 1 {
		t.Fatalf("idempotent completion = %#v, calls=%d", again, repository.completeCalls)
	}
}

func TestCompleteRecoversAfterPreparedBlobPublicationBeforeFinalization(t *testing.T) {
	service, repository, uploadsRoot, repositoryRoot := newTestService(t)
	ctx := context.Background()
	view, err := service.Create(ctx, CreateInput{
		Filename: "sample.bin", Size: 4,
		ContentType: "application/octet-stream", CreatedBy: 7,
		IdempotencyKey: "upload-create-key", InputCategory: inputcategory.Binary,
	})
	if err != nil {
		t.Fatal(err)
	}
	principal := auth.Principal{UserID: 7, Role: auth.RoleOperator}
	content := []byte("safe")
	if err := service.PutPart(
		ctx,
		view.ID,
		principal,
		1,
		Range{Start: 0, End: 3, Total: 4, Raw: "bytes 0-3/4"},
		hashBytes(content),
		bytes.NewReader(content),
	); err != nil {
		t.Fatal(err)
	}
	finalizeErr := errors.New("completion commit unavailable")
	repository.finalizeErr = finalizeErr
	if _, err := service.Complete(ctx, view.ID, principal); !errors.Is(err, finalizeErr) {
		t.Fatalf("first Complete() error = %v", err)
	}
	expectedHash := hashBytes(content)
	blobPath := filepath.Join(
		repositoryRoot,
		"blobs",
		"sha256",
		expectedHash[:2],
		expectedHash,
	)
	if content, err := os.ReadFile(blobPath); err != nil || string(content) != "safe" {
		t.Fatalf("prepared blob = %q, %v", content, err)
	}
	if repository.upload.Status != "assembling" || repository.upload.BlobID == nil {
		t.Fatalf("prepared upload = %#v", repository.upload)
	}
	if _, err := os.Stat(filepath.Join(uploadsRoot, view.ID)); err != nil {
		t.Fatalf("recoverable parts missing: %v", err)
	}

	repository.finalizeErr = nil
	completed, err := service.Complete(ctx, view.ID, principal)
	if err != nil {
		t.Fatal(err)
	}
	if completed.Status != "completed" || completed.SHA256 != expectedHash ||
		repository.upload.PartsCleanedAt == nil {
		t.Fatalf("replayed completion = %#v", completed)
	}
	if repository.prepareCalls != 2 || repository.completeCalls != 2 {
		t.Fatalf(
			"prepare/finalize calls = %d/%d",
			repository.prepareCalls,
			repository.completeCalls,
		)
	}
	if _, err := os.Stat(filepath.Join(uploadsRoot, view.ID)); !os.IsNotExist(err) {
		t.Fatalf("replayed completion retained upload parts: %v", err)
	}
}

func TestCompleteKeepsDurableCleanupPendingStateOnFilesystemFailure(t *testing.T) {
	service, repository, uploadsRoot, repositoryRoot := newTestService(t)
	ctx := context.Background()
	view, err := service.Create(ctx, CreateInput{
		Filename: "sample.bin", Size: 4,
		ContentType: "application/octet-stream", CreatedBy: 7,
		IdempotencyKey: "upload-create-key", InputCategory: inputcategory.Binary,
	})
	if err != nil {
		t.Fatal(err)
	}
	principal := auth.Principal{UserID: 7, Role: auth.RoleOperator}
	content := []byte("safe")
	if err := service.PutPart(
		ctx,
		view.ID,
		principal,
		1,
		Range{Start: 0, End: 3, Total: 4, Raw: "bytes 0-3/4"},
		hashBytes(content),
		bytes.NewReader(content),
	); err != nil {
		t.Fatal(err)
	}
	cleanupErr := errors.New("upload storage temporarily unavailable")
	repository.cleanupErr = cleanupErr
	completed, err := service.Complete(ctx, view.ID, principal)
	if err != nil {
		t.Fatalf("Complete() returned cleanup-only failure: %v", err)
	}
	if completed.Status != "completed" || repository.upload.PartsCleanedAt != nil {
		t.Fatalf("completion cleanup state = %#v", completed)
	}
	expectedHash := hashBytes(content)
	if _, err := os.Stat(filepath.Join(
		repositoryRoot,
		"blobs",
		"sha256",
		expectedHash[:2],
		expectedHash,
	)); err != nil {
		t.Fatalf("completed blob missing after cleanup failure: %v", err)
	}
	if _, err := os.Stat(filepath.Join(uploadsRoot, view.ID)); err != nil {
		t.Fatalf("pending upload directory missing: %v", err)
	}

	repository.cleanupErr = nil
	replayed, err := service.Complete(ctx, view.ID, principal)
	if err != nil {
		t.Fatal(err)
	}
	if repository.upload.PartsCleanedAt == nil || repository.completeCalls != 1 ||
		repository.cleanupCalls != 2 {
		t.Fatalf(
			"cleanup replay = %#v, finalize=%d cleanup=%d",
			replayed,
			repository.completeCalls,
			repository.cleanupCalls,
		)
	}
	if _, err := os.Stat(filepath.Join(uploadsRoot, view.ID)); !os.IsNotExist(err) {
		t.Fatalf("cleanup replay retained upload directory: %v", err)
	}
}

func TestPutPartIsIdempotentButRejectsDifferentContent(t *testing.T) {
	service, _, _, _ := newTestService(t)
	view, err := service.Create(context.Background(), CreateInput{
		Filename: "sample.bin", Size: 4, ContentType: "application/octet-stream", CreatedBy: 7,
		IdempotencyKey: "upload-create-key", InputCategory: inputcategory.Binary,
	})
	if err != nil {
		t.Fatal(err)
	}
	principal := auth.Principal{UserID: 7, Role: auth.RoleOperator}
	byteRange := Range{Start: 0, End: 3, Total: 4, Raw: "bytes 0-3/4"}
	hash := hashBytes([]byte("same"))
	if err := service.PutPart(context.Background(), view.ID, principal, 1, byteRange, hash, bytes.NewBufferString("same")); err != nil {
		t.Fatal(err)
	}
	if err := service.PutPart(context.Background(), view.ID, principal, 1, byteRange, hash, bytes.NewBufferString("ignored")); err != nil {
		t.Fatalf("idempotent PutPart() error = %v", err)
	}
	if err := service.PutPart(
		context.Background(), view.ID, principal, 1, byteRange,
		hashBytes([]byte("diff")), bytes.NewBufferString("diff"),
	); err != ErrConflict {
		t.Fatalf("conflicting PutPart() error = %v, want ErrConflict", err)
	}
}

func TestPutPartRecoversOrphanedPublishedPart(t *testing.T) {
	service, repository, uploadsRoot, _ := newTestService(t)
	view, err := service.Create(context.Background(), CreateInput{
		Filename: "sample.bin", Size: 4, ContentType: "application/octet-stream", CreatedBy: 7,
		IdempotencyKey: "upload-create-key", InputCategory: inputcategory.Binary,
	})
	if err != nil {
		t.Fatal(err)
	}
	orphanPath := filepath.Join(uploadsRoot, view.ID, "parts", "00000001.part")
	if err := os.MkdirAll(filepath.Dir(orphanPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(orphanPath, []byte("safe"), 0o600); err != nil {
		t.Fatal(err)
	}
	principal := auth.Principal{UserID: 7, Role: auth.RoleOperator}
	byteRange := Range{Start: 0, End: 3, Total: 4, Raw: "bytes 0-3/4"}
	if err := service.PutPart(
		context.Background(), view.ID, principal, 1, byteRange,
		hashBytes([]byte("safe")), bytes.NewBufferString("safe"),
	); err != nil {
		t.Fatal(err)
	}
	if len(repository.parts) != 1 {
		t.Fatalf("parts = %d, want 1", len(repository.parts))
	}
}

func TestPutPartCompensatesForDatabaseFailure(t *testing.T) {
	service, repository, uploadsRoot, _ := newTestService(t)
	view, err := service.Create(context.Background(), CreateInput{
		Filename: "sample.bin", Size: 4, ContentType: "application/octet-stream", CreatedBy: 7,
		IdempotencyKey: "upload-create-key", InputCategory: inputcategory.Binary,
	})
	if err != nil {
		t.Fatal(err)
	}
	repository.insertErr = errors.New("database unavailable")
	principal := auth.Principal{UserID: 7, Role: auth.RoleOperator}
	byteRange := Range{Start: 0, End: 3, Total: 4, Raw: "bytes 0-3/4"}
	err = service.PutPart(
		context.Background(), view.ID, principal, 1, byteRange,
		hashBytes([]byte("safe")), bytes.NewBufferString("safe"),
	)
	if err == nil {
		t.Fatal("PutPart() error = nil, want database failure")
	}
	path := filepath.Join(uploadsRoot, view.ID, "parts", "00000001.part")
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("published part was not compensated: %v", err)
	}
}

func TestConcurrentIdenticalPartUploadsAreIdempotent(t *testing.T) {
	service, repository, _, _ := newTestService(t)
	view, err := service.Create(context.Background(), CreateInput{
		Filename: "sample.bin", Size: 4, ContentType: "application/octet-stream", CreatedBy: 7,
		IdempotencyKey: "upload-create-key", InputCategory: inputcategory.Binary,
	})
	if err != nil {
		t.Fatal(err)
	}
	principal := auth.Principal{UserID: 7, Role: auth.RoleOperator}
	byteRange := Range{Start: 0, End: 3, Total: 4, Raw: "bytes 0-3/4"}
	hash := hashBytes([]byte("safe"))
	errs := make(chan error, 2)
	for range 2 {
		go func() {
			errs <- service.PutPart(
				context.Background(), view.ID, principal, 1, byteRange,
				hash, bytes.NewBufferString("safe"),
			)
		}()
	}
	for range 2 {
		if err := <-errs; err != nil {
			t.Errorf("PutPart() error = %v", err)
		}
	}
	if len(repository.parts) != 1 {
		t.Fatalf("parts = %d, want 1", len(repository.parts))
	}
}

func TestCompleteDetectsSameSizePartTampering(t *testing.T) {
	service, _, uploadsRoot, _ := newTestService(t)
	view, err := service.Create(context.Background(), CreateInput{
		Filename: "sample.bin", Size: 4, ContentType: "application/octet-stream", CreatedBy: 7,
		IdempotencyKey: "upload-create-key", InputCategory: inputcategory.Binary,
	})
	if err != nil {
		t.Fatal(err)
	}
	principal := auth.Principal{UserID: 7, Role: auth.RoleOperator}
	byteRange := Range{Start: 0, End: 3, Total: 4, Raw: "bytes 0-3/4"}
	if err := service.PutPart(
		context.Background(), view.ID, principal, 1, byteRange,
		hashBytes([]byte("safe")), bytes.NewBufferString("safe"),
	); err != nil {
		t.Fatal(err)
	}
	partPath := filepath.Join(uploadsRoot, view.ID, "parts", "00000001.part")
	if err := os.WriteFile(partPath, []byte("evil"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Complete(context.Background(), view.ID, principal); err != ErrHashMismatch {
		t.Fatalf("Complete() error = %v, want ErrHashMismatch", err)
	}
}

func TestCompleteRejectsPartStorageKeyOutsideUploadRoot(t *testing.T) {
	service, repository, uploadsRoot, _ := newTestService(t)
	view, err := service.Create(context.Background(), CreateInput{
		Filename: "sample.bin", Size: 4,
		ContentType: "application/octet-stream", CreatedBy: 7,
		IdempotencyKey: "upload-create-key", InputCategory: inputcategory.Binary,
	})
	if err != nil {
		t.Fatal(err)
	}
	principal := auth.Principal{UserID: 7, Role: auth.RoleOperator}
	if err := service.PutPart(
		context.Background(),
		view.ID,
		principal,
		1,
		Range{Start: 0, End: 3, Total: 4, Raw: "bytes 0-3/4"},
		hashBytes([]byte("safe")),
		bytes.NewBufferString("safe"),
	); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(filepath.Dir(uploadsRoot), "outside.part")
	if err := os.WriteFile(outside, []byte("safe"), 0o600); err != nil {
		t.Fatal(err)
	}
	repository.parts[0].StorageKey = "../outside.part"

	if _, err := service.Complete(
		context.Background(),
		view.ID,
		principal,
	); err != ErrInvalidInput {
		t.Fatalf("Complete() error = %v, want ErrInvalidInput", err)
	}
	if content, err := os.ReadFile(outside); err != nil || string(content) != "safe" {
		t.Fatalf("outside file changed: %q, %v", content, err)
	}
	if repository.prepareCalls != 0 {
		t.Fatalf("unsafe part reached completion preparation %d times", repository.prepareCalls)
	}
}

func TestCompleteSupportsEmptyFile(t *testing.T) {
	service, repository, _, repositoryRoot := newTestService(t)
	view, err := service.Create(context.Background(), CreateInput{
		Filename: "empty.bin", Size: 0, ContentType: "application/octet-stream", CreatedBy: 7,
		IdempotencyKey: "upload-create-key", InputCategory: inputcategory.Binary,
	})
	if err != nil {
		t.Fatal(err)
	}
	completed, err := service.Complete(
		context.Background(), view.ID,
		auth.Principal{UserID: 7, Role: auth.RoleOperator},
	)
	if err != nil {
		t.Fatal(err)
	}
	expectedHash := hashBytes(nil)
	if completed.SHA256 != expectedHash || completed.SizeBytes == nil || *completed.SizeBytes != 0 ||
		repository.completeCalls != 1 {
		t.Fatalf("completion = %#v, calls=%d", completed, repository.completeCalls)
	}
	path := filepath.Join(repositoryRoot, "blobs", "sha256", expectedHash[:2], expectedHash)
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Size() != 0 {
		t.Fatalf("empty blob size = %d", info.Size())
	}
}

func TestNewServiceRejectsUnsafeStorageConfiguration(t *testing.T) {
	root := t.TempDir()
	deleter := &testUploadDirectoryDeleter{root: root}
	valid := Config{
		UploadsRoot:    filepath.Join(root, "uploads"),
		RepositoryRoot: filepath.Join(root, "repository"),
		MaxUploadBytes: 1,
		PartSize:       1,
		Retention:      time.Hour,
		PartDeleter:    deleter,
	}
	tests := []struct {
		name   string
		mutate func(*Config)
	}{
		{
			name: "relative upload root",
			mutate: func(config *Config) {
				config.UploadsRoot = "uploads"
			},
		},
		{
			name: "filesystem root repository",
			mutate: func(config *Config) {
				config.RepositoryRoot = string(filepath.Separator)
			},
		},
		{
			name: "missing confined deleter",
			mutate: func(config *Config) {
				config.PartDeleter = nil
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			config := valid
			test.mutate(&config)
			if _, err := NewService(&repositoryStub{}, config); err == nil {
				t.Fatal("NewService() accepted unsafe storage configuration")
			}
		})
	}
}

func TestUploadOwnershipAndExpiryAreEnforced(t *testing.T) {
	service, repository, _, _ := newTestService(t)
	view, err := service.Create(context.Background(), CreateInput{
		Filename: "sample.bin", Size: 4, ContentType: "application/octet-stream", CreatedBy: 7,
		IdempotencyKey: "upload-create-key", InputCategory: inputcategory.Binary,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.Get(
		context.Background(), view.ID,
		auth.Principal{UserID: 8, Role: auth.RoleOperator},
	); err != ErrNotFound {
		t.Fatalf("other operator Get() error = %v, want ErrNotFound", err)
	}
	if _, err := service.Get(
		context.Background(), view.ID,
		auth.Principal{UserID: 8, Role: auth.RoleAdministrator},
	); err != nil {
		t.Fatalf("administrator Get() error = %v", err)
	}
	repository.upload.ExpiresAt = time.Date(2026, 7, 29, 11, 0, 0, 0, time.UTC)
	byteRange := Range{Start: 0, End: 3, Total: 4, Raw: "bytes 0-3/4"}
	err = service.PutPart(
		context.Background(), view.ID,
		auth.Principal{UserID: 7, Role: auth.RoleOperator},
		1, byteRange, hashBytes([]byte("safe")), bytes.NewBufferString("safe"),
	)
	if err != ErrExpired {
		t.Fatalf("expired PutPart() error = %v, want ErrExpired", err)
	}
}

func TestCreateRejectsUnsafeFilenameAndOversize(t *testing.T) {
	service, _, _, _ := newTestService(t)
	for _, input := range []CreateInput{
		{Filename: "../sample", Size: 1, ContentType: "application/octet-stream", CreatedBy: 1, IdempotencyKey: "upload-create-key", InputCategory: inputcategory.Binary},
		{Filename: "C:sample.bin", Size: 1, ContentType: "application/octet-stream", CreatedBy: 1, IdempotencyKey: "upload-create-key", InputCategory: inputcategory.Binary},
		{Filename: "sample\n.bin", Size: 1, ContentType: "application/octet-stream", CreatedBy: 1, IdempotencyKey: "upload-create-key", InputCategory: inputcategory.Binary},
		{Filename: "sample.bin", Size: 1025, ContentType: "application/octet-stream", CreatedBy: 1, IdempotencyKey: "upload-create-key", InputCategory: inputcategory.Binary},
		{Filename: "sample.bin", Size: 1, ContentType: "application/octet-stream", CreatedBy: 1, InputCategory: inputcategory.Binary},
		{Filename: "sample.bin", Size: 1, ContentType: "application/octet-stream", CreatedBy: 1, IdempotencyKey: "upload-create-key"},
		{Filename: "sample.bin", Size: 1, ContentType: "application/octet-stream", CreatedBy: 1, IdempotencyKey: "contains space"},
		{Filename: "sample.bin", Size: 1, ContentType: "application/octet-stream", CreatedBy: 1, IdempotencyKey: "contains\ncontrol"},
		{Filename: "sample.bin", Size: 1, ContentType: "application/octet-stream", CreatedBy: 1, IdempotencyKey: strings.Repeat("a", 129)},
	} {
		if _, err := service.Create(context.Background(), input); err != ErrInvalidInput {
			t.Errorf("Create(%#v) error = %v, want ErrInvalidInput", input, err)
		}
	}
}

func TestCreateReplayReturnsCreationSnapshotWithoutCapacityProbe(t *testing.T) {
	service, repository, _, _ := newTestService(t)
	guard := &capacityGuardStub{}
	service.config.CapacityGuard = guard
	input := CreateInput{
		Filename:       "sample.bin",
		Size:           4,
		ContentType:    "application/octet-stream",
		CreatedBy:      7,
		IdempotencyKey: "stable-create-key",
		InputCategory:  inputcategory.Binary,
	}

	first, err := service.Create(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	completedAt := time.Date(2026, 7, 29, 12, 30, 0, 0, time.UTC)
	blobID := uint64(91)
	repository.upload.Status = "completed"
	repository.upload.ActualSHA256 = strings.Repeat("a", 64)
	repository.upload.BlobID = &blobID
	repository.upload.CompletedAt = &completedAt
	repository.parts = []Part{{Number: 1}}
	guard.err = errors.New("capacity unavailable")

	replay, err := service.Create(context.Background(), input)
	if err != nil {
		t.Fatalf("Create() replay error = %v", err)
	}
	if replay.ID != first.ID ||
		replay.PartSize != first.PartSize ||
		!replay.ExpiresAt.Equal(first.ExpiresAt) ||
		replay.SizeBytes == nil ||
		first.SizeBytes == nil ||
		*replay.SizeBytes != *first.SizeBytes ||
		replay.Status != "created" ||
		replay.SHA256 != "" ||
		replay.UploadedParts == nil ||
		len(replay.UploadedParts) != 0 {
		t.Fatalf("Create() replay = %#v, want original creation snapshot %#v", replay, first)
	}
	if guard.createCalls != 1 {
		t.Fatalf("capacity guard calls = %d, want only the original request", guard.createCalls)
	}

	conflicting := input
	conflicting.Filename = "different.bin"
	if _, err := service.Create(context.Background(), conflicting); !errors.Is(
		err,
		ErrIdempotencyConflict,
	) {
		t.Fatalf("conflicting Create() error = %v, want ErrIdempotencyConflict", err)
	}
	if guard.createCalls != 1 {
		t.Fatalf("conflicting replay reached capacity guard %d times", guard.createCalls)
	}
}

func TestCreateCapacityFailureRechecksConcurrentIdempotencyWinner(t *testing.T) {
	service, repository, _, _ := newTestService(t)
	capacityErr := errors.New("capacity unavailable")
	input := CreateInput{
		Filename:       "sample.bin",
		Size:           4,
		ContentType:    "application/octet-stream",
		CreatedBy:      7,
		IdempotencyKey: "concurrent-create-key",
		InputCategory:  inputcategory.Binary,
	}
	fingerprint, err := createRequestFingerprint(input)
	if err != nil {
		t.Fatal(err)
	}
	winner := Upload{
		ID:             "123e4567-e89b-42d3-a456-426614174000",
		CreatedBy:      input.CreatedBy,
		OriginalName:   []byte(input.Filename),
		DisplayName:    input.Filename,
		ContentType:    input.ContentType,
		DeclaredSize:   input.Size,
		PartSize:       service.config.PartSize,
		Status:         "created",
		ExpiresAt:      time.Date(2026, 7, 29, 13, 0, 0, 0, time.UTC),
		CreatedAt:      time.Date(2026, 7, 29, 12, 0, 0, 0, time.UTC),
		PartsCleanedAt: nil,
	}
	guard := &capacityGuardStub{
		err: capacityErr,
		onCreate: func() {
			repository.upload = winner
			repository.createKey = input.IdempotencyKey
			repository.createFingerprint = fingerprint
		},
	}
	service.config.CapacityGuard = guard

	view, err := service.Create(context.Background(), input)
	if err != nil {
		t.Fatalf("Create() concurrent replay error = %v", err)
	}
	if view.ID != winner.ID || view.Status != "created" {
		t.Fatalf("Create() concurrent replay = %#v", view)
	}
	if guard.createCalls != 1 {
		t.Fatalf("capacity guard calls = %d, want 1", guard.createCalls)
	}
}

func TestCreateCapacityFailureRecheckPreservesFingerprintConflict(t *testing.T) {
	service, repository, _, _ := newTestService(t)
	capacityErr := errors.New("capacity unavailable")
	input := CreateInput{
		Filename:       "sample.bin",
		Size:           4,
		ContentType:    "application/octet-stream",
		CreatedBy:      7,
		IdempotencyKey: "concurrent-conflict-key",
		InputCategory:  inputcategory.Binary,
	}
	guard := &capacityGuardStub{
		err: capacityErr,
		onCreate: func() {
			repository.upload = Upload{
				ID:           "123e4567-e89b-42d3-a456-426614174000",
				CreatedBy:    input.CreatedBy,
				OriginalName: []byte("different.bin"),
				DisplayName:  "different.bin",
				ContentType:  input.ContentType,
				DeclaredSize: input.Size,
				PartSize:     service.config.PartSize,
				Status:       "created",
				ExpiresAt:    time.Date(2026, 7, 29, 13, 0, 0, 0, time.UTC),
			}
			repository.createKey = input.IdempotencyKey
			repository.createFingerprint = strings.Repeat("f", 64)
		},
	}
	service.config.CapacityGuard = guard

	if _, err := service.Create(context.Background(), input); !errors.Is(
		err,
		ErrIdempotencyConflict,
	) {
		t.Fatalf(
			"Create() concurrent conflicting replay error = %v, want ErrIdempotencyConflict",
			err,
		)
	}
}

func TestCapacityGuardRunsAfterDomainValidationAndBeforeWrites(t *testing.T) {
	service, repository, uploadsRoot, _ := newTestService(t)
	guard := &capacityGuardStub{}
	service.config.CapacityGuard = guard
	ctx := context.Background()

	if _, err := service.Create(ctx, CreateInput{
		Filename: "../sample", Size: 4,
		ContentType: "application/octet-stream", CreatedBy: 7,
		IdempotencyKey: "upload-create-key", InputCategory: inputcategory.Binary,
	}); err != ErrInvalidInput {
		t.Fatalf("invalid Create() error = %v", err)
	}
	if guard.createCalls != 0 {
		t.Fatalf("invalid create reached capacity guard %d times", guard.createCalls)
	}

	view, err := service.Create(ctx, CreateInput{
		Filename: "sample.bin", Size: 4,
		ContentType: "application/octet-stream", CreatedBy: 7,
		IdempotencyKey: "upload-create-key", InputCategory: inputcategory.Binary,
	})
	if err != nil {
		t.Fatal(err)
	}
	principal := auth.Principal{UserID: 7, Role: auth.RoleOperator}
	validRange := Range{
		Start: 0, End: 3, Total: 4, Raw: "bytes 0-3/4",
	}
	if err := service.PutPart(
		ctx,
		view.ID,
		principal,
		1,
		Range{Start: 0, End: 2, Total: 4, Raw: "bytes 0-2/4"},
		hashBytes([]byte("bad")),
		bytes.NewBufferString("bad"),
	); err != ErrRangeMismatch {
		t.Fatalf("invalid PutPart() error = %v", err)
	}
	if guard.partCalls != 0 {
		t.Fatalf("invalid part reached capacity guard %d times", guard.partCalls)
	}
	if _, err := service.Complete(ctx, view.ID, principal); err != ErrIncomplete {
		t.Fatalf("incomplete Complete() error = %v", err)
	}
	if guard.assemblyCalls != 0 {
		t.Fatalf(
			"incomplete assembly reached capacity guard %d times",
			guard.assemblyCalls,
		)
	}

	capacityErr := errors.New("capacity unavailable")
	guard.err = capacityErr
	if err := service.PutPart(
		ctx,
		view.ID,
		principal,
		1,
		validRange,
		hashBytes([]byte("safe")),
		bytes.NewBufferString("safe"),
	); !errors.Is(err, capacityErr) {
		t.Fatalf("guarded PutPart() error = %v", err)
	}
	if _, err := os.Stat(filepath.Join(
		uploadsRoot,
		view.ID,
		"parts",
		"00000001.part",
	)); !os.IsNotExist(err) {
		t.Fatalf("capacity rejection wrote a part: %v", err)
	}

	guard.err = nil
	if err := service.PutPart(
		ctx,
		view.ID,
		principal,
		1,
		validRange,
		hashBytes([]byte("safe")),
		bytes.NewBufferString("safe"),
	); err != nil {
		t.Fatal(err)
	}
	if guard.partCalls != 2 || guard.releases != 1 {
		t.Fatalf("part guard calls/releases = %#v", guard)
	}
	guard.err = capacityErr
	if err := service.PutPart(
		ctx,
		view.ID,
		principal,
		1,
		validRange,
		hashBytes([]byte("safe")),
		bytes.NewBufferString("ignored"),
	); err != nil {
		t.Fatalf("idempotent replay consulted low-water guard: %v", err)
	}
	if guard.partCalls != 2 {
		t.Fatalf("idempotent replay guard calls = %d", guard.partCalls)
	}

	if _, err := service.Complete(ctx, view.ID, principal); !errors.Is(err, capacityErr) {
		t.Fatalf("guarded Complete() error = %v", err)
	}
	if repository.completeCalls != 0 || guard.assemblyCalls != 1 {
		t.Fatalf(
			"assembly guard/repository calls = %d/%d",
			guard.assemblyCalls,
			repository.completeCalls,
		)
	}
}

func TestDeleteCancelsUploadAndRemovesPartsIdempotently(t *testing.T) {
	service, repository, uploadsRoot, _ := newTestService(t)
	view, err := service.Create(context.Background(), CreateInput{
		Filename: "sample.bin", Size: 4,
		ContentType: "application/octet-stream", CreatedBy: 7,
		IdempotencyKey: "upload-create-key", InputCategory: inputcategory.Binary,
	})
	if err != nil {
		t.Fatal(err)
	}
	partPath := filepath.Join(uploadsRoot, view.ID, "parts", "00000001.part")
	if err := os.MkdirAll(filepath.Dir(partPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(partPath, []byte("safe"), 0o600); err != nil {
		t.Fatal(err)
	}
	principal := auth.Principal{UserID: 7, Role: auth.RoleOperator}
	if err := service.Delete(context.Background(), view.ID, principal); err != nil {
		t.Fatalf("Delete() error = %v", err)
	}
	if repository.cancelCalls != 1 || repository.upload.Status != "cancelled" {
		t.Fatalf(
			"cancel state = (%d, %q), want one cancelled transition",
			repository.cancelCalls,
			repository.upload.Status,
		)
	}
	if _, err := os.Stat(filepath.Join(uploadsRoot, view.ID)); !os.IsNotExist(err) {
		t.Fatalf("cancelled upload directory still exists: %v", err)
	}
	if err := service.Delete(context.Background(), view.ID, principal); err != nil {
		t.Fatalf("idempotent Delete() error = %v", err)
	}
	if repository.cancelCalls != 1 {
		t.Fatalf("idempotent Delete() transitions = %d, want 1", repository.cancelCalls)
	}
}

func TestDeleteEnforcesOwnershipRoleAndState(t *testing.T) {
	tests := []struct {
		name       string
		principal  auth.Principal
		status     string
		want       error
		wantCancel bool
	}{
		{
			name: "other operator is hidden",
			principal: auth.Principal{
				UserID: 8,
				Role:   auth.RoleOperator,
			},
			status: "created",
			want:   ErrNotFound,
		},
		{
			name: "reader is forbidden",
			principal: auth.Principal{
				UserID: 7,
				Role:   auth.RoleReader,
			},
			status: "created",
			want:   ErrForbidden,
		},
		{
			name: "completed unused upload is released",
			principal: auth.Principal{
				UserID: 7,
				Role:   auth.RoleOperator,
			},
			status:     "completed",
			wantCancel: true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			service, repository, _, _ := newTestService(t)
			view, err := service.Create(context.Background(), CreateInput{
				Filename: "sample.bin", Size: 4,
				ContentType: "application/octet-stream", CreatedBy: 7,
				IdempotencyKey: "upload-create-key", InputCategory: inputcategory.Binary,
			})
			if err != nil {
				t.Fatal(err)
			}
			repository.upload.Status = test.status
			if err := service.Delete(
				context.Background(),
				view.ID,
				test.principal,
			); !errors.Is(err, test.want) {
				t.Fatalf("Delete() error = %v, want %v", err, test.want)
			}
			wantCalls := 0
			if test.wantCancel {
				wantCalls = 1
			}
			if repository.cancelCalls != wantCalls {
				t.Fatalf("Cancel() calls = %d, want %d", repository.cancelCalls, wantCalls)
			}
		})
	}

	t.Run("administrator can cancel another user's upload", func(t *testing.T) {
		service, repository, _, _ := newTestService(t)
		view, err := service.Create(context.Background(), CreateInput{
			Filename: "sample.bin", Size: 4,
			ContentType: "application/octet-stream", CreatedBy: 7,
			IdempotencyKey: "upload-create-key", InputCategory: inputcategory.Binary,
		})
		if err != nil {
			t.Fatal(err)
		}
		if err := service.Delete(context.Background(), view.ID, auth.Principal{
			UserID: 8,
			Role:   auth.RoleAdministrator,
		}); err != nil {
			t.Fatalf("administrator Delete() error = %v", err)
		}
		if repository.cancelCalls != 1 {
			t.Fatalf("administrator Cancel() calls = %d, want 1", repository.cancelCalls)
		}
	})
}

func newTestService(t *testing.T) (*Service, *repositoryStub, string, string) {
	t.Helper()
	root := t.TempDir()
	uploadsRoot := filepath.Join(root, "uploads")
	repositoryRoot := filepath.Join(root, "repository")
	if err := os.MkdirAll(uploadsRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(repositoryRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	repository := &repositoryStub{}
	partDeleter := &testUploadDirectoryDeleter{root: uploadsRoot}
	service, err := NewService(repository, Config{
		UploadsRoot: uploadsRoot, RepositoryRoot: repositoryRoot,
		MaxUploadBytes: 1024, PartSize: 4, Retention: time.Hour,
		PartDeleter: partDeleter,
		Detector: contentDetectorStub{result: filetype.Result{
			Format: "pe32", MIMEType: "application/vnd.microsoft.portable-executable",
		}},
		EnsureDirectTask: func(_ context.Context, _ DirectTaskRequest) (string, error) {
			repository.taskID = "723e4567-e89b-42d3-a456-426614174000"
			return repository.taskID, nil
		},
		Now: func() time.Time { return time.Date(2026, 7, 29, 12, 0, 0, 0, time.UTC) },
	})
	if err != nil {
		t.Fatal(err)
	}
	return service, repository, uploadsRoot, repositoryRoot
}

func hashBytes(value []byte) string {
	hash := sha256.Sum256(value)
	return hex.EncodeToString(hash[:])
}

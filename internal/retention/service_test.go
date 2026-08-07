package retention

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"binaryscan/internal/taskcleanup"
)

type repositoryStub struct {
	taskIDs         []string
	cleanupIDs      []string
	uploadIDs       []string
	blobIDs         []uint64
	taskResults     map[string]stubResult
	cleanupResults  map[string]stubResult
	uploadResults   map[string]stubResult
	blobResults     map[uint64]stubResult
	blobs           map[uint64]Blob
	listTaskErr     error
	listCleanupErr  error
	listUploadErr   error
	listBlobErr     error
	taskCalls       []string
	cleanupCalls    []string
	uploadCalls     []string
	blobCalls       []uint64
	finalizeStarted chan struct{}
	onTask          func(string)
}

type stubResult struct {
	changed bool
	err     error
}

func (s *repositoryStub) ListExpiredTaskIDs(context.Context, int) ([]string, error) {
	return append([]string(nil), s.taskIDs...), s.listTaskErr
}

func (s *repositoryStub) ClaimExpiredTaskSample(
	_ context.Context,
	id string,
	owner string,
	duration time.Duration,
) (TaskSampleClaim, bool, error) {
	s.taskCalls = append(s.taskCalls, id)
	if s.onTask != nil {
		s.onTask(id)
	}
	result := s.taskResults[id]
	return TaskSampleClaim{
		TaskID: id, LeaseOwner: owner, FencingToken: 1, Attempt: 1,
		LeaseUntil: time.Now().Add(duration),
	}, result.changed, result.err
}

func (s *repositoryStub) RenewExpiredTaskSample(
	context.Context,
	TaskSampleClaim,
	time.Duration,
) (bool, error) {
	return true, nil
}

func (s *repositoryStub) CompleteExpiredTaskSample(
	_ context.Context,
	claim TaskSampleClaim,
) (bool, error) {
	return s.taskResults[claim.TaskID].changed, nil
}

func (s *repositoryStub) FailExpiredTaskSample(
	context.Context,
	TaskSampleClaim,
	string,
) (bool, error) {
	return true, nil
}

func (s *repositoryStub) ListExpiredUploadIDs(context.Context, int) ([]string, error) {
	return append([]string(nil), s.uploadIDs...), s.listUploadErr
}

func (s *repositoryStub) ListPendingUploadPartCleanupIDs(
	context.Context,
	int,
) ([]string, error) {
	return append([]string(nil), s.cleanupIDs...), s.listCleanupErr
}

func (s *repositoryStub) CleanupUploadParts(
	_ context.Context,
	id string,
	deleteDirectory func() error,
) (bool, error) {
	s.cleanupCalls = append(s.cleanupCalls, id)
	result := s.cleanupResults[id]
	if result.err != nil {
		return false, result.err
	}
	if err := deleteDirectory(); err != nil {
		return false, err
	}
	return result.changed, nil
}

func (s *repositoryStub) ExpireUpload(
	_ context.Context,
	id string,
	deleteDirectory func() error,
) (bool, error) {
	s.uploadCalls = append(s.uploadCalls, id)
	result := s.uploadResults[id]
	if result.err != nil {
		return false, result.err
	}
	if err := deleteDirectory(); err != nil {
		return false, err
	}
	return result.changed, result.err
}

func (s *repositoryStub) ListDeletingBlobIDs(context.Context, int) ([]uint64, error) {
	return append([]uint64(nil), s.blobIDs...), s.listBlobErr
}

func (s *repositoryStub) FinalizeDeletingBlob(
	_ context.Context,
	id uint64,
	deleteFile func(Blob) error,
) (bool, error) {
	s.blobCalls = append(s.blobCalls, id)
	if s.finalizeStarted != nil {
		close(s.finalizeStarted)
		s.finalizeStarted = nil
	}
	result := s.blobResults[id]
	if result.err != nil {
		return false, result.err
	}
	if err := deleteFile(s.blobs[id]); err != nil {
		return false, err
	}
	return result.changed, nil
}

type deleterStub struct {
	mu      sync.Mutex
	results map[uint64]error
	calls   []uint64
}

type uploadDeleterStub struct {
	mu      sync.Mutex
	results map[string]error
	calls   []string
}

type outputDeleterStub struct{}

func (*outputDeleterStub) DeleteFile(
	context.Context,
	taskcleanup.StoredFile,
) (bool, error) {
	return false, nil
}

func (*outputDeleterStub) DeleteScope(
	context.Context,
	taskcleanup.Scope,
) error {
	return nil
}

func testRetentionConfig() Config {
	return Config{
		LeaseOwner:    "sample-retention-test",
		LeaseDuration: time.Minute,
		OutputDeleter: &outputDeleterStub{},
	}
}

func (s *uploadDeleterStub) Delete(_ context.Context, uploadID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls = append(s.calls, uploadID)
	return s.results[uploadID]
}

func (s *deleterStub) Delete(_ context.Context, blob Blob) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls = append(s.calls, blob.ID)
	return s.results[blob.ID]
}

func TestSweeperProcessesAllCategoriesAndContinuesAfterItemErrors(t *testing.T) {
	sentinel := errors.New("fixture failure")
	repository := &repositoryStub{
		taskIDs:    []string{"task-a", "task-b"},
		cleanupIDs: []string{"upload-cleanup"},
		uploadIDs:  []string{"upload-a", "upload-b"},
		blobIDs:    []uint64{1, 2},
		taskResults: map[string]stubResult{
			"task-a": {changed: true},
			"task-b": {err: sentinel},
		},
		uploadResults: map[string]stubResult{
			"upload-a": {changed: true},
			"upload-b": {err: sentinel},
		},
		cleanupResults: map[string]stubResult{
			"upload-cleanup": {changed: true},
		},
		blobResults: map[uint64]stubResult{
			1: {changed: true},
			2: {changed: true},
		},
		blobs: map[uint64]Blob{
			1: {ID: 1},
			2: {ID: 2},
		},
	}
	deleter := &deleterStub{results: map[uint64]error{2: sentinel}}
	sweeper, err := NewSweeper(
		repository,
		deleter,
		&uploadDeleterStub{results: map[string]error{}},
		testRetentionConfig(),
	)
	if err != nil {
		t.Fatal(err)
	}

	report, err := sweeper.Sweep(context.Background(), 10)
	if !errors.Is(err, sentinel) {
		t.Fatalf("Sweep() error = %v, want fixture error", err)
	}
	if report.TaskSamplesReleased != 1 ||
		report.UploadPartsCleaned != 1 ||
		report.UploadsExpired != 1 ||
		report.BlobsDeleted != 1 ||
		report.Failures != 3 {
		t.Fatalf("Sweep() report = %+v", report)
	}
	if len(repository.taskCalls) != 2 ||
		len(repository.cleanupCalls) != 1 ||
		len(repository.uploadCalls) != 2 ||
		len(repository.blobCalls) != 2 {
		t.Fatalf(
			"calls task=%v cleanup=%v upload=%v blob=%v",
			repository.taskCalls,
			repository.cleanupCalls,
			repository.uploadCalls,
			repository.blobCalls,
		)
	}
}

func TestSweeperContinuesCategoriesAfterListFailure(t *testing.T) {
	sentinel := errors.New("task list failed")
	repository := &repositoryStub{
		listTaskErr: sentinel,
		uploadIDs:   []string{"upload"},
		blobIDs:     []uint64{1},
		uploadResults: map[string]stubResult{
			"upload": {changed: true},
		},
		blobResults: map[uint64]stubResult{
			1: {changed: true},
		},
		blobs: map[uint64]Blob{1: {ID: 1}},
	}
	sweeper, err := NewSweeper(
		repository,
		&deleterStub{results: map[uint64]error{}},
		&uploadDeleterStub{results: map[string]error{}},
		testRetentionConfig(),
	)
	if err != nil {
		t.Fatal(err)
	}
	report, err := sweeper.Sweep(context.Background(), 5)
	if !errors.Is(err, sentinel) ||
		report.UploadsExpired != 1 ||
		report.BlobsDeleted != 1 ||
		report.Failures != 1 {
		t.Fatalf("Sweep() = (%+v, %v)", report, err)
	}
}

func TestSweeperStopsOnCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	repository := &repositoryStub{
		taskIDs: []string{"task-a", "task-b"},
		taskResults: map[string]stubResult{
			"task-a": {changed: true},
			"task-b": {changed: true},
		},
		onTask: func(id string) {
			if id == "task-a" {
				cancel()
			}
		},
	}
	deleter := &deleterStub{results: map[uint64]error{}}
	sweeper, err := NewSweeper(
		repository,
		deleter,
		&uploadDeleterStub{results: map[string]error{}},
		testRetentionConfig(),
	)
	if err != nil {
		t.Fatal(err)
	}

	report, err := sweeper.Sweep(ctx, 10)
	if !errors.Is(err, context.Canceled) ||
		report.TaskSamplesReleased != 1 ||
		report.UploadsExpired != 0 ||
		report.BlobsDeleted != 0 {
		t.Fatalf("Sweep() = (%+v, %v)", report, err)
	}
	if len(repository.taskCalls) != 1 || repository.taskCalls[0] != "task-a" {
		t.Fatalf("cancelled sweep task calls: %v", repository.taskCalls)
	}
}

func TestSweeperValidatesDependenciesAndBatchSize(t *testing.T) {
	uploadDeleter := &uploadDeleterStub{}
	if _, err := NewSweeper(
		nil, &deleterStub{}, uploadDeleter, testRetentionConfig(),
	); err == nil {
		t.Fatal("NewSweeper() accepted nil repository")
	}
	if _, err := NewSweeper(
		&repositoryStub{}, nil, uploadDeleter, testRetentionConfig(),
	); err == nil {
		t.Fatal("NewSweeper() accepted nil blob deleter")
	}
	if _, err := NewSweeper(
		&repositoryStub{}, &deleterStub{}, nil, testRetentionConfig(),
	); err == nil {
		t.Fatal("NewSweeper() accepted nil upload deleter")
	}
	sweeper, err := NewSweeper(
		&repositoryStub{},
		&deleterStub{},
		uploadDeleter,
		testRetentionConfig(),
	)
	if err != nil {
		t.Fatal(err)
	}
	for _, limit := range []int{0, MaxBatchSize + 1} {
		if _, err := sweeper.Sweep(context.Background(), limit); err == nil {
			t.Fatalf("Sweep() accepted limit %d", limit)
		}
	}
}

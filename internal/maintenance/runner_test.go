package maintenance

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"binaryscan/internal/orphanreaper"
	"binaryscan/internal/retention"
	"binaryscan/internal/taskcleanup"
	"binaryscan/internal/workspace"
)

type databaseStub struct {
	mu      sync.Mutex
	results []error
	calls   int
}

func (s *databaseStub) PingContext(context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls++
	if len(s.results) == 0 {
		return nil
	}
	result := s.results[0]
	s.results = s.results[1:]
	return result
}

func (s *databaseStub) callCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls
}

type recovererStub struct {
	mu      sync.Mutex
	results []recoverResult
	calls   int
	limits  []int
	onCall  func(int)
}

type recoverResult struct {
	count int
	err   error
}

type workspaceSweeperStub struct {
	mu      sync.Mutex
	results []workspaceSweepResult
	calls   int
	limits  []int
	onCall  func(int)
	events  *[]string
}

type workspaceSweepResult struct {
	report workspace.SweepReport
	err    error
}

type retentionSweeperStub struct {
	mu      sync.Mutex
	results []retentionSweepResult
	calls   int
	limits  []int
	onCall  func(int)
	events  *[]string
}

type retentionSweepResult struct {
	report retention.Report
	err    error
}

type orphanSweeperStub struct {
	mu      sync.Mutex
	results []orphanSweepResult
	calls   int
	limits  []int
	events  *[]string
}

type orphanSweepResult struct {
	report orphanreaper.Report
	err    error
}

func (s *orphanSweeperStub) Sweep(
	_ context.Context,
	limit int,
) (orphanreaper.Report, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls++
	s.limits = append(s.limits, limit)
	if s.events != nil {
		*s.events = append(*s.events, "orphan")
	}
	result := orphanSweepResult{}
	if len(s.results) > 0 {
		result = s.results[0]
		s.results = s.results[1:]
	}
	return result.report, result.err
}

func (s *orphanSweeperStub) snapshot() (int, []int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls, append([]int(nil), s.limits...)
}

type taskDeletionSweeperStub struct {
	mu      sync.Mutex
	results []taskDeletionSweepResult
	calls   int
	limits  []int
	events  *[]string
}

type taskDeletionSweepResult struct {
	report taskcleanup.Report
	err    error
}

func (s *taskDeletionSweeperStub) Sweep(
	_ context.Context,
	limit int,
) (taskcleanup.Report, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls++
	s.limits = append(s.limits, limit)
	if s.events != nil {
		*s.events = append(*s.events, "task-deletion")
	}
	result := taskDeletionSweepResult{}
	if len(s.results) > 0 {
		result = s.results[0]
		s.results = s.results[1:]
	}
	return result.report, result.err
}

func (s *taskDeletionSweeperStub) snapshot() (int, []int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls, append([]int(nil), s.limits...)
}

func (s *retentionSweeperStub) Sweep(
	_ context.Context,
	limit int,
) (retention.Report, error) {
	s.mu.Lock()
	s.calls++
	call := s.calls
	s.limits = append(s.limits, limit)
	if s.events != nil {
		*s.events = append(*s.events, "retention")
	}
	result := retentionSweepResult{}
	if len(s.results) > 0 {
		result = s.results[0]
		s.results = s.results[1:]
	}
	onCall := s.onCall
	s.mu.Unlock()
	if onCall != nil {
		onCall(call)
	}
	return result.report, result.err
}

func (s *retentionSweeperStub) snapshot() (int, []int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls, append([]int(nil), s.limits...)
}

func (s *workspaceSweeperStub) Sweep(
	_ context.Context,
	limit int,
) (workspace.SweepReport, error) {
	s.mu.Lock()
	s.calls++
	call := s.calls
	s.limits = append(s.limits, limit)
	if s.events != nil {
		*s.events = append(*s.events, "sweep")
	}
	result := workspaceSweepResult{}
	if len(s.results) > 0 {
		result = s.results[0]
		s.results = s.results[1:]
	}
	onCall := s.onCall
	s.mu.Unlock()
	if onCall != nil {
		onCall(call)
	}
	return result.report, result.err
}

func (s *workspaceSweeperStub) snapshot() (int, []int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls, append([]int(nil), s.limits...)
}

func (s *recovererStub) RecoverExpired(_ context.Context, limit int) (int, error) {
	s.mu.Lock()
	s.calls++
	call := s.calls
	s.limits = append(s.limits, limit)
	result := recoverResult{}
	if len(s.results) != 0 {
		result = s.results[0]
		s.results = s.results[1:]
	}
	onCall := s.onCall
	s.mu.Unlock()
	if onCall != nil {
		onCall(call)
	}
	return result.count, result.err
}

func (s *recovererStub) snapshot() (int, []int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls, append([]int(nil), s.limits...)
}

type recordHandler struct {
	mu      sync.Mutex
	records []slog.Record
}

func (h *recordHandler) Enabled(context.Context, slog.Level) bool { return true }

func (h *recordHandler) Handle(_ context.Context, record slog.Record) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.records = append(h.records, record.Clone())
	return nil
}

func (h *recordHandler) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h *recordHandler) WithGroup(string) slog.Handler      { return h }

func (h *recordHandler) hasRecord(level slog.Level, message string, key string, value int64) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, record := range h.records {
		if record.Level != level || record.Message != message {
			continue
		}
		found := false
		record.Attrs(func(attr slog.Attr) bool {
			if attr.Key == key && attr.Value.Int64() == value {
				found = true
			}
			return true
		})
		if found {
			return true
		}
	}
	return false
}

func (h *recordHandler) hasMessage(level slog.Level, message string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, record := range h.records {
		if record.Level == level && record.Message == message {
			return true
		}
	}
	return false
}

func newTestRunner(
	t *testing.T,
	database Database,
	recoverer Recoverer,
	sweeper WorkspaceSweeper,
	logger *slog.Logger,
	interval time.Duration,
) *Runner {
	t.Helper()
	runner, err := NewRunner(RunnerConfig{
		Interval: interval, PingTimeout: 50 * time.Millisecond,
		Database: database, Queue: recoverer,
		TaskDeletion: &taskDeletionSweeperStub{},
		Retention:    &retentionSweeperStub{}, Workspace: sweeper,
		Logger: logger,
	})
	if err != nil {
		t.Fatal(err)
	}
	return runner
}

func TestRunnerRecoversImmediatelyAndLogsCount(t *testing.T) {
	database := &databaseStub{}
	ctx, cancel := context.WithCancel(context.Background())
	recoverer := &recovererStub{
		results: []recoverResult{{count: 3}},
		onCall: func(int) {
			cancel()
		},
	}
	handler := &recordHandler{}
	runner := newTestRunner(
		t, database, recoverer, &workspaceSweeperStub{},
		slog.New(handler), time.Hour,
	)

	if err := runner.Run(ctx); err != nil {
		t.Fatal(err)
	}

	calls, limits := recoverer.snapshot()
	if calls != 1 || len(limits) != 1 || limits[0] != recoveryBatchSize {
		t.Fatalf("recover calls=%d limits=%v", calls, limits)
	}
	if !handler.hasRecord(slog.LevelInfo, "expired jobs recovered", "recovered_jobs", 3) {
		t.Fatal("structured recovery count log not found")
	}
}

func TestRunnerRunsPeriodically(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	recoverer := &recovererStub{
		onCall: func(call int) {
			if call == 3 {
				cancel()
			}
		},
	}
	runner := newTestRunner(
		t, &databaseStub{}, recoverer, &workspaceSweeperStub{},
		slog.New(slog.NewTextHandler(discardWriter{}, nil)), time.Millisecond,
	)

	if err := runner.Run(ctx); err != nil {
		t.Fatal(err)
	}
	calls, _ := recoverer.snapshot()
	if calls != 3 {
		t.Fatalf("recover calls=%d, want 3", calls)
	}
}

func TestRunnerContinuesAfterDatabaseAndRecoveryErrors(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	database := &databaseStub{results: []error{errors.New("database unavailable"), nil, nil}}
	recoverer := &recovererStub{
		results: []recoverResult{
			{err: errors.New("recovery failed")},
			{count: 1},
		},
		onCall: func(call int) {
			if call == 2 {
				cancel()
			}
		},
	}
	handler := &recordHandler{}
	sweeper := &workspaceSweeperStub{}
	runner := newTestRunner(
		t, database, recoverer, sweeper,
		slog.New(handler), time.Millisecond,
	)

	if err := runner.Run(ctx); err != nil {
		t.Fatal(err)
	}

	if database.callCount() != 3 {
		t.Fatalf("database calls=%d, want 3", database.callCount())
	}
	calls, _ := recoverer.snapshot()
	if calls != 2 {
		t.Fatalf("recover calls=%d, want 2", calls)
	}
	if !handler.hasMessage(slog.LevelWarn, "maintenance database check failed") {
		t.Fatal("database failure warning not found")
	}
	if !handler.hasMessage(slog.LevelWarn, "expired job recovery failed") {
		t.Fatal("recovery failure warning not found")
	}
	if !handler.hasRecord(slog.LevelInfo, "expired jobs recovered", "recovered_jobs", 1) {
		t.Fatal("runner did not continue to successful recovery")
	}
	if calls, _ := sweeper.snapshot(); calls != 1 {
		t.Fatalf("sweep calls=%d, want 1 after recovery failure", calls)
	}
}

func TestRunnerReturnsCleanlyWhenAlreadyCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	database := &databaseStub{}
	recoverer := &recovererStub{}
	runner := newTestRunner(
		t, database, recoverer, &workspaceSweeperStub{},
		slog.New(slog.NewTextHandler(discardWriter{}, nil)), time.Hour,
	)

	if err := runner.Run(ctx); err != nil {
		t.Fatal(err)
	}
	if database.callCount() != 0 {
		t.Fatalf("database calls=%d, want 0", database.callCount())
	}
	if calls, _ := recoverer.snapshot(); calls != 0 {
		t.Fatalf("recover calls=%d, want 0", calls)
	}
}

func TestRunnerRecoversBeforeSweepingAndLogsBoundedWorkspaceResults(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	events := make([]string, 0, 2)
	recoverer := &recovererStub{
		onCall: func(int) {
			events = append(events, "recover")
		},
	}
	sweeper := &workspaceSweeperStub{
		events: &events,
		results: []workspaceSweepResult{{report: workspace.SweepReport{
			Scanned: 4, Removed: 2, Active: 1, Skipped: 1,
			Diagnostics: []workspace.Diagnostic{{
				Name: "damaged", Err: errors.New("bad marker"),
			}},
		}}},
		onCall: func(int) {
			cancel()
		},
	}
	handler := &recordHandler{}
	runner := newTestRunner(
		t, &databaseStub{}, recoverer, sweeper,
		slog.New(handler), time.Hour,
	)

	if err := runner.Run(ctx); err != nil {
		t.Fatal(err)
	}
	if strings.Join(events, ",") != "recover,sweep" {
		t.Fatalf("maintenance order = %v", events)
	}
	calls, limits := sweeper.snapshot()
	if calls != 1 || len(limits) != 1 ||
		limits[0] != workspaceSweepBatchSize ||
		workspaceSweepBatchSize != 1 {
		t.Fatalf("sweep calls=%d limits=%v", calls, limits)
	}
	if !handler.hasRecord(
		slog.LevelInfo,
		"inactive task workspaces removed",
		"removed_workspaces",
		2,
	) {
		t.Fatal("workspace removal count log not found")
	}
	if !handler.hasMessage(slog.LevelWarn, "task workspace skipped") {
		t.Fatal("workspace diagnostic warning not found")
	}
}

func TestRunnerSweepsConservativelyWhenRecoveryBatchFails(t *testing.T) {
	events := make([]string, 0, 2)
	recoverer := &recovererStub{
		results: []recoverResult{{err: errors.New("poisoned recovery row")}},
		onCall: func(int) {
			events = append(events, "recover")
		},
	}
	sweeper := &workspaceSweeperStub{events: &events}
	handler := &recordHandler{}
	runner := newTestRunner(
		t, &databaseStub{}, recoverer, sweeper,
		slog.New(handler), time.Hour,
	)

	runner.recover(context.Background())

	if strings.Join(events, ",") != "recover,sweep" {
		t.Fatalf("maintenance order after recovery failure = %v", events)
	}
	calls, limits := sweeper.snapshot()
	if calls != 1 || len(limits) != 1 ||
		limits[0] != workspaceSweepBatchSize ||
		workspaceSweepBatchSize != 1 {
		t.Fatalf("sweep calls=%d limits=%v", calls, limits)
	}
	if !handler.hasMessage(slog.LevelWarn, "expired job recovery failed") {
		t.Fatal("recovery failure warning not found")
	}
}

func TestRunnerRetentionFailureDoesNotStopWorkspaceSweepOrLeakDetails(t *testing.T) {
	events := make([]string, 0, 3)
	recoverer := &recovererStub{
		onCall: func(int) {
			events = append(events, "recover")
		},
	}
	retentionSweeper := &retentionSweeperStub{
		events: &events,
		results: []retentionSweepResult{{
			report: retention.Report{
				TaskSamplesReleased: 2,
				UploadsExpired:      3,
				BlobsDeleted:        1,
				Failures:            1,
			},
			err: errors.New("blobs/sha256/secret-storage-key"),
		}},
	}
	taskDeletionSweeper := &taskDeletionSweeperStub{
		events: &events,
		results: []taskDeletionSweepResult{{
			report: taskcleanup.Report{
				Claimed: 1, Completed: 1, FilesDeleted: 3,
			},
		}},
	}
	workspaceSweeper := &workspaceSweeperStub{events: &events}
	handler := &recordHandler{}
	runner, err := NewRunner(RunnerConfig{
		Interval: time.Hour, PingTimeout: 50 * time.Millisecond,
		Database: &databaseStub{}, Queue: recoverer,
		TaskDeletion: taskDeletionSweeper,
		Retention:    retentionSweeper, Workspace: workspaceSweeper,
		Logger: slog.New(handler),
	})
	if err != nil {
		t.Fatal(err)
	}

	runner.recover(context.Background())

	if strings.Join(events, ",") != "recover,task-deletion,retention,sweep" {
		t.Fatalf("maintenance order = %v", events)
	}
	if calls, limits := taskDeletionSweeper.snapshot(); calls != 1 ||
		len(limits) != 1 || limits[0] != taskDeletionBatchSize {
		t.Fatalf("task deletion calls=%d limits=%v", calls, limits)
	}
	if calls, limits := retentionSweeper.snapshot(); calls != 1 ||
		len(limits) != 1 || limits[0] != retentionBatchSize {
		t.Fatalf("retention calls=%d limits=%v", calls, limits)
	}
	if calls, _ := workspaceSweeper.snapshot(); calls != 1 {
		t.Fatalf("workspace sweep calls=%d, want 1", calls)
	}
	if !handler.hasMessage(slog.LevelWarn, "retention sweep failed") ||
		!handler.hasRecord(
			slog.LevelInfo,
			"task deletion sweep completed",
			"deleted_tasks",
			1,
		) ||
		!handler.hasRecord(
			slog.LevelInfo,
			"retention sweep completed",
			"task_samples_released",
			2,
		) {
		t.Fatal("retention count or generic failure log not found")
	}
	handler.mu.Lock()
	defer handler.mu.Unlock()
	for _, record := range handler.records {
		record.Attrs(func(attr slog.Attr) bool {
			if strings.Contains(attr.Value.String(), "secret-storage-key") {
				t.Fatal("retention log exposed storage key")
			}
			return true
		})
	}
}

func TestRunnerOrphanFailureIsObservableAndDoesNotStopWorkspaceSweep(t *testing.T) {
	events := make([]string, 0, 5)
	recoverer := &recovererStub{
		onCall: func(int) {
			events = append(events, "recover")
		},
	}
	taskDeletionSweeper := &taskDeletionSweeperStub{events: &events}
	retentionSweeper := &retentionSweeperStub{events: &events}
	orphanSweeper := &orphanSweeperStub{
		events: &events,
		results: []orphanSweepResult{{
			report: orphanreaper.Report{
				BlobFilesScanned:  5,
				UploadDirsScanned: 3,
				OrphanBlobs:       2,
				RemovedBlobs:      1,
				RecheckProtected:  1,
				Failures:          1,
			},
			err: errors.New("blobs/sha256/secret-orphan-key"),
		}},
	}
	workspaceSweeper := &workspaceSweeperStub{events: &events}
	handler := &recordHandler{}
	runner, err := NewRunner(RunnerConfig{
		Interval: time.Hour, PingTimeout: 50 * time.Millisecond,
		Database: &databaseStub{}, Queue: recoverer,
		TaskDeletion: taskDeletionSweeper,
		Retention:    retentionSweeper,
		Orphans:      orphanSweeper,
		Workspace:    workspaceSweeper,
		Logger:       slog.New(handler),
	})
	if err != nil {
		t.Fatal(err)
	}

	runner.recover(context.Background())

	if strings.Join(events, ",") != "recover,task-deletion,retention,orphan,sweep" {
		t.Fatalf("maintenance order = %v", events)
	}
	if calls, limits := orphanSweeper.snapshot(); calls != 1 ||
		len(limits) != 1 || limits[0] != orphanSweepBatchSize {
		t.Fatalf("orphan sweep calls=%d limits=%v", calls, limits)
	}
	if !handler.hasRecord(
		slog.LevelInfo,
		"orphan reconciliation sweep completed",
		"removed_blob_files",
		1,
	) || !handler.hasMessage(slog.LevelWarn, "orphan reconciliation sweep failed") {
		t.Fatal("orphan sweep counters or generic failure warning not found")
	}
	if calls, _ := workspaceSweeper.snapshot(); calls != 1 {
		t.Fatalf("workspace sweep calls=%d, want 1 after orphan failure", calls)
	}

	handler.mu.Lock()
	defer handler.mu.Unlock()
	for _, record := range handler.records {
		record.Attrs(func(attr slog.Attr) bool {
			if strings.Contains(attr.Value.String(), "secret-orphan-key") {
				t.Fatal("orphan cleanup log exposed a storage key")
			}
			return true
		})
	}
}

type discardWriter struct{}

func (discardWriter) Write(value []byte) (int, error) { return len(value), nil }

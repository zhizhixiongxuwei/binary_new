package main

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"

	"binaryscan/internal/retention"
)

func TestMaintenanceRejectsUnknownActionBeforeLoadingConfiguration(t *testing.T) {
	if err := run([]string{"--action=unknown"}); err == nil {
		t.Fatal("run() error = nil, want invalid action error")
	}
}

func TestMaintenanceRejectsInvalidCleanupBatchBeforeLoadingConfiguration(t *testing.T) {
	for _, value := range []string{"0", "101", "not-a-number"} {
		err := run([]string{"cleanup-expired", "--batch-size=" + value})
		if err == nil || !strings.Contains(err.Error(), "batch-size") {
			t.Fatalf("batch size %q error = %v", value, err)
		}
	}
	if err := run([]string{"migrate", "--batch-size=25"}); err == nil ||
		!strings.Contains(err.Error(), "only valid") {
		t.Fatalf("non-cleanup batch size error = %v", err)
	}
}

func TestCleanupExpiredResultPreservesEveryRetentionCounter(t *testing.T) {
	result := newCleanupExpiredResult(25, retention.Report{
		TaskSamplesReleased:   1,
		UploadPartsCleaned:    2,
		UploadsExpired:        3,
		BlobsDeleted:          4,
		Failures:              5,
		DecompileFilesDeleted: 6,
		TaskSampleConflicts:   7,
	})
	if result.BatchSize != 25 || result.TaskSamplesReleased != 1 ||
		result.UploadPartsCleaned != 2 || result.UploadsExpired != 3 ||
		result.BlobsDeleted != 4 || result.Failures != 5 ||
		result.DecompileFilesDeleted != 6 || result.TaskSampleConflicts != 7 {
		t.Fatalf("cleanup result = %+v", result)
	}
}

func TestRunBackgroundLoopsCancelsSiblingsAndReturnsNamedError(t *testing.T) {
	sentinel := errors.New("secondary loop stopped")
	var siblingCancelled atomic.Bool
	err := runBackgroundLoops(
		context.Background(),
		namedLoop{
			name: "maintenance",
			run: func(ctx context.Context) error {
				<-ctx.Done()
				siblingCancelled.Store(true)
				return nil
			},
		},
		namedLoop{
			name: "secondary",
			run: func(context.Context) error {
				return sentinel
			},
		},
	)
	if !errors.Is(err, sentinel) ||
		!strings.Contains(err.Error(), "secondary loop") ||
		!siblingCancelled.Load() {
		t.Fatalf("runBackgroundLoops() error = %v", err)
	}
}

func TestRunBackgroundLoopsStopsCleanlyWithParent(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	var started atomic.Int32
	wait := func(ctx context.Context) error {
		started.Add(1)
		<-ctx.Done()
		return nil
	}
	done := make(chan error, 1)
	go func() {
		done <- runBackgroundLoops(
			ctx,
			namedLoop{name: "one", run: wait},
			namedLoop{name: "two", run: wait},
		)
	}()
	for started.Load() != 2 {
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("runBackgroundLoops() error = %v", err)
	}
}

func TestRunBackgroundLoopsRejectsInvalidInput(t *testing.T) {
	if err := runBackgroundLoops(context.Background()); err == nil {
		t.Fatal("runBackgroundLoops() accepted no loops")
	}
	if err := runBackgroundLoops(
		context.Background(),
		namedLoop{name: "missing"},
	); err == nil {
		t.Fatal("runBackgroundLoops() accepted a nil runner")
	}
}

func TestRunBackgroundLoopsPreservesUnexpectedFirstStop(t *testing.T) {
	err := runBackgroundLoops(
		context.Background(),
		namedLoop{
			name: "stopped",
			run: func(context.Context) error {
				return nil
			},
		},
		namedLoop{
			name: "cancelled sibling",
			run: func(ctx context.Context) error {
				<-ctx.Done()
				return ctx.Err()
			},
		},
	)
	if err == nil ||
		!strings.Contains(err.Error(), "stopped loop stopped unexpectedly") {
		t.Fatalf("runBackgroundLoops() error = %v", err)
	}
}

func TestRunBackgroundLoopsTreatsParentCancellationAsClean(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	var started atomic.Int32
	cancelled := func(ctx context.Context) error {
		started.Add(1)
		<-ctx.Done()
		return ctx.Err()
	}
	done := make(chan error, 1)
	go func() {
		done <- runBackgroundLoops(
			ctx,
			namedLoop{name: "one", run: cancelled},
			namedLoop{name: "two", run: cancelled},
		)
	}()
	for started.Load() != 2 {
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("runBackgroundLoops() error = %v", err)
	}
}

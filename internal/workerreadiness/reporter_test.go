package workerreadiness

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type repositoryStub struct {
	mu          sync.Mutex
	registered  int
	heartbeats  int
	removed     int
	pruned      int
	heartbeat   chan struct{}
	registerErr error
}

func (s *repositoryStub) Register(context.Context, Registration) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.registered++
	return s.registerErr
}

func (s *repositoryStub) Heartbeat(context.Context, string) error {
	s.mu.Lock()
	s.heartbeats++
	s.mu.Unlock()
	select {
	case s.heartbeat <- struct{}{}:
	default:
	}
	return nil
}

func (s *repositoryStub) Remove(context.Context, string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.removed++
	return nil
}

func (s *repositoryStub) Prune(context.Context, time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruned++
	return nil
}

func TestReporterRegistersHeartbeatsAndRemoves(t *testing.T) {
	repository := &repositoryStub{heartbeat: make(chan struct{}, 1)}
	reporter, err := NewReporter(
		repository,
		Registration{
			Owner: "trivy:fixture", WorkerKind: "trivy",
			AnalyzerName: "trivy", AnalyzerVersion: "0.72.0",
		},
		10*time.Millisecond,
		5*time.Millisecond,
		slog.New(slog.NewTextHandler(io.Discard, nil)),
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := reporter.Register(context.Background()); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		reporter.Run(ctx)
		close(done)
	}()
	select {
	case <-repository.heartbeat:
	case <-time.After(time.Second):
		t.Fatal("reporter did not heartbeat")
	}
	cancel()
	<-done
	if err := reporter.Remove(context.Background()); err != nil {
		t.Fatal(err)
	}
	repository.mu.Lock()
	defer repository.mu.Unlock()
	if repository.registered != 1 || repository.pruned != 1 ||
		repository.heartbeats < 1 || repository.removed != 1 {
		t.Fatalf("reporter calls = %#v", repository)
	}
}

func TestReporterFailsClosedOnInitialRegistration(t *testing.T) {
	repository := &repositoryStub{
		heartbeat: make(chan struct{}, 1), registerErr: errors.New("schema missing"),
	}
	reporter, err := NewReporter(
		repository,
		Registration{
			Owner: "native:fixture", WorkerKind: "native",
			AnalyzerName: "ghidra", AnalyzerVersion: "12.1.2",
			RuntimeName: "jdk", RuntimeVersion: `openjdk version "21.0.4"`,
		},
		time.Second,
		100*time.Millisecond,
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := reporter.Register(context.Background()); err == nil {
		t.Fatal("Register() error = nil")
	}
}

func TestReporterStopsFreshnessHeartbeatsWhileRuntimeProbeFails(t *testing.T) {
	repository := &repositoryStub{heartbeat: make(chan struct{}, 1)}
	reporter, err := NewReporter(
		repository,
		Registration{
			Owner: "c-analysis:fixture", WorkerKind: "c_analysis",
			AnalyzerName: "binaryscan-c-checker", AnalyzerVersion: "0.1.0",
		},
		10*time.Millisecond,
		5*time.Millisecond,
		slog.New(slog.NewTextHandler(io.Discard, nil)),
	)
	if err != nil {
		t.Fatal(err)
	}
	var ready atomic.Bool
	if err := reporter.SetRuntimeProbe(func(context.Context) error {
		if !ready.Load() {
			return errors.New("checker unavailable")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		reporter.Run(ctx)
		close(done)
	}()
	t.Cleanup(func() {
		cancel()
		<-done
	})
	time.Sleep(35 * time.Millisecond)
	repository.mu.Lock()
	heartbeats := repository.heartbeats
	repository.mu.Unlock()
	if heartbeats != 0 {
		t.Fatalf("heartbeats while checker unavailable = %d, want 0", heartbeats)
	}
	ready.Store(true)
	select {
	case <-repository.heartbeat:
	case <-time.After(time.Second):
		t.Fatal("reporter did not restore heartbeat after checker recovery")
	}
}

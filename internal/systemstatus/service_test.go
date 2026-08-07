package systemstatus

import (
	"context"
	"errors"
	"testing"
	"time"

	"binaryscan/internal/buildinfo"
)

type statusRepositoryStub struct {
	bundle    *DatabaseBundleRecord
	bundleErr error
	readiness []WorkerReadinessRecord
}

func (s statusRepositoryStub) TaskCounts(context.Context) (map[string]int64, error) {
	return map[string]int64{"QUEUED": 2, "SCANNING": 1}, nil
}

func (s statusRepositoryStub) Queue(context.Context) (QueueRecord, error) {
	return QueueRecord{Depth: 2, LeasesByKind: map[string]int64{"trivy": 1}}, nil
}

func (s statusRepositoryStub) TrivyDatabaseBundle(context.Context) (*DatabaseBundleRecord, error) {
	return s.bundle, s.bundleErr
}

func (s statusRepositoryStub) ObservedAnalyzers(context.Context) ([]ObservedAnalyzer, error) {
	return []ObservedAnalyzer{}, nil
}

func (s statusRepositoryStub) WorkerReadiness(context.Context) ([]WorkerReadinessRecord, error) {
	return s.readiness, nil
}

func (s statusRepositoryStub) OperationalMetrics(context.Context) (OperationalMetricsRecord, error) {
	return OperationalMetricsRecord{
		StageDurations:       []StageDurationMetric{},
		AnalyzerFailureRates: []AnalyzerFailureMetric{},
	}, nil
}

type storageProbeStub struct{}

func (storageProbeStub) Probe(context.Context, string) (DiskUsage, error) {
	return DiskUsage{UsedBytes: 100, TotalBytes: 1_000, FreeBytes: 900, Writable: true}, nil
}

func TestServiceReportsFixedTrivyBundle(t *testing.T) {
	now := time.Date(2026, 8, 7, 8, 0, 0, 0, time.UTC)
	repository := statusRepositoryStub{
		bundle: &DatabaseBundleRecord{
			ID: "123e4567-e89b-42d3-a456-426614174000", Version: "2026.08.07",
			GeneratedAt: now.Add(-24 * time.Hour), RegisteredAt: now,
			ContentSHA256:  "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			TrivyDBVersion: "2026.08.07", TrivyJavaDBVersion: "2026.08.07",
		},
		readiness: readyAnalyzers(now),
	}
	service := newStatusService(t, repository)
	service.now = func() time.Time { return now }

	status, err := service.Get(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if status.ServiceStatus != ServiceHealthy {
		t.Fatalf("service status = %q, diagnostics = %#v", status.ServiceStatus, status.Diagnostics)
	}
	if status.TrivyDatabaseBundle == nil ||
		status.TrivyDatabaseBundle.Status != DatabaseBundleActive ||
		status.TrivyDatabaseBundle.TrivyJavaDBVersion != "2026.08.07" {
		t.Fatalf("database bundle = %#v", status.TrivyDatabaseBundle)
	}
	if status.ActiveTasks != 1 || status.QueuedTasks != 2 {
		t.Fatalf("task counts = %#v", status.TaskCounts)
	}
}

func TestServiceDegradesWhenFixedBundleIsMissing(t *testing.T) {
	now := time.Date(2026, 8, 7, 8, 0, 0, 0, time.UTC)
	service := newStatusService(t, statusRepositoryStub{readiness: readyAnalyzers(now)})
	service.now = func() time.Time { return now }

	status, err := service.Get(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if status.ServiceStatus != ServiceDegraded || status.TrivyDatabaseBundle != nil {
		t.Fatalf("status = %#v", status)
	}
	if !hasDiagnostic(status.Diagnostics, "trivy_database_bundle_missing") {
		t.Fatalf("diagnostics = %#v", status.Diagnostics)
	}
}

func TestServiceReportsBundleRepositoryFailureWithoutLeakingError(t *testing.T) {
	now := time.Date(2026, 8, 7, 8, 0, 0, 0, time.UTC)
	service := newStatusService(t, statusRepositoryStub{
		bundleErr: errors.New("secret database detail"), readiness: readyAnalyzers(now),
	})
	service.now = func() time.Time { return now }

	status, err := service.Get(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !hasDiagnostic(status.Diagnostics, "trivy_database_bundle_unavailable") {
		t.Fatalf("diagnostics = %#v", status.Diagnostics)
	}
}

func newStatusService(t *testing.T, repository Repository) *Service {
	t.Helper()
	service, err := NewService(repository, Config{
		Service: "api", Build: buildinfo.Info{Version: "test"},
		UploadsRoot: "/data/uploads", RepositoryRoot: "/data/repository",
		TaskWorkRoot: "/data/work", StorageMinFreeBytes: 1,
		StorageProbe: storageProbeStub{},
	})
	if err != nil {
		t.Fatal(err)
	}
	return service
}

func readyAnalyzers(now time.Time) []WorkerReadinessRecord {
	return []WorkerReadinessRecord{
		{Owner: "native", WorkerKind: "native", AnalyzerName: "ghidra", Status: "ready", LastCheckedAt: now},
		{Owner: "image", WorkerKind: "image", AnalyzerName: "trivy", Status: "ready", LastCheckedAt: now},
		{Owner: "trivy", WorkerKind: "trivy", AnalyzerName: "trivy", Status: "ready", LastCheckedAt: now},
	}
}

func hasDiagnostic(values []Diagnostic, code string) bool {
	for _, value := range values {
		if value.Code == code {
			return true
		}
	}
	return false
}

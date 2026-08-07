package systemstatus

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
)

func TestMySQLRepositoryCollectsSystemStatusMetadata(t *testing.T) {
	database, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	repository := NewMySQLRepository(database)
	now := time.Date(2026, 7, 30, 8, 0, 0, 0, time.UTC)

	mock.ExpectQuery(`(?s)SELECT status, COUNT\(\*\).*FROM tasks.*deleted_at IS NULL.*GROUP BY status`).
		WillReturnRows(sqlmock.NewRows([]string{"status", "count"}).
			AddRow("QUEUED", int64(2)).
			AddRow("SCANNING", int64(1)).
			AddRow("SUCCEEDED", int64(8)))
	counts, err := repository.TaskCounts(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if counts["QUEUED"] != 2 || counts["SCANNING"] != 1 ||
		counts["SUCCEEDED"] != 8 {
		t.Fatalf("task counts = %#v", counts)
	}

	mock.ExpectQuery(`(?s)SELECT.*job\.status = 'queued'.*COUNT\(DISTINCT CASE.*FROM jobs job.*JOIN tasks task.*deleted_at IS NULL`).
		WillReturnRows(sqlmock.NewRows([]string{
			"depth", "leases", "owners", "oldest", "latest",
		}).AddRow(int64(4), int64(3), int64(2), now.Add(-time.Minute), now))
	mock.ExpectQuery(`(?s)SELECT job\.kind, COUNT\(\*\).*FROM jobs job.*lease_until > UTC_TIMESTAMP`).
		WillReturnRows(sqlmock.NewRows([]string{"kind", "count"}).
			AddRow("scan", int64(2)).
			AddRow("trivy", int64(1)))
	queue, err := repository.Queue(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if queue.Depth != 4 || queue.ObservedLeases != 3 ||
		queue.ObservedOwners != 2 || queue.LeasesByKind["scan"] != 2 ||
		queue.OldestHeartbeatAt == nil || queue.LatestHeartbeatAt == nil {
		t.Fatalf("queue = %#v", queue)
	}

	generatedAt := now.Add(-24 * time.Hour)
	registeredAt := now.Add(-time.Hour)
	mock.ExpectQuery(`(?s)SELECT id, version, generated_at, content_sha256, trivy_db_version,.*FROM trivy_database_bundles.*ORDER BY registered_at DESC`).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "version", "generated_at", "content_sha256",
			"trivy_db_version", "trivy_java_db_version", "registered_at",
		}).AddRow(
			"123e4567-e89b-42d3-a456-426614174000",
			"2026-07-29",
			generatedAt,
			"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			"2026-07-29",
			"2026-07-29",
			registeredAt,
		))
	bundle, err := repository.TrivyDatabaseBundle(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if bundle == nil || bundle.Version != "2026-07-29" ||
		bundle.RegisteredAt != registeredAt {
		t.Fatalf("database bundle = %#v", bundle)
	}

	mock.ExpectQuery(`(?s)SELECT analyzer_name, analyzer_version, created_at.*FROM analyzer_runs.*ORDER BY created_at DESC, id DESC.*LIMIT 256`).
		WillReturnRows(sqlmock.NewRows([]string{
			"analyzer_name", "analyzer_version", "created_at",
		}).
			AddRow("ghidra", "11.4", now).
			AddRow("trivy", "0.69", now.Add(-time.Minute)).
			AddRow("ghidra", "11.3", now.Add(-time.Hour)))
	analyzers, err := repository.ObservedAnalyzers(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	mock.ExpectQuery(`(?s)SELECT worker_owner, worker_kind, analyzer_name, analyzer_version.*FROM worker_readiness.*LIMIT 256`).
		WillReturnRows(sqlmock.NewRows([]string{
			"worker_owner", "worker_kind", "analyzer_name", "analyzer_version",
			"runtime_name", "runtime_version", "status", "started_at", "last_checked_at",
		}).
			AddRow(
				"native/host/1", "native", "ghidra", "12.1.2", "jdk",
				`openjdk version "21.0.4"`, "ready", now.Add(-time.Hour), now,
			).
			AddRow(
				"trivy/host/1", "trivy", "trivy", "0.72.0", "", "",
				"ready", now.Add(-time.Hour), now,
			))
	readiness, err := repository.WorkerReadiness(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(readiness) != 2 || readiness[0].WorkerKind != "native" ||
		readiness[0].RuntimeName != "jdk" || readiness[1].AnalyzerName != "trivy" {
		t.Fatalf("worker readiness = %#v", readiness)
	}
	if len(analyzers) != 2 || analyzers[0].Name != "ghidra" ||
		analyzers[0].Version != "11.4" ||
		analyzers[1].Name != "trivy" {
		t.Fatalf("observed analyzers = %#v", analyzers)
	}

	mock.ExpectQuery(`(?s)WITH ordered_events AS.*LAG\(UPPER\(stage\)\).*FROM task_events.*INTERVAL 168 HOUR.*SELECT stage.*average_duration_ms`).
		WillReturnRows(sqlmock.NewRows([]string{
			"stage", "sample_count", "average_duration_ms",
		}).
			AddRow("IDENTIFYING", int64(8), uint64(420)).
			AddRow("SCANNING", int64(5), uint64(1250)))
	mock.ExpectQuery(`(?s)SELECT analyzer_name.*total_runs.*failed_runs.*failure_rate_basis_points.*FROM analyzer_runs.*status IN.*'succeeded'.*'timed_out'.*INTERVAL 168 HOUR.*LIMIT 32`).
		WillReturnRows(sqlmock.NewRows([]string{
			"analyzer_name", "total_runs", "failed_runs",
			"failure_rate_basis_points",
		}).
			AddRow("ghidra", int64(10), int64(2), uint64(2000)).
			AddRow("trivy", int64(8), int64(0), uint64(0)))
	metrics, err := repository.OperationalMetrics(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(metrics.StageDurations) != 2 ||
		metrics.StageDurations[1].Stage != "SCANNING" ||
		metrics.StageDurations[1].AverageDurationMilliseconds != 1250 ||
		len(metrics.AnalyzerFailureRates) != 2 ||
		metrics.AnalyzerFailureRates[0].FailureRateBasisPoints != 2000 {
		t.Fatalf("operational metrics = %#v", metrics)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestMySQLRepositoryQueueLeavesMissingHeartbeatNullable(t *testing.T) {
	database, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	repository := NewMySQLRepository(database)

	mock.ExpectQuery(`(?s)SELECT.*FROM jobs job.*JOIN tasks task`).
		WillReturnRows(sqlmock.NewRows([]string{
			"depth", "leases", "owners", "oldest", "latest",
		}).AddRow(int64(0), int64(0), int64(0), nil, nil))
	mock.ExpectQuery(`(?s)SELECT job\.kind, COUNT\(\*\).*FROM jobs job`).
		WillReturnRows(sqlmock.NewRows([]string{"kind", "count"}))

	queue, err := repository.Queue(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if queue.OldestHeartbeatAt != nil || queue.LatestHeartbeatAt != nil {
		t.Fatalf("queue heartbeat bounds = %#v", queue)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestMySQLRepositoryHonorsCancelledContext(t *testing.T) {
	database, _, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	repository := NewMySQLRepository(database)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if _, err := repository.TaskCounts(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("TaskCounts() error = %v", err)
	}
	if _, err := repository.Queue(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("Queue() error = %v", err)
	}
	if _, err := repository.TrivyDatabaseBundle(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("TrivyDatabaseBundle() error = %v", err)
	}
	if _, err := repository.ObservedAnalyzers(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("ObservedAnalyzers() error = %v", err)
	}
	if _, err := repository.WorkerReadiness(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("WorkerReadiness() error = %v", err)
	}
	if _, err := repository.OperationalMetrics(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("OperationalMetrics() error = %v", err)
	}
}

func TestMySQLRepositoryWrapsQueryFailure(t *testing.T) {
	database, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	repository := NewMySQLRepository(database)

	mock.ExpectQuery(`(?s)SELECT status, COUNT\(\*\).*FROM tasks`).
		WillReturnError(sql.ErrConnDone)
	_, err = repository.TaskCounts(context.Background())
	if !errors.Is(err, sql.ErrConnDone) {
		t.Fatalf("TaskCounts() error = %v", err)
	}
}

func TestMySQLRepositoryRejectsInvalidAnalyzerFailureRate(t *testing.T) {
	database, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	repository := NewMySQLRepository(database)

	mock.ExpectQuery(`(?s)WITH ordered_events AS.*FROM task_events`).
		WillReturnRows(sqlmock.NewRows([]string{
			"stage", "sample_count", "average_duration_ms",
		}))
	mock.ExpectQuery(`(?s)SELECT analyzer_name.*FROM analyzer_runs`).
		WillReturnRows(sqlmock.NewRows([]string{
			"analyzer_name", "total_runs", "failed_runs",
			"failure_rate_basis_points",
		}).AddRow("trivy", int64(1), int64(1), uint64(10_001)))

	if _, err := repository.OperationalMetrics(context.Background()); err == nil {
		t.Fatal("OperationalMetrics() error = nil, want invalid rate")
	}
}

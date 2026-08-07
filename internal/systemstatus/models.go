package systemstatus

import "time"

const (
	ServiceHealthy     = "healthy"
	ServiceDegraded    = "degraded"
	ServiceUnavailable = "unavailable"

	AnalyzerAvailable   = "available"
	AnalyzerUnavailable = "unavailable"

	StorageHealthy     = "healthy"
	StorageWarning     = "warning"
	StorageCritical    = "critical"
	StorageUnavailable = "unavailable"

	DatabaseBundleActive = "active"
	DatabaseBundleStale  = "stale"
)

type Build struct {
	Version   string `json:"version"`
	Commit    string `json:"commit"`
	BuildTime string `json:"build_time"`
	GoVersion string `json:"go_version"`
}

type Analyzer struct {
	Name                string     `json:"name"`
	Version             string     `json:"version"`
	ExpectedVersion     string     `json:"expected_version"`
	Status              string     `json:"status"`
	Scope               string     `json:"scope"`
	RequiredWorkerKinds []string   `json:"required_worker_kinds"`
	ReadyWorkerKinds    []string   `json:"ready_worker_kinds"`
	ReadyWorkers        int64      `json:"ready_workers"`
	RuntimeName         string     `json:"runtime_name"`
	RuntimeVersion      string     `json:"runtime_version"`
	LastCheckedAt       *time.Time `json:"last_checked_at"`
	LastRunAt           *time.Time `json:"last_run_at"`
	Detail              string     `json:"detail"`
}

type DatabaseBundle struct {
	ID                 string    `json:"id"`
	Version            string    `json:"version"`
	TrivyDBVersion     string    `json:"trivy_db_version"`
	TrivyJavaDBVersion string    `json:"trivy_java_db_version"`
	Status             string    `json:"status"`
	GeneratedAt        time.Time `json:"generated_at"`
	RegisteredAt       time.Time `json:"registered_at"`
	AgeDays            int       `json:"age_days"`
	StaleAfterDays     int       `json:"stale_after_days"`
	ContentSHA256      string    `json:"content_sha256"`
}

type StorageMount struct {
	ID               string   `json:"id"`
	Label            string   `json:"label"`
	Purpose          string   `json:"purpose"`
	HostPath         *string  `json:"host_path"`
	ContainerPath    string   `json:"container_path"`
	Services         []string `json:"services"`
	UsedBytes        *uint64  `json:"used_bytes"`
	TotalBytes       *uint64  `json:"total_bytes"`
	FreeBytes        *uint64  `json:"free_bytes"`
	MinimumFreeBytes uint64   `json:"minimum_free_bytes"`
	WarningPercent   int      `json:"warning_percent"`
	CriticalPercent  int      `json:"critical_percent"`
	Writable         *bool    `json:"writable"`
	LowWater         *bool    `json:"low_water"`
	Status           string   `json:"status"`
}

type WorkerSummary struct {
	ObservedLeases    int64            `json:"observed_leases"`
	ObservedOwners    int64            `json:"observed_owners"`
	LeasesByKind      map[string]int64 `json:"leases_by_kind"`
	OldestHeartbeatAt *time.Time       `json:"oldest_heartbeat_at"`
	LatestHeartbeatAt *time.Time       `json:"latest_heartbeat_at"`
}

type StageDurationMetric struct {
	Stage                       string `json:"stage"`
	SampleCount                 int64  `json:"sample_count"`
	AverageDurationMilliseconds uint64 `json:"average_duration_ms"`
}

type AnalyzerFailureMetric struct {
	Name                   string `json:"name"`
	TotalRuns              int64  `json:"total_runs"`
	FailedRuns             int64  `json:"failed_runs"`
	FailureRateBasisPoints uint16 `json:"failure_rate_basis_points"`
}

type OperationalMetrics struct {
	WindowHours          uint16                  `json:"window_hours"`
	StageDurations       []StageDurationMetric   `json:"stage_durations"`
	AnalyzerFailureRates []AnalyzerFailureMetric `json:"analyzer_failure_rates"`
}

type Diagnostic struct {
	Code        string `json:"code"`
	Severity    string `json:"severity"`
	Component   string `json:"component"`
	Message     string `json:"message"`
	Remediation string `json:"remediation"`
}

type Status struct {
	Version              string             `json:"version"`
	Service              string             `json:"service"`
	ServiceStatus        string             `json:"service_status"`
	Build                Build              `json:"build"`
	ActiveTasks          int64              `json:"active_tasks"`
	QueuedTasks          int64              `json:"queued_tasks"`
	QueueDepth           int64              `json:"queue_depth"`
	RepositoryUsedBytes  uint64             `json:"repository_used_bytes"`
	RepositoryTotalBytes uint64             `json:"repository_total_bytes"`
	TrivyDBVersion       string             `json:"trivy_db_version"`
	Analyzers            []Analyzer         `json:"analyzers"`
	StorageMounts        []StorageMount     `json:"storage_mounts"`
	TrivyDatabaseBundle  *DatabaseBundle    `json:"trivy_database_bundle"`
	TaskCounts           map[string]int64   `json:"task_counts"`
	WorkerSummary        WorkerSummary      `json:"worker_summary"`
	OperationalMetrics   OperationalMetrics `json:"operational_metrics"`
	CollectedAt          time.Time          `json:"collected_at"`
	Diagnostics          []Diagnostic       `json:"diagnostics"`
}

type QueueRecord struct {
	Depth             int64
	ObservedLeases    int64
	ObservedOwners    int64
	LeasesByKind      map[string]int64
	OldestHeartbeatAt *time.Time
	LatestHeartbeatAt *time.Time
}

type DatabaseBundleRecord struct {
	ID                 string
	Version            string
	GeneratedAt        time.Time
	ContentSHA256      string
	TrivyDBVersion     string
	TrivyJavaDBVersion string
	RegisteredAt       time.Time
}

type ObservedAnalyzer struct {
	Name          string
	Version       string
	LastCheckedAt time.Time
}

type WorkerReadinessRecord struct {
	Owner           string
	WorkerKind      string
	AnalyzerName    string
	AnalyzerVersion string
	RuntimeName     string
	RuntimeVersion  string
	Status          string
	StartedAt       time.Time
	LastCheckedAt   time.Time
}

type OperationalMetricsRecord struct {
	StageDurations       []StageDurationMetric
	AnalyzerFailureRates []AnalyzerFailureMetric
}

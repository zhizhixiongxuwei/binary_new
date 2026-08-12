package systemstatus

import (
	"context"
	"errors"
	"fmt"
	"math"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"binaryscan/internal/buildinfo"
)

const (
	defaultCollectionTimeout       = 2 * time.Second
	defaultProbeTimeout            = 500 * time.Millisecond
	defaultStaleAfterDays          = 7
	defaultAnalyzerHeartbeatMaxAge = 45 * time.Second
	storageWarningPercent          = 80
	storageCriticalPercent         = 90
	maxAnalyzerStatuses            = 16
	operationalWindowHours         = 168
)

var taskStatuses = []string{
	"UPLOADING",
	"QUEUED",
	"VALIDATING",
	"IDENTIFYING",
	"EXTRACTING",
	"INDEXING",
	"SCANNING",
	"REPORTING",
	"SUCCEEDED",
	"PARTIAL_SUCCEEDED",
	"FAILED",
	"CANCEL_REQUESTED",
	"CANCELLED",
	"DELETING",
	"DELETED",
}

var activeTaskStatuses = map[string]struct{}{
	"VALIDATING":       {},
	"IDENTIFYING":      {},
	"EXTRACTING":       {},
	"INDEXING":         {},
	"SCANNING":         {},
	"REPORTING":        {},
	"CANCEL_REQUESTED": {},
	"DELETING":         {},
}

var jobKinds = []string{
	"scan", "image", "native", "bytecode", "trivy", "report", "decompile",
	"c_analysis",
	"java_analysis",
}

type AnalyzerRegistration struct {
	Name                string
	Version             string
	Scope               string
	RequiredWorkerKinds []string
}

type Config struct {
	Service                 string
	Build                   buildinfo.Info
	UploadsRoot             string
	RepositoryRoot          string
	TaskWorkRoot            string
	StorageMinFreeBytes     int64
	CollectionTimeout       time.Duration
	ProbeTimeout            time.Duration
	AnalyzerHeartbeatMaxAge time.Duration
	Analyzers               []AnalyzerRegistration
	StorageProbe            StorageProbe
}

type Service struct {
	repository              Repository
	service                 string
	build                   buildinfo.Info
	mounts                  []mountDefinition
	minimumFreeBytes        uint64
	collectionTimeout       time.Duration
	probeTimeout            time.Duration
	analyzerHeartbeatMaxAge time.Duration
	analyzers               []AnalyzerRegistration
	storageProbe            StorageProbe
	probeSlots              chan struct{}
	now                     func() time.Time
}

type mountDefinition struct {
	ID            string
	Label         string
	Purpose       string
	ContainerPath string
	Services      []string
}

type probeResult struct {
	usage DiskUsage
	err   error
}

func NewService(repository Repository, config Config) (*Service, error) {
	if repository == nil {
		return nil, errors.New("system status repository is required")
	}
	if strings.TrimSpace(config.Service) == "" {
		return nil, errors.New("system status service name is required")
	}
	if config.StorageMinFreeBytes <= 0 {
		return nil, errors.New("system status minimum free bytes must be positive")
	}
	for name, root := range map[string]string{
		"uploads":    config.UploadsRoot,
		"repository": config.RepositoryRoot,
		"task-work":  config.TaskWorkRoot,
	} {
		if !filepath.IsAbs(root) || root == "/" || filepath.Clean(root) != root {
			return nil, fmt.Errorf("%s storage root must be a canonical absolute path below /", name)
		}
	}
	if config.CollectionTimeout == 0 {
		config.CollectionTimeout = defaultCollectionTimeout
	}
	if config.ProbeTimeout == 0 {
		config.ProbeTimeout = defaultProbeTimeout
	}
	if config.AnalyzerHeartbeatMaxAge == 0 {
		config.AnalyzerHeartbeatMaxAge = defaultAnalyzerHeartbeatMaxAge
	}
	if config.CollectionTimeout < 0 || config.ProbeTimeout < 0 ||
		config.AnalyzerHeartbeatMaxAge < time.Second {
		return nil, errors.New("system status timeouts must be positive")
	}
	if config.StorageProbe == nil {
		config.StorageProbe = SecureStorageProbe{}
	}
	analyzers, err := normalizeAnalyzerRegistrations(config.Analyzers)
	if err != nil {
		return nil, err
	}
	return &Service{
		repository:              repository,
		service:                 strings.TrimSpace(config.Service),
		build:                   config.Build,
		minimumFreeBytes:        uint64(config.StorageMinFreeBytes),
		collectionTimeout:       config.CollectionTimeout,
		probeTimeout:            config.ProbeTimeout,
		analyzerHeartbeatMaxAge: config.AnalyzerHeartbeatMaxAge,
		analyzers:               analyzers,
		storageProbe:            config.StorageProbe,
		probeSlots:              make(chan struct{}, 3),
		now:                     time.Now,
		mounts: []mountDefinition{
			{
				ID: "uploads", Label: "Upload staging",
				Purpose:       "Browser multipart upload staging",
				ContainerPath: config.UploadsRoot,
				Services:      []string{"app"},
			},
			{
				ID: "repository", Label: "Artifact repository",
				Purpose:       "Samples, extracted content, analyzer artifacts, and reports",
				ContainerPath: config.RepositoryRoot,
				Services:      []string{"app", "scanner", "java", "ghidra"},
			},
			{
				ID: "task-work", Label: "Task workspace",
				Purpose:       "Ephemeral per-task extraction and analyzer workspaces",
				ContainerPath: config.TaskWorkRoot,
				Services:      []string{"app", "scanner", "java", "ghidra"},
			},
		},
	}, nil
}

func (s *Service) Get(ctx context.Context) (Status, error) {
	if err := ctx.Err(); err != nil {
		return Status{}, err
	}
	now := s.now().UTC()
	value := Status{
		Version:       s.build.Version,
		Service:       s.service,
		ServiceStatus: ServiceHealthy,
		Build: Build{
			Version: s.build.Version, Commit: s.build.Commit,
			BuildTime: s.build.BuildTime, GoVersion: s.build.GoVersion,
		},
		Analyzers:     make([]Analyzer, 0),
		StorageMounts: make([]StorageMount, 0, len(s.mounts)),
		TaskCounts:    zeroTaskCounts(),
		WorkerSummary: WorkerSummary{
			LeasesByKind: zeroLeaseKinds(),
		},
		OperationalMetrics: OperationalMetrics{
			WindowHours:          operationalWindowHours,
			StageDurations:       make([]StageDurationMetric, 0),
			AnalyzerFailureRates: make([]AnalyzerFailureMetric, 0),
		},
		CollectedAt: now,
		Diagnostics: make([]Diagnostic, 0),
	}

	collectionCtx, cancel := context.WithTimeout(ctx, s.collectionTimeout)
	defer cancel()
	coreUnavailable := false
	if counts, err := s.repository.TaskCounts(collectionCtx); err != nil {
		coreUnavailable = true
		value.Diagnostics = append(value.Diagnostics, Diagnostic{
			Code: "task_counts_unavailable", Severity: "error",
			Component: "mysql", Message: "Task status counts could not be collected.",
			Remediation: "Verify MySQL readiness and the applied database schema.",
		})
	} else {
		for status, count := range counts {
			value.TaskCounts[status] = count
			if _, active := activeTaskStatuses[status]; active {
				value.ActiveTasks += count
			}
		}
		value.QueuedTasks = value.TaskCounts["QUEUED"]
	}

	if queue, err := s.repository.Queue(collectionCtx); err != nil {
		coreUnavailable = true
		value.Diagnostics = append(value.Diagnostics, Diagnostic{
			Code: "queue_summary_unavailable", Severity: "error",
			Component: "mysql", Message: "Queue and lease summaries could not be collected.",
			Remediation: "Verify MySQL readiness and the jobs table schema.",
		})
	} else {
		value.QueueDepth = queue.Depth
		value.WorkerSummary.ObservedLeases = queue.ObservedLeases
		value.WorkerSummary.ObservedOwners = queue.ObservedOwners
		value.WorkerSummary.OldestHeartbeatAt = queue.OldestHeartbeatAt
		value.WorkerSummary.LatestHeartbeatAt = queue.LatestHeartbeatAt
		for kind, count := range queue.LeasesByKind {
			value.WorkerSummary.LeasesByKind[kind] = count
		}
	}

	if record, err := s.repository.TrivyDatabaseBundle(collectionCtx); err != nil {
		value.Diagnostics = append(value.Diagnostics, Diagnostic{
			Code: "trivy_database_bundle_unavailable", Severity: "warning",
			Component: "mysql", Message: "Trivy database bundle metadata could not be collected.",
			Remediation: "Verify MySQL readiness and the Trivy bundle metadata schema.",
		})
	} else {
		value.TrivyDatabaseBundle = s.databaseBundle(record, now, &value.Diagnostics)
		if record != nil {
			value.TrivyDBVersion = record.TrivyDBVersion
		}
	}

	readiness, readinessErr := s.repository.WorkerReadiness(collectionCtx)
	if readinessErr != nil {
		value.Diagnostics = append(value.Diagnostics, Diagnostic{
			Code: "analyzer_readiness_unavailable", Severity: "warning",
			Component: "mysql", Message: "Live analyzer worker readiness could not be collected.",
			Remediation: "Verify the worker_readiness migration and MySQL access for the API.",
		})
	}
	observed, observedErr := s.repository.ObservedAnalyzers(collectionCtx)
	if observedErr != nil {
		value.Diagnostics = append(value.Diagnostics, Diagnostic{
			Code: "analyzer_observations_unavailable", Severity: "warning",
			Component: "mysql", Message: "Historical analyzer observations could not be collected.",
			Remediation: "Verify MySQL readiness and the analyzer run metadata schema.",
		})
	}
	value.Analyzers = mergeAnalyzers(
		s.analyzers,
		readiness,
		observed,
		now,
		s.analyzerHeartbeatMaxAge,
	)
	requireTrivyBundle(value.Analyzers, value.TrivyDatabaseBundle)
	for _, analyzer := range value.Analyzers {
		if analyzer.Status == AnalyzerUnavailable {
			value.Diagnostics = append(value.Diagnostics, Diagnostic{
				Code: "analyzer_unavailable", Severity: "warning",
				Component:   analyzer.Name,
				Message:     "No fresh, identity-matched heartbeat covers every required analyzer worker.",
				Remediation: "Start the preloaded analyzer workers and verify their locked tool versions and health checks.",
			})
		}
	}

	if metrics, err := s.repository.OperationalMetrics(collectionCtx); err != nil {
		value.Diagnostics = append(value.Diagnostics, Diagnostic{
			Code: "operational_metrics_unavailable", Severity: "warning",
			Component: "mysql", Message: "Stage duration and analyzer failure metrics could not be collected.",
			Remediation: "Verify MySQL readiness and the task event and analyzer run indexes.",
		})
	} else {
		value.OperationalMetrics.StageDurations = metrics.StageDurations
		value.OperationalMetrics.AnalyzerFailureRates = metrics.AnalyzerFailureRates
		if value.OperationalMetrics.StageDurations == nil {
			value.OperationalMetrics.StageDurations = make([]StageDurationMetric, 0)
		}
		if value.OperationalMetrics.AnalyzerFailureRates == nil {
			value.OperationalMetrics.AnalyzerFailureRates = make(
				[]AnalyzerFailureMetric,
				0,
			)
		}
	}

	value.StorageMounts = s.collectStorage(ctx, &value.Diagnostics)
	for _, mount := range value.StorageMounts {
		if mount.ID == "repository" && mount.UsedBytes != nil && mount.TotalBytes != nil {
			value.RepositoryUsedBytes = *mount.UsedBytes
			value.RepositoryTotalBytes = *mount.TotalBytes
		}
		if mount.ID == "repository" &&
			(mount.Status == StorageUnavailable ||
				(mount.Writable != nil && !*mount.Writable)) {
			coreUnavailable = true
		}
	}

	switch {
	case coreUnavailable:
		value.ServiceStatus = ServiceUnavailable
	case len(value.Diagnostics) != 0 || storageIsDegraded(value.StorageMounts):
		value.ServiceStatus = ServiceDegraded
	default:
		value.ServiceStatus = ServiceHealthy
	}
	return value, nil
}

func (s *Service) collectStorage(
	ctx context.Context,
	diagnostics *[]Diagnostic,
) []StorageMount {
	results := make([]probeResult, len(s.mounts))
	done := make(chan int, len(s.mounts))
	for index, mount := range s.mounts {
		index, mount := index, mount
		go func() {
			results[index] = s.probe(ctx, mount.ContainerPath)
			done <- index
		}()
	}
	for range s.mounts {
		<-done
	}

	mounts := make([]StorageMount, 0, len(s.mounts))
	for index, definition := range s.mounts {
		mount := StorageMount{
			ID: definition.ID, Label: definition.Label,
			Purpose: definition.Purpose, HostPath: nil,
			ContainerPath:    definition.ContainerPath,
			Services:         append([]string(nil), definition.Services...),
			MinimumFreeBytes: s.minimumFreeBytes,
			WarningPercent:   storageWarningPercent,
			CriticalPercent:  storageCriticalPercent,
			Status:           StorageUnavailable,
		}
		result := results[index]
		if result.err != nil {
			*diagnostics = append(*diagnostics, Diagnostic{
				Code: "storage_unavailable", Severity: "warning",
				Component:   definition.ID,
				Message:     "The configured container storage root could not be inspected.",
				Remediation: "Verify the configured container mount and restart the affected service.",
			})
			mounts = append(mounts, mount)
			continue
		}
		mount.UsedBytes = uint64Pointer(result.usage.UsedBytes)
		mount.TotalBytes = uint64Pointer(result.usage.TotalBytes)
		mount.FreeBytes = uint64Pointer(result.usage.FreeBytes)
		mount.Writable = boolPointer(result.usage.Writable)
		lowWater := result.usage.FreeBytes < s.minimumFreeBytes
		mount.LowWater = boolPointer(lowWater)
		usedPercent := storageUsedPercent(
			result.usage.UsedBytes,
			result.usage.TotalBytes,
		)
		switch {
		case !result.usage.Writable || lowWater ||
			usedPercent >= storageCriticalPercent:
			mount.Status = StorageCritical
		case usedPercent >= storageWarningPercent ||
			nearLowWater(result.usage.FreeBytes, s.minimumFreeBytes):
			mount.Status = StorageWarning
		default:
			mount.Status = StorageHealthy
		}
		if !result.usage.Writable {
			*diagnostics = append(*diagnostics, Diagnostic{
				Code: "storage_not_writable", Severity: "error",
				Component:   definition.ID,
				Message:     "The configured container storage root is not writable.",
				Remediation: "Correct mount ownership or read/write mode before accepting new uploads.",
			})
		} else if lowWater {
			*diagnostics = append(*diagnostics, Diagnostic{
				Code: "storage_low_water", Severity: "warning",
				Component:   definition.ID,
				Message:     "Free capacity is below the configured low-water threshold.",
				Remediation: "Free space or expand the mounted volume before accepting new uploads.",
			})
		}
		mounts = append(mounts, mount)
	}
	return mounts
}

func (s *Service) probe(ctx context.Context, root string) probeResult {
	probeCtx, cancel := context.WithTimeout(ctx, s.probeTimeout)
	defer cancel()
	select {
	case s.probeSlots <- struct{}{}:
	case <-probeCtx.Done():
		return probeResult{err: probeCtx.Err()}
	}

	result := make(chan probeResult, 1)
	go func() {
		usage, err := s.storageProbe.Probe(probeCtx, root)
		<-s.probeSlots
		result <- probeResult{usage: usage, err: err}
	}()
	select {
	case value := <-result:
		return value
	case <-probeCtx.Done():
		return probeResult{err: probeCtx.Err()}
	}
}

func (s *Service) databaseBundle(
	record *DatabaseBundleRecord,
	now time.Time,
	diagnostics *[]Diagnostic,
) *DatabaseBundle {
	if record == nil {
		*diagnostics = append(*diagnostics, Diagnostic{
			Code: "trivy_database_bundle_missing", Severity: "warning",
			Component:   "trivy",
			Message:     "No Trivy database bundle has been registered by a scanner worker.",
			Remediation: "Start the scanner image that contains both fixed Trivy databases.",
		})
		return nil
	}
	ageDays := elapsedDays(now, record.GeneratedAt)
	status := DatabaseBundleActive
	if ageDays >= defaultStaleAfterDays {
		status = DatabaseBundleStale
		*diagnostics = append(*diagnostics, Diagnostic{
			Code: "trivy_database_bundle_stale", Severity: "warning",
			Component:   "trivy",
			Message:     "The fixed Trivy database bundle is older than its freshness threshold.",
			Remediation: "Load and deploy a newer scanner image with an updated database bundle.",
		})
	}
	return &DatabaseBundle{
		ID: record.ID, Version: record.Version,
		TrivyDBVersion:     record.TrivyDBVersion,
		TrivyJavaDBVersion: record.TrivyJavaDBVersion,
		Status:             status, GeneratedAt: record.GeneratedAt.UTC(),
		RegisteredAt: record.RegisteredAt.UTC(), AgeDays: ageDays,
		StaleAfterDays: defaultStaleAfterDays,
		ContentSHA256:  record.ContentSHA256,
	}
}

func normalizeAnalyzerRegistrations(
	values []AnalyzerRegistration,
) ([]AnalyzerRegistration, error) {
	if len(values) == 0 {
		values = []AnalyzerRegistration{
			{
				Name: "ghidra", Scope: "native_binary",
				RequiredWorkerKinds: []string{"native"},
			},
			{
				Name: "trivy", Scope: "container_image",
				RequiredWorkerKinds: []string{"image", "trivy"},
			},
		}
	}
	if len(values) > maxAnalyzerStatuses {
		return nil, fmt.Errorf(
			"system status analyzer count exceeds %d",
			maxAnalyzerStatuses,
		)
	}
	seen := make(map[string]struct{}, len(values))
	result := make([]AnalyzerRegistration, 0, len(values))
	for _, value := range values {
		value.Name = strings.TrimSpace(value.Name)
		value.Version = strings.TrimSpace(value.Version)
		value.Scope = strings.TrimSpace(value.Scope)
		value.RequiredWorkerKinds = append(
			[]string(nil), value.RequiredWorkerKinds...,
		)
		if value.Name == "" || value.Scope == "" {
			return nil, errors.New("system status analyzer name and scope are required")
		}
		if len(value.RequiredWorkerKinds) == 0 {
			return nil, fmt.Errorf("analyzer %q requires at least one worker kind", value.Name)
		}
		kindSeen := make(map[string]struct{}, len(value.RequiredWorkerKinds))
		for index, kind := range value.RequiredWorkerKinds {
			kind = strings.TrimSpace(kind)
			if kind == "" {
				return nil, fmt.Errorf("analyzer %q has an empty worker kind", value.Name)
			}
			if _, duplicate := kindSeen[kind]; duplicate {
				return nil, fmt.Errorf("analyzer %q has duplicate worker kind %q", value.Name, kind)
			}
			kindSeen[kind] = struct{}{}
			value.RequiredWorkerKinds[index] = kind
		}
		sort.Strings(value.RequiredWorkerKinds)
		key := strings.ToLower(value.Name)
		if _, exists := seen[key]; exists {
			return nil, fmt.Errorf("duplicate system status analyzer %q", value.Name)
		}
		seen[key] = struct{}{}
		result = append(result, value)
	}
	sort.Slice(result, func(left, right int) bool {
		return result[left].Name < result[right].Name
	})
	return result, nil
}

func mergeAnalyzers(
	registrations []AnalyzerRegistration,
	readiness []WorkerReadinessRecord,
	observed []ObservedAnalyzer,
	now time.Time,
	heartbeatMaxAge time.Duration,
) []Analyzer {
	result := make([]Analyzer, 0, len(registrations)+len(observed))
	index := make(map[string]int, len(registrations))
	lastRuns := make(map[string]ObservedAnalyzer, len(observed))
	for _, observation := range observed {
		key := strings.ToLower(strings.TrimSpace(observation.Name))
		if key == "" {
			continue
		}
		if current, exists := lastRuns[key]; !exists ||
			observation.LastCheckedAt.After(current.LastCheckedAt) {
			lastRuns[key] = observation
		}
	}
	cutoff := now.Add(-heartbeatMaxAge)
	for _, registration := range registrations {
		key := strings.ToLower(registration.Name)
		analyzer := Analyzer{
			Name: registration.Name, ExpectedVersion: registration.Version,
			Status: AnalyzerUnavailable, Scope: registration.Scope,
			RequiredWorkerKinds: append(
				[]string(nil), registration.RequiredWorkerKinds...,
			),
			ReadyWorkerKinds: make([]string, 0),
		}
		if observation, exists := lastRuns[key]; exists {
			checkedAt := observation.LastCheckedAt.UTC()
			analyzer.LastRunAt = &checkedAt
		}
		readyKinds := make(map[string]struct{})
		var latest *WorkerReadinessRecord
		identityMismatch := false
		for position := range readiness {
			record := readiness[position]
			if !strings.EqualFold(strings.TrimSpace(record.AnalyzerName), registration.Name) {
				continue
			}
			if latest == nil || record.LastCheckedAt.After(latest.LastCheckedAt) {
				copy := record
				latest = &copy
			}
			fresh := record.Status == "ready" &&
				!record.LastCheckedAt.Before(cutoff) &&
				!record.LastCheckedAt.After(now.Add(heartbeatMaxAge))
			if !fresh {
				continue
			}
			if registration.Version != "" &&
				record.AnalyzerVersion != registration.Version {
				identityMismatch = true
				continue
			}
			if analyzer.RuntimeName == "" {
				analyzer.RuntimeName = record.RuntimeName
				analyzer.RuntimeVersion = record.RuntimeVersion
			} else if analyzer.RuntimeName != record.RuntimeName ||
				analyzer.RuntimeVersion != record.RuntimeVersion {
				identityMismatch = true
				continue
			}
			analyzer.Version = record.AnalyzerVersion
			analyzer.ReadyWorkers++
			readyKinds[record.WorkerKind] = struct{}{}
		}
		if latest != nil {
			checkedAt := latest.LastCheckedAt.UTC()
			analyzer.LastCheckedAt = &checkedAt
			if analyzer.Version == "" {
				analyzer.Version = latest.AnalyzerVersion
				analyzer.RuntimeName = latest.RuntimeName
				analyzer.RuntimeVersion = latest.RuntimeVersion
			}
		}
		for kind := range readyKinds {
			analyzer.ReadyWorkerKinds = append(analyzer.ReadyWorkerKinds, kind)
		}
		sort.Strings(analyzer.ReadyWorkerKinds)
		missingKinds := make([]string, 0)
		for _, required := range registration.RequiredWorkerKinds {
			if _, ready := readyKinds[required]; !ready {
				missingKinds = append(missingKinds, required)
			}
		}
		switch {
		case identityMismatch:
			analyzer.Detail = "A fresh worker heartbeat reported a tool or runtime identity that differs from the configured lock."
		case len(missingKinds) == 0 && analyzer.ReadyWorkers > 0:
			analyzer.Status = AnalyzerAvailable
			analyzer.Detail = fmt.Sprintf(
				"%d ready worker(s) cover required kinds: %s.",
				analyzer.ReadyWorkers,
				strings.Join(analyzer.ReadyWorkerKinds, ", "),
			)
		case latest == nil:
			analyzer.Detail = "No worker readiness heartbeat has been registered."
		case latest.LastCheckedAt.Before(cutoff):
			analyzer.Detail = "The latest worker readiness heartbeat is stale."
		default:
			analyzer.Detail = "Fresh readiness is missing for required worker kinds: " +
				strings.Join(missingKinds, ", ") + "."
		}
		index[key] = len(result)
		result = append(result, analyzer)
	}
	for _, observation := range observed {
		key := strings.ToLower(strings.TrimSpace(observation.Name))
		if key == "" {
			continue
		}
		checkedAt := observation.LastCheckedAt.UTC()
		if _, exists := index[key]; exists {
			continue
		}
		if len(result) == maxAnalyzerStatuses {
			break
		}
		index[key] = len(result)
		result = append(result, Analyzer{
			Name: observation.Name, Version: observation.Version,
			Status: AnalyzerUnavailable, Scope: "historical",
			RequiredWorkerKinds: []string{}, ReadyWorkerKinds: []string{},
			LastRunAt: &checkedAt,
			Detail:    "A historical analyzer run was observed, but no live adapter is registered.",
		})
	}
	sort.Slice(result, func(left, right int) bool {
		return result[left].Name < result[right].Name
	})
	return result
}

func zeroTaskCounts() map[string]int64 {
	counts := make(map[string]int64, len(taskStatuses))
	for _, status := range taskStatuses {
		counts[status] = 0
	}
	return counts
}

func requireTrivyBundle(
	analyzers []Analyzer,
	bundle *DatabaseBundle,
) {
	if bundle != nil {
		return
	}
	for index := range analyzers {
		if !strings.EqualFold(analyzers[index].Name, "trivy") {
			continue
		}
		analyzers[index].Status = AnalyzerUnavailable
		analyzers[index].Detail = "Worker and tool readiness are reported separately; the fixed Trivy database bundle is missing."
	}
}

func zeroLeaseKinds() map[string]int64 {
	counts := make(map[string]int64, len(jobKinds))
	for _, kind := range jobKinds {
		counts[kind] = 0
	}
	return counts
}

func elapsedDays(now, generatedAt time.Time) int {
	if !generatedAt.Before(now) {
		return 0
	}
	return int(now.Sub(generatedAt) / (24 * time.Hour))
}

func storageUsedPercent(used, total uint64) int {
	if total == 0 {
		return 100
	}
	return int(math.Round((float64(used) / float64(total)) * 100))
}

func nearLowWater(free, minimum uint64) bool {
	if minimum > math.MaxUint64/2 {
		return free < math.MaxUint64
	}
	return free < minimum*2
}

func storageIsDegraded(mounts []StorageMount) bool {
	for _, mount := range mounts {
		if mount.Status != StorageHealthy {
			return true
		}
	}
	return false
}

func uint64Pointer(value uint64) *uint64 {
	return &value
}

func boolPointer(value bool) *bool {
	return &value
}

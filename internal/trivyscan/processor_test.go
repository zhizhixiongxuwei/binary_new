package trivyscan

import (
	"archive/tar"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	trivyadapter "binaryscan/internal/analyzers/trivy"
	"binaryscan/internal/containerarchive"
	"binaryscan/internal/queue"
	"binaryscan/internal/storageguard"
	"binaryscan/internal/trivydb"
)

type repositoryStub struct {
	mu           sync.Mutex
	publications []Publication
	onPublish    func(Publication) error
}

type summaryRepositoryStub struct {
	repositoryStub
	summary PublishSummary
}

type progressStub struct {
	inputs     []queue.ProgressInput
	activities []queue.ActivityInput
	err        error
}

func (s *progressStub) TaskActivity(
	_ context.Context,
	_ queue.Lease,
	input queue.ActivityInput,
) error {
	s.activities = append(s.activities, input)
	return s.err
}

func (s *progressStub) TaskProgress(
	_ context.Context,
	_ queue.Lease,
	input queue.ProgressInput,
) error {
	s.inputs = append(s.inputs, input)
	return s.err
}

func (r *summaryRepositoryStub) PublishWithSummary(
	_ context.Context,
	_ queue.Lease,
	value Publication,
) (PublishSummary, error) {
	r.publications = append(r.publications, value)
	return r.summary, nil
}

func (r *repositoryStub) Publish(
	_ context.Context,
	_ queue.Lease,
	value Publication,
) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.onPublish != nil {
		if err := r.onPublish(value); err != nil {
			return err
		}
	}
	r.publications = append(r.publications, value)
	return nil
}

type databaseViewStub struct {
	path     string
	snapshot trivydb.Snapshot
	closed   bool
}

func (v *databaseViewStub) Path() string {
	return v.path
}

func (v *databaseViewStub) Snapshot() trivydb.Snapshot {
	return v.snapshot
}

func (v *databaseViewStub) Close() error {
	v.closed = true
	return os.Remove(v.path)
}

type storageGuardStub struct {
	err             error
	calls           int
	workBytes       int64
	repositoryBytes int64
	releases        int
}

func (g *storageGuardStub) CheckCreate(context.Context, int64) error {
	g.calls++
	return g.err
}

func (g *storageGuardStub) ReservePlan(
	_ context.Context,
	workBytes int64,
	repositoryBytes int64,
) (func(), error) {
	g.calls++
	g.workBytes = workBytes
	g.repositoryBytes = repositoryBytes
	if g.err != nil {
		return nil, g.err
	}
	return func() {
		g.releases++
	}, nil
}

type analyzerFunc func(
	context.Context,
	trivyadapter.Request,
) (trivyadapter.Report, error)

func (f analyzerFunc) Analyze(
	ctx context.Context,
	request trivyadapter.Request,
) (trivyadapter.Report, error) {
	return f(ctx, request)
}

func TestProcessorRunsRealOfflineAdapterForSingleDockerImage(t *testing.T) {
	fixture := newProcessorFixture(t, dockerTAR(t, 1))
	executable := writeFakeTrivy(t, fixture.root, successfulReportJSON)
	base := trivyadapter.Config{
		Executable:             executable,
		MaxDuration:            30 * time.Second,
		TerminationGracePeriod: 50 * time.Millisecond,
		MaxStandardOutputBytes: 1 << 20,
		MaxStandardErrorBytes:  1 << 20,
		MaxReportBytes:         4 << 20,
		MaxResults:             100,
		MaxFindings:            1_000,
	}
	processor := fixture.processor(t, NewAdapterFactory(base))
	outcome, err := processor.Process(context.Background(), fixture.lease(false))
	if err != nil {
		t.Fatal(err)
	}
	if outcome.Outcome != queue.OutcomeSucceeded {
		t.Fatalf("outcome = %+v", outcome)
	}
	if fixture.guard.calls != 1 {
		t.Fatalf("storage checks = %d, want 1", fixture.guard.calls)
	}
	if fixture.guard.workBytes <= fixture.size ||
		fixture.guard.repositoryBytes != 4<<20 ||
		fixture.guard.releases != 1 {
		t.Fatalf(
			"storage reservation = work:%d repository:%d releases:%d",
			fixture.guard.workBytes,
			fixture.guard.repositoryBytes,
			fixture.guard.releases,
		)
	}
	if len(fixture.repository.publications) != 1 {
		t.Fatalf("publications = %d", len(fixture.repository.publications))
	}
	if len(fixture.progress.inputs) != 1 ||
		fixture.progress.inputs[0].TaskStatus != "REPORTING" ||
		fixture.progress.inputs[0].Stage != "REPORTING" {
		t.Fatalf("progress inputs = %+v", fixture.progress.inputs)
	}
	publication := fixture.repository.publications[0]
	if publication.Snapshot.Trivy.ID != testSnapshot().Trivy.ID ||
		len(publication.Runs) != 1 ||
		publication.Runs[0].Status != "succeeded" ||
		publication.Runs[0].Platform != "linux/amd64" ||
		len(publication.Runs[0].Findings) != 1 ||
		publication.Runs[0].Findings[0].VulnerabilityID != "CVE-2026-0001" {
		t.Fatalf("publication = %+v", publication)
	}
	if publication.Runs[0].Raw == nil {
		t.Fatal("raw report metadata was not published")
	}
	wantedPhases := []string{
		"verifying",
		"database_ready",
		"targets_ready",
		"scanning",
		"target_completed",
		"publishing",
		"completed",
	}
	if len(fixture.progress.activities) != len(wantedPhases) {
		t.Fatalf(
			"activity count = %d, want %d: %+v",
			len(fixture.progress.activities),
			len(wantedPhases),
			fixture.progress.activities,
		)
	}
	for index, input := range fixture.progress.activities {
		var payload trivyActivityPayload
		if err := json.Unmarshal(input.Payload, &payload); err != nil {
			t.Fatalf("activity %d payload = %q: %v", index, input.Payload, err)
		}
		if payload.Phase != wantedPhases[index] {
			t.Fatalf(
				"activity %d phase = %q, want %q",
				index,
				payload.Phase,
				wantedPhases[index],
			)
		}
		serialized := string(input.Payload)
		for _, forbidden := range []string{
			fixture.repositoryRoot,
			fixture.workRoot,
			"SourceStorageKey",
			"blobs/sha256/",
		} {
			if strings.Contains(serialized, forbidden) {
				t.Fatalf("activity %d leaked internal data: %s", index, serialized)
			}
		}
	}
}

func TestProcessorRequiresReportingTransitionBeforePublication(t *testing.T) {
	fixture := newProcessorFixture(t, dockerTAR(t, 1))
	progressErr := errors.New("progress lease lost")
	fixture.progress.err = progressErr
	processor := fixture.processor(t, func(
		string,
		string,
		[]string,
		int64,
	) (Analyzer, error) {
		return analyzerFunc(func(
			context.Context,
			trivyadapter.Request,
		) (trivyadapter.Report, error) {
			return trivyadapter.Report{}, nil
		}), nil
	})

	_, err := processor.Process(context.Background(), fixture.lease(false))
	if !errors.Is(err, progressErr) {
		t.Fatalf("Process() error = %v, want reporting progress error", err)
	}
	if len(fixture.repository.publications) != 0 {
		t.Fatalf(
			"publications after rejected reporting transition = %d",
			len(fixture.repository.publications),
		)
	}
}

func TestProcessorScansEveryOCIManifestDigestExplicitly(t *testing.T) {
	fixture := newProcessorFixture(t, ociTAR(t))
	var digests []string
	analyzer := analyzerFunc(func(
		_ context.Context,
		request trivyadapter.Request,
	) (trivyadapter.Report, error) {
		digests = append(digests, request.Source.ManifestDigest())
		raw := []byte(`{"SchemaVersion":2,"ArtifactName":"fixture",` +
			`"ArtifactType":"container_image","Results":[]}`)
		rawPath := filepath.Join(request.WorkDirectory, "trivy-result.json")
		if err := os.WriteFile(rawPath, raw, 0o600); err != nil {
			return trivyadapter.Report{}, err
		}
		hash := sha256.Sum256(raw)
		return trivyadapter.Report{
			Findings: []trivyadapter.Finding{},
			Raw: trivyadapter.RawReportMetadata{
				Path: rawPath, SHA256: hex.EncodeToString(hash[:]),
				SizeBytes: int64(len(raw)), SchemaVersion: 2,
				ArtifactName: "fixture", ArtifactType: "container_image",
				ResultCount: 0, FindingCount: 0,
			},
		}, nil
	})
	var adapterWorkBytes int64
	processor := fixture.processor(t, func(
		_ string,
		_ string,
		_ []string,
		maxWorkBytes int64,
	) (Analyzer, error) {
		adapterWorkBytes = maxWorkBytes
		return analyzer, nil
	})
	outcome, err := processor.Process(context.Background(), fixture.lease(false))
	if err != nil {
		t.Fatal(err)
	}
	if outcome.Outcome != queue.OutcomeSucceeded {
		t.Fatalf("outcome = %+v", outcome)
	}
	if len(digests) != 2 || digests[0] == "" || digests[1] == "" ||
		digests[0] == digests[1] {
		t.Fatalf("explicit OCI digests = %#v", digests)
	}
	expectedAdapterWork := int64(50<<20) +
		2*int64(4<<20) +
		trivyRuntimeReserveBytes
	if adapterWorkBytes != expectedAdapterWork ||
		fixture.guard.repositoryBytes != 2*int64(4<<20) {
		t.Fatalf(
			"quota = adapter:%d repository:%d, want %d/%d",
			adapterWorkBytes,
			fixture.guard.repositoryBytes,
			expectedAdapterWork,
			2*int64(4<<20),
		)
	}
	publication := fixture.repository.publications[0]
	if len(publication.Runs) != 2 {
		t.Fatalf("runs = %+v", publication.Runs)
	}
	handoff := HandoffSource{
		Format:           fixture.format,
		SourceStorageKey: "blobs/sha256/" + fixture.hash[:2] + "/" + fixture.hash,
		SourceSHA256:     fixture.hash,
		SourceSizeBytes:  fixture.size,
		ImageLogicalPath: "/",
	}
	for index, run := range publication.Runs {
		if run.ManifestDigest != digests[index] ||
			run.TargetKey != stableTargetKey(
				handoff,
				containerarchive.Target{ManifestDigest: digests[index]},
			) ||
			run.SourceSHA256 != fixture.hash ||
			run.Status != "succeeded" {
			t.Fatalf("run %d = %+v", index, run)
		}
	}
}

func TestProcessorRunsAtMostTenAutomaticOCITargets(t *testing.T) {
	fixture := newProcessorFixture(t, ociTARWithTargetCount(t, 11))
	analyzerCalls := 0
	analyzer := analyzerFunc(func(
		_ context.Context,
		request trivyadapter.Request,
	) (trivyadapter.Report, error) {
		analyzerCalls++
		raw := []byte(`{"SchemaVersion":2,"ArtifactName":"fixture",` +
			`"ArtifactType":"container_image","Results":[]}`)
		rawPath := filepath.Join(request.WorkDirectory, "trivy-result.json")
		if err := os.WriteFile(rawPath, raw, 0o600); err != nil {
			return trivyadapter.Report{}, err
		}
		hash := sha256.Sum256(raw)
		return trivyadapter.Report{Raw: trivyadapter.RawReportMetadata{
			Path: rawPath, SHA256: hex.EncodeToString(hash[:]),
			SizeBytes: int64(len(raw)), SchemaVersion: 2,
			ArtifactName: "fixture", ArtifactType: "container_image",
		}}, nil
	})
	processor := fixture.processor(t, func(
		_ string,
		_ string,
		_ []string,
		_ int64,
	) (Analyzer, error) {
		return analyzer, nil
	})
	outcome, err := processor.Process(
		context.Background(),
		fixture.lease(false),
	)
	if err != nil {
		t.Fatal(err)
	}
	if outcome.Outcome != queue.OutcomePartialSucceeded ||
		analyzerCalls != maxAutomaticImageTargets {
		t.Fatalf(
			"outcome=%+v analyzer calls=%d",
			outcome,
			analyzerCalls,
		)
	}
	runs := fixture.repository.publications[0].Runs
	if len(runs) != maxAutomaticImageTargets+1 ||
		runs[len(runs)-1].Status != "failed" ||
		runs[len(runs)-1].ErrorCode != "trivy_target_limit" {
		t.Fatalf("target-limited runs = %+v", runs)
	}
}

func TestProcessorRejectsMultiImageDockerSaveBeforeTrivy(t *testing.T) {
	fixture := newProcessorFixture(t, dockerTAR(t, 2))
	adapterCalls := 0
	processor := fixture.processor(t, func(
		_ string,
		_ string,
		_ []string,
		_ int64,
	) (Analyzer, error) {
		adapterCalls++
		return nil, errors.New("must not be called")
	})
	outcome, err := processor.Process(context.Background(), fixture.lease(false))
	if err != nil {
		t.Fatal(err)
	}
	if outcome.Outcome != queue.OutcomeDeterministicFailure ||
		outcome.ErrorCode != "docker_multi_image_unsupported" {
		t.Fatalf("outcome = %+v", outcome)
	}
	if adapterCalls != 0 || fixture.guard.calls != 0 ||
		len(fixture.repository.publications) != 0 {
		t.Fatal("rejected Docker archive reached a downstream side effect")
	}
	assertLastTrivyFailureActivity(
		t,
		fixture.progress.activities,
		"docker_multi_image_unsupported",
	)
}

func TestProcessorStorageLowIsTransientBeforeWorkspace(t *testing.T) {
	fixture := newProcessorFixture(t, dockerTAR(t, 1))
	fixture.guard.err = storageguard.ErrInsufficientStorage
	processor := fixture.processor(t, func(
		_ string,
		_ string,
		_ []string,
		_ int64,
	) (Analyzer, error) {
		return nil, errors.New("must not be called")
	})
	outcome, err := processor.Process(context.Background(), fixture.lease(false))
	if err != nil {
		t.Fatal(err)
	}
	if outcome.Outcome != queue.OutcomeTransientFailure ||
		outcome.ErrorCode != "trivy_storage_low" {
		t.Fatalf("outcome = %+v", outcome)
	}
	entries, err := os.ReadDir(fixture.workRoot)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 || len(fixture.repository.publications) != 0 {
		t.Fatalf("storage rejection left work: %+v", entries)
	}
	if fixture.guard.releases != 0 {
		t.Fatalf("rejected storage reservation releases = %d", fixture.guard.releases)
	}
	assertLastTrivyFailureActivity(
		t,
		fixture.progress.activities,
		"trivy_storage_low",
	)
}

func assertLastTrivyFailureActivity(
	t *testing.T,
	inputs []queue.ActivityInput,
	wantedCode string,
) {
	t.Helper()
	if len(inputs) == 0 {
		t.Fatal("failure did not emit a structured activity")
	}
	last := inputs[len(inputs)-1]
	var payload trivyActivityPayload
	if err := json.Unmarshal(last.Payload, &payload); err != nil ||
		last.EventType != "trivy.failed" ||
		payload.Phase != "failed" || payload.ErrorCode != wantedCode {
		t.Fatalf("failure activity = %#v payload=%+v err=%v", last, payload, err)
	}
}

func TestProcessorReleasesStorageReservationWhenDatabasePreparationFails(
	t *testing.T,
) {
	fixture := newProcessorFixture(t, dockerTAR(t, 1))
	processor := fixture.processor(t, func(
		_ string,
		_ string,
		_ []string,
		_ int64,
	) (Analyzer, error) {
		return nil, errors.New("adapter must not be created")
	})
	processor.databases = func(
		context.Context,
		string,
		trivydb.JavaDBPolicy,
	) (DatabaseView, error) {
		return nil, trivydb.ErrUnavailable
	}
	outcome, err := processor.Process(
		context.Background(),
		fixture.lease(false),
	)
	if err != nil {
		t.Fatal(err)
	}
	if outcome.Outcome != queue.OutcomeTransientFailure ||
		outcome.ErrorCode != "trivy_database_unavailable" ||
		fixture.guard.calls != 1 ||
		fixture.guard.releases != 1 {
		t.Fatalf(
			"outcome/reservation = %+v calls:%d releases:%d",
			outcome,
			fixture.guard.calls,
			fixture.guard.releases,
		)
	}
	entries, err := os.ReadDir(fixture.workRoot)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("database failure left workspaces: %+v", entries)
	}
}

func TestProcessorPropagatesUpstreamPartialAndPlatformFailure(t *testing.T) {
	fixture := newProcessorFixture(t, ociTAR(t))
	calls := 0
	analyzer := analyzerFunc(func(
		_ context.Context,
		request trivyadapter.Request,
	) (trivyadapter.Report, error) {
		calls++
		if calls == 2 {
			return trivyadapter.Report{}, fmt.Errorf(
				"%w: fixture",
				trivyadapter.ErrExecutionFailed,
			)
		}
		raw := []byte(`{"SchemaVersion":2,"ArtifactName":"fixture",` +
			`"ArtifactType":"container_image","Results":[]}`)
		rawPath := filepath.Join(request.WorkDirectory, "trivy-result.json")
		if err := os.WriteFile(rawPath, raw, 0o600); err != nil {
			return trivyadapter.Report{}, err
		}
		hash := sha256.Sum256(raw)
		return trivyadapter.Report{Raw: trivyadapter.RawReportMetadata{
			Path: rawPath, SHA256: hex.EncodeToString(hash[:]),
			SizeBytes: int64(len(raw)), SchemaVersion: 2,
			ArtifactName: "fixture", ArtifactType: "container_image",
		}}, nil
	})
	processor := fixture.processor(t, func(
		_ string,
		_ string,
		_ []string,
		_ int64,
	) (Analyzer, error) {
		return analyzer, nil
	})
	outcome, err := processor.Process(context.Background(), fixture.lease(true))
	if err != nil {
		t.Fatal(err)
	}
	if outcome.Outcome != queue.OutcomePartialSucceeded {
		t.Fatalf("outcome = %+v", outcome)
	}
	runs := fixture.repository.publications[0].Runs
	if len(runs) != 2 || runs[0].Status != "succeeded" ||
		runs[1].Status != "failed" ||
		runs[1].ErrorCode != "trivy_execution_failed" {
		t.Fatalf("runs = %+v", runs)
	}
}

func TestProcessorFindingLimitIsDeterministicAndPublishesFailedRun(t *testing.T) {
	fixture := newProcessorFixture(t, dockerTAR(t, 1))
	analyzer := analyzerFunc(func(
		_ context.Context,
		_ trivyadapter.Request,
	) (trivyadapter.Report, error) {
		return trivyadapter.Report{
			Findings: []trivyadapter.Finding{
				testFinding("CVE-2026-0001"),
				testFinding("CVE-2026-0002"),
			},
		}, nil
	})
	processor := fixture.processor(t, func(
		_ string,
		_ string,
		_ []string,
		_ int64,
	) (Analyzer, error) {
		return analyzer, nil
	})
	processor.config.MaxPublishedFindings = 1
	outcome, err := processor.Process(context.Background(), fixture.lease(false))
	if err != nil {
		t.Fatal(err)
	}
	if outcome.Outcome != queue.OutcomeDeterministicFailure ||
		outcome.ErrorCode != "trivy_scan_rejected" {
		t.Fatalf("outcome = %+v", outcome)
	}
	runs := fixture.repository.publications[0].Runs
	if len(runs) != 1 || runs[0].Status != "failed" ||
		runs[0].ErrorCode != "trivy_finding_limit" ||
		runs[0].Raw != nil || len(runs[0].Findings) != 0 {
		t.Fatalf("runs = %+v", runs)
	}
}

func TestProcessorUsesPersistedCompletedRunOnFencedReplay(t *testing.T) {
	fixture := newProcessorFixture(t, dockerTAR(t, 1))
	repository := &summaryRepositoryStub{
		summary: PublishSummary{Succeeded: 1},
	}
	fixture.repository = &repository.repositoryStub
	processor := fixture.processor(t, func(
		_ string,
		_ string,
		_ []string,
		_ int64,
	) (Analyzer, error) {
		return analyzerFunc(func(
			_ context.Context,
			_ trivyadapter.Request,
		) (trivyadapter.Report, error) {
			return trivyadapter.Report{}, fmt.Errorf(
				"%w: retry fixture",
				trivyadapter.ErrExecutionFailed,
			)
		}), nil
	})
	// NewProcessor received the embedded Repository interface. Replace it with
	// the summary-capable concrete repository to exercise effective replay.
	processor.repository = repository
	outcome, err := processor.Process(context.Background(), fixture.lease(false))
	if err != nil {
		t.Fatal(err)
	}
	if outcome.Outcome != queue.OutcomeSucceeded {
		t.Fatalf("outcome = %+v", outcome)
	}
}

func TestProcessorCancellationDoesNotPublish(t *testing.T) {
	fixture := newProcessorFixture(t, dockerTAR(t, 1))
	processor := fixture.processor(t, func(
		_ string,
		_ string,
		_ []string,
		_ int64,
	) (Analyzer, error) {
		return analyzerFunc(func(
			ctx context.Context,
			_ trivyadapter.Request,
		) (trivyadapter.Report, error) {
			<-ctx.Done()
			return trivyadapter.Report{}, ctx.Err()
		}), nil
	})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := processor.Process(ctx, fixture.lease(false)); !errors.Is(err, context.Canceled) {
		t.Fatalf("Process() error = %v", err)
	}
	if len(fixture.repository.publications) != 0 {
		t.Fatal("cancelled processor published a result")
	}
}

func TestDecodePayloadRejectsMissingUnknownAndNonCanonicalFields(t *testing.T) {
	valid := `{"schema_version":1,"format":"docker-tar",` +
		`"source_storage_key":"blobs/sha256/aa/` + strings.Repeat("a", 64) + `",` +
		`"source_sha256":"` + strings.Repeat("a", 64) + `",` +
		`"source_size_bytes":512,"image_logical_path":"/",` +
		`"upstream_partial":false}`
	if _, err := DecodePayload([]byte(valid), 1024); err != nil {
		t.Fatal(err)
	}
	for _, raw := range []string{
		strings.Replace(valid, `,"upstream_partial":false`, "", 1),
		strings.Replace(valid, `}`, `,"extra":true}`, 1),
		strings.Replace(valid, `"image_logical_path":"/"`, `"image_logical_path":"../x"`, 1),
		strings.Replace(valid, `"source_size_bytes":512`, `"source_size_bytes":2048`, 1),
	} {
		if _, err := DecodePayload([]byte(raw), 1024); !errors.Is(err, ErrInvalidPayload) {
			t.Fatalf("DecodePayload(%s) error = %v", raw, err)
		}
	}
}

func TestDatabaseUnavailableAndTimeoutAreTransient(t *testing.T) {
	if value := finishForDatabaseError(trivydb.ErrUnavailable); value.Outcome != queue.OutcomeTransientFailure {
		t.Fatalf("database outcome = %+v", value)
	}
	failure := classifyAnalyzerFailure(context.DeadlineExceeded)
	if failure.deterministic || failure.status != "timed_out" {
		t.Fatalf("timeout classification = %+v", failure)
	}
}

func TestProcessorConfigAcceptsGlobalMillionFindingLimit(t *testing.T) {
	root := t.TempDir()
	repositoryRoot := filepath.Join(root, "repository")
	workRoot := filepath.Join(root, "work")
	if err := os.Mkdir(repositoryRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(workRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	config := Config{
		RepositoryRoot:       repositoryRoot,
		TaskWorkRoot:         workRoot,
		AnalyzerVersion:      "0.72.0",
		JavaDBPolicy:         trivydb.JavaDBRequired,
		MaxSourceBytes:       maxSupportedSourceBytes,
		MaxExpandedBytes:     maxSupportedExpandedBytes,
		MaxReportBytes:       maxSupportedReportBytes,
		MaxPublishedFindings: 1_000_000,
		StorageMinFreeBytes:  1,
		StorageGuard:         &storageGuardStub{},
	}
	newProcessor := func(config Config) error {
		_, err := NewProcessor(
			&repositoryStub{},
			&progressStub{},
			func(
				context.Context,
				string,
				trivydb.JavaDBPolicy,
			) (DatabaseView, error) {
				return nil, errors.New("unused")
			},
			func(string, string, []string, int64) (Analyzer, error) {
				return nil, errors.New("unused")
			},
			config,
		)
		return err
	}
	if err := newProcessor(config); err != nil {
		t.Fatalf("one-million finding limit rejected: %v", err)
	}
	config.MaxPublishedFindings++
	if err := newProcessor(config); !errors.Is(err, ErrInvalidConfiguration) {
		t.Fatalf("over-limit configuration error = %v", err)
	}
}

func testFinding(id string) trivyadapter.Finding {
	return trivyadapter.Finding{
		VulnerabilityID:  id,
		Severity:         "HIGH",
		PackageName:      "libfixture",
		InstalledVersion: "1.0.0",
		Target:           "fixture",
		Class:            "os-pkgs",
		Type:             "alpine",
	}
}

type processorFixture struct {
	root           string
	repositoryRoot string
	workRoot       string
	hash           string
	size           int64
	format         string
	repository     *repositoryStub
	progress       *progressStub
	guard          *storageGuardStub
}

func newProcessorFixture(t *testing.T, archive []byte) *processorFixture {
	t.Helper()
	root := t.TempDir()
	repositoryRoot := filepath.Join(root, "repository")
	workRoot := filepath.Join(root, "task-work")
	if err := os.Mkdir(repositoryRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(workRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(archive)
	hash := hex.EncodeToString(digest[:])
	storagePath := filepath.Join(
		repositoryRoot,
		"blobs",
		"sha256",
		hash[:2],
		hash,
	)
	if err := os.MkdirAll(filepath.Dir(storagePath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(storagePath, archive, 0o600); err != nil {
		t.Fatal(err)
	}
	format := containerarchive.FormatDocker
	if strings.Contains(string(archive), `"imageLayoutVersion"`) {
		format = containerarchive.FormatOCI
	}
	return &processorFixture{
		root: root, repositoryRoot: repositoryRoot, workRoot: workRoot,
		hash: hash, size: int64(len(archive)), format: format,
		repository: &repositoryStub{}, guard: &storageGuardStub{},
		progress: &progressStub{},
	}
}

func (f *processorFixture) processor(
	t *testing.T,
	factory AdapterFactory,
) *Processor {
	t.Helper()
	provider := func(
		_ context.Context,
		workspaceRoot string,
		_ trivydb.JavaDBPolicy,
	) (DatabaseView, error) {
		cache := filepath.Join(workspaceRoot, "test-cache")
		if err := os.Mkdir(cache, 0o700); err != nil {
			return nil, err
		}
		return &databaseViewStub{
			path: cache, snapshot: testSnapshot(),
		}, nil
	}
	processor, err := NewProcessor(
		f.repository,
		f.progress,
		provider,
		factory,
		Config{
			RepositoryRoot:       f.repositoryRoot,
			TaskWorkRoot:         f.workRoot,
			AnalyzerVersion:      "0.72.0",
			JavaDBPolicy:         trivydb.JavaDBOptional,
			MaxSourceBytes:       10 << 20,
			MaxExpandedBytes:     50 << 20,
			MaxReportBytes:       4 << 20,
			MaxPublishedFindings: 1_000,
			StorageMinFreeBytes:  1,
			StorageGuard:         f.guard,
			Now: func() time.Time {
				return time.Date(2026, 7, 31, 12, 0, 0, 0, time.UTC)
			},
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	return processor
}

func (f *processorFixture) lease(upstreamPartial bool) queue.Lease {
	attemptID := uint64(71)
	payload, _ := json.Marshal(HandoffPayload{
		SchemaVersion:    PayloadSchemaVersion,
		Format:           f.format,
		SourceStorageKey: "blobs/sha256/" + f.hash[:2] + "/" + f.hash,
		SourceSHA256:     f.hash,
		SourceSizeBytes:  f.size,
		ImageLogicalPath: "/",
		UpstreamPartial:  upstreamPartial,
	})
	return queue.Lease{
		JobID:         "123e4567-e89b-42d3-a456-000000000001",
		TaskID:        "123e4567-e89b-42d3-a456-000000000002",
		TaskAttemptID: &attemptID,
		Kind:          queue.KindTrivy,
		Payload:       payload,
		Attempt:       1,
		MaxAttempts:   3,
		FencingToken:  99,
		Owner:         "trivy-test",
		LeaseUntil:    time.Now().Add(time.Minute),
	}
}

func testSnapshot() trivydb.Snapshot {
	fileHash := strings.Repeat("a", 64)
	java := trivydb.Version{
		ID:                    "123e4567-e89b-42d3-a456-000000000004",
		DatabaseType:          trivydb.DatabaseTrivyJava,
		DatabaseSchemaVersion: 1,
		Version:               "2026.07.31",
		StorageKey:            "trivy/java-db/versions/123e4567-e89b-42d3-a456-000000000004",
		Files: []trivydb.File{{
			Path: "trivy-java.db", SHA256: fileHash, SizeBytes: 1,
		}},
	}
	return trivydb.Snapshot{
		Bundle: trivydb.Bundle{
			ID:            "123e4567-e89b-42d3-a456-000000000005",
			Version:       "2026.07.31",
			GeneratedAt:   time.Date(2026, 7, 31, 0, 0, 0, 0, time.UTC),
			ContentSHA256: strings.Repeat("b", 64),
			ManifestJSON:  []byte(`{"schema_version":1}`),
		},
		Trivy: trivydb.Version{
			ID:                    "123e4567-e89b-42d3-a456-000000000003",
			DatabaseType:          trivydb.DatabaseTrivy,
			DatabaseSchemaVersion: 2,
			Version:               "2026.07.31",
			StorageKey:            "trivy/db/versions/123e4567-e89b-42d3-a456-000000000003",
			Files: []trivydb.File{{
				Path: "trivy.db", SHA256: fileHash, SizeBytes: 1,
			}},
		},
		Java: &java,
	}
}

const successfulReportJSON = `{
  "SchemaVersion": 2,
  "CreatedAt": "2026-07-31T00:00:00Z",
  "ArtifactName": "fixture",
  "ArtifactType": "container_image",
  "Results": [{
    "Target": "fixture (alpine 3.20)",
    "Class": "os-pkgs",
    "Type": "alpine",
    "Vulnerabilities": [{
      "VulnerabilityID": "CVE-2026-0001",
      "PkgName": "libfixture",
      "InstalledVersion": "1.0.0",
      "FixedVersion": "1.0.1",
      "Severity": "HIGH"
    }]
  }]
}`

func writeFakeTrivy(t *testing.T, root, report string) string {
	t.Helper()
	value := filepath.Join(root, "fake-trivy.sh")
	quoted := strings.ReplaceAll(report, "'", "'\"'\"'")
	body := "#!/bin/sh\nset -eu\noutput=\n" +
		"while [ \"$#\" -gt 0 ]; do\n" +
		"  if [ \"$1\" = \"--output\" ]; then shift; output=$1; fi\n" +
		"  shift\n" +
		"done\n" +
		"printf '%s' '" + quoted + "' > \"$output\"\n"
	if err := os.WriteFile(value, []byte(body), 0o700); err != nil {
		t.Fatal(err)
	}
	return value
}

func dockerTAR(t *testing.T, images int) []byte {
	t.Helper()
	files := make(map[string][]byte)
	manifest := make([]map[string]any, 0, images)
	for index := range images {
		configName := fmt.Sprintf("config-%d.json", index)
		layerName := fmt.Sprintf("layer-%d.tar", index)
		files[configName] = []byte(`{"architecture":"amd64","os":"linux"}`)
		files[layerName] = []byte("fixture layer")
		manifest = append(manifest, map[string]any{
			"Config":   configName,
			"RepoTags": []string{fmt.Sprintf("fixture-%d:latest", index)},
			"Layers":   []string{layerName},
		})
	}
	files["manifest.json"], _ = json.Marshal(manifest)
	return tarBytes(t, files)
}

func ociTAR(t *testing.T) []byte {
	return ociTARWithTargetCount(t, 2)
}

func ociTARWithTargetCount(t *testing.T, count int) []byte {
	t.Helper()
	files := map[string][]byte{
		"oci-layout": []byte(`{"imageLayoutVersion":"1.0.0"}`),
	}
	descriptors := make([]map[string]any, 0, count)
	for index := range count {
		architecture := fmt.Sprintf("arch%d", index)
		if index == 0 {
			architecture = "amd64"
		} else if index == 1 {
			architecture = "arm64"
		}
		config := []byte(fmt.Sprintf(
			`{"architecture":%q,"os":"linux"}`,
			architecture,
		))
		configDigest := addOCIBlob(files, config)
		layer := []byte("layer-" + architecture)
		layerDigest := addOCIBlob(files, layer)
		manifest, _ := json.Marshal(map[string]any{
			"schemaVersion": 2,
			"mediaType":     "application/vnd.oci.image.manifest.v1+json",
			"config": map[string]any{
				"mediaType": "application/vnd.oci.image.config.v1+json",
				"digest":    configDigest, "size": len(config),
			},
			"layers": []map[string]any{{
				"mediaType": "application/vnd.oci.image.layer.v1.tar",
				"digest":    layerDigest, "size": len(layer),
			}},
		})
		manifestDigest := addOCIBlob(files, manifest)
		descriptors = append(descriptors, map[string]any{
			"mediaType": "application/vnd.oci.image.manifest.v1+json",
			"digest":    manifestDigest,
			"size":      len(manifest),
			"platform": map[string]any{
				"os": "linux", "architecture": architecture,
			},
			"annotations": map[string]any{
				"org.opencontainers.image.ref.name": fmt.Sprintf("fixture-%d", index),
			},
		})
	}
	files["index.json"], _ = json.Marshal(map[string]any{
		"schemaVersion": 2,
		"mediaType":     "application/vnd.oci.image.index.v1+json",
		"manifests":     descriptors,
	})
	return tarBytes(t, files)
}

func addOCIBlob(files map[string][]byte, value []byte) string {
	hash := sha256.Sum256(value)
	encoded := hex.EncodeToString(hash[:])
	files["blobs/sha256/"+encoded] = value
	return "sha256:" + encoded
}

func tarBytes(t *testing.T, files map[string][]byte) []byte {
	t.Helper()
	path := filepath.Join(t.TempDir(), "fixture.tar")
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	writer := tar.NewWriter(file)
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		content := files[name]
		if err := writer.WriteHeader(&tar.Header{
			Name: name, Mode: 0o600, Size: int64(len(content)),
			Typeflag: tar.TypeReg,
		}); err != nil {
			t.Fatal(err)
		}
		if _, err := writer.Write(content); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	value, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return value
}

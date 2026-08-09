package main

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"binaryscan/internal/config"
	"binaryscan/internal/queue"
	"binaryscan/internal/workerreadiness"
	"binaryscan/internal/workerrunner"

	"github.com/DATA-DOG/go-sqlmock"
)

func TestWorkerRejectsUnknownKindBeforeLoadingConfiguration(t *testing.T) {
	for _, test := range []struct {
		args    []string
		message string
	}{
		{args: []string{"--kind=unknown"}, message: "--kind must be one of"},
		{
			args:    []string{"healthcheck", "--role", "unknown"},
			message: "--role must be one of",
		},
	} {
		if err := run(test.args); err == nil || !strings.Contains(err.Error(), test.message) {
			t.Fatalf("run(%v) error = %v, want %q", test.args, err, test.message)
		}
	}
}

func TestWorkerAcceptsComposeCommandForms(t *testing.T) {
	tests := []struct {
		args        []string
		wantCommand string
		wantKind    string
	}{
		{args: []string{"scan"}, wantCommand: "run", wantKind: "scan"},
		{args: []string{"--kind=trivy"}, wantCommand: "run", wantKind: "trivy"},
		{args: []string{"healthcheck", "--role", "image"}, wantCommand: "healthcheck", wantKind: "image"},
	}
	for _, tt := range tests {
		command, kind, err := parseCommand(tt.args)
		if err != nil {
			t.Fatalf("parseCommand(%v) error = %v", tt.args, err)
		}
		if command != tt.wantCommand || kind != tt.wantKind {
			t.Fatalf("parseCommand(%v) = %q, %q", tt.args, command, kind)
		}
	}
}

func TestAssembleWorkerRunnerBuildsScanRuntime(t *testing.T) {
	cfg := testWorkerConfig()
	logger := testWorkerLogger()
	runner, err := assembleWorkerRunner(
		"scan",
		cfg,
		&sql.DB{},
		logger,
		"scan/test-host/42/00112233445566778899aabbccddeeff",
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := runner.(*workerrunner.Runner); !ok {
		t.Fatalf("scan runner type = %T, want *workerrunner.Runner", runner)
	}

	queueConfig := workerQueueConfig(cfg)
	if queueConfig.LeaseDuration != cfg.QueueLeaseInterval ||
		queueConfig.RetryDelay != cfg.QueuePollInterval ||
		queueConfig.SampleRetention != cfg.SampleRetention ||
		queueConfig.HeavySlotLimit != cfg.QueueHeavySlots ||
		queueConfig.TrivySlotLimit != cfg.QueueTrivySlots ||
		queueConfig.NativeSlotLimit != cfg.QueueNativeSlots {
		t.Fatalf("queue config = %+v", queueConfig)
	}
	runnerConfig := workerRunnerConfig(cfg, queue.KindScan, "scan-owner")
	if runnerConfig.Kind != queue.KindScan ||
		runnerConfig.Owner != "scan-owner" ||
		runnerConfig.PollInterval != cfg.QueuePollInterval ||
		runnerConfig.HeartbeatInterval != cfg.HeartbeatInterval {
		t.Fatalf("runner config = %+v", runnerConfig)
	}
}

func TestAssembleWorkerRunnerBuildsTrivyRuntime(t *testing.T) {
	cfg := testWorkerConfig()
	cfg.RepositoryRoot = t.TempDir()
	cfg.TaskWorkRoot = t.TempDir()
	cfg.TrivyDBRoot = t.TempDir()
	cfg.TrivyExecutable = filepath.Join(t.TempDir(), "trivy")
	cfg.TrivyVersion = "0.72.0"
	cfg.TrivyMaxDuration = 30 * time.Minute
	cfg.TrivyTerminationGrace = 10 * time.Second
	cfg.TrivyMaxStandardOutputBytes = 1024
	cfg.TrivyMaxStandardErrorBytes = 1024
	cfg.TrivyMaxReportBytes = 1024
	cfg.TrivyMaxResults = 100
	cfg.TrivyMaxFindings = 100
	cfg.MaxUploadBytes = 10 * 1024 * 1024
	cfg.MaxExpandedBytes = 100 * 1024 * 1024
	cfg.MaxArchiveRatio = 100
	cfg.MaxFileNodes = 100
	cfg.MaxDepth = 10
	cfg.StorageMinFreeBytes = 1

	runner, err := assembleWorkerRunner(
		"trivy",
		cfg,
		&sql.DB{},
		testWorkerLogger(),
		"trivy/test-host/42/00112233445566778899aabbccddeeff",
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := runner.(*workerrunner.Runner); !ok {
		t.Fatalf("trivy runner type = %T, want *workerrunner.Runner", runner)
	}

	runnerConfig := workerRunnerConfig(cfg, queue.KindTrivy, "trivy-owner")
	if runnerConfig.Kind != queue.KindTrivy ||
		runnerConfig.Owner != "trivy-owner" {
		t.Fatalf("Trivy runner config = %+v", runnerConfig)
	}
}

func TestAssembleWorkerRunnerBuildsManualImageRuntime(t *testing.T) {
	cfg := testWorkerConfig()
	cfg.RepositoryRoot = t.TempDir()
	cfg.TaskWorkRoot = t.TempDir()
	cfg.TrivyDBRoot = t.TempDir()
	cfg.TrivyExecutable = filepath.Join(t.TempDir(), "trivy")
	cfg.TrivyVersion = "0.72.0"
	cfg.TrivyMaxDuration = 30 * time.Minute
	cfg.TrivyTerminationGrace = 10 * time.Second
	cfg.TrivyMaxStandardOutputBytes = 1024
	cfg.TrivyMaxStandardErrorBytes = 1024
	cfg.TrivyMaxReportBytes = 1024
	cfg.TrivyMaxResults = 100
	cfg.TrivyMaxFindings = 100
	cfg.MaxUploadBytes = 10 * 1024 * 1024
	cfg.MaxExpandedBytes = 100 * 1024 * 1024
	cfg.MaxArchiveRatio = 100
	cfg.MaxFileNodes = 100
	cfg.MaxDepth = 10
	cfg.StorageMinFreeBytes = 1
	runner, err := assembleWorkerRunner(
		"image",
		cfg,
		&sql.DB{},
		testWorkerLogger(),
		"image/test-host/42/00112233445566778899aabbccddeeff",
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := runner.(*workerrunner.Runner); !ok {
		t.Fatalf("image runner type = %T, want *workerrunner.Runner", runner)
	}
}

func TestQueueWorkerKinds(t *testing.T) {
	for _, test := range []struct {
		kind string
		want bool
	}{
		{kind: "scan", want: true},
		{kind: "trivy", want: true},
		{kind: "image", want: true},
		{kind: "native", want: true},
		{kind: "bytecode", want: true},
	} {
		if got := isQueueWorker(test.kind); got != test.want {
			t.Fatalf("isQueueWorker(%q) = %t, want %t", test.kind, got, test.want)
		}
	}
}

func TestAssembleWorkerRunnerBuildsBytecodeRuntime(t *testing.T) {
	cfg := testWorkerConfig()
	cfg.RepositoryRoot = t.TempDir()
	cfg.TaskWorkRoot = t.TempDir()
	cfg.MaxFileNodes = 100
	cfg.MaxExpandedBytes = 100 * 1024 * 1024
	cfg.MaxArchiveRatio = 100
	runner, err := assembleWorkerRunner(
		"bytecode", cfg, &sql.DB{}, testWorkerLogger(),
		"bytecode/test-host/42/00112233445566778899aabbccddeeff",
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := runner.(*workerrunner.Runner); !ok {
		t.Fatalf("bytecode runner type = %T, want *workerrunner.Runner", runner)
	}
}

func TestAssembleWorkerRunnerForwardsBytecodeArchiveDepth(t *testing.T) {
	cfg := testWorkerConfig()
	cfg.RepositoryRoot = t.TempDir()
	cfg.TaskWorkRoot = t.TempDir()
	cfg.MaxFileNodes = 100
	cfg.MaxExpandedBytes = 100 * 1024 * 1024
	cfg.MaxArchiveRatio = 100
	cfg.MaxDepth = 11
	_, err := assembleWorkerRunner(
		"bytecode", cfg, &sql.DB{}, testWorkerLogger(),
		"bytecode/test-host/42/00112233445566778899aabbccddeeff",
	)
	if err == nil || !strings.Contains(err.Error(), "initialize JVM bytecode fallback") {
		t.Fatalf("assembleWorkerRunner() depth error = %v", err)
	}
}

func TestAssembleWorkerRunnerBuildsNativeRuntime(t *testing.T) {
	cfg := testWorkerConfig()
	cfg.RepositoryRoot = t.TempDir()
	cfg.TaskWorkRoot = t.TempDir()
	cfg.GhidraExecutable = filepath.Join(t.TempDir(), "analyzeHeadless")
	cfg.GhidraScriptDirectory = t.TempDir()
	cfg.GhidraVersion = "12.1.2"
	cfg.GhidraMaxDuration = time.Minute
	cfg.GhidraTerminationGrace = time.Second
	cfg.GhidraMaxStandardOutputBytes = 1024
	cfg.GhidraMaxStandardErrorBytes = 1024
	cfg.GhidraMaxIndexBytes = 4096
	cfg.GhidraMaxOutputBytes = 4096
	cfg.GhidraMaxFunctions = 10
	runner, err := assembleWorkerRunner(
		"native", cfg, &sql.DB{}, testWorkerLogger(),
		"native/test-host/42/00112233445566778899aabbccddeeff",
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := runner.(*workerrunner.Runner); !ok {
		t.Fatalf("native runner type = %T, want *workerrunner.Runner", runner)
	}
}

func TestAssembleWorkerRunnerValidatesScanAssembly(t *testing.T) {
	cfg := testWorkerConfig()
	cfg.RepositoryRoot = "/"
	_, err := assembleWorkerRunner(
		"scan",
		cfg,
		&sql.DB{},
		testWorkerLogger(),
		"scan/test-host/42/00112233445566778899aabbccddeeff",
	)
	if err == nil || !strings.Contains(err.Error(), "initialize scan processor") {
		t.Fatalf("assembleWorkerRunner() error = %v", err)
	}
}

func TestCheckWorkerHealthUsesDatabaseOnlyForLightweightWorker(t *testing.T) {
	db, mock, err := sqlmock.New(sqlmock.MonitorPingsOption(true))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	mock.ExpectPing()

	cfg := testWorkerConfig()
	if err := checkWorkerHealth(context.Background(), "bytecode", cfg, db); err != nil {
		t.Fatal(err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestNativeAnalyzerReadinessRequiresExactGhidraAndJavaVersions(t *testing.T) {
	db, mock, err := sqlmock.New(sqlmock.MonitorPingsOption(true))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	mock.ExpectPing()
	root := t.TempDir()
	ghidraRoot := filepath.Join(root, "ghidra")
	scriptDirectory := filepath.Join(root, "scripts")
	javaRoot := filepath.Join(root, "jdk")
	for _, directory := range []string{
		filepath.Join(ghidraRoot, "support"),
		filepath.Join(ghidraRoot, "Ghidra"),
		scriptDirectory,
		filepath.Join(javaRoot, "bin"),
	} {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	ghidraExecutable := filepath.Join(ghidraRoot, "support", "analyzeHeadless")
	if err := os.WriteFile(ghidraExecutable, []byte("#!/bin/sh\nexit 99\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(
		filepath.Join(ghidraRoot, "Ghidra", "application.properties"),
		[]byte("application.name=Ghidra\napplication.version=12.1.2\n"),
		0o600,
	); err != nil {
		t.Fatal(err)
	}
	javaExecutable := filepath.Join(javaRoot, "bin", "java")
	elf := make([]byte, 20)
	copy(elf, []byte{0x7f, 'E', 'L', 'F', 2, 1, 1})
	elf[18] = 62
	if err := os.WriteFile(javaExecutable, elf, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(
		filepath.Join(javaRoot, "release"),
		[]byte("JAVA_VERSION=\"21.0.7\"\nJAVA_VERSION_DATE=\"2025-04-15\"\nOS_NAME=\"Linux\"\nOS_ARCH=\"x86_64\"\n"),
		0o600,
	); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(
		filepath.Join(scriptDirectory, "ExportDecompiledFunctions.java"),
		[]byte("// Ghidra export script\n"), 0o600,
	); err != nil {
		t.Fatal(err)
	}
	cfg := testWorkerConfig()
	cfg.GhidraExecutable = ghidraExecutable
	cfg.GhidraScriptDirectory = scriptDirectory
	cfg.GhidraVersion = "12.1.2"
	cfg.GhidraJavaVersionLine = `openjdk version "21.0.7" 2025-04-15 LTS`
	cfg.GhidraJavaExecutable = javaExecutable
	cfg.GhidraTerminationGrace = 20 * time.Millisecond
	if err := checkAnalyzerRuntimeReady(
		context.Background(), "native", cfg, db,
	); err != nil {
		t.Fatal(err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestAnalyzerReadinessRegistrationUsesVerifiedRuntimeIdentity(t *testing.T) {
	cfg := testWorkerConfig()
	cfg.GhidraVersion = "12.1.2"
	cfg.GhidraJavaVersionLine = `openjdk version "21.0.4"`
	cfg.TrivyVersion = "0.72.0"

	native, ok := analyzerReadinessRegistration("native", "native:owner", cfg)
	if !ok || native.AnalyzerName != "ghidra" ||
		native.AnalyzerVersion != cfg.GhidraVersion ||
		native.RuntimeName != "jdk" ||
		native.RuntimeVersion != cfg.GhidraJavaVersionLine {
		t.Fatalf("native readiness = (%#v, %v)", native, ok)
	}
	for _, kind := range []string{"image", "trivy"} {
		registration, available := analyzerReadinessRegistration(
			kind, kind+":owner", cfg,
		)
		if !available || registration.AnalyzerName != "trivy" ||
			registration.AnalyzerVersion != cfg.TrivyVersion ||
			registration.WorkerKind != kind {
			t.Fatalf("%s readiness = (%#v, %v)", kind, registration, available)
		}
	}
	if _, ok := analyzerReadinessRegistration("scan", "scan:owner", cfg); ok {
		t.Fatal("scan worker unexpectedly registered an analyzer runtime")
	}
}

func TestAnalyzerReadinessRejectsMismatchedTrivyBeforeDatabaseResolution(
	t *testing.T,
) {
	db, mock, err := sqlmock.New(sqlmock.MonitorPingsOption(true))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	mock.ExpectPing()

	cfg := testWorkerConfig()
	cfg.TrivyExecutable = writeFakeTrivy(t, "0.71.0")
	cfg.TrivyVersion = "0.72.0"
	cfg.TrivyDBRoot = t.TempDir()
	cfg.TrivyTerminationGrace = 20 * time.Millisecond

	err = checkAnalyzerRuntimeReady(context.Background(), "trivy", cfg, db)
	if err == nil || !strings.Contains(err.Error(), "does not match locked version") {
		t.Fatalf("checkWorkerHealth() error = %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestWorkerLivenessDoesNotRequireAnalyzerAssetsOrDatabases(t *testing.T) {
	db, mock, err := sqlmock.New(sqlmock.MonitorPingsOption(true))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	mock.ExpectPing()

	cfg := testWorkerConfig()
	err = checkWorkerHealth(context.Background(), "trivy", cfg, db)
	if err != nil {
		t.Fatalf("checkWorkerHealth() error = %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestAnalyzerWorkerWaitsWithoutClaimingUntilRuntimeBecomesReady(t *testing.T) {
	cfg := testWorkerConfig()
	cfg.HeartbeatInterval = 5 * time.Millisecond
	firstProbe := make(chan struct{}, 1)
	var ready atomic.Bool
	probe := func(
		context.Context, string, config.Config, *sql.DB,
	) error {
		select {
		case firstProbe <- struct{}{}:
		default:
		}
		if ready.Load() {
			return nil
		}
		return errors.New("runtime fixture is not ready")
	}
	result := make(chan bool, 1)
	go func() {
		result <- awaitAnalyzerRuntimeReadyWithProbe(
			context.Background(), "native", cfg, nil,
			testWorkerLogger(), probe,
		)
	}()
	select {
	case <-firstProbe:
	case <-time.After(time.Second):
		t.Fatal("analyzer readiness probe did not run")
	}
	select {
	case <-result:
		t.Fatal("analyzer worker advanced to queue assembly while unavailable")
	case <-time.After(25 * time.Millisecond):
	}
	ready.Store(true)
	select {
	case available := <-result:
		if !available {
			t.Fatal("analyzer readiness wait stopped instead of becoming ready")
		}
	case <-time.After(time.Second):
		t.Fatal("analyzer worker did not advance after runtime became ready")
	}
}

type readinessOrderRepository struct {
	mu          sync.Mutex
	registered  bool
	removed     bool
	registerErr error
	heartbeat   chan struct{}
}

func (r *readinessOrderRepository) Register(
	context.Context,
	workerreadiness.Registration,
) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.registerErr != nil {
		return r.registerErr
	}
	r.registered = true
	return nil
}

func (r *readinessOrderRepository) Heartbeat(context.Context, string) error {
	select {
	case r.heartbeat <- struct{}{}:
	default:
	}
	return nil
}

func (r *readinessOrderRepository) Remove(context.Context, string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.removed = true
	return nil
}

func (r *readinessOrderRepository) Prune(context.Context, time.Time) error {
	return nil
}

type claimOrderLoop struct {
	repository *readinessOrderRepository
	started    atomic.Bool
}

func (loop *claimOrderLoop) Run(ctx context.Context) error {
	loop.repository.mu.Lock()
	registered := loop.repository.registered
	loop.repository.mu.Unlock()
	if !registered {
		return errors.New("queue claim loop started before readiness registration")
	}
	loop.started.Store(true)
	select {
	case <-loop.repository.heartbeat:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func TestAnalyzerClaimLoopStartsOnlyAfterRegistrationAndHeartbeats(t *testing.T) {
	repository := &readinessOrderRepository{heartbeat: make(chan struct{}, 1)}
	reporter, err := workerreadiness.NewReporter(
		repository,
		workerreadiness.Registration{
			Owner: "native/test/fixture", WorkerKind: "native",
			AnalyzerName: "ghidra", AnalyzerVersion: "12.1.2",
			RuntimeName: "jdk", RuntimeVersion: `openjdk version "21.0.4"`,
		},
		10*time.Millisecond,
		5*time.Millisecond,
		testWorkerLogger(),
	)
	if err != nil {
		t.Fatal(err)
	}
	claimLoop := &claimOrderLoop{repository: repository}
	loop := &readinessWorkerLoop{
		workerLoop: claimLoop,
		reporter:   reporter,
		logger:     testWorkerLogger(),
	}
	if err := loop.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	repository.mu.Lock()
	removed := repository.removed
	repository.mu.Unlock()
	if !claimLoop.started.Load() || !removed {
		t.Fatalf("claim started = %t, readiness removed = %t", claimLoop.started.Load(), removed)
	}
}

func TestAnalyzerClaimLoopDoesNotStartWhenRegistrationFails(t *testing.T) {
	repository := &readinessOrderRepository{
		heartbeat:   make(chan struct{}, 1),
		registerErr: errors.New("readiness schema unavailable"),
	}
	reporter, err := workerreadiness.NewReporter(
		repository,
		workerreadiness.Registration{
			Owner: "trivy/test/fixture", WorkerKind: "trivy",
			AnalyzerName: "trivy", AnalyzerVersion: "0.72.0",
		},
		10*time.Millisecond,
		5*time.Millisecond,
		testWorkerLogger(),
	)
	if err != nil {
		t.Fatal(err)
	}
	claimLoop := &claimOrderLoop{repository: repository}
	loop := &readinessWorkerLoop{
		workerLoop: claimLoop,
		reporter:   reporter,
		logger:     testWorkerLogger(),
	}
	if err := loop.Run(context.Background()); err == nil ||
		!strings.Contains(err.Error(), "register analyzer readiness") {
		t.Fatalf("readiness registration error = %v", err)
	}
	if claimLoop.started.Load() {
		t.Fatal("queue claim loop started after readiness registration failed")
	}
}

func TestTrivyAnalyzerReadinessRequiresFixedDatabaseBundle(t *testing.T) {
	db, mock, err := sqlmock.New(sqlmock.MonitorPingsOption(true))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	mock.ExpectPing()

	cfg := testWorkerConfig()
	cfg.TrivyExecutable = writeFakeTrivy(t, "0.72.0")
	cfg.TrivyVersion = "0.72.0"
	cfg.TrivyDBRoot = t.TempDir()
	cfg.TrivyTerminationGrace = 20 * time.Millisecond

	err = checkAnalyzerRuntimeReady(context.Background(), "trivy", cfg, db)
	if err == nil || !strings.Contains(err.Error(), "database bundle") {
		t.Fatalf("checkAnalyzerRuntimeReady() error = %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestCheckTrivyExecutableAcceptsLockedLocalVersion(t *testing.T) {
	cfg := testWorkerConfig()
	cfg.TrivyExecutable = writeFakeTrivy(t, "0.72.0")
	cfg.TrivyVersion = "0.72.0"
	cfg.TrivyTerminationGrace = 20 * time.Millisecond

	if err := checkTrivyExecutable(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
}

func TestCheckTrivyExecutableBoundsIndependentDatabaseTimeout(t *testing.T) {
	cfg := testWorkerConfig()
	cfg.DatabasePingTimeout = 2 * time.Minute
	cfg.TrivyExecutable = writeFakeTrivy(t, "0.72.0")
	cfg.TrivyVersion = "0.72.0"
	cfg.TrivyTerminationGrace = 20 * time.Millisecond

	if err := checkTrivyExecutable(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
}

func TestNewWorkerOwnerIsUniqueBoundedASCII(t *testing.T) {
	hostname := strings.Repeat("\u4e3b\u673a name/\n.", 80)
	first, err := newWorkerOwner(
		"scan",
		hostname,
		4242,
		bytes.NewReader(bytes.Repeat([]byte{0xab}, workerOwnerEntropy)),
	)
	if err != nil {
		t.Fatal(err)
	}
	second, err := newWorkerOwner(
		"scan",
		hostname,
		4242,
		bytes.NewReader(bytes.Repeat([]byte{0xcd}, workerOwnerEntropy)),
	)
	if err != nil {
		t.Fatal(err)
	}
	if first == second {
		t.Fatal("different process entropy produced the same owner")
	}
	if len(first) > maxWorkerOwnerBytes {
		t.Fatalf("owner length = %d, want <= %d", len(first), maxWorkerOwnerBytes)
	}
	if !strings.HasPrefix(first, "scan/") ||
		!strings.HasSuffix(first, "/4242/"+strings.Repeat("ab", workerOwnerEntropy)) {
		t.Fatalf("owner = %q", first)
	}
	for _, value := range []byte(first) {
		if value > 127 || value < 32 || value == 127 {
			t.Fatalf("owner contains non-printable ASCII byte %#x: %q", value, first)
		}
	}
}

func TestNewWorkerOwnerRejectsMissingEntropy(t *testing.T) {
	_, err := newWorkerOwner("scan", "host", 42, bytes.NewReader([]byte{1}))
	if err == nil || !strings.Contains(err.Error(), "entropy") {
		t.Fatalf("newWorkerOwner() error = %v", err)
	}
}

func testWorkerConfig() config.Config {
	return config.Config{
		HeartbeatInterval:   10 * time.Second,
		DatabasePingTimeout: 30 * time.Second,
		RepositoryRoot:      "/data/repository",
		TaskWorkRoot:        "/data/task-work",
		QueueLeaseInterval:  time.Minute,
		QueuePollInterval:   2 * time.Second,
		QueueHeavySlots:     2,
		QueueTrivySlots:     1,
		QueueNativeSlots:    1,
	}
}

func writeFakeTrivy(t *testing.T, version string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "trivy")
	body := "#!/bin/sh\nprintf '%s\\n' '{\"Version\":\"" + version + "\"}'\n"
	if err := os.WriteFile(path, []byte(body), 0o700); err != nil {
		t.Fatal(err)
	}
	return path
}

func testWorkerLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

package main

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	trivyadapter "binaryscan/internal/analyzers/trivy"
	"binaryscan/internal/archiveimport"
	"binaryscan/internal/archivesandbox"
	"binaryscan/internal/bytecode"
	"binaryscan/internal/canalysis"
	"binaryscan/internal/config"
	"binaryscan/internal/containerarchive"
	"binaryscan/internal/database"
	"binaryscan/internal/decompile"
	"binaryscan/internal/extract"
	"binaryscan/internal/filetype"
	"binaryscan/internal/ghidra"
	"binaryscan/internal/healthcheck"
	"binaryscan/internal/javaanalysis"
	"binaryscan/internal/logging"
	"binaryscan/internal/queue"
	"binaryscan/internal/report"
	"binaryscan/internal/retention"
	"binaryscan/internal/scan"
	"binaryscan/internal/task"
	"binaryscan/internal/trivydb"
	"binaryscan/internal/trivyscan"
	"binaryscan/internal/upload"
	"binaryscan/internal/workerreadiness"
	"binaryscan/internal/workerrunner"
)

const (
	maxWorkerOwnerBytes = 255
	workerOwnerEntropy  = 16
)

var validKinds = map[string]struct{}{
	"scan":           {},
	"image":          {},
	"native":         {},
	"bytecode":       {},
	"trivy":          {},
	"c_analysis":     {},
	"java_analysis":  {},
	"archive_import": {},
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		slog.New(slog.NewJSONHandler(os.Stderr, nil)).Error("worker stopped", "error", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	command, kind, err := parseCommand(args)
	if err != nil {
		return err
	}
	if _, ok := validKinds[kind]; !ok {
		kinds := make([]string, 0, len(validKinds))
		for value := range validKinds {
			kinds = append(kinds, value)
		}
		sort.Strings(kinds)
		flagName := "--kind"
		if command == "healthcheck" {
			flagName = "--role"
		}
		return fmt.Errorf("%s must be one of %s", flagName, strings.Join(kinds, ", "))
	}

	cfg, err := config.Load(kind + "-worker")
	if err != nil {
		return fmt.Errorf("load configuration: %w", err)
	}
	db, err := database.Open(cfg)
	if err != nil {
		return err
	}
	defer db.Close()
	if command == "healthcheck" {
		return checkWorkerHealth(
			context.Background(),
			kind,
			cfg,
			db,
		)
	}
	logger, closer, err := logging.New(cfg.Service, cfg.LogLevel, cfg.LogDir)
	if err != nil {
		return fmt.Errorf("initialize logging: %w", err)
	}
	defer closer.Close()
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if isAnalyzerWorker(kind) {
		if !awaitAnalyzerRuntimeReady(ctx, kind, cfg, db, logger) {
			return nil
		}
	}
	if archiveSandboxRequired(kind, cfg) {
		if !awaitArchiveSandboxReady(ctx, cfg, logger) {
			return nil
		}
		// Exactly one required child performs the full production-tool probe for
		// the scanner container. A failure is fatal, so supervisor tears down the
		// group instead of leaving a Ping-healthy scanner that cannot extract
		// 7Z/CAB. The scan worker waits only for Ping and therefore does not race
		// this probe for the sandbox's single execution slot.
		if kind == "archive_import" {
			if err := selfTestArchiveSandbox(ctx, cfg); err != nil {
				return fmt.Errorf("archive sandbox startup self-test: %w", err)
			}
		}
	}

	owner := ""
	if isQueueWorker(kind) || kind == "archive_import" {
		owner, err = generateWorkerOwner(kind)
		if err != nil {
			return fmt.Errorf("generate worker owner: %w", err)
		}
	}
	if isQueueWorker(kind) {
		queueService, err := queue.NewService(
			queue.NewMySQLRepository(db),
			workerQueueConfig(cfg),
		)
		if err != nil {
			return fmt.Errorf("initialize queue capacity: %w", err)
		}
		if err := queueService.ConfigureResourceLimits(ctx); err != nil {
			return fmt.Errorf("configure queue capacity: %w", err)
		}
	}
	runner, err := assembleWorkerRunner(kind, cfg, db, logger, owner)
	if err != nil {
		return fmt.Errorf("initialize %s worker: %w", kind, err)
	}
	if registration, ok := analyzerReadinessRegistration(kind, owner, cfg); ok {
		repository, err := workerreadiness.NewMySQLRepository(db)
		if err != nil {
			return fmt.Errorf("initialize analyzer readiness repository: %w", err)
		}
		reporter, err := workerreadiness.NewReporter(
			repository,
			registration,
			cfg.HeartbeatInterval,
			min(cfg.DatabasePingTimeout, cfg.HeartbeatInterval),
			logger,
		)
		if err != nil {
			return fmt.Errorf("initialize analyzer readiness reporter: %w", err)
		}
		if kind == string(queue.KindCAnalysis) {
			client, err := canalysis.NewHTTPClient(canalysis.ClientConfig{
				BaseURL: cfg.CCheckerURL, MaxDuration: cfg.CAnalysisMaxDuration,
				MaxResponseBytes: cfg.CAnalysisMaxResponseBytes,
				MaxFindings:      cfg.CAnalysisMaxFindings,
				MaxDiagnostics:   cfg.CAnalysisMaxDiagnostics,
			})
			if err != nil {
				return fmt.Errorf("initialize C checker readiness probe: %w", err)
			}
			if err := reporter.SetRuntimeProbe(client.Ready); err != nil {
				return fmt.Errorf("configure C checker readiness probe: %w", err)
			}
		}
		if kind == string(queue.KindJavaAnalysis) {
			client, err := javaanalysis.NewHTTPClient(javaanalysis.ClientConfig{
				BaseURL:          cfg.JavaCheckerURL,
				MaxDuration:      cfg.JavaAnalysisMaxDuration,
				MaxResponseBytes: cfg.JavaAnalysisMaxResponseBytes,
				MaxFindings:      cfg.JavaAnalysisMaxFindings,
				MaxDiagnostics:   cfg.JavaAnalysisMaxDiagnostics,
			})
			if err != nil {
				return fmt.Errorf("initialize Java checker readiness probe: %w", err)
			}
			if err := reporter.SetRuntimeProbe(client.Ready); err != nil {
				return fmt.Errorf("configure Java checker readiness probe: %w", err)
			}
		}
		runner = &readinessWorkerLoop{
			workerLoop: runner,
			reporter:   reporter,
			logger:     logger,
		}
	}
	if isQueueWorker(kind) || kind == "archive_import" {
		logger.Info("worker started", "worker_kind", kind, "worker_owner", owner)
	} else {
		logger.Info("worker started in safe idle mode", "worker_kind", kind)
	}
	if err := runner.Run(ctx); err != nil {
		return fmt.Errorf("worker main loop: %w", err)
	}
	logger.Info("worker stopped", "worker_kind", kind)
	return nil
}

func checkWorkerHealth(
	ctx context.Context,
	kind string,
	cfg config.Config,
	db *sql.DB,
) error {
	if err := healthcheck.CheckDatabase(
		ctx,
		db,
		cfg.DatabasePingTimeout,
	); err != nil {
		return err
	}
	if kind == "archive_import" {
		return checkArchiveSandbox(ctx, cfg)
	}
	return nil
}

func archiveSandboxRequired(kind string, cfg config.Config) bool {
	return kind == "archive_import" || (kind == string(queue.KindScan) && cfg.ArchiveSandboxEnabled)
}

func awaitArchiveSandboxReady(
	ctx context.Context,
	cfg config.Config,
	logger *slog.Logger,
) bool {
	for {
		if err := checkArchiveSandbox(ctx, cfg); err == nil {
			return true
		} else if ctx.Err() == nil {
			logger.WarnContext(ctx, "archive sandbox is not ready; claims remain paused", "error", err)
		}
		if !waitWorkerContext(ctx, cfg.QueuePollInterval) {
			return false
		}
	}
}

func checkArchiveSandbox(ctx context.Context, cfg config.Config) error {
	if !cfg.ArchiveSandboxEnabled {
		return errors.New("archive sandbox must be enabled")
	}
	client, err := newArchiveSandboxClient(cfg)
	if err != nil {
		return err
	}
	defer client.Close()
	checkCtx, cancel := context.WithTimeout(ctx, min(cfg.DatabasePingTimeout, cfg.ArchiveSandboxTimeout))
	defer cancel()
	return client.Ping(checkCtx)
}

func selfTestArchiveSandbox(ctx context.Context, cfg config.Config) error {
	if !cfg.ArchiveSandboxEnabled {
		return errors.New("archive sandbox must be enabled")
	}
	client, err := newArchiveSandboxClient(cfg)
	if err != nil {
		return err
	}
	defer client.Close()
	selfTestTimeout := min(cfg.ArchiveSandboxTimeout, 45*time.Second)
	selfTestCtx, cancel := context.WithTimeout(ctx, selfTestTimeout)
	defer cancel()
	return client.SelfTest(selfTestCtx)
}

func waitWorkerContext(ctx context.Context, duration time.Duration) bool {
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

func newArchiveSandboxClient(cfg config.Config) (*archivesandbox.Client, error) {
	return archivesandbox.NewClient(archivesandbox.ClientConfig{
		SocketPath:       cfg.ArchiveSandboxSocket,
		InputRoot:        cfg.ArchiveSandboxInputRoot,
		OutputRoot:       cfg.ArchiveSandboxOutputRoot,
		Timeout:          cfg.ArchiveSandboxTimeout,
		MinimumFreeBytes: cfg.StorageMinFreeBytes,
	})
}

func checkAnalyzerRuntimeReady(
	ctx context.Context,
	kind string,
	cfg config.Config,
	db *sql.DB,
) error {
	if err := checkWorkerHealth(ctx, kind, cfg, db); err != nil {
		return err
	}
	if kind == string(queue.KindNative) {
		if err := ghidra.ProbeInstallation(
			cfg.GhidraExecutable,
			cfg.GhidraScriptDirectory,
			cfg.GhidraVersion,
			cfg.GhidraJavaExecutable,
			cfg.GhidraJavaVersionLine,
		); err != nil {
			return fmt.Errorf("Ghidra runtime is not ready: %w", err)
		}
		return nil
	}
	if kind == string(queue.KindCAnalysis) {
		client, err := canalysis.NewHTTPClient(canalysis.ClientConfig{
			BaseURL: cfg.CCheckerURL, MaxDuration: cfg.CAnalysisMaxDuration,
			MaxResponseBytes: cfg.CAnalysisMaxResponseBytes,
			MaxFindings:      cfg.CAnalysisMaxFindings,
			MaxDiagnostics:   cfg.CAnalysisMaxDiagnostics,
		})
		if err != nil {
			return fmt.Errorf("initialize C checker readiness client: %w", err)
		}
		checkCtx, cancel := context.WithTimeout(ctx, cfg.DatabasePingTimeout)
		defer cancel()
		if err := client.Ready(checkCtx); err != nil {
			return fmt.Errorf("C checker runtime is not ready: %w", err)
		}
		return nil
	}
	if kind == string(queue.KindJavaAnalysis) {
		client, err := javaanalysis.NewHTTPClient(javaanalysis.ClientConfig{
			BaseURL:          cfg.JavaCheckerURL,
			MaxDuration:      cfg.JavaAnalysisMaxDuration,
			MaxResponseBytes: cfg.JavaAnalysisMaxResponseBytes,
			MaxFindings:      cfg.JavaAnalysisMaxFindings,
			MaxDiagnostics:   cfg.JavaAnalysisMaxDiagnostics,
		})
		if err != nil {
			return fmt.Errorf("initialize Java checker readiness client: %w", err)
		}
		checkCtx, cancel := context.WithTimeout(ctx, cfg.DatabasePingTimeout)
		defer cancel()
		if err := client.Ready(checkCtx); err != nil {
			return fmt.Errorf("Java checker runtime is not ready: %w", err)
		}
		return nil
	}
	if kind != string(queue.KindTrivy) && kind != string(queue.KindImage) {
		return nil
	}
	if err := checkTrivyExecutable(ctx, cfg); err != nil {
		return fmt.Errorf("Trivy executable is not ready: %w", err)
	}
	resolver, err := trivydb.NewResolver(cfg.TrivyDBRoot)
	if err != nil {
		return fmt.Errorf("initialize Trivy database readiness: %w", err)
	}
	checkCtx, cancel := context.WithTimeout(ctx, cfg.DatabasePingTimeout)
	defer cancel()
	if _, err := resolver.Resolve(checkCtx, trivydb.JavaDBRequired); err != nil {
		return fmt.Errorf("fixed Trivy database bundle is not ready: %w", err)
	}
	return nil
}

func awaitAnalyzerRuntimeReady(
	ctx context.Context,
	kind string,
	cfg config.Config,
	db *sql.DB,
	logger *slog.Logger,
) bool {
	return awaitAnalyzerRuntimeReadyWithProbe(
		ctx, kind, cfg, db, logger, checkAnalyzerRuntimeReady,
	)
}

func awaitAnalyzerRuntimeReadyWithProbe(
	ctx context.Context,
	kind string,
	cfg config.Config,
	db *sql.DB,
	logger *slog.Logger,
	probe func(context.Context, string, config.Config, *sql.DB) error,
) bool {
	for {
		if err := probe(ctx, kind, cfg, db); err == nil {
			logger.InfoContext(ctx, "analyzer runtime is ready", "worker_kind", kind)
			return true
		} else if ctx.Err() == nil {
			logger.WarnContext(
				ctx,
				"analyzer runtime is not ready; queue claims remain paused",
				"worker_kind", kind,
				"error", err,
			)
		}
		timer := time.NewTimer(cfg.HeartbeatInterval)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			return false
		case <-timer.C:
		}
	}
}

func isAnalyzerWorker(kind string) bool {
	return kind == string(queue.KindNative) ||
		kind == string(queue.KindBytecode) ||
		kind == string(queue.KindImage) ||
		kind == string(queue.KindTrivy) ||
		kind == string(queue.KindCAnalysis) ||
		kind == string(queue.KindJavaAnalysis)
}

func checkTrivyExecutable(ctx context.Context, cfg config.Config) error {
	grace := min(cfg.TrivyTerminationGrace, time.Second)
	timeout := min(cfg.DatabasePingTimeout, time.Minute)
	_, err := trivyadapter.ProbeVersion(
		ctx,
		cfg.TrivyExecutable,
		cfg.TrivyVersion,
		timeout,
		grace,
	)
	return err
}

func parseCommand(args []string) (command, kind string, err error) {
	if len(args) > 0 && args[0] == "healthcheck" {
		flags := flag.NewFlagSet("worker healthcheck", flag.ContinueOnError)
		role := flags.String("role", "", "worker role")
		if err := flags.Parse(args[1:]); err != nil {
			return "", "", err
		}
		if flags.NArg() != 0 {
			return "", "", errors.New("worker healthcheck does not accept positional arguments")
		}
		return "healthcheck", *role, nil
	}
	if len(args) == 1 && args[0] != "" && args[0][0] != '-' {
		return "run", args[0], nil
	}
	flags := flag.NewFlagSet("worker", flag.ContinueOnError)
	kindFlag := flags.String(
		"kind", "",
		"worker kind: scan, image, native, bytecode, trivy, c_analysis, java_analysis, or archive_import",
	)
	if err := flags.Parse(args); err != nil {
		return "", "", err
	}
	if flags.NArg() != 0 {
		return "", "", errors.New("worker does not accept positional arguments")
	}
	return "run", *kindFlag, nil
}

type workerLoop interface {
	Run(context.Context) error
}

type closingWorkerLoop struct {
	workerLoop
	closer io.Closer
}

type readinessWorkerLoop struct {
	workerLoop
	reporter *workerreadiness.Reporter
	logger   *slog.Logger
}

func (loop *readinessWorkerLoop) Run(ctx context.Context) error {
	if err := loop.reporter.Register(ctx); err != nil {
		return fmt.Errorf("register analyzer readiness: %w", err)
	}
	heartbeatCtx, cancelHeartbeat := context.WithCancel(ctx)
	heartbeatDone := make(chan struct{})
	go func() {
		loop.reporter.Run(heartbeatCtx)
		close(heartbeatDone)
	}()
	runErr := loop.workerLoop.Run(ctx)
	cancelHeartbeat()
	<-heartbeatDone
	cleanupCtx, cancelCleanup := context.WithTimeout(
		context.WithoutCancel(ctx),
		5*time.Second,
	)
	defer cancelCleanup()
	if err := loop.reporter.Remove(cleanupCtx); err != nil {
		loop.logger.WarnContext(
			cleanupCtx,
			"analyzer readiness cleanup failed; heartbeat will expire",
			slog.String("error", err.Error()),
		)
	}
	return runErr
}

func analyzerReadinessRegistration(
	kind string,
	owner string,
	cfg config.Config,
) (workerreadiness.Registration, bool) {
	switch kind {
	case string(queue.KindNative):
		return workerreadiness.Registration{
			Owner: owner, WorkerKind: kind,
			AnalyzerName: "ghidra", AnalyzerVersion: cfg.GhidraVersion,
			RuntimeName: "jdk", RuntimeVersion: cfg.GhidraJavaVersionLine,
		}, true
	case string(queue.KindBytecode):
		name := bytecode.RoutingEngineName
		version := "bytecode-only"
		if available, err := bytecode.ExternalToolchainAvailable(cfg.TaskWorkRoot); err == nil && available {
			name = "vineflower-cfr-jadx"
			version = bytecode.DefaultVineflowerVersion + "+" +
				bytecode.DefaultCFRVersion + "+" + bytecode.DefaultJADXVersion
		}
		return workerreadiness.Registration{
			Owner: owner, WorkerKind: kind,
			AnalyzerName: name, AnalyzerVersion: version,
		}, true
	case string(queue.KindImage), string(queue.KindTrivy):
		return workerreadiness.Registration{
			Owner: owner, WorkerKind: kind,
			AnalyzerName: "trivy", AnalyzerVersion: cfg.TrivyVersion,
		}, true
	case string(queue.KindCAnalysis):
		return workerreadiness.Registration{
			Owner: owner, WorkerKind: kind,
			AnalyzerName:    canalysis.AnalyzerName,
			AnalyzerVersion: cfg.CCheckerVersion,
			RuntimeName:     "spring-boot",
		}, true
	case string(queue.KindJavaAnalysis):
		return workerreadiness.Registration{
			Owner: owner, WorkerKind: kind,
			AnalyzerName:    javaanalysis.AnalyzerName,
			AnalyzerVersion: cfg.JavaCheckerVersion,
			RuntimeName:     "spring-boot",
		}, true
	default:
		return workerreadiness.Registration{}, false
	}
}

func (loop *closingWorkerLoop) Run(ctx context.Context) error {
	return errors.Join(loop.workerLoop.Run(ctx), loop.closer.Close())
}

func assembleWorkerRunner(
	kind string,
	cfg config.Config,
	db *sql.DB,
	logger *slog.Logger,
	owner string,
) (workerLoop, error) {
	if db == nil {
		return nil, errors.New("worker database is required")
	}
	if logger == nil {
		return nil, errors.New("worker logger is required")
	}

	switch kind {
	case "archive_import":
		if !cfg.ArchiveSandboxEnabled {
			return nil, errors.New("archive import requires the archive sandbox")
		}
		sandboxClient, err := newArchiveSandboxClient(cfg)
		if err != nil {
			return nil, fmt.Errorf("initialize archive import sandbox client: %w", err)
		}
		// Structural classification stays in-process; the sandbox is reserved
		// for 7Z/CAB extraction rather than forking file(1) per archive member.
		detector := filetype.Detector{}
		engine, err := extract.NewEngineWithArchiveSandbox(
			detector,
			extract.Limits{
				MaxExpandedBytes: cfg.MaxExpandedBytes,
				MaxEntryBytes:    cfg.MaxUploadBytes,
				MaxNodes:         cfg.MaxFileNodes,
				MaxDepth:         cfg.MaxDepth,
				MaxRatio:         int64(cfg.MaxArchiveRatio),
			},
			sandboxClient,
		)
		if err != nil {
			_ = sandboxClient.Close()
			return nil, fmt.Errorf("initialize logical archive extractor: %w", err)
		}
		repository, err := archiveimport.NewMySQLRepository(db)
		if err != nil {
			_ = sandboxClient.Close()
			return nil, err
		}
		storage, err := archiveimport.NewBlobStorage(cfg.RepositoryRoot)
		if err != nil {
			_ = sandboxClient.Close()
			return nil, err
		}
		partDeleter, err := retention.NewRepositoryUploadDirectoryDeleter(cfg.UploadsRoot)
		if err != nil {
			_ = sandboxClient.Close()
			return nil, fmt.Errorf("initialize derived upload cleanup: %w", err)
		}
		uploadService, err := upload.NewService(
			upload.NewMySQLRepository(db),
			upload.Config{
				UploadsRoot: cfg.UploadsRoot, RepositoryRoot: cfg.RepositoryRoot,
				MaxUploadBytes: cfg.MaxUploadBytes, PartSize: upload.DefaultPartSize,
				Retention: cfg.IncompleteUploadRetention, PartDeleter: partDeleter,
				Detector: detector,
			},
		)
		if err != nil {
			_ = sandboxClient.Close()
			return nil, fmt.Errorf("initialize derived archive uploads: %w", err)
		}
		taskService, err := task.NewService(
			task.NewMySQLRepository(db),
			task.ServiceConfig{
				Limits: task.LimitsSnapshot{
					MaxUploadBytes:   cfg.MaxUploadBytes,
					MaxExpandedBytes: cfg.MaxExpandedBytes,
					MaxArchiveRatio:  cfg.MaxArchiveRatio,
					MaxDepth:         cfg.MaxDepth, MaxFileNodes: cfg.MaxFileNodes,
					MaxNestedImages: cfg.MaxNestedImages,
				},
				SampleRetention: cfg.SampleRetention,
			},
		)
		if err != nil {
			_ = sandboxClient.Close()
			return nil, fmt.Errorf("initialize archive entry tasks: %w", err)
		}
		uploadAdapter := archiveimport.UploadServiceAdapter{Service: uploadService}
		service, err := archiveimport.NewService(
			repository,
			archiveimport.ServiceConfig{
				Limits: archiveimport.Limits{
					MaxUploadBytes:   cfg.MaxUploadBytes,
					MaxExpandedBytes: cfg.MaxExpandedBytes,
					MaxArchiveRatio:  int64(cfg.MaxArchiveRatio),
					MaxEntries:       cfg.MaxFileNodes, MaxEntryBytes: cfg.MaxUploadBytes,
					MaxDepth: cfg.MaxDepth,
				},
				BatchLeaseDuration: cfg.QueueLeaseInterval,
				BatchRecoveryAge:   cfg.QueueLeaseInterval,
				DerivedUploads:     uploadAdapter, DeleteDerived: uploadAdapter,
				Tasks:   archiveimport.TaskServiceAdapter{Service: taskService},
				Storage: storage,
			},
		)
		if err != nil {
			_ = sandboxClient.Close()
			return nil, fmt.Errorf("initialize archive import service: %w", err)
		}
		archiveStorageGuard, err := newArchiveStorageGuard(cfg)
		if err != nil {
			_ = sandboxClient.Close()
			return nil, err
		}
		processor, err := archiveimport.NewProcessor(
			repository, engine, storage,
			archiveimport.ProcessorConfig{
				WorkRoot: cfg.TaskWorkRoot, LeaseDuration: cfg.QueueLeaseInterval,
				HeartbeatInterval: cfg.HeartbeatInterval, Logger: logger,
				StorageGuard: archiveStorageGuard,
			},
		)
		if err != nil {
			_ = sandboxClient.Close()
			return nil, fmt.Errorf("initialize archive import processor: %w", err)
		}
		runner, err := archiveimport.NewRunner(
			repository, processor, service,
			archiveimport.RunnerConfig{
				Owner: owner, PollInterval: cfg.QueuePollInterval,
				LeaseDuration: cfg.QueueLeaseInterval,
				RetryDelay:    cfg.QueuePollInterval, Logger: logger,
			},
		)
		if err != nil {
			_ = sandboxClient.Close()
			return nil, fmt.Errorf("initialize archive import runner: %w", err)
		}
		return &closingWorkerLoop{workerLoop: runner, closer: sandboxClient}, nil
	case string(queue.KindScan):
		queueService, err := queue.NewService(
			queue.NewMySQLRepository(db),
			workerQueueConfig(cfg),
		)
		if err != nil {
			return nil, fmt.Errorf("initialize queue service: %w", err)
		}
		var sandboxClient *archivesandbox.Client
		detector := filetype.Detector{}
		if cfg.ArchiveSandboxEnabled {
			sandboxClient, err = newArchiveSandboxClient(cfg)
			if err != nil {
				return nil, fmt.Errorf(
					"initialize archive sandbox client: %w",
					err,
				)
			}
		}
		processor, err := scan.NewProcessor(
			scan.NewMySQLRepository(db),
			queueService,
			detector,
			cfg.RepositoryRoot,
			cfg.TaskWorkRoot,
		)
		if err != nil {
			if sandboxClient != nil {
				_ = sandboxClient.Close()
			}
			return nil, fmt.Errorf("initialize scan processor: %w", err)
		}
		if sandboxClient != nil {
			archiveStorageGuard, guardErr := newArchiveStorageGuard(cfg)
			if guardErr != nil {
				_ = sandboxClient.Close()
				return nil, guardErr
			}
			reserveArchive := func(
				ctx context.Context,
				sourceBytes, expandedBytes int64,
			) (func(), error) {
				return archiveStorageGuard.ReservePlan(ctx, archiveimport.StoragePlan{
					SourceBytes: sourceBytes, ExpandedBytes: expandedBytes,
				})
			}
			if err := processor.EnableArchiveSandbox(
				sandboxClient, reserveArchive,
			); err != nil {
				_ = sandboxClient.Close()
				return nil, fmt.Errorf(
					"enable archive sandbox extraction: %w",
					err,
				)
			}
		}
		runner, err := workerrunner.New(
			queueService,
			processor,
			logger,
			workerRunnerConfig(cfg, queue.KindScan, owner),
		)
		if err != nil {
			if sandboxClient != nil {
				_ = sandboxClient.Close()
			}
			return nil, fmt.Errorf("initialize queue runner: %w", err)
		}
		if sandboxClient != nil {
			return &closingWorkerLoop{
				workerLoop: runner,
				closer:     sandboxClient,
			}, nil
		}
		return runner, nil
	case string(queue.KindNative):
		queueService, err := queue.NewService(
			queue.NewMySQLRepository(db), workerQueueConfig(cfg),
		)
		if err != nil {
			return nil, fmt.Errorf("initialize queue service: %w", err)
		}
		adapter, err := ghidra.New(ghidra.Config{
			Executable:       cfg.GhidraExecutable,
			ScriptDirectory:  cfg.GhidraScriptDirectory,
			Version:          cfg.GhidraVersion,
			MaxDuration:      cfg.GhidraMaxDuration,
			TerminationGrace: cfg.GhidraTerminationGrace,
			MaxStdoutBytes:   cfg.GhidraMaxStandardOutputBytes,
			MaxStderrBytes:   cfg.GhidraMaxStandardErrorBytes,
			MaxIndexBytes:    cfg.GhidraMaxIndexBytes,
			MaxOutputBytes:   cfg.GhidraMaxOutputBytes,
			MaxFunctions:     cfg.GhidraMaxFunctions,
		})
		if err != nil {
			return nil, fmt.Errorf("initialize Ghidra adapter: %w", err)
		}
		processor, err := decompile.NewNativeProcessor(
			decompile.NewMySQLRepository(db), adapter, queueService,
			decompile.NativeProcessorConfig{
				RepositoryRoot: cfg.RepositoryRoot,
				TaskWorkRoot:   cfg.TaskWorkRoot,
				EngineVersion:  cfg.GhidraVersion,
			},
		)
		if err != nil {
			return nil, fmt.Errorf("initialize native decompile processor: %w", err)
		}
		runner, err := workerrunner.New(
			nativeQueue{Service: queueService}, processor, logger,
			workerRunnerConfig(cfg, queue.KindNative, owner),
		)
		if err != nil {
			return nil, fmt.Errorf("initialize native worker runner: %w", err)
		}
		return runner, nil
	case string(queue.KindBytecode):
		queueService, err := queue.NewService(
			queue.NewMySQLRepository(db), workerQueueConfig(cfg),
		)
		if err != nil {
			return nil, fmt.Errorf("initialize queue service: %w", err)
		}
		engine, targets, validator, err := assembleBytecodeEngine(cfg)
		if err != nil {
			return nil, err
		}
		analyzer, err := decompile.NewEngineBytecodeAnalyzer(
			engine,
			engine.ConfigFingerprint(),
			nil,
			targets,
		)
		if err != nil {
			return nil, fmt.Errorf("initialize bytecode analyzer: %w", err)
		}
		processor, err := decompile.NewBytecodeProcessor(
			decompile.NewMySQLRepository(db), analyzer, queueService,
			decompile.BytecodeProcessorConfig{
				RepositoryRoot:    cfg.RepositoryRoot,
				TaskWorkRoot:      cfg.TaskWorkRoot,
				EngineName:        engine.Descriptor().Name,
				EngineVersion:     engine.Descriptor().Version,
				ArtifactValidator: validator,
			},
		)
		if err != nil {
			return nil, fmt.Errorf("initialize bytecode decompile processor: %w", err)
		}
		runner, err := workerrunner.New(
			bytecodeQueue{Service: queueService}, processor, logger,
			workerRunnerConfig(cfg, queue.KindBytecode, owner),
		)
		if err != nil {
			return nil, fmt.Errorf("initialize bytecode worker runner: %w", err)
		}
		return runner, nil
	case string(queue.KindTrivy), string(queue.KindImage):
		jobKind := queue.KindTrivy
		if kind == string(queue.KindImage) {
			jobKind = queue.KindImage
		}
		queueService, err := queue.NewService(
			queue.NewMySQLRepository(db),
			workerQueueConfig(cfg),
		)
		if err != nil {
			return nil, fmt.Errorf("initialize queue service: %w", err)
		}
		resolver, err := trivydb.NewResolver(cfg.TrivyDBRoot)
		if err != nil {
			return nil, fmt.Errorf("initialize Trivy database resolver: %w", err)
		}
		repository, err := trivyscan.NewMySQLRepository(
			db,
			cfg.RepositoryRoot,
			cfg.TaskWorkRoot,
			cfg.TrivyMaxReportBytes,
		)
		if err != nil {
			return nil, fmt.Errorf("initialize Trivy result repository: %w", err)
		}
		processor, err := trivyscan.NewProcessor(
			repository,
			queueService,
			trivyscan.NewDatabaseProvider(resolver),
			trivyscan.NewAdapterFactory(trivyadapter.Config{
				Executable:             cfg.TrivyExecutable,
				MaxDuration:            cfg.TrivyMaxDuration,
				TerminationGracePeriod: cfg.TrivyTerminationGrace,
				MaxStandardOutputBytes: cfg.TrivyMaxStandardOutputBytes,
				MaxStandardErrorBytes:  cfg.TrivyMaxStandardErrorBytes,
				MaxReportBytes:         cfg.TrivyMaxReportBytes,
				MaxResults:             cfg.TrivyMaxResults,
				MaxFindings:            cfg.TrivyMaxFindings,
			}),
			trivyscan.Config{
				RepositoryRoot:  cfg.RepositoryRoot,
				TaskWorkRoot:    cfg.TaskWorkRoot,
				AnalyzerVersion: cfg.TrivyVersion,
				JavaDBPolicy:    trivydb.JavaDBRequired,
				ArchiveLimits: containerarchive.Limits{
					MaxEntries:      cfg.MaxFileNodes,
					MaxDescriptors:  cfg.MaxFileNodes,
					MaxIndexDepth:   cfg.MaxDepth,
					MaxArchiveRatio: cfg.MaxArchiveRatio,
				},
				MaxSourceBytes:       cfg.MaxUploadBytes,
				MaxExpandedBytes:     cfg.MaxExpandedBytes,
				MaxReportBytes:       cfg.TrivyMaxReportBytes,
				MaxPublishedFindings: cfg.TrivyMaxFindings,
				StorageMinFreeBytes:  cfg.StorageMinFreeBytes,
			},
		)
		if err != nil {
			return nil, fmt.Errorf("initialize Trivy processor: %w", err)
		}
		runner, err := workerrunner.New(
			queueService,
			processor,
			logger,
			workerRunnerConfig(cfg, jobKind, owner),
		)
		if err != nil {
			return nil, fmt.Errorf("initialize queue runner: %w", err)
		}
		return runner, nil
	case string(queue.KindCAnalysis):
		queueService, err := queue.NewService(
			queue.NewMySQLRepository(db), workerQueueConfig(cfg),
		)
		if err != nil {
			return nil, fmt.Errorf("initialize C analysis queue service: %w", err)
		}
		repository, err := canalysis.NewMySQLRepository(db, canalysis.RepositoryConfig{
			AnalyzerVersion: cfg.CCheckerVersion,
			ReadyMaxAge:     3 * cfg.HeartbeatInterval,
		})
		if err != nil {
			return nil, fmt.Errorf("initialize C analysis repository: %w", err)
		}
		client, err := canalysis.NewHTTPClient(canalysis.ClientConfig{
			BaseURL: cfg.CCheckerURL, MaxDuration: cfg.CAnalysisMaxDuration,
			MaxResponseBytes: cfg.CAnalysisMaxResponseBytes,
			MaxFindings:      cfg.CAnalysisMaxFindings,
			MaxDiagnostics:   cfg.CAnalysisMaxDiagnostics,
		})
		if err != nil {
			return nil, fmt.Errorf("initialize C checker client: %w", err)
		}
		processor, err := canalysis.NewProcessor(
			repository, client,
			canalysis.ProcessorConfig{
				RepositoryRoot: cfg.RepositoryRoot,
				TaskWorkRoot:   cfg.TaskWorkRoot,
			},
		)
		if err != nil {
			return nil, fmt.Errorf("initialize C analysis processor: %w", err)
		}
		runnerConfig := workerRunnerConfig(cfg, queue.KindCAnalysis, owner)
		runnerConfig.ClaimGate = checkerClaimGate(client.Ready)
		runner, err := workerrunner.New(
			queueService, processor, logger,
			runnerConfig,
		)
		if err != nil {
			return nil, fmt.Errorf("initialize C analysis worker runner: %w", err)
		}
		return runner, nil
	case string(queue.KindJavaAnalysis):
		queueService, err := queue.NewService(
			queue.NewMySQLRepository(db), workerQueueConfig(cfg),
		)
		if err != nil {
			return nil, fmt.Errorf("initialize Java analysis queue service: %w", err)
		}
		repository, err := javaanalysis.NewMySQLRepository(
			db, javaAnalysisRepositoryConfig(cfg),
		)
		if err != nil {
			return nil, fmt.Errorf("initialize Java analysis repository: %w", err)
		}
		client, err := javaanalysis.NewHTTPClient(javaanalysis.ClientConfig{
			BaseURL:          cfg.JavaCheckerURL,
			MaxDuration:      cfg.JavaAnalysisMaxDuration,
			MaxResponseBytes: cfg.JavaAnalysisMaxResponseBytes,
			MaxFindings:      cfg.JavaAnalysisMaxFindings,
			MaxDiagnostics:   cfg.JavaAnalysisMaxDiagnostics,
		})
		if err != nil {
			return nil, fmt.Errorf("initialize Java checker client: %w", err)
		}
		processor, err := javaanalysis.NewProcessor(
			repository, client, javaanalysis.ProcessorConfig{
				RepositoryRoot: cfg.RepositoryRoot,
				TaskWorkRoot:   cfg.TaskWorkRoot,
			},
		)
		if err != nil {
			return nil, fmt.Errorf("initialize Java analysis processor: %w", err)
		}
		runnerConfig := workerRunnerConfig(cfg, queue.KindJavaAnalysis, owner)
		runnerConfig.ClaimGate = checkerClaimGate(client.Ready)
		runner, err := workerrunner.New(
			queueService, processor, logger,
			runnerConfig,
		)
		if err != nil {
			return nil, fmt.Errorf("initialize Java analysis worker runner: %w", err)
		}
		return runner, nil
	default:
		return nil, fmt.Errorf("unsupported worker kind %q", kind)
	}
}

func newArchiveStorageGuard(cfg config.Config) (archiveimport.StorageGuard, error) {
	checker, err := archiveimport.NewCapacityGuard(archiveimport.CapacityGuardConfig{
		SandboxRoots: []string{
			cfg.ArchiveSandboxInputRoot,
			cfg.ArchiveSandboxOutputRoot,
			cfg.ArchiveSandboxRunRoot,
			cfg.TaskWorkRoot,
		},
		RepositoryRoot: cfg.RepositoryRoot,
		MinimumFree:    cfg.StorageMinFreeBytes,
	})
	if err != nil {
		return nil, fmt.Errorf("initialize archive storage guard: %w", err)
	}
	return checker, nil
}

func javaAnalysisRepositoryConfig(cfg config.Config) javaanalysis.RepositoryConfig {
	return javaanalysis.RepositoryConfig{
		AnalyzerVersion: cfg.JavaCheckerVersion,
		ReadyMaxAge:     3 * cfg.HeartbeatInterval,
		InvalidateReports: func(ctx context.Context, tx *sql.Tx, taskID string) error {
			return report.InvalidateTaskSourceAnalysisReports(ctx, tx, taskID)
		},
	}
}

func assembleBytecodeEngine(
	cfg config.Config,
) (*bytecode.RoutingEngine, []string, bytecode.ArtifactValidator, error) {
	pycEngine, err := bytecode.NewPYCFallbackEngine(bytecode.PYCConfig{})
	if err != nil {
		return nil, nil, nil, fmt.Errorf("initialize PYC bytecode fallback: %w", err)
	}
	available, err := bytecode.ExternalToolchainAvailable(cfg.TaskWorkRoot)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("verify bytecode source toolchain: %w", err)
	}
	if available {
		jvmEngine, err := bytecode.NewJVMSourceEngine(
			bytecode.DefaultJVMSourceEngineConfig(cfg.TaskWorkRoot),
		)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("initialize Vineflower/CFR engine: %w", err)
		}
		jadxEngine, err := bytecode.NewJADXSourceEngine(
			bytecode.DefaultJADXSourceEngineConfig(cfg.TaskWorkRoot),
		)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("initialize JADX engine: %w", err)
		}
		engine, err := bytecode.NewRoutingEngine(jvmEngine, jadxEngine, pycEngine)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("initialize bytecode source routing engine: %w", err)
		}
		validator, err := bytecode.NewFileArtifactValidator(map[string]bytecode.SourceInspector{
			"text/x-java-source":   bytecode.SourceInspectorFunc(bytecode.InspectUTF8Source),
			"text/x-kotlin-source": bytecode.SourceInspectorFunc(bytecode.InspectUTF8Source),
			"text/x-python":        bytecode.SourceInspectorFunc(bytecode.InspectUTF8Source),
		})
		if err != nil {
			return nil, nil, nil, fmt.Errorf("initialize source artifact validator: %w", err)
		}
		return engine, []string{
			decompile.EngineVineflower,
			decompile.EngineJADX,
			decompile.EnginePythonBytecode,
		}, validator, nil
	}

	jvmEngine, err := bytecode.NewJVMFallbackEngine(bytecode.JVMEngineConfig{
		TargetJavaRelease:   bytecode.DefaultJVMTargetJavaRelease,
		MaxArchiveEntries:   cfg.MaxFileNodes,
		MaxExpandedBytes:    cfg.MaxExpandedBytes,
		MaxCompressionRatio: cfg.MaxArchiveRatio,
		MaxArchiveDepth:     cfg.MaxDepth,
	})
	if err != nil {
		return nil, nil, nil, fmt.Errorf("initialize JVM bytecode fallback: %w", err)
	}
	engine, err := bytecode.NewRoutingEngine(jvmEngine, pycEngine)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("initialize bytecode fallback routing engine: %w", err)
	}
	validator, err := bytecode.NewFileArtifactValidator(nil)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("initialize bytecode artifact validator: %w", err)
	}
	return engine, []string{
		decompile.EngineVineflower,
		decompile.EnginePythonBytecode,
	}, validator, nil
}

func workerQueueConfig(cfg config.Config) queue.Config {
	return queue.Config{
		LeaseDuration:   cfg.QueueLeaseInterval,
		RetryDelay:      cfg.QueuePollInterval,
		SampleRetention: cfg.SampleRetention,
		HeavySlotLimit:  cfg.QueueHeavySlots,
		TrivySlotLimit:  cfg.QueueTrivySlots,
		NativeSlotLimit: cfg.QueueNativeSlots,
	}
}

func workerRunnerConfig(
	cfg config.Config,
	kind queue.Kind,
	owner string,
) workerrunner.Config {
	return workerrunner.Config{
		Kind:              kind,
		Owner:             owner,
		PollInterval:      cfg.QueuePollInterval,
		HeartbeatInterval: cfg.HeartbeatInterval,
	}
}

func checkerClaimGate(
	ready func(context.Context) error,
) func(context.Context) error {
	return func(ctx context.Context) error {
		probeCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		return ready(probeCtx)
	}
}

func isQueueWorker(kind string) bool {
	return kind == string(queue.KindScan) ||
		kind == string(queue.KindImage) ||
		kind == string(queue.KindNative) ||
		kind == string(queue.KindBytecode) ||
		kind == string(queue.KindTrivy) ||
		kind == string(queue.KindCAnalysis) ||
		kind == string(queue.KindJavaAnalysis)
}

type nativeQueue struct{ *queue.Service }

func (q nativeQueue) Claim(
	ctx context.Context,
	_ queue.Kind,
	owner string,
) (queue.Lease, bool, error) {
	return q.ClaimDecompileWorker(ctx, queue.KindNative, owner)
}

type bytecodeQueue struct{ *queue.Service }

func (q bytecodeQueue) Claim(
	ctx context.Context,
	_ queue.Kind,
	owner string,
) (queue.Lease, bool, error) {
	return q.ClaimDecompileWorker(ctx, queue.KindBytecode, owner)
}

func generateWorkerOwner(kind string) (string, error) {
	hostname, err := os.Hostname()
	if err != nil {
		return "", fmt.Errorf("read hostname: %w", err)
	}
	return newWorkerOwner(kind, hostname, os.Getpid(), rand.Reader)
}

func newWorkerOwner(kind string, hostname string, pid int, entropy io.Reader) (string, error) {
	if _, ok := validKinds[kind]; !ok {
		return "", fmt.Errorf("unsupported worker kind %q", kind)
	}
	if pid <= 0 {
		return "", errors.New("worker process ID must be positive")
	}
	if entropy == nil {
		return "", errors.New("worker owner entropy is required")
	}

	random := make([]byte, workerOwnerEntropy)
	if _, err := io.ReadFull(entropy, random); err != nil {
		return "", fmt.Errorf("read worker owner entropy: %w", err)
	}
	suffix := "/" + strconv.Itoa(pid) + "/" + hex.EncodeToString(random)
	hostLimit := maxWorkerOwnerBytes - len(kind) - 1 - len(suffix)
	if hostLimit < 1 {
		return "", errors.New("worker owner components exceed the length limit")
	}
	host := sanitizeOwnerToken(hostname)
	if len(host) > hostLimit {
		host = strings.Trim(host[:hostLimit], "-._")
	}
	if host == "" {
		host = "host"
	}
	if len(host) > hostLimit {
		host = host[:hostLimit]
	}

	owner := kind + "/" + host + suffix
	if len(owner) > maxWorkerOwnerBytes {
		return "", errors.New("worker owner exceeds the length limit")
	}
	return owner, nil
}

func sanitizeOwnerToken(value string) string {
	var token strings.Builder
	separated := false
	for _, character := range value {
		if character <= 127 &&
			((character >= 'a' && character <= 'z') ||
				(character >= 'A' && character <= 'Z') ||
				(character >= '0' && character <= '9') ||
				character == '-' || character == '_' || character == '.') {
			token.WriteByte(byte(character))
			separated = false
			continue
		}
		if token.Len() != 0 && !separated {
			token.WriteByte('-')
			separated = true
		}
	}
	result := strings.Trim(token.String(), "-._")
	if result == "" {
		return "host"
	}
	return result
}

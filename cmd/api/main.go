package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"binaryscan/internal/api"
	"binaryscan/internal/archiveimport"
	"binaryscan/internal/audit"
	"binaryscan/internal/auth"
	"binaryscan/internal/buildinfo"
	"binaryscan/internal/bytecode"
	"binaryscan/internal/canalysis"
	"binaryscan/internal/config"
	"binaryscan/internal/database"
	"binaryscan/internal/decompile"
	"binaryscan/internal/filetree"
	"binaryscan/internal/healthcheck"
	"binaryscan/internal/javaanalysis"
	"binaryscan/internal/logging"
	"binaryscan/internal/manualimagescan"
	"binaryscan/internal/report"
	"binaryscan/internal/retention"
	"binaryscan/internal/sampleexport"
	"binaryscan/internal/storageguard"
	"binaryscan/internal/systemstatus"
	"binaryscan/internal/task"
	"binaryscan/internal/taskevent"
	"binaryscan/internal/upload"
	"binaryscan/internal/useradmin"
	"binaryscan/internal/vulnerability"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		slog.New(slog.NewJSONHandler(os.Stderr, nil)).Error("api stopped", "error", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	command := "serve"
	if len(args) > 0 {
		command = args[0]
		args = args[1:]
	}
	if len(args) != 0 {
		return errors.New("api command does not accept additional arguments")
	}
	if command != "serve" && command != "healthcheck" {
		return errors.New("api command must be serve or healthcheck")
	}
	cfg, err := config.Load("api")
	if err != nil {
		return fmt.Errorf("load configuration: %w", err)
	}
	if command == "healthcheck" {
		return healthcheck.CheckAPI(context.Background(), cfg.HTTPAddr, cfg.DatabasePingTimeout)
	}
	logger, closer, err := logging.New(cfg.Service, cfg.LogLevel, cfg.LogDir)
	if err != nil {
		return fmt.Errorf("initialize logging: %w", err)
	}
	defer closer.Close()

	db, err := database.Open(cfg)
	if err != nil {
		return err
	}
	defer db.Close()
	auditRepository := audit.NewMySQLRepository(db)
	auditService, err := audit.NewService(auditRepository)
	if err != nil {
		return fmt.Errorf("initialize audit logs: %w", err)
	}
	passwordParameters := auth.PasswordParameters{
		MemoryKiB: cfg.Argon2MemoryKiB, Iterations: cfg.Argon2Iterations,
		Parallelism: cfg.Argon2Parallelism, SaltLength: 16, KeyLength: 32,
	}
	authService, err := auth.NewService(auth.NewMySQLRepository(db), auth.ServiceConfig{
		PasswordParameters:   passwordParameters,
		MinimumPasswordBytes: cfg.AuthPasswordMinimumBytes,
		SessionTTL:           cfg.SessionTTL, FailureThreshold: cfg.LoginFailureThreshold,
		LockDuration: cfg.LoginLockDuration,
		LoginRateLimit: auth.LoginRateLimitPolicy{
			Threshold:     cfg.LoginRateLimitThreshold,
			Window:        cfg.LoginRateLimitWindow,
			BlockDuration: cfg.LoginRateLimitBlock,
		},
		LoginAudit: audit.LoginRecorder{Recorder: auditRepository},
	})
	if err != nil {
		return fmt.Errorf("initialize authentication: %w", err)
	}
	userAdminService, err := useradmin.NewService(
		useradmin.NewMySQLRepository(db),
		auditRepository,
		useradmin.ServiceConfig{
			PasswordParameters:   passwordParameters,
			MinimumPasswordBytes: cfg.AuthPasswordMinimumBytes,
		},
	)
	if err != nil {
		return fmt.Errorf("initialize user administration: %w", err)
	}
	systemStatusService, err := systemstatus.NewService(
		systemstatus.NewMySQLRepository(db),
		systemstatus.Config{
			Service:                 cfg.Service,
			Build:                   buildinfo.Current(),
			UploadsRoot:             cfg.UploadsRoot,
			RepositoryRoot:          cfg.RepositoryRoot,
			TaskWorkRoot:            cfg.TaskWorkRoot,
			StorageMinFreeBytes:     cfg.StorageMinFreeBytes,
			AnalyzerHeartbeatMaxAge: 3 * cfg.HeartbeatInterval,
			Analyzers: []systemstatus.AnalyzerRegistration{
				{
					Name: "vineflower-cfr-jadx",
					Version: bytecode.DefaultVineflowerVersion + "+" +
						bytecode.DefaultCFRVersion + "+" + bytecode.DefaultJADXVersion,
					Scope:               "jvm_android_python",
					RequiredWorkerKinds: []string{"bytecode"},
				},
				{
					Name: "ghidra", Version: cfg.GhidraVersion,
					Scope:               "native_binary",
					RequiredWorkerKinds: []string{"native"},
				},
				{
					Name: "trivy", Version: cfg.TrivyVersion,
					Scope:               "container_image",
					RequiredWorkerKinds: []string{"image", "trivy"},
				},
				{
					Name: canalysis.AnalyzerName, Version: cfg.CCheckerVersion,
					Scope:               "ghidra_pseudoc_security",
					RequiredWorkerKinds: []string{"c_analysis"},
				},
				{
					Name: javaanalysis.AnalyzerName, Version: cfg.JavaCheckerVersion,
					Scope:               "decompiled_java_security",
					RequiredWorkerKinds: []string{"java_analysis"},
				},
			},
		},
	)
	if err != nil {
		return fmt.Errorf("initialize system status: %w", err)
	}
	uploadStorageChecker, err := storageguard.NewChecker(storageguard.Config{
		UploadsRoot:      cfg.UploadsRoot,
		RepositoryRoot:   cfg.RepositoryRoot,
		MinimumFreeBytes: cfg.StorageMinFreeBytes,
	})
	if err != nil {
		return fmt.Errorf("initialize upload storage guard: %w", err)
	}
	uploadPartDeleter, err := retention.NewRepositoryUploadDirectoryDeleter(
		cfg.UploadsRoot,
	)
	if err != nil {
		return fmt.Errorf("initialize upload part cleanup: %w", err)
	}
	archiveImportRepository, err := archiveimport.NewMySQLRepository(db)
	if err != nil {
		return fmt.Errorf("initialize archive import repository: %w", err)
	}
	archiveImportStorage, err := archiveimport.NewBlobStorage(cfg.RepositoryRoot)
	if err != nil {
		return fmt.Errorf("initialize archive import storage: %w", err)
	}
	var archiveImportService *archiveimport.Service
	var taskService *task.Service
	uploadService, err := upload.NewService(upload.NewMySQLRepository(db), upload.Config{
		UploadsRoot: cfg.UploadsRoot, RepositoryRoot: cfg.RepositoryRoot,
		MaxUploadBytes: cfg.MaxUploadBytes, PartSize: upload.DefaultPartSize,
		Retention:     cfg.IncompleteUploadRetention,
		CapacityGuard: uploadStorageChecker,
		PartDeleter:   uploadPartDeleter,
		EnsureArchiveImport: func(
			ctx context.Context,
			request upload.ArchiveImportRequest,
		) (string, error) {
			if archiveImportService == nil {
				return "", errors.New("archive import service is not initialized")
			}
			id, err := archiveImportService.EnsureForUpload(ctx, archiveimport.EnsureInput{
				UploadID: request.UploadID, CreatedBy: request.CreatedBy,
				Filename: request.Filename, Size: request.Size,
				SHA256: request.SHA256, DetectedFormat: request.DetectedFormat,
			})
			return id, mapArchiveImportUploadError(err)
		},
		EnsureDirectTask: func(
			ctx context.Context,
			request upload.DirectTaskRequest,
		) (string, error) {
			if taskService == nil {
				return "", errors.New("task service is not initialized")
			}
			value, _, err := taskService.Create(
				ctx, request.CreatedBy, auth.RoleOperator,
				request.UploadID, request.TaskName, request.IdempotencyKey,
			)
			return value.ID, err
		},
		DeleteArchiveImport: func(
			ctx context.Context,
			request upload.ArchiveImportDeleteRequest,
		) error {
			if archiveImportService == nil {
				return errors.New("archive import service is not initialized")
			}
			return mapArchiveImportUploadError(archiveImportService.DeleteForUpload(
				ctx, request.UploadID, request.Actor,
			))
		},
	})
	if err != nil {
		return fmt.Errorf("initialize uploads: %w", err)
	}
	taskService, err = task.NewService(task.NewMySQLRepository(db), task.ServiceConfig{
		Limits: task.LimitsSnapshot{
			MaxUploadBytes: cfg.MaxUploadBytes, MaxExpandedBytes: cfg.MaxExpandedBytes,
			MaxArchiveRatio: cfg.MaxArchiveRatio, MaxDepth: cfg.MaxDepth,
			MaxFileNodes: cfg.MaxFileNodes, MaxNestedImages: cfg.MaxNestedImages,
		},
		SampleRetention: cfg.SampleRetention,
	})
	if err != nil {
		return fmt.Errorf("initialize tasks: %w", err)
	}
	archiveImportService, err = archiveimport.NewService(
		archiveImportRepository,
		archiveimport.ServiceConfig{
			Limits: archiveimport.Limits{
				MaxUploadBytes:   cfg.MaxUploadBytes,
				MaxExpandedBytes: cfg.MaxExpandedBytes,
				MaxArchiveRatio:  int64(cfg.MaxArchiveRatio),
				MaxEntries:       cfg.MaxFileNodes,
				MaxEntryBytes:    cfg.MaxUploadBytes,
				MaxDepth:         cfg.MaxDepth,
			},
			BatchLeaseDuration: cfg.QueueLeaseInterval,
			BatchRecoveryAge:   cfg.QueueLeaseInterval,
			DerivedUploads: archiveimport.UploadServiceAdapter{
				Service: uploadService,
			},
			DeleteDerived: archiveimport.UploadServiceAdapter{
				Service: uploadService,
			},
			Tasks: archiveimport.TaskServiceAdapter{
				Service: taskService,
			},
			Storage: archiveImportStorage,
		},
	)
	if err != nil {
		return fmt.Errorf("initialize archive imports: %w", err)
	}
	taskEventService, err := taskevent.NewService(
		taskevent.NewMySQLRepository(db),
	)
	if err != nil {
		return fmt.Errorf("initialize task events: %w", err)
	}
	fileTreeService, err := filetree.NewService(filetree.NewMySQLRepository(db))
	if err != nil {
		return fmt.Errorf("initialize file tree: %w", err)
	}
	decompileService, err := decompile.NewService(
		decompile.NewMySQLRepository(db),
		decompile.Config{RepositoryRoot: cfg.RepositoryRoot},
	)
	if err != nil {
		return fmt.Errorf("initialize decompile results: %w", err)
	}
	cAnalysisRepository, err := canalysis.NewMySQLRepository(
		db,
		canalysis.RepositoryConfig{
			AnalyzerVersion: cfg.CCheckerVersion,
			ReadyMaxAge:     3 * cfg.HeartbeatInterval,
		},
	)
	if err != nil {
		return fmt.Errorf("initialize C analysis repository: %w", err)
	}
	cAnalysisRunDeleter, err := report.NewCAnalysisRunCascadeDeleter(
		db, cfg.RepositoryRoot,
	)
	if err != nil {
		return fmt.Errorf("initialize C analysis run deletion: %w", err)
	}
	cAnalysisService, err := canalysis.NewService(
		cAnalysisRepository,
		canalysis.Config{RunDeleter: cAnalysisRunDeleter},
	)
	if err != nil {
		return fmt.Errorf("initialize C analysis service: %w", err)
	}
	javaAnalysisRepository, err := javaanalysis.NewMySQLRepository(
		db,
		javaanalysis.RepositoryConfig{
			AnalyzerVersion: cfg.JavaCheckerVersion,
			ReadyMaxAge:     3 * cfg.HeartbeatInterval,
			InvalidateReports: func(ctx context.Context, tx *sql.Tx, taskID string) error {
				return report.InvalidateTaskSourceAnalysisReports(ctx, tx, taskID)
			},
		},
	)
	if err != nil {
		return fmt.Errorf("initialize Java analysis repository: %w", err)
	}
	javaAnalysisRunDeleter, err := report.NewJavaAnalysisRunCascadeDeleter(
		db, cfg.RepositoryRoot,
	)
	if err != nil {
		return fmt.Errorf("initialize Java analysis run deletion: %w", err)
	}
	javaAnalysisService, err := javaanalysis.NewService(
		javaAnalysisRepository,
		javaanalysis.Config{RunDeleter: javaAnalysisRunDeleter},
	)
	if err != nil {
		return fmt.Errorf("initialize Java analysis service: %w", err)
	}
	manualImageScanService, err := manualimagescan.NewService(
		manualimagescan.NewMySQLRepository(db),
		manualimagescan.Config{},
	)
	if err != nil {
		return fmt.Errorf("initialize manual image scans: %w", err)
	}
	vulnerabilityService, err := vulnerability.NewService(
		vulnerability.NewMySQLRepository(db),
	)
	if err != nil {
		return fmt.Errorf("initialize vulnerability results: %w", err)
	}
	reportService, err := report.NewService(
		report.NewMySQLRepository(db),
		report.Config{
			RepositoryRoot: cfg.RepositoryRoot,
			LeaseDuration:  cfg.QueueLeaseInterval,
		},
	)
	if err != nil {
		return fmt.Errorf("initialize reports: %w", err)
	}
	var sampleExportService api.SampleExportService
	if cfg.RawSampleDownloadEnabled {
		sampleExportService, err = sampleexport.NewService(
			sampleexport.NewMySQLRepository(db),
			sampleexport.Config{RepositoryRoot: cfg.RepositoryRoot},
		)
		if err != nil {
			return fmt.Errorf("initialize sample export: %w", err)
		}
	}

	router, err := api.NewRouter(api.Dependencies{
		Logger:           logger,
		Database:         database.NewReadiness(db),
		ReadinessTimeout: cfg.DatabasePingTimeout,
		TrustedProxies:   cfg.TrustedProxies,
		Auth:             authService,
		AuthHTTP: api.AuthHTTPConfig{
			CookieSecure: cfg.CookieSecure,
			SessionTTL:   cfg.SessionTTL,
		},
		Uploads:             uploadService,
		ArchiveImports:      archiveImportService,
		Tasks:               taskService,
		TaskEvents:          taskEventService,
		FileTree:            fileTreeService,
		Decompile:           decompileService,
		CAnalysis:           cAnalysisService,
		JavaAnalysis:        javaAnalysisService,
		ManualImageScan:     manualImageScanService,
		Vulnerabilities:     vulnerabilityService,
		Reports:             reportService,
		UserAdmin:           userAdminService,
		AuditLogs:           auditService,
		AuditRecorder:       auditRepository,
		SystemStatus:        systemStatusService,
		SampleExport:        sampleExportService,
		SampleExportEnabled: cfg.RawSampleDownloadEnabled,
		Build:               buildinfo.Current(),
	})
	if err != nil {
		return fmt.Errorf("initialize API router: %w", err)
	}

	server := &http.Server{
		Addr:              cfg.HTTPAddr,
		Handler:           router,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	serverErrors := make(chan error, 1)
	go func() {
		logger.Info("api listening", "address", cfg.HTTPAddr, "version", buildinfo.Version)
		serverErrors <- server.ListenAndServe()
	}()

	select {
	case err := <-serverErrors:
		if !errors.Is(err, http.ErrServerClosed) {
			return fmt.Errorf("serve HTTP: %w", err)
		}
		return nil
	case <-ctx.Done():
		logger.Info("api shutdown requested")
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), cfg.ShutdownTimeout)
	defer cancel()
	if err := server.Shutdown(shutdownCtx); err != nil {
		_ = server.Close()
		return fmt.Errorf("gracefully shut down API: %w", err)
	}
	if err := <-serverErrors; err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("serve HTTP during shutdown: %w", err)
	}
	logger.Info("api stopped")
	return nil
}

func mapArchiveImportUploadError(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, archiveimport.ErrInvalidInput):
		return upload.ErrInvalidInput
	case errors.Is(err, archiveimport.ErrNotFound):
		return upload.ErrNotFound
	case errors.Is(err, archiveimport.ErrForbidden):
		return upload.ErrForbidden
	case errors.Is(err, archiveimport.ErrConflict):
		return upload.ErrInvalidState
	default:
		return err
	}
}

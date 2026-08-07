package main

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"binaryscan/internal/auth"
	"binaryscan/internal/config"
	"binaryscan/internal/database"
	"binaryscan/internal/healthcheck"
	"binaryscan/internal/logging"
	maintenancerunner "binaryscan/internal/maintenance"
	"binaryscan/internal/orphanreaper"
	"binaryscan/internal/queue"
	"binaryscan/internal/report"
	"binaryscan/internal/retention"
	"binaryscan/internal/taskcleanup"
	"binaryscan/internal/workspace"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		slog.New(slog.NewJSONHandler(os.Stderr, nil)).Error("maintenance stopped", "error", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) > 0 {
		switch args[0] {
		case "run", "migrate", "healthcheck", "init-admin", "cleanup-expired":
			action := args[0]
			if action == "run" {
				action = "idle"
			}
			args = append([]string{"--action=" + action}, args[1:]...)
		}
	}
	flags := flag.NewFlagSet("maintenance", flag.ContinueOnError)
	action := flags.String("action", "idle", "maintenance action: idle, migrate, healthcheck, init-admin, or cleanup-expired")
	batchSize := flags.Int("batch-size", 100, "maximum expired records to process per category")
	adminUsername := flags.String("username", "admin", "initial administrator username")
	adminDisplayName := flags.String("display-name", "Administrator", "initial administrator display name")
	adminPasswordFile := flags.String("password-file", "", "initial administrator password secret file")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("maintenance does not accept positional arguments")
	}
	batchSizeSet := false
	flags.Visit(func(value *flag.Flag) {
		if value.Name == "batch-size" {
			batchSizeSet = true
		}
	})
	if *action != "idle" && *action != "migrate" && *action != "healthcheck" &&
		*action != "init-admin" && *action != "cleanup-expired" {
		return errors.New("--action must be idle, migrate, healthcheck, init-admin, or cleanup-expired")
	}
	if *batchSize < 1 || *batchSize > retention.MaxBatchSize {
		return fmt.Errorf("--batch-size must be between 1 and %d", retention.MaxBatchSize)
	}
	if batchSizeSet && *action != "cleanup-expired" {
		return errors.New("--batch-size is only valid with cleanup-expired")
	}

	cfg, err := config.Load("maintenance")
	if err != nil {
		return fmt.Errorf("load configuration: %w", err)
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
	if *action == "healthcheck" {
		return healthcheck.CheckDatabase(context.Background(), db, cfg.DatabasePingTimeout)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if *action == "cleanup-expired" {
		probeCtx, cancel := context.WithTimeout(ctx, cfg.DatabasePingTimeout)
		defer cancel()
		if err := database.NewReadiness(db).PingContext(probeCtx); err != nil {
			return fmt.Errorf("check cleanup database readiness: %w", err)
		}
		outputDeleter, err := taskcleanup.NewRepositoryFileDeleter(
			cfg.RepositoryRoot,
		)
		if err != nil {
			return fmt.Errorf("initialize cleanup output deletion: %w", err)
		}
		blobDeleter, uploadDeleter, err := newRetentionDeleters(cfg)
		if err != nil {
			return err
		}
		retentionSweeper, err := newRetentionSweeper(
			db, cfg, outputDeleter, blobDeleter, uploadDeleter,
		)
		if err != nil {
			return err
		}
		report, sweepErr := retentionSweeper.Sweep(ctx, *batchSize)
		result := newCleanupExpiredResult(*batchSize, report)
		if err := json.NewEncoder(os.Stdout).Encode(result); err != nil {
			return fmt.Errorf("write expired cleanup result: %w", err)
		}
		if sweepErr != nil {
			return fmt.Errorf("sweep expired data: %w", sweepErr)
		}
		return nil
	}
	if *action == "migrate" {
		if err := database.Migrate(ctx, db); err != nil {
			return err
		}
		logger.Info("database migrations complete")
		return nil
	}
	if *action == "init-admin" {
		if err := database.Migrate(ctx, db); err != nil {
			return err
		}
		passwordFile := *adminPasswordFile
		if passwordFile == "" {
			passwordFile = os.Getenv("BINARYSCAN_INITIAL_ADMIN_PASSWORD_FILE")
		}
		password, err := auth.ReadPasswordSecret(passwordFile)
		if err != nil {
			return err
		}
		defer clear(password)
		authService, err := auth.NewService(auth.NewMySQLRepository(db), auth.ServiceConfig{
			PasswordParameters: auth.PasswordParameters{
				MemoryKiB: cfg.Argon2MemoryKiB, Iterations: cfg.Argon2Iterations,
				Parallelism: cfg.Argon2Parallelism, SaltLength: 16, KeyLength: 32,
			},
			MinimumPasswordBytes: cfg.AuthPasswordMinimumBytes,
			SessionTTL:           cfg.SessionTTL, FailureThreshold: cfg.LoginFailureThreshold,
			LockDuration: cfg.LoginLockDuration,
			LoginRateLimit: auth.LoginRateLimitPolicy{
				Threshold:     cfg.LoginRateLimitThreshold,
				Window:        cfg.LoginRateLimitWindow,
				BlockDuration: cfg.LoginRateLimitBlock,
			},
		})
		if err != nil {
			return err
		}
		if err := authService.CreateInitialAdministrator(
			ctx, *adminUsername, *adminDisplayName, password,
		); err != nil {
			return err
		}
		logger.Info("initial administrator created", "username", *adminUsername)
		return nil
	}

	logger.Info("maintenance started")
	if err := database.Migrate(ctx, db); err != nil {
		return fmt.Errorf("apply startup database migrations: %w", err)
	}
	queueService, err := queue.NewService(
		queue.NewMySQLRepository(db),
		queue.Config{
			LeaseDuration:   cfg.QueueLeaseInterval,
			RetryDelay:      cfg.QueuePollInterval,
			SampleRetention: cfg.SampleRetention,
		},
	)
	if err != nil {
		return fmt.Errorf("initialize maintenance queue service: %w", err)
	}
	workspaceReaper, err := workspace.NewReaper(
		cfg.TaskWorkRoot,
		queueService,
	)
	if err != nil {
		return fmt.Errorf("initialize task workspace reaper: %w", err)
	}
	blobDeleter, uploadDeleter, err := newRetentionDeleters(cfg)
	if err != nil {
		return err
	}
	taskDeletionDeleter, err := taskcleanup.NewRepositoryFileDeleter(
		cfg.RepositoryRoot,
	)
	if err != nil {
		return fmt.Errorf("initialize task deletion file cleanup: %w", err)
	}
	taskDeletionOwner, err := taskcleanup.NewLeaseOwner(
		os.Getpid(),
		rand.Reader,
	)
	if err != nil {
		return fmt.Errorf("initialize task deletion lease owner: %w", err)
	}
	retentionSweeper, err := newRetentionSweeper(
		db, cfg, taskDeletionDeleter, blobDeleter, uploadDeleter,
	)
	if err != nil {
		return err
	}
	orphanSweeper, err := orphanreaper.NewSweeper(
		orphanreaper.NewMySQLRepository(db),
		orphanreaper.Config{
			RepositoryRoot: cfg.RepositoryRoot,
			UploadsRoot:    cfg.UploadsRoot,
			GracePeriod:    orphanreaper.DefaultGracePeriod,
			BlobDeleter:    blobDeleter,
			UploadDeleter:  uploadDeleter,
		},
	)
	if err != nil {
		return fmt.Errorf("initialize orphan reconciliation sweeper: %w", err)
	}
	taskDeletionSweeper, err := taskcleanup.NewSweeper(
		taskcleanup.NewMySQLRepository(db),
		taskDeletionDeleter,
		taskcleanup.Config{
			LeaseOwner: taskDeletionOwner, LeaseDuration: cfg.QueueLeaseInterval,
		},
	)
	if err != nil {
		return fmt.Errorf("initialize task deletion sweeper: %w", err)
	}
	runner, err := maintenancerunner.NewRunner(maintenancerunner.RunnerConfig{
		Interval: cfg.QueuePollInterval, PingTimeout: cfg.DatabasePingTimeout,
		Database: db, Queue: queueService,
		ReportGeneration: report.NewMySQLRepository(db),
		TaskDeletion:     taskDeletionSweeper,
		Retention:        retentionSweeper,
		Orphans:          orphanSweeper,
		Workspace:        workspaceReaper,
		Logger:           logger,
	})
	if err != nil {
		return fmt.Errorf("initialize maintenance runner: %w", err)
	}
	if err := runBackgroundLoops(
		ctx,
		namedLoop{name: "maintenance", run: runner.Run},
	); err != nil {
		return err
	}
	logger.Info("maintenance stopped")
	return nil
}

type cleanupExpiredResult struct {
	BatchSize             int `json:"batch_size"`
	TaskSamplesReleased   int `json:"task_samples_released"`
	UploadPartsCleaned    int `json:"upload_parts_cleaned"`
	UploadsExpired        int `json:"uploads_expired"`
	BlobsDeleted          int `json:"blobs_deleted"`
	DecompileFilesDeleted int `json:"decompile_files_deleted"`
	TaskSampleConflicts   int `json:"task_sample_conflicts"`
	Failures              int `json:"failures"`
}

func newCleanupExpiredResult(
	batchSize int,
	report retention.Report,
) cleanupExpiredResult {
	return cleanupExpiredResult{
		BatchSize:             batchSize,
		TaskSamplesReleased:   report.TaskSamplesReleased,
		UploadPartsCleaned:    report.UploadPartsCleaned,
		UploadsExpired:        report.UploadsExpired,
		BlobsDeleted:          report.BlobsDeleted,
		DecompileFilesDeleted: report.DecompileFilesDeleted,
		TaskSampleConflicts:   report.TaskSampleConflicts,
		Failures:              report.Failures,
	}
}

func newRetentionSweeper(
	db *sql.DB,
	cfg config.Config,
	outputDeleter taskcleanup.FileDeleter,
	blobDeleter retention.BlobDeleter,
	uploadDeleter retention.UploadDirectoryDeleter,
) (*retention.Sweeper, error) {
	leaseOwner, err := retention.NewLeaseOwner(os.Getpid(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("initialize sample retention lease owner: %w", err)
	}
	sweeper, err := retention.NewSweeper(
		retention.NewMySQLRepository(db),
		blobDeleter,
		uploadDeleter,
		retention.Config{
			LeaseOwner:    leaseOwner,
			LeaseDuration: cfg.QueueLeaseInterval,
			OutputDeleter: outputDeleter,
		},
	)
	if err != nil {
		return nil, fmt.Errorf("initialize retention sweeper: %w", err)
	}
	return sweeper, nil
}

func newRetentionDeleters(
	cfg config.Config,
) (retention.BlobDeleter, retention.UploadDirectoryDeleter, error) {
	blobDeleter, err := retention.NewRepositoryBlobDeleter(cfg.RepositoryRoot)
	if err != nil {
		return nil, nil, fmt.Errorf("initialize retained blob deletion: %w", err)
	}
	uploadDeleter, err := retention.NewRepositoryUploadDirectoryDeleter(
		cfg.UploadsRoot,
	)
	if err != nil {
		return nil, nil, fmt.Errorf("initialize expired upload deletion: %w", err)
	}
	return blobDeleter, uploadDeleter, nil
}

type namedLoop struct {
	name string
	run  func(context.Context) error
}

type loopResult struct {
	name string
	err  error
}

func runBackgroundLoops(ctx context.Context, loops ...namedLoop) error {
	if len(loops) == 0 {
		return errors.New("at least one maintenance loop is required")
	}
	child, cancel := context.WithCancel(ctx)
	defer cancel()
	results := make(chan loopResult, len(loops))
	for _, loop := range loops {
		if loop.name == "" || loop.run == nil {
			return errors.New("maintenance loop name and runner are required")
		}
	}
	for _, loop := range loops {
		current := loop
		go func() {
			results <- loopResult{
				name: current.name,
				err:  current.run(child),
			}
		}()
	}
	first := <-results
	cancel()
	for range len(loops) - 1 {
		<-results
	}
	if first.err != nil {
		if ctx.Err() != nil &&
			(errors.Is(first.err, context.Canceled) ||
				errors.Is(first.err, context.DeadlineExceeded)) {
			return nil
		}
		return fmt.Errorf("%s loop: %w", first.name, first.err)
	}
	if ctx.Err() == nil {
		return fmt.Errorf("%s loop stopped unexpectedly", first.name)
	}
	return nil
}

package trivyscan

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	trivyadapter "binaryscan/internal/analyzers/trivy"
	"binaryscan/internal/containerarchive"
	"binaryscan/internal/queue"
	"binaryscan/internal/storageguard"
	"binaryscan/internal/trivydb"
	"binaryscan/internal/workspace"
)

const (
	maxSupportedSourceBytes  = int64(10 * 1024 * 1024 * 1024)
	maxSupportedFindings     = 1_000_000
	maxAutomaticImageTargets = 10
)

type scanFailure struct {
	status        string
	code          string
	message       string
	deterministic bool
}

type sourcePlan struct {
	handoff    HandoffSource
	source     *sourceFile
	inspection containerarchive.Inspection
	ociPlan    *containerarchive.OCIPlan
}

type targetPlan struct {
	handoff HandoffSource
	target  containerarchive.Target
	source  trivyadapter.VerifiedSource
	limited bool
}

func NewProcessor(
	repository Repository,
	progress ProgressReporter,
	databases DatabaseProvider,
	newAdapter AdapterFactory,
	config Config,
) (*Processor, error) {
	if repository == nil || progress == nil || databases == nil || newAdapter == nil {
		return nil, fmt.Errorf(
			"%w: repository, progress reporter, database provider, and adapter factory are required",
			ErrInvalidConfiguration,
		)
	}
	repositoryRoot, repositoryOK := cleanAbsoluteRoot(config.RepositoryRoot)
	workRoot, workOK := cleanAbsoluteRoot(config.TaskWorkRoot)
	if !repositoryOK || !workOK || rootsOverlap(repositoryRoot, workRoot) {
		return nil, fmt.Errorf(
			"%w: repository and task-work roots must be disjoint absolute paths",
			ErrInvalidConfiguration,
		)
	}
	if config.MaxSourceBytes <= 0 ||
		config.MaxSourceBytes > maxSupportedSourceBytes ||
		config.MaxExpandedBytes < config.MaxSourceBytes ||
		config.MaxExpandedBytes > maxSupportedExpandedBytes ||
		config.MaxReportBytes <= 0 ||
		config.MaxReportBytes > maxSupportedReportBytes ||
		config.MaxPublishedFindings <= 0 ||
		config.MaxPublishedFindings > maxSupportedFindings ||
		config.StorageMinFreeBytes <= 0 ||
		!analyzerVersionPattern.MatchString(config.AnalyzerVersion) ||
		(config.JavaDBPolicy != trivydb.JavaDBOptional &&
			config.JavaDBPolicy != trivydb.JavaDBRequired) ||
		!validArchiveLimits(config.ArchiveLimits) {
		return nil, fmt.Errorf(
			"%w: analyzer identity, database policy, or limits are invalid",
			ErrInvalidConfiguration,
		)
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	if config.ArchiveLimits.MaxArchiveRatio == 0 {
		config.ArchiveLimits.MaxArchiveRatio = 100
	}
	config.RepositoryRoot = repositoryRoot
	config.TaskWorkRoot = workRoot
	guard := config.StorageGuard
	if guard == nil {
		createdGuard, err := storageguard.NewChecker(storageguard.Config{
			UploadsRoot:      workRoot,
			RepositoryRoot:   repositoryRoot,
			MinimumFreeBytes: config.StorageMinFreeBytes,
		})
		if err != nil {
			return nil, fmt.Errorf(
				"%w: create Trivy storage guard: %v",
				ErrInvalidConfiguration,
				err,
			)
		}
		guard = createdGuard
	}
	processor := &Processor{
		repository: repository,
		progress:   progress,
		databases:  databases,
		newAdapter: newAdapter,
		config:     config,
		storage:    guard,
	}
	processor.newWorkspace = func(root string, lease queue.Lease) (workDirectory, error) {
		if lease.TaskAttemptID == nil {
			return nil, errors.New("Trivy workspace requires a task attempt")
		}
		return workspace.Create(root, workspace.Identity{
			JobID: lease.JobID, TaskID: lease.TaskID,
			TaskAttemptID: *lease.TaskAttemptID,
			FencingToken:  lease.FencingToken,
			Kind:          string(lease.Kind),
		})
	}
	return processor, nil
}

func (p *Processor) Process(
	ctx context.Context,
	lease queue.Lease,
) (finish queue.FinishInput, returnErr error) {
	if ctx == nil {
		return queue.FinishInput{}, errors.New("Trivy processor context is nil")
	}
	if (lease.Kind != queue.KindTrivy && lease.Kind != queue.KindImage) ||
		lease.TaskAttemptID == nil ||
		lease.JobID == "" || lease.TaskID == "" || lease.Owner == "" ||
		lease.FencingToken == 0 || lease.Attempt == 0 {
		return queue.FinishInput{}, errors.New(
			"Trivy processor requires an exact image-scanning lease",
		)
	}
	p.emitActivity(ctx, lease, "trivy.progress", "info", trivyActivityPayload{
		Analyzer: "trivy", Phase: "verifying",
	})
	defer func() {
		if returnErr == nil &&
			finish.Outcome != queue.OutcomeDeterministicFailure &&
			finish.Outcome != queue.OutcomeTransientFailure {
			return
		}
		code := finish.ErrorCode
		if code == "" {
			code = "trivy_execution_failed"
			if errors.Is(returnErr, context.Canceled) {
				code = "trivy_context_cancelled"
			} else if errors.Is(returnErr, context.DeadlineExceeded) {
				code = "trivy_timeout"
			}
		}
		p.emitActivity(ctx, lease, "trivy.failed", "error", trivyActivityPayload{
			Analyzer: "trivy", Phase: "failed", ErrorCode: code,
		})
	}()
	payload, err := DecodePayload(lease.Payload, p.config.MaxSourceBytes)
	if err != nil {
		return deterministicFinish(
			"trivy_handoff_invalid",
			"The image scan handoff is invalid.",
		), nil
	}
	maxExpandedBytes := payload.MaxExpandedBytes
	maxArchiveRatio := payload.MaxArchiveRatio
	if payload.SchemaVersion == PayloadSchemaVersion {
		maxExpandedBytes = p.config.MaxExpandedBytes
		maxArchiveRatio = p.config.ArchiveLimits.MaxArchiveRatio
	}
	if maxExpandedBytes <= 0 ||
		maxExpandedBytes > maxSupportedExpandedBytes ||
		maxArchiveRatio <= 0 ||
		maxArchiveRatio > 100 {
		return deterministicFinish(
			"trivy_handoff_invalid",
			"The image scan handoff limits are invalid.",
		), nil
	}
	archiveLimits := p.config.ArchiveLimits
	archiveLimits.MaxArchiveRatio = maxArchiveRatio
	plans := make([]sourcePlan, 0, len(payload.Sources))
	defer func() {
		for index := range plans {
			if closeErr := plans[index].source.close(); closeErr != nil {
				returnErr = errors.Join(
					returnErr,
					fmt.Errorf("close Trivy source: %w", closeErr),
				)
				finish = queue.FinishInput{}
			}
		}
	}()
	for _, handoff := range payload.Sources {
		source, openErr := openRepositorySource(
			p.config.RepositoryRoot,
			handoff,
		)
		if openErr != nil {
			return finishForSourceError(openErr), nil
		}
		plan := sourcePlan{handoff: handoff, source: source}
		plans = append(plans, plan)
		if verifyErr := source.verify(ctx); verifyErr != nil {
			if ctx.Err() != nil {
				return queue.FinishInput{}, ctx.Err()
			}
			return finishForSourceError(verifyErr), nil
		}
		switch handoff.Format {
		case containerarchive.FormatDocker:
			plans[len(plans)-1].inspection, err = containerarchive.Inspect(
				ctx,
				source.file,
				source.size,
				containerarchive.FormatDocker,
				archiveLimits,
			)
			if err == nil &&
				len(plans[len(plans)-1].inspection.Targets) != 1 {
				return deterministicFinish(
					"docker_multi_image_unsupported",
					"Docker Save archives must contain exactly one image.",
				), nil
			}
		case containerarchive.FormatOCI:
			plans[len(plans)-1].ociPlan, err = containerarchive.PlanOCI(
				ctx,
				source.file,
				source.size,
				archiveLimits,
			)
			if err == nil {
				plans[len(plans)-1].inspection =
					plans[len(plans)-1].ociPlan.Inspection()
			}
		default:
			return deterministicFinish(
				"trivy_handoff_invalid",
				"The image scan handoff format is invalid.",
			), nil
		}
		if err != nil {
			if ctx.Err() != nil {
				return queue.FinishInput{}, ctx.Err()
			}
			return finishForArchiveError(err), nil
		}
	}
	quota, err := buildQuotaPlan(
		ctx,
		plans,
		maxExpandedBytes,
		p.config.MaxReportBytes,
	)
	if err != nil {
		if ctx.Err() != nil {
			return queue.FinishInput{}, ctx.Err()
		}
		var limit *quotaLimitError
		if errors.As(err, &limit) &&
			validErrorCode(limit.code) &&
			validMessage(limit.message) {
			return deterministicFinish(limit.code, limit.message), nil
		}
		var archiveErr *containerarchive.Error
		if errors.As(err, &archiveErr) {
			return finishForArchiveError(err), nil
		}
		return queue.FinishInput{}, fmt.Errorf(
			"plan Trivy temporary storage: %w",
			err,
		)
	}
	releaseStorage, err := p.storage.ReservePlan(
		ctx,
		quota.WorkBytes,
		quota.RepositoryBytes,
	)
	if err != nil {
		if ctx.Err() != nil {
			return queue.FinishInput{}, ctx.Err()
		}
		return transientFinish(
			"trivy_storage_low",
			"Image scanning is paused because storage is below its low-water mark.",
		), nil
	}
	if releaseStorage == nil {
		return queue.FinishInput{}, errors.New(
			"Trivy storage guard returned an empty release function",
		)
	}
	defer releaseStorage()

	work, err := p.newWorkspace(p.config.TaskWorkRoot, lease)
	if err != nil {
		return queue.FinishInput{}, fmt.Errorf("create Trivy workspace: %w", err)
	}
	defer func() {
		if cleanupErr := work.Cleanup(); cleanupErr != nil {
			returnErr = errors.Join(
				returnErr,
				fmt.Errorf("cleanup Trivy workspace: %w", cleanupErr),
			)
			finish = queue.FinishInput{}
		}
	}()
	inputRoot, outputRoot, err := createSiblingRoots(work.Path())
	if err != nil {
		return queue.FinishInput{}, err
	}

	view, err := p.databases(ctx, work.Path(), p.config.JavaDBPolicy)
	if err != nil {
		if ctx.Err() != nil {
			return queue.FinishInput{}, ctx.Err()
		}
		return finishForDatabaseError(err), nil
	}
	if view == nil || view.Path() == "" {
		return queue.FinishInput{}, errors.New("database provider returned an empty view")
	}
	defer func() {
		if closeErr := view.Close(); closeErr != nil {
			returnErr = errors.Join(
				returnErr,
				fmt.Errorf("close Trivy database view: %w", closeErr),
			)
			finish = queue.FinishInput{}
		}
	}()
	snapshot := view.Snapshot()
	databasePayload := trivyActivityPayload{
		Analyzer: "trivy", Phase: "database_ready",
		DatabaseVersion: snapshot.Trivy.Version,
	}
	if snapshot.Java != nil {
		databasePayload.JavaDatabaseVersion = snapshot.Java.Version
	}
	p.emitActivity(ctx, lease, "trivy.progress", "info", databasePayload)
	adapter, err := p.newAdapter(
		view.Path(),
		outputRoot,
		[]string{inputRoot},
		quota.AdapterWorkBytes,
	)
	if err != nil {
		return queue.FinishInput{}, fmt.Errorf("create Trivy adapter: %w", err)
	}

	targets := make([]targetPlan, 0, len(plans))
	targetLimitRecorded := false
	for sourceIndex, plan := range plans {
		if len(targets) >= maxAutomaticImageTargets {
			if !targetLimitRecorded && len(plan.inspection.Targets) > 0 {
				targets = append(targets, targetPlan{
					handoff: plan.handoff,
					target:  plan.inspection.Targets[0],
					limited: true,
				})
				targetLimitRecorded = true
			}
			continue
		}
		sourceInputRoot := filepath.Join(
			inputRoot,
			fmt.Sprintf("source-%02d", sourceIndex+1),
		)
		if err := makePrivateDirectory(sourceInputRoot); err != nil {
			return queue.FinishInput{}, err
		}
		switch plan.handoff.Format {
		case containerarchive.FormatDocker:
			if len(targets) >= maxAutomaticImageTargets {
				if !targetLimitRecorded {
					targets = append(targets, targetPlan{
						handoff: plan.handoff,
						target:  plan.inspection.Targets[0],
						limited: true,
					})
					targetLimitRecorded = true
				}
				continue
			}
			verifiedPath, copyErr := plan.source.copyVerified(
				ctx,
				sourceInputRoot,
				"docker-save.tar",
			)
			if copyErr != nil {
				if ctx.Err() != nil {
					return queue.FinishInput{}, ctx.Err()
				}
				return finishForSourceError(copyErr), nil
			}
			verified, verifyErr := trivyadapter.VerifyDockerSaveTAR(verifiedPath)
			if verifyErr != nil {
				return deterministicFinish(
					"docker_archive_verification_failed",
					"The verified Docker Save input was rejected.",
				), nil
			}
			targets = append(targets, targetPlan{
				handoff: plan.handoff,
				target:  plan.inspection.Targets[0],
				source:  verified,
			})
		case containerarchive.FormatOCI:
			layoutPath := filepath.Join(sourceInputRoot, "oci-layout")
			if err := plan.ociPlan.Materialize(ctx, layoutPath); err != nil {
				if ctx.Err() != nil {
					return queue.FinishInput{}, ctx.Err()
				}
				return finishForArchiveError(err), nil
			}
			for _, target := range plan.inspection.Targets {
				if len(targets) >= maxAutomaticImageTargets {
					if !targetLimitRecorded {
						targets = append(targets, targetPlan{
							handoff: plan.handoff,
							target:  target,
							limited: true,
						})
						targetLimitRecorded = true
					}
					break
				}
				verified, verifyErr := trivyadapter.VerifyOCILayoutTarget(
					layoutPath,
					target.ManifestDigest,
				)
				if verifyErr != nil {
					return deterministicFinish(
						"oci_target_verification_failed",
						"A materialized OCI target was rejected.",
					), nil
				}
				targets = append(targets, targetPlan{
					handoff: plan.handoff,
					target:  target,
					source:  verified,
				})
			}
		default:
			return queue.FinishInput{}, errors.New(
				"unreachable Trivy source format",
			)
		}
	}
	return p.scanAndPublish(
		ctx,
		lease,
		payload,
		snapshot,
		adapter,
		targets,
		outputRoot,
	)
}

func (p *Processor) scanAndPublish(
	ctx context.Context,
	lease queue.Lease,
	payload HandoffPayload,
	snapshot trivydb.Snapshot,
	adapter Analyzer,
	targets []targetPlan,
	outputRoot string,
) (queue.FinishInput, error) {
	if len(targets) == 0 {
		return queue.FinishInput{}, errors.New("Trivy target plan is inconsistent")
	}
	startedAt := p.config.Now().UTC()
	runs := make([]RunResult, 0, len(targets))
	successes := 0
	transientFailures := 0
	publishedFindingCount := 0
	p.emitActivity(ctx, lease, "trivy.progress", "info", trivyActivityPayload{
		Analyzer: "trivy", Phase: "targets_ready", Total: len(targets),
	})
	for targetIndex, plan := range targets {
		if err := ctx.Err(); err != nil {
			return queue.FinishInput{}, err
		}
		targetKey := stableTargetKey(plan.handoff, plan.target)
		directoryName := "target-" + strings.TrimPrefix(targetKey, "sha256:")
		run := RunResult{
			TargetKey:        targetKey,
			SourceFormat:     plan.handoff.Format,
			SourceStorageKey: plan.handoff.SourceStorageKey,
			SourceSHA256:     plan.handoff.SourceSHA256,
			SourceSizeBytes:  plan.handoff.SourceSizeBytes,
			ImageLogicalPath: plan.handoff.ImageLogicalPath,
			Platform:         plan.target.Platform.String(),
			ManifestDigest:   plan.target.ManifestDigest,
			References:       append([]string(nil), plan.target.References...),
		}
		if plan.limited {
			run.Status = "failed"
			run.ErrorCode = "trivy_target_limit"
			run.ErrorMessage =
				"The automatic image target limit was exceeded; remaining targets were not scanned."
			runs = append(runs, run)
			p.emitActivity(ctx, lease, "trivy.target_failed", "warning", trivyActivityPayload{
				Analyzer: "trivy", Phase: "target_failed",
				Current: targetIndex + 1, Total: len(targets),
				ErrorCode: run.ErrorCode,
			})
			continue
		}
		outputDirectory := filepath.Join(outputRoot, directoryName)
		if err := makePrivateDirectory(outputDirectory); err != nil {
			return queue.FinishInput{}, err
		}
		report, analyzeErr := p.analyzeTargetWithActivity(
			ctx, lease, targetIndex+1, len(targets), adapter,
			trivyadapter.Request{
				Source:        plan.source,
				WorkDirectory: outputDirectory,
			},
		)
		if analyzeErr != nil {
			if ctx.Err() != nil {
				return queue.FinishInput{}, ctx.Err()
			}
			failure := classifyAnalyzerFailure(analyzeErr)
			run.Status = failure.status
			run.ErrorCode = failure.code
			run.ErrorMessage = failure.message
			if !failure.deterministic {
				transientFailures++
			}
			runs = append(runs, run)
			p.emitActivity(ctx, lease, "trivy.target_failed", "warning", trivyActivityPayload{
				Analyzer: "trivy", Phase: "target_failed",
				Current: targetIndex + 1, Total: len(targets),
				ErrorCode: run.ErrorCode,
			})
			continue
		}
		if len(report.Findings) >
			p.config.MaxPublishedFindings-publishedFindingCount {
			run.Status = "failed"
			run.ErrorCode = "trivy_finding_limit"
			run.ErrorMessage = "The normalized finding limit was exceeded."
			runs = append(runs, run)
			continue
		}
		raw := report.Raw
		run.Status = "succeeded"
		run.Raw = &raw
		run.Findings = append(
			[]trivyadapter.Finding(nil),
			report.Findings...,
		)
		publishedFindingCount += len(run.Findings)
		successes++
		runs = append(runs, run)
		p.emitActivity(ctx, lease, "trivy.target_completed", "info", trivyActivityPayload{
			Analyzer: "trivy", Phase: "target_completed",
			Current: targetIndex + 1, Total: len(targets),
			FindingCount: len(run.Findings),
		})
	}
	if err := ctx.Err(); err != nil {
		return queue.FinishInput{}, err
	}
	// Every source is re-opened after all scans so a mutated retained blob can
	// never authorize the shared result transaction.
	for _, handoff := range payload.Sources {
		source, openErr := openRepositorySource(
			p.config.RepositoryRoot,
			handoff,
		)
		if openErr != nil {
			return finishForSourceError(openErr), nil
		}
		verifyErr := source.verify(ctx)
		closeErr := source.close()
		if verifyErr != nil || closeErr != nil {
			if ctx.Err() != nil {
				return queue.FinishInput{}, ctx.Err()
			}
			return finishForSourceError(
				errors.Join(verifyErr, closeErr),
			), nil
		}
	}
	completedAt := p.config.Now().UTC()
	p.emitActivity(ctx, lease, "trivy.progress", "info", trivyActivityPayload{
		Analyzer: "trivy", Phase: "publishing",
		Current: len(targets), Total: len(targets),
		FindingCount: publishedFindingCount,
	})
	if lease.Kind == queue.KindTrivy {
		if err := p.progress.TaskProgress(ctx, lease, queue.ProgressInput{
			TaskStatus: "REPORTING",
			Stage:      "REPORTING",
		}); err != nil {
			return queue.FinishInput{}, fmt.Errorf(
				"advance Trivy task to reporting: %w",
				err,
			)
		}
	}
	firstSource := payload.Sources[0]
	publication := Publication{
		AnalyzerVersion:  p.config.AnalyzerVersion,
		SourceFormat:     firstSource.Format,
		SourceSHA256:     firstSource.SourceSHA256,
		SourceStorageKey: firstSource.SourceStorageKey,
		StartedAt:        startedAt,
		CompletedAt:      completedAt,
		Snapshot:         snapshot,
		Runs:             runs,
	}
	effective := PublishSummary{
		Succeeded:         successes,
		Failed:            len(runs) - successes,
		TransientFailures: transientFailures,
	}
	var publishErr error
	if repository, ok := p.repository.(SummaryRepository); ok {
		effective, publishErr = repository.PublishWithSummary(
			ctx,
			lease,
			publication,
		)
	} else {
		publishErr = p.repository.Publish(ctx, lease, publication)
	}
	if publishErr != nil {
		return queue.FinishInput{}, fmt.Errorf(
			"publish Trivy results: %w",
			publishErr,
		)
	}
	if effective.Succeeded+effective.Failed != len(runs) {
		return queue.FinishInput{}, errors.New(
			"Trivy repository returned an inconsistent publication summary",
		)
	}
	if effective.Succeeded == len(runs) {
		p.emitActivity(ctx, lease, "trivy.completed", "info", trivyActivityPayload{
			Analyzer: "trivy", Phase: "completed",
			Current: len(targets), Total: len(targets),
			FindingCount: publishedFindingCount,
		})
		if payload.UpstreamPartial {
			return queue.FinishInput{Outcome: queue.OutcomePartialSucceeded}, nil
		}
		return queue.FinishInput{Outcome: queue.OutcomeSucceeded}, nil
	}
	if effective.Succeeded > 0 {
		p.emitActivity(ctx, lease, "trivy.completed", "warning", trivyActivityPayload{
			Analyzer: "trivy", Phase: "completed",
			Current: len(targets), Total: len(targets),
			FindingCount: publishedFindingCount,
		})
		return queue.FinishInput{Outcome: queue.OutcomePartialSucceeded}, nil
	}
	if effective.TransientFailures > 0 {
		return transientFinish(
			"trivy_scan_failed",
			"All image vulnerability scan targets failed.",
		), nil
	}
	return deterministicFinish(
		"trivy_scan_rejected",
		"All image vulnerability scan targets were rejected.",
	), nil
}

const trivyActivityHeartbeatInterval = 30 * time.Second

type trivyActivityPayload struct {
	Analyzer            string `json:"analyzer"`
	Phase               string `json:"phase"`
	Current             int    `json:"current,omitempty"`
	Total               int    `json:"total,omitempty"`
	ElapsedSeconds      int64  `json:"elapsed_seconds,omitempty"`
	FindingCount        int    `json:"finding_count,omitempty"`
	DatabaseVersion     string `json:"database_version,omitempty"`
	JavaDatabaseVersion string `json:"java_database_version,omitempty"`
	ErrorCode           string `json:"error_code,omitempty"`
}

func (p *Processor) analyzeTargetWithActivity(
	ctx context.Context,
	lease queue.Lease,
	current int,
	total int,
	analyzer Analyzer,
	request trivyadapter.Request,
) (trivyadapter.Report, error) {
	startedAt := time.Now()
	p.emitActivity(ctx, lease, "trivy.progress", "info", trivyActivityPayload{
		Analyzer: "trivy", Phase: "scanning", Current: current, Total: total,
	})
	stop := make(chan struct{})
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		ticker := time.NewTicker(trivyActivityHeartbeatInterval)
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				return
			case <-ticker.C:
				p.emitActivity(ctx, lease, "trivy.progress", "info", trivyActivityPayload{
					Analyzer: "trivy", Phase: "scanning",
					Current: current, Total: total,
					ElapsedSeconds: int64(time.Since(startedAt) / time.Second),
				})
			}
		}
	}()
	report, err := analyzer.Analyze(ctx, request)
	close(stop)
	<-finished
	return report, err
}

func (p *Processor) emitActivity(
	ctx context.Context,
	lease queue.Lease,
	eventType string,
	severity string,
	payload trivyActivityPayload,
) {
	encoded, err := json.Marshal(payload)
	if err != nil {
		return
	}
	message := "Trivy scan progress changed."
	switch payload.Phase {
	case "verifying":
		message = "The image archive is being verified."
	case "database_ready":
		message = "The fixed vulnerability database Bundle is ready."
	case "targets_ready":
		message = "Image scan targets are ready."
	case "scanning":
		message = "Trivy is scanning an image target."
	case "target_completed":
		message = "An image target scan completed."
	case "target_failed":
		message = "An image target scan failed."
	case "publishing":
		message = "Trivy findings are being published."
	case "completed":
		message = "Trivy vulnerability scanning completed."
	case "failed":
		message = "Trivy vulnerability scanning failed."
	}
	_ = p.progress.TaskActivity(ctx, lease, queue.ActivityInput{
		EventType: eventType,
		Severity:  severity,
		Message:   message,
		Payload:   encoded,
	})
}

func stableTargetKey(
	source HandoffSource,
	target containerarchive.Target,
) string {
	hasher := sha256.New()
	_, _ = hasher.Write([]byte(source.Format))
	_, _ = hasher.Write([]byte{0})
	_, _ = hasher.Write([]byte(source.ImageLogicalPath))
	_, _ = hasher.Write([]byte{0})
	_, _ = hasher.Write([]byte(source.SourceSHA256))
	_, _ = hasher.Write([]byte{0})
	_, _ = hasher.Write([]byte(target.ManifestDigest))
	return "sha256:" + hex.EncodeToString(hasher.Sum(nil))
}

func createSiblingRoots(workspaceRoot string) (string, string, error) {
	inputRoot := filepath.Join(workspaceRoot, "input")
	outputRoot := filepath.Join(workspaceRoot, "output")
	if err := makePrivateDirectory(inputRoot); err != nil {
		return "", "", err
	}
	if err := makePrivateDirectory(outputRoot); err != nil {
		return "", "", err
	}
	return inputRoot, outputRoot, nil
}

func makePrivateDirectory(value string) error {
	if err := os.Mkdir(value, 0o700); err != nil {
		return fmt.Errorf("create private Trivy directory: %w", err)
	}
	info, err := os.Lstat(value)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 ||
		info.Mode().Perm() != 0o700 {
		return errors.New("private Trivy directory is unsafe")
	}
	return nil
}

func classifyAnalyzerFailure(err error) scanFailure {
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return scanFailure{
			status: "timed_out", code: "trivy_timeout",
			message: "The vulnerability scan timed out.",
		}
	case errors.Is(err, trivyadapter.ErrOutputLimit):
		return scanFailure{
			status: "failed", code: "trivy_output_limit",
			message: "The Trivy output limit was exceeded.", deterministic: true,
		}
	case errors.Is(err, trivyadapter.ErrInvalidInput):
		return scanFailure{
			status: "failed", code: "trivy_input_invalid",
			message: "The verified image target was rejected.", deterministic: true,
		}
	case errors.Is(err, trivyadapter.ErrInvalidReport):
		return scanFailure{
			status: "failed", code: "trivy_report_invalid",
			message:       "Trivy returned an invalid JSON report.",
			deterministic: true,
		}
	case errors.Is(err, trivyadapter.ErrExecutionFailed):
		return scanFailure{
			status: "failed", code: "trivy_execution_failed",
			message: "The Trivy process failed.",
		}
	default:
		return scanFailure{
			status: "failed", code: "trivy_internal_error",
			message: "The image vulnerability scan failed.",
		}
	}
}

func finishForArchiveError(err error) queue.FinishInput {
	var archiveErr *containerarchive.Error
	if errors.As(err, &archiveErr) &&
		validErrorCode(archiveErr.Code) &&
		validMessage(archiveErr.Message) {
		return deterministicFinish(archiveErr.Code, archiveErr.Message)
	}
	return deterministicFinish(
		"container_archive_invalid",
		"The container image archive is invalid.",
	)
}

func finishForSourceError(err error) queue.FinishInput {
	switch {
	case errors.Is(err, ErrSourceMismatch):
		return deterministicFinish(
			"trivy_source_mismatch",
			"The retained image does not match its handoff metadata.",
		)
	case errors.Is(err, ErrUnsafeSource):
		return deterministicFinish(
			"trivy_source_unsafe",
			"The retained image storage path is unsafe.",
		)
	default:
		return transientFinish(
			"trivy_source_unavailable",
			"The retained image could not be read.",
		)
	}
}

func finishForDatabaseError(err error) queue.FinishInput {
	switch {
	case errors.Is(err, trivydb.ErrUnavailable):
		return transientFinish(
			"trivy_database_unavailable",
			"The required fixed Trivy database Bundle is unavailable.",
		)
	case errors.Is(err, trivydb.ErrInvalidSnapshot),
		errors.Is(err, trivydb.ErrUnsafeStorage):
		return deterministicFinish(
			"trivy_database_invalid",
			"The fixed Trivy database Bundle is invalid.",
		)
	default:
		return transientFinish(
			"trivy_database_error",
			"The fixed Trivy database Bundle could not be prepared.",
		)
	}
}

func deterministicFinish(code, message string) queue.FinishInput {
	return queue.FinishInput{
		Outcome:   queue.OutcomeDeterministicFailure,
		ErrorCode: code, ErrorMessage: message,
	}
}

func transientFinish(code, message string) queue.FinishInput {
	return queue.FinishInput{
		Outcome:   queue.OutcomeTransientFailure,
		ErrorCode: code, ErrorMessage: message,
	}
}

func rootsOverlap(left, right string) bool {
	return pathWithin(left, right) || pathWithin(right, left)
}

func pathWithin(candidate, root string) bool {
	relative, err := filepath.Rel(root, candidate)
	return err == nil &&
		(relative == "." ||
			(relative != ".." &&
				!strings.HasPrefix(
					relative,
					".."+string(filepath.Separator),
				)))
}

func validArchiveLimits(value containerarchive.Limits) bool {
	return (value.MaxEntries == 0 ||
		value.MaxEntries > 0 && value.MaxEntries <= 100_000) &&
		(value.MaxMetadataBytes == 0 ||
			value.MaxMetadataBytes > 0 && value.MaxMetadataBytes <= 64<<20) &&
		(value.MaxDescriptors == 0 ||
			value.MaxDescriptors > 0 && value.MaxDescriptors <= 100_000) &&
		(value.MaxIndexDepth == 0 ||
			value.MaxIndexDepth > 0 && value.MaxIndexDepth <= 32) &&
		(value.MaxArchiveRatio == 0 ||
			value.MaxArchiveRatio > 0 && value.MaxArchiveRatio <= 100)
}

package canalysis

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"binaryscan/internal/queue"
	"binaryscan/internal/workspace"
)

type ProcessorConfig struct {
	RepositoryRoot string
	TaskWorkRoot   string
	CancelTimeout  time.Duration
}

type Processor struct {
	repository     ProcessorRepository
	checker        Checker
	repositoryRoot string
	taskWorkRoot   string
	cancelTimeout  time.Duration
}

func NewProcessor(
	repository ProcessorRepository,
	checker Checker,
	config ProcessorConfig,
) (*Processor, error) {
	if repository == nil || checker == nil {
		return nil, errors.New("C analysis processor dependencies are required")
	}
	for _, root := range []string{config.RepositoryRoot, config.TaskWorkRoot} {
		if !filepath.IsAbs(root) || filepath.Clean(root) != root || root == "/" {
			return nil, errors.New("C analysis processor roots are invalid")
		}
	}
	if config.CancelTimeout == 0 {
		config.CancelTimeout = 10 * time.Second
	}
	if config.CancelTimeout <= 0 || config.CancelTimeout > time.Minute {
		return nil, errors.New("C analysis cancellation timeout is invalid")
	}
	return &Processor{
		repository: repository, checker: checker,
		repositoryRoot: config.RepositoryRoot,
		taskWorkRoot:   config.TaskWorkRoot,
		cancelTimeout:  config.CancelTimeout,
	}, nil
}

func (p *Processor) Process(
	ctx context.Context,
	lease queue.Lease,
) (finish queue.FinishInput, returnErr error) {
	payload, err := decodeJobPayload(lease.Payload)
	if err != nil || !validCAnalysisLease(lease) {
		return deterministicFailure("c_analysis_payload_invalid"), nil
	}
	project, err := p.repository.Begin(ctx, lease)
	if errors.Is(err, ErrAlreadyPublished) {
		return queue.FinishInput{Outcome: queue.OutcomeSucceeded}, nil
	}
	if errors.Is(err, ErrFailedResultPublished) {
		return deterministicFailure("c_checker_failed"), nil
	}
	if errors.Is(err, ErrAlreadyTerminal) {
		return deterministicFailure("c_analysis_already_terminal"), nil
	}
	if errors.Is(err, ErrSourceUnavailable) || errors.Is(err, ErrProjectNotFound) {
		return p.failDeterministic(
			lease, "c_analysis_source_unavailable", "C source project is unavailable.",
		)
	}
	if err != nil {
		return queue.FinishInput{}, err
	}
	workDirectory, err := workspace.Create(
		p.taskWorkRoot,
		workspace.Identity{
			JobID: lease.JobID, TaskID: lease.TaskID,
			TaskAttemptID: *lease.TaskAttemptID,
			FencingToken:  lease.FencingToken,
			Kind:          string(lease.Kind),
		},
	)
	if err != nil {
		return p.failTransientOrFinal(
			lease, "c_analysis_workspace_failed", "Create C analysis workspace failed.", err,
		)
	}
	defer func() {
		if cleanupErr := workDirectory.Cleanup(); cleanupErr != nil {
			wrapped := fmt.Errorf("cleanup C analysis workspace: %w", cleanupErr)
			if returnErr != nil {
				returnErr = errors.Join(returnErr, wrapped)
			} else if finish.Outcome == "" {
				finish = queue.FinishInput{}
				returnErr = wrapped
			}
		}
	}()
	source, err := copyVerifiedProjectSource(
		ctx, p.repositoryRoot, workDirectory.Path(), project,
	)
	if err != nil {
		if ctx.Err() != nil {
			p.cancelRemote(payload.RunID)
			return p.failTransientOrFinal(
				lease, "c_analysis_interrupted", "C analysis was interrupted.",
				ctx.Err(),
			)
		}
		return p.failDeterministic(
			lease, "c_analysis_source_invalid", "C source project verification failed.",
		)
	}
	defer source.Close()
	metadata := RequestMetadata{
		SchemaVersion: RequestSchemaVersion,
		AnalysisID:    payload.RunID, ProjectID: project.ProjectID,
		CanonicalSHA256:    project.CanonicalSHA256,
		CanonicalSizeBytes: project.CanonicalSizeBytes,
		ProjectStatus:      project.Status, EngineName: project.EngineName,
		EngineVersion: project.EngineVersion,
		Functions:     project.Functions,
	}
	result, err := p.checker.Analyze(ctx, AnalysisRequest{
		Metadata: metadata, Source: source,
	})
	if err != nil {
		if ctx.Err() != nil {
			p.cancelRemote(payload.RunID)
			return p.failTransientOrFinal(
				lease, "c_analysis_interrupted", "C analysis was interrupted.",
				ctx.Err(),
			)
		}
		switch {
		case errors.Is(err, ErrInvalidInput):
			return p.failDeterministic(
				lease, "c_analysis_metadata_invalid",
				"C source project metadata is invalid.",
			)
		case errors.Is(err, ErrCheckerTransient):
			return p.failTransientOrFinal(
				lease, "c_checker_unavailable", "C checker request failed.", err,
			)
		case errors.Is(err, ErrCheckerTimedOut):
			p.cancelRemote(payload.RunID)
			return p.failDeterministic(
				lease, "c_analysis_timeout", "C analysis exceeded ten minutes.",
			)
		case errors.Is(err, ErrCheckerRejected):
			message := "C checker rejected the source project."
			var rejection *CheckerRejection
			if errors.As(err, &rejection) && rejection.Message != "" {
				message = rejection.Message
			}
			return p.failDeterministic(
				lease, "c_checker_rejected", message,
			)
		case errors.Is(err, ErrCheckerInvalidResponse):
			return p.failDeterministic(
				lease, "c_checker_response_invalid", "C checker returned an invalid response.",
			)
		default:
			return p.failTransientOrFinal(
				lease, "c_checker_request_failed", "C checker request failed.", err,
			)
		}
	}
	switch result.Status {
	case "succeeded", "partial":
		if err := p.repository.Publish(ctx, lease, result); err != nil {
			if errors.Is(err, ErrInvalidInput) {
				return p.failDeterministic(
					lease, "c_checker_response_invalid",
					"C checker returned an invalid response.",
				)
			}
			if errors.Is(err, ErrSourceUnavailable) ||
				errors.Is(err, ErrProjectNotFound) {
				return p.failDeterministic(
					lease, "c_analysis_source_changed",
					"C source project changed before publication.",
				)
			}
			if errors.Is(err, ErrLeaseLost) {
				return queue.FinishInput{}, err
			}
			confirmCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			_, confirmErr := p.repository.Begin(confirmCtx, lease)
			cancel()
			if errors.Is(confirmErr, ErrAlreadyPublished) {
				return successfulFinish(result.Status), nil
			}
			return p.failTransientOrFinal(
				lease, "c_analysis_publish_failed",
				"Publish C analysis result failed.", err,
			)
		}
		return successfulFinish(result.Status), nil
	case "failed":
		if err := p.repository.PublishFailed(ctx, lease, result); err != nil {
			if errors.Is(err, ErrInvalidInput) {
				return p.failDeterministic(
					lease, "c_checker_response_invalid",
					"C checker returned an invalid response.",
				)
			}
			if errors.Is(err, ErrSourceUnavailable) ||
				errors.Is(err, ErrProjectNotFound) {
				return p.failDeterministic(
					lease, "c_analysis_source_changed",
					"C source project changed before publication.",
				)
			}
			if errors.Is(err, ErrLeaseLost) {
				return queue.FinishInput{}, err
			}
			confirmCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			_, confirmErr := p.repository.Begin(confirmCtx, lease)
			cancel()
			if errors.Is(confirmErr, ErrFailedResultPublished) {
				return deterministicFailure("c_checker_failed"), nil
			}
			return p.failTransientOrFinal(
				lease, "c_analysis_publish_failed",
				"Publish C analysis failure failed.", err,
			)
		}
		return deterministicFailure("c_checker_failed"), nil
	case "cancelled":
		if err := p.repository.CancelRun(ctx, lease); err != nil {
			return queue.FinishInput{}, err
		}
		return deterministicFailure("c_analysis_cancelled"), nil
	default:
		return p.failDeterministic(
			lease, "c_checker_response_invalid", "C checker returned an invalid status.",
		)
	}
}

func successfulFinish(status string) queue.FinishInput {
	outcome := queue.OutcomeSucceeded
	if status == "partial" {
		outcome = queue.OutcomePartialSucceeded
	}
	return queue.FinishInput{Outcome: outcome}
}

func (p *Processor) failTransientOrFinal(
	lease queue.Lease,
	code string,
	message string,
	cause error,
) (queue.FinishInput, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if lease.Attempt < lease.MaxAttempts {
		if err := p.repository.Retry(ctx, lease, code, message); err != nil {
			return queue.FinishInput{}, errors.Join(cause, err)
		}
		return transientFailure(code), nil
	}
	if err := p.repository.Fail(ctx, lease, code, message); err != nil {
		return queue.FinishInput{}, errors.Join(cause, err)
	}
	return transientFailure(code), nil
}

func (p *Processor) failDeterministic(
	lease queue.Lease,
	code string,
	message string,
) (queue.FinishInput, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := p.repository.Fail(ctx, lease, code, message); err != nil {
		return queue.FinishInput{}, err
	}
	return deterministicFailure(code), nil
}

func (p *Processor) cancelRemote(runID string) {
	ctx, cancel := context.WithTimeout(context.Background(), p.cancelTimeout)
	defer cancel()
	_ = p.checker.Cancel(ctx, runID)
}

func copyVerifiedProjectSource(
	ctx context.Context,
	repositoryRoot string,
	workRoot string,
	project ProjectSnapshot,
) (*os.File, error) {
	if project.CanonicalStorageKey == "" ||
		!sha256Pattern.MatchString(project.CanonicalSHA256) ||
		project.CanonicalSizeBytes == 0 ||
		project.CanonicalSizeBytes > uint64(MaxSourceBytes) {
		return nil, ErrSourceUnavailable
	}
	repository, err := os.OpenRoot(repositoryRoot)
	if err != nil {
		return nil, fmt.Errorf("open C source repository: %w", err)
	}
	info, err := repository.Lstat(project.CanonicalStorageKey)
	if err != nil || !info.Mode().IsRegular() ||
		info.Mode()&os.ModeSymlink != 0 ||
		uint64(info.Size()) != project.CanonicalSizeBytes {
		repository.Close()
		return nil, ErrSourceUnavailable
	}
	source, err := repository.Open(project.CanonicalStorageKey)
	repository.Close()
	if err != nil {
		return nil, ErrSourceUnavailable
	}
	openedInfo, err := source.Stat()
	if err != nil || !openedInfo.Mode().IsRegular() ||
		!os.SameFile(info, openedInfo) ||
		uint64(openedInfo.Size()) != project.CanonicalSizeBytes {
		source.Close()
		return nil, ErrSourceUnavailable
	}
	work, err := os.OpenRoot(workRoot)
	if err != nil {
		source.Close()
		return nil, fmt.Errorf("open C analysis workspace: %w", err)
	}
	defer work.Close()
	if err := work.Mkdir("c-analysis-input", 0o700); err != nil {
		source.Close()
		return nil, fmt.Errorf("create C analysis input directory: %w", err)
	}
	destinationKey := "c-analysis-input/decompiled.c"
	destination, err := work.OpenFile(
		destinationKey, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600,
	)
	if err != nil {
		source.Close()
		return nil, fmt.Errorf("create fenced C analysis source: %w", err)
	}
	hasher := sha256.New()
	written, copyErr := io.Copy(
		io.MultiWriter(destination, hasher),
		io.LimitReader(
			&cancellableReader{ctx: ctx, reader: source},
			int64(project.CanonicalSizeBytes)+1,
		),
	)
	afterInfo, statErr := source.Stat()
	syncErr := destination.Sync()
	chmodErr := destination.Chmod(0o400)
	closeErr := errors.Join(destination.Close(), source.Close())
	if copyErr != nil || statErr != nil || syncErr != nil || chmodErr != nil ||
		closeErr != nil || !os.SameFile(openedInfo, afterInfo) ||
		uint64(afterInfo.Size()) != project.CanonicalSizeBytes ||
		uint64(written) != project.CanonicalSizeBytes ||
		hex.EncodeToString(hasher.Sum(nil)) != project.CanonicalSHA256 {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, ErrSourceUnavailable
	}
	readable, err := work.Open(destinationKey)
	if err != nil {
		return nil, fmt.Errorf("open fenced C analysis source: %w", err)
	}
	readInfo, err := readable.Stat()
	if err != nil || !readInfo.Mode().IsRegular() ||
		uint64(readInfo.Size()) != project.CanonicalSizeBytes {
		readable.Close()
		return nil, ErrSourceUnavailable
	}
	return readable, nil
}

type cancellableReader struct {
	ctx    context.Context
	reader io.Reader
}

func (r *cancellableReader) Read(buffer []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.reader.Read(buffer)
}

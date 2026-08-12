package javaanalysis

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
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
		return nil, errors.New("Java analysis processor dependencies are required")
	}
	for _, root := range []string{config.RepositoryRoot, config.TaskWorkRoot} {
		if !filepath.IsAbs(root) || filepath.Clean(root) != root || root == "/" {
			return nil, errors.New("Java analysis processor roots are invalid")
		}
	}
	if config.CancelTimeout == 0 {
		config.CancelTimeout = 10 * time.Second
	}
	if config.CancelTimeout <= 0 || config.CancelTimeout > time.Minute {
		return nil, errors.New("Java analysis cancellation timeout is invalid")
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
	if err != nil || !validJavaAnalysisLease(lease) {
		return deterministicFailure("java_analysis_payload_invalid"), nil
	}
	project, err := p.repository.Begin(ctx, lease)
	if errors.Is(err, ErrAlreadyPublished) {
		return queue.FinishInput{Outcome: queue.OutcomeSucceeded}, nil
	}
	if errors.Is(err, ErrFailedResultPublished) {
		return deterministicFailure("java_checker_failed"), nil
	}
	if errors.Is(err, ErrAlreadyTerminal) {
		return deterministicFailure("java_analysis_already_terminal"), nil
	}
	if errors.Is(err, ErrSourceUnavailable) || errors.Is(err, ErrProjectNotFound) {
		return p.failDeterministic(
			lease, "java_analysis_source_unavailable", "Java source project is unavailable.",
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
			lease, "java_analysis_workspace_failed", "Create Java analysis workspace failed.", err,
		)
	}
	defer func() {
		if cleanupErr := workDirectory.Cleanup(); cleanupErr != nil {
			wrapped := fmt.Errorf("cleanup Java analysis workspace: %w", cleanupErr)
			if returnErr != nil {
				returnErr = errors.Join(returnErr, wrapped)
			} else if finish.Outcome == "" {
				finish = queue.FinishInput{}
				returnErr = wrapped
			}
		}
	}()
	source, bundleSHA, files, err := buildVerifiedJavaBundle(
		ctx, p.repositoryRoot, workDirectory.Path(), project,
	)
	if err != nil {
		if ctx.Err() != nil {
			return p.failTransientOrFinal(
				lease, "java_analysis_interrupted", "Java analysis was interrupted.",
				ctx.Err(),
			)
		}
		return p.failDeterministic(
			lease, "java_analysis_source_invalid", "Java source project verification failed.",
		)
	}
	defer source.Close()
	if err := p.repository.SetBundleIdentity(ctx, lease, bundleSHA); err != nil {
		if errors.Is(err, ErrLeaseLost) {
			return queue.FinishInput{}, err
		}
		return p.failTransientOrFinal(
			lease, "java_analysis_bundle_publish_failed",
			"Publish Java analysis bundle identity failed.", err,
		)
	}
	engineAnalysisID := javaCheckerAnalysisID(
		payload.RunID, lease.JobID, lease.FencingToken,
	)
	metadata := RequestMetadata{
		SchemaVersion: RequestSchemaVersion, AnalysisID: engineAnalysisID,
		InputSHA256: project.InputSHA256, BundleSHA256: bundleSHA,
		SourceManifestSHA256: project.ManifestSHA256,
		ProjectID:            project.ProjectID,
		Language:             project.Language,
		ProjectStatus:        project.AnalysisProjectStatus,
		Files:                files,
	}
	result, err := p.checker.Analyze(ctx, AnalysisRequest{
		Metadata: metadata, Source: source,
	})
	if err != nil {
		if ctx.Err() != nil {
			p.cancelRemote(engineAnalysisID)
			return p.failTransientOrFinal(
				lease, "java_analysis_interrupted", "Java analysis was interrupted.",
				ctx.Err(),
			)
		}
		switch {
		case errors.Is(err, ErrInvalidInput):
			return p.failDeterministic(
				lease, "java_analysis_metadata_invalid",
				"Java source project metadata is invalid.",
			)
		case errors.Is(err, ErrCheckerTransient):
			p.cancelRemote(engineAnalysisID)
			return p.failTransientOrFinal(
				lease, "java_checker_unavailable", "Java checker request failed.", err,
			)
		case errors.Is(err, ErrCheckerTimedOut):
			p.cancelRemote(engineAnalysisID)
			return p.failDeterministic(
				lease, "java_analysis_timeout", "Java analysis exceeded ten minutes.",
			)
		case errors.Is(err, ErrCheckerRejected):
			message := "Java checker rejected the source project."
			var rejection *CheckerRejection
			if errors.As(err, &rejection) && rejection.Message != "" {
				message = rejection.Message
			}
			return p.failDeterministic(
				lease, "java_checker_rejected", message,
			)
		case errors.Is(err, ErrCheckerInvalidResponse):
			return p.failDeterministic(
				lease, "java_checker_response_invalid", "Java checker returned an invalid response.",
			)
		default:
			return p.failTransientOrFinal(
				lease, "java_checker_request_failed", "Java checker request failed.", err,
			)
		}
	}
	switch result.Status {
	case "complete", "partial":
		if err := p.repository.Publish(ctx, lease, metadata, result); err != nil {
			if errors.Is(err, ErrInvalidInput) {
				return p.failDeterministic(
					lease, "java_checker_response_invalid",
					"Java checker returned an invalid response.",
				)
			}
			if errors.Is(err, ErrSourceUnavailable) ||
				errors.Is(err, ErrProjectNotFound) {
				return p.failDeterministic(
					lease, "java_analysis_source_changed",
					"Java source project changed before publication.",
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
				lease, "java_analysis_publish_failed",
				"Publish Java analysis result failed.", err,
			)
		}
		return successfulFinish(result.Status), nil
	case "failed":
		if err := p.repository.PublishFailed(ctx, lease, metadata, result); err != nil {
			if errors.Is(err, ErrInvalidInput) {
				return p.failDeterministic(
					lease, "java_checker_response_invalid",
					"Java checker returned an invalid response.",
				)
			}
			if errors.Is(err, ErrSourceUnavailable) ||
				errors.Is(err, ErrProjectNotFound) {
				return p.failDeterministic(
					lease, "java_analysis_source_changed",
					"Java source project changed before publication.",
				)
			}
			if errors.Is(err, ErrLeaseLost) {
				return queue.FinishInput{}, err
			}
			confirmCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			_, confirmErr := p.repository.Begin(confirmCtx, lease)
			cancel()
			if errors.Is(confirmErr, ErrFailedResultPublished) {
				return deterministicFailure("java_checker_failed"), nil
			}
			return p.failTransientOrFinal(
				lease, "java_analysis_publish_failed",
				"Publish Java analysis failure failed.", err,
			)
		}
		return deterministicFailure("java_checker_failed"), nil
	case "cancelled":
		if err := p.repository.CancelRun(ctx, lease); err != nil {
			return queue.FinishInput{}, err
		}
		return deterministicFailure("java_analysis_cancelled"), nil
	default:
		return p.failDeterministic(
			lease, "java_checker_response_invalid", "Java checker returned an invalid status.",
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

func (p *Processor) cancelRemote(analysisID string) {
	ctx, cancel := context.WithTimeout(context.Background(), p.cancelTimeout)
	defer cancel()
	_ = p.checker.Cancel(ctx, analysisID)
}

// A checker cancellation belongs to one fenced delivery, not to the durable
// user-visible run. Reusing the run ID would let a late DELETE from an expired
// lease cancel the next delivery of the same job.
func javaCheckerAnalysisID(runID, jobID string, fencingToken uint64) string {
	hasher := sha256.New()
	_, _ = io.WriteString(hasher, "binaryscan-java-checker-delivery-v1\x00")
	_, _ = io.WriteString(hasher, runID)
	_, _ = hasher.Write([]byte{0})
	_, _ = io.WriteString(hasher, jobID)
	_, _ = hasher.Write([]byte{0})
	var fence [8]byte
	for index := range fence {
		fence[len(fence)-1-index] = byte(fencingToken >> (index * 8))
	}
	_, _ = hasher.Write(fence[:])
	value := hasher.Sum(nil)[:16]
	value[6] = (value[6] & 0x0f) | 0x40
	value[8] = (value[8] & 0x3f) | 0x80
	encoded := hex.EncodeToString(value)
	return encoded[0:8] + "-" + encoded[8:12] + "-" +
		encoded[12:16] + "-" + encoded[16:20] + "-" + encoded[20:32]
}

func buildVerifiedJavaBundle(
	ctx context.Context,
	repositoryRoot string,
	workRoot string,
	project ProjectSnapshot,
) (*os.File, string, []SourceFile, error) {
	if project.RootStorageKey == "" || project.ManifestStorageKey == "" ||
		!sha256Pattern.MatchString(project.ManifestSHA256) ||
		project.ManifestSizeBytes == 0 ||
		project.ManifestSizeBytes > uint64(MaxManifestBytes) ||
		project.SourceSizeBytes == 0 ||
		project.SourceSizeBytes > uint64(MaxSourceBytes) {
		return nil, "", nil, ErrSourceUnavailable
	}
	repository, err := os.OpenRoot(repositoryRoot)
	if err != nil {
		return nil, "", nil, fmt.Errorf("open Java source repository: %w", err)
	}
	defer repository.Close()
	manifestInfo, err := repository.Lstat(project.ManifestStorageKey)
	if err != nil || !manifestInfo.Mode().IsRegular() ||
		manifestInfo.Mode()&os.ModeSymlink != 0 ||
		uint64(manifestInfo.Size()) != project.ManifestSizeBytes {
		return nil, "", nil, ErrSourceUnavailable
	}
	manifestFile, err := repository.Open(project.ManifestStorageKey)
	if err != nil {
		return nil, "", nil, ErrSourceUnavailable
	}
	manifestOpenedInfo, err := manifestFile.Stat()
	if err != nil || !manifestOpenedInfo.Mode().IsRegular() ||
		!os.SameFile(manifestInfo, manifestOpenedInfo) {
		manifestFile.Close()
		return nil, "", nil, ErrSourceUnavailable
	}
	manifestHasher := sha256.New()
	var manifest bytes.Buffer
	written, copyErr := io.Copy(
		io.MultiWriter(&manifest, manifestHasher),
		io.LimitReader(
			&cancellableReader{ctx: ctx, reader: manifestFile},
			int64(project.ManifestSizeBytes)+1,
		),
	)
	manifestAfterInfo, statErr := manifestFile.Stat()
	closeErr := manifestFile.Close()
	if copyErr != nil || statErr != nil || closeErr != nil ||
		!os.SameFile(manifestOpenedInfo, manifestAfterInfo) ||
		uint64(manifestAfterInfo.Size()) != project.ManifestSizeBytes ||
		uint64(written) != project.ManifestSizeBytes ||
		hex.EncodeToString(manifestHasher.Sum(nil)) != project.ManifestSHA256 {
		if ctx.Err() != nil {
			return nil, "", nil, ctx.Err()
		}
		return nil, "", nil, ErrSourceUnavailable
	}
	files, err := decodeAndValidateManifest(&manifest, project)
	if err != nil {
		return nil, "", nil, ErrSourceUnavailable
	}
	work, err := os.OpenRoot(workRoot)
	if err != nil {
		return nil, "", nil, fmt.Errorf("open Java analysis workspace: %w", err)
	}
	defer work.Close()
	if err := work.Mkdir("java-analysis-input", 0o700); err != nil {
		return nil, "", nil, fmt.Errorf("create Java analysis input directory: %w", err)
	}
	destinationKey := "java-analysis-input/source.bundle"
	destination, err := work.OpenFile(
		destinationKey, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600,
	)
	if err != nil {
		return nil, "", nil, fmt.Errorf("create fenced Java analysis bundle: %w", err)
	}
	bundleHasher := sha256.New()
	var offset uint64
	for index := range files {
		file := &files[index]
		storageKey := path.Join(project.RootStorageKey, file.LogicalPath)
		if storageKey != project.RootStorageKey+"/"+file.LogicalPath {
			destination.Close()
			return nil, "", nil, ErrSourceUnavailable
		}
		info, err := repository.Lstat(storageKey)
		if err != nil || !info.Mode().IsRegular() ||
			info.Mode()&os.ModeSymlink != 0 || uint64(info.Size()) != file.SizeBytes {
			destination.Close()
			return nil, "", nil, ErrSourceUnavailable
		}
		source, err := repository.Open(storageKey)
		if err != nil {
			destination.Close()
			return nil, "", nil, ErrSourceUnavailable
		}
		openedInfo, err := source.Stat()
		if err != nil || !openedInfo.Mode().IsRegular() ||
			!os.SameFile(info, openedInfo) {
			source.Close()
			destination.Close()
			return nil, "", nil, ErrSourceUnavailable
		}
		fileHasher := sha256.New()
		lineCounter := javaLineCounter{}
		copied, copyErr := io.Copy(
			io.MultiWriter(destination, bundleHasher, fileHasher, &lineCounter),
			io.LimitReader(
				&cancellableReader{ctx: ctx, reader: source}, int64(file.SizeBytes)+1,
			),
		)
		afterInfo, statErr := source.Stat()
		closeErr := source.Close()
		if copyErr != nil || statErr != nil || closeErr != nil ||
			!os.SameFile(openedInfo, afterInfo) ||
			uint64(afterInfo.Size()) != file.SizeBytes ||
			uint64(copied) != file.SizeBytes ||
			hex.EncodeToString(fileHasher.Sum(nil)) != file.SHA256 {
			destination.Close()
			if ctx.Err() != nil {
				return nil, "", nil, ctx.Err()
			}
			return nil, "", nil, ErrSourceUnavailable
		}
		file.LineCount = lineCounter.Count()
		if file.LineCount == 0 {
			destination.Close()
			return nil, "", nil, ErrSourceUnavailable
		}
		file.OffsetBytes = offset
		file.LengthBytes = file.SizeBytes
		offset += file.SizeBytes
	}
	syncErr := destination.Sync()
	chmodErr := destination.Chmod(0o400)
	closeErr = destination.Close()
	if syncErr != nil || chmodErr != nil || closeErr != nil ||
		offset != project.SourceSizeBytes {
		return nil, "", nil, ErrSourceUnavailable
	}
	readable, err := work.Open(destinationKey)
	if err != nil {
		return nil, "", nil, fmt.Errorf("open fenced Java analysis bundle: %w", err)
	}
	readInfo, err := readable.Stat()
	if err != nil || !readInfo.Mode().IsRegular() ||
		uint64(readInfo.Size()) != project.SourceSizeBytes {
		readable.Close()
		return nil, "", nil, ErrSourceUnavailable
	}
	return readable, hex.EncodeToString(bundleHasher.Sum(nil)), files, nil
}

type cancellableReader struct {
	ctx    context.Context
	reader io.Reader
}

type javaLineCounter struct {
	breaks             uint32
	previousWasCR      bool
	endsWithTerminator bool
	sawByte            bool
}

func (c *javaLineCounter) Write(value []byte) (int, error) {
	for _, current := range value {
		c.sawByte = true
		switch current {
		case '\r':
			c.breaks++
			c.previousWasCR = true
			c.endsWithTerminator = true
		case '\n':
			if !c.previousWasCR {
				c.breaks++
			}
			c.previousWasCR = false
			c.endsWithTerminator = true
		default:
			c.previousWasCR = false
			c.endsWithTerminator = false
		}
	}
	return len(value), nil
}

func (c javaLineCounter) Count() uint32 {
	if !c.sawByte {
		return 0
	}
	if c.endsWithTerminator {
		return c.breaks
	}
	return c.breaks + 1
}

func (r *cancellableReader) Read(buffer []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.reader.Read(buffer)
}

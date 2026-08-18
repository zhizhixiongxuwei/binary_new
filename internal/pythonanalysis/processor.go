package pythonanalysis

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"

	"binaryscan/internal/queue"
	"binaryscan/internal/workspace"
)

var (
	ErrAlreadyPublished   = errors.New("python analysis result is already published")
	ErrFailedResultPublished = errors.New("python analysis failure is already published")
	ErrAlreadyTerminal    = errors.New("python analysis run is already terminal")
	ErrSourceUnavailable  = errors.New("python source project is unavailable")
	ErrProjectNotFound    = errors.New("python source project is not found")
	ErrInvalidLease       = errors.New("python analysis lease is invalid")
)

var sha256Pattern = regexp.MustCompile(`^[a-f0-9]{64}$`)

// ProcessorConfig fixes the roots and cancellation timeout.
type ProcessorConfig struct {
	RepositoryRoot string
	TaskWorkRoot   string
}

// Processor drives one python-analysis job from lease to publication.
type Processor struct {
	repository     ProcessorRepository
	checker        Checker
	repositoryRoot string
	taskWorkRoot   string
}

func NewProcessor(
	repository ProcessorRepository,
	checker Checker,
	config ProcessorConfig,
) (*Processor, error) {
	if repository == nil || checker == nil {
		return nil, errors.New("python analysis processor dependencies are required")
	}
	for _, root := range []string{config.RepositoryRoot, config.TaskWorkRoot} {
		if !filepath.IsAbs(root) || filepath.Clean(root) != root || root == "/" {
			return nil, errors.New("python analysis processor roots are invalid")
		}
	}
	return &Processor{
		repository: repository, checker: checker,
		repositoryRoot: config.RepositoryRoot,
		taskWorkRoot:   config.TaskWorkRoot,
	}, nil
}

func (p *Processor) Process(
	ctx context.Context,
	lease queue.Lease,
) (finish queue.FinishInput, returnErr error) {
	payload, err := decodeJobPayload(lease.Payload)
	if err != nil || !validLease(lease) {
		return deterministicFailure(
			"python_analysis_payload_invalid",
			"The Python analysis handoff is invalid.",
		), nil
	}
	project, err := p.repository.Begin(ctx, lease)
	if errors.Is(err, ErrAlreadyPublished) {
		return queue.FinishInput{Outcome: queue.OutcomeSucceeded}, nil
	}
	if errors.Is(err, ErrFailedResultPublished) {
		return deterministicFailure(
			"python_checker_failed",
			"The Python checker failure was already recorded.",
		), nil
	}
	if errors.Is(err, ErrAlreadyTerminal) {
		return deterministicFailure(
			"python_analysis_already_terminal",
			"The Python analysis run is already terminal.",
		), nil
	}
	if errors.Is(err, ErrSourceUnavailable) || errors.Is(err, ErrProjectNotFound) {
		return p.failDeterministic(
			lease, "python_analysis_source_unavailable",
			"The Python source project is unavailable.",
		), nil
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
			lease, "python_analysis_workspace_failed",
			"Creating the Python analysis workspace failed.", err,
		), nil
	}
	defer func() {
		if cleanupErr := workDirectory.Cleanup(); cleanupErr != nil {
			wrapped := fmt.Errorf("cleanup Python analysis workspace: %w", cleanupErr)
			if returnErr != nil {
				returnErr = errors.Join(returnErr, wrapped)
			} else if finish.Outcome == "" {
				finish = queue.FinishInput{}
				returnErr = wrapped
			}
		}
	}()

	sources, err := p.loadSources(ctx, project)
	if err != nil {
		if ctx.Err() != nil {
			return p.failTransientOrFinal(
				lease, "python_analysis_interrupted",
				"The Python analysis was interrupted.", ctx.Err(),
			), nil
		}
		return p.failDeterministic(
			lease, "python_analysis_source_unavailable",
			"The Python source project could not be verified.",
		), nil
	}

	metadata := RequestMetadata{
		RunID:    payload.RunID,
		TaskID:   lease.TaskID,
		JobID:    lease.JobID,
		Attempt:  lease.Attempt,
		Manifest: sha256.Sum256([]byte(project.ManifestSHA256)),
	}
	result, err := p.checker.Analyze(ctx, AnalysisRequest{
		Source:   sources,
		Metadata: metadata,
	})
	if err != nil {
		if ctx.Err() != nil {
			return p.failTransientOrFinal(
				lease, "python_analysis_interrupted",
				"The Python analysis was interrupted.", ctx.Err(),
			), nil
		}
		var rejection *CheckerRejection
		if errors.As(err, &rejection) {
			return p.failDeterministic(
				lease, "python_checker_rejected",
				"The Python checker rejected the analysis.",
			), nil
		}
		if errors.Is(err, ErrCheckerTimedOut) {
			return p.failTransientOrFinal(
				lease, "python_analysis_timed_out",
				"The Python analysis timed out.", err,
			), nil
		}
		return p.failTransientOrFinal(
			lease, "python_analysis_failed",
			"The Python analysis failed transiently.", err,
		), nil
	}

	// The checker reports only the analyzed-file count; derive the parsed
	// and failed counts so the persisted run satisfies its count contract.
	result.ParsedFiles = result.AnalyzedFiles
	result.FailedFiles = len(sources) - result.AnalyzedFiles
	if result.FailedFiles < 0 {
		result.FailedFiles = 0
	}
	if err := p.repository.Publish(
		ctx, lease, metadata, result,
	); err != nil {
		if ctx.Err() != nil {
			return queue.FinishInput{}, ctx.Err()
		}
		return queue.FinishInput{}, fmt.Errorf(
			"publish python analysis result: %w", err,
		)
	}
	return queue.FinishInput{Outcome: queue.OutcomeSucceeded}, nil
}

// loadSources verifies the manifest and reads every Python source file from
// the content-addressed repository into memory-bounded SourceFile values.
func (p *Processor) loadSources(
	ctx context.Context,
	project ProjectSnapshot,
) ([]SourceFile, error) {
	if project.RootStorageKey == "" || project.ManifestStorageKey == "" ||
		!sha256Pattern.MatchString(project.ManifestSHA256) ||
		project.ManifestSizeBytes == 0 ||
		project.ManifestSizeBytes > uint64(MaxSourceBytes) ||
		len(project.Files) == 0 || len(project.Files) > MaxFileCount {
		return nil, ErrSourceUnavailable
	}
	repository, err := os.OpenRoot(p.repositoryRoot)
	if err != nil {
		return nil, fmt.Errorf("open Python source repository: %w", err)
	}
	defer repository.Close()
	manifestFile, err := repository.Open(project.ManifestStorageKey)
	if err != nil {
		return nil, ErrSourceUnavailable
	}
	manifestHasher := sha256.New()
	written, copyErr := io.Copy(
		manifestHasher,
		io.LimitReader(manifestFile, int64(project.ManifestSizeBytes)+1),
	)
	closeErr := manifestFile.Close()
	if copyErr != nil || closeErr != nil ||
		uint64(written) != project.ManifestSizeBytes ||
		hex.EncodeToString(manifestHasher.Sum(nil)) != project.ManifestSHA256 {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, ErrSourceUnavailable
	}

	var totalBytes int64
	sources := make([]SourceFile, 0, len(project.Files))
	for index := range project.Files {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		file := &project.Files[index]
		if file.LogicalPath == "" || len(file.LogicalPath) > MaxFileNameBytes ||
			path.IsAbs(file.LogicalPath) ||
			strings.Contains(file.LogicalPath, `\`) ||
			!sha256Pattern.MatchString(file.SHA256) || file.SizeBytes == 0 {
			return nil, ErrSourceUnavailable
		}
		cleaned := path.Clean(file.LogicalPath)
		if cleaned != file.LogicalPath || cleaned == ".." ||
			strings.HasPrefix(cleaned, "../") {
			return nil, ErrSourceUnavailable
		}
		storageKey := path.Join(project.RootStorageKey, cleaned)
		info, err := repository.Lstat(storageKey)
		if err != nil || !info.Mode().IsRegular() ||
			info.Mode()&os.ModeSymlink != 0 ||
			uint64(info.Size()) != file.SizeBytes ||
			info.Size() > MaxSourceBytes {
			return nil, ErrSourceUnavailable
		}
		content, err := readBoundedSource(ctx, repository, storageKey, info.Size())
		if err != nil {
			return nil, err
		}
		digest := sha256.Sum256(content)
		if hex.EncodeToString(digest[:]) != file.SHA256 {
			return nil, ErrSourceUnavailable
		}
		totalBytes += int64(len(content))
		if totalBytes > MaxSourceBytes {
			return nil, ErrSourceUnavailable
		}
		sources = append(sources, SourceFile{
			FileIdentity: FileIdentity{
				ResultID:    file.ResultID,
				LogicalPath: cleaned,
				BinaryName:  cleaned,
			},
			Content: string(content),
		})
	}
	return sources, nil
}

func readBoundedSource(
	ctx context.Context,
	repository *os.Root,
	storageKey string,
	size int64,
) ([]byte, error) {
	file, err := repository.Open(storageKey)
	if err != nil {
		return nil, ErrSourceUnavailable
	}
	defer file.Close()
	reader := &contextReader{ctx: ctx, reader: io.LimitReader(file, size)}
	content, err := io.ReadAll(reader)
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, ErrSourceUnavailable
	}
	if int64(len(content)) != size {
		return nil, ErrSourceUnavailable
	}
	return content, nil
}

type contextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (r *contextReader) Read(buffer []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	read, err := r.reader.Read(buffer)
	if read > 0 {
		if contextErr := r.ctx.Err(); contextErr != nil {
			return read, contextErr
		}
	}
	return read, err
}

func validLease(lease queue.Lease) bool {
	return lease.Kind == queue.KindPythonAnalysis &&
		lease.TaskAttemptID != nil && lease.JobID != "" &&
		lease.TaskID != "" && lease.Owner != "" && lease.FencingToken != 0
}

func (p *Processor) failDeterministic(
	lease queue.Lease,
	code string,
	message string,
) queue.FinishInput {
	if err := p.repository.Fail(
		context.Background(), lease, code, message,
	); err != nil {
		return queue.FinishInput{Outcome: queue.OutcomeTransientFailure}
	}
	return deterministicFailure(code, message)
}

func (p *Processor) failTransientOrFinal(
	lease queue.Lease,
	code string,
	message string,
	err error,
) queue.FinishInput {
	if retryErr := p.repository.Retry(
		context.Background(), lease, code, message,
	); retryErr == nil {
		return queue.FinishInput{Outcome: queue.OutcomeTransientFailure}
	}
	_ = err
	return deterministicFailure(code, message)
}

func deterministicFailure(code string, message string) queue.FinishInput {
	return queue.FinishInput{
		Outcome: queue.OutcomeDeterministicFailure,
		ErrorCode: code, ErrorMessage: message,
	}
}

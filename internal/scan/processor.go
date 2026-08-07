package scan

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"

	"binaryscan/internal/extract"
	"binaryscan/internal/filetype"
	"binaryscan/internal/queue"
	"binaryscan/internal/trivyhandoff"
	"binaryscan/internal/workspace"
)

var lowercaseSHA256Pattern = regexp.MustCompile(`^[a-f0-9]{64}$`)

type Processor struct {
	repository     Repository
	progress       ProgressReporter
	detector       Detector
	repositoryRoot string
	taskWorkRoot   string
	newExtractor   extractorFactory
	newWorkspace   workspaceFactory
}

type extractionEngine interface {
	Supports(string) bool
	Extract(context.Context, *os.File, string, string) (extract.Result, error)
}

type contextDetector interface {
	DetectContext(context.Context, io.ReaderAt, int64) (filetype.Result, error)
}

func detectSample(
	ctx context.Context,
	detector Detector,
	source io.ReaderAt,
	size int64,
) (filetype.Result, error) {
	if contextual, ok := detector.(contextDetector); ok {
		return contextual.DetectContext(ctx, source, size)
	}
	return detector.Detect(source, size)
}

type extractorFactory func(Detector, extract.Limits) extractionEngine

type workDirectory interface {
	Path() string
	Cleanup() error
}

type workspaceFactory func(string, workspace.Identity) (workDirectory, error)

func NewProcessor(
	repository Repository,
	progress ProgressReporter,
	detector Detector,
	repositoryRoot string,
	taskWorkRoot string,
) (*Processor, error) {
	if repository == nil {
		return nil, errors.New("scan repository is required")
	}
	if progress == nil {
		return nil, errors.New("scan progress reporter is required")
	}
	if detector == nil {
		return nil, errors.New("scan file type detector is required")
	}
	cleanRoot := filepath.Clean(repositoryRoot)
	if !filepath.IsAbs(cleanRoot) || cleanRoot == string(filepath.Separator) {
		return nil, errors.New("scan repository root must be an absolute non-root path")
	}
	cleanWorkRoot := filepath.Clean(taskWorkRoot)
	if !filepath.IsAbs(cleanWorkRoot) ||
		cleanWorkRoot == string(filepath.Separator) {
		return nil, errors.New("scan task work root must be an absolute non-root path")
	}
	if pathsOverlap(cleanRoot, cleanWorkRoot) {
		return nil, errors.New("scan repository and task work roots must not overlap")
	}
	return &Processor{
		repository: repository, progress: progress, detector: detector,
		repositoryRoot: cleanRoot, taskWorkRoot: cleanWorkRoot,
		newExtractor: func(detector Detector, limits extract.Limits) extractionEngine {
			return extract.NewEngine(detector, limits)
		},
		newWorkspace: func(
			root string,
			identity workspace.Identity,
		) (workDirectory, error) {
			return workspace.Create(root, identity)
		},
	}, nil
}

// EnableArchiveSandbox routes 7Z and CAB extraction through the dedicated
// no-network archive service while preserving the processor's normal limits.
func (p *Processor) EnableArchiveSandbox(
	adapter extract.ExternalArchiveAdapter,
) error {
	if p == nil {
		return errors.New("scan processor is nil")
	}
	if adapter == nil {
		return errors.New("archive sandbox adapter is required")
	}
	p.newExtractor = func(
		detector Detector,
		limits extract.Limits,
	) extractionEngine {
		engine, err := extract.NewEngineWithArchiveSandbox(
			detector,
			limits,
			adapter,
		)
		if err != nil {
			return nil
		}
		return engine
	}
	return nil
}

func (p *Processor) Process(
	ctx context.Context,
	lease queue.Lease,
) (finish queue.FinishInput, returnErr error) {
	if lease.Kind != queue.KindScan || lease.TaskAttemptID == nil {
		return queue.FinishInput{}, errors.New("scan processor requires a scan lease")
	}
	sample, err := p.repository.Load(ctx, lease)
	if err != nil {
		return finishForSampleError(err)
	}
	if sample.TaskID != lease.TaskID {
		return deterministicFailure(
			"sample_content_mismatch",
			"The retained sample does not match its task metadata.",
		), nil
	}
	if err := validateStorageKey(sample); err != nil {
		return finishForSampleError(err)
	}

	source, err := openSample(p.repositoryRoot, sample.StorageKey)
	if err != nil {
		return finishForSampleError(err)
	}
	defer source.Close()
	if err := verifySample(ctx, source, sample); err != nil {
		return finishForSampleError(err)
	}
	if err := p.progress.TaskProgress(ctx, lease, queue.ProgressInput{
		TaskStatus: "IDENTIFYING",
		Stage:      "IDENTIFYING",
	}); err != nil {
		return queue.FinishInput{}, fmt.Errorf("advance scan task to identifying: %w", err)
	}

	detected, err := detectSample(ctx, p.detector, source, sample.SizeBytes)
	if err != nil {
		return queue.FinishInput{}, fmt.Errorf("identify root sample: %w", err)
	}
	node, err := rootNode(sample, detected)
	if err != nil {
		return queue.FinishInput{}, err
	}
	if err := p.repository.Publish(ctx, lease, node); err != nil {
		return queue.FinishInput{}, fmt.Errorf("publish root file identification: %w", err)
	}
	engine := p.newExtractor(p.detector, sample.Limits)
	if engine == nil {
		return queue.FinishInput{}, errors.New("initialize archive extractor: nil engine")
	}
	if !engine.Supports(detected.Format) {
		if !formatRequiresExtraction(detected.Format) {
			if err := p.reportProgress(ctx, lease, "REPORTING"); err != nil {
				return queue.FinishInput{}, err
			}
			return queue.FinishInput{Outcome: queue.OutcomeSucceeded}, nil
		}
		if err := p.reportProgress(ctx, lease, "EXTRACTING"); err != nil {
			return queue.FinishInput{}, err
		}
		if err := p.reportProgress(ctx, lease, "INDEXING"); err != nil {
			return queue.FinishInput{}, err
		}
		if err := p.repository.PublishTree(
			ctx, lease, "unsupported", nil,
		); err != nil {
			return queue.FinishInput{}, fmt.Errorf(
				"publish unsupported extraction result: %w", err,
			)
		}
		if err := p.reportProgress(ctx, lease, "REPORTING"); err != nil {
			return queue.FinishInput{}, err
		}
		return queue.FinishInput{Outcome: queue.OutcomePartialSucceeded}, nil
	}
	if err := p.reportProgress(ctx, lease, "EXTRACTING"); err != nil {
		return queue.FinishInput{}, err
	}
	if sample.Limits.MaxNodes == 0 {
		if err := p.reportProgress(ctx, lease, "INDEXING"); err != nil {
			return queue.FinishInput{}, err
		}
		if err := p.repository.PublishTree(
			ctx, lease, "limit_reached", nil,
		); err != nil {
			return queue.FinishInput{}, fmt.Errorf(
				"publish node-limit extraction result: %w", err,
			)
		}
		return p.finishPublishedTree(
			ctx,
			lease,
			rootContainerSources(detected.Format, sample),
			sample.Limits,
			true,
		)
	}

	workDirectory, err := p.newWorkspace(
		p.taskWorkRoot,
		workspace.Identity{
			JobID: lease.JobID, TaskID: lease.TaskID,
			TaskAttemptID: *lease.TaskAttemptID,
			FencingToken:  lease.FencingToken,
			Kind:          string(lease.Kind),
		},
	)
	if err != nil {
		return queue.FinishInput{}, fmt.Errorf(
			"create scan task workspace: %w", err,
		)
	}
	defer func() {
		if cleanupErr := workDirectory.Cleanup(); cleanupErr != nil {
			wrapped := fmt.Errorf(
				"cleanup scan task workspace: %w", cleanupErr,
			)
			if returnErr != nil {
				returnErr = errors.Join(returnErr, wrapped)
				return
			}
			finish = queue.FinishInput{}
			returnErr = wrapped
		}
	}()
	result, err := engine.Extract(
		ctx, source, detected.Format, workDirectory.Path(),
	)
	if err != nil {
		if ctx.Err() != nil {
			return queue.FinishInput{}, ctx.Err()
		}
		return queue.FinishInput{}, fmt.Errorf("extract root archive: %w", err)
	}
	sources, err := p.prepareContainerSources(
		ctx,
		workDirectory.Path(),
		detected.Format,
		sample,
		&result,
	)
	if err != nil {
		return queue.FinishInput{}, err
	}
	if err := p.reportProgress(ctx, lease, "INDEXING"); err != nil {
		return queue.FinishInput{}, err
	}
	rootExtractionStatus := "extracted"
	if result.LimitCode != "" {
		rootExtractionStatus = "limit_reached"
	}
	if err := p.repository.PublishTree(
		ctx, lease, rootExtractionStatus, result.Nodes,
	); err != nil {
		return queue.FinishInput{}, fmt.Errorf("publish extracted file tree: %w", err)
	}
	return p.finishPublishedTree(
		ctx, lease, sources, sample.Limits, result.Partial,
	)
}

func (p *Processor) finishPublishedTree(
	ctx context.Context,
	lease queue.Lease,
	sources []TrivySource,
	limits extract.Limits,
	partial bool,
) (queue.FinishInput, error) {
	if len(sources) > 0 {
		if err := p.repository.EnqueueTrivy(ctx, lease, TrivyJobPayload{
			SchemaVersion:    TrivyJobPayloadSchemaVersion,
			Sources:          sources,
			MaxExpandedBytes: limits.MaxExpandedBytes,
			MaxArchiveRatio:  int(limits.MaxRatio),
			UpstreamPartial:  partial,
		}); err != nil {
			return queue.FinishInput{}, fmt.Errorf("enqueue Trivy image scan: %w", err)
		}
	} else if err := p.reportProgress(ctx, lease, "REPORTING"); err != nil {
		return queue.FinishInput{}, err
	}
	outcome := queue.OutcomeSucceeded
	if partial {
		outcome = queue.OutcomePartialSucceeded
	}
	return queue.FinishInput{Outcome: outcome}, nil
}

func rootContainerSources(format string, sample Sample) []TrivySource {
	if format != "docker-tar" && format != "oci-tar" {
		return nil
	}
	return []TrivySource{{
		Format:           format,
		SourceStorageKey: sample.StorageKey,
		SourceSHA256:     sample.SHA256,
		SourceSizeBytes:  sample.SizeBytes,
		ImageLogicalPath: "/",
	}}
}

func (p *Processor) prepareContainerSources(
	ctx context.Context,
	workspaceRoot string,
	rootFormat string,
	sample Sample,
	result *extract.Result,
) ([]TrivySource, error) {
	sources := rootContainerSources(rootFormat, sample)
	if result == nil || len(result.ContainerImages) == 0 {
		return sources, nil
	}
	nodes := make(map[int]*extract.Node, len(result.Nodes))
	for index := range result.Nodes {
		nodes[result.Nodes[index].LocalID] = &result.Nodes[index]
	}
	var selectedBytes int64
	for _, source := range sources {
		selectedBytes += source.SourceSizeBytes
	}
	for _, image := range result.ContainerImages {
		node := nodes[image.LocalID]
		if node == nil || node.LogicalPath != image.LogicalPath ||
			node.Format != image.Format || node.SHA256 != image.SHA256 ||
			node.SizeBytes != image.SizeBytes {
			return nil, errors.New(
				"nested container image does not match its extracted file node",
			)
		}
		storageKey, err := publishDerivedBlob(
			ctx,
			p.repositoryRoot,
			workspaceRoot,
			image,
		)
		if err != nil {
			return nil, fmt.Errorf(
				"publish nested image %q: %w",
				image.LogicalPath,
				err,
			)
		}
		node.StorageKey = storageKey
		if len(sources) >= trivyhandoff.MaxSources {
			node.ExtractionStatus = extract.StatusLimitExceeded
			node.ErrorCode = extract.LimitMaxContainerImages
			node.ErrorMessage = "automatic container image scan limit reached"
			result.Partial = true
			if result.LimitCode == "" {
				result.LimitCode = extract.LimitMaxContainerImages
			}
			continue
		}
		if image.SizeBytes > sample.Limits.MaxExpandedBytes-selectedBytes {
			node.ExtractionStatus = extract.StatusLimitExceeded
			node.ErrorCode = extract.LimitMaxContainerBytes
			node.ErrorMessage =
				"automatic container image aggregate size limit reached"
			result.Partial = true
			if result.LimitCode == "" {
				result.LimitCode = extract.LimitMaxContainerBytes
			}
			continue
		}
		sources = append(sources, TrivySource{
			Format:           image.Format,
			SourceStorageKey: storageKey,
			SourceSHA256:     image.SHA256,
			SourceSizeBytes:  image.SizeBytes,
			ImageLogicalPath: image.LogicalPath,
		})
		selectedBytes += image.SizeBytes
	}
	return sources, nil
}

func formatRequiresExtraction(format string) bool {
	switch format {
	case "7z", "ar", "cab", "cpio", "deb", "ext2", "ext3", "ext4",
		"gpt-img", "iso9660", "mbr-img", "rar", "rpm", "squashfs",
		"udf", "xz", "zstd":
		return true
	default:
		return false
	}
}

func (p *Processor) reportProgress(
	ctx context.Context,
	lease queue.Lease,
	status string,
) error {
	if err := p.progress.TaskProgress(ctx, lease, queue.ProgressInput{
		TaskStatus: status, Stage: status,
	}); err != nil {
		return fmt.Errorf("advance scan task to %s: %w", strings.ToLower(status), err)
	}
	return nil
}

func pathsOverlap(left string, right string) bool {
	return pathWithin(left, right) || pathWithin(right, left)
}

func pathWithin(candidate string, parent string) bool {
	relative, err := filepath.Rel(parent, candidate)
	return err == nil && relative != ".." &&
		!strings.HasPrefix(relative, ".."+string(filepath.Separator))
}

func validateStorageKey(sample Sample) error {
	if sample.SizeBytes < 0 || !lowercaseSHA256Pattern.MatchString(sample.SHA256) {
		return ErrSampleMismatch
	}
	expected := "blobs/sha256/" + sample.SHA256[:2] + "/" + sample.SHA256
	if sample.StorageKey != expected ||
		path.IsAbs(sample.StorageKey) ||
		path.Clean(sample.StorageKey) != sample.StorageKey ||
		strings.Contains(sample.StorageKey, `\`) {
		return ErrUnsafeSample
	}
	return nil
}

func openSample(repositoryRoot string, storageKey string) (*os.File, error) {
	rootInfo, err := os.Lstat(repositoryRoot)
	if err != nil {
		return nil, fmt.Errorf("inspect sample repository root: %w", err)
	}
	if rootInfo.Mode()&os.ModeSymlink != 0 {
		return nil, ErrUnsafeSample
	}
	if !rootInfo.IsDir() {
		return nil, fmt.Errorf("sample repository root is not a directory")
	}
	root, err := os.OpenRoot(repositoryRoot)
	if err != nil {
		return nil, fmt.Errorf("open sample repository root: %w", err)
	}
	defer root.Close()
	openedRootInfo, err := root.Stat(".")
	if err != nil {
		return nil, fmt.Errorf("inspect opened sample repository root: %w", err)
	}
	if !openedRootInfo.IsDir() || !os.SameFile(rootInfo, openedRootInfo) {
		return nil, ErrUnsafeSample
	}

	segments := strings.Split(storageKey, "/")
	for index := range segments {
		name := path.Join(segments[:index+1]...)
		info, err := root.Lstat(name)
		if err != nil {
			return nil, classifySamplePathError(err)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return nil, ErrUnsafeSample
		}
		opened, err := root.Open(name)
		if err != nil {
			return nil, classifySamplePathError(err)
		}
		openedInfo, statErr := opened.Stat()
		if statErr != nil {
			_ = opened.Close()
			return nil, fmt.Errorf("inspect opened sample path: %w", statErr)
		}
		if !os.SameFile(info, openedInfo) {
			_ = opened.Close()
			return nil, ErrUnsafeSample
		}
		final := index == len(segments)-1
		if !final {
			if !openedInfo.IsDir() {
				_ = opened.Close()
				return nil, ErrUnsafeSample
			}
			if err := opened.Close(); err != nil {
				return nil, fmt.Errorf("close sample path component: %w", err)
			}
			continue
		}
		if !openedInfo.Mode().IsRegular() {
			_ = opened.Close()
			return nil, ErrUnsafeSample
		}
		return opened, nil
	}
	return nil, ErrUnsafeSample
}

func classifySamplePathError(err error) error {
	if errors.Is(err, fs.ErrNotExist) {
		return ErrSampleMissing
	}
	if errors.Is(err, fs.ErrInvalid) {
		return ErrUnsafeSample
	}
	if errors.Is(err, syscall.ELOOP) || errors.Is(err, syscall.ENOTDIR) {
		return ErrUnsafeSample
	}
	return fmt.Errorf("open retained sample: %w", err)
}

func verifySample(ctx context.Context, source *os.File, sample Sample) error {
	info, err := source.Stat()
	if err != nil {
		return fmt.Errorf("inspect retained sample: %w", err)
	}
	if !info.Mode().IsRegular() {
		return ErrUnsafeSample
	}
	if info.Size() != sample.SizeBytes {
		return ErrSampleMismatch
	}

	digest := sha256.New()
	read, err := io.CopyBuffer(
		digest,
		&contextReader{
			ctx:    ctx,
			reader: io.NewSectionReader(source, 0, sample.SizeBytes),
		},
		make([]byte, 1024*1024),
	)
	if err != nil {
		return fmt.Errorf("hash retained sample: %w", err)
	}
	if read != sample.SizeBytes {
		return ErrSampleMismatch
	}
	after, err := source.Stat()
	if err != nil {
		return fmt.Errorf("reinspect retained sample: %w", err)
	}
	if !after.Mode().IsRegular() || after.Size() != sample.SizeBytes {
		return ErrSampleMismatch
	}
	if hex.EncodeToString(digest.Sum(nil)) != sample.SHA256 {
		return ErrSampleMismatch
	}
	return nil
}

type contextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (r *contextReader) Read(value []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.reader.Read(value)
}

func rootNode(sample Sample, detected filetype.Result) (RootNode, error) {
	if detected.Metadata == nil {
		detected.Metadata = map[string]any{}
	}
	metadata, err := json.Marshal(detected.Metadata)
	if err != nil {
		return RootNode{}, fmt.Errorf("encode root file metadata: %w", err)
	}
	return RootNode{
		LogicalPath:     "/",
		LogicalPathHash: sha256.Sum256([]byte("/")),
		DisplayName:     sample.DisplayName,
		Format:          detected.Format,
		MIMEType:        detected.MIMEType,
		Architecture:    detected.Architecture,
		SizeBytes:       sample.SizeBytes,
		SHA256:          sample.SHA256,
		StorageKey:      sample.StorageKey,
		MetadataJSON:    metadata,
	}, nil
}

func finishForSampleError(err error) (queue.FinishInput, error) {
	switch {
	case errors.Is(err, ErrSampleMissing):
		return deterministicFailure(
			"sample_missing",
			"The retained sample is unavailable.",
		), nil
	case errors.Is(err, ErrUnsafeSample):
		return deterministicFailure(
			"sample_path_unsafe",
			"The retained sample path is unsafe.",
		), nil
	case errors.Is(err, ErrSampleMismatch):
		return deterministicFailure(
			"sample_content_mismatch",
			"The retained sample does not match its database metadata.",
		), nil
	case errors.Is(err, ErrInvalidLimits):
		return deterministicFailure(
			"task_limits_invalid",
			"The scan task limits snapshot is invalid.",
		), nil
	default:
		return queue.FinishInput{}, err
	}
}

func deterministicFailure(code string, message string) queue.FinishInput {
	return queue.FinishInput{
		Outcome: queue.OutcomeDeterministicFailure, ErrorCode: code,
		ErrorMessage: message,
	}
}

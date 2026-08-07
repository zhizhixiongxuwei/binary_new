package decompile

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"binaryscan/internal/ghidra"
	"binaryscan/internal/queue"
	"binaryscan/internal/workspace"
)

type NativeAnalyzer interface {
	Analyze(context.Context, ghidra.Request) (ghidra.Result, error)
	Identity() ghidra.Identity
}

type ActivityReporter interface {
	TaskActivity(context.Context, queue.Lease, queue.ActivityInput) error
}

var errNativeAlreadyPublished = errors.New(
	"native decompile results already published",
)

type NativeRun struct {
	ID string
}

type NativePublishedResult struct {
	ID          string
	SymbolKey   string
	StorageKey  string
	SHA256      string
	SizeBytes   uint64
	Diagnostics json.RawMessage
}

// NativeResultPublisher promotes analyzer output from its fenced attempt
// workspace into repository storage. The repository invokes it only while the
// exact job lease and analyzer run are locked and valid.
type NativeResultPublisher func(
	context.Context,
) ([]NativePublishedResult, func(), error)

type NativeRunRepository interface {
	BeginNativeRun(
		context.Context, queue.Lease, JobPayload, string, string, string,
	) error
	PublishNativeRun(
		context.Context, queue.Lease, JobPayload, string, string, string, string,
		NativeResultPublisher,
	) error
	FailNativeRun(
		context.Context, queue.Lease, string, string, string,
	) error
}

type NativeProcessorConfig struct {
	RepositoryRoot string
	TaskWorkRoot   string
	EngineVersion  string
}

type NativeProcessor struct {
	repository NativeRunRepository
	analyzer   NativeAnalyzer
	activity   ActivityReporter
	config     NativeProcessorConfig
	identity   ghidra.Identity
	newID      func() (string, error)
}

func NewNativeProcessor(
	repository NativeRunRepository,
	analyzer NativeAnalyzer,
	activity ActivityReporter,
	config NativeProcessorConfig,
) (*NativeProcessor, error) {
	if repository == nil || analyzer == nil || activity == nil {
		return nil, errors.New("native decompile dependencies are required")
	}
	for _, root := range []string{config.RepositoryRoot, config.TaskWorkRoot} {
		if !filepath.IsAbs(root) || filepath.Clean(root) != root || root == "/" {
			return nil, errors.New("native decompile roots are invalid")
		}
	}
	if !safeEngineVersion(config.EngineVersion) {
		return nil, errors.New("native decompile engine version is invalid")
	}
	identity := analyzer.Identity()
	if identity.EngineVersion != config.EngineVersion ||
		!sha256Pattern.MatchString(identity.ParametersSHA256) {
		return nil, errors.New(
			"native decompile analyzer identity does not match configuration",
		)
	}
	return &NativeProcessor{
		repository: repository, analyzer: analyzer, activity: activity,
		config:   config,
		identity: identity,
		newID:    nativeUUID,
	}, nil
}

func (p *NativeProcessor) Process(
	ctx context.Context,
	lease queue.Lease,
) (finish queue.FinishInput, returnErr error) {
	payload, err := decodeJobPayload(lease.Payload)
	if err != nil || lease.Kind != queue.KindDecompile ||
		lease.TaskAttemptID == nil ||
		payload.TaskID != lease.TaskID ||
		payload.Engine.WorkerKind != TargetNative ||
		payload.Engine.Target != EngineGhidra {
		return deterministic("decompile_payload_invalid"), nil
	}
	parameterKey, err := nativeParameterCacheKey(payload, p.identity)
	if err != nil {
		return deterministic("decompile_payload_invalid"), nil
	}
	runID, err := p.newID()
	if err != nil {
		return queue.FinishInput{}, err
	}
	if err := p.repository.BeginNativeRun(
		ctx, lease, payload, runID, p.config.EngineVersion, parameterKey,
	); err != nil {
		if errors.Is(err, errNativeAlreadyPublished) {
			return queue.FinishInput{Outcome: queue.OutcomeSucceeded}, nil
		}
		if errors.Is(err, ErrRequestConflict) ||
			errors.Is(err, ErrSourceUnavailable) {
			return deterministic("decompile_source_unavailable"), nil
		}
		return queue.FinishInput{}, err
	}
	p.emitActivity(ctx, lease, "decompile.progress", "info", nativeActivityPayload{
		Analyzer: "ghidra", Phase: "preparing",
	})
	workDirectory, err := workspace.Create(
		p.config.TaskWorkRoot,
		workspace.Identity{
			JobID: lease.JobID, TaskID: lease.TaskID,
			TaskAttemptID: *lease.TaskAttemptID,
			FencingToken:  lease.FencingToken,
			Kind:          string(lease.Kind),
		},
	)
	if err != nil {
		p.emitFailure(ctx, lease, "decompile_workspace_failed")
		processErr := fmt.Errorf(
			"create native decompile workspace: %w", err,
		)
		if failErr := p.failRun(
			lease, runID, "decompile_workspace_failed",
		); failErr != nil {
			processErr = errors.Join(processErr, failErr)
		}
		return queue.FinishInput{}, processErr
	}
	defer func() {
		if cleanupErr := workDirectory.Cleanup(); cleanupErr != nil {
			wrapped := fmt.Errorf(
				"cleanup native decompile workspace: %w", cleanupErr,
			)
			if returnErr != nil {
				returnErr = errors.Join(returnErr, wrapped)
				return
			}
			finish = queue.FinishInput{}
			returnErr = wrapped
		}
	}()
	sourcePath, cleanup, err := copyVerifiedNativeSource(
		ctx, p.config.RepositoryRoot, workDirectory.Path(),
		lease, payload.Target,
	)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			p.emitFailure(ctx, lease, "decompile_context_cancelled")
			if failErr := p.failRun(
				lease, runID, "decompile_context_cancelled",
			); failErr != nil {
				return queue.FinishInput{}, errors.Join(ctxErr, failErr)
			}
			return queue.FinishInput{}, ctxErr
		}
		p.emitFailure(ctx, lease, "decompile_source_invalid")
		if failErr := p.failRun(
			lease, runID, "decompile_source_invalid",
		); failErr != nil {
			return queue.FinishInput{}, errors.Join(err, failErr)
		}
		return deterministic("decompile_source_invalid"), nil
	}
	defer cleanup()
	result, err := p.analyzeWithActivity(ctx, lease, ghidra.Request{
		SourcePath: sourcePath, SourceSHA256: payload.Target.SHA256,
		SourceSize: payload.Target.SizeBytes, WorkRoot: workDirectory.Path(),
		JobID: lease.JobID, Attempt: lease.Attempt,
		FencingToken: lease.FencingToken,
		Limits: ghidra.ExecutionLimits{
			MaxDuration:            time.Duration(payload.Limits.MaxDurationSeconds) * time.Second,
			MaxOutputBytes:         payload.Limits.MaxOutputBytes,
			MaxFunctions:           payload.Limits.MaxArtifacts,
			MaxStandardOutputBytes: payload.Limits.MaxStandardOutputBytes,
		},
	})
	if err != nil {
		finish := classifyNativeFailure(err)
		code := finish.ErrorCode
		p.emitFailure(ctx, lease, code)
		if failErr := p.failRun(lease, runID, code); failErr != nil {
			return queue.FinishInput{}, errors.Join(err, failErr)
		}
		return finish, nil
	}
	if result.Cleanup != nil {
		defer func() { _ = result.Cleanup() }()
	}
	if !validNativeResultEnvelope(result.Index) {
		code := "ghidra_output_invalid"
		if len(result.Index.Functions) == 0 &&
			result.Index.SchemaVersion == ghidra.IndexSchemaVersion &&
			result.Index.Completeness == "complete" &&
			result.Index.CandidateFunctionCount == 0 &&
			result.Index.DecompiledFunctionCount == 0 {
			code = "ghidra_no_decompilable_functions"
		}
		p.emitFailure(ctx, lease, code)
		if failErr := p.failRun(lease, runID, code); failErr != nil {
			return queue.FinishInput{}, failErr
		}
		return deterministic(code), nil
	}
	if !nativeResultWithinLimits(result.Index, payload.Limits) {
		code := "ghidra_output_limit"
		p.emitFailure(ctx, lease, code)
		if failErr := p.failRun(lease, runID, code); failErr != nil {
			return queue.FinishInput{}, failErr
		}
		return deterministic(code), nil
	}
	p.emitActivity(ctx, lease, "decompile.progress", "info", nativeActivityPayload{
		Analyzer: "ghidra", Phase: "publishing",
		Current: len(result.Index.Functions), Total: result.Index.CandidateFunctionCount,
	})
	if err := p.repository.PublishNativeRun(
		ctx, lease, payload, runID, p.config.EngineVersion, parameterKey,
		result.Index.Completeness,
		func(publishCtx context.Context) ([]NativePublishedResult, func(), error) {
			return p.publishFiles(publishCtx, runID, result)
		},
	); err != nil {
		p.emitFailure(ctx, lease, "decompile_publish_failed")
		if failErr := p.failRun(
			lease, runID, "decompile_publish_failed",
		); failErr != nil {
			return queue.FinishInput{}, errors.Join(err, failErr)
		}
		return queue.FinishInput{}, err
	}
	p.emitActivity(ctx, lease, "decompile.completed", "info", nativeActivityPayload{
		Analyzer: "ghidra", Phase: "completed",
		Current: len(result.Index.Functions), Total: result.Index.CandidateFunctionCount,
		Completeness: result.Index.Completeness,
	})
	outcome := queue.OutcomeSucceeded
	if result.Index.Completeness == "partial" {
		outcome = queue.OutcomePartialSucceeded
	}
	return queue.FinishInput{Outcome: outcome}, nil
}

const nativeActivityHeartbeatInterval = 30 * time.Second

type nativeActivityPayload struct {
	Analyzer       string `json:"analyzer"`
	Phase          string `json:"phase"`
	Current        int    `json:"current,omitempty"`
	Total          int    `json:"total,omitempty"`
	ElapsedSeconds int64  `json:"elapsed_seconds,omitempty"`
	ErrorCode      string `json:"error_code,omitempty"`
	Completeness   string `json:"completeness,omitempty"`
}

func (p *NativeProcessor) analyzeWithActivity(
	ctx context.Context,
	lease queue.Lease,
	request ghidra.Request,
) (ghidra.Result, error) {
	updates := make(chan ghidra.Progress, 16)
	finished := make(chan struct{})
	startedAt := time.Now()
	request.Progress = func(progress ghidra.Progress) {
		select {
		case updates <- progress:
		default:
		}
	}
	p.emitActivity(ctx, lease, "decompile.progress", "info", nativeActivityPayload{
		Analyzer: "ghidra", Phase: "starting",
	})
	go func() {
		defer close(finished)
		ticker := time.NewTicker(nativeActivityHeartbeatInterval)
		defer ticker.Stop()
		current := 0
		total := 0
		for {
			select {
			case progress, ok := <-updates:
				if !ok {
					return
				}
				current = progress.Current
				total = progress.Total
				p.emitActivity(ctx, lease, "decompile.progress", "info", nativeActivityPayload{
					Analyzer: "ghidra", Phase: "running",
					Current: current, Total: total,
					ElapsedSeconds: int64(time.Since(startedAt) / time.Second),
				})
			case <-ticker.C:
				p.emitActivity(ctx, lease, "decompile.progress", "info", nativeActivityPayload{
					Analyzer: "ghidra", Phase: "running",
					Current: current, Total: total,
					ElapsedSeconds: int64(time.Since(startedAt) / time.Second),
				})
			}
		}
	}()
	result, err := p.analyzer.Analyze(ctx, request)
	close(updates)
	<-finished
	return result, err
}

func (p *NativeProcessor) emitActivity(
	ctx context.Context,
	lease queue.Lease,
	eventType string,
	severity string,
	payload nativeActivityPayload,
) {
	encoded, err := json.Marshal(payload)
	if err != nil {
		return
	}
	message := "Ghidra decompilation progress changed."
	switch payload.Phase {
	case "preparing":
		message = "Ghidra input is being prepared."
	case "starting":
		message = "Ghidra JVM is starting."
	case "publishing":
		message = "Ghidra results are being published."
	case "completed":
		message = "Ghidra decompilation completed."
	case "failed":
		message = "Ghidra decompilation failed."
	}
	_ = p.activity.TaskActivity(ctx, lease, queue.ActivityInput{
		EventType: eventType,
		Severity:  severity,
		Message:   message,
		Payload:   encoded,
	})
}

func (p *NativeProcessor) emitFailure(
	ctx context.Context,
	lease queue.Lease,
	code string,
) {
	p.emitActivity(ctx, lease, "decompile.failed", "error", nativeActivityPayload{
		Analyzer: "ghidra", Phase: "failed",
		ErrorCode: code,
	})
}

func classifyNativeFailure(err error) queue.FinishInput {
	for _, value := range []struct {
		target error
		code   string
	}{
		{ghidra.ErrUnsupportedArchitecture, "ghidra_architecture_unsupported"},
		{ghidra.ErrUnsupportedInstruction, "ghidra_instruction_unsupported"},
		{ghidra.ErrDecompileIncomplete, "ghidra_decompile_incomplete"},
		{ghidra.ErrScriptLimit, "ghidra_script_limit"},
		{ghidra.ErrLimitMismatch, "ghidra_limit_mismatch"},
		{ghidra.ErrOutputLimit, "ghidra_output_limit"},
		{ghidra.ErrInvalidResult, "ghidra_output_invalid"},
	} {
		if errors.Is(err, value.target) {
			return deterministic(value.code)
		}
	}
	code := "ghidra_execution_failed"
	if errors.Is(err, ghidra.ErrTimedOut) {
		code = "ghidra_timeout"
	}
	return queue.FinishInput{
		Outcome:   queue.OutcomeTransientFailure,
		ErrorCode: code, ErrorMessage: "Ghidra execution failed.",
	}
}

func validNativeResultEnvelope(index ghidra.Index) bool {
	functionCount := len(index.Functions)
	if index.SchemaVersion != ghidra.IndexSchemaVersion || functionCount == 0 ||
		index.DecompiledFunctionCount != functionCount ||
		index.CandidateFunctionCount < functionCount {
		return false
	}
	switch index.Completeness {
	case "complete":
		return index.CandidateFunctionCount == functionCount
	case "partial":
		return index.CandidateFunctionCount > functionCount
	default:
		return false
	}
}

func nativeResultWithinLimits(index ghidra.Index, limits JobLimits) bool {
	if !validJobLimits(limits) || len(index.Functions) > limits.MaxArtifacts {
		return false
	}
	maximum := uint64(limits.MaxOutputBytes)
	var total uint64
	for _, function := range index.Functions {
		if function.SourceSize == 0 || function.SourceSize > maximum-total {
			return false
		}
		total += function.SourceSize
	}
	return true
}

func (p *NativeProcessor) failRun(
	lease queue.Lease,
	runID string,
	code string,
) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return p.repository.FailNativeRun(
		ctx, lease, runID, code, "Native decompilation failed.",
	)
}

func deterministic(code string) queue.FinishInput {
	return queue.FinishInput{
		Outcome:   queue.OutcomeDeterministicFailure,
		ErrorCode: code, ErrorMessage: "Native decompilation could not be completed.",
	}
}

func (p *NativeProcessor) publishFiles(
	ctx context.Context,
	runID string,
	result ghidra.Result,
) ([]NativePublishedResult, func(), error) {
	values := make([]NativePublishedResult, 0, len(result.Index.Functions))
	directories := make([]string, 0, len(result.Index.Functions))
	entryPoints := make(map[string]struct{}, len(result.Index.EntryPoints))
	for _, entry := range result.Index.EntryPoints {
		entryPoints[entry.Address] = struct{}{}
	}
	outgoingCalls := make(map[string][]ghidra.CallEdge)
	for _, edge := range result.Index.CallEdges {
		outgoingCalls[edge.CallerAddress] = append(
			outgoingCalls[edge.CallerAddress], edge,
		)
	}
	cleanup := func() {
		root, err := os.OpenRoot(p.config.RepositoryRoot)
		if err != nil {
			return
		}
		defer root.Close()
		for _, directory := range directories {
			_ = root.RemoveAll(directory)
		}
	}
	outputRoot, err := os.OpenRoot(result.OutputDir)
	if err != nil {
		return nil, func() {}, err
	}
	defer outputRoot.Close()
	for _, function := range result.Index.Functions {
		if err := ctx.Err(); err != nil {
			cleanup()
			return nil, func() {}, err
		}
		id := nativeResultID(runID, function.Address)
		directory := path.Join("decompile", id)
		key := path.Join(directory, "source.c")
		root, err := os.OpenRoot(p.config.RepositoryRoot)
		if err != nil {
			cleanup()
			return nil, func() {}, err
		}
		if err := ensureNativeDirectory(root, "decompile"); err != nil {
			root.Close()
			cleanup()
			return nil, func() {}, err
		}
		if err := root.Mkdir(directory, 0o700); err != nil {
			root.Close()
			cleanup()
			return nil, func() {}, err
		}
		directories = append(directories, directory)
		sourceInfo, err := outputRoot.Lstat(function.SourceFile)
		if err != nil || !sourceInfo.Mode().IsRegular() ||
			sourceInfo.Mode()&os.ModeSymlink != 0 ||
			uint64(sourceInfo.Size()) != function.SourceSize {
			root.Close()
			cleanup()
			return nil, func() {}, errors.New(
				"native decompile source artifact identity is invalid",
			)
		}
		source, err := outputRoot.Open(function.SourceFile)
		if err != nil {
			root.Close()
			cleanup()
			return nil, func() {}, err
		}
		openedSourceInfo, statErr := source.Stat()
		if statErr != nil || !openedSourceInfo.Mode().IsRegular() ||
			!os.SameFile(sourceInfo, openedSourceInfo) ||
			uint64(openedSourceInfo.Size()) != function.SourceSize {
			source.Close()
			root.Close()
			cleanup()
			return nil, func() {}, errors.New(
				"native decompile source artifact changed while opening",
			)
		}
		destination, err := root.OpenFile(
			key, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600,
		)
		if err != nil {
			source.Close()
			root.Close()
			cleanup()
			return nil, func() {}, err
		}
		hasher := sha256.New()
		written, copyErr := io.Copy(
			io.MultiWriter(destination, hasher),
			io.LimitReader(source, int64(function.SourceSize)+1),
		)
		afterSourceInfo, afterStatErr := source.Stat()
		syncErr := destination.Sync()
		closeErr := errors.Join(destination.Close(), source.Close(), root.Close())
		if copyErr != nil || afterStatErr != nil || syncErr != nil || closeErr != nil ||
			!os.SameFile(openedSourceInfo, afterSourceInfo) ||
			uint64(afterSourceInfo.Size()) != function.SourceSize ||
			uint64(written) != function.SourceSize ||
			hex.EncodeToString(hasher.Sum(nil)) != function.SHA256 {
			cleanup()
			return nil, func() {}, errors.Join(
				copyErr, afterStatErr, syncErr, closeErr,
			)
		}
		_, isEntryPoint := entryPoints[function.Address]
		calls := outgoingCalls[function.Address]
		if calls == nil {
			calls = []ghidra.CallEdge{}
		}
		diagnostics, err := json.Marshal(map[string]any{
			"symbol_kind": "function", "display_name": function.Name,
			"location": function.Address, "size_bytes": function.SizeBytes,
			"program_format":            result.Index.Format,
			"architecture":              result.Index.Architecture,
			"is_entry_point":            isEntryPoint,
			"outgoing_calls":            calls,
			"program_entry_point_count": len(result.Index.EntryPoints),
			"program_segment_count":     len(result.Index.Segments),
			"program_call_edge_count":   len(result.Index.CallEdges),
			"program_completeness":      result.Index.Completeness,
			"candidate_function_count":  result.Index.CandidateFunctionCount,
			"decompiled_function_count": result.Index.DecompiledFunctionCount,
		})
		if err != nil {
			cleanup()
			return nil, func() {}, err
		}
		values = append(values, NativePublishedResult{
			ID: id, SymbolKey: function.Address, StorageKey: key,
			SHA256: function.SHA256, SizeBytes: function.SourceSize,
			Diagnostics: diagnostics,
		})
	}
	return values, cleanup, nil
}

func copyVerifiedNativeSource(
	ctx context.Context,
	repositoryRoot string,
	workRoot string,
	lease queue.Lease,
	target JobTarget,
) (string, func(), error) {
	if target.StorageKey == "" || path.IsAbs(target.StorageKey) ||
		path.Clean(target.StorageKey) != target.StorageKey ||
		strings.Contains(target.StorageKey, `\`) ||
		!sha256Pattern.MatchString(target.SHA256) ||
		target.SizeBytes == 0 || target.SizeBytes > uint64(1<<63-2) {
		return "", func() {}, ErrSourceUnavailable
	}
	root, err := os.OpenRoot(repositoryRoot)
	if err != nil {
		return "", func() {}, err
	}
	info, err := root.Lstat(target.StorageKey)
	if err != nil || !info.Mode().IsRegular() ||
		info.Mode()&os.ModeSymlink != 0 ||
		uint64(info.Size()) != target.SizeBytes {
		root.Close()
		return "", func() {}, ErrSourceUnavailable
	}
	source, err := root.Open(target.StorageKey)
	root.Close()
	if err != nil {
		return "", func() {}, ErrSourceUnavailable
	}
	openedInfo, err := source.Stat()
	if err != nil || !openedInfo.Mode().IsRegular() ||
		!os.SameFile(info, openedInfo) ||
		uint64(openedInfo.Size()) != target.SizeBytes {
		source.Close()
		return "", func() {}, ErrSourceUnavailable
	}
	if err := ensureNativeRootDirectory(workRoot); err != nil {
		source.Close()
		return "", func() {}, err
	}
	work, err := os.OpenRoot(workRoot)
	if err != nil {
		source.Close()
		return "", func() {}, err
	}
	if err := ensureNativeDirectory(work, "native-input"); err != nil {
		work.Close()
		source.Close()
		return "", func() {}, err
	}
	privateKey := path.Join(
		"native-input",
		fmt.Sprintf("%s-a%d-f%d", lease.JobID, lease.Attempt, lease.FencingToken),
	)
	if err := work.Mkdir(privateKey, 0o700); err != nil {
		work.Close()
		source.Close()
		return "", func() {}, err
	}
	var cleanupOnce sync.Once
	cleanup := func() {
		cleanupOnce.Do(func() {
			_ = work.RemoveAll(privateKey)
			_ = work.Close()
		})
	}
	destinationKey := path.Join(privateKey, "input.bin")
	destinationPath := filepath.Join(
		workRoot, filepath.FromSlash(destinationKey),
	)
	destination, err := work.OpenFile(
		destinationKey, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600,
	)
	if err != nil {
		source.Close()
		cleanup()
		return "", func() {}, err
	}
	hasher := sha256.New()
	written, copyErr := io.Copy(
		io.MultiWriter(destination, hasher),
		io.LimitReader(
			&contextReader{ctx: ctx, reader: source},
			int64(target.SizeBytes)+1,
		),
	)
	afterInfo, afterErr := source.Stat()
	syncErr := destination.Sync()
	chmodErr := destination.Chmod(0o400)
	closeErr := errors.Join(destination.Close(), source.Close())
	if copyErr != nil || afterErr != nil || syncErr != nil || chmodErr != nil ||
		closeErr != nil || !os.SameFile(openedInfo, afterInfo) ||
		uint64(afterInfo.Size()) != target.SizeBytes ||
		uint64(written) != target.SizeBytes ||
		hex.EncodeToString(hasher.Sum(nil)) != target.SHA256 {
		cleanup()
		if ctx.Err() != nil {
			return "", func() {}, ctx.Err()
		}
		return "", func() {}, ErrSourceUnavailable
	}
	return destinationPath, cleanup, nil
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

func ensureNativeDirectory(root *os.Root, name string) error {
	info, err := root.Lstat(name)
	if errors.Is(err, os.ErrNotExist) {
		if err := root.Mkdir(name, 0o700); err != nil &&
			!errors.Is(err, os.ErrExist) {
			return err
		}
		info, err = root.Lstat(name)
	}
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("native decompile repository directory is invalid")
	}
	return nil
}

func ensureNativeRootDirectory(value string) error {
	info, err := os.Lstat(value)
	if errors.Is(err, os.ErrNotExist) {
		if err := os.MkdirAll(value, 0o700); err != nil {
			return err
		}
		info, err = os.Lstat(value)
	}
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("native decompile work root is invalid")
	}
	return nil
}

func safeEngineVersion(value string) bool {
	if value == "" || len(value) > 128 || strings.TrimSpace(value) != value {
		return false
	}
	for _, character := range value {
		if character < 0x21 || character > 0x7e {
			return false
		}
	}
	return true
}

type nativeParameterContract struct {
	Contract                 string          `json:"contract"`
	PayloadSchemaVersion     int             `json:"payload_schema_version"`
	EngineTarget             string          `json:"engine_target"`
	EngineVersion            string          `json:"engine_version"`
	AnalyzerParametersSHA256 string          `json:"analyzer_parameters_sha256"`
	Options                  json.RawMessage `json:"options"`
	Limits                   JobLimits       `json:"limits"`
}

func nativeParameterCacheKey(
	payload JobPayload,
	identity ghidra.Identity,
) (string, error) {
	if !safeEngineVersion(identity.EngineVersion) ||
		!sha256Pattern.MatchString(identity.ParametersSHA256) ||
		payload.Engine.Target != EngineGhidra ||
		!json.Valid(payload.Options) ||
		!validJobLimits(payload.Limits) {
		return "", ErrRequestConflict
	}
	encoded, err := json.Marshal(nativeParameterContract{
		Contract:                 "binaryscan-native-decompile-cache-v2",
		PayloadSchemaVersion:     payload.SchemaVersion,
		EngineTarget:             payload.Engine.Target,
		EngineVersion:            identity.EngineVersion,
		AnalyzerParametersSHA256: identity.ParametersSHA256,
		Options:                  payload.Options,
		Limits:                   payload.Limits,
	})
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:]), nil
}

func nativeUUID() (string, error) {
	var value [16]byte
	if _, err := io.ReadFull(rand.Reader, value[:]); err != nil {
		return "", err
	}
	value[6] = (value[6] & 0x0f) | 0x40
	value[8] = (value[8] & 0x3f) | 0x80
	encoded := hex.EncodeToString(value[:])
	return encoded[:8] + "-" + encoded[8:12] + "-" + encoded[12:16] +
		"-" + encoded[16:20] + "-" + encoded[20:], nil
}

func nativeResultID(runID string, symbolKey string) string {
	sum := sha256.Sum256([]byte(runID + "\x00" + symbolKey))
	sum[6] = (sum[6] & 0x0f) | 0x40
	sum[8] = (sum[8] & 0x3f) | 0x80
	encoded := hex.EncodeToString(sum[:16])
	return encoded[:8] + "-" + encoded[8:12] + "-" + encoded[12:16] +
		"-" + encoded[16:20] + "-" + encoded[20:32]
}

func targetNodeID(payload JobPayload) (uint64, error) {
	return strconv.ParseUint(payload.Target.FileNodeID, 10, 64)
}

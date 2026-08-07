package decompile

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"binaryscan/internal/bytecode"
	"binaryscan/internal/queue"
	"binaryscan/internal/workspace"
)

const maxBytecodeDiagnosticsBytes = 8 << 20

// BytecodeAnalyzer is the engine-neutral boundary used by the queue processor.
// Implementations are expected to return a result produced by bytecode.Execute.
type BytecodeAnalyzer interface {
	Analyze(context.Context, bytecode.Request) (bytecode.Result, error)
	Identity() BytecodeAnalyzerIdentity
}

// EngineBytecodeAnalyzer adapts an internal/bytecode Engine without changing
// its descriptor. This keeps fallback engines visibly distinct from requested
// products such as Vineflower while still letting them serve an explicit
// payload target.
type EngineBytecodeAnalyzer struct {
	engine   bytecode.Engine
	identity BytecodeAnalyzerIdentity
}

func NewEngineBytecodeAnalyzer(
	engine bytecode.Engine,
	parametersSHA256 string,
	arguments []string,
	targets []string,
) (*EngineBytecodeAnalyzer, error) {
	if engine == nil || !sha256Pattern.MatchString(parametersSHA256) {
		return nil, errors.New("bytecode engine analyzer identity is invalid")
	}
	identity := BytecodeAnalyzerIdentity{
		Engine: engine.Descriptor(), ParametersSHA256: parametersSHA256,
		Arguments: append([]string(nil), arguments...),
		Targets:   append([]string(nil), targets...),
	}
	if _, err := bytecode.CacheKey(
		strings.Repeat("0", 64), bytecode.FormatClass, identity.Engine,
		identity.Arguments, bytecode.Limits{},
	); err != nil {
		return nil, errors.New("bytecode engine analyzer descriptor is invalid")
	}
	return &EngineBytecodeAnalyzer{engine: engine, identity: identity}, nil
}

func (analyzer *EngineBytecodeAnalyzer) Analyze(
	ctx context.Context,
	request bytecode.Request,
) (bytecode.Result, error) {
	if analyzer == nil || analyzer.engine == nil {
		return bytecode.Result{}, errors.New("bytecode engine analyzer is nil")
	}
	return bytecode.Execute(ctx, analyzer.engine, request)
}

func (analyzer *EngineBytecodeAnalyzer) Identity() BytecodeAnalyzerIdentity {
	if analyzer == nil {
		return BytecodeAnalyzerIdentity{}
	}
	identity := analyzer.identity
	identity.Arguments = append([]string(nil), identity.Arguments...)
	identity.Targets = append([]string(nil), identity.Targets...)
	return identity
}

type BytecodeAnalyzerIdentity struct {
	Engine           bytecode.Descriptor
	ParametersSHA256 string
	Arguments        []string
	Targets          []string
}

type BytecodeRunIdentity struct {
	EngineName            string
	EngineVersion         string
	AnalyzerParametersSHA string
	CacheParametersSHA    string
	ReuseIdentitySHA      string
}

var (
	errBytecodeAlreadyPublished = errors.New(
		"bytecode decompile results already published",
	)
	errBytecodeCacheStale           = errors.New("bytecode decompile cache candidate is stale")
	errBytecodeCacheCommitUncertain = errors.New(
		"bytecode decompile cache commit outcome is uncertain",
	)
	errBytecodeCacheInvalid = errors.New(
		"bytecode decompile cache artifact is invalid",
	)
)

type bytecodeAlreadyPublishedError struct {
	status bytecode.Status
}

func (err bytecodeAlreadyPublishedError) Error() string {
	return errBytecodeAlreadyPublished.Error()
}

func (err bytecodeAlreadyPublishedError) Is(target error) bool {
	return target == errBytecodeAlreadyPublished
}

type BytecodeCachedResult struct {
	ID          string
	SymbolKey   string
	Language    string
	Status      string
	StorageKey  string
	SHA256      string
	SizeBytes   uint64
	Diagnostics json.RawMessage
}

type BytecodeCacheCandidate struct {
	RunID        string
	TaskID       string
	ResultStatus bytecode.Status
	Results      []BytecodeCachedResult
}

type BytecodePublishedResult struct {
	ID          string
	SymbolKey   string
	Language    string
	Status      string
	StorageKey  string
	SHA256      string
	SizeBytes   uint64
	Diagnostics json.RawMessage
}

type BytecodeResultPublisher func(
	context.Context,
) ([]BytecodePublishedResult, func(), error)

type BytecodeRunRepository interface {
	BeginBytecodeRun(
		context.Context, queue.Lease, JobPayload, string, BytecodeRunIdentity,
	) error
	PublishBytecodeRun(
		context.Context, queue.Lease, JobPayload, string, BytecodeRunIdentity,
		bytecode.Status, int, BytecodeResultPublisher,
	) error
	FindBytecodeCache(
		context.Context, queue.Lease, JobPayload, string, BytecodeRunIdentity,
	) (BytecodeCacheCandidate, bool, error)
	PublishBytecodeCacheHit(
		context.Context, queue.Lease, JobPayload, string, BytecodeRunIdentity,
		BytecodeCacheCandidate, []BytecodePublishedResult,
	) error
	FailBytecodeRun(
		context.Context, queue.Lease, string, string, string,
	) error
}

type BytecodeProcessorConfig struct {
	RepositoryRoot    string
	TaskWorkRoot      string
	EngineName        string
	EngineVersion     string
	ArtifactValidator bytecode.ArtifactValidator
}

type BytecodeProcessor struct {
	repository BytecodeRunRepository
	analyzer   BytecodeAnalyzer
	activity   ActivityReporter
	config     BytecodeProcessorConfig
	identity   BytecodeAnalyzerIdentity
	newID      func() (string, error)
}

func NewBytecodeProcessor(
	repository BytecodeRunRepository,
	analyzer BytecodeAnalyzer,
	activity ActivityReporter,
	config BytecodeProcessorConfig,
) (*BytecodeProcessor, error) {
	if repository == nil || analyzer == nil || activity == nil ||
		config.ArtifactValidator == nil {
		return nil, errors.New("bytecode decompile dependencies are required")
	}
	for _, root := range []string{config.RepositoryRoot, config.TaskWorkRoot} {
		if !filepath.IsAbs(root) || filepath.Clean(root) != root || root == "/" {
			return nil, errors.New("bytecode decompile roots are invalid")
		}
	}
	identity := analyzer.Identity()
	if !safeEngineVersion(config.EngineName) ||
		!safeEngineVersion(config.EngineVersion) ||
		identity.Engine.Name != config.EngineName ||
		identity.Engine.Version != config.EngineVersion ||
		!sha256Pattern.MatchString(identity.ParametersSHA256) {
		return nil, errors.New(
			"bytecode decompile analyzer identity does not match configuration",
		)
	}
	arguments := append([]string(nil), identity.Arguments...)
	if _, err := bytecode.CacheKey(
		strings.Repeat("0", 64), bytecode.FormatClass, identity.Engine,
		arguments, bytecode.Limits{},
	); err != nil {
		return nil, errors.New("bytecode decompile analyzer arguments are invalid")
	}
	identity.Arguments = arguments
	identity.Targets = append([]string(nil), identity.Targets...)
	if len(identity.Targets) == 0 {
		return nil, errors.New("bytecode decompile analyzer supports no targets")
	}
	seenTargets := make(map[string]struct{}, len(identity.Targets))
	for _, target := range identity.Targets {
		if target != EngineVineflower && target != EngineJADX &&
			target != EnginePythonBytecode {
			return nil, errors.New("bytecode decompile analyzer target is invalid")
		}
		if _, exists := seenTargets[target]; exists {
			return nil, errors.New("bytecode decompile analyzer target is duplicated")
		}
		seenTargets[target] = struct{}{}
	}
	sort.Strings(identity.Targets)
	return &BytecodeProcessor{
		repository: repository, analyzer: analyzer, activity: activity, config: config,
		identity: identity, newID: nativeUUID,
	}, nil
}

func (p *BytecodeProcessor) Process(
	ctx context.Context,
	lease queue.Lease,
) (finish queue.FinishInput, returnErr error) {
	payload, err := decodeJobPayload(lease.Payload)
	if err != nil || lease.Kind != queue.KindDecompile ||
		lease.TaskAttemptID == nil || payload.TaskID != lease.TaskID ||
		payload.Engine.WorkerKind != TargetBytecode {
		return bytecodeDeterministic("decompile_payload_invalid"), nil
	}
	if !bytecodeAnalyzerSupportsTarget(p.identity, payload.Engine.Target) {
		return bytecodeDeterministic("bytecode_engine_unavailable"), nil
	}
	format, ok := bytecodeFormat(payload.Target.Format)
	if !ok {
		return bytecodeDeterministic("bytecode_format_unsupported"), nil
	}
	attemptCtx, cancelAttempt := context.WithTimeout(
		ctx, time.Duration(payload.Limits.MaxDurationSeconds)*time.Second,
	)
	defer cancelAttempt()
	parameterKey, err := bytecodeParameterCacheKey(payload, p.identity)
	if err != nil {
		return bytecodeDeterministic("decompile_payload_invalid"), nil
	}
	if contextErr := bytecodeAttemptContextError(ctx, attemptCtx); contextErr != nil {
		return finishForBytecodeContextError(contextErr)
	}
	reuseIdentity, err := bytecodeReuseIdentity(payload, p.identity, parameterKey)
	if err != nil {
		return bytecodeDeterministic("decompile_payload_invalid"), nil
	}
	runIdentity := BytecodeRunIdentity{
		EngineName:            p.identity.Engine.Name,
		EngineVersion:         p.identity.Engine.Version,
		AnalyzerParametersSHA: p.identity.ParametersSHA256,
		CacheParametersSHA:    parameterKey,
		ReuseIdentitySHA:      reuseIdentity,
	}
	runID, err := p.newID()
	if err != nil {
		return queue.FinishInput{}, err
	}
	err = p.repository.BeginBytecodeRun(
		attemptCtx, lease, payload, runID, runIdentity,
	)
	if err != nil {
		if errors.Is(err, errBytecodeAlreadyPublished) {
			published := bytecode.StatusComplete
			var replay bytecodeAlreadyPublishedError
			if errors.As(err, &replay) {
				published = replay.status
			}
			return finishForBytecodeStatus(published), nil
		}
		if contextErr := bytecodeAttemptContextError(ctx, attemptCtx); contextErr != nil {
			return finishForBytecodeContextError(contextErr)
		}
		if errors.Is(err, ErrRequestConflict) || errors.Is(err, ErrSourceUnavailable) {
			return bytecodeDeterministic("decompile_source_unavailable"), nil
		}
		return queue.FinishInput{}, err
	}
	p.emitActivity(ctx, lease, payload.Engine.Target, "decompile.progress", "info", bytecodeActivityPayload{
		Phase: "preparing",
	})
	workDirectory, err := workspace.Create(
		p.config.TaskWorkRoot,
		workspace.Identity{
			JobID: lease.JobID, TaskID: lease.TaskID,
			TaskAttemptID: *lease.TaskAttemptID,
			FencingToken:  lease.FencingToken, Kind: string(lease.Kind),
		},
	)
	if err != nil {
		if contextErr := bytecodeAttemptContextError(ctx, attemptCtx); contextErr != nil {
			if failErr := p.failRun(
				lease, runID, bytecodeContextFailureCode(contextErr),
			); failErr != nil {
				return queue.FinishInput{}, errors.Join(contextErr, failErr)
			}
			return finishForBytecodeContextError(contextErr)
		}
		processErr := fmt.Errorf("create bytecode decompile workspace: %w", err)
		if failErr := p.failRun(lease, runID, "decompile_workspace_failed"); failErr != nil {
			processErr = errors.Join(processErr, failErr)
		}
		return queue.FinishInput{}, processErr
	}
	defer func() {
		if cleanupErr := workDirectory.Cleanup(); cleanupErr != nil {
			wrapped := fmt.Errorf("cleanup bytecode decompile workspace: %w", cleanupErr)
			if returnErr != nil {
				returnErr = errors.Join(returnErr, wrapped)
				return
			}
			finish = queue.FinishInput{}
			returnErr = wrapped
		}
	}()
	if contextErr := bytecodeAttemptContextError(ctx, attemptCtx); contextErr != nil {
		if failErr := p.failRun(
			lease, runID, bytecodeContextFailureCode(contextErr),
		); failErr != nil {
			return queue.FinishInput{}, errors.Join(contextErr, failErr)
		}
		return finishForBytecodeContextError(contextErr)
	}

	sourcePath, cleanupSource, err := copyVerifiedNativeSource(
		attemptCtx, p.config.RepositoryRoot, workDirectory.Path(), lease, payload.Target,
	)
	if err != nil {
		if ctxErr := bytecodeAttemptContextError(ctx, attemptCtx); ctxErr != nil {
			if failErr := p.failRun(
				lease, runID, bytecodeContextFailureCode(ctxErr),
			); failErr != nil {
				return queue.FinishInput{}, errors.Join(ctxErr, failErr)
			}
			return finishForBytecodeContextError(ctxErr)
		}
		if failErr := p.failRun(lease, runID, "decompile_source_invalid"); failErr != nil {
			return queue.FinishInput{}, errors.Join(err, failErr)
		}
		return bytecodeDeterministic("decompile_source_invalid"), nil
	}
	defer cleanupSource()

	limits, ok := bytecodeLimits(payload, attemptCtx)
	if !ok {
		if contextErr := bytecodeAttemptContextError(ctx, attemptCtx); contextErr != nil {
			if failErr := p.failRun(
				lease, runID, bytecodeContextFailureCode(contextErr),
			); failErr != nil {
				return queue.FinishInput{}, errors.Join(contextErr, failErr)
			}
			return finishForBytecodeContextError(contextErr)
		}
		if failErr := p.failRun(lease, runID, "bytecode_limit_invalid"); failErr != nil {
			return queue.FinishInput{}, failErr
		}
		return bytecodeDeterministic("bytecode_limit_invalid"), nil
	}
	request := bytecode.Request{
		Input: bytecode.Input{
			Path: sourcePath, SHA256: payload.Target.SHA256,
			Format: format, SizeBytes: int64(payload.Target.SizeBytes),
		},
		Workspace: workDirectory.Path(),
		Arguments: append([]string(nil), p.identity.Arguments...),
		Limits:    limits, ArtifactValidator: p.config.ArtifactValidator,
	}
	p.emitActivity(attemptCtx, lease, payload.Engine.Target, "decompile.progress", "info", bytecodeActivityPayload{
		Phase: "starting",
	})
	if candidate, found, cacheErr := p.repository.FindBytecodeCache(
		attemptCtx, lease, payload, runID, runIdentity,
	); cacheErr == nil && found {
		published, cleanup, materializeErr := p.materializeBytecodeCache(
			attemptCtx, runID, candidate, payload.Limits,
		)
		if materializeErr == nil {
			cacheErr = p.repository.PublishBytecodeCacheHit(
				attemptCtx, lease, payload, runID, runIdentity,
				candidate, published,
			)
			if cacheErr == nil {
				finish := finishForBytecodeStatus(candidate.ResultStatus)
				p.emitBytecodeFinish(attemptCtx, lease, payload.Engine.Target, finish, len(published))
				return finish, nil
			}
			if errors.Is(cacheErr, errBytecodeCacheCommitUncertain) {
				// The rows and private files may already be committed. Leave both
				// untouched so a retry can reconcile through BeginBytecodeRun.
				return queue.FinishInput{}, cacheErr
			}
			cleanup()
			if !errors.Is(cacheErr, errBytecodeCacheStale) {
				if contextErr := bytecodeAttemptContextError(ctx, attemptCtx); contextErr != nil {
					return finishForBytecodeContextError(contextErr)
				}
				if failErr := p.failRun(
					lease, runID, "bytecode_cache_publish_failed",
				); failErr != nil {
					return queue.FinishInput{}, errors.Join(cacheErr, failErr)
				}
				return queue.FinishInput{}, cacheErr
			}
		} else if !errors.Is(materializeErr, errBytecodeCacheInvalid) {
			if contextErr := bytecodeAttemptContextError(ctx, attemptCtx); contextErr != nil {
				return finishForBytecodeContextError(contextErr)
			}
			if failErr := p.failRun(
				lease, runID, "bytecode_cache_materialize_failed",
			); failErr != nil {
				return queue.FinishInput{}, errors.Join(materializeErr, failErr)
			}
			return queue.FinishInput{}, materializeErr
		}
	}
	p.emitActivity(attemptCtx, lease, payload.Engine.Target, "decompile.progress", "info", bytecodeActivityPayload{
		Phase: "running",
	})
	result, err := p.analyzer.Analyze(attemptCtx, request)
	if err != nil {
		slog.WarnContext(
			context.WithoutCancel(attemptCtx),
			"bytecode analyzer execution failed",
			slog.String("engine", p.identity.Engine.Name),
			slog.String("format", string(format)),
			slog.String("error", err.Error()),
		)
		if contextErr := bytecodeAttemptContextError(ctx, attemptCtx); contextErr != nil {
			if failErr := p.failRun(
				lease, runID, bytecodeContextFailureCode(contextErr),
			); failErr != nil {
				return queue.FinishInput{}, errors.Join(contextErr, failErr)
			}
			return finishForBytecodeContextError(contextErr)
		}
		classified := classifyBytecodeFailure(err)
		if failErr := p.failRun(lease, runID, classified.ErrorCode); failErr != nil {
			return queue.FinishInput{}, errors.Join(err, failErr)
		}
		return classified, nil
	}
	if !validBytecodeResultEnvelope(result, request, p.identity) ||
		!publishableBytecodeResult(result) {
		if failErr := p.failRun(lease, runID, "bytecode_output_invalid"); failErr != nil {
			return queue.FinishInput{}, failErr
		}
		return bytecodeDeterministic("bytecode_output_invalid"), nil
	}
	exitCode := 0
	if result.Execution != nil {
		exitCode = result.Execution.ExitCode
	}
	p.emitActivity(attemptCtx, lease, payload.Engine.Target, "decompile.progress", "info", bytecodeActivityPayload{
		Phase: "publishing", Current: len(result.Classes), Total: len(result.Classes),
	})
	if err := p.repository.PublishBytecodeRun(
		attemptCtx, lease, payload, runID, runIdentity, result.Status, exitCode,
		func(publishCtx context.Context) ([]BytecodePublishedResult, func(), error) {
			return p.publishResults(publishCtx, runID, workDirectory.Path(), result)
		},
	); err != nil {
		if contextErr := bytecodeAttemptContextError(ctx, attemptCtx); contextErr != nil {
			if failErr := p.failRun(
				lease, runID, bytecodeContextFailureCode(contextErr),
			); failErr != nil {
				return queue.FinishInput{}, errors.Join(contextErr, failErr)
			}
			return finishForBytecodeContextError(contextErr)
		}
		if failErr := p.failRun(lease, runID, "decompile_publish_failed"); failErr != nil {
			return queue.FinishInput{}, errors.Join(err, failErr)
		}
		return queue.FinishInput{}, err
	}
	if contextErr := bytecodeAttemptContextError(ctx, attemptCtx); contextErr != nil {
		return finishForBytecodeContextError(contextErr)
	}
	finish = finishForBytecodeStatus(result.Status)
	p.emitBytecodeFinish(attemptCtx, lease, payload.Engine.Target, finish, len(result.Classes))
	return finish, nil
}

type bytecodeActivityPayload struct {
	Analyzer  string `json:"analyzer"`
	Phase     string `json:"phase"`
	Current   int    `json:"current,omitempty"`
	Total     int    `json:"total,omitempty"`
	ErrorCode string `json:"error_code,omitempty"`
}

func (p *BytecodeProcessor) emitActivity(
	ctx context.Context,
	lease queue.Lease,
	analyzer string,
	eventType string,
	severity string,
	payload bytecodeActivityPayload,
) {
	payload.Analyzer = analyzer
	encoded, err := json.Marshal(payload)
	if err != nil {
		return
	}
	message := "Bytecode decompiler activity updated."
	switch payload.Phase {
	case "preparing":
		message = "Bytecode decompiler is preparing input."
	case "starting":
		message = "Bytecode decompiler is starting."
	case "running":
		message = "Bytecode decompilation is running."
	case "publishing":
		message = "Bytecode decompilation results are being published."
	case "completed":
		message = "Bytecode decompilation completed."
	case "failed":
		message = "Bytecode decompilation failed."
	}
	_ = p.activity.TaskActivity(ctx, lease, queue.ActivityInput{
		EventType: eventType,
		Severity:  severity,
		Message:   message,
		Payload:   encoded,
	})
}

func (p *BytecodeProcessor) emitBytecodeFinish(
	ctx context.Context,
	lease queue.Lease,
	analyzer string,
	finish queue.FinishInput,
	total int,
) {
	if finish.Outcome == queue.OutcomeSucceeded ||
		finish.Outcome == queue.OutcomePartialSucceeded {
		severity := "info"
		if finish.Outcome == queue.OutcomePartialSucceeded {
			severity = "warning"
		}
		p.emitActivity(ctx, lease, analyzer, "decompile.completed", severity, bytecodeActivityPayload{
			Phase: "completed", Current: total, Total: total,
		})
		return
	}
	p.emitActivity(ctx, lease, analyzer, "decompile.failed", "error", bytecodeActivityPayload{
		Phase: "failed", ErrorCode: finish.ErrorCode,
	})
}

func bytecodeFormat(value string) (bytecode.Format, bool) {
	switch value {
	case "java-class":
		return bytecode.FormatClass, true
	case "jar":
		return bytecode.FormatJAR, true
	case "war":
		return bytecode.FormatWAR, true
	case "ear":
		return bytecode.FormatEAR, true
	case "dex":
		return bytecode.FormatDEX, true
	case "apk":
		return bytecode.FormatAPK, true
	case "pyc":
		return bytecode.FormatPYC, true
	default:
		return "", false
	}
}

func bytecodeAnalyzerSupportsTarget(
	identity BytecodeAnalyzerIdentity,
	target string,
) bool {
	index := sort.SearchStrings(identity.Targets, target)
	return index < len(identity.Targets) && identity.Targets[index] == target
}

func bytecodeLimits(
	payload JobPayload,
	attemptCtx context.Context,
) (bytecode.Limits, bool) {
	if !validJobLimits(payload.Limits) || payload.Target.SizeBytes == 0 ||
		payload.Target.SizeBytes > uint64(bytecode.DefaultMaxInputBytes) {
		return bytecode.Limits{}, false
	}
	deadline, hasDeadline := attemptCtx.Deadline()
	remaining := time.Until(deadline)
	if !hasDeadline || remaining <= 0 {
		return bytecode.Limits{}, false
	}
	return bytecode.Limits{
		MaxDuration:      remaining,
		MaxInputBytes:    int64(payload.Target.SizeBytes),
		MaxClasses:       payload.Limits.MaxArtifacts,
		MaxArtifacts:     payload.Limits.MaxArtifacts,
		MaxArtifactBytes: payload.Limits.MaxOutputBytes,
		MaxClassErrors:   payload.Limits.MaxArtifacts,
	}, true
}

func bytecodeAttemptContextError(
	parent context.Context,
	attempt context.Context,
) error {
	if err := parent.Err(); err != nil {
		return err
	}
	if errors.Is(attempt.Err(), context.DeadlineExceeded) {
		return bytecode.ErrTimedOut
	}
	return attempt.Err()
}

func finishForBytecodeContextError(
	err error,
) (queue.FinishInput, error) {
	if errors.Is(err, bytecode.ErrTimedOut) {
		return queue.FinishInput{
			Outcome: queue.OutcomeTransientFailure, ErrorCode: "bytecode_timeout",
			ErrorMessage: "Bytecode decompiler attempt timed out.",
		}, nil
	}
	return queue.FinishInput{}, err
}

func bytecodeContextFailureCode(err error) string {
	if errors.Is(err, bytecode.ErrTimedOut) {
		return "bytecode_timeout"
	}
	return "decompile_context_cancelled"
}

func validBytecodeResultEnvelope(
	result bytecode.Result,
	request bytecode.Request,
	identity BytecodeAnalyzerIdentity,
) bool {
	expectedCache, err := bytecode.CacheKey(
		request.Input.SHA256, request.Input.Format, identity.Engine,
		request.Arguments, request.Limits,
	)
	if err != nil || result.SchemaVersion != bytecode.SchemaVersion ||
		result.Engine != identity.Engine || result.CacheKey != expectedCache ||
		result.Input.SHA256 != request.Input.SHA256 ||
		result.Input.Format != request.Input.Format ||
		result.Input.SizeBytes != request.Input.SizeBytes {
		return false
	}
	switch result.Status {
	case bytecode.StatusComplete, bytecode.StatusPartial,
		bytecode.StatusBytecodeOnly:
		return len(result.Classes) > 0
	case bytecode.StatusUnsupported:
		return len(result.Classes) == 0 && len(result.Artifacts) == 0
	default:
		return false
	}
}

func publishableBytecodeResult(result bytecode.Result) bool {
	source, bytecodeOnly, failed := 0, 0, 0
	for _, class := range result.Classes {
		switch class.Status {
		case bytecode.ClassSource:
			source++
		case bytecode.ClassBytecodeOnly:
			bytecodeOnly++
		case bytecode.ClassFailed, bytecode.ClassUnsupported:
			failed++
		default:
			return false
		}
	}
	switch result.Status {
	case bytecode.StatusComplete:
		return source == len(result.Classes)
	case bytecode.StatusPartial:
		return failed > 0
	case bytecode.StatusBytecodeOnly:
		return bytecodeOnly == len(result.Classes)
	case bytecode.StatusUnsupported:
		return len(result.Classes) == 0
	default:
		return false
	}
}

func classifyBytecodeFailure(err error) queue.FinishInput {
	for _, value := range []struct {
		target error
		code   string
	}{
		{bytecode.ErrInvalidResult, "bytecode_output_invalid"},
		{bytecode.ErrInvalidRequest, "bytecode_request_invalid"},
		{bytecode.ErrOutputLimit, "bytecode_output_limit"},
		{bytecode.ErrFileCountLimit, "bytecode_file_limit"},
		{bytecode.ErrStdoutLimit, "bytecode_stdout_limit"},
		{bytecode.ErrStderrLimit, "bytecode_stderr_limit"},
		{bytecode.ErrUnsafeOutput, "bytecode_output_unsafe"},
		{bytecode.ErrJVMArchiveLimit, "bytecode_archive_limit"},
		{bytecode.ErrNoJVMClasses, "bytecode_no_classes"},
	} {
		if errors.Is(err, value.target) {
			return bytecodeDeterministic(value.code)
		}
	}
	code := "bytecode_execution_failed"
	if errors.Is(err, bytecode.ErrTimedOut) {
		code = "bytecode_timeout"
	}
	return queue.FinishInput{
		Outcome: queue.OutcomeTransientFailure, ErrorCode: code,
		ErrorMessage: "Bytecode decompiler execution failed.",
	}
}

func bytecodeDeterministic(code string) queue.FinishInput {
	return queue.FinishInput{
		Outcome: queue.OutcomeDeterministicFailure, ErrorCode: code,
		ErrorMessage: "Bytecode decompilation could not be completed.",
	}
}

func finishForBytecodeStatus(status bytecode.Status) queue.FinishInput {
	switch status {
	case bytecode.StatusComplete:
		return queue.FinishInput{Outcome: queue.OutcomeSucceeded}
	case bytecode.StatusPartial, bytecode.StatusBytecodeOnly:
		return queue.FinishInput{Outcome: queue.OutcomePartialSucceeded}
	case bytecode.StatusUnsupported:
		return bytecodeDeterministic("bytecode_format_unsupported")
	default:
		return bytecodeDeterministic("bytecode_output_invalid")
	}
}

func (p *BytecodeProcessor) failRun(
	lease queue.Lease,
	runID string,
	code string,
) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	analyzer := EngineVineflower
	if payload, err := decodeJobPayload(lease.Payload); err == nil &&
		bytecodeAnalyzerSupportsTarget(p.identity, payload.Engine.Target) {
		analyzer = payload.Engine.Target
	}
	p.emitActivity(ctx, lease, analyzer, "decompile.failed", "error", bytecodeActivityPayload{
		Phase: "failed", ErrorCode: code,
	})
	return p.repository.FailBytecodeRun(
		ctx, lease, runID, code, "Bytecode decompilation failed.",
	)
}

func (p *BytecodeProcessor) publishResults(
	ctx context.Context,
	runID string,
	workRoot string,
	result bytecode.Result,
) ([]BytecodePublishedResult, func(), error) {
	artifacts := make(map[string]bytecode.Artifact, len(result.Artifacts))
	for _, artifact := range result.Artifacts {
		artifacts[artifact.ID] = artifact
	}
	classes := result.Classes
	if result.Status == bytecode.StatusUnsupported {
		classes = []bytecode.ClassIndex{{
			Key:  "input:" + result.Input.SHA256,
			Kind: bytecode.KindModule, BinaryName: result.Input.SHA256,
			DisplayName: "Unsupported bytecode input", Language: "unknown",
			Status:      bytecode.ClassUnsupported,
			ArtifactIDs: []string{}, Methods: []bytecode.MethodIndex{},
		}}
	}
	values := make([]BytecodePublishedResult, 0, len(classes))
	directories := make([]string, 0, len(classes))
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
	workspaceRoot, err := os.OpenRoot(workRoot)
	if err != nil {
		return nil, func() {}, err
	}
	defer workspaceRoot.Close()
	classErrors := make(map[string][]bytecode.ClassError)
	for _, classErr := range result.ClassErrors {
		classErrors[classErr.ClassKey] = append(classErrors[classErr.ClassKey], classErr)
	}
	for _, class := range classes {
		if err := ctx.Err(); err != nil {
			cleanup()
			return nil, func() {}, err
		}
		id := bytecodeResultID(runID, class.Key)
		status := persistedBytecodeStatus(class.Status)
		language := persistedBytecodeLanguage(class)
		value := BytecodePublishedResult{
			ID: id, SymbolKey: class.Key, Language: language, Status: status,
		}
		readableArtifacts := readableArtifactsForClass(class, artifacts)
		if class.Status == bytecode.ClassSource ||
			class.Status == bytecode.ClassBytecodeOnly {
			if len(readableArtifacts) == 0 {
				cleanup()
				return nil, func() {}, errors.New(
					"bytecode class has no readable artifacts",
				)
			}
			directory := path.Join("decompile", id)
			key := path.Join(
				directory, bytecodeReadableName(class.Status, readableArtifacts),
			)
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
			digest, size, err := copyBytecodeReadableArtifacts(
				ctx, workspaceRoot, root, key, readableArtifacts,
			)
			root.Close()
			if err != nil {
				cleanup()
				return nil, func() {}, err
			}
			value.StorageKey = key
			value.SHA256 = digest
			value.SizeBytes = size
		}
		groupName := bytecodeGroupName(class.BinaryName)
		location := class.SourceFile
		if location == "" {
			location = class.BinaryName
		}
		diagnostics, err := json.Marshal(map[string]any{
			"symbol_kind": class.Kind, "display_name": class.DisplayName,
			"group_name": groupName, "location": location,
			"signature": class.BinaryName,
			"detail": fmt.Sprintf(
				"%s; %d indexed methods", class.Status, len(class.Methods),
			),
			"binary_name": class.BinaryName, "source_file": class.SourceFile,
			"language": language, "class_status": class.Status,
			"methods": class.Methods, "class_errors": classErrors[class.Key],
			"readable_artifacts": readableArtifacts,
			"result_status":      result.Status, "result_cache_key": result.CacheKey,
			"warnings": result.Warnings,
		})
		if err != nil || len(diagnostics) == 0 ||
			len(diagnostics) > maxBytecodeDiagnosticsBytes {
			cleanup()
			return nil, func() {}, errors.New("bytecode diagnostics exceed publication limit")
		}
		value.Diagnostics = diagnostics
		values = append(values, value)
	}
	return values, cleanup, nil
}

func readableArtifactsForClass(
	class bytecode.ClassIndex,
	artifacts map[string]bytecode.Artifact,
) []bytecode.Artifact {
	values := make([]bytecode.Artifact, 0, len(class.ArtifactIDs))
	for _, id := range class.ArtifactIDs {
		artifact, found := artifacts[id]
		if !found {
			continue
		}
		switch class.Status {
		case bytecode.ClassSource:
			if artifact.Kind == bytecode.ArtifactSource &&
				artifact.Validation == bytecode.ValidationContentVerified {
				values = append(values, artifact)
			}
		case bytecode.ClassBytecodeOnly:
			if (artifact.Kind == bytecode.ArtifactBytecode ||
				artifact.Kind == bytecode.ArtifactIndex) &&
				(artifact.Validation == bytecode.ValidationHashVerified ||
					artifact.Validation == bytecode.ValidationContentVerified) {
				values = append(values, artifact)
			}
		}
	}
	sort.Slice(values, func(left, right int) bool {
		if values[left].Chunk.SetID != values[right].Chunk.SetID {
			return values[left].Chunk.SetID < values[right].Chunk.SetID
		}
		if values[left].Chunk.Index != values[right].Chunk.Index {
			return values[left].Chunk.Index < values[right].Chunk.Index
		}
		return values[left].ID < values[right].ID
	})
	return values
}

func copyBytecodeReadableArtifacts(
	ctx context.Context,
	sourceRoot *os.Root,
	destinationRoot *os.Root,
	destinationKey string,
	artifacts []bytecode.Artifact,
) (string, uint64, error) {
	destination, err := destinationRoot.OpenFile(
		destinationKey, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600,
	)
	if err != nil {
		return "", 0, err
	}
	overall := sha256.New()
	textValidator := &utf8StreamValidator{}
	var total uint64
	fail := func(err error) (string, uint64, error) {
		return "", 0, errors.Join(err, destination.Close())
	}
	for _, artifact := range artifacts {
		if err := ctx.Err(); err != nil {
			return fail(err)
		}
		if artifact.SizeBytes <= 0 || artifact.SizeBytes > 1<<63-2 ||
			!sha256Pattern.MatchString(artifact.SHA256) {
			return fail(errors.New("bytecode source artifact metadata is invalid"))
		}
		expected, err := sourceRoot.Lstat(artifact.RelativePath)
		if err != nil || !expected.Mode().IsRegular() ||
			expected.Mode()&os.ModeSymlink != 0 ||
			expected.Size() != artifact.SizeBytes {
			return fail(errors.New("bytecode source artifact identity is invalid"))
		}
		source, err := sourceRoot.Open(artifact.RelativePath)
		if err != nil {
			return fail(err)
		}
		opened, statErr := source.Stat()
		if statErr != nil || !opened.Mode().IsRegular() ||
			!os.SameFile(expected, opened) || opened.Size() != artifact.SizeBytes {
			source.Close()
			return fail(errors.New("bytecode source artifact changed while opening"))
		}
		artifactHasher := sha256.New()
		written, copyErr := io.Copy(
			io.MultiWriter(destination, overall, artifactHasher, textValidator),
			io.LimitReader(&contextReader{ctx: ctx, reader: source}, artifact.SizeBytes+1),
		)
		after, afterErr := source.Stat()
		closeErr := source.Close()
		if copyErr != nil || afterErr != nil || closeErr != nil ||
			!os.SameFile(opened, after) || after.Size() != artifact.SizeBytes ||
			written != artifact.SizeBytes ||
			hex.EncodeToString(artifactHasher.Sum(nil)) != artifact.SHA256 {
			return fail(errors.Join(copyErr, afterErr, closeErr))
		}
		if uint64(written) > ^uint64(0)-total {
			return fail(errors.New("bytecode source artifact size overflow"))
		}
		total += uint64(written)
	}
	if !textValidator.Valid() {
		return fail(errors.New("bytecode readable artifact is not valid UTF-8"))
	}
	if err := destination.Sync(); err != nil {
		return fail(err)
	}
	if err := destination.Close(); err != nil {
		return "", 0, err
	}
	return hex.EncodeToString(overall.Sum(nil)), total, nil
}

func persistedBytecodeStatus(status bytecode.ClassStatus) string {
	switch status {
	case bytecode.ClassSource:
		return "complete"
	case bytecode.ClassBytecodeOnly:
		return "bytecode_only"
	case bytecode.ClassUnsupported:
		return "unsupported"
	default:
		return "failed"
	}
}

func persistedBytecodeLanguage(class bytecode.ClassIndex) string {
	language := strings.ToLower(class.Language)
	if class.Status != bytecode.ClassBytecodeOnly ||
		strings.Contains(language, "bytecode") {
		return language
	}
	if len(language)+len("-bytecode") <= 32 {
		return language + "-bytecode"
	}
	return "bytecode"
}

func bytecodeGroupName(binaryName string) string {
	if index := strings.LastIndexAny(binaryName, ".$/"); index > 0 {
		return binaryName[:index]
	}
	return "Default package"
}

func bytecodeSourceName(language string) string {
	switch strings.ToLower(language) {
	case "java":
		return "source.java"
	case "kotlin":
		return "source.kt"
	case "python":
		return "source.py"
	default:
		return "source.txt"
	}
}

func bytecodeReadableName(
	status bytecode.ClassStatus,
	artifacts []bytecode.Artifact,
) string {
	if status == bytecode.ClassSource {
		return bytecodeSourceName(artifactsLanguageHint(artifacts))
	}
	for _, artifact := range artifacts {
		if artifact.MediaType == "application/json" ||
			strings.HasSuffix(artifact.MediaType, "+json") {
			return "bytecode.json"
		}
	}
	return "bytecode.txt"
}

func artifactsLanguageHint(artifacts []bytecode.Artifact) string {
	for _, artifact := range artifacts {
		switch artifact.MediaType {
		case "text/x-java-source":
			return "java"
		case "text/x-kotlin-source":
			return "kotlin"
		case "text/x-python":
			return "python"
		}
	}
	return ""
}

type utf8StreamValidator struct {
	tail    []byte
	invalid bool
}

func (validator *utf8StreamValidator) Write(payload []byte) (int, error) {
	originalLength := len(payload)
	data := make([]byte, 0, len(validator.tail)+len(payload))
	data = append(data, validator.tail...)
	data = append(data, payload...)
	validator.tail = validator.tail[:0]
	for len(data) > 0 {
		if !utf8.FullRune(data) {
			validator.tail = append(validator.tail, data...)
			break
		}
		decoded, size := utf8.DecodeRune(data)
		if decoded == utf8.RuneError && size == 1 {
			validator.invalid = true
		}
		data = data[size:]
	}
	return originalLength, nil
}

func (validator *utf8StreamValidator) Valid() bool {
	return !validator.invalid && len(validator.tail) == 0
}

type bytecodeParameterContract struct {
	Contract                 string              `json:"contract"`
	PayloadSchemaVersion     int                 `json:"payload_schema_version"`
	BytecodeSchemaVersion    string              `json:"bytecode_schema_version"`
	EngineTarget             string              `json:"engine_target"`
	Engine                   bytecode.Descriptor `json:"engine"`
	AnalyzerParametersSHA256 string              `json:"analyzer_parameters_sha256"`
	Arguments                []string            `json:"arguments"`
	Options                  json.RawMessage     `json:"options"`
	Limits                   JobLimits           `json:"limits"`
}

func bytecodeParameterCacheKey(
	payload JobPayload,
	identity BytecodeAnalyzerIdentity,
) (string, error) {
	if !bytecodeAnalyzerSupportsTarget(identity, payload.Engine.Target) ||
		!safeEngineVersion(identity.Engine.Name) ||
		!safeEngineVersion(identity.Engine.Version) ||
		!sha256Pattern.MatchString(identity.ParametersSHA256) ||
		!json.Valid(payload.Options) || !validJobLimits(payload.Limits) {
		return "", ErrRequestConflict
	}
	encoded, err := json.Marshal(bytecodeParameterContract{
		Contract:              "binaryscan-bytecode-decompile-cache-v1",
		PayloadSchemaVersion:  payload.SchemaVersion,
		BytecodeSchemaVersion: bytecode.SchemaVersion,
		EngineTarget:          payload.Engine.Target, Engine: identity.Engine,
		AnalyzerParametersSHA256: identity.ParametersSHA256,
		Arguments:                append([]string(nil), identity.Arguments...),
		Options:                  payload.Options, Limits: payload.Limits,
	})
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:]), nil
}

func bytecodeResultID(runID string, symbolKey string) string {
	sum := sha256.Sum256([]byte("bytecode\x00" + runID + "\x00" + symbolKey))
	sum[6] = (sum[6] & 0x0f) | 0x40
	sum[8] = (sum[8] & 0x3f) | 0x80
	encoded := hex.EncodeToString(sum[:16])
	return encoded[:8] + "-" + encoded[8:12] + "-" + encoded[12:16] +
		"-" + encoded[16:20] + "-" + encoded[20:32]
}

package ghidra

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode/utf8"
)

var (
	safeName      = regexp.MustCompile(`^[A-Za-z0-9._-]{1,128}$`)
	digestPattern = regexp.MustCompile(`^[a-f0-9]{64}$`)
	failureMarker = regexp.MustCompile(
		`BINARYSCAN_GHIDRA_ERROR=(unsupported_architecture|unsupported_instruction|decompile_incomplete|script_limit)`,
	)
	progressMarker = regexp.MustCompile(
		`BINARYSCAN_GHIDRA_PROGRESS=([0-9]{1,6})/([0-9]{1,6})`,
	)
)

var (
	ErrTimedOut                = errors.New("ghidra analysis timed out")
	ErrOutputLimit             = errors.New("ghidra output limit exceeded")
	ErrInvalidResult           = errors.New("ghidra result is invalid")
	ErrUnsupportedArchitecture = errors.New("ghidra architecture is unsupported")
	ErrUnsupportedInstruction  = errors.New("ghidra instruction is unsupported")
	ErrDecompileIncomplete     = errors.New("ghidra decompilation is incomplete")
	ErrScriptLimit             = errors.New("ghidra export script limit exceeded")
	ErrLimitMismatch           = errors.New("ghidra request exceeds adapter limits")
)

const (
	IndexSchemaVersion          = 3
	exportScriptContractVersion = 5
	exportScriptFilename        = "ExportDecompiledFunctions.java"
	functionTimeoutSeconds      = 60
	maxDerivedSegments          = 8_192
	maxDerivedCallEdges         = 1_000_000
	sourceSnapshotName          = "source.snapshot"
)

type Config struct {
	Executable       string
	ScriptDirectory  string
	Version          string
	MaxDuration      time.Duration
	TerminationGrace time.Duration
	MaxStdoutBytes   int64
	MaxStderrBytes   int64
	MaxIndexBytes    int64
	MaxOutputBytes   int64
	MaxFunctions     int
}

type Request struct {
	SourcePath   string
	SourceSHA256 string
	SourceSize   uint64
	WorkRoot     string
	JobID        string
	Attempt      uint32
	FencingToken uint64
	Limits       ExecutionLimits
	Progress     func(Progress)
}

type Progress struct {
	Current int
	Total   int
}

// ExecutionLimits are the per-job ceilings enforced by Analyze. Config holds
// the adapter's maximum capacity; a request may only lower those values.
type ExecutionLimits struct {
	MaxDuration            time.Duration
	MaxOutputBytes         int64
	MaxFunctions           int
	MaxStandardOutputBytes int64
}

type Function struct {
	Name       string `json:"name"`
	Address    string `json:"address"`
	SizeBytes  uint64 `json:"size_bytes"`
	SourceFile string `json:"source_file"`
	SHA256     string `json:"sha256"`
	SourceSize uint64 `json:"source_size"`
}

type EntryPoint struct {
	Address string `json:"address"`
	Symbol  string `json:"symbol"`
}

type Segment struct {
	Name        string `json:"name"`
	Start       string `json:"start"`
	End         string `json:"end"`
	SizeBytes   uint64 `json:"size_bytes"`
	Permissions string `json:"permissions"`
	Initialized bool   `json:"initialized"`
	Overlay     bool   `json:"overlay"`
}

type CallEdge struct {
	CallerAddress string `json:"caller_address"`
	CalleeAddress string `json:"callee_address"`
	CalleeName    string `json:"callee_name"`
	External      bool   `json:"external"`
}

type Index struct {
	SchemaVersion           int          `json:"schema_version"`
	Format                  string       `json:"format"`
	Architecture            string       `json:"architecture"`
	Completeness            string       `json:"completeness"`
	CandidateFunctionCount  int          `json:"candidate_function_count"`
	DecompiledFunctionCount int          `json:"decompiled_function_count"`
	EntryPoints             []EntryPoint `json:"entry_points"`
	Segments                []Segment    `json:"segments"`
	Functions               []Function   `json:"functions"`
	CallEdges               []CallEdge   `json:"call_edges"`
}

// Identity binds a result to the exact engine version and exporter settings.
// ParametersSHA256 deliberately excludes installation paths, so moving the
// same pinned tool does not invalidate otherwise identical successful output.
type Identity struct {
	EngineVersion    string
	ParametersSHA256 string
}

type Result struct {
	Index     Index
	OutputDir string
	Stdout    string
	Stderr    string
	Cleanup   func() error
}

type Adapter struct {
	config   Config
	identity Identity
}

type exportParameters struct {
	ContractVersion        int   `json:"contract_version"`
	FunctionTimeoutSeconds int   `json:"function_timeout_seconds"`
	MaxDurationNanos       int64 `json:"max_duration_nanos"`
	TerminationGraceNanos  int64 `json:"termination_grace_nanos"`
	MaxStdoutBytes         int64 `json:"max_stdout_bytes"`
	MaxStderrBytes         int64 `json:"max_stderr_bytes"`
	MaxIndexBytes          int64 `json:"max_index_bytes"`
	MaxOutputBytes         int64 `json:"max_output_bytes"`
	MaxFunctions           int   `json:"max_functions"`
	MaxEntryPoints         int   `json:"max_entry_points"`
	MaxSegments            int   `json:"max_segments"`
	MaxCallEdges           int   `json:"max_call_edges"`
}

func New(config Config) (*Adapter, error) {
	for _, value := range []string{
		config.Executable, config.ScriptDirectory,
	} {
		if !filepath.IsAbs(value) || filepath.Clean(value) != value ||
			value == string(filepath.Separator) {
			return nil, errors.New("ghidra paths must be canonical absolute paths")
		}
	}
	if !safeName.MatchString(config.Version) ||
		config.MaxDuration <= 0 || config.MaxDuration > 24*time.Hour ||
		config.TerminationGrace <= 0 || config.TerminationGrace > time.Minute ||
		config.MaxStdoutBytes <= 0 || config.MaxStderrBytes <= 0 ||
		config.MaxIndexBytes <= 0 || config.MaxOutputBytes <= 0 ||
		config.MaxFunctions <= 0 || config.MaxFunctions > 100_000 {
		return nil, errors.New("ghidra adapter limits are invalid")
	}
	parameters := parametersFor(config)
	encoded, err := json.Marshal(parameters)
	if err != nil {
		return nil, fmt.Errorf("encode Ghidra cache parameters: %w", err)
	}
	digest := sha256.Sum256(encoded)
	return &Adapter{
		config: config,
		identity: Identity{
			EngineVersion:    config.Version,
			ParametersSHA256: hex.EncodeToString(digest[:]),
		},
	}, nil
}

func (a *Adapter) Identity() Identity { return a.identity }

func (a *Adapter) Analyze(ctx context.Context, request Request) (Result, error) {
	if ctx == nil {
		return Result{}, errors.New("ghidra analysis context is required")
	}
	if err := validateRequest(request); err != nil {
		return Result{}, err
	}
	effective, err := effectiveConfig(a.config, request.Limits)
	if err != nil {
		return Result{}, err
	}
	runCtx, cancel := context.WithTimeout(ctx, effective.MaxDuration)
	defer cancel()
	privateName := fmt.Sprintf(
		"%s-a%d-f%d", request.JobID, request.Attempt, request.FencingToken,
	)
	runKey := path.Join("ghidra", privateName)
	cleanup, err := prepareRunDirectory(request.WorkRoot, runKey)
	if err != nil {
		return Result{}, err
	}
	keep := false
	defer func() {
		if !keep {
			_ = cleanup()
		}
	}()
	runRoot := filepath.Join(
		request.WorkRoot, filepath.FromSlash(runKey),
	)
	projectDir := filepath.Join(runRoot, "project")
	outputDir := filepath.Join(runRoot, "output")
	source, err := createVerifiedSourceSnapshot(runCtx, request, runRoot)
	if err != nil {
		if ctx.Err() != nil {
			return Result{}, ctx.Err()
		}
		if errors.Is(runCtx.Err(), context.DeadlineExceeded) {
			return Result{}, ErrTimedOut
		}
		return Result{}, err
	}
	defer source.Close()
	parameters := parametersFor(effective)
	args := []string{
		projectDir, "project-" + privateName,
		"-import", filepath.Join(runRoot, sourceSnapshotName),
		"-scriptPath", a.config.ScriptDirectory,
		"-postScript", exportScriptFilename,
		filepath.Join(outputDir, "index.json"), outputDir,
		strconv.Itoa(parameters.MaxFunctions),
		strconv.FormatInt(parameters.MaxOutputBytes, 10),
		strconv.Itoa(parameters.MaxEntryPoints),
		strconv.Itoa(parameters.MaxSegments),
		strconv.Itoa(parameters.MaxCallEdges),
		strconv.FormatInt(parameters.MaxIndexBytes, 10),
		"-deleteProject",
	}
	budget := newOutputBudget(request.Limits.MaxStandardOutputBytes)
	stdout := newBoundedBuffer(effective.MaxStdoutBytes, budget)
	stderr := newBoundedBuffer(effective.MaxStderrBytes, budget)
	command := exec.Command(a.config.Executable, args...)
	command.Stdout = newProgressWriter(
		stdout,
		request.Progress,
		effective.MaxFunctions,
	)
	command.Stderr = stderr
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := command.Start(); err != nil {
		return Result{}, fmt.Errorf("start analyzeHeadless: %w", err)
	}
	wait := make(chan error, 1)
	go func() { wait <- command.Wait() }()
	var runErr error
	outputExceeded := false
	select {
	case runErr = <-wait:
	case <-budget.exceeded:
		outputExceeded = true
		terminateProcess(command.Process.Pid, a.config.TerminationGrace, wait)
	case <-runCtx.Done():
		terminateProcess(command.Process.Pid, a.config.TerminationGrace, wait)
		if errors.Is(runCtx.Err(), context.DeadlineExceeded) {
			return Result{}, ErrTimedOut
		}
		return Result{}, runCtx.Err()
	}
	combinedOutput := stdout.String() + "\n" + stderr.String()
	if classified := classifyStructuredFailure(combinedOutput); classified != nil {
		return Result{}, fmt.Errorf(
			"analyzeHeadless reported a classified failure: %w; stderr=%q",
			classified, stderr.String(),
		)
	}
	if outputExceeded || stdout.exceeded || stderr.exceeded || budget.isExceeded() {
		return Result{}, ErrOutputLimit
	}
	if runErr != nil {
		if classified := classifyExecutionFailure(combinedOutput); classified != nil {
			return Result{}, fmt.Errorf(
				"analyzeHeadless failed: %w; stderr=%q",
				classified, stderr.String(),
			)
		}
		return Result{}, fmt.Errorf(
			"analyzeHeadless failed: %w; stderr=%q",
			runErr, stderr.String(),
		)
	}
	index, err := a.readIndex(outputDir, effective)
	if err != nil {
		return Result{}, err
	}
	keep = true
	return Result{
		Index: index, OutputDir: outputDir,
		Stdout: stdout.String(), Stderr: stderr.String(),
		Cleanup: cleanup,
	}, nil
}

func effectiveConfig(config Config, limits ExecutionLimits) (Config, error) {
	if limits.MaxDuration <= 0 || limits.MaxDuration > config.MaxDuration ||
		limits.MaxOutputBytes <= 0 || limits.MaxOutputBytes > config.MaxOutputBytes ||
		limits.MaxFunctions <= 0 || limits.MaxFunctions > config.MaxFunctions ||
		limits.MaxStandardOutputBytes <= 0 ||
		limits.MaxStandardOutputBytes > config.MaxStdoutBytes ||
		limits.MaxStandardOutputBytes > config.MaxStderrBytes {
		return Config{}, ErrLimitMismatch
	}
	result := config
	result.MaxDuration = limits.MaxDuration
	result.MaxOutputBytes = limits.MaxOutputBytes
	result.MaxFunctions = limits.MaxFunctions
	result.MaxStdoutBytes = limits.MaxStandardOutputBytes
	result.MaxStderrBytes = limits.MaxStandardOutputBytes
	return result, nil
}

func terminateProcess(pid int, grace time.Duration, wait <-chan error) {
	_ = syscall.Kill(-pid, syscall.SIGTERM)
	timer := time.NewTimer(grace)
	defer timer.Stop()
	select {
	case <-wait:
	case <-timer.C:
		_ = syscall.Kill(-pid, syscall.SIGKILL)
		<-wait
	}
}

func parametersFor(config Config) exportParameters {
	segments := config.MaxFunctions
	if segments > maxDerivedSegments {
		segments = maxDerivedSegments
	}
	callEdges := config.MaxFunctions * 64
	if callEdges > maxDerivedCallEdges {
		callEdges = maxDerivedCallEdges
	}
	return exportParameters{
		ContractVersion:        exportScriptContractVersion,
		FunctionTimeoutSeconds: functionTimeoutSeconds,
		MaxDurationNanos:       config.MaxDuration.Nanoseconds(),
		TerminationGraceNanos:  config.TerminationGrace.Nanoseconds(),
		MaxStdoutBytes:         config.MaxStdoutBytes,
		MaxStderrBytes:         config.MaxStderrBytes,
		MaxIndexBytes:          config.MaxIndexBytes,
		MaxOutputBytes:         config.MaxOutputBytes,
		MaxFunctions:           config.MaxFunctions,
		MaxEntryPoints:         config.MaxFunctions,
		MaxSegments:            segments,
		MaxCallEdges:           callEdges,
	}
}

func classifyExecutionFailure(stderr string) error {
	if classified := classifyStructuredFailure(stderr); classified != nil {
		return classified
	}
	lower := strings.ToLower(stderr)
	for _, marker := range []string{
		"language not found",
		"unable to resolve language",
		"no load spec found",
		"no loader found",
		"could not find a language",
	} {
		if strings.Contains(lower, marker) {
			return ErrUnsupportedArchitecture
		}
	}
	return nil
}

func classifyStructuredFailure(output string) error {
	match := failureMarker.FindStringSubmatch(output)
	if len(match) == 2 {
		switch match[1] {
		case "unsupported_architecture":
			return ErrUnsupportedArchitecture
		case "unsupported_instruction":
			return ErrUnsupportedInstruction
		case "decompile_incomplete":
			return ErrDecompileIncomplete
		case "script_limit":
			return ErrScriptLimit
		}
	}
	return nil
}

func prepareRunDirectory(
	workRoot string,
	runKey string,
) (func() error, error) {
	if err := ensureSafeRootDirectory(workRoot); err != nil {
		return nil, err
	}
	root, err := os.OpenRoot(workRoot)
	if err != nil {
		return nil, fmt.Errorf("open Ghidra work root: %w", err)
	}
	if err := ensureRootDirectory(root, "ghidra"); err != nil {
		root.Close()
		return nil, err
	}
	if err := root.Mkdir(runKey, 0o700); err != nil {
		root.Close()
		return nil, fmt.Errorf("create private Ghidra run directory: %w", err)
	}
	var (
		cleanupOnce sync.Once
		cleanupErr  error
	)
	cleanup := func() error {
		cleanupOnce.Do(func() {
			cleanupErr = errors.Join(root.RemoveAll(runKey), root.Close())
		})
		return cleanupErr
	}
	for _, child := range []string{
		path.Join(runKey, "project"),
		path.Join(runKey, "output"),
	} {
		if err := root.Mkdir(child, 0o700); err != nil {
			_ = cleanup()
			return nil, fmt.Errorf("create private Ghidra directory: %w", err)
		}
	}
	return cleanup, nil
}

func ensureSafeRootDirectory(value string) error {
	info, err := os.Lstat(value)
	if errors.Is(err, os.ErrNotExist) {
		if err := os.MkdirAll(value, 0o700); err != nil {
			return fmt.Errorf("create Ghidra work root: %w", err)
		}
		info, err = os.Lstat(value)
	}
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("Ghidra work root is not a real directory")
	}
	return nil
}

func ensureRootDirectory(root *os.Root, name string) error {
	info, err := root.Lstat(name)
	if errors.Is(err, os.ErrNotExist) {
		if err := root.Mkdir(name, 0o700); err != nil &&
			!errors.Is(err, os.ErrExist) {
			return err
		}
		info, err = root.Lstat(name)
	}
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("Ghidra work directory is invalid")
	}
	return nil
}

func validateRequest(request Request) error {
	if !safeName.MatchString(request.JobID) || request.Attempt == 0 ||
		request.FencingToken == 0 || request.SourceSize == 0 ||
		request.SourceSize > uint64(1<<63-2) ||
		!digestPattern.MatchString(request.SourceSHA256) {
		return errors.New("ghidra request identity is invalid")
	}
	for _, value := range []string{request.SourcePath, request.WorkRoot} {
		if !filepath.IsAbs(value) || filepath.Clean(value) != value ||
			value == string(filepath.Separator) {
			return errors.New("ghidra request paths are invalid")
		}
	}
	info, err := os.Lstat(request.SourcePath)
	if err != nil {
		return fmt.Errorf("inspect ghidra source: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("ghidra source is not a regular file")
	}
	return nil
}

func createVerifiedSourceSnapshot(
	ctx context.Context,
	request Request,
	runRoot string,
) (*os.File, error) {
	before, err := os.Lstat(request.SourcePath)
	if err != nil || !before.Mode().IsRegular() ||
		before.Mode()&os.ModeSymlink != 0 || uint64(before.Size()) != request.SourceSize {
		return nil, errors.New("ghidra source identity is invalid")
	}
	source, err := os.Open(request.SourcePath)
	if err != nil {
		return nil, fmt.Errorf("open ghidra source: %w", err)
	}
	defer source.Close()
	opened, statErr := source.Stat()
	if statErr != nil || !opened.Mode().IsRegular() ||
		!os.SameFile(before, opened) || uint64(opened.Size()) != request.SourceSize {
		return nil, errors.New("ghidra source changed while opening")
	}
	root, err := os.OpenRoot(runRoot)
	if err != nil {
		return nil, fmt.Errorf("open ghidra run root for source snapshot: %w", err)
	}
	defer root.Close()
	destination, err := root.OpenFile(
		sourceSnapshotName, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600,
	)
	if err != nil {
		return nil, fmt.Errorf("create ghidra source snapshot: %w", err)
	}
	hasher := sha256.New()
	written, copyErr := io.Copy(
		io.MultiWriter(destination, hasher),
		io.LimitReader(
			&snapshotContextReader{ctx: ctx, reader: source},
			int64(request.SourceSize)+1,
		),
	)
	syncErr := destination.Sync()
	chmodErr := destination.Chmod(0o400)
	closeErr := destination.Close()
	after, afterErr := source.Stat()
	if copyErr != nil || syncErr != nil || chmodErr != nil || closeErr != nil ||
		afterErr != nil || !os.SameFile(opened, after) ||
		uint64(after.Size()) != request.SourceSize ||
		uint64(written) != request.SourceSize ||
		hex.EncodeToString(hasher.Sum(nil)) != request.SourceSHA256 {
		_ = root.Remove(sourceSnapshotName)
		return nil, fmt.Errorf(
			"ghidra source content does not match request: %w",
			errors.Join(copyErr, syncErr, chmodErr, closeErr, afterErr),
		)
	}
	snapshotInfo, err := root.Lstat(sourceSnapshotName)
	if err != nil || !snapshotInfo.Mode().IsRegular() ||
		snapshotInfo.Mode().Perm() != 0o400 || uint64(snapshotInfo.Size()) != request.SourceSize {
		_ = root.Remove(sourceSnapshotName)
		return nil, errors.New("ghidra source snapshot is invalid")
	}
	snapshot, err := root.Open(sourceSnapshotName)
	if err != nil {
		_ = root.Remove(sourceSnapshotName)
		return nil, fmt.Errorf("reopen ghidra source snapshot: %w", err)
	}
	openedSnapshot, statErr := snapshot.Stat()
	if statErr != nil || !openedSnapshot.Mode().IsRegular() ||
		!os.SameFile(snapshotInfo, openedSnapshot) {
		snapshot.Close()
		_ = root.Remove(sourceSnapshotName)
		return nil, errors.New("ghidra source snapshot changed while reopening")
	}
	return snapshot, nil
}

type snapshotContextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (reader *snapshotContextReader) Read(value []byte) (int, error) {
	if err := reader.ctx.Err(); err != nil {
		return 0, err
	}
	return reader.reader.Read(value)
}

func (a *Adapter) readIndex(outputDir string, config Config) (Index, error) {
	root, err := os.OpenRoot(outputDir)
	if err != nil {
		return Index{}, fmt.Errorf("%w: open output root: %v", ErrInvalidResult, err)
	}
	defer root.Close()
	indexInfo, err := root.Lstat("index.json")
	if err != nil || !indexInfo.Mode().IsRegular() ||
		indexInfo.Mode()&os.ModeSymlink != 0 {
		return Index{}, fmt.Errorf(
			"%w: index.json is missing or is not a regular file: %v",
			ErrInvalidResult, err,
		)
	}
	file, err := root.Open("index.json")
	if err != nil {
		return Index{}, fmt.Errorf("%w: open index: %v", ErrInvalidResult, err)
	}
	defer file.Close()
	limited := io.LimitReader(file, config.MaxIndexBytes+1)
	raw, err := io.ReadAll(limited)
	if err != nil || int64(len(raw)) > config.MaxIndexBytes {
		return Index{}, ErrOutputLimit
	}
	var index Index
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&index); err != nil {
		return Index{}, fmt.Errorf("%w: decode index: %v", ErrInvalidResult, err)
	}
	parameters := parametersFor(config)
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return Index{}, fmt.Errorf("%w: index contains trailing JSON", ErrInvalidResult)
	}
	if index.SchemaVersion != IndexSchemaVersion {
		return Index{}, fmt.Errorf("%w: index schema version is %d", ErrInvalidResult, index.SchemaVersion)
	}
	if !validIndexText(index.Format, 128) || !validIndexText(index.Architecture, 128) {
		return Index{}, fmt.Errorf("%w: format or architecture is invalid", ErrInvalidResult)
	}
	if index.Completeness != "complete" && index.Completeness != "partial" {
		return Index{}, fmt.Errorf("%w: index completeness is %q", ErrInvalidResult, index.Completeness)
	}
	functionCount := len(index.Functions)
	countsValid := index.DecompiledFunctionCount == functionCount &&
		index.CandidateFunctionCount >= index.DecompiledFunctionCount
	if index.Completeness == "complete" {
		countsValid = countsValid && index.CandidateFunctionCount == functionCount
	} else {
		countsValid = countsValid && index.CandidateFunctionCount > functionCount
	}
	if !countsValid {
		return Index{}, fmt.Errorf(
			"%w: function counts are candidate=%d decompiled=%d functions=%d",
			ErrInvalidResult, index.CandidateFunctionCount,
			index.DecompiledFunctionCount, len(index.Functions),
		)
	}
	if index.EntryPoints == nil || index.Segments == nil ||
		index.Functions == nil || index.CallEdges == nil {
		return Index{}, fmt.Errorf("%w: index collection is null", ErrInvalidResult)
	}
	if len(index.EntryPoints) > parameters.MaxEntryPoints ||
		len(index.Segments) > parameters.MaxSegments ||
		len(index.Functions) > parameters.MaxFunctions ||
		len(index.CallEdges) > parameters.MaxCallEdges {
		return Index{}, fmt.Errorf("%w: index collection exceeds its limit", ErrInvalidResult)
	}
	entryAddresses := make(map[string]struct{}, len(index.EntryPoints))
	for _, entry := range index.EntryPoints {
		if !validIndexText(entry.Address, 128) ||
			!validOptionalIndexText(entry.Symbol, 512) {
			return Index{}, fmt.Errorf("%w: entry point is invalid", ErrInvalidResult)
		}
		if _, duplicate := entryAddresses[entry.Address]; duplicate {
			return Index{}, fmt.Errorf("%w: duplicate entry point", ErrInvalidResult)
		}
		entryAddresses[entry.Address] = struct{}{}
	}
	segmentKeys := make(map[string]struct{}, len(index.Segments))
	for _, segment := range index.Segments {
		key := segment.Name + "\x00" + segment.Start
		if !validIndexText(segment.Name, 512) ||
			!validIndexText(segment.Start, 128) ||
			!validIndexText(segment.End, 128) ||
			segment.SizeBytes == 0 ||
			!validPermissions(segment.Permissions) {
			return Index{}, fmt.Errorf("%w: segment %q is invalid", ErrInvalidResult, segment.Name)
		}
		if _, duplicate := segmentKeys[key]; duplicate {
			return Index{}, fmt.Errorf("%w: duplicate segment", ErrInvalidResult)
		}
		segmentKeys[key] = struct{}{}
	}
	var total uint64
	functionAddresses := make(map[string]struct{}, len(index.Functions))
	sourceFiles := make(map[string]struct{}, len(index.Functions))
	for _, function := range index.Functions {
		if !validIndexText(function.Name, 512) ||
			!validIndexText(function.Address, 128) ||
			!safeName.MatchString(function.SourceFile) ||
			filepath.Base(function.SourceFile) != function.SourceFile ||
			!digestPattern.MatchString(function.SHA256) ||
			function.SourceSize == 0 {
			return Index{}, fmt.Errorf(
				"%w: function %q metadata is invalid", ErrInvalidResult, function.Name,
			)
		}
		if _, duplicate := functionAddresses[function.Address]; duplicate {
			return Index{}, fmt.Errorf("%w: duplicate function address", ErrInvalidResult)
		}
		if _, duplicate := sourceFiles[function.SourceFile]; duplicate {
			return Index{}, fmt.Errorf("%w: duplicate function source file", ErrInvalidResult)
		}
		functionAddresses[function.Address] = struct{}{}
		sourceFiles[function.SourceFile] = struct{}{}
		if function.SourceSize > uint64(config.MaxOutputBytes) {
			return Index{}, ErrOutputLimit
		}
		info, err := root.Lstat(function.SourceFile)
		if err != nil || !info.Mode().IsRegular() ||
			uint64(info.Size()) != function.SourceSize {
			return Index{}, fmt.Errorf(
				"%w: function %q source metadata differs: %v",
				ErrInvalidResult, function.Name, err,
			)
		}
		source, err := root.Open(function.SourceFile)
		if err != nil {
			return Index{}, fmt.Errorf("%w: open function source: %v", ErrInvalidResult, err)
		}
		hasher := sha256.New()
		_, copyErr := io.Copy(hasher, io.LimitReader(
			source, int64(function.SourceSize)+1,
		))
		closeErr := source.Close()
		if copyErr != nil || closeErr != nil ||
			hex.EncodeToString(hasher.Sum(nil)) != function.SHA256 {
			return Index{}, fmt.Errorf(
				"%w: function %q source digest differs: %v",
				ErrInvalidResult, function.Name, errors.Join(copyErr, closeErr),
			)
		}
		maximum := uint64(config.MaxOutputBytes)
		if function.SourceSize > maximum-total {
			return Index{}, ErrOutputLimit
		}
		total += function.SourceSize
	}
	callKeys := make(map[string]struct{}, len(index.CallEdges))
	for _, edge := range index.CallEdges {
		key := edge.CallerAddress + "\x00" + edge.CalleeAddress
		if !validIndexText(edge.CallerAddress, 128) ||
			!validIndexText(edge.CalleeAddress, 128) ||
			!validIndexText(edge.CalleeName, 512) {
			return Index{}, fmt.Errorf("%w: call edge is invalid", ErrInvalidResult)
		}
		if _, exists := functionAddresses[edge.CallerAddress]; !exists {
			return Index{}, fmt.Errorf("%w: call edge caller is unknown", ErrInvalidResult)
		}
		if _, duplicate := callKeys[key]; duplicate {
			return Index{}, fmt.Errorf("%w: duplicate call edge", ErrInvalidResult)
		}
		callKeys[key] = struct{}{}
	}
	if err := verifyOutputInventory(root, sourceFiles); err != nil {
		return Index{}, err
	}
	return index, nil
}

func validIndexText(value string, limit int) bool {
	return value != "" && validOptionalIndexText(value, limit)
}

func validOptionalIndexText(value string, limit int) bool {
	if len(value) > limit || !utf8.ValidString(value) {
		return false
	}
	for _, character := range value {
		if character < 0x20 || character == 0x7f {
			return false
		}
	}
	return true
}

func validPermissions(value string) bool {
	return len(value) == 3 &&
		(value[0] == 'r' || value[0] == '-') &&
		(value[1] == 'w' || value[1] == '-') &&
		(value[2] == 'x' || value[2] == '-')
}

func verifyOutputInventory(
	root *os.Root,
	sourceFiles map[string]struct{},
) error {
	directory, err := root.Open(".")
	if err != nil {
		return fmt.Errorf("%w: open output directory: %v", ErrInvalidResult, err)
	}
	entries, readErr := directory.ReadDir(-1)
	closeErr := directory.Close()
	if readErr != nil || closeErr != nil {
		return fmt.Errorf(
			"%w: read output directory: %v",
			ErrInvalidResult, errors.Join(readErr, closeErr),
		)
	}
	seenIndex := false
	for _, entry := range entries {
		if entry.Name() == "index.json" && entry.Type().IsRegular() {
			if seenIndex {
				return fmt.Errorf("%w: duplicate index inventory entry", ErrInvalidResult)
			}
			seenIndex = true
			continue
		}
		if _, expected := sourceFiles[entry.Name()]; !expected || !entry.Type().IsRegular() {
			return fmt.Errorf(
				"%w: unexpected output inventory entry %q with type %v",
				ErrInvalidResult, entry.Name(), entry.Type(),
			)
		}
	}
	if !seenIndex || len(entries) != len(sourceFiles)+1 {
		return fmt.Errorf(
			"%w: output inventory count is %d, expected %d",
			ErrInvalidResult, len(entries), len(sourceFiles)+1,
		)
	}
	return nil
}

type boundedBuffer struct {
	buffer   bytes.Buffer
	limit    int64
	total    int64
	exceeded bool
	budget   *outputBudget
}

type outputBudget struct {
	mu       sync.Mutex
	limit    int64
	total    int64
	over     bool
	exceeded chan struct{}
	once     sync.Once
}

func newOutputBudget(limit int64) *outputBudget {
	return &outputBudget{limit: limit, exceeded: make(chan struct{})}
}

func (b *outputBudget) consume(size int) {
	b.mu.Lock()
	b.total += int64(size)
	if b.total > b.limit {
		b.over = true
	}
	over := b.over
	b.mu.Unlock()
	if over {
		b.once.Do(func() { close(b.exceeded) })
	}
}

func (b *outputBudget) isExceeded() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.over
}

func newBoundedBuffer(limit int64, budget *outputBudget) *boundedBuffer {
	return &boundedBuffer{limit: limit, budget: budget}
}

func (b *boundedBuffer) Write(value []byte) (int, error) {
	if b.budget != nil {
		b.budget.consume(len(value))
	}
	b.total += int64(len(value))
	remaining := b.limit - int64(b.buffer.Len())
	if remaining > 0 {
		write := int64(len(value))
		if write > remaining {
			write = remaining
		}
		_, _ = b.buffer.Write(value[:write])
	}
	if b.total > b.limit {
		b.exceeded = true
	}
	return len(value), nil
}

func (b *boundedBuffer) String() string {
	return strings.TrimSpace(b.buffer.String())
}

type progressWriter struct {
	destination io.Writer
	callback    func(Progress)
	maximum     int
	pending     []byte
	last        Progress
}

func newProgressWriter(
	destination io.Writer,
	callback func(Progress),
	maximum int,
) io.Writer {
	if callback == nil {
		return destination
	}
	return &progressWriter{
		destination: destination,
		callback:    callback,
		maximum:     maximum,
		pending:     make([]byte, 0, 256),
	}
}

func (writer *progressWriter) Write(value []byte) (int, error) {
	written, err := writer.destination.Write(value)
	if written > 0 {
		writer.observe(value[:written])
	}
	return written, err
}

func (writer *progressWriter) observe(value []byte) {
	writer.pending = append(writer.pending, value...)
	for {
		newline := bytes.IndexByte(writer.pending, '\n')
		if newline < 0 {
			if len(writer.pending) > 4096 {
				writer.pending = writer.pending[:0]
			}
			return
		}
		line := string(writer.pending[:newline])
		writer.pending = writer.pending[newline+1:]
		matches := progressMarker.FindStringSubmatch(line)
		if len(matches) != 3 {
			continue
		}
		current, currentErr := strconv.Atoi(matches[1])
		total, totalErr := strconv.Atoi(matches[2])
		if currentErr != nil || totalErr != nil || total < 1 ||
			total > writer.maximum || current < 0 || current > total ||
			(writer.last.Total != 0 &&
				(total != writer.last.Total || current < writer.last.Current)) ||
			(current == writer.last.Current && total == writer.last.Total) {
			continue
		}
		writer.last = Progress{Current: current, Total: total}
		writer.callback(writer.last)
	}
}

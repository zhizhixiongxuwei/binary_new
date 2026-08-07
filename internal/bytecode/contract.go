package bytecode

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	DefaultMaxDuration            = 20 * time.Minute
	DefaultMaxInputBytes    int64 = 2 << 30
	DefaultMaxClasses             = 20_000
	DefaultMaxMethods             = 200_000
	DefaultMaxArtifacts           = 3_000
	DefaultMaxArtifactBytes int64 = 128 << 20
	DefaultMaxClassErrors         = 3_000

	maxContractArguments          = 1024
	maxContractArgumentBytes      = 64 << 10
	maxContractTotalArgumentBytes = 1 << 20
)

var (
	sha256Pattern     = regexp.MustCompile(`^[a-f0-9]{64}$`)
	descriptorPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+\-]{0,127}$`)
	identifierPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/@+\-$]{0,999}$`)
	codePattern       = regexp.MustCompile(`^[a-z][a-z0-9_.-]{0,127}$`)
)

type Engine interface {
	Descriptor() Descriptor
	// Supports must be a pure, bounded in-memory capability lookup. It must not
	// perform filesystem, process, or network work because it has no context.
	Supports(Format) bool
	Decompile(context.Context, Request) (Output, error)
}

type EngineFunc struct {
	EngineDescriptor Descriptor
	SupportedFormats []Format
	Run              func(context.Context, Request) (Output, error)
}

func (engine EngineFunc) Descriptor() Descriptor { return engine.EngineDescriptor }

func (engine EngineFunc) Supports(format Format) bool {
	for _, candidate := range engine.SupportedFormats {
		if candidate == format {
			return true
		}
	}
	return false
}

func (engine EngineFunc) Decompile(
	ctx context.Context,
	request Request,
) (Output, error) {
	if engine.Run == nil {
		return Output{}, errors.New("bytecode engine function is nil")
	}
	return engine.Run(ctx, request)
}

func Execute(
	ctx context.Context,
	engine Engine,
	request Request,
) (Result, error) {
	if ctx == nil {
		return Result{}, fmt.Errorf("%w: context is nil", ErrInvalidRequest)
	}
	if engine == nil || nilEngine(engine) {
		return Result{}, fmt.Errorf("%w: engine is nil", ErrInvalidConfiguration)
	}
	descriptor := engine.Descriptor()
	if err := validateDescriptor(descriptor); err != nil {
		return Result{}, err
	}
	normalized, err := normalizeRequest(request)
	if err != nil {
		return Result{}, err
	}
	runCtx, cancel := context.WithTimeout(ctx, normalized.Limits.MaxDuration)
	defer cancel()
	bound, err := bindInput(runCtx, normalized.Input, normalized.Workspace)
	if err != nil {
		if contextErr := mappedContextError(ctx, runCtx); contextErr != nil {
			return Result{}, contextErr
		}
		return Result{}, err
	}
	defer bound.close()
	publicInput := normalized.Input
	publicInput.verified = nil
	normalized.Input.Path = ""
	normalized.Input.verified = bound
	if contextErr := mappedContextError(ctx, runCtx); contextErr != nil {
		return Result{}, contextErr
	}
	cacheKey, err := CacheKey(
		normalized.Input.SHA256,
		normalized.Input.Format,
		descriptor,
		normalized.Arguments,
		normalized.Limits,
	)
	if err != nil {
		return Result{}, err
	}
	base := Result{
		SchemaVersion: SchemaVersion,
		Engine:        descriptor,
		Input:         publicInput,
		CacheKey:      cacheKey,
		Classes:       []ClassIndex{}, Artifacts: []Artifact{},
		ClassErrors: []ClassError{}, Warnings: []string{},
	}
	if contextErr := mappedContextError(ctx, runCtx); contextErr != nil {
		return Result{}, contextErr
	}
	supported := engine.Supports(normalized.Input.Format)
	if contextErr := mappedContextError(ctx, runCtx); contextErr != nil {
		return Result{}, contextErr
	}
	if !supported {
		base.Status = StatusUnsupported
		if contextErr := mappedContextError(ctx, runCtx); contextErr != nil {
			return Result{}, contextErr
		}
		return base, nil
	}

	output, runErr := engine.Decompile(runCtx, normalized)
	if contextErr := runCtx.Err(); contextErr != nil {
		if errors.Is(contextErr, context.DeadlineExceeded) && ctx.Err() == nil {
			return Result{}, ErrTimedOut
		}
		return Result{}, contextErr
	}
	if runErr != nil {
		return Result{}, fmt.Errorf("bytecode engine %s failed: %w", descriptor.Name, runErr)
	}
	output = deepCopyAndNormalizeOutput(output)
	if contextErr := mappedContextError(ctx, runCtx); contextErr != nil {
		return Result{}, contextErr
	}
	if err := prevalidateOutputStructure(output, normalized.Limits); err != nil {
		return Result{}, err
	}
	if contextErr := mappedContextError(ctx, runCtx); contextErr != nil {
		return Result{}, contextErr
	}
	if err := validateArtifacts(runCtx, normalized, &output); err != nil {
		if contextErr := mappedContextError(ctx, runCtx); contextErr != nil {
			return Result{}, contextErr
		}
		return Result{}, err
	}
	if contextErr := mappedContextError(ctx, runCtx); contextErr != nil {
		return Result{}, contextErr
	}
	if err := validateOutput(output, normalized.Limits); err != nil {
		return Result{}, err
	}
	if contextErr := mappedContextError(ctx, runCtx); contextErr != nil {
		return Result{}, contextErr
	}
	base.Status = output.Status
	base.Classes = output.Classes
	base.Artifacts = output.Artifacts
	base.ClassErrors = output.ClassErrors
	base.Warnings = output.Warnings
	base.Execution = cloneExecution(output.Execution)
	if contextErr := mappedContextError(ctx, runCtx); contextErr != nil {
		return Result{}, contextErr
	}
	return base, nil
}

func mappedContextError(parent context.Context, operation context.Context) error {
	if parentErr := parent.Err(); parentErr != nil {
		return parentErr
	}
	if errors.Is(operation.Err(), context.DeadlineExceeded) {
		return ErrTimedOut
	}
	return operation.Err()
}

func nilEngine(engine Engine) bool {
	value := reflect.ValueOf(engine)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map,
		reflect.Pointer, reflect.Slice:
		return value.IsNil()
	default:
		return false
	}
}

func validateDescriptor(descriptor Descriptor) error {
	if !descriptorPattern.MatchString(descriptor.Name) ||
		!descriptorPattern.MatchString(descriptor.Version) {
		return fmt.Errorf("%w: engine descriptor is invalid", ErrInvalidConfiguration)
	}
	return nil
}

func normalizeRequest(request Request) (Request, error) {
	if !request.Input.Format.Valid() ||
		!sha256Pattern.MatchString(request.Input.SHA256) ||
		request.Input.SizeBytes < 0 ||
		!canonicalAbsolute(request.Input.Path) ||
		!canonicalAbsolute(request.Workspace) {
		return Request{}, fmt.Errorf("%w: input is invalid", ErrInvalidRequest)
	}
	inputInfo, err := os.Lstat(request.Input.Path)
	if err != nil || !inputInfo.Mode().IsRegular() ||
		inputInfo.Mode()&os.ModeSymlink != 0 ||
		inputInfo.Size() != request.Input.SizeBytes {
		return Request{}, fmt.Errorf("%w: input file is invalid", ErrInvalidRequest)
	}
	workspaceInfo, err := os.Lstat(request.Workspace)
	if err != nil || !workspaceInfo.IsDir() ||
		workspaceInfo.Mode()&os.ModeSymlink != 0 {
		return Request{}, fmt.Errorf("%w: workspace is invalid", ErrInvalidRequest)
	}
	arguments, err := validateAndCloneArguments(
		request.Arguments,
		maxContractArguments,
		maxContractArgumentBytes,
		maxContractTotalArgumentBytes,
	)
	if err != nil {
		return Request{}, err
	}
	limits, err := normalizeLimits(request.Limits)
	if err != nil {
		return Request{}, err
	}
	if request.Input.SizeBytes > limits.MaxInputBytes {
		return Request{}, fmt.Errorf("%w: input exceeds byte limit", ErrInvalidRequest)
	}
	request.Arguments = arguments
	request.Limits = limits
	return request, nil
}

func normalizeLimits(limits Limits) (Limits, error) {
	if limits.MaxDuration < 0 || limits.MaxInputBytes < 0 ||
		limits.MaxClasses < 0 ||
		limits.MaxMethods < 0 || limits.MaxArtifacts < 0 ||
		limits.MaxArtifactBytes < 0 ||
		limits.MaxClassErrors < 0 {
		return Limits{}, fmt.Errorf("%w: limits are negative", ErrInvalidRequest)
	}
	if limits.MaxDuration == 0 {
		limits.MaxDuration = DefaultMaxDuration
	}
	if limits.MaxInputBytes == 0 {
		limits.MaxInputBytes = DefaultMaxInputBytes
	}
	if limits.MaxClasses == 0 {
		limits.MaxClasses = DefaultMaxClasses
	}
	if limits.MaxMethods == 0 {
		limits.MaxMethods = DefaultMaxMethods
	}
	if limits.MaxArtifacts == 0 {
		limits.MaxArtifacts = DefaultMaxArtifacts
	}
	if limits.MaxArtifactBytes == 0 {
		limits.MaxArtifactBytes = DefaultMaxArtifactBytes
	}
	if limits.MaxClassErrors == 0 {
		limits.MaxClassErrors = DefaultMaxClassErrors
	}
	if limits.MaxDuration > DefaultMaxDuration ||
		limits.MaxInputBytes > DefaultMaxInputBytes ||
		limits.MaxClasses > DefaultMaxClasses ||
		limits.MaxMethods > DefaultMaxMethods ||
		limits.MaxArtifacts > DefaultMaxArtifacts ||
		limits.MaxArtifactBytes > DefaultMaxArtifactBytes ||
		limits.MaxClassErrors > DefaultMaxClassErrors {
		return Limits{}, fmt.Errorf("%w: limits exceed ceilings", ErrInvalidRequest)
	}
	return limits, nil
}

func validateArtifacts(
	ctx context.Context,
	request Request,
	output *Output,
) error {
	if len(output.Artifacts) == 0 {
		return nil
	}
	if request.ArtifactValidator == nil || nilInterface(request.ArtifactValidator) {
		return fmt.Errorf(
			"%w: artifact validator is required", ErrInvalidResult,
		)
	}
	for index := range output.Artifacts {
		candidate := output.Artifacts[index]
		candidate.ClassKeys = append([]string(nil), candidate.ClassKeys...)
		candidate.Validation = ""
		validation, err := request.ArtifactValidator.ValidateArtifact(
			ctx, request.Workspace, candidate,
		)
		if err != nil {
			if contextErr := ctx.Err(); contextErr != nil {
				return contextErr
			}
			return fmt.Errorf(
				"%w: validate artifact %s: %v",
				ErrInvalidResult, candidate.ID, err,
			)
		}
		output.Artifacts[index].Validation = validation
	}
	return nil
}

func prevalidateOutputStructure(output Output, limits Limits) error {
	if len(output.Classes) > limits.MaxClasses ||
		len(output.Artifacts) > limits.MaxArtifacts ||
		len(output.ClassErrors) > limits.MaxClassErrors {
		return invalidResult("result count exceeds a limit")
	}
	if output.Status != StatusComplete && output.Status != StatusPartial &&
		output.Status != StatusBytecodeOnly && output.Status != StatusUnsupported {
		return invalidResult("status is invalid")
	}
	if output.Execution != nil &&
		(output.Execution.ExitCode < 0 || output.Execution.DurationMS < 0 ||
			output.Execution.OutputBytes < 0 || output.Execution.OutputFiles < 0) {
		return invalidResult("execution summary is invalid")
	}
	if output.Status == StatusUnsupported &&
		(len(output.Classes) != 0 || len(output.Artifacts) != 0 ||
			len(output.ClassErrors) != 0) {
		return invalidResult("unsupported result contains output")
	}
	if output.Status != StatusUnsupported && len(output.Classes) == 0 {
		return invalidResult("result has no class or module index")
	}
	classes := make(map[string]ClassIndex, len(output.Classes))
	methodKeys := make(map[string]struct{})
	methodCount := 0
	for _, class := range output.Classes {
		if _, exists := classes[class.Key]; exists {
			return invalidResult("class key is duplicated")
		}
		if err := validateClass(class); err != nil {
			return err
		}
		if len(class.Methods) > limits.MaxMethods-methodCount {
			return invalidResult("method count exceeds limit")
		}
		methodCount += len(class.Methods)
		for _, method := range class.Methods {
			if _, exists := methodKeys[method.Key]; exists {
				return invalidResult("method key is duplicated")
			}
			methodKeys[method.Key] = struct{}{}
		}
		classes[class.Key] = class
	}
	if _, err := validateArtifactMetadata(output.Artifacts, limits, false); err != nil {
		return err
	}
	if _, err := validateClassErrors(output.ClassErrors, classes); err != nil {
		return err
	}
	return validateWarnings(output.Warnings)
}

func validateOutput(output Output, limits Limits) error {
	if len(output.Classes) > limits.MaxClasses ||
		len(output.Artifacts) > limits.MaxArtifacts ||
		len(output.ClassErrors) > limits.MaxClassErrors {
		return invalidResult("result count exceeds a limit")
	}
	if output.Status != StatusComplete && output.Status != StatusPartial &&
		output.Status != StatusBytecodeOnly && output.Status != StatusUnsupported {
		return invalidResult("status is invalid")
	}
	if output.Execution != nil &&
		(output.Execution.ExitCode < 0 || output.Execution.DurationMS < 0 ||
			output.Execution.OutputBytes < 0 || output.Execution.OutputFiles < 0) {
		return invalidResult("execution summary is invalid")
	}
	if output.Status == StatusUnsupported {
		if len(output.Classes) != 0 || len(output.Artifacts) != 0 ||
			len(output.ClassErrors) != 0 {
			return invalidResult("unsupported result contains output")
		}
		return validateWarnings(output.Warnings)
	}
	if len(output.Classes) == 0 {
		return invalidResult("result has no class or module index")
	}

	artifacts, err := validateArtifactMetadata(output.Artifacts, limits, true)
	if err != nil {
		return err
	}
	classes := make(map[string]ClassIndex, len(output.Classes))
	methodKeys := make(map[string]struct{})
	methodCount := 0
	sourceClasses := 0
	bytecodeClasses := 0
	failureClasses := 0
	for _, class := range output.Classes {
		if _, exists := classes[class.Key]; exists {
			return invalidResult("class key is duplicated")
		}
		if err := validateClass(class); err != nil {
			return err
		}
		methodCount += len(class.Methods)
		if methodCount > limits.MaxMethods {
			return invalidResult("method count exceeds limit")
		}
		for _, method := range class.Methods {
			if _, exists := methodKeys[method.Key]; exists {
				return invalidResult("method key is duplicated")
			}
			methodKeys[method.Key] = struct{}{}
		}
		for _, artifactID := range class.ArtifactIDs {
			artifact, exists := artifacts[artifactID]
			if !exists || !containsSorted(artifact.ClassKeys, class.Key) {
				return invalidResult("class artifact link is inconsistent")
			}
		}
		classes[class.Key] = class
		if class.Status == ClassSource {
			sourceClasses++
			if !hasValidatedArtifact(class, artifacts, ArtifactSource,
				ValidationContentVerified) {
				return invalidResult("source class lacks validated source")
			}
		}
		if class.Status == ClassBytecodeOnly {
			bytecodeClasses++
		}
		if class.Status == ClassFailed || class.Status == ClassUnsupported {
			failureClasses++
		}
		if class.Status == ClassBytecodeOnly &&
			!hasValidatedBytecode(class, artifacts) {
			return invalidResult("bytecode class lacks validated bytecode")
		}
	}
	for _, artifact := range output.Artifacts {
		for _, classKey := range artifact.ClassKeys {
			class, exists := classes[classKey]
			if !exists || !containsSorted(class.ArtifactIDs, artifact.ID) {
				return invalidResult("artifact class link is inconsistent")
			}
		}
	}
	classErrors, err := validateClassErrors(output.ClassErrors, classes)
	if err != nil {
		return err
	}
	for _, class := range output.Classes {
		if (class.Status == ClassFailed || class.Status == ClassUnsupported) &&
			classErrors[class.Key] == 0 {
			return invalidResult("failed class lacks a class error")
		}
	}
	if err := validateWarnings(output.Warnings); err != nil {
		return err
	}

	switch output.Status {
	case StatusComplete:
		if sourceClasses != len(output.Classes) || len(output.ClassErrors) != 0 ||
			(output.Execution != nil && output.Execution.ExitCode != 0) {
			return invalidResult("complete result is not wholly successful")
		}
	case StatusPartial:
		if failureClasses == 0 && len(output.ClassErrors) == 0 {
			return invalidResult("partial result lacks failure evidence")
		}
	case StatusBytecodeOnly:
		if sourceClasses != 0 || bytecodeClasses != len(output.Classes) ||
			len(output.ClassErrors) != 0 {
			return invalidResult("bytecode-only result lacks bytecode-only classes")
		}
		for _, artifact := range output.Artifacts {
			if artifact.Kind == ArtifactSource {
				return invalidResult("bytecode-only result contains source artifacts")
			}
		}
	}
	return nil
}

func validateArtifactMetadata(
	artifacts []Artifact,
	limits Limits,
	requireValidation bool,
) (map[string]Artifact, error) {
	byID := make(map[string]Artifact, len(artifacts))
	paths := make(map[string]struct{}, len(artifacts))
	var declaredBytes int64
	type chunkSet struct {
		count uint32
		seen  map[uint32]struct{}
	}
	sets := make(map[string]*chunkSet)
	for _, artifact := range artifacts {
		if !identifierPattern.MatchString(artifact.ID) ||
			!identifierPattern.MatchString(artifact.Chunk.SetID) ||
			!validArtifactKind(artifact.Kind) ||
			!validMediaType(artifact.MediaType) ||
			!validRelativePath(artifact.RelativePath) ||
			!sha256Pattern.MatchString(artifact.SHA256) ||
			artifact.SizeBytes <= 0 ||
			artifact.Chunk.Count == 0 ||
			artifact.Chunk.Index >= artifact.Chunk.Count ||
			artifact.Chunk.Count > uint32(limits.MaxArtifacts) {
			return nil, invalidResult("artifact metadata is invalid")
		}
		if requireValidation &&
			artifact.Validation != ValidationHashVerified &&
			artifact.Validation != ValidationContentVerified {
			return nil, invalidResult("artifact validation is invalid")
		}
		if _, exists := byID[artifact.ID]; exists {
			return nil, invalidResult("artifact ID is duplicated")
		}
		if _, exists := paths[artifact.RelativePath]; exists {
			return nil, invalidResult("artifact path is duplicated")
		}
		paths[artifact.RelativePath] = struct{}{}
		if artifact.SizeBytes > limits.MaxArtifactBytes-declaredBytes {
			return nil, invalidResult("artifact bytes exceed limit")
		}
		declaredBytes += artifact.SizeBytes
		if requireValidation && artifact.Kind == ArtifactSource &&
			artifact.Validation != ValidationContentVerified {
			return nil, invalidResult("source artifact was not content validated")
		}
		if !sortedUnique(artifact.ClassKeys) {
			return nil, invalidResult("artifact class keys are not unique")
		}
		set := sets[artifact.Chunk.SetID]
		if set == nil {
			set = &chunkSet{count: artifact.Chunk.Count, seen: make(map[uint32]struct{})}
			sets[artifact.Chunk.SetID] = set
		}
		if set.count != artifact.Chunk.Count {
			return nil, invalidResult("artifact chunk count is inconsistent")
		}
		if _, exists := set.seen[artifact.Chunk.Index]; exists {
			return nil, invalidResult("artifact chunk index is duplicated")
		}
		set.seen[artifact.Chunk.Index] = struct{}{}
		byID[artifact.ID] = artifact
	}
	for _, set := range sets {
		if len(set.seen) != int(set.count) {
			return nil, invalidResult("artifact chunk set is incomplete")
		}
	}
	return byID, nil
}

func validateClass(class ClassIndex) error {
	if !identifierPattern.MatchString(class.Key) ||
		(class.Kind != KindClass && class.Kind != KindModule) ||
		!validText(class.BinaryName, 2048) ||
		!validText(class.DisplayName, 2048) ||
		!validText(class.Language, 64) ||
		(class.SourceFile != "" && !validRelativePath(class.SourceFile)) ||
		(class.Status != ClassSource && class.Status != ClassBytecodeOnly &&
			class.Status != ClassFailed && class.Status != ClassUnsupported) ||
		!sortedUnique(class.ArtifactIDs) {
		return invalidResult("class index is invalid")
	}
	for _, method := range class.Methods {
		if !identifierPattern.MatchString(method.Key) ||
			!validText(method.Name, 1024) ||
			(method.QualifiedName != "" && !validText(method.QualifiedName, 4096)) ||
			(method.Descriptor != "" && !validText(method.Descriptor, 4096)) ||
			(method.Signature != "" && !validText(method.Signature, 4096)) {
			return invalidResult("method index is invalid")
		}
		if method.Source != nil &&
			(method.Source.StartLine == 0 ||
				method.Source.EndLine < method.Source.StartLine) {
			return invalidResult("method source range is invalid")
		}
		if method.Bytecode != nil && method.Bytecode.SizeBytes == 0 {
			return invalidResult("method bytecode range is invalid")
		}
	}
	return nil
}

func validateClassErrors(
	errors []ClassError,
	classes map[string]ClassIndex,
) (map[string]int, error) {
	counts := make(map[string]int)
	seen := make(map[string]struct{})
	for _, classError := range errors {
		if _, exists := classes[classError.ClassKey]; !exists ||
			!codePattern.MatchString(classError.Code) ||
			!validText(classError.Message, 4096) {
			return nil, invalidResult("class error is invalid")
		}
		key := classError.ClassKey + "\x00" + classError.Code + "\x00" + classError.Message
		if _, exists := seen[key]; exists {
			return nil, invalidResult("class error is duplicated")
		}
		seen[key] = struct{}{}
		counts[classError.ClassKey]++
	}
	return counts, nil
}

func validateWarnings(warnings []string) error {
	for _, warning := range warnings {
		if !validText(warning, 4096) {
			return invalidResult("warning is invalid")
		}
	}
	return nil
}

func hasValidatedArtifact(
	class ClassIndex,
	artifacts map[string]Artifact,
	kind ArtifactKind,
	validation ArtifactValidation,
) bool {
	for _, id := range class.ArtifactIDs {
		artifact := artifacts[id]
		if artifact.Kind == kind && artifact.Validation == validation {
			return true
		}
	}
	return false
}

func hasValidatedBytecode(
	class ClassIndex,
	artifacts map[string]Artifact,
) bool {
	for _, id := range class.ArtifactIDs {
		artifact := artifacts[id]
		if artifact.Kind == ArtifactBytecode || artifact.Kind == ArtifactIndex {
			return true
		}
	}
	return false
}

func deepCopyAndNormalizeOutput(output Output) Output {
	cloned := Output{
		Status:      output.Status,
		Classes:     append([]ClassIndex(nil), output.Classes...),
		Artifacts:   append([]Artifact(nil), output.Artifacts...),
		ClassErrors: append([]ClassError(nil), output.ClassErrors...),
		Warnings:    append([]string(nil), output.Warnings...),
		Execution:   cloneExecution(output.Execution),
	}
	for index := range cloned.Classes {
		cloned.Classes[index].ArtifactIDs = append(
			[]string(nil), cloned.Classes[index].ArtifactIDs...,
		)
		cloned.Classes[index].Methods = append(
			[]MethodIndex(nil), cloned.Classes[index].Methods...,
		)
		for methodIndex := range cloned.Classes[index].Methods {
			method := &cloned.Classes[index].Methods[methodIndex]
			if method.Source != nil {
				source := *method.Source
				method.Source = &source
			}
			if method.Bytecode != nil {
				bytecode := *method.Bytecode
				method.Bytecode = &bytecode
			}
		}
		sort.Strings(cloned.Classes[index].ArtifactIDs)
		sort.Slice(cloned.Classes[index].Methods, func(left, right int) bool {
			return cloned.Classes[index].Methods[left].Key <
				cloned.Classes[index].Methods[right].Key
		})
		if cloned.Classes[index].ArtifactIDs == nil {
			cloned.Classes[index].ArtifactIDs = []string{}
		}
		if cloned.Classes[index].Methods == nil {
			cloned.Classes[index].Methods = []MethodIndex{}
		}
	}
	for index := range cloned.Artifacts {
		cloned.Artifacts[index].ClassKeys = append(
			[]string(nil), cloned.Artifacts[index].ClassKeys...,
		)
		sort.Strings(cloned.Artifacts[index].ClassKeys)
		if cloned.Artifacts[index].ClassKeys == nil {
			cloned.Artifacts[index].ClassKeys = []string{}
		}
	}
	sort.Slice(cloned.Classes, func(left, right int) bool {
		return cloned.Classes[left].Key < cloned.Classes[right].Key
	})
	sort.Slice(cloned.Artifacts, func(left, right int) bool {
		return cloned.Artifacts[left].ID < cloned.Artifacts[right].ID
	})
	sort.Slice(cloned.ClassErrors, func(left, right int) bool {
		leftError, rightError := cloned.ClassErrors[left], cloned.ClassErrors[right]
		if leftError.ClassKey != rightError.ClassKey {
			return leftError.ClassKey < rightError.ClassKey
		}
		if leftError.Code != rightError.Code {
			return leftError.Code < rightError.Code
		}
		return leftError.Message < rightError.Message
	})
	sort.Strings(cloned.Warnings)
	if cloned.Classes == nil {
		cloned.Classes = []ClassIndex{}
	}
	if cloned.Artifacts == nil {
		cloned.Artifacts = []Artifact{}
	}
	if cloned.ClassErrors == nil {
		cloned.ClassErrors = []ClassError{}
	}
	if cloned.Warnings == nil {
		cloned.Warnings = []string{}
	}
	return cloned
}

func cloneExecution(execution *Execution) *Execution {
	if execution == nil {
		return nil
	}
	cloned := *execution
	return &cloned
}

func validateAndCloneArguments(
	arguments []string,
	maxArguments int,
	maxArgumentBytes int,
	maxTotalBytes int,
) ([]string, error) {
	if len(arguments) > maxArguments {
		return nil, fmt.Errorf("%w: too many arguments", ErrInvalidRequest)
	}
	cloned := make([]string, len(arguments))
	total := 0
	for index, argument := range arguments {
		if len(argument) > maxArgumentBytes || !utf8.ValidString(argument) ||
			strings.IndexByte(argument, 0) >= 0 {
			return nil, fmt.Errorf("%w: argument is invalid", ErrInvalidRequest)
		}
		total += len(argument)
		if total > maxTotalBytes {
			return nil, fmt.Errorf("%w: arguments exceed byte limit", ErrInvalidRequest)
		}
		cloned[index] = argument
	}
	return cloned, nil
}

func canonicalAbsolute(value string) bool {
	return value != "" && filepath.IsAbs(value) && filepath.Clean(value) == value
}

func validRelativePath(value string) bool {
	return value != "" && fs.ValidPath(value) && path.Clean(value) == value &&
		!strings.Contains(value, "\\")
}

func validArtifactKind(kind ArtifactKind) bool {
	return kind == ArtifactSource || kind == ArtifactBytecode ||
		kind == ArtifactIndex || kind == ArtifactDiagnostics
}

func validMediaType(value string) bool {
	if len(value) < 3 || len(value) > 255 || !utf8.ValidString(value) ||
		strings.IndexByte(value, 0) >= 0 || strings.Count(value, "/") != 1 {
		return false
	}
	for _, character := range value {
		if character <= 0x20 || character >= 0x7f {
			return false
		}
	}
	return true
}

func validText(value string, maximum int) bool {
	return value != "" && len(value) <= maximum && utf8.ValidString(value) &&
		strings.IndexByte(value, 0) < 0
}

func sortedUnique(values []string) bool {
	for index, value := range values {
		if !identifierPattern.MatchString(value) ||
			(index > 0 && values[index-1] >= value) {
			return false
		}
	}
	return true
}

func containsSorted(values []string, target string) bool {
	index := sort.SearchStrings(values, target)
	return index < len(values) && values[index] == target
}

func invalidResult(message string) error {
	return fmt.Errorf("%w: %s", ErrInvalidResult, message)
}

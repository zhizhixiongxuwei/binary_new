package bytecode

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	DefaultBytecodeToolExecutable = "/usr/local/bin/binaryscan-bytecode-tool"
	DefaultVineflowerJar          = "/opt/bytecode-tools/vineflower/vineflower.jar"
	DefaultCFRJar                 = "/opt/bytecode-tools/cfr/cfr.jar"
	DefaultJADXJar                = "/opt/bytecode-tools/jadx/lib/jadx-all.jar"

	DefaultVineflowerVersion = "1.12.0"
	DefaultCFRVersion        = "0.152"
	DefaultJADXVersion       = "1.5.6"

	DefaultVineflowerSHA256 = "1dfcfe974395734fa467ce620661c7623d05ba83670de0529b1fbd63ff548b9d"
	DefaultCFRSHA256        = "f686e8f3ded377d7bc87d216a90e9e9512df4156e75b06c655a16648ae8765b2"
	DefaultJADXSHA256       = "fe3e12c45acf75f92369685fd02d1d7a7323385dc725680a9b98a0dac0ea554b"

	JVMSourceEngineName  = "vineflower-cfr"
	JADXSourceEngineName = "jadx"
)

type processExecutor interface {
	Run(context.Context, ProcessInvocation) (ProcessResult, error)
}

type SourceProcessConfig struct {
	ToolExecutable string
	WorkRoot       string
	Limits         ProcessLimits
	Environment    []string
}

type JVMSourceEngineConfig struct {
	SourceProcessConfig
	VineflowerJar     string
	VineflowerVersion string
	VineflowerSHA256  string
	CFRJar            string
	CFRVersion        string
	CFRSHA256         string
}

type JADXSourceEngineConfig struct {
	SourceProcessConfig
	JADXJar     string
	JADXVersion string
	JADXSHA256  string
}

type JVMSourceEngine struct {
	runner     processExecutor
	workRoot   string
	descriptor Descriptor
}

type JADXSourceEngine struct {
	runner     processExecutor
	workRoot   string
	descriptor Descriptor
}

func DefaultSourceProcessConfig(workRoot string) SourceProcessConfig {
	return SourceProcessConfig{
		ToolExecutable: DefaultBytecodeToolExecutable,
		WorkRoot:       workRoot,
		Environment: []string{
			"HOME=/tmp", "TMPDIR=/tmp", "LANG=C.UTF-8", "LC_ALL=C.UTF-8",
		},
		Limits: ProcessLimits{
			MaxDuration: 20 * time.Minute, TerminationGrace: 10 * time.Second,
			MaxStdoutBytes: 8 << 20, MaxStderrBytes: 8 << 20,
			MaxOutputBytes: 128 << 20, MaxOutputFiles: 3_000,
		},
	}
}

func DefaultJVMSourceEngineConfig(workRoot string) JVMSourceEngineConfig {
	return JVMSourceEngineConfig{
		SourceProcessConfig: DefaultSourceProcessConfig(workRoot),
		VineflowerJar:       DefaultVineflowerJar, VineflowerVersion: DefaultVineflowerVersion,
		VineflowerSHA256: DefaultVineflowerSHA256,
		CFRJar:           DefaultCFRJar, CFRVersion: DefaultCFRVersion, CFRSHA256: DefaultCFRSHA256,
	}
}

func DefaultJADXSourceEngineConfig(workRoot string) JADXSourceEngineConfig {
	return JADXSourceEngineConfig{
		SourceProcessConfig: DefaultSourceProcessConfig(workRoot),
		JADXJar:             DefaultJADXJar, JADXVersion: DefaultJADXVersion,
		JADXSHA256: DefaultJADXSHA256,
	}
}

// ExternalToolchainAvailable distinguishes the intentionally minimal fallback
// image from a partially installed or tampered source-decompiler image.
func ExternalToolchainAvailable(workRoot string) (bool, error) {
	paths := []string{
		DefaultBytecodeToolExecutable, DefaultVineflowerJar,
		DefaultCFRJar, DefaultJADXJar,
	}
	present := 0
	for _, name := range paths {
		if _, err := os.Lstat(name); err == nil {
			present++
		} else if !errors.Is(err, fs.ErrNotExist) {
			return false, err
		}
	}
	if present == 0 {
		return false, nil
	}
	if present != len(paths) {
		return false, fmt.Errorf("%w: bytecode source toolchain is incomplete", ErrInvalidConfiguration)
	}
	jvm, err := NewJVMSourceEngine(DefaultJVMSourceEngineConfig(workRoot))
	if err != nil {
		return false, err
	}
	if _, err := NewJADXSourceEngine(DefaultJADXSourceEngineConfig(workRoot)); err != nil {
		return false, err
	}
	_ = jvm
	return true, nil
}

func NewJVMSourceEngine(config JVMSourceEngineConfig) (*JVMSourceEngine, error) {
	if !safeToolVersion(config.VineflowerVersion) || !safeToolVersion(config.CFRVersion) {
		return nil, fmt.Errorf("%w: JVM source engine version is invalid", ErrInvalidConfiguration)
	}
	if err := verifyPinnedTool(config.VineflowerJar, config.VineflowerSHA256); err != nil {
		return nil, fmt.Errorf("verify Vineflower: %w", err)
	}
	if err := verifyPinnedTool(config.CFRJar, config.CFRSHA256); err != nil {
		return nil, fmt.Errorf("verify CFR: %w", err)
	}
	runner, err := newSourceProcessRunner(config.SourceProcessConfig)
	if err != nil {
		return nil, err
	}
	return &JVMSourceEngine{
		runner: runner, workRoot: config.WorkRoot,
		descriptor: Descriptor{
			Name:    JVMSourceEngineName,
			Version: "vf" + config.VineflowerVersion + "-cfr" + config.CFRVersion,
		},
	}, nil
}

func NewJADXSourceEngine(config JADXSourceEngineConfig) (*JADXSourceEngine, error) {
	if !safeToolVersion(config.JADXVersion) {
		return nil, fmt.Errorf("%w: JADX version is invalid", ErrInvalidConfiguration)
	}
	if err := verifyPinnedTool(config.JADXJar, config.JADXSHA256); err != nil {
		return nil, fmt.Errorf("verify JADX: %w", err)
	}
	runner, err := newSourceProcessRunner(config.SourceProcessConfig)
	if err != nil {
		return nil, err
	}
	return &JADXSourceEngine{
		runner: runner, workRoot: config.WorkRoot,
		descriptor: Descriptor{Name: JADXSourceEngineName, Version: config.JADXVersion},
	}, nil
}

func newSourceProcessRunner(config SourceProcessConfig) (*ProcessRunner, error) {
	return NewProcessRunner(ProcessConfig{
		Executable: config.ToolExecutable, WorkRoot: config.WorkRoot,
		Environment: config.Environment, Limits: config.Limits,
	})
}

func (engine *JVMSourceEngine) Descriptor() Descriptor {
	if engine == nil {
		return Descriptor{}
	}
	return engine.descriptor
}

func (engine *JVMSourceEngine) Supports(format Format) bool {
	if engine == nil {
		return false
	}
	switch format {
	case FormatClass, FormatJAR, FormatWAR, FormatEAR:
		return true
	default:
		return false
	}
}

func (engine *JADXSourceEngine) Descriptor() Descriptor {
	if engine == nil {
		return Descriptor{}
	}
	return engine.descriptor
}

func (engine *JADXSourceEngine) Supports(format Format) bool {
	return engine != nil && (format == FormatDEX || format == FormatAPK)
}

func (engine *JVMSourceEngine) Decompile(ctx context.Context, request Request) (Output, error) {
	if engine == nil || engine.runner == nil {
		return Output{}, fmt.Errorf("%w: JVM source engine is nil", ErrInvalidConfiguration)
	}
	working, input, err := prepareSourceWorkspace(ctx, engine.workRoot, request, "jvm-source")
	if err != nil {
		return Output{}, err
	}
	primary, err := engine.runner.Run(ctx, ProcessInvocation{
		Arguments:        []string{"vineflower", input, "vineflower-output"},
		WorkingDirectory: working, OutputDirectory: filepath.Join(working, "vineflower-output"),
	})
	if err != nil {
		return Output{}, err
	}
	if primary.ExitCode == 0 {
		output, collectErr := collectSourceOutput(
			ctx, request.Workspace, filepath.Join("jvm-source", "vineflower-output"),
			primary, "java", nil,
		)
		if collectErr == nil {
			return output, nil
		}
		if !errors.Is(collectErr, errNoSourceArtifacts) {
			return Output{}, collectErr
		}
	}
	fallback, err := engine.runner.Run(ctx, ProcessInvocation{
		Arguments:        []string{"cfr", input, "cfr-output"},
		WorkingDirectory: working, OutputDirectory: filepath.Join(working, "cfr-output"),
	})
	if err != nil {
		return Output{}, err
	}
	if fallback.ExitCode != 0 {
		return Output{}, fmt.Errorf("bytecode source decompilers exited with codes %d and %d", primary.ExitCode, fallback.ExitCode)
	}
	return collectSourceOutput(
		ctx, request.Workspace, filepath.Join("jvm-source", "cfr-output"),
		fallback, "java", []string{"Vineflower did not publish source; CFR fallback was used."},
	)
}

func (engine *JADXSourceEngine) Decompile(ctx context.Context, request Request) (Output, error) {
	if engine == nil || engine.runner == nil {
		return Output{}, fmt.Errorf("%w: JADX source engine is nil", ErrInvalidConfiguration)
	}
	working, input, err := prepareSourceWorkspace(ctx, engine.workRoot, request, "jadx-source")
	if err != nil {
		return Output{}, err
	}
	result, err := engine.runner.Run(ctx, ProcessInvocation{
		Arguments:        []string{"jadx", input, "jadx-output"},
		WorkingDirectory: working, OutputDirectory: filepath.Join(working, "jadx-output"),
	})
	if err != nil {
		return Output{}, err
	}
	if result.ExitCode != 0 {
		return Output{}, fmt.Errorf("JADX exited with code %d", result.ExitCode)
	}
	return collectSourceOutput(
		ctx, request.Workspace, filepath.Join("jadx-source", "jadx-output"),
		result, "java", nil,
	)
}

var errNoSourceArtifacts = errors.New("bytecode: source decompiler produced no source files")

func prepareSourceWorkspace(
	ctx context.Context,
	workRoot string,
	request Request,
	directory string,
) (string, string, error) {
	relative, err := filepath.Rel(workRoot, request.Workspace)
	if err != nil || relative == "." || !filepath.IsLocal(relative) {
		return "", "", fmt.Errorf("%w: bytecode workspace is outside its work root", ErrInvalidRequest)
	}
	working := filepath.Join(relative, directory)
	absolute := filepath.Join(request.Workspace, directory)
	if err := os.Mkdir(absolute, 0o700); err != nil {
		return "", "", fmt.Errorf("%w: create source workspace", ErrInvalidRequest)
	}
	for _, child := range []string{"vineflower-output", "cfr-output", "jadx-output"} {
		if err := os.Mkdir(filepath.Join(absolute, child), 0o700); err != nil {
			return "", "", fmt.Errorf("%w: create source output directory", ErrInvalidRequest)
		}
	}
	extension := string(request.Input.Format)
	if extension == "class" {
		extension = "class"
	}
	inputName := "input." + extension
	inputPath := filepath.Join(absolute, inputName)
	input, err := request.Input.VerifiedReader()
	if err != nil {
		return "", "", err
	}
	file, err := os.OpenFile(inputPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return "", "", fmt.Errorf("%w: create source input", ErrInvalidRequest)
	}
	hasher := sha256.New()
	written, copyErr := io.Copy(
		io.MultiWriter(file, hasher),
		io.LimitReader(&contextReader{ctx: ctx, reader: input}, request.Input.SizeBytes+1),
	)
	syncErr := file.Sync()
	closeErr := file.Close()
	if copyErr != nil || syncErr != nil || closeErr != nil ||
		written != request.Input.SizeBytes || hex.EncodeToString(hasher.Sum(nil)) != request.Input.SHA256 {
		return "", "", errors.Join(copyErr, syncErr, closeErr, ErrInvalidRequest)
	}
	if err := os.Chmod(inputPath, 0o400); err != nil {
		return "", "", fmt.Errorf("%w: protect source input", ErrInvalidRequest)
	}
	return working, inputName, nil
}

func collectSourceOutput(
	ctx context.Context,
	workspace string,
	outputRelative string,
	execution ProcessResult,
	defaultLanguage string,
	warnings []string,
) (Output, error) {
	root := filepath.Join(workspace, outputRelative)
	type candidate struct {
		artifactPath string
		sourcePath   string
		language     string
	}
	values := make([]candidate, 0)
	err := filepath.WalkDir(root, func(name string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return ErrUnsafeOutput
		}
		if entry.IsDir() {
			return nil
		}
		if !entry.Type().IsRegular() {
			return ErrUnsafeOutput
		}
		extension := strings.ToLower(filepath.Ext(entry.Name()))
		language := defaultLanguage
		switch extension {
		case ".java":
			language = "java"
		case ".kt":
			language = "kotlin"
		default:
			return nil
		}
		artifactPath, err := filepath.Rel(workspace, name)
		if err != nil || !filepath.IsLocal(artifactPath) {
			return ErrUnsafeOutput
		}
		sourcePath, err := filepath.Rel(root, name)
		if err != nil || !filepath.IsLocal(sourcePath) || !utf8.ValidString(sourcePath) {
			return ErrUnsafeOutput
		}
		values = append(values, candidate{
			artifactPath: filepath.ToSlash(artifactPath),
			sourcePath:   filepath.ToSlash(sourcePath), language: language,
		})
		return nil
	})
	if err != nil {
		return Output{}, err
	}
	if len(values) == 0 {
		return Output{}, errNoSourceArtifacts
	}
	sort.Slice(values, func(left, right int) bool {
		return values[left].sourcePath < values[right].sourcePath
	})
	output := Output{
		Status: StatusComplete, Classes: make([]ClassIndex, 0, len(values)),
		Artifacts: make([]Artifact, 0, len(values)), ClassErrors: []ClassError{},
		Warnings: append([]string(nil), warnings...),
		Execution: &Execution{
			ExitCode: execution.ExitCode, DurationMS: execution.Duration.Milliseconds(),
			OutputBytes: execution.OutputBytes, OutputFiles: execution.OutputFiles,
		},
	}
	for _, value := range values {
		if len(output.Classes) >= DefaultMaxClasses {
			return Output{}, ErrFileCountLimit
		}
		digest, size, err := digestSourceArtifact(ctx, filepath.Join(workspace, filepath.FromSlash(value.artifactPath)))
		if err != nil {
			return Output{}, err
		}
		pathDigest := sha256.Sum256([]byte(value.sourcePath))
		identity := hex.EncodeToString(pathDigest[:])
		classKey := "source:" + identity
		artifactID := "source:" + identity
		binaryName := strings.TrimSuffix(value.sourcePath, filepath.Ext(value.sourcePath))
		binaryName = strings.TrimPrefix(binaryName, "sources/")
		binaryName = strings.ReplaceAll(binaryName, "/", ".")
		mediaType := "text/x-java-source"
		if value.language == "kotlin" {
			mediaType = "text/x-kotlin-source"
		}
		output.Classes = append(output.Classes, ClassIndex{
			Key: classKey, Kind: KindClass, BinaryName: binaryName,
			DisplayName: filepath.Base(value.sourcePath), SourceFile: value.sourcePath,
			Language: value.language, Status: ClassSource,
			ArtifactIDs: []string{artifactID}, Methods: []MethodIndex{},
		})
		output.Artifacts = append(output.Artifacts, Artifact{
			ID: artifactID, Kind: ArtifactSource, MediaType: mediaType,
			RelativePath: value.artifactPath, SHA256: digest, SizeBytes: size,
			Chunk:     ArtifactChunk{SetID: artifactID, Index: 0, Count: 1},
			ClassKeys: []string{classKey},
		})
	}
	return output, nil
}

func digestSourceArtifact(ctx context.Context, name string) (string, int64, error) {
	info, err := os.Lstat(name)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() <= 0 {
		return "", 0, ErrUnsafeOutput
	}
	file, err := os.Open(name)
	if err != nil {
		return "", 0, err
	}
	defer file.Close()
	hasher := sha256.New()
	written, err := io.Copy(hasher, &contextReader{ctx: ctx, reader: file})
	if err != nil || written != info.Size() {
		return "", 0, errors.Join(err, ErrUnsafeOutput)
	}
	return hex.EncodeToString(hasher.Sum(nil)), written, nil
}

func verifyPinnedTool(name string, expectedSHA256 string) error {
	if !filepath.IsAbs(name) || filepath.Clean(name) != name || !sha256Pattern.MatchString(expectedSHA256) {
		return ErrInvalidConfiguration
	}
	info, err := os.Lstat(name)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 ||
		info.Size() <= 0 || info.Size() > 256<<20 {
		return fmt.Errorf("%w: pinned tool file is invalid", ErrInvalidConfiguration)
	}
	file, err := os.Open(name)
	if err != nil {
		return err
	}
	defer file.Close()
	hasher := sha256.New()
	written, err := io.Copy(hasher, io.LimitReader(file, info.Size()+1))
	if err != nil || written != info.Size() || hex.EncodeToString(hasher.Sum(nil)) != expectedSHA256 {
		return fmt.Errorf("%w: pinned tool digest differs", ErrInvalidConfiguration)
	}
	return nil
}

func safeToolVersion(value string) bool {
	if value == "" || len(value) > 64 {
		return false
	}
	for _, character := range value {
		if (character < '0' || character > '9') && character != '.' && character != '-' {
			return false
		}
	}
	return true
}

// InspectUTF8Source rejects empty, binary, NUL-containing, or malformed text.
// Language grammar validation remains the responsibility of the pinned tool;
// this independent check ensures a source claim is backed by readable text.
func InspectUTF8Source(ctx context.Context, reader io.Reader) error {
	validator := &sourceUTF8Validator{}
	buffer := make([]byte, 32<<10)
	nonSpace := false
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		count, err := reader.Read(buffer)
		if count > 0 {
			for _, value := range buffer[:count] {
				if value == 0 {
					return errors.New("source contains a NUL byte")
				}
				if value != ' ' && value != '\t' && value != '\r' && value != '\n' {
					nonSpace = true
				}
			}
			_, _ = validator.Write(buffer[:count])
		}
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return err
		}
	}
	if !nonSpace || !validator.Valid() {
		return errors.New("source is empty or not valid UTF-8")
	}
	return nil
}

type sourceUTF8Validator struct {
	tail    []byte
	invalid bool
}

func (validator *sourceUTF8Validator) Write(payload []byte) (int, error) {
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

func (validator *sourceUTF8Validator) Valid() bool {
	return !validator.invalid && len(validator.tail) == 0
}

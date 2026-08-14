package bytecode

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// PYCSourceEngine decompiles PYC bytecode into Python source with the offline
// pycdc binary (a single statically linked executable with no runtime
// dependencies). When pycdc cannot decompile the file (unknown magic number,
// unsupported CPython version, malformed input), the engine falls back to the
// structural go-python-bytecode index so callers still receive a bounded
// result instead of a hard failure.
type PYCSourceEngine struct {
	runner     *ProcessRunner
	fallback   Engine
	config     PYCSourceConfig
	descriptor Descriptor
}

// PYCSourceConfig fixes every path and limit controlled by the engine.
type PYCSourceConfig struct {
	Executable string
	WorkRoot   string
	MaxDuration      time.Duration
	TerminationGrace time.Duration
	MaxStdoutBytes   int64
	MaxStderrBytes   int64
	MaxInputBytes    int64
	MaxOutputBytes   int64
	MaxArguments     int
	MaxArgumentBytes int
	MaxTotalArgumentBytes int
}

const (
	PYCSourceEngineName    = "pycdc"
	PYCSourceEngineVersion = "1.1.1"
	pycSourceArtifactName  = "main.py"
	pycSourceModuleName    = "main"

	// DefaultPYCDCSourceExecutable is the fixed offline image path, kept next
	// to the JVM decompilers under /opt/bytecode-tools.
	DefaultPYCDCSourceExecutable = "/opt/bytecode-tools/pycdc/pycdc"

	DefaultPYCSourceMaxDuration      = 120 * time.Second
	DefaultPYCSourceTerminationGrace = 5 * time.Second
	DefaultPYCSourceMaxStdoutBytes   = int64(32 << 20)
	DefaultPYCSourceMaxStderrBytes   = int64(4 << 20)
	DefaultPYCSourceMaxInputBytes    = int64(64 << 20)
	DefaultPYCSourceMaxOutputBytes   = int64(64 << 20)
	DefaultPYCSourceMaxArguments     = 8
	DefaultPYCSourceMaxArgumentBytes = 4 << 10
	DefaultPYCSourceMaxTotalArgumentBytes = 64 << 10
)

// DefaultPYCSourceEngineConfig returns the fixed-limit configuration used by
// the bytecode worker, mirroring the JVM source engine defaults.
func DefaultPYCSourceEngineConfig(workRoot string) PYCSourceConfig {
	return PYCSourceConfig{
		Executable: DefaultPYCDCSourceExecutable,
		WorkRoot:   workRoot,
		MaxDuration:      DefaultPYCSourceMaxDuration,
		TerminationGrace: DefaultPYCSourceTerminationGrace,
		MaxStdoutBytes:   DefaultPYCSourceMaxStdoutBytes,
		MaxStderrBytes:   DefaultPYCSourceMaxStderrBytes,
		MaxInputBytes:    DefaultPYCSourceMaxInputBytes,
		MaxOutputBytes:   DefaultPYCSourceMaxOutputBytes,
		MaxArguments:     DefaultPYCSourceMaxArguments,
		MaxArgumentBytes: DefaultPYCSourceMaxArgumentBytes,
		MaxTotalArgumentBytes: DefaultPYCSourceMaxTotalArgumentBytes,
	}
}

func NewPYCSourceEngine(
	config PYCSourceConfig,
	fallback Engine,
) (*PYCSourceEngine, error) {
	if fallback == nil {
		return nil, fmt.Errorf("%w: PYC source engine fallback is nil", ErrInvalidConfiguration)
	}
	if config.Executable == "" || config.WorkRoot == "" ||
		config.MaxDuration <= 0 || config.TerminationGrace <= 0 ||
		config.MaxStdoutBytes <= 0 || config.MaxStderrBytes <= 0 ||
		config.MaxInputBytes <= 0 || config.MaxOutputBytes <= 0 ||
		config.MaxArguments <= 0 || config.MaxArgumentBytes <= 0 ||
		config.MaxTotalArgumentBytes <= 0 {
		return nil, fmt.Errorf(
			"%w: PYC source engine limits are invalid",
			ErrInvalidConfiguration,
		)
	}
	runner, err := NewProcessRunner(ProcessConfig{
		Executable: config.Executable,
		WorkRoot:   config.WorkRoot,
		Limits: ProcessLimits{
			MaxDuration:      config.MaxDuration,
			TerminationGrace: config.TerminationGrace,
			MaxStdoutBytes:   config.MaxStdoutBytes,
			MaxStderrBytes:   config.MaxStderrBytes,
			MaxOutputBytes:   config.MaxOutputBytes,
			MaxOutputFiles:   4,
			MaxArguments:     config.MaxArguments,
			MaxArgumentBytes: config.MaxArgumentBytes,
			MaxTotalArgumentBytes: config.MaxTotalArgumentBytes,
		},
	})
	if err != nil {
		return nil, err
	}
	return &PYCSourceEngine{
		runner: runner, fallback: fallback, config: config,
		descriptor: Descriptor{
			Name: PYCSourceEngineName, Version: PYCSourceEngineVersion,
		},
	}, nil
}

func (engine *PYCSourceEngine) Descriptor() Descriptor {
	if engine == nil {
		return Descriptor{}
	}
	return engine.descriptor
}

func (engine *PYCSourceEngine) Config() PYCSourceConfig {
	if engine == nil {
		return PYCSourceConfig{}
	}
	return engine.config
}

func (engine *PYCSourceEngine) Supports(format Format) bool {
	return engine != nil && format == FormatPYC
}

func (engine *PYCSourceEngine) Decompile(
	ctx context.Context,
	request Request,
) (Output, error) {
	if engine == nil {
		return Output{}, fmt.Errorf("%w: PYC source engine is nil", ErrInvalidConfiguration)
	}
	if ctx == nil {
		return Output{}, fmt.Errorf("%w: context is nil", ErrInvalidRequest)
	}
	if err := ctx.Err(); err != nil {
		return Output{}, err
	}
	if request.Input.Format != FormatPYC {
		return Output{}, fmt.Errorf("%w: PYC input format is required", ErrInvalidRequest)
	}
	payload, err := readVerifiedPYC(ctx, request.Input, engine.config.MaxInputBytes)
	if err != nil {
		return Output{}, err
	}
	if _, err := inspectPYCHeader(payload); err != nil {
		if errors.Is(err, ErrMalformedPYC) {
			// pycdc would fail identically; keep the structured classification.
			return failedPYCOutput(request, "invalid_pyc", err.Error()), nil
		}
		return Output{}, err
	}

	// Materialize the verified input beneath the runner work root. The
	// process runner resolves working directories relative to its work root.
	workingDirectory, err := engine.newInputDirectory(ctx)
	if err != nil {
		return Output{}, err
	}
	defer os.RemoveAll(workingDirectory)
	workingRelative := filepath.Base(workingDirectory)
	inputPath := filepath.Join(workingDirectory, "input.pyc")
	if err := writeVerifiedPYC(ctx, payload, inputPath); err != nil {
		return Output{}, err
	}
	outputDirectory := filepath.Join(workingDirectory, "output")
	if err := os.Mkdir(outputDirectory, 0o700); err != nil {
		return Output{}, fmt.Errorf("%w: create PYC source output directory: %v", ErrInvalidRequest, err)
	}

	result, err := engine.runner.Run(ctx, ProcessInvocation{
		Arguments:        []string{"input.pyc"},
		WorkingDirectory: workingRelative,
		OutputDirectory:  workingRelative + "/output",
	})
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return Output{}, ctxErr
		}
		return Output{}, err
	}
	if result.ExitCode != 0 || len(result.Stdout) == 0 {
		return engine.fallback.Decompile(ctx, request)
	}
	if err := ctx.Err(); err != nil {
		return Output{}, err
	}
	source := strings.TrimSpace(string(result.Stdout))
	if source == "" {
		return engine.fallback.Decompile(ctx, request)
	}

	artifactID := pycStableKey("source", request.Input.SHA256, pycSourceArtifactName)
	digestBytes := sha256.Sum256(result.Stdout)
	moduleKey := pycStableKey("module", request.Input.SHA256, pycSourceModuleName)
	artifactRelativePath := "output/main.py"
	artifactOutputRoot := filepath.Join(request.Workspace, "output")
	if err := os.Mkdir(artifactOutputRoot, 0o700); err != nil {
		return Output{}, fmt.Errorf(
			"%w: create PYC source artifact directory: %v",
			ErrInvalidRequest, err,
		)
	}
	artifactPath := filepath.Join(artifactOutputRoot, "main.py")
	if err := os.WriteFile(artifactPath, result.Stdout, 0o400); err != nil {
		return Output{}, fmt.Errorf(
			"%w: write PYC source artifact: %v",
			ErrInvalidRequest, err,
		)
	}
	artifact := Artifact{
		ID: artifactID, Kind: ArtifactSource,
		MediaType: "text/x-python", RelativePath: artifactRelativePath,
		SizeBytes: int64(len(result.Stdout)),
		SHA256:    hex.EncodeToString(digestBytes[:]),
		Chunk:     ArtifactChunk{SetID: artifactID, Index: 0, Count: 1},
		ClassKeys: []string{moduleKey},
	}
	return Output{
		Status: StatusComplete,
		Classes: []ClassIndex{{
			Key: moduleKey, Kind: KindModule, BinaryName: pycSourceModuleName,
			DisplayName: pycSourceModuleName, Language: "python",
			Status: ClassSource, ArtifactIDs: []string{artifactID},
			Methods: []MethodIndex{},
		}},
		Artifacts:   []Artifact{artifact},
		ClassErrors: []ClassError{},
		Warnings:    []string{},
		Execution: &Execution{
			DurationMS: result.Duration.Milliseconds(), ExitCode: result.ExitCode,
			OutputBytes: result.OutputBytes, OutputFiles: result.OutputFiles,
		},
	}, nil
}

func (engine *PYCSourceEngine) newInputDirectory(ctx context.Context) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	path, err := os.MkdirTemp(engine.config.WorkRoot, "pycdc-input-")
	if err != nil {
		return "", fmt.Errorf("%w: create PYC source input directory: %v", ErrInvalidRequest, err)
	}
	return path, nil
}

// writeVerifiedPYC stores the already-verified PYC payload beneath a private
// input directory with restrictive permissions and syncs it before the
// process runner binds it.
func writeVerifiedPYC(
	ctx context.Context,
	payload []byte,
	path string,
) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("%w: create PYC source input: %v", ErrInvalidRequest, err)
	}
	keep := false
	defer func() {
		_ = file.Close()
		if !keep {
			_ = os.Remove(path)
		}
	}()
	if _, err := file.Write(payload); err != nil {
		return fmt.Errorf("%w: write PYC source input: %v", ErrInvalidRequest, err)
	}
	if err := file.Sync(); err != nil {
		return fmt.Errorf("%w: sync PYC source input: %v", ErrInvalidRequest, err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("%w: close PYC source input: %v", ErrInvalidRequest, err)
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() ||
		info.Size() != int64(len(payload)) {
		return fmt.Errorf("%w: PYC source input changed", ErrInvalidRequest)
	}
	keep = true
	return nil
}

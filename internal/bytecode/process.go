package bytecode

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode/utf8"
)

const (
	DefaultProcessDuration               = 20 * time.Minute
	DefaultTerminationGrace              = 2 * time.Second
	DefaultMaxStdoutBytes          int64 = 8 << 20
	DefaultMaxStderrBytes          int64 = 8 << 20
	DefaultMaxProcessOutputBytes   int64 = 128 << 20
	DefaultMaxProcessFiles               = 3_000
	DefaultMaxProcessArguments           = 256
	DefaultMaxProcessArgumentBytes       = 64 << 10
	DefaultMaxProcessArgumentTotal       = 1 << 20

	maxProcessDuration                 = 20 * time.Minute
	maxTerminationGrace                = time.Minute
	maxProcessStreamBytes        int64 = 64 << 20
	maxProcessOutputBytes        int64 = 128 << 20
	maxProcessFiles                    = 3_000
	maxProcessArguments                = 1024
	maxProcessArgumentBytes            = 1 << 20
	maxProcessArgumentTotal            = 8 << 20
	outputPollInterval                 = 20 * time.Millisecond
	finalOutputInspectionTimeout       = 2 * time.Second
	maxExecutableSnapshotBytes   int64 = 256 << 20
)

var environmentNamePattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

type ProcessLimits struct {
	MaxDuration      time.Duration
	TerminationGrace time.Duration
	MaxStdoutBytes   int64
	MaxStderrBytes   int64
	MaxOutputBytes   int64
	// MaxOutputFiles counts all files and directories below the output root,
	// so a directory-only output bomb consumes the same bounded namespace.
	MaxOutputFiles        int
	MaxArguments          int
	MaxArgumentBytes      int
	MaxTotalArgumentBytes int
}

type ProcessConfig struct {
	Executable  string
	WorkRoot    string
	Environment []string
	Limits      ProcessLimits
}

// ProcessInvocation contains only an argument vector and root-relative
// directories. ProcessRunner never accepts or evaluates a shell command.
type ProcessInvocation struct {
	Arguments        []string
	WorkingDirectory string
	OutputDirectory  string
}

type ProcessResult struct {
	ExitCode    int
	Stdout      []byte
	Stderr      []byte
	Duration    time.Duration
	OutputBytes int64
	OutputFiles int
}

// ProcessRunner bounds a directly executed process and its initial process
// group. A descendant can escape a process group by calling setsid(2); Linux
// deployment must still use the Worker PID/cgroup and OS sandbox controls.
type ProcessRunner struct {
	executable       string
	executableInfo   fs.FileInfo
	executableSHA256 [sha256.Size]byte
	executableSize   int64
	workRoot         string
	workRootInfo     fs.FileInfo
	workRootDevice   uint64
	environment      []string
	limits           ProcessLimits
	timeoutContext   func(
		context.Context,
		time.Duration,
	) (context.Context, context.CancelFunc)
}

func NewProcessRunner(config ProcessConfig) (*ProcessRunner, error) {
	if !canonicalAbsolute(config.Executable) ||
		!canonicalAbsolute(config.WorkRoot) {
		return nil, fmt.Errorf(
			"%w: process paths must be canonical absolute paths",
			ErrInvalidConfiguration,
		)
	}
	executableInfo, err := os.Lstat(config.Executable)
	if err != nil || !executableInfo.Mode().IsRegular() ||
		executableInfo.Mode()&os.ModeSymlink != 0 ||
		executableInfo.Mode().Perm()&0o111 == 0 {
		return nil, fmt.Errorf(
			"%w: executable is not a real executable file",
			ErrInvalidConfiguration,
		)
	}
	workRootInfo, err := os.Lstat(config.WorkRoot)
	if err != nil || !workRootInfo.IsDir() ||
		workRootInfo.Mode()&os.ModeSymlink != 0 ||
		filepath.Dir(config.WorkRoot) == config.WorkRoot ||
		workRootInfo.Mode().Perm()&0o022 != 0 {
		return nil, fmt.Errorf(
			"%w: work root is not a real directory",
			ErrInvalidConfiguration,
		)
	}
	executableDigest, executableSize, err := digestExecutable(
		context.Background(), config.Executable, executableInfo,
	)
	if err != nil {
		return nil, err
	}
	workRootDevice, ok := trustedRootDevice(workRootInfo)
	if !ok {
		return nil, fmt.Errorf(
			"%w: work root filesystem metadata is unavailable",
			ErrInvalidConfiguration,
		)
	}
	limits, err := normalizeProcessLimits(config.Limits)
	if err != nil {
		return nil, err
	}
	environment, err := validateEnvironment(config.Environment)
	if err != nil {
		return nil, err
	}
	return &ProcessRunner{
		executable: config.Executable, executableInfo: executableInfo,
		executableSHA256: executableDigest, executableSize: executableSize,
		workRoot: config.WorkRoot, workRootInfo: workRootInfo,
		workRootDevice: workRootDevice,
		environment:    environment, limits: limits,
		timeoutContext: context.WithTimeout,
	}, nil
}

func (runner *ProcessRunner) Run(
	ctx context.Context,
	invocation ProcessInvocation,
) (ProcessResult, error) {
	startedAt := time.Now()
	if runner == nil {
		return ProcessResult{}, fmt.Errorf("%w: runner is nil", ErrInvalidConfiguration)
	}
	if ctx == nil {
		return ProcessResult{}, fmt.Errorf("%w: context is nil", ErrInvalidRequest)
	}
	if err := ctx.Err(); err != nil {
		return ProcessResult{}, err
	}
	timeoutContext := runner.timeoutContext
	if timeoutContext == nil {
		timeoutContext = context.WithTimeout
	}
	runCtx, cancel := timeoutContext(ctx, runner.limits.MaxDuration)
	defer cancel()
	if invocation.WorkingDirectory == "." || invocation.OutputDirectory == "." {
		return ProcessResult{}, fmt.Errorf(
			"%w: process directories cannot be the work root", ErrInvalidRequest,
		)
	}
	arguments, err := validateAndCloneArguments(
		invocation.Arguments,
		runner.limits.MaxArguments,
		runner.limits.MaxArgumentBytes,
		runner.limits.MaxTotalArgumentBytes,
	)
	if err != nil {
		return ProcessResult{}, err
	}
	workingPath, workingInfo, err := runner.resolveDirectory(
		invocation.WorkingDirectory,
	)
	if err != nil {
		return ProcessResult{}, err
	}
	outputPath, outputInfo, err := runner.resolveDirectory(
		invocation.OutputDirectory,
	)
	if err != nil {
		return ProcessResult{}, err
	}
	if !pathWithin(workingPath, outputPath) {
		return ProcessResult{}, fmt.Errorf(
			"%w: output directory is outside working directory",
			ErrInvalidRequest,
		)
	}
	if err := runner.revalidateRoots(); err != nil {
		return ProcessResult{}, err
	}
	workingHandle, err := os.Open(workingPath)
	if err != nil {
		return ProcessResult{}, fmt.Errorf("%w: open working directory", ErrInvalidRequest)
	}
	defer workingHandle.Close()
	boundWorkingInfo, err := workingHandle.Stat()
	if err != nil || !os.SameFile(workingInfo, boundWorkingInfo) ||
		!trustedEntry(boundWorkingInfo, runner.workRootDevice) {
		return ProcessResult{}, fmt.Errorf("%w: working directory changed", ErrInvalidRequest)
	}
	outputRoot, err := os.OpenRoot(outputPath)
	if err != nil {
		return ProcessResult{}, fmt.Errorf("%w: open output root", ErrUnsafeOutput)
	}
	defer outputRoot.Close()
	usage, err := runner.inspectOutput(runCtx, outputRoot, outputPath, outputInfo)
	if err != nil {
		return ProcessResult{}, runner.preparationError(ctx, runCtx, err)
	}
	overflow := make(chan streamLimit, 2)
	stdout := newProcessCapture(
		ErrStdoutLimit, runner.limits.MaxStdoutBytes, overflow,
	)
	stderr := newProcessCapture(
		ErrStderrLimit, runner.limits.MaxStderrBytes, overflow,
	)
	executablePath := runner.executable
	commandExtraFiles := []*os.File(nil)
	descriptorBound := linuxProcessFDDirectoryAvailable()
	var executableSnapshot *preparedExecutable
	if descriptorBound || runtime.GOOS != "linux" {
		if descriptorBound && rootOwnedReadOnlyPath(runner.executable, runner.executableInfo) {
			executableSnapshot, err = runner.bindReadOnlyExecutable(runCtx)
		} else {
			executableSnapshot, err = runner.prepareExecutableSnapshot(runCtx)
		}
		if err != nil {
			return ProcessResult{}, runner.preparationError(ctx, runCtx, err)
		}
		defer executableSnapshot.cleanup()
		executablePath = executableSnapshot.path
	}
	if descriptorBound {
		path, _ := processExecutableFDPath(4)
		executablePath = path
		commandExtraFiles = []*os.File{workingHandle, executableSnapshot.file}
	} else if runtime.GOOS == "linux" &&
		!rootOwnedReadOnlyPath(runner.executable, runner.executableInfo) {
		return ProcessResult{}, fmt.Errorf(
			"%w: /proc descriptor binding is unavailable and executable path is mutable",
			ErrInvalidConfiguration,
		)
	}
	command := exec.Command(executablePath, arguments...)
	command.Dir = workingPath
	// Go 1.24 performs Cmd.Dir chdir before remapping ExtraFiles. Therefore
	// cwd must name the already-open inherited descriptor, not its future fd 3
	// target. ExtraFiles still keeps that descriptor alive through fork.
	if directory, bound := processDirectoryFDPath(workingHandle.Fd()); bound && descriptorBound {
		command.Dir = directory
	}
	command.ExtraFiles = commandExtraFiles
	if runtime.GOOS != "linux" && !executableSnapshot.pathIsBound() {
		return ProcessResult{}, fmt.Errorf(
			"%w: executable snapshot path changed", ErrInvalidConfiguration,
		)
	}
	command.Env = append([]string(nil), runner.environment...)
	command.Stdout = stdout
	command.Stderr = stderr
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := command.Start(); err != nil {
		// Some container runtimes reject exec through /proc/self/fd. Both the
		// bind case (immutable root-owned path) and the snapshot case (private
		// copy beneath the work root) have a direct path that is
		// security-equivalent, so retry through it once.
		fallbackPath := executableSnapshot.path
		if fallbackPath == "" {
			fallbackPath = runner.executable
		}
		if descriptorBound && fallbackPath != "" {
			fallback := exec.Command(fallbackPath, arguments...)
			fallback.Dir = command.Dir
			fallback.Env = command.Env
			fallback.Stdout = stdout
			fallback.Stderr = stderr
			fallback.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
			if startErr := fallback.Start(); startErr == nil {
				command = fallback
			} else {
				return ProcessResult{}, runner.preparationError(
					ctx, runCtx, fmt.Errorf("%w: %v", ErrProcessStart, startErr),
				)
			}
		} else {
			return ProcessResult{}, runner.preparationError(
				ctx, runCtx, fmt.Errorf("%w: %v", ErrProcessStart, err),
			)
		}
	}
	if runtime.GOOS != "linux" && !executableSnapshot.pathIsBound() {
		_ = syscall.Kill(-command.Process.Pid, syscall.SIGKILL)
		waitErr := command.Wait()
		cleanupErr := cleanupExitedProcessGroup(
			command.Process.Pid, runner.limits.TerminationGrace,
		)
		return ProcessResult{}, errors.Join(
			fmt.Errorf("%w: executable snapshot path changed", ErrInvalidConfiguration),
			waitErr, cleanupErr,
		)
	}
	if runtime.GOOS == "linux" && !descriptorBound {
		if err := runner.revalidateRoots(); err != nil ||
			!rootOwnedReadOnlyPath(runner.executable, runner.executableInfo) {
			_ = syscall.Kill(-command.Process.Pid, syscall.SIGKILL)
			waitErr := command.Wait()
			cleanupErr := cleanupExitedProcessGroup(
				command.Process.Pid, runner.limits.TerminationGrace,
			)
			return ProcessResult{}, errors.Join(
				fmt.Errorf("%w: executable path changed", ErrInvalidConfiguration),
				err, waitErr, cleanupErr,
			)
		}
	}
	_ = workingHandle.Close()
	currentWorking, workingErr := os.Lstat(workingPath)
	if workingErr != nil || !os.SameFile(workingInfo, currentWorking) ||
		!trustedEntry(currentWorking, runner.workRootDevice) {
		_ = syscall.Kill(-command.Process.Pid, syscall.SIGKILL)
		waitErr := command.Wait()
		cleanupErr := cleanupExitedProcessGroup(
			command.Process.Pid, runner.limits.TerminationGrace,
		)
		return ProcessResult{}, errors.Join(
			fmt.Errorf("%w: working directory changed", ErrInvalidRequest),
			waitErr, cleanupErr,
		)
	}
	done := make(chan error, 1)
	go func() { done <- command.Wait() }()
	ticker := time.NewTicker(outputPollInterval)
	defer ticker.Stop()

	result := func() ProcessResult {
		return ProcessResult{
			Stdout: stdout.Bytes(), Stderr: stderr.Bytes(),
			Duration:    time.Since(startedAt),
			OutputBytes: usage.bytes, OutputFiles: usage.files,
		}
	}
	for {
		select {
		case waitErr := <-done:
			if priorityErr := prioritizedCompletionError(ctx.Err(), runCtx.Err()); priorityErr != nil {
				cleanupErr := cleanupExitedProcessGroup(
					command.Process.Pid, runner.limits.TerminationGrace,
				)
				return result(), errors.Join(priorityErr, cleanupErr)
			}
			if cleanupErr := cleanupExitedProcessGroup(
				command.Process.Pid, runner.limits.TerminationGrace,
			); cleanupErr != nil {
				return result(), cleanupErr
			}
			if stdout.Exceeded() {
				return result(), ErrStdoutLimit
			}
			if stderr.Exceeded() {
				return result(), ErrStderrLimit
			}
			cleanupCtx, cleanupCancel := context.WithTimeout(
				context.Background(), finalOutputInspectionTimeout,
			)
			usage, err = runner.inspectOutput(
				cleanupCtx, outputRoot, outputPath, outputInfo,
			)
			cleanupCancel()
			completed := result()
			if err != nil {
				if errors.Is(err, context.DeadlineExceeded) {
					return completed, fmt.Errorf(
						"%w: final output inspection timed out", ErrUnsafeOutput,
					)
				}
				return completed, err
			}
			if priorityErr := prioritizedCompletionError(
				ctx.Err(), runCtx.Err(),
			); priorityErr != nil {
				return completed, priorityErr
			}
			completed.OutputBytes = usage.bytes
			completed.OutputFiles = usage.files
			exitCode, err := processExitCode(command, waitErr)
			completed.ExitCode = exitCode
			if err != nil {
				return completed, err
			}
			if priorityErr := prioritizedCompletionError(
				ctx.Err(), runCtx.Err(),
			); priorityErr != nil {
				return completed, priorityErr
			}
			return completed, nil
		case limit := <-overflow:
			cleanupErr := terminateProcessGroup(
				command, done, runner.limits.TerminationGrace,
			)
			mainErr := limit.err
			if priorityErr := prioritizedCompletionError(
				ctx.Err(), runCtx.Err(),
			); priorityErr != nil {
				mainErr = priorityErr
			}
			return result(), errors.Join(mainErr, cleanupErr)
		case <-ticker.C:
			usage, err = runner.inspectOutput(runCtx, outputRoot, outputPath, outputInfo)
			if err != nil {
				cleanupErr := terminateProcessGroup(
					command, done, runner.limits.TerminationGrace,
				)
				mainErr := err
				if priorityErr := prioritizedCompletionError(
					ctx.Err(), runCtx.Err(),
				); priorityErr != nil {
					mainErr = priorityErr
				}
				return result(), errors.Join(mainErr, cleanupErr)
			}
		case <-runCtx.Done():
			cleanupErr := terminateProcessGroup(
				command, done, runner.limits.TerminationGrace,
			)
			completed := result()
			return completed, errors.Join(
				prioritizedCompletionError(ctx.Err(), runCtx.Err()), cleanupErr,
			)
		}
	}
}

func (runner *ProcessRunner) preparationError(
	parent context.Context,
	operation context.Context,
	err error,
) error {
	if priorityErr := prioritizedCompletionError(parent.Err(), operation.Err()); priorityErr != nil {
		return priorityErr
	}
	return err
}

func prioritizedCompletionError(parentErr error, operationErr error) error {
	if parentErr != nil {
		return parentErr
	}
	if errors.Is(operationErr, context.DeadlineExceeded) {
		return ErrTimedOut
	}
	return operationErr
}

func processDirectoryFDPath(descriptor uintptr) (string, bool) {
	if runtime.GOOS == "linux" {
		return linuxProcessFDPath(descriptor), true
	}
	return "", false
}

func linuxProcessFDPath(descriptor uintptr) string {
	return "/proc/self/fd/" + strconv.FormatUint(uint64(descriptor), 10)
}

func processExecutableFDPath(descriptor int) (string, bool) {
	if runtime.GOOS == "linux" {
		return "/proc/self/fd/" + strconv.Itoa(descriptor), true
	}
	return "", false
}

// Some hardened container profiles intentionally deny all /proc/self/fd
// traversal. Descriptor-bound execution remains the preferred path; the
// caller may use an immutable root-owned image path when it is unavailable.
func linuxProcessFDDirectoryAvailable() bool {
	if runtime.GOOS != "linux" {
		return false
	}
	probe, err := os.Open(os.DevNull)
	if err != nil {
		return false
	}
	defer probe.Close()
	bound, err := os.Open(linuxProcessFDPath(probe.Fd()))
	if err != nil {
		return false
	}
	closeErr := bound.Close()
	_, linkErr := os.Readlink(linuxProcessFDPath(probe.Fd()))
	return closeErr == nil && linkErr == nil
}

func rootOwnedReadOnlyPath(name string, expected fs.FileInfo) bool {
	if runtime.GOOS != "linux" || os.Geteuid() == 0 ||
		!filepath.IsAbs(name) || expected == nil {
		return false
	}
	current := filepath.Clean(name)
	first := true
	for {
		info, err := os.Lstat(current)
		if err != nil || info.Mode()&os.ModeSymlink != 0 ||
			info.Mode().Perm()&0o022 != 0 {
			return false
		}
		metadata, ok := info.Sys().(*syscall.Stat_t)
		if !ok || metadata.Uid != 0 {
			return false
		}
		if first {
			if !info.Mode().IsRegular() || info.Mode().Perm()&0o111 == 0 ||
				!os.SameFile(expected, info) {
				return false
			}
			first = false
		} else if !info.IsDir() {
			return false
		}
		parent := filepath.Dir(current)
		if parent == current {
			return true
		}
		current = parent
	}
}

func digestExecutable(
	ctx context.Context,
	path string,
	expected fs.FileInfo,
) ([sha256.Size]byte, int64, error) {
	var empty [sha256.Size]byte
	if expected.Size() <= 0 || expected.Size() > maxExecutableSnapshotBytes {
		return empty, 0, fmt.Errorf(
			"%w: executable size is invalid", ErrInvalidConfiguration,
		)
	}
	file, err := os.Open(path)
	if err != nil {
		return empty, 0, fmt.Errorf("%w: open executable", ErrInvalidConfiguration)
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(expected, opened) ||
		!opened.Mode().IsRegular() || opened.Size() != expected.Size() {
		return empty, 0, fmt.Errorf("%w: executable changed", ErrInvalidConfiguration)
	}
	hasher := sha256.New()
	written, err := io.Copy(
		hasher,
		io.LimitReader(&contextReader{ctx: ctx, reader: file}, expected.Size()+1),
	)
	if err != nil {
		if contextErr := ctx.Err(); contextErr != nil {
			return empty, 0, contextErr
		}
		return empty, 0, fmt.Errorf("%w: hash executable", ErrInvalidConfiguration)
	}
	after, err := file.Stat()
	if err != nil || !os.SameFile(opened, after) || after.Size() != expected.Size() ||
		written != expected.Size() {
		return empty, 0, fmt.Errorf("%w: executable changed", ErrInvalidConfiguration)
	}
	var digest [sha256.Size]byte
	copy(digest[:], hasher.Sum(nil))
	return digest, written, nil
}

type preparedExecutable struct {
	path string
	file *os.File
	info fs.FileInfo
	once sync.Once
}

func (snapshot *preparedExecutable) cleanup() {
	if snapshot == nil {
		return
	}
	snapshot.once.Do(func() {
		if snapshot.file != nil {
			_ = snapshot.file.Close()
		}
		if snapshot.path != "" {
			current, err := os.Lstat(snapshot.path)
			if err == nil && snapshot.info != nil && os.SameFile(snapshot.info, current) {
				_ = os.Remove(snapshot.path)
			}
		}
	})
}

func (snapshot *preparedExecutable) pathIsBound() bool {
	if snapshot == nil || snapshot.path == "" || snapshot.info == nil {
		return false
	}
	current, err := os.Lstat(snapshot.path)
	return err == nil && os.SameFile(snapshot.info, current) &&
		trustedEntry(current, mustFileDevice(snapshot.info))
}

func mustFileDevice(info fs.FileInfo) uint64 {
	device, _, _ := fileDeviceAndLinks(info)
	return device
}

func (runner *ProcessRunner) prepareExecutableSnapshot(
	ctx context.Context,
) (*preparedExecutable, error) {
	if err := runner.revalidateRoots(); err != nil {
		return nil, err
	}
	source, err := os.Open(runner.executable)
	if err != nil {
		return nil, fmt.Errorf("%w: open executable", ErrInvalidConfiguration)
	}
	defer source.Close()
	opened, err := source.Stat()
	if err != nil || !os.SameFile(runner.executableInfo, opened) ||
		opened.Size() != runner.executableSize {
		return nil, fmt.Errorf("%w: executable changed", ErrInvalidConfiguration)
	}
	temporary, err := os.CreateTemp(runner.workRoot, ".bytecode-exec-*")
	if err != nil {
		return nil, fmt.Errorf("%w: create executable snapshot", ErrInvalidConfiguration)
	}
	snapshot := &preparedExecutable{path: temporary.Name()}
	initialInfo, statErr := temporary.Stat()
	if statErr != nil {
		_ = temporary.Close()
		_ = os.Remove(snapshot.path)
		return nil, fmt.Errorf("%w: inspect executable snapshot", ErrInvalidConfiguration)
	}
	snapshot.info = initialInfo
	fail := func(err error) (*preparedExecutable, error) {
		_ = temporary.Close()
		snapshot.cleanup()
		return nil, err
	}
	hasher := sha256.New()
	written, err := io.Copy(
		io.MultiWriter(temporary, hasher),
		io.LimitReader(
			&contextReader{ctx: ctx, reader: source}, runner.executableSize+1,
		),
	)
	if err != nil {
		if contextErr := ctx.Err(); contextErr != nil {
			return fail(contextErr)
		}
		return fail(fmt.Errorf("%w: copy executable snapshot", ErrInvalidConfiguration))
	}
	var digest [sha256.Size]byte
	copy(digest[:], hasher.Sum(nil))
	if written != runner.executableSize || digest != runner.executableSHA256 {
		return fail(fmt.Errorf("%w: executable content changed", ErrInvalidConfiguration))
	}
	if err := temporary.Sync(); err != nil {
		return fail(fmt.Errorf("%w: sync executable snapshot", ErrInvalidConfiguration))
	}
	if err := temporary.Chmod(0o500); err != nil {
		return fail(fmt.Errorf("%w: protect executable snapshot", ErrInvalidConfiguration))
	}
	if err := temporary.Close(); err != nil {
		return fail(fmt.Errorf("%w: close executable snapshot", ErrInvalidConfiguration))
	}
	info, err := os.Lstat(snapshot.path)
	if err != nil || !os.SameFile(snapshot.info, info) ||
		!info.Mode().IsRegular() || info.Size() != runner.executableSize ||
		!trustedEntry(info, runner.workRootDevice) {
		return fail(fmt.Errorf("%w: executable snapshot is unsafe", ErrInvalidConfiguration))
	}
	snapshot.info = info
	verifiedDigest, verifiedSize, err := digestExecutable(ctx, snapshot.path, info)
	if err != nil || verifiedDigest != runner.executableSHA256 ||
		verifiedSize != runner.executableSize {
		return fail(fmt.Errorf("%w: executable snapshot verification failed", ErrInvalidConfiguration))
	}
	bound, err := os.Open(snapshot.path)
	if err != nil {
		return fail(fmt.Errorf("%w: bind executable snapshot", ErrInvalidConfiguration))
	}
	boundInfo, err := bound.Stat()
	if err != nil || !os.SameFile(snapshot.info, boundInfo) ||
		!trustedEntry(boundInfo, runner.workRootDevice) {
		bound.Close()
		return fail(fmt.Errorf("%w: executable snapshot binding changed", ErrInvalidConfiguration))
	}
	snapshot.file = bound
	if runtime.GOOS == "linux" {
		if err := os.Remove(snapshot.path); err != nil {
			return fail(fmt.Errorf("%w: unlink executable snapshot", ErrInvalidConfiguration))
		}
		snapshot.path = ""
	}
	if err := runner.revalidateRoots(); err != nil {
		return fail(err)
	}
	return snapshot, nil
}

func (runner *ProcessRunner) bindReadOnlyExecutable(
	ctx context.Context,
) (*preparedExecutable, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !rootOwnedReadOnlyPath(runner.executable, runner.executableInfo) {
		return nil, fmt.Errorf("%w: executable path is mutable", ErrInvalidConfiguration)
	}
	bound, err := os.Open(runner.executable)
	if err != nil {
		return nil, fmt.Errorf("%w: bind executable", ErrInvalidConfiguration)
	}
	info, err := bound.Stat()
	if err != nil || !os.SameFile(runner.executableInfo, info) ||
		!rootOwnedReadOnlyPath(runner.executable, info) {
		_ = bound.Close()
		return nil, fmt.Errorf("%w: executable binding changed", ErrInvalidConfiguration)
	}
	return &preparedExecutable{file: bound, info: info}, nil
}

func normalizeProcessLimits(limits ProcessLimits) (ProcessLimits, error) {
	if limits.MaxDuration < 0 || limits.TerminationGrace < 0 ||
		limits.MaxStdoutBytes < 0 || limits.MaxStderrBytes < 0 ||
		limits.MaxOutputBytes < 0 || limits.MaxOutputFiles < 0 ||
		limits.MaxArguments < 0 || limits.MaxArgumentBytes < 0 ||
		limits.MaxTotalArgumentBytes < 0 {
		return ProcessLimits{}, fmt.Errorf(
			"%w: process limits are negative", ErrInvalidConfiguration,
		)
	}
	setDurationDefault(&limits.MaxDuration, DefaultProcessDuration)
	setDurationDefault(&limits.TerminationGrace, DefaultTerminationGrace)
	setInt64Default(&limits.MaxStdoutBytes, DefaultMaxStdoutBytes)
	setInt64Default(&limits.MaxStderrBytes, DefaultMaxStderrBytes)
	setInt64Default(&limits.MaxOutputBytes, DefaultMaxProcessOutputBytes)
	setIntDefault(&limits.MaxOutputFiles, DefaultMaxProcessFiles)
	setIntDefault(&limits.MaxArguments, DefaultMaxProcessArguments)
	setIntDefault(&limits.MaxArgumentBytes, DefaultMaxProcessArgumentBytes)
	setIntDefault(&limits.MaxTotalArgumentBytes, DefaultMaxProcessArgumentTotal)
	if limits.MaxDuration > maxProcessDuration ||
		limits.TerminationGrace > maxTerminationGrace ||
		limits.MaxStdoutBytes > maxProcessStreamBytes ||
		limits.MaxStderrBytes > maxProcessStreamBytes ||
		limits.MaxOutputBytes > maxProcessOutputBytes ||
		limits.MaxOutputFiles > maxProcessFiles ||
		limits.MaxArguments > maxProcessArguments ||
		limits.MaxArgumentBytes > maxProcessArgumentBytes ||
		limits.MaxTotalArgumentBytes > maxProcessArgumentTotal {
		return ProcessLimits{}, fmt.Errorf(
			"%w: process limits exceed ceilings", ErrInvalidConfiguration,
		)
	}
	return limits, nil
}

func setDurationDefault(value *time.Duration, fallback time.Duration) {
	if *value == 0 {
		*value = fallback
	}
}

func setInt64Default(value *int64, fallback int64) {
	if *value == 0 {
		*value = fallback
	}
}

func setIntDefault(value *int, fallback int) {
	if *value == 0 {
		*value = fallback
	}
}

func validateEnvironment(environment []string) ([]string, error) {
	cloned := make([]string, len(environment))
	seen := make(map[string]struct{}, len(environment))
	for index, entry := range environment {
		name, _, found := strings.Cut(entry, "=")
		if !found || !environmentNamePattern.MatchString(name) ||
			!utf8.ValidString(entry) || strings.IndexByte(entry, 0) >= 0 ||
			len(entry) > 64<<10 {
			return nil, fmt.Errorf(
				"%w: process environment is invalid", ErrInvalidConfiguration,
			)
		}
		if _, exists := seen[name]; exists {
			return nil, fmt.Errorf(
				"%w: process environment has duplicate keys",
				ErrInvalidConfiguration,
			)
		}
		seen[name] = struct{}{}
		cloned[index] = entry
	}
	return cloned, nil
}

func (runner *ProcessRunner) resolveDirectory(relative string) (string, fs.FileInfo, error) {
	if relative == "" || filepath.IsAbs(relative) || filepath.Clean(relative) != relative ||
		(relative != "." && !filepath.IsLocal(relative)) {
		return "", nil, fmt.Errorf(
			"%w: process directory is invalid", ErrInvalidRequest,
		)
	}
	current := runner.workRoot
	if relative != "." {
		for _, component := range strings.Split(relative, string(filepath.Separator)) {
			current = filepath.Join(current, component)
			info, err := os.Lstat(current)
			if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 ||
				!trustedEntry(info, runner.workRootDevice) {
				return "", nil, fmt.Errorf(
					"%w: process directory contains an unsafe component",
					ErrInvalidRequest,
				)
			}
		}
	}
	info, err := os.Lstat(current)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 ||
		!trustedEntry(info, runner.workRootDevice) {
		return "", nil, fmt.Errorf(
			"%w: process directory is unavailable", ErrInvalidRequest,
		)
	}
	return current, info, nil
}

func (runner *ProcessRunner) revalidateRoots() error {
	executableInfo, err := os.Lstat(runner.executable)
	if err != nil || !os.SameFile(runner.executableInfo, executableInfo) ||
		executableInfo.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%w: executable changed", ErrInvalidConfiguration)
	}
	rootInfo, err := os.Lstat(runner.workRoot)
	if err != nil || !os.SameFile(runner.workRootInfo, rootInfo) ||
		rootInfo.Mode()&os.ModeSymlink != 0 ||
		!trustedEntry(rootInfo, runner.workRootDevice) {
		return fmt.Errorf("%w: work root changed", ErrInvalidConfiguration)
	}
	return nil
}

func pathWithin(parent string, child string) bool {
	relative, err := filepath.Rel(parent, child)
	return err == nil && (relative == "." || filepath.IsLocal(relative))
}

type outputUsage struct {
	bytes int64
	files int
}

func (runner *ProcessRunner) inspectOutput(
	ctx context.Context,
	root *os.Root,
	path string,
	expected fs.FileInfo,
) (outputUsage, error) {
	if err := ctx.Err(); err != nil {
		return outputUsage{}, err
	}
	current, err := os.Lstat(path)
	if err != nil || !os.SameFile(expected, current) ||
		!current.IsDir() || current.Mode()&os.ModeSymlink != 0 ||
		!trustedEntry(current, runner.workRootDevice) {
		return outputUsage{}, fmt.Errorf("%w: output root changed", ErrUnsafeOutput)
	}
	bound, err := root.Lstat(".")
	if err != nil || !os.SameFile(expected, bound) ||
		!os.SameFile(current, bound) ||
		!trustedEntry(bound, runner.workRootDevice) {
		return outputUsage{}, fmt.Errorf(
			"%w: output root descriptor does not match its path", ErrUnsafeOutput,
		)
	}
	usage := outputUsage{}
	err = fs.WalkDir(root.FS(), ".", func(
		entryPath string,
		entry fs.DirEntry,
		walkErr error,
	) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if walkErr != nil {
			return fmt.Errorf("%w: inspect output entry", ErrUnsafeOutput)
		}
		if entryPath == "." {
			return nil
		}
		usage.files++
		if usage.files > runner.limits.MaxOutputFiles {
			return ErrFileCountLimit
		}
		info, err := entry.Info()
		if err != nil {
			return fmt.Errorf("%w: inspect output metadata", ErrUnsafeOutput)
		}
		if info.Mode()&os.ModeSymlink != 0 ||
			(!info.IsDir() && !info.Mode().IsRegular()) ||
			!trustedEntry(info, runner.workRootDevice) {
			return ErrUnsafeOutput
		}
		if info.Mode().IsRegular() {
			if info.Size() < 0 || info.Size() > runner.limits.MaxOutputBytes-usage.bytes {
				return ErrOutputLimit
			}
			usage.bytes += info.Size()
		}
		return nil
	})
	if err != nil {
		if contextErr := ctx.Err(); contextErr != nil {
			return usage, contextErr
		}
		if errors.Is(err, ErrOutputLimit) || errors.Is(err, ErrFileCountLimit) ||
			errors.Is(err, ErrUnsafeOutput) {
			return usage, err
		}
		return usage, fmt.Errorf("%w: walk output", ErrUnsafeOutput)
	}
	return usage, nil
}

type streamLimit struct{ err error }

type processCapture struct {
	mu       sync.Mutex
	buffer   bytes.Buffer
	maximum  int64
	exceeded bool
	once     sync.Once
	notify   chan<- streamLimit
	err      error
}

func newProcessCapture(
	err error,
	maximum int64,
	notify chan<- streamLimit,
) *processCapture {
	return &processCapture{maximum: maximum, notify: notify, err: err}
}

func (capture *processCapture) Write(payload []byte) (int, error) {
	capture.mu.Lock()
	defer capture.mu.Unlock()
	remaining := capture.maximum - int64(capture.buffer.Len())
	if remaining > 0 {
		writable := int64(len(payload))
		if writable > remaining {
			writable = remaining
		}
		_, _ = capture.buffer.Write(payload[:int(writable)])
	}
	if int64(len(payload)) > remaining {
		capture.exceeded = true
		capture.once.Do(func() { capture.notify <- streamLimit{err: capture.err} })
	}
	return len(payload), nil
}

func (capture *processCapture) Bytes() []byte {
	capture.mu.Lock()
	defer capture.mu.Unlock()
	return append([]byte(nil), capture.buffer.Bytes()...)
}

func (capture *processCapture) Exceeded() bool {
	capture.mu.Lock()
	defer capture.mu.Unlock()
	return capture.exceeded
}

func processExitCode(command *exec.Cmd, waitErr error) (int, error) {
	if waitErr == nil {
		if command.ProcessState == nil {
			return 0, fmt.Errorf("%w: process state is missing", ErrProcessWait)
		}
		return command.ProcessState.ExitCode(), nil
	}
	var exitError *exec.ExitError
	if errors.As(waitErr, &exitError) {
		return exitError.ExitCode(), nil
	}
	return 0, fmt.Errorf("%w: %v", ErrProcessWait, waitErr)
}

func terminateProcessGroup(
	command *exec.Cmd,
	done <-chan error,
	grace time.Duration,
) error {
	if command == nil || command.Process == nil {
		return nil
	}
	_ = syscall.Kill(-command.Process.Pid, syscall.SIGTERM)
	timer := time.NewTimer(grace)
	defer timer.Stop()
	var waitErr error
	select {
	case waitErr = <-done:
	case <-timer.C:
		_ = syscall.Kill(-command.Process.Pid, syscall.SIGKILL)
		waitErr = <-done
	}
	cleanupErr := cleanupExitedProcessGroup(command.Process.Pid, grace)
	return errors.Join(waitErr, cleanupErr)
}

func cleanupExitedProcessGroup(pid int, grace time.Duration) error {
	if pid <= 0 || syscall.Kill(-pid, 0) != nil {
		return nil
	}
	_ = syscall.Kill(-pid, syscall.SIGTERM)
	if waitForProcessGroup(pid, grace) {
		return nil
	}
	_ = syscall.Kill(-pid, syscall.SIGKILL)
	if waitForProcessGroup(pid, grace) {
		return nil
	}
	return fmt.Errorf("%w: process group %d survived cleanup", ErrProcessWait, pid)
}

func waitForProcessGroup(pid int, maximum time.Duration) bool {
	deadline := time.Now().Add(maximum)
	for {
		if syscall.Kill(-pid, 0) != nil {
			return true
		}
		if !time.Now().Before(deadline) {
			return false
		}
		time.Sleep(10 * time.Millisecond)
	}
}

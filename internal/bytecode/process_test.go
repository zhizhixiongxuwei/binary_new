package bytecode

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

const processHelperEnvironment = "BINARYSCAN_BYTECODE_PROCESS_HELPER"

func TestProcessHelper(t *testing.T) {
	if os.Getenv(processHelperEnvironment) != "1" {
		return
	}
	separator := -1
	for index, argument := range os.Args {
		if argument == "--" {
			separator = index
			break
		}
	}
	if separator < 0 || separator+1 >= len(os.Args) {
		os.Exit(90)
	}
	arguments := os.Args[separator+1:]
	switch arguments[0] {
	case "arguments":
		if err := json.NewEncoder(os.Stdout).Encode(arguments[1:]); err != nil {
			os.Exit(91)
		}
	case "streams":
		stdoutBytes, _ := strconv.Atoi(arguments[1])
		stderrBytes, _ := strconv.Atoi(arguments[2])
		_, _ = os.Stdout.Write([]byte(strings.Repeat("o", stdoutBytes)))
		_, _ = os.Stderr.Write([]byte(strings.Repeat("e", stderrBytes)))
	case "write-bytes":
		count, _ := strconv.Atoi(arguments[2])
		if err := os.WriteFile(arguments[1], []byte(strings.Repeat("x", count)), 0o600); err != nil {
			os.Exit(92)
		}
	case "write-files":
		count, _ := strconv.Atoi(arguments[2])
		for index := 0; index < count; index++ {
			name := filepath.Join(arguments[1], fmt.Sprintf("%d.txt", index))
			if err := os.WriteFile(name, []byte("x"), 0o600); err != nil {
				os.Exit(93)
			}
		}
	case "symlink":
		if err := os.Symlink(arguments[2], arguments[1]); err != nil {
			os.Exit(94)
		}
	case "hardlink":
		if err := os.Link(arguments[1], arguments[2]); err != nil {
			os.Exit(99)
		}
	case "exit":
		code, _ := strconv.Atoi(arguments[1])
		os.Exit(code)
	case "hang":
		time.Sleep(10 * time.Second)
	case "spawn-child":
		executable, err := processHelperExecutable()
		if err != nil {
			os.Exit(95)
		}
		child := exec.Command(
			executable, "-test.run=^TestProcessHelper$", "--", "child", arguments[1],
		)
		child.Env = os.Environ()
		child.Stdout = io.Discard
		child.Stderr = io.Discard
		if err := child.Start(); err != nil {
			os.Exit(96)
		}
		time.Sleep(10 * time.Second)
	case "spawn-child-ready":
		executable, err := processHelperExecutable()
		if err != nil {
			os.Exit(103)
		}
		child := exec.Command(
			executable, "-test.run=^TestProcessHelper$", "--",
			"child-ready", arguments[1],
		)
		child.Env = os.Environ()
		child.Stdout = io.Discard
		child.Stderr = io.Discard
		if err := child.Start(); err != nil {
			os.Exit(104)
		}
		if !helperWaitForFile(arguments[1], 10*time.Second) {
			os.Exit(105)
		}
		if err := helperAtomicWrite(arguments[2], []byte("ready")); err != nil {
			os.Exit(106)
		}
		time.Sleep(10 * time.Second)
	case "child-ready":
		if err := helperAtomicWrite(
			arguments[1], []byte(strconv.Itoa(os.Getpid())),
		); err != nil {
			os.Exit(107)
		}
		time.Sleep(10 * time.Second)
	case "child":
		if err := os.WriteFile(
			arguments[1], []byte(strconv.Itoa(os.Getpid())), 0o600,
		); err != nil {
			os.Exit(97)
		}
		time.Sleep(10 * time.Second)
	case "cwd":
		workingDirectory, err := os.Getwd()
		if err != nil {
			os.Exit(100)
		}
		if err := os.WriteFile(arguments[1], []byte("bound"), 0o600); err != nil {
			os.Exit(101)
		}
		if err := json.NewEncoder(os.Stdout).Encode(struct {
			WorkingDirectory string `json:"working_directory"`
		}{WorkingDirectory: workingDirectory}); err != nil {
			os.Exit(102)
		}
	default:
		os.Exit(98)
	}
	os.Exit(0)
}

func TestProcessRunnerPreservesArgumentArrayWithoutShell(t *testing.T) {
	runner, invocation, prefix := processFixture(t, ProcessLimits{})
	literal := []string{"a b", "$(touch should-not-run)", ";", "*.class", ""}
	invocation.Arguments = append(prefix, append([]string{"arguments"}, literal...)...)
	result, err := runner.Run(context.Background(), invocation)
	if err != nil {
		t.Fatalf("Run() error = %v; stderr=%q", err, result.Stderr)
	}
	var received []string
	if err := json.Unmarshal(result.Stdout, &received); err != nil {
		t.Fatalf("decode stdout %q: %v", result.Stdout, err)
	}
	if fmt.Sprint(received) != fmt.Sprint(literal) || result.ExitCode != 0 {
		t.Fatalf("arguments = %#v, exit = %d", received, result.ExitCode)
	}
}

func TestProcessRunnerReturnsNonzeroExitWithoutClaimingInvalidOutput(t *testing.T) {
	runner, invocation, prefix := processFixture(t, ProcessLimits{})
	invocation.Arguments = append(prefix, "exit", "7")
	result, err := runner.Run(context.Background(), invocation)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if result.ExitCode != 7 {
		t.Fatalf("exit code = %d, want 7", result.ExitCode)
	}
}

func TestProcessRunnerEnforcesIndependentStreamLimits(t *testing.T) {
	tests := []struct {
		name        string
		stdoutBytes string
		stderrBytes string
		want        error
	}{
		{"stdout", "65", "1", ErrStdoutLimit},
		{"stderr", "1", "65", ErrStderrLimit},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			runner, invocation, prefix := processFixture(t, ProcessLimits{
				MaxStdoutBytes: 64, MaxStderrBytes: 64,
			})
			invocation.Arguments = append(
				prefix, "streams", test.stdoutBytes, test.stderrBytes,
			)
			result, err := runner.Run(context.Background(), invocation)
			if !errors.Is(err, test.want) {
				t.Fatalf("Run() error = %v, want %v", err, test.want)
			}
			if len(result.Stdout) > 64 || len(result.Stderr) > 64 {
				t.Fatalf("unbounded output: stdout=%d stderr=%d", len(result.Stdout), len(result.Stderr))
			}
		})
	}
}

func TestProcessRunnerEnforcesOutputBytesAndFileCount(t *testing.T) {
	t.Run("bytes", func(t *testing.T) {
		runner, invocation, prefix := processFixture(t, ProcessLimits{MaxOutputBytes: 32})
		outputPath := filepath.Join(runner.workRoot, "run", "out", "large.bin")
		invocation.Arguments = append(prefix, "write-bytes", outputPath, "33")
		result, err := runner.Run(context.Background(), invocation)
		if !errors.Is(err, ErrOutputLimit) || result.OutputBytes > 32 {
			t.Fatalf("Run() = %#v, %v", result, err)
		}
	})
	t.Run("files", func(t *testing.T) {
		runner, invocation, prefix := processFixture(t, ProcessLimits{MaxOutputFiles: 2})
		outputPath := filepath.Join(runner.workRoot, "run", "out")
		invocation.Arguments = append(prefix, "write-files", outputPath, "3")
		result, err := runner.Run(context.Background(), invocation)
		if !errors.Is(err, ErrFileCountLimit) || result.OutputFiles > 3 {
			t.Fatalf("Run() = %#v, %v", result, err)
		}
	})
}

func TestProcessRunnerRejectsUnsafeOutput(t *testing.T) {
	runner, invocation, prefix := processFixture(t, ProcessLimits{})
	linkPath := filepath.Join(runner.workRoot, "run", "out", "link")
	invocation.Arguments = append(prefix, "symlink", linkPath, "../outside")
	_, err := runner.Run(context.Background(), invocation)
	if !errors.Is(err, ErrUnsafeOutput) {
		t.Fatalf("Run() error = %v", err)
	}
}

func TestProcessRunnerRejectsHardLinkedOutput(t *testing.T) {
	runner, invocation, prefix := processFixture(t, ProcessLimits{})
	original := filepath.Join(runner.workRoot, "run", "original.bin")
	linked := filepath.Join(runner.workRoot, "run", "out", "linked.bin")
	if err := os.WriteFile(original, []byte("shared"), 0o600); err != nil {
		t.Fatal(err)
	}
	invocation.Arguments = append(prefix, "hardlink", original, linked)
	_, err := runner.Run(context.Background(), invocation)
	if !errors.Is(err, ErrUnsafeOutput) {
		t.Fatalf("Run() error = %v", err)
	}
}

func TestProcessRunnerTimeoutKillsEntireProcessGroup(t *testing.T) {
	runner, invocation, prefix := processFixture(t, ProcessLimits{
		MaxDuration:      10 * time.Minute,
		TerminationGrace: 50 * time.Millisecond,
	})
	timeoutDeadline := newManualDeadlineContext(context.Background())
	runner.timeoutContext = func(
		context.Context,
		time.Duration,
	) (context.Context, context.CancelFunc) {
		return timeoutDeadline, func() {}
	}
	pidFile := filepath.Join(runner.workRoot, "run", "out", "child.pid")
	readyFile := filepath.Join(runner.workRoot, "run", "out", "parent.ready")
	invocation.Arguments = append(
		prefix, "spawn-child-ready", pidFile, readyFile,
	)
	type outcome struct {
		result ProcessResult
		err    error
	}
	finished := make(chan outcome, 1)
	go func() {
		result, err := runner.Run(context.Background(), invocation)
		finished <- outcome{result: result, err: err}
	}()
	if !helperWaitForFile(readyFile, 10*time.Second) {
		t.Fatal("helper process group did not reach ready state")
	}
	payload, err := os.ReadFile(pidFile)
	if err != nil {
		t.Fatalf("read child PID: %v", err)
	}
	pid, err := strconv.Atoi(string(payload))
	if err != nil {
		t.Fatalf("parse child PID: %v", err)
	}
	timeoutDeadline.Trigger()
	var completed outcome
	select {
	case completed = <-finished:
	case <-time.After(10 * time.Second):
		t.Fatal("Runner did not stop after triggered deadline")
	}
	result, err := completed.result, completed.err
	if !errors.Is(err, ErrTimedOut) {
		t.Fatalf("Run() result = %#v, error = %v", result, err)
	}
	processDeadline := time.Now().Add(2 * time.Second)
	for processExists(pid) && time.Now().Before(processDeadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if processExists(pid) {
		t.Fatalf("child process %d survived group cleanup", pid)
	}
}

func TestProcessRunnerPropagatesParentCancellation(t *testing.T) {
	runner, invocation, prefix := processFixture(t, ProcessLimits{
		MaxDuration: time.Minute, TerminationGrace: 20 * time.Millisecond,
	})
	invocation.Arguments = append(prefix, "hang")
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(50*time.Millisecond, cancel)
	_, err := runner.Run(ctx, invocation)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Run() error = %v", err)
	}
}

func TestProcessRunnerReportsFinalOutputUsage(t *testing.T) {
	runner, invocation, prefix := processFixture(t, ProcessLimits{})
	outputPath := filepath.Join(runner.workRoot, "run", "out", "artifact.bin")
	invocation.Arguments = append(prefix, "write-bytes", outputPath, "17")
	result, err := runner.Run(context.Background(), invocation)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if result.OutputBytes != 17 || result.OutputFiles != 1 ||
		result.Duration <= 0 || result.ExitCode != 0 {
		t.Fatalf("Run() result = %#v", result)
	}
}

func TestProcessRunnerRejectsUnsafeConfigurationAndInvocation(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	_, err = NewProcessRunner(ProcessConfig{
		Executable: "relative-tool", WorkRoot: t.TempDir(),
	})
	if !errors.Is(err, ErrInvalidConfiguration) {
		t.Fatalf("relative executable error = %v", err)
	}
	_, err = NewProcessRunner(ProcessConfig{
		Executable: executable, WorkRoot: t.TempDir(),
		Environment: []string{"A=1", "A=2"},
	})
	if !errors.Is(err, ErrInvalidConfiguration) {
		t.Fatalf("duplicate environment error = %v", err)
	}
	_, err = NewProcessRunner(ProcessConfig{
		Executable: executable, WorkRoot: string(filepath.Separator),
	})
	if !errors.Is(err, ErrInvalidConfiguration) {
		t.Fatalf("filesystem root error = %v", err)
	}
	insecureRoot := t.TempDir()
	if err := os.Chmod(insecureRoot, 0o777); err != nil {
		t.Fatal(err)
	}
	_, err = NewProcessRunner(ProcessConfig{
		Executable: executable, WorkRoot: insecureRoot,
	})
	if !errors.Is(err, ErrInvalidConfiguration) {
		t.Fatalf("writable work root error = %v", err)
	}

	runner, invocation, prefix := processFixture(t, ProcessLimits{MaxArguments: 3})
	invocation.Arguments = append(prefix, "arguments", "too-many")
	if _, err := runner.Run(context.Background(), invocation); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("argument limit error = %v", err)
	}
	invocation.Arguments = prefix
	invocation.OutputDirectory = "../outside"
	if _, err := runner.Run(context.Background(), invocation); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("directory traversal error = %v", err)
	}
	invocation.WorkingDirectory = "."
	invocation.OutputDirectory = "."
	if _, err := runner.Run(context.Background(), invocation); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("work-root invocation error = %v", err)
	}
}

func TestProcessRunnerRejectsExecutableContentChange(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "run", "out"), 0o700); err != nil {
		t.Fatal(err)
	}
	original, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	tool := filepath.Join(root, "tool")
	copyExecutableForTest(t, original, tool)
	runner, err := NewProcessRunner(ProcessConfig{
		Executable: tool, WorkRoot: root,
		Environment: []string{processHelperEnvironment + "=1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	file, err := os.OpenFile(tool, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	_, writeErr := file.WriteAt([]byte("X"), 0)
	closeErr := file.Close()
	if writeErr != nil || closeErr != nil {
		t.Fatalf("mutate executable: write=%v close=%v", writeErr, closeErr)
	}
	_, err = runner.Run(context.Background(), ProcessInvocation{
		Arguments:        []string{"-test.run=^TestProcessHelper$", "--", "arguments"},
		WorkingDirectory: "run", OutputDirectory: filepath.Join("run", "out"),
	})
	if !errors.Is(err, ErrInvalidConfiguration) {
		t.Fatalf("changed executable error = %v", err)
	}
}

func TestProcessRunnerRejectsWorkingDirectorySymlink(t *testing.T) {
	runner, invocation, prefix := processFixture(t, ProcessLimits{})
	if err := os.Symlink("run", filepath.Join(runner.workRoot, "linked-run")); err != nil {
		t.Fatal(err)
	}
	invocation.Arguments = append(prefix, "arguments")
	invocation.WorkingDirectory = "linked-run"
	invocation.OutputDirectory = filepath.Join("linked-run", "out")
	if _, err := runner.Run(context.Background(), invocation); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("working symlink error = %v", err)
	}
}

func TestProcessCompletionPrioritizesDeadlineDeterministically(t *testing.T) {
	if err := prioritizedCompletionError(nil, context.DeadlineExceeded); !errors.Is(err, ErrTimedOut) {
		t.Fatalf("internal deadline priority error = %v", err)
	}
	if err := prioritizedCompletionError(context.Canceled, context.DeadlineExceeded); !errors.Is(err, context.Canceled) {
		t.Fatalf("parent cancellation priority error = %v", err)
	}
	if runtime.GOOS == "linux" {
		executablePath, executableBound := processExecutableFDPath(4)
		if !executableBound || executablePath != "/proc/self/fd/4" {
			t.Fatalf("Linux executable binding = %q, %v", executablePath, executableBound)
		}
	}
}

func TestLinuxWorkingDirectoryPathUsesInheritedDescriptorNumber(t *testing.T) {
	placeholders := make([]*os.File, 0, 24)
	for index := 0; index < cap(placeholders); index++ {
		file, err := os.Open(os.DevNull)
		if err != nil {
			t.Fatal(err)
		}
		placeholders = append(placeholders, file)
		defer file.Close()
	}
	directory, err := os.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer directory.Close()
	want := "/proc/self/fd/" + strconv.FormatUint(uint64(directory.Fd()), 10)
	if got := linuxProcessFDPath(directory.Fd()); got != want || got == "/proc/self/fd/3" {
		t.Fatalf("linuxProcessFDPath() = %q, want actual descriptor path %q", got, want)
	}
	if runtime.GOOS == "linux" {
		got, bound := processDirectoryFDPath(directory.Fd())
		if !bound || got != want {
			t.Fatalf("processDirectoryFDPath() = %q, %v", got, bound)
		}
	}
}

func TestLinuxRunnerStartsWithHighWorkingDirectoryFD(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux /proc/self/fd integration")
	}
	runner, invocation, prefix := processFixture(t, ProcessLimits{})
	placeholders := make([]*os.File, 0, 48)
	for index := 0; index < cap(placeholders); index++ {
		file, err := os.Open(os.DevNull)
		if err != nil {
			t.Fatal(err)
		}
		placeholders = append(placeholders, file)
		defer file.Close()
	}
	marker := filepath.Join("out", "cwd-marker")
	invocation.Arguments = append(prefix, "cwd", marker)
	result, err := runner.Run(context.Background(), invocation)
	if err != nil {
		t.Fatalf("Run() error = %v; stderr=%q", err, result.Stderr)
	}
	var observed struct {
		WorkingDirectory string `json:"working_directory"`
	}
	if err := json.Unmarshal(result.Stdout, &observed); err != nil {
		t.Fatalf("decode cwd %q: %v", result.Stdout, err)
	}
	expectedInfo, err := os.Stat(filepath.Join(runner.workRoot, "run"))
	if err != nil {
		t.Fatal(err)
	}
	observedInfo, err := os.Stat(observed.WorkingDirectory)
	if err != nil || !os.SameFile(expectedInfo, observedInfo) {
		t.Fatalf("child cwd = %q, info error = %v", observed.WorkingDirectory, err)
	}
	if _, err := os.Stat(filepath.Join(runner.workRoot, "run", marker)); err != nil {
		t.Fatalf("relative cwd marker: %v", err)
	}
}

func TestPreparedExecutableFDIsStableAcrossConcurrentReplacement(t *testing.T) {
	root := t.TempDir()
	original, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	tool := filepath.Join(root, "tool")
	copyExecutableForTest(t, original, tool)
	runner, err := NewProcessRunner(ProcessConfig{Executable: tool, WorkRoot: root})
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := runner.prepareExecutableSnapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer snapshot.cleanup()
	replacement := filepath.Join(root, "replacement-tool")
	copyExecutableForTest(t, original, replacement)

	start := make(chan struct{})
	digestResult := make(chan [sha256.Size]byte, 1)
	errResult := make(chan error, 1)
	go func() {
		<-start
		hasher := sha256.New()
		_, err := io.Copy(
			hasher, io.NewSectionReader(snapshot.file, 0, runner.executableSize),
		)
		if err != nil {
			errResult <- err
			return
		}
		var digest [sha256.Size]byte
		copy(digest[:], hasher.Sum(nil))
		digestResult <- digest
	}()
	go func() {
		<-start
		errResult <- os.Rename(replacement, tool)
	}()
	close(start)
	var digest [sha256.Size]byte
	for index := 0; index < 2; index++ {
		select {
		case err := <-errResult:
			if err != nil {
				t.Fatal(err)
			}
		case digest = <-digestResult:
		}
	}
	if digest != runner.executableSHA256 {
		t.Fatalf("bound executable digest = %x, want %x", digest, runner.executableSHA256)
	}
	if runtime.GOOS == "linux" && snapshot.path != "" {
		t.Fatal("Linux executable snapshot retained a pathname")
	}
}

func TestInspectOutputRejectsOpenRootSwapBack(t *testing.T) {
	runner, _, _ := processFixture(t, ProcessLimits{})
	outputPath := filepath.Join(runner.workRoot, "run", "out")
	expected, err := os.Lstat(outputPath)
	if err != nil {
		t.Fatal(err)
	}
	savedPath := filepath.Join(runner.workRoot, "run", "saved-out")
	if err := os.Rename(outputPath, savedPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(outputPath, 0o700); err != nil {
		t.Fatal(err)
	}
	wrongRoot, err := os.OpenRoot(outputPath)
	if err != nil {
		t.Fatal(err)
	}
	defer wrongRoot.Close()
	if err := os.Remove(outputPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(savedPath, outputPath); err != nil {
		t.Fatal(err)
	}
	_, err = runner.inspectOutput(
		context.Background(), wrongRoot, outputPath, expected,
	)
	if !errors.Is(err, ErrUnsafeOutput) {
		t.Fatalf("inspectOutput() error = %v", err)
	}
}

func TestProcessRunnerSupportsConcurrentRunsWithoutSharedCapture(t *testing.T) {
	root := t.TempDir()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	runner, err := NewProcessRunner(ProcessConfig{
		Executable: executable, WorkRoot: root,
		Environment: []string{processHelperEnvironment + "=1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	prefix := []string{"-test.run=^TestProcessHelper$", "--", "arguments"}
	const runs = 8
	errorsChannel := make(chan error, runs)
	var wait sync.WaitGroup
	for index := 0; index < runs; index++ {
		name := fmt.Sprintf("run-%d", index)
		if err := os.MkdirAll(filepath.Join(root, name, "out"), 0o700); err != nil {
			t.Fatal(err)
		}
		wait.Add(1)
		go func(index int, name string) {
			defer wait.Done()
			arguments := append(append([]string(nil), prefix...), strconv.Itoa(index))
			result, err := runner.Run(context.Background(), ProcessInvocation{
				Arguments: arguments, WorkingDirectory: name,
				OutputDirectory: filepath.Join(name, "out"),
			})
			if err != nil {
				errorsChannel <- err
				return
			}
			var received []string
			if json.Unmarshal(result.Stdout, &received) != nil ||
				len(received) != 1 || received[0] != strconv.Itoa(index) {
				errorsChannel <- fmt.Errorf(
					"run %d received %q, exit=%d stderr=%q",
					index, result.Stdout, result.ExitCode, result.Stderr,
				)
			}
		}(index, name)
	}
	wait.Wait()
	close(errorsChannel)
	for err := range errorsChannel {
		t.Errorf("concurrent Run() error = %v", err)
	}
}

func processFixture(
	t *testing.T,
	limits ProcessLimits,
) (*ProcessRunner, ProcessInvocation, []string) {
	t.Helper()
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "run", "out"), 0o700); err != nil {
		t.Fatal(err)
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	runner, err := NewProcessRunner(ProcessConfig{
		Executable: executable, WorkRoot: root,
		Environment: []string{processHelperEnvironment + "=1"},
		Limits:      limits,
	})
	if err != nil {
		t.Fatalf("NewProcessRunner() error = %v", err)
	}
	return runner, ProcessInvocation{
		WorkingDirectory: "run", OutputDirectory: filepath.Join("run", "out"),
	}, []string{"-test.run=^TestProcessHelper$", "--"}
}

func copyExecutableForTest(t *testing.T, sourcePath string, destinationPath string) {
	t.Helper()
	source, err := os.Open(sourcePath)
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	destination, err := os.OpenFile(
		destinationPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o700,
	)
	if err != nil {
		t.Fatal(err)
	}
	_, copyErr := io.Copy(destination, source)
	closeErr := destination.Close()
	if copyErr != nil || closeErr != nil {
		t.Fatalf("copy executable: copy=%v close=%v", copyErr, closeErr)
	}
}

func processExists(pid int) bool {
	err := syscall.Kill(pid, 0)
	return err == nil || errors.Is(err, syscall.EPERM)
}

func processHelperExecutable() (string, error) {
	if runtime.GOOS == "linux" {
		return "/proc/self/exe", nil
	}
	return os.Executable()
}

func helperAtomicWrite(path string, payload []byte) error {
	temporary := fmt.Sprintf("%s.tmp-%d", path, os.Getpid())
	if err := os.WriteFile(temporary, payload, 0o600); err != nil {
		return err
	}
	if err := os.Rename(temporary, path); err != nil {
		_ = os.Remove(temporary)
		return err
	}
	return nil
}

func helperWaitForFile(path string, maximum time.Duration) bool {
	deadline := time.Now().Add(maximum)
	for {
		if _, err := os.Stat(path); err == nil {
			return true
		}
		if !time.Now().Before(deadline) {
			return false
		}
		time.Sleep(5 * time.Millisecond)
	}
}

type manualDeadlineContext struct {
	parent context.Context
	done   chan struct{}
	once   sync.Once
	mu     sync.Mutex
	err    error
}

func newManualDeadlineContext(parent context.Context) *manualDeadlineContext {
	return &manualDeadlineContext{parent: parent, done: make(chan struct{})}
}

func (ctx *manualDeadlineContext) Deadline() (time.Time, bool) {
	return ctx.parent.Deadline()
}

func (ctx *manualDeadlineContext) Done() <-chan struct{} { return ctx.done }

func (ctx *manualDeadlineContext) Err() error {
	ctx.mu.Lock()
	defer ctx.mu.Unlock()
	return ctx.err
}

func (ctx *manualDeadlineContext) Value(key any) any { return ctx.parent.Value(key) }

func (ctx *manualDeadlineContext) Trigger() {
	ctx.once.Do(func() {
		ctx.mu.Lock()
		ctx.err = context.DeadlineExceeded
		ctx.mu.Unlock()
		close(ctx.done)
	})
}

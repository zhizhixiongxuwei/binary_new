package trivy

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"math"
	"os"
	"os/exec"
	"sync"
	"syscall"
	"time"
)

const (
	workspaceEntryOverheadBytes = int64(4 << 10)
	workspaceQuotaPollTicks     = 25
)

type commandSpec struct {
	Executable             string
	Arguments              []string
	Environment            []string
	Directory              string
	OutputPath             string
	MaxStandardOutputBytes int64
	MaxStandardErrorBytes  int64
	MaxReportBytes         int64
	QuotaRoot              string
	MaxQuotaBytes          int64
	TerminationGracePeriod time.Duration
}

type commandResult struct {
	ExitCode int
	Stdout   string
	Stderr   string
}

type streamOverflow struct {
	name string
}

func runCommand(ctx context.Context, specification commandSpec) (commandResult, error) {
	overflow := make(chan streamOverflow, 2)
	stdout := newBoundedCapture(
		"stdout",
		specification.MaxStandardOutputBytes,
		overflow,
	)
	stderr := newBoundedCapture(
		"stderr",
		specification.MaxStandardErrorBytes,
		overflow,
	)
	command := exec.Command(specification.Executable, specification.Arguments...)
	command.Dir = specification.Directory
	command.Env = append([]string(nil), specification.Environment...)
	command.Stdout = stdout
	command.Stderr = stderr
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := command.Start(); err != nil {
		return commandResult{}, fmt.Errorf("%w: start process: %v", ErrExecutionFailed, err)
	}

	done := make(chan error, 1)
	go func() {
		done <- command.Wait()
	}()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	quotaTicks := 0
	for {
		select {
		case waitErr := <-done:
			if specification.MaxQuotaBytes > 0 {
				if err := checkWorkspaceUsage(
					ctx,
					specification.QuotaRoot,
					specification.MaxQuotaBytes,
				); err != nil {
					return commandResult{}, err
				}
			}
			return completedCommand(command, waitErr, stdout, stderr)
		case exceeded := <-overflow:
			waitErr := terminateProcessGroup(
				command,
				done,
				specification.TerminationGracePeriod,
			)
			_ = waitErr
			return commandResult{}, fmt.Errorf(
				"%w: %s exceeded %d bytes",
				ErrOutputLimit,
				exceeded.name,
				captureLimit(exceeded.name, specification),
			)
		case <-ticker.C:
			if specification.OutputPath != "" {
				if err := checkGrowingReport(
					specification.OutputPath,
					specification.MaxReportBytes,
				); err != nil {
					_ = terminateProcessGroup(
						command,
						done,
						specification.TerminationGracePeriod,
					)
					return commandResult{}, err
				}
			}
			if specification.MaxQuotaBytes > 0 {
				quotaTicks++
				if quotaTicks == workspaceQuotaPollTicks {
					quotaTicks = 0
					if err := checkWorkspaceUsage(
						ctx,
						specification.QuotaRoot,
						specification.MaxQuotaBytes,
					); err != nil {
						_ = terminateProcessGroup(
							command,
							done,
							specification.TerminationGracePeriod,
						)
						return commandResult{}, err
					}
				}
			}
		case <-ctx.Done():
			select {
			case waitErr := <-done:
				return completedCommand(command, waitErr, stdout, stderr)
			default:
			}
			_ = terminateProcessGroup(
				command,
				done,
				specification.TerminationGracePeriod,
			)
			return commandResult{}, ctx.Err()
		}
	}
}

func checkWorkspaceUsage(
	ctx context.Context,
	root string,
	maximum int64,
) error {
	if ctx == nil {
		return fmt.Errorf(
			"%w: workspace quota context is nil",
			ErrInvalidConfiguration,
		)
	}
	if root == "" || maximum <= 0 {
		return fmt.Errorf(
			"%w: workspace quota configuration is invalid",
			ErrInvalidConfiguration,
		)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	before, err := os.Lstat(root)
	if err != nil || !before.IsDir() ||
		before.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf(
			"%w: workspace quota root is unavailable or unsafe",
			ErrInvalidReport,
		)
	}
	opened, err := os.OpenRoot(root)
	if err != nil {
		return fmt.Errorf(
			"%w: open workspace quota root",
			ErrInvalidReport,
		)
	}
	defer opened.Close()
	after, err := opened.Lstat(".")
	if err != nil || !os.SameFile(before, after) {
		return fmt.Errorf(
			"%w: workspace quota root changed during inspection",
			ErrInvalidReport,
		)
	}

	var total int64
	err = fs.WalkDir(opened.FS(), ".", func(
		path string,
		entry fs.DirEntry,
		walkErr error,
	) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if path != "." && errors.Is(walkErr, os.ErrNotExist) {
			// Trivy creates and removes analyzer scratch trees while the quota
			// walk is running. A vanished entry no longer consumes space and is
			// safe to omit from this poll; the final poll runs after Trivy exits.
			return nil
		}
		if walkErr != nil {
			return fmt.Errorf("inspect workspace entry: %w", walkErr)
		}
		info, err := entry.Info()
		if path != "." && errors.Is(err, os.ErrNotExist) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("inspect workspace file: %w", err)
		}
		size := workspaceEntryOverheadBytes
		mode := info.Mode()
		switch {
		case mode&os.ModeSymlink != 0:
			return fmt.Errorf(
				"%w: workspace contains a symbolic link",
				ErrInvalidReport,
			)
		case mode.IsDir():
			if allocated, ok := workspaceAllocatedBytes(info); ok &&
				allocated > size {
				size = allocated
			}
		case mode.IsRegular():
			contentSize := info.Size()
			if allocated, ok := workspaceAllocatedBytes(info); ok &&
				allocated > contentSize {
				contentSize = allocated
			}
			if contentSize < 0 || contentSize > maximum-size {
				return fmt.Errorf(
					"%w: workspace exceeded %d bytes",
					ErrOutputLimit,
					maximum,
				)
			}
			size += contentSize
		default:
			return fmt.Errorf(
				"%w: workspace contains a special file",
				ErrInvalidReport,
			)
		}
		if total > maximum-size {
			return fmt.Errorf(
				"%w: workspace exceeded %d bytes",
				ErrOutputLimit,
				maximum,
			)
		}
		total += size
		return nil
	})
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}
		if errors.Is(err, ErrOutputLimit) ||
			errors.Is(err, ErrInvalidReport) {
			return err
		}
		return fmt.Errorf("%w: inspect workspace usage: %v", ErrInvalidReport, err)
	}
	return nil
}

func workspaceAllocatedBytes(info fs.FileInfo) (int64, bool) {
	value, ok := info.Sys().(*syscall.Stat_t)
	if !ok || value.Blocks < 0 ||
		value.Blocks > math.MaxInt64/512 {
		return 0, false
	}
	return value.Blocks * 512, true
}

func completedCommand(
	command *exec.Cmd,
	waitErr error,
	stdout *boundedCapture,
	stderr *boundedCapture,
) (commandResult, error) {
	if stdout.Exceeded() {
		return commandResult{}, fmt.Errorf("%w: stdout exceeded limit", ErrOutputLimit)
	}
	if stderr.Exceeded() {
		return commandResult{}, fmt.Errorf("%w: stderr exceeded limit", ErrOutputLimit)
	}
	exitCode := 0
	if waitErr != nil {
		var exitError *exec.ExitError
		if !errors.As(waitErr, &exitError) {
			return commandResult{}, fmt.Errorf("%w: wait for process: %v", ErrExecutionFailed, waitErr)
		}
		exitCode = exitError.ExitCode()
	} else if command.ProcessState != nil {
		exitCode = command.ProcessState.ExitCode()
	}
	return commandResult{
		ExitCode: exitCode,
		Stdout:   stdout.String(),
		Stderr:   stderr.String(),
	}, nil
}

func terminateProcessGroup(
	command *exec.Cmd,
	done <-chan error,
	gracePeriod time.Duration,
) error {
	if command.Process == nil {
		return nil
	}
	_ = syscall.Kill(-command.Process.Pid, syscall.SIGTERM)
	timer := time.NewTimer(gracePeriod)
	defer timer.Stop()
	select {
	case err := <-done:
		return err
	case <-timer.C:
	}
	_ = syscall.Kill(-command.Process.Pid, syscall.SIGKILL)
	return <-done
}

func checkGrowingReport(path string, maximum int64) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("%w: inspect raw report: %v", ErrInvalidReport, err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return fmt.Errorf("%w: raw report is not a regular file", ErrInvalidReport)
	}
	if info.Size() > maximum {
		return fmt.Errorf(
			"%w: raw report exceeded %d bytes",
			ErrOutputLimit,
			maximum,
		)
	}
	return nil
}

func captureLimit(name string, specification commandSpec) int64 {
	if name == "stderr" {
		return specification.MaxStandardErrorBytes
	}
	return specification.MaxStandardOutputBytes
}

type boundedCapture struct {
	mu       sync.Mutex
	name     string
	maximum  int64
	buffer   bytes.Buffer
	exceeded bool
	once     sync.Once
	notify   chan<- streamOverflow
}

func newBoundedCapture(
	name string,
	maximum int64,
	notify chan<- streamOverflow,
) *boundedCapture {
	return &boundedCapture{name: name, maximum: maximum, notify: notify}
}

func (b *boundedCapture) Write(value []byte) (int, error) {
	b.mu.Lock()
	remaining := b.maximum - int64(b.buffer.Len())
	if remaining < 0 {
		remaining = 0
	}
	toWrite := int64(len(value))
	if toWrite > remaining {
		toWrite = remaining
		b.exceeded = true
	}
	if toWrite > 0 {
		_, _ = b.buffer.Write(value[:toWrite])
	}
	exceeded := b.exceeded
	b.mu.Unlock()
	if exceeded {
		b.once.Do(func() {
			b.notify <- streamOverflow{name: b.name}
		})
	}
	// Report the full write so os/exec cannot turn the bounded diagnostic into
	// an unclassified short-write error while the supervisor terminates it.
	return len(value), nil
}

func (b *boundedCapture) Exceeded() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.exceeded
}

func (b *boundedCapture) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buffer.String()
}

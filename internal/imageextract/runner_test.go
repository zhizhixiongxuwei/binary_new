package imageextract

import (
	"bytes"
	"context"
	"errors"
	"io"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestRunnerRoutesAllowlistedToolsAndPreservesArgumentArray(t *testing.T) {
	arguments := []string{
		"-r", "name with spaces", "; echo not-a-shell", "$HOME", "*.img",
	}
	wantArguments := append([]string(nil), arguments...)
	backend := &toolBackendStub{
		mmls: func(
			_ context.Context,
			got []string,
			stdout io.Writer,
			_ io.Writer,
		) (int, error) {
			if !reflect.DeepEqual(got, wantArguments) {
				t.Fatalf("RunMMLS() arguments = %#v, want %#v", got, wantArguments)
			}
			got[0] = "backend mutation"
			_, err := stdout.Write([]byte("mmls"))
			return 7, err
		},
		fls: func(
			_ context.Context,
			got []string,
			_ io.Writer,
			stderr io.Writer,
		) (int, error) {
			if !reflect.DeepEqual(got, []string{"--", "disk image.raw"}) {
				t.Fatalf("RunFLS() arguments = %#v", got)
			}
			_, err := stderr.Write([]byte("fls"))
			return 3, err
		},
	}
	runner := newTestToolRunner(t, backend, RunnerLimits{})

	mmlsOutput, err := runner.Run(context.Background(), ToolInvocation{
		Tool: ToolMMLS, Arguments: arguments,
	})
	if err != nil {
		t.Fatalf("Run(mmls) error = %v", err)
	}
	if string(mmlsOutput.Stdout) != "mmls" || mmlsOutput.ExitCode != 7 {
		t.Fatalf("Run(mmls) output = %#v", mmlsOutput)
	}
	if !reflect.DeepEqual(arguments, wantArguments) {
		t.Fatalf("caller arguments were modified: %#v", arguments)
	}

	flsOutput, err := runner.Run(context.Background(), ToolInvocation{
		Tool: ToolFLS, Arguments: []string{"--", "disk image.raw"},
	})
	if err != nil {
		t.Fatalf("Run(fls) error = %v", err)
	}
	if string(flsOutput.Stderr) != "fls" || flsOutput.ExitCode != 3 {
		t.Fatalf("Run(fls) output = %#v", flsOutput)
	}
	if backend.mmlsCalls.Load() != 1 || backend.flsCalls.Load() != 1 {
		t.Fatalf(
			"backend calls = mmls:%d fls:%d",
			backend.mmlsCalls.Load(), backend.flsCalls.Load(),
		)
	}
}

func TestRunnerRejectsUnknownToolAndInvalidArgumentsBeforeDispatch(t *testing.T) {
	backend := &toolBackendStub{}
	runner := newTestToolRunner(t, backend, RunnerLimits{
		MaxOutputBytes:        10,
		MaxArguments:          2,
		MaxArgumentBytes:      4,
		MaxTotalArgumentBytes: 5,
	})

	_, err := runner.Run(context.Background(), ToolInvocation{
		Tool: Tool("/usr/bin/arbitrary"), Arguments: []string{"ok"},
	})
	if !errors.Is(err, ErrToolNotAllowed) {
		t.Fatalf("unknown tool error = %v", err)
	}

	tests := []struct {
		name        string
		arguments   []string
		outputLimit int64
	}{
		{name: "empty", arguments: []string{""}},
		{name: "nul", arguments: []string{"a\x00b"}},
		{name: "control", arguments: []string{"a\nb"}},
		{name: "invalid utf8", arguments: []string{string([]byte{0xff})}},
		{name: "argument bytes", arguments: []string{"12345"}},
		{name: "argument count", arguments: []string{"a", "b", "c"}},
		{name: "total bytes", arguments: []string{"abc", "def"}},
		{name: "negative output", arguments: []string{"ok"}, outputLimit: -1},
		{name: "output ceiling", arguments: []string{"ok"}, outputLimit: 11},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := runner.Run(context.Background(), ToolInvocation{
				Tool: ToolMMLS, Arguments: test.arguments,
				MaxOutputBytes: test.outputLimit,
			})
			if !errors.Is(err, ErrInvalidRun) {
				t.Fatalf("Run() error = %v, want ErrInvalidRun", err)
			}
		})
	}
	if backend.mmlsCalls.Load() != 0 || backend.flsCalls.Load() != 0 {
		t.Fatalf("invalid invocations reached backend")
	}
}

func TestNewRunnerRejectsTypedNilBackend(t *testing.T) {
	var backend *toolBackendStub
	if _, err := NewRunner(backend, RunnerLimits{}); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("NewRunner() error = %v, want ErrInvalidRequest", err)
	}
}

func TestRunnerUsesOneExactLimitAcrossStdoutAndStderr(t *testing.T) {
	t.Run("exact", func(t *testing.T) {
		backend := &toolBackendStub{mmls: func(
			_ context.Context,
			_ []string,
			stdout io.Writer,
			stderr io.Writer,
		) (int, error) {
			if _, err := stdout.Write([]byte("abc")); err != nil {
				return 0, err
			}
			_, err := stderr.Write([]byte("de"))
			return 0, err
		}}
		runner := newTestToolRunner(t, backend, RunnerLimits{MaxOutputBytes: 5})
		output, err := runner.Run(context.Background(), ToolInvocation{
			Tool: ToolMMLS, Arguments: []string{"image"}, MaxOutputBytes: 5,
		})
		if err != nil {
			t.Fatalf("Run() error = %v", err)
		}
		if string(output.Stdout) != "abc" || string(output.Stderr) != "de" {
			t.Fatalf("Run() output = %#v", output)
		}
	})

	t.Run("plus one", func(t *testing.T) {
		backend := &toolBackendStub{mmls: func(
			_ context.Context,
			_ []string,
			stdout io.Writer,
			stderr io.Writer,
		) (int, error) {
			if _, err := stdout.Write([]byte("abc")); err != nil {
				return 0, err
			}
			_, err := stderr.Write([]byte("def"))
			return 9, err
		}}
		runner := newTestToolRunner(t, backend, RunnerLimits{MaxOutputBytes: 5})
		output, err := runner.Run(context.Background(), ToolInvocation{
			Tool: ToolMMLS, Arguments: []string{"image"}, MaxOutputBytes: 5,
		})
		if !errors.Is(err, ErrRunnerOutput) {
			t.Fatalf("Run() error = %v, want ErrRunnerOutput", err)
		}
		if len(output.Stdout)+len(output.Stderr) != 5 ||
			string(output.Stdout) != "abc" || string(output.Stderr) != "de" ||
			output.ExitCode != 9 {
			t.Fatalf("Run() bounded output = %#v", output)
		}
	})
}

func TestRunnerPropagatesCancellation(t *testing.T) {
	started := make(chan struct{})
	backend := &toolBackendStub{fls: func(
		ctx context.Context,
		_ []string,
		_ io.Writer,
		_ io.Writer,
	) (int, error) {
		close(started)
		<-ctx.Done()
		return 0, ctx.Err()
	}}
	runner := newTestToolRunner(t, backend, RunnerLimits{})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := runner.Run(ctx, ToolInvocation{
			Tool: ToolFLS, Arguments: []string{"image"},
		})
		done <- err
	}()

	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("backend did not start")
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Run() error = %v, want context.Canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Run() did not stop after cancellation")
	}
}

func TestRunnerRejectsNegativeExitCodeAndRetainsBoundedOutput(t *testing.T) {
	backend := &toolBackendStub{mmls: func(
		_ context.Context,
		_ []string,
		stdout io.Writer,
		_ io.Writer,
	) (int, error) {
		_, err := stdout.Write([]byte("diagnostic"))
		return -9, err
	}}
	runner := newTestToolRunner(t, backend, RunnerLimits{})
	output, err := runner.Run(context.Background(), ToolInvocation{
		Tool: ToolMMLS, Arguments: []string{"image"},
	})
	if !errors.Is(err, ErrInvalidRun) {
		t.Fatalf("Run() error = %v, want ErrInvalidRun", err)
	}
	if output.ExitCode != -9 || string(output.Stdout) != "diagnostic" {
		t.Fatalf("Run() output = %#v", output)
	}
}

func TestToolOutputCollectorReturnsDeepCopies(t *testing.T) {
	collector := newToolOutputCollector(32, func() {})
	stdout := streamWriter{collector: collector}
	stderr := streamWriter{collector: collector, stderr: true}
	if _, err := stdout.Write([]byte("stdout")); err != nil {
		t.Fatalf("write stdout: %v", err)
	}
	if _, err := stderr.Write([]byte("stderr")); err != nil {
		t.Fatalf("write stderr: %v", err)
	}

	first, exceeded := collector.result(0)
	if exceeded {
		t.Fatal("collector unexpectedly exceeded its limit")
	}
	first.Stdout[0] = 'X'
	first.Stderr[0] = 'Y'
	second, exceeded := collector.result(0)
	if exceeded || string(second.Stdout) != "stdout" || string(second.Stderr) != "stderr" {
		t.Fatalf("collector result aliases internal buffers: %#v", second)
	}
}

func TestRunnerCollectsConcurrentStdoutAndStderr(t *testing.T) {
	const (
		chunks    = 128
		chunkSize = 64
	)
	stdoutChunk := bytes.Repeat([]byte{'o'}, chunkSize)
	stderrChunk := bytes.Repeat([]byte{'e'}, chunkSize)
	backend := &toolBackendStub{mmls: func(
		_ context.Context,
		_ []string,
		stdout io.Writer,
		stderr io.Writer,
	) (int, error) {
		var wait sync.WaitGroup
		errorsFound := make(chan error, 2)
		write := func(destination io.Writer, payload []byte) {
			defer wait.Done()
			for range chunks {
				if _, err := destination.Write(payload); err != nil {
					errorsFound <- err
					return
				}
			}
		}
		wait.Add(2)
		go write(stdout, stdoutChunk)
		go write(stderr, stderrChunk)
		wait.Wait()
		close(errorsFound)
		for err := range errorsFound {
			return 0, err
		}
		return 0, nil
	}}
	limit := int64(2 * chunks * chunkSize)
	runner := newTestToolRunner(t, backend, RunnerLimits{MaxOutputBytes: limit})
	output, err := runner.Run(context.Background(), ToolInvocation{
		Tool: ToolMMLS, Arguments: []string{"image"}, MaxOutputBytes: limit,
	})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if len(output.Stdout) != chunks*chunkSize ||
		len(output.Stderr) != chunks*chunkSize ||
		!bytes.Equal(output.Stdout, bytes.Repeat(stdoutChunk, chunks)) ||
		!bytes.Equal(output.Stderr, bytes.Repeat(stderrChunk, chunks)) {
		t.Fatalf(
			"concurrent output sizes = stdout:%d stderr:%d",
			len(output.Stdout), len(output.Stderr),
		)
	}
}

type toolBackendStub struct {
	mmls func(context.Context, []string, io.Writer, io.Writer) (int, error)
	fls  func(context.Context, []string, io.Writer, io.Writer) (int, error)

	mmlsCalls atomic.Int32
	flsCalls  atomic.Int32
}

func (backend *toolBackendStub) RunMMLS(
	ctx context.Context,
	arguments []string,
	stdout io.Writer,
	stderr io.Writer,
) (int, error) {
	backend.mmlsCalls.Add(1)
	if backend.mmls == nil {
		return 0, nil
	}
	return backend.mmls(ctx, arguments, stdout, stderr)
}

func (backend *toolBackendStub) RunFLS(
	ctx context.Context,
	arguments []string,
	stdout io.Writer,
	stderr io.Writer,
) (int, error) {
	backend.flsCalls.Add(1)
	if backend.fls == nil {
		return 0, nil
	}
	return backend.fls(ctx, arguments, stdout, stderr)
}

func newTestToolRunner(
	t *testing.T,
	backend ToolBackend,
	limits RunnerLimits,
) Runner {
	t.Helper()
	runner, err := NewRunner(backend, limits)
	if err != nil {
		t.Fatalf("NewRunner() error = %v", err)
	}
	return runner
}

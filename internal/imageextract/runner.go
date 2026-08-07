package imageextract

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"reflect"
	"strings"
	"sync"
	"unicode"
	"unicode/utf8"
)

const (
	DefaultMaxToolOutputBytes        = int64(8 << 20)
	DefaultMaxToolArguments          = 64
	DefaultMaxToolArgumentBytes      = 4096
	DefaultMaxToolTotalArgumentBytes = 32 << 10
)

// Tool is a closed list of reviewed, read-only image inspection capabilities.
// It is deliberately not an executable path.
type Tool string

const (
	ToolMMLS Tool = "mmls"
	ToolFLS  Tool = "fls"
)

// ToolInvocation preserves arguments as an array. MaxOutputBytes can lower,
// but never raise, the Runner-wide output ceiling.
type ToolInvocation struct {
	Tool           Tool
	Arguments      []string
	MaxOutputBytes int64
}

// ToolOutput contains bounded copies of both output streams. ExitCode is the
// backend-reported process exit status and is never inferred from output text.
type ToolOutput struct {
	Stdout   []byte
	Stderr   []byte
	ExitCode int
}

// Runner dispatches only allowlisted tools. Implementations returned by
// NewRunner never evaluate a command string or accept an executable or env.
type Runner interface {
	Run(context.Context, ToolInvocation) (ToolOutput, error)
}

// ToolBackend is the narrow process boundary used by a reviewed platform
// adapter. Its two methods must execute the named binary directly with the
// supplied argument array, without a shell. The writers enforce a combined
// memory ceiling even if the backend emits both streams concurrently.
type ToolBackend interface {
	RunMMLS(
		context.Context,
		[]string,
		io.Writer,
		io.Writer,
	) (exitCode int, err error)
	RunFLS(
		context.Context,
		[]string,
		io.Writer,
		io.Writer,
	) (exitCode int, err error)
}

type RunnerLimits struct {
	MaxOutputBytes        int64
	MaxArguments          int
	MaxArgumentBytes      int
	MaxTotalArgumentBytes int
}

type controlledRunner struct {
	backend ToolBackend
	limits  RunnerLimits
}

// NewRunner creates an in-memory output guard and fixed dispatch table. It
// does not discover tools, inspect PATH, spawn a process, or create a shell.
func NewRunner(backend ToolBackend, limits RunnerLimits) (Runner, error) {
	if backend == nil || nilBackend(backend) {
		return nil, invalidRequest("tool backend is required")
	}
	limits = normalizedRunnerLimits(limits)
	return &controlledRunner{backend: backend, limits: limits}, nil
}

func nilBackend(backend ToolBackend) bool {
	value := reflect.ValueOf(backend)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map,
		reflect.Pointer, reflect.Slice:
		return value.IsNil()
	default:
		return false
	}
}

func normalizedRunnerLimits(limits RunnerLimits) RunnerLimits {
	limits.MaxOutputBytes = boundedInt64(
		limits.MaxOutputBytes,
		DefaultMaxToolOutputBytes,
	)
	limits.MaxArguments = boundedInt(
		limits.MaxArguments,
		DefaultMaxToolArguments,
	)
	limits.MaxArgumentBytes = boundedInt(
		limits.MaxArgumentBytes,
		DefaultMaxToolArgumentBytes,
	)
	limits.MaxTotalArgumentBytes = boundedInt(
		limits.MaxTotalArgumentBytes,
		DefaultMaxToolTotalArgumentBytes,
	)
	return limits
}

func (runner *controlledRunner) Run(
	ctx context.Context,
	invocation ToolInvocation,
) (ToolOutput, error) {
	if runner == nil || runner.backend == nil {
		return ToolOutput{}, fmt.Errorf("%w: runner is nil", ErrInvalidRun)
	}
	if ctx == nil {
		return ToolOutput{}, fmt.Errorf("%w: context is nil", ErrInvalidRun)
	}
	if err := ctx.Err(); err != nil {
		return ToolOutput{}, err
	}
	if invocation.Tool != ToolMMLS && invocation.Tool != ToolFLS {
		return ToolOutput{}, fmt.Errorf(
			"%w: %s", ErrToolNotAllowed, invocation.Tool,
		)
	}
	arguments, err := runner.validateArguments(invocation.Arguments)
	if err != nil {
		return ToolOutput{}, err
	}
	outputLimit := invocation.MaxOutputBytes
	if outputLimit < 0 {
		return ToolOutput{}, fmt.Errorf(
			"%w: output limit is negative", ErrInvalidRun,
		)
	}
	if outputLimit == 0 {
		outputLimit = runner.limits.MaxOutputBytes
	}
	if outputLimit > runner.limits.MaxOutputBytes {
		return ToolOutput{}, fmt.Errorf(
			"%w: output limit exceeds runner ceiling", ErrInvalidRun,
		)
	}

	operationCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	collector := newToolOutputCollector(outputLimit, cancel)
	stdout := streamWriter{collector: collector, stderr: false}
	stderr := streamWriter{collector: collector, stderr: true}
	var exitCode int
	switch invocation.Tool {
	case ToolMMLS:
		exitCode, err = runner.backend.RunMMLS(
			operationCtx, arguments, stdout, stderr,
		)
	case ToolFLS:
		exitCode, err = runner.backend.RunFLS(
			operationCtx, arguments, stdout, stderr,
		)
	}
	output, exceeded := collector.result(exitCode)
	if exceeded {
		return output, fmt.Errorf(
			"%w: maximum is %d bytes", ErrRunnerOutput, outputLimit,
		)
	}
	if exitCode < 0 {
		return output, fmt.Errorf("%w: negative exit code", ErrInvalidRun)
	}
	if contextErr := ctx.Err(); contextErr != nil {
		return output, contextErr
	}
	return output, err
}

func (runner *controlledRunner) validateArguments(
	arguments []string,
) ([]string, error) {
	if len(arguments) > runner.limits.MaxArguments {
		return nil, fmt.Errorf("%w: too many arguments", ErrInvalidRun)
	}
	total := 0
	cloned := make([]string, len(arguments))
	for index, argument := range arguments {
		if argument == "" || len(argument) > runner.limits.MaxArgumentBytes ||
			!utf8.ValidString(argument) || strings.IndexByte(argument, 0) >= 0 {
			return nil, fmt.Errorf("%w: argument is invalid", ErrInvalidRun)
		}
		for _, character := range argument {
			if unicode.IsControl(character) {
				return nil, fmt.Errorf(
					"%w: argument contains a control character", ErrInvalidRun,
				)
			}
		}
		total += len(argument)
		if total > runner.limits.MaxTotalArgumentBytes {
			return nil, fmt.Errorf(
				"%w: arguments exceed byte limit", ErrInvalidRun,
			)
		}
		cloned[index] = argument
	}
	return cloned, nil
}

type toolOutputCollector struct {
	mu        sync.Mutex
	remaining int64
	stdout    bytes.Buffer
	stderr    bytes.Buffer
	exceeded  bool
	cancel    context.CancelFunc
}

func newToolOutputCollector(
	limit int64,
	cancel context.CancelFunc,
) *toolOutputCollector {
	return &toolOutputCollector{remaining: limit, cancel: cancel}
}

type streamWriter struct {
	collector *toolOutputCollector
	stderr    bool
}

func (writer streamWriter) Write(payload []byte) (int, error) {
	return writer.collector.write(payload, writer.stderr)
}

func (collector *toolOutputCollector) write(
	payload []byte,
	stderr bool,
) (int, error) {
	collector.mu.Lock()
	defer collector.mu.Unlock()
	if len(payload) == 0 {
		return 0, nil
	}
	if collector.exceeded || collector.remaining == 0 {
		collector.exceeded = true
		collector.cancel()
		return 0, ErrRunnerOutput
	}
	writable := int64(len(payload))
	if writable > collector.remaining {
		writable = collector.remaining
		collector.exceeded = true
	}
	var count int
	if stderr {
		count, _ = collector.stderr.Write(payload[:int(writable)])
	} else {
		count, _ = collector.stdout.Write(payload[:int(writable)])
	}
	collector.remaining -= int64(count)
	if collector.exceeded {
		collector.cancel()
		return count, ErrRunnerOutput
	}
	return count, nil
}

func (collector *toolOutputCollector) result(
	exitCode int,
) (ToolOutput, bool) {
	collector.mu.Lock()
	defer collector.mu.Unlock()
	return ToolOutput{
		Stdout:   append([]byte(nil), collector.stdout.Bytes()...),
		Stderr:   append([]byte(nil), collector.stderr.Bytes()...),
		ExitCode: exitCode,
	}, collector.exceeded
}

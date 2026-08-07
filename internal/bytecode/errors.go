package bytecode

import "errors"

var (
	ErrInvalidConfiguration = errors.New("bytecode: invalid configuration")
	ErrInvalidRequest       = errors.New("bytecode: invalid request")
	ErrInvalidResult        = errors.New("bytecode: invalid result")
	ErrProcessStart         = errors.New("bytecode: process start failed")
	ErrProcessWait          = errors.New("bytecode: process wait failed")
	ErrTimedOut             = errors.New("bytecode: process timed out")
	ErrStdoutLimit          = errors.New("bytecode: stdout limit exceeded")
	ErrStderrLimit          = errors.New("bytecode: stderr limit exceeded")
	ErrOutputLimit          = errors.New("bytecode: output byte limit exceeded")
	ErrFileCountLimit       = errors.New("bytecode: output file count limit exceeded")
	ErrUnsafeOutput         = errors.New("bytecode: unsafe output")
)

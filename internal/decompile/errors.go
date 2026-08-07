package decompile

import "errors"

var (
	ErrInvalidInput        = errors.New("invalid decompile input")
	ErrTaskNotFound        = errors.New("decompile task not found")
	ErrFileNodeNotFound    = errors.New("decompile file node not found")
	ErrUnsupportedTarget   = errors.New("unsupported decompile target")
	ErrSourceUnavailable   = errors.New("decompile source unavailable")
	ErrTaskStateConflict   = errors.New("task state does not permit decompilation")
	ErrRequestConflict     = errors.New("decompile request conflicts with stored state")
	ErrDecompileInProgress = errors.New("decompile request is already active")
	ErrSampleUnavailable   = errors.New("decompile sample is deleted or expired")
	ErrRequestNotFound     = errors.New("decompile request not found")
	ErrResultNotFound      = errors.New("decompile result not found")
	ErrExportTooLarge      = errors.New("decompile source export is too large")
)

package javaanalysis

import "errors"

var (
	ErrInvalidInput          = errors.New("invalid Java analysis input")
	ErrTaskNotFound          = errors.New("Java analysis task not found")
	ErrProjectNotFound       = errors.New("Java analysis source project not found")
	ErrRunNotFound           = errors.New("Java analysis run not found")
	ErrSourceUnavailable     = errors.New("Java analysis source unavailable")
	ErrAlreadyActive         = errors.New("Java analysis is already active for this project")
	ErrIdempotencyConflict   = errors.New("Java analysis idempotency key conflict")
	ErrNotReady              = errors.New("Java analysis checker is not ready")
	ErrRunNotCancellable     = errors.New("Java analysis run is not cancellable")
	ErrRunNotDeletable       = errors.New("Java analysis run is not deletable")
	ErrLeaseLost             = errors.New("Java analysis worker lease lost")
	ErrAlreadyPublished      = errors.New("Java analysis result already published")
	ErrFailedResultPublished = errors.New("Java analysis failed result already published")
	ErrAlreadyTerminal       = errors.New("Java analysis run is already terminal")
)

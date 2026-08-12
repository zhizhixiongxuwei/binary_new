package canalysis

import "errors"

var (
	ErrInvalidInput          = errors.New("invalid C analysis input")
	ErrTaskNotFound          = errors.New("C analysis task not found")
	ErrProjectNotFound       = errors.New("C analysis source project not found")
	ErrRunNotFound           = errors.New("C analysis run not found")
	ErrSourceUnavailable     = errors.New("C analysis source unavailable")
	ErrAlreadyActive         = errors.New("C analysis is already active for this project")
	ErrIdempotencyConflict   = errors.New("C analysis idempotency key conflict")
	ErrNotReady              = errors.New("C analysis checker is not ready")
	ErrRunNotCancellable     = errors.New("C analysis run is not cancellable")
	ErrRunNotDeletable       = errors.New("C analysis run is not deletable")
	ErrLeaseLost             = errors.New("C analysis worker lease lost")
	ErrAlreadyPublished      = errors.New("C analysis result already published")
	ErrFailedResultPublished = errors.New("C analysis failed result already published")
	ErrAlreadyTerminal       = errors.New("C analysis run is already terminal")
)

package archiveimport

import "errors"

var (
	ErrInvalidInput        = errors.New("archive import input is invalid")
	ErrNotFound            = errors.New("archive import was not found")
	ErrForbidden           = errors.New("archive import access is forbidden")
	ErrConflict            = errors.New("archive import state conflict")
	ErrLeaseLost           = errors.New("archive import lease was lost")
	ErrIdempotencyConflict = errors.New("archive import idempotency conflict")
	ErrSourceUnavailable   = errors.New("archive import source is unavailable")
)

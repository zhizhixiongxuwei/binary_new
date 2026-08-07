package upload

import "errors"

var (
	ErrInvalidInput        = errors.New("invalid upload input")
	ErrNotFound            = errors.New("upload not found")
	ErrForbidden           = errors.New("upload access is forbidden")
	ErrConflict            = errors.New("upload part conflicts with existing content")
	ErrIdempotencyConflict = errors.New("upload idempotency key was reused")
	ErrIncomplete          = errors.New("upload is incomplete")
	ErrExpired             = errors.New("upload has expired")
	ErrInvalidState        = errors.New("upload state does not allow this operation")
	ErrHashMismatch        = errors.New("chunk SHA-256 does not match")
	ErrRangeMismatch       = errors.New("chunk range does not match upload layout")
	ErrTooLarge            = errors.New("upload or chunk exceeds configured limit")
)

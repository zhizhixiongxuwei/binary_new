package upload

import (
	"errors"
	"fmt"

	"binaryscan/internal/inputcategory"
)

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
	ErrCategoryMismatch    = errors.New("detected input category does not match the selected category")
	ErrUnsupportedFormat   = errors.New("detected input format is not supported for task creation")
)

type CompletionValidationError struct {
	UploadID         string
	InputCategory    inputcategory.Category
	DetectedCategory inputcategory.Category
	DetectedFormat   string
	Status           string
}

func (e *CompletionValidationError) Error() string {
	return fmt.Sprintf("upload %s validation %s for format %s", e.UploadID, e.Status, e.DetectedFormat)
}

func (e *CompletionValidationError) Unwrap() error {
	if e.Status == ValidationMismatch {
		return ErrCategoryMismatch
	}
	return ErrUnsupportedFormat
}

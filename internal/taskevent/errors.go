package taskevent

import "errors"

var (
	ErrInvalidInput = errors.New("invalid task event input")
	ErrNotFound     = errors.New("task event stream not found")
)

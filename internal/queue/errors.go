package queue

import "errors"

var (
	ErrInvalidInput          = errors.New("queue input is invalid")
	ErrLeaseLost             = errors.New("job lease was lost")
	ErrInconsistentState     = errors.New("queue state is inconsistent")
	ErrResourceLimitMismatch = errors.New(
		"queue resource limits differ from the active database limits",
	)
)

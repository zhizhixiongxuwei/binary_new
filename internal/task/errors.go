package task

import "errors"

var (
	ErrInvalidInput       = errors.New("invalid task input")
	ErrNotFound           = errors.New("task or upload not found")
	ErrForbidden          = errors.New("task operation is forbidden")
	ErrConflict           = errors.New("task operation conflicts with the stored state")
	ErrInvalidState       = errors.New("task state does not permit the operation")
	ErrSampleUnavailable  = errors.New("task sample is deleted or expired")
	ErrUploadNotCompleted = errors.New("upload is not completed")
	ErrUploadNotEligible  = errors.New("upload intake validation does not permit task creation")
)

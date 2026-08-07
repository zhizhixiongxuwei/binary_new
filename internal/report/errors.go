package report

import "errors"

var (
	ErrInvalidInput         = errors.New("invalid report input")
	ErrTaskNotFound         = errors.New("report task not found")
	ErrReportNotFound       = errors.New("report not found")
	ErrTaskNotTerminal      = errors.New("task is not in a reportable terminal state")
	ErrGenerationInProgress = errors.New("report generation is already in progress")
	ErrReportConflict       = errors.New("report cannot be generated in its current state")
	ErrArtifactUnavailable  = errors.New("report artifact is unavailable")
)

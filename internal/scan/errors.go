package scan

import "errors"

var (
	ErrSampleMissing   = errors.New("scan sample is missing")
	ErrUnsafeSample    = errors.New("scan sample path is unsafe")
	ErrSampleMismatch  = errors.New("scan sample does not match database metadata")
	ErrInvalidLimits   = errors.New("scan task limits are invalid")
	ErrInvalidTree     = errors.New("scan extraction tree is invalid")
	ErrInvalidTrivyJob = errors.New("scan Trivy job handoff is invalid")
)

package manualimagescan

import "errors"

var (
	ErrInvalidInput          = errors.New("invalid manual image scan input")
	ErrTaskNotFound          = errors.New("manual image scan task not found")
	ErrFileNodeNotFound      = errors.New("manual image scan file node not found")
	ErrManualScanNotRequired = errors.New("file node is not eligible for manual image scan")
	ErrSourceUnavailable     = errors.New("manual image scan source unavailable")
	ErrTaskStateConflict     = errors.New("task state does not permit manual image scan")
	ErrSampleUnavailable     = errors.New("manual image scan sample is deleted or expired")
	ErrImageScanInProgress   = errors.New("manual image scan is already active")
	ErrRequestConflict       = errors.New("manual image scan request conflicts with stored state")
)

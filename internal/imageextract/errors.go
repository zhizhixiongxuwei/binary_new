package imageextract

import (
	"errors"
	"fmt"
)

var (
	ErrInvalidRequest  = errors.New("imageextract: invalid request")
	ErrUnsupported     = errors.New("imageextract: unsupported format")
	ErrDuplicateFormat = errors.New("imageextract: format already registered")
	ErrInvalidResult   = errors.New("imageextract: extractor emitted an invalid result")
	ErrCorruptImage    = errors.New("imageextract: corrupt image")
	ErrExtractorPanic  = errors.New("imageextract: extractor panicked")
	ErrToolNotAllowed  = errors.New("imageextract: external tool is not allowed")
	ErrInvalidRun      = errors.New("imageextract: external tool request is invalid")
	ErrRunnerOutput    = errors.New("imageextract: external tool output exceeded its limit")
)

// LimitError tells an Extractor to stop after a shared Engine limit is
// reached. Engine converts it into Result.Partial and Result.LimitCode.
type LimitError struct {
	Code LimitCode
}

func (err *LimitError) Error() string {
	if err == nil {
		return "imageextract: limit reached"
	}
	return "imageextract: limit reached: " + string(err.Code)
}

func invalidRequest(message string) error {
	return fmt.Errorf("%w: %s", ErrInvalidRequest, message)
}

func invalidResult(message string) error {
	return fmt.Errorf("%w: %s", ErrInvalidResult, message)
}

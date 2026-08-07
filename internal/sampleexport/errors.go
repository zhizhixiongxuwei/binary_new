package sampleexport

import "errors"

var (
	ErrInvalidInput = errors.New("invalid sample export input")
	ErrNotFound     = errors.New("sample export task not found")
	ErrUnavailable  = errors.New("sample export is unavailable")
	ErrIntegrity    = errors.New("sample export integrity check failed")
)

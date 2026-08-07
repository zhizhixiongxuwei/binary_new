package filetree

import "errors"

var (
	ErrInvalidInput = errors.New("invalid file tree input")
	ErrNotFound     = errors.New("task or file node not found")
	ErrTaskNotFound = errors.New("file tree task not found")
	ErrNodeNotFound = errors.New("file tree node not found")
)

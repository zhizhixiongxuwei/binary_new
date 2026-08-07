package taskevent

import (
	"encoding/json"
	"time"
)

const (
	DefaultBatchSize = 100
	MaxBatchSize     = 100
)

type Query struct {
	TaskID        string
	AfterSequence uint64
	Limit         int
}

type Event struct {
	Sequence              uint64          `json:"sequence"`
	Type                  string          `json:"type"`
	Stage                 *string         `json:"stage"`
	Progress              *float64        `json:"progress"`
	ProgressIndeterminate bool            `json:"progress_indeterminate"`
	Severity              string          `json:"severity"`
	Message               *string         `json:"message"`
	Payload               json.RawMessage `json:"payload"`
	CreatedAt             time.Time       `json:"created_at"`
}

// Activity is a bounded, user-visible analyzer milestone. Callers must keep
// Payload free of source text, host paths, credentials, and raw tool output.
type Activity struct {
	EventType string
	Severity  string
	Message   string
	Payload   json.RawMessage
}

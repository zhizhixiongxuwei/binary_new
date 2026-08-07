package audit

import (
	"encoding/json"
	"time"
)

type Outcome string

const (
	OutcomeSuccess Outcome = "success"
	OutcomeFailure Outcome = "failure"
	OutcomeDenied  Outcome = "denied"
)

func (o Outcome) Valid() bool {
	return o == OutcomeSuccess || o == OutcomeFailure || o == OutcomeDenied
}

// Event is the append-only write contract. ClientIP and UserAgent are retained
// for incident response, but are deliberately absent from the read DTO.
type Event struct {
	ActorUserID *uint64
	RequestID   string
	Action      string
	ObjectType  string
	ObjectID    string
	Outcome     Outcome
	ClientIP    []byte
	UserAgent   string
	Metadata    map[string]any
}

type Actor struct {
	ID          string `json:"id"`
	Username    string `json:"username"`
	DisplayName string `json:"display_name"`
}

type Log struct {
	ID         string          `json:"id"`
	Actor      *Actor          `json:"actor"`
	RequestID  string          `json:"request_id"`
	Action     string          `json:"action"`
	ObjectType string          `json:"object_type"`
	ObjectID   *string         `json:"object_id"`
	Outcome    Outcome         `json:"outcome"`
	Metadata   json.RawMessage `json:"metadata"`
	CreatedAt  time.Time       `json:"created_at"`
}

type ListQuery struct {
	Cursor      string
	PageSize    int
	Action      string
	Outcome     string
	Actor       string
	CreatedFrom string
	CreatedTo   string
}

type RepositoryListQuery struct {
	Cursor      uint64
	PageSize    int
	Action      string
	Outcome     Outcome
	Actor       string
	CreatedFrom *time.Time
	CreatedTo   *time.Time
}

type Page struct {
	Items      []Log  `json:"items"`
	NextCursor string `json:"next_cursor,omitempty"`
}

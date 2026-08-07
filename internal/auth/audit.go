package auth

import (
	"context"
)

type LoginAuditEvent struct {
	ActorUserID *uint64
	RequestID   string
	Outcome     string
	ClientIP    []byte
	UserAgent   string
	Metadata    map[string]any
}

// LoginAuditRecorder is optional so authentication remains usable during
// staged upgrades. Recording is best effort: an audit storage failure never
// changes a credential decision or leaves a successfully-created session
// undisclosed to the client.
type LoginAuditRecorder interface {
	RecordLogin(context.Context, LoginAuditEvent) error
}

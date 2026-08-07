package audit

import (
	"context"

	"binaryscan/internal/auth"
)

type LoginRecorder struct {
	Recorder Recorder
}

func (r LoginRecorder) RecordLogin(ctx context.Context, value auth.LoginAuditEvent) error {
	if r.Recorder == nil {
		return ErrInvalidInput
	}
	outcome := Outcome(value.Outcome)
	return r.Recorder.Record(ctx, Event{
		ActorUserID: value.ActorUserID,
		RequestID:   value.RequestID,
		Action:      "auth.login",
		ObjectType:  "session",
		Outcome:     outcome,
		ClientIP:    value.ClientIP,
		UserAgent:   value.UserAgent,
		Metadata:    value.Metadata,
	})
}

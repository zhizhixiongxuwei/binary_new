package auth

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	"binaryscan/internal/requestctx"
)

type loginAuditRecorderStub struct {
	events     []LoginAuditEvent
	err        error
	contextErr error
}

func (r *loginAuditRecorderStub) RecordLogin(ctx context.Context, event LoginAuditEvent) error {
	r.events = append(r.events, event)
	r.contextErr = ctx.Err()
	return r.err
}

func newAuditTestService(
	t *testing.T,
	repository Repository,
	recorder LoginAuditRecorder,
) *Service {
	t.Helper()
	service, err := NewService(repository, ServiceConfig{
		PasswordParameters: testPasswordParameters(),
		SessionTTL:         time.Hour,
		FailureThreshold:   5,
		LockDuration:       time.Minute,
		LoginRateLimit: LoginRateLimitPolicy{
			Threshold: 10, Window: time.Minute,
			BlockDuration: 5 * time.Minute,
		},
		LoginAudit: recorder,
	})
	if err != nil {
		t.Fatal(err)
	}
	return service
}

func TestLoginAuditDoesNotIdentifyUnknownUsername(t *testing.T) {
	recorder := &loginAuditRecorderStub{}
	service := newAuditTestService(
		t,
		&repositoryStub{userErr: sql.ErrNoRows},
		recorder,
	)
	ctx := requestctx.WithRequestID(context.Background(), "login-request")
	_, err := service.Login(
		ctx, "not-a-user", []byte("wrong-password-value"),
		[]byte{127, 0, 0, 1}, "browser",
	)
	if !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("Login() error = %v", err)
	}
	if len(recorder.events) != 1 {
		t.Fatalf("events = %#v", recorder.events)
	}
	event := recorder.events[0]
	if event.ActorUserID != nil || event.RequestID != "login-request" ||
		event.Outcome != "failure" ||
		event.Metadata["reason"] != "invalid_credentials" {
		t.Fatalf("event = %#v", event)
	}
	for _, value := range event.Metadata {
		if value == "not-a-user" {
			t.Fatalf("event leaked attempted username: %#v", event)
		}
	}
}

func TestLoginAuditFailureDoesNotChangeSuccessfulCredentialDecision(t *testing.T) {
	password := []byte("a-secure-test-password")
	hash, err := HashPassword(password, testPasswordParameters())
	if err != nil {
		t.Fatal(err)
	}
	repository := &repositoryStub{user: User{
		ID: 42, PublicID: "user-id", Username: "admin", DisplayName: "Admin",
		PasswordHash: hash, Role: RoleAdministrator, Status: "active",
	}}
	recorder := &loginAuditRecorderStub{err: errors.New("audit unavailable")}
	service := newAuditTestService(t, repository, recorder)
	result, err := service.Login(
		context.Background(), "admin", password, nil, "browser",
	)
	if err != nil || result.SessionToken == "" {
		t.Fatalf("Login() result/error = %#v / %v", result, err)
	}
	if len(recorder.events) != 1 ||
		recorder.events[0].ActorUserID == nil ||
		*recorder.events[0].ActorUserID != 42 ||
		recorder.events[0].Outcome != "success" {
		t.Fatalf("event = %#v", recorder.events)
	}
}

func TestLoginAuditSurvivesCancelledRequestContext(t *testing.T) {
	recorder := &loginAuditRecorderStub{}
	service := newAuditTestService(
		t,
		&repositoryStub{userErr: sql.ErrNoRows},
		recorder,
	)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := service.Login(
		ctx,
		"unknown",
		[]byte("wrong-password-value"),
		nil,
		"browser",
	)
	if !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("Login() error = %v", err)
	}
	if len(recorder.events) != 1 || recorder.contextErr != nil {
		t.Fatalf(
			"audit events/context = %#v / %v",
			recorder.events,
			recorder.contextErr,
		)
	}
}

func TestLoginAuditRecordsRateLimitedWithoutUsername(t *testing.T) {
	recorder := &loginAuditRecorderStub{}
	repository := &repositoryStub{loginAttempt: LoginAttempt{
		Limited: true, RetryAfter: 20 * time.Second,
	}}
	service := newAuditTestService(t, repository, recorder)
	_, err := service.Login(
		context.Background(),
		"known-or-unknown",
		[]byte("a-secure-test-password"),
		nil,
		"browser",
	)
	if !errors.Is(err, ErrLoginRateLimited) {
		t.Fatalf("Login() error = %v", err)
	}
	if len(recorder.events) != 1 {
		t.Fatalf("events = %#v", recorder.events)
	}
	event := recorder.events[0]
	if event.ActorUserID != nil ||
		event.Outcome != "failure" ||
		event.Metadata["reason"] != "rate_limited" {
		t.Fatalf("event = %#v", event)
	}
	for _, value := range event.Metadata {
		if value == "known-or-unknown" {
			t.Fatalf("event leaked attempted username: %#v", event)
		}
	}
}

package api

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"binaryscan/internal/auth"
	"binaryscan/internal/buildinfo"
	"binaryscan/internal/taskevent"
)

const taskEventTestID = "123e4567-e89b-42d3-a456-426614174000"

type taskEventServiceStub struct {
	events      []taskevent.Event
	err         error
	calls       int
	taskIDs     []string
	after       []uint64
	limits      []int
	cancel      context.CancelFunc
	cancelAfter int
}

func (s *taskEventServiceStub) List(
	_ context.Context,
	taskID string,
	afterSequence uint64,
	limit int,
) ([]taskevent.Event, error) {
	s.calls++
	s.taskIDs = append(s.taskIDs, taskID)
	s.after = append(s.after, afterSequence)
	s.limits = append(s.limits, limit)
	if s.cancel != nil && s.calls >= s.cancelAfter {
		s.cancel()
	}
	if s.calls == 1 {
		return s.events, s.err
	}
	return []taskevent.Event{}, s.err
}

func TestTaskEventStreamAllowsEveryAuthenticatedRoleAndResumes(t *testing.T) {
	roles := []auth.Role{
		auth.RoleAdministrator,
		auth.RoleOperator,
		auth.RoleReader,
	}
	for _, role := range roles {
		t.Run(string(role), func(t *testing.T) {
			stage := "SCANNING"
			progress := 27.5
			message := "Task progress changed."
			ctx, cancel := context.WithCancel(context.Background())
			service := &taskEventServiceStub{
				events: []taskevent.Event{{
					Sequence:              8,
					Type:                  "task.progress",
					Stage:                 &stage,
					Progress:              &progress,
					ProgressIndeterminate: true,
					Severity:              "info",
					Message:               &message,
					Payload: json.RawMessage(
						`{"status":"SCANNING","progress_basis_points":2750}`,
					),
					CreatedAt: time.Date(
						2026, 7, 30, 1, 2, 3, 0, time.UTC,
					),
				}},
				cancel: cancel, cancelAfter: 2,
			}
			router := taskEventTestRouter(
				t,
				&authManagerStub{session: auth.Session{
					User: auth.Principal{UserID: 7, Role: role},
				}},
				service,
				TaskEventHTTPConfig{
					PollInterval: time.Millisecond, HeartbeatInterval: time.Hour,
					RetryInterval: 2500 * time.Millisecond, BatchSize: 10,
				},
			)
			request := httptest.NewRequest(
				http.MethodGet,
				"/api/v1/tasks/"+taskEventTestID+"/events",
				nil,
			).WithContext(ctx)
			request.Header.Set("Last-Event-ID", "7")
			request.AddCookie(&http.Cookie{
				Name: sessionCookieName, Value: "session-token",
			})
			response := httptest.NewRecorder()
			router.ServeHTTP(response, request)

			if response.Code != http.StatusOK {
				t.Fatalf(
					"status = %d; body=%s",
					response.Code,
					response.Body.String(),
				)
			}
			for name, want := range map[string]string{
				"Content-Type":      "text/event-stream; charset=utf-8",
				"Cache-Control":     "no-cache",
				"Connection":        "keep-alive",
				"X-Accel-Buffering": "no",
			} {
				if got := response.Header().Get(name); got != want {
					t.Errorf("%s = %q, want %q", name, got, want)
				}
			}
			body := response.Body.String()
			for _, fragment := range []string{
				"retry: 2500\n\n",
				"id: 8\n",
				"event: task.progress\n",
				`"sequence":8`,
				`"type":"task.progress"`,
				`"stage":"SCANNING"`,
				`"progress":27.5`,
				`"progress_indeterminate":true`,
				`"severity":"info"`,
				`"message":"Task progress changed."`,
				`"payload":{"status":"SCANNING","progress_basis_points":2750}`,
				`"created_at":"2026-07-30T01:02:03Z"`,
			} {
				if !strings.Contains(body, fragment) {
					t.Errorf("stream lacks %q: %s", fragment, body)
				}
			}
			if service.calls != 2 ||
				service.taskIDs[0] != taskEventTestID ||
				service.after[0] != 7 || service.after[1] != 8 ||
				service.limits[0] != 10 {
				t.Fatalf(
					"service calls/task/after/limit = %d/%v/%v/%v",
					service.calls,
					service.taskIDs,
					service.after,
					service.limits,
				)
			}
		})
	}
}

func TestTaskEventStreamRejectsMalformedLastEventIDAndQuery(t *testing.T) {
	targets := []struct {
		name   string
		target string
		header string
	}{
		{name: "negative", target: "/events", header: "-1"},
		{name: "leading zero", target: "/events", header: "01"},
		{name: "overflow", target: "/events", header: "18446744073709551616"},
		{name: "spaces", target: "/events", header: " 1"},
		{name: "unknown query", target: "/events?cursor=1"},
	}
	for _, test := range targets {
		t.Run(test.name, func(t *testing.T) {
			service := &taskEventServiceStub{}
			router := taskEventTestRouter(
				t,
				&authManagerStub{session: auth.Session{
					User: auth.Principal{Role: auth.RoleReader},
				}},
				service,
				TaskEventHTTPConfig{},
			)
			request := authenticatedTaskEventRequest(
				"/api/v1/tasks/" + taskEventTestID + test.target,
			)
			if test.header != "" {
				request.Header.Set("Last-Event-ID", test.header)
			}
			response := httptest.NewRecorder()
			router.ServeHTTP(response, request)
			if response.Code != http.StatusBadRequest || service.calls != 0 {
				t.Fatalf(
					"status/calls = %d/%d; body=%s",
					response.Code,
					service.calls,
					response.Body.String(),
				)
			}
		})
	}
}

func TestTaskEventStreamMapsInitialErrorsBeforeOpeningStream(t *testing.T) {
	tests := []struct {
		name string
		err  error
		code int
	}{
		{name: "invalid task id", err: taskevent.ErrInvalidInput, code: http.StatusBadRequest},
		{name: "missing task", err: taskevent.ErrNotFound, code: http.StatusNotFound},
		{name: "repository failure", err: errors.New("private mysql detail"), code: http.StatusInternalServerError},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			service := &taskEventServiceStub{err: test.err}
			router := taskEventTestRouter(
				t,
				&authManagerStub{session: auth.Session{
					User: auth.Principal{Role: auth.RoleReader},
				}},
				service,
				TaskEventHTTPConfig{},
			)
			response := httptest.NewRecorder()
			router.ServeHTTP(
				response,
				authenticatedTaskEventRequest(
					"/api/v1/tasks/"+taskEventTestID+"/events",
				),
			)
			if response.Code != test.code {
				t.Fatalf(
					"status = %d; body=%s",
					response.Code,
					response.Body.String(),
				)
			}
			if strings.HasPrefix(
				response.Header().Get("Content-Type"),
				"text/event-stream",
			) {
				t.Fatal("failed initial request opened an SSE stream")
			}
		})
	}
}

func TestTaskEventStreamWritesHeartbeatAndExitsOnCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	service := &taskEventServiceStub{}
	router := taskEventTestRouter(
		t,
		&authManagerStub{session: auth.Session{
			User: auth.Principal{Role: auth.RoleReader},
		}},
		service,
		TaskEventHTTPConfig{
			PollInterval: time.Hour, HeartbeatInterval: time.Millisecond,
			RetryInterval: time.Second, BatchSize: 10,
		},
	)
	timer := time.AfterFunc(15*time.Millisecond, cancel)
	defer timer.Stop()
	request := authenticatedTaskEventRequest(
		"/api/v1/tasks/" + taskEventTestID + "/events",
	).WithContext(ctx)
	response := httptest.NewRecorder()
	started := time.Now()
	router.ServeHTTP(response, request)
	if elapsed := time.Since(started); elapsed > 250*time.Millisecond {
		t.Fatalf("handler took %s to observe cancellation", elapsed)
	}
	if !strings.Contains(response.Body.String(), ": heartbeat\n\n") {
		t.Fatalf("stream lacks heartbeat: %s", response.Body.String())
	}

	alreadyCancelled, stop := context.WithCancel(context.Background())
	stop()
	service = &taskEventServiceStub{}
	router = taskEventTestRouter(
		t,
		&authManagerStub{session: auth.Session{
			User: auth.Principal{Role: auth.RoleReader},
		}},
		service,
		TaskEventHTTPConfig{PollInterval: time.Hour, HeartbeatInterval: time.Hour},
	)
	response = httptest.NewRecorder()
	router.ServeHTTP(
		response,
		authenticatedTaskEventRequest(
			"/api/v1/tasks/"+taskEventTestID+"/events",
		).WithContext(alreadyCancelled),
	)
	if service.calls != 1 {
		t.Fatalf("cancelled stream service calls = %d, want 1", service.calls)
	}
}

func TestTaskEventStreamRequiresAuthentication(t *testing.T) {
	service := &taskEventServiceStub{}
	router := taskEventTestRouter(
		t,
		&authManagerStub{},
		service,
		TaskEventHTTPConfig{},
	)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(
		http.MethodGet,
		"/api/v1/tasks/"+taskEventTestID+"/events",
		nil,
	))
	if response.Code != http.StatusUnauthorized || service.calls != 0 {
		t.Fatalf("status/calls = %d/%d", response.Code, service.calls)
	}
}

func authenticatedTaskEventRequest(target string) *http.Request {
	request := httptest.NewRequest(http.MethodGet, target, nil)
	request.AddCookie(&http.Cookie{
		Name: sessionCookieName, Value: "session-token",
	})
	return request
}

func taskEventTestRouter(
	t *testing.T,
	manager AuthManager,
	service TaskEventService,
	config TaskEventHTTPConfig,
) http.Handler {
	t.Helper()
	router, err := NewRouter(Dependencies{
		Logger:   slog.New(slog.NewJSONHandler(io.Discard, nil)),
		Database: readinessStub{}, ReadinessTimeout: time.Second,
		Auth: manager, AuthHTTP: AuthHTTPConfig{SessionTTL: time.Hour},
		TaskEvents: service, TaskEventsHTTP: config,
		Build: buildinfo.Current(),
	})
	if err != nil {
		t.Fatal(err)
	}
	return router
}

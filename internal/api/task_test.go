package api

import (
	"bytes"
	"context"
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
	"binaryscan/internal/task"
)

type taskServiceStub struct {
	createUserID      uint64
	createRole        auth.Role
	createUpload      string
	createName        string
	createKey         string
	created           bool
	listQuery         task.ListQuery
	view              task.View
	page              task.Page
	err               error
	cancelUserID      uint64
	cancelRole        auth.Role
	cancelID          string
	cancelKey         string
	retryUserID       uint64
	retryRole         auth.Role
	retryID           string
	retryKey          string
	deleteUserID      uint64
	deleteRole        auth.Role
	deleteID          string
	retentionUserID   uint64
	retentionRole     auth.Role
	retentionID       string
	retentionExpected string
	retentionValue    string
}

func (s *taskServiceStub) Create(
	_ context.Context,
	userID uint64,
	role auth.Role,
	uploadID string,
	name string,
	idempotencyKey string,
) (task.View, bool, error) {
	s.createUserID = userID
	s.createRole = role
	s.createUpload = uploadID
	s.createName = name
	s.createKey = idempotencyKey
	return s.view, s.created, s.err
}

func (s *taskServiceStub) List(_ context.Context, query task.ListQuery) (task.Page, error) {
	s.listQuery = query
	return s.page, s.err
}

func (s *taskServiceStub) Get(context.Context, string) (task.View, error) {
	return s.view, s.err
}

func (s *taskServiceStub) Cancel(
	_ context.Context,
	userID uint64,
	role auth.Role,
	id string,
	idempotencyKey string,
) (task.View, error) {
	s.cancelUserID = userID
	s.cancelRole = role
	s.cancelID = id
	s.cancelKey = idempotencyKey
	return s.view, s.err
}

func (s *taskServiceStub) Retry(
	_ context.Context,
	userID uint64,
	role auth.Role,
	id string,
	idempotencyKey string,
) (task.View, error) {
	s.retryUserID = userID
	s.retryRole = role
	s.retryID = id
	s.retryKey = idempotencyKey
	return s.view, s.err
}

func (s *taskServiceStub) Delete(
	_ context.Context,
	userID uint64,
	role auth.Role,
	id string,
) (task.View, error) {
	s.deleteUserID = userID
	s.deleteRole = role
	s.deleteID = id
	return s.view, s.err
}

func (s *taskServiceStub) ExtendRetention(
	_ context.Context,
	userID uint64,
	role auth.Role,
	id string,
	expectedSampleExpiresAt string,
	sampleExpiresAt string,
) (task.View, error) {
	s.retentionUserID = userID
	s.retentionRole = role
	s.retentionID = id
	s.retentionExpected = expectedSampleExpiresAt
	s.retentionValue = sampleExpiresAt
	return s.view, s.err
}

func TestCreateTaskContractAndIdempotentStatus(t *testing.T) {
	const creatorID = "40000000-0000-4000-8000-000000000004"
	csrf := "csrf-token"
	manager := &authManagerStub{
		session: auth.Session{User: auth.Principal{
			UserID: 7, Role: auth.RoleOperator,
		}},
		csrfToken: csrf,
	}
	service := &taskServiceStub{
		created: true,
		view: task.View{
			ID:        "123e4567-e89b-42d3-a456-426614174000",
			CreatorID: creatorID,
		},
	}
	router := taskTestRouter(t, manager, service)
	request := httptest.NewRequest(
		http.MethodPost,
		"/api/v1/tasks",
		strings.NewReader(`{"upload_id":"123e4567-e89b-42d3-a456-426614174001","name":"sample.bin"}`),
	)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Idempotency-Key", "task-request-1")
	addAuthAndCSRF(request, csrf)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusCreated {
		t.Fatalf("status = %d; body=%s", response.Code, response.Body.String())
	}
	if !strings.Contains(response.Body.String(), `"creator_id":"`+creatorID+`"`) {
		t.Fatalf("response omits stable creator ID: %s", response.Body.String())
	}
	if service.createUserID != 7 || service.createRole != auth.RoleOperator ||
		service.createUpload != "123e4567-e89b-42d3-a456-426614174001" ||
		service.createName != "sample.bin" || service.createKey != "task-request-1" {
		t.Fatalf("create capture = %#v", service)
	}

	service.created = false
	replay := httptest.NewRecorder()
	replayRequest := httptest.NewRequest(
		http.MethodPost,
		"/api/v1/tasks",
		strings.NewReader(`{"upload_id":"123e4567-e89b-42d3-a456-426614174001","name":"sample.bin"}`),
	)
	replayRequest.Header.Set("Content-Type", "application/json")
	replayRequest.Header.Set("Idempotency-Key", "task-request-1")
	addAuthAndCSRF(replayRequest, csrf)
	router.ServeHTTP(replay, replayRequest)
	if replay.Code != http.StatusOK {
		t.Fatalf("replay status = %d, want 200", replay.Code)
	}
}

func TestCreateTaskRejectsReaderBeforeService(t *testing.T) {
	csrf := "csrf-token"
	manager := &authManagerStub{
		session: auth.Session{User: auth.Principal{
			UserID: 9, Role: auth.RoleReader,
		}},
		csrfToken: csrf,
	}
	service := &taskServiceStub{created: true}
	router := taskTestRouter(t, manager, service)
	request := httptest.NewRequest(
		http.MethodPost,
		"/api/v1/tasks",
		strings.NewReader(`{"upload_id":"123e4567-e89b-42d3-a456-426614174001","name":"sample.bin"}`),
	)
	request.Header.Set("Idempotency-Key", "task-request-1")
	addAuthAndCSRF(request, csrf)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", response.Code)
	}
	if service.createUserID != 0 {
		t.Fatal("reader request reached task service")
	}
}

func TestTaskLifecycleRoutesRequireCSRFAndForwardPrincipal(t *testing.T) {
	const taskID = "20000000-0000-4000-8000-000000000002"
	csrf := "csrf-token"
	manager := &authManagerStub{
		session: auth.Session{User: auth.Principal{
			UserID: 7, Role: auth.RoleOperator,
		}},
		csrfToken: csrf,
	}
	service := &taskServiceStub{
		view: task.View{ID: taskID, Status: task.StatusQueued},
	}
	router := taskTestRouter(t, manager, service)

	cancel := httptest.NewRequest(
		http.MethodPost, "/api/v1/tasks/"+taskID+"/cancel", nil,
	)
	cancel.Header.Set("Idempotency-Key", "cancel-request")
	addAuthAndCSRF(cancel, csrf)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, cancel)
	if response.Code != http.StatusOK {
		t.Fatalf("cancel status = %d; body=%s", response.Code, response.Body.String())
	}
	if service.cancelUserID != 7 || service.cancelRole != auth.RoleOperator ||
		service.cancelID != taskID || service.cancelKey != "cancel-request" {
		t.Fatalf("cancel capture = %#v", service)
	}

	retry := httptest.NewRequest(
		http.MethodPost, "/api/v1/tasks/"+taskID+"/retry", nil,
	)
	retry.Header.Set("Idempotency-Key", "retry-request")
	addAuthAndCSRF(retry, csrf)
	response = httptest.NewRecorder()
	router.ServeHTTP(response, retry)
	if response.Code != http.StatusOK {
		t.Fatalf("retry status = %d; body=%s", response.Code, response.Body.String())
	}
	if service.retryUserID != 7 || service.retryRole != auth.RoleOperator ||
		service.retryID != taskID || service.retryKey != "retry-request" {
		t.Fatalf("retry capture = %#v", service)
	}

	deleteRequest := httptest.NewRequest(
		http.MethodDelete, "/api/v1/tasks/"+taskID, nil,
	)
	addAuthAndCSRF(deleteRequest, csrf)
	response = httptest.NewRecorder()
	router.ServeHTTP(response, deleteRequest)
	if response.Code != http.StatusOK {
		t.Fatalf("delete status = %d; body=%s", response.Code, response.Body.String())
	}
	if service.deleteUserID != 7 || service.deleteRole != auth.RoleOperator ||
		service.deleteID != taskID {
		t.Fatalf("delete capture = %#v", service)
	}

	service.cancelUserID = 0
	withoutCSRF := httptest.NewRequest(
		http.MethodPost, "/api/v1/tasks/"+taskID+"/cancel", nil,
	)
	withoutCSRF.AddCookie(&http.Cookie{Name: sessionCookieName, Value: "session-token"})
	response = httptest.NewRecorder()
	router.ServeHTTP(response, withoutCSRF)
	if response.Code != http.StatusForbidden || service.cancelUserID != 0 {
		t.Fatalf(
			"missing CSRF = status %d, service user %d",
			response.Code, service.cancelUserID,
		)
	}
}

func TestTaskLifecycleRoutesRejectReaderBeforeService(t *testing.T) {
	const taskID = "20000000-0000-4000-8000-000000000002"
	csrf := "csrf-token"
	manager := &authManagerStub{
		session: auth.Session{User: auth.Principal{
			UserID: 9, Role: auth.RoleReader,
		}},
		csrfToken: csrf,
	}
	service := &taskServiceStub{}
	router := taskTestRouter(t, manager, service)
	requests := []*http.Request{
		httptest.NewRequest(http.MethodPost, "/api/v1/tasks/"+taskID+"/cancel", nil),
		httptest.NewRequest(http.MethodPost, "/api/v1/tasks/"+taskID+"/retry", nil),
		httptest.NewRequest(http.MethodDelete, "/api/v1/tasks/"+taskID, nil),
	}
	for _, request := range requests {
		request.Header.Set("Idempotency-Key", "request-key")
		addAuthAndCSRF(request, csrf)
		response := httptest.NewRecorder()
		router.ServeHTTP(response, request)
		if response.Code != http.StatusForbidden {
			t.Fatalf("%s %s status = %d, want 403", request.Method, request.URL, response.Code)
		}
	}
	if service.cancelUserID != 0 || service.retryUserID != 0 || service.deleteUserID != 0 {
		t.Fatalf("reader lifecycle request reached service: %#v", service)
	}
}

func TestExtendTaskRetentionRequiresAdministratorAndCSRF(t *testing.T) {
	const taskID = "20000000-0000-4000-8000-000000000002"
	const body = `{"expected_sample_expires_at":"2026-07-29T00:00:00Z",` +
		`"sample_expires_at":"2026-08-28T00:00:00Z"}`
	csrf := "csrf-token"

	t.Run("administrator", func(t *testing.T) {
		manager := &authManagerStub{
			session: auth.Session{User: auth.Principal{
				UserID: 7, Role: auth.RoleAdministrator,
			}},
			csrfToken: csrf,
		}
		service := &taskServiceStub{
			view: task.View{ID: taskID, SampleExpiresAt: time.Date(
				2026, 8, 28, 0, 0, 0, 0, time.UTC,
			)},
		}
		router := taskTestRouter(t, manager, service)
		request := httptest.NewRequest(
			http.MethodPatch, "/api/v1/tasks/"+taskID+"/retention",
			strings.NewReader(body),
		)
		request.Header.Set("Content-Type", "application/json")
		addAuthAndCSRF(request, csrf)
		response := httptest.NewRecorder()
		router.ServeHTTP(response, request)

		if response.Code != http.StatusOK {
			t.Fatalf("status = %d; body=%s", response.Code, response.Body.String())
		}
		if service.retentionUserID != 7 ||
			service.retentionRole != auth.RoleAdministrator ||
			service.retentionID != taskID ||
			service.retentionExpected != "2026-07-29T00:00:00Z" ||
			service.retentionValue != "2026-08-28T00:00:00Z" {
			t.Fatalf("retention capture = %#v", service)
		}
		if !strings.Contains(response.Body.String(), `"sample_expires_at":"2026-08-28T00:00:00Z"`) {
			t.Fatalf("response did not contain latest task view: %s", response.Body.String())
		}
	})

	for _, test := range []struct {
		name        string
		userID      uint64
		role        auth.Role
		includeAuth bool
		includeCSRF bool
		want        int
	}{
		{
			name: "operator", userID: 8, role: auth.RoleOperator,
			includeAuth: true, includeCSRF: true, want: http.StatusForbidden,
		},
		{
			name: "missing csrf", userID: 7, role: auth.RoleAdministrator,
			includeAuth: true, want: http.StatusForbidden,
		},
		{
			name: "missing session", role: auth.RoleAdministrator,
			includeCSRF: true, want: http.StatusUnauthorized,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			manager := &authManagerStub{
				session: auth.Session{User: auth.Principal{
					UserID: test.userID, Role: test.role,
				}},
				csrfToken: csrf,
			}
			service := &taskServiceStub{}
			router := taskTestRouter(t, manager, service)
			request := httptest.NewRequest(
				http.MethodPatch, "/api/v1/tasks/"+taskID+"/retention",
				strings.NewReader(body),
			)
			if test.includeAuth {
				request.AddCookie(&http.Cookie{
					Name: sessionCookieName, Value: "session-token",
				})
			}
			if test.includeCSRF {
				request.Header.Set(csrfHeaderName, csrf)
			}
			response := httptest.NewRecorder()
			router.ServeHTTP(response, request)
			if response.Code != test.want {
				t.Fatalf("status = %d, want %d; body=%s", response.Code, test.want, response.Body.String())
			}
			if service.retentionUserID != 0 {
				t.Fatal("unauthorized retention request reached service")
			}
		})
	}
}

func TestExtendTaskRetentionRejectsInvalidJSONAndMapsStateErrors(t *testing.T) {
	const taskID = "20000000-0000-4000-8000-000000000002"
	csrf := "csrf-token"
	manager := &authManagerStub{
		session: auth.Session{User: auth.Principal{
			UserID: 7, Role: auth.RoleAdministrator,
		}},
		csrfToken: csrf,
	}

	service := &taskServiceStub{}
	router := taskTestRouter(t, manager, service)
	request := httptest.NewRequest(
		http.MethodPatch, "/api/v1/tasks/"+taskID+"/retention",
		strings.NewReader(
			`{"expected_sample_expires_at":"2026-07-29T00:00:00Z",`+
				`"sample_expires_at":"2026-08-28T00:00:00Z","unknown":true}`,
		),
	)
	addAuthAndCSRF(request, csrf)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest || service.retentionUserID != 0 {
		t.Fatalf(
			"invalid JSON = status %d, service user %d; body=%s",
			response.Code, service.retentionUserID, response.Body.String(),
		)
	}

	for _, test := range []struct {
		name string
		err  error
		code string
	}{
		{name: "stale CAS", err: task.ErrConflict, code: "task_conflict"},
		{
			name: "expired or deleted sample", err: task.ErrSampleUnavailable,
			code: "task_sample_unavailable",
		},
		{
			name: "deleting task", err: task.ErrInvalidState,
			code: "task_state_conflict",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			service := &taskServiceStub{err: test.err}
			router := taskTestRouter(t, manager, service)
			request := httptest.NewRequest(
				http.MethodPatch, "/api/v1/tasks/"+taskID+"/retention",
				strings.NewReader(
					`{"expected_sample_expires_at":"2026-07-29T00:00:00Z",`+
						`"sample_expires_at":"2026-08-28T00:00:00Z"}`,
				),
			)
			addAuthAndCSRF(request, csrf)
			response := httptest.NewRecorder()
			router.ServeHTTP(response, request)
			if response.Code != http.StatusConflict ||
				!strings.Contains(response.Body.String(), `"`+test.code+`"`) {
				t.Fatalf(
					"error mapping = status %d; body=%s",
					response.Code, response.Body.String(),
				)
			}
		})
	}
}

func TestListTasksParsesFiltersForReader(t *testing.T) {
	manager := &authManagerStub{
		session: auth.Session{User: auth.Principal{
			UserID: 9, Role: auth.RoleReader,
		}},
	}
	service := &taskServiceStub{page: task.Page{Items: []task.View{}}}
	router := taskTestRouter(t, manager, service)
	request := httptest.NewRequest(
		http.MethodGet,
		"/api/v1/tasks?cursor=opaque_cursor-2&page_size=25&keyword=sample&status=queued&input_type=unknown"+
			"&creator=analyst&tag=release%20candidate&created_from=2026-07-01&created_to=2026-07-29",
		nil,
	)
	request.AddCookie(&http.Cookie{Name: sessionCookieName, Value: "session-token"})
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d; body=%s", response.Code, response.Body.String())
	}
	if strings.Contains(response.Body.String(), "next_cursor") {
		t.Fatalf("terminal task page did not omit next_cursor: %s", response.Body.String())
	}
	want := task.ListQuery{
		Cursor: "opaque_cursor-2", PageSize: 25, Keyword: "sample",
		Status: "queued", InputType: "unknown",
		Creator: "analyst", Tag: "release candidate",
		CreatedFrom: "2026-07-01", CreatedTo: "2026-07-29",
	}
	if service.listQuery != want {
		t.Fatalf("list query = %#v, want %#v", service.listQuery, want)
	}

	for _, target := range []string{
		"/api/v1/tasks?unknown=true",
		"/api/v1/tasks?page=2",
		"/api/v1/tasks?cursor=",
		"/api/v1/tasks?cursor=one&cursor=two",
		"/api/v1/tasks?status=queued&status=failed",
		"/api/v1/tasks?tag=release&tag=stable",
	} {
		invalid := httptest.NewRecorder()
		request = httptest.NewRequest(http.MethodGet, target, nil)
		request.AddCookie(&http.Cookie{Name: sessionCookieName, Value: "session-token"})
		router.ServeHTTP(invalid, request)
		if invalid.Code != http.StatusBadRequest {
			t.Fatalf("invalid query %q status = %d, want 400", target, invalid.Code)
		}
	}
}

func TestTaskResponsesExposeNullableSampleCleanupState(t *testing.T) {
	const taskID = "20000000-0000-4000-8000-000000000002"
	expiresAt := time.Date(2026, 8, 29, 1, 2, 3, 0, time.UTC)
	cleanedAt := time.Date(2026, 8, 29, 1, 3, 4, 0, time.UTC)
	manager := &authManagerStub{
		session: auth.Session{User: auth.Principal{
			UserID: 9, Role: auth.RoleReader,
		}},
	}
	service := &taskServiceStub{
		view: task.View{
			ID: taskID, SampleExpiresAt: expiresAt, SampleDeletedAt: nil,
			Progress: 70, ProgressIndeterminate: true,
		},
		page: task.Page{
			Items: []task.View{{
				ID: taskID, SampleExpiresAt: expiresAt, SampleDeletedAt: &cleanedAt,
			}},
			NextCursor: "opaque_next_cursor",
		},
	}
	router := taskTestRouter(t, manager, service)

	detailRequest := httptest.NewRequest(
		http.MethodGet,
		"/api/v1/tasks/"+taskID,
		nil,
	)
	detailRequest.AddCookie(&http.Cookie{
		Name: sessionCookieName, Value: "session-token",
	})
	detail := httptest.NewRecorder()
	router.ServeHTTP(detail, detailRequest)
	if detail.Code != http.StatusOK {
		t.Fatalf("detail status = %d; body=%s", detail.Code, detail.Body.String())
	}
	if !strings.Contains(detail.Body.String(), `"sample_deleted_at":null`) {
		t.Fatalf("detail omits explicit pending cleanup state: %s", detail.Body.String())
	}
	if !strings.Contains(detail.Body.String(), `"progress_indeterminate":true`) {
		t.Fatalf("detail omits progress mode: %s", detail.Body.String())
	}

	listRequest := httptest.NewRequest(http.MethodGet, "/api/v1/tasks", nil)
	listRequest.AddCookie(&http.Cookie{
		Name: sessionCookieName, Value: "session-token",
	})
	list := httptest.NewRecorder()
	router.ServeHTTP(list, listRequest)
	if list.Code != http.StatusOK {
		t.Fatalf("list status = %d; body=%s", list.Code, list.Body.String())
	}
	if !strings.Contains(
		list.Body.String(),
		`"sample_deleted_at":"2026-08-29T01:03:04Z"`,
	) {
		t.Fatalf("list omits persisted task sample cleanup time: %s", list.Body.String())
	}
	if !strings.Contains(list.Body.String(), `"next_cursor":"opaque_next_cursor"`) {
		t.Fatalf("list omits the task continuation cursor: %s", list.Body.String())
	}
}

func TestTaskInternalErrorIsLoggedButNotExposed(t *testing.T) {
	const privateDetail = "mysql task query failed: secret diagnostic"
	manager := &authManagerStub{
		session: auth.Session{User: auth.Principal{UserID: 9, Role: auth.RoleReader}},
	}
	service := &taskServiceStub{err: errors.New(privateDetail)}
	var logOutput bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logOutput, nil))
	router := taskTestRouterWithLogger(t, manager, service, logger)
	request := httptest.NewRequest(http.MethodGet, "/api/v1/tasks", nil)
	request.AddCookie(&http.Cookie{Name: sessionCookieName, Value: "session-token"})
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)

	if response.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500; body=%s", response.Code, response.Body.String())
	}
	if strings.Contains(response.Body.String(), privateDetail) {
		t.Fatal("private task error leaked into the response")
	}
	if log := logOutput.String(); !strings.Contains(log, privateDetail) ||
		!strings.Contains(log, `"level":"ERROR"`) {
		t.Fatalf("private error was not logged at ERROR level: %s", log)
	}
}

func taskTestRouter(t *testing.T, manager AuthManager, service TaskService) http.Handler {
	t.Helper()
	return taskTestRouterWithLogger(
		t, manager, service, slog.New(slog.NewJSONHandler(io.Discard, nil)),
	)
}

func taskTestRouterWithLogger(
	t *testing.T,
	manager AuthManager,
	service TaskService,
	logger *slog.Logger,
) http.Handler {
	t.Helper()
	router, err := NewRouter(Dependencies{
		Logger:   logger,
		Database: readinessStub{}, ReadinessTimeout: time.Second,
		Auth: manager, AuthHTTP: AuthHTTPConfig{SessionTTL: time.Hour},
		Tasks: service,
		Build: buildinfo.Current(),
	})
	if err != nil {
		t.Fatal(err)
	}
	return router
}

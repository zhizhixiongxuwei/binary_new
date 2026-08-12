package api

import (
	"bytes"
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"binaryscan/internal/auth"
	"binaryscan/internal/javaanalysis"

	"github.com/gin-gonic/gin"
)

const (
	apiJavaAnalysisTaskID    = "61111111-1111-4111-8111-111111111111"
	apiJavaAnalysisProjectID = "62222222-2222-4222-8222-222222222222"
	apiJavaAnalysisRunID     = "63333333-3333-4333-8333-333333333333"
)

type javaAnalysisServiceStub struct {
	createInput   javaanalysis.CreateInput
	createRun     javaanalysis.Run
	created       bool
	createErr     error
	createCalls   int
	listQuery     javaanalysis.ListQuery
	findingsQuery javaanalysis.FindingsQuery
}

func (s *javaAnalysisServiceStub) Create(
	_ context.Context,
	input javaanalysis.CreateInput,
) (javaanalysis.Run, bool, error) {
	s.createCalls++
	s.createInput = input
	return s.createRun, s.created, s.createErr
}

func (s *javaAnalysisServiceStub) List(
	_ context.Context,
	query javaanalysis.ListQuery,
) (javaanalysis.RunPage, error) {
	s.listQuery = query
	return javaanalysis.RunPage{Items: []javaanalysis.Run{}}, nil
}

func (s *javaAnalysisServiceStub) Get(
	context.Context,
	javaanalysis.RunQuery,
) (javaanalysis.Run, error) {
	return s.createRun, nil
}

func (s *javaAnalysisServiceStub) ListFindings(
	_ context.Context,
	query javaanalysis.FindingsQuery,
) (javaanalysis.FindingPage, error) {
	s.findingsQuery = query
	return javaanalysis.FindingPage{Items: []javaanalysis.Finding{}}, nil
}

func (s *javaAnalysisServiceStub) Cancel(
	context.Context,
	javaanalysis.ActionInput,
) (javaanalysis.Run, error) {
	return s.createRun, nil
}

func (s *javaAnalysisServiceStub) Delete(
	context.Context,
	javaanalysis.ActionInput,
) error {
	return nil
}

func TestCreateJavaAnalysisRequiresOperatorCSRFAndIdempotency(t *testing.T) {
	for _, test := range []struct {
		name       string
		role       auth.Role
		csrf       bool
		key        bool
		wantStatus int
		wantCalls  int
	}{
		{"operator", auth.RoleOperator, true, true, http.StatusCreated, 1},
		{"administrator", auth.RoleAdministrator, true, true, http.StatusCreated, 1},
		{"reader", auth.RoleReader, true, true, http.StatusForbidden, 0},
		{"missing csrf", auth.RoleOperator, false, true, http.StatusForbidden, 0},
		{"missing idempotency", auth.RoleOperator, true, false, http.StatusBadRequest, 0},
	} {
		t.Run(test.name, func(t *testing.T) {
			service := &javaAnalysisServiceStub{
				createRun: javaanalysis.Run{ID: apiJavaAnalysisRunID}, created: true,
			}
			manager := &authManagerStub{
				session: auth.Session{User: auth.Principal{
					UserID: 7, Role: test.role,
				}},
				csrfToken: "csrf-token",
			}
			router := javaAnalysisTestRouter(manager, service)
			request := httptest.NewRequest(
				http.MethodPost,
				"/api/v1/tasks/"+apiJavaAnalysisTaskID+
					"/decompile-projects/"+apiJavaAnalysisProjectID+
					"/java-analysis-runs",
				nil,
			)
			request.AddCookie(&http.Cookie{Name: sessionCookieName, Value: "session-token"})
			if test.key {
				request.Header.Set("Idempotency-Key", "java-analysis-click")
			}
			if test.csrf {
				request.AddCookie(&http.Cookie{Name: csrfCookieName, Value: "csrf-token"})
				request.Header.Set(csrfHeaderName, "csrf-token")
			}
			response := httptest.NewRecorder()
			router.ServeHTTP(response, request)
			if response.Code != test.wantStatus || service.createCalls != test.wantCalls {
				t.Fatalf(
					"status=%d calls=%d body=%s", response.Code,
					service.createCalls, response.Body.String(),
				)
			}
			if test.wantCalls == 1 &&
				(service.createInput.TaskID != apiJavaAnalysisTaskID ||
					service.createInput.SourceProjectID != apiJavaAnalysisProjectID ||
					service.createInput.IdempotencyKey != "java-analysis-click" ||
					service.createInput.UserID != 7) {
				t.Fatalf("create input = %#v", service.createInput)
			}
		})
	}
}

func TestCreateJavaAnalysisMapsReadinessTo503(t *testing.T) {
	service := &javaAnalysisServiceStub{createErr: javaanalysis.ErrNotReady}
	manager := &authManagerStub{
		session:   auth.Session{User: auth.Principal{UserID: 7, Role: auth.RoleOperator}},
		csrfToken: "csrf-token",
	}
	router := javaAnalysisTestRouter(manager, service)
	request := httptest.NewRequest(
		http.MethodPost,
		"/api/v1/tasks/"+apiJavaAnalysisTaskID+
			"/decompile-projects/"+apiJavaAnalysisProjectID+"/java-analysis-runs",
		nil,
	)
	request.Header.Set("Idempotency-Key", "java-analysis-click")
	request.Header.Set(csrfHeaderName, "csrf-token")
	request.AddCookie(&http.Cookie{Name: sessionCookieName, Value: "session-token"})
	request.AddCookie(&http.Cookie{Name: csrfCookieName, Value: "csrf-token"})
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusServiceUnavailable ||
		!bytes.Contains(response.Body.Bytes(), []byte(`"java_analysis_not_ready"`)) {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestCreateJavaAnalysisRejectsChunkedBody(t *testing.T) {
	service := &javaAnalysisServiceStub{}
	manager := &authManagerStub{
		session:   auth.Session{User: auth.Principal{UserID: 7, Role: auth.RoleOperator}},
		csrfToken: "csrf-token",
	}
	router := javaAnalysisTestRouter(manager, service)
	request := httptest.NewRequest(
		http.MethodPost,
		"/api/v1/tasks/"+apiJavaAnalysisTaskID+
			"/decompile-projects/"+apiJavaAnalysisProjectID+"/java-analysis-runs",
		strings.NewReader("{}"),
	)
	request.ContentLength = -1
	request.Header.Set("Idempotency-Key", "java-analysis-click")
	request.Header.Set(csrfHeaderName, "csrf-token")
	request.AddCookie(&http.Cookie{Name: sessionCookieName, Value: "session-token"})
	request.AddCookie(&http.Cookie{Name: csrfCookieName, Value: "csrf-token"})
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest || service.createCalls != 0 {
		t.Fatalf(
			"status=%d calls=%d body=%s",
			response.Code, service.createCalls, response.Body.String(),
		)
	}
}

func TestListJavaAnalysisFindingsPassesServerFiltersAndStrictCursor(t *testing.T) {
	service := &javaAnalysisServiceStub{}
	manager := &authManagerStub{session: auth.Session{User: auth.Principal{
		Role: auth.RoleReader,
	}}}
	router := javaAnalysisTestRouter(manager, service)
	request := httptest.NewRequest(
		http.MethodGet,
		"/api/v1/tasks/"+apiJavaAnalysisTaskID+
			"/java-analysis-runs/"+apiJavaAnalysisRunID+
			"/findings?cursor=19&page_size=25&cwe=CWE-328&severity=HIGH&file=A.java&callable=main",
		nil,
	)
	request.AddCookie(&http.Cookie{Name: sessionCookieName, Value: "session-token"})
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusOK || service.findingsQuery.Cursor != 19 ||
		service.findingsQuery.CWE != "CWE-328" ||
		service.findingsQuery.Severity != "HIGH" ||
		service.findingsQuery.File != "A.java" ||
		service.findingsQuery.Callable != "main" {
		t.Fatalf("status=%d query=%#v body=%s", response.Code, service.findingsQuery, response.Body.String())
	}
}

func javaAnalysisTestRouter(manager AuthManager, service JavaAnalysisService) http.Handler {
	gin.SetMode(gin.ReleaseMode)
	router := gin.New()
	router.Use(
		RequestIDMiddleware(),
		AccessLogMiddleware(slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil))),
	)
	registerJavaAnalysisRoutes(router.Group("/api/v1"), manager, service)
	return router
}

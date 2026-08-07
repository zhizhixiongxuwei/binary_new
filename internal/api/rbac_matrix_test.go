package api

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"binaryscan/internal/auth"
	"binaryscan/internal/buildinfo"
	"binaryscan/internal/sampleexport"

	"github.com/gin-gonic/gin"
)

func TestEveryRegisteredBusinessRouteRequiresAuthentication(t *testing.T) {
	router := completePolicyTestRouter(t, &authManagerStub{})
	public := map[string]struct{}{
		"GET /api/v1/health/live":  {},
		"GET /api/v1/health/ready": {},
		"GET /api/v1/version":      {},
		"POST /api/v1/auth/login":  {},
	}
	protected := 0
	for _, route := range router.Routes() {
		key := route.Method + " " + route.Path
		if _, ok := public[key]; ok {
			continue
		}
		protected++
		request := httptest.NewRequest(
			route.Method,
			concretePolicyPath(route.Path),
			strings.NewReader(`{}`),
		)
		request.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		router.ServeHTTP(response, request)
		if response.Code != http.StatusUnauthorized {
			t.Errorf(
				"%s without a session returned %d, want 401; body=%s",
				key,
				response.Code,
				response.Body.String(),
			)
			continue
		}
		var body ErrorResponse
		if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
			t.Errorf("%s returned invalid error JSON: %v", key, err)
		} else if body.Error.Code != "authentication_required" {
			t.Errorf(
				"%s error code = %q, want authentication_required",
				key,
				body.Error.Code,
			)
		}
	}
	if protected < 30 {
		t.Fatalf("protected route inventory = %d, want at least 30", protected)
	}
}

func TestReaderCannotInvokeAnyBusinessMutation(t *testing.T) {
	manager := &authManagerStub{
		session: auth.Session{
			ID: "reader-session",
			User: auth.Principal{
				UserID: 7, PublicID: "reader-id", Username: "reader",
				DisplayName: "Reader", Role: auth.RoleReader,
			},
		},
		csrfToken: "csrf-token",
	}
	router := completePolicyTestRouter(t, manager)
	exempt := map[string]struct{}{
		"POST /api/v1/auth/login":  {},
		"POST /api/v1/auth/logout": {},
		"PUT /api/v1/me/password":  {},
	}
	checked := 0
	for _, route := range router.Routes() {
		if route.Method == http.MethodGet || route.Method == http.MethodHead ||
			route.Method == http.MethodOptions {
			continue
		}
		key := route.Method + " " + route.Path
		if _, ok := exempt[key]; ok {
			continue
		}
		checked++
		request := httptest.NewRequest(
			route.Method,
			concretePolicyPath(route.Path),
			strings.NewReader(`{}`),
		)
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set(csrfHeaderName, manager.csrfToken)
		request.AddCookie(&http.Cookie{
			Name: sessionCookieName, Value: "reader-session-token",
		})
		request.AddCookie(&http.Cookie{
			Name: csrfCookieName, Value: manager.csrfToken,
		})
		response := httptest.NewRecorder()
		router.ServeHTTP(response, request)
		if response.Code != http.StatusForbidden {
			t.Errorf(
				"%s as reader returned %d, want 403; body=%s",
				key,
				response.Code,
				response.Body.String(),
			)
			continue
		}
		var body ErrorResponse
		if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
			t.Errorf("%s returned invalid error JSON: %v", key, err)
		} else if body.Error.Code != "permission_denied" {
			t.Errorf(
				"%s error code = %q, want permission_denied",
				key,
				body.Error.Code,
			)
		}
	}
	if checked < 14 {
		t.Fatalf("reader mutation inventory = %d, want at least 14", checked)
	}
}

func TestOperatorCannotInvokeAdministratorOnlyRoutes(t *testing.T) {
	manager := &authManagerStub{
		session: auth.Session{
			ID: "operator-session",
			User: auth.Principal{
				UserID: 8, PublicID: "operator-id", Username: "operator",
				DisplayName: "Operator", Role: auth.RoleOperator,
			},
		},
		csrfToken: "csrf-token",
	}
	router := completePolicyTestRouter(t, manager)
	checked := 0
	for _, route := range router.Routes() {
		administratorOnly := strings.HasPrefix(
			route.Path,
			"/api/v1/admin/",
		) || (route.Method == http.MethodPatch &&
			route.Path == "/api/v1/tasks/:id/retention")
		if !administratorOnly {
			continue
		}
		checked++
		request := httptest.NewRequest(
			route.Method,
			concretePolicyPath(route.Path),
			strings.NewReader(`{}`),
		)
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set(csrfHeaderName, manager.csrfToken)
		request.AddCookie(&http.Cookie{
			Name: sessionCookieName, Value: "operator-session-token",
		})
		request.AddCookie(&http.Cookie{
			Name: csrfCookieName, Value: manager.csrfToken,
		})
		response := httptest.NewRecorder()
		router.ServeHTTP(response, request)
		if response.Code != http.StatusForbidden {
			t.Errorf(
				"%s %s as operator returned %d, want 403; body=%s",
				route.Method,
				route.Path,
				response.Code,
				response.Body.String(),
			)
		}
	}
	if checked < 7 {
		t.Fatalf("administrator-only route inventory = %d, want at least 7", checked)
	}
}

func TestRawSampleDownloadRouteIsAbsentByDefault(t *testing.T) {
	manager := &authManagerStub{session: auth.Session{
		ID: "administrator-session",
		User: auth.Principal{
			UserID: 1, PublicID: "administrator-id",
			Role: auth.RoleAdministrator,
		},
	}}
	router := completePolicyTestRouter(t, manager)
	for _, route := range router.Routes() {
		if strings.Contains(route.Path, "/download") &&
			!strings.Contains(route.Path, "/reports/") {
			t.Fatalf("unexpected non-report download route: %s %s", route.Method, route.Path)
		}
	}

	request := httptest.NewRequest(
		http.MethodGet,
		"/api/v1/tasks/1/sample/download",
		nil,
	)
	request.AddCookie(&http.Cookie{
		Name: sessionCookieName, Value: "administrator-session-token",
	})
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusNotFound {
		t.Fatalf(
			"raw sample download status = %d, want 404; body=%s",
			response.Code,
			response.Body.String(),
		)
	}
}

func TestEnabledRawSampleDownloadRoutePolicyMatrix(t *testing.T) {
	tests := []struct {
		name        string
		role        auth.Role
		withSession bool
		status      int
		serviceCall int
	}{
		{
			name: "anonymous", status: http.StatusUnauthorized,
		},
		{
			name: "reader", role: auth.RoleReader, withSession: true,
			status: http.StatusForbidden,
		},
		{
			name: "operator", role: auth.RoleOperator, withSession: true,
			status: http.StatusForbidden,
		},
		{
			name: "administrator", role: auth.RoleAdministrator,
			withSession: true, status: http.StatusNotFound, serviceCall: 1,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			manager := &authManagerStub{}
			if test.withSession {
				manager.session = auth.Session{
					ID: "policy-session",
					User: auth.Principal{
						UserID: 1, PublicID: "policy-user",
						Role: test.role,
					},
					ExpiresAt: time.Now().Add(time.Hour),
				}
			}
			service := &sampleExportServiceStub{
				err: sampleexport.ErrNotFound,
			}
			router, err := NewRouter(Dependencies{
				Logger: slog.New(
					slog.NewJSONHandler(io.Discard, nil),
				),
				Database: readinessStub{}, ReadinessTimeout: time.Second,
				Auth: manager,
				AuthHTTP: AuthHTTPConfig{
					SessionTTL: time.Hour,
				},
				SampleExport: service, SampleExportEnabled: true,
				Build: buildinfo.Current(),
			})
			if err != nil {
				t.Fatal(err)
			}
			found := false
			for _, route := range router.Routes() {
				if route.Method == http.MethodGet &&
					route.Path == "/api/v1/tasks/:id/sample/download" {
					found = true
				}
			}
			if !found {
				t.Fatal("enabled raw sample download route is absent")
			}
			request := httptest.NewRequest(
				http.MethodGet,
				"/api/v1/tasks/"+sampleExportTaskID+"/sample/download",
				nil,
			)
			if test.withSession {
				request.AddCookie(&http.Cookie{
					Name: sessionCookieName, Value: "policy-token",
				})
			}
			response := httptest.NewRecorder()
			router.ServeHTTP(response, request)
			if response.Code != test.status ||
				service.calls != test.serviceCall {
				t.Fatalf(
					"status/calls = %d/%d, want %d/%d; body=%s",
					response.Code,
					service.calls,
					test.status,
					test.serviceCall,
					response.Body.String(),
				)
			}
		})
	}
}

func completePolicyTestRouter(
	t *testing.T,
	manager AuthManager,
) *gin.Engine {
	t.Helper()
	router, err := NewRouter(Dependencies{
		Logger:           slog.New(slog.NewJSONHandler(io.Discard, nil)),
		Database:         readinessStub{},
		ReadinessTimeout: time.Second,
		Auth:             manager,
		AuthHTTP: AuthHTTPConfig{
			SessionTTL: time.Hour,
		},
		Uploads:         &uploadServiceStub{},
		Tasks:           &taskServiceStub{},
		TaskEvents:      &taskEventServiceStub{},
		FileTree:        &fileTreeServiceStub{},
		Decompile:       &decompileServiceStub{},
		Vulnerabilities: &vulnerabilityServiceStub{},
		Reports:         &reportServiceStub{},
		UserAdmin:       &userAdminServiceStub{},
		AuditLogs:       &auditLogServiceStub{},
		SystemStatus:    &systemStatusServiceStub{},
		Build:           buildinfo.Current(),
	})
	if err != nil {
		t.Fatal(err)
	}
	return router
}

func concretePolicyPath(path string) string {
	parts := strings.Split(path, "/")
	for index, part := range parts {
		if strings.HasPrefix(part, ":") {
			parts[index] = "1"
		}
	}
	return strings.Join(parts, "/")
}

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
	"binaryscan/internal/systemstatus"

	"github.com/gin-gonic/gin"
)

type systemStatusServiceStub struct {
	value systemstatus.Status
	err   error
	calls int
}

func (s *systemStatusServiceStub) Get(
	context.Context,
) (systemstatus.Status, error) {
	s.calls++
	return s.value, s.err
}

func TestSystemStatusRouteRequiresAdministrator(t *testing.T) {
	service := &systemStatusServiceStub{value: testSystemStatus()}
	manager := &authManagerStub{session: auth.Session{
		ID: "session",
		User: auth.Principal{
			Role: auth.RoleReader,
		},
	}}
	router := systemStatusTestRouter(t, manager, service)

	request := httptest.NewRequest(
		http.MethodGet,
		"/api/v1/admin/system",
		nil,
	)
	request.AddCookie(&http.Cookie{Name: sessionCookieName, Value: "token"})
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusForbidden || service.calls != 0 {
		t.Fatalf(
			"reader status/calls = %d/%d; body=%s",
			response.Code,
			service.calls,
			response.Body.String(),
		)
	}
	if response.Header().Get("Cache-Control") != "private, no-store" ||
		response.Header().Get("Pragma") != "no-cache" {
		t.Fatalf("reader cache headers = %#v", response.Header())
	}

	manager.session.User.Role = auth.RoleAdministrator
	response = httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusOK || service.calls != 1 {
		t.Fatalf(
			"administrator status/calls = %d/%d; body=%s",
			response.Code,
			service.calls,
			response.Body.String(),
		)
	}
	if response.Header().Get("Cache-Control") != "private, no-store" ||
		response.Header().Get("Pragma") != "no-cache" {
		t.Fatalf("administrator cache headers = %#v", response.Header())
	}
	var payload Response
	if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	data, ok := payload.Data.(map[string]any)
	if !ok || data["service_status"] != systemstatus.ServiceDegraded ||
		data["version"] != "1.2.3" {
		t.Fatalf("response data = %#v", payload.Data)
	}
}

func TestSystemStatusHandlerRejectsQueryParameters(t *testing.T) {
	service := &systemStatusServiceStub{value: testSystemStatus()}
	router := gin.New()
	router.Use(RequestIDMiddleware())
	router.GET("/status", systemStatusHandler(service))
	response := httptest.NewRecorder()
	router.ServeHTTP(
		response,
		httptest.NewRequest(http.MethodGet, "/status?path=/etc", nil),
	)
	if response.Code != http.StatusBadRequest || service.calls != 0 ||
		!strings.Contains(response.Body.String(), "invalid_system_status_query") {
		t.Fatalf(
			"status/calls/body = %d/%d/%s",
			response.Code,
			service.calls,
			response.Body.String(),
		)
	}
}

func TestSystemStatusHandlerHidesCollectorErrors(t *testing.T) {
	service := &systemStatusServiceStub{
		err: errors.New("password=secret path=/private/repository"),
	}
	router := gin.New()
	router.Use(RequestIDMiddleware())
	router.GET("/status", systemStatusHandler(service))
	response := httptest.NewRecorder()
	router.ServeHTTP(
		response,
		httptest.NewRequest(http.MethodGet, "/status", nil),
	)
	if response.Code != http.StatusServiceUnavailable ||
		!strings.Contains(response.Body.String(), "system_status_unavailable") {
		t.Fatalf("status/body = %d/%s", response.Code, response.Body.String())
	}
	if strings.Contains(response.Body.String(), "password") ||
		strings.Contains(response.Body.String(), "/private") {
		t.Fatalf("collector error leaked in response: %s", response.Body.String())
	}
}

func systemStatusTestRouter(
	t *testing.T,
	manager AuthManager,
	service SystemStatusService,
) http.Handler {
	t.Helper()
	gin.SetMode(gin.ReleaseMode)
	router := gin.New()
	router.Use(
		RequestIDMiddleware(),
		AccessLogMiddleware(slog.New(slog.NewJSONHandler(io.Discard, nil))),
	)
	v1 := router.Group("/api/v1")
	registerSystemStatusRoutes(v1, manager, service)
	return router
}

func testSystemStatus() systemstatus.Status {
	collectedAt := time.Date(2026, 7, 30, 8, 0, 0, 0, time.UTC)
	return systemstatus.Status{
		Version: "1.2.3", Service: "api",
		ServiceStatus:       systemstatus.ServiceDegraded,
		Build:               systemstatus.Build{Version: "1.2.3"},
		Analyzers:           []systemstatus.Analyzer{},
		StorageMounts:       []systemstatus.StorageMount{},
		TrivyDatabaseBundle: nil,
		TaskCounts:          map[string]int64{"QUEUED": 0},
		WorkerSummary: systemstatus.WorkerSummary{
			LeasesByKind: map[string]int64{"scan": 0},
		},
		OperationalMetrics: systemstatus.OperationalMetrics{
			WindowHours:          168,
			StageDurations:       []systemstatus.StageDurationMetric{},
			AnalyzerFailureRates: []systemstatus.AnalyzerFailureMetric{},
		},
		CollectedAt: collectedAt,
		Diagnostics: []systemstatus.Diagnostic{{
			Code: "analyzer_unavailable", Severity: "warning",
			Component: "trivy", Message: "Analyzer is unavailable.",
			Remediation: "Install the analyzer.",
		}},
	}
}

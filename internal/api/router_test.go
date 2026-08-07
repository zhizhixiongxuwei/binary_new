package api

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"binaryscan/internal/buildinfo"
)

type readinessStub struct {
	err error
}

func (s readinessStub) PingContext(context.Context) error { return s.err }

func TestLiveEndpointReturnsEnvelopeAndRequestID(t *testing.T) {
	router := testRouter(t, readinessStub{})
	request := httptest.NewRequest(http.MethodGet, "/api/v1/health/live", nil)
	request.Header.Set("X-Request-ID", "test-request-1")
	response := httptest.NewRecorder()

	router.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusOK)
	}
	if got := response.Header().Get("X-Request-ID"); got != "test-request-1" {
		t.Fatalf("X-Request-ID = %q", got)
	}
	var body Response
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Meta.RequestID != "test-request-1" {
		t.Fatalf("request id = %q", body.Meta.RequestID)
	}
}

func TestReadyEndpointReflectsDatabaseState(t *testing.T) {
	tests := []struct {
		name    string
		checker ReadinessChecker
		status  int
	}{
		{name: "ready", checker: readinessStub{}, status: http.StatusOK},
		{name: "database unavailable", checker: readinessStub{err: errors.New("offline")}, status: http.StatusServiceUnavailable},
		{name: "database missing", checker: nil, status: http.StatusServiceUnavailable},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			router := testRouter(t, tt.checker)
			response := httptest.NewRecorder()
			router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/api/v1/health/ready", nil))
			if response.Code != tt.status {
				t.Fatalf("status = %d, want %d; body=%s", response.Code, tt.status, response.Body.String())
			}
		})
	}
}

func TestUnknownRouteUsesStructuredError(t *testing.T) {
	router := testRouter(t, readinessStub{})
	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/api/v1/unknown", nil))

	if response.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusNotFound)
	}
	var body ErrorResponse
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Error.Code != "route_not_found" || body.Meta.RequestID == "" {
		t.Fatalf("unexpected error response: %#v", body)
	}
}

func TestInvalidClientRequestIDIsReplaced(t *testing.T) {
	router := testRouter(t, readinessStub{})
	request := httptest.NewRequest(http.MethodGet, "/api/v1/health/live", nil)
	request.Header.Set("X-Request-ID", "invalid request id")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if got := response.Header().Get("X-Request-ID"); got == "" || got == "invalid request id" {
		t.Fatalf("X-Request-ID = %q, want generated id", got)
	}
}

func testRouter(t *testing.T, checker ReadinessChecker) http.Handler {
	t.Helper()
	logger := slog.New(slog.NewJSONHandler(io.Discard, nil))
	router, err := NewRouter(Dependencies{
		Logger:           logger,
		Database:         checker,
		ReadinessTimeout: time.Second,
		Build:            buildinfo.Current(),
	})
	if err != nil {
		t.Fatal(err)
	}
	return router
}

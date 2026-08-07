package api

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
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
	"binaryscan/internal/sampleexport"
)

const sampleExportTaskID = "00000000-0000-4000-8000-000000000001"

type sampleExportServiceStub struct {
	value  sampleexport.Download
	err    error
	calls  int
	taskID string
}

func (s *sampleExportServiceStub) Open(
	_ context.Context,
	taskID string,
) (sampleexport.Download, error) {
	s.calls++
	s.taskID = taskID
	return s.value, s.err
}

type testReadSeekCloser struct {
	*bytes.Reader
}

func (c testReadSeekCloser) Close() error { return nil }

func TestEnabledSampleExportReturnsVerifiedAttachmentMetadata(t *testing.T) {
	content := []byte("raw sample fixture")
	sum := sha256.Sum256(content)
	digest := hex.EncodeToString(sum[:])
	service := &sampleExportServiceStub{value: sampleexport.Download{
		Content:   testReadSeekCloser{bytes.NewReader(content)},
		SizeBytes: uint64(len(content)),
		SHA256:    digest,
		Filename:  `private-original"; filename="inline.html`,
	}}
	router := sampleExportRouter(
		t,
		auth.RoleAdministrator,
		service,
		nil,
	)
	request := httptest.NewRequest(
		http.MethodGet,
		"/api/v1/tasks/"+sampleExportTaskID+"/sample/download",
		nil,
	)
	request.AddCookie(&http.Cookie{
		Name: sessionCookieName, Value: "session-token",
	})
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)

	if response.Code != http.StatusOK ||
		response.Body.String() != string(content) ||
		service.calls != 1 ||
		service.taskID != sampleExportTaskID {
		t.Fatalf(
			"status/body/calls/task = %d/%q/%d/%q",
			response.Code,
			response.Body.String(),
			service.calls,
			service.taskID,
		)
	}
	expected := map[string]string{
		"Content-Type":           "application/octet-stream",
		"Content-Length":         "18",
		"Content-Disposition":    `attachment; filename="binaryscan-sample.bin"`,
		"X-Content-Type-Options": "nosniff",
		"Cache-Control":          "private, no-store",
		"ETag":                   `"` + digest + `"`,
		"Digest": "sha-256=" +
			base64.StdEncoding.EncodeToString(sum[:]),
		"X-Checksum-SHA256": digest,
	}
	for name, wanted := range expected {
		if actual := response.Header().Get(name); actual != wanted {
			t.Errorf("%s = %q, want %q", name, actual, wanted)
		}
	}
	headers := response.Header().Get("Content-Disposition")
	if strings.Contains(headers, "original") ||
		strings.Contains(headers, "/data/") {
		t.Fatalf("sample export headers exposed source metadata: %q", headers)
	}
}

func TestEnabledSampleExportRejectsQueryAndMapsSafeErrors(t *testing.T) {
	tests := []struct {
		name   string
		query  string
		err    error
		status int
		code   string
		calls  int
	}{
		{
			name: "query rejected", query: "?download=inline",
			status: http.StatusBadRequest,
			code:   "invalid_sample_export_request",
		},
		{
			name: "not found", err: sampleexport.ErrNotFound,
			status: http.StatusNotFound, code: "sample_not_available",
			calls: 1,
		},
		{
			name: "retention changed", err: sampleexport.ErrUnavailable,
			status: http.StatusNotFound, code: "sample_not_available",
			calls: 1,
		},
		{
			name: "integrity failed", err: sampleexport.ErrIntegrity,
			status: http.StatusConflict, code: "sample_integrity_failed",
			calls: 1,
		},
		{
			name: "database failed", err: errors.New("database failed"),
			status: http.StatusInternalServerError, code: "sample_export_failed",
			calls: 1,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			service := &sampleExportServiceStub{err: test.err}
			router := sampleExportRouter(
				t,
				auth.RoleAdministrator,
				service,
				nil,
			)
			request := httptest.NewRequest(
				http.MethodGet,
				"/api/v1/tasks/"+sampleExportTaskID+
					"/sample/download"+test.query,
				nil,
			)
			request.AddCookie(&http.Cookie{
				Name: sessionCookieName, Value: "session-token",
			})
			response := httptest.NewRecorder()
			router.ServeHTTP(response, request)
			if response.Code != test.status ||
				!strings.Contains(
					response.Body.String(),
					`"code":"`+test.code+`"`,
				) ||
				service.calls != test.calls {
				t.Fatalf(
					"status/body/calls = %d/%s/%d",
					response.Code,
					response.Body.String(),
					service.calls,
				)
			}
			if strings.Contains(response.Body.String(), "database failed") {
				t.Fatal("internal error leaked through sample export response")
			}
		})
	}
}

func TestEnabledSampleExportAuditsSuccessAndStreamFailure(t *testing.T) {
	tests := []struct {
		name    string
		content io.ReadSeeker
		size    uint64
		outcome string
		body    string
	}{
		{
			name:    "success",
			content: bytes.NewReader([]byte("sample")),
			size:    6, outcome: "success", body: "sample",
		},
		{
			name:    "truncated stream",
			content: bytes.NewReader([]byte("short")),
			size:    6, outcome: "failure", body: "short",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			recorder := &auditRecorderStub{}
			digest := strings.Repeat("a", 64)
			service := &sampleExportServiceStub{value: sampleexport.Download{
				Content: testReadSeekCloser{
					test.content.(*bytes.Reader),
				},
				SizeBytes: test.size,
				SHA256:    digest,
				Filename:  sampleexport.DownloadFilename,
			}}
			router := sampleExportRouter(
				t,
				auth.RoleAdministrator,
				service,
				recorder,
			)
			request := httptest.NewRequest(
				http.MethodGet,
				"/api/v1/tasks/"+sampleExportTaskID+"/sample/download",
				nil,
			)
			request.AddCookie(&http.Cookie{
				Name: sessionCookieName, Value: "session-token",
			})
			response := httptest.NewRecorder()
			router.ServeHTTP(response, request)
			if response.Code != http.StatusOK ||
				response.Body.String() != test.body ||
				strings.Contains(response.Body.String(), `"error"`) ||
				len(recorder.events) != 1 {
				t.Fatalf(
					"status/body/audit events = %d/%q/%d",
					response.Code,
					response.Body.String(),
					len(recorder.events),
				)
			}
			event := recorder.events[0]
			if event.Action != "sample.export" ||
				event.ObjectType != "task" ||
				event.ObjectID != sampleExportTaskID ||
				string(event.Outcome) != test.outcome {
				t.Fatalf("sample export audit = %+v", event)
			}
		})
	}
}

func TestRouterFailsClosedWhenEnabledSampleExportIsIncomplete(t *testing.T) {
	logger := slog.New(slog.NewJSONHandler(io.Discard, nil))
	for _, deps := range []Dependencies{
		{
			Logger: logger, SampleExportEnabled: true,
			SampleExport: &sampleExportServiceStub{},
		},
		{
			Logger: logger, SampleExportEnabled: true,
			Auth: &authManagerStub{},
		},
	} {
		if _, err := NewRouter(deps); err == nil {
			t.Fatal("NewRouter() error = nil for incomplete sample export")
		}
	}
}

func sampleExportRouter(
	t *testing.T,
	role auth.Role,
	service SampleExportService,
	recorder AuditRecorder,
) http.Handler {
	t.Helper()
	manager := &authManagerStub{session: auth.Session{
		ID: "session-id",
		User: auth.Principal{
			UserID: 1, PublicID: "user-id", Role: role,
		},
		ExpiresAt: time.Now().Add(time.Hour),
	}}
	router, err := NewRouter(Dependencies{
		Logger:   slog.New(slog.NewJSONHandler(io.Discard, nil)),
		Database: readinessStub{}, ReadinessTimeout: time.Second,
		Auth: manager,
		AuthHTTP: AuthHTTPConfig{
			SessionTTL: time.Hour,
		},
		SampleExport:        service,
		SampleExportEnabled: true,
		AuditRecorder:       recorder,
		Build:               buildinfo.Current(),
	})
	if err != nil {
		t.Fatal(err)
	}
	return router
}

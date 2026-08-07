package api

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"binaryscan/internal/auth"
	"binaryscan/internal/buildinfo"
	"binaryscan/internal/report"

	"github.com/gin-gonic/gin"
)

const (
	apiReportTaskID = "123e4567-e89b-42d3-a456-426614174000"
	apiReportID     = "223e4567-e89b-42d3-a456-426614174001"
)

type reportServiceStub struct {
	listTaskID       string
	list             report.List
	listErr          error
	generateTaskID   string
	generateFormat   report.Format
	idempotencyKey   string
	generated        report.Report
	generatedCreated bool
	generateErr      error
	generateCalls    int
	downloadTaskID   string
	downloadReportID string
	download         report.Download
	downloadErr      error
}

func (s *reportServiceStub) List(
	_ context.Context,
	taskID string,
) (report.List, error) {
	s.listTaskID = taskID
	return s.list, s.listErr
}

func (s *reportServiceStub) Generate(
	_ context.Context,
	taskID string,
	format report.Format,
	idempotencyKey string,
) (report.Report, bool, error) {
	s.generateCalls++
	s.generateTaskID = taskID
	s.generateFormat = format
	s.idempotencyKey = idempotencyKey
	return s.generated, s.generatedCreated, s.generateErr
}

func (s *reportServiceStub) Download(
	_ context.Context,
	taskID string,
	reportID string,
) (report.Download, error) {
	s.downloadTaskID = taskID
	s.downloadReportID = reportID
	return s.download, s.downloadErr
}

type memoryReadSeekCloser struct {
	*bytes.Reader
	closed bool
}

func (r *memoryReadSeekCloser) Close() error {
	r.closed = true
	return nil
}

func reportFixture() report.Report {
	digest := strings.Repeat("a", 64)
	size := uint64(42)
	completedAt := time.Date(2026, 7, 30, 12, 1, 0, 0, time.UTC)
	return report.Report{
		ID: apiReportID, TaskID: apiReportTaskID, Format: report.FormatJSON,
		SchemaVersion: report.SchemaVersion, Status: "complete",
		SHA256: &digest, SizeBytes: &size,
		CreatedAt:   time.Date(2026, 7, 30, 12, 0, 0, 0, time.UTC),
		CompletedAt: &completedAt,
	}
}

func TestListReportsAllowsEveryAuthenticatedRoleAndUsesEnvelope(t *testing.T) {
	for _, role := range []auth.Role{
		auth.RoleAdministrator, auth.RoleOperator, auth.RoleReader,
	} {
		t.Run(string(role), func(t *testing.T) {
			service := &reportServiceStub{
				list: report.List{
					Items:          []report.Report{reportFixture()},
					SampleRelation: "retained",
				},
			}
			router := reportTestRouter(
				&authManagerStub{session: auth.Session{
					User: auth.Principal{Role: role},
				}},
				service,
			)
			request := httptest.NewRequest(
				http.MethodGet,
				"/api/v1/tasks/"+apiReportTaskID+"/reports",
				nil,
			)
			request.AddCookie(&http.Cookie{
				Name: sessionCookieName, Value: "session-token",
			})
			response := httptest.NewRecorder()
			router.ServeHTTP(response, request)

			if response.Code != http.StatusOK {
				t.Fatalf("status = %d; body=%s", response.Code, response.Body.String())
			}
			if service.listTaskID != apiReportTaskID {
				t.Fatalf("list task ID = %q", service.listTaskID)
			}
			var body struct {
				Data report.List `json:"data"`
			}
			if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
				t.Fatal(err)
			}
			if len(body.Data.Items) != 1 ||
				body.Data.Items[0].ID != apiReportID {
				t.Fatalf("report list = %#v", body.Data)
			}
			lower := strings.ToLower(response.Body.String())
			if strings.Contains(lower, "storage_key") ||
				strings.Contains(lower, "storagekey") {
				t.Fatalf("list leaks storage key: %s", response.Body.String())
			}
		})
	}
}

func TestDownloadJSONReportStreamsDeterministicGzipRepresentation(t *testing.T) {
	content := []byte(`{"schemaVersion":"1.0.0","fileNodes":[{"format":"elf64"}]}`)
	reader := &memoryReadSeekCloser{Reader: bytes.NewReader(content)}
	service := &reportServiceStub{download: report.Download{
		Content: reader, ContentType: "application/json",
		Filename:  "binaryscan-" + apiReportTaskID + "-report.json",
		SHA256:    strings.Repeat("a", 64),
		SizeBytes: uint64(len(content)),
	}}
	router := reportTestRouter(
		&authManagerStub{session: auth.Session{
			User: auth.Principal{Role: auth.RoleReader},
		}},
		service,
	)
	request := httptest.NewRequest(
		http.MethodGet,
		"/api/v1/tasks/"+apiReportTaskID+"/reports/"+
			apiReportID+"/download?encoding=gzip",
		nil,
	)
	request.AddCookie(&http.Cookie{
		Name: sessionCookieName, Value: "session-token",
	})
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("download status = %d body %q", response.Code, response.Body.String())
	}
	compressed := response.Body.Bytes()
	uncompressed, err := gzip.NewReader(bytes.NewReader(compressed))
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := io.ReadAll(uncompressed)
	if err != nil {
		t.Fatal(err)
	}
	if err := uncompressed.Close(); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decoded, content) {
		t.Fatalf("decoded gzip = %q", decoded)
	}
	digest := sha256.Sum256(compressed)
	digestHex := hex.EncodeToString(digest[:])
	for name, expected := range map[string]string{
		"Content-Type":           "application/gzip",
		"Content-Length":         strconv.Itoa(len(compressed)),
		"Content-Disposition":    `attachment; filename="binaryscan-` + apiReportTaskID + `-report.json.gz"`,
		"X-Content-Type-Options": "nosniff",
		"Cache-Control":          "private, no-store",
		"ETag":                   `"` + digestHex + `"`,
		"Digest":                 "sha-256=" + base64.StdEncoding.EncodeToString(digest[:]),
		"X-Checksum-SHA256":      digestHex,
	} {
		if got := response.Header().Get(name); got != expected {
			t.Errorf("%s = %q, want %q", name, got, expected)
		}
	}
	if !reader.closed {
		t.Error("report reader was not closed")
	}
}

func TestDownloadReportRejectsUnknownEncodingBeforeOpeningArtifact(t *testing.T) {
	service := &reportServiceStub{}
	router := reportTestRouter(
		&authManagerStub{session: auth.Session{
			User: auth.Principal{Role: auth.RoleReader},
		}},
		service,
	)
	request := httptest.NewRequest(
		http.MethodGet,
		"/api/v1/tasks/"+apiReportTaskID+"/reports/"+
			apiReportID+"/download?encoding=br",
		nil,
	)
	request.AddCookie(&http.Cookie{
		Name: sessionCookieName, Value: "session-token",
	})
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)

	if response.Code != http.StatusBadRequest ||
		service.downloadTaskID != "" {
		t.Fatalf(
			"invalid encoding status/call = %d %q",
			response.Code, service.downloadTaskID,
		)
	}
}

func TestDownloadReportRejectsGzipForHTML(t *testing.T) {
	reader := &memoryReadSeekCloser{
		Reader: bytes.NewReader([]byte("<!doctype html>")),
	}
	service := &reportServiceStub{download: report.Download{
		Content: reader, ContentType: "text/html; charset=utf-8",
		Filename: "binaryscan-report.html",
		SHA256:   strings.Repeat("a", 64), SizeBytes: 15,
	}}
	router := reportTestRouter(
		&authManagerStub{session: auth.Session{
			User: auth.Principal{Role: auth.RoleReader},
		}},
		service,
	)
	request := httptest.NewRequest(
		http.MethodGet,
		"/api/v1/tasks/"+apiReportTaskID+"/reports/"+
			apiReportID+"/download?encoding=gzip",
		nil,
	)
	request.AddCookie(&http.Cookie{
		Name: sessionCookieName, Value: "session-token",
	})
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)

	if response.Code != http.StatusBadRequest || !reader.closed {
		t.Fatalf(
			"HTML gzip status/closed = %d %v",
			response.Code, reader.closed,
		)
	}
}

func TestGenerateReportRequiresRoleSessionCSRFAndStrictBody(t *testing.T) {
	tests := []struct {
		name       string
		role       auth.Role
		auth       bool
		csrf       bool
		body       string
		wantStatus int
		wantCalls  int
	}{
		{
			name: "operator", role: auth.RoleOperator, auth: true, csrf: true,
			body: `{"format":"json"}`, wantStatus: http.StatusCreated, wantCalls: 1,
		},
		{
			name: "administrator", role: auth.RoleAdministrator,
			auth: true, csrf: true, body: `{"format":"json"}`,
			wantStatus: http.StatusCreated, wantCalls: 1,
		},
		{
			name: "reader", role: auth.RoleReader, auth: true, csrf: true,
			body: `{"format":"json"}`, wantStatus: http.StatusForbidden,
		},
		{
			name: "missing csrf", role: auth.RoleOperator, auth: true,
			body: `{"format":"json"}`, wantStatus: http.StatusForbidden,
		},
		{
			name: "missing session", role: auth.RoleOperator, csrf: true,
			body: `{"format":"json"}`, wantStatus: http.StatusUnauthorized,
		},
		{
			name: "unknown field", role: auth.RoleOperator, auth: true, csrf: true,
			body:       `{"format":"json","storage_key":"secret"}`,
			wantStatus: http.StatusBadRequest,
		},
		{
			name: "trailing object", role: auth.RoleOperator, auth: true, csrf: true,
			body: `{"format":"json"}{}`, wantStatus: http.StatusBadRequest,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			service := &reportServiceStub{
				generated: reportFixture(), generatedCreated: true,
			}
			manager := &authManagerStub{
				session:   auth.Session{User: auth.Principal{Role: test.role}},
				csrfToken: "csrf-token",
			}
			router := reportTestRouter(manager, service)
			request := httptest.NewRequest(
				http.MethodPost,
				"/api/v1/tasks/"+apiReportTaskID+"/reports",
				strings.NewReader(test.body),
			)
			request.Header.Set("Content-Type", "application/json")
			request.Header.Set("Idempotency-Key", "report-key")
			if test.auth {
				request.AddCookie(&http.Cookie{
					Name: sessionCookieName, Value: "session-token",
				})
			}
			if test.csrf {
				request.AddCookie(&http.Cookie{
					Name: csrfCookieName, Value: "csrf-token",
				})
				request.Header.Set(csrfHeaderName, "csrf-token")
			}
			response := httptest.NewRecorder()
			router.ServeHTTP(response, request)
			if response.Code != test.wantStatus {
				t.Fatalf(
					"status = %d, want %d; body=%s",
					response.Code, test.wantStatus, response.Body.String(),
				)
			}
			if service.generateCalls != test.wantCalls {
				t.Fatalf("generate calls = %d", service.generateCalls)
			}
			if test.wantCalls == 1 &&
				(service.generateTaskID != apiReportTaskID ||
					service.generateFormat != report.FormatJSON ||
					service.idempotencyKey != "report-key") {
				t.Fatalf(
					"generate arguments = %q %q %q",
					service.generateTaskID, service.generateFormat,
					service.idempotencyKey,
				)
			}
		})
	}
}

func TestGenerateReportMapsConflicts(t *testing.T) {
	for _, test := range []struct {
		err  error
		code string
	}{
		{err: report.ErrTaskNotTerminal, code: "task_not_reportable"},
		{err: report.ErrGenerationInProgress, code: "report_generation_in_progress"},
		{err: report.ErrReportConflict, code: "report_conflict"},
	} {
		service := &reportServiceStub{generateErr: test.err}
		manager := &authManagerStub{
			session:   auth.Session{User: auth.Principal{Role: auth.RoleOperator}},
			csrfToken: "csrf-token",
		}
		router := reportTestRouter(manager, service)
		request := httptest.NewRequest(
			http.MethodPost,
			"/api/v1/tasks/"+apiReportTaskID+"/reports",
			strings.NewReader(`{"format":"html"}`),
		)
		addAuthAndCSRF(request, "csrf-token")
		request.Header.Set("Idempotency-Key", "report-key")
		response := httptest.NewRecorder()
		router.ServeHTTP(response, request)
		if response.Code != http.StatusConflict {
			t.Fatalf("status = %d; body=%s", response.Code, response.Body.String())
		}
		var body ErrorResponse
		if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		if body.Error.Code != test.code {
			t.Fatalf("error code = %q, want %q", body.Error.Code, test.code)
		}
	}
}

func TestGenerateReportRejectsInvalidFormatAndIdempotencyKeyBeforeService(
	t *testing.T,
) {
	tests := []struct {
		name string
		body string
		key  string
	}{
		{name: "format", body: `{"format":"xml"}`, key: "key"},
		{name: "missing key", body: `{"format":"json"}`},
		{name: "control key", body: `{"format":"html"}`, key: "bad\nkey"},
		{
			name: "long key", body: `{"format":"json"}`,
			key: strings.Repeat("x", 129),
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			service := &reportServiceStub{}
			manager := &authManagerStub{
				session: auth.Session{
					User: auth.Principal{Role: auth.RoleOperator},
				},
				csrfToken: "csrf-token",
			}
			router := reportTestRouter(manager, service)
			request := httptest.NewRequest(
				http.MethodPost,
				"/api/v1/tasks/"+apiReportTaskID+"/reports",
				strings.NewReader(test.body),
			)
			addAuthAndCSRF(request, "csrf-token")
			request.Header.Set("Idempotency-Key", test.key)
			response := httptest.NewRecorder()
			router.ServeHTTP(response, request)
			if response.Code != http.StatusBadRequest ||
				service.generateCalls != 0 {
				t.Fatalf(
					"response = %d %s, calls=%d",
					response.Code, response.Body.String(),
					service.generateCalls,
				)
			}
		})
	}
}

func TestDownloadReportStreamsRawFileWithSecurityHeadersForEveryRole(
	t *testing.T,
) {
	content := []byte(`{"schemaVersion":"1.0.0"}`)
	for _, role := range []auth.Role{
		auth.RoleAdministrator, auth.RoleOperator, auth.RoleReader,
	} {
		t.Run(string(role), func(t *testing.T) {
			reader := &memoryReadSeekCloser{
				Reader: bytes.NewReader(content),
			}
			service := &reportServiceStub{download: report.Download{
				Content: reader, ContentType: "application/json",
				Filename:  "binaryscan-" + apiReportTaskID + "-report.json",
				SHA256:    strings.Repeat("a", 64),
				SizeBytes: uint64(len(content)),
			}}
			router := reportTestRouter(
				&authManagerStub{session: auth.Session{
					User: auth.Principal{Role: role},
				}},
				service,
			)
			request := httptest.NewRequest(
				http.MethodGet,
				"/api/v1/tasks/"+apiReportTaskID+"/reports/"+
					apiReportID+"/download",
				nil,
			)
			request.AddCookie(&http.Cookie{
				Name: sessionCookieName, Value: "session-token",
			})
			response := httptest.NewRecorder()
			router.ServeHTTP(response, request)

			if response.Code != http.StatusOK ||
				!bytes.Equal(response.Body.Bytes(), content) {
				t.Fatalf(
					"download = status %d body %q",
					response.Code, response.Body.Bytes(),
				)
			}
			for name, expected := range map[string]string{
				"Content-Type":           "application/json",
				"Content-Length":         "25",
				"X-Content-Type-Options": "nosniff",
				"ETag":                   `"` + strings.Repeat("a", 64) + `"`,
				"X-Checksum-SHA256":      strings.Repeat("a", 64),
			} {
				if got := response.Header().Get(name); got != expected {
					t.Errorf("%s = %q, want %q", name, got, expected)
				}
			}
			if got := response.Header().Get("Content-Disposition"); got !=
				`attachment; filename="binaryscan-`+
					apiReportTaskID+`-report.json"` {
				t.Errorf("Content-Disposition = %q", got)
			}
			if response.Header().Get("Digest") == "" {
				t.Error("Digest header is empty")
			}
			if service.downloadTaskID != apiReportTaskID ||
				service.downloadReportID != apiReportID ||
				!reader.closed {
				t.Fatalf(
					"download arguments/close = %q %q %v",
					service.downloadTaskID, service.downloadReportID,
					reader.closed,
				)
			}
			if bytes.Contains(response.Body.Bytes(), []byte(`"data"`)) {
				t.Fatalf("download was wrapped in API envelope: %s", response.Body.Bytes())
			}
		})
	}
}

func TestReportAPINotFoundMappings(t *testing.T) {
	for _, test := range []struct {
		target string
		err    error
		code   string
	}{
		{
			target: "/api/v1/tasks/" + apiReportTaskID + "/reports",
			err:    report.ErrTaskNotFound, code: "task_not_found",
		},
		{
			target: "/api/v1/tasks/" + apiReportTaskID + "/reports/" +
				apiReportID + "/download",
			err: report.ErrReportNotFound, code: "report_not_found",
		},
	} {
		service := &reportServiceStub{}
		if test.err == report.ErrTaskNotFound {
			service.listErr = test.err
		} else {
			service.downloadErr = test.err
		}
		router := reportTestRouter(
			&authManagerStub{session: auth.Session{
				User: auth.Principal{Role: auth.RoleReader},
			}},
			service,
		)
		request := httptest.NewRequest(http.MethodGet, test.target, nil)
		request.AddCookie(&http.Cookie{
			Name: sessionCookieName, Value: "session-token",
		})
		response := httptest.NewRecorder()
		router.ServeHTTP(response, request)
		if response.Code != http.StatusNotFound {
			t.Fatalf("status = %d; body=%s", response.Code, response.Body.String())
		}
		var body ErrorResponse
		if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		if body.Error.Code != test.code {
			t.Fatalf("error code = %q, want %q", body.Error.Code, test.code)
		}
	}
}

func TestNewRouterWiresReportRoutesAlongsideCoreRoutes(t *testing.T) {
	service := &reportServiceStub{list: report.List{Items: []report.Report{}}}
	router, err := NewRouter(Dependencies{
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		Auth: &authManagerStub{session: auth.Session{
			User: auth.Principal{Role: auth.RoleReader},
		}},
		Reports: service,
		Build:   buildinfo.Current(),
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, target := range []string{
		"/api/v1/tasks/" + apiReportTaskID + "/reports",
		"/api/v1/health/live",
	} {
		request := httptest.NewRequest(http.MethodGet, target, nil)
		request.AddCookie(&http.Cookie{
			Name: sessionCookieName, Value: "session-token",
		})
		response := httptest.NewRecorder()
		router.ServeHTTP(response, request)
		if response.Code != http.StatusOK {
			t.Fatalf(
				"%s status = %d; body=%s",
				target, response.Code, response.Body.String(),
			)
		}
	}
}

func reportTestRouter(
	manager AuthManager,
	service ReportService,
) http.Handler {
	gin.SetMode(gin.ReleaseMode)
	router := gin.New()
	router.Use(
		RequestIDMiddleware(),
		AccessLogMiddleware(slog.New(slog.NewTextHandler(io.Discard, nil))),
	)
	registerReportRoutes(router.Group("/api/v1"), manager, service)
	return router
}

var _ ReportService = (*reportServiceStub)(nil)

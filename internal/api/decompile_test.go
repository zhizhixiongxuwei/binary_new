package api

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"binaryscan/internal/auth"
	"binaryscan/internal/decompile"

	"github.com/gin-gonic/gin"
)

const (
	decompileTaskTestID    = "123e4567-e89b-42d3-a456-426614174000"
	decompileResultTestID  = "223e4567-e89b-42d3-a456-426614174001"
	decompileJobTestID     = "323e4567-e89b-42d3-a456-426614174002"
	decompileRequestTestID = "423e4567-e89b-42d3-a456-426614174003"
)

func decompileCursorTestValue() string {
	return base64.RawURLEncoding.EncodeToString([]byte(
		`{"created_at":"2026-07-30T02:03:04Z","id":"` +
			decompileResultTestID + `"}`,
	))
}

type decompileServiceStub struct {
	createInput  decompile.CreateInput
	request      decompile.Request
	createErr    error
	created      bool
	createCalls  int
	requestQuery decompile.RequestQuery
	requestErr   error
	requestCalls int
	listQuery    decompile.ListQuery
	page         decompile.Page
	listErr      error
	listCalls    int
	sourceQuery  decompile.SourceQuery
	chunk        decompile.SourceChunk
	sourceErr    error
	sourceCalls  int
	archiveQuery decompile.SourceArchiveQuery
	archive      decompile.SourceArchive
	archiveErr   error
	archiveCalls int
}

type decompileRepositoryStub struct {
	listCalls int
}

type decompileArchiveReader struct {
	*bytes.Reader
	closed bool
}

func (reader *decompileArchiveReader) Close() error {
	reader.closed = true
	return nil
}

func (s *decompileRepositoryStub) GetRequest(
	_ context.Context,
	_ decompile.RequestQuery,
) (decompile.Request, error) {
	return decompile.Request{}, nil
}

func (s *decompileRepositoryStub) Enqueue(
	_ context.Context,
	_ decompile.CreateRecord,
) (decompile.Request, bool, error) {
	return decompile.Request{}, false, nil
}

func (s *decompileRepositoryStub) List(
	_ context.Context,
	_ decompile.ListQuery,
) (decompile.Page, error) {
	s.listCalls++
	return decompile.Page{}, nil
}

func (s *decompileRepositoryStub) GetSource(
	_ context.Context,
	_ decompile.SourceQuery,
) (decompile.SourceDescriptor, error) {
	return decompile.SourceDescriptor{}, nil
}

func (s *decompileServiceStub) List(
	_ context.Context,
	query decompile.ListQuery,
) (decompile.Page, error) {
	s.listCalls++
	s.listQuery = query
	return s.page, s.listErr
}

func (s *decompileServiceStub) Create(
	_ context.Context,
	input decompile.CreateInput,
) (decompile.Request, bool, error) {
	s.createCalls++
	s.createInput = input
	return s.request, s.created, s.createErr
}

func (s *decompileServiceStub) GetRequest(
	_ context.Context,
	query decompile.RequestQuery,
) (decompile.Request, error) {
	s.requestCalls++
	s.requestQuery = query
	return s.request, s.requestErr
}

func (s *decompileServiceStub) Source(
	_ context.Context,
	query decompile.SourceQuery,
) (decompile.SourceChunk, error) {
	s.sourceCalls++
	s.sourceQuery = query
	return s.chunk, s.sourceErr
}

func (s *decompileServiceStub) ExportSources(
	_ context.Context,
	query decompile.SourceArchiveQuery,
) (decompile.SourceArchive, error) {
	s.archiveCalls++
	s.archiveQuery = query
	return s.archive, s.archiveErr
}

func TestDownloadDecompileSourcesStreamsTaskCurrentArchive(t *testing.T) {
	payload := []byte("PK\x03\x04fixture-archive")
	digest := sha256.Sum256(payload)
	reader := &decompileArchiveReader{Reader: bytes.NewReader(payload)}
	service := &decompileServiceStub{archive: decompile.SourceArchive{
		Content:  reader,
		Filename: "binaryscan-" + decompileTaskTestID + "-decompile-sources.zip",
		SHA256:   hex.EncodeToString(digest[:]), SizeBytes: uint64(len(payload)),
		ResultCount: 2084,
	}}
	router := decompileTestRouter(
		&authManagerStub{session: auth.Session{
			User: auth.Principal{Role: auth.RoleReader},
		}},
		service,
		discardLogger(),
	)
	response := httptest.NewRecorder()
	router.ServeHTTP(
		response,
		authenticatedDecompileRequest(
			"/api/v1/tasks/"+decompileTaskTestID+
				"/decompile-sources.zip?combined=true",
		),
	)

	if response.Code != http.StatusOK ||
		!bytes.Equal(response.Body.Bytes(), payload) || !reader.closed {
		t.Fatalf(
			"archive status/body/closed = %d/%q/%v",
			response.Code, response.Body.Bytes(), reader.closed,
		)
	}
	if service.archiveCalls != 1 ||
		service.archiveQuery.TaskID != decompileTaskTestID ||
		!service.archiveQuery.IncludeCombined {
		t.Fatalf("archive query = %#v", service.archiveQuery)
	}
	for name, want := range map[string]string{
		"Content-Type":   "application/zip",
		"Content-Length": strconv.Itoa(len(payload)),
		"Content-Disposition": `attachment; filename="binaryscan-` +
			decompileTaskTestID + `-decompile-sources.zip"`,
		"X-Content-Type-Options":   "nosniff",
		"Cache-Control":            "private, no-store",
		"ETag":                     `"` + hex.EncodeToString(digest[:]) + `"`,
		"Digest":                   "sha-256=" + base64.StdEncoding.EncodeToString(digest[:]),
		"X-Checksum-SHA256":        hex.EncodeToString(digest[:]),
		"X-Decompile-Result-Count": "2084",
	} {
		if got := response.Header().Get(name); got != want {
			t.Errorf("%s = %q, want %q", name, got, want)
		}
	}
}

func TestDownloadDecompileSourcesRejectsInvalidQueryAndMapsLimit(t *testing.T) {
	manager := &authManagerStub{session: auth.Session{
		User: auth.Principal{Role: auth.RoleReader},
	}}
	service := &decompileServiceStub{}
	router := decompileTestRouter(manager, service, discardLogger())
	invalid := httptest.NewRecorder()
	router.ServeHTTP(
		invalid,
		authenticatedDecompileRequest(
			"/api/v1/tasks/"+decompileTaskTestID+
				"/decompile-sources.zip?combined=false",
		),
	)
	assertDecompileError(t, invalid, http.StatusBadRequest, "invalid_query")
	if service.archiveCalls != 0 {
		t.Fatal("invalid archive query reached service")
	}

	service.archiveErr = decompile.ErrExportTooLarge
	tooLarge := httptest.NewRecorder()
	router.ServeHTTP(
		tooLarge,
		authenticatedDecompileRequest(
			"/api/v1/tasks/"+decompileTaskTestID+"/decompile-sources.zip",
		),
	)
	assertDecompileError(
		t, tooLarge, http.StatusRequestEntityTooLarge,
		"decompile_export_too_large",
	)
}

func TestCreateDecompileRequiresWriteRoleCSRFAndStrictRequest(t *testing.T) {
	tests := []struct {
		name       string
		role       auth.Role
		auth       bool
		csrf       bool
		body       string
		nodeID     string
		query      string
		keys       []string
		wantStatus int
		wantCalls  int
	}{
		{
			name: "operator", role: auth.RoleOperator, auth: true, csrf: true,
			body:   `{"engine_target":"auto","options":{"symbols":["public"]}}`,
			nodeID: "42", keys: []string{"decompile-key"},
			wantStatus: http.StatusCreated, wantCalls: 1,
		},
		{
			name: "administrator", role: auth.RoleAdministrator,
			auth: true, csrf: true, body: `{}`, nodeID: "42",
			keys:       []string{"decompile-key"},
			wantStatus: http.StatusCreated, wantCalls: 1,
		},
		{
			name: "reader", role: auth.RoleReader, auth: true, csrf: true,
			body: `{}`, nodeID: "42", keys: []string{"decompile-key"},
			wantStatus: http.StatusForbidden,
		},
		{
			name: "missing csrf", role: auth.RoleOperator, auth: true,
			body: `{}`, nodeID: "42", keys: []string{"decompile-key"},
			wantStatus: http.StatusForbidden,
		},
		{
			name: "missing session", role: auth.RoleOperator, csrf: true,
			body: `{}`, nodeID: "42", keys: []string{"decompile-key"},
			wantStatus: http.StatusUnauthorized,
		},
		{
			name: "unknown field", role: auth.RoleOperator, auth: true, csrf: true,
			body: `{"storage_key":"secret"}`, nodeID: "42",
			keys:       []string{"decompile-key"},
			wantStatus: http.StatusBadRequest,
		},
		{
			name: "trailing value", role: auth.RoleOperator, auth: true, csrf: true,
			body: `{}{}`, nodeID: "42", keys: []string{"decompile-key"},
			wantStatus: http.StatusBadRequest,
		},
		{
			name: "missing idempotency key", role: auth.RoleOperator,
			auth: true, csrf: true, body: `{}`, nodeID: "42",
			wantStatus: http.StatusBadRequest,
		},
		{
			name: "duplicate idempotency key", role: auth.RoleOperator,
			auth: true, csrf: true, body: `{}`, nodeID: "42",
			keys: []string{"one", "two"}, wantStatus: http.StatusBadRequest,
		},
		{
			name: "noncanonical node", role: auth.RoleOperator,
			auth: true, csrf: true, body: `{}`, nodeID: "042",
			keys: []string{"key"}, wantStatus: http.StatusBadRequest,
		},
		{
			name: "query rejected", role: auth.RoleOperator,
			auth: true, csrf: true, body: `{}`, nodeID: "42", query: "?force=true",
			keys: []string{"key"}, wantStatus: http.StatusBadRequest,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			service := &decompileServiceStub{
				request: decompile.Request{
					RequestID:  decompileRequestTestID,
					JobID:      decompileJobTestID,
					TaskID:     decompileTaskTestID,
					FileNodeID: "42",
					Status:     "queued",
				},
				created: true,
			}
			manager := &authManagerStub{
				session: auth.Session{User: auth.Principal{
					UserID: 7,
					Role:   test.role,
				}},
				csrfToken: "csrf-token",
			}
			router := decompileTestRouter(
				manager,
				service,
				slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil)),
			)
			target := "/api/v1/tasks/" + decompileTaskTestID +
				"/files/" + test.nodeID + "/decompile" + test.query
			request := httptest.NewRequest(
				http.MethodPost,
				target,
				strings.NewReader(test.body),
			)
			request.Header.Set("Content-Type", "application/json")
			for _, key := range test.keys {
				request.Header.Add("Idempotency-Key", key)
			}
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
					response.Code,
					test.wantStatus,
					response.Body.String(),
				)
			}
			if service.createCalls != test.wantCalls {
				t.Fatalf(
					"Create() calls = %d, want %d",
					service.createCalls,
					test.wantCalls,
				)
			}
			if test.wantCalls == 1 &&
				(service.createInput.TaskID != decompileTaskTestID ||
					service.createInput.FileNodeID != 42 ||
					service.createInput.UserID != 7 ||
					service.createInput.Role != test.role ||
					service.createInput.IdempotencyKey != "decompile-key") {
				t.Fatalf("Create() input = %#v", service.createInput)
			}
		})
	}
}

func TestCreateDecompileMapsDomainConflicts(t *testing.T) {
	tests := []struct {
		err    error
		status int
		code   string
	}{
		{decompile.ErrTaskNotFound, http.StatusNotFound, "task_not_found"},
		{decompile.ErrFileNodeNotFound, http.StatusNotFound, "file_node_not_found"},
		{decompile.ErrUnsupportedTarget, http.StatusUnprocessableEntity, "decompile_target_unsupported"},
		{decompile.ErrSourceUnavailable, http.StatusConflict, "decompile_source_unavailable"},
		{decompile.ErrSampleUnavailable, http.StatusConflict, "task_sample_unavailable"},
		{decompile.ErrTaskStateConflict, http.StatusConflict, "task_state_conflict"},
		{decompile.ErrDecompileInProgress, http.StatusConflict, "decompile_in_progress"},
		{decompile.ErrRequestConflict, http.StatusConflict, "idempotency_conflict"},
	}
	for _, test := range tests {
		service := &decompileServiceStub{createErr: test.err}
		router := decompileTestRouter(
			&authManagerStub{
				session: auth.Session{User: auth.Principal{
					UserID: 7,
					Role:   auth.RoleOperator,
				}},
				csrfToken: "csrf-token",
			},
			service,
			slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil)),
		)
		request := httptest.NewRequest(
			http.MethodPost,
			"/api/v1/tasks/"+decompileTaskTestID+
				"/files/42/decompile",
			strings.NewReader(`{}`),
		)
		request.AddCookie(&http.Cookie{
			Name: sessionCookieName, Value: "session-token",
		})
		request.AddCookie(&http.Cookie{
			Name: csrfCookieName, Value: "csrf-token",
		})
		request.Header.Set(csrfHeaderName, "csrf-token")
		request.Header.Set("Idempotency-Key", "key")
		response := httptest.NewRecorder()
		router.ServeHTTP(response, request)
		assertDecompileError(t, response, test.status, test.code)
	}
}

func TestGetDecompileRequestStatusAllowsAuthenticatedRoles(t *testing.T) {
	completedAt := time.Date(2026, 8, 3, 22, 16, 43, 0, time.UTC)
	for _, role := range []auth.Role{
		auth.RoleAdministrator,
		auth.RoleOperator,
		auth.RoleReader,
	} {
		t.Run(string(role), func(t *testing.T) {
			service := &decompileServiceStub{request: decompile.Request{
				RequestID:   decompileRequestTestID,
				JobID:       decompileJobTestID,
				TaskID:      decompileTaskTestID,
				FileNodeID:  "42",
				Status:      "succeeded",
				CompletedAt: &completedAt,
			}}
			router := decompileTestRouter(
				&authManagerStub{session: auth.Session{
					User: auth.Principal{UserID: 7, Role: role},
				}},
				service,
				discardLogger(),
			)
			response := httptest.NewRecorder()
			router.ServeHTTP(
				response,
				authenticatedDecompileRequest(
					"/api/v1/tasks/"+decompileTaskTestID+
						"/decompile-jobs/"+decompileJobTestID,
				),
			)

			if response.Code != http.StatusOK {
				t.Fatalf("status = %d; body=%s", response.Code, response.Body.String())
			}
			if service.requestCalls != 1 ||
				service.requestQuery.TaskID != decompileTaskTestID ||
				service.requestQuery.JobID != decompileJobTestID {
				t.Fatalf("GetRequest() query = %#v", service.requestQuery)
			}
			if !strings.Contains(response.Body.String(), `"status":"succeeded"`) ||
				!strings.Contains(response.Body.String(), `"completed_at"`) {
				t.Fatalf("response = %s", response.Body.String())
			}
		})
	}
}

func TestGetDecompileRequestStatusMapsNotFoundAndRejectsQuery(t *testing.T) {
	tests := []struct {
		name       string
		target     string
		err        error
		wantStatus int
		wantCode   string
		wantCalls  int
	}{
		{
			name: "not found",
			target: "/api/v1/tasks/" + decompileTaskTestID +
				"/decompile-jobs/" + decompileJobTestID,
			err:        decompile.ErrRequestNotFound,
			wantStatus: http.StatusNotFound,
			wantCode:   "decompile_request_not_found",
			wantCalls:  1,
		},
		{
			name: "query rejected",
			target: "/api/v1/tasks/" + decompileTaskTestID +
				"/decompile-jobs/" + decompileJobTestID + "?verbose=true",
			wantStatus: http.StatusBadRequest,
			wantCode:   "invalid_query",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			service := &decompileServiceStub{requestErr: test.err}
			router := decompileTestRouter(
				&authManagerStub{session: auth.Session{
					User: auth.Principal{Role: auth.RoleReader},
				}},
				service,
				discardLogger(),
			)
			response := httptest.NewRecorder()
			router.ServeHTTP(response, authenticatedDecompileRequest(test.target))
			assertDecompileError(t, response, test.wantStatus, test.wantCode)
			if service.requestCalls != test.wantCalls {
				t.Fatalf("GetRequest() calls = %d, want %d", service.requestCalls, test.wantCalls)
			}
		})
	}
}

func TestListDecompileResultsAllowsEveryAuthenticatedRole(t *testing.T) {
	roles := []auth.Role{
		auth.RoleAdministrator,
		auth.RoleOperator,
		auth.RoleReader,
	}
	for _, role := range roles {
		t.Run(string(role), func(t *testing.T) {
			cursor := decompileCursorTestValue()
			size := uint64(173)
			completedAt := time.Date(2026, 7, 30, 2, 4, 6, 0, time.UTC)
			service := &decompileServiceStub{page: decompile.Page{
				Items: []decompile.Result{{
					ID: decompileResultTestID, FileNodeID: "42",
					SymbolKey: "FUN_00401000", SymbolKind: "function",
					DisplayName: "parse_header", GroupName: "app",
					Location: "0x00401000", Signature: "int parse_header(void)",
					Detail: "native function", Language: "c",
					EngineName: "ghidra", EngineVersion: "11.4",
					Status: "complete", SizeBytes: &size,
					Diagnostics: json.RawMessage(`{"warnings":[]}`),
					CreatedAt: time.Date(
						2026, 7, 30, 2, 3, 4, 0, time.UTC,
					),
					CompletedAt: &completedAt,
				}},
				NextCursor: cursor,
			}}
			router := decompileTestRouter(
				&authManagerStub{session: auth.Session{
					User: auth.Principal{UserID: 7, Role: role},
				}},
				service,
				discardLogger(),
			)
			response := httptest.NewRecorder()
			router.ServeHTTP(
				response,
				authenticatedDecompileRequest(
					"/api/v1/tasks/"+decompileTaskTestID+
						"/decompile-results?cursor="+
						cursor+"&page_size=25",
				),
			)

			if response.Code != http.StatusOK {
				t.Fatalf(
					"status = %d; body=%s",
					response.Code,
					response.Body.String(),
				)
			}
			if service.listCalls != 1 ||
				service.listQuery.TaskID != decompileTaskTestID ||
				service.listQuery.Cursor != cursor ||
				service.listQuery.PageSize != 25 {
				t.Fatalf("service query = %#v", service.listQuery)
			}
			var body struct {
				Data decompile.Page `json:"data"`
			}
			if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
				t.Fatal(err)
			}
			if len(body.Data.Items) != 1 ||
				body.Data.NextCursor != cursor {
				t.Fatalf("response page = %#v", body.Data)
			}
			result := body.Data.Items[0]
			if result.ID != decompileResultTestID ||
				result.FileNodeID != "42" ||
				result.SymbolKind != "function" ||
				result.DisplayName != "parse_header" ||
				result.EngineName != "ghidra" ||
				result.SizeBytes == nil || *result.SizeBytes != size ||
				string(result.Diagnostics) != `{"warnings":[]}` ||
				result.CompletedAt == nil ||
				!result.CompletedAt.Equal(completedAt) {
				t.Fatalf("response result = %#v", result)
			}
		})
	}
}

func TestListDecompileResultsUsesDefaultsAndOmitsEmptyCursor(
	t *testing.T,
) {
	service := &decompileServiceStub{page: decompile.Page{
		Items: []decompile.Result{},
	}}
	router := decompileTestRouter(
		&authManagerStub{session: auth.Session{
			User: auth.Principal{Role: auth.RoleReader},
		}},
		service,
		discardLogger(),
	)
	response := httptest.NewRecorder()
	router.ServeHTTP(
		response,
		authenticatedDecompileRequest(
			"/api/v1/tasks/"+decompileTaskTestID+"/decompile-results",
		),
	)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d; body=%s", response.Code, response.Body.String())
	}
	if service.listQuery.Cursor != "" ||
		service.listQuery.PageSize != decompile.DefaultPageSize {
		t.Fatalf("default query = %#v", service.listQuery)
	}
	if strings.Contains(response.Body.String(), "next_cursor") {
		t.Fatalf(
			"empty next cursor must be omitted: %s",
			response.Body.String(),
		)
	}
}

func TestListDecompileResultsRejectsMalformedQueryBeforeService(
	t *testing.T,
) {
	tests := []string{
		"?unknown=1",
		"?cursor=",
		"?cursor=one&cursor=two",
		"?page_size=",
		"?page_size=0",
		"?page_size=-1",
		"?page_size=1.5",
		"?page_size=201",
		"?page_size=1&page_size=2",
		"?page_size=18446744073709551616",
	}
	for _, suffix := range tests {
		t.Run(suffix, func(t *testing.T) {
			service := &decompileServiceStub{}
			router := decompileTestRouter(
				&authManagerStub{session: auth.Session{
					User: auth.Principal{Role: auth.RoleReader},
				}},
				service,
				discardLogger(),
			)
			response := httptest.NewRecorder()
			router.ServeHTTP(
				response,
				authenticatedDecompileRequest(
					"/api/v1/tasks/"+decompileTaskTestID+
						"/decompile-results"+suffix,
				),
			)
			assertDecompileError(
				t,
				response,
				http.StatusBadRequest,
				"invalid_query",
			)
			if service.listCalls != 0 {
				t.Fatalf("service calls = %d, want 0", service.listCalls)
			}
		})
	}
}

func TestListDecompileResultsRejectsInvalidOpaqueCursor(t *testing.T) {
	repository := &decompileRepositoryStub{}
	service, err := decompile.NewService(
		repository,
		decompile.Config{RepositoryRoot: t.TempDir()},
	)
	if err != nil {
		t.Fatal(err)
	}
	router := decompileTestRouter(
		&authManagerStub{session: auth.Session{
			User: auth.Principal{Role: auth.RoleReader},
		}},
		service,
		discardLogger(),
	)
	response := httptest.NewRecorder()
	router.ServeHTTP(
		response,
		authenticatedDecompileRequest(
			"/api/v1/tasks/"+decompileTaskTestID+
				"/decompile-results?cursor="+decompileResultTestID,
		),
	)

	assertDecompileError(
		t,
		response,
		http.StatusBadRequest,
		"invalid_query",
	)
	if repository.listCalls != 0 {
		t.Fatalf("repository calls = %d, want 0", repository.listCalls)
	}
}

func TestGetDecompileSourceForwardsRangeAndReturnsChunk(t *testing.T) {
	nextOffset := uint64(4099)
	service := &decompileServiceStub{chunk: decompile.SourceChunk{
		ResultID:   decompileResultTestID,
		Offset:     3,
		Content:    "int main(void) {\n",
		NextOffset: &nextOffset,
		Complete:   false,
		SHA256:     strings.Repeat("a", 64),
		SizeBytes:  8192,
	}}
	router := decompileTestRouter(
		&authManagerStub{session: auth.Session{
			User: auth.Principal{Role: auth.RoleReader},
		}},
		service,
		discardLogger(),
	)
	response := httptest.NewRecorder()
	router.ServeHTTP(
		response,
		authenticatedDecompileRequest(
			"/api/v1/tasks/"+decompileTaskTestID+
				"/decompile-results/"+decompileResultTestID+
				"/source?offset=3&limit=4096",
		),
	)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d; body=%s", response.Code, response.Body.String())
	}
	if service.sourceCalls != 1 ||
		service.sourceQuery.TaskID != decompileTaskTestID ||
		service.sourceQuery.ResultID != decompileResultTestID ||
		service.sourceQuery.Offset != 3 ||
		service.sourceQuery.Limit != 4096 {
		t.Fatalf("service query = %#v", service.sourceQuery)
	}
	var body struct {
		Data decompile.SourceChunk `json:"data"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Data.ResultID != decompileResultTestID ||
		body.Data.Content != "int main(void) {\n" ||
		body.Data.NextOffset == nil ||
		*body.Data.NextOffset != nextOffset ||
		body.Data.Complete ||
		body.Data.SizeBytes != 8192 {
		t.Fatalf("response chunk = %#v", body.Data)
	}
}

func TestGetDecompileSourceUsesDefaultRange(t *testing.T) {
	service := &decompileServiceStub{chunk: decompile.SourceChunk{
		ResultID: decompileResultTestID,
		Complete: true,
		SHA256:   strings.Repeat("b", 64),
	}}
	router := decompileTestRouter(
		&authManagerStub{session: auth.Session{
			User: auth.Principal{Role: auth.RoleReader},
		}},
		service,
		discardLogger(),
	)
	response := httptest.NewRecorder()
	router.ServeHTTP(
		response,
		authenticatedDecompileRequest(
			"/api/v1/tasks/"+decompileTaskTestID+
				"/decompile-results/"+decompileResultTestID+"/source",
		),
	)
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d; body=%s", response.Code, response.Body.String())
	}
	if service.sourceQuery.Offset != 0 ||
		service.sourceQuery.Limit != decompile.DefaultSourceLimit {
		t.Fatalf("default source query = %#v", service.sourceQuery)
	}
	if strings.Contains(response.Body.String(), "next_offset") {
		t.Fatalf(
			"complete chunk must omit next_offset: %s",
			response.Body.String(),
		)
	}
}

func TestGetDecompileSourceRejectsMalformedQueryBeforeService(
	t *testing.T,
) {
	tests := []string{
		"?unknown=1",
		"?offset=",
		"?offset=-1",
		"?offset=1.5",
		"?offset=1&offset=2",
		"?offset=18446744073709551616",
		"?limit=",
		"?limit=0",
		"?limit=-1",
		"?limit=1048577",
		"?limit=1&limit=2",
		"?limit=18446744073709551616",
	}
	for _, suffix := range tests {
		t.Run(suffix, func(t *testing.T) {
			service := &decompileServiceStub{}
			router := decompileTestRouter(
				&authManagerStub{session: auth.Session{
					User: auth.Principal{Role: auth.RoleReader},
				}},
				service,
				discardLogger(),
			)
			response := httptest.NewRecorder()
			router.ServeHTTP(
				response,
				authenticatedDecompileRequest(
					"/api/v1/tasks/"+decompileTaskTestID+
						"/decompile-results/"+decompileResultTestID+
						"/source"+suffix,
				),
			)
			assertDecompileError(
				t,
				response,
				http.StatusBadRequest,
				"invalid_query",
			)
			if service.sourceCalls != 0 {
				t.Fatalf("service calls = %d, want 0", service.sourceCalls)
			}
		})
	}
}

func TestDecompileRoutesMapDomainErrors(t *testing.T) {
	tests := []struct {
		name      string
		source    bool
		err       error
		status    int
		errorCode string
	}{
		{
			name: "invalid list query", err: decompile.ErrInvalidInput,
			status: http.StatusBadRequest, errorCode: "invalid_query",
		},
		{
			name: "missing list task", err: decompile.ErrTaskNotFound,
			status: http.StatusNotFound, errorCode: "task_not_found",
		},
		{
			name: "invalid source query", source: true,
			err:    decompile.ErrInvalidInput,
			status: http.StatusBadRequest, errorCode: "invalid_query",
		},
		{
			name: "missing source task", source: true,
			err:    decompile.ErrTaskNotFound,
			status: http.StatusNotFound, errorCode: "task_not_found",
		},
		{
			name: "missing result", source: true,
			err:    decompile.ErrResultNotFound,
			status: http.StatusNotFound, errorCode: "result_not_found",
		},
		{
			name: "unavailable source", source: true,
			err:    decompile.ErrSourceUnavailable,
			status: http.StatusConflict, errorCode: "source_unavailable",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			service := &decompileServiceStub{}
			target := "/api/v1/tasks/" + decompileTaskTestID +
				"/decompile-results"
			if test.source {
				service.sourceErr = test.err
				target += "/" + decompileResultTestID + "/source"
			} else {
				service.listErr = test.err
			}
			router := decompileTestRouter(
				&authManagerStub{session: auth.Session{
					User: auth.Principal{Role: auth.RoleReader},
				}},
				service,
				discardLogger(),
			)
			response := httptest.NewRecorder()
			router.ServeHTTP(
				response,
				authenticatedDecompileRequest(target),
			)
			assertDecompileError(
				t,
				response,
				test.status,
				test.errorCode,
			)
		})
	}
}

func TestDecompileRoutesRequireAuthentication(t *testing.T) {
	tests := []string{
		"/api/v1/tasks/" + decompileTaskTestID + "/decompile-jobs/" +
			decompileJobTestID,
		"/api/v1/tasks/" + decompileTaskTestID + "/decompile-results",
		"/api/v1/tasks/" + decompileTaskTestID + "/decompile-results/" +
			decompileResultTestID + "/source",
		"/api/v1/tasks/" + decompileTaskTestID + "/decompile-sources.zip",
	}
	for _, target := range tests {
		t.Run(target, func(t *testing.T) {
			service := &decompileServiceStub{}
			router := decompileTestRouter(
				&authManagerStub{},
				service,
				discardLogger(),
			)
			response := httptest.NewRecorder()
			router.ServeHTTP(
				response,
				httptest.NewRequest(http.MethodGet, target, nil),
			)
			if response.Code != http.StatusUnauthorized ||
				service.requestCalls != 0 || service.listCalls != 0 ||
				service.sourceCalls != 0 || service.archiveCalls != 0 {
				t.Fatalf(
					"status/request/list/source calls = %d/%d/%d/%d",
					response.Code, service.requestCalls,
					service.listCalls,
					service.sourceCalls,
				)
			}
		})
	}
}

func TestDecompileRoutesShareTheExistingTaskWildcard(t *testing.T) {
	gin.SetMode(gin.ReleaseMode)
	router := gin.New()
	v1 := router.Group("/api/v1")
	manager := &authManagerStub{}
	var fileTreeService FileTreeService

	defer func() {
		if recovered := recover(); recovered != nil {
			t.Fatalf("registering task result routes panicked: %v", recovered)
		}
	}()
	registerFileTreeRoutes(v1, manager, fileTreeService)
	registerDecompileRoutes(v1, manager, &decompileServiceStub{})
}

func TestDecompileRoutesDoNotExposePrivateErrors(t *testing.T) {
	const privateDetail = "mysql decompile failed: private diagnostic"
	tests := []struct {
		name   string
		source bool
		code   string
	}{
		{
			name: "list failure",
			code: "decompile_results_failed",
		},
		{
			name: "source failure", source: true,
			code: "decompile_source_failed",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			service := &decompileServiceStub{}
			target := "/api/v1/tasks/" + decompileTaskTestID +
				"/decompile-results"
			if test.source {
				service.sourceErr = errors.New(privateDetail)
				target += "/" + decompileResultTestID + "/source"
			} else {
				service.listErr = errors.New(privateDetail)
			}
			var output bytes.Buffer
			logger := slog.New(slog.NewJSONHandler(&output, nil))
			router := decompileTestRouter(
				&authManagerStub{session: auth.Session{
					User: auth.Principal{Role: auth.RoleReader},
				}},
				service,
				logger,
			)
			response := httptest.NewRecorder()
			router.ServeHTTP(
				response,
				authenticatedDecompileRequest(target),
			)
			assertDecompileError(
				t,
				response,
				http.StatusInternalServerError,
				test.code,
			)
			if strings.Contains(response.Body.String(), privateDetail) {
				t.Fatal("private service error leaked into response")
			}
			if log := output.String(); !strings.Contains(log, privateDetail) ||
				!strings.Contains(log, `"level":"ERROR"`) {
				t.Fatalf("private error was not logged: %s", log)
			}
		})
	}
}

func authenticatedDecompileRequest(target string) *http.Request {
	request := httptest.NewRequest(http.MethodGet, target, nil)
	request.AddCookie(&http.Cookie{
		Name: sessionCookieName, Value: "session-token",
	})
	return request
}

func decompileTestRouter(
	manager AuthManager,
	service DecompileService,
	logger *slog.Logger,
) http.Handler {
	gin.SetMode(gin.ReleaseMode)
	router := gin.New()
	router.Use(
		RequestIDMiddleware(),
		AccessLogMiddleware(logger),
		RecoveryMiddleware(logger),
	)
	registerDecompileRoutes(router.Group("/api/v1"), manager, service)
	return router
}

func assertDecompileError(
	t *testing.T,
	response *httptest.ResponseRecorder,
	status int,
	code string,
) {
	t.Helper()
	if response.Code != status {
		t.Fatalf(
			"status = %d, want %d; body=%s",
			response.Code,
			status,
			response.Body.String(),
		)
	}
	var body ErrorResponse
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Error.Code != code {
		t.Fatalf("error code = %q, want %q", body.Error.Code, code)
	}
}

var _ DecompileService = (*decompileServiceStub)(nil)

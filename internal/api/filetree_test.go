package api

import (
	"bytes"
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
	"binaryscan/internal/filetree"
)

type fileTreeServiceStub struct {
	query    filetree.ListQuery
	page     filetree.Page
	err      error
	calls    int
	getQuery filetree.GetQuery
	detail   filetree.Detail
	getErr   error
	getCalls int
}

func (s *fileTreeServiceStub) List(
	_ context.Context,
	query filetree.ListQuery,
) (filetree.Page, error) {
	s.calls++
	s.query = query
	return s.page, s.err
}

func (s *fileTreeServiceStub) Get(
	_ context.Context,
	query filetree.GetQuery,
) (filetree.Detail, error) {
	s.getCalls++
	s.getQuery = query
	return s.detail, s.getErr
}

func TestListFileNodesAllowsEveryAuthenticatedRole(t *testing.T) {
	roles := []auth.Role{
		auth.RoleAdministrator,
		auth.RoleOperator,
		auth.RoleReader,
	}
	for _, role := range roles {
		t.Run(string(role), func(t *testing.T) {
			parent := "41"
			size := uint64(8192)
			service := &fileTreeServiceStub{page: filetree.Page{
				Items: []filetree.Node{{
					ID: "51", ParentID: &parent, LogicalPath: "/bin/app",
					DisplayName: "app", NodeType: "file", Depth: 1,
					Format: "elf64", MIMEType: "application/x-elf",
					Architecture: "x86_64", SizeBytes: &size,
					SHA256: strings.Repeat("a", 64), ExtractionStatus: "indexed",
					SourceContainer: &filetree.SourceContainer{
						ID: "1", LogicalPath: "/", Format: "zip",
					},
					HasChildren: true,
				}},
				NextCursor: "51",
			}}
			manager := &authManagerStub{session: auth.Session{
				User: auth.Principal{UserID: 7, Role: role},
			}}
			router := fileTreeTestRouter(t, manager, service, discardLogger())
			request := authenticatedFileTreeRequest(
				"/api/v1/tasks/123e4567-e89b-42d3-a456-426614174000/files" +
					"?parent_id=41&cursor=50&page_size=2",
			)
			response := httptest.NewRecorder()
			router.ServeHTTP(response, request)

			if response.Code != http.StatusOK {
				t.Fatalf("status = %d; body=%s", response.Code, response.Body.String())
			}
			if service.calls != 1 || service.query.TaskID !=
				"123e4567-e89b-42d3-a456-426614174000" ||
				service.query.ParentID == nil || *service.query.ParentID != 41 ||
				service.query.Cursor != 50 || service.query.PageSize != 2 {
				t.Fatalf("service query = %#v", service.query)
			}
			var body struct {
				Data struct {
					Items      []map[string]any `json:"items"`
					NextCursor string           `json:"next_cursor"`
				} `json:"data"`
			}
			if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
				t.Fatal(err)
			}
			if len(body.Data.Items) != 1 || body.Data.NextCursor != "51" {
				t.Fatalf("response data = %#v", body.Data)
			}
			for _, field := range []string{
				"id", "parent_id", "logical_path", "display_name",
				"archive_name_id", "node_type", "depth", "format", "mime_type",
				"architecture", "size_bytes", "sha256", "extraction_status",
				"error_code", "error_message", "source_container",
				"has_children",
			} {
				if _, ok := body.Data.Items[0][field]; !ok {
					t.Errorf("response node omits %q", field)
				}
			}
		})
	}
}

func TestGetFileNodeAllowsEveryAuthenticatedRoleAndReturnsStructuredDetail(
	t *testing.T,
) {
	roles := []auth.Role{
		auth.RoleAdministrator,
		auth.RoleOperator,
		auth.RoleReader,
	}
	for _, role := range roles {
		t.Run(string(role), func(t *testing.T) {
			parentID := "41"
			size := uint64(8192)
			service := &fileTreeServiceStub{detail: filetree.Detail{
				Node: filetree.Node{
					ID: "51", ParentID: &parentID, LogicalPath: "/bin/app",
					DisplayName: "app", NodeType: "file", Depth: 2,
					Format: "elf64", MIMEType: "application/x-elf",
					Architecture: "x86_64", SizeBytes: &size,
					SHA256: strings.Repeat("a", 64), ExtractionStatus: "indexed",
					SourceContainer: &filetree.SourceContainer{
						ID: "1", LogicalPath: "/", Format: "zip",
					},
					HasChildren: true,
				},
				MetadataJSON: json.RawMessage(
					`{"detection":{"compiler":"gcc"}}`,
				),
				SourceParent: &filetree.SourceParent{
					ID: "41", LogicalPath: "/bin",
				},
			}}
			manager := &authManagerStub{session: auth.Session{
				User: auth.Principal{UserID: 7, Role: role},
			}}
			router := fileTreeTestRouter(t, manager, service, discardLogger())
			request := authenticatedFileTreeRequest(
				"/api/v1/tasks/123e4567-e89b-42d3-a456-426614174000/files/51",
			)
			response := httptest.NewRecorder()
			router.ServeHTTP(response, request)

			if response.Code != http.StatusOK {
				t.Fatalf(
					"status = %d; body=%s",
					response.Code,
					response.Body.String(),
				)
			}
			if service.getCalls != 1 ||
				service.getQuery.TaskID !=
					"123e4567-e89b-42d3-a456-426614174000" ||
				service.getQuery.FileID != 51 {
				t.Fatalf("service query = %#v", service.getQuery)
			}
			var body struct {
				Data map[string]any `json:"data"`
			}
			if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
				t.Fatal(err)
			}
			metadata, metadataOK := body.Data["metadata_json"].(map[string]any)
			sourceParent, parentOK := body.Data["source_parent"].(map[string]any)
			sourceContainer, sourceOK := body.Data["source_container"].(map[string]any)
			if !metadataOK || metadata["detection"] == nil ||
				!parentOK || sourceParent["id"] != "41" ||
				sourceParent["logical_path"] != "/bin" ||
				!sourceOK || sourceContainer["id"] != "1" ||
				sourceContainer["logical_path"] != "/" ||
				sourceContainer["format"] != "zip" {
				t.Fatalf("response data = %#v", body.Data)
			}
			for _, forbidden := range []string{
				"storage_key", "work_dir", "absolute_path",
			} {
				if strings.Contains(response.Body.String(), forbidden) {
					t.Fatalf(
						"response exposes %q: %s",
						forbidden,
						response.Body.String(),
					)
				}
			}
		})
	}
}

func TestListFileNodesDefaultsToRootPage(t *testing.T) {
	service := &fileTreeServiceStub{page: filetree.Page{
		Items: []filetree.Node{{
			ID:               "1",
			LogicalPath:      "/",
			DisplayName:      "sample.zip",
			NodeType:         "file",
			Format:           "zip",
			ExtractionStatus: "extracted",
		}},
	}}
	manager := &authManagerStub{session: auth.Session{
		User: auth.Principal{Role: auth.RoleReader},
	}}
	router := fileTreeTestRouter(t, manager, service, discardLogger())
	request := authenticatedFileTreeRequest(
		"/api/v1/tasks/123e4567-e89b-42d3-a456-426614174000/files",
	)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d; body=%s", response.Code, response.Body.String())
	}
	if service.query.ParentID != nil || service.query.Cursor != 0 ||
		service.query.PageSize != defaultFileTreePageSize {
		t.Fatalf("default query = %#v", service.query)
	}
	if strings.Contains(response.Body.String(), "next_cursor") {
		t.Fatalf("empty next cursor must be omitted: %s", response.Body.String())
	}
	var body struct {
		Data struct {
			Items []map[string]any `json:"items"`
		} `json:"data"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if len(body.Data.Items) != 1 ||
		body.Data.Items[0]["source_container"] != nil {
		t.Fatalf("root source container = %#v", body.Data.Items)
	}
}

func TestListFileNodesRejectsMalformedQueryBeforeService(t *testing.T) {
	tests := []string{
		"?unknown=1",
		"?parent_id=1&parent_id=2",
		"?parent_id=",
		"?parent_id=0",
		"?parent_id=-1",
		"?parent_id=+1",
		"?parent_id=%201",
		"?cursor=0",
		"?cursor=1.5",
		"?cursor=18446744073709551616",
		"?page_size=0",
		"?page_size=201",
		"?page_size=1&page_size=2",
	}
	for _, suffix := range tests {
		t.Run(suffix, func(t *testing.T) {
			service := &fileTreeServiceStub{}
			manager := &authManagerStub{session: auth.Session{
				User: auth.Principal{Role: auth.RoleReader},
			}}
			router := fileTreeTestRouter(t, manager, service, discardLogger())
			request := authenticatedFileTreeRequest(
				"/api/v1/tasks/123e4567-e89b-42d3-a456-426614174000/files" + suffix,
			)
			response := httptest.NewRecorder()
			router.ServeHTTP(response, request)
			if response.Code != http.StatusBadRequest {
				t.Fatalf("status = %d; body=%s", response.Code, response.Body.String())
			}
			if service.calls != 0 {
				t.Fatalf("service calls = %d, want 0", service.calls)
			}
		})
	}
}

func TestListFileNodesMapsValidationAndMissingErrors(t *testing.T) {
	tests := []struct {
		name string
		err  error
		code int
	}{
		{name: "invalid task UUID", err: filetree.ErrInvalidInput, code: http.StatusBadRequest},
		{name: "missing task or parent", err: filetree.ErrNotFound, code: http.StatusNotFound},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			service := &fileTreeServiceStub{err: test.err}
			manager := &authManagerStub{session: auth.Session{
				User: auth.Principal{Role: auth.RoleReader},
			}}
			router := fileTreeTestRouter(t, manager, service, discardLogger())
			request := authenticatedFileTreeRequest(
				"/api/v1/tasks/not-a-uuid/files",
			)
			response := httptest.NewRecorder()
			router.ServeHTTP(response, request)
			if response.Code != test.code {
				t.Fatalf("status = %d; body=%s", response.Code, response.Body.String())
			}
		})
	}
}

func TestListFileNodesRequiresAuthentication(t *testing.T) {
	service := &fileTreeServiceStub{}
	manager := &authManagerStub{}
	router := fileTreeTestRouter(t, manager, service, discardLogger())
	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(
		http.MethodGet,
		"/api/v1/tasks/123e4567-e89b-42d3-a456-426614174000/files",
		nil,
	))
	if response.Code != http.StatusUnauthorized || service.calls != 0 {
		t.Fatalf("status/calls = %d/%d", response.Code, service.calls)
	}
}

func TestListFileNodesDoesNotExposePrivateErrors(t *testing.T) {
	const privateDetail = "mysql file tree failed: private diagnostic"
	service := &fileTreeServiceStub{err: errors.New(privateDetail)}
	manager := &authManagerStub{session: auth.Session{
		User: auth.Principal{Role: auth.RoleReader},
	}}
	var output bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&output, nil))
	router := fileTreeTestRouter(t, manager, service, logger)
	request := authenticatedFileTreeRequest(
		"/api/v1/tasks/123e4567-e89b-42d3-a456-426614174000/files",
	)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d; body=%s", response.Code, response.Body.String())
	}
	if strings.Contains(response.Body.String(), privateDetail) {
		t.Fatal("private repository error leaked into response")
	}
	if log := output.String(); !strings.Contains(log, privateDetail) ||
		!strings.Contains(log, `"level":"ERROR"`) {
		t.Fatalf("private error was not logged: %s", log)
	}
}

func TestGetFileNodeRejectsMalformedFileIDAndQueryBeforeService(t *testing.T) {
	targets := []string{
		"/files/0",
		"/files/01",
		"/files/-1",
		"/files/+1",
		"/files/1.5",
		"/files/18446744073709551616",
		"/files/51?unexpected=1",
	}
	for _, target := range targets {
		t.Run(target, func(t *testing.T) {
			service := &fileTreeServiceStub{}
			manager := &authManagerStub{session: auth.Session{
				User: auth.Principal{Role: auth.RoleReader},
			}}
			router := fileTreeTestRouter(t, manager, service, discardLogger())
			request := authenticatedFileTreeRequest(
				"/api/v1/tasks/123e4567-e89b-42d3-a456-426614174000" +
					target,
			)
			response := httptest.NewRecorder()
			router.ServeHTTP(response, request)
			if response.Code != http.StatusBadRequest || service.getCalls != 0 {
				t.Fatalf(
					"status/calls = %d/%d; body=%s",
					response.Code,
					service.getCalls,
					response.Body.String(),
				)
			}
		})
	}
}

func TestParseFileNodeIDAcceptsMaximumUnsignedDecimal(t *testing.T) {
	const raw = "18446744073709551615"
	value, err := parseFileNodeID(raw)
	if err != nil || value != ^uint64(0) {
		t.Fatalf("parseFileNodeID(%q) = %d, %v", raw, value, err)
	}
}

func TestGetFileNodeDistinguishesValidationTaskAndNodeErrors(t *testing.T) {
	tests := []struct {
		name       string
		target     string
		err        error
		status     int
		errorCode  string
		errorWords string
	}{
		{
			name: "invalid task UUID", target: "/api/v1/tasks/not-a-uuid/files/51",
			err: filetree.ErrInvalidInput, status: http.StatusBadRequest,
			errorCode: "invalid_file_detail_request",
		},
		{
			name:   "missing task",
			target: "/api/v1/tasks/123e4567-e89b-42d3-a456-426614174000/files/51",
			err:    filetree.ErrTaskNotFound, status: http.StatusNotFound,
			errorCode: "file_detail_task_not_found", errorWords: "task",
		},
		{
			name:   "missing node",
			target: "/api/v1/tasks/123e4567-e89b-42d3-a456-426614174000/files/51",
			err:    filetree.ErrNodeNotFound, status: http.StatusNotFound,
			errorCode: "file_node_not_found", errorWords: "file node",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			service := &fileTreeServiceStub{getErr: test.err}
			manager := &authManagerStub{session: auth.Session{
				User: auth.Principal{Role: auth.RoleReader},
			}}
			router := fileTreeTestRouter(t, manager, service, discardLogger())
			response := httptest.NewRecorder()
			router.ServeHTTP(
				response,
				authenticatedFileTreeRequest(test.target),
			)
			if response.Code != test.status {
				t.Fatalf(
					"status = %d; body=%s",
					response.Code,
					response.Body.String(),
				)
			}
			var body ErrorResponse
			if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
				t.Fatal(err)
			}
			if body.Error.Code != test.errorCode ||
				(test.errorWords != "" &&
					!strings.Contains(
						strings.ToLower(body.Error.Message),
						test.errorWords,
					)) {
				t.Fatalf("error body = %#v", body)
			}
		})
	}
}

func TestGetFileNodeRequiresAuthentication(t *testing.T) {
	service := &fileTreeServiceStub{}
	router := fileTreeTestRouter(
		t,
		&authManagerStub{},
		service,
		discardLogger(),
	)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(
		http.MethodGet,
		"/api/v1/tasks/123e4567-e89b-42d3-a456-426614174000/files/51",
		nil,
	))
	if response.Code != http.StatusUnauthorized || service.getCalls != 0 {
		t.Fatalf("status/calls = %d/%d", response.Code, service.getCalls)
	}
}

func authenticatedFileTreeRequest(target string) *http.Request {
	request := httptest.NewRequest(http.MethodGet, target, nil)
	request.AddCookie(&http.Cookie{Name: sessionCookieName, Value: "session-token"})
	return request
}

func fileTreeTestRouter(
	t *testing.T,
	manager AuthManager,
	service FileTreeService,
	logger *slog.Logger,
) http.Handler {
	t.Helper()
	router, err := NewRouter(Dependencies{
		Logger: logger, Database: readinessStub{}, ReadinessTimeout: time.Second,
		Auth: manager, AuthHTTP: AuthHTTPConfig{SessionTTL: time.Hour},
		FileTree: service, Build: buildinfo.Current(),
	})
	if err != nil {
		t.Fatal(err)
	}
	return router
}

func discardLogger() *slog.Logger {
	return slog.New(slog.NewJSONHandler(io.Discard, nil))
}

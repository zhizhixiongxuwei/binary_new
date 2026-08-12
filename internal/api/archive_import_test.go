package api

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"binaryscan/internal/archiveimport"
	"binaryscan/internal/auth"

	"github.com/gin-gonic/gin"
)

const (
	apiArchiveImportID = "71111111-1111-4111-8111-111111111111"
	apiArchiveEntryID  = "72222222-2222-4222-8222-222222222222"
)

type archiveImportServiceStub struct {
	principal auth.Principal
	listQuery archiveimport.ImportListQuery
	batch     archiveimport.BatchInput
	result    archiveimport.BatchResult
	created   bool
	err       error
	calls     int
}

func (stub *archiveImportServiceStub) ListImports(
	_ context.Context,
	query archiveimport.ImportListQuery,
	principal auth.Principal,
) (archiveimport.ImportPage, error) {
	stub.principal = principal
	stub.listQuery = query
	return archiveimport.ImportPage{Items: []archiveimport.Import{{
		ID: apiArchiveImportID, Status: archiveimport.StatusRunning,
	}}}, stub.err
}

func (stub *archiveImportServiceStub) Get(
	_ context.Context,
	_ string,
	principal auth.Principal,
) (archiveimport.Import, error) {
	stub.principal = principal
	return archiveimport.Import{ID: apiArchiveImportID, Status: archiveimport.StatusReady}, stub.err
}

func (stub *archiveImportServiceStub) ListEntries(
	_ context.Context,
	_ string,
	_ archiveimport.EntryListQuery,
	principal auth.Principal,
) (archiveimport.EntryPage, error) {
	stub.principal = principal
	return archiveimport.EntryPage{Items: []archiveimport.Entry{}}, stub.err
}

func (stub *archiveImportServiceStub) CreateBatch(
	_ context.Context,
	input archiveimport.BatchInput,
) (archiveimport.BatchResult, bool, error) {
	stub.calls++
	stub.batch = input
	return stub.result, stub.created, stub.err
}

func TestCreateArchiveImportBatchEnforcesCSRFRoleAndIdempotency(t *testing.T) {
	for _, test := range []struct {
		name       string
		role       auth.Role
		csrf       bool
		key        string
		wantStatus int
		wantCalls  int
	}{
		{"operator", auth.RoleOperator, true, "batch-key", http.StatusCreated, 1},
		{"administrator", auth.RoleAdministrator, true, "batch-key", http.StatusCreated, 1},
		{"reader", auth.RoleReader, true, "batch-key", http.StatusForbidden, 0},
		{"missing csrf", auth.RoleOperator, false, "batch-key", http.StatusForbidden, 0},
		{"missing key", auth.RoleOperator, true, "", http.StatusBadRequest, 0},
	} {
		t.Run(test.name, func(t *testing.T) {
			service := &archiveImportServiceStub{
				created: true,
				result: archiveimport.BatchResult{Items: []archiveimport.BatchItem{{
					EntryID: apiArchiveEntryID, Outcome: archiveimport.OutcomeCreated,
					TaskID: "73333333-3333-4333-8333-333333333333",
				}}},
			}
			manager := &authManagerStub{
				session: auth.Session{User: auth.Principal{
					UserID: 9, Role: test.role,
				}},
				csrfToken: "csrf-token",
			}
			router := archiveImportTestRouter(manager, service)
			request := httptest.NewRequest(
				http.MethodPost,
				"/api/v1/archive-imports/"+apiArchiveImportID+"/task-batches",
				strings.NewReader(`{"entry_ids":["`+apiArchiveEntryID+`"]}`),
			)
			request.AddCookie(&http.Cookie{Name: sessionCookieName, Value: "session-token"})
			if test.key != "" {
				request.Header.Set("Idempotency-Key", test.key)
			}
			if test.csrf {
				request.AddCookie(&http.Cookie{Name: csrfCookieName, Value: "csrf-token"})
				request.Header.Set(csrfHeaderName, "csrf-token")
			}
			response := httptest.NewRecorder()
			router.ServeHTTP(response, request)
			if response.Code != test.wantStatus || service.calls != test.wantCalls {
				t.Fatalf("status=%d calls=%d body=%s", response.Code, service.calls, response.Body.String())
			}
			if service.calls == 1 &&
				(service.batch.CreatedBy != 9 || service.batch.Role != test.role ||
					service.batch.ImportID != apiArchiveImportID ||
					service.batch.IdempotencyKey != "batch-key") {
				t.Fatalf("batch input = %+v", service.batch)
			}
		})
	}
}

func TestListArchiveImportsUsesOwnerPrincipalAndBoundedCursorQuery(t *testing.T) {
	service := &archiveImportServiceStub{}
	manager := &authManagerStub{session: auth.Session{User: auth.Principal{
		UserID: 19, Role: auth.RoleOperator,
	}}}
	router := archiveImportTestRouter(manager, service)
	request := httptest.NewRequest(
		http.MethodGet, "/api/v1/archive-imports?page_size=50&cursor=opaque", nil,
	)
	request.AddCookie(&http.Cookie{Name: sessionCookieName, Value: "session-token"})
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	if service.principal.UserID != 19 || service.principal.Role != auth.RoleOperator ||
		service.listQuery.PageSize != 50 || service.listQuery.Cursor != "opaque" {
		t.Fatalf("list principal/query = %+v/%+v", service.principal, service.listQuery)
	}
	if !strings.Contains(response.Body.String(), `"status":"running"`) {
		t.Fatalf("response=%s", response.Body.String())
	}
}

func TestArchiveImportExistingOutcomeAllowsDeletedTaskSnapshot(t *testing.T) {
	service := &archiveImportServiceStub{
		created: false,
		result: archiveimport.BatchResult{Items: []archiveimport.BatchItem{{
			EntryID: apiArchiveEntryID, Outcome: archiveimport.OutcomeExisting,
		}}},
	}
	manager := &authManagerStub{
		session:   auth.Session{User: auth.Principal{UserID: 9, Role: auth.RoleAdministrator}},
		csrfToken: "csrf-token",
	}
	router := archiveImportTestRouter(manager, service)
	request := httptest.NewRequest(
		http.MethodPost,
		"/api/v1/archive-imports/"+apiArchiveImportID+"/task-batches",
		strings.NewReader(`{"entry_ids":["`+apiArchiveEntryID+`"]}`),
	)
	request.AddCookie(&http.Cookie{Name: sessionCookieName, Value: "session-token"})
	request.AddCookie(&http.Cookie{Name: csrfCookieName, Value: "csrf-token"})
	request.Header.Set(csrfHeaderName, "csrf-token")
	request.Header.Set("Idempotency-Key", "existing-task")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	var envelope struct {
		Data archiveimport.BatchResult `json:"data"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &envelope); err != nil {
		t.Fatal(err)
	}
	if len(envelope.Data.Items) != 1 || envelope.Data.Items[0].Outcome != archiveimport.OutcomeExisting ||
		envelope.Data.Items[0].TaskID != "" {
		t.Fatalf("response = %+v", envelope.Data)
	}
}

func archiveImportTestRouter(
	manager AuthManager,
	service ArchiveImportService,
) http.Handler {
	gin.SetMode(gin.ReleaseMode)
	router := gin.New()
	router.Use(
		RequestIDMiddleware(),
		AccessLogMiddleware(slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil))),
	)
	registerArchiveImportRoutes(router.Group("/api/v1"), manager, service)
	return router
}

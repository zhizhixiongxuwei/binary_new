package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"binaryscan/internal/audit"
	"binaryscan/internal/auth"
	"binaryscan/internal/useradmin"

	"github.com/gin-gonic/gin"
)

type userAdminServiceStub struct {
	listCalls   int
	createCalls int
	panicCreate bool
	result      useradmin.User
}

func (s *userAdminServiceStub) List(
	context.Context,
	useradmin.ListQuery,
) (useradmin.Page, error) {
	s.listCalls++
	return useradmin.Page{Items: []useradmin.User{s.result}}, nil
}
func (s *userAdminServiceStub) Create(
	context.Context,
	useradmin.AuditContext,
	string,
	string,
	auth.Role,
	[]byte,
) (useradmin.User, error) {
	s.createCalls++
	if s.panicCreate {
		panic("user administration panic")
	}
	return s.result, nil
}
func (s *userAdminServiceStub) Update(
	context.Context,
	useradmin.AuditContext,
	string,
	*auth.Role,
	*string,
	string,
) (useradmin.User, error) {
	return s.result, nil
}
func (s *userAdminServiceStub) ResetPassword(
	context.Context,
	useradmin.AuditContext,
	string,
	[]byte,
	string,
) (useradmin.User, error) {
	return s.result, nil
}

type auditLogServiceStub struct {
	page audit.Page
}

func (s *auditLogServiceStub) List(context.Context, audit.ListQuery) (audit.Page, error) {
	return s.page, nil
}

func adminIdentityTestRouter(
	t *testing.T,
	role auth.Role,
	users UserAdminService,
	logs AuditLogService,
) (*gin.Engine, *authManagerStub) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	manager := &authManagerStub{
		session: auth.Session{
			ID: "session",
			User: auth.Principal{
				UserID: 7, PublicID: "admin-id", Role: role,
				Username: "admin", DisplayName: "Administrator",
			},
		},
		csrfToken: "csrf-token",
	}
	router := gin.New()
	router.Use(RequestIDMiddleware())
	v1 := router.Group("/api/v1")
	RegisterIdentityAdminRoutes(v1, manager, users, logs)
	return router, manager
}

func authenticatedRequest(method, target, body string, csrf bool) *http.Request {
	request := httptest.NewRequest(method, target, strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	request.AddCookie(&http.Cookie{Name: sessionCookieName, Value: "session-token"})
	if csrf {
		request.Header.Set(csrfHeaderName, "csrf-token")
		request.AddCookie(&http.Cookie{Name: csrfCookieName, Value: "csrf-token"})
	}
	return request
}

func TestAdminUserRoutesEnforceRoleAndCSRF(t *testing.T) {
	now := time.Date(2026, 7, 30, 12, 0, 0, 0, time.UTC)
	users := &userAdminServiceStub{result: useradmin.User{
		ID:       "00000000-0000-4000-8000-000000000001",
		Username: "reader", DisplayName: "Reader", Role: auth.RoleReader,
		Status: "active", MustChangePassword: true,
		CreatedAt: now, UpdatedAt: now,
	}}
	readerRouter, _ := adminIdentityTestRouter(
		t, auth.RoleReader, users, &auditLogServiceStub{},
	)
	response := httptest.NewRecorder()
	readerRouter.ServeHTTP(
		response,
		authenticatedRequest(http.MethodGet, "/api/v1/admin/users", "", false),
	)
	if response.Code != http.StatusForbidden || users.listCalls != 0 {
		t.Fatalf("reader status/calls = %d/%d", response.Code, users.listCalls)
	}
	assertAdminNoStore(t, response)

	adminRouter, _ := adminIdentityTestRouter(
		t, auth.RoleAdministrator, users, &auditLogServiceStub{},
	)
	response = httptest.NewRecorder()
	adminRouter.ServeHTTP(
		response,
		authenticatedRequest(
			http.MethodPost,
			"/api/v1/admin/users",
			`{"username":"reader","display_name":"Reader","role":"reader","temporary_password":"temporary-password"}`,
			false,
		),
	)
	if response.Code != http.StatusForbidden || users.createCalls != 0 {
		t.Fatalf("missing CSRF status/calls = %d/%d", response.Code, users.createCalls)
	}

	response = httptest.NewRecorder()
	adminRouter.ServeHTTP(
		response,
		authenticatedRequest(
			http.MethodPost,
			"/api/v1/admin/users",
			`{"username":"reader","display_name":"Reader","role":"reader","temporary_password":"temporary-password"}`,
			true,
		),
	)
	if response.Code != http.StatusCreated || users.createCalls != 1 {
		t.Fatalf("create status/calls = %d/%d; body=%s", response.Code, users.createCalls, response.Body.String())
	}
	assertAdminNoStore(t, response)
	if strings.Contains(response.Body.String(), "temporary-password") ||
		strings.Contains(response.Body.String(), "password_hash") {
		t.Fatalf("response leaked a password field: %s", response.Body.String())
	}
}

func TestAdminUserPanicIsAuditedAsFailure(t *testing.T) {
	gin.SetMode(gin.TestMode)
	recorder := &auditRecorderStub{}
	users := &userAdminServiceStub{panicCreate: true}
	manager := &authManagerStub{
		session: auth.Session{
			ID: "session",
			User: auth.Principal{
				UserID: 7, PublicID: "admin-id",
				Role: auth.RoleAdministrator, Username: "admin",
			},
		},
		csrfToken: "csrf-token",
	}
	router := gin.New()
	router.Use(
		func(c *gin.Context) {
			defer func() {
				if recover() != nil {
					WriteError(
						c,
						http.StatusInternalServerError,
						"internal_error",
						"Internal error.",
						nil,
					)
				}
			}()
			c.Next()
		},
		AuditActivityMiddleware(recorder),
	)
	v1 := router.Group("/api/v1")
	RegisterIdentityAdminRoutes(v1, manager, users, nil)

	response := httptest.NewRecorder()
	router.ServeHTTP(
		response,
		authenticatedRequest(
			http.MethodPost,
			"/api/v1/admin/users",
			`{"username":"reader","display_name":"Reader","role":"reader","temporary_password":"temporary-password"}`,
			true,
		),
	)
	if response.Code != http.StatusInternalServerError ||
		len(recorder.events) != 1 ||
		recorder.events[0].Action != "user.create" ||
		recorder.events[0].Outcome != audit.OutcomeFailure ||
		recorder.events[0].Metadata["http_status"] !=
			http.StatusInternalServerError {
		t.Fatalf(
			"panic status/audit = %d/%#v",
			response.Code,
			recorder.events,
		)
	}
	assertAdminNoStore(t, response)
}

func TestAdminUserBoundaryRejectionsAreAuditedWithoutDuplicatingServiceAudit(
	t *testing.T,
) {
	gin.SetMode(gin.TestMode)
	recorder := &auditRecorderStub{}
	users := &userAdminServiceStub{result: useradmin.User{
		ID:       "00000000-0000-4000-8000-000000000001",
		Username: "reader", DisplayName: "Reader", Role: auth.RoleReader,
		Status: "active", CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC(),
	}}
	newRouter := func(role auth.Role) *gin.Engine {
		manager := &authManagerStub{
			session: auth.Session{
				ID: "session",
				User: auth.Principal{
					UserID: 7, PublicID: "admin-id", Role: role,
					Username: "admin", DisplayName: "Administrator",
				},
			},
			csrfToken: "csrf-token",
		}
		router := gin.New()
		router.Use(
			RequestIDMiddleware(),
			AuditActivityMiddleware(recorder),
		)
		v1 := router.Group("/api/v1")
		RegisterIdentityAdminRoutes(v1, manager, users, nil)
		return router
	}
	validBody := `{"username":"reader","display_name":"Reader","role":"reader","temporary_password":"temporary-password"}`

	response := httptest.NewRecorder()
	newRouter(auth.RoleOperator).ServeHTTP(
		response,
		authenticatedRequest(
			http.MethodPost,
			"/api/v1/admin/users",
			validBody,
			true,
		),
	)
	if response.Code != http.StatusForbidden {
		t.Fatalf("role rejection status = %d", response.Code)
	}

	response = httptest.NewRecorder()
	adminRouter := newRouter(auth.RoleAdministrator)
	adminRouter.ServeHTTP(
		response,
		authenticatedRequest(
			http.MethodPost,
			"/api/v1/admin/users",
			validBody,
			false,
		),
	)
	if response.Code != http.StatusForbidden {
		t.Fatalf("CSRF rejection status = %d", response.Code)
	}

	response = httptest.NewRecorder()
	adminRouter.ServeHTTP(
		response,
		authenticatedRequest(
			http.MethodPost,
			"/api/v1/admin/users",
			`{"username":`,
			true,
		),
	)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("JSON rejection status = %d", response.Code)
	}
	if len(recorder.events) != 3 {
		t.Fatalf("boundary audit events = %#v", recorder.events)
	}
	for _, event := range recorder.events {
		if event.Action != "user.create" ||
			event.Outcome != audit.OutcomeDenied {
			t.Fatalf("unexpected boundary audit event: %#v", event)
		}
	}

	response = httptest.NewRecorder()
	adminRouter.ServeHTTP(
		response,
		authenticatedRequest(
			http.MethodPost,
			"/api/v1/admin/users",
			validBody,
			true,
		),
	)
	if response.Code != http.StatusCreated || len(recorder.events) != 3 {
		t.Fatalf(
			"service-owned audit status/events = %d/%#v",
			response.Code,
			recorder.events,
		)
	}
}

func TestAdminQueriesRejectUnknownOrRepeatedFields(t *testing.T) {
	users := &userAdminServiceStub{}
	router, _ := adminIdentityTestRouter(
		t, auth.RoleAdministrator, users, &auditLogServiceStub{},
	)
	for _, target := range []string{
		"/api/v1/admin/users?unknown=value",
		"/api/v1/admin/users?page_size=10&page_size=20",
		"/api/v1/admin/users?page_size=",
		"/api/v1/admin/users?cursor=",
		"/api/v1/admin/audit-logs?source_ip=127.0.0.1",
	} {
		response := httptest.NewRecorder()
		router.ServeHTTP(
			response,
			authenticatedRequest(http.MethodGet, target, "", false),
		)
		if response.Code != http.StatusBadRequest {
			t.Fatalf("%s status = %d; body=%s", target, response.Code, response.Body.String())
		}
	}
	if users.listCalls != 0 {
		t.Fatalf("invalid user queries reached service %d times", users.listCalls)
	}
}

func TestAuditLogResponseOmitsClientIPAndUserAgent(t *testing.T) {
	now := time.Date(2026, 7, 30, 12, 0, 0, 0, time.UTC)
	objectID := "target"
	logs := &auditLogServiceStub{
		page: audit.Page{
			Items: []audit.Log{
				{
					ID: "9",
					Actor: &audit.Actor{
						ID:       "00000000-0000-4000-8000-000000000001",
						Username: "admin", DisplayName: "Administrator",
					},
					RequestID: "request-9", Action: "user.update", ObjectType: "user",
					ObjectID: &objectID, Outcome: audit.OutcomeSuccess,
					Metadata: json.RawMessage(`{"role":"reader"}`), CreatedAt: now,
				},
			},
		},
	}
	router, _ := adminIdentityTestRouter(
		t, auth.RoleAdministrator, &userAdminServiceStub{}, logs,
	)
	response := httptest.NewRecorder()
	router.ServeHTTP(
		response,
		authenticatedRequest(http.MethodGet, "/api/v1/admin/audit-logs", "", false),
	)
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d; body=%s", response.Code, response.Body.String())
	}
	assertAdminNoStore(t, response)
	body := response.Body.String()
	for _, forbidden := range []string{"client_ip", "source_ip", "user_agent"} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("audit response contains %q: %s", forbidden, body)
		}
	}
}

func assertAdminNoStore(t *testing.T, response *httptest.ResponseRecorder) {
	t.Helper()
	if response.Header().Get("Cache-Control") != "private, no-store" ||
		response.Header().Get("Pragma") != "no-cache" {
		t.Fatalf("admin cache headers = %#v", response.Header())
	}
}

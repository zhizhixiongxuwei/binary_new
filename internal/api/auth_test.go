package api

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"binaryscan/internal/auth"
	"binaryscan/internal/buildinfo"

	"github.com/gin-gonic/gin"
)

type authManagerStub struct {
	loginResult auth.LoginResult
	loginErr    error
	session     auth.Session
	csrfToken   string
	loggedOut   bool
	changedUser auth.Principal
}

func (m *authManagerStub) Login(context.Context, string, []byte, []byte, string) (auth.LoginResult, error) {
	return m.loginResult, m.loginErr
}
func (m *authManagerStub) Authenticate(context.Context, string) (auth.Session, error) {
	return m.session, nil
}
func (m *authManagerStub) ValidateCSRF(_ auth.Session, token string) error {
	if token != m.csrfToken {
		return auth.ErrCSRF
	}
	return nil
}
func (m *authManagerStub) Logout(context.Context, string) error {
	m.loggedOut = true
	return nil
}
func (m *authManagerStub) ChangePassword(context.Context, auth.Session, []byte, []byte) (auth.Principal, error) {
	return m.changedUser, nil
}

func TestLoginSetsHttpOnlySessionAndCSRFCookie(t *testing.T) {
	expires := time.Now().Add(time.Hour).UTC()
	manager := &authManagerStub{loginResult: auth.LoginResult{
		SessionToken: "session-token", CSRFToken: "csrf-token",
		Session: auth.Session{
			ExpiresAt: expires,
			User: auth.Principal{
				PublicID: "id", Username: "admin", DisplayName: "Administrator",
				Role: auth.RoleAdministrator, ForcePasswordChange: true,
			},
		},
	}}
	router := authTestRouter(t, manager)
	request := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", strings.NewReader(
		`{"username":"admin","password":"a-secure-test-password"}`,
	))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d; body=%s", response.Code, response.Body.String())
	}
	cookies := response.Result().Cookies()
	if len(cookies) != 2 {
		t.Fatalf("cookies = %d, want 2", len(cookies))
	}
	var sessionCookie, csrfCookie *http.Cookie
	for _, cookie := range cookies {
		if cookie.Name == sessionCookieName {
			sessionCookie = cookie
		}
		if cookie.Name == csrfCookieName {
			csrfCookie = cookie
		}
	}
	if sessionCookie == nil || !sessionCookie.HttpOnly || sessionCookie.SameSite != http.SameSiteStrictMode {
		t.Fatalf("invalid session cookie: %#v", sessionCookie)
	}
	if csrfCookie == nil || csrfCookie.HttpOnly || csrfCookie.Path != "/" {
		t.Fatalf("invalid CSRF cookie: %#v", csrfCookie)
	}
	var payload struct {
		Data map[string]any `json:"data"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if payload.Data["username"] != "admin" || payload.Data["role"] != "administrator" {
		t.Fatalf("unexpected login data: %#v", payload.Data)
	}
	if payload.Data["display_name"] != "Administrator" || payload.Data["must_change_password"] != true {
		t.Fatalf("login data does not match CurrentUser DTO: %#v", payload.Data)
	}
	if _, exists := payload.Data["user"]; exists {
		t.Fatal("login data must be the user DTO directly, not a user wrapper")
	}
	if _, exists := payload.Data["csrfToken"]; exists {
		t.Fatal("CSRF token must be delivered by the readable CSRF cookie")
	}
}

func TestLoginRateLimitedResponseDoesNotRevealAccountExistence(t *testing.T) {
	var firstError ErrorBody
	for index, username := range []string{"known", "unknown"} {
		manager := &authManagerStub{
			loginErr: auth.NewLoginRateLimitedError(
				1500 * time.Millisecond,
			),
		}
		router := authTestRouter(t, manager)
		request := httptest.NewRequest(
			http.MethodPost,
			"/api/v1/auth/login",
			strings.NewReader(
				`{"username":"`+username+
					`","password":"a-secure-test-password"}`,
			),
		)
		request.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		router.ServeHTTP(response, request)
		if response.Code != http.StatusTooManyRequests ||
			response.Header().Get("Retry-After") != "2" {
			t.Fatalf(
				"%s status/retry = %d/%q; body=%s",
				username,
				response.Code,
				response.Header().Get("Retry-After"),
				response.Body.String(),
			)
		}
		if len(response.Result().Cookies()) != 0 {
			t.Fatalf("%s response set auth cookies", username)
		}
		var payload ErrorResponse
		if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
			t.Fatal(err)
		}
		if payload.Meta.RequestID == "" {
			t.Fatalf("%s response has no request ID", username)
		}
		if index == 0 {
			firstError = payload.Error
		} else if payload.Error.Code != firstError.Code ||
			payload.Error.Message != firstError.Message ||
			!reflect.DeepEqual(
				payload.Error.Details,
				firstError.Details,
			) {
			t.Fatalf(
				"known/unknown errors differ: %#v / %#v",
				firstError,
				payload.Error,
			)
		}
	}
}

func TestLoginRateLimitedRetryAfterIsBounded(t *testing.T) {
	for _, test := range []struct {
		name  string
		err   error
		value string
	}{
		{name: "missing duration", err: auth.ErrLoginRateLimited, value: "1"},
		{
			name:  "long duration",
			err:   auth.NewLoginRateLimitedError(48 * time.Hour),
			value: "86400",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			router := authTestRouter(
				t,
				&authManagerStub{loginErr: test.err},
			)
			request := httptest.NewRequest(
				http.MethodPost,
				"/api/v1/auth/login",
				strings.NewReader(
					`{"username":"user","password":"password-value"}`,
				),
			)
			response := httptest.NewRecorder()
			router.ServeHTTP(response, request)
			if response.Code != http.StatusTooManyRequests ||
				response.Header().Get("Retry-After") != test.value {
				t.Fatalf(
					"status/retry = %d/%q",
					response.Code,
					response.Header().Get("Retry-After"),
				)
			}
		})
	}
}

func TestLogoutRequiresMatchingCSRFHeaderAndCookie(t *testing.T) {
	csrf := "csrf-token"
	manager := &authManagerStub{
		session:   auth.Session{ID: "session", User: auth.Principal{Role: auth.RoleOperator}},
		csrfToken: csrf,
	}
	router := authTestRouter(t, manager)

	denied := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/api/v1/auth/logout", nil)
	request.AddCookie(&http.Cookie{Name: sessionCookieName, Value: "session-token"})
	router.ServeHTTP(denied, request)
	if denied.Code != http.StatusForbidden || manager.loggedOut {
		t.Fatalf("missing CSRF status/loggedOut = %d/%v", denied.Code, manager.loggedOut)
	}

	allowed := httptest.NewRecorder()
	request = httptest.NewRequest(http.MethodPost, "/api/v1/auth/logout", nil)
	request.AddCookie(&http.Cookie{Name: sessionCookieName, Value: "session-token"})
	request.AddCookie(&http.Cookie{Name: csrfCookieName, Value: csrf})
	request.Header.Set(csrfHeaderName, csrf)
	router.ServeHTTP(allowed, request)
	if allowed.Code != http.StatusNoContent || !manager.loggedOut {
		t.Fatalf("valid CSRF status/loggedOut = %d/%v; body=%s", allowed.Code, manager.loggedOut, allowed.Body.String())
	}
}

func TestMeReturnsCurrentUserDTO(t *testing.T) {
	manager := &authManagerStub{session: auth.Session{
		ID: "session",
		User: auth.Principal{
			PublicID: "user-id", Username: "reader", DisplayName: "Read Only",
			Role: auth.RoleReader,
		},
	}}
	router := authTestRouter(t, manager)
	request := httptest.NewRequest(http.MethodGet, "/api/v1/me", nil)
	request.AddCookie(&http.Cookie{Name: sessionCookieName, Value: "token"})
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d; body=%s", response.Code, response.Body.String())
	}
	var payload struct {
		Data map[string]any `json:"data"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if payload.Data["id"] != "user-id" || payload.Data["display_name"] != "Read Only" {
		t.Fatalf("unexpected /me data: %#v", payload.Data)
	}
}

func TestAuthenticatedRequestRefreshesSecureSessionCookies(t *testing.T) {
	expiresAt := time.Now().UTC().Add(45 * time.Minute)
	manager := &authManagerStub{session: auth.Session{
		ID:        "session",
		ExpiresAt: expiresAt,
		User: auth.Principal{
			PublicID: "user-id", Username: "reader", DisplayName: "Read Only",
			Role: auth.RoleReader,
		},
	}}
	router, err := NewRouter(Dependencies{
		Logger:   slog.New(slog.NewJSONHandler(io.Discard, nil)),
		Database: readinessStub{}, ReadinessTimeout: time.Second,
		Auth: manager, AuthHTTP: AuthHTTPConfig{
			CookieSecure: true,
			SessionTTL:   time.Hour,
		},
		Build: buildinfo.Current(),
	})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, "/api/v1/me", nil)
	request.AddCookie(&http.Cookie{
		Name: sessionCookieName, Value: "session-token",
	})
	request.AddCookie(&http.Cookie{
		Name: csrfCookieName, Value: "csrf-token",
	})
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d; body=%s", response.Code, response.Body.String())
	}

	cookies := response.Result().Cookies()
	if len(cookies) != 2 {
		t.Fatalf("refreshed cookies = %d, want 2", len(cookies))
	}
	for _, cookie := range cookies {
		if !cookie.Secure || cookie.SameSite != http.SameSiteStrictMode ||
			cookie.MaxAge < 44*60 || cookie.MaxAge > 45*60 {
			t.Fatalf("refreshed cookie = %#v", cookie)
		}
		if !cookie.Expires.Equal(expiresAt.Truncate(time.Second)) {
			t.Fatalf(
				"cookie expiry = %v, want %v",
				cookie.Expires,
				expiresAt.Truncate(time.Second),
			)
		}
	}
}

func TestRequireRolesDeniesReader(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(RequestIDMiddleware())
	router.GET("/admin", func(c *gin.Context) {
		c.Set(authSessionKey, auth.Session{User: auth.Principal{Role: auth.RoleReader}})
		c.Next()
	}, RequireRoles(auth.RoleAdministrator), func(c *gin.Context) {
		Write(c, http.StatusOK, gin.H{"ok": true})
	})
	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/admin", nil))
	if response.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", response.Code)
	}
	var body ErrorResponse
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Error.Code != "permission_denied" {
		t.Fatalf("error code = %q", body.Error.Code)
	}
}

func TestForcedPasswordChangeBlocksOtherAuthenticatedRoutes(t *testing.T) {
	manager := &authManagerStub{session: auth.Session{
		ID: "session", User: auth.Principal{Role: auth.RoleAdministrator, ForcePasswordChange: true},
	}}
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(RequestIDMiddleware())
	router.GET("/api/v1/tasks", RequireSession(manager), func(c *gin.Context) {
		Write(c, http.StatusOK, gin.H{"unexpected": true})
	})
	request := httptest.NewRequest(http.MethodGet, "/api/v1/tasks", nil)
	request.AddCookie(&http.Cookie{Name: sessionCookieName, Value: "token"})
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", response.Code)
	}
	var body ErrorResponse
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Error.Code != "password_change_required" {
		t.Fatalf("error code = %q", body.Error.Code)
	}
}

func TestChangePasswordAllowsForcedSessionWithCSRF(t *testing.T) {
	csrf := "csrf-token"
	manager := &authManagerStub{
		session: auth.Session{
			ID:   "session",
			User: auth.Principal{UserID: 7, Role: auth.RoleAdministrator, ForcePasswordChange: true},
		},
		csrfToken: csrf,
		changedUser: auth.Principal{
			PublicID: "id", Username: "admin", Role: auth.RoleAdministrator,
		},
	}
	router := authTestRouter(t, manager)
	request := httptest.NewRequest(http.MethodPut, "/api/v1/me/password", strings.NewReader(
		`{"current_password":"current-secure-password","new_password":"new-secure-password"}`,
	))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set(csrfHeaderName, csrf)
	request.AddCookie(&http.Cookie{Name: sessionCookieName, Value: "token"})
	request.AddCookie(&http.Cookie{Name: csrfCookieName, Value: csrf})
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d; body=%s", response.Code, response.Body.String())
	}
}

func authTestRouter(t *testing.T, manager AuthManager) http.Handler {
	t.Helper()
	router, err := NewRouter(Dependencies{
		Logger:   slog.New(slog.NewJSONHandler(io.Discard, nil)),
		Database: readinessStub{}, ReadinessTimeout: time.Second,
		Auth: manager, AuthHTTP: AuthHTTPConfig{SessionTTL: time.Hour},
		Build: buildinfo.Current(),
	})
	if err != nil {
		t.Fatal(err)
	}
	return router
}

package api

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"binaryscan/internal/auth"

	"github.com/gin-gonic/gin"
)

const (
	sessionCookieName = "binaryscan_session"
	csrfCookieName    = "binaryscan_csrf"
	csrfHeaderName    = "X-CSRF-Token"
	authSessionKey    = "binaryscan.auth_session"
	authHTTPConfigKey = "binaryscan.auth_http_config"
)

type AuthManager interface {
	Login(context.Context, string, []byte, []byte, string) (auth.LoginResult, error)
	Authenticate(context.Context, string) (auth.Session, error)
	ValidateCSRF(auth.Session, string) error
	Logout(context.Context, string) error
	ChangePassword(context.Context, auth.Session, []byte, []byte) (auth.Principal, error)
}

type AuthHTTPConfig struct {
	CookieSecure bool
	SessionTTL   time.Duration
}

func registerAuthRoutes(v1 *gin.RouterGroup, manager AuthManager, config AuthHTTPConfig) {
	authRoutes := v1.Group("/auth")
	authRoutes.POST("/login", loginHandler(manager, config))
	authRoutes.POST("/logout", RequireSession(manager), RequireCSRF(manager), logoutHandler(manager, config))
	v1.GET("/me", RequireSession(manager), meHandler)
	v1.PUT("/me/password", RequireSession(manager), RequireCSRF(manager), changePasswordHandler(manager))
}

func loginHandler(manager AuthManager, config AuthHTTPConfig) gin.HandlerFunc {
	type loginRequest struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	return func(c *gin.Context) {
		c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, 16*1024)
		decoder := json.NewDecoder(c.Request.Body)
		decoder.DisallowUnknownFields()
		var request loginRequest
		if err := decoder.Decode(&request); err != nil {
			WriteError(c, http.StatusBadRequest, "invalid_request", "The login request is not valid JSON.", nil)
			return
		}
		if err := ensureJSONEnd(decoder); err != nil {
			WriteError(c, http.StatusBadRequest, "invalid_request", "The login request must contain one JSON object.", nil)
			return
		}

		result, err := manager.Login(
			c.Request.Context(), request.Username, []byte(request.Password),
			auth.ParseClientIP(c.ClientIP()), c.Request.UserAgent(),
		)
		request.Password = ""
		if err != nil {
			if errors.Is(err, auth.ErrLoginRateLimited) {
				retryAfter := auth.LoginRateLimitRetryAfter(err)
				seconds := int64(
					(retryAfter + time.Second - 1) / time.Second,
				)
				if seconds < 1 {
					seconds = 1
				}
				if seconds > 24*60*60 {
					seconds = 24 * 60 * 60
				}
				c.Header("Retry-After", strconv.FormatInt(seconds, 10))
				WriteError(
					c,
					http.StatusTooManyRequests,
					"login_rate_limited",
					"Login attempts are temporarily limited.",
					nil,
				)
				return
			}
			if errors.Is(err, auth.ErrInvalidCredentials) {
				WriteError(c, http.StatusUnauthorized, "invalid_credentials", "The username or password is incorrect.", nil)
				return
			}
			WriteError(c, http.StatusInternalServerError, "authentication_failed", "Authentication could not be completed.", nil)
			return
		}

		setAuthCookies(c, result, config)
		Write(c, http.StatusOK, result.Session.User)
	}
}

func logoutHandler(manager AuthManager, config AuthHTTPConfig) gin.HandlerFunc {
	return func(c *gin.Context) {
		session, ok := CurrentSession(c)
		if !ok {
			WriteError(c, http.StatusUnauthorized, "authentication_required", "Authentication is required.", nil)
			return
		}
		if err := manager.Logout(c.Request.Context(), session.ID); err != nil {
			WriteError(c, http.StatusInternalServerError, "logout_failed", "The session could not be revoked.", nil)
			return
		}
		clearAuthCookies(c, config)
		c.Status(http.StatusNoContent)
	}
}

func meHandler(c *gin.Context) {
	session, ok := CurrentSession(c)
	if !ok {
		WriteError(c, http.StatusUnauthorized, "authentication_required", "Authentication is required.", nil)
		return
	}
	Write(c, http.StatusOK, session.User)
}

func RequireSession(manager AuthManager) gin.HandlerFunc {
	return func(c *gin.Context) {
		token, err := c.Cookie(sessionCookieName)
		if err != nil {
			WriteError(c, http.StatusUnauthorized, "authentication_required", "Authentication is required.", nil)
			return
		}
		session, err := manager.Authenticate(c.Request.Context(), token)
		if err != nil {
			if errors.Is(err, auth.ErrUnauthenticated) {
				WriteError(c, http.StatusUnauthorized, "authentication_required", "Authentication is required.", nil)
				return
			}
			WriteError(c, http.StatusServiceUnavailable, "authentication_unavailable", "Authentication is temporarily unavailable.", nil)
			return
		}
		c.Set(authSessionKey, session)
		refreshAuthCookies(c, token, session)
		if session.User.ForcePasswordChange && !passwordChangeExempt(c.Request.Method, c.Request.URL.Path) {
			WriteError(c, http.StatusForbidden, "password_change_required", "The initial password must be changed before continuing.", nil)
			return
		}
		c.Next()
	}
}

func authHTTPConfigContext(config AuthHTTPConfig) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Set(authHTTPConfigKey, config)
		c.Next()
	}
}

func refreshAuthCookies(
	c *gin.Context,
	sessionToken string,
	session auth.Session,
) {
	value, exists := c.Get(authHTTPConfigKey)
	config, valid := value.(AuthHTTPConfig)
	if !exists || !valid || sessionToken == "" {
		return
	}
	now := time.Now().UTC()
	if !session.ExpiresAt.After(now) {
		return
	}
	remaining := session.ExpiresAt.Sub(now)
	maxAge := int((remaining + time.Second - 1) / time.Second)
	if maxAge < 1 {
		return
	}
	http.SetCookie(c.Writer, &http.Cookie{
		Name: sessionCookieName, Value: sessionToken, Path: "/api/v1",
		MaxAge: maxAge, Expires: session.ExpiresAt,
		HttpOnly: true, Secure: config.CookieSecure,
		SameSite: http.SameSiteStrictMode,
	})
	csrfToken, err := c.Cookie(csrfCookieName)
	if err != nil || csrfToken == "" {
		return
	}
	http.SetCookie(c.Writer, &http.Cookie{
		Name: csrfCookieName, Value: csrfToken, Path: "/",
		MaxAge: maxAge, Expires: session.ExpiresAt,
		HttpOnly: false, Secure: config.CookieSecure,
		SameSite: http.SameSiteStrictMode,
	})
}

func changePasswordHandler(manager AuthManager) gin.HandlerFunc {
	type passwordRequest struct {
		CurrentPassword string `json:"current_password"`
		NewPassword     string `json:"new_password"`
	}
	return func(c *gin.Context) {
		session, ok := CurrentSession(c)
		if !ok {
			WriteError(c, http.StatusUnauthorized, "authentication_required", "Authentication is required.", nil)
			return
		}
		c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, 16*1024)
		decoder := json.NewDecoder(c.Request.Body)
		decoder.DisallowUnknownFields()
		var request passwordRequest
		if err := decoder.Decode(&request); err != nil || ensureJSONEnd(decoder) != nil {
			WriteError(c, http.StatusBadRequest, "invalid_request", "The password request is not valid.", nil)
			return
		}
		principal, err := manager.ChangePassword(
			c.Request.Context(), session, []byte(request.CurrentPassword), []byte(request.NewPassword),
		)
		request.CurrentPassword = ""
		request.NewPassword = ""
		if err != nil {
			switch {
			case errors.Is(err, auth.ErrInvalidCredentials):
				WriteError(c, http.StatusBadRequest, "current_password_invalid", "The current password is incorrect.", nil)
			case errors.Is(err, auth.ErrPasswordReuse):
				WriteError(c, http.StatusBadRequest, "password_reused", "The new password must differ from the current password.", nil)
			case errors.Is(err, auth.ErrPasswordPolicy):
				WriteError(c, http.StatusBadRequest, "password_policy_failed", "The new password does not satisfy the password policy.", nil)
			case errors.Is(err, auth.ErrUnauthenticated):
				WriteError(c, http.StatusUnauthorized, "authentication_required", "Authentication is required.", nil)
			default:
				WriteError(c, http.StatusInternalServerError, "password_change_failed", "The password could not be changed.", nil)
			}
			return
		}
		Write(c, http.StatusOK, principal)
	}
}

func RequireCSRF(manager AuthManager) gin.HandlerFunc {
	return func(c *gin.Context) {
		if isSafeMethod(c.Request.Method) {
			c.Next()
			return
		}
		session, ok := CurrentSession(c)
		if !ok {
			WriteError(c, http.StatusUnauthorized, "authentication_required", "Authentication is required.", nil)
			return
		}
		headerToken := c.GetHeader(csrfHeaderName)
		cookieToken, err := c.Cookie(csrfCookieName)
		if err != nil || !constantTimeStringEqual(headerToken, cookieToken) ||
			manager.ValidateCSRF(session, headerToken) != nil {
			WriteError(c, http.StatusForbidden, "csrf_failed", "The CSRF token is missing or invalid.", nil)
			return
		}
		c.Next()
	}
}

func RequireRoles(roles ...auth.Role) gin.HandlerFunc {
	allowed := make(map[auth.Role]struct{}, len(roles))
	for _, role := range roles {
		allowed[role] = struct{}{}
	}
	return func(c *gin.Context) {
		session, ok := CurrentSession(c)
		if !ok {
			WriteError(c, http.StatusUnauthorized, "authentication_required", "Authentication is required.", nil)
			return
		}
		if _, ok := allowed[session.User.Role]; !ok {
			WriteError(c, http.StatusForbidden, "permission_denied", "The current role cannot perform this action.", nil)
			return
		}
		c.Next()
	}
}

func CurrentSession(c *gin.Context) (auth.Session, bool) {
	value, exists := c.Get(authSessionKey)
	if !exists {
		return auth.Session{}, false
	}
	session, ok := value.(auth.Session)
	return session, ok
}

func setAuthCookies(c *gin.Context, result auth.LoginResult, config AuthHTTPConfig) {
	maxAge := int(config.SessionTTL.Seconds())
	http.SetCookie(c.Writer, &http.Cookie{
		Name: sessionCookieName, Value: result.SessionToken, Path: "/api/v1",
		MaxAge: maxAge, Expires: result.Session.ExpiresAt,
		HttpOnly: true, Secure: config.CookieSecure, SameSite: http.SameSiteStrictMode,
	})
	http.SetCookie(c.Writer, &http.Cookie{
		Name: csrfCookieName, Value: result.CSRFToken, Path: "/",
		MaxAge: maxAge, Expires: result.Session.ExpiresAt,
		HttpOnly: false, Secure: config.CookieSecure, SameSite: http.SameSiteStrictMode,
	})
}

func clearAuthCookies(c *gin.Context, config AuthHTTPConfig) {
	for _, cookie := range []*http.Cookie{
		{Name: sessionCookieName, Path: "/api/v1", HttpOnly: true},
		{Name: csrfCookieName, Path: "/", HttpOnly: false},
	} {
		cookie.Value = ""
		cookie.MaxAge = -1
		cookie.Expires = time.Unix(1, 0)
		cookie.Secure = config.CookieSecure
		cookie.SameSite = http.SameSiteStrictMode
		http.SetCookie(c.Writer, cookie)
	}
}

func ensureJSONEnd(decoder *json.Decoder) error {
	var extra any
	err := decoder.Decode(&extra)
	if errors.Is(err, io.EOF) {
		return nil
	}
	return errors.New("extra JSON content")
}

func isSafeMethod(method string) bool {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return true
	default:
		return false
	}
}

func passwordChangeExempt(method, path string) bool {
	return (method == http.MethodGet && path == "/api/v1/me") ||
		(method == http.MethodPut && path == "/api/v1/me/password") ||
		(method == http.MethodPost && path == "/api/v1/auth/logout")
}

func constantTimeStringEqual(left, right string) bool {
	if len(left) == 0 || len(left) != len(right) {
		subtle.ConstantTimeCompare([]byte(strings.Repeat("0", 32)), []byte(strings.Repeat("1", 32)))
		return false
	}
	return subtle.ConstantTimeCompare([]byte(left), []byte(right)) == 1
}

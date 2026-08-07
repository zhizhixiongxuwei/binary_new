package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"

	"binaryscan/internal/audit"
	"binaryscan/internal/auth"
	"binaryscan/internal/useradmin"

	"github.com/gin-gonic/gin"
)

const defaultAdminPageSize = 50

type UserAdminService interface {
	List(context.Context, useradmin.ListQuery) (useradmin.Page, error)
	Create(
		context.Context,
		useradmin.AuditContext,
		string,
		string,
		auth.Role,
		[]byte,
	) (useradmin.User, error)
	Update(
		context.Context,
		useradmin.AuditContext,
		string,
		*auth.Role,
		*string,
		string,
	) (useradmin.User, error)
	ResetPassword(
		context.Context,
		useradmin.AuditContext,
		string,
		[]byte,
		string,
	) (useradmin.User, error)
}

type AuditLogService interface {
	List(context.Context, audit.ListQuery) (audit.Page, error)
}

// AuditRecorder is the minimal append-only dependency for request audit
// middleware. RecordRequestAudit returns write errors to the caller; it never
// silently converts a failed append into a successful audited operation.
type AuditRecorder interface {
	Record(context.Context, audit.Event) error
}

func RegisterIdentityAdminRoutes(
	v1 *gin.RouterGroup,
	manager AuthManager,
	users UserAdminService,
	auditLogs AuditLogService,
) {
	routes := v1.Group("/admin")
	routes.Use(
		adminNoStore(),
		RequireSession(manager),
		RequireRoles(auth.RoleAdministrator),
	)
	if users != nil {
		routes.GET("/users", listUsersHandler(users))
		routes.POST("/users", RequireCSRF(manager), createUserHandler(users))
		routes.PATCH("/users/:id", RequireCSRF(manager), updateUserHandler(users))
		routes.POST(
			"/users/:id/reset-password",
			RequireCSRF(manager),
			resetUserPasswordHandler(users),
		)
	}
	if auditLogs != nil {
		routes.GET("/audit-logs", listAuditLogsHandler(auditLogs))
	}
}

func RecordRequestAudit(
	ctx context.Context,
	c *gin.Context,
	recorder AuditRecorder,
	action string,
	objectType string,
	objectID string,
	outcome audit.Outcome,
	metadata map[string]any,
) error {
	if recorder == nil {
		return errors.New("audit recorder is not configured")
	}
	session, ok := CurrentSession(c)
	if !ok {
		return auth.ErrUnauthenticated
	}
	actorID := session.User.UserID
	return recorder.Record(ctx, audit.Event{
		ActorUserID: &actorID,
		RequestID:   RequestID(c),
		Action:      action,
		ObjectType:  objectType,
		ObjectID:    objectID,
		Outcome:     outcome,
		ClientIP:    auth.ParseClientIP(c.ClientIP()),
		UserAgent:   safeUserAgent(c.Request.UserAgent()),
		Metadata:    metadata,
	})
}

func listUsersHandler(service UserAdminService) gin.HandlerFunc {
	return func(c *gin.Context) {
		values := c.Request.URL.Query()
		if !queryFieldsValid(
			values,
			"cursor", "page_size", "keyword", "role", "status",
		) || !optionalCursorValid(values) {
			writeUserAdminInvalidQuery(c)
			return
		}
		pageSize, err := adminPageSize(values)
		if err != nil {
			writeUserAdminInvalidQuery(c)
			return
		}
		page, err := service.List(c.Request.Context(), useradmin.ListQuery{
			Cursor:   queryValue(values, "cursor"),
			PageSize: pageSize,
			Keyword:  queryValue(values, "keyword"),
			Role:     queryValue(values, "role"),
			Status:   queryValue(values, "status"),
		})
		if err != nil {
			if errors.Is(err, useradmin.ErrInvalidInput) {
				writeUserAdminInvalidQuery(c)
				return
			}
			c.Error(err).SetType(gin.ErrorTypePrivate)
			WriteError(
				c, http.StatusInternalServerError, "user_list_failed",
				"The user list could not be loaded.", nil,
			)
			return
		}
		Write(c, http.StatusOK, page)
	}
}

func createUserHandler(service UserAdminService) gin.HandlerFunc {
	type requestBody struct {
		Username          string    `json:"username"`
		DisplayName       string    `json:"display_name"`
		Role              auth.Role `json:"role"`
		TemporaryPassword string    `json:"temporary_password"`
	}
	return func(c *gin.Context) {
		var request requestBody
		if !decodeAdminJSON(c, &request) {
			return
		}
		password := []byte(request.TemporaryPassword)
		defer zeroAPIBytes(password)
		request.TemporaryPassword = ""
		user, err := service.Create(
			c.Request.Context(),
			adminAuditContext(c),
			request.Username,
			request.DisplayName,
			request.Role,
			password,
		)
		markUserAdminAuditHandled(c)
		if err != nil {
			writeUserAdminError(c, err)
			return
		}
		Write(c, http.StatusCreated, user)
	}
}

func updateUserHandler(service UserAdminService) gin.HandlerFunc {
	type requestBody struct {
		Role              *auth.Role `json:"role"`
		Status            *string    `json:"status"`
		ExpectedUpdatedAt string     `json:"expected_updated_at"`
	}
	return func(c *gin.Context) {
		var request requestBody
		if !decodeAdminJSON(c, &request) {
			return
		}
		user, err := service.Update(
			c.Request.Context(),
			adminAuditContext(c),
			c.Param("id"),
			request.Role,
			request.Status,
			request.ExpectedUpdatedAt,
		)
		markUserAdminAuditHandled(c)
		if err != nil {
			writeUserAdminError(c, err)
			return
		}
		Write(c, http.StatusOK, user)
	}
}

func resetUserPasswordHandler(service UserAdminService) gin.HandlerFunc {
	type requestBody struct {
		TemporaryPassword string `json:"temporary_password"`
		ExpectedUpdatedAt string `json:"expected_updated_at"`
	}
	return func(c *gin.Context) {
		var request requestBody
		if !decodeAdminJSON(c, &request) {
			return
		}
		password := []byte(request.TemporaryPassword)
		defer zeroAPIBytes(password)
		request.TemporaryPassword = ""
		user, err := service.ResetPassword(
			c.Request.Context(),
			adminAuditContext(c),
			c.Param("id"),
			password,
			request.ExpectedUpdatedAt,
		)
		markUserAdminAuditHandled(c)
		if err != nil {
			writeUserAdminError(c, err)
			return
		}
		Write(c, http.StatusOK, user)
	}
}

func listAuditLogsHandler(service AuditLogService) gin.HandlerFunc {
	return func(c *gin.Context) {
		values := c.Request.URL.Query()
		if !queryFieldsValid(
			values,
			"cursor", "page_size", "action", "outcome", "actor",
			"created_from", "created_to",
		) || !optionalCursorValid(values) {
			writeAuditInvalidQuery(c)
			return
		}
		pageSize, err := adminPageSize(values)
		if err != nil {
			writeAuditInvalidQuery(c)
			return
		}
		page, err := service.List(c.Request.Context(), audit.ListQuery{
			Cursor: queryValue(values, "cursor"), PageSize: pageSize,
			Action: queryValue(values, "action"), Outcome: queryValue(values, "outcome"),
			Actor:       queryValue(values, "actor"),
			CreatedFrom: queryValue(values, "created_from"),
			CreatedTo:   queryValue(values, "created_to"),
		})
		if err != nil {
			if errors.Is(err, audit.ErrInvalidInput) {
				writeAuditInvalidQuery(c)
				return
			}
			c.Error(err).SetType(gin.ErrorTypePrivate)
			WriteError(
				c, http.StatusInternalServerError, "audit_log_list_failed",
				"The audit log could not be loaded.", nil,
			)
			return
		}
		Write(c, http.StatusOK, page)
	}
}

func decodeAdminJSON(c *gin.Context, target any) bool {
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, 16*1024)
	decoder := json.NewDecoder(c.Request.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil || ensureJSONEnd(decoder) != nil {
		WriteError(
			c, http.StatusBadRequest, "invalid_request",
			"The user administration request is not valid.", nil,
		)
		return false
	}
	return true
}

func adminAuditContext(c *gin.Context) useradmin.AuditContext {
	session, _ := CurrentSession(c)
	return useradmin.AuditContext{
		ActorUserID: session.User.UserID,
		RequestID:   RequestID(c),
		ClientIP:    auth.ParseClientIP(c.ClientIP()),
		UserAgent:   safeUserAgent(c.Request.UserAgent()),
	}
}

func safeUserAgent(value string) string {
	value = strings.ToValidUTF8(value, "")
	value = strings.Map(func(character rune) rune {
		if character < 0x20 || character == 0x7f {
			return -1
		}
		return character
	}, value)
	characters := []rune(value)
	if len(characters) > 512 {
		return string(characters[:512])
	}
	return value
}

func queryFieldsValid(values url.Values, allowed ...string) bool {
	fields := make(map[string]struct{}, len(allowed))
	for _, field := range allowed {
		fields[field] = struct{}{}
	}
	for name, entries := range values {
		if _, ok := fields[name]; !ok || len(entries) != 1 {
			return false
		}
	}
	return true
}

func queryValue(values url.Values, name string) string {
	entries := values[name]
	if len(entries) == 0 {
		return ""
	}
	return entries[0]
}

func adminPageSize(values url.Values) (int, error) {
	entries, exists := values["page_size"]
	if !exists {
		return defaultAdminPageSize, nil
	}
	raw := entries[0]
	value, err := parseCanonicalPositiveUint(raw)
	if err != nil || value > useradmin.MaxPageSize {
		return 0, useradmin.ErrInvalidInput
	}
	return int(value), nil
}

func optionalCursorValid(values url.Values) bool {
	entries, exists := values["cursor"]
	return !exists || entries[0] != ""
}

func writeUserAdminInvalidQuery(c *gin.Context) {
	WriteError(
		c, http.StatusBadRequest, "invalid_query",
		"The user query is invalid.", nil,
	)
}

func writeAuditInvalidQuery(c *gin.Context) {
	WriteError(
		c, http.StatusBadRequest, "invalid_query",
		"The audit log query is invalid.", nil,
	)
}

func writeUserAdminError(c *gin.Context, err error) {
	switch {
	case errors.Is(err, useradmin.ErrInvalidInput):
		WriteError(
			c, http.StatusBadRequest, "invalid_request",
			"The user administration request is invalid.", nil,
		)
	case errors.Is(err, useradmin.ErrNotFound):
		WriteError(c, http.StatusNotFound, "user_not_found", "The user was not found.", nil)
	case errors.Is(err, useradmin.ErrUsernameExists):
		WriteError(
			c, http.StatusConflict, "username_exists",
			"The username is already in use.", nil,
		)
	case errors.Is(err, useradmin.ErrCurrentUserGuard):
		WriteError(
			c, http.StatusConflict, "current_user_protected",
			"The current administrator cannot disable or demote itself.", nil,
		)
	case errors.Is(err, useradmin.ErrLastAdministrator):
		WriteError(
			c, http.StatusConflict, "last_administrator",
			"At least one active administrator must remain.", nil,
		)
	case errors.Is(err, useradmin.ErrConflict):
		WriteError(
			c, http.StatusConflict, "user_changed",
			"The user changed after it was loaded.", nil,
		)
	case errors.Is(err, useradmin.ErrForbidden):
		WriteError(c, http.StatusForbidden, "permission_denied", "Permission is denied.", nil)
	default:
		c.Error(err).SetType(gin.ErrorTypePrivate)
		WriteError(
			c, http.StatusInternalServerError, "user_administration_failed",
			"The user administration operation could not be completed.", nil,
		)
	}
}

func zeroAPIBytes(value []byte) {
	for index := range value {
		value[index] = 0
	}
}

func adminNoStore() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("Cache-Control", "private, no-store")
		c.Header("Pragma", "no-cache")
		c.Next()
	}
}

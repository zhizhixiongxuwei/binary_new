package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"

	"binaryscan/internal/auth"
	"binaryscan/internal/task"

	"github.com/gin-gonic/gin"
)

type TaskService interface {
	Create(context.Context, uint64, auth.Role, string, string, string) (task.View, bool, error)
	List(context.Context, task.ListQuery) (task.Page, error)
	Get(context.Context, string) (task.View, error)
	Cancel(context.Context, uint64, auth.Role, string, string) (task.View, error)
	Retry(context.Context, uint64, auth.Role, string, string) (task.View, error)
	Delete(context.Context, uint64, auth.Role, string) (task.View, error)
	ExtendRetention(context.Context, uint64, auth.Role, string, string, string) (task.View, error)
}

func registerTaskRoutes(v1 *gin.RouterGroup, manager AuthManager, service TaskService) {
	routes := v1.Group("/tasks")
	routes.Use(RequireSession(manager))
	routes.GET("", listTasksHandler(service))
	routes.GET("/:id", getTaskHandler(service))
	routes.POST(
		"",
		RequireCSRF(manager),
		RequireRoles(auth.RoleAdministrator, auth.RoleOperator),
		createTaskHandler(service),
	)
	routes.POST(
		"/:id/cancel",
		RequireCSRF(manager),
		RequireRoles(auth.RoleAdministrator, auth.RoleOperator),
		cancelTaskHandler(service),
	)
	routes.POST(
		"/:id/retry",
		RequireCSRF(manager),
		RequireRoles(auth.RoleAdministrator, auth.RoleOperator),
		retryTaskHandler(service),
	)
	routes.DELETE(
		"/:id",
		RequireCSRF(manager),
		RequireRoles(auth.RoleAdministrator, auth.RoleOperator),
		deleteTaskHandler(service),
	)
	routes.PATCH(
		"/:id/retention",
		RequireCSRF(manager),
		RequireRoles(auth.RoleAdministrator),
		extendTaskRetentionHandler(service),
	)
}

func createTaskHandler(service TaskService) gin.HandlerFunc {
	type createRequest struct {
		UploadID string `json:"upload_id"`
		Name     string `json:"name"`
	}
	return func(c *gin.Context) {
		c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, 16*1024)
		decoder := json.NewDecoder(c.Request.Body)
		decoder.DisallowUnknownFields()
		var request createRequest
		if err := decoder.Decode(&request); err != nil || ensureJSONEnd(decoder) != nil {
			WriteError(c, http.StatusBadRequest, "invalid_request", "The task request is not valid.", nil)
			return
		}
		session, ok := CurrentSession(c)
		if !ok {
			WriteError(c, http.StatusUnauthorized, "authentication_required", "Authentication is required.", nil)
			return
		}
		value, created, err := service.Create(
			c.Request.Context(),
			session.User.UserID,
			session.User.Role,
			request.UploadID,
			request.Name,
			c.GetHeader("Idempotency-Key"),
		)
		if err != nil {
			writeTaskError(c, err)
			return
		}
		status := http.StatusOK
		if created {
			status = http.StatusCreated
		}
		Write(c, status, value)
	}
}

func listTasksHandler(service TaskService) gin.HandlerFunc {
	return func(c *gin.Context) {
		values := c.Request.URL.Query()
		if !taskQueryFieldsValid(values) || !optionalCursorValid(values) {
			WriteError(c, http.StatusBadRequest, "invalid_task_query", "The task query is invalid.", nil)
			return
		}
		pageSize, err := positiveQueryInt(c, "page_size", 20)
		if err != nil {
			WriteError(c, http.StatusBadRequest, "invalid_task_query", "The task query is invalid.", nil)
			return
		}
		result, err := service.List(c.Request.Context(), task.ListQuery{
			Cursor: c.Query("cursor"), PageSize: pageSize,
			Keyword: c.Query("keyword"), Status: c.Query("status"),
			InputType: c.Query("input_type"),
			Creator:   c.Query("creator"), Tag: c.Query("tag"),
			CreatedFrom: c.Query("created_from"), CreatedTo: c.Query("created_to"),
		})
		if err != nil {
			writeTaskError(c, err)
			return
		}
		Write(c, http.StatusOK, result)
	}
}

func getTaskHandler(service TaskService) gin.HandlerFunc {
	return func(c *gin.Context) {
		value, err := service.Get(c.Request.Context(), c.Param("id"))
		if err != nil {
			writeTaskError(c, err)
			return
		}
		Write(c, http.StatusOK, value)
	}
}

func cancelTaskHandler(service TaskService) gin.HandlerFunc {
	return func(c *gin.Context) {
		session, ok := CurrentSession(c)
		if !ok {
			WriteError(c, http.StatusUnauthorized, "authentication_required", "Authentication is required.", nil)
			return
		}
		value, err := service.Cancel(
			c.Request.Context(), session.User.UserID, session.User.Role,
			c.Param("id"), c.GetHeader("Idempotency-Key"),
		)
		if err != nil {
			writeTaskError(c, err)
			return
		}
		Write(c, http.StatusOK, value)
	}
}

func retryTaskHandler(service TaskService) gin.HandlerFunc {
	return func(c *gin.Context) {
		session, ok := CurrentSession(c)
		if !ok {
			WriteError(c, http.StatusUnauthorized, "authentication_required", "Authentication is required.", nil)
			return
		}
		value, err := service.Retry(
			c.Request.Context(), session.User.UserID, session.User.Role,
			c.Param("id"), c.GetHeader("Idempotency-Key"),
		)
		if err != nil {
			writeTaskError(c, err)
			return
		}
		Write(c, http.StatusOK, value)
	}
}

func deleteTaskHandler(service TaskService) gin.HandlerFunc {
	return func(c *gin.Context) {
		session, ok := CurrentSession(c)
		if !ok {
			WriteError(c, http.StatusUnauthorized, "authentication_required", "Authentication is required.", nil)
			return
		}
		value, err := service.Delete(
			c.Request.Context(), session.User.UserID, session.User.Role, c.Param("id"),
		)
		if err != nil {
			writeTaskError(c, err)
			return
		}
		Write(c, http.StatusOK, value)
	}
}

func extendTaskRetentionHandler(service TaskService) gin.HandlerFunc {
	type retentionRequest struct {
		ExpectedSampleExpiresAt string `json:"expected_sample_expires_at"`
		SampleExpiresAt         string `json:"sample_expires_at"`
	}
	return func(c *gin.Context) {
		c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, 4*1024)
		decoder := json.NewDecoder(c.Request.Body)
		decoder.DisallowUnknownFields()
		var request retentionRequest
		if err := decoder.Decode(&request); err != nil || ensureJSONEnd(decoder) != nil {
			WriteError(c, http.StatusBadRequest, "invalid_request", "The retention request is not valid.", nil)
			return
		}
		session, ok := CurrentSession(c)
		if !ok {
			WriteError(c, http.StatusUnauthorized, "authentication_required", "Authentication is required.", nil)
			return
		}
		value, err := service.ExtendRetention(
			c.Request.Context(),
			session.User.UserID,
			session.User.Role,
			c.Param("id"),
			request.ExpectedSampleExpiresAt,
			request.SampleExpiresAt,
		)
		if err != nil {
			writeTaskError(c, err)
			return
		}
		Write(c, http.StatusOK, value)
	}
}

func positiveQueryInt(c *gin.Context, name string, fallback int) (int, error) {
	raw := strings.TrimSpace(c.Query(name))
	if raw == "" {
		return fallback, nil
	}
	value, err := strconv.Atoi(raw)
	if err != nil || value <= 0 {
		return 0, task.ErrInvalidInput
	}
	return value, nil
}

func taskQueryFieldsValid(values map[string][]string) bool {
	allowed := map[string]struct{}{
		"cursor": {}, "page_size": {}, "keyword": {}, "status": {}, "input_type": {},
		"creator": {}, "tag": {}, "created_from": {}, "created_to": {},
	}
	for name, entries := range values {
		if _, ok := allowed[name]; !ok || len(entries) != 1 {
			return false
		}
	}
	return true
}

func writeTaskError(c *gin.Context, err error) {
	switch {
	case errors.Is(err, task.ErrInvalidInput):
		WriteError(c, http.StatusBadRequest, "invalid_task", "The task request is invalid.", nil)
	case errors.Is(err, task.ErrForbidden):
		WriteError(c, http.StatusForbidden, "task_forbidden", "The task operation is not permitted for this user.", nil)
	case errors.Is(err, task.ErrNotFound):
		WriteError(c, http.StatusNotFound, "task_not_found", "The task or upload was not found.", nil)
	case errors.Is(err, task.ErrUploadNotCompleted):
		WriteError(c, http.StatusConflict, "upload_not_completed", "The upload must be completed first.", nil)
	case errors.Is(err, task.ErrUploadNotEligible):
		WriteError(c, http.StatusUnprocessableEntity, "upload_not_task_eligible", "The upload is not eligible for direct task creation.", nil)
	case errors.Is(err, task.ErrConflict):
		WriteError(c, http.StatusConflict, "task_conflict", "The task conflicts with an existing request.", nil)
	case errors.Is(err, task.ErrInvalidState):
		WriteError(c, http.StatusConflict, "task_state_conflict", "The task state does not permit this operation.", nil)
	case errors.Is(err, task.ErrSampleUnavailable):
		WriteError(c, http.StatusConflict, "task_sample_unavailable", "The retained sample is deleted or expired.", nil)
	default:
		c.Error(err).SetType(gin.ErrorTypePrivate)
		WriteError(c, http.StatusInternalServerError, "task_failed", "The task operation could not be completed.", nil)
	}
}

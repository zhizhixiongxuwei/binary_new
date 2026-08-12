package api

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strconv"

	"binaryscan/internal/auth"
	"binaryscan/internal/javaanalysis"

	"github.com/gin-gonic/gin"
)

type JavaAnalysisService interface {
	Create(context.Context, javaanalysis.CreateInput) (javaanalysis.Run, bool, error)
	List(context.Context, javaanalysis.ListQuery) (javaanalysis.RunPage, error)
	Get(context.Context, javaanalysis.RunQuery) (javaanalysis.Run, error)
	ListFindings(
		context.Context, javaanalysis.FindingsQuery,
	) (javaanalysis.FindingPage, error)
	Cancel(context.Context, javaanalysis.ActionInput) (javaanalysis.Run, error)
	Delete(context.Context, javaanalysis.ActionInput) error
}

func registerJavaAnalysisRoutes(
	v1 *gin.RouterGroup,
	manager AuthManager,
	service JavaAnalysisService,
) {
	routes := v1.Group("/tasks")
	routes.Use(RequireSession(manager))
	routes.GET("/:id/java-analysis-runs", listJavaAnalysisRunsHandler(service))
	routes.GET("/:id/java-analysis-runs/:run_id", getJavaAnalysisRunHandler(service))
	routes.GET(
		"/:id/java-analysis-runs/:run_id/findings",
		listJavaAnalysisFindingsHandler(service),
	)
	routes.POST(
		"/:id/decompile-projects/:project_id/java-analysis-runs",
		RequireCSRF(manager),
		RequireRoles(auth.RoleAdministrator, auth.RoleOperator),
		createJavaAnalysisRunHandler(service),
	)
	routes.POST(
		"/:id/java-analysis-runs/:run_id/cancel",
		RequireCSRF(manager),
		RequireRoles(auth.RoleAdministrator, auth.RoleOperator),
		cancelJavaAnalysisRunHandler(service),
	)
	routes.DELETE(
		"/:id/java-analysis-runs/:run_id",
		RequireCSRF(manager),
		RequireRoles(auth.RoleAdministrator, auth.RoleOperator),
		deleteJavaAnalysisRunHandler(service),
	)
}

func createJavaAnalysisRunHandler(service JavaAnalysisService) gin.HandlerFunc {
	return func(c *gin.Context) {
		if len(c.Request.URL.Query()) != 0 || !javaAnalysisBodyEmpty(c.Request) {
			writeJavaAnalysisInvalid(c)
			return
		}
		keys := c.Request.Header.Values("Idempotency-Key")
		if len(keys) != 1 {
			WriteError(
				c, http.StatusBadRequest, "idempotency_key_required",
				"A single valid Idempotency-Key header is required.", nil,
			)
			return
		}
		session, ok := CurrentSession(c)
		if !ok {
			WriteError(
				c, http.StatusUnauthorized, "authentication_required",
				"Authentication is required.", nil,
			)
			return
		}
		value, created, err := service.Create(
			c.Request.Context(),
			javaanalysis.CreateInput{
				TaskID: c.Param("id"), SourceProjectID: c.Param("project_id"),
				IdempotencyKey: keys[0], UserID: session.User.UserID,
				Role: session.User.Role,
			},
		)
		if err != nil {
			writeJavaAnalysisError(c, err)
			return
		}
		status := http.StatusOK
		if created {
			status = http.StatusCreated
		}
		Write(c, status, value)
	}
}

func listJavaAnalysisRunsHandler(service JavaAnalysisService) gin.HandlerFunc {
	return func(c *gin.Context) {
		values := c.Request.URL.Query()
		if !javaAnalysisQueryFieldsValid(
			values, "cursor", "page_size", "project_id",
		) {
			writeJavaAnalysisInvalid(c)
			return
		}
		pageSize, err := javaAnalysisPageSize(values)
		if err != nil {
			writeJavaAnalysisInvalid(c)
			return
		}
		var after *javaanalysis.RunCursor
		if cursor := values.Get("cursor"); cursor != "" {
			decoded, err := javaanalysis.DecodeRunCursor(cursor)
			if err != nil {
				writeJavaAnalysisInvalid(c)
				return
			}
			after = &decoded
		}
		page, err := service.List(c.Request.Context(), javaanalysis.ListQuery{
			TaskID: c.Param("id"), SourceProjectID: values.Get("project_id"),
			After: after, PageSize: pageSize,
		})
		if err != nil {
			writeJavaAnalysisError(c, err)
			return
		}
		Write(c, http.StatusOK, page)
	}
}

func getJavaAnalysisRunHandler(service JavaAnalysisService) gin.HandlerFunc {
	return func(c *gin.Context) {
		if len(c.Request.URL.Query()) != 0 {
			writeJavaAnalysisInvalid(c)
			return
		}
		value, err := service.Get(c.Request.Context(), javaanalysis.RunQuery{
			TaskID: c.Param("id"), RunID: c.Param("run_id"),
		})
		if err != nil {
			writeJavaAnalysisError(c, err)
			return
		}
		Write(c, http.StatusOK, value)
	}
}

func listJavaAnalysisFindingsHandler(service JavaAnalysisService) gin.HandlerFunc {
	return func(c *gin.Context) {
		values := c.Request.URL.Query()
		if !javaAnalysisQueryFieldsValid(
			values, "cursor", "page_size", "cwe", "severity", "file", "callable",
		) {
			writeJavaAnalysisInvalid(c)
			return
		}
		pageSize, err := javaAnalysisPageSize(values)
		if err != nil {
			writeJavaAnalysisInvalid(c)
			return
		}
		var cursor uint64
		if raw := values.Get("cursor"); raw != "" {
			cursor, err = strconv.ParseUint(raw, 10, 64)
			if err != nil || cursor == 0 || strconv.FormatUint(cursor, 10) != raw {
				writeJavaAnalysisInvalid(c)
				return
			}
		}
		page, err := service.ListFindings(
			c.Request.Context(),
			javaanalysis.FindingsQuery{
				TaskID: c.Param("id"), RunID: c.Param("run_id"),
				Cursor: cursor, PageSize: pageSize, CWE: values.Get("cwe"),
				Severity: values.Get("severity"), File: values.Get("file"),
				Callable: values.Get("callable"),
			},
		)
		if err != nil {
			writeJavaAnalysisError(c, err)
			return
		}
		Write(c, http.StatusOK, page)
	}
}

func cancelJavaAnalysisRunHandler(service JavaAnalysisService) gin.HandlerFunc {
	return func(c *gin.Context) {
		if len(c.Request.URL.Query()) != 0 || !javaAnalysisBodyEmpty(c.Request) {
			writeJavaAnalysisInvalid(c)
			return
		}
		session, ok := CurrentSession(c)
		if !ok {
			WriteError(
				c, http.StatusUnauthorized, "authentication_required",
				"Authentication is required.", nil,
			)
			return
		}
		value, err := service.Cancel(
			c.Request.Context(),
			javaanalysis.ActionInput{
				TaskID: c.Param("id"), RunID: c.Param("run_id"),
				UserID: session.User.UserID, Role: session.User.Role,
			},
		)
		if err != nil {
			writeJavaAnalysisError(c, err)
			return
		}
		Write(c, http.StatusOK, value)
	}
}

func deleteJavaAnalysisRunHandler(service JavaAnalysisService) gin.HandlerFunc {
	return func(c *gin.Context) {
		if len(c.Request.URL.Query()) != 0 || !javaAnalysisBodyEmpty(c.Request) {
			writeJavaAnalysisInvalid(c)
			return
		}
		session, ok := CurrentSession(c)
		if !ok {
			WriteError(
				c, http.StatusUnauthorized, "authentication_required",
				"Authentication is required.", nil,
			)
			return
		}
		err := service.Delete(
			c.Request.Context(),
			javaanalysis.ActionInput{
				TaskID: c.Param("id"), RunID: c.Param("run_id"),
				UserID: session.User.UserID, Role: session.User.Role,
			},
		)
		if err != nil {
			writeJavaAnalysisError(c, err)
			return
		}
		c.Status(http.StatusNoContent)
	}
}

func javaAnalysisBodyEmpty(request *http.Request) bool {
	if request == nil || request.ContentLength > 0 {
		return false
	}
	if request.Body == nil || request.Body == http.NoBody {
		return true
	}
	written, err := io.Copy(io.Discard, io.LimitReader(request.Body, 1))
	return err == nil && written == 0
}

func javaAnalysisPageSize(values url.Values) (int, error) {
	raw := values.Get("page_size")
	if raw == "" {
		return 50, nil
	}
	value, err := strconv.Atoi(raw)
	if err != nil || value < 1 || value > javaanalysis.MaxPageSize ||
		strconv.Itoa(value) != raw {
		return 0, javaanalysis.ErrInvalidInput
	}
	return value, nil
}

func javaAnalysisQueryFieldsValid(values url.Values, allowed ...string) bool {
	accepted := make(map[string]struct{}, len(allowed))
	for _, field := range allowed {
		accepted[field] = struct{}{}
	}
	for field, entries := range values {
		if _, ok := accepted[field]; !ok || len(entries) != 1 {
			return false
		}
	}
	return true
}

func writeJavaAnalysisInvalid(c *gin.Context) {
	WriteError(
		c, http.StatusBadRequest, "invalid_java_analysis_request",
		"The Java analysis request is invalid.", nil,
	)
}

func writeJavaAnalysisError(c *gin.Context, err error) {
	switch {
	case errors.Is(err, javaanalysis.ErrInvalidInput):
		writeJavaAnalysisInvalid(c)
	case errors.Is(err, javaanalysis.ErrTaskNotFound):
		WriteError(c, http.StatusNotFound, "task_not_found", "The task was not found.", nil)
	case errors.Is(err, javaanalysis.ErrProjectNotFound):
		WriteError(
			c, http.StatusNotFound, "java_analysis_project_not_found",
			"The eligible Java source project was not found.", nil,
		)
	case errors.Is(err, javaanalysis.ErrRunNotFound):
		WriteError(
			c, http.StatusNotFound, "java_analysis_run_not_found",
			"The Java analysis run was not found.", nil,
		)
	case errors.Is(err, javaanalysis.ErrNotReady):
		WriteError(
			c, http.StatusServiceUnavailable, "java_analysis_not_ready",
			"The Java analysis checker is not ready.", nil,
		)
	case errors.Is(err, javaanalysis.ErrAlreadyActive):
		WriteError(
			c, http.StatusConflict, "java_analysis_already_active",
			"This source project already has an active Java analysis run.", nil,
		)
	case errors.Is(err, javaanalysis.ErrIdempotencyConflict):
		WriteError(
			c, http.StatusConflict, "idempotency_conflict",
			"The Idempotency-Key was already used for another Java analysis request.", nil,
		)
	case errors.Is(err, javaanalysis.ErrSourceUnavailable):
		WriteError(
			c, http.StatusConflict, "java_analysis_source_unavailable",
			"The Java source project is unavailable or ineligible.", nil,
		)
	case errors.Is(err, javaanalysis.ErrRunNotCancellable):
		WriteError(
			c, http.StatusConflict, "java_analysis_not_cancellable",
			"The Java analysis run cannot be cancelled in its current state.", nil,
		)
	case errors.Is(err, javaanalysis.ErrRunNotDeletable):
		WriteError(
			c, http.StatusConflict, "java_analysis_not_deletable",
			"Only a fully terminal Java analysis run can be deleted.", nil,
		)
	default:
		WriteError(
			c, http.StatusInternalServerError, "java_analysis_operation_failed",
			"The Java analysis operation failed.", nil,
		)
	}
}

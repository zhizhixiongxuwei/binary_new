package api

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strconv"

	"binaryscan/internal/auth"
	"binaryscan/internal/pythonanalysis"

	"github.com/gin-gonic/gin"
)

type PythonAnalysisService interface {
	Create(context.Context, pythonanalysis.CreateInput) (pythonanalysis.Run, bool, error)
	List(context.Context, pythonanalysis.ListQuery) (pythonanalysis.RunPage, error)
	Get(context.Context, pythonanalysis.RunQuery) (pythonanalysis.Run, error)
	ListFindings(
		context.Context, pythonanalysis.FindingsQuery,
	) (pythonanalysis.FindingPage, error)
	Cancel(context.Context, pythonanalysis.ActionInput) (pythonanalysis.Run, error)
	Delete(context.Context, pythonanalysis.ActionInput) error
}

func registerPythonAnalysisRoutes(
	v1 *gin.RouterGroup,
	manager AuthManager,
	service PythonAnalysisService,
) {
	routes := v1.Group("/tasks")
	routes.Use(RequireSession(manager))
	routes.GET("/:id/python-analysis-runs", listPythonAnalysisRunsHandler(service))
	routes.GET("/:id/python-analysis-runs/:run_id", getPythonAnalysisRunHandler(service))
	routes.GET(
		"/:id/python-analysis-runs/:run_id/findings",
		listPythonAnalysisFindingsHandler(service),
	)
	routes.POST(
		"/:id/decompile-projects/:project_id/python-analysis-runs",
		RequireCSRF(manager),
		RequireRoles(auth.RoleAdministrator, auth.RoleOperator),
		createPythonAnalysisRunHandler(service),
	)
	routes.POST(
		"/:id/python-analysis-runs/:run_id/cancel",
		RequireCSRF(manager),
		RequireRoles(auth.RoleAdministrator, auth.RoleOperator),
		cancelPythonAnalysisRunHandler(service),
	)
	routes.DELETE(
		"/:id/python-analysis-runs/:run_id",
		RequireCSRF(manager),
		RequireRoles(auth.RoleAdministrator, auth.RoleOperator),
		deletePythonAnalysisRunHandler(service),
	)
}

func createPythonAnalysisRunHandler(service PythonAnalysisService) gin.HandlerFunc {
	return func(c *gin.Context) {
		if len(c.Request.URL.Query()) != 0 || !pythonAnalysisBodyEmpty(c.Request) {
			writePythonAnalysisInvalid(c)
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
			pythonanalysis.CreateInput{
				TaskID: c.Param("id"), SourceProjectID: c.Param("project_id"),
				IdempotencyKey: keys[0], UserID: session.User.UserID,
				Role: session.User.Role,
			},
		)
		if err != nil {
			writePythonAnalysisError(c, err)
			return
		}
		status := http.StatusOK
		if created {
			status = http.StatusCreated
		}
		Write(c, status, value)
	}
}

func listPythonAnalysisRunsHandler(service PythonAnalysisService) gin.HandlerFunc {
	return func(c *gin.Context) {
		values := c.Request.URL.Query()
		if !pythonAnalysisQueryFieldsValid(
			values, "cursor", "page_size", "project_id",
		) {
			writePythonAnalysisInvalid(c)
			return
		}
		pageSize, err := pythonAnalysisPageSize(values)
		if err != nil {
			writePythonAnalysisInvalid(c)
			return
		}
		var after *pythonanalysis.RunCursor
		if cursor := values.Get("cursor"); cursor != "" {
			decoded, err := pythonanalysis.DecodeRunCursor(cursor)
			if err != nil {
				writePythonAnalysisInvalid(c)
				return
			}
			after = &decoded
		}
		page, err := service.List(c.Request.Context(), pythonanalysis.ListQuery{
			TaskID: c.Param("id"), SourceProjectID: values.Get("project_id"),
			After: after, PageSize: pageSize,
		})
		if err != nil {
			writePythonAnalysisError(c, err)
			return
		}
		Write(c, http.StatusOK, page)
	}
}

func getPythonAnalysisRunHandler(service PythonAnalysisService) gin.HandlerFunc {
	return func(c *gin.Context) {
		if len(c.Request.URL.Query()) != 0 {
			writePythonAnalysisInvalid(c)
			return
		}
		value, err := service.Get(c.Request.Context(), pythonanalysis.RunQuery{
			TaskID: c.Param("id"), RunID: c.Param("run_id"),
		})
		if err != nil {
			writePythonAnalysisError(c, err)
			return
		}
		Write(c, http.StatusOK, value)
	}
}

func listPythonAnalysisFindingsHandler(service PythonAnalysisService) gin.HandlerFunc {
	return func(c *gin.Context) {
		values := c.Request.URL.Query()
		if !pythonAnalysisQueryFieldsValid(
			values, "cursor", "page_size", "cwe", "severity", "file", "callable",
		) {
			writePythonAnalysisInvalid(c)
			return
		}
		pageSize, err := pythonAnalysisPageSize(values)
		if err != nil {
			writePythonAnalysisInvalid(c)
			return
		}
		var cursor uint64
		if raw := values.Get("cursor"); raw != "" {
			cursor, err = strconv.ParseUint(raw, 10, 64)
			if err != nil || cursor == 0 || strconv.FormatUint(cursor, 10) != raw {
				writePythonAnalysisInvalid(c)
				return
			}
		}
		page, err := service.ListFindings(
			c.Request.Context(),
			pythonanalysis.FindingsQuery{
				TaskID: c.Param("id"), RunID: c.Param("run_id"),
				Cursor: cursor, PageSize: pageSize, CWE: values.Get("cwe"),
				Severity: values.Get("severity"), File: values.Get("file"),
				Callable: values.Get("callable"),
			},
		)
		if err != nil {
			writePythonAnalysisError(c, err)
			return
		}
		Write(c, http.StatusOK, page)
	}
}

func cancelPythonAnalysisRunHandler(service PythonAnalysisService) gin.HandlerFunc {
	return func(c *gin.Context) {
		if len(c.Request.URL.Query()) != 0 || !pythonAnalysisBodyEmpty(c.Request) {
			writePythonAnalysisInvalid(c)
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
			pythonanalysis.ActionInput{
				TaskID: c.Param("id"), RunID: c.Param("run_id"),
				UserID: session.User.UserID, Role: session.User.Role,
			},
		)
		if err != nil {
			writePythonAnalysisError(c, err)
			return
		}
		Write(c, http.StatusOK, value)
	}
}

func deletePythonAnalysisRunHandler(service PythonAnalysisService) gin.HandlerFunc {
	return func(c *gin.Context) {
		if len(c.Request.URL.Query()) != 0 || !pythonAnalysisBodyEmpty(c.Request) {
			writePythonAnalysisInvalid(c)
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
			pythonanalysis.ActionInput{
				TaskID: c.Param("id"), RunID: c.Param("run_id"),
				UserID: session.User.UserID, Role: session.User.Role,
			},
		)
		if err != nil {
			writePythonAnalysisError(c, err)
			return
		}
		c.Status(http.StatusNoContent)
	}
}

func pythonAnalysisBodyEmpty(request *http.Request) bool {
	if request == nil || request.ContentLength > 0 {
		return false
	}
	if request.Body == nil || request.Body == http.NoBody {
		return true
	}
	written, err := io.Copy(io.Discard, io.LimitReader(request.Body, 1))
	return err == nil && written == 0
}

func pythonAnalysisPageSize(values url.Values) (int, error) {
	raw := values.Get("page_size")
	if raw == "" {
		return 50, nil
	}
	value, err := strconv.Atoi(raw)
	if err != nil || value < 1 || value > pythonanalysis.MaxPageSize ||
		strconv.Itoa(value) != raw {
		return 0, pythonanalysis.ErrInvalidInput
	}
	return value, nil
}

func pythonAnalysisQueryFieldsValid(values url.Values, allowed ...string) bool {
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

func writePythonAnalysisInvalid(c *gin.Context) {
	WriteError(
		c, http.StatusBadRequest, "invalid_python_analysis_request",
		"The Python analysis request is invalid.", nil,
	)
}

func writePythonAnalysisError(c *gin.Context, err error) {
	switch {
	case errors.Is(err, pythonanalysis.ErrInvalidInput):
		writePythonAnalysisInvalid(c)
	case errors.Is(err, pythonanalysis.ErrTaskNotFound):
		WriteError(c, http.StatusNotFound, "task_not_found", "The task was not found.", nil)
	case errors.Is(err, pythonanalysis.ErrProjectNotFound):
		WriteError(
			c, http.StatusNotFound, "python_analysis_project_not_found",
			"The eligible Java source project was not found.", nil,
		)
	case errors.Is(err, pythonanalysis.ErrRunNotFound):
		WriteError(
			c, http.StatusNotFound, "python_analysis_run_not_found",
			"The Python analysis run was not found.", nil,
		)
	case errors.Is(err, pythonanalysis.ErrNotReady):
		WriteError(
			c, http.StatusServiceUnavailable, "python_analysis_not_ready",
			"The Python analysis checker is not ready.", nil,
		)
	case errors.Is(err, pythonanalysis.ErrAlreadyActive):
		WriteError(
			c, http.StatusConflict, "python_analysis_already_active",
			"This source project already has an active Python analysis run.", nil,
		)
	case errors.Is(err, pythonanalysis.ErrIdempotencyConflict):
		WriteError(
			c, http.StatusConflict, "idempotency_conflict",
			"The Idempotency-Key was already used for another Python analysis request.", nil,
		)
	case errors.Is(err, pythonanalysis.ErrSourceUnavailable):
		WriteError(
			c, http.StatusConflict, "python_analysis_source_unavailable",
			"The Java source project is unavailable or ineligible.", nil,
		)
	case errors.Is(err, pythonanalysis.ErrRunNotCancellable):
		WriteError(
			c, http.StatusConflict, "python_analysis_not_cancellable",
			"The Python analysis run cannot be cancelled in its current state.", nil,
		)
	case errors.Is(err, pythonanalysis.ErrRunNotDeletable):
		WriteError(
			c, http.StatusConflict, "python_analysis_not_deletable",
			"Only a fully terminal Python analysis run can be deleted.", nil,
		)
	default:
		c.Error(err).SetType(gin.ErrorTypePrivate)
		WriteError(
			c, http.StatusInternalServerError, "python_analysis_operation_failed",
			"The Python analysis operation failed.", nil,
		)
	}
}

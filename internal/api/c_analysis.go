package api

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strconv"

	"binaryscan/internal/auth"
	"binaryscan/internal/canalysis"

	"github.com/gin-gonic/gin"
)

type CAnalysisService interface {
	Create(context.Context, canalysis.CreateInput) (canalysis.Run, bool, error)
	List(context.Context, canalysis.ListQuery) (canalysis.RunPage, error)
	Get(context.Context, canalysis.RunQuery) (canalysis.Run, error)
	ListFindings(
		context.Context, canalysis.FindingsQuery,
	) (canalysis.FindingPage, error)
	Cancel(context.Context, canalysis.ActionInput) (canalysis.Run, error)
	Delete(context.Context, canalysis.ActionInput) error
}

func registerCAnalysisRoutes(
	v1 *gin.RouterGroup,
	manager AuthManager,
	service CAnalysisService,
) {
	routes := v1.Group("/tasks")
	routes.Use(RequireSession(manager))
	routes.GET("/:id/c-analysis-runs", listCAnalysisRunsHandler(service))
	routes.GET("/:id/c-analysis-runs/:run_id", getCAnalysisRunHandler(service))
	routes.GET(
		"/:id/c-analysis-runs/:run_id/findings",
		listCAnalysisFindingsHandler(service),
	)
	routes.POST(
		"/:id/decompile-projects/:project_id/c-analysis-runs",
		RequireCSRF(manager),
		RequireRoles(auth.RoleAdministrator, auth.RoleOperator),
		createCAnalysisRunHandler(service),
	)
	routes.POST(
		"/:id/c-analysis-runs/:run_id/cancel",
		RequireCSRF(manager),
		RequireRoles(auth.RoleAdministrator, auth.RoleOperator),
		cancelCAnalysisRunHandler(service),
	)
	routes.DELETE(
		"/:id/c-analysis-runs/:run_id",
		RequireCSRF(manager),
		RequireRoles(auth.RoleAdministrator, auth.RoleOperator),
		deleteCAnalysisRunHandler(service),
	)
}

func createCAnalysisRunHandler(service CAnalysisService) gin.HandlerFunc {
	return func(c *gin.Context) {
		if len(c.Request.URL.Query()) != 0 || !cAnalysisBodyEmpty(c.Request) {
			writeCAnalysisInvalid(c)
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
			canalysis.CreateInput{
				TaskID: c.Param("id"), SourceProjectID: c.Param("project_id"),
				IdempotencyKey: keys[0], UserID: session.User.UserID,
				Role: session.User.Role,
			},
		)
		if err != nil {
			writeCAnalysisError(c, err)
			return
		}
		status := http.StatusOK
		if created {
			status = http.StatusCreated
		}
		Write(c, status, value)
	}
}

func listCAnalysisRunsHandler(service CAnalysisService) gin.HandlerFunc {
	return func(c *gin.Context) {
		values := c.Request.URL.Query()
		if !cAnalysisQueryFieldsValid(
			values, "cursor", "page_size", "project_id",
		) {
			writeCAnalysisInvalid(c)
			return
		}
		pageSize, err := cAnalysisPageSize(values)
		if err != nil {
			writeCAnalysisInvalid(c)
			return
		}
		var after *canalysis.RunCursor
		if cursor := values.Get("cursor"); cursor != "" {
			decoded, err := canalysis.DecodeRunCursor(cursor)
			if err != nil {
				writeCAnalysisInvalid(c)
				return
			}
			after = &decoded
		}
		page, err := service.List(c.Request.Context(), canalysis.ListQuery{
			TaskID: c.Param("id"), SourceProjectID: values.Get("project_id"),
			After: after, PageSize: pageSize,
		})
		if err != nil {
			writeCAnalysisError(c, err)
			return
		}
		Write(c, http.StatusOK, page)
	}
}

func getCAnalysisRunHandler(service CAnalysisService) gin.HandlerFunc {
	return func(c *gin.Context) {
		if len(c.Request.URL.Query()) != 0 {
			writeCAnalysisInvalid(c)
			return
		}
		value, err := service.Get(c.Request.Context(), canalysis.RunQuery{
			TaskID: c.Param("id"), RunID: c.Param("run_id"),
		})
		if err != nil {
			writeCAnalysisError(c, err)
			return
		}
		Write(c, http.StatusOK, value)
	}
}

func listCAnalysisFindingsHandler(service CAnalysisService) gin.HandlerFunc {
	return func(c *gin.Context) {
		values := c.Request.URL.Query()
		if !cAnalysisQueryFieldsValid(
			values, "cursor", "page_size", "cwe", "severity", "function",
		) {
			writeCAnalysisInvalid(c)
			return
		}
		pageSize, err := cAnalysisPageSize(values)
		if err != nil {
			writeCAnalysisInvalid(c)
			return
		}
		var cursor uint64
		if raw := values.Get("cursor"); raw != "" {
			cursor, err = strconv.ParseUint(raw, 10, 64)
			if err != nil || cursor == 0 || strconv.FormatUint(cursor, 10) != raw {
				writeCAnalysisInvalid(c)
				return
			}
		}
		page, err := service.ListFindings(
			c.Request.Context(),
			canalysis.FindingsQuery{
				TaskID: c.Param("id"), RunID: c.Param("run_id"),
				Cursor: cursor, PageSize: pageSize, CWE: values.Get("cwe"),
				Severity: values.Get("severity"), Function: values.Get("function"),
			},
		)
		if err != nil {
			writeCAnalysisError(c, err)
			return
		}
		Write(c, http.StatusOK, page)
	}
}

func cancelCAnalysisRunHandler(service CAnalysisService) gin.HandlerFunc {
	return func(c *gin.Context) {
		if len(c.Request.URL.Query()) != 0 || !cAnalysisBodyEmpty(c.Request) {
			writeCAnalysisInvalid(c)
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
			canalysis.ActionInput{
				TaskID: c.Param("id"), RunID: c.Param("run_id"),
				UserID: session.User.UserID, Role: session.User.Role,
			},
		)
		if err != nil {
			writeCAnalysisError(c, err)
			return
		}
		Write(c, http.StatusOK, value)
	}
}

func deleteCAnalysisRunHandler(service CAnalysisService) gin.HandlerFunc {
	return func(c *gin.Context) {
		if len(c.Request.URL.Query()) != 0 || !cAnalysisBodyEmpty(c.Request) {
			writeCAnalysisInvalid(c)
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
			canalysis.ActionInput{
				TaskID: c.Param("id"), RunID: c.Param("run_id"),
				UserID: session.User.UserID, Role: session.User.Role,
			},
		)
		if err != nil {
			writeCAnalysisError(c, err)
			return
		}
		c.Status(http.StatusNoContent)
	}
}

func cAnalysisBodyEmpty(request *http.Request) bool {
	if request == nil || request.ContentLength > 0 {
		return false
	}
	if request.Body == nil || request.Body == http.NoBody {
		return true
	}
	written, err := io.Copy(io.Discard, io.LimitReader(request.Body, 1))
	return err == nil && written == 0
}

func cAnalysisPageSize(values url.Values) (int, error) {
	raw := values.Get("page_size")
	if raw == "" {
		return 50, nil
	}
	value, err := strconv.Atoi(raw)
	if err != nil || value < 1 || value > canalysis.MaxPageSize ||
		strconv.Itoa(value) != raw {
		return 0, canalysis.ErrInvalidInput
	}
	return value, nil
}

func cAnalysisQueryFieldsValid(values url.Values, allowed ...string) bool {
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

func writeCAnalysisInvalid(c *gin.Context) {
	WriteError(
		c, http.StatusBadRequest, "invalid_c_analysis_request",
		"The C analysis request is invalid.", nil,
	)
}

func writeCAnalysisError(c *gin.Context, err error) {
	switch {
	case errors.Is(err, canalysis.ErrInvalidInput):
		writeCAnalysisInvalid(c)
	case errors.Is(err, canalysis.ErrTaskNotFound):
		WriteError(c, http.StatusNotFound, "task_not_found", "The task was not found.", nil)
	case errors.Is(err, canalysis.ErrProjectNotFound):
		WriteError(
			c, http.StatusNotFound, "c_analysis_project_not_found",
			"The eligible C source project was not found.", nil,
		)
	case errors.Is(err, canalysis.ErrRunNotFound):
		WriteError(
			c, http.StatusNotFound, "c_analysis_run_not_found",
			"The C analysis run was not found.", nil,
		)
	case errors.Is(err, canalysis.ErrNotReady):
		WriteError(
			c, http.StatusServiceUnavailable, "c_analysis_not_ready",
			"The C analysis checker is not ready.", nil,
		)
	case errors.Is(err, canalysis.ErrAlreadyActive):
		WriteError(
			c, http.StatusConflict, "c_analysis_already_active",
			"This source project already has an active C analysis run.", nil,
		)
	case errors.Is(err, canalysis.ErrIdempotencyConflict):
		WriteError(
			c, http.StatusConflict, "idempotency_conflict",
			"The Idempotency-Key was already used for another C analysis request.", nil,
		)
	case errors.Is(err, canalysis.ErrSourceUnavailable):
		WriteError(
			c, http.StatusConflict, "c_analysis_source_unavailable",
			"The C source project is unavailable or ineligible.", nil,
		)
	case errors.Is(err, canalysis.ErrRunNotCancellable):
		WriteError(
			c, http.StatusConflict, "c_analysis_not_cancellable",
			"The C analysis run cannot be cancelled in its current state.", nil,
		)
	case errors.Is(err, canalysis.ErrRunNotDeletable):
		WriteError(
			c, http.StatusConflict, "c_analysis_not_deletable",
			"Only a fully terminal C analysis run can be deleted.", nil,
		)
	default:
		WriteError(
			c, http.StatusInternalServerError, "c_analysis_operation_failed",
			"The C analysis operation failed.", nil,
		)
	}
}

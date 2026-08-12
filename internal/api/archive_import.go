package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strconv"

	"binaryscan/internal/archiveimport"
	"binaryscan/internal/auth"

	"github.com/gin-gonic/gin"
)

type ArchiveImportService interface {
	Get(context.Context, string, auth.Principal) (archiveimport.Import, error)
	ListImports(
		context.Context,
		archiveimport.ImportListQuery,
		auth.Principal,
	) (archiveimport.ImportPage, error)
	ListEntries(
		context.Context,
		string,
		archiveimport.EntryListQuery,
		auth.Principal,
	) (archiveimport.EntryPage, error)
	CreateBatch(
		context.Context,
		archiveimport.BatchInput,
	) (archiveimport.BatchResult, bool, error)
}

func registerArchiveImportRoutes(
	v1 *gin.RouterGroup,
	manager AuthManager,
	service ArchiveImportService,
) {
	routes := v1.Group("/archive-imports")
	routes.Use(RequireSession(manager))
	routes.GET("", listArchiveImportsHandler(service))
	routes.GET("/:id", getArchiveImportHandler(service))
	routes.GET("/:id/entries", listArchiveImportEntriesHandler(service))
	routes.POST(
		"/:id/task-batches",
		RequireCSRF(manager),
		RequireRoles(auth.RoleAdministrator, auth.RoleOperator),
		createArchiveImportBatchHandler(service),
	)
}

func listArchiveImportsHandler(service ArchiveImportService) gin.HandlerFunc {
	return func(c *gin.Context) {
		values := c.Request.URL.Query()
		if !archiveImportListQueryValid(values) {
			writeArchiveImportInvalid(c)
			return
		}
		pageSize := 25
		if raw := values.Get("page_size"); raw != "" {
			parsed, err := strconv.Atoi(raw)
			if err != nil || parsed < 1 || parsed > 100 || strconv.Itoa(parsed) != raw {
				writeArchiveImportInvalid(c)
				return
			}
			pageSize = parsed
		}
		session, ok := CurrentSession(c)
		if !ok {
			WriteError(c, http.StatusUnauthorized, "authentication_required", "Authentication is required.", nil)
			return
		}
		page, err := service.ListImports(
			c.Request.Context(),
			archiveimport.ImportListQuery{
				Cursor: values.Get("cursor"), PageSize: pageSize,
			},
			session.User,
		)
		if err != nil {
			writeArchiveImportError(c, err)
			return
		}
		Write(c, http.StatusOK, page)
	}
}

func getArchiveImportHandler(service ArchiveImportService) gin.HandlerFunc {
	return func(c *gin.Context) {
		if len(c.Request.URL.Query()) != 0 {
			writeArchiveImportInvalid(c)
			return
		}
		session, ok := CurrentSession(c)
		if !ok {
			WriteError(c, http.StatusUnauthorized, "authentication_required", "Authentication is required.", nil)
			return
		}
		value, err := service.Get(c.Request.Context(), c.Param("id"), session.User)
		if err != nil {
			writeArchiveImportError(c, err)
			return
		}
		Write(c, http.StatusOK, value)
	}
}

func listArchiveImportEntriesHandler(service ArchiveImportService) gin.HandlerFunc {
	return func(c *gin.Context) {
		values := c.Request.URL.Query()
		if !archiveEntryQueryValid(values) {
			writeArchiveImportInvalid(c)
			return
		}
		pageSize := 20
		if raw := values.Get("page_size"); raw != "" {
			parsed, err := strconv.Atoi(raw)
			if err != nil || parsed < 1 || parsed > 100 || strconv.Itoa(parsed) != raw {
				writeArchiveImportInvalid(c)
				return
			}
			pageSize = parsed
		}
		session, ok := CurrentSession(c)
		if !ok {
			WriteError(c, http.StatusUnauthorized, "authentication_required", "Authentication is required.", nil)
			return
		}
		page, err := service.ListEntries(
			c.Request.Context(),
			c.Param("id"),
			archiveimport.EntryListQuery{
				Filter: values.Get("filter"), Cursor: values.Get("cursor"),
				PageSize: pageSize,
			},
			session.User,
		)
		if err != nil {
			writeArchiveImportError(c, err)
			return
		}
		Write(c, http.StatusOK, page)
	}
}

func createArchiveImportBatchHandler(service ArchiveImportService) gin.HandlerFunc {
	type request struct {
		EntryIDs []string `json:"entry_ids"`
	}
	return func(c *gin.Context) {
		if len(c.Request.URL.Query()) != 0 {
			writeArchiveImportInvalid(c)
			return
		}
		keys := c.Request.Header.Values("Idempotency-Key")
		if len(keys) != 1 || !validArchiveImportIdempotencyKey(keys[0]) {
			WriteError(c, http.StatusBadRequest, "idempotency_key_required", "A single valid Idempotency-Key header is required.", nil)
			return
		}
		c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, 16*1024)
		decoder := json.NewDecoder(c.Request.Body)
		decoder.DisallowUnknownFields()
		var payload request
		if err := decoder.Decode(&payload); err != nil || ensureJSONEnd(decoder) != nil {
			writeArchiveImportInvalid(c)
			return
		}
		session, ok := CurrentSession(c)
		if !ok {
			WriteError(c, http.StatusUnauthorized, "authentication_required", "Authentication is required.", nil)
			return
		}
		result, created, err := service.CreateBatch(
			c.Request.Context(),
			archiveimport.BatchInput{
				ImportID: c.Param("id"), EntryIDs: payload.EntryIDs,
				CreatedBy: session.User.UserID, Role: session.User.Role,
				IdempotencyKey: keys[0],
			},
		)
		if err != nil {
			writeArchiveImportError(c, err)
			return
		}
		status := http.StatusOK
		if created {
			status = http.StatusCreated
		}
		Write(c, status, result)
	}
}

func archiveEntryQueryValid(values url.Values) bool {
	allowed := map[string]bool{"filter": true, "page_size": true, "cursor": true}
	for key, entries := range values {
		if !allowed[key] || len(entries) != 1 {
			return false
		}
	}
	return true
}

func archiveImportListQueryValid(values url.Values) bool {
	allowed := map[string]bool{"page_size": true, "cursor": true}
	for key, entries := range values {
		if !allowed[key] || len(entries) != 1 {
			return false
		}
	}
	return true
}

func validArchiveImportIdempotencyKey(value string) bool {
	if len(value) == 0 || len(value) > 128 {
		return false
	}
	for index := range len(value) {
		if value[index] < 0x21 || value[index] > 0x7e {
			return false
		}
	}
	return true
}

func writeArchiveImportInvalid(c *gin.Context) {
	WriteError(c, http.StatusBadRequest, "invalid_archive_import_request", "The archive import request is invalid.", nil)
}

func writeArchiveImportError(c *gin.Context, err error) {
	switch {
	case errors.Is(err, archiveimport.ErrInvalidInput):
		writeArchiveImportInvalid(c)
	case errors.Is(err, archiveimport.ErrNotFound):
		WriteError(c, http.StatusNotFound, "archive_import_not_found", "The archive import was not found.", nil)
	case errors.Is(err, archiveimport.ErrForbidden):
		WriteError(c, http.StatusForbidden, "permission_denied", "The current role cannot perform this action.", nil)
	case errors.Is(err, archiveimport.ErrConflict):
		WriteError(c, http.StatusConflict, "archive_import_state_conflict", "The archive import state does not permit this action.", nil)
	case errors.Is(err, archiveimport.ErrIdempotencyConflict):
		WriteError(c, http.StatusConflict, "idempotency_conflict", "The Idempotency-Key conflicts with a previous request.", nil)
	default:
		_ = c.Error(err)
		WriteError(c, http.StatusInternalServerError, "archive_import_failed", "The archive import request could not be completed.", nil)
	}
}

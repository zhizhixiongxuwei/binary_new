package api

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strconv"

	"binaryscan/internal/filetree"

	"github.com/gin-gonic/gin"
)

const defaultFileTreePageSize = 100

type FileTreeService interface {
	List(context.Context, filetree.ListQuery) (filetree.Page, error)
	Get(context.Context, filetree.GetQuery) (filetree.Detail, error)
}

func registerFileTreeRoutes(
	v1 *gin.RouterGroup,
	manager AuthManager,
	service FileTreeService,
) {
	routes := v1.Group("/tasks")
	routes.Use(RequireSession(manager))
	routes.GET("/:id/files", listFileNodesHandler(service))
	routes.GET("/:id/files/:file_id", getFileNodeHandler(service))
}

func listFileNodesHandler(service FileTreeService) gin.HandlerFunc {
	return func(c *gin.Context) {
		values := c.Request.URL.Query()
		if !fileTreeQueryFieldsValid(values) {
			writeFileTreeInvalid(c)
			return
		}
		parentID, err := optionalPositiveUint(values, "parent_id")
		if err != nil {
			writeFileTreeInvalid(c)
			return
		}
		cursor, err := optionalPositiveUint(values, "cursor")
		if err != nil {
			writeFileTreeInvalid(c)
			return
		}
		pageSize, err := fileTreePageSize(values)
		if err != nil {
			writeFileTreeInvalid(c)
			return
		}

		var cursorValue uint64
		if cursor != nil {
			cursorValue = *cursor
		}
		page, err := service.List(c.Request.Context(), filetree.ListQuery{
			TaskID: c.Param("id"), ParentID: parentID,
			Cursor: cursorValue, PageSize: pageSize,
		})
		if err != nil {
			writeFileTreeError(c, err)
			return
		}
		Write(c, http.StatusOK, page)
	}
}

func getFileNodeHandler(service FileTreeService) gin.HandlerFunc {
	return func(c *gin.Context) {
		if len(c.Request.URL.Query()) != 0 {
			writeFileDetailInvalid(c)
			return
		}
		fileID, err := parseFileNodeID(c.Param("file_id"))
		if err != nil {
			writeFileDetailInvalid(c)
			return
		}
		detail, err := service.Get(c.Request.Context(), filetree.GetQuery{
			TaskID: c.Param("id"),
			FileID: fileID,
		})
		if err != nil {
			writeFileDetailError(c, err)
			return
		}
		Write(c, http.StatusOK, detail)
	}
}

func parseFileNodeID(raw string) (uint64, error) {
	if raw == "" || raw[0] < '1' || raw[0] > '9' || !decimalDigits(raw) {
		return 0, filetree.ErrInvalidInput
	}
	value, err := strconv.ParseUint(raw, 10, 64)
	if err != nil || value == 0 {
		return 0, filetree.ErrInvalidInput
	}
	return value, nil
}

func optionalPositiveUint(values url.Values, name string) (*uint64, error) {
	entries, exists := values[name]
	if !exists {
		return nil, nil
	}
	if len(entries) != 1 || !decimalDigits(entries[0]) {
		return nil, filetree.ErrInvalidInput
	}
	value, err := strconv.ParseUint(entries[0], 10, 64)
	if err != nil || value == 0 {
		return nil, filetree.ErrInvalidInput
	}
	return &value, nil
}

func fileTreePageSize(values url.Values) (int, error) {
	entries, exists := values["page_size"]
	if !exists {
		return defaultFileTreePageSize, nil
	}
	if len(entries) != 1 || !decimalDigits(entries[0]) {
		return 0, filetree.ErrInvalidInput
	}
	value, err := strconv.ParseUint(entries[0], 10, 16)
	if err != nil || value == 0 || value > filetree.MaxPageSize {
		return 0, filetree.ErrInvalidInput
	}
	return int(value), nil
}

func decimalDigits(value string) bool {
	if value == "" {
		return false
	}
	for index := 0; index < len(value); index++ {
		if value[index] < '0' || value[index] > '9' {
			return false
		}
	}
	return true
}

func fileTreeQueryFieldsValid(values url.Values) bool {
	allowed := map[string]struct{}{
		"parent_id": {}, "cursor": {}, "page_size": {},
	}
	for name, entries := range values {
		if _, ok := allowed[name]; !ok || len(entries) != 1 {
			return false
		}
	}
	return true
}

func writeFileTreeInvalid(c *gin.Context) {
	WriteError(
		c, http.StatusBadRequest, "invalid_file_tree_query",
		"The file tree query is invalid.", nil,
	)
}

func writeFileTreeError(c *gin.Context, err error) {
	switch {
	case errors.Is(err, filetree.ErrInvalidInput):
		writeFileTreeInvalid(c)
	case errors.Is(err, filetree.ErrNotFound):
		WriteError(
			c, http.StatusNotFound, "file_tree_not_found",
			"The task or parent file node was not found.", nil,
		)
	default:
		c.Error(err).SetType(gin.ErrorTypePrivate)
		WriteError(
			c, http.StatusInternalServerError, "file_tree_failed",
			"The file tree could not be loaded.", nil,
		)
	}
}

func writeFileDetailInvalid(c *gin.Context) {
	WriteError(
		c, http.StatusBadRequest, "invalid_file_detail_request",
		"The file detail request is invalid.", nil,
	)
}

func writeFileDetailError(c *gin.Context, err error) {
	switch {
	case errors.Is(err, filetree.ErrInvalidInput):
		writeFileDetailInvalid(c)
	case errors.Is(err, filetree.ErrTaskNotFound):
		WriteError(
			c, http.StatusNotFound, "file_detail_task_not_found",
			"The task was not found.", nil,
		)
	case errors.Is(err, filetree.ErrNodeNotFound):
		WriteError(
			c, http.StatusNotFound, "file_node_not_found",
			"The file node was not found.", nil,
		)
	default:
		c.Error(err).SetType(gin.ErrorTypePrivate)
		WriteError(
			c, http.StatusInternalServerError, "file_detail_failed",
			"The file detail could not be loaded.", nil,
		)
	}
}

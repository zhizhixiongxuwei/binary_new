package api

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"strconv"

	"binaryscan/internal/auth"
	"binaryscan/internal/decompile"

	"github.com/gin-gonic/gin"
)

type DecompileService interface {
	Create(
		context.Context,
		decompile.CreateInput,
	) (decompile.Request, bool, error)
	GetRequest(
		context.Context,
		decompile.RequestQuery,
	) (decompile.Request, error)
	List(context.Context, decompile.ListQuery) (decompile.Page, error)
	Source(context.Context, decompile.SourceQuery) (decompile.SourceChunk, error)
	ExportSources(
		context.Context,
		decompile.SourceArchiveQuery,
	) (decompile.SourceArchive, error)
}

const (
	decompileAuditJobIDKey               = "binaryscan.decompile_job_id"
	decompileAuditRequestIDKey           = "binaryscan.decompile_request_id"
	decompileSourceExportCountKey        = "binaryscan.decompile_source_export_count"
	decompileSourceExportStreamFailedKey = "binaryscan.decompile_source_export_stream_failed"
)

func registerDecompileRoutes(
	v1 *gin.RouterGroup,
	manager AuthManager,
	service DecompileService,
) {
	routes := v1.Group("/tasks")
	routes.Use(RequireSession(manager))
	routes.GET(
		"/:id/decompile-jobs/:job_id",
		getDecompileRequestHandler(service),
	)
	routes.GET(
		"/:id/decompile-results",
		listDecompileResultsHandler(service),
	)
	routes.GET(
		"/:id/decompile-results/:result_id/source",
		getDecompileSourceHandler(service),
	)
	routes.GET(
		"/:id/decompile-sources.zip",
		downloadDecompileSourcesHandler(service),
	)
	routes.POST(
		"/:id/files/:node_id/decompile",
		RequireCSRF(manager),
		RequireRoles(auth.RoleAdministrator, auth.RoleOperator),
		createDecompileRequestHandler(service),
	)
}

func getDecompileRequestHandler(service DecompileService) gin.HandlerFunc {
	return func(c *gin.Context) {
		if len(c.Request.URL.Query()) != 0 {
			writeDecompileInvalidQuery(c)
			return
		}
		value, err := service.GetRequest(
			c.Request.Context(),
			decompile.RequestQuery{
				TaskID: c.Param("id"),
				JobID:  c.Param("job_id"),
			},
		)
		if err != nil {
			writeDecompileRequestStatusError(c, err)
			return
		}
		Write(c, http.StatusOK, value)
	}
}

func createDecompileRequestHandler(service DecompileService) gin.HandlerFunc {
	type requestBody struct {
		EngineTarget string          `json:"engine_target"`
		Options      json.RawMessage `json:"options"`
	}
	return func(c *gin.Context) {
		if len(c.Request.URL.Query()) != 0 {
			writeDecompileInvalidCreate(c)
			return
		}
		nodeIDText := c.Param("node_id")
		nodeID, err := strconv.ParseUint(nodeIDText, 10, 64)
		if err != nil || nodeID == 0 ||
			strconv.FormatUint(nodeID, 10) != nodeIDText {
			writeDecompileInvalidCreate(c)
			return
		}
		keys := c.Request.Header.Values("Idempotency-Key")
		if len(keys) != 1 || !validDecompileIdempotencyKey(keys[0]) {
			WriteError(
				c,
				http.StatusBadRequest,
				"idempotency_key_required",
				"A single valid Idempotency-Key header is required.",
				nil,
			)
			return
		}
		c.Request.Body = http.MaxBytesReader(
			c.Writer,
			c.Request.Body,
			16<<10,
		)
		decoder := json.NewDecoder(c.Request.Body)
		decoder.DisallowUnknownFields()
		var request requestBody
		if err := decoder.Decode(&request); err != nil ||
			ensureJSONEnd(decoder) != nil {
			writeDecompileInvalidCreate(c)
			return
		}
		session, ok := CurrentSession(c)
		if !ok {
			WriteError(
				c,
				http.StatusUnauthorized,
				"authentication_required",
				"Authentication is required.",
				nil,
			)
			return
		}
		value, created, err := service.Create(
			c.Request.Context(),
			decompile.CreateInput{
				TaskID:         c.Param("id"),
				FileNodeID:     nodeID,
				UserID:         session.User.UserID,
				Role:           session.User.Role,
				EngineTarget:   request.EngineTarget,
				Options:        request.Options,
				IdempotencyKey: keys[0],
			},
		)
		if err != nil {
			writeDecompileCreateError(c, err)
			return
		}
		c.Set(decompileAuditJobIDKey, value.JobID)
		c.Set(decompileAuditRequestIDKey, value.RequestID)
		status := http.StatusOK
		if created {
			status = http.StatusCreated
		}
		Write(c, status, value)
	}
}

func validDecompileIdempotencyKey(value string) bool {
	if len(value) == 0 || len(value) > 128 {
		return false
	}
	for index := range len(value) {
		if value[index] < 0x20 || value[index] > 0x7e {
			return false
		}
	}
	return true
}

func listDecompileResultsHandler(service DecompileService) gin.HandlerFunc {
	return func(c *gin.Context) {
		values := c.Request.URL.Query()
		if !decompileQueryFieldsValid(values, "cursor", "page_size") {
			writeDecompileInvalidQuery(c)
			return
		}

		cursor, err := optionalDecompileCursor(values)
		if err != nil {
			writeDecompileInvalidQuery(c)
			return
		}
		pageSize, err := decompilePageSize(values)
		if err != nil {
			writeDecompileInvalidQuery(c)
			return
		}

		page, err := service.List(c.Request.Context(), decompile.ListQuery{
			TaskID:   c.Param("id"),
			Cursor:   cursor,
			PageSize: pageSize,
		})
		if err != nil {
			writeDecompileListError(c, err)
			return
		}
		Write(c, http.StatusOK, page)
	}
}

func getDecompileSourceHandler(service DecompileService) gin.HandlerFunc {
	return func(c *gin.Context) {
		values := c.Request.URL.Query()
		if !decompileQueryFieldsValid(values, "offset", "limit") {
			writeDecompileInvalidQuery(c)
			return
		}

		offset, err := optionalDecompileOffset(values)
		if err != nil {
			writeDecompileInvalidQuery(c)
			return
		}
		limit, err := decompileSourceLimit(values)
		if err != nil {
			writeDecompileInvalidQuery(c)
			return
		}

		chunk, err := service.Source(c.Request.Context(), decompile.SourceQuery{
			TaskID:   c.Param("id"),
			ResultID: c.Param("result_id"),
			Offset:   offset,
			Limit:    limit,
		})
		if err != nil {
			writeDecompileSourceError(c, err)
			return
		}
		Write(c, http.StatusOK, chunk)
	}
}

func downloadDecompileSourcesHandler(
	service DecompileService,
) gin.HandlerFunc {
	return func(c *gin.Context) {
		values := c.Request.URL.Query()
		if !decompileQueryFieldsValid(values, "combined") {
			writeDecompileInvalidQuery(c)
			return
		}
		includeCombined := false
		if entries, exists := values["combined"]; exists {
			if len(entries) != 1 || entries[0] != "true" {
				writeDecompileInvalidQuery(c)
				return
			}
			includeCombined = true
		}

		archive, err := service.ExportSources(
			c.Request.Context(),
			decompile.SourceArchiveQuery{
				TaskID:          c.Param("id"),
				IncludeCombined: includeCombined,
			},
		)
		if err != nil {
			writeDecompileArchiveError(c, err)
			return
		}
		defer archive.Content.Close()

		digest, err := hex.DecodeString(archive.SHA256)
		if err != nil || len(digest) != sha256.Size ||
			archive.SizeBytes > math.MaxInt64 {
			writeDecompileArchiveError(c, decompile.ErrSourceUnavailable)
			return
		}
		c.Header("Content-Type", "application/zip")
		c.Header("Content-Length", strconv.FormatUint(archive.SizeBytes, 10))
		c.Header(
			"Content-Disposition",
			fmt.Sprintf(`attachment; filename="%s"`, archive.Filename),
		)
		c.Header("X-Content-Type-Options", "nosniff")
		c.Header("Cache-Control", "private, no-store")
		c.Header("ETag", `"`+archive.SHA256+`"`)
		c.Header(
			"Digest",
			"sha-256="+base64.StdEncoding.EncodeToString(digest),
		)
		c.Header("X-Checksum-SHA256", archive.SHA256)
		c.Header("X-Decompile-Result-Count", strconv.Itoa(archive.ResultCount))
		c.Set(decompileSourceExportCountKey, archive.ResultCount)
		c.Status(http.StatusOK)
		written, copyErr := io.CopyN(
			c.Writer, archive.Content, int64(archive.SizeBytes),
		)
		if copyErr != nil || uint64(written) != archive.SizeBytes {
			c.Set(decompileSourceExportStreamFailedKey, true)
			if copyErr == nil {
				copyErr = io.ErrUnexpectedEOF
			}
			c.Error(copyErr).SetType(gin.ErrorTypePrivate)
		}
	}
}

func decompileQueryFieldsValid(values url.Values, allowedNames ...string) bool {
	allowed := make(map[string]struct{}, len(allowedNames))
	for _, name := range allowedNames {
		allowed[name] = struct{}{}
	}
	for name, entries := range values {
		if _, ok := allowed[name]; !ok || len(entries) != 1 {
			return false
		}
	}
	return true
}

func optionalDecompileCursor(values url.Values) (string, error) {
	entries, exists := values["cursor"]
	if !exists {
		return "", nil
	}
	if len(entries) != 1 || entries[0] == "" {
		return "", decompile.ErrInvalidInput
	}
	return entries[0], nil
}

func decompilePageSize(values url.Values) (int, error) {
	entries, exists := values["page_size"]
	if !exists {
		return decompile.DefaultPageSize, nil
	}
	value, err := parseBoundedDecompileInt(entries, decompile.MaxPageSize)
	if err != nil {
		return 0, err
	}
	return value, nil
}

func optionalDecompileOffset(values url.Values) (uint64, error) {
	entries, exists := values["offset"]
	if !exists {
		return 0, nil
	}
	if len(entries) != 1 || !decimalDigits(entries[0]) {
		return 0, decompile.ErrInvalidInput
	}
	value, err := strconv.ParseUint(entries[0], 10, 64)
	if err != nil {
		return 0, decompile.ErrInvalidInput
	}
	return value, nil
}

func decompileSourceLimit(values url.Values) (int, error) {
	entries, exists := values["limit"]
	if !exists {
		return decompile.DefaultSourceLimit, nil
	}
	return parseBoundedDecompileInt(entries, decompile.MaxSourceLimit)
}

func parseBoundedDecompileInt(entries []string, maximum int) (int, error) {
	if len(entries) != 1 || !decimalDigits(entries[0]) {
		return 0, decompile.ErrInvalidInput
	}
	value, err := strconv.ParseUint(entries[0], 10, 64)
	if err != nil || value == 0 || value > uint64(maximum) {
		return 0, decompile.ErrInvalidInput
	}
	return int(value), nil
}

func writeDecompileInvalidQuery(c *gin.Context) {
	WriteError(
		c,
		http.StatusBadRequest,
		"invalid_query",
		"The decompile result query is invalid.",
		nil,
	)
}

func writeDecompileInvalidCreate(c *gin.Context) {
	WriteError(
		c,
		http.StatusBadRequest,
		"invalid_decompile_request",
		"The decompile request is invalid.",
		nil,
	)
}

func writeDecompileCreateError(c *gin.Context, err error) {
	switch {
	case errors.Is(err, decompile.ErrInvalidInput):
		writeDecompileInvalidCreate(c)
	case errors.Is(err, decompile.ErrTaskNotFound):
		WriteError(
			c, http.StatusNotFound, "task_not_found",
			"The task was not found.", nil,
		)
	case errors.Is(err, decompile.ErrFileNodeNotFound):
		WriteError(
			c, http.StatusNotFound, "file_node_not_found",
			"The file node was not found in this task.", nil,
		)
	case errors.Is(err, decompile.ErrUnsupportedTarget):
		WriteError(
			c, http.StatusUnprocessableEntity, "decompile_target_unsupported",
			"The file node is not supported by the selected decompile engine.",
			nil,
		)
	case errors.Is(err, decompile.ErrSourceUnavailable):
		WriteError(
			c, http.StatusConflict, "decompile_source_unavailable",
			"The retained file node source is unavailable.", nil,
		)
	case errors.Is(err, decompile.ErrSampleUnavailable):
		WriteError(
			c, http.StatusConflict, "task_sample_unavailable",
			"The retained sample is deleted or expired.", nil,
		)
	case errors.Is(err, decompile.ErrTaskStateConflict):
		WriteError(
			c, http.StatusConflict, "task_state_conflict",
			"The task state does not permit decompilation.", nil,
		)
	case errors.Is(err, decompile.ErrDecompileInProgress):
		WriteError(
			c, http.StatusConflict, "decompile_in_progress",
			"A decompile request is already active for this file node.", nil,
		)
	case errors.Is(err, decompile.ErrRequestConflict):
		WriteError(
			c, http.StatusConflict, "idempotency_conflict",
			"The Idempotency-Key was already used for another request.", nil,
		)
	default:
		c.Error(err).SetType(gin.ErrorTypePrivate)
		WriteError(
			c, http.StatusInternalServerError, "decompile_request_failed",
			"The decompile request could not be created.", nil,
		)
	}
}

func writeDecompileKnownError(c *gin.Context, err error) bool {
	switch {
	case errors.Is(err, decompile.ErrInvalidInput):
		writeDecompileInvalidQuery(c)
	case errors.Is(err, decompile.ErrTaskNotFound):
		WriteError(
			c,
			http.StatusNotFound,
			"task_not_found",
			"The task was not found.",
			nil,
		)
	case errors.Is(err, decompile.ErrResultNotFound):
		WriteError(
			c,
			http.StatusNotFound,
			"result_not_found",
			"The decompile result was not found.",
			nil,
		)
	case errors.Is(err, decompile.ErrSourceUnavailable):
		WriteError(
			c,
			http.StatusConflict,
			"source_unavailable",
			"The decompiled source is unavailable.",
			nil,
		)
	default:
		return false
	}
	return true
}

func writeDecompileListError(c *gin.Context, err error) {
	if writeDecompileKnownError(c, err) {
		return
	}
	c.Error(err).SetType(gin.ErrorTypePrivate)
	WriteError(
		c,
		http.StatusInternalServerError,
		"decompile_results_failed",
		"The decompile results could not be loaded.",
		nil,
	)
}

func writeDecompileRequestStatusError(c *gin.Context, err error) {
	if errors.Is(err, decompile.ErrInvalidInput) {
		writeDecompileInvalidQuery(c)
		return
	}
	if errors.Is(err, decompile.ErrRequestNotFound) {
		WriteError(
			c,
			http.StatusNotFound,
			"decompile_request_not_found",
			"The decompile request was not found.",
			nil,
		)
		return
	}
	c.Error(err).SetType(gin.ErrorTypePrivate)
	WriteError(
		c,
		http.StatusInternalServerError,
		"decompile_request_status_failed",
		"The decompile request status could not be loaded.",
		nil,
	)
}

func writeDecompileSourceError(c *gin.Context, err error) {
	if writeDecompileKnownError(c, err) {
		return
	}
	c.Error(err).SetType(gin.ErrorTypePrivate)
	WriteError(
		c,
		http.StatusInternalServerError,
		"decompile_source_failed",
		"The decompiled source could not be loaded.",
		nil,
	)
}

func writeDecompileArchiveError(c *gin.Context, err error) {
	if writeDecompileKnownError(c, err) {
		return
	}
	if errors.Is(err, decompile.ErrExportTooLarge) {
		WriteError(
			c,
			http.StatusRequestEntityTooLarge,
			"decompile_export_too_large",
			"The decompile source export exceeds the configured limit.",
			nil,
		)
		return
	}
	c.Error(err).SetType(gin.ErrorTypePrivate)
	WriteError(
		c,
		http.StatusInternalServerError,
		"decompile_export_failed",
		"The decompile source archive could not be generated.",
		nil,
	)
}

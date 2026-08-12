package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"binaryscan/internal/auth"
	"binaryscan/internal/inputcategory"
	"binaryscan/internal/storageguard"
	"binaryscan/internal/upload"

	"github.com/gin-gonic/gin"
)

var contentRangePattern = regexp.MustCompile(`^bytes ([0-9]+)-([0-9]+)/([0-9]+)$`)

type UploadService interface {
	Create(context.Context, upload.CreateInput) (upload.View, error)
	Get(context.Context, string, auth.Principal) (upload.View, error)
	PutPart(context.Context, string, auth.Principal, uint32, upload.Range, string, io.Reader) error
	Complete(context.Context, string, auth.Principal) (upload.View, error)
	Delete(context.Context, string, auth.Principal) error
}

func registerUploadRoutes(v1 *gin.RouterGroup, manager AuthManager, service UploadService) {
	routes := v1.Group("/uploads")
	routes.Use(RequireSession(manager), RequireRoles(auth.RoleAdministrator, auth.RoleOperator))
	routes.POST("", RequireCSRF(manager), createUploadHandler(service))
	routes.GET("/:id", getUploadHandler(service))
	routes.PUT("/:id/parts/:partNumber", RequireCSRF(manager), putUploadPartHandler(service))
	routes.POST("/:id/complete", RequireCSRF(manager), completeUploadHandler(service))
	routes.DELETE("/:id", RequireCSRF(manager), deleteUploadHandler(service))
}

func createUploadHandler(service UploadService) gin.HandlerFunc {
	type createRequest struct {
		Filename      string                 `json:"filename"`
		Size          int64                  `json:"size"`
		ContentType   string                 `json:"content_type"`
		InputCategory inputcategory.Category `json:"input_category"`
	}
	return func(c *gin.Context) {
		if len(c.Request.URL.Query()) != 0 {
			WriteError(c, http.StatusBadRequest, "invalid_request", "The upload request is not valid.", nil)
			return
		}
		idempotencyKey, ok := uploadIdempotencyKey(c)
		if !ok {
			return
		}
		c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, 16*1024)
		decoder := json.NewDecoder(c.Request.Body)
		decoder.DisallowUnknownFields()
		var request createRequest
		if err := decoder.Decode(&request); err != nil || ensureJSONEnd(decoder) != nil {
			WriteError(c, http.StatusBadRequest, "invalid_request", "The upload request is not valid.", nil)
			return
		}
		if !request.InputCategory.Valid() {
			WriteError(c, http.StatusBadRequest, "invalid_upload", "The upload request is invalid.", nil)
			return
		}
		session, ok := CurrentSession(c)
		if !ok {
			WriteError(c, http.StatusUnauthorized, "authentication_required", "Authentication is required.", nil)
			return
		}
		view, err := service.Create(c.Request.Context(), upload.CreateInput{
			Filename: request.Filename, Size: request.Size,
			ContentType: request.ContentType, CreatedBy: session.User.UserID,
			IdempotencyKey: idempotencyKey, InputCategory: request.InputCategory,
		})
		if err != nil {
			writeUploadError(c, err)
			return
		}
		Write(c, http.StatusCreated, view)
	}
}

func uploadIdempotencyKey(c *gin.Context) (string, bool) {
	values := c.Request.Header.Values("Idempotency-Key")
	if len(values) != 1 || !validUploadIdempotencyKey(values[0]) {
		WriteError(
			c,
			http.StatusBadRequest,
			"idempotency_key_required",
			"A single valid Idempotency-Key header is required.",
			nil,
		)
		return "", false
	}
	return values[0], true
}

func validUploadIdempotencyKey(value string) bool {
	if len(value) == 0 || len(value) > 128 {
		return false
	}
	for index := 0; index < len(value); index++ {
		if value[index] < 0x21 || value[index] > 0x7e {
			return false
		}
	}
	return true
}

func getUploadHandler(service UploadService) gin.HandlerFunc {
	return func(c *gin.Context) {
		session, ok := CurrentSession(c)
		if !ok {
			WriteError(c, http.StatusUnauthorized, "authentication_required", "Authentication is required.", nil)
			return
		}
		view, err := service.Get(c.Request.Context(), c.Param("id"), session.User)
		if err != nil {
			writeUploadError(c, err)
			return
		}
		Write(c, http.StatusOK, view)
	}
}

func putUploadPartHandler(service UploadService) gin.HandlerFunc {
	return func(c *gin.Context) {
		session, ok := CurrentSession(c)
		if !ok {
			WriteError(c, http.StatusUnauthorized, "authentication_required", "Authentication is required.", nil)
			return
		}
		numberValue, err := strconv.ParseUint(c.Param("partNumber"), 10, 32)
		if err != nil || numberValue == 0 {
			WriteError(c, http.StatusBadRequest, "invalid_part_number", "The part number must be a positive integer.", nil)
			return
		}
		byteRange, err := parseContentRange(c.GetHeader("Content-Range"))
		if err != nil {
			WriteError(c, http.StatusBadRequest, "invalid_content_range", "Content-Range must use bytes start-end/total.", nil)
			return
		}
		expectedHash := c.GetHeader("X-Chunk-SHA256")
		if !hashHeaderValid(expectedHash) {
			WriteError(c, http.StatusBadRequest, "invalid_chunk_hash", "X-Chunk-SHA256 must be a lowercase SHA-256 value.", nil)
			return
		}
		if c.Request.ContentLength > byteRange.Size() {
			WriteError(c, http.StatusRequestEntityTooLarge, "chunk_too_large", "The request body exceeds the declared chunk range.", nil)
			return
		}
		if err := service.PutPart(
			c.Request.Context(), c.Param("id"), session.User, uint32(numberValue),
			byteRange, expectedHash, c.Request.Body,
		); err != nil {
			writeUploadError(c, err)
			return
		}
		c.Status(http.StatusNoContent)
	}
}

func completeUploadHandler(service UploadService) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, 1)
		count, err := io.Copy(io.Discard, io.LimitReader(c.Request.Body, 1))
		if count != 0 || err != nil {
			WriteError(c, http.StatusBadRequest, "invalid_request", "The completion request body must be empty.", nil)
			return
		}
		session, ok := CurrentSession(c)
		if !ok {
			WriteError(c, http.StatusUnauthorized, "authentication_required", "Authentication is required.", nil)
			return
		}
		view, err := service.Complete(c.Request.Context(), c.Param("id"), session.User)
		if err != nil {
			writeUploadError(c, err)
			return
		}
		Write(c, http.StatusOK, view)
	}
}

func deleteUploadHandler(service UploadService) gin.HandlerFunc {
	return func(c *gin.Context) {
		session, ok := CurrentSession(c)
		if !ok {
			WriteError(c, http.StatusUnauthorized, "authentication_required", "Authentication is required.", nil)
			return
		}
		if err := service.Delete(c.Request.Context(), c.Param("id"), session.User); err != nil {
			writeUploadError(c, err)
			return
		}
		c.Status(http.StatusNoContent)
	}
}

func parseContentRange(value string) (upload.Range, error) {
	matches := contentRangePattern.FindStringSubmatch(strings.TrimSpace(value))
	if len(matches) != 4 {
		return upload.Range{}, upload.ErrInvalidInput
	}
	start, err := strconv.ParseInt(matches[1], 10, 64)
	if err != nil {
		return upload.Range{}, upload.ErrInvalidInput
	}
	end, err := strconv.ParseInt(matches[2], 10, 64)
	if err != nil {
		return upload.Range{}, upload.ErrInvalidInput
	}
	total, err := strconv.ParseInt(matches[3], 10, 64)
	if err != nil || total <= 0 || end < start || end >= total {
		return upload.Range{}, upload.ErrInvalidInput
	}
	return upload.Range{
		Start: start, End: end, Total: total,
		Raw: fmt.Sprintf("bytes %d-%d/%d", start, end, total),
	}, nil
}

func hashHeaderValid(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, character := range value {
		if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
			return false
		}
	}
	return true
}

func writeUploadError(c *gin.Context, err error) {
	switch {
	case errors.Is(err, storageguard.ErrInsufficientStorage):
		WriteError(
			c,
			http.StatusInsufficientStorage,
			"insufficient_storage",
			"Available storage is below the configured upload safety threshold.",
			nil,
		)
	case errors.Is(err, upload.ErrInvalidInput), errors.Is(err, upload.ErrRangeMismatch):
		WriteError(c, http.StatusBadRequest, "invalid_upload", "The upload request is invalid.", nil)
	case errors.Is(err, upload.ErrNotFound):
		WriteError(c, http.StatusNotFound, "upload_not_found", "The upload was not found.", nil)
	case errors.Is(err, upload.ErrForbidden):
		WriteError(c, http.StatusForbidden, "upload_forbidden", "The upload cannot be accessed.", nil)
	case errors.Is(err, upload.ErrIdempotencyConflict):
		WriteError(
			c,
			http.StatusConflict,
			"idempotency_conflict",
			"The Idempotency-Key was already used for another upload request.",
			nil,
		)
	case errors.Is(err, upload.ErrCategoryMismatch), errors.Is(err, upload.ErrUnsupportedFormat):
		var validationError *upload.CompletionValidationError
		if !errors.As(err, &validationError) {
			c.Error(err).SetType(gin.ErrorTypePrivate)
			WriteError(c, http.StatusInternalServerError, "upload_failed", "The upload operation could not be completed.", nil)
			return
		}
		details := map[string]any{
			"upload_id":       validationError.UploadID,
			"input_category":  validationError.InputCategory,
			"detected_format": validationError.DetectedFormat,
		}
		if validationError.DetectedCategory != "" {
			details["detected_category"] = validationError.DetectedCategory
		}
		code := "unsupported_input_format"
		message := "The detected format is not supported for task creation."
		if errors.Is(err, upload.ErrCategoryMismatch) {
			code = "input_category_mismatch"
			message = "The detected format does not match the selected input category."
		}
		WriteError(c, http.StatusUnprocessableEntity, code, message, details)
	case errors.Is(err, upload.ErrConflict):
		WriteError(c, http.StatusConflict, "upload_conflict", "The upload part conflicts with existing content.", nil)
	case errors.Is(err, upload.ErrIncomplete):
		WriteError(c, http.StatusConflict, "upload_incomplete", "The upload does not contain every required part.", nil)
	case errors.Is(err, upload.ErrExpired):
		WriteError(c, http.StatusGone, "upload_expired", "The upload session has expired.", nil)
	case errors.Is(err, upload.ErrInvalidState):
		WriteError(c, http.StatusConflict, "upload_invalid_state", "The upload state does not allow this operation.", nil)
	case errors.Is(err, upload.ErrHashMismatch):
		WriteError(c, http.StatusUnprocessableEntity, "chunk_hash_mismatch", "The chunk SHA-256 does not match.", nil)
	case errors.Is(err, upload.ErrTooLarge):
		WriteError(c, http.StatusRequestEntityTooLarge, "chunk_too_large", "The chunk exceeds the allowed size.", nil)
	default:
		c.Error(err).SetType(gin.ErrorTypePrivate)
		WriteError(c, http.StatusInternalServerError, "upload_failed", "The upload operation could not be completed.", nil)
	}
}

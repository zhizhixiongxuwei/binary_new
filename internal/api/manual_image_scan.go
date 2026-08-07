package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"

	"binaryscan/internal/auth"
	"binaryscan/internal/manualimagescan"

	"github.com/gin-gonic/gin"
)

type ManualImageScanService interface {
	Create(
		context.Context,
		manualimagescan.CreateInput,
	) (manualimagescan.Request, bool, error)
}

const imageScanAuditJobIDKey = "binaryscan.image_scan_job_id"

func registerManualImageScanRoutes(
	v1 *gin.RouterGroup,
	manager AuthManager,
	service ManualImageScanService,
) {
	routes := v1.Group("/tasks")
	routes.Use(RequireSession(manager))
	routes.POST(
		"/:id/files/:node_id/image-scan",
		RequireCSRF(manager),
		RequireRoles(auth.RoleAdministrator, auth.RoleOperator),
		createManualImageScanHandler(service),
	)
}

func createManualImageScanHandler(
	service ManualImageScanService,
) gin.HandlerFunc {
	return func(c *gin.Context) {
		if len(c.Request.URL.Query()) != 0 {
			writeManualImageScanInvalid(c)
			return
		}
		nodeIDText := c.Param("node_id")
		nodeID, err := strconv.ParseUint(nodeIDText, 10, 64)
		if err != nil || nodeID == 0 ||
			strconv.FormatUint(nodeID, 10) != nodeIDText {
			writeManualImageScanInvalid(c)
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
		c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, 1024)
		decoder := json.NewDecoder(c.Request.Body)
		decoder.DisallowUnknownFields()
		var request struct{}
		if err := decoder.Decode(&request); err != nil ||
			ensureJSONEnd(decoder) != nil {
			writeManualImageScanInvalid(c)
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
			manualimagescan.CreateInput{
				TaskID:         c.Param("id"),
				FileNodeID:     nodeID,
				UserID:         session.User.UserID,
				Role:           session.User.Role,
				IdempotencyKey: keys[0],
			},
		)
		if err != nil {
			writeManualImageScanError(c, err)
			return
		}
		c.Set(imageScanAuditJobIDKey, value.JobID)
		status := http.StatusOK
		if created {
			status = http.StatusCreated
		}
		Write(c, status, value)
	}
}

func writeManualImageScanInvalid(c *gin.Context) {
	WriteError(
		c,
		http.StatusBadRequest,
		"invalid_image_scan_request",
		"The manual image scan request is invalid.",
		nil,
	)
}

func writeManualImageScanError(c *gin.Context, err error) {
	switch {
	case errors.Is(err, manualimagescan.ErrInvalidInput):
		writeManualImageScanInvalid(c)
	case errors.Is(err, manualimagescan.ErrTaskNotFound):
		WriteError(c, http.StatusNotFound, "task_not_found", "The task was not found.", nil)
	case errors.Is(err, manualimagescan.ErrFileNodeNotFound):
		WriteError(c, http.StatusNotFound, "file_node_not_found", "The file node was not found in this task.", nil)
	case errors.Is(err, manualimagescan.ErrManualScanNotRequired):
		WriteError(c, http.StatusConflict, "image_scan_not_required", "This file node is not an eligible retained container image.", nil)
	case errors.Is(err, manualimagescan.ErrSourceUnavailable):
		WriteError(c, http.StatusConflict, "image_scan_source_unavailable", "The retained container image source is unavailable.", nil)
	case errors.Is(err, manualimagescan.ErrSampleUnavailable):
		WriteError(c, http.StatusConflict, "task_sample_unavailable", "The task sample is deleted or expired.", nil)
	case errors.Is(err, manualimagescan.ErrTaskStateConflict):
		WriteError(c, http.StatusConflict, "task_state_conflict", "The task state does not permit a manual image scan.", nil)
	case errors.Is(err, manualimagescan.ErrImageScanInProgress):
		WriteError(c, http.StatusConflict, "image_scan_in_progress", "A manual image scan is already active for this file node.", nil)
	case errors.Is(err, manualimagescan.ErrRequestConflict):
		WriteError(c, http.StatusConflict, "idempotency_conflict", "The Idempotency-Key conflicts with a previous request.", nil)
	default:
		_ = c.Error(err)
		WriteError(c, http.StatusInternalServerError, "image_scan_request_failed", "The manual image scan request could not be created.", nil)
	}
}

package api

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"

	"binaryscan/internal/auth"
	"binaryscan/internal/sampleexport"

	"github.com/gin-gonic/gin"
)

const sampleExportStreamFailedKey = "binaryscan.sample_export_stream_failed"

type SampleExportService interface {
	Open(context.Context, string) (sampleexport.Download, error)
}

func registerSampleExportRoutes(
	v1 *gin.RouterGroup,
	manager AuthManager,
	service SampleExportService,
) {
	routes := v1.Group("/tasks")
	routes.Use(RequireSession(manager))
	routes.GET(
		"/:id/sample/download",
		RequireRoles(auth.RoleAdministrator),
		downloadSampleHandler(service),
	)
}

func downloadSampleHandler(service SampleExportService) gin.HandlerFunc {
	return func(c *gin.Context) {
		if len(c.Request.URL.Query()) != 0 {
			WriteError(
				c,
				http.StatusBadRequest,
				"invalid_sample_export_request",
				"The sample export request is invalid.",
				nil,
			)
			return
		}
		value, err := service.Open(c.Request.Context(), c.Param("id"))
		if err != nil {
			writeSampleExportError(c, err)
			return
		}
		defer value.Content.Close()

		rawDigest, err := hex.DecodeString(value.SHA256)
		if err != nil || len(rawDigest) != 32 {
			c.Error(sampleexport.ErrIntegrity).SetType(gin.ErrorTypePrivate)
			WriteError(
				c,
				http.StatusInternalServerError,
				"sample_export_failed",
				"The sample could not be exported.",
				nil,
			)
			return
		}
		c.Header("Content-Type", "application/octet-stream")
		c.Header("Content-Length", strconv.FormatUint(value.SizeBytes, 10))
		c.Header(
			"Content-Disposition",
			fmt.Sprintf(
				`attachment; filename="%s"`,
				sampleexport.DownloadFilename,
			),
		)
		c.Header("X-Content-Type-Options", "nosniff")
		c.Header("Cache-Control", "private, no-store")
		c.Header("ETag", `"`+value.SHA256+`"`)
		c.Header(
			"Digest",
			"sha-256="+base64.StdEncoding.EncodeToString(rawDigest),
		)
		c.Header("X-Checksum-SHA256", value.SHA256)
		c.Status(http.StatusOK)
		if value.SizeBytes == 0 {
			return
		}
		if value.SizeBytes > uint64(^uint64(0)>>1) {
			c.Set(sampleExportStreamFailedKey, true)
			c.Error(sampleexport.ErrIntegrity).SetType(gin.ErrorTypePrivate)
			return
		}
		written, copyErr := io.CopyN(
			c.Writer,
			value.Content,
			int64(value.SizeBytes),
		)
		if copyErr != nil || uint64(written) != value.SizeBytes {
			if copyErr == nil {
				copyErr = io.ErrUnexpectedEOF
			}
			c.Set(sampleExportStreamFailedKey, true)
			c.Error(copyErr).SetType(gin.ErrorTypePrivate)
		}
	}
}

func writeSampleExportError(c *gin.Context, err error) {
	switch {
	case errors.Is(err, sampleexport.ErrInvalidInput):
		WriteError(
			c,
			http.StatusBadRequest,
			"invalid_sample_export_request",
			"The sample export request is invalid.",
			nil,
		)
	case errors.Is(err, sampleexport.ErrNotFound),
		errors.Is(err, sampleexport.ErrUnavailable):
		WriteError(
			c,
			http.StatusNotFound,
			"sample_not_available",
			"The retained sample is not available.",
			nil,
		)
	case errors.Is(err, sampleexport.ErrIntegrity):
		c.Error(err).SetType(gin.ErrorTypePrivate)
		WriteError(
			c,
			http.StatusConflict,
			"sample_integrity_failed",
			"The retained sample failed integrity verification.",
			nil,
		)
	default:
		c.Error(err).SetType(gin.ErrorTypePrivate)
		WriteError(
			c,
			http.StatusInternalServerError,
			"sample_export_failed",
			"The sample could not be exported.",
			nil,
		)
	}
}

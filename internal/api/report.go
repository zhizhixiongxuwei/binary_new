package api

import (
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"

	"binaryscan/internal/auth"
	"binaryscan/internal/report"

	"github.com/gin-gonic/gin"
)

type ReportService interface {
	List(context.Context, string) (report.List, error)
	Generate(
		context.Context,
		string,
		report.Format,
		string,
	) (report.Report, bool, error)
	Download(context.Context, string, string) (report.Download, error)
}

func registerReportRoutes(
	v1 *gin.RouterGroup,
	manager AuthManager,
	service ReportService,
) {
	routes := v1.Group("/tasks")
	routes.Use(RequireSession(manager))
	routes.GET("/:id/reports", listReportsHandler(service))
	routes.POST(
		"/:id/reports",
		RequireCSRF(manager),
		RequireRoles(auth.RoleAdministrator, auth.RoleOperator),
		generateReportHandler(service),
	)
	routes.GET(
		"/:id/reports/:report_id/download",
		downloadReportHandler(service),
	)
}

func listReportsHandler(service ReportService) gin.HandlerFunc {
	return func(c *gin.Context) {
		if len(c.Request.URL.Query()) != 0 {
			writeReportInvalid(c)
			return
		}
		value, err := service.List(c.Request.Context(), c.Param("id"))
		if err != nil {
			writeReportError(c, err)
			return
		}
		Write(c, http.StatusOK, value)
	}
}

func generateReportHandler(service ReportService) gin.HandlerFunc {
	type requestBody struct {
		Format report.Format `json:"format"`
	}
	return func(c *gin.Context) {
		if len(c.Request.URL.Query()) != 0 {
			writeReportInvalid(c)
			return
		}
		c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, 4096)
		decoder := json.NewDecoder(c.Request.Body)
		decoder.DisallowUnknownFields()
		var request requestBody
		if err := decoder.Decode(&request); err != nil ||
			ensureJSONEnd(decoder) != nil {
			writeReportInvalid(c)
			return
		}
		idempotencyKey := c.GetHeader("Idempotency-Key")
		if (request.Format != report.FormatJSON &&
			request.Format != report.FormatHTML &&
			request.Format != report.FormatDOCX) ||
			!validReportIdempotencyKey(idempotencyKey) {
			writeReportInvalid(c)
			return
		}
		value, created, err := service.Generate(
			c.Request.Context(),
			c.Param("id"),
			request.Format,
			idempotencyKey,
		)
		if err != nil {
			writeReportError(c, err)
			return
		}
		status := http.StatusOK
		if created {
			status = http.StatusCreated
		}
		Write(c, status, value)
	}
}

func validReportIdempotencyKey(value string) bool {
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

func downloadReportHandler(service ReportService) gin.HandlerFunc {
	return func(c *gin.Context) {
		encoding, valid := reportDownloadEncoding(c)
		if !valid {
			writeReportInvalid(c)
			return
		}
		value, err := service.Download(
			c.Request.Context(),
			c.Param("id"),
			c.Param("report_id"),
		)
		if err != nil {
			writeReportError(c, err)
			return
		}
		defer value.Content.Close()

		if encoding == "gzip" && value.ContentType != "application/json" {
			writeReportInvalid(c)
			return
		}

		sha256Hex := value.SHA256
		sizeBytes := value.SizeBytes
		contentType := value.ContentType
		filename := value.Filename
		if encoding == "gzip" {
			sha256Hex, sizeBytes, err = gzipReportRepresentation(
				value.Content, value.SizeBytes,
			)
			if err != nil {
				c.Error(err).SetType(gin.ErrorTypePrivate)
				WriteError(
					c, http.StatusInternalServerError, "report_download_failed",
					"The report could not be downloaded.", nil,
				)
				return
			}
			contentType = "application/gzip"
			filename += ".gz"
		}

		rawDigest, err := hex.DecodeString(sha256Hex)
		if err != nil {
			c.Error(err).SetType(gin.ErrorTypePrivate)
			WriteError(
				c, http.StatusInternalServerError, "report_download_failed",
				"The report could not be downloaded.", nil,
			)
			return
		}
		c.Header("Content-Type", contentType)
		c.Header("Content-Length", strconv.FormatUint(sizeBytes, 10))
		c.Header(
			"Content-Disposition",
			fmt.Sprintf(`attachment; filename="%s"`, filename),
		)
		c.Header("X-Content-Type-Options", "nosniff")
		c.Header("Cache-Control", "private, no-store")
		c.Header("ETag", `"`+sha256Hex+`"`)
		c.Header("Digest", "sha-256="+base64.StdEncoding.EncodeToString(rawDigest))
		c.Header("X-Checksum-SHA256", sha256Hex)
		c.Status(http.StatusOK)
		var written int64
		var copyErr error
		if encoding == "gzip" {
			compressed := gzip.NewWriter(c.Writer)
			written, copyErr = io.CopyN(
				compressed, value.Content, int64(value.SizeBytes),
			)
			copyErr = errors.Join(copyErr, compressed.Close())
		} else {
			written, copyErr = io.CopyN(
				c.Writer, value.Content, int64(value.SizeBytes),
			)
		}
		if copyErr != nil || uint64(written) != value.SizeBytes {
			if copyErr == nil {
				copyErr = io.ErrUnexpectedEOF
			}
			c.Error(copyErr).SetType(gin.ErrorTypePrivate)
		}
	}
}

func reportDownloadEncoding(c *gin.Context) (string, bool) {
	query := c.Request.URL.Query()
	if len(query) == 0 {
		return "", true
	}
	values, ok := query["encoding"]
	if !ok || len(query) != 1 || len(values) != 1 || values[0] != "gzip" {
		return "", false
	}
	return "gzip", true
}

func gzipReportRepresentation(
	content report.ReadSeekCloser,
	sizeBytes uint64,
) (string, uint64, error) {
	if sizeBytes > uint64(^uint64(0)>>1) {
		return "", 0, errors.New("report is too large to compress")
	}
	hasher := sha256.New()
	counter := &reportByteCounter{}
	compressed := gzip.NewWriter(io.MultiWriter(hasher, counter))
	written, copyErr := io.CopyN(compressed, content, int64(sizeBytes))
	closeErr := compressed.Close()
	if copyErr != nil || closeErr != nil || uint64(written) != sizeBytes {
		return "", 0, errors.Join(copyErr, closeErr, io.ErrUnexpectedEOF)
	}
	if _, err := content.Seek(0, io.SeekStart); err != nil {
		return "", 0, fmt.Errorf("rewind report after gzip sizing: %w", err)
	}
	return hex.EncodeToString(hasher.Sum(nil)), counter.bytes, nil
}

type reportByteCounter struct {
	bytes uint64
}

func (counter *reportByteCounter) Write(value []byte) (int, error) {
	counter.bytes += uint64(len(value))
	return len(value), nil
}

func writeReportInvalid(c *gin.Context) {
	WriteError(
		c,
		http.StatusBadRequest,
		"invalid_report_request",
		"The report request is invalid.",
		nil,
	)
}

func writeReportError(c *gin.Context, err error) {
	switch {
	case errors.Is(err, report.ErrInvalidInput):
		writeReportInvalid(c)
	case errors.Is(err, report.ErrTaskNotFound):
		WriteError(
			c, http.StatusNotFound, "task_not_found",
			"The task was not found.", nil,
		)
	case errors.Is(err, report.ErrReportNotFound):
		WriteError(
			c, http.StatusNotFound, "report_not_found",
			"The report was not found.", nil,
		)
	case errors.Is(err, report.ErrTaskNotTerminal):
		WriteError(
			c, http.StatusConflict, "task_not_reportable",
			"The task is not in a reportable terminal state.", nil,
		)
	case errors.Is(err, report.ErrGenerationInProgress):
		WriteError(
			c, http.StatusConflict, "report_generation_in_progress",
			"The report is already being generated.", nil,
		)
	case errors.Is(err, report.ErrReportConflict):
		WriteError(
			c, http.StatusConflict, "report_conflict",
			"The report cannot be generated in its current state.", nil,
		)
	case errors.Is(err, report.ErrArtifactUnavailable):
		WriteError(
			c, http.StatusConflict, "report_unavailable",
			"The report artifact is unavailable.", nil,
		)
	default:
		c.Error(err).SetType(gin.ErrorTypePrivate)
		WriteError(
			c, http.StatusInternalServerError, "report_operation_failed",
			"The report operation could not be completed.", nil,
		)
	}
}

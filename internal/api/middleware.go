package api

import (
	"crypto/rand"
	"encoding/hex"
	"log/slog"
	"net/http"
	"regexp"
	"runtime/debug"
	"strings"
	"time"

	"binaryscan/internal/requestctx"

	"github.com/gin-gonic/gin"
)

const requestIDContextKey = "binaryscan.request_id"

var validRequestID = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)

func RequestIDMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		requestID := c.GetHeader("X-Request-ID")
		if !validRequestID.MatchString(requestID) {
			requestID = newRequestID()
		}
		c.Set(requestIDContextKey, requestID)
		c.Header("X-Request-ID", requestID)
		c.Request = c.Request.WithContext(requestctx.WithRequestID(c.Request.Context(), requestID))
		c.Next()
	}
}

func AccessLogMiddleware(logger *slog.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		started := time.Now()
		c.Next()
		attributes := []slog.Attr{
			slog.String("request_id", RequestID(c)),
			slog.String("method", c.Request.Method),
			slog.String("path", c.Request.URL.Path),
			slog.Int("status", c.Writer.Status()),
			slog.Int64("duration_ms", time.Since(started).Milliseconds()),
			slog.Int("response_bytes", c.Writer.Size()),
			slog.String("client_ip", c.ClientIP()),
		}
		attributes = appendRouteLogIdentity(attributes, c)
		if len(c.Errors) != 0 {
			attributes = append(attributes, slog.Any("errors", c.Errors.Errors()))
			logger.LogAttrs(
				c.Request.Context(),
				slog.LevelError,
				"http request",
				attributes...,
			)
			return
		}
		logger.LogAttrs(
			c.Request.Context(),
			slog.LevelInfo,
			"http request",
			attributes...,
		)
	}
}

func appendRouteLogIdentity(attributes []slog.Attr, c *gin.Context) []slog.Attr {
	if strings.HasPrefix(c.FullPath(), "/api/v1/tasks/:id") {
		if taskID := c.Param("id"); taskID != "" && safeAuditObjectID(taskID) {
			attributes = append(attributes, slog.String("task_id", taskID))
		}
	}
	if jobID := c.GetString(decompileAuditJobIDKey); jobID != "" &&
		safeAuditObjectID(jobID) {
		attributes = append(attributes, slog.String("job_id", jobID))
	}
	if jobID := c.GetString(imageScanAuditJobIDKey); jobID != "" &&
		safeAuditObjectID(jobID) {
		attributes = append(attributes, slog.String("job_id", jobID))
	}
	return attributes
}

func RecoveryMiddleware(logger *slog.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		defer func() {
			if recovered := recover(); recovered != nil {
				logger.ErrorContext(
					c.Request.Context(),
					"panic recovered",
					slog.String("request_id", RequestID(c)),
					slog.Any("panic", recovered),
					slog.String("stack", string(debug.Stack())),
				)
				if !c.Writer.Written() {
					WriteError(c, http.StatusInternalServerError, "internal_error", "An unexpected server error occurred.", nil)
				}
				c.Abort()
			}
		}()
		c.Next()
	}
}

func newRequestID() string {
	var value [16]byte
	if _, err := rand.Read(value[:]); err == nil {
		return hex.EncodeToString(value[:])
	}
	return hex.EncodeToString([]byte(time.Now().UTC().Format(time.RFC3339Nano)))
}

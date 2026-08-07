package api

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"binaryscan/internal/buildinfo"

	"github.com/gin-gonic/gin"
)

type ReadinessChecker interface {
	PingContext(context.Context) error
}

type Dependencies struct {
	Logger              *slog.Logger
	Database            ReadinessChecker
	ReadinessTimeout    time.Duration
	TrustedProxies      []string
	Auth                AuthManager
	AuthHTTP            AuthHTTPConfig
	Uploads             UploadService
	Tasks               TaskService
	TaskEvents          TaskEventService
	TaskEventsHTTP      TaskEventHTTPConfig
	FileTree            FileTreeService
	Decompile           DecompileService
	ManualImageScan     ManualImageScanService
	Vulnerabilities     VulnerabilityService
	Reports             ReportService
	UserAdmin           UserAdminService
	AuditLogs           AuditLogService
	AuditRecorder       AuditRecorder
	SystemStatus        SystemStatusService
	SampleExport        SampleExportService
	SampleExportEnabled bool
	Build               buildinfo.Info
}

func NewRouter(deps Dependencies) (*gin.Engine, error) {
	if deps.SampleExportEnabled {
		if deps.Auth == nil {
			return nil, errors.New(
				"sample export requires authentication",
			)
		}
		if deps.SampleExport == nil {
			return nil, errors.New(
				"sample export service is required when enabled",
			)
		}
	}
	gin.SetMode(gin.ReleaseMode)
	router := gin.New()
	if err := router.SetTrustedProxies(deps.TrustedProxies); err != nil {
		return nil, err
	}
	router.Use(
		authHTTPConfigContext(deps.AuthHTTP),
		RequestIDMiddleware(),
		AccessLogMiddleware(deps.Logger),
		RecoveryMiddleware(deps.Logger),
	)
	if deps.AuditRecorder != nil {
		router.Use(AuditActivityMiddleware(deps.AuditRecorder))
	}
	router.NoRoute(NotFound)
	router.NoMethod(MethodNotAllowed)
	router.HandleMethodNotAllowed = true

	v1 := router.Group("/api/v1")
	health := v1.Group("/health")
	health.GET("/live", func(c *gin.Context) {
		Write(c, http.StatusOK, gin.H{"status": "ok"})
	})
	health.GET("/ready", readinessHandler(deps.Database, deps.ReadinessTimeout))
	v1.GET("/version", func(c *gin.Context) {
		Write(c, http.StatusOK, deps.Build)
	})
	if deps.Auth != nil {
		registerAuthRoutes(v1, deps.Auth, deps.AuthHTTP)
		if deps.Uploads != nil {
			registerUploadRoutes(v1, deps.Auth, deps.Uploads)
		}
		if deps.Tasks != nil {
			registerTaskRoutes(v1, deps.Auth, deps.Tasks)
		}
		if deps.TaskEvents != nil {
			registerTaskEventRoutes(
				v1,
				deps.Auth,
				deps.TaskEvents,
				deps.TaskEventsHTTP,
			)
		}
		if deps.FileTree != nil {
			registerFileTreeRoutes(v1, deps.Auth, deps.FileTree)
		}
		if deps.Decompile != nil {
			registerDecompileRoutes(v1, deps.Auth, deps.Decompile)
		}
		if deps.ManualImageScan != nil {
			registerManualImageScanRoutes(
				v1,
				deps.Auth,
				deps.ManualImageScan,
			)
		}
		if deps.Vulnerabilities != nil {
			registerVulnerabilityRoutes(v1, deps.Auth, deps.Vulnerabilities)
		}
		if deps.Reports != nil {
			registerReportRoutes(v1, deps.Auth, deps.Reports)
		}
		if deps.UserAdmin != nil || deps.AuditLogs != nil {
			RegisterIdentityAdminRoutes(
				v1,
				deps.Auth,
				deps.UserAdmin,
				deps.AuditLogs,
			)
		}
		if deps.SystemStatus != nil {
			registerSystemStatusRoutes(v1, deps.Auth, deps.SystemStatus)
		}
		if deps.SampleExportEnabled {
			registerSampleExportRoutes(v1, deps.Auth, deps.SampleExport)
		}
	}
	return router, nil
}

func readinessHandler(database ReadinessChecker, timeout time.Duration) gin.HandlerFunc {
	return func(c *gin.Context) {
		ctx, cancel := context.WithTimeout(c.Request.Context(), timeout)
		defer cancel()

		if database == nil {
			Write(c, http.StatusServiceUnavailable, gin.H{
				"status": "not_ready",
				"dependencies": gin.H{
					"mysql": gin.H{"status": "not_configured"},
				},
			})
			return
		}
		if err := database.PingContext(ctx); err != nil {
			Write(c, http.StatusServiceUnavailable, gin.H{
				"status": "not_ready",
				"dependencies": gin.H{
					"mysql": gin.H{"status": "unavailable"},
				},
			})
			return
		}
		Write(c, http.StatusOK, gin.H{
			"status": "ready",
			"dependencies": gin.H{
				"mysql": gin.H{"status": "ready"},
			},
		})
	}
}

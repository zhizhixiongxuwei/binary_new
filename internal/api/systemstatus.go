package api

import (
	"context"
	"net/http"

	"binaryscan/internal/auth"
	"binaryscan/internal/systemstatus"

	"github.com/gin-gonic/gin"
)

type SystemStatusService interface {
	Get(context.Context) (systemstatus.Status, error)
}

func registerSystemStatusRoutes(
	v1 *gin.RouterGroup,
	manager AuthManager,
	service SystemStatusService,
) {
	routes := v1.Group("/admin")
	routes.Use(
		adminNoStore(),
		RequireSession(manager),
		RequireRoles(auth.RoleAdministrator),
	)
	routes.GET("/system", systemStatusHandler(service))
}

func systemStatusHandler(service SystemStatusService) gin.HandlerFunc {
	return func(c *gin.Context) {
		if len(c.Request.URL.Query()) != 0 {
			WriteError(
				c,
				http.StatusBadRequest,
				"invalid_system_status_query",
				"The system status query is invalid.",
				nil,
			)
			return
		}
		value, err := service.Get(c.Request.Context())
		if err != nil {
			c.Error(err).SetType(gin.ErrorTypePrivate)
			WriteError(
				c,
				http.StatusServiceUnavailable,
				"system_status_unavailable",
				"The system status could not be collected.",
				nil,
			)
			return
		}
		Write(c, http.StatusOK, value)
	}
}

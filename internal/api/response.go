package api

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

type Meta struct {
	RequestID string `json:"requestId"`
}

type Response struct {
	Data any  `json:"data"`
	Meta Meta `json:"meta"`
}

type ErrorBody struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Details any    `json:"details,omitempty"`
}

type ErrorResponse struct {
	Error ErrorBody `json:"error"`
	Meta  Meta      `json:"meta"`
}

func Write(c *gin.Context, status int, data any) {
	c.JSON(status, Response{
		Data: data,
		Meta: Meta{RequestID: RequestID(c)},
	})
}

func WriteError(c *gin.Context, status int, code, message string, details any) {
	c.AbortWithStatusJSON(status, ErrorResponse{
		Error: ErrorBody{
			Code:    code,
			Message: message,
			Details: details,
		},
		Meta: Meta{RequestID: RequestID(c)},
	})
}

func NotFound(c *gin.Context) {
	WriteError(c, http.StatusNotFound, "route_not_found", "The requested API route does not exist.", nil)
}

func MethodNotAllowed(c *gin.Context) {
	WriteError(c, http.StatusMethodNotAllowed, "method_not_allowed", "The HTTP method is not allowed for this route.", nil)
}

func RequestID(c *gin.Context) string {
	value, _ := c.Get(requestIDContextKey)
	requestID, _ := value.(string)
	return requestID
}

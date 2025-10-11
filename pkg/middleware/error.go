package middleware

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/taqiudeen275/go-foward/pkg/errors"
	"github.com/taqiudeen275/go-foward/pkg/logger"
)

// ErrorResponse represents a standardized error response
type ErrorResponse struct {
	Error     string                 `json:"error"`
	Code      string                 `json:"code,omitempty"`
	Details   map[string]interface{} `json:"details,omitempty"`
	RequestID string                 `json:"request_id,omitempty"`
	Timestamp string                 `json:"timestamp"`
}

// ErrorMiddleware handles errors and converts them to appropriate HTTP responses
func ErrorMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Next()

		// Check if there are any errors
		if len(c.Errors) > 0 {
			err := c.Errors.Last()
			handleError(c, err.Err)
		}
	}
}

// handleError processes different types of errors and returns appropriate responses
func handleError(c *gin.Context, err error) {
	log := logger.GetLogger()

	requestID := ""
	if id, exists := c.Get(RequestIDKey); exists {
		requestID = id.(string)
	}

	// Handle UnifiedError
	if unifiedErr, ok := err.(*errors.UnifiedError); ok {
		handleUnifiedError(c, unifiedErr, requestID, log)
		return
	}

	// Handle other error types
	log.WithRequestID(requestID).Error("Unhandled error", "error", err.Error())

	response := ErrorResponse{
		Error:     "Internal server error",
		RequestID: requestID,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	}

	c.JSON(http.StatusInternalServerError, response)
}

// handleUnifiedError processes UnifiedError instances
func handleUnifiedError(c *gin.Context, err *errors.UnifiedError, requestID string, log *logger.Logger) {
	// Set request ID if not already set
	if err.RequestID == "" {
		err.RequestID = requestID
	}

	// Log the error
	log.LogError(c.Request.Context(), err)

	// Create audit log if required
	if err.ShouldAudit {
		auditEvent := logger.CreateAuditEvent(err.UserID, "error_occurred", err.Resource).
			WithDetails("error_code", err.Code).
			WithDetails("error_message", err.Message).
			WithDetails("severity", err.Severity).
			WithDetails("category", err.Category).
			WithRequestID(requestID).
			WithError(string(err.Code))

		log.LogAudit(c.Request.Context(), auditEvent)
	}

	// Send alert if required
	if err.ShouldAlert {
		// In a real implementation, this would send alerts via email, Slack, etc.
		log.LogSecurity(c.Request.Context(), "error_alert", string(err.Severity), map[string]interface{}{
			"error_code":    err.Code,
			"error_message": err.Message,
			"user_id":       err.UserID,
			"resource":      err.Resource,
			"action":        err.Action,
			"request_id":    requestID,
		})
	}

	// Determine HTTP status code
	statusCode := getHTTPStatusFromError(err)

	// Create response
	response := ErrorResponse{
		Error:     err.Message,
		Code:      string(err.Code),
		Details:   err.Details,
		RequestID: requestID,
		Timestamp: err.Timestamp.Format("2006-01-02T15:04:05Z07:00"),
	}

	c.JSON(statusCode, response)
}

// getHTTPStatusFromError maps error codes to HTTP status codes
func getHTTPStatusFromError(err *errors.UnifiedError) int {
	switch err.Code {
	case errors.ErrInvalidCredentials:
		return http.StatusUnauthorized
	case errors.ErrTokenExpired:
		return http.StatusUnauthorized
	case errors.ErrUnauthorized:
		return http.StatusUnauthorized
	case errors.ErrForbidden:
		return http.StatusForbidden
	case errors.ErrRecordNotFound:
		return http.StatusNotFound
	case errors.ErrDuplicateRecord:
		return http.StatusConflict
	case errors.ErrInvalidConfig:
		return http.StatusBadRequest
	case errors.ErrMissingConfig:
		return http.StatusBadRequest
	case errors.ErrDatabaseConnection:
		return http.StatusServiceUnavailable
	case errors.ErrServiceUnavailable:
		return http.StatusServiceUnavailable
	default:
		return http.StatusInternalServerError
	}
}

// AbortWithError is a helper function to abort with a UnifiedError
func AbortWithError(c *gin.Context, err *errors.UnifiedError) {
	c.Error(err)
	c.Abort()
}

// AbortWithUnauthorized is a helper for unauthorized errors
func AbortWithUnauthorized(c *gin.Context, message string) {
	err := errors.NewAuthError(message).WithRequestID(getRequestID(c))
	AbortWithError(c, err)
}

// AbortWithForbidden is a helper for forbidden errors
func AbortWithForbidden(c *gin.Context, message string) {
	err := errors.NewSecurityError(message).WithRequestID(getRequestID(c))
	AbortWithError(c, err)
}

// AbortWithBadRequest is a helper for bad request errors
func AbortWithBadRequest(c *gin.Context, message string) {
	err := errors.New(errors.ErrInvalidConfig, message).
		WithCategory(errors.CategoryConfig).
		WithSeverity(errors.SeverityMedium).
		WithRequestID(getRequestID(c))
	AbortWithError(c, err)
}

// AbortWithInternalError is a helper for internal server errors
func AbortWithInternalError(c *gin.Context, message string) {
	err := errors.New(errors.ErrInternalServer, message).
		WithCategory(errors.CategoryServer).
		WithSeverity(errors.SeverityHigh).
		WithRequestID(getRequestID(c)).
		ShouldSendAlert()
	AbortWithError(c, err)
}

// getRequestID extracts request ID from context
func getRequestID(c *gin.Context) string {
	if id, exists := c.Get(RequestIDKey); exists {
		return id.(string)
	}
	return ""
}

// GetRequestID extracts request ID from Gin context (public function)
func GetRequestID(c *gin.Context) string {
	return getRequestID(c)
}

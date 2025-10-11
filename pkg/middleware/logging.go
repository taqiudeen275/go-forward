package middleware

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/taqiudeen275/go-foward/pkg/logger"
)

// RequestIDKey is the key used to store request ID in context
const RequestIDKey = "request_id"

// RequestIDMiddleware adds a unique request ID to each request
func RequestIDMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		requestID := c.GetHeader("X-Request-ID")
		if requestID == "" {
			// Generate a simple request ID without external dependencies
			requestID = generateRequestID()
		}

		// Set request ID in context and header
		c.Set(RequestIDKey, requestID)
		c.Header("X-Request-ID", requestID)

		// Add to Gin context for logging
		ctx := context.WithValue(c.Request.Context(), RequestIDKey, requestID)
		c.Request = c.Request.WithContext(ctx)

		c.Next()
	}
}

// LoggingMiddleware provides structured request logging
func LoggingMiddleware() gin.HandlerFunc {
	return gin.LoggerWithFormatter(func(param gin.LogFormatterParams) string {
		log := logger.GetLogger()

		// Get request ID from context
		requestID := ""
		if id, exists := param.Keys[RequestIDKey]; exists {
			requestID = id.(string)
		}

		// Create structured log entry
		log.WithRequestID(requestID).Info("HTTP Request",
			"method", param.Method,
			"path", param.Path,
			"status", param.StatusCode,
			"latency", param.Latency,
			"ip", param.ClientIP,
			"user_agent", param.Request.UserAgent(),
			"error", param.ErrorMessage,
		)

		return ""
	})
}

// AuditMiddleware logs requests for audit purposes
func AuditMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()

		// Capture request body for audit (be careful with large payloads)
		var requestBody []byte
		if c.Request.Body != nil && c.Request.ContentLength < 1024*1024 { // Max 1MB
			requestBody, _ = io.ReadAll(c.Request.Body)
			c.Request.Body = io.NopCloser(bytes.NewBuffer(requestBody))
		}

		// Process request
		c.Next()

		// Log audit event
		duration := time.Since(start)
		log := logger.GetLogger()

		requestID := ""
		if id, exists := c.Get(RequestIDKey); exists {
			requestID = id.(string)
		}

		// Create audit event
		auditEvent := logger.CreateAuditEvent("", "http_request", c.FullPath()).
			WithDetails("method", c.Request.Method).
			WithDetails("status_code", c.Writer.Status()).
			WithDetails("duration_ms", duration.Milliseconds()).
			WithDetails("request_size", c.Request.ContentLength).
			WithDetails("response_size", c.Writer.Size()).
			WithIPAddress(c.ClientIP()).
			WithUserAgent(c.Request.UserAgent()).
			WithRequestID(requestID)

		// Add request body to audit if it's a sensitive operation
		if c.Request.Method != "GET" && len(requestBody) > 0 {
			auditEvent.WithDetails("request_body", string(requestBody))
		}

		// Mark as failed if status code indicates error
		if c.Writer.Status() >= 400 {
			auditEvent.WithError(string(rune(c.Writer.Status())))
		}

		log.LogAudit(c.Request.Context(), auditEvent)
	}
}

// ErrorHandlingMiddleware handles panics and errors
func ErrorHandlingMiddleware() gin.HandlerFunc {
	return gin.CustomRecovery(func(c *gin.Context, recovered interface{}) {
		log := logger.GetLogger()

		requestID := ""
		if id, exists := c.Get(RequestIDKey); exists {
			requestID = id.(string)
		}

		// Log the panic
		log.WithRequestID(requestID).Error("Panic recovered",
			"error", recovered,
			"method", c.Request.Method,
			"path", c.Request.URL.Path,
			"ip", c.ClientIP(),
		)

		// Create security event for potential attacks
		securityEvent := map[string]interface{}{
			"type":       "panic_recovered",
			"error":      recovered,
			"method":     c.Request.Method,
			"path":       c.Request.URL.Path,
			"ip":         c.ClientIP(),
			"user_agent": c.Request.UserAgent(),
			"request_id": requestID,
		}

		log.LogSecurity(c.Request.Context(), "panic_recovered", "high", securityEvent)

		// Return error response
		c.JSON(500, gin.H{
			"error":      "Internal server error",
			"request_id": requestID,
		})
	})
}

// PerformanceMiddleware tracks performance metrics
func PerformanceMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()

		// Process request
		c.Next()

		// Calculate metrics
		duration := time.Since(start)

		// Log performance metrics for slow requests (>1s)
		if duration > time.Second {
			log := logger.GetLogger()

			requestID := ""
			if id, exists := c.Get(RequestIDKey); exists {
				requestID = id.(string)
			}

			details := map[string]interface{}{
				"method":        c.Request.Method,
				"path":          c.Request.URL.Path,
				"status_code":   c.Writer.Status(),
				"request_size":  c.Request.ContentLength,
				"response_size": c.Writer.Size(),
				"ip":            c.ClientIP(),
				"request_id":    requestID,
			}

			log.LogPerformance(c.Request.Context(), "slow_request", duration, details)
		}
	}
}

// SecurityHeadersMiddleware adds security headers
func SecurityHeadersMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Security headers
		c.Header("X-Content-Type-Options", "nosniff")
		c.Header("X-Frame-Options", "DENY")
		c.Header("X-XSS-Protection", "1; mode=block")
		c.Header("Referrer-Policy", "strict-origin-when-cross-origin")
		c.Header("Content-Security-Policy", "default-src 'self'")
		c.Header("Strict-Transport-Security", "max-age=31536000; includeSubDomains")

		c.Next()
	}
}

// generateRequestID generates a simple request ID
func generateRequestID() string {
	// Simple request ID generation using timestamp and random component
	return fmt.Sprintf("req_%d_%d", time.Now().UnixNano(), time.Now().Nanosecond()%10000)
}

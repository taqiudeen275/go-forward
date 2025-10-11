package middleware

import (
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/taqiudeen275/go-foward/pkg/logger"
)

// RequestMetrics holds request metrics
type RequestMetrics struct {
	TotalRequests    int64
	RequestsByPath   map[string]int64
	RequestsByMethod map[string]int64
	RequestsByStatus map[int]int64
	AverageLatency   time.Duration
	totalLatency     time.Duration
}

// MonitoringMiddleware creates a monitoring middleware
func MonitoringMiddleware(logger logger.Logger) gin.HandlerFunc {
	metrics := &RequestMetrics{
		RequestsByPath:   make(map[string]int64),
		RequestsByMethod: make(map[string]int64),
		RequestsByStatus: make(map[int]int64),
	}

	return func(c *gin.Context) {
		start := time.Now()

		// Process request
		c.Next()

		// Calculate metrics
		latency := time.Since(start)
		status := c.Writer.Status()
		method := c.Request.Method
		path := c.FullPath()

		// Update metrics
		metrics.TotalRequests++
		metrics.RequestsByPath[path]++
		metrics.RequestsByMethod[method]++
		metrics.RequestsByStatus[status]++
		metrics.totalLatency += latency
		metrics.AverageLatency = metrics.totalLatency / time.Duration(metrics.TotalRequests)

		// Log detailed request information
		logger.Info("Request completed: method=%s path=%s status=%d latency=%v size=%d ip=%s user_agent=%s",
			method,
			path,
			status,
			latency,
			c.Writer.Size(),
			c.ClientIP(),
			c.Request.UserAgent(),
		)

		// Set response headers for monitoring
		c.Header("X-Response-Time", latency.String())
		c.Header("X-Request-ID", getRequestID(c))
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

		c.Next()
	}
}

// RequestIDMiddleware adds a unique request ID to each request
func RequestIDMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		requestID := c.GetHeader("X-Request-ID")
		if requestID == "" {
			requestID = generateRequestID()
		}

		c.Set("request_id", requestID)
		c.Header("X-Request-ID", requestID)

		c.Next()
	}
}

// getRequestID gets the request ID from context
func getRequestID(c *gin.Context) string {
	if requestID, exists := c.Get("request_id"); exists {
		if id, ok := requestID.(string); ok {
			return id
		}
	}
	return ""
}

// generateRequestID generates a unique request ID
func generateRequestID() string {
	// Simple request ID generation using timestamp and random component
	return strconv.FormatInt(time.Now().UnixNano(), 36)
}

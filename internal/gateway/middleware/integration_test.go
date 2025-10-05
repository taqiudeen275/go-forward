package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/taqiudeen275/go-foward/internal/config"
	"github.com/taqiudeen275/go-foward/pkg/logger"
)

func TestMiddlewareIntegration(t *testing.T) {
	gin.SetMode(gin.TestMode)

	// Create configuration
	cfg := config.Config{
		Server: config.ServerConfig{
			CORS: config.CORSConfig{
				AllowedOrigins: []string{"https://example.com"},
				AllowedMethods: []string{"GET", "POST", "OPTIONS"},
				AllowedHeaders: []string{"Content-Type", "Authorization"},
			},
			RateLimit: config.RateLimitConfig{
				Enabled:           true,
				RequestsPerMinute: 60,
				BurstSize:         5,
				CleanupInterval:   time.Minute,
			},
		},
	}

	// Create router with all middleware
	router := gin.New()
	logger := logger.New("debug")

	// Add all middleware in the same order as the server
	router.Use(CORS(cfg.Server.CORS))
	router.Use(RateLimit(cfg.Server.RateLimit))
	router.Use(MonitoringMiddleware(logger))
	router.Use(SecurityHeadersMiddleware())
	router.Use(RequestIDMiddleware())

	// Add test endpoint
	router.GET("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"message":    "success",
			"request_id": c.GetString("request_id"),
		})
	})

	t.Run("All middleware working together", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/test", nil)
		req.Header.Set("Origin", "https://example.com")
		req.Header.Set("User-Agent", "test-client")

		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		// Check response status
		assert.Equal(t, http.StatusOK, w.Code)

		// Check CORS headers
		assert.Equal(t, "https://example.com", w.Header().Get("Access-Control-Allow-Origin"))
		assert.Equal(t, "GET, POST, OPTIONS", w.Header().Get("Access-Control-Allow-Methods"))

		// Check security headers
		assert.Equal(t, "nosniff", w.Header().Get("X-Content-Type-Options"))
		assert.Equal(t, "DENY", w.Header().Get("X-Frame-Options"))

		// Check monitoring headers
		assert.NotEmpty(t, w.Header().Get("X-Response-Time"))
		assert.NotEmpty(t, w.Header().Get("X-Request-ID"))
	})

	t.Run("CORS preflight request", func(t *testing.T) {
		req := httptest.NewRequest("OPTIONS", "/test", nil)
		req.Header.Set("Origin", "https://example.com")
		req.Header.Set("Access-Control-Request-Method", "POST")
		req.Header.Set("Access-Control-Request-Headers", "Content-Type")

		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		// Check preflight response
		assert.Equal(t, http.StatusNoContent, w.Code)
		assert.Equal(t, "https://example.com", w.Header().Get("Access-Control-Allow-Origin"))
		assert.Equal(t, "GET, POST, OPTIONS", w.Header().Get("Access-Control-Allow-Methods"))
	})

	t.Run("Rate limiting works", func(t *testing.T) {
		// Make requests up to the burst limit
		for i := 0; i < 5; i++ {
			req := httptest.NewRequest("GET", "/test", nil)
			req.RemoteAddr = "192.168.1.100:12345" // Fixed IP for testing

			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			assert.Equal(t, http.StatusOK, w.Code, "Request %d should succeed", i+1)
		}

		// Next request should be rate limited
		req := httptest.NewRequest("GET", "/test", nil)
		req.RemoteAddr = "192.168.1.100:12345"

		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusTooManyRequests, w.Code)
	})

	t.Run("Unauthorized CORS origin", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/test", nil)
		req.Header.Set("Origin", "https://unauthorized.com")

		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		// Request should still succeed but without CORS headers
		assert.Equal(t, http.StatusOK, w.Code)
		assert.Empty(t, w.Header().Get("Access-Control-Allow-Origin"))

		// Security headers should still be present
		assert.Equal(t, "nosniff", w.Header().Get("X-Content-Type-Options"))
	})
}

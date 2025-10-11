package gateway

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/taqiudeen275/go-foward/internal/config"
	"github.com/taqiudeen275/go-foward/internal/gateway/middleware"
	"github.com/taqiudeen275/go-foward/pkg/logger"
)

// MockService implements ServiceHandler for testing
type MockService struct {
	name string
}

func (m *MockService) RegisterRoutes(router gin.IRouter) {
	router.GET("/mock", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"service": m.name})
	})
}

func (m *MockService) Name() string {
	return m.name
}

func TestGateway_New(t *testing.T) {
	cfg := &config.Config{
		Server: config.ServerConfig{
			Host:         "localhost",
			Port:         8080,
			ReadTimeout:  30 * time.Second,
			WriteTimeout: 30 * time.Second,
			LogLevel:     "debug",
		},
	}

	log := logger.New("debug")
	gateway := New(cfg, log)

	assert.NotNil(t, gateway)
	assert.Equal(t, cfg, gateway.config)
	assert.NotNil(t, gateway.router)
	assert.NotNil(t, gateway.logger)
	assert.NotNil(t, gateway.services)
	assert.NotNil(t, gateway.middleware)
}

func TestGateway_RegisterService(t *testing.T) {
	cfg := &config.Config{
		Server: config.ServerConfig{LogLevel: "debug"},
	}
	log := logger.New("debug")
	gateway := New(cfg, log)

	mockService := &MockService{name: "test-service"}

	// Test successful registration
	err := gateway.RegisterService(mockService)
	assert.NoError(t, err)

	// Test duplicate registration
	err = gateway.RegisterService(mockService)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "already registered")
}

func TestGateway_HealthEndpoints(t *testing.T) {
	cfg := &config.Config{
		Server: config.ServerConfig{LogLevel: "debug"},
	}
	log := logger.New("debug")
	gateway := New(cfg, log)

	// Setup middleware and routes
	gateway.setupMiddleware()
	gateway.setupRoutes()

	tests := []struct {
		name           string
		endpoint       string
		expectedStatus int
		checkResponse  func(t *testing.T, body map[string]interface{})
	}{
		{
			name:           "Health Check",
			endpoint:       "/health",
			expectedStatus: http.StatusOK,
			checkResponse: func(t *testing.T, body map[string]interface{}) {
				assert.Equal(t, "ok", body["status"])
				assert.Contains(t, body, "timestamp")
				assert.Contains(t, body, "version")
				assert.Contains(t, body, "services")
			},
		},
		{
			name:           "Readiness Check",
			endpoint:       "/health/ready",
			expectedStatus: http.StatusOK,
			checkResponse: func(t *testing.T, body map[string]interface{}) {
				assert.Equal(t, "ready", body["status"])
				assert.Contains(t, body, "checks")
			},
		},
		{
			name:           "Liveness Check",
			endpoint:       "/health/live",
			expectedStatus: http.StatusOK,
			checkResponse: func(t *testing.T, body map[string]interface{}) {
				assert.Equal(t, "alive", body["status"])
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, tt.endpoint, nil)
			w := httptest.NewRecorder()

			gateway.router.ServeHTTP(w, req)

			assert.Equal(t, tt.expectedStatus, w.Code)

			var response map[string]interface{}
			err := json.Unmarshal(w.Body.Bytes(), &response)
			require.NoError(t, err)

			tt.checkResponse(t, response)
		})
	}
}

func TestGateway_ServiceRoutes(t *testing.T) {
	cfg := &config.Config{
		Server: config.ServerConfig{LogLevel: "debug"},
	}
	log := logger.New("debug")
	gateway := New(cfg, log)

	// Register a mock service
	mockService := &MockService{name: "test-service"}
	err := gateway.RegisterService(mockService)
	require.NoError(t, err)

	// Setup middleware and routes
	gateway.setupMiddleware()
	gateway.setupRoutes()

	// Test service route
	req := httptest.NewRequest(http.MethodGet, "/mock", nil)
	w := httptest.NewRecorder()

	gateway.router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var response map[string]interface{}
	err = json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)

	assert.Equal(t, "test-service", response["service"])
}

func TestGateway_AddMiddleware(t *testing.T) {
	cfg := &config.Config{
		Server: config.ServerConfig{LogLevel: "debug"},
	}
	log := logger.New("debug")
	gateway := New(cfg, log)

	// Add custom middleware
	middlewareCalled := false
	customMiddleware := func(c *gin.Context) {
		middlewareCalled = true
		c.Next()
	}

	gateway.AddMiddleware(customMiddleware)
	gateway.setupMiddleware()
	gateway.setupRoutes()

	// Make a request to trigger middleware
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	w := httptest.NewRecorder()

	gateway.router.ServeHTTP(w, req)

	assert.True(t, middlewareCalled)
}

// Integration Tests for Gateway

func TestGateway_ServiceRegistrationAndRouting(t *testing.T) {
	cfg := &config.Config{
		Server: config.ServerConfig{
			LogLevel: "debug",
			CORS: config.CORSConfig{
				AllowedOrigins: []string{"*"},
				AllowedMethods: []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
				AllowedHeaders: []string{"Content-Type", "Authorization"},
			},
		},
	}
	log := logger.New("debug")
	gateway := New(cfg, log)

	// Create multiple mock services with different routes
	authService := &UniqueRouteService{name: "auth", route: "/auth-test"}
	apiService := &UniqueRouteService{name: "api", route: "/api-test"}
	storageService := &UniqueRouteService{name: "storage", route: "/storage-test"}

	// Register services
	err := gateway.RegisterService(authService)
	require.NoError(t, err)

	err = gateway.RegisterService(apiService)
	require.NoError(t, err)

	err = gateway.RegisterService(storageService)
	require.NoError(t, err)

	// Setup gateway
	gateway.Setup()

	tests := []struct {
		name           string
		path           string
		expectedStatus int
		expectedBody   map[string]any
	}{
		{
			name:           "Auth service route",
			path:           "/auth-test",
			expectedStatus: http.StatusOK,
			expectedBody:   map[string]any{"service": "auth"},
		},
		{
			name:           "API service route",
			path:           "/api-test",
			expectedStatus: http.StatusOK,
			expectedBody:   map[string]any{"service": "api"},
		},
		{
			name:           "Storage service route",
			path:           "/storage-test",
			expectedStatus: http.StatusOK,
			expectedBody:   map[string]any{"service": "storage"},
		},
		{
			name:           "Health check includes all services",
			path:           "/health",
			expectedStatus: http.StatusOK,
			expectedBody: map[string]any{
				"status":  "ok",
				"version": "1.0.0",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, tt.path, nil)
			w := httptest.NewRecorder()

			gateway.router.ServeHTTP(w, req)

			assert.Equal(t, tt.expectedStatus, w.Code)

			var response map[string]any
			err := json.Unmarshal(w.Body.Bytes(), &response)
			require.NoError(t, err)

			for key, expectedValue := range tt.expectedBody {
				assert.Equal(t, expectedValue, response[key])
			}

			// Special check for health endpoint services list
			if tt.path == "/health" {
				services, ok := response["services"].([]any)
				require.True(t, ok)
				assert.Len(t, services, 3)

				serviceNames := make([]string, len(services))
				for i, s := range services {
					serviceNames[i] = s.(string)
				}
				assert.Contains(t, serviceNames, "auth")
				assert.Contains(t, serviceNames, "api")
				assert.Contains(t, serviceNames, "storage")
			}
		})
	}
}

func TestGateway_MiddlewareIntegration(t *testing.T) {
	cfg := &config.Config{
		Server: config.ServerConfig{
			LogLevel: "debug",
			CORS: config.CORSConfig{
				AllowedOrigins:   []string{"https://example.com", "https://app.example.com"},
				AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
				AllowedHeaders:   []string{"Content-Type", "Authorization", "X-Custom-Header"},
				ExposedHeaders:   []string{"X-Total-Count"},
				AllowCredentials: true,
				MaxAge:           3600,
			},
			RateLimit: config.RateLimitConfig{
				Enabled:           true,
				RequestsPerMinute: 60,
				BurstSize:         5,
				CleanupInterval:   time.Minute,
			},
		},
	}
	log := logger.New("debug")
	gateway := New(cfg, log)

	// Add all middleware
	gateway.AddMiddleware(middleware.CORS(cfg.Server.CORS))
	gateway.AddMiddleware(middleware.RateLimit(cfg.Server.RateLimit))
	gateway.AddMiddleware(middleware.MonitoringMiddleware(log))
	gateway.AddMiddleware(middleware.SecurityHeadersMiddleware())
	gateway.AddMiddleware(middleware.RequestIDMiddleware())

	// Register a test service
	testService := &MockService{name: "test"}
	err := gateway.RegisterService(testService)
	require.NoError(t, err)

	gateway.Setup()

	t.Run("CORS middleware integration", func(t *testing.T) {
		// Test allowed origin
		req := httptest.NewRequest(http.MethodGet, "/mock", nil)
		req.Header.Set("Origin", "https://example.com")
		w := httptest.NewRecorder()

		gateway.router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.Equal(t, "https://example.com", w.Header().Get("Access-Control-Allow-Origin"))
		assert.Equal(t, "GET, POST, PUT, DELETE, OPTIONS", w.Header().Get("Access-Control-Allow-Methods"))
		assert.Equal(t, "true", w.Header().Get("Access-Control-Allow-Credentials"))

		// Test preflight request
		req = httptest.NewRequest(http.MethodOptions, "/mock", nil)
		req.Header.Set("Origin", "https://app.example.com")
		req.Header.Set("Access-Control-Request-Method", "POST")
		req.Header.Set("Access-Control-Request-Headers", "Content-Type")
		w = httptest.NewRecorder()

		gateway.router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusNoContent, w.Code)
		assert.Equal(t, "https://app.example.com", w.Header().Get("Access-Control-Allow-Origin"))
	})

	t.Run("Security headers middleware integration", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/mock", nil)
		w := httptest.NewRecorder()

		gateway.router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.Equal(t, "nosniff", w.Header().Get("X-Content-Type-Options"))
		assert.Equal(t, "DENY", w.Header().Get("X-Frame-Options"))
		assert.Equal(t, "1; mode=block", w.Header().Get("X-XSS-Protection"))
		assert.Equal(t, "strict-origin-when-cross-origin", w.Header().Get("Referrer-Policy"))
		assert.Equal(t, "default-src 'self'", w.Header().Get("Content-Security-Policy"))
	})

	t.Run("Monitoring middleware integration", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/mock", nil)
		req.Header.Set("User-Agent", "test-client/1.0")
		w := httptest.NewRecorder()

		gateway.router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.NotEmpty(t, w.Header().Get("X-Response-Time"))
		assert.NotEmpty(t, w.Header().Get("X-Request-ID"))
	})

	t.Run("Rate limiting middleware integration", func(t *testing.T) {
		clientIP := "192.168.1.100"

		// Make requests up to burst limit
		for i := range 5 {
			req := httptest.NewRequest(http.MethodGet, "/mock", nil)
			req.RemoteAddr = fmt.Sprintf("%s:%d", clientIP, 12345+i)
			w := httptest.NewRecorder()

			gateway.router.ServeHTTP(w, req)

			assert.Equal(t, http.StatusOK, w.Code, "Request %d should succeed", i+1)
		}

		// Next request should be rate limited
		req := httptest.NewRequest(http.MethodGet, "/mock", nil)
		req.RemoteAddr = fmt.Sprintf("%s:12350", clientIP)
		w := httptest.NewRecorder()

		gateway.router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusTooManyRequests, w.Code)

		var response map[string]any
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)
		assert.Equal(t, "Rate limit exceeded", response["error"])
	})

	t.Run("Request ID middleware integration", func(t *testing.T) {
		// Test with custom request ID
		customID := "custom-request-123"
		req := httptest.NewRequest(http.MethodGet, "/mock", nil)
		req.Header.Set("X-Request-ID", customID)
		w := httptest.NewRecorder()

		gateway.router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.Equal(t, customID, w.Header().Get("X-Request-ID"))

		// Test auto-generated request ID
		req = httptest.NewRequest(http.MethodGet, "/mock", nil)
		w = httptest.NewRecorder()

		gateway.router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.NotEmpty(t, w.Header().Get("X-Request-ID"))
	})
}

func TestGateway_EndToEndRequestFlows(t *testing.T) {
	cfg := &config.Config{
		Server: config.ServerConfig{
			LogLevel: "debug",
			CORS: config.CORSConfig{
				AllowedOrigins: []string{"*"},
				AllowedMethods: []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
				AllowedHeaders: []string{"Content-Type", "Authorization"},
			},
			RateLimit: config.RateLimitConfig{
				Enabled: false, // Disable for cleaner testing
			},
		},
	}
	log := logger.New("debug")
	gateway := New(cfg, log)

	// Create comprehensive mock services
	authService := &ComplexMockService{
		name: "auth",
		routes: map[string]map[string]gin.HandlerFunc{
			"/auth": {
				"POST": func(c *gin.Context) {
					var body map[string]any
					if err := c.ShouldBindJSON(&body); err != nil {
						c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid JSON"})
						return
					}

					action := body["action"].(string)
					switch action {
					case "login":
						c.JSON(http.StatusOK, gin.H{
							"token": "mock-jwt-token",
							"user":  gin.H{"id": "123", "email": "test@example.com"},
						})
					case "register":
						c.JSON(http.StatusCreated, gin.H{
							"message": "User created successfully",
							"user":    gin.H{"id": "124", "email": body["email"]},
						})
					default:
						c.JSON(http.StatusBadRequest, gin.H{"error": "Unknown action"})
					}
				},
			},
		},
	}

	apiService := &ComplexMockService{
		name: "api",
		routes: map[string]map[string]gin.HandlerFunc{
			"/api/users": {
				"GET": func(c *gin.Context) {
					c.JSON(http.StatusOK, gin.H{
						"users": []gin.H{
							{"id": "1", "name": "John Doe"},
							{"id": "2", "name": "Jane Smith"},
						},
						"total": 2,
					})
				},
				"POST": func(c *gin.Context) {
					var body map[string]any
					if err := c.ShouldBindJSON(&body); err != nil {
						c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid JSON"})
						return
					}

					c.JSON(http.StatusCreated, gin.H{
						"id":      "3",
						"name":    body["name"],
						"message": "User created",
					})
				},
			},
			"/api/users/:id": {
				"GET": func(c *gin.Context) {
					id := c.Param("id")
					c.JSON(http.StatusOK, gin.H{
						"id":   id,
						"name": fmt.Sprintf("User %s", id),
					})
				},
				"PUT": func(c *gin.Context) {
					id := c.Param("id")
					var body map[string]any
					if err := c.ShouldBindJSON(&body); err != nil {
						c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid JSON"})
						return
					}

					c.JSON(http.StatusOK, gin.H{
						"id":      id,
						"name":    body["name"],
						"message": "User updated",
					})
				},
				"DELETE": func(c *gin.Context) {
					id := c.Param("id")
					c.JSON(http.StatusOK, gin.H{
						"message": fmt.Sprintf("User %s deleted", id),
					})
				},
			},
		},
	}

	// Register services
	err := gateway.RegisterService(authService)
	require.NoError(t, err)

	err = gateway.RegisterService(apiService)
	require.NoError(t, err)

	// Add middleware
	gateway.AddMiddleware(middleware.CORS(cfg.Server.CORS))
	gateway.AddMiddleware(middleware.MonitoringMiddleware(log))
	gateway.AddMiddleware(middleware.SecurityHeadersMiddleware())
	gateway.AddMiddleware(middleware.RequestIDMiddleware())

	gateway.Setup()

	t.Run("Authentication flow", func(t *testing.T) {
		// Test user registration
		registerPayload := map[string]any{
			"action":   "register",
			"email":    "newuser@example.com",
			"password": "securepassword",
		}
		body, _ := json.Marshal(registerPayload)

		req := httptest.NewRequest(http.MethodPost, "/auth", bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		gateway.router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusCreated, w.Code)

		var response map[string]any
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)
		assert.Equal(t, "User created successfully", response["message"])

		// Test user login
		loginPayload := map[string]any{
			"action":   "login",
			"email":    "test@example.com",
			"password": "password",
		}
		body, _ = json.Marshal(loginPayload)

		req = httptest.NewRequest(http.MethodPost, "/auth", bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json")
		w = httptest.NewRecorder()

		gateway.router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		err = json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)
		assert.Equal(t, "mock-jwt-token", response["token"])
		assert.NotNil(t, response["user"])
	})

	t.Run("API CRUD operations flow", func(t *testing.T) {
		// Test GET users list
		req := httptest.NewRequest(http.MethodGet, "/api/users", nil)
		w := httptest.NewRecorder()

		gateway.router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var response map[string]any
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)
		assert.Equal(t, float64(2), response["total"])

		// Test GET single user
		req = httptest.NewRequest(http.MethodGet, "/api/users/1", nil)
		w = httptest.NewRecorder()

		gateway.router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		err = json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)
		assert.Equal(t, "1", response["id"])
		assert.Equal(t, "User 1", response["name"])

		// Test POST create user
		createPayload := map[string]any{
			"name": "New User",
		}
		body, _ := json.Marshal(createPayload)

		req = httptest.NewRequest(http.MethodPost, "/api/users", bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json")
		w = httptest.NewRecorder()

		gateway.router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusCreated, w.Code)

		err = json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)
		assert.Equal(t, "3", response["id"])
		assert.Equal(t, "New User", response["name"])

		// Test PUT update user
		updatePayload := map[string]any{
			"name": "Updated User",
		}
		body, _ = json.Marshal(updatePayload)

		req = httptest.NewRequest(http.MethodPut, "/api/users/1", bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json")
		w = httptest.NewRecorder()

		gateway.router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		err = json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)
		assert.Equal(t, "1", response["id"])
		assert.Equal(t, "Updated User", response["name"])

		// Test DELETE user
		req = httptest.NewRequest(http.MethodDelete, "/api/users/1", nil)
		w = httptest.NewRecorder()

		gateway.router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		err = json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)
		assert.Contains(t, response["message"], "User 1 deleted")
	})

	t.Run("Error handling flow", func(t *testing.T) {
		// Test invalid JSON
		req := httptest.NewRequest(http.MethodPost, "/auth", strings.NewReader("invalid json"))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		gateway.router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)

		var response map[string]any
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)
		assert.Equal(t, "Invalid JSON", response["error"])

		// Test unknown action
		unknownPayload := map[string]any{
			"action": "unknown",
		}
		body, _ := json.Marshal(unknownPayload)

		req = httptest.NewRequest(http.MethodPost, "/auth", bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json")
		w = httptest.NewRecorder()

		gateway.router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)

		err = json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)
		assert.Equal(t, "Unknown action", response["error"])
	})

	t.Run("Cross-service integration", func(t *testing.T) {
		// Test that all middleware is applied to all services
		tests := []struct {
			name string
			path string
		}{
			{"Auth service", "/auth"},
			{"API service", "/api/users"},
			{"Health check", "/health"},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				var req *http.Request
				if tt.path == "/auth" {
					payload := map[string]any{"action": "login"}
					body, _ := json.Marshal(payload)
					req = httptest.NewRequest(http.MethodPost, tt.path, bytes.NewBuffer(body))
					req.Header.Set("Content-Type", "application/json")
				} else {
					req = httptest.NewRequest(http.MethodGet, tt.path, nil)
				}

				req.Header.Set("Origin", "https://example.com")
				req.Header.Set("User-Agent", "integration-test")
				w := httptest.NewRecorder()

				gateway.router.ServeHTTP(w, req)

				// All requests should have security headers
				assert.Equal(t, "nosniff", w.Header().Get("X-Content-Type-Options"))
				assert.Equal(t, "DENY", w.Header().Get("X-Frame-Options"))

				// All requests should have monitoring headers
				assert.NotEmpty(t, w.Header().Get("X-Response-Time"))
				assert.NotEmpty(t, w.Header().Get("X-Request-ID"))

				// All requests should have CORS headers for allowed origins
				assert.Equal(t, "https://example.com", w.Header().Get("Access-Control-Allow-Origin"))
			})
		}
	})
}

// ComplexMockService implements ServiceHandler with multiple routes
type ComplexMockService struct {
	name   string
	routes map[string]map[string]gin.HandlerFunc
}

func (m *ComplexMockService) RegisterRoutes(router gin.IRouter) {
	for path, methods := range m.routes {
		for method, handler := range methods {
			switch method {
			case "GET":
				router.GET(path, handler)
			case "POST":
				router.POST(path, handler)
			case "PUT":
				router.PUT(path, handler)
			case "DELETE":
				router.DELETE(path, handler)
			case "PATCH":
				router.PATCH(path, handler)
			}
		}
	}
}

func (m *ComplexMockService) Name() string {
	return m.name
}

// UniqueRouteService implements ServiceHandler with unique routes for testing
type UniqueRouteService struct {
	name  string
	route string
}

func (u *UniqueRouteService) RegisterRoutes(router gin.IRouter) {
	router.GET(u.route, func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"service": u.name})
	})
}

func (u *UniqueRouteService) Name() string {
	return u.name
}

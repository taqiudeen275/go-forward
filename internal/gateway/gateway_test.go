package gateway

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/taqiudeen275/go-foward/internal/config"
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

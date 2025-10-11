package middleware

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/taqiudeen275/go-foward/internal/auth"
	"github.com/taqiudeen275/go-foward/pkg/logger"
)

// MockAuthService implements auth.AuthServiceInterface for testing
type MockAuthService struct{}

func (m *MockAuthService) CreateUser(ctx context.Context, req *auth.CreateUserRequest) (*auth.User, error) {
	return nil, nil
}

func (m *MockAuthService) GetUserByID(ctx context.Context, id string) (*auth.User, error) {
	return nil, nil
}

func (m *MockAuthService) GetUserByEmail(ctx context.Context, email string) (*auth.User, error) {
	return nil, nil
}

func (m *MockAuthService) GetUserByPhone(ctx context.Context, phone string) (*auth.User, error) {
	return nil, nil
}

func (m *MockAuthService) GetUserByUsername(ctx context.Context, username string) (*auth.User, error) {
	return nil, nil
}

func (m *MockAuthService) GetUserByIdentifier(ctx context.Context, identifier string) (*auth.User, error) {
	return nil, nil
}

func (m *MockAuthService) UpdateUser(ctx context.Context, id string, req *auth.UpdateUserRequest) (*auth.User, error) {
	return nil, nil
}

func (m *MockAuthService) DeleteUser(ctx context.Context, id string) error {
	return nil
}

func (m *MockAuthService) ListUsers(ctx context.Context, filter *auth.UserFilter) ([]*auth.User, error) {
	return nil, nil
}

func (m *MockAuthService) ValidatePassword(ctx context.Context, identifier, password string) (*auth.User, error) {
	return nil, nil
}

func (m *MockAuthService) UpdatePassword(ctx context.Context, id, newPassword string) error {
	return nil
}

func (m *MockAuthService) VerifyEmail(ctx context.Context, id string) error {
	return nil
}

func (m *MockAuthService) VerifyPhone(ctx context.Context, id string) error {
	return nil
}

func (m *MockAuthService) RequestPasswordReset(ctx context.Context, req *auth.PasswordResetRequest) error {
	return nil
}

func (m *MockAuthService) ConfirmPasswordReset(ctx context.Context, req *auth.PasswordResetConfirmRequest) error {
	return nil
}

func (m *MockAuthService) SendOTP(ctx context.Context, req *auth.OTPRequest) error {
	return nil
}

func (m *MockAuthService) VerifyOTP(ctx context.Context, req *auth.VerifyOTPRequest) (*auth.User, error) {
	return nil, nil
}

func (m *MockAuthService) LoginWithOTP(ctx context.Context, req *auth.VerifyOTPRequest) (*auth.AuthResponse, error) {
	return nil, nil
}

func (m *MockAuthService) RegisterWithOTP(ctx context.Context, req *auth.VerifyOTPRequest, password *string) (*auth.AuthResponse, error) {
	return nil, nil
}

func (m *MockAuthService) RegisterCustomAuthProvider(provider auth.CustomAuthProvider) error {
	return nil
}

func (m *MockAuthService) UnregisterCustomAuthProvider(name string) error {
	return nil
}

func (m *MockAuthService) GetCustomAuthProvider(name string) (auth.CustomAuthProvider, error) {
	return nil, nil
}

func (m *MockAuthService) ListCustomAuthProviders() map[string]auth.CustomAuthProvider {
	return nil
}

func (m *MockAuthService) GetEnabledCustomAuthProviders() map[string]auth.CustomAuthProvider {
	return nil
}

func (m *MockAuthService) GetCustomAuthProviderInfo(providerName string) (map[string]interface{}, error) {
	return nil, nil
}

func (m *MockAuthService) ValidateCustomAuthCredentials(providerName string, credentials map[string]interface{}) error {
	return nil
}

func (m *MockAuthService) AuthenticateWithCustomProvider(ctx context.Context, req *auth.CustomAuthRequest) (*auth.AuthResponse, error) {
	return nil, nil
}

func TestSecurityGatewayMiddleware(t *testing.T) {
	// Set gin to test mode
	gin.SetMode(gin.TestMode)

	// Create test logger
	testLogger := logger.New("debug")

	// Create test configuration
	config := GetDefaultSecurityConfig()

	// Create mock auth service
	mockAuthService := &MockAuthService{}

	// Create security middleware stack
	stack := NewSecurityMiddlewareStack(
		config,
		testLogger,
		mockAuthService,
		NewMockGeolocationProvider(),
	)

	// Create test router
	router := gin.New()

	// Apply security middleware
	stack.ApplySecurityMiddleware(router)

	// Add test endpoint
	router.GET("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "success"})
	})

	t.Run("Basic request should pass", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var response map[string]interface{}
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)
		assert.Equal(t, "success", response["message"])
	})

	t.Run("Request with security headers", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		// Check security headers
		assert.Equal(t, "nosniff", w.Header().Get("X-Content-Type-Options"))
		assert.Equal(t, "DENY", w.Header().Get("X-Frame-Options"))
		assert.Equal(t, "1; mode=block", w.Header().Get("X-XSS-Protection"))
		assert.NotEmpty(t, w.Header().Get("X-Request-ID"))
	})

	t.Run("Rate limiting", func(t *testing.T) {
		// Make multiple requests to trigger rate limiting
		clientIP := "192.168.1.100"

		// First few requests should succeed
		for i := 0; i < 5; i++ {
			req := httptest.NewRequest(http.MethodGet, "/test", nil)
			req.RemoteAddr = clientIP + ":12345"
			w := httptest.NewRecorder()

			router.ServeHTTP(w, req)
			assert.Equal(t, http.StatusOK, w.Code, "Request %d should succeed", i+1)
		}
	})
}

func TestInputValidationMiddleware(t *testing.T) {
	gin.SetMode(gin.TestMode)
	testLogger := logger.New("debug")

	config := InputValidationConfig{
		Enabled:                          true,
		MaxRequestSize:                   1024,
		MaxFieldLength:                   100,
		EnableXSSProtection:              true,
		EnableSQLInjectionProtection:     true,
		EnableCommandInjectionProtection: true,
		AllowedContentTypes:              []string{"application/json"},
	}

	router := gin.New()
	router.Use(InputValidationMiddleware(config, testLogger))

	router.POST("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "success"})
	})

	t.Run("Valid JSON should pass", func(t *testing.T) {
		payload := map[string]string{"name": "test"}
		body, _ := json.Marshal(payload)

		req := httptest.NewRequest(http.MethodPost, "/test", bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)
		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("XSS attempt should be blocked", func(t *testing.T) {
		payload := map[string]string{"name": "<script>alert('xss')</script>"}
		body, _ := json.Marshal(payload)

		req := httptest.NewRequest(http.MethodPost, "/test", bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("SQL injection attempt should be blocked", func(t *testing.T) {
		payload := map[string]string{"query": "SELECT * FROM users WHERE id = 1 OR 1=1"}
		body, _ := json.Marshal(payload)

		req := httptest.NewRequest(http.MethodPost, "/test", bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("Invalid content type should be blocked", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/test", bytes.NewBufferString("test"))
		req.Header.Set("Content-Type", "text/plain")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)
		assert.Equal(t, http.StatusUnsupportedMediaType, w.Code)
	})
}

func TestAdvancedRateLimiter(t *testing.T) {
	testLogger := logger.New("debug")

	config := AdvancedRateLimitConfig{
		Enabled:           true,
		Algorithm:         TokenBucket,
		RequestsPerMinute: 5,
		BurstSize:         3,
		CleanupInterval:   time.Minute,
	}

	limiter := NewAdvancedRateLimiter(config, testLogger)
	defer limiter.Stop()

	clientID := "test-client"

	t.Run("Requests within limit should be allowed", func(t *testing.T) {
		for i := 0; i < 3; i++ {
			allowed, info := limiter.Allow(clientID)
			assert.True(t, allowed, "Request %d should be allowed", i+1)
			assert.True(t, info.Remaining >= 0, "Remaining should be non-negative")
		}
	})

	t.Run("Requests exceeding burst should be denied", func(t *testing.T) {
		// Reset the limiter
		limiter.Reset(clientID)

		// Use up the burst
		for i := 0; i < 3; i++ {
			allowed, _ := limiter.Allow(clientID)
			assert.True(t, allowed, "Burst request %d should be allowed", i+1)
		}

		// Next request should be denied
		allowed, info := limiter.Allow(clientID)
		assert.False(t, allowed, "Request exceeding burst should be denied")
		assert.Greater(t, info.RetryAfter, time.Duration(0), "RetryAfter should be set")
	})

	t.Run("Client blocking should work", func(t *testing.T) {
		testClientID := "blocked-client"

		// Block the client
		err := limiter.Block(testClientID, time.Minute)
		assert.NoError(t, err)

		// Check if client is blocked
		assert.True(t, limiter.IsBlocked(testClientID))

		// Unblock the client
		err = limiter.Unblock(testClientID)
		assert.NoError(t, err)

		// Check if client is unblocked
		assert.False(t, limiter.IsBlocked(testClientID))
	})
}

func TestIPFiltering(t *testing.T) {
	testLogger := logger.New("debug")
	geoProvider := NewMockGeolocationProvider()

	config := IPFilterConfig{
		Enabled:         true,
		WhitelistedIPs:  []string{"127.0.0.1", "192.168.1.100"},
		BlacklistedIPs:  []string{"10.0.0.1"},
		AllowPrivateIPs: true,
	}

	filter := NewIPFilter(config, testLogger, geoProvider)

	t.Run("Whitelisted IP should be allowed", func(t *testing.T) {
		allowed, reason, err := filter.IsIPAllowed("127.0.0.1")
		assert.NoError(t, err)
		assert.True(t, allowed)
		assert.Contains(t, reason, "whitelisted")
	})

	t.Run("Blacklisted IP should be denied", func(t *testing.T) {
		allowed, reason, err := filter.IsIPAllowed("10.0.0.1")
		assert.NoError(t, err)
		assert.False(t, allowed)
		assert.Contains(t, reason, "blacklisted")
	})

	t.Run("Unknown IP should be allowed when no whitelist", func(t *testing.T) {
		configNoWhitelist := config
		configNoWhitelist.WhitelistedIPs = []string{}
		filterNoWhitelist := NewIPFilter(configNoWhitelist, testLogger, geoProvider)

		allowed, reason, err := filterNoWhitelist.IsIPAllowed("8.8.8.8")
		assert.NoError(t, err)
		assert.True(t, allowed)
		assert.Contains(t, reason, "allowed")
	})
}

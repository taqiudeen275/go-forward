package middleware

import (
	"time"

	"github.com/gin-gonic/gin"
	"github.com/taqiudeen275/go-foward/internal/auth"
	"github.com/taqiudeen275/go-foward/internal/config"
	"github.com/taqiudeen275/go-foward/pkg/logger"
)

// SecurityMiddlewareConfig represents comprehensive security middleware configuration
type SecurityMiddlewareConfig struct {
	Authentication  AuthMiddlewareConfig    `json:"authentication"`
	RateLimit       AdvancedRateLimitConfig `json:"rate_limit"`
	InputValidation InputValidationConfig   `json:"input_validation"`
	IPFiltering     IPFilterConfig          `json:"ip_filtering"`
	Audit           AuditConfig             `json:"audit"`
	CORS            config.CORSConfig       `json:"cors"`
	SecurityHeaders bool                    `json:"security_headers"`
	RequestID       bool                    `json:"request_id"`
	Monitoring      bool                    `json:"monitoring"`
}

// SecurityMiddlewareStack represents a complete security middleware stack
type SecurityMiddlewareStack struct {
	config          SecurityMiddlewareConfig
	logger          logger.Logger
	authService     auth.AuthServiceInterface
	securityGateway SecurityGateway
	auditLogger     AuditLogger
	geoProvider     GeolocationProvider
}

// NewSecurityMiddlewareStack creates a new security middleware stack
func NewSecurityMiddlewareStack(
	config SecurityMiddlewareConfig,
	logger logger.Logger,
	authService auth.AuthServiceInterface,
	geoProvider GeolocationProvider,
) *SecurityMiddlewareStack {
	auditLogger := NewAuditLogger(logger, config.Audit)
	securityGateway := NewSecurityGateway(authService, logger, nil, auditLogger)

	return &SecurityMiddlewareStack{
		config:          config,
		logger:          logger,
		authService:     authService,
		securityGateway: securityGateway,
		auditLogger:     auditLogger,
		geoProvider:     geoProvider,
	}
}

// ApplySecurityMiddleware applies all security middleware to a gin router
func (sms *SecurityMiddlewareStack) ApplySecurityMiddleware(router *gin.Engine) {
	// Apply middleware in the correct order for security

	// 1. Request ID (first, for tracking)
	if sms.config.RequestID {
		router.Use(RequestIDMiddleware())
	}

	// 2. Security headers (early, for all responses)
	if sms.config.SecurityHeaders {
		router.Use(SecurityHeadersMiddleware())
	}

	// 3. CORS (before authentication)
	router.Use(CORS(sms.config.CORS))

	// 4. IP filtering (early security check)
	if sms.config.IPFiltering.Enabled {
		router.Use(IPWhitelistMiddleware(sms.config.IPFiltering, sms.logger, sms.geoProvider))
		if sms.config.IPFiltering.GeolocationFilter {
			router.Use(GeolocationFilterMiddleware(sms.config.IPFiltering, sms.logger, sms.geoProvider))
		}
	}

	// 5. Rate limiting (before expensive operations)
	if sms.config.RateLimit.Enabled {
		router.Use(AdvancedRateLimitMiddleware(sms.config.RateLimit, sms.logger))
	}

	// 6. Input validation (before processing)
	if sms.config.InputValidation.Enabled {
		router.Use(InputValidationMiddleware(sms.config.InputValidation, sms.logger))
		router.Use(FileUploadSecurityMiddleware(sms.config.InputValidation, sms.logger))
	}

	// 7. Authentication (after input validation)
	if sms.config.Authentication.RequireAuth {
		router.Use(sms.securityGateway.CreateAuthMiddleware(sms.config.Authentication))
	}

	// 8. Audit logging (after authentication, to capture user context)
	if sms.config.Audit.Enabled {
		router.Use(sms.securityGateway.CreateAuditMiddleware(sms.config.Audit))
	}

	// 9. Monitoring (last, for complete request context)
	if sms.config.Monitoring {
		router.Use(MonitoringMiddleware(sms.logger))
	}
}

// ApplyAdminSecurityMiddleware applies enhanced security for admin endpoints
func (sms *SecurityMiddlewareStack) ApplyAdminSecurityMiddleware(adminGroup *gin.RouterGroup) {
	// Enhanced authentication for admin endpoints
	adminAuthConfig := sms.config.Authentication
	adminAuthConfig.AdminOnly = true
	adminAuthConfig.RequireMFA = true
	adminAuthConfig.RequireVerified = true

	adminGroup.Use(sms.securityGateway.CreateAuthMiddleware(adminAuthConfig))

	// Stricter rate limiting for admin endpoints
	adminRateLimitConfig := sms.config.RateLimit
	adminRateLimitConfig.RequestsPerMinute = adminRateLimitConfig.RequestsPerMinute / 2 // Half the normal rate
	adminRateLimitConfig.ProgressiveEnabled = true
	adminRateLimitConfig.SuspiciousThreshold = 3

	adminGroup.Use(AdvancedRateLimitMiddleware(adminRateLimitConfig, sms.logger))

	// Enhanced audit logging for admin actions
	adminAuditConfig := sms.config.Audit
	adminAuditConfig.LogRequests = true
	adminAuditConfig.LogResponses = true
	adminAuditConfig.LogHeaders = true
	adminAuditConfig.IncludeUserAgent = true
	adminAuditConfig.IncludeIP = true

	adminGroup.Use(sms.securityGateway.CreateAuditMiddleware(adminAuditConfig))
}

// GetDefaultSecurityConfig returns a default security configuration
func GetDefaultSecurityConfig() SecurityMiddlewareConfig {
	return SecurityMiddlewareConfig{
		Authentication: AuthMiddlewareConfig{
			RequireAuth:     false,
			RequiredRoles:   []string{},
			RequireMFA:      false,
			AllowAPIKeys:    true,
			SkipPaths:       []string{"/health", "/metrics", "/auth/login", "/auth/register"},
			AdminOnly:       false,
			RequireVerified: false,
		},
		RateLimit: AdvancedRateLimitConfig{
			Enabled:                 true,
			Algorithm:               TokenBucket,
			RequestsPerMinute:       60,
			BurstSize:               10,
			WindowSize:              time.Minute,
			CleanupInterval:         5 * time.Minute,
			ProgressiveEnabled:      true,
			SuspiciousThreshold:     10,
			ProgressiveMultiplier:   1.5,
			ProgressiveMaxDelay:     5 * time.Minute,
			DDoSProtection:          true,
			DDoSThreshold:           100,
			DDoSWindowSize:          time.Minute,
			DDoSBlockDuration:       10 * time.Minute,
			EmergencyMode:           false,
			EmergencyThreshold:      5,
			EmergencyRequestsPerMin: 10,
			WhitelistedIPs:          []string{"127.0.0.1", "::1"},
			EndpointLimits:          make(map[string]EndpointLimit),
		},
		InputValidation: InputValidationConfig{
			Enabled:                          true,
			MaxRequestSize:                   10 * 1024 * 1024, // 10MB
			MaxFieldLength:                   1000,
			MaxArrayLength:                   100,
			MaxNestingDepth:                  10,
			AllowedContentTypes:              []string{"application/json", "application/x-www-form-urlencoded", "multipart/form-data"},
			BlockedFileExtensions:            []string{".exe", ".bat", ".cmd", ".com", ".pif", ".scr", ".vbs", ".js"},
			AllowedFileExtensions:            []string{".jpg", ".jpeg", ".png", ".gif", ".pdf", ".txt", ".doc", ".docx"},
			MaxFileSize:                      5 * 1024 * 1024, // 5MB
			ScanFileContent:                  true,
			StrictJSONValidation:             true,
			EnableXSSProtection:              true,
			EnableSQLInjectionProtection:     true,
			EnableCommandInjectionProtection: true,
			EnablePathTraversalProtection:    true,
			CustomPatterns:                   []CustomPattern{},
		},
		IPFiltering: IPFilterConfig{
			Enabled:           false,
			WhitelistedIPs:    []string{},
			BlacklistedIPs:    []string{},
			WhitelistedCIDRs:  []string{},
			BlacklistedCIDRs:  []string{},
			AllowPrivateIPs:   true,
			GeolocationFilter: false,
			AllowedCountries:  []string{},
			BlockedCountries:  []string{},
			TrustedProxies:    []string{},
		},
		Audit: AuditConfig{
			Enabled:          true,
			LogRequests:      false,
			LogResponses:     false,
			LogHeaders:       false,
			LogBody:          false,
			SensitiveHeaders: []string{"Authorization", "Cookie", "X-API-Key", "X-Auth-Token"},
			ExcludePaths:     []string{"/health", "/metrics"},
			IncludeUserAgent: true,
			IncludeIP:        true,
		},
		CORS: config.CORSConfig{
			AllowedOrigins:   []string{"*"},
			AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
			AllowedHeaders:   []string{"Content-Type", "Authorization"},
			ExposedHeaders:   []string{},
			AllowCredentials: false,
			MaxAge:           3600,
		},
		SecurityHeaders: true,
		RequestID:       true,
		Monitoring:      true,
	}
}

// GetAdminSecurityConfig returns a security configuration optimized for admin endpoints
func GetAdminSecurityConfig() SecurityMiddlewareConfig {
	config := GetDefaultSecurityConfig()

	// Enhanced authentication for admin
	config.Authentication.RequireAuth = true
	config.Authentication.AdminOnly = true
	config.Authentication.RequireMFA = true
	config.Authentication.RequireVerified = true
	config.Authentication.SkipPaths = []string{} // No skip paths for admin

	// Stricter rate limiting
	config.RateLimit.RequestsPerMinute = 30
	config.RateLimit.BurstSize = 5
	config.RateLimit.ProgressiveEnabled = true
	config.RateLimit.SuspiciousThreshold = 5

	// Enhanced input validation
	config.InputValidation.MaxRequestSize = 5 * 1024 * 1024 // 5MB for admin
	config.InputValidation.StrictJSONValidation = true

	// IP filtering for admin (can be configured per deployment)
	config.IPFiltering.Enabled = false // Can be enabled with specific IPs

	// Comprehensive audit logging
	config.Audit.LogRequests = true
	config.Audit.LogResponses = true
	config.Audit.LogHeaders = true
	config.Audit.IncludeUserAgent = true
	config.Audit.IncludeIP = true

	// Stricter CORS for admin
	config.CORS.AllowedOrigins = []string{} // Should be configured with specific origins
	config.CORS.AllowCredentials = true

	return config
}

package middleware

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/taqiudeen275/go-foward/internal/auth"
	"github.com/taqiudeen275/go-foward/internal/config"
	"github.com/taqiudeen275/go-foward/pkg/logger"
)

// SecurityGateway interface defines security middleware functionality
type SecurityGateway interface {
	CreateAuthMiddleware(config AuthMiddlewareConfig) gin.HandlerFunc
	CreateRateLimitMiddleware(config RateLimitConfig) gin.HandlerFunc
	CreateAuditMiddleware(config AuditConfig) gin.HandlerFunc
	ValidateRequest(req *http.Request) (*ValidationResult, error)
	EnforceRateLimit(userID string, endpoint string) error
	CheckIPWhitelist(ip string, context SecurityContext) (bool, error)
}

// SecurityGatewayImpl implements the SecurityGateway interface
type SecurityGatewayImpl struct {
	authService auth.AuthServiceInterface
	logger      logger.Logger
	config      *config.Config
	rateLimiter *RateLimiter
	ipWhitelist map[string]bool
	auditLogger AuditLogger
}

// AuthMiddlewareConfig represents authentication middleware configuration
type AuthMiddlewareConfig struct {
	RequireAuth     bool     `json:"require_auth"`
	RequiredRoles   []string `json:"required_roles"`
	RequireMFA      bool     `json:"require_mfa"`
	AllowAPIKeys    bool     `json:"allow_api_keys"`
	SkipPaths       []string `json:"skip_paths"`
	AdminOnly       bool     `json:"admin_only"`
	RequireVerified bool     `json:"require_verified"`
}

// RateLimitConfig represents rate limiting configuration
type RateLimitConfig struct {
	Enabled             bool          `json:"enabled"`
	RequestsPerMinute   int           `json:"requests_per_minute"`
	BurstSize           int           `json:"burst_size"`
	ProgressiveEnabled  bool          `json:"progressive_enabled"`
	SuspiciousThreshold int           `json:"suspicious_threshold"`
	EmergencyMode       bool          `json:"emergency_mode"`
	WhitelistedIPs      []string      `json:"whitelisted_ips"`
	CleanupInterval     time.Duration `json:"cleanup_interval"`
}

// AuditConfig represents audit logging configuration
type AuditConfig struct {
	Enabled          bool     `json:"enabled"`
	LogRequests      bool     `json:"log_requests"`
	LogResponses     bool     `json:"log_responses"`
	LogHeaders       bool     `json:"log_headers"`
	LogBody          bool     `json:"log_body"`
	SensitiveHeaders []string `json:"sensitive_headers"`
	ExcludePaths     []string `json:"exclude_paths"`
	IncludeUserAgent bool     `json:"include_user_agent"`
	IncludeIP        bool     `json:"include_ip"`
}

// ValidationResult represents request validation result
type ValidationResult struct {
	Valid    bool                   `json:"valid"`
	Errors   []string               `json:"errors"`
	Warnings []string               `json:"warnings"`
	Metadata map[string]interface{} `json:"metadata"`
}

// SecurityContext represents security context for requests
type SecurityContext struct {
	UserID       string                 `json:"user_id"`
	AdminLevel   string                 `json:"admin_level"`
	IPAddress    string                 `json:"ip_address"`
	UserAgent    string                 `json:"user_agent"`
	SessionID    string                 `json:"session_id"`
	RequestID    string                 `json:"request_id"`
	Capabilities map[string]interface{} `json:"capabilities"`
	Timestamp    time.Time              `json:"timestamp"`
}

// AuditLogger interface for audit logging
type AuditLogger interface {
	LogSecurityEvent(event SecurityEvent) error
	LogRequest(req *http.Request, context SecurityContext) error
	LogResponse(resp *gin.ResponseWriter, context SecurityContext) error
}

// SecurityEvent represents a security event for audit logging
type SecurityEvent struct {
	Type      string                 `json:"type"`
	Severity  string                 `json:"severity"`
	UserID    string                 `json:"user_id"`
	Resource  string                 `json:"resource"`
	Action    string                 `json:"action"`
	Details   map[string]interface{} `json:"details"`
	IPAddress string                 `json:"ip_address"`
	UserAgent string                 `json:"user_agent"`
	Timestamp time.Time              `json:"timestamp"`
	SessionID string                 `json:"session_id"`
	RequestID string                 `json:"request_id"`
	Outcome   string                 `json:"outcome"`
	ErrorCode string                 `json:"error_code,omitempty"`
}

// NewSecurityGateway creates a new security gateway instance
func NewSecurityGateway(
	authService auth.AuthServiceInterface,
	logger logger.Logger,
	cfg *config.Config,
	auditLogger AuditLogger,
) SecurityGateway {
	// Create default rate limit config if config is nil
	var rateLimitConfig config.RateLimitConfig
	if cfg != nil {
		rateLimitConfig = cfg.Server.RateLimit
	} else {
		rateLimitConfig = config.RateLimitConfig{
			Enabled:           true,
			RequestsPerMinute: 60,
			BurstSize:         10,
			CleanupInterval:   5 * time.Minute,
		}
	}

	return &SecurityGatewayImpl{
		authService: authService,
		logger:      logger,
		config:      cfg,
		rateLimiter: NewRateLimiter(rateLimitConfig),
		ipWhitelist: make(map[string]bool),
		auditLogger: auditLogger,
	}
}

// CreateAuthMiddleware creates authentication middleware
func (sg *SecurityGatewayImpl) CreateAuthMiddleware(config AuthMiddlewareConfig) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Skip authentication for specified paths
		if sg.shouldSkipAuth(c.Request.URL.Path, config.SkipPaths) {
			c.Next()
			return
		}

		// Extract and validate authentication token
		token := sg.extractToken(c)
		if token == "" && config.RequireAuth {
			sg.logSecurityEvent("AUTH_MISSING", "MEDIUM", "", c)
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "Authentication required",
				"code":  "AUTH_REQUIRED",
			})
			c.Abort()
			return
		}

		if token != "" {
			// Validate token and get user context
			userContext, err := sg.validateToken(c.Request.Context(), token)
			if err != nil {
				sg.logSecurityEvent("AUTH_INVALID", "MEDIUM", "", c)
				c.JSON(http.StatusUnauthorized, gin.H{
					"error": "Invalid authentication token",
					"code":  "AUTH_INVALID",
				})
				c.Abort()
				return
			}

			// Set user context in gin context
			c.Set("user_id", userContext.UserID)
			c.Set("admin_level", userContext.AdminLevel)
			c.Set("user_capabilities", userContext.Capabilities)
			c.Set("session_id", userContext.SessionID)

			// Check admin requirements
			if config.AdminOnly && !sg.isAdmin(userContext) {
				sg.logSecurityEvent("AUTH_INSUFFICIENT_PRIVILEGES", "HIGH", userContext.UserID, c)
				c.JSON(http.StatusForbidden, gin.H{
					"error": "Admin privileges required",
					"code":  "INSUFFICIENT_PRIVILEGES",
				})
				c.Abort()
				return
			}

			// Check role requirements
			if len(config.RequiredRoles) > 0 && !sg.hasRequiredRoles(userContext, config.RequiredRoles) {
				sg.logSecurityEvent("AUTH_INSUFFICIENT_ROLES", "HIGH", userContext.UserID, c)
				c.JSON(http.StatusForbidden, gin.H{
					"error": "Insufficient role privileges",
					"code":  "INSUFFICIENT_ROLES",
				})
				c.Abort()
				return
			}

			// Check MFA requirements
			if config.RequireMFA && !sg.isMFAVerified(userContext) {
				sg.logSecurityEvent("AUTH_MFA_REQUIRED", "MEDIUM", userContext.UserID, c)
				c.JSON(http.StatusForbidden, gin.H{
					"error": "Multi-factor authentication required",
					"code":  "MFA_REQUIRED",
				})
				c.Abort()
				return
			}

			// Check verification requirements
			if config.RequireVerified && !sg.isUserVerified(userContext) {
				sg.logSecurityEvent("AUTH_VERIFICATION_REQUIRED", "MEDIUM", userContext.UserID, c)
				c.JSON(http.StatusForbidden, gin.H{
					"error": "Account verification required",
					"code":  "VERIFICATION_REQUIRED",
				})
				c.Abort()
				return
			}

			sg.logSecurityEvent("AUTH_SUCCESS", "LOW", userContext.UserID, c)
		}

		c.Next()
	}
}

// CreateRateLimitMiddleware creates rate limiting middleware
func (sg *SecurityGatewayImpl) CreateRateLimitMiddleware(config RateLimitConfig) gin.HandlerFunc {
	return func(c *gin.Context) {
		if !config.Enabled {
			c.Next()
			return
		}

		clientID := sg.getClientID(c)
		clientIP := c.ClientIP()

		// Check IP whitelist
		if sg.isIPWhitelisted(clientIP, config.WhitelistedIPs) {
			c.Next()
			return
		}

		// Check emergency mode
		if config.EmergencyMode {
			sg.logSecurityEvent("RATE_LIMIT_EMERGENCY", "HIGH", clientID, c)
			c.JSON(http.StatusServiceUnavailable, gin.H{
				"error": "Service temporarily unavailable",
				"code":  "EMERGENCY_MODE",
			})
			c.Abort()
			return
		}

		// Apply rate limiting
		allowed := sg.rateLimiter.Allow(clientID)
		if !allowed {
			sg.logSecurityEvent("RATE_LIMIT_EXCEEDED", "MEDIUM", clientID, c)

			// Progressive rate limiting for suspicious activity
			if config.ProgressiveEnabled {
				sg.handleProgressiveRateLimit(c, clientID, config)
				return
			}

			c.Header("Retry-After", "60")
			c.JSON(http.StatusTooManyRequests, gin.H{
				"error":   "Rate limit exceeded",
				"message": "Too many requests, please try again later",
				"code":    "RATE_LIMIT_EXCEEDED",
			})
			c.Abort()
			return
		}

		c.Next()
	}
}

// CreateAuditMiddleware creates audit logging middleware
func (sg *SecurityGatewayImpl) CreateAuditMiddleware(config AuditConfig) gin.HandlerFunc {
	return func(c *gin.Context) {
		if !config.Enabled {
			c.Next()
			return
		}

		// Skip audit logging for excluded paths
		if sg.shouldSkipAudit(c.Request.URL.Path, config.ExcludePaths) {
			c.Next()
			return
		}

		// Create security context
		securityContext := sg.createSecurityContext(c)

		// Log request if enabled
		if config.LogRequests {
			sg.auditLogger.LogRequest(c.Request, securityContext)
		}

		// Process request
		c.Next()

		// Log response if enabled
		if config.LogResponses {
			sg.auditLogger.LogResponse(&c.Writer, securityContext)
		}

		// Log security events based on response status
		status := c.Writer.Status()
		if status >= 400 {
			eventType := sg.getEventTypeFromStatus(status)
			severity := sg.getSeverityFromStatus(status)
			sg.logSecurityEventWithContext(eventType, severity, securityContext.UserID, c, securityContext)
		}
	}
}

// Helper methods

func (sg *SecurityGatewayImpl) shouldSkipAuth(path string, skipPaths []string) bool {
	for _, skipPath := range skipPaths {
		if strings.HasPrefix(path, skipPath) {
			return true
		}
	}
	return false
}

func (sg *SecurityGatewayImpl) shouldSkipAudit(path string, excludePaths []string) bool {
	for _, excludePath := range excludePaths {
		if strings.HasPrefix(path, excludePath) {
			return true
		}
	}
	return false
}

func (sg *SecurityGatewayImpl) extractToken(c *gin.Context) string {
	// Try Authorization header first
	authHeader := c.GetHeader("Authorization")
	if authHeader != "" {
		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) == 2 && strings.ToLower(parts[0]) == "bearer" {
			return parts[1]
		}
	}

	// Try cookie
	if cookie, err := c.Cookie("auth_token"); err == nil {
		return cookie
	}

	// Try query parameter (less secure, for specific use cases)
	return c.Query("token")
}

func (sg *SecurityGatewayImpl) validateToken(ctx context.Context, token string) (*SecurityContext, error) {
	// This would integrate with your JWT validation logic
	// For now, returning a mock implementation
	// In real implementation, this would:
	// 1. Validate JWT signature
	// 2. Check expiration
	// 3. Extract user claims
	// 4. Validate session if needed
	// 5. Check token blacklist

	return &SecurityContext{
		UserID:       "mock-user-id",
		AdminLevel:   "regular",
		IPAddress:    "",
		UserAgent:    "",
		SessionID:    "mock-session-id",
		RequestID:    "",
		Capabilities: make(map[string]interface{}),
		Timestamp:    time.Now(),
	}, nil
}

func (sg *SecurityGatewayImpl) isAdmin(context *SecurityContext) bool {
	adminLevels := []string{"system_admin", "super_admin", "regular_admin", "moderator"}
	for _, level := range adminLevels {
		if context.AdminLevel == level {
			return true
		}
	}
	return false
}

func (sg *SecurityGatewayImpl) hasRequiredRoles(context *SecurityContext, requiredRoles []string) bool {
	// This would check user roles against required roles
	// Implementation depends on your role system
	return true // Mock implementation
}

func (sg *SecurityGatewayImpl) isMFAVerified(context *SecurityContext) bool {
	// Check if MFA is verified for this session
	if verified, exists := context.Capabilities["mfa_verified"]; exists {
		if v, ok := verified.(bool); ok {
			return v
		}
	}
	return false
}

func (sg *SecurityGatewayImpl) isUserVerified(context *SecurityContext) bool {
	// Check if user account is verified
	if verified, exists := context.Capabilities["account_verified"]; exists {
		if v, ok := verified.(bool); ok {
			return v
		}
	}
	return false
}

func (sg *SecurityGatewayImpl) getClientID(c *gin.Context) string {
	// Try to get user ID from context if authenticated
	if userID, exists := c.Get("user_id"); exists {
		if uid, ok := userID.(string); ok {
			return "user:" + uid
		}
	}

	// Fall back to IP address
	return "ip:" + c.ClientIP()
}

func (sg *SecurityGatewayImpl) isIPWhitelisted(ip string, whitelistedIPs []string) bool {
	for _, whitelistedIP := range whitelistedIPs {
		if ip == whitelistedIP {
			return true
		}

		// Check CIDR ranges
		if strings.Contains(whitelistedIP, "/") {
			if _, network, err := net.ParseCIDR(whitelistedIP); err == nil {
				if parsedIP := net.ParseIP(ip); parsedIP != nil {
					if network.Contains(parsedIP) {
						return true
					}
				}
			}
		}
	}
	return false
}

func (sg *SecurityGatewayImpl) handleProgressiveRateLimit(c *gin.Context, clientID string, config RateLimitConfig) {
	// Implement progressive rate limiting logic
	// This could include increasing delays, temporary bans, etc.

	c.Header("Retry-After", "120") // Longer delay for suspicious activity
	c.JSON(http.StatusTooManyRequests, gin.H{
		"error":   "Suspicious activity detected",
		"message": "Account temporarily restricted due to suspicious activity",
		"code":    "SUSPICIOUS_ACTIVITY",
	})
	c.Abort()
}

func (sg *SecurityGatewayImpl) createSecurityContext(c *gin.Context) SecurityContext {
	userID := ""
	if uid, exists := c.Get("user_id"); exists {
		if u, ok := uid.(string); ok {
			userID = u
		}
	}

	adminLevel := ""
	if level, exists := c.Get("admin_level"); exists {
		if l, ok := level.(string); ok {
			adminLevel = l
		}
	}

	sessionID := ""
	if sid, exists := c.Get("session_id"); exists {
		if s, ok := sid.(string); ok {
			sessionID = s
		}
	}

	requestID := ""
	if rid, exists := c.Get("request_id"); exists {
		if r, ok := rid.(string); ok {
			requestID = r
		}
	}

	capabilities := make(map[string]interface{})
	if caps, exists := c.Get("user_capabilities"); exists {
		if c, ok := caps.(map[string]interface{}); ok {
			capabilities = c
		}
	}

	return SecurityContext{
		UserID:       userID,
		AdminLevel:   adminLevel,
		IPAddress:    c.ClientIP(),
		UserAgent:    c.Request.UserAgent(),
		SessionID:    sessionID,
		RequestID:    requestID,
		Capabilities: capabilities,
		Timestamp:    time.Now(),
	}
}

func (sg *SecurityGatewayImpl) getEventTypeFromStatus(status int) string {
	switch {
	case status == 401:
		return "AUTH_FAILURE"
	case status == 403:
		return "ACCESS_DENIED"
	case status == 429:
		return "RATE_LIMIT_EXCEEDED"
	case status >= 400 && status < 500:
		return "CLIENT_ERROR"
	case status >= 500:
		return "SERVER_ERROR"
	default:
		return "UNKNOWN_ERROR"
	}
}

func (sg *SecurityGatewayImpl) getSeverityFromStatus(status int) string {
	switch {
	case status == 401 || status == 403:
		return "HIGH"
	case status == 429:
		return "MEDIUM"
	case status >= 400 && status < 500:
		return "LOW"
	case status >= 500:
		return "HIGH"
	default:
		return "LOW"
	}
}

func (sg *SecurityGatewayImpl) logSecurityEvent(eventType, severity, userID string, c *gin.Context) {
	event := SecurityEvent{
		Type:      eventType,
		Severity:  severity,
		UserID:    userID,
		Resource:  c.Request.URL.Path,
		Action:    c.Request.Method,
		Details:   make(map[string]interface{}),
		IPAddress: c.ClientIP(),
		UserAgent: c.Request.UserAgent(),
		Timestamp: time.Now(),
		Outcome:   "ERROR",
	}

	if requestID, exists := c.Get("request_id"); exists {
		if rid, ok := requestID.(string); ok {
			event.RequestID = rid
		}
	}

	sg.auditLogger.LogSecurityEvent(event)
}

func (sg *SecurityGatewayImpl) logSecurityEventWithContext(eventType, severity, userID string, c *gin.Context, context SecurityContext) {
	event := SecurityEvent{
		Type:      eventType,
		Severity:  severity,
		UserID:    userID,
		Resource:  c.Request.URL.Path,
		Action:    c.Request.Method,
		Details:   make(map[string]interface{}),
		IPAddress: context.IPAddress,
		UserAgent: context.UserAgent,
		SessionID: context.SessionID,
		RequestID: context.RequestID,
		Timestamp: time.Now(),
		Outcome:   "ERROR",
	}

	sg.auditLogger.LogSecurityEvent(event)
}

// ValidateRequest validates an HTTP request
func (sg *SecurityGatewayImpl) ValidateRequest(req *http.Request) (*ValidationResult, error) {
	result := &ValidationResult{
		Valid:    true,
		Errors:   make([]string, 0),
		Warnings: make([]string, 0),
		Metadata: make(map[string]interface{}),
	}

	// Validate request method
	allowedMethods := []string{"GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"}
	methodValid := false
	for _, method := range allowedMethods {
		if req.Method == method {
			methodValid = true
			break
		}
	}
	if !methodValid {
		result.Valid = false
		result.Errors = append(result.Errors, fmt.Sprintf("Invalid HTTP method: %s", req.Method))
	}

	// Validate content type for POST/PUT requests
	if req.Method == "POST" || req.Method == "PUT" || req.Method == "PATCH" {
		contentType := req.Header.Get("Content-Type")
		if contentType == "" {
			result.Warnings = append(result.Warnings, "Missing Content-Type header")
		}
	}

	// Validate request size
	if req.ContentLength > 10*1024*1024 { // 10MB limit
		result.Valid = false
		result.Errors = append(result.Errors, "Request body too large")
	}

	// Check for suspicious headers
	suspiciousHeaders := []string{"X-Forwarded-For", "X-Real-IP", "X-Originating-IP"}
	for _, header := range suspiciousHeaders {
		if value := req.Header.Get(header); value != "" {
			result.Warnings = append(result.Warnings, fmt.Sprintf("Suspicious header detected: %s", header))
		}
	}

	return result, nil
}

// EnforceRateLimit enforces rate limiting for a specific user and endpoint
func (sg *SecurityGatewayImpl) EnforceRateLimit(userID string, endpoint string) error {
	clientID := "user:" + userID + ":" + endpoint

	if !sg.rateLimiter.Allow(clientID) {
		return fmt.Errorf("rate limit exceeded for user %s on endpoint %s", userID, endpoint)
	}

	return nil
}

// CheckIPWhitelist checks if an IP is whitelisted
func (sg *SecurityGatewayImpl) CheckIPWhitelist(ip string, context SecurityContext) (bool, error) {
	// Check static whitelist
	if whitelisted, exists := sg.ipWhitelist[ip]; exists {
		return whitelisted, nil
	}

	// Check dynamic whitelist based on context
	// This could include checking database, external services, etc.

	return false, nil
}

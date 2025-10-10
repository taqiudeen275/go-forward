package auth

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

// APISecurityMiddleware provides middleware for API security enforcement
type APISecurityMiddleware struct {
	enforcer     APISecurityEnforcer
	authService  AuthenticationCore
	rbacEngine   RBACEngine
	auditService AuditService
}

// NewAPISecurityMiddleware creates a new API security middleware
func NewAPISecurityMiddleware(enforcer APISecurityEnforcer, authService AuthenticationCore, rbacEngine RBACEngine, auditService AuditService) *APISecurityMiddleware {
	return &APISecurityMiddleware{
		enforcer:     enforcer,
		authService:  authService,
		rbacEngine:   rbacEngine,
		auditService: auditService,
	}
}

// TableSecurityMiddleware returns middleware that enforces table-level security
func (m *APISecurityMiddleware) TableSecurityMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Extract table and schema from request path or headers
		tableName := c.Param("table")
		schemaName := c.GetHeader("X-Schema-Name")
		if schemaName == "" {
			schemaName = "public"
		}

		// Skip security for non-table endpoints
		if tableName == "" {
			c.Next()
			return
		}

		// Build security context
		userContext, err := m.buildSecurityContext(c)
		if err != nil {
			m.handleSecurityError(c, "Failed to build security context", err, http.StatusInternalServerError)
			return
		}

		// Validate request
		decision, err := m.enforcer.ValidateRequest(tableName, schemaName, c.Request.Method, userContext)
		if err != nil {
			m.handleSecurityError(c, "Security validation failed", err, http.StatusInternalServerError)
			return
		}

		// Handle security decision
		if !decision.Allowed {
			m.handleSecurityDenied(c, decision)
			return
		}

		// Handle MFA requirement
		if decision.RequiresMFA {
			c.Header("X-MFA-Required", "true")
			if c.Request.Method != "GET" {
				m.handleMFARequired(c, decision)
				return
			}
		}

		// Handle rate limiting
		if decision.RateLimited {
			m.handleRateLimited(c, decision)
			return
		}

		// Store security context and restrictions for downstream handlers
		c.Set("security_context", userContext)
		c.Set("security_decision", decision)
		c.Set("table_name", tableName)
		c.Set("schema_name", schemaName)

		// Add security warnings to response headers
		if len(decision.Warnings) > 0 {
			warningsJSON, _ := json.Marshal(decision.Warnings)
			c.Header("X-Security-Warnings", string(warningsJSON))
		}

		c.Next()
	}
}

// RequestValidationMiddleware validates request data against field permissions
func (m *APISecurityMiddleware) RequestValidationMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Only validate for write operations
		if c.Request.Method == "GET" || c.Request.Method == "HEAD" || c.Request.Method == "OPTIONS" {
			c.Next()
			return
		}

		tableName, exists := c.Get("table_name")
		if !exists {
			c.Next()
			return
		}

		schemaName, _ := c.Get("schema_name")
		userContext, _ := c.Get("security_context")

		// Parse request body
		var requestData map[string]interface{}
		if err := c.ShouldBindJSON(&requestData); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "Invalid JSON in request body",
				"code":  "INVALID_JSON",
			})
			c.Abort()
			return
		}

		// Validate writable fields
		err := m.enforcer.ValidateWritableFields(
			tableName.(string),
			schemaName.(string),
			requestData,
			userContext.(*APISecurityContext),
		)
		if err != nil {
			c.JSON(http.StatusForbidden, gin.H{
				"error": err.Error(),
				"code":  "FIELD_WRITE_DENIED",
			})
			c.Abort()
			return
		}

		// Store validated data back to context
		c.Set("validated_data", requestData)
		c.Next()
	}
}

// ResponseFilteringMiddleware filters response data based on field permissions
func (m *APISecurityMiddleware) ResponseFilteringMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Next()

		// Only filter for successful responses
		if c.Writer.Status() >= 400 {
			return
		}

		_, exists := c.Get("table_name")
		if !exists {
			return
		}

		// This is a simplified implementation
		// In a real scenario, you would intercept the response body and filter it
		// For now, we'll add headers to indicate filtering is active
		decision, exists := c.Get("security_decision")
		if exists {
			secDecision := decision.(*SecurityDecision)
			if restrictions, ok := secDecision.Restrictions["readable_fields"]; ok {
				if fields, ok := restrictions.([]string); ok && len(fields) > 0 {
					c.Header("X-Filtered-Fields", "true")
					fieldsJSON, _ := json.Marshal(fields)
					c.Header("X-Readable-Fields", string(fieldsJSON))
				}
			}
			if restrictions, ok := secDecision.Restrictions["hidden_fields"]; ok {
				if fields, ok := restrictions.([]string); ok && len(fields) > 0 {
					hiddenFieldsJSON, _ := json.Marshal(fields)
					c.Header("X-Hidden-Fields", string(hiddenFieldsJSON))
				}
			}
		}
	}
}

// OwnershipValidationMiddleware validates ownership for resource access
func (m *APISecurityMiddleware) OwnershipValidationMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		tableName, exists := c.Get("table_name")
		if !exists {
			c.Next()
			return
		}

		schemaName, _ := c.Get("schema_name")
		userContext, _ := c.Get("security_context")
		resourceID := c.Param("id")

		if resourceID == "" {
			c.Next()
			return
		}

		// Validate ownership
		err := m.enforcer.ValidateOwnership(
			tableName.(string),
			schemaName.(string),
			resourceID,
			userContext.(*APISecurityContext),
		)
		if err != nil {
			c.JSON(http.StatusForbidden, gin.H{
				"error": err.Error(),
				"code":  "OWNERSHIP_DENIED",
			})
			c.Abort()
			return
		}

		c.Next()
	}
}

// AuditLoggingMiddleware logs API access for audit purposes
func (m *APISecurityMiddleware) AuditLoggingMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Capture request start time
		startTime := c.GetTime("start_time")
		if startTime.IsZero() {
			c.Set("start_time", c.Request.Context().Value("start_time"))
		}

		c.Next()

		// Log after request completion
		tableName, exists := c.Get("table_name")
		if !exists {
			return
		}

		schemaName, _ := c.Get("schema_name")
		userContext, _ := c.Get("security_context")
		decision, _ := c.Get("security_decision")

		if userContext != nil {
			ctx := userContext.(*SecurityContext)
			var decisionData map[string]interface{}
			if decision != nil {
				decisionData = map[string]interface{}{
					"allowed":      decision.(*SecurityDecision).Allowed,
					"reason":       decision.(*SecurityDecision).Reason,
					"rate_limited": decision.(*SecurityDecision).RateLimited,
					"requires_mfa": decision.(*SecurityDecision).RequiresMFA,
				}
			}

			m.auditService.LogAdminAction(
				ctx.UserID,
				fmt.Sprintf("API_%s", c.Request.Method),
				fmt.Sprintf("%s.%s", schemaName, tableName),
				map[string]interface{}{
					"path":              c.Request.URL.Path,
					"method":            c.Request.Method,
					"status_code":       c.Writer.Status(),
					"ip_address":        ctx.IPAddress,
					"user_agent":        ctx.UserAgent,
					"security_decision": decisionData,
					"request_id":        ctx.RequestID,
				},
			)
		}
	}
}

// buildSecurityContext builds a security context from the request
func (m *APISecurityMiddleware) buildSecurityContext(c *gin.Context) (*APISecurityContext, error) {
	context := &APISecurityContext{
		IPAddress: c.ClientIP(),
		UserAgent: c.GetHeader("User-Agent"),
		RequestID: c.GetHeader("X-Request-ID"),
		Timestamp: time.Now(),
		Metadata:  make(map[string]string),
	}

	// Generate request ID if not provided
	if context.RequestID == "" {
		context.RequestID = generateRequestID()
	}

	// Extract user information from JWT token or session
	token := extractTokenFromRequest(c)
	if token != "" {
		// Validate token and extract user info
		userInfo, err := m.authService.ValidateToken(token)
		if err == nil && userInfo != nil {
			context.UserID = userInfo.UserID
			context.SessionID = userInfo.SessionID

			// Get user roles and capabilities
			ctx := c.Request.Context()
			roles, err := m.rbacEngine.GetUserRoles(ctx, userInfo.UserID)
			if err == nil {
				context.UserRoles = make([]string, len(roles))
				for i, role := range roles {
					context.UserRoles[i] = role.Name
				}

				// Determine admin level
				context.AdminLevel = m.determineAdminLevel(roles)
			}

			// Get user capabilities
			capabilities, err := m.rbacEngine.GetUserCapabilities(ctx, userInfo.UserID)
			if err == nil {
				context.Capabilities = *capabilities
			}

			// Check MFA status
			context.MFAVerified = userInfo.MFAVerified
		}
	}

	return context, nil
}

// handleSecurityError handles security-related errors
func (m *APISecurityMiddleware) handleSecurityError(c *gin.Context, message string, err error, statusCode int) {
	c.JSON(statusCode, gin.H{
		"error":   message,
		"code":    "SECURITY_ERROR",
		"details": err.Error(),
	})
	c.Abort()
}

// handleSecurityDenied handles access denied scenarios
func (m *APISecurityMiddleware) handleSecurityDenied(c *gin.Context, decision *SecurityDecision) {
	response := gin.H{
		"error": decision.Reason,
		"code":  "ACCESS_DENIED",
	}

	if len(decision.RequiredRoles) > 0 {
		response["required_roles"] = decision.RequiredRoles
	}

	statusCode := http.StatusForbidden
	if decision.Reason == "Authentication required" {
		statusCode = http.StatusUnauthorized
	}

	c.JSON(statusCode, response)
	c.Abort()
}

// handleMFARequired handles MFA requirement scenarios
func (m *APISecurityMiddleware) handleMFARequired(c *gin.Context, decision *SecurityDecision) {
	c.JSON(http.StatusForbidden, gin.H{
		"error":         "Multi-factor authentication required",
		"code":          "MFA_REQUIRED",
		"mfa_setup_url": "/auth/mfa/setup",
	})
	c.Abort()
}

// handleRateLimited handles rate limiting scenarios
func (m *APISecurityMiddleware) handleRateLimited(c *gin.Context, decision *SecurityDecision) {
	c.Header("X-RateLimit-Exceeded", "true")
	c.Header("Retry-After", "60") // Suggest retry after 60 seconds

	c.JSON(http.StatusTooManyRequests, gin.H{
		"error":       decision.Reason,
		"code":        "RATE_LIMIT_EXCEEDED",
		"retry_after": 60,
	})
	c.Abort()
}

// extractTokenFromRequest extracts JWT token from request
func extractTokenFromRequest(c *gin.Context) string {
	// Try Authorization header first
	authHeader := c.GetHeader("Authorization")
	if authHeader != "" && strings.HasPrefix(authHeader, "Bearer ") {
		return strings.TrimPrefix(authHeader, "Bearer ")
	}

	// Try cookie
	cookie, err := c.Cookie("auth_token")
	if err == nil && cookie != "" {
		return cookie
	}

	// Try query parameter (less secure, for development only)
	return c.Query("token")
}

// generateRequestID generates a unique request ID
func generateRequestID() string {
	// This is a simplified implementation
	// In production, use a proper UUID library
	return fmt.Sprintf("req_%d", time.Now().UnixNano())
}

// determineAdminLevel determines the admin level from user roles
func (m *APISecurityMiddleware) determineAdminLevel(roles []*AdminRole) AdminLevel {
	minLevel := AdminLevel("none") // Start with no admin level

	for _, role := range roles {
		if role.Level < minLevel {
			minLevel = role.Level
		}
	}

	if minLevel == AdminLevel("none") {
		return AdminLevel("none") // No admin role
	}

	return minLevel
}

// Note: UserInfo is defined in admin_auth_core.go

// TokenValidator interface for token validation
type TokenValidator interface {
	ValidateToken(token string) (*UserInfo, error)
}

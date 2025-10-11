package auth

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/taqiudeen275/go-foward/internal/config"
	"github.com/taqiudeen275/go-foward/pkg/errors"
)

// ContextKey represents keys used in request context
type ContextKey string

const (
	UserContextKey    ContextKey = "user"
	SessionContextKey ContextKey = "session"
	ClaimsContextKey  ContextKey = "claims"
)

// AuthMiddleware provides authentication middleware
type AuthMiddleware struct {
	authService AuthService
	config      *config.Config
}

// NewAuthMiddleware creates a new authentication middleware
func NewAuthMiddleware(authService AuthService, cfg *config.Config) *AuthMiddleware {
	return &AuthMiddleware{
		authService: authService,
		config:      cfg,
	}
}

// RequireAuth middleware that requires valid authentication
func (m *AuthMiddleware) RequireAuth() gin.HandlerFunc {
	return func(c *gin.Context) {
		user, claims, err := m.authenticateRequest(c)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error":   "authentication required",
				"message": err.Error(),
			})
			c.Abort()
			return
		}

		// Set user and claims in context
		c.Set(string(UserContextKey), user)
		c.Set(string(ClaimsContextKey), claims)

		// Add user context for downstream services
		ctx := context.WithValue(c.Request.Context(), UserContextKey, user)
		ctx = context.WithValue(ctx, ClaimsContextKey, claims)
		c.Request = c.Request.WithContext(ctx)

		c.Next()
	}
}

// RequireAdmin middleware that requires admin privileges
func (m *AuthMiddleware) RequireAdmin() gin.HandlerFunc {
	return func(c *gin.Context) {
		user, claims, err := m.authenticateRequest(c)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error":   "authentication required",
				"message": err.Error(),
			})
			c.Abort()
			return
		}

		if !user.IsAdmin() {
			c.JSON(http.StatusForbidden, gin.H{
				"error":   "admin privileges required",
				"message": "insufficient permissions",
			})
			c.Abort()
			return
		}

		// Set user and claims in context
		c.Set(string(UserContextKey), user)
		c.Set(string(ClaimsContextKey), claims)

		// Add user context for downstream services
		ctx := context.WithValue(c.Request.Context(), UserContextKey, user)
		ctx = context.WithValue(ctx, ClaimsContextKey, claims)
		c.Request = c.Request.WithContext(ctx)

		c.Next()
	}
}

// RequireAdminLevel middleware that requires specific admin level or higher
func (m *AuthMiddleware) RequireAdminLevel(requiredLevel AdminLevel) gin.HandlerFunc {
	return func(c *gin.Context) {
		user, claims, err := m.authenticateRequest(c)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error":   "authentication required",
				"message": err.Error(),
			})
			c.Abort()
			return
		}

		if !user.IsAdmin() || !user.AdminLevel.IsHigherOrEqual(requiredLevel) {
			c.JSON(http.StatusForbidden, gin.H{
				"error":   "insufficient admin level",
				"message": "higher admin privileges required",
			})
			c.Abort()
			return
		}

		// Set user and claims in context
		c.Set(string(UserContextKey), user)
		c.Set(string(ClaimsContextKey), claims)

		// Add user context for downstream services
		ctx := context.WithValue(c.Request.Context(), UserContextKey, user)
		ctx = context.WithValue(ctx, ClaimsContextKey, claims)
		c.Request = c.Request.WithContext(ctx)

		c.Next()
	}
}

// RequireCapability middleware that requires specific capability
func (m *AuthMiddleware) RequireCapability(capability string) gin.HandlerFunc {
	return func(c *gin.Context) {
		user, claims, err := m.authenticateRequest(c)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error":   "authentication required",
				"message": err.Error(),
			})
			c.Abort()
			return
		}

		if !user.HasCapability(capability) {
			c.JSON(http.StatusForbidden, gin.H{
				"error":   "insufficient permissions",
				"message": "required capability not found",
			})
			c.Abort()
			return
		}

		// Set user and claims in context
		c.Set(string(UserContextKey), user)
		c.Set(string(ClaimsContextKey), claims)

		// Add user context for downstream services
		ctx := context.WithValue(c.Request.Context(), UserContextKey, user)
		ctx = context.WithValue(ctx, ClaimsContextKey, claims)
		c.Request = c.Request.WithContext(ctx)

		c.Next()
	}
}

// RequireAdminSession middleware for admin dashboard routes
func (m *AuthMiddleware) RequireAdminSession() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Try to get session token from cookie or header
		sessionToken := m.getSessionToken(c)
		if sessionToken == "" {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error":   "admin session required",
				"message": "no valid session found",
			})
			c.Abort()
			return
		}

		// Validate admin session
		session, user, err := m.authService.ValidateSession(c.Request.Context(), sessionToken)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error":   "invalid session",
				"message": err.Error(),
			})
			c.Abort()
			return
		}

		// Set user and session in context
		c.Set(string(UserContextKey), user)
		c.Set(string(SessionContextKey), session)

		// Add context for downstream services
		ctx := context.WithValue(c.Request.Context(), UserContextKey, user)
		ctx = context.WithValue(ctx, SessionContextKey, session)
		c.Request = c.Request.WithContext(ctx)

		c.Next()
	}
}

// OptionalAuth middleware that sets user context if authenticated but doesn't require it
func (m *AuthMiddleware) OptionalAuth() gin.HandlerFunc {
	return func(c *gin.Context) {
		user, claims, err := m.authenticateRequest(c)
		if err == nil && user != nil {
			// Set user and claims in context if authentication succeeded
			c.Set(string(UserContextKey), user)
			c.Set(string(ClaimsContextKey), claims)

			// Add user context for downstream services
			ctx := context.WithValue(c.Request.Context(), UserContextKey, user)
			ctx = context.WithValue(ctx, ClaimsContextKey, claims)
			c.Request = c.Request.WithContext(ctx)
		}

		c.Next()
	}
}

// RateLimitMiddleware provides rate limiting functionality
func (m *AuthMiddleware) RateLimitMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// TODO: Implement rate limiting logic
		// This will be implemented in the security gateway task
		c.Next()
	}
}

// AuditMiddleware logs requests for audit purposes
func (m *AuthMiddleware) AuditMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()

		// Process request
		c.Next()

		// Log audit information
		duration := time.Since(start)

		// Get user from context if available
		var userID *uuid.UUID
		if user := GetUserFromContext(c); user != nil {
			userID = &user.ID
		}

		// Create audit log entry
		// TODO: This should use the audit service when implemented
		_ = userID
		_ = duration

		// For now, we'll skip the actual logging to avoid dependency issues
		// The audit logging will be properly implemented in the audit system task
	}
}

// SecurityHeadersMiddleware adds security headers
func (m *AuthMiddleware) SecurityHeadersMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		if m.config.Security.EnableSecurityHeaders {
			// Add security headers
			c.Header("X-Content-Type-Options", "nosniff")
			c.Header("X-Frame-Options", "DENY")
			c.Header("X-XSS-Protection", "1; mode=block")
			c.Header("Referrer-Policy", "strict-origin-when-cross-origin")

			if m.config.Security.ContentSecurityPolicy != "" {
				c.Header("Content-Security-Policy", m.config.Security.ContentSecurityPolicy)
			}

			// Add HSTS header for HTTPS
			if c.Request.TLS != nil {
				c.Header("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
			}
		}

		c.Next()
	}
}

// CORSMiddleware handles Cross-Origin Resource Sharing
func (m *AuthMiddleware) CORSMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		if m.config.Security.EnableCORS {
			origin := c.Request.Header.Get("Origin")

			// Check if origin is allowed
			allowed := false
			for _, allowedOrigin := range m.config.Security.AllowedOrigins {
				if allowedOrigin == "*" || allowedOrigin == origin {
					allowed = true
					break
				}
			}

			if allowed {
				c.Header("Access-Control-Allow-Origin", origin)
				c.Header("Access-Control-Allow-Credentials", "true")
				c.Header("Access-Control-Allow-Headers", "Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization, accept, origin, Cache-Control, X-Requested-With")
				c.Header("Access-Control-Allow-Methods", "POST, OPTIONS, GET, PUT, DELETE, PATCH")
			}

			if c.Request.Method == "OPTIONS" {
				c.AbortWithStatus(http.StatusNoContent)
				return
			}
		}

		c.Next()
	}
}

// Helper methods

// authenticateRequest authenticates a request using JWT token or session
func (m *AuthMiddleware) authenticateRequest(c *gin.Context) (*UnifiedUser, *JWTClaims, error) {
	// Try JWT token first (from Authorization header or cookie)
	token := m.getJWTToken(c)
	if token != "" {
		claims, err := m.authService.ValidateToken(c.Request.Context(), token)
		if err != nil {
			return nil, nil, err
		}

		// Get user from claims
		user, err := m.getUserFromClaims(c.Request.Context(), claims)
		if err != nil {
			return nil, nil, err
		}

		return user, claims, nil
	}

	// Try admin session token
	sessionToken := m.getSessionToken(c)
	if sessionToken != "" {
		session, user, err := m.authService.ValidateSession(c.Request.Context(), sessionToken)
		if err != nil {
			return nil, nil, err
		}

		// Create claims from session
		claims := &JWTClaims{
			UserID:     user.ID,
			AdminLevel: user.AdminLevel,
			SessionID:  &session.ID,
		}

		if user.Email != nil {
			claims.Email = *user.Email
		}

		return user, claims, nil
	}

	return nil, nil, errors.NewAuthError("no valid authentication found")
}

// getJWTToken extracts JWT token from Authorization header or cookie
func (m *AuthMiddleware) getJWTToken(c *gin.Context) string {
	// Try Authorization header first
	authHeader := c.GetHeader("Authorization")
	if authHeader != "" {
		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) == 2 && strings.ToLower(parts[0]) == "bearer" {
			return parts[1]
		}
	}

	// Try cookie if cookie auth is enabled
	if m.config.Auth.EnableCookieAuth {
		if cookie, err := c.Cookie("access_token"); err == nil {
			return cookie
		}
	}

	return ""
}

// getSessionToken extracts session token from cookie or header
func (m *AuthMiddleware) getSessionToken(c *gin.Context) string {
	// Try session cookie first
	if cookie, err := c.Cookie("admin_session"); err == nil {
		return cookie
	}

	// Try X-Session-Token header
	return c.GetHeader("X-Session-Token")
}

// getUserFromClaims retrieves user from JWT claims
func (m *AuthMiddleware) getUserFromClaims(ctx context.Context, claims *JWTClaims) (*UnifiedUser, error) {
	// For now, we'll need to get the repository from the auth service
	// In a real implementation, we might want to cache user data or pass the repository
	// This is a simplified approach for the current implementation

	// TODO: Implement proper user retrieval from claims
	// This would typically involve getting the user from the database using the UserID from claims
	// For now, we'll return an error indicating this needs to be implemented with proper dependency injection

	return nil, errors.NewAuthError("user retrieval from claims not implemented - requires repository access")
}

// Context helper functions

// GetUserFromContext retrieves the authenticated user from gin context
func GetUserFromContext(c *gin.Context) *UnifiedUser {
	if user, exists := c.Get(string(UserContextKey)); exists {
		if u, ok := user.(*UnifiedUser); ok {
			return u
		}
	}
	return nil
}

// GetUserFromRequestContext retrieves the authenticated user from request context
func GetUserFromRequestContext(ctx context.Context) *UnifiedUser {
	if user := ctx.Value(UserContextKey); user != nil {
		if u, ok := user.(*UnifiedUser); ok {
			return u
		}
	}
	return nil
}

// GetSessionFromContext retrieves the admin session from gin context
func GetSessionFromContext(c *gin.Context) *AdminSession {
	if session, exists := c.Get(string(SessionContextKey)); exists {
		if s, ok := session.(*AdminSession); ok {
			return s
		}
	}
	return nil
}

// GetClaimsFromContext retrieves JWT claims from gin context
func GetClaimsFromContext(c *gin.Context) *JWTClaims {
	if claims, exists := c.Get(string(ClaimsContextKey)); exists {
		if cl, ok := claims.(*JWTClaims); ok {
			return cl
		}
	}
	return nil
}

// RequireUserID middleware that ensures the authenticated user matches the requested user ID
func (m *AuthMiddleware) RequireUserID() gin.HandlerFunc {
	return func(c *gin.Context) {
		user := GetUserFromContext(c)
		if user == nil {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error":   "authentication required",
				"message": "user not found in context",
			})
			c.Abort()
			return
		}

		// Get user ID from URL parameter
		userIDParam := c.Param("userID")
		if userIDParam == "" {
			userIDParam = c.Param("id")
		}

		if userIDParam == "" {
			c.JSON(http.StatusBadRequest, gin.H{
				"error":   "invalid request",
				"message": "user ID parameter required",
			})
			c.Abort()
			return
		}

		requestedUserID, err := uuid.Parse(userIDParam)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"error":   "invalid user ID",
				"message": "user ID must be a valid UUID",
			})
			c.Abort()
			return
		}

		// Check if user is accessing their own resource or is an admin
		if user.ID != requestedUserID && !user.IsAdmin() {
			c.JSON(http.StatusForbidden, gin.H{
				"error":   "access denied",
				"message": "cannot access another user's resources",
			})
			c.Abort()
			return
		}

		c.Next()
	}
}

// RequireTableAccess middleware that checks if user can access a specific table
func (m *AuthMiddleware) RequireTableAccess(tableName string) gin.HandlerFunc {
	return func(c *gin.Context) {
		user := GetUserFromContext(c)
		if user == nil {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error":   "authentication required",
				"message": "user not found in context",
			})
			c.Abort()
			return
		}

		if !user.CanAccessTable(tableName) {
			c.JSON(http.StatusForbidden, gin.H{
				"error":   "table access denied",
				"message": "insufficient permissions for this table",
			})
			c.Abort()
			return
		}

		c.Next()
	}
}

// RequireVerification middleware that requires email or phone verification
func (m *AuthMiddleware) RequireVerification() gin.HandlerFunc {
	return func(c *gin.Context) {
		user := GetUserFromContext(c)
		if user == nil {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error":   "authentication required",
				"message": "user not found in context",
			})
			c.Abort()
			return
		}

		if !user.EmailVerified && !user.PhoneVerified {
			c.JSON(http.StatusForbidden, gin.H{
				"error":   "verification required",
				"message": "email or phone verification required",
			})
			c.Abort()
			return
		}

		c.Next()
	}
}

// MiddlewareConfig represents configuration for middleware
type MiddlewareConfig struct {
	RequiredLevel       *AdminLevel `json:"required_level,omitempty"`
	RequiredCapability  string      `json:"required_capability,omitempty"`
	RequireVerification bool        `json:"require_verification"`
	AllowSelfAccess     bool        `json:"allow_self_access"`
	TableName           string      `json:"table_name,omitempty"`
}

// DynamicAuthMiddleware creates middleware based on configuration
func (m *AuthMiddleware) DynamicAuthMiddleware(config MiddlewareConfig) gin.HandlerFunc {
	return func(c *gin.Context) {
		user, claims, err := m.authenticateRequest(c)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error":   "authentication required",
				"message": err.Error(),
			})
			c.Abort()
			return
		}

		// Check admin level requirement
		if config.RequiredLevel != nil {
			if !user.IsAdmin() || !user.AdminLevel.IsHigherOrEqual(*config.RequiredLevel) {
				c.JSON(http.StatusForbidden, gin.H{
					"error":   "insufficient admin level",
					"message": "higher admin privileges required",
				})
				c.Abort()
				return
			}
		}

		// Check capability requirement
		if config.RequiredCapability != "" {
			if !user.HasCapability(config.RequiredCapability) {
				c.JSON(http.StatusForbidden, gin.H{
					"error":   "insufficient permissions",
					"message": "required capability not found",
				})
				c.Abort()
				return
			}
		}

		// Check verification requirement
		if config.RequireVerification {
			if !user.EmailVerified && !user.PhoneVerified {
				c.JSON(http.StatusForbidden, gin.H{
					"error":   "verification required",
					"message": "email or phone verification required",
				})
				c.Abort()
				return
			}
		}

		// Check table access requirement
		if config.TableName != "" {
			if !user.CanAccessTable(config.TableName) {
				c.JSON(http.StatusForbidden, gin.H{
					"error":   "table access denied",
					"message": "insufficient permissions for this table",
				})
				c.Abort()
				return
			}
		}

		// Set user and claims in context
		c.Set(string(UserContextKey), user)
		c.Set(string(ClaimsContextKey), claims)

		// Add user context for downstream services
		ctx := context.WithValue(c.Request.Context(), UserContextKey, user)
		ctx = context.WithValue(ctx, ClaimsContextKey, claims)
		c.Request = c.Request.WithContext(ctx)

		c.Next()
	}
}

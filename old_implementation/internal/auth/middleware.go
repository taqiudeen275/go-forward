package auth

import (
	"context"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

// ContextKey represents a key for storing values in context
type ContextKey string

const (
	// UserContextKey is the key for storing user in context
	UserContextKey ContextKey = "user"
	// ClaimsContextKey is the key for storing JWT claims in context
	ClaimsContextKey ContextKey = "claims"
)

// Middleware handles JWT authentication middleware
type Middleware struct {
	jwtManager *JWTManager
	service    *Service
}

// NewMiddleware creates a new authentication middleware
func NewMiddleware(jwtManager *JWTManager, service *Service) *Middleware {
	return &Middleware{
		jwtManager: jwtManager,
		service:    service,
	}
}

// RequireAuth is a middleware that requires valid JWT authentication
func (m *Middleware) RequireAuth() gin.HandlerFunc {
	return func(c *gin.Context) {
		token := m.extractToken(c)
		if token == "" {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "Authorization token required",
				"code":  "MISSING_TOKEN",
			})
			c.Abort()
			return
		}

		claims, err := m.jwtManager.ValidateAccessToken(token)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "Invalid or expired token",
				"code":  "INVALID_TOKEN",
			})
			c.Abort()
			return
		}

		// Get user from database to ensure they still exist
		user, err := m.service.GetUserByID(c.Request.Context(), claims.UserID)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "User not found",
				"code":  "USER_NOT_FOUND",
			})
			c.Abort()
			return
		}

		// Store user and claims in context
		c.Set(string(UserContextKey), user)
		c.Set(string(ClaimsContextKey), claims)

		c.Next()
	}
}

// OptionalAuth is a middleware that optionally validates JWT authentication
func (m *Middleware) OptionalAuth() gin.HandlerFunc {
	return func(c *gin.Context) {
		token := m.extractToken(c)
		if token == "" {
			c.Next()
			return
		}

		claims, err := m.jwtManager.ValidateAccessToken(token)
		if err != nil {
			// Don't abort for optional auth, just continue without user context
			c.Next()
			return
		}

		// Get user from database
		user, err := m.service.GetUserByID(c.Request.Context(), claims.UserID)
		if err != nil {
			// Don't abort for optional auth, just continue without user context
			c.Next()
			return
		}

		// Store user and claims in context
		c.Set(string(UserContextKey), user)
		c.Set(string(ClaimsContextKey), claims)

		c.Next()
	}
}

// RequireVerifiedEmail is a middleware that requires the user to have a verified email
func (m *Middleware) RequireVerifiedEmail() gin.HandlerFunc {
	return func(c *gin.Context) {
		user := m.GetUserFromContext(c)
		if user == nil {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "Authentication required",
				"code":  "AUTH_REQUIRED",
			})
			c.Abort()
			return
		}

		if !user.EmailVerified {
			c.JSON(http.StatusForbidden, gin.H{
				"error": "Email verification required",
				"code":  "EMAIL_NOT_VERIFIED",
			})
			c.Abort()
			return
		}

		c.Next()
	}
}

// RequireVerifiedPhone is a middleware that requires the user to have a verified phone
func (m *Middleware) RequireVerifiedPhone() gin.HandlerFunc {
	return func(c *gin.Context) {
		user := m.GetUserFromContext(c)
		if user == nil {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "Authentication required",
				"code":  "AUTH_REQUIRED",
			})
			c.Abort()
			return
		}

		if !user.PhoneVerified {
			c.JSON(http.StatusForbidden, gin.H{
				"error": "Phone verification required",
				"code":  "PHONE_NOT_VERIFIED",
			})
			c.Abort()
			return
		}

		c.Next()
	}
}

// RequireRole is a middleware that requires the user to have a specific role
func (m *Middleware) RequireRole(role string) gin.HandlerFunc {
	return func(c *gin.Context) {
		user := m.GetUserFromContext(c)
		if user == nil {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "Authentication required",
				"code":  "AUTH_REQUIRED",
			})
			c.Abort()
			return
		}

		userRole, exists := user.Metadata["role"]
		if !exists {
			c.JSON(http.StatusForbidden, gin.H{
				"error": "Insufficient permissions",
				"code":  "INSUFFICIENT_PERMISSIONS",
			})
			c.Abort()
			return
		}

		if userRole != role {
			c.JSON(http.StatusForbidden, gin.H{
				"error": "Insufficient permissions",
				"code":  "INSUFFICIENT_PERMISSIONS",
			})
			c.Abort()
			return
		}

		c.Next()
	}
}

// RequireAnyRole is a middleware that requires the user to have any of the specified roles
func (m *Middleware) RequireAnyRole(roles ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		user := m.GetUserFromContext(c)
		if user == nil {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "Authentication required",
				"code":  "AUTH_REQUIRED",
			})
			c.Abort()
			return
		}

		userRole, exists := user.Metadata["role"]
		if !exists {
			c.JSON(http.StatusForbidden, gin.H{
				"error": "Insufficient permissions",
				"code":  "INSUFFICIENT_PERMISSIONS",
			})
			c.Abort()
			return
		}

		userRoleStr, ok := userRole.(string)
		if !ok {
			c.JSON(http.StatusForbidden, gin.H{
				"error": "Invalid role format",
				"code":  "INVALID_ROLE",
			})
			c.Abort()
			return
		}

		for _, role := range roles {
			if userRoleStr == role {
				c.Next()
				return
			}
		}

		c.JSON(http.StatusForbidden, gin.H{
			"error": "Insufficient permissions",
			"code":  "INSUFFICIENT_PERMISSIONS",
		})
		c.Abort()
	}
}

// extractToken extracts JWT token from Authorization header
func (m *Middleware) extractToken(c *gin.Context) string {
	authHeader := c.GetHeader("Authorization")
	if authHeader == "" {
		return ""
	}

	// Check for Bearer token format
	parts := strings.SplitN(authHeader, " ", 2)
	if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
		return ""
	}

	return parts[1]
}

// GetUserFromContext retrieves the authenticated user from the Gin context
func (m *Middleware) GetUserFromContext(c *gin.Context) *User {
	value, exists := c.Get(string(UserContextKey))
	if !exists {
		return nil
	}

	user, ok := value.(*User)
	if !ok {
		return nil
	}

	return user
}

// GetClaimsFromContext retrieves the JWT claims from the Gin context
func (m *Middleware) GetClaimsFromContext(c *gin.Context) *Claims {
	value, exists := c.Get(string(ClaimsContextKey))
	if !exists {
		return nil
	}

	claims, ok := value.(*Claims)
	if !ok {
		return nil
	}

	return claims
}

// GetUserFromStandardContext retrieves the authenticated user from standard context
func GetUserFromStandardContext(ctx context.Context) *User {
	value := ctx.Value(UserContextKey)
	if value == nil {
		return nil
	}

	user, ok := value.(*User)
	if !ok {
		return nil
	}

	return user
}

// GetClaimsFromStandardContext retrieves the JWT claims from standard context
func GetClaimsFromStandardContext(ctx context.Context) *Claims {
	value := ctx.Value(ClaimsContextKey)
	if value == nil {
		return nil
	}

	claims, ok := value.(*Claims)
	if !ok {
		return nil
	}

	return claims
}

// WithUser adds a user to the standard context
func WithUser(ctx context.Context, user *User) context.Context {
	return context.WithValue(ctx, UserContextKey, user)
}

// WithClaims adds JWT claims to the standard context
func WithClaims(ctx context.Context, claims *Claims) context.Context {
	return context.WithValue(ctx, ClaimsContextKey, claims)
}

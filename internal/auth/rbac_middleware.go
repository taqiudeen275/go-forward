package auth

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/taqiudeen275/go-foward/pkg/errors"
)

// RBACMiddleware provides role-based access control middleware
type RBACMiddleware struct {
	rbac RBACService
}

// NewRBACMiddleware creates a new RBAC middleware
func NewRBACMiddleware(rbac RBACService) *RBACMiddleware {
	return &RBACMiddleware{
		rbac: rbac,
	}
}

// RequireAdmin middleware that requires admin privileges
func (m *RBACMiddleware) RequireAdmin() gin.HandlerFunc {
	return func(c *gin.Context) {
		userID, exists := c.Get("user_id")
		if !exists {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "authentication required"})
			c.Abort()
			return
		}

		uid, ok := userID.(uuid.UUID)
		if !ok {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid user ID"})
			c.Abort()
			return
		}

		// Create auth context
		authCtx, err := m.rbac.CreateAuthContext(c.Request.Context(), uid, c.ClientIP(), c.GetHeader("User-Agent"))
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create auth context"})
			c.Abort()
			return
		}

		// Validate auth context
		if err := m.rbac.ValidateAuthContext(c.Request.Context(), authCtx); err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
			c.Abort()
			return
		}

		// Check if user is admin
		if !authCtx.User.IsAdmin() {
			c.JSON(http.StatusForbidden, gin.H{"error": "admin privileges required"})
			c.Abort()
			return
		}

		// Store auth context for use in handlers
		c.Set("auth_context", authCtx)
		c.Next()
	}
}

// RequireAdminLevel middleware that requires specific admin level or higher
func (m *RBACMiddleware) RequireAdminLevel(requiredLevel AdminLevel) gin.HandlerFunc {
	return func(c *gin.Context) {
		authCtx, exists := c.Get("auth_context")
		if !exists {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "authentication context required"})
			c.Abort()
			return
		}

		ctx, ok := authCtx.(*AuthContext)
		if !ok {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "invalid auth context"})
			c.Abort()
			return
		}

		// Check admin level
		if ctx.User.AdminLevel == nil || !ctx.User.AdminLevel.IsHigherOrEqual(requiredLevel) {
			c.JSON(http.StatusForbidden, gin.H{
				"error":    "insufficient admin level",
				"required": requiredLevel,
				"current":  ctx.User.AdminLevel,
			})
			c.Abort()
			return
		}

		c.Next()
	}
}

// RequireCapability middleware that requires specific capability
func (m *RBACMiddleware) RequireCapability(capability string) gin.HandlerFunc {
	return func(c *gin.Context) {
		authCtx, exists := c.Get("auth_context")
		if !exists {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "authentication context required"})
			c.Abort()
			return
		}

		ctx, ok := authCtx.(*AuthContext)
		if !ok {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "invalid auth context"})
			c.Abort()
			return
		}

		// Check capability
		hasCapability, err := m.rbac.HasCapability(c.Request.Context(), ctx.UserID, capability)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to check capability"})
			c.Abort()
			return
		}

		if !hasCapability {
			c.JSON(http.StatusForbidden, gin.H{
				"error":      "missing required capability",
				"capability": capability,
			})
			c.Abort()
			return
		}

		c.Next()
	}
}

// RequireAction middleware that requires permission for specific action
func (m *RBACMiddleware) RequireAction(action string, resource string) gin.HandlerFunc {
	return func(c *gin.Context) {
		authCtx, exists := c.Get("auth_context")
		if !exists {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "authentication context required"})
			c.Abort()
			return
		}

		ctx, ok := authCtx.(*AuthContext)
		if !ok {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "invalid auth context"})
			c.Abort()
			return
		}

		// Get resource ID from URL parameters if available
		var resourceID *string
		if id := c.Param("id"); id != "" {
			resourceID = &id
		}

		// Check action permission
		allowed, err := m.rbac.CanPerformAction(c.Request.Context(), ctx.UserID, action, resource, resourceID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to check permissions"})
			c.Abort()
			return
		}

		if !allowed {
			c.JSON(http.StatusForbidden, gin.H{
				"error":    "insufficient permissions",
				"action":   action,
				"resource": resource,
			})
			c.Abort()
			return
		}

		c.Next()
	}
}

// RequireTableAccess middleware that requires access to specific table
func (m *RBACMiddleware) RequireTableAccess(tableName string, operation TableOperation) gin.HandlerFunc {
	return func(c *gin.Context) {
		authCtx, exists := c.Get("auth_context")
		if !exists {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "authentication context required"})
			c.Abort()
			return
		}

		ctx, ok := authCtx.(*AuthContext)
		if !ok {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "invalid auth context"})
			c.Abort()
			return
		}

		// Check table access
		allowed, err := m.rbac.CanAccessTable(c.Request.Context(), ctx.UserID, tableName, operation)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to check table access"})
			c.Abort()
			return
		}

		if !allowed {
			c.JSON(http.StatusForbidden, gin.H{
				"error":     "insufficient table access",
				"table":     tableName,
				"operation": operation,
			})
			c.Abort()
			return
		}

		c.Next()
	}
}

// RequireOwnership middleware that requires ownership of resource
func (m *RBACMiddleware) RequireOwnership(resourceParam string) gin.HandlerFunc {
	return func(c *gin.Context) {
		authCtx, exists := c.Get("auth_context")
		if !exists {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "authentication context required"})
			c.Abort()
			return
		}

		ctx, ok := authCtx.(*AuthContext)
		if !ok {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "invalid auth context"})
			c.Abort()
			return
		}

		// Get resource ID from parameters
		resourceID := c.Param(resourceParam)
		if resourceID == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "resource ID required"})
			c.Abort()
			return
		}

		// For user resources, check if user owns the resource or is admin
		if resourceParam == "user_id" || resourceParam == "id" {
			if resourceID != ctx.UserID.String() && !ctx.User.IsAdmin() {
				c.JSON(http.StatusForbidden, gin.H{"error": "resource ownership required"})
				c.Abort()
				return
			}
		}

		c.Next()
	}
}

// RequireSystemAdmin middleware that requires system admin privileges
func (m *RBACMiddleware) RequireSystemAdmin() gin.HandlerFunc {
	return m.RequireAdminLevel(AdminLevelSystemAdmin)
}

// RequireSuperAdmin middleware that requires super admin privileges or higher
func (m *RBACMiddleware) RequireSuperAdmin() gin.HandlerFunc {
	return m.RequireAdminLevel(AdminLevelSuperAdmin)
}

// RequireRegularAdmin middleware that requires regular admin privileges or higher
func (m *RBACMiddleware) RequireRegularAdmin() gin.HandlerFunc {
	return m.RequireAdminLevel(AdminLevelRegularAdmin)
}

// RequireModerator middleware that requires moderator privileges or higher
func (m *RBACMiddleware) RequireModerator() gin.HandlerFunc {
	return m.RequireAdminLevel(AdminLevelModerator)
}

// ConditionalAdmin middleware that applies admin check only for certain paths
func (m *RBACMiddleware) ConditionalAdmin(adminPaths []string) gin.HandlerFunc {
	return func(c *gin.Context) {
		path := c.Request.URL.Path

		// Check if current path requires admin privileges
		requiresAdmin := false
		for _, adminPath := range adminPaths {
			if strings.HasPrefix(path, adminPath) {
				requiresAdmin = true
				break
			}
		}

		if requiresAdmin {
			// Apply admin middleware
			m.RequireAdmin()(c)
		} else {
			c.Next()
		}
	}
}

// AdminDashboardMiddleware middleware specifically for admin dashboard routes
func (m *RBACMiddleware) AdminDashboardMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Admin dashboard routes are prefixed with /_/
		if strings.HasPrefix(c.Request.URL.Path, "/_/") {
			m.RequireAdmin()(c)
		} else {
			c.Next()
		}
	}
}

// Helper functions for extracting auth context

// GetAuthContext extracts auth context from gin context
func GetAuthContext(c *gin.Context) (*AuthContext, error) {
	authCtx, exists := c.Get("auth_context")
	if !exists {
		return nil, errors.NewAuthError("authentication context not found")
	}

	ctx, ok := authCtx.(*AuthContext)
	if !ok {
		return nil, errors.NewAuthError("invalid authentication context")
	}

	return ctx, nil
}

// GetCurrentUser extracts current user from gin context
func GetCurrentUser(c *gin.Context) (*UnifiedUser, error) {
	authCtx, err := GetAuthContext(c)
	if err != nil {
		return nil, err
	}

	return authCtx.User, nil
}

// GetCurrentUserID extracts current user ID from gin context
func GetCurrentUserID(c *gin.Context) (uuid.UUID, error) {
	authCtx, err := GetAuthContext(c)
	if err != nil {
		return uuid.Nil, err
	}

	return authCtx.UserID, nil
}

// IsCurrentUserAdmin checks if current user is admin
func IsCurrentUserAdmin(c *gin.Context) bool {
	user, err := GetCurrentUser(c)
	if err != nil {
		return false
	}

	return user.IsAdmin()
}

// GetCurrentUserAdminLevel gets current user's admin level
func GetCurrentUserAdminLevel(c *gin.Context) *AdminLevel {
	user, err := GetCurrentUser(c)
	if err != nil {
		return nil
	}

	return user.AdminLevel
}

// CanCurrentUserManage checks if current user can manage target user
func CanCurrentUserManage(c *gin.Context, targetUserID uuid.UUID, rbac RBACService) (bool, error) {
	authCtx, err := GetAuthContext(c)
	if err != nil {
		return false, err
	}

	return rbac.CanManageUser(c.Request.Context(), authCtx.UserID, targetUserID)
}

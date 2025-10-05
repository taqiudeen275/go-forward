package storage

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/taqiudeen275/go-foward/pkg/interfaces"
)

// PermissionHandlers provides HTTP handlers for permission management
type PermissionHandlers struct {
	accessControl interfaces.AccessControl
}

// NewPermissionHandlers creates new permission handlers
func NewPermissionHandlers(accessControl interfaces.AccessControl) *PermissionHandlers {
	return &PermissionHandlers{
		accessControl: accessControl,
	}
}

// SetFilePermissions handles setting file permissions
func (h *PermissionHandlers) SetFilePermissions(c *gin.Context) {
	bucket := c.Param("bucket")
	path := c.Param("path")

	if bucket == "" || path == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "bucket and path are required"})
		return
	}

	// Get user ID from context
	userID, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "user not authenticated"})
		return
	}

	// Check if user can modify permissions (must have delete permission)
	if !h.accessControl.CanDelete(c.Request.Context(), userID.(string), bucket, path) {
		c.JSON(http.StatusForbidden, gin.H{"error": "insufficient permissions to modify file permissions"})
		return
	}

	// Parse permissions from request body
	var permissions interfaces.FilePermissions
	if err := c.ShouldBindJSON(&permissions); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid permissions format"})
		return
	}

	// Validate permissions
	if ac, ok := h.accessControl.(*AccessControlService); ok {
		if err := ac.ValidatePermissions(&permissions); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
	}

	// Set permissions
	err := h.accessControl.SetPermissions(c.Request.Context(), bucket, path, permissions)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "permissions updated successfully"})
}

// GetFilePermissions handles getting file permissions
func (h *PermissionHandlers) GetFilePermissions(c *gin.Context) {
	bucket := c.Param("bucket")
	path := c.Param("path")

	if bucket == "" || path == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "bucket and path are required"})
		return
	}

	// Get user ID from context
	userID, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "user not authenticated"})
		return
	}

	// Check if user can read the file
	if !h.accessControl.CanRead(c.Request.Context(), userID.(string), bucket, path) {
		c.JSON(http.StatusForbidden, gin.H{"error": "insufficient permissions to view file permissions"})
		return
	}

	// Get permissions
	permissions, err := h.accessControl.GetPermissions(c.Request.Context(), bucket, path)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "file not found"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"permissions": permissions})
}

// GetUserPermissions handles getting all permissions for a user
func (h *PermissionHandlers) GetUserPermissions(c *gin.Context) {
	// Get user ID from context
	userID, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "user not authenticated"})
		return
	}

	// Get target user ID from query parameter (defaults to current user)
	targetUserID := c.DefaultQuery("user_id", userID.(string))

	// Only allow users to view their own permissions unless they're admin
	// TODO: Implement admin role checking
	if targetUserID != userID.(string) {
		c.JSON(http.StatusForbidden, gin.H{"error": "can only view your own permissions"})
		return
	}

	// Get user permissions
	if ac, ok := h.accessControl.(*AccessControlService); ok {
		permissions, err := ac.GetUserPermissions(c.Request.Context(), targetUserID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		c.JSON(http.StatusOK, gin.H{"permissions": permissions})
	} else {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "access control service not available"})
	}
}

// CheckPermissions handles permission checking requests
func (h *PermissionHandlers) CheckPermissions(c *gin.Context) {
	bucket := c.Param("bucket")
	path := c.Query("path")
	operation := c.Query("operation")

	if bucket == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "bucket is required"})
		return
	}

	if operation == "" {
		operation = "read"
	}

	// Validate operation
	validOperations := map[string]bool{
		"read":   true,
		"write":  true,
		"delete": true,
	}

	if !validOperations[operation] {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid operation, must be read, write, or delete"})
		return
	}

	// Get user ID from context (may be empty for public access)
	userID, _ := c.Get("user_id")
	userIDStr := ""
	if userID != nil {
		userIDStr = userID.(string)
	}

	// Check permissions based on operation
	var hasPermission bool
	switch operation {
	case "read":
		hasPermission = h.accessControl.CanRead(c.Request.Context(), userIDStr, bucket, path)
	case "write":
		hasPermission = h.accessControl.CanWrite(c.Request.Context(), userIDStr, bucket, path)
	case "delete":
		hasPermission = h.accessControl.CanDelete(c.Request.Context(), userIDStr, bucket, path)
	}

	c.JSON(http.StatusOK, gin.H{
		"bucket":    bucket,
		"path":      path,
		"operation": operation,
		"allowed":   hasPermission,
		"user_id":   userIDStr,
	})
}

// RegisterPermissionRoutes registers permission management routes
func (h *PermissionHandlers) RegisterPermissionRoutes(router *gin.RouterGroup) {
	permissions := router.Group("/permissions")
	{
		// File permission management
		permissions.PUT("/files/:bucket/*path", h.SetFilePermissions)
		permissions.GET("/files/:bucket/*path", h.GetFilePermissions)

		// User permission queries
		permissions.GET("/user", h.GetUserPermissions)

		// Permission checking
		permissions.GET("/check/:bucket", h.CheckPermissions)
	}
}

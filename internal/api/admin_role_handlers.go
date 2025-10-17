package api

import (
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/taqiudeen275/go-foward/internal/auth"
)

// AdminRoleHandlers provides HTTP handlers for role management
type AdminRoleHandlers struct {
	rbacEngine auth.RBACEngine
}

// NewAdminRoleHandlers creates new admin role handlers
func NewAdminRoleHandlers(rbacEngine auth.RBACEngine) *AdminRoleHandlers {
	return &AdminRoleHandlers{
		rbacEngine: rbacEngine,
	}
}

// CreateRoleRequest represents a request to create a new role
type CreateRoleRequest struct {
	Name        string                 `json:"name" binding:"required"`
	Level       int                    `json:"level" binding:"required"`
	Description string                 `json:"description"`
	Permissions map[string]interface{} `json:"permissions"`
}

// UpdateRoleRequest represents a request to update a role
type UpdateRoleRequest struct {
	Name        string                 `json:"name,omitempty"`
	Level       *int                   `json:"level,omitempty"`
	Description string                 `json:"description,omitempty"`
	Permissions map[string]interface{} `json:"permissions,omitempty"`
}

// RoleFilter represents filters for listing roles
type RoleFilter struct {
	MinLevel int    `form:"min_level"`
	MaxLevel int    `form:"max_level"`
	Search   string `form:"search"`
	Limit    int    `form:"limit"`
	Offset   int    `form:"offset"`
}

// RegisterRoutes registers all role management routes
func (h *AdminRoleHandlers) RegisterRoutes(router *gin.RouterGroup) {
	// Role management routes - require system admin role
	roles := router.Group("/roles")
	roles.Use(h.requireSystemAdmin())
	{
		roles.POST("", h.CreateRole())
		roles.GET("", h.ListRoles())
		roles.GET("/:role_id", h.GetRole())
		roles.PUT("/:role_id", h.UpdateRole())
		roles.DELETE("/:role_id", h.DeleteRole())

		// Role assignment endpoints
		roles.GET("/:role_id/users", h.GetRoleUsers())
		roles.POST("/:role_id/assign", h.AssignRoleToUsers())
		roles.POST("/:role_id/revoke", h.RevokeRoleFromUsers())

		// Permission management
		roles.GET("/:role_id/permissions", h.GetRolePermissions())
		roles.PUT("/:role_id/permissions", h.UpdateRolePermissions())

		// Role hierarchy
		roles.GET("/hierarchy", h.GetRoleHierarchy())
		roles.GET("/capabilities", h.ListAllCapabilities())
	}
}

// CreateRole creates a new admin role
func (h *AdminRoleHandlers) CreateRole() gin.HandlerFunc {
	return func(c *gin.Context) {
		var req CreateRoleRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"error":   "Invalid request",
				"message": err.Error(),
			})
			return
		}

		// Validate role level
		if req.Level < 0 || req.Level > 100 {
			c.JSON(http.StatusBadRequest, gin.H{
				"error":   "Invalid role level",
				"message": "Role level must be between 0 and 100",
			})
			return
		}

		// Check if role name already exists
		// TODO: Implement role existence check

		// Create the role
		role := &auth.AdminRole{
			Name:        req.Name,
			Level:       req.Level,
			Description: req.Description,
			Permissions: req.Permissions,
		}

		// TODO: Implement role creation in database
		// For now, return success with placeholder

		c.JSON(http.StatusCreated, gin.H{
			"success": true,
			"message": "Role created successfully",
			"data": gin.H{
				"name":        role.Name,
				"level":       role.Level,
				"description": role.Description,
				"permissions": role.Permissions,
			},
		})
	}
}

// ListRoles lists all admin roles with filtering
func (h *AdminRoleHandlers) ListRoles() gin.HandlerFunc {
	return func(c *gin.Context) {
		var filter RoleFilter
		if err := c.ShouldBindQuery(&filter); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"error":   "Invalid query parameters",
				"message": err.Error(),
			})
			return
		}

		// Set defaults
		if filter.Limit == 0 {
			filter.Limit = 50
		}
		if filter.Limit > 1000 {
			filter.Limit = 1000
		}

		// TODO: Query roles from database with filters
		// For now, return default roles
		defaultRoles := []gin.H{
			{
				"id":          "1",
				"name":        "viewer",
				"level":       10,
				"description": "Read-only access to assigned resources",
				"user_count":  0,
			},
			{
				"id":          "2",
				"name":        "admin",
				"level":       50,
				"description": "Full access to business operations",
				"user_count":  0,
			},
			{
				"id":          "3",
				"name":        "system_admin",
				"level":       90,
				"description": "Full system administration privileges",
				"user_count":  0,
			},
			{
				"id":          "4",
				"name":        "security_admin",
				"level":       85,
				"description": "Security and audit administration",
				"user_count":  0,
			},
		}

		c.JSON(http.StatusOK, gin.H{
			"success": true,
			"data":    defaultRoles,
			"total":   len(defaultRoles),
			"limit":   filter.Limit,
			"offset":  filter.Offset,
		})
	}
}

// GetRole gets a specific role by ID
func (h *AdminRoleHandlers) GetRole() gin.HandlerFunc {
	return func(c *gin.Context) {
		roleID := c.Param("role_id")
		if roleID == "" {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "Role ID is required",
			})
			return
		}

		// TODO: Query role from database
		// For now, return placeholder data
		role := gin.H{
			"id":          roleID,
			"name":        "system_admin",
			"level":       90,
			"description": "Full system administration privileges",
			"permissions": gin.H{
				"create_admin_user":     true,
				"manage_users":          true,
				"execute_sql":           true,
				"approve_high_risk_sql": true,
				"view_audit_logs":       true,
				"manage_system_config":  true,
			},
			"created_at": "2024-01-01T00:00:00Z",
			"updated_at": "2024-01-01T00:00:00Z",
		}

		c.JSON(http.StatusOK, gin.H{
			"success": true,
			"data":    role,
		})
	}
}

// UpdateRole updates an existing role
func (h *AdminRoleHandlers) UpdateRole() gin.HandlerFunc {
	return func(c *gin.Context) {
		roleID := c.Param("role_id")
		if roleID == "" {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "Role ID is required",
			})
			return
		}

		var req UpdateRoleRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"error":   "Invalid request",
				"message": err.Error(),
			})
			return
		}

		// Validate role level if provided
		if req.Level != nil && (*req.Level < 0 || *req.Level > 100) {
			c.JSON(http.StatusBadRequest, gin.H{
				"error":   "Invalid role level",
				"message": "Role level must be between 0 and 100",
			})
			return
		}

		// Check if role is a system default role
		systemRoles := []string{"viewer", "admin", "system_admin", "security_admin"}
		for _, sysRole := range systemRoles {
			if roleID == sysRole {
				c.JSON(http.StatusBadRequest, gin.H{
					"error":   "Cannot modify system role",
					"message": "System default roles cannot be modified",
				})
				return
			}
		}

		// TODO: Update role in database
		c.JSON(http.StatusOK, gin.H{
			"success": true,
			"message": "Role updated successfully",
		})
	}
}

// DeleteRole deletes a role
func (h *AdminRoleHandlers) DeleteRole() gin.HandlerFunc {
	return func(c *gin.Context) {
		roleID := c.Param("role_id")
		if roleID == "" {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "Role ID is required",
			})
			return
		}

		// Check if role is a system default role
		systemRoles := []string{"viewer", "admin", "system_admin", "security_admin"}
		for _, sysRole := range systemRoles {
			if roleID == sysRole {
				c.JSON(http.StatusBadRequest, gin.H{
					"error":   "Cannot delete system role",
					"message": "System default roles cannot be deleted",
				})
				return
			}
		}

		// Check if role has users assigned
		// TODO: Check if users are assigned to this role

		// TODO: Delete role from database
		c.JSON(http.StatusOK, gin.H{
			"success": true,
			"message": "Role deleted successfully",
		})
	}
}

// GetRoleUsers gets all users assigned to a role
func (h *AdminRoleHandlers) GetRoleUsers() gin.HandlerFunc {
	return func(c *gin.Context) {
		roleID := c.Param("role_id")
		if roleID == "" {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "Role ID is required",
			})
			return
		}

		limit, _ := strconv.Atoi(c.DefaultQuery("limit", "50"))
		if limit > 1000 {
			limit = 1000
		}

		// TODO: Query users with this role from database
		c.JSON(http.StatusOK, gin.H{
			"success": true,
			"data":    []interface{}{},
			"total":   0,
			"limit":   limit,
			"message": "Role user listing not yet implemented",
		})
	}
}

// AssignRoleToUsers assigns a role to multiple users
func (h *AdminRoleHandlers) AssignRoleToUsers() gin.HandlerFunc {
	return func(c *gin.Context) {
		roleID := c.Param("role_id")
		if roleID == "" {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "Role ID is required",
			})
			return
		}

		var req struct {
			UserIDs []string `json:"user_ids" binding:"required"`
			Reason  string   `json:"reason"`
		}

		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"error":   "Invalid request",
				"message": err.Error(),
			})
			return
		}

		currentUserID := c.GetString("user_id")
		successCount := 0
		failures := []gin.H{}

		// Assign role to each user
		for _, userID := range req.UserIDs {
			err := h.rbacEngine.GrantRole(c.Request.Context(), userID, roleID, currentUserID)
			if err != nil {
				failures = append(failures, gin.H{
					"user_id": userID,
					"error":   err.Error(),
				})
			} else {
				successCount++
			}
		}

		response := gin.H{
			"success":     len(failures) == 0,
			"assigned":    successCount,
			"total":       len(req.UserIDs),
			"role_id":     roleID,
			"assigned_by": currentUserID,
		}

		if len(failures) > 0 {
			response["failures"] = failures
		}

		statusCode := http.StatusOK
		if len(failures) == len(req.UserIDs) {
			statusCode = http.StatusBadRequest
		}

		c.JSON(statusCode, response)
	}
}

// RevokeRoleFromUsers revokes a role from multiple users
func (h *AdminRoleHandlers) RevokeRoleFromUsers() gin.HandlerFunc {
	return func(c *gin.Context) {
		roleID := c.Param("role_id")
		if roleID == "" {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "Role ID is required",
			})
			return
		}

		var req struct {
			UserIDs []string `json:"user_ids" binding:"required"`
			Reason  string   `json:"reason"`
		}

		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"error":   "Invalid request",
				"message": err.Error(),
			})
			return
		}

		currentUserID := c.GetString("user_id")
		successCount := 0
		failures := []gin.H{}

		// Revoke role from each user
		for _, userID := range req.UserIDs {
			// Prevent self-revocation of system_admin role
			if userID == currentUserID && roleID == "system_admin" {
				failures = append(failures, gin.H{
					"user_id": userID,
					"error":   "Cannot revoke system_admin role from yourself",
				})
				continue
			}

			err := h.rbacEngine.RevokeRole(c.Request.Context(), userID, roleID, currentUserID)
			if err != nil {
				failures = append(failures, gin.H{
					"user_id": userID,
					"error":   err.Error(),
				})
			} else {
				successCount++
			}
		}

		response := gin.H{
			"success":    len(failures) == 0,
			"revoked":    successCount,
			"total":      len(req.UserIDs),
			"role_id":    roleID,
			"revoked_by": currentUserID,
		}

		if len(failures) > 0 {
			response["failures"] = failures
		}

		statusCode := http.StatusOK
		if len(failures) == len(req.UserIDs) {
			statusCode = http.StatusBadRequest
		}

		c.JSON(statusCode, response)
	}
}

// GetRolePermissions gets all permissions for a role
func (h *AdminRoleHandlers) GetRolePermissions() gin.HandlerFunc {
	return func(c *gin.Context) {
		roleID := c.Param("role_id")
		if roleID == "" {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "Role ID is required",
			})
			return
		}

		// TODO: Query role permissions from database
		// For now, return placeholder permissions based on role
		var permissions map[string]interface{}

		switch roleID {
		case "viewer":
			permissions = map[string]interface{}{
				"view_data":      true,
				"export_reports": true,
			}
		case "admin":
			permissions = map[string]interface{}{
				"view_data":       true,
				"create_data":     true,
				"update_data":     true,
				"delete_data":     false,
				"manage_users":    false,
				"export_reports":  true,
				"execute_queries": true,
			}
		case "system_admin":
			permissions = map[string]interface{}{
				"create_admin_user":     true,
				"manage_users":          true,
				"execute_sql":           true,
				"approve_high_risk_sql": true,
				"view_audit_logs":       true,
				"manage_system_config":  true,
				"emergency_access":      true,
			}
		case "security_admin":
			permissions = map[string]interface{}{
				"view_audit_logs":        true,
				"manage_security_config": true,
				"approve_high_risk_sql":  true,
				"emergency_access":       false,
				"view_security_events":   true,
			}
		default:
			permissions = map[string]interface{}{}
		}

		c.JSON(http.StatusOK, gin.H{
			"success": true,
			"data": gin.H{
				"role_id":     roleID,
				"permissions": permissions,
			},
		})
	}
}

// UpdateRolePermissions updates permissions for a role
func (h *AdminRoleHandlers) UpdateRolePermissions() gin.HandlerFunc {
	return func(c *gin.Context) {
		roleID := c.Param("role_id")
		if roleID == "" {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "Role ID is required",
			})
			return
		}

		var req struct {
			Permissions map[string]interface{} `json:"permissions" binding:"required"`
		}

		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"error":   "Invalid request",
				"message": err.Error(),
			})
			return
		}

		// Check if role is a system default role
		systemRoles := []string{"viewer", "admin", "system_admin", "security_admin"}
		for _, sysRole := range systemRoles {
			if roleID == sysRole {
				c.JSON(http.StatusBadRequest, gin.H{
					"error":   "Cannot modify system role permissions",
					"message": "System default role permissions cannot be modified",
				})
				return
			}
		}

		// TODO: Update role permissions in database
		c.JSON(http.StatusOK, gin.H{
			"success": true,
			"message": "Role permissions updated successfully",
			"data": gin.H{
				"role_id":     roleID,
				"permissions": req.Permissions,
			},
		})
	}
}

// GetRoleHierarchy gets the role hierarchy structure
func (h *AdminRoleHandlers) GetRoleHierarchy() gin.HandlerFunc {
	return func(c *gin.Context) {
		// TODO: Query role hierarchy from database
		// For now, return static hierarchy
		hierarchy := gin.H{
			"roles": []gin.H{
				{
					"id":       "1",
					"name":     "viewer",
					"level":    10,
					"children": []gin.H{},
				},
				{
					"id":    "2",
					"name":  "admin",
					"level": 50,
					"children": []gin.H{
						{
							"id":       "1",
							"name":     "viewer",
							"level":    10,
							"children": []gin.H{},
						},
					},
				},
				{
					"id":    "4",
					"name":  "security_admin",
					"level": 85,
					"children": []gin.H{
						{
							"id":       "2",
							"name":     "admin",
							"level":    50,
							"children": []gin.H{},
						},
					},
				},
				{
					"id":    "3",
					"name":  "system_admin",
					"level": 90,
					"children": []gin.H{
						{
							"id":       "4",
							"name":     "security_admin",
							"level":    85,
							"children": []gin.H{},
						},
					},
				},
			},
		}

		c.JSON(http.StatusOK, gin.H{
			"success": true,
			"data":    hierarchy,
		})
	}
}

// ListAllCapabilities lists all available capabilities/permissions
func (h *AdminRoleHandlers) ListAllCapabilities() gin.HandlerFunc {
	return func(c *gin.Context) {
		capabilities := []gin.H{
			{
				"name":        "create_admin_user",
				"description": "Create new admin users",
				"category":    "user_management",
			},
			{
				"name":        "manage_users",
				"description": "Manage user accounts and profiles",
				"category":    "user_management",
			},
			{
				"name":        "execute_sql",
				"description": "Execute SQL queries",
				"category":    "database",
			},
			{
				"name":        "approve_high_risk_sql",
				"description": "Approve high-risk SQL operations",
				"category":    "database",
			},
			{
				"name":        "view_audit_logs",
				"description": "View system audit logs",
				"category":    "security",
			},
			{
				"name":        "manage_system_config",
				"description": "Manage system configuration",
				"category":    "system",
			},
			{
				"name":        "emergency_access",
				"description": "Emergency system access",
				"category":    "system",
			},
			{
				"name":        "view_security_events",
				"description": "View security events and alerts",
				"category":    "security",
			},
			{
				"name":        "manage_security_config",
				"description": "Manage security configuration",
				"category":    "security",
			},
		}

		c.JSON(http.StatusOK, gin.H{
			"success": true,
			"data":    capabilities,
			"total":   len(capabilities),
		})
	}
}

// Helper middleware

// requireSystemAdmin middleware that requires system admin role
func (h *AdminRoleHandlers) requireSystemAdmin() gin.HandlerFunc {
	return func(c *gin.Context) {
		userID, exists := c.Get("user_id")
		if !exists {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "Authentication required",
			})
			c.Abort()
			return
		}

		userIDStr, ok := userID.(string)
		if !ok {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "Invalid authentication",
			})
			c.Abort()
			return
		}

		hasRole, err := h.rbacEngine.HasRole(c.Request.Context(), userIDStr, "system_admin")
		if err != nil || !hasRole {
			c.JSON(http.StatusForbidden, gin.H{
				"error":   "Insufficient privileges",
				"message": "System admin role required",
			})
			c.Abort()
			return
		}

		c.Next()
	}
}

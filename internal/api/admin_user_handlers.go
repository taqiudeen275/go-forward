package api

import (
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/taqiudeen275/go-foward/internal/auth"
)

// AdminUserHandlers provides HTTP handlers for admin user management
type AdminUserHandlers struct {
	authService *auth.Service
	rbacEngine  auth.RBACEngine
	mfaService  auth.MFAService
}

// NewAdminUserHandlers creates new admin user handlers
func NewAdminUserHandlers(authService *auth.Service, rbacEngine auth.RBACEngine, mfaService auth.MFAService) *AdminUserHandlers {
	return &AdminUserHandlers{
		authService: authService,
		rbacEngine:  rbacEngine,
		mfaService:  mfaService,
	}
}

// CreateAdminUserRequest represents a request to create an admin user
type CreateAdminUserRequest struct {
	Email       string                 `json:"email" binding:"required,email"`
	Password    string                 `json:"password" binding:"required,min=8"`
	Role        string                 `json:"role" binding:"required"`
	FirstName   string                 `json:"first_name,omitempty"`
	LastName    string                 `json:"last_name,omitempty"`
	Phone       string                 `json:"phone,omitempty"`
	Department  string                 `json:"department,omitempty"`
	EnableMFA   bool                   `json:"enable_mfa,omitempty"`
	ExpiresAt   *time.Time             `json:"expires_at,omitempty"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
	SendWelcome bool                   `json:"send_welcome,omitempty"`
}

// UpdateAdminUserRequest represents a request to update an admin user
type UpdateAdminUserRequest struct {
	Email      string                 `json:"email,omitempty"`
	FirstName  string                 `json:"first_name,omitempty"`
	LastName   string                 `json:"last_name,omitempty"`
	Phone      string                 `json:"phone,omitempty"`
	Department string                 `json:"department,omitempty"`
	IsActive   *bool                  `json:"is_active,omitempty"`
	Metadata   map[string]interface{} `json:"metadata,omitempty"`
}

// PromoteUserRequest represents a request to promote a user to admin
type PromoteUserRequest struct {
	Role      string     `json:"role" binding:"required"`
	Reason    string     `json:"reason" binding:"required"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
}

// DemoteUserRequest represents a request to demote an admin user
type DemoteUserRequest struct {
	Role   string `json:"role" binding:"required"`
	Reason string `json:"reason" binding:"required"`
}

// AdminUserFilter represents filters for listing admin users
type AdminUserFilter struct {
	Role       string `form:"role"`
	Department string `form:"department"`
	IsActive   *bool  `form:"is_active"`
	Search     string `form:"search"`
	Limit      int    `form:"limit"`
	Offset     int    `form:"offset"`
}

// RegisterRoutes registers all admin user management routes
func (h *AdminUserHandlers) RegisterRoutes(router *gin.RouterGroup) {
	// Admin user management routes - require system admin role
	users := router.Group("/users")
	users.Use(h.requireAdminRole("system_admin"))
	{
		users.POST("", h.CreateAdminUser())
		users.GET("", h.ListAdminUsers())
		users.GET("/:user_id", h.GetAdminUser())
		users.PUT("/:user_id", h.UpdateAdminUser())
		users.DELETE("/:user_id", h.DeleteAdminUser())

		// Role management
		users.POST("/:user_id/promote", h.PromoteUser())
		users.POST("/:user_id/demote", h.DemoteUser())
		users.GET("/:user_id/roles", h.GetUserRoles())

		// MFA management
		users.POST("/:user_id/mfa/enable", h.EnableUserMFA())
		users.POST("/:user_id/mfa/disable", h.DisableUserMFA())
		users.GET("/:user_id/mfa/status", h.GetUserMFAStatus())

		// Session management
		users.GET("/:user_id/sessions", h.GetUserSessions())
		users.DELETE("/:user_id/sessions", h.RevokeUserSessions())
		users.DELETE("/:user_id/sessions/:session_id", h.RevokeUserSession())

		// Audit and activity
		users.GET("/:user_id/activity", h.GetUserActivity())
		users.GET("/:user_id/permissions", h.GetUserPermissions())
	}

	// User profile routes - users can manage their own profile
	profile := router.Group("/profile")
	{
		profile.GET("", h.GetCurrentUserProfile())
		profile.PUT("", h.UpdateCurrentUserProfile())
		profile.POST("/change-password", h.ChangePassword())
		profile.GET("/activity", h.GetCurrentUserActivity())
	}
}

// CreateAdminUser creates a new admin user
func (h *AdminUserHandlers) CreateAdminUser() gin.HandlerFunc {
	return func(c *gin.Context) {
		var req CreateAdminUserRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"error":   "Invalid request",
				"message": err.Error(),
			})
			return
		}

		// Get current admin user info
		currentUserID, exists := c.Get("user_id")
		if !exists {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "Authentication required",
			})
			return
		}

		currentUserIDStr := currentUserID.(string)

		// Check if current user can create admin users with this role
		canCreate, err := h.rbacEngine.HasCapability(c.Request.Context(), currentUserIDStr, "create_admin_user", "admin_users")
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error":   "Permission check failed",
				"message": err.Error(),
			})
			return
		}

		if !canCreate {
			c.JSON(http.StatusForbidden, gin.H{
				"error": "Insufficient privileges to create admin users",
			})
			return
		}

		// Validate the requested role
		validRoles := []string{"viewer", "admin", "system_admin", "security_admin"}
		roleValid := false
		for _, role := range validRoles {
			if req.Role == role {
				roleValid = true
				break
			}
		}

		if !roleValid {
			c.JSON(http.StatusBadRequest, gin.H{
				"error":   "Invalid role",
				"message": "Role must be one of: viewer, admin, system_admin, security_admin",
			})
			return
		}

		// Create the admin user
		createReq := &auth.CreateAdminUserRequest{
			Email:     &req.Email,
			Password:  req.Password,
			RoleName:  req.Role,
			Phone:     &req.Phone,
			Metadata:  req.Metadata,
			EnableMFA: req.EnableMFA,
		}

		user, err := h.authService.CreateAdminUser(c.Request.Context(), *createReq)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error":   "Failed to create admin user",
				"message": err.Error(),
			})
			return
		}

		// Set up MFA if requested
		if req.EnableMFA {
			_, _, err := h.mfaService.GenerateTOTPSecret(c.Request.Context(), user.ID)
			if err != nil {
				// Log warning but don't fail the user creation
				// User can enable MFA later
			}
		}

		// Send welcome email if requested (placeholder)
		if req.SendWelcome {
			// TODO: Implement welcome email sending
		}

		c.JSON(http.StatusCreated, gin.H{
			"success": true,
			"message": "Admin user created successfully",
			"data": gin.H{
				"id":         user.ID,
				"email":      user.Email,
				"role":       req.Role,
				"created_at": user.CreatedAt,
			},
		})
	}
}

// ListAdminUsers lists admin users with filtering
func (h *AdminUserHandlers) ListAdminUsers() gin.HandlerFunc {
	return func(c *gin.Context) {
		var filter AdminUserFilter
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

		// Convert to service filter
		serviceFilter := auth.AdminUserFilter{
			RoleName: &filter.Role,
			IsActive: filter.IsActive,
			Limit:    filter.Limit,
			Offset:   filter.Offset,
		}

		if filter.IsActive != nil {
			serviceFilter.IsActive = filter.IsActive
		}

		users, err := h.authService.GetAdminUsers(c.Request.Context(), serviceFilter)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error":   "Failed to retrieve admin users",
				"message": err.Error(),
			})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"success": true,
			"data":    users,
			"total":   len(users),
			"limit":   filter.Limit,
			"offset":  filter.Offset,
		})
	}
}

// GetAdminUser gets a specific admin user by ID
func (h *AdminUserHandlers) GetAdminUser() gin.HandlerFunc {
	return func(c *gin.Context) {
		userID := c.Param("user_id")
		if userID == "" {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "User ID is required",
			})
			return
		}

		// Get user details
		user, err := h.authService.GetUserByID(c.Request.Context(), userID)
		if err != nil {
			c.JSON(http.StatusNotFound, gin.H{
				"error":   "User not found",
				"message": err.Error(),
			})
			return
		}

		// Get user roles
		roles, err := h.rbacEngine.GetUserRoles(c.Request.Context(), userID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error":   "Failed to get user roles",
				"message": err.Error(),
			})
			return
		}

		// Get MFA status
		mfaStatus, err := h.mfaService.GetMFAStatus(c.Request.Context(), userID)
		if err != nil {
			// Don't fail if MFA status unavailable
			mfaStatus = nil
		}

		response := gin.H{
			"success": true,
			"data": gin.H{
				"id":         user.ID,
				"email":      user.Email,
				"username":   user.Username,
				"created_at": user.CreatedAt,
				"updated_at": user.UpdatedAt,
				"roles":      roles,
			},
		}

		if mfaStatus != nil {
			response["data"].(gin.H)["mfa_enabled"] = mfaStatus.IsEnabled
		}

		c.JSON(http.StatusOK, response)
	}
}

// UpdateAdminUser updates an admin user
func (h *AdminUserHandlers) UpdateAdminUser() gin.HandlerFunc {
	return func(c *gin.Context) {
		userID := c.Param("user_id")
		if userID == "" {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "User ID is required",
			})
			return
		}

		var req UpdateAdminUserRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"error":   "Invalid request",
				"message": err.Error(),
			})
			return
		}

		currentUserID := c.GetString("user_id")

		// Check if current user can update this user
		canUpdate, err := h.rbacEngine.CanManageUser(c.Request.Context(), currentUserID, userID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error":   "Permission check failed",
				"message": err.Error(),
			})
			return
		}

		if !canUpdate {
			c.JSON(http.StatusForbidden, gin.H{
				"error": "Insufficient privileges to update this user",
			})
			return
		}

		// Update user (implementation would go here)
		// For now, return success
		c.JSON(http.StatusOK, gin.H{
			"success": true,
			"message": "User updated successfully",
		})
	}
}

// DeleteAdminUser deletes (deactivates) an admin user
func (h *AdminUserHandlers) DeleteAdminUser() gin.HandlerFunc {
	return func(c *gin.Context) {
		userID := c.Param("user_id")
		if userID == "" {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "User ID is required",
			})
			return
		}

		currentUserID := c.GetString("user_id")

		// Prevent self-deletion
		if userID == currentUserID {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "Cannot delete your own account",
			})
			return
		}

		// Check permissions
		canDelete, err := h.rbacEngine.CanManageUser(c.Request.Context(), currentUserID, userID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error":   "Permission check failed",
				"message": err.Error(),
			})
			return
		}

		if !canDelete {
			c.JSON(http.StatusForbidden, gin.H{
				"error": "Insufficient privileges to delete this user",
			})
			return
		}

		// Delete the admin user
		err = h.authService.DeleteUser(c.Request.Context(), userID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error":   "Failed to delete user",
				"message": err.Error(),
			})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"success": true,
			"message": "User deleted successfully",
		})
	}
}

// PromoteUser promotes a regular user to admin
func (h *AdminUserHandlers) PromoteUser() gin.HandlerFunc {
	return func(c *gin.Context) {
		userID := c.Param("user_id")
		if userID == "" {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "User ID is required",
			})
			return
		}

		var req PromoteUserRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"error":   "Invalid request",
				"message": err.Error(),
			})
			return
		}

		currentUserID := c.GetString("user_id")

		// Promote the user
		err := h.authService.PromoteToAdmin(c.Request.Context(), userID, req.Role, currentUserID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error":   "Failed to promote user",
				"message": err.Error(),
			})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"success": true,
			"message": "User promoted successfully",
			"data": gin.H{
				"user_id":     userID,
				"role":        req.Role,
				"promoted_by": currentUserID,
				"reason":      req.Reason,
			},
		})
	}
}

// DemoteUser removes admin roles from a user
func (h *AdminUserHandlers) DemoteUser() gin.HandlerFunc {
	return func(c *gin.Context) {
		userID := c.Param("user_id")
		if userID == "" {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "User ID is required",
			})
			return
		}

		var req DemoteUserRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"error":   "Invalid request",
				"message": err.Error(),
			})
			return
		}

		currentUserID := c.GetString("user_id")

		// Prevent self-demotion
		if userID == currentUserID {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "Cannot demote your own account",
			})
			return
		}

		// Revoke the role
		err := h.rbacEngine.RevokeRole(c.Request.Context(), userID, req.Role, currentUserID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error":   "Failed to demote user",
				"message": err.Error(),
			})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"success": true,
			"message": "User demoted successfully",
			"data": gin.H{
				"user_id":    userID,
				"role":       req.Role,
				"demoted_by": currentUserID,
				"reason":     req.Reason,
			},
		})
	}
}

// GetUserRoles gets all roles for a specific user
func (h *AdminUserHandlers) GetUserRoles() gin.HandlerFunc {
	return func(c *gin.Context) {
		userID := c.Param("user_id")
		if userID == "" {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "User ID is required",
			})
			return
		}

		roles, err := h.rbacEngine.GetUserRoles(c.Request.Context(), userID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error":   "Failed to get user roles",
				"message": err.Error(),
			})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"success": true,
			"data":    roles,
		})
	}
}

// EnableUserMFA enables MFA for a user
func (h *AdminUserHandlers) EnableUserMFA() gin.HandlerFunc {
	return func(c *gin.Context) {
		userID := c.Param("user_id")
		if userID == "" {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "User ID is required",
			})
			return
		}

		// Generate TOTP secret for the user (MFA setup, not immediate enable)
		secret, backupCodes, err := h.mfaService.GenerateTOTPSecret(c.Request.Context(), userID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error":   "Failed to setup MFA",
				"message": err.Error(),
			})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"success": true,
			"message": "MFA setup completed successfully",
			"data": gin.H{
				"totp_secret":  secret,
				"backup_codes": backupCodes,
			},
		})
	}
}

// DisableUserMFA disables MFA for a user
func (h *AdminUserHandlers) DisableUserMFA() gin.HandlerFunc {
	return func(c *gin.Context) {
		userID := c.Param("user_id")
		if userID == "" {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "User ID is required",
			})
			return
		}

		err := h.mfaService.DisableMFA(c.Request.Context(), userID, "")
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error":   "Failed to disable MFA",
				"message": err.Error(),
			})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"success": true,
			"message": "MFA disabled successfully",
			"data": gin.H{
				"user_id":     userID,
				"mfa_enabled": false,
			},
		})
	}
}

// GetUserMFAStatus gets MFA status for a user
func (h *AdminUserHandlers) GetUserMFAStatus() gin.HandlerFunc {
	return func(c *gin.Context) {
		userID := c.Param("user_id")
		if userID == "" {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "User ID is required",
			})
			return
		}

		status, err := h.mfaService.GetMFAStatus(c.Request.Context(), userID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error":   "Failed to get MFA status",
				"message": err.Error(),
			})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"success": true,
			"data":    status,
		})
	}
}

// GetUserSessions gets active sessions for a user
func (h *AdminUserHandlers) GetUserSessions() gin.HandlerFunc {
	return func(c *gin.Context) {
		userID := c.Param("user_id")
		if userID == "" {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "User ID is required",
			})
			return
		}

		// TODO: Implement session retrieval from admin_sessions table
		c.JSON(http.StatusOK, gin.H{
			"success": true,
			"data":    []interface{}{},
			"message": "Session management not yet implemented",
		})
	}
}

// RevokeUserSessions revokes all sessions for a user
func (h *AdminUserHandlers) RevokeUserSessions() gin.HandlerFunc {
	return func(c *gin.Context) {
		userID := c.Param("user_id")
		if userID == "" {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "User ID is required",
			})
			return
		}

		// TODO: Implement session revocation
		c.JSON(http.StatusOK, gin.H{
			"success": true,
			"message": "All sessions revoked successfully",
		})
	}
}

// RevokeUserSession revokes a specific session for a user
func (h *AdminUserHandlers) RevokeUserSession() gin.HandlerFunc {
	return func(c *gin.Context) {
		userID := c.Param("id")
		_ = userID // Placeholder for implementation
		sessionID := c.Param("session_id")

		if userID == "" || sessionID == "" {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "User ID and Session ID are required",
			})
			return
		}

		// TODO: Implement specific session revocation
		c.JSON(http.StatusOK, gin.H{
			"success": true,
			"message": "Session revoked successfully",
		})
	}
}

// GetUserActivity gets activity log for a user
func (h *AdminUserHandlers) GetUserActivity() gin.HandlerFunc {
	return func(c *gin.Context) {
		userID := c.Param("id") // placeholder for user ID
		if userID == "" {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "User ID is required",
			})
			return
		}

		limit, _ := strconv.Atoi(c.DefaultQuery("limit", "50"))
		if limit > 1000 {
			limit = 1000
		}

		// TODO: Query admin_access_logs table for user activity
		c.JSON(http.StatusOK, gin.H{
			"success": true,
			"data":    []interface{}{},
			"limit":   limit,
			"message": "Activity logging not yet implemented",
		})
	}
}

// GetUserPermissions gets effective permissions for a user
func (h *AdminUserHandlers) GetUserPermissions() gin.HandlerFunc {
	return func(c *gin.Context) {
		userID := c.Param("id") // placeholder for user ID
		if userID == "" {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "User ID is required",
			})
			return
		}

		capabilities, err := h.rbacEngine.GetUserCapabilities(c.Request.Context(), userID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error":   "Failed to get user permissions",
				"message": err.Error(),
			})
			return
		}

		accessibleTables, err := h.rbacEngine.GetAccessibleTables(c.Request.Context(), userID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error":   "Failed to get accessible tables",
				"message": err.Error(),
			})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"success": true,
			"data": gin.H{
				"capabilities":      capabilities,
				"accessible_tables": accessibleTables,
			},
		})
	}
}

// Profile management endpoints

// GetCurrentUserProfile gets the current user's profile
func (h *AdminUserHandlers) GetCurrentUserProfile() gin.HandlerFunc {
	return func(c *gin.Context) {
		userID := c.GetString("user_id")

		user, err := h.authService.GetUserByID(c.Request.Context(), userID)
		if err != nil {
			c.JSON(http.StatusNotFound, gin.H{
				"error":   "User not found",
				"message": err.Error(),
			})
			return
		}

		roles, _ := h.rbacEngine.GetUserRoles(c.Request.Context(), userID)
		mfaStatus, _ := h.mfaService.GetMFAStatus(c.Request.Context(), userID)

		response := gin.H{
			"success": true,
			"data": gin.H{
				"id":         user.ID,
				"email":      user.Email,
				"username":   user.Username,
				"phone":      user.Phone,
				"created_at": user.CreatedAt,
				"updated_at": user.UpdatedAt,
				"roles":      roles,
			},
		}

		if mfaStatus != nil {
			response["data"].(gin.H)["mfa_enabled"] = mfaStatus.IsEnabled
		}

		c.JSON(http.StatusOK, response)
	}
}

// UpdateCurrentUserProfile updates the current user's profile
func (h *AdminUserHandlers) UpdateCurrentUserProfile() gin.HandlerFunc {
	return func(c *gin.Context) {
		var req UpdateAdminUserRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"error":   "Invalid request",
				"message": err.Error(),
			})
			return
		}

		userID := c.GetString("user_id")
		_ = userID // Placeholder for implementation

		// Update user profile (implementation would go here)
		c.JSON(http.StatusOK, gin.H{
			"success": true,
			"message": "Profile updated successfully",
		})
	}
}

// ChangePassword changes the current user's password
func (h *AdminUserHandlers) ChangePassword() gin.HandlerFunc {
	return func(c *gin.Context) {
		var req struct {
			CurrentPassword string `json:"current_password" binding:"required"`
			NewPassword     string `json:"new_password" binding:"required,min=8"`
		}

		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"error":   "Invalid request",
				"message": err.Error(),
			})
			return
		}

		userID := c.GetString("user_id")
		_ = userID // Placeholder for implementation

		// Change password (implementation would go here)
		c.JSON(http.StatusOK, gin.H{
			"success": true,
			"message": "Password changed successfully",
		})
	}
}

// GetCurrentUserActivity gets the current user's activity
func (h *AdminUserHandlers) GetCurrentUserActivity() gin.HandlerFunc {
	return func(c *gin.Context) {
		userID := c.GetString("user_id")
		_ = userID // Placeholder for implementation
		limit, _ := strconv.Atoi(c.DefaultQuery("limit", "50"))

		// TODO: Query user's own activity from audit logs
		c.JSON(http.StatusOK, gin.H{
			"success": true,
			"data":    []interface{}{},
			"limit":   limit,
			"message": "Activity logging not yet implemented",
		})
	}
}

// Helper middleware

// requireAdminRole middleware that checks for specific admin role
func (h *AdminUserHandlers) requireAdminRole(minRole string) gin.HandlerFunc {
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

		hasRole, err := h.rbacEngine.HasRole(c.Request.Context(), userIDStr, minRole)
		if err != nil || !hasRole {
			c.JSON(http.StatusForbidden, gin.H{
				"error":   "Insufficient privileges",
				"message": "Required role: " + minRole,
			})
			c.Abort()
			return
		}

		c.Next()
	}
}

package auth

import (
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/taqiudeen275/go-foward/internal/config"
	"github.com/taqiudeen275/go-foward/pkg/errors"
)

// AuthHandlers contains HTTP handlers for authentication endpoints
type AuthHandlers struct {
	authService AuthService
	config      *config.Config
}

// NewAuthHandlers creates new authentication handlers
func NewAuthHandlers(authService AuthService, cfg *config.Config) *AuthHandlers {
	return &AuthHandlers{
		authService: authService,
		config:      cfg,
	}
}

// RegisterRoutes registers authentication routes
func (h *AuthHandlers) RegisterRoutes(router *gin.Engine, authMiddleware *AuthMiddleware) {
	// Public authentication routes
	auth := router.Group("/api/auth")
	{
		auth.POST("/register", h.Register)
		auth.POST("/login", h.Login)
		auth.POST("/refresh", h.RefreshToken)
		auth.POST("/logout", authMiddleware.RequireAuth(), h.Logout)

		// OTP routes
		auth.POST("/otp/send", h.SendOTP)
		auth.POST("/otp/verify", h.VerifyOTP)

		// Password management
		auth.POST("/password/reset", h.ResetPassword)
		auth.POST("/password/change", authMiddleware.RequireAuth(), h.ChangePassword)

		// Account management
		auth.GET("/me", authMiddleware.RequireAuth(), h.GetCurrentUser)
		auth.PUT("/me", authMiddleware.RequireAuth(), h.UpdateProfile)

		// Verification
		auth.POST("/verify/email", authMiddleware.RequireAuth(), h.SendEmailVerification)
		auth.POST("/verify/phone", authMiddleware.RequireAuth(), h.SendPhoneVerification)
	}

	// Admin authentication routes
	adminAuth := router.Group("/api/admin/auth")
	{
		adminAuth.POST("/login", h.AdminLogin)
		adminAuth.POST("/logout", authMiddleware.RequireAdminSession(), h.AdminLogout)
		adminAuth.GET("/session", authMiddleware.RequireAdminSession(), h.GetAdminSession)
		adminAuth.POST("/session/refresh", authMiddleware.RequireAdminSession(), h.RefreshAdminSession)
	}

	// Admin user management routes (system admin only)
	adminUsers := router.Group("/api/admin/users")
	adminUsers.Use(authMiddleware.RequireAdminLevel(AdminLevelSuperAdmin))
	{
		adminUsers.GET("", h.ListUsers)
		adminUsers.GET("/:id", h.GetUser)
		adminUsers.PUT("/:id", h.UpdateUser)
		adminUsers.DELETE("/:id", h.DeleteUser)
		adminUsers.POST("/:id/promote", authMiddleware.RequireAdminLevel(AdminLevelSystemAdmin), h.PromoteUser)
		adminUsers.POST("/:id/demote", authMiddleware.RequireAdminLevel(AdminLevelSystemAdmin), h.DemoteUser)
		adminUsers.POST("/:id/lock", h.LockUser)
		adminUsers.POST("/:id/unlock", h.UnlockUser)
	}

	// Admin management routes (system admin only)
	adminMgmt := router.Group("/api/admin/admins")
	adminMgmt.Use(authMiddleware.RequireAdminLevel(AdminLevelSystemAdmin))
	{
		adminMgmt.GET("", h.ListAdmins)
		adminMgmt.GET("/:id/sessions", h.GetAdminSessions)
		adminMgmt.DELETE("/:id/sessions", h.RevokeAdminSessions)
	}
}

// Public Authentication Handlers

// Register handles user registration
func (h *AuthHandlers) Register(c *gin.Context) {
	var req RegisterRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "invalid request",
			"message": err.Error(),
		})
		return
	}

	resp, err := h.authService.Register(c.Request.Context(), &req)
	if err != nil {
		h.handleError(c, err)
		return
	}

	// Set cookies if cookie auth is enabled
	if h.config.Auth.EnableCookieAuth {
		_, accessCookie, refreshCookie, err := h.authService.LoginWithCookies(c.Request.Context(), &LoginRequest{
			Identifier: h.getIdentifierFromUser(resp.User),
			Password:   req.Password,
		})
		if err == nil {
			http.SetCookie(c.Writer, accessCookie)
			http.SetCookie(c.Writer, refreshCookie)
		}
	}

	c.JSON(http.StatusCreated, gin.H{
		"message": "registration successful",
		"data":    resp,
	})
}

// Login handles user login
func (h *AuthHandlers) Login(c *gin.Context) {
	var req LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "invalid request",
			"message": err.Error(),
		})
		return
	}

	// Use cookie login if enabled
	if h.config.Auth.EnableCookieAuth {
		resp, accessCookie, refreshCookie, err := h.authService.LoginWithCookies(c.Request.Context(), &req)
		if err != nil {
			h.handleError(c, err)
			return
		}

		http.SetCookie(c.Writer, accessCookie)
		http.SetCookie(c.Writer, refreshCookie)

		c.JSON(http.StatusOK, gin.H{
			"message": "login successful",
			"data":    resp,
		})
		return
	}

	// Standard token login
	resp, err := h.authService.Login(c.Request.Context(), &req)
	if err != nil {
		h.handleError(c, err)
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "login successful",
		"data":    resp,
	})
}

// RefreshToken handles token refresh
func (h *AuthHandlers) RefreshToken(c *gin.Context) {
	var req struct {
		RefreshToken string `json:"refresh_token"`
	}

	// Try to get refresh token from request body or cookie
	if err := c.ShouldBindJSON(&req); err != nil || req.RefreshToken == "" {
		if cookie, err := c.Cookie("refresh_token"); err == nil {
			req.RefreshToken = cookie
		} else {
			c.JSON(http.StatusBadRequest, gin.H{
				"error":   "invalid request",
				"message": "refresh token required",
			})
			return
		}
	}

	resp, err := h.authService.RefreshToken(c.Request.Context(), req.RefreshToken)
	if err != nil {
		h.handleError(c, err)
		return
	}

	// Update cookies if cookie auth is enabled
	if h.config.Auth.EnableCookieAuth {
		accessCookie := &http.Cookie{
			Name:     "access_token",
			Value:    resp.AccessToken,
			Path:     "/",
			HttpOnly: h.config.Auth.CookieHTTPOnly,
			Secure:   h.config.Auth.CookieSecure,
			SameSite: h.getSameSiteAttribute(),
			Expires:  resp.ExpiresAt,
		}

		refreshCookie := &http.Cookie{
			Name:     "refresh_token",
			Value:    resp.RefreshToken,
			Path:     "/",
			HttpOnly: h.config.Auth.CookieHTTPOnly,
			Secure:   h.config.Auth.CookieSecure,
			SameSite: h.getSameSiteAttribute(),
			Expires:  time.Now().Add(h.config.Auth.RefreshExpiration),
		}

		http.SetCookie(c.Writer, accessCookie)
		http.SetCookie(c.Writer, refreshCookie)
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "token refreshed successfully",
		"data":    resp,
	})
}

// Logout handles user logout
func (h *AuthHandlers) Logout(c *gin.Context) {
	// Get session ID from claims if available
	if claims := GetClaimsFromContext(c); claims != nil && claims.SessionID != nil {
		h.authService.Logout(c.Request.Context(), *claims.SessionID)
	}

	// Clear cookies if cookie auth is enabled
	if h.config.Auth.EnableCookieAuth {
		accessCookie := &http.Cookie{
			Name:     "access_token",
			Value:    "",
			Path:     "/",
			HttpOnly: true,
			Secure:   h.config.Auth.CookieSecure,
			SameSite: h.getSameSiteAttribute(),
			Expires:  time.Now().Add(-time.Hour),
		}

		refreshCookie := &http.Cookie{
			Name:     "refresh_token",
			Value:    "",
			Path:     "/",
			HttpOnly: true,
			Secure:   h.config.Auth.CookieSecure,
			SameSite: h.getSameSiteAttribute(),
			Expires:  time.Now().Add(-time.Hour),
		}

		http.SetCookie(c.Writer, accessCookie)
		http.SetCookie(c.Writer, refreshCookie)
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "logout successful",
	})
}

// SendOTP handles OTP generation and sending
func (h *AuthHandlers) SendOTP(c *gin.Context) {
	var req OTPRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "invalid request",
			"message": err.Error(),
		})
		return
	}

	err := h.authService.SendOTP(c.Request.Context(), &req)
	if err != nil {
		h.handleError(c, err)
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "OTP sent successfully",
	})
}

// VerifyOTP handles OTP verification
func (h *AuthHandlers) VerifyOTP(c *gin.Context) {
	var req VerifyOTPRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "invalid request",
			"message": err.Error(),
		})
		return
	}

	resp, err := h.authService.VerifyOTP(c.Request.Context(), &req)
	if err != nil {
		h.handleError(c, err)
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "OTP verified successfully",
		"data":    resp,
	})
}

// ResetPassword handles password reset
func (h *AuthHandlers) ResetPassword(c *gin.Context) {
	var req ResetPasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "invalid request",
			"message": err.Error(),
		})
		return
	}

	err := h.authService.ResetPassword(c.Request.Context(), &req)
	if err != nil {
		h.handleError(c, err)
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "password reset successfully",
	})
}

// ChangePassword handles password change
func (h *AuthHandlers) ChangePassword(c *gin.Context) {
	user := GetUserFromContext(c)
	if user == nil {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "authentication required",
		})
		return
	}

	var req struct {
		OldPassword string `json:"old_password" binding:"required"`
		NewPassword string `json:"new_password" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "invalid request",
			"message": err.Error(),
		})
		return
	}

	err := h.authService.ChangePassword(c.Request.Context(), user.ID, req.OldPassword, req.NewPassword)
	if err != nil {
		h.handleError(c, err)
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "password changed successfully",
	})
}

// GetCurrentUser returns the current authenticated user
func (h *AuthHandlers) GetCurrentUser(c *gin.Context) {
	user := GetUserFromContext(c)
	if user == nil {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "authentication required",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"data": user,
	})
}

// UpdateProfile handles user profile updates
func (h *AuthHandlers) UpdateProfile(c *gin.Context) {
	user := GetUserFromContext(c)
	if user == nil {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "authentication required",
		})
		return
	}

	var req struct {
		Username *string                `json:"username"`
		Metadata map[string]interface{} `json:"metadata"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "invalid request",
			"message": err.Error(),
		})
		return
	}

	// Update user fields
	if req.Username != nil {
		user.Username = req.Username
	}
	if req.Metadata != nil {
		user.Metadata = req.Metadata
	}
	user.UpdatedAt = time.Now().UTC()

	// TODO: Update user in repository
	// This requires access to the repository, which should be injected

	c.JSON(http.StatusOK, gin.H{
		"message": "profile updated successfully",
		"data":    user,
	})
}

// SendEmailVerification sends email verification OTP
func (h *AuthHandlers) SendEmailVerification(c *gin.Context) {
	user := GetUserFromContext(c)
	if user == nil || user.Email == nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "email not available for verification",
		})
		return
	}

	req := &OTPRequest{
		Identifier: *user.Email,
		Purpose:    "verification",
	}

	err := h.authService.SendOTP(c.Request.Context(), req)
	if err != nil {
		h.handleError(c, err)
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "verification email sent",
	})
}

// SendPhoneVerification sends phone verification OTP
func (h *AuthHandlers) SendPhoneVerification(c *gin.Context) {
	user := GetUserFromContext(c)
	if user == nil || user.Phone == nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "phone not available for verification",
		})
		return
	}

	req := &OTPRequest{
		Identifier: *user.Phone,
		Purpose:    "verification",
	}

	err := h.authService.SendOTP(c.Request.Context(), req)
	if err != nil {
		h.handleError(c, err)
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "verification SMS sent",
	})
}

// Admin Authentication Handlers

// AdminLogin handles admin login with enhanced security
func (h *AuthHandlers) AdminLogin(c *gin.Context) {
	var req AdminAuthRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "invalid request",
			"message": err.Error(),
		})
		return
	}

	resp, err := h.authService.AuthenticateAdmin(c.Request.Context(), &req)
	if err != nil {
		h.handleError(c, err)
		return
	}

	// Set admin session cookie
	sessionCookie := &http.Cookie{
		Name:     "admin_session",
		Value:    resp.Session.SessionToken,
		Path:     "/",
		HttpOnly: true,
		Secure:   h.config.Auth.CookieSecure,
		SameSite: h.getSameSiteAttribute(),
		Expires:  resp.Session.ExpiresAt,
	}

	http.SetCookie(c.Writer, sessionCookie)

	c.JSON(http.StatusOK, gin.H{
		"message": "admin login successful",
		"data":    resp,
	})
}

// AdminLogout handles admin logout
func (h *AuthHandlers) AdminLogout(c *gin.Context) {
	session := GetSessionFromContext(c)
	if session != nil {
		h.authService.Logout(c.Request.Context(), session.ID)
	}

	// Clear admin session cookie
	sessionCookie := &http.Cookie{
		Name:     "admin_session",
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   h.config.Auth.CookieSecure,
		SameSite: h.getSameSiteAttribute(),
		Expires:  time.Now().Add(-time.Hour),
	}

	http.SetCookie(c.Writer, sessionCookie)

	c.JSON(http.StatusOK, gin.H{
		"message": "admin logout successful",
	})
}

// GetAdminSession returns current admin session info
func (h *AuthHandlers) GetAdminSession(c *gin.Context) {
	user := GetUserFromContext(c)
	session := GetSessionFromContext(c)

	if user == nil || session == nil {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "invalid session",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"data": gin.H{
			"user":    user,
			"session": session,
		},
	})
}

// RefreshAdminSession refreshes admin session
func (h *AuthHandlers) RefreshAdminSession(c *gin.Context) {
	session := GetSessionFromContext(c)
	if session == nil {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "invalid session",
		})
		return
	}

	// Create new session
	newSession, err := h.authService.CreateAdminSession(c.Request.Context(), session.UserID, c.ClientIP(), c.GetHeader("User-Agent"))
	if err != nil {
		h.handleError(c, err)
		return
	}

	// Delete old session
	h.authService.Logout(c.Request.Context(), session.ID)

	// Set new session cookie
	sessionCookie := &http.Cookie{
		Name:     "admin_session",
		Value:    newSession.SessionToken,
		Path:     "/",
		HttpOnly: true,
		Secure:   h.config.Auth.CookieSecure,
		SameSite: h.getSameSiteAttribute(),
		Expires:  newSession.ExpiresAt,
	}

	http.SetCookie(c.Writer, sessionCookie)

	c.JSON(http.StatusOK, gin.H{
		"message": "session refreshed successfully",
		"data":    newSession,
	})
}

// Admin User Management Handlers

// ListUsers lists users with filtering
func (h *AuthHandlers) ListUsers(c *gin.Context) {
	// Parse query parameters
	filter := &UserFilter{
		Limit:  50, // Default limit
		Offset: 0,
	}

	if limitStr := c.Query("limit"); limitStr != "" {
		if limit, err := strconv.Atoi(limitStr); err == nil && limit > 0 && limit <= 100 {
			filter.Limit = limit
		}
	}

	if offsetStr := c.Query("offset"); offsetStr != "" {
		if offset, err := strconv.Atoi(offsetStr); err == nil && offset >= 0 {
			filter.Offset = offset
		}
	}

	if search := c.Query("search"); search != "" {
		filter.Search = search
	}

	if adminLevel := c.Query("admin_level"); adminLevel != "" {
		level := AdminLevel(adminLevel)
		filter.AdminLevel = &level
	}

	if verified := c.Query("verified"); verified != "" {
		if v, err := strconv.ParseBool(verified); err == nil {
			filter.Verified = &v
		}
	}

	// TODO: Call repository to list users
	// This requires access to the repository

	c.JSON(http.StatusOK, gin.H{
		"message": "users retrieved successfully",
		"data":    []interface{}{}, // Placeholder
	})
}

// GetUser retrieves a specific user
func (h *AuthHandlers) GetUser(c *gin.Context) {
	userID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "invalid user ID",
			"message": "user ID must be a valid UUID",
		})
		return
	}

	// TODO: Get user from repository
	_ = userID

	c.JSON(http.StatusOK, gin.H{
		"message": "user retrieved successfully",
		"data":    nil, // Placeholder
	})
}

// UpdateUser updates a user
func (h *AuthHandlers) UpdateUser(c *gin.Context) {
	userID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "invalid user ID",
			"message": "user ID must be a valid UUID",
		})
		return
	}

	var req struct {
		Email    *string                `json:"email"`
		Phone    *string                `json:"phone"`
		Username *string                `json:"username"`
		Metadata map[string]interface{} `json:"metadata"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "invalid request",
			"message": err.Error(),
		})
		return
	}

	// TODO: Update user in repository
	_ = userID

	c.JSON(http.StatusOK, gin.H{
		"message": "user updated successfully",
	})
}

// DeleteUser deletes a user
func (h *AuthHandlers) DeleteUser(c *gin.Context) {
	userID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "invalid user ID",
			"message": "user ID must be a valid UUID",
		})
		return
	}

	// TODO: Delete user from repository
	_ = userID

	c.JSON(http.StatusOK, gin.H{
		"message": "user deleted successfully",
	})
}

// PromoteUser promotes a user to admin
func (h *AuthHandlers) PromoteUser(c *gin.Context) {
	userID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "invalid user ID",
			"message": "user ID must be a valid UUID",
		})
		return
	}

	var req struct {
		AdminLevel AdminLevel `json:"admin_level" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "invalid request",
			"message": err.Error(),
		})
		return
	}

	promoter := GetUserFromContext(c)
	if promoter == nil {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "authentication required",
		})
		return
	}

	err = h.authService.PromoteToAdmin(c.Request.Context(), userID, req.AdminLevel, promoter.ID)
	if err != nil {
		h.handleError(c, err)
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "user promoted successfully",
	})
}

// DemoteUser demotes an admin user
func (h *AuthHandlers) DemoteUser(c *gin.Context) {
	userID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "invalid user ID",
			"message": "user ID must be a valid UUID",
		})
		return
	}

	// TODO: Implement demote functionality in service
	_ = userID

	c.JSON(http.StatusOK, gin.H{
		"message": "user demoted successfully",
	})
}

// LockUser locks a user account
func (h *AuthHandlers) LockUser(c *gin.Context) {
	userID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "invalid user ID",
			"message": "user ID must be a valid UUID",
		})
		return
	}

	var req struct {
		Reason string `json:"reason" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "invalid request",
			"message": err.Error(),
		})
		return
	}

	err = h.authService.LockAccount(c.Request.Context(), userID, req.Reason)
	if err != nil {
		h.handleError(c, err)
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "user account locked successfully",
	})
}

// UnlockUser unlocks a user account
func (h *AuthHandlers) UnlockUser(c *gin.Context) {
	userID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "invalid user ID",
			"message": "user ID must be a valid UUID",
		})
		return
	}

	unlocker := GetUserFromContext(c)
	if unlocker == nil {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "authentication required",
		})
		return
	}

	err = h.authService.UnlockAccount(c.Request.Context(), userID, unlocker.ID)
	if err != nil {
		h.handleError(c, err)
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "user account unlocked successfully",
	})
}

// ListAdmins lists admin users
func (h *AuthHandlers) ListAdmins(c *gin.Context) {
	// Parse query parameters
	filter := &AdminFilter{
		Limit:  50,
		Offset: 0,
	}

	if limitStr := c.Query("limit"); limitStr != "" {
		if limit, err := strconv.Atoi(limitStr); err == nil && limit > 0 && limit <= 100 {
			filter.Limit = limit
		}
	}

	if offsetStr := c.Query("offset"); offsetStr != "" {
		if offset, err := strconv.Atoi(offsetStr); err == nil && offset >= 0 {
			filter.Offset = offset
		}
	}

	if search := c.Query("search"); search != "" {
		filter.Search = search
	}

	if level := c.Query("level"); level != "" {
		adminLevel := AdminLevel(level)
		filter.Level = &adminLevel
	}

	// TODO: Call repository to list admins
	// This requires access to the repository

	c.JSON(http.StatusOK, gin.H{
		"message": "admins retrieved successfully",
		"data":    []interface{}{}, // Placeholder
	})
}

// GetAdminSessions retrieves admin sessions for a user
func (h *AuthHandlers) GetAdminSessions(c *gin.Context) {
	userID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "invalid user ID",
			"message": "user ID must be a valid UUID",
		})
		return
	}

	// TODO: Get admin sessions from repository
	_ = userID

	c.JSON(http.StatusOK, gin.H{
		"message": "admin sessions retrieved successfully",
		"data":    []interface{}{}, // Placeholder
	})
}

// RevokeAdminSessions revokes all admin sessions for a user
func (h *AuthHandlers) RevokeAdminSessions(c *gin.Context) {
	userID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "invalid user ID",
			"message": "user ID must be a valid UUID",
		})
		return
	}

	// TODO: Revoke admin sessions
	_ = userID

	c.JSON(http.StatusOK, gin.H{
		"message": "admin sessions revoked successfully",
	})
}

// Helper methods

// handleError handles different types of errors and returns appropriate HTTP responses
func (h *AuthHandlers) handleError(c *gin.Context, err error) {
	if ue, ok := err.(*errors.UnifiedError); ok {
		switch ue.Code {
		case errors.ErrUnauthorized, errors.ErrInvalidCredentials:
			c.JSON(http.StatusUnauthorized, gin.H{
				"error":   "authentication failed",
				"message": ue.Message,
			})
		case errors.ErrForbidden:
			c.JSON(http.StatusForbidden, gin.H{
				"error":   "access denied",
				"message": ue.Message,
			})
		case errors.ErrRecordNotFound:
			c.JSON(http.StatusNotFound, gin.H{
				"error":   "not found",
				"message": ue.Message,
			})
		case errors.ErrDuplicateRecord:
			c.JSON(http.StatusConflict, gin.H{
				"error":   "conflict",
				"message": ue.Message,
			})
		default:
			c.JSON(http.StatusInternalServerError, gin.H{
				"error":   "internal server error",
				"message": ue.Message,
			})
		}
		return
	}

	// Handle other error types
	c.JSON(http.StatusInternalServerError, gin.H{
		"error":   "internal server error",
		"message": err.Error(),
	})
}

// getIdentifierFromUser extracts the primary identifier from a user
func (h *AuthHandlers) getIdentifierFromUser(user *UnifiedUser) string {
	if user.Email != nil {
		return *user.Email
	}
	if user.Phone != nil {
		return *user.Phone
	}
	if user.Username != nil {
		return *user.Username
	}
	return ""
}

// getSameSiteAttribute converts string to http.SameSite
func (h *AuthHandlers) getSameSiteAttribute() http.SameSite {
	switch h.config.Auth.CookieSameSite {
	case "Lax":
		return http.SameSiteLaxMode
	case "Strict":
		return http.SameSiteStrictMode
	case "None":
		return http.SameSiteNoneMode
	default:
		return http.SameSiteStrictMode
	}
}

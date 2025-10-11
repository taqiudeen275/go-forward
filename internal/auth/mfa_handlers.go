package auth

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/taqiudeen275/go-foward/pkg/errors"
)

// MFAHandlers provides HTTP handlers for MFA operations
type MFAHandlers struct {
	authService AuthService
}

// NewMFAHandlers creates new MFA handlers
func NewMFAHandlers(authService AuthService) *MFAHandlers {
	return &MFAHandlers{
		authService: authService,
	}
}

// SetupMFARequest represents the request to setup MFA
type SetupMFARequest struct {
	Issuer      string `json:"issuer" binding:"required"`
	AccountName string `json:"account_name" binding:"required"`
}

// SetupMFAResponse represents the response for MFA setup
type SetupMFAResponse struct {
	Secret    string `json:"secret"`
	QRCode    string `json:"qr_code"`
	BackupURL string `json:"backup_url"`
}

// EnableMFARequest represents the request to enable MFA
type EnableMFARequest struct {
	TOTPCode string `json:"totp_code" binding:"required"`
}

// EnableMFAResponse represents the response for enabling MFA
type EnableMFAResponse struct {
	BackupCodes []string `json:"backup_codes"`
	Message     string   `json:"message"`
}

// DisableMFARequest represents the request to disable MFA
type DisableMFARequest struct {
	TOTPCode string `json:"totp_code" binding:"required"`
}

// VerifyMFARequest represents the request to verify MFA
type VerifyMFARequest struct {
	Code string `json:"code" binding:"required"`
}

// GenerateBackupCodesResponse represents the response for generating backup codes
type GenerateBackupCodesResponse struct {
	BackupCodes []string `json:"backup_codes"`
	Message     string   `json:"message"`
}

// SetupMFA generates a new TOTP secret for MFA setup
// @Summary Setup MFA for user
// @Description Generate TOTP secret and QR code for MFA setup
// @Tags MFA
// @Accept json
// @Produce json
// @Param request body SetupMFARequest true "Setup MFA request"
// @Success 200 {object} SetupMFAResponse
// @Failure 400 {object} errors.ErrorResponse
// @Failure 401 {object} errors.ErrorResponse
// @Failure 500 {object} errors.ErrorResponse
// @Security BearerAuth
// @Router /auth/mfa/setup [post]
func (h *MFAHandlers) SetupMFA(c *gin.Context) {
	// Get user from context (set by auth middleware)
	userID, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}

	userUUID, ok := userID.(uuid.UUID)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid user ID"})
		return
	}

	var req SetupMFARequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Generate TOTP secret
	setup, err := h.authService.GenerateTOTPSecret(c.Request.Context(), userUUID, req.Issuer, req.AccountName)
	if err != nil {
		if errors.IsAuthError(err) {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to setup MFA"})
		return
	}

	response := SetupMFAResponse{
		Secret:    setup.Secret,
		QRCode:    setup.QRCode,
		BackupURL: setup.BackupURL,
	}

	c.JSON(http.StatusOK, response)
}

// EnableMFA enables MFA for the user after verifying TOTP code
// @Summary Enable MFA for user
// @Description Enable MFA after verifying TOTP code
// @Tags MFA
// @Accept json
// @Produce json
// @Param request body EnableMFARequest true "Enable MFA request"
// @Success 200 {object} EnableMFAResponse
// @Failure 400 {object} errors.ErrorResponse
// @Failure 401 {object} errors.ErrorResponse
// @Failure 500 {object} errors.ErrorResponse
// @Security BearerAuth
// @Router /auth/mfa/enable [post]
func (h *MFAHandlers) EnableMFA(c *gin.Context) {
	// Get user from context
	userID, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}

	userUUID, ok := userID.(uuid.UUID)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid user ID"})
		return
	}

	var req EnableMFARequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Enable MFA
	if err := h.authService.EnableMFA(c.Request.Context(), userUUID, req.TOTPCode); err != nil {
		if errors.IsAuthError(err) {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to enable MFA"})
		return
	}

	// Generate backup codes
	backupCodes, err := h.authService.GenerateBackupCodes(c.Request.Context(), userUUID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "MFA enabled but failed to generate backup codes"})
		return
	}

	response := EnableMFAResponse{
		BackupCodes: backupCodes,
		Message:     "MFA enabled successfully. Please save these backup codes in a secure location.",
	}

	c.JSON(http.StatusOK, response)
}

// DisableMFA disables MFA for the user after verifying TOTP code
// @Summary Disable MFA for user
// @Description Disable MFA after verifying TOTP code
// @Tags MFA
// @Accept json
// @Produce json
// @Param request body DisableMFARequest true "Disable MFA request"
// @Success 200 {object} map[string]string
// @Failure 400 {object} errors.ErrorResponse
// @Failure 401 {object} errors.ErrorResponse
// @Failure 500 {object} errors.ErrorResponse
// @Security BearerAuth
// @Router /auth/mfa/disable [post]
func (h *MFAHandlers) DisableMFA(c *gin.Context) {
	// Get user from context
	userID, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}

	userUUID, ok := userID.(uuid.UUID)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid user ID"})
		return
	}

	var req DisableMFARequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Disable MFA
	if err := h.authService.DisableMFA(c.Request.Context(), userUUID, req.TOTPCode); err != nil {
		if errors.IsAuthError(err) {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to disable MFA"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "MFA disabled successfully"})
}

// VerifyMFA verifies an MFA code (TOTP or backup code)
// @Summary Verify MFA code
// @Description Verify TOTP or backup code for MFA
// @Tags MFA
// @Accept json
// @Produce json
// @Param request body VerifyMFARequest true "Verify MFA request"
// @Success 200 {object} map[string]string
// @Failure 400 {object} errors.ErrorResponse
// @Failure 401 {object} errors.ErrorResponse
// @Failure 500 {object} errors.ErrorResponse
// @Security BearerAuth
// @Router /auth/mfa/verify [post]
func (h *MFAHandlers) VerifyMFA(c *gin.Context) {
	// Get user from context
	userID, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}

	userUUID, ok := userID.(uuid.UUID)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid user ID"})
		return
	}

	var req VerifyMFARequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Verify MFA code
	if err := h.authService.VerifyMFACode(c.Request.Context(), userUUID, req.Code); err != nil {
		if errors.IsAuthError(err) {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to verify MFA code"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "MFA code verified successfully"})
}

// GenerateBackupCodes generates new backup codes for the user
// @Summary Generate backup codes
// @Description Generate new backup codes for MFA
// @Tags MFA
// @Produce json
// @Success 200 {object} GenerateBackupCodesResponse
// @Failure 400 {object} errors.ErrorResponse
// @Failure 401 {object} errors.ErrorResponse
// @Failure 500 {object} errors.ErrorResponse
// @Security BearerAuth
// @Router /auth/mfa/backup-codes [post]
func (h *MFAHandlers) GenerateBackupCodes(c *gin.Context) {
	// Get user from context
	userID, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}

	userUUID, ok := userID.(uuid.UUID)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid user ID"})
		return
	}

	// Generate backup codes
	backupCodes, err := h.authService.GenerateBackupCodes(c.Request.Context(), userUUID)
	if err != nil {
		if errors.IsAuthError(err) {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to generate backup codes"})
		return
	}

	response := GenerateBackupCodesResponse{
		BackupCodes: backupCodes,
		Message:     "New backup codes generated. Please save these in a secure location. Previous backup codes are now invalid.",
	}

	c.JSON(http.StatusOK, response)
}

// GetMFAStatus returns the MFA status for the current user
// @Summary Get MFA status
// @Description Get MFA status and requirements for current user
// @Tags MFA
// @Produce json
// @Success 200 {object} map[string]interface{}
// @Failure 401 {object} errors.ErrorResponse
// @Failure 500 {object} errors.ErrorResponse
// @Security BearerAuth
// @Router /auth/mfa/status [get]
func (h *MFAHandlers) GetMFAStatus(c *gin.Context) {
	// Get user from context
	userID, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}

	userUUID, ok := userID.(uuid.UUID)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid user ID"})
		return
	}

	// Get user details (this would need to be added to the auth service)
	// For now, we'll return a basic status
	c.JSON(http.StatusOK, gin.H{
		"user_id":            userUUID,
		"mfa_enabled":        false, // This would be fetched from the user record
		"mfa_required":       false, // This would be determined by user role
		"backup_codes_count": 0,     // This would be the count of remaining backup codes
	})
}

// RegisterMFARoutes registers MFA routes with the router
func RegisterMFARoutes(router *gin.RouterGroup, authService AuthService, authMiddleware gin.HandlerFunc) {
	handlers := NewMFAHandlers(authService)

	mfa := router.Group("/mfa")
	mfa.Use(authMiddleware) // Require authentication for all MFA endpoints
	{
		mfa.POST("/setup", handlers.SetupMFA)
		mfa.POST("/enable", handlers.EnableMFA)
		mfa.POST("/disable", handlers.DisableMFA)
		mfa.POST("/verify", handlers.VerifyMFA)
		mfa.POST("/backup-codes", handlers.GenerateBackupCodes)
		mfa.GET("/status", handlers.GetMFAStatus)
	}
}

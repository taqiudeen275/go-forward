package auth

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/taqiudeen275/go-foward/pkg/errors"
)

// OTPHandlers provides HTTP handlers for OTP operations
type OTPHandlers struct {
	authService AuthService
}

// NewOTPHandlers creates new OTP handlers
func NewOTPHandlers(authService AuthService) *OTPHandlers {
	return &OTPHandlers{
		authService: authService,
	}
}

// SendOTPHandler handles OTP generation and sending
// @Summary Send OTP code
// @Description Generates and sends an OTP code via email or SMS
// @Tags Authentication
// @Accept json
// @Produce json
// @Param request body OTPRequest true "OTP request"
// @Success 200 {object} map[string]interface{} "OTP sent successfully"
// @Failure 400 {object} map[string]interface{} "Bad request"
// @Failure 429 {object} map[string]interface{} "Rate limit exceeded"
// @Failure 500 {object} map[string]interface{} "Internal server error"
// @Router /auth/otp/send [post]
func (h *OTPHandlers) SendOTPHandler(c *gin.Context) {
	var req OTPRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "Invalid request format",
			"details": err.Error(),
		})
		return
	}

	// Send OTP
	if err := h.authService.SendOTP(c.Request.Context(), &req); err != nil {
		switch {
		case errors.IsValidationError(err):
			c.JSON(http.StatusBadRequest, gin.H{
				"error":   "Validation failed",
				"details": err.Error(),
			})
		case errors.IsRateLimitError(err):
			c.JSON(http.StatusTooManyRequests, gin.H{
				"error":   "Rate limit exceeded",
				"details": err.Error(),
			})
		default:
			c.JSON(http.StatusInternalServerError, gin.H{
				"error":   "Failed to send OTP",
				"details": err.Error(),
			})
		}
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "OTP sent successfully",
		"success": true,
	})
}

// VerifyOTPHandler handles OTP verification
// @Summary Verify OTP code
// @Description Verifies an OTP code and returns authentication tokens
// @Tags Authentication
// @Accept json
// @Produce json
// @Param request body VerifyOTPRequest true "OTP verification request"
// @Success 200 {object} AuthResponse "Authentication successful"
// @Failure 400 {object} map[string]interface{} "Bad request"
// @Failure 401 {object} map[string]interface{} "Invalid OTP"
// @Failure 500 {object} map[string]interface{} "Internal server error"
// @Router /auth/otp/verify [post]
func (h *OTPHandlers) VerifyOTPHandler(c *gin.Context) {
	var req VerifyOTPRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "Invalid request format",
			"details": err.Error(),
		})
		return
	}

	// Verify OTP
	response, err := h.authService.VerifyOTP(c.Request.Context(), &req)
	if err != nil {
		switch {
		case errors.IsValidationError(err):
			c.JSON(http.StatusBadRequest, gin.H{
				"error":   "Validation failed",
				"details": err.Error(),
			})
		case errors.IsAuthError(err):
			c.JSON(http.StatusUnauthorized, gin.H{
				"error":   "Authentication failed",
				"details": err.Error(),
			})
		default:
			c.JSON(http.StatusInternalServerError, gin.H{
				"error":   "Failed to verify OTP",
				"details": err.Error(),
			})
		}
		return
	}

	c.JSON(http.StatusOK, response)
}

// LoginWithOTPHandler handles OTP-based login
// @Summary Login with OTP
// @Description Initiates OTP-based login by sending OTP to user's email or phone
// @Tags Authentication
// @Accept json
// @Produce json
// @Param request body OTPLoginRequest true "OTP login request"
// @Success 200 {object} map[string]interface{} "OTP sent for login"
// @Failure 400 {object} map[string]interface{} "Bad request"
// @Failure 404 {object} map[string]interface{} "User not found"
// @Failure 429 {object} map[string]interface{} "Rate limit exceeded"
// @Failure 500 {object} map[string]interface{} "Internal server error"
// @Router /auth/login/otp [post]
func (h *OTPHandlers) LoginWithOTPHandler(c *gin.Context) {
	var req OTPLoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "Invalid request format",
			"details": err.Error(),
		})
		return
	}

	// Create OTP request for login
	otpReq := &OTPRequest{
		Identifier: req.Identifier,
		Purpose:    "login",
	}

	// Send OTP
	if err := h.authService.SendOTP(c.Request.Context(), otpReq); err != nil {
		switch {
		case errors.IsValidationError(err):
			c.JSON(http.StatusBadRequest, gin.H{
				"error":   "Validation failed",
				"details": err.Error(),
			})
		case errors.IsNotFoundError(err):
			c.JSON(http.StatusNotFound, gin.H{
				"error":   "User not found",
				"details": "No account found with this identifier",
			})
		case errors.IsRateLimitError(err):
			c.JSON(http.StatusTooManyRequests, gin.H{
				"error":   "Rate limit exceeded",
				"details": err.Error(),
			})
		default:
			c.JSON(http.StatusInternalServerError, gin.H{
				"error":   "Failed to send login OTP",
				"details": err.Error(),
			})
		}
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message":    "Login OTP sent successfully",
		"success":    true,
		"identifier": req.Identifier,
	})
}

// RegisterWithOTPHandler handles OTP-based registration
// @Summary Register with OTP
// @Description Initiates OTP-based registration by sending OTP to user's email or phone
// @Tags Authentication
// @Accept json
// @Produce json
// @Param request body OTPRegistrationRequest true "OTP registration request"
// @Success 200 {object} map[string]interface{} "OTP sent for registration"
// @Failure 400 {object} map[string]interface{} "Bad request"
// @Failure 409 {object} map[string]interface{} "User already exists"
// @Failure 429 {object} map[string]interface{} "Rate limit exceeded"
// @Failure 500 {object} map[string]interface{} "Internal server error"
// @Router /auth/register/otp [post]
func (h *OTPHandlers) RegisterWithOTPHandler(c *gin.Context) {
	var req OTPRegistrationRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "Invalid request format",
			"details": err.Error(),
		})
		return
	}

	// Create OTP request for registration
	otpReq := &OTPRequest{
		Identifier: req.Identifier,
		Purpose:    "registration",
	}

	// Send OTP
	if err := h.authService.SendOTP(c.Request.Context(), otpReq); err != nil {
		switch {
		case errors.IsValidationError(err):
			c.JSON(http.StatusBadRequest, gin.H{
				"error":   "Validation failed",
				"details": err.Error(),
			})
		case errors.IsConflictError(err):
			c.JSON(http.StatusConflict, gin.H{
				"error":   "User already exists",
				"details": "An account with this identifier already exists",
			})
		case errors.IsRateLimitError(err):
			c.JSON(http.StatusTooManyRequests, gin.H{
				"error":   "Rate limit exceeded",
				"details": err.Error(),
			})
		default:
			c.JSON(http.StatusInternalServerError, gin.H{
				"error":   "Failed to send registration OTP",
				"details": err.Error(),
			})
		}
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message":    "Registration OTP sent successfully",
		"success":    true,
		"identifier": req.Identifier,
	})
}

// VerifyEmailHandler handles email verification with OTP
// @Summary Verify email with OTP
// @Description Verifies user's email address using OTP
// @Tags Authentication
// @Accept json
// @Produce json
// @Param request body VerifyOTPRequest true "Email verification request"
// @Success 200 {object} map[string]interface{} "Email verified successfully"
// @Failure 400 {object} map[string]interface{} "Bad request"
// @Failure 401 {object} map[string]interface{} "Invalid OTP"
// @Failure 500 {object} map[string]interface{} "Internal server error"
// @Router /auth/verify/email [post]
func (h *OTPHandlers) VerifyEmailHandler(c *gin.Context) {
	var req VerifyOTPRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "Invalid request format",
			"details": err.Error(),
		})
		return
	}

	// Set purpose to verification
	req.Purpose = "verification"

	// Verify OTP
	response, err := h.authService.VerifyOTP(c.Request.Context(), &req)
	if err != nil {
		switch {
		case errors.IsValidationError(err):
			c.JSON(http.StatusBadRequest, gin.H{
				"error":   "Validation failed",
				"details": err.Error(),
			})
		case errors.IsAuthError(err):
			c.JSON(http.StatusUnauthorized, gin.H{
				"error":   "Verification failed",
				"details": err.Error(),
			})
		default:
			c.JSON(http.StatusInternalServerError, gin.H{
				"error":   "Failed to verify email",
				"details": err.Error(),
			})
		}
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message":        "Email verified successfully",
		"success":        true,
		"email_verified": response.User.EmailVerified,
		"phone_verified": response.User.PhoneVerified,
	})
}

// SendVerificationOTPHandler sends OTP for email/phone verification
// @Summary Send verification OTP
// @Description Sends OTP for email or phone verification
// @Tags Authentication
// @Accept json
// @Produce json
// @Param request body OTPRequest true "Verification OTP request"
// @Success 200 {object} map[string]interface{} "Verification OTP sent"
// @Failure 400 {object} map[string]interface{} "Bad request"
// @Failure 429 {object} map[string]interface{} "Rate limit exceeded"
// @Failure 500 {object} map[string]interface{} "Internal server error"
// @Router /auth/verify/send [post]
func (h *OTPHandlers) SendVerificationOTPHandler(c *gin.Context) {
	var req OTPRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "Invalid request format",
			"details": err.Error(),
		})
		return
	}

	// Set purpose to verification
	req.Purpose = "verification"

	// Send OTP
	if err := h.authService.SendOTP(c.Request.Context(), &req); err != nil {
		switch {
		case errors.IsValidationError(err):
			c.JSON(http.StatusBadRequest, gin.H{
				"error":   "Validation failed",
				"details": err.Error(),
			})
		case errors.IsRateLimitError(err):
			c.JSON(http.StatusTooManyRequests, gin.H{
				"error":   "Rate limit exceeded",
				"details": err.Error(),
			})
		default:
			c.JSON(http.StatusInternalServerError, gin.H{
				"error":   "Failed to send verification OTP",
				"details": err.Error(),
			})
		}
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Verification OTP sent successfully",
		"success": true,
	})
}

// OTPLoginRequest represents a request to login with OTP
type OTPLoginRequest struct {
	Identifier string `json:"identifier" binding:"required" example:"user@example.com"`
}

// OTPRegistrationRequest represents a request to register with OTP
type OTPRegistrationRequest struct {
	Identifier string `json:"identifier" binding:"required" example:"user@example.com"`
}

// RegisterOTPRoutes registers OTP-related routes
func RegisterOTPRoutes(router *gin.RouterGroup, handlers *OTPHandlers) {
	otp := router.Group("/otp")
	{
		otp.POST("/send", handlers.SendOTPHandler)
		otp.POST("/verify", handlers.VerifyOTPHandler)
	}

	// Convenience endpoints
	router.POST("/login/otp", handlers.LoginWithOTPHandler)
	router.POST("/register/otp", handlers.RegisterWithOTPHandler)

	verify := router.Group("/verify")
	{
		verify.POST("/send", handlers.SendVerificationOTPHandler)
		verify.POST("/email", handlers.VerifyEmailHandler)
	}
}

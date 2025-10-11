package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/taqiudeen275/go-foward/internal/config"
	"github.com/taqiudeen275/go-foward/internal/template"
	"github.com/taqiudeen275/go-foward/pkg/errors"
)

// OTPService handles OTP generation, delivery, and verification
type OTPService interface {
	// OTP generation and delivery
	SendOTP(ctx context.Context, req *OTPRequest) error
	VerifyOTP(ctx context.Context, req *VerifyOTPRequest) (*AuthResponse, error)

	// Rate limiting and security
	CheckOTPRateLimit(ctx context.Context, identifier string) error
	RecordOTPAttempt(ctx context.Context, identifier string, success bool) error

	// OTP management
	InvalidateOTPs(ctx context.Context, identifier string, purpose string) error
	CleanupExpiredOTPs(ctx context.Context) error
}

// otpService implements the OTPService interface
type otpService struct {
	repo           Repository
	templateSvc    *template.Service
	config         *config.Config
	rateLimitCache map[string]*RateLimitInfo // In production, use Redis
}

// RateLimitInfo tracks rate limiting for OTP requests
type RateLimitInfo struct {
	Count     int
	FirstTime time.Time
	LastTime  time.Time
}

// NewOTPService creates a new OTP service
func NewOTPService(repo Repository, templateSvc *template.Service, cfg *config.Config) OTPService {
	return &otpService{
		repo:           repo,
		templateSvc:    templateSvc,
		config:         cfg,
		rateLimitCache: make(map[string]*RateLimitInfo),
	}
}

// SendOTP generates and sends an OTP code via email or SMS
func (s *otpService) SendOTP(ctx context.Context, req *OTPRequest) error {
	// Validate request
	if err := s.validateOTPRequest(req); err != nil {
		return err
	}

	// Check rate limiting
	if err := s.CheckOTPRateLimit(ctx, req.Identifier); err != nil {
		return err
	}

	// Determine delivery method (email or phone)
	isEmail := strings.Contains(req.Identifier, "@")

	// Generate OTP code
	code, err := s.generateOTPCode()
	if err != nil {
		return errors.Wrap(err, "failed to generate OTP code")
	}

	// Prepare OTP record
	var email, phone *string
	if isEmail {
		email = &req.Identifier
	} else {
		phone = &req.Identifier
	}

	// Try to find existing user for audit purposes
	var userID *uuid.UUID
	if email != nil {
		if user, _ := s.repo.GetUserByEmail(ctx, *email); user != nil {
			userID = &user.ID
		}
	} else if phone != nil {
		if user, _ := s.repo.GetUserByPhone(ctx, *phone); user != nil {
			userID = &user.ID
		}
	}

	// Invalidate any existing OTPs for this identifier and purpose (security measure)
	if err := s.InvalidateOTPs(ctx, req.Identifier, req.Purpose); err != nil {
		return errors.Wrap(err, "failed to invalidate existing OTPs")
	}

	// Hash the OTP code for secure storage
	hashedCode := s.hashOTPCode(code)

	// Create OTP record with hashed code
	otp := &OTPCode{
		ID:          uuid.New(),
		UserID:      userID,
		Email:       email,
		Phone:       phone,
		Code:        hashedCode, // Store hashed version
		Purpose:     req.Purpose,
		MaxAttempts: 3,
		ExpiresAt:   time.Now().Add(s.config.Auth.OTPExpiration),
		CreatedAt:   time.Now().UTC(),
	}

	if err := s.repo.CreateOTP(ctx, otp); err != nil {
		return errors.Wrap(err, "failed to create OTP record")
	}

	// Send OTP via appropriate channel
	if err := s.deliverOTP(ctx, otp, req.Purpose); err != nil {
		return errors.Wrap(err, "failed to deliver OTP")
	}

	// Record rate limit attempt
	s.RecordOTPAttempt(ctx, req.Identifier, true)

	return nil
}

// VerifyOTP verifies an OTP code and returns authentication response
func (s *otpService) VerifyOTP(ctx context.Context, req *VerifyOTPRequest) (*AuthResponse, error) {
	// Validate request
	if err := s.validateVerifyOTPRequest(req); err != nil {
		return nil, err
	}

	// Get OTP by identifier and purpose
	otp, err := s.repo.GetOTPByIdentifier(ctx, req.Identifier, req.Purpose)
	if err != nil {
		return nil, errors.NewAuthError("invalid or expired OTP")
	}

	// Check if OTP is expired
	if otp.IsExpired() {
		return nil, errors.NewAuthError("OTP has expired")
	}

	// Check if OTP is already used
	if otp.IsUsed() {
		return nil, errors.NewAuthError("OTP has already been used")
	}

	// Check attempts
	if !otp.CanAttempt() {
		return nil, errors.NewAuthError("maximum OTP attempts exceeded")
	}

	// Verify code (hash the provided code and compare with stored hash)
	if !s.verifyOTPCode(req.Code, otp.Code) {
		// Increment attempts and update in database immediately
		otp.Attempts++
		if err := s.repo.UpdateOTPAttempts(ctx, otp.ID, otp.Attempts); err != nil {
			return nil, errors.Wrap(err, "failed to update OTP attempts")
		}

		// Add a small delay to prevent rapid brute force attempts
		time.Sleep(100 * time.Millisecond)

		return nil, errors.NewAuthError("invalid OTP code")
	}

	// Mark OTP as used
	if err := s.repo.MarkOTPUsed(ctx, otp.ID); err != nil {
		return nil, errors.Wrap(err, "failed to mark OTP as used")
	}

	// Handle different purposes
	return s.handleOTPVerification(ctx, otp, req)
}

// CheckOTPRateLimit checks if the identifier has exceeded OTP rate limits
func (s *otpService) CheckOTPRateLimit(ctx context.Context, identifier string) error {
	now := time.Now()
	windowDuration := 15 * time.Minute // 15-minute window
	maxAttempts := 5                   // Max 5 OTP requests per window

	// Get or create rate limit info
	rateLimitKey := fmt.Sprintf("otp_rate_limit:%s", identifier)

	// Use Redis for distributed rate limiting if available, fallback to in-memory
	if s.hasRedis() {
		return s.checkRedisRateLimit(ctx, rateLimitKey, windowDuration, maxAttempts)
	}

	// Fallback to in-memory rate limiting (for development/testing)
	info, exists := s.rateLimitCache[rateLimitKey]
	if !exists {
		s.rateLimitCache[rateLimitKey] = &RateLimitInfo{
			Count:     0,
			FirstTime: now,
			LastTime:  now,
		}
		return nil
	}

	// Check if window has expired
	if now.Sub(info.FirstTime) > windowDuration {
		// Reset window
		info.Count = 0
		info.FirstTime = now
		info.LastTime = now
		return nil
	}

	// Check if rate limit exceeded
	if info.Count >= maxAttempts {
		timeRemaining := windowDuration - now.Sub(info.FirstTime)
		return errors.NewRateLimitError(fmt.Sprintf("OTP rate limit exceeded. Try again in %v", timeRemaining.Round(time.Minute)))
	}

	return nil
}

// RecordOTPAttempt records an OTP attempt for rate limiting
func (s *otpService) RecordOTPAttempt(ctx context.Context, identifier string, success bool) error {
	now := time.Now()
	rateLimitKey := fmt.Sprintf("otp_rate_limit:%s", identifier)

	// Use Redis for distributed rate limiting if available, fallback to in-memory
	if s.hasRedis() {
		return s.recordRedisRateLimit(ctx, rateLimitKey)
	}

	// Fallback to in-memory rate limiting (for development/testing)
	info, exists := s.rateLimitCache[rateLimitKey]
	if !exists {
		s.rateLimitCache[rateLimitKey] = &RateLimitInfo{
			Count:     1,
			FirstTime: now,
			LastTime:  now,
		}
		return nil
	}

	info.Count++
	info.LastTime = now

	return nil
}

// InvalidateOTPs invalidates existing OTPs for an identifier and purpose
func (s *otpService) InvalidateOTPs(ctx context.Context, identifier string, purpose string) error {
	// Mark all existing unused OTPs for this identifier and purpose as used
	return s.repo.InvalidateOTPsByIdentifier(ctx, identifier, purpose)
}

// CleanupExpiredOTPs removes expired OTP codes
func (s *otpService) CleanupExpiredOTPs(ctx context.Context) error {
	return s.repo.CleanExpiredOTPs(ctx)
}

// generateOTPCode generates a cryptographically secure OTP code
func (s *otpService) generateOTPCode() (string, error) {
	length := s.config.Auth.OTPLength
	if length < 4 || length > 10 {
		length = 6 // Default to 6 digits
	}

	// Generate cryptographically secure random number
	max := new(big.Int)
	max.Exp(big.NewInt(10), big.NewInt(int64(length)), nil)

	// Ensure we don't generate codes that start with 0 (for better UX)
	minValue := new(big.Int)
	minValue.Exp(big.NewInt(10), big.NewInt(int64(length-1)), nil)

	for {
		n, err := rand.Int(rand.Reader, max)
		if err != nil {
			return "", err
		}

		// Ensure the number has the correct length (no leading zeros)
		if n.Cmp(minValue) >= 0 {
			format := fmt.Sprintf("%%0%dd", length)
			return fmt.Sprintf(format, n), nil
		}
	}
}

// deliverOTP sends the OTP via email or SMS using templates
func (s *otpService) deliverOTP(ctx context.Context, otp *OTPCode, purpose string) error {
	// Prepare template variables
	variables := s.prepareTemplateVariables(otp, purpose)

	if otp.Email != nil {
		// Send via email
		return s.templateSvc.SendEmail(ctx,
			template.TemplateTypeEmail,
			template.TemplatePurpose(purpose),
			"en",
			variables,
			[]string{*otp.Email})
	} else if otp.Phone != nil {
		// Send via SMS
		return s.templateSvc.SendSMS(ctx,
			template.TemplatePurpose(purpose),
			"en",
			variables,
			*otp.Phone)
	}

	return errors.NewValidationError("no delivery method available")
}

// prepareTemplateVariables prepares variables for template rendering
func (s *otpService) prepareTemplateVariables(otp *OTPCode, purpose string) map[string]interface{} {
	expiryMinutes := int(s.config.Auth.OTPExpiration.Minutes())

	variables := map[string]interface{}{
		"otp_code":       otp.Code,
		"expiry_minutes": expiryMinutes,
		"app_name":       "Go Forward Framework",
		"app_url":        "https://localhost:8080", // This should come from config
		"timestamp":      time.Now(),
	}

	// Add user-specific variables if user exists
	if otp.UserID != nil {
		if user, err := s.repo.GetUserByID(context.Background(), *otp.UserID); err == nil {
			if user.Email != nil {
				variables["user_email"] = *user.Email
			}
			if user.Username != nil {
				variables["user_name"] = *user.Username
			} else if user.Email != nil {
				variables["user_name"] = *user.Email
			}
		}
	}

	// Add identifier as user_name if no user found
	if _, exists := variables["user_name"]; !exists {
		if otp.Email != nil {
			variables["user_name"] = *otp.Email
		} else if otp.Phone != nil {
			variables["user_name"] = *otp.Phone
		}
	}

	return variables
}

// handleOTPVerification handles different OTP verification purposes
func (s *otpService) handleOTPVerification(ctx context.Context, otp *OTPCode, req *VerifyOTPRequest) (*AuthResponse, error) {
	var user *UnifiedUser
	var err error

	switch req.Purpose {
	case "registration":
		// Create new user for registration
		user = &UnifiedUser{
			ID:        uuid.New(),
			Email:     otp.Email,
			Phone:     otp.Phone,
			Metadata:  make(map[string]interface{}),
			CreatedAt: time.Now().UTC(),
			UpdatedAt: time.Now().UTC(),
		}

		// Set verification status
		if otp.Email != nil {
			user.EmailVerified = true
		}
		if otp.Phone != nil {
			user.PhoneVerified = true
		}

		if err := s.repo.CreateUser(ctx, user); err != nil {
			return nil, errors.Wrap(err, "failed to create user")
		}

	case "login", "verification", "password_reset":
		// Find existing user
		if otp.Email != nil {
			user, err = s.repo.GetUserByEmail(ctx, *otp.Email)
		} else if otp.Phone != nil {
			user, err = s.repo.GetUserByPhone(ctx, *otp.Phone)
		}

		if err != nil {
			return nil, errors.NewAuthError("user not found")
		}

		// Update verification status if needed
		if req.Purpose == "verification" {
			updated := false
			if otp.Email != nil && !user.EmailVerified {
				user.EmailVerified = true
				updated = true
			}
			if otp.Phone != nil && !user.PhoneVerified {
				user.PhoneVerified = true
				updated = true
			}
			if updated {
				user.UpdatedAt = time.Now().UTC()
				s.repo.UpdateUser(ctx, user)
			}
		}

	default:
		return nil, errors.NewValidationError(fmt.Sprintf("unsupported OTP purpose: %s", req.Purpose))
	}

	// Return user without tokens - tokens will be generated by the main auth service
	return &AuthResponse{
		User:      user,
		ExpiresAt: time.Now().Add(s.config.Auth.JWTExpiration),
	}, nil
}

// validateOTPRequest validates an OTP request
func (s *otpService) validateOTPRequest(req *OTPRequest) error {
	if req.Identifier == "" {
		return errors.NewValidationError("identifier is required")
	}

	if req.Purpose == "" {
		return errors.NewValidationError("purpose is required")
	}

	// Validate purpose
	validPurposes := []string{"login", "registration", "verification", "password_reset"}
	valid := false
	for _, purpose := range validPurposes {
		if req.Purpose == purpose {
			valid = true
			break
		}
	}
	if !valid {
		return errors.NewValidationError("invalid purpose")
	}

	// Validate identifier format
	if strings.Contains(req.Identifier, "@") {
		// Email validation (basic)
		if !strings.Contains(req.Identifier, ".") {
			return errors.NewValidationError("invalid email format")
		}
	} else {
		// Phone validation (basic)
		if len(req.Identifier) < 10 {
			return errors.NewValidationError("invalid phone number format")
		}
	}

	return nil
}

// validateVerifyOTPRequest validates an OTP verification request
func (s *otpService) validateVerifyOTPRequest(req *VerifyOTPRequest) error {
	if req.Identifier == "" {
		return errors.NewValidationError("identifier is required")
	}

	if req.Code == "" {
		return errors.NewValidationError("code is required")
	}

	if req.Purpose == "" {
		return errors.NewValidationError("purpose is required")
	}

	// Validate code format
	if len(req.Code) != s.config.Auth.OTPLength {
		return errors.NewValidationError("invalid code format")
	}

	return nil
}

// verifyOTPCode verifies OTP by hashing provided code and comparing with stored hash
func (s *otpService) verifyOTPCode(provided, storedHash string) bool {
	// Hash the provided code
	providedHash := s.hashOTPCode(provided)

	// Perform constant-time comparison of hashes
	if len(providedHash) != len(storedHash) {
		return false
	}

	result := 0
	for i := 0; i < len(providedHash); i++ {
		result |= int(providedHash[i]) ^ int(storedHash[i])
	}

	return result == 0
}

// hashOTPCode creates a secure hash of the OTP code for storage
func (s *otpService) hashOTPCode(code string) string {
	// Use SHA-256 with a salt for hashing OTP codes
	salt := s.config.Auth.JWTSecret // Use JWT secret as salt
	hasher := sha256.New()
	hasher.Write([]byte(code + salt))
	hash := hasher.Sum(nil)
	return hex.EncodeToString(hash)
}

// hasRedis checks if Redis is available for rate limiting
func (s *otpService) hasRedis() bool {
	// This would check if Redis connection is available
	// For now, we'll return false to use in-memory fallback
	return false
}

// checkRedisRateLimit checks rate limit using Redis
func (s *otpService) checkRedisRateLimit(ctx context.Context, key string, window time.Duration, maxAttempts int) error {
	// Implementation would use Redis INCR with EXPIRE
	// This is a placeholder for Redis-based rate limiting
	return nil
}

// recordRedisRateLimit records rate limit attempt in Redis
func (s *otpService) recordRedisRateLimit(ctx context.Context, key string) error {
	// Implementation would use Redis INCR
	// This is a placeholder for Redis-based rate limiting
	return nil
}

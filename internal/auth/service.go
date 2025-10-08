package auth

import (
	"context"
	"crypto/rand"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/taqiudeen275/go-foward/internal/database"
	"github.com/taqiudeen275/go-foward/internal/email"
	"github.com/taqiudeen275/go-foward/internal/sms"
	"github.com/taqiudeen275/go-foward/pkg/interfaces"
)

// Service handles authentication business logic
type Service struct {
	repo            UserRepositoryInterface
	hasher          *PasswordHasher
	validator       *Validator
	jwtManager      *JWTManager
	emailService    email.EmailService
	smsService      sms.SMSService
	securityMonitor *SecurityMonitor
	customProviders *CustomAuthProviderManager
}

// NewService creates a new authentication service
func NewService(db *database.DB) *Service {
	// Default JWT configuration - should be overridden with actual config
	jwtManager := NewJWTManager("default-secret-key", 24*time.Hour, 7*24*time.Hour)

	return &Service{
		repo:            NewUserRepository(db),
		hasher:          NewPasswordHasher(),
		validator:       NewValidator(),
		jwtManager:      jwtManager,
		emailService:    nil, // Will be set via SetEmailService
		smsService:      nil, // Will be set via SetSMSService
		securityMonitor: NewSecurityMonitor(),
		customProviders: NewCustomAuthProviderManager(),
	}
}

// NewServiceWithConfig creates a new authentication service with custom JWT configuration
func NewServiceWithConfig(db *database.DB, jwtSecret string, accessExpiration, refreshExpiration time.Duration) *Service {
	jwtManager := NewJWTManager(jwtSecret, accessExpiration, refreshExpiration)

	return &Service{
		repo:            NewUserRepository(db),
		hasher:          NewPasswordHasher(),
		validator:       NewValidator(),
		jwtManager:      jwtManager,
		emailService:    nil, // Will be set via SetEmailService
		smsService:      nil, // Will be set via SetSMSService
		securityMonitor: NewSecurityMonitor(),
		customProviders: NewCustomAuthProviderManager(),
	}
}

// SetEmailService sets the email service for the auth service
func (s *Service) SetEmailService(emailService email.EmailService) {
	s.emailService = emailService
}

// SetSMSService sets the SMS service for the auth service
func (s *Service) SetSMSService(smsService sms.SMSService) {
	s.smsService = smsService
}

// GetEmailService returns the email service
func (s *Service) GetEmailService() email.EmailService {
	return s.emailService
}

// GetSMSService returns the SMS service
func (s *Service) GetSMSService() sms.SMSService {
	return s.smsService
}

// CreateUser creates a new user with hashed password
func (s *Service) CreateUser(ctx context.Context, req *CreateUserRequest) (*User, error) {
	// Validate request
	if err := s.validator.ValidateCreateUserRequest(req); err != nil {
		return nil, err
	}

	// Check if user already exists with any of the provided identifiers
	if req.Email != nil {
		exists, err := s.repo.Exists(ctx, *req.Email)
		if err != nil {
			return nil, fmt.Errorf("failed to check email existence: %w", err)
		}
		if exists {
			return nil, fmt.Errorf("user with email already exists")
		}
	}

	if req.Phone != nil {
		exists, err := s.repo.Exists(ctx, *req.Phone)
		if err != nil {
			return nil, fmt.Errorf("failed to check phone existence: %w", err)
		}
		if exists {
			return nil, fmt.Errorf("user with phone already exists")
		}
	}

	if req.Username != nil {
		exists, err := s.repo.Exists(ctx, *req.Username)
		if err != nil {
			return nil, fmt.Errorf("failed to check username existence: %w", err)
		}
		if exists {
			return nil, fmt.Errorf("user with username already exists")
		}
	}

	// Hash password
	hashedPassword, err := s.hasher.HashPassword(req.Password)
	if err != nil {
		return nil, fmt.Errorf("failed to hash password: %w", err)
	}

	// Create user
	user := &User{
		ID:            uuid.New().String(),
		Email:         req.Email,
		Phone:         req.Phone,
		Username:      req.Username,
		PasswordHash:  hashedPassword,
		EmailVerified: false,
		PhoneVerified: false,
		Metadata:      req.Metadata,
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
	}

	if user.Metadata == nil {
		user.Metadata = make(map[string]interface{})
	}

	err = s.repo.Create(ctx, user)
	if err != nil {
		return nil, fmt.Errorf("failed to create user: %w", err)
	}

	return user, nil
}

// GetUserByID retrieves a user by ID
func (s *Service) GetUserByID(ctx context.Context, id string) (*User, error) {
	return s.repo.GetByID(ctx, id)
}

// GetUserByEmail retrieves a user by email
func (s *Service) GetUserByEmail(ctx context.Context, email string) (*User, error) {
	return s.repo.GetByEmail(ctx, email)
}

// GetUserByPhone retrieves a user by phone
func (s *Service) GetUserByPhone(ctx context.Context, phone string) (*User, error) {
	return s.repo.GetByPhone(ctx, phone)
}

// GetUserByUsername retrieves a user by username
func (s *Service) GetUserByUsername(ctx context.Context, username string) (*User, error) {
	return s.repo.GetByUsername(ctx, username)
}

// GetUserByIdentifier retrieves a user by email, phone, or username
func (s *Service) GetUserByIdentifier(ctx context.Context, identifier string) (*User, error) {
	return s.repo.GetByIdentifier(ctx, identifier)
}

// UpdateUser updates a user
func (s *Service) UpdateUser(ctx context.Context, id string, req *UpdateUserRequest) (*User, error) {
	// Validate user ID
	if err := s.validator.ValidateUserID(id); err != nil {
		return nil, err
	}

	// Validate request
	if err := s.validator.ValidateUpdateUserRequest(req); err != nil {
		return nil, err
	}

	// Check if user exists
	_, err := s.repo.GetByID(ctx, id)
	if err != nil {
		return nil, err
	}

	// Check for conflicts with other users if updating identifiers
	if req.Email != nil {
		existing, err := s.repo.GetByEmail(ctx, *req.Email)
		if err == nil && existing.ID != id {
			return nil, fmt.Errorf("email already in use by another user")
		}
	}

	if req.Phone != nil {
		existing, err := s.repo.GetByPhone(ctx, *req.Phone)
		if err == nil && existing.ID != id {
			return nil, fmt.Errorf("phone already in use by another user")
		}
	}

	if req.Username != nil {
		existing, err := s.repo.GetByUsername(ctx, *req.Username)
		if err == nil && existing.ID != id {
			return nil, fmt.Errorf("username already in use by another user")
		}
	}

	return s.repo.Update(ctx, id, req)
}

// DeleteUser deletes a user
func (s *Service) DeleteUser(ctx context.Context, id string) error {
	return s.repo.Delete(ctx, id)
}

// ListUsers retrieves users with optional filtering
func (s *Service) ListUsers(ctx context.Context, filter *UserFilter) ([]*User, error) {
	return s.repo.List(ctx, filter)
}

// ValidatePassword validates a user's password
func (s *Service) ValidatePassword(ctx context.Context, identifier, password string) (*User, error) {
	// Validate login request
	loginReq := &LoginRequest{
		Identifier: identifier,
		Password:   password,
	}
	if err := s.validator.ValidateLoginRequest(loginReq); err != nil {
		return nil, fmt.Errorf("invalid credentials")
	}

	user, err := s.repo.GetByIdentifier(ctx, identifier)
	if err != nil {
		return nil, fmt.Errorf("invalid credentials")
	}

	err = s.hasher.ValidatePassword(password, user.PasswordHash)
	if err != nil {
		return nil, fmt.Errorf("invalid credentials")
	}

	return user, nil
}

// UpdatePassword updates a user's password
func (s *Service) UpdatePassword(ctx context.Context, id, newPassword string) error {
	// Hash new password
	hashedPassword, err := s.hasher.HashPassword(newPassword)
	if err != nil {
		return fmt.Errorf("failed to hash password: %w", err)
	}

	// Update password in database
	err = s.repo.UpdatePassword(ctx, id, hashedPassword)
	if err != nil {
		return fmt.Errorf("failed to update password: %w", err)
	}

	return nil
}

// VerifyEmail marks a user's email as verified
func (s *Service) VerifyEmail(ctx context.Context, id string) error {
	verified := true
	_, err := s.repo.Update(ctx, id, &UpdateUserRequest{
		EmailVerified: &verified,
	})

	return err
}

// VerifyPhone marks a user's phone as verified
func (s *Service) VerifyPhone(ctx context.Context, id string) error {
	verified := true
	_, err := s.repo.Update(ctx, id, &UpdateUserRequest{
		PhoneVerified: &verified,
	})

	return err
}

// Login authenticates a user and returns JWT tokens
func (s *Service) Login(ctx context.Context, req *LoginRequest) (*AuthResponse, error) {
	// Validate request
	if err := s.validator.ValidateLoginRequest(req); err != nil {
		return nil, err
	}

	// Validate user credentials
	user, err := s.ValidatePassword(ctx, req.Identifier, req.Password)
	if err != nil {
		return nil, err
	}

	// Generate JWT tokens
	tokenPair, err := s.jwtManager.GenerateTokenPair(user)
	if err != nil {
		return nil, fmt.Errorf("failed to generate tokens: %w", err)
	}

	return &AuthResponse{
		User:         user,
		AccessToken:  tokenPair.AccessToken,
		RefreshToken: tokenPair.RefreshToken,
		ExpiresIn:    int(tokenPair.ExpiresIn),
	}, nil
}

// Register creates a new user and returns JWT tokens
func (s *Service) Register(ctx context.Context, req *CreateUserRequest) (*AuthResponse, error) {
	// Create user
	user, err := s.CreateUser(ctx, req)
	if err != nil {
		return nil, err
	}

	// Generate JWT tokens
	tokenPair, err := s.jwtManager.GenerateTokenPair(user)
	if err != nil {
		return nil, fmt.Errorf("failed to generate tokens: %w", err)
	}

	return &AuthResponse{
		User:         user,
		AccessToken:  tokenPair.AccessToken,
		RefreshToken: tokenPair.RefreshToken,
		ExpiresIn:    int(tokenPair.ExpiresIn),
	}, nil
}

// RefreshToken generates new tokens using a valid refresh token
func (s *Service) RefreshToken(ctx context.Context, refreshToken string) (*AuthResponse, error) {
	// Validate refresh token and extract user ID
	claims, err := s.jwtManager.ValidateRefreshToken(refreshToken)
	if err != nil {
		return nil, fmt.Errorf("invalid refresh token: %w", err)
	}

	// Get user from database
	user, err := s.GetUserByID(ctx, claims.UserID)
	if err != nil {
		return nil, fmt.Errorf("user not found: %w", err)
	}

	// Generate new token pair
	tokenPair, err := s.jwtManager.RefreshTokenPair(refreshToken, user)
	if err != nil {
		return nil, fmt.Errorf("failed to refresh tokens: %w", err)
	}

	return &AuthResponse{
		User:         user,
		AccessToken:  tokenPair.AccessToken,
		RefreshToken: tokenPair.RefreshToken,
		ExpiresIn:    int(tokenPair.ExpiresIn),
	}, nil
}

// ValidateToken validates a JWT token and returns the claims
func (s *Service) ValidateToken(ctx context.Context, token string) (*Claims, error) {
	return s.jwtManager.ValidateAccessToken(token)
}

// ValidateTokenInterface validates a JWT token and returns interface claims
func (s *Service) ValidateTokenInterface(ctx context.Context, token string) (*interfaces.Claims, error) {
	claims, err := s.jwtManager.ValidateAccessToken(token)
	if err != nil {
		return nil, err
	}

	// Convert to interface claims
	interfaceClaims := &interfaces.Claims{
		UserID:    claims.UserID,
		Email:     claims.Email,
		Metadata:  claims.Metadata,
		IssuedAt:  claims.IssuedAt.Time,
		ExpiresAt: claims.ExpiresAt.Time,
	}

	return interfaceClaims, nil
}

// GetJWTManager returns the JWT manager (for middleware usage)
func (s *Service) GetJWTManager() *JWTManager {
	return s.jwtManager
}

// CreateMiddleware creates authentication middleware
func (s *Service) CreateMiddleware() *Middleware {
	return NewMiddleware(s.jwtManager, s)
}

// RequestPasswordReset sends an OTP for password reset
func (s *Service) RequestPasswordReset(ctx context.Context, req *PasswordResetRequest) error {
	// Validate request
	if err := s.validator.ValidatePasswordResetRequest(req); err != nil {
		return err
	}

	// Find user by identifier
	user, err := s.GetUserByIdentifier(ctx, req.Identifier)
	if err != nil {
		// Don't reveal if user exists or not for security
		return nil
	}

	// Check rate limiting
	if err := s.securityMonitor.CheckOTPRequestRate(req.Identifier); err != nil {
		return err
	}

	// Check if recipient is locked out
	if s.securityMonitor.IsLocked(req.Identifier) {
		return fmt.Errorf("account temporarily locked due to suspicious activity")
	}

	// Determine OTP type based on identifier
	var otpType OTPType
	var recipient string

	if user.Email != nil && *user.Email == req.Identifier {
		otpType = OTPTypeEmail
		recipient = *user.Email
	} else if user.Phone != nil && *user.Phone == req.Identifier {
		otpType = OTPTypeSMS
		recipient = *user.Phone
	} else {
		// If identifier is username, prefer email, fallback to phone
		if user.Email != nil {
			otpType = OTPTypeEmail
			recipient = *user.Email
		} else if user.Phone != nil {
			otpType = OTPTypeSMS
			recipient = *user.Phone
		} else {
			return fmt.Errorf("no email or phone available for password reset")
		}
	}

	// Create OTP generator
	otpGenerator := NewOTPGeneratorWithConfig(6, 10*time.Minute, 3)

	// Generate OTP for password reset (using verification purpose)
	otp, err := otpGenerator.CreateOTP(&user.ID, otpType, OTPPurposeVerification, recipient)
	if err != nil {
		return fmt.Errorf("failed to generate password reset OTP: %w", err)
	}

	// Save OTP to database
	err = s.repo.CreateOTP(ctx, otp)
	if err != nil {
		return fmt.Errorf("failed to save password reset OTP: %w", err)
	}

	// Send OTP via email or SMS
	switch otpType {
	case OTPTypeEmail:
		if s.emailService != nil {
			err = s.emailService.SendPasswordResetOTP(ctx, recipient, otp.Code, "Go Forward")
			if err != nil {
				return fmt.Errorf("failed to send password reset OTP email: %w", err)
			}
		} else {
			fmt.Printf("Password reset OTP for %s: %s (email service not configured)\n", recipient, otp.Code)
		}

	case OTPTypeSMS:
		if s.smsService != nil {
			err = s.smsService.SendPasswordResetOTP(ctx, recipient, otp.Code, "Go Forward")
			if err != nil {
				return fmt.Errorf("failed to send password reset OTP SMS: %w", err)
			}
		} else {
			fmt.Printf("Password reset OTP for %s: %s (SMS service not configured)\n", recipient, otp.Code)
		}
	}

	return nil
}

// ConfirmPasswordReset validates the OTP and updates the user's password
func (s *Service) ConfirmPasswordReset(ctx context.Context, req *PasswordResetConfirmRequest) error {
	// Validate request
	if err := s.validator.ValidatePasswordResetConfirmRequest(req); err != nil {
		return err
	}

	// Find user by identifier
	user, err := s.GetUserByIdentifier(ctx, req.Identifier)
	if err != nil {
		return fmt.Errorf("user not found")
	}

	// Determine OTP type and recipient based on identifier
	var otpType OTPType
	var recipient string

	if user.Email != nil && *user.Email == req.Identifier {
		otpType = OTPTypeEmail
		recipient = *user.Email
	} else if user.Phone != nil && *user.Phone == req.Identifier {
		otpType = OTPTypeSMS
		recipient = *user.Phone
	} else {
		// If identifier is username, check which contact method was used for OTP
		// Try email first, then phone
		if user.Email != nil {
			otpType = OTPTypeEmail
			recipient = *user.Email
		} else if user.Phone != nil {
			otpType = OTPTypeSMS
			recipient = *user.Phone
		} else {
			return fmt.Errorf("no email or phone available for password reset")
		}
	}

	// Get the latest OTP for password reset (verification purpose)
	otp, err := s.repo.GetLatestOTPWithPurpose(ctx, recipient, otpType, OTPPurposeVerification)
	if err != nil {
		return fmt.Errorf("invalid or expired OTP")
	}

	// Increment attempts first
	err = s.repo.IncrementOTPAttempts(ctx, otp.ID)
	if err != nil {
		return fmt.Errorf("failed to update OTP attempts: %w", err)
	}

	// Create OTP generator for validation
	otpGenerator := NewOTPGeneratorWithConfig(6, 10*time.Minute, 3)

	// Validate the OTP code
	err = otpGenerator.ValidateCode(otp, req.OTPCode)
	if err != nil {
		// Record failed attempt for security monitoring
		s.securityMonitor.RecordFailedAttempt(recipient)
		return err
	}

	// Clear failed attempts on successful verification
	s.securityMonitor.ClearFailedAttempts(recipient)

	// Mark OTP as used
	err = s.repo.MarkOTPUsed(ctx, otp.ID)
	if err != nil {
		return fmt.Errorf("failed to mark OTP as used: %w", err)
	}

	// Update user's password
	err = s.UpdatePassword(ctx, user.ID, req.NewPassword)
	if err != nil {
		return fmt.Errorf("failed to update password: %w", err)
	}

	return nil
}

// generateSecureToken generates a secure random token for password reset
func generateSecureToken() string {
	// Generate a random UUID and remove hyphens for simplicity
	token := uuid.New().String()
	return strings.ReplaceAll(token, "-", "")
}

// generateSecurePassword generates a secure password that meets all validation requirements
func generateSecurePassword() string {
	// Define character sets
	uppercase := "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	lowercase := "abcdefghijklmnopqrstuvwxyz"
	digits := "0123456789"
	special := "!@#$%^&*()_+-=[]{}|;:,.<>?"

	// Ensure at least one character from each required set
	var password strings.Builder
	password.WriteByte(uppercase[generateRandomIndex(len(uppercase))])
	password.WriteByte(lowercase[generateRandomIndex(len(lowercase))])
	password.WriteByte(digits[generateRandomIndex(len(digits))])
	password.WriteByte(special[generateRandomIndex(len(special))])

	// Fill remaining characters (minimum 8 total, we'll make it 12 for security)
	allChars := uppercase + lowercase + digits + special
	for i := 4; i < 12; i++ {
		password.WriteByte(allChars[generateRandomIndex(len(allChars))])
	}

	// Shuffle the password to avoid predictable patterns
	passwordBytes := []byte(password.String())
	for i := len(passwordBytes) - 1; i > 0; i-- {
		j := generateRandomIndex(i + 1)
		passwordBytes[i], passwordBytes[j] = passwordBytes[j], passwordBytes[i]
	}

	return string(passwordBytes)
}

// generateRandomIndex generates a cryptographically secure random index
func generateRandomIndex(max int) int {
	if max <= 0 {
		return 0
	}

	// Use crypto/rand for secure random generation
	n, err := rand.Int(rand.Reader, big.NewInt(int64(max)))
	if err != nil {
		// Fallback to a simple method if crypto/rand fails
		return int(time.Now().UnixNano()) % max
	}

	return int(n.Int64())
}

// SendOTP generates and sends an OTP to the specified recipient
func (s *Service) SendOTP(ctx context.Context, req *OTPRequest) error {
	// Validate request
	if err := s.validator.ValidateOTPRequest(req); err != nil {
		return err
	}

	// Check rate limiting
	if err := s.securityMonitor.CheckOTPRequestRate(req.Recipient); err != nil {
		return err
	}

	// Check if recipient is locked out
	if s.securityMonitor.IsLocked(req.Recipient) {
		return fmt.Errorf("account temporarily locked due to suspicious activity")
	}

	// Check user existence based on purpose
	user, err := s.GetUserByIdentifier(ctx, req.Recipient)
	var userID *string

	switch req.Purpose {
	case OTPPurposeLogin:
		// For login, user must exist
		if err != nil {
			return fmt.Errorf("user not found")
		}
		userID = &user.ID

	case OTPPurposeRegistration:
		// For registration, user must NOT exist
		if err == nil {
			return fmt.Errorf("user already exists")
		}
		userID = nil // No user ID for registration

	case OTPPurposeVerification:
		// For verification, user must exist
		if err != nil {
			return fmt.Errorf("user not found")
		}
		userID = &user.ID
	}

	// Create OTP generator with config-based expiration
	otpGenerator := NewOTPGeneratorWithConfig(6, 10*time.Minute, 3)

	// Generate OTP
	otp, err := otpGenerator.CreateOTP(userID, req.Type, req.Purpose, req.Recipient)
	if err != nil {
		return fmt.Errorf("failed to generate OTP: %w", err)
	}

	// Save OTP to database
	err = s.repo.CreateOTP(ctx, otp)
	if err != nil {
		return fmt.Errorf("failed to save OTP: %w", err)
	}

	// Send OTP via email or SMS with purpose-specific message
	switch req.Type {
	case OTPTypeEmail:
		if s.emailService != nil {
			err = s.emailService.SendOTPWithPurpose(ctx, req.Recipient, otp.Code, string(req.Purpose), "Go Forward")
			if err != nil {
				return fmt.Errorf("failed to send OTP email: %w", err)
			}
		} else {
			fmt.Printf("Email OTP for %s (%s): %s (email service not configured)\n", req.Recipient, req.Purpose, otp.Code)
		}

	case OTPTypeSMS:
		if s.smsService != nil {
			err = s.smsService.SendOTPWithPurpose(ctx, req.Recipient, otp.Code, string(req.Purpose), "Go Forward")
			if err != nil {
				return fmt.Errorf("failed to send OTP SMS: %w", err)
			}
		} else {
			fmt.Printf("SMS OTP for %s (%s): %s (SMS service not configured)\n", req.Recipient, req.Purpose, otp.Code)
		}
	}

	return nil
}

// VerifyOTPWithPurpose verifies an OTP code with a specific purpose and returns the associated user if found
func (s *Service) VerifyOTPWithPurpose(ctx context.Context, req *VerifyOTPRequest, purpose OTPPurpose) (*User, error) {
	// Validate request
	if err := s.validator.ValidateVerifyOTPRequest(req); err != nil {
		return nil, err
	}

	// Only allow verification purpose for this method
	if purpose != OTPPurposeVerification {
		return nil, fmt.Errorf("this method only supports verification purpose")
	}

	// Get the latest OTP for this recipient, type, and purpose
	otp, err := s.repo.GetLatestOTPWithPurpose(ctx, req.Recipient, req.Type, purpose)
	if err != nil {
		return nil, fmt.Errorf("invalid or expired OTP")
	}

	// Verify purpose matches
	if otp.Purpose != purpose {
		return nil, fmt.Errorf("OTP purpose mismatch")
	}

	// Increment attempts first
	err = s.repo.IncrementOTPAttempts(ctx, otp.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to update OTP attempts: %w", err)
	}

	// Create OTP generator for validation
	otpGenerator := NewOTPGeneratorWithConfig(6, 10*time.Minute, 3)

	// Validate the OTP code
	err = otpGenerator.ValidateCode(otp, req.Code)
	if err != nil {
		// Record failed attempt for security monitoring
		s.securityMonitor.RecordFailedAttempt(req.Recipient)
		return nil, err
	}

	// Clear failed attempts on successful verification
	s.securityMonitor.ClearFailedAttempts(req.Recipient)

	// Mark OTP as used
	err = s.repo.MarkOTPUsed(ctx, otp.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to mark OTP as used: %w", err)
	}

	// If OTP has a user ID, return the user
	if otp.UserID != nil {
		user, err := s.GetUserByID(ctx, *otp.UserID)
		if err != nil {
			return nil, fmt.Errorf("user not found: %w", err)
		}

		// Mark the appropriate field as verified
		switch req.Type {
		case OTPTypeEmail:
			err = s.VerifyEmail(ctx, user.ID)
		case OTPTypeSMS:
			err = s.VerifyPhone(ctx, user.ID)
		}

		if err != nil {
			return nil, fmt.Errorf("failed to mark as verified: %w", err)
		}

		return user, nil
	}

	return nil, nil
}

// LoginWithOTPPurpose authenticates a user using OTP and returns JWT tokens
func (s *Service) LoginWithOTPPurpose(ctx context.Context, req *VerifyOTPRequest, purpose OTPPurpose) (*AuthResponse, error) {
	// Only allow login purpose for this method
	if purpose != OTPPurposeLogin {
		return nil, fmt.Errorf("this method only supports login purpose")
	}

	// Get the latest OTP for this recipient, type, and purpose
	otp, err := s.repo.GetLatestOTPWithPurpose(ctx, req.Recipient, req.Type, purpose)
	if err != nil {
		return nil, fmt.Errorf("invalid or expired OTP")
	}

	// Verify purpose matches
	if otp.Purpose != purpose {
		return nil, fmt.Errorf("OTP purpose mismatch")
	}

	// Increment attempts first
	err = s.repo.IncrementOTPAttempts(ctx, otp.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to update OTP attempts: %w", err)
	}

	// Create OTP generator for validation
	otpGenerator := NewOTPGeneratorWithConfig(6, 10*time.Minute, 3)

	// Validate the OTP code
	err = otpGenerator.ValidateCode(otp, req.Code)
	if err != nil {
		return nil, err
	}

	// Mark OTP as used
	err = s.repo.MarkOTPUsed(ctx, otp.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to mark OTP as used: %w", err)
	}

	// Get user (must exist for login)
	if otp.UserID == nil {
		return nil, fmt.Errorf("no user associated with this OTP")
	}

	user, err := s.GetUserByID(ctx, *otp.UserID)
	if err != nil {
		return nil, fmt.Errorf("user not found: %w", err)
	}

	// Generate JWT tokens
	tokenPair, err := s.jwtManager.GenerateTokenPair(user)
	if err != nil {
		return nil, fmt.Errorf("failed to generate tokens: %w", err)
	}

	return &AuthResponse{
		User:         user,
		AccessToken:  tokenPair.AccessToken,
		RefreshToken: tokenPair.RefreshToken,
		ExpiresIn:    int(tokenPair.ExpiresIn),
	}, nil
}

// RegisterWithOTPPurpose creates a new user using OTP verification and returns JWT tokens
func (s *Service) RegisterWithOTPPurpose(ctx context.Context, req *VerifyOTPRequest, purpose OTPPurpose, password *string) (*AuthResponse, error) {
	// Only allow registration purpose for this method
	if purpose != OTPPurposeRegistration {
		return nil, fmt.Errorf("this method only supports registration purpose")
	}

	// Get the latest OTP for this recipient, type, and purpose
	otp, err := s.repo.GetLatestOTPWithPurpose(ctx, req.Recipient, req.Type, purpose)
	if err != nil {
		return nil, fmt.Errorf("invalid or expired OTP")
	}

	// Verify purpose matches
	if otp.Purpose != purpose {
		return nil, fmt.Errorf("OTP purpose mismatch")
	}

	// Increment attempts first
	err = s.repo.IncrementOTPAttempts(ctx, otp.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to update OTP attempts: %w", err)
	}

	// Create OTP generator for validation
	otpGenerator := NewOTPGeneratorWithConfig(6, 10*time.Minute, 3)

	// Validate the OTP code
	err = otpGenerator.ValidateCode(otp, req.Code)
	if err != nil {
		return nil, err
	}

	// Mark OTP as used
	err = s.repo.MarkOTPUsed(ctx, otp.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to mark OTP as used: %w", err)
	}

	// Create user registration request
	createReq := &CreateUserRequest{
		Metadata: make(map[string]interface{}),
	}

	// Set the verified field based on OTP type
	switch req.Type {
	case OTPTypeEmail:
		createReq.Email = &req.Recipient
	case OTPTypeSMS:
		createReq.Phone = &req.Recipient
	}

	// Set password if provided, otherwise generate a random one
	if password != nil && *password != "" {
		createReq.Password = *password
	} else {
		// Generate a secure password that meets all validation requirements
		createReq.Password = generateSecurePassword()
	}

	// Create user
	user, err := s.CreateUser(ctx, createReq)
	if err != nil {
		return nil, fmt.Errorf("failed to create user: %w", err)
	}

	// Mark the appropriate field as verified since OTP was successful
	switch req.Type {
	case OTPTypeEmail:
		err = s.VerifyEmail(ctx, user.ID)
	case OTPTypeSMS:
		err = s.VerifyPhone(ctx, user.ID)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to mark as verified: %w", err)
	}

	// Generate JWT tokens
	tokenPair, err := s.jwtManager.GenerateTokenPair(user)
	if err != nil {
		return nil, fmt.Errorf("failed to generate tokens: %w", err)
	}

	return &AuthResponse{
		User:         user,
		AccessToken:  tokenPair.AccessToken,
		RefreshToken: tokenPair.RefreshToken,
		ExpiresIn:    int(tokenPair.ExpiresIn),
	}, nil
}

// VerifyOTP verifies an OTP code and returns the associated user if found (backward compatibility)
func (s *Service) VerifyOTP(ctx context.Context, req *VerifyOTPRequest) (*User, error) {
	return s.VerifyOTPWithPurpose(ctx, req, OTPPurposeVerification)
}

// LoginWithOTP authenticates a user using OTP and returns JWT tokens (backward compatibility)
func (s *Service) LoginWithOTP(ctx context.Context, req *VerifyOTPRequest) (*AuthResponse, error) {
	return s.LoginWithOTPPurpose(ctx, req, OTPPurposeLogin)
}

// RegisterWithOTP creates a new user using OTP verification and returns JWT tokens (backward compatibility)
func (s *Service) RegisterWithOTP(ctx context.Context, req *VerifyOTPRequest, password *string) (*AuthResponse, error) {
	return s.RegisterWithOTPPurpose(ctx, req, OTPPurposeRegistration, password)
}

// Logout blacklists user tokens to prevent further use
func (s *Service) Logout(ctx context.Context, accessToken, refreshToken string) error {
	var errors []string

	// Blacklist access token if provided
	if accessToken != "" {
		if err := s.jwtManager.BlacklistToken(accessToken); err != nil {
			errors = append(errors, fmt.Sprintf("failed to blacklist access token: %v", err))
		}
	}

	// Blacklist refresh token if provided
	if refreshToken != "" {
		if err := s.jwtManager.BlacklistToken(refreshToken); err != nil {
			errors = append(errors, fmt.Sprintf("failed to blacklist refresh token: %v", err))
		}
	}

	if len(errors) > 0 {
		return fmt.Errorf("logout errors: %s", strings.Join(errors, "; "))
	}

	return nil
}

// Custom Auth Provider Management Methods

// RegisterCustomAuthProvider registers a new custom authentication provider
func (s *Service) RegisterCustomAuthProvider(provider CustomAuthProvider) error {
	return s.customProviders.RegisterProvider(provider)
}

// UnregisterCustomAuthProvider removes a custom authentication provider
func (s *Service) UnregisterCustomAuthProvider(name string) error {
	return s.customProviders.UnregisterProvider(name)
}

// GetCustomAuthProvider retrieves a provider by name
func (s *Service) GetCustomAuthProvider(name string) (CustomAuthProvider, error) {
	return s.customProviders.GetProvider(name)
}

// ListCustomAuthProviders returns all registered providers
func (s *Service) ListCustomAuthProviders() map[string]CustomAuthProvider {
	return s.customProviders.ListProviders()
}

// GetEnabledCustomAuthProviders returns only enabled providers
func (s *Service) GetEnabledCustomAuthProviders() map[string]CustomAuthProvider {
	return s.customProviders.GetEnabledProviders()
}

// GetCustomAuthProviderInfo returns information about a provider
func (s *Service) GetCustomAuthProviderInfo(providerName string) (map[string]interface{}, error) {
	return s.customProviders.GetProviderInfo(providerName)
}

// ValidateCustomAuthCredentials validates credentials for a specific provider
func (s *Service) ValidateCustomAuthCredentials(providerName string, credentials map[string]interface{}) error {
	return s.customProviders.ValidateCredentials(providerName, credentials)
}

// AuthenticateWithCustomProvider performs authentication using a custom provider
func (s *Service) AuthenticateWithCustomProvider(ctx context.Context, req *CustomAuthRequest) (*AuthResponse, error) {
	// Validate request
	if err := s.validator.ValidateCustomAuthRequest(req); err != nil {
		return nil, err
	}

	// Check rate limiting for the provider
	providerKey := fmt.Sprintf("custom_auth_%s", req.Provider)
	if err := s.securityMonitor.CheckOTPRequestRate(providerKey); err != nil {
		return nil, err
	}

	// Check if provider is locked out
	if s.securityMonitor.IsLocked(providerKey) {
		return nil, fmt.Errorf("provider temporarily locked due to suspicious activity")
	}

	// Authenticate using the custom provider
	user, err := s.customProviders.Authenticate(ctx, req.Provider, req.Credentials)
	if err != nil {
		// Record failed attempt for security monitoring
		s.securityMonitor.RecordFailedAttempt(providerKey)
		return nil, fmt.Errorf("authentication failed: %w", err)
	}

	// Clear failed attempts on successful authentication
	s.securityMonitor.ClearFailedAttempts(providerKey)

	// Generate JWT tokens
	tokenPair, err := s.jwtManager.GenerateTokenPair(user)
	if err != nil {
		return nil, fmt.Errorf("failed to generate tokens: %w", err)
	}

	return &AuthResponse{
		User:         user,
		AccessToken:  tokenPair.AccessToken,
		RefreshToken: tokenPair.RefreshToken,
		ExpiresIn:    int(tokenPair.ExpiresIn),
	}, nil
}

package auth

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/taqiudeen275/go-foward/internal/database"
	"github.com/taqiudeen275/go-foward/internal/email"
	"github.com/taqiudeen275/go-foward/internal/sms"
)

// Service handles authentication business logic
type Service struct {
	repo         UserRepositoryInterface
	hasher       *PasswordHasher
	validator    *Validator
	jwtManager   *JWTManager
	emailService email.EmailService
	smsService   sms.SMSService
}

// NewService creates a new authentication service
func NewService(db *database.DB) *Service {
	// Default JWT configuration - should be overridden with actual config
	jwtManager := NewJWTManager("default-secret-key", 24*time.Hour, 7*24*time.Hour)

	return &Service{
		repo:         NewUserRepository(db),
		hasher:       NewPasswordHasher(),
		validator:    NewValidator(),
		jwtManager:   jwtManager,
		emailService: nil, // Will be set via SetEmailService
		smsService:   nil, // Will be set via SetSMSService
	}
}

// NewServiceWithConfig creates a new authentication service with custom JWT configuration
func NewServiceWithConfig(db *database.DB, jwtSecret string, accessExpiration, refreshExpiration time.Duration) *Service {
	jwtManager := NewJWTManager(jwtSecret, accessExpiration, refreshExpiration)

	return &Service{
		repo:         NewUserRepository(db),
		hasher:       NewPasswordHasher(),
		validator:    NewValidator(),
		jwtManager:   jwtManager,
		emailService: nil, // Will be set via SetEmailService
		smsService:   nil, // Will be set via SetSMSService
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

// GetJWTManager returns the JWT manager (for middleware usage)
func (s *Service) GetJWTManager() *JWTManager {
	return s.jwtManager
}

// CreateMiddleware creates authentication middleware
func (s *Service) CreateMiddleware() *Middleware {
	return NewMiddleware(s.jwtManager, s)
}

// RequestPasswordReset creates a password reset token and sends it to the user
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

	// Generate reset token
	resetToken := &PasswordResetToken{
		ID:        uuid.New().String(),
		UserID:    user.ID,
		Token:     generateSecureToken(),
		ExpiresAt: time.Now().Add(1 * time.Hour), // Token expires in 1 hour
		Used:      false,
		CreatedAt: time.Now(),
	}

	// Save token to database
	err = s.repo.CreatePasswordResetToken(ctx, resetToken)
	if err != nil {
		return fmt.Errorf("failed to create password reset token: %w", err)
	}

	// Send password reset email
	if s.emailService != nil && user.Email != nil {
		err = s.emailService.SendPasswordReset(ctx, *user.Email, resetToken.Token, "Go Forward")
		if err != nil {
			return fmt.Errorf("failed to send password reset email: %w", err)
		}
	} else {
		// Fallback: log the token if email service is not configured
		fmt.Printf("Password reset token for user %s: %s (email service not configured)\n", user.ID, resetToken.Token)
	}

	return nil
}

// ConfirmPasswordReset validates the reset token and updates the user's password
func (s *Service) ConfirmPasswordReset(ctx context.Context, req *PasswordResetConfirmRequest) error {
	// Validate request
	if err := s.validator.ValidatePasswordResetConfirmRequest(req); err != nil {
		return err
	}

	// Get and validate reset token
	resetToken, err := s.repo.GetPasswordResetToken(ctx, req.Token)
	if err != nil {
		return fmt.Errorf("invalid or expired reset token")
	}

	// Update user's password
	err = s.UpdatePassword(ctx, resetToken.UserID, req.NewPassword)
	if err != nil {
		return fmt.Errorf("failed to update password: %w", err)
	}

	// Mark token as used
	err = s.repo.MarkPasswordResetTokenUsed(ctx, resetToken.ID)
	if err != nil {
		return fmt.Errorf("failed to mark reset token as used: %w", err)
	}

	return nil
}

// generateSecureToken generates a secure random token for password reset
func generateSecureToken() string {
	// Generate a random UUID and remove hyphens for simplicity
	token := uuid.New().String()
	return strings.ReplaceAll(token, "-", "")
}

// SendOTP generates and sends an OTP to the specified recipient
func (s *Service) SendOTP(ctx context.Context, req *OTPRequest) error {
	// Validate request
	if err := s.validator.ValidateOTPRequest(req); err != nil {
		return err
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

// VerifyOTP verifies an OTP code and returns the associated user if found
func (s *Service) VerifyOTP(ctx context.Context, req *VerifyOTPRequest) (*User, error) {
	// Validate request
	if err := s.validator.ValidateVerifyOTPRequest(req); err != nil {
		return nil, err
	}

	// Get the latest OTP for this recipient, type, and purpose
	otp, err := s.repo.GetLatestOTPWithPurpose(ctx, req.Recipient, req.Type, req.Purpose)
	if err != nil {
		return nil, fmt.Errorf("invalid or expired OTP")
	}

	// Verify purpose matches
	if otp.Purpose != req.Purpose {
		return nil, fmt.Errorf("OTP purpose mismatch")
	}

	// Only allow verification endpoint for verification purpose
	if req.Purpose != OTPPurposeVerification {
		return nil, fmt.Errorf("use appropriate endpoint for %s OTP", req.Purpose)
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

// LoginWithOTP authenticates a user using OTP and returns JWT tokens
func (s *Service) LoginWithOTP(ctx context.Context, req *VerifyOTPRequest) (*AuthResponse, error) {
	// Only allow login purpose for this endpoint
	if req.Purpose != OTPPurposeLogin {
		return nil, fmt.Errorf("only login OTPs are allowed for this endpoint")
	}

	// Get the latest OTP for this recipient, type, and purpose
	otp, err := s.repo.GetLatestOTPWithPurpose(ctx, req.Recipient, req.Type, req.Purpose)
	if err != nil {
		return nil, fmt.Errorf("invalid or expired OTP")
	}

	// Verify purpose matches
	if otp.Purpose != req.Purpose {
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

// RegisterWithOTP creates a new user using OTP verification and returns JWT tokens
func (s *Service) RegisterWithOTP(ctx context.Context, req *VerifyOTPRequest, password *string) (*AuthResponse, error) {
	// Only allow registration purpose for this endpoint
	if req.Purpose != OTPPurposeRegistration {
		return nil, fmt.Errorf("only registration OTPs are allowed for this endpoint")
	}

	// Get the latest OTP for this recipient, type, and purpose
	otp, err := s.repo.GetLatestOTPWithPurpose(ctx, req.Recipient, req.Type, req.Purpose)
	if err != nil {
		return nil, fmt.Errorf("invalid or expired OTP")
	}

	// Verify purpose matches
	if otp.Purpose != req.Purpose {
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
		// Generate a random password for phone-only registration
		createReq.Password = generateSecureToken()[:16]
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

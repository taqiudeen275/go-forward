package auth

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/taqiudeen275/go-foward/internal/database"
)

// Service handles authentication business logic
type Service struct {
	repo       UserRepositoryInterface
	hasher     *PasswordHasher
	validator  *Validator
	jwtManager *JWTManager
}

// NewService creates a new authentication service
func NewService(db *database.DB) *Service {
	// Default JWT configuration - should be overridden with actual config
	jwtManager := NewJWTManager("default-secret-key", 24*time.Hour, 7*24*time.Hour)

	return &Service{
		repo:       NewUserRepository(db),
		hasher:     NewPasswordHasher(),
		validator:  NewValidator(),
		jwtManager: jwtManager,
	}
}

// NewServiceWithConfig creates a new authentication service with custom JWT configuration
func NewServiceWithConfig(db *database.DB, jwtSecret string, accessExpiration, refreshExpiration time.Duration) *Service {
	jwtManager := NewJWTManager(jwtSecret, accessExpiration, refreshExpiration)

	return &Service{
		repo:       NewUserRepository(db),
		hasher:     NewPasswordHasher(),
		validator:  NewValidator(),
		jwtManager: jwtManager,
	}
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

	// TODO: Send email/SMS with reset token
	// For now, we'll just log it (in production, this should send an email/SMS)
	fmt.Printf("Password reset token for user %s: %s\n", user.ID, resetToken.Token)

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

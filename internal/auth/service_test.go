package auth

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// MockUserRepository is a mock implementation of UserRepository for testing
type MockUserRepository struct {
	mock.Mock
}

func (m *MockUserRepository) Create(ctx context.Context, user *User) error {
	args := m.Called(ctx, user)
	return args.Error(0)
}

func (m *MockUserRepository) GetByID(ctx context.Context, id string) (*User, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*User), args.Error(1)
}

func (m *MockUserRepository) GetByEmail(ctx context.Context, email string) (*User, error) {
	args := m.Called(ctx, email)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*User), args.Error(1)
}

func (m *MockUserRepository) GetByPhone(ctx context.Context, phone string) (*User, error) {
	args := m.Called(ctx, phone)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*User), args.Error(1)
}

func (m *MockUserRepository) GetByUsername(ctx context.Context, username string) (*User, error) {
	args := m.Called(ctx, username)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*User), args.Error(1)
}

func (m *MockUserRepository) GetByIdentifier(ctx context.Context, identifier string) (*User, error) {
	args := m.Called(ctx, identifier)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*User), args.Error(1)
}

func (m *MockUserRepository) Update(ctx context.Context, id string, req *UpdateUserRequest) (*User, error) {
	args := m.Called(ctx, id, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*User), args.Error(1)
}

func (m *MockUserRepository) Delete(ctx context.Context, id string) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

func (m *MockUserRepository) List(ctx context.Context, filter *UserFilter) ([]*User, error) {
	args := m.Called(ctx, filter)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*User), args.Error(1)
}

func (m *MockUserRepository) Exists(ctx context.Context, identifier string) (bool, error) {
	args := m.Called(ctx, identifier)
	return args.Bool(0), args.Error(1)
}

func (m *MockUserRepository) UpdatePassword(ctx context.Context, id string, hashedPassword string) error {
	args := m.Called(ctx, id, hashedPassword)
	return args.Error(0)
}

func (m *MockUserRepository) CreatePasswordResetToken(ctx context.Context, token *PasswordResetToken) error {
	args := m.Called(ctx, token)
	return args.Error(0)
}

func (m *MockUserRepository) GetPasswordResetToken(ctx context.Context, token string) (*PasswordResetToken, error) {
	args := m.Called(ctx, token)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*PasswordResetToken), args.Error(1)
}

func (m *MockUserRepository) MarkPasswordResetTokenUsed(ctx context.Context, tokenID string) error {
	args := m.Called(ctx, tokenID)
	return args.Error(0)
}

func (m *MockUserRepository) CleanupExpiredPasswordResetTokens(ctx context.Context) error {
	args := m.Called(ctx)
	return args.Error(0)
}

// OTP methods
func (m *MockUserRepository) CreateOTP(ctx context.Context, otp *OTP) error {
	args := m.Called(ctx, otp)
	return args.Error(0)
}

func (m *MockUserRepository) GetOTP(ctx context.Context, recipient string, otpType OTPType, code string) (*OTP, error) {
	args := m.Called(ctx, recipient, otpType, code)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*OTP), args.Error(1)
}

func (m *MockUserRepository) GetLatestOTP(ctx context.Context, recipient string, otpType OTPType) (*OTP, error) {
	args := m.Called(ctx, recipient, otpType)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*OTP), args.Error(1)
}

func (m *MockUserRepository) MarkOTPUsed(ctx context.Context, otpID string) error {
	args := m.Called(ctx, otpID)
	return args.Error(0)
}

func (m *MockUserRepository) IncrementOTPAttempts(ctx context.Context, otpID string) error {
	args := m.Called(ctx, otpID)
	return args.Error(0)
}

func (m *MockUserRepository) GetLatestOTPWithPurpose(ctx context.Context, recipient string, otpType OTPType, purpose OTPPurpose) (*OTP, error) {
	args := m.Called(ctx, recipient, otpType, purpose)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*OTP), args.Error(1)
}

func (m *MockUserRepository) CleanupExpiredOTPs(ctx context.Context) error {
	args := m.Called(ctx)
	return args.Error(0)
}

// createTestService creates a service with mocked dependencies for testing
func createTestService() (*Service, *MockUserRepository) {
	mockRepo := &MockUserRepository{}

	service := &Service{
		repo:       mockRepo,
		hasher:     NewPasswordHasher(),
		validator:  NewValidator(),
		jwtManager: NewJWTManager("test-secret-key", time.Hour, 24*time.Hour),
	}

	return service, mockRepo
}

// createTestUser creates a test user for testing
func createTestUser() *User {
	email := "test@example.com"
	username := "testuser"
	phone := "+1234567890"

	return &User{
		ID:            "test-user-id",
		Email:         &email,
		Username:      &username,
		Phone:         &phone,
		PasswordHash:  "$2a$12$test.hash.here",
		EmailVerified: false,
		PhoneVerified: false,
		Metadata:      map[string]interface{}{"role": "user"},
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
	}
}

func TestService_Register_Success(t *testing.T) {
	service, mockRepo := createTestService()
	ctx := context.Background()

	email := "test@example.com"
	req := &CreateUserRequest{
		Email:    &email,
		Password: "TestPassword123!",
		Metadata: map[string]interface{}{"role": "user"},
	}

	// Mock repository calls
	mockRepo.On("Exists", ctx, email).Return(false, nil)
	mockRepo.On("Create", ctx, mock.AnythingOfType("*auth.User")).Return(nil)

	// Execute
	response, err := service.Register(ctx, req)

	// Assert
	require.NoError(t, err)
	assert.NotNil(t, response)
	assert.NotNil(t, response.User)
	assert.NotEmpty(t, response.AccessToken)
	assert.NotEmpty(t, response.RefreshToken)
	assert.Greater(t, response.ExpiresIn, 0)
	assert.Equal(t, email, *response.User.Email)

	mockRepo.AssertExpectations(t)
}

func TestService_Register_UserAlreadyExists(t *testing.T) {
	service, mockRepo := createTestService()
	ctx := context.Background()

	email := "existing@example.com"
	req := &CreateUserRequest{
		Email:    &email,
		Password: "TestPassword123!",
	}

	// Mock repository calls
	mockRepo.On("Exists", ctx, email).Return(true, nil)

	// Execute
	response, err := service.Register(ctx, req)

	// Assert
	assert.Error(t, err)
	assert.Nil(t, response)
	assert.Contains(t, err.Error(), "already exists")

	mockRepo.AssertExpectations(t)
}

func TestService_Register_InvalidRequest(t *testing.T) {
	service, _ := createTestService()
	ctx := context.Background()

	testCases := []struct {
		name string
		req  *CreateUserRequest
	}{
		{
			name: "nil request",
			req:  nil,
		},
		{
			name: "no identifiers",
			req: &CreateUserRequest{
				Password: "TestPassword123!",
			},
		},
		{
			name: "weak password",
			req: &CreateUserRequest{
				Email:    stringPtr("test@example.com"),
				Password: "weak",
			},
		},
		{
			name: "invalid email",
			req: &CreateUserRequest{
				Email:    stringPtr("invalid-email"),
				Password: "TestPassword123!",
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			response, err := service.Register(ctx, tc.req)
			assert.Error(t, err)
			assert.Nil(t, response)
		})
	}
}

func TestService_Login_Success(t *testing.T) {
	service, mockRepo := createTestService()
	ctx := context.Background()

	user := createTestUser()
	password := "TestPassword123!"

	// Hash the password for comparison
	hashedPassword, err := service.hasher.HashPassword(password)
	require.NoError(t, err)
	user.PasswordHash = hashedPassword

	req := &LoginRequest{
		Identifier: *user.Email,
		Password:   password,
	}

	// Mock repository calls
	mockRepo.On("GetByIdentifier", ctx, *user.Email).Return(user, nil)

	// Execute
	response, err := service.Login(ctx, req)

	// Assert
	require.NoError(t, err)
	assert.NotNil(t, response)
	assert.NotNil(t, response.User)
	assert.NotEmpty(t, response.AccessToken)
	assert.NotEmpty(t, response.RefreshToken)
	assert.Greater(t, response.ExpiresIn, 0)
	assert.Equal(t, user.ID, response.User.ID)

	mockRepo.AssertExpectations(t)
}

func TestService_Login_InvalidCredentials(t *testing.T) {
	service, mockRepo := createTestService()
	ctx := context.Background()

	testCases := []struct {
		name       string
		identifier string
		password   string
		mockSetup  func()
	}{
		{
			name:       "user not found",
			identifier: "nonexistent@example.com",
			password:   "TestPassword123!",
			mockSetup: func() {
				mockRepo.On("GetByIdentifier", ctx, "nonexistent@example.com").Return(nil, assert.AnError)
			},
		},
		{
			name:       "wrong password",
			identifier: "test@example.com",
			password:   "WrongPassword123!",
			mockSetup: func() {
				user := createTestUser()
				hashedPassword, _ := service.hasher.HashPassword("CorrectPassword123!")
				user.PasswordHash = hashedPassword
				mockRepo.On("GetByIdentifier", ctx, "test@example.com").Return(user, nil)
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Reset mock
			mockRepo.ExpectedCalls = nil
			tc.mockSetup()

			req := &LoginRequest{
				Identifier: tc.identifier,
				Password:   tc.password,
			}

			response, err := service.Login(ctx, req)

			assert.Error(t, err)
			assert.Nil(t, response)
			assert.Contains(t, err.Error(), "invalid credentials")
		})
	}
}

func TestService_Login_InvalidRequest(t *testing.T) {
	service, _ := createTestService()
	ctx := context.Background()

	testCases := []struct {
		name string
		req  *LoginRequest
	}{
		{
			name: "nil request",
			req:  nil,
		},
		{
			name: "empty identifier",
			req: &LoginRequest{
				Identifier: "",
				Password:   "TestPassword123!",
			},
		},
		{
			name: "empty password",
			req: &LoginRequest{
				Identifier: "test@example.com",
				Password:   "",
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			response, err := service.Login(ctx, tc.req)
			assert.Error(t, err)
			assert.Nil(t, response)
		})
	}
}

func TestService_RefreshToken_Success(t *testing.T) {
	service, mockRepo := createTestService()
	ctx := context.Background()

	user := createTestUser()

	// Generate initial token pair
	tokenPair, err := service.jwtManager.GenerateTokenPair(user)
	require.NoError(t, err)

	// Mock repository calls
	mockRepo.On("GetByID", ctx, user.ID).Return(user, nil)

	// Execute
	response, err := service.RefreshToken(ctx, tokenPair.RefreshToken)

	// Assert
	require.NoError(t, err)
	assert.NotNil(t, response)
	assert.NotNil(t, response.User)
	assert.NotEmpty(t, response.AccessToken)
	assert.NotEmpty(t, response.RefreshToken)
	assert.Greater(t, response.ExpiresIn, 0)
	assert.Equal(t, user.ID, response.User.ID)

	// Validate that new tokens are valid (they may be the same due to same timestamp)
	newAccessClaims, err := service.ValidateToken(ctx, response.AccessToken)
	require.NoError(t, err)
	assert.Equal(t, user.ID, newAccessClaims.UserID)

	mockRepo.AssertExpectations(t)
}

func TestService_RefreshToken_InvalidToken(t *testing.T) {
	service, _ := createTestService()
	ctx := context.Background()

	testCases := []struct {
		name  string
		token string
	}{
		{
			name:  "invalid token",
			token: "invalid.token.here",
		},
		{
			name:  "empty token",
			token: "",
		},
		{
			name: "access token instead of refresh token",
			token: func() string {
				user := createTestUser()
				tokenPair, _ := service.jwtManager.GenerateTokenPair(user)
				return tokenPair.AccessToken
			}(),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			response, err := service.RefreshToken(ctx, tc.token)
			assert.Error(t, err)
			assert.Nil(t, response)
		})
	}
}

func TestService_ValidateToken_Success(t *testing.T) {
	service, _ := createTestService()
	ctx := context.Background()

	user := createTestUser()

	// Generate token pair
	tokenPair, err := service.jwtManager.GenerateTokenPair(user)
	require.NoError(t, err)

	// Execute
	claims, err := service.ValidateToken(ctx, tokenPair.AccessToken)

	// Assert
	require.NoError(t, err)
	assert.NotNil(t, claims)
	assert.Equal(t, user.ID, claims.UserID)
	assert.Equal(t, "access", claims.TokenType)
	assert.Equal(t, *user.Email, claims.Email)
	assert.Equal(t, *user.Username, claims.Username)
}

func TestService_ValidateToken_InvalidToken(t *testing.T) {
	service, _ := createTestService()
	ctx := context.Background()

	testCases := []struct {
		name  string
		token string
	}{
		{
			name:  "invalid token",
			token: "invalid.token.here",
		},
		{
			name:  "empty token",
			token: "",
		},
		{
			name: "expired token",
			token: func() string {
				// Create a JWT manager with very short expiration
				shortJWT := NewJWTManager("test-secret", time.Nanosecond, time.Hour)
				user := createTestUser()
				tokenPair, _ := shortJWT.GenerateTokenPair(user)
				time.Sleep(time.Millisecond) // Ensure token expires
				return tokenPair.AccessToken
			}(),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			claims, err := service.ValidateToken(ctx, tc.token)
			assert.Error(t, err)
			assert.Nil(t, claims)
		})
	}
}

// Helper function to create string pointers
func stringPtr(s string) *string {
	return &s
}

// JWT Token Generation and Validation Tests

func TestJWTManager_GenerateTokenPair_Success(t *testing.T) {
	jwtManager := NewJWTManager("test-secret-key", time.Hour, 24*time.Hour)
	user := createTestUser()

	// Execute
	tokenPair, err := jwtManager.GenerateTokenPair(user)

	// Assert
	require.NoError(t, err)
	assert.NotNil(t, tokenPair)
	assert.NotEmpty(t, tokenPair.AccessToken)
	assert.NotEmpty(t, tokenPair.RefreshToken)
	assert.Equal(t, int64(3600), tokenPair.ExpiresIn) // 1 hour in seconds

	// Validate that tokens are different
	assert.NotEqual(t, tokenPair.AccessToken, tokenPair.RefreshToken)
}

func TestJWTManager_ValidateAccessToken_Success(t *testing.T) {
	jwtManager := NewJWTManager("test-secret-key", time.Hour, 24*time.Hour)
	user := createTestUser()

	// Generate token pair
	tokenPair, err := jwtManager.GenerateTokenPair(user)
	require.NoError(t, err)

	// Execute
	claims, err := jwtManager.ValidateAccessToken(tokenPair.AccessToken)

	// Assert
	require.NoError(t, err)
	assert.NotNil(t, claims)
	assert.Equal(t, user.ID, claims.UserID)
	assert.Equal(t, "access", claims.TokenType)
	assert.Equal(t, *user.Email, claims.Email)
	assert.Equal(t, *user.Username, claims.Username)
	assert.Equal(t, *user.Phone, claims.Phone)
	assert.Equal(t, user.Metadata, claims.Metadata)
	assert.Equal(t, "go-forward", claims.Issuer)
	assert.Equal(t, user.ID, claims.Subject)
}

func TestJWTManager_ValidateRefreshToken_Success(t *testing.T) {
	jwtManager := NewJWTManager("test-secret-key", time.Hour, 24*time.Hour)
	user := createTestUser()

	// Generate token pair
	tokenPair, err := jwtManager.GenerateTokenPair(user)
	require.NoError(t, err)

	// Execute
	claims, err := jwtManager.ValidateRefreshToken(tokenPair.RefreshToken)

	// Assert
	require.NoError(t, err)
	assert.NotNil(t, claims)
	assert.Equal(t, user.ID, claims.UserID)
	assert.Equal(t, "refresh", claims.TokenType)
}

func TestJWTManager_ValidateToken_WrongTokenType(t *testing.T) {
	jwtManager := NewJWTManager("test-secret-key", time.Hour, 24*time.Hour)
	user := createTestUser()

	// Generate token pair
	tokenPair, err := jwtManager.GenerateTokenPair(user)
	require.NoError(t, err)

	// Try to validate access token as refresh token
	claims, err := jwtManager.ValidateRefreshToken(tokenPair.AccessToken)
	assert.Error(t, err)
	assert.Nil(t, claims)
	assert.Contains(t, err.Error(), "invalid token type")

	// Try to validate refresh token as access token
	claims, err = jwtManager.ValidateAccessToken(tokenPair.RefreshToken)
	assert.Error(t, err)
	assert.Nil(t, claims)
	assert.Contains(t, err.Error(), "invalid token type")
}

func TestJWTManager_ValidateToken_ExpiredToken(t *testing.T) {
	// Create JWT manager with very short expiration
	jwtManager := NewJWTManager("test-secret-key", time.Nanosecond, time.Nanosecond)
	user := createTestUser()

	// Generate token pair
	tokenPair, err := jwtManager.GenerateTokenPair(user)
	require.NoError(t, err)

	// Wait for token to expire
	time.Sleep(time.Millisecond)

	// Execute
	claims, err := jwtManager.ValidateAccessToken(tokenPair.AccessToken)

	// Assert
	assert.Error(t, err)
	assert.Nil(t, claims)
	assert.Contains(t, err.Error(), "expired")
}

func TestJWTManager_ValidateToken_InvalidSignature(t *testing.T) {
	jwtManager1 := NewJWTManager("secret-key-1", time.Hour, 24*time.Hour)
	jwtManager2 := NewJWTManager("secret-key-2", time.Hour, 24*time.Hour)
	user := createTestUser()

	// Generate token with first manager
	tokenPair, err := jwtManager1.GenerateTokenPair(user)
	require.NoError(t, err)

	// Try to validate with second manager (different secret)
	claims, err := jwtManager2.ValidateAccessToken(tokenPair.AccessToken)

	// Assert
	assert.Error(t, err)
	assert.Nil(t, claims)
}

func TestJWTManager_RefreshTokenPair_Success(t *testing.T) {
	jwtManager := NewJWTManager("test-secret-key", time.Hour, 24*time.Hour)
	user := createTestUser()

	// Generate initial token pair
	initialTokenPair, err := jwtManager.GenerateTokenPair(user)
	require.NoError(t, err)

	// Execute refresh
	newTokenPair, err := jwtManager.RefreshTokenPair(initialTokenPair.RefreshToken, user)

	// Assert
	require.NoError(t, err)
	assert.NotNil(t, newTokenPair)
	assert.NotEmpty(t, newTokenPair.AccessToken)
	assert.NotEmpty(t, newTokenPair.RefreshToken)

	// Validate that new tokens are valid (they may be the same due to same timestamp)
	accessClaims, err := jwtManager.ValidateAccessToken(newTokenPair.AccessToken)
	require.NoError(t, err)
	assert.Equal(t, user.ID, accessClaims.UserID)

	refreshClaims, err := jwtManager.ValidateRefreshToken(newTokenPair.RefreshToken)
	require.NoError(t, err)
	assert.Equal(t, user.ID, refreshClaims.UserID)
}

func TestJWTManager_ExtractUserID_Success(t *testing.T) {
	jwtManager := NewJWTManager("test-secret-key", time.Hour, 24*time.Hour)
	user := createTestUser()

	// Generate token pair
	tokenPair, err := jwtManager.GenerateTokenPair(user)
	require.NoError(t, err)

	// Execute
	userID, err := jwtManager.ExtractUserID(tokenPair.AccessToken)

	// Assert
	require.NoError(t, err)
	assert.Equal(t, user.ID, userID)
}

func TestJWTManager_GetTokenExpiration_Success(t *testing.T) {
	jwtManager := NewJWTManager("test-secret-key", time.Hour, 24*time.Hour)
	user := createTestUser()

	// Generate token pair
	tokenPair, err := jwtManager.GenerateTokenPair(user)
	require.NoError(t, err)

	// Execute
	expiration, err := jwtManager.GetTokenExpiration(tokenPair.AccessToken)

	// Assert
	require.NoError(t, err)
	assert.True(t, expiration.After(time.Now()))
	assert.True(t, expiration.Before(time.Now().Add(2*time.Hour))) // Should be within 2 hours
}

func TestJWTManager_IsTokenExpired(t *testing.T) {
	user := createTestUser()

	// Test with valid token
	jwtManager := NewJWTManager("test-secret-key", time.Hour, 24*time.Hour)
	tokenPair, err := jwtManager.GenerateTokenPair(user)
	require.NoError(t, err)

	assert.False(t, jwtManager.IsTokenExpired(tokenPair.AccessToken))

	// Test with expired token
	expiredJWT := NewJWTManager("test-secret-key", time.Nanosecond, time.Nanosecond)
	expiredTokenPair, err := expiredJWT.GenerateTokenPair(user)
	require.NoError(t, err)

	time.Sleep(time.Millisecond)
	assert.True(t, jwtManager.IsTokenExpired(expiredTokenPair.AccessToken))

	// Test with invalid token
	assert.True(t, jwtManager.IsTokenExpired("invalid.token.here"))
}

// Password Hashing and Validation Tests

func TestPasswordHasher_HashPassword_Success(t *testing.T) {
	hasher := NewPasswordHasher()
	password := "TestPassword123!"

	// Execute
	hash, err := hasher.HashPassword(password)

	// Assert
	require.NoError(t, err)
	assert.NotEmpty(t, hash)
	assert.NotEqual(t, password, hash)
	assert.True(t, len(hash) > 50) // bcrypt hashes are typically 60 characters
}

func TestPasswordHasher_HashPassword_EmptyPassword(t *testing.T) {
	hasher := NewPasswordHasher()

	// Execute
	hash, err := hasher.HashPassword("")

	// Assert
	assert.Error(t, err)
	assert.Empty(t, hash)
	assert.Contains(t, err.Error(), "password cannot be empty")
}

func TestPasswordHasher_ValidatePassword_Success(t *testing.T) {
	hasher := NewPasswordHasher()
	password := "TestPassword123!"

	// Hash the password
	hash, err := hasher.HashPassword(password)
	require.NoError(t, err)

	// Execute validation
	err = hasher.ValidatePassword(password, hash)

	// Assert
	assert.NoError(t, err)
}

func TestPasswordHasher_ValidatePassword_WrongPassword(t *testing.T) {
	hasher := NewPasswordHasher()
	password := "TestPassword123!"
	wrongPassword := "WrongPassword123!"

	// Hash the correct password
	hash, err := hasher.HashPassword(password)
	require.NoError(t, err)

	// Execute validation with wrong password
	err = hasher.ValidatePassword(wrongPassword, hash)

	// Assert
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid password")
}

func TestPasswordHasher_ValidatePassword_EmptyInputs(t *testing.T) {
	hasher := NewPasswordHasher()

	testCases := []struct {
		name     string
		password string
		hash     string
	}{
		{
			name:     "empty password",
			password: "",
			hash:     "$2a$12$test.hash.here",
		},
		{
			name:     "empty hash",
			password: "TestPassword123!",
			hash:     "",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := hasher.ValidatePassword(tc.password, tc.hash)
			assert.Error(t, err)
		})
	}
}

func TestPasswordHasher_NeedsRehash(t *testing.T) {
	// Test with same cost
	hasher := NewPasswordHasher()
	password := "TestPassword123!"

	hash, err := hasher.HashPassword(password)
	require.NoError(t, err)

	assert.False(t, hasher.NeedsRehash(hash))

	// Test with different cost
	differentCostHasher := NewPasswordHasherWithCost(10)
	assert.True(t, differentCostHasher.NeedsRehash(hash))

	// Test with invalid hash
	assert.True(t, hasher.NeedsRehash("invalid-hash"))
}

func TestPasswordHasher_CustomCost(t *testing.T) {
	cost := 10
	hasher := NewPasswordHasherWithCost(cost)
	password := "TestPassword123!"

	// Execute
	hash, err := hasher.HashPassword(password)

	// Assert
	require.NoError(t, err)
	assert.NotEmpty(t, hash)

	// Validate the password works
	err = hasher.ValidatePassword(password, hash)
	assert.NoError(t, err)
}

// Integration Tests for Authentication Flows

func TestService_CompleteRegistrationAndLoginFlow(t *testing.T) {
	service, mockRepo := createTestService()
	ctx := context.Background()

	email := "integration@example.com"
	password := "TestPassword123!"

	// Registration
	registerReq := &CreateUserRequest{
		Email:    &email,
		Password: password,
		Metadata: map[string]interface{}{"role": "user"},
	}

	// Mock repository calls for registration
	mockRepo.On("Exists", ctx, email).Return(false, nil)
	mockRepo.On("Create", ctx, mock.AnythingOfType("*auth.User")).Return(nil)

	// Execute registration
	registerResponse, err := service.Register(ctx, registerReq)
	require.NoError(t, err)
	assert.NotNil(t, registerResponse)

	// Simulate user creation in repository for login
	user := registerResponse.User
	hashedPassword, err := service.hasher.HashPassword(password)
	require.NoError(t, err)
	user.PasswordHash = hashedPassword

	// Login
	loginReq := &LoginRequest{
		Identifier: email,
		Password:   password,
	}

	// Mock repository calls for login
	mockRepo.On("GetByIdentifier", ctx, email).Return(user, nil)

	// Execute login
	loginResponse, err := service.Login(ctx, loginReq)
	require.NoError(t, err)
	assert.NotNil(t, loginResponse)
	assert.Equal(t, user.ID, loginResponse.User.ID)

	// Validate tokens
	accessClaims, err := service.ValidateToken(ctx, loginResponse.AccessToken)
	require.NoError(t, err)
	assert.Equal(t, user.ID, accessClaims.UserID)

	refreshClaims, err := service.jwtManager.ValidateRefreshToken(loginResponse.RefreshToken)
	require.NoError(t, err)
	assert.Equal(t, user.ID, refreshClaims.UserID)

	mockRepo.AssertExpectations(t)
}

func TestService_TokenRefreshFlow(t *testing.T) {
	service, mockRepo := createTestService()
	ctx := context.Background()

	user := createTestUser()

	// Generate initial tokens
	initialTokenPair, err := service.jwtManager.GenerateTokenPair(user)
	require.NoError(t, err)

	// Mock repository call for refresh
	mockRepo.On("GetByID", ctx, user.ID).Return(user, nil)

	// Execute token refresh
	refreshResponse, err := service.RefreshToken(ctx, initialTokenPair.RefreshToken)
	require.NoError(t, err)
	assert.NotNil(t, refreshResponse)

	// Verify new tokens are valid (they may be the same due to same timestamp)

	// Verify new tokens are valid
	newAccessClaims, err := service.ValidateToken(ctx, refreshResponse.AccessToken)
	require.NoError(t, err)
	assert.Equal(t, user.ID, newAccessClaims.UserID)

	newRefreshClaims, err := service.jwtManager.ValidateRefreshToken(refreshResponse.RefreshToken)
	require.NoError(t, err)
	assert.Equal(t, user.ID, newRefreshClaims.UserID)

	mockRepo.AssertExpectations(t)
}

func TestService_PasswordValidationFlow(t *testing.T) {
	service, mockRepo := createTestService()
	ctx := context.Background()

	user := createTestUser()
	password := "TestPassword123!"

	// Hash password
	hashedPassword, err := service.hasher.HashPassword(password)
	require.NoError(t, err)
	user.PasswordHash = hashedPassword

	// Mock repository call
	mockRepo.On("GetByIdentifier", ctx, *user.Email).Return(user, nil)

	// Execute password validation
	validatedUser, err := service.ValidatePassword(ctx, *user.Email, password)

	// Assert
	require.NoError(t, err)
	assert.NotNil(t, validatedUser)
	assert.Equal(t, user.ID, validatedUser.ID)

	mockRepo.AssertExpectations(t)
}

func TestService_PasswordValidationFlow_InvalidPassword(t *testing.T) {
	service, mockRepo := createTestService()
	ctx := context.Background()

	user := createTestUser()
	correctPassword := "TestPassword123!"
	wrongPassword := "WrongPassword123!"

	// Hash correct password
	hashedPassword, err := service.hasher.HashPassword(correctPassword)
	require.NoError(t, err)
	user.PasswordHash = hashedPassword

	// Mock repository call
	mockRepo.On("GetByIdentifier", ctx, *user.Email).Return(user, nil)

	// Execute password validation with wrong password
	validatedUser, err := service.ValidatePassword(ctx, *user.Email, wrongPassword)

	// Assert
	assert.Error(t, err)
	assert.Nil(t, validatedUser)
	assert.Contains(t, err.Error(), "invalid credentials")

	mockRepo.AssertExpectations(t)
}

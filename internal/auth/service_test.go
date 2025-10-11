package auth

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"golang.org/x/crypto/bcrypt"

	"github.com/taqiudeen275/go-foward/internal/config"
	"github.com/taqiudeen275/go-foward/pkg/errors"
)

// MockRepository is a mock implementation of the Repository interface
type MockRepository struct {
	mock.Mock
}

func (m *MockRepository) CreateUser(ctx context.Context, user *UnifiedUser) error {
	args := m.Called(ctx, user)
	return args.Error(0)
}

func (m *MockRepository) GetUserByID(ctx context.Context, id uuid.UUID) (*UnifiedUser, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*UnifiedUser), args.Error(1)
}

func (m *MockRepository) GetUserByEmail(ctx context.Context, email string) (*UnifiedUser, error) {
	args := m.Called(ctx, email)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*UnifiedUser), args.Error(1)
}

func (m *MockRepository) GetUserByPhone(ctx context.Context, phone string) (*UnifiedUser, error) {
	args := m.Called(ctx, phone)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*UnifiedUser), args.Error(1)
}

func (m *MockRepository) GetUserByUsername(ctx context.Context, username string) (*UnifiedUser, error) {
	args := m.Called(ctx, username)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*UnifiedUser), args.Error(1)
}

func (m *MockRepository) UpdateUser(ctx context.Context, user *UnifiedUser) error {
	args := m.Called(ctx, user)
	return args.Error(0)
}

func (m *MockRepository) DeleteUser(ctx context.Context, id uuid.UUID) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

func (m *MockRepository) ListUsers(ctx context.Context, filter *UserFilter) ([]*UnifiedUser, error) {
	args := m.Called(ctx, filter)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*UnifiedUser), args.Error(1)
}

func (m *MockRepository) PromoteToAdmin(ctx context.Context, userID uuid.UUID, level AdminLevel, capabilities *AdminCapabilities, promotedBy uuid.UUID) error {
	args := m.Called(ctx, userID, level, capabilities, promotedBy)
	return args.Error(0)
}

func (m *MockRepository) DemoteAdmin(ctx context.Context, userID uuid.UUID, demotedBy uuid.UUID) error {
	args := m.Called(ctx, userID, demotedBy)
	return args.Error(0)
}

func (m *MockRepository) ListAdmins(ctx context.Context, filter *AdminFilter) ([]*UnifiedUser, error) {
	args := m.Called(ctx, filter)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*UnifiedUser), args.Error(1)
}

func (m *MockRepository) CreateSession(ctx context.Context, session *AdminSession) error {
	args := m.Called(ctx, session)
	return args.Error(0)
}

func (m *MockRepository) GetSessionByToken(ctx context.Context, token string) (*AdminSession, error) {
	args := m.Called(ctx, token)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*AdminSession), args.Error(1)
}

func (m *MockRepository) UpdateSessionActivity(ctx context.Context, sessionID uuid.UUID) error {
	args := m.Called(ctx, sessionID)
	return args.Error(0)
}

func (m *MockRepository) DeleteSession(ctx context.Context, sessionID uuid.UUID) error {
	args := m.Called(ctx, sessionID)
	return args.Error(0)
}

func (m *MockRepository) DeleteUserSessions(ctx context.Context, userID uuid.UUID) error {
	args := m.Called(ctx, userID)
	return args.Error(0)
}

func (m *MockRepository) CleanExpiredSessions(ctx context.Context) error {
	args := m.Called(ctx)
	return args.Error(0)
}

func (m *MockRepository) CreateAPIKey(ctx context.Context, apiKey *APIKey) error {
	args := m.Called(ctx, apiKey)
	return args.Error(0)
}

func (m *MockRepository) GetAPIKeyByHash(ctx context.Context, keyHash string) (*APIKey, error) {
	args := m.Called(ctx, keyHash)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*APIKey), args.Error(1)
}

func (m *MockRepository) ListAPIKeys(ctx context.Context, userID uuid.UUID) ([]*APIKey, error) {
	args := m.Called(ctx, userID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*APIKey), args.Error(1)
}

func (m *MockRepository) UpdateAPIKeyLastUsed(ctx context.Context, id uuid.UUID) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

func (m *MockRepository) DeleteAPIKey(ctx context.Context, id uuid.UUID) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

func (m *MockRepository) CreateOTP(ctx context.Context, otp *OTPCode) error {
	args := m.Called(ctx, otp)
	return args.Error(0)
}

func (m *MockRepository) GetOTPByCode(ctx context.Context, code string, purpose string) (*OTPCode, error) {
	args := m.Called(ctx, code, purpose)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*OTPCode), args.Error(1)
}

func (m *MockRepository) GetOTPByIdentifier(ctx context.Context, identifier string, purpose string) (*OTPCode, error) {
	args := m.Called(ctx, identifier, purpose)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*OTPCode), args.Error(1)
}

func (m *MockRepository) UpdateOTPAttempts(ctx context.Context, id uuid.UUID, attempts int) error {
	args := m.Called(ctx, id, attempts)
	return args.Error(0)
}

func (m *MockRepository) MarkOTPUsed(ctx context.Context, id uuid.UUID) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

func (m *MockRepository) CleanExpiredOTPs(ctx context.Context) error {
	args := m.Called(ctx)
	return args.Error(0)
}

func (m *MockRepository) CreateTemplate(ctx context.Context, template *Template) error {
	args := m.Called(ctx, template)
	return args.Error(0)
}

func (m *MockRepository) GetTemplate(ctx context.Context, templateType TemplateType, purpose string, language string) (*Template, error) {
	args := m.Called(ctx, templateType, purpose, language)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*Template), args.Error(1)
}

func (m *MockRepository) UpdateTemplate(ctx context.Context, template *Template) error {
	args := m.Called(ctx, template)
	return args.Error(0)
}

func (m *MockRepository) DeleteTemplate(ctx context.Context, id uuid.UUID) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

func (m *MockRepository) ListTemplates(ctx context.Context, filter *TemplateFilter) ([]*Template, error) {
	args := m.Called(ctx, filter)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*Template), args.Error(1)
}

func (m *MockRepository) CreateAuditLog(ctx context.Context, log *AuditLog) error {
	args := m.Called(ctx, log)
	return args.Error(0)
}

func (m *MockRepository) ListAuditLogs(ctx context.Context, filter *AuditFilter) ([]*AuditLog, error) {
	args := m.Called(ctx, filter)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*AuditLog), args.Error(1)
}

func (m *MockRepository) CreateSecurityEvent(ctx context.Context, event *SecurityEvent) error {
	args := m.Called(ctx, event)
	return args.Error(0)
}

func (m *MockRepository) ListSecurityEvents(ctx context.Context, filter *SecurityEventFilter) ([]*SecurityEvent, error) {
	args := m.Called(ctx, filter)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*SecurityEvent), args.Error(1)
}

func (m *MockRepository) ResolveSecurityEvent(ctx context.Context, id uuid.UUID, resolvedBy uuid.UUID) error {
	args := m.Called(ctx, id, resolvedBy)
	return args.Error(0)
}

func (m *MockRepository) GetRateLimit(ctx context.Context, key string) (*RateLimit, error) {
	args := m.Called(ctx, key)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*RateLimit), args.Error(1)
}

func (m *MockRepository) UpsertRateLimit(ctx context.Context, rateLimit *RateLimit) error {
	args := m.Called(ctx, rateLimit)
	return args.Error(0)
}

func (m *MockRepository) CleanExpiredRateLimits(ctx context.Context) error {
	args := m.Called(ctx)
	return args.Error(0)
}

// Emergency access operations
func (m *MockRepository) CreateEmergencyAccess(ctx context.Context, access *EmergencyAccess) error {
	args := m.Called(ctx, access)
	return args.Error(0)
}

func (m *MockRepository) GetEmergencyAccessByID(ctx context.Context, id uuid.UUID) (*EmergencyAccess, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*EmergencyAccess), args.Error(1)
}

func (m *MockRepository) GetEmergencyAccessByToken(ctx context.Context, token string) (*EmergencyAccess, error) {
	args := m.Called(ctx, token)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*EmergencyAccess), args.Error(1)
}

func (m *MockRepository) UpdateEmergencyAccess(ctx context.Context, access *EmergencyAccess) error {
	args := m.Called(ctx, access)
	return args.Error(0)
}

func (m *MockRepository) ListEmergencyAccess(ctx context.Context, filter *EmergencyAccessFilter) ([]*EmergencyAccess, error) {
	args := m.Called(ctx, filter)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*EmergencyAccess), args.Error(1)
}

// Test helper functions
func createTestConfig() *config.Config {
	return &config.Config{
		Environment: "test",
		Auth: config.AuthConfig{
			JWTSecret:           "test-secret-key-that-is-long-enough-for-security",
			JWTExpiration:       24 * time.Hour,
			RefreshExpiration:   7 * 24 * time.Hour,
			OTPExpiration:       10 * time.Minute,
			OTPLength:           6,
			MaxFailedAttempts:   5,
			LockoutDuration:     15 * time.Minute,
			EnableMFA:           false,
			EnableCookieAuth:    true,
			CookieSecure:        true,
			CookieHTTPOnly:      true,
			CookieSameSite:      "Strict",
			PasswordMinLength:   8,
			RequireSpecialChars: true,
		},
		Admin: config.AdminConfig{
			SessionTimeout: 8 * time.Hour,
		},
	}
}

func createTestUser() *UnifiedUser {
	email := "test@example.com"
	// Generate proper bcrypt hash for "password123"
	hash, _ := bcrypt.GenerateFromPassword([]byte("password123"), 12)
	return &UnifiedUser{
		ID:            uuid.New(),
		Email:         &email,
		PasswordHash:  string(hash),
		EmailVerified: true,
		Metadata:      make(map[string]any),
		CreatedAt:     time.Now().UTC(),
		UpdatedAt:     time.Now().UTC(),
	}
}

func createTestAdmin() *UnifiedUser {
	email := "admin@example.com"
	adminLevel := AdminLevelSystemAdmin
	capabilities := GetDefaultCapabilities(AdminLevelSystemAdmin)
	// Generate proper bcrypt hash for "password123"
	hash, _ := bcrypt.GenerateFromPassword([]byte("password123"), 12)

	return &UnifiedUser{
		ID:             uuid.New(),
		Email:          &email,
		PasswordHash:   string(hash),
		EmailVerified:  true,
		AdminLevel:     &adminLevel,
		Capabilities:   &capabilities,
		AssignedTables: []string{},
		Metadata:       make(map[string]any),
		CreatedAt:      time.Now().UTC(),
		UpdatedAt:      time.Now().UTC(),
	}
}

// Test cases

func TestAuthService_Register(t *testing.T) {
	mockRepo := new(MockRepository)
	cfg := createTestConfig()
	service := NewAuthService(mockRepo, cfg)
	ctx := context.Background()

	t.Run("successful registration with email", func(t *testing.T) {
		email := "newuser@example.com"
		req := &RegisterRequest{
			Email:    &email,
			Password: "Password123!",
		}

		// Mock repository calls
		mockRepo.On("GetUserByEmail", ctx, email).Return(nil, errors.NewNotFound("user not found"))
		mockRepo.On("CreateUser", ctx, mock.AnythingOfType("*auth.UnifiedUser")).Return(nil)
		mockRepo.On("CreateAuditLog", ctx, mock.AnythingOfType("*auth.AuditLog")).Return(nil)

		resp, err := service.Register(ctx, req)

		assert.NoError(t, err)
		assert.NotNil(t, resp)
		assert.NotEmpty(t, resp.AccessToken)
		assert.NotEmpty(t, resp.RefreshToken)
		assert.Equal(t, email, *resp.User.Email)
		assert.True(t, resp.ExpiresAt.After(time.Now()))

		mockRepo.AssertExpectations(t)
	})

	t.Run("registration with existing email", func(t *testing.T) {
		email := "existing@example.com"
		req := &RegisterRequest{
			Email:    &email,
			Password: "Password123!",
		}

		existingUser := createTestUser()
		mockRepo.On("GetUserByEmail", ctx, email).Return(existingUser, nil)

		resp, err := service.Register(ctx, req)

		assert.Error(t, err)
		assert.Nil(t, resp)
		assert.Contains(t, err.Error(), "email already registered")

		mockRepo.AssertExpectations(t)
	})

	t.Run("registration with weak password", func(t *testing.T) {
		email := "newuser@example.com"
		req := &RegisterRequest{
			Email:    &email,
			Password: "weak",
		}

		resp, err := service.Register(ctx, req)

		assert.Error(t, err)
		assert.Nil(t, resp)
		assert.Contains(t, err.Error(), "password must be at least")
	})

	t.Run("registration without identifier", func(t *testing.T) {
		req := &RegisterRequest{
			Password: "Password123!",
		}

		resp, err := service.Register(ctx, req)

		assert.Error(t, err)
		assert.Nil(t, resp)
		assert.Contains(t, err.Error(), "at least one identifier")
	})
}

func TestAuthService_Login(t *testing.T) {
	mockRepo := new(MockRepository)
	cfg := createTestConfig()
	service := NewAuthService(mockRepo, cfg)
	ctx := context.Background()

	t.Run("successful login", func(t *testing.T) {
		user := createTestUser()
		req := &LoginRequest{
			Identifier: *user.Email,
			Password:   "password123",
		}

		mockRepo.On("GetUserByEmail", ctx, *user.Email).Return(user, nil)
		mockRepo.On("UpdateUser", ctx, mock.AnythingOfType("*auth.UnifiedUser")).Return(nil)
		mockRepo.On("CreateAuditLog", ctx, mock.AnythingOfType("*auth.AuditLog")).Return(nil)
		mockRepo.On("CreateSecurityEvent", ctx, mock.AnythingOfType("*auth.SecurityEvent")).Return(nil)

		resp, err := service.Login(ctx, req)

		assert.NoError(t, err)
		assert.NotNil(t, resp)
		assert.NotEmpty(t, resp.AccessToken)
		assert.NotEmpty(t, resp.RefreshToken)
		assert.Equal(t, user.ID, resp.User.ID)

		mockRepo.AssertExpectations(t)
	})

	t.Run("login with invalid password", func(t *testing.T) {
		user := createTestUser()
		req := &LoginRequest{
			Identifier: *user.Email,
			Password:   "wrongpassword",
		}

		mockRepo.On("GetUserByEmail", ctx, *user.Email).Return(user, nil)
		mockRepo.On("UpdateUser", ctx, mock.AnythingOfType("*auth.UnifiedUser")).Return(nil)
		mockRepo.On("CreateSecurityEvent", ctx, mock.AnythingOfType("*auth.SecurityEvent")).Return(nil)

		resp, err := service.Login(ctx, req)

		assert.Error(t, err)
		assert.Nil(t, resp)
		assert.Contains(t, err.Error(), "invalid credentials")

		mockRepo.AssertExpectations(t)
	})

	t.Run("login with locked account", func(t *testing.T) {
		// Create a fresh mock for this test to avoid interference
		freshMockRepo := new(MockRepository)
		freshService := NewAuthService(freshMockRepo, cfg)

		user := createTestUser()
		lockUntil := time.Now().Add(time.Hour)
		user.LockedUntil = &lockUntil

		req := &LoginRequest{
			Identifier: *user.Email,
			Password:   "password123",
		}

		freshMockRepo.On("GetUserByEmail", ctx, *user.Email).Return(user, nil)
		freshMockRepo.On("CreateSecurityEvent", ctx, mock.AnythingOfType("*auth.SecurityEvent")).Return(nil)

		resp, err := freshService.Login(ctx, req)

		assert.Error(t, err)
		assert.Nil(t, resp)
		assert.Contains(t, err.Error(), "account is locked")

		freshMockRepo.AssertExpectations(t)
	})

	t.Run("login with non-existent user", func(t *testing.T) {
		req := &LoginRequest{
			Identifier: "nonexistent@example.com",
			Password:   "password123",
		}

		mockRepo.On("GetUserByEmail", ctx, "nonexistent@example.com").Return(nil, errors.NewNotFound("user not found"))
		mockRepo.On("CreateSecurityEvent", ctx, mock.AnythingOfType("*auth.SecurityEvent")).Return(nil)

		resp, err := service.Login(ctx, req)

		assert.Error(t, err)
		assert.Nil(t, resp)
		assert.Contains(t, err.Error(), "invalid credentials")

		mockRepo.AssertExpectations(t)
	})
}

func TestAuthService_SendOTP(t *testing.T) {
	mockRepo := new(MockRepository)
	cfg := createTestConfig()
	service := NewAuthService(mockRepo, cfg)
	ctx := context.Background()

	t.Run("send OTP to email", func(t *testing.T) {
		req := &OTPRequest{
			Identifier: "test@example.com",
			Purpose:    "login",
		}

		user := createTestUser()
		mockRepo.On("GetUserByEmail", ctx, "test@example.com").Return(user, nil)
		mockRepo.On("CreateOTP", ctx, mock.AnythingOfType("*auth.OTPCode")).Return(nil)
		mockRepo.On("CreateAuditLog", ctx, mock.AnythingOfType("*auth.AuditLog")).Return(nil)

		err := service.SendOTP(ctx, req)

		assert.NoError(t, err)
		mockRepo.AssertExpectations(t)
	})

	t.Run("send OTP to phone", func(t *testing.T) {
		req := &OTPRequest{
			Identifier: "+1234567890",
			Purpose:    "login",
		}

		mockRepo.On("GetUserByPhone", ctx, "+1234567890").Return(nil, errors.NewNotFound("user not found"))
		mockRepo.On("CreateOTP", ctx, mock.AnythingOfType("*auth.OTPCode")).Return(nil)

		err := service.SendOTP(ctx, req)

		assert.NoError(t, err)
		mockRepo.AssertExpectations(t)
	})
}

func TestAuthService_VerifyOTP(t *testing.T) {
	mockRepo := new(MockRepository)
	cfg := createTestConfig()
	service := NewAuthService(mockRepo, cfg)
	ctx := context.Background()

	t.Run("successful OTP verification for login", func(t *testing.T) {
		email := "test@example.com"
		otp := &OTPCode{
			ID:          uuid.New(),
			Email:       &email,
			Code:        "123456",
			Purpose:     "login",
			MaxAttempts: 3,
			ExpiresAt:   time.Now().Add(10 * time.Minute),
			CreatedAt:   time.Now().UTC(),
		}

		user := createTestUser()
		user.Email = &email

		req := &VerifyOTPRequest{
			Identifier: email,
			Code:       "123456",
			Purpose:    "login",
		}

		mockRepo.On("GetOTPByIdentifier", ctx, email, "login").Return(otp, nil)
		mockRepo.On("MarkOTPUsed", ctx, otp.ID).Return(nil)
		mockRepo.On("GetUserByEmail", ctx, email).Return(user, nil)
		mockRepo.On("CreateAuditLog", ctx, mock.AnythingOfType("*auth.AuditLog")).Return(nil)

		resp, err := service.VerifyOTP(ctx, req)

		assert.NoError(t, err)
		assert.NotNil(t, resp)
		assert.NotEmpty(t, resp.AccessToken)
		assert.Equal(t, user.ID, resp.User.ID)

		mockRepo.AssertExpectations(t)
	})

	t.Run("OTP verification with expired code", func(t *testing.T) {
		// Create a fresh mock for this test to avoid interference
		freshMockRepo := new(MockRepository)
		freshService := NewAuthService(freshMockRepo, cfg)

		email := "test@example.com"
		otp := &OTPCode{
			ID:          uuid.New(),
			Email:       &email,
			Code:        "123456",
			Purpose:     "login",
			MaxAttempts: 3,
			ExpiresAt:   time.Now().Add(-time.Minute), // Expired
			CreatedAt:   time.Now().UTC(),
		}

		req := &VerifyOTPRequest{
			Identifier: email,
			Code:       "123456",
			Purpose:    "login",
		}

		freshMockRepo.On("GetOTPByIdentifier", ctx, email, "login").Return(otp, nil)
		freshMockRepo.On("CreateSecurityEvent", ctx, mock.AnythingOfType("*auth.SecurityEvent")).Return(nil)

		resp, err := freshService.VerifyOTP(ctx, req)

		assert.Error(t, err)
		assert.Nil(t, resp)
		assert.Contains(t, err.Error(), "OTP has expired")

		freshMockRepo.AssertExpectations(t)
	})

	t.Run("OTP verification with invalid code", func(t *testing.T) {
		email := "test@example.com"
		otp := &OTPCode{
			ID:          uuid.New(),
			Email:       &email,
			Code:        "123456",
			Purpose:     "login",
			MaxAttempts: 3,
			ExpiresAt:   time.Now().Add(10 * time.Minute),
			CreatedAt:   time.Now().UTC(),
		}

		req := &VerifyOTPRequest{
			Identifier: email,
			Code:       "654321", // Wrong code
			Purpose:    "login",
		}

		mockRepo.On("GetOTPByIdentifier", ctx, email, "login").Return(otp, nil)
		mockRepo.On("UpdateOTPAttempts", ctx, mock.AnythingOfType("uuid.UUID"), 1).Return(nil)
		mockRepo.On("CreateSecurityEvent", ctx, mock.AnythingOfType("*auth.SecurityEvent")).Return(nil)

		resp, err := service.VerifyOTP(ctx, req)

		assert.Error(t, err)
		assert.Nil(t, resp)
		assert.Contains(t, err.Error(), "invalid OTP code")

		mockRepo.AssertExpectations(t)
	})
}

func TestAuthService_AuthenticateAdmin(t *testing.T) {
	mockRepo := new(MockRepository)
	cfg := createTestConfig()
	service := NewAuthService(mockRepo, cfg)
	ctx := context.Background()

	t.Run("successful admin authentication", func(t *testing.T) {
		admin := createTestAdmin()
		req := &AdminAuthRequest{
			Identifier: *admin.Email,
			Password:   "password123",
		}

		mockRepo.On("GetUserByEmail", ctx, *admin.Email).Return(admin, nil)
		mockRepo.On("UpdateUser", ctx, mock.AnythingOfType("*auth.UnifiedUser")).Return(nil)
		mockRepo.On("CreateSession", ctx, mock.AnythingOfType("*auth.AdminSession")).Return(nil)
		mockRepo.On("CreateAuditLog", ctx, mock.AnythingOfType("*auth.AuditLog")).Return(nil)

		resp, err := service.AuthenticateAdmin(ctx, req)

		assert.NoError(t, err)
		assert.NotNil(t, resp)
		assert.NotEmpty(t, resp.AccessToken)
		assert.NotNil(t, resp.Session)
		assert.Equal(t, admin.ID, resp.User.ID)
		assert.True(t, resp.User.IsAdmin())

		mockRepo.AssertExpectations(t)
	})

	t.Run("admin authentication with non-admin user", func(t *testing.T) {
		user := createTestUser() // Regular user, not admin
		req := &AdminAuthRequest{
			Identifier: *user.Email,
			Password:   "password123",
		}

		mockRepo.On("GetUserByEmail", ctx, *user.Email).Return(user, nil)
		mockRepo.On("CreateSecurityEvent", ctx, mock.AnythingOfType("*auth.SecurityEvent")).Return(nil)

		resp, err := service.AuthenticateAdmin(ctx, req)

		assert.Error(t, err)
		assert.Nil(t, resp)
		assert.Contains(t, err.Error(), "insufficient privileges")

		mockRepo.AssertExpectations(t)
	})
}

func TestAuthService_CreateSystemAdmin(t *testing.T) {
	mockRepo := new(MockRepository)
	cfg := createTestConfig()
	service := NewAuthService(mockRepo, cfg)
	ctx := context.Background()

	t.Run("successful system admin creation", func(t *testing.T) {
		req := &CreateSystemAdminRequest{
			Email:    "sysadmin@example.com",
			Password: "SecurePassword123!",
			Username: "sysadmin",
		}

		mockRepo.On("GetUserByEmail", ctx, req.Email).Return(nil, errors.NewNotFound("user not found"))
		mockRepo.On("GetUserByUsername", ctx, req.Username).Return(nil, errors.NewNotFound("user not found"))
		mockRepo.On("CreateUser", ctx, mock.AnythingOfType("*auth.UnifiedUser")).Return(nil)
		mockRepo.On("CreateAuditLog", ctx, mock.AnythingOfType("*auth.AuditLog")).Return(nil)

		user, err := service.CreateSystemAdmin(ctx, req)

		assert.NoError(t, err)
		assert.NotNil(t, user)
		assert.Equal(t, req.Email, *user.Email)
		assert.Equal(t, req.Username, *user.Username)
		assert.True(t, user.IsSystemAdmin())
		assert.True(t, user.EmailVerified)

		mockRepo.AssertExpectations(t)
	})

	t.Run("system admin creation with existing email", func(t *testing.T) {
		req := &CreateSystemAdminRequest{
			Email:    "existing@example.com",
			Password: "SecurePassword123!",
		}

		existingUser := createTestUser()
		mockRepo.On("GetUserByEmail", ctx, req.Email).Return(existingUser, nil)

		user, err := service.CreateSystemAdmin(ctx, req)

		assert.Error(t, err)
		assert.Nil(t, user)
		assert.Contains(t, err.Error(), "email already registered")

		mockRepo.AssertExpectations(t)
	})
}

func TestAuthService_ValidatePassword(t *testing.T) {
	mockRepo := new(MockRepository)
	cfg := createTestConfig()
	service := NewAuthService(mockRepo, cfg)

	t.Run("valid password", func(t *testing.T) {
		err := service.ValidatePassword("SecurePassword123!")
		assert.NoError(t, err)
	})

	t.Run("password too short", func(t *testing.T) {
		err := service.ValidatePassword("Short1!")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "password must be at least")
	})

	t.Run("password missing uppercase", func(t *testing.T) {
		err := service.ValidatePassword("lowercase123!")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "must contain uppercase")
	})

	t.Run("password missing lowercase", func(t *testing.T) {
		err := service.ValidatePassword("UPPERCASE123!")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "must contain uppercase")
	})

	t.Run("password missing digit", func(t *testing.T) {
		err := service.ValidatePassword("NoDigitsHere!")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "must contain uppercase")
	})

	t.Run("password missing special character", func(t *testing.T) {
		err := service.ValidatePassword("NoSpecialChars123")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "must contain uppercase")
	})
}

func TestAuthService_ChangePassword(t *testing.T) {
	mockRepo := new(MockRepository)
	cfg := createTestConfig()
	service := NewAuthService(mockRepo, cfg)
	ctx := context.Background()

	t.Run("successful password change", func(t *testing.T) {
		user := createTestUser()
		userID := user.ID

		mockRepo.On("GetUserByID", ctx, userID).Return(user, nil)
		mockRepo.On("UpdateUser", ctx, mock.AnythingOfType("*auth.UnifiedUser")).Return(nil)
		mockRepo.On("DeleteUserSessions", ctx, userID).Return(nil)
		mockRepo.On("CreateAuditLog", ctx, mock.AnythingOfType("*auth.AuditLog")).Return(nil)

		err := service.ChangePassword(ctx, userID, "password123", "NewPassword123!")

		assert.NoError(t, err)
		mockRepo.AssertExpectations(t)
	})

	t.Run("password change with invalid old password", func(t *testing.T) {
		user := createTestUser()
		userID := user.ID

		mockRepo.On("GetUserByID", ctx, userID).Return(user, nil)
		mockRepo.On("CreateSecurityEvent", ctx, mock.AnythingOfType("*auth.SecurityEvent")).Return(nil)

		err := service.ChangePassword(ctx, userID, "wrongpassword", "NewPassword123!")

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid current password")
		mockRepo.AssertExpectations(t)
	})
}

func TestAuthService_ValidateToken(t *testing.T) {
	mockRepo := new(MockRepository)
	cfg := createTestConfig()
	service := NewAuthService(mockRepo, cfg)
	ctx := context.Background()

	t.Run("valid token", func(t *testing.T) {
		user := createTestUser()

		// Generate a token first
		accessToken, _, _, err := service.(*authService).generateTokens(user)
		assert.NoError(t, err)

		// Validate the token
		claims, err := service.ValidateToken(ctx, accessToken)

		assert.NoError(t, err)
		assert.NotNil(t, claims)
		assert.Equal(t, user.ID, claims.UserID)
	})

	t.Run("invalid token", func(t *testing.T) {
		claims, err := service.ValidateToken(ctx, "invalid.token.here")

		assert.Error(t, err)
		assert.Nil(t, claims)
		assert.Contains(t, err.Error(), "invalid token")
	})

	t.Run("expired token", func(t *testing.T) {
		// This would require mocking time or using a very short expiration
		// For now, we'll test with a malformed token
		claims, err := service.ValidateToken(ctx, "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE1MTYyMzkwMjJ9.invalid")

		assert.Error(t, err)
		assert.Nil(t, claims)
	})
}

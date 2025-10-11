package auth

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/taqiudeen275/go-foward/internal/config"
	"github.com/taqiudeen275/go-foward/internal/template"
)

// TestOTPIntegration tests the complete OTP flow with templates
func TestOTPIntegration(t *testing.T) {
	// Create mock repository
	mockRepo := &MockRepository{}

	// Create mock template service
	mockTemplateService := &MockTemplateService{}

	// Create test config
	cfg := &config.Config{
		Auth: config.AuthConfig{
			OTPLength:     6,
			OTPExpiration: 10 * time.Minute,
		},
	}

	// Create OTP service
	otpService := NewOTPService(mockRepo, mockTemplateService, cfg)

	ctx := context.Background()

	t.Run("Send OTP via Email", func(t *testing.T) {
		// Setup mocks
		mockRepo.On("GetUserByEmail", ctx, "test@example.com").Return(nil, nil)
		mockRepo.On("CreateOTP", ctx, mock.AnythingOfType("*auth.OTPCode")).Return(nil)
		mockTemplateService.On("SendEmail", ctx,
			template.TemplateTypeEmail,
			template.TemplatePurpose("login"),
			"en",
			mock.AnythingOfType("map[string]interface {}"),
			[]string{"test@example.com"}).Return(nil)

		// Test OTP request
		req := &OTPRequest{
			Identifier: "test@example.com",
			Purpose:    "login",
		}

		err := otpService.SendOTP(ctx, req)
		assert.NoError(t, err)

		// Verify mocks were called
		mockRepo.AssertExpectations(t)
		mockTemplateService.AssertExpectations(t)
	})

	t.Run("Send OTP via SMS", func(t *testing.T) {
		// Reset mocks
		mockRepo = &MockRepository{}
		mockTemplateService = &MockTemplateService{}
		otpService = NewOTPService(mockRepo, mockTemplateService, cfg)

		// Setup mocks
		mockRepo.On("GetUserByPhone", ctx, "+1234567890").Return(nil, nil)
		mockRepo.On("CreateOTP", ctx, mock.AnythingOfType("*auth.OTPCode")).Return(nil)
		mockTemplateService.On("SendSMS", ctx,
			template.TemplatePurpose("login"),
			"en",
			mock.AnythingOfType("map[string]interface {}"),
			"+1234567890").Return(nil)

		// Test OTP request
		req := &OTPRequest{
			Identifier: "+1234567890",
			Purpose:    "login",
		}

		err := otpService.SendOTP(ctx, req)
		assert.NoError(t, err)

		// Verify mocks were called
		mockRepo.AssertExpectations(t)
		mockTemplateService.AssertExpectations(t)
	})

	t.Run("Verify OTP Success", func(t *testing.T) {
		// Reset mocks
		mockRepo = &MockRepository{}
		mockTemplateService = &MockTemplateService{}
		otpService = NewOTPService(mockRepo, mockTemplateService, cfg)

		// Create test OTP
		otp := &OTPCode{
			Email:       stringPtrHelper("test@example.com"),
			Code:        "123456",
			Purpose:     "login",
			Attempts:    0,
			MaxAttempts: 3,
			ExpiresAt:   time.Now().Add(10 * time.Minute),
		}

		// Create test user
		user := &UnifiedUser{
			Email:         stringPtrHelper("test@example.com"),
			EmailVerified: true,
		}

		// Setup mocks
		mockRepo.On("GetOTPByIdentifier", ctx, "test@example.com", "login").Return(otp, nil)
		mockRepo.On("MarkOTPUsed", ctx, otp.ID).Return(nil)
		mockRepo.On("GetUserByEmail", ctx, "test@example.com").Return(user, nil)

		// Test OTP verification
		req := &VerifyOTPRequest{
			Identifier: "test@example.com",
			Code:       "123456",
			Purpose:    "login",
		}

		resp, err := otpService.VerifyOTP(ctx, req)
		assert.NoError(t, err)
		assert.NotNil(t, resp)
		assert.Equal(t, user, resp.User)

		// Verify mocks were called
		mockRepo.AssertExpectations(t)
	})

	t.Run("Rate Limiting", func(t *testing.T) {
		// Reset mocks
		mockRepo = &MockRepository{}
		mockTemplateService = &MockTemplateService{}
		otpService = NewOTPService(mockRepo, mockTemplateService, cfg)

		identifier := "test@example.com"

		// First request should succeed
		err := otpService.CheckOTPRateLimit(ctx, identifier)
		assert.NoError(t, err)

		// Record multiple attempts
		for i := 0; i < 5; i++ {
			otpService.RecordOTPAttempt(ctx, identifier, true)
		}

		// Next request should be rate limited
		err = otpService.CheckOTPRateLimit(ctx, identifier)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "rate limit exceeded")
	})
}

// MockTemplateService for testing
type MockTemplateService struct {
	mock.Mock
}

func (m *MockTemplateService) SendEmail(ctx context.Context, templateType template.TemplateType, purpose template.TemplatePurpose, language string, variables map[string]interface{}, to []string) error {
	args := m.Called(ctx, templateType, purpose, language, variables, to)
	return args.Error(0)
}

func (m *MockTemplateService) SendSMS(ctx context.Context, purpose template.TemplatePurpose, language string, variables map[string]interface{}, to string) error {
	args := m.Called(ctx, purpose, language, variables, to)
	return args.Error(0)
}

// Helper function for string pointer
func stringPtrHelper(s string) *string {
	return &s
}

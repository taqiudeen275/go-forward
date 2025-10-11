package email

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// MockEmailProvider is a mock implementation of EmailProvider for testing
type MockEmailProvider struct {
	mock.Mock
}

func (m *MockEmailProvider) SendEmail(ctx context.Context, to, subject, body string) error {
	args := m.Called(ctx, to, subject, body)
	return args.Error(0)
}

func (m *MockEmailProvider) SendHTMLEmail(ctx context.Context, to, subject, htmlBody, textBody string) error {
	args := m.Called(ctx, to, subject, htmlBody, textBody)
	return args.Error(0)
}

func TestService_SendOTP(t *testing.T) {
	mockProvider := &MockEmailProvider{}
	service := NewService(mockProvider, "Test App")

	ctx := context.Background()
	to := "test@example.com"
	otp := "123456"
	appName := "Test App"

	// Set up mock expectations
	mockProvider.On("SendHTMLEmail", ctx, to, mock.AnythingOfType("string"), mock.AnythingOfType("string"), mock.AnythingOfType("string")).Return(nil)

	// Call the method
	err := service.SendOTP(ctx, to, otp, appName)

	// Assertions
	assert.NoError(t, err)
	mockProvider.AssertExpectations(t)

	// Verify the call was made with correct parameters
	calls := mockProvider.Calls
	assert.Len(t, calls, 1)

	// Check that the subject contains the app name
	subject := calls[0].Arguments[2].(string)
	assert.Contains(t, subject, appName)

	// Check that the HTML body contains the OTP
	htmlBody := calls[0].Arguments[3].(string)
	assert.Contains(t, htmlBody, otp)

	// Check that the text body contains the OTP
	textBody := calls[0].Arguments[4].(string)
	assert.Contains(t, textBody, otp)
}

func TestService_SendPasswordReset(t *testing.T) {
	mockProvider := &MockEmailProvider{}
	service := NewService(mockProvider, "Test App")

	ctx := context.Background()
	to := "test@example.com"
	resetToken := "reset-token-123"
	appName := "Test App"

	// Set up mock expectations
	mockProvider.On("SendHTMLEmail", ctx, to, mock.AnythingOfType("string"), mock.AnythingOfType("string"), mock.AnythingOfType("string")).Return(nil)

	// Call the method
	err := service.SendPasswordReset(ctx, to, resetToken, appName)

	// Assertions
	assert.NoError(t, err)
	mockProvider.AssertExpectations(t)

	// Verify the call was made with correct parameters
	calls := mockProvider.Calls
	assert.Len(t, calls, 1)

	// Check that the subject contains password reset
	subject := calls[0].Arguments[2].(string)
	assert.Contains(t, strings.ToLower(subject), "password reset")

	// Check that the HTML body contains the reset token
	htmlBody := calls[0].Arguments[3].(string)
	assert.Contains(t, htmlBody, resetToken)

	// Check that the text body contains the reset token
	textBody := calls[0].Arguments[4].(string)
	assert.Contains(t, textBody, resetToken)
}

func TestService_SendWelcome(t *testing.T) {
	mockProvider := &MockEmailProvider{}
	service := NewService(mockProvider, "Test App")

	ctx := context.Background()
	to := "test@example.com"
	name := "John Doe"
	appName := "Test App"

	// Set up mock expectations
	mockProvider.On("SendHTMLEmail", ctx, to, mock.AnythingOfType("string"), mock.AnythingOfType("string"), mock.AnythingOfType("string")).Return(nil)

	// Call the method
	err := service.SendWelcome(ctx, to, name, appName)

	// Assertions
	assert.NoError(t, err)
	mockProvider.AssertExpectations(t)

	// Verify the call was made with correct parameters
	calls := mockProvider.Calls
	assert.Len(t, calls, 1)

	// Check that the subject contains welcome
	subject := calls[0].Arguments[2].(string)
	assert.Contains(t, strings.ToLower(subject), "welcome")

	// Check that the HTML body contains the user name
	htmlBody := calls[0].Arguments[3].(string)
	assert.Contains(t, htmlBody, name)

	// Check that the text body contains the user name
	textBody := calls[0].Arguments[4].(string)
	assert.Contains(t, textBody, name)
}

func TestService_renderTemplate(t *testing.T) {
	service := NewService(nil, "Test App")

	template := "Hello {{.UserName}}, welcome to {{.AppName}}! Your OTP is {{.OTP}}"
	data := TemplateData{
		AppName:  "Test App",
		UserName: "John Doe",
		OTP:      "123456",
	}

	result := service.renderTemplate(template, data)
	expected := "Hello John Doe, welcome to Test App! Your OTP is 123456"

	assert.Equal(t, expected, result)
}

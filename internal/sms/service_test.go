package sms

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// MockSMSProvider is a mock implementation of SMSProvider for testing
type MockSMSProvider struct {
	mock.Mock
}

func (m *MockSMSProvider) SendSMS(ctx context.Context, to, message string) error {
	args := m.Called(ctx, to, message)
	return args.Error(0)
}

func (m *MockSMSProvider) SendOTP(ctx context.Context, to, otp, appName string) error {
	args := m.Called(ctx, to, otp, appName)
	return args.Error(0)
}

func (m *MockSMSProvider) GetBalance(ctx context.Context) (*BalanceInfo, error) {
	args := m.Called(ctx)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*BalanceInfo), args.Error(1)
}

func TestService_SendOTP(t *testing.T) {
	mockProvider := &MockSMSProvider{}
	service := NewService(mockProvider, "Test App")

	ctx := context.Background()
	to := "+233123456789"
	otp := "123456"
	appName := "Test App"

	// Set up mock expectations
	mockProvider.On("SendOTP", ctx, to, otp, appName).Return(nil)

	// Call the method
	err := service.SendOTP(ctx, to, otp, appName)

	// Assertions
	assert.NoError(t, err)
	mockProvider.AssertExpectations(t)
}

func TestService_SendOTP_InvalidPhone(t *testing.T) {
	mockProvider := &MockSMSProvider{}
	service := NewService(mockProvider, "Test App")

	ctx := context.Background()
	invalidPhones := []string{
		"",
		"123",
		"invalid-phone",
		"12345678901234567890123", // too long
	}

	for _, phone := range invalidPhones {
		err := service.SendOTP(ctx, phone, "123456", "Test App")
		assert.Error(t, err, "Expected error for phone: %s", phone)
		assert.Contains(t, err.Error(), "invalid phone number")
	}
}

func TestService_SendMessage(t *testing.T) {
	mockProvider := &MockSMSProvider{}
	service := NewService(mockProvider, "Test App")

	ctx := context.Background()
	to := "+233123456789"
	message := "Test message"

	// Set up mock expectations
	mockProvider.On("SendSMS", ctx, to, message).Return(nil)

	// Call the method
	err := service.SendMessage(ctx, to, message)

	// Assertions
	assert.NoError(t, err)
	mockProvider.AssertExpectations(t)
}

func TestService_GetBalance(t *testing.T) {
	mockProvider := &MockSMSProvider{}
	service := NewService(mockProvider, "Test App")

	ctx := context.Background()
	expectedBalance := &BalanceInfo{
		Balance:  100.50,
		Currency: "GHS",
		Units:    "SMS",
	}

	// Set up mock expectations
	mockProvider.On("GetBalance", ctx).Return(expectedBalance, nil)

	// Call the method
	balance, err := service.GetBalance(ctx)

	// Assertions
	assert.NoError(t, err)
	assert.Equal(t, expectedBalance, balance)
	mockProvider.AssertExpectations(t)
}

func TestService_validatePhoneNumber(t *testing.T) {
	service := NewService(nil, "Test App")

	// Valid phone numbers
	validPhones := []string{
		"+233123456789",
		"233123456789",
		"0123456789",
		"+1234567890",
		"(233) 123-456-789",
		"233 123 456 789",
	}

	for _, phone := range validPhones {
		err := service.validatePhoneNumber(phone)
		assert.NoError(t, err, "Expected no error for phone: %s", phone)
	}

	// Invalid phone numbers
	invalidPhones := []string{
		"",
		"123",
		"invalid-phone",
		"12345678901234567890123", // too long
		"abc123456789",
	}

	for _, phone := range invalidPhones {
		err := service.validatePhoneNumber(phone)
		assert.Error(t, err, "Expected error for phone: %s", phone)
	}
}

func TestService_FormatPhoneNumber(t *testing.T) {
	service := NewService(nil, "Test App")

	testCases := []struct {
		input    string
		expected string
	}{
		{"+233123456789", "+233123456789"},
		{"233123456789", "+233123456789"},
		{"0123456789", "+233123456789"},
		{"123456789", "+233123456789"},
		{"+1234567890", "+1234567890"},
		{"(233) 123-456-789", "+233123456789"},
		{"233 123 456 789", "+233123456789"},
	}

	for _, tc := range testCases {
		result := service.FormatPhoneNumber(tc.input)
		assert.Equal(t, tc.expected, result, "Input: %s", tc.input)
	}
}

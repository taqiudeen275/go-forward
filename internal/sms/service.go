package sms

import (
	"context"
	"fmt"
	"regexp"
	"strings"
)

// Service implements the SMSService interface
type Service struct {
	provider SMSProvider
	appName  string
}

// NewService creates a new SMS service
func NewService(provider SMSProvider, appName string) *Service {
	return &Service{
		provider: provider,
		appName:  appName,
	}
}

// SendOTP sends an OTP SMS message
func (s *Service) SendOTP(ctx context.Context, to, otp, appName string) error {
	if appName == "" {
		appName = s.appName
	}

	// Validate phone number
	if err := s.validatePhoneNumber(to); err != nil {
		return fmt.Errorf("invalid phone number: %w", err)
	}

	return s.provider.SendOTP(ctx, to, otp, appName)
}

// SendMessage sends a custom SMS message
func (s *Service) SendMessage(ctx context.Context, to, message string) error {
	// Validate phone number
	if err := s.validatePhoneNumber(to); err != nil {
		return fmt.Errorf("invalid phone number: %w", err)
	}

	return s.provider.SendSMS(ctx, to, message)
}

// GetBalance retrieves account balance
func (s *Service) GetBalance(ctx context.Context) (*BalanceInfo, error) {
	return s.provider.GetBalance(ctx)
}

// validatePhoneNumber validates a phone number format
func (s *Service) validatePhoneNumber(phone string) error {
	if strings.TrimSpace(phone) == "" {
		return fmt.Errorf("phone number cannot be empty")
	}

	// Remove common phone number characters for validation
	cleanPhone := strings.ReplaceAll(phone, " ", "")
	cleanPhone = strings.ReplaceAll(cleanPhone, "-", "")
	cleanPhone = strings.ReplaceAll(cleanPhone, "(", "")
	cleanPhone = strings.ReplaceAll(cleanPhone, ")", "")
	cleanPhone = strings.ReplaceAll(cleanPhone, "+", "")

	// Check if remaining characters are digits and length is appropriate
	phoneRegex := regexp.MustCompile(`^\d{10,15}$`)
	if !phoneRegex.MatchString(cleanPhone) {
		return fmt.Errorf("phone number must contain 10-15 digits")
	}

	if len(phone) > 20 {
		return fmt.Errorf("phone number too long (max 20 characters)")
	}

	return nil
}

// FormatPhoneNumber formats a phone number for international use
func (s *Service) FormatPhoneNumber(phone string) string {
	// This is a basic implementation - in production, use a proper phone number library
	cleanPhone := strings.ReplaceAll(phone, " ", "")
	cleanPhone = strings.ReplaceAll(cleanPhone, "-", "")
	cleanPhone = strings.ReplaceAll(cleanPhone, "(", "")
	cleanPhone = strings.ReplaceAll(cleanPhone, ")", "")

	// If it doesn't start with +, assume it needs country code
	if !strings.HasPrefix(cleanPhone, "+") {
		// Default to Ghana country code for Arkesel
		if strings.HasPrefix(cleanPhone, "0") {
			cleanPhone = "+233" + cleanPhone[1:]
		} else if !strings.HasPrefix(cleanPhone, "233") {
			cleanPhone = "+233" + cleanPhone
		} else {
			cleanPhone = "+" + cleanPhone
		}
	}

	return cleanPhone
}

// SendOTPWithPurpose sends an OTP SMS message with purpose-specific content
func (s *Service) SendOTPWithPurpose(ctx context.Context, to, otp, purpose, appName string) error {
	if appName == "" {
		appName = s.appName
	}

	// Validate phone number
	if err := s.validatePhoneNumber(to); err != nil {
		return fmt.Errorf("invalid phone number: %w", err)
	}

	return s.provider.SendOTPWithPurpose(ctx, to, otp, purpose, appName)
}

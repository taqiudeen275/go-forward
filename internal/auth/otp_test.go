package auth

import (
	"testing"
	"time"
)

func TestOTPGenerator_GenerateCode(t *testing.T) {
	generator := NewOTPGenerator()

	code, err := generator.GenerateCode()
	if err != nil {
		t.Fatalf("Failed to generate OTP code: %v", err)
	}

	if len(code) != 6 {
		t.Errorf("Expected code length 6, got %d", len(code))
	}

	// Check if code contains only digits
	for _, char := range code {
		if char < '0' || char > '9' {
			t.Errorf("Code contains non-digit character: %c", char)
		}
	}
}

func TestOTPGenerator_CreateOTP(t *testing.T) {
	generator := NewOTPGenerator()
	userID := "test-user-id"
	recipient := "test@example.com"

	otp, err := generator.CreateOTP(&userID, OTPTypeEmail, OTPPurposeVerification, recipient)
	if err != nil {
		t.Fatalf("Failed to create OTP: %v", err)
	}

	if otp.ID == "" {
		t.Error("OTP ID should not be empty")
	}

	if otp.UserID == nil || *otp.UserID != userID {
		t.Errorf("Expected user ID %s, got %v", userID, otp.UserID)
	}

	if otp.Type != OTPTypeEmail {
		t.Errorf("Expected type %s, got %s", OTPTypeEmail, otp.Type)
	}

	if otp.Recipient != recipient {
		t.Errorf("Expected recipient %s, got %s", recipient, otp.Recipient)
	}

	if len(otp.Code) != 6 {
		t.Errorf("Expected code length 6, got %d", len(otp.Code))
	}

	if otp.Used {
		t.Error("New OTP should not be marked as used")
	}

	if otp.Attempts != 0 {
		t.Errorf("Expected 0 attempts, got %d", otp.Attempts)
	}

	if otp.MaxAttempts != 3 {
		t.Errorf("Expected 3 max attempts, got %d", otp.MaxAttempts)
	}
}

func TestOTPGenerator_ValidateCode(t *testing.T) {
	generator := NewOTPGenerator()
	userID := "test-user-id"

	otp, err := generator.CreateOTP(&userID, OTPTypeEmail, OTPPurposeVerification, "test@example.com")
	if err != nil {
		t.Fatalf("Failed to create OTP: %v", err)
	}

	// Test valid code
	err = generator.ValidateCode(otp, otp.Code)
	if err != nil {
		t.Errorf("Valid code should pass validation: %v", err)
	}

	// Test invalid code
	err = generator.ValidateCode(otp, "000000")
	if err == nil {
		t.Error("Invalid code should fail validation")
	}

	// Test used OTP
	otp.Used = true
	err = generator.ValidateCode(otp, otp.Code)
	if err == nil {
		t.Error("Used OTP should fail validation")
	}

	// Test expired OTP
	otp.Used = false
	otp.ExpiresAt = time.Now().Add(-1 * time.Minute)
	err = generator.ValidateCode(otp, otp.Code)
	if err == nil {
		t.Error("Expired OTP should fail validation")
	}

	// Test max attempts reached
	otp.ExpiresAt = time.Now().Add(10 * time.Minute)
	otp.Attempts = 3
	err = generator.ValidateCode(otp, otp.Code)
	if err == nil {
		t.Error("OTP with max attempts reached should fail validation")
	}
}

func TestOTPGenerator_IsExpired(t *testing.T) {
	generator := NewOTPGenerator()
	userID := "test-user-id"

	otp, err := generator.CreateOTP(&userID, OTPTypeEmail, OTPPurposeVerification, "test@example.com")
	if err != nil {
		t.Fatalf("Failed to create OTP: %v", err)
	}

	// Test non-expired OTP
	if generator.IsExpired(otp) {
		t.Error("New OTP should not be expired")
	}

	// Test expired OTP
	otp.ExpiresAt = time.Now().Add(-1 * time.Minute)
	if !generator.IsExpired(otp) {
		t.Error("OTP with past expiration should be expired")
	}
}

func TestOTPGenerator_IsMaxAttemptsReached(t *testing.T) {
	generator := NewOTPGenerator()
	userID := "test-user-id"

	otp, err := generator.CreateOTP(&userID, OTPTypeEmail, OTPPurposeVerification, "test@example.com")
	if err != nil {
		t.Fatalf("Failed to create OTP: %v", err)
	}

	// Test with no attempts
	if generator.IsMaxAttemptsReached(otp) {
		t.Error("OTP with 0 attempts should not have reached max attempts")
	}

	// Test with max attempts
	otp.Attempts = 3
	if !generator.IsMaxAttemptsReached(otp) {
		t.Error("OTP with 3 attempts should have reached max attempts")
	}
}

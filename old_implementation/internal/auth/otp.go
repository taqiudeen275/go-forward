package auth

import (
	"fmt"
	"time"

	"github.com/google/uuid"
)

// OTPGenerator handles OTP generation and validation
type OTPGenerator struct {
	codeLength     int
	expirationTime time.Duration
	maxAttempts    int
	hasher         *OTPHasher
}

// NewOTPGenerator creates a new OTP generator with default settings
func NewOTPGenerator() *OTPGenerator {
	return &OTPGenerator{
		codeLength:     6,
		expirationTime: 10 * time.Minute,
		maxAttempts:    3,
		hasher:         NewOTPHasher(),
	}
}

// NewOTPGeneratorWithConfig creates a new OTP generator with custom settings
func NewOTPGeneratorWithConfig(codeLength int, expirationTime time.Duration, maxAttempts int) *OTPGenerator {
	return &OTPGenerator{
		codeLength:     codeLength,
		expirationTime: expirationTime,
		maxAttempts:    maxAttempts,
		hasher:         NewOTPHasher(),
	}
}

// GenerateCode generates a cryptographically secure random numeric OTP code
func (g *OTPGenerator) GenerateCode() (string, error) {
	return g.hasher.GenerateSecureOTP(g.codeLength)
}

// CreateOTP creates a new OTP instance with hashed code
func (g *OTPGenerator) CreateOTP(userID *string, otpType OTPType, purpose OTPPurpose, recipient string) (*OTP, error) {
	code, err := g.GenerateCode()
	if err != nil {
		return nil, err
	}

	// Hash the OTP code for secure storage
	codeHash, err := g.hasher.HashOTP(code)
	if err != nil {
		return nil, fmt.Errorf("failed to hash OTP: %w", err)
	}

	return &OTP{
		ID:          uuid.New().String(),
		UserID:      userID,
		Code:        code,     // Plain text for immediate use (not stored in DB)
		CodeHash:    codeHash, // Hashed version for DB storage
		Type:        otpType,
		Purpose:     purpose,
		Recipient:   recipient,
		ExpiresAt:   time.Now().Add(g.expirationTime),
		Used:        false,
		Attempts:    0,
		MaxAttempts: g.maxAttempts,
		CreatedAt:   time.Now(),
	}, nil
}

// IsExpired checks if an OTP has expired
func (g *OTPGenerator) IsExpired(otp *OTP) bool {
	return time.Now().After(otp.ExpiresAt)
}

// IsMaxAttemptsReached checks if maximum attempts have been reached
func (g *OTPGenerator) IsMaxAttemptsReached(otp *OTP) bool {
	return otp.Attempts >= otp.MaxAttempts
}

// ValidateCode validates an OTP code against its hash
func (g *OTPGenerator) ValidateCode(otp *OTP, code string) error {
	if otp.Used {
		return fmt.Errorf("OTP has already been used")
	}

	if g.IsExpired(otp) {
		return fmt.Errorf("OTP has expired")
	}

	if g.IsMaxAttemptsReached(otp) {
		return fmt.Errorf("maximum attempts reached")
	}

	// Verify the code against the stored hash
	valid, err := g.hasher.VerifyOTP(code, otp.CodeHash)
	if err != nil {
		return fmt.Errorf("failed to verify OTP: %w", err)
	}

	if !valid {
		return fmt.Errorf("invalid OTP code")
	}

	return nil
}

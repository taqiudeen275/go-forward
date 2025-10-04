package auth

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"time"

	"github.com/google/uuid"
)

// OTPGenerator handles OTP generation and validation
type OTPGenerator struct {
	codeLength     int
	expirationTime time.Duration
	maxAttempts    int
}

// NewOTPGenerator creates a new OTP generator with default settings
func NewOTPGenerator() *OTPGenerator {
	return &OTPGenerator{
		codeLength:     6,
		expirationTime: 10 * time.Minute,
		maxAttempts:    3,
	}
}

// NewOTPGeneratorWithConfig creates a new OTP generator with custom settings
func NewOTPGeneratorWithConfig(codeLength int, expirationTime time.Duration, maxAttempts int) *OTPGenerator {
	return &OTPGenerator{
		codeLength:     codeLength,
		expirationTime: expirationTime,
		maxAttempts:    maxAttempts,
	}
}

// GenerateCode generates a random numeric OTP code
func (g *OTPGenerator) GenerateCode() (string, error) {
	// Generate a random number with the specified length
	max := new(big.Int)
	max.Exp(big.NewInt(10), big.NewInt(int64(g.codeLength)), nil)

	n, err := rand.Int(rand.Reader, max)
	if err != nil {
		return "", fmt.Errorf("failed to generate random number: %w", err)
	}

	// Format with leading zeros if necessary
	format := fmt.Sprintf("%%0%dd", g.codeLength)
	return fmt.Sprintf(format, n), nil
}

// CreateOTP creates a new OTP instance
func (g *OTPGenerator) CreateOTP(userID *string, otpType OTPType, recipient string) (*OTP, error) {
	code, err := g.GenerateCode()
	if err != nil {
		return nil, err
	}

	return &OTP{
		ID:          uuid.New().String(),
		UserID:      userID,
		Code:        code,
		Type:        otpType,
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

// ValidateCode validates an OTP code
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

	if otp.Code != code {
		return fmt.Errorf("invalid OTP code")
	}

	return nil
}

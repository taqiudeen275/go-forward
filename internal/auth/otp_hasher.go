package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
)

// OTPHasher handles secure OTP hashing and verification
type OTPHasher struct {
	saltLength int
}

// NewOTPHasher creates a new OTP hasher
func NewOTPHasher() *OTPHasher {
	return &OTPHasher{
		saltLength: 16, // 16 bytes = 128 bits of salt
	}
}

// HashOTP creates a salted hash of an OTP code
func (h *OTPHasher) HashOTP(code string) (string, error) {
	// Generate random salt
	salt := make([]byte, h.saltLength)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return "", fmt.Errorf("failed to generate salt: %w", err)
	}

	// Create hash with salt
	hash := sha256.New()
	hash.Write(salt)
	hash.Write([]byte(code))
	hashedCode := hash.Sum(nil)

	// Combine salt + hash and encode as hex
	combined := append(salt, hashedCode...)
	return hex.EncodeToString(combined), nil
}

// VerifyOTP verifies an OTP code against its hash
func (h *OTPHasher) VerifyOTP(code, hashedCode string) (bool, error) {
	// Decode the stored hash
	combined, err := hex.DecodeString(hashedCode)
	if err != nil {
		return false, fmt.Errorf("invalid hash format: %w", err)
	}

	// Extract salt and hash
	if len(combined) < h.saltLength+sha256.Size {
		return false, fmt.Errorf("invalid hash length")
	}

	salt := combined[:h.saltLength]
	storedHash := combined[h.saltLength:]

	// Hash the provided code with the same salt
	hash := sha256.New()
	hash.Write(salt)
	hash.Write([]byte(code))
	computedHash := hash.Sum(nil)

	// Compare hashes using constant-time comparison
	return constantTimeCompare(storedHash, computedHash), nil
}

// constantTimeCompare performs constant-time comparison to prevent timing attacks
func constantTimeCompare(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}

	var result byte
	for i := 0; i < len(a); i++ {
		result |= a[i] ^ b[i]
	}

	return result == 0
}

// GenerateSecureOTP generates a cryptographically secure OTP
func (h *OTPHasher) GenerateSecureOTP(length int) (string, error) {
	if length <= 0 || length > 10 {
		return "", fmt.Errorf("invalid OTP length: must be between 1 and 10")
	}

	// Generate random bytes
	bytes := make([]byte, length)
	if _, err := io.ReadFull(rand.Reader, bytes); err != nil {
		return "", fmt.Errorf("failed to generate random bytes: %w", err)
	}

	// Convert to digits
	digits := make([]byte, length)
	for i, b := range bytes {
		digits[i] = '0' + (b % 10)
	}

	return string(digits), nil
}

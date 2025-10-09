package auth

import (
	"context"
	"crypto/rand"
	"encoding/base32"
	"fmt"
	"strings"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

// MFAServiceImpl implements the MFAService interface
type MFAServiceImpl struct {
	userRepo UserRepositoryInterface
	hasher   *PasswordHasher
}

// NewMFAService creates a new MFA service
func NewMFAService(userRepo UserRepositoryInterface) MFAService {
	return &MFAServiceImpl{
		userRepo: userRepo,
		hasher:   NewPasswordHasher(),
	}
}

// GenerateTOTPSecret generates a new TOTP secret for a user
func (mfa *MFAServiceImpl) GenerateTOTPSecret(userID string) (*TOTPSecret, error) {
	// Get user information for TOTP setup
	user, err := mfa.userRepo.GetByID(context.Background(), userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	// Determine account identifier for TOTP
	var account string
	if user.Email != nil {
		account = *user.Email
	} else if user.Username != nil {
		account = *user.Username
	} else if user.Phone != nil {
		account = *user.Phone
	} else {
		account = userID
	}

	// Generate TOTP key
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "Go Forward Admin",
		AccountName: account,
		SecretSize:  32,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to generate TOTP key: %w", err)
	}

	return &TOTPSecret{
		Secret:    key.Secret(),
		QRCodeURL: key.URL(),
		Issuer:    "Go Forward Admin",
		Account:   account,
	}, nil
}

// ValidateTOTPCode validates a TOTP code for a user
func (mfa *MFAServiceImpl) ValidateTOTPCode(userID string, code string) error {
	// Get MFA configuration
	mfaConfig, err := mfa.GetMFAConfiguration(context.Background(), userID)
	if err != nil {
		return fmt.Errorf("MFA not configured: %w", err)
	}

	if !mfaConfig.IsEnabled || mfaConfig.Secret == "" {
		return fmt.Errorf("TOTP not enabled for user")
	}

	// Validate TOTP code with some time skew tolerance
	valid := totp.Validate(code, mfaConfig.Secret)
	if !valid {
		// Try with time skew (±1 period)
		now := time.Now()
		valid, _ = totp.ValidateCustom(code, mfaConfig.Secret, now.Add(-30*time.Second), totp.ValidateOpts{
			Period:    30,
			Skew:      1,
			Digits:    otp.DigitsSix,
			Algorithm: otp.AlgorithmSHA1,
		})

		if !valid {
			valid, _ = totp.ValidateCustom(code, mfaConfig.Secret, now.Add(30*time.Second), totp.ValidateOpts{
				Period:    30,
				Skew:      1,
				Digits:    otp.DigitsSix,
				Algorithm: otp.AlgorithmSHA1,
			})
		}
	}

	if !valid {
		return fmt.Errorf("invalid TOTP code")
	}

	return nil
}

// GenerateBackupCodes generates backup codes for a user
func (mfa *MFAServiceImpl) GenerateBackupCodes(userID string) ([]string, error) {
	const numCodes = 10
	const codeLength = 8

	codes := make([]string, numCodes)

	for i := 0; i < numCodes; i++ {
		// Generate random bytes
		bytes := make([]byte, codeLength)
		_, err := rand.Read(bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to generate random bytes: %w", err)
		}

		// Convert to base32 and format nicely
		code := base32.StdEncoding.EncodeToString(bytes)
		code = strings.ToUpper(code)
		code = code[:8] // Take first 8 characters

		// Format as XXXX-XXXX for readability
		codes[i] = fmt.Sprintf("%s-%s", code[:4], code[4:8])
	}

	return codes, nil
}

// ValidateBackupCode validates a backup code for a user
func (mfa *MFAServiceImpl) ValidateBackupCode(userID string, code string) error {
	// Get MFA configuration
	mfaConfig, err := mfa.GetMFAConfiguration(context.Background(), userID)
	if err != nil {
		return fmt.Errorf("MFA not configured: %w", err)
	}

	if !mfaConfig.IsEnabled || len(mfaConfig.BackupCodes) == 0 {
		return fmt.Errorf("backup codes not enabled for user")
	}

	// Normalize the input code (remove spaces, hyphens, convert to uppercase)
	normalizedCode := strings.ToUpper(strings.ReplaceAll(strings.ReplaceAll(code, " ", ""), "-", ""))

	// Check if code exists in backup codes
	for i, backupCode := range mfaConfig.BackupCodes {
		normalizedBackupCode := strings.ToUpper(strings.ReplaceAll(strings.ReplaceAll(backupCode, " ", ""), "-", ""))

		if normalizedCode == normalizedBackupCode {
			// Remove the used backup code
			mfaConfig.BackupCodes = append(mfaConfig.BackupCodes[:i], mfaConfig.BackupCodes[i+1:]...)

			// Update MFA configuration to remove used code
			err = mfa.UpdateMFAConfiguration(context.Background(), mfaConfig)
			if err != nil {
				return fmt.Errorf("failed to update backup codes: %w", err)
			}

			return nil
		}
	}

	return fmt.Errorf("invalid backup code")
}

// GetMFAConfiguration retrieves MFA configuration for a user
func (mfa *MFAServiceImpl) GetMFAConfiguration(ctx context.Context, userID string) (*MFAConfiguration, error) {
	// TODO: Implement actual database lookup
	// For now, return a placeholder that indicates MFA is not configured
	return nil, fmt.Errorf("MFA configuration not found")
}

// UpdateMFAConfiguration updates MFA configuration for a user
func (mfa *MFAServiceImpl) UpdateMFAConfiguration(ctx context.Context, config *MFAConfiguration) error {
	// TODO: Implement actual database update
	// This would save/update the MFA configuration in the database
	return fmt.Errorf("MFA configuration update not implemented")
}

// Helper functions for MFA management

// GenerateSecureSecret generates a cryptographically secure secret
func GenerateSecureSecret(length int) (string, error) {
	bytes := make([]byte, length)
	_, err := rand.Read(bytes)
	if err != nil {
		return "", fmt.Errorf("failed to generate secure secret: %w", err)
	}

	return base32.StdEncoding.EncodeToString(bytes), nil
}

// FormatBackupCode formats a backup code for display
func FormatBackupCode(code string) string {
	// Remove any existing formatting
	clean := strings.ReplaceAll(strings.ReplaceAll(code, " ", ""), "-", "")
	clean = strings.ToUpper(clean)

	// Format as XXXX-XXXX
	if len(clean) >= 8 {
		return fmt.Sprintf("%s-%s", clean[:4], clean[4:8])
	}

	return clean
}

// ValidateBackupCodeFormat validates the format of a backup code
func ValidateBackupCodeFormat(code string) error {
	// Remove formatting for validation
	clean := strings.ReplaceAll(strings.ReplaceAll(code, " ", ""), "-", "")

	if len(clean) != 8 {
		return fmt.Errorf("backup code must be 8 characters long")
	}

	// Check if it's valid base32
	_, err := base32.StdEncoding.DecodeString(clean + "======") // Add padding
	if err != nil {
		return fmt.Errorf("invalid backup code format")
	}

	return nil
}

// IsTOTPCodeValid checks if a TOTP code format is valid
func IsTOTPCodeValid(code string) bool {
	// TOTP codes should be 6 digits
	if len(code) != 6 {
		return false
	}

	// Check if all characters are digits
	for _, char := range code {
		if char < '0' || char > '9' {
			return false
		}
	}

	return true
}

package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	"golang.org/x/crypto/bcrypt"
)

// MFAService defines the interface for multi-factor authentication operations
type MFAService interface {
	// TOTP operations
	GenerateTOTPSecret(ctx context.Context, userID string) (string, []string, error)
	VerifyTOTP(ctx context.Context, userID string, code string) (bool, error)
	GetTOTPQRCode(ctx context.Context, userID string, issuer string) (string, error)

	// Backup code operations
	VerifyBackupCode(ctx context.Context, userID string, code string) (bool, error)
	RegenerateBackupCodes(ctx context.Context, userID string) ([]string, error)

	// MFA lifecycle
	EnableMFA(ctx context.Context, userID string, totpCode string) error
	DisableMFA(ctx context.Context, userID string, totpCode string) error
	GetMFAStatus(ctx context.Context, userID string) (*MFASettings, error)

	// Emergency access
	CreateBypassToken(ctx context.Context, userID string, reason string, createdBy string, expiresIn time.Duration) (string, error)
	VerifyBypassToken(ctx context.Context, userID string, token string) (bool, error)

	// Trusted devices
	TrustDevice(ctx context.Context, userID string, deviceFingerprint string, deviceName string, trustDuration time.Duration) error
	IsTrustedDevice(ctx context.Context, userID string, deviceFingerprint string) (bool, error)
	RevokeTrustedDevice(ctx context.Context, userID string, deviceFingerprint string) error

	// Security monitoring
	LogMFAAttempt(ctx context.Context, userID string, method string, attemptType string, success bool, failureReason string, sessionID string, ipAddress string, userAgent string) error
	CheckMFAAttemptLimits(ctx context.Context, userID string) (bool, error)
}

// mfaService implements the MFAService interface
type mfaService struct {
	db         *pgxpool.Pool
	rbac       RBACEngine
	issuer     string
	bcryptCost int
}

// NewMFAService creates a new MFA service instance
func NewMFAService(db *pgxpool.Pool, rbac RBACEngine, issuer string) MFAService {
	return &mfaService{
		db:         db,
		rbac:       rbac,
		issuer:     issuer,
		bcryptCost: 12, // Standard cost for backup codes
	}
}

// GenerateTOTPSecret generates a new TOTP secret and backup codes for a user
func (m *mfaService) GenerateTOTPSecret(ctx context.Context, userID string) (string, []string, error) {
	// Generate TOTP secret
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      m.issuer,
		AccountName: userID,
		SecretSize:  32,
	})
	if err != nil {
		return "", nil, fmt.Errorf("failed to generate TOTP secret: %w", err)
	}

	secret := key.Secret()

	// Generate backup codes
	backupCodes, err := m.generateBackupCodes(10)
	if err != nil {
		return "", nil, fmt.Errorf("failed to generate backup codes: %w", err)
	}

	// Hash backup codes for storage
	hashedBackupCodes := make([]string, len(backupCodes))
	for i, code := range backupCodes {
		hash, err := bcrypt.GenerateFromPassword([]byte(code), m.bcryptCost)
		if err != nil {
			return "", nil, fmt.Errorf("failed to hash backup code: %w", err)
		}
		hashedBackupCodes[i] = string(hash)
	}

	// Store MFA settings (but not enabled yet)
	query := `
		INSERT INTO user_mfa_settings (user_id, totp_secret, backup_codes, is_enabled)
		VALUES ($1, $2, $3, FALSE)
		ON CONFLICT (user_id) DO UPDATE SET
			totp_secret = EXCLUDED.totp_secret,
			backup_codes = EXCLUDED.backup_codes,
			is_enabled = FALSE,
			updated_at = NOW()
	`

	_, err = m.db.Exec(ctx, query, userID, secret, hashedBackupCodes)
	if err != nil {
		return "", nil, fmt.Errorf("failed to store MFA settings: %w", err)
	}

	return secret, backupCodes, nil
}

// VerifyTOTP verifies a TOTP code for a user
func (m *mfaService) VerifyTOTP(ctx context.Context, userID string, code string) (bool, error) {
	// Get user's TOTP secret
	var secret string
	err := m.db.QueryRow(ctx, "SELECT totp_secret FROM user_mfa_settings WHERE user_id = $1 AND is_enabled = TRUE", userID).Scan(&secret)
	if err != nil {
		if err == pgx.ErrNoRows {
			return false, nil
		}
		return false, fmt.Errorf("failed to get TOTP secret: %w", err)
	}

	// Verify TOTP code
	valid := totp.Validate(code, secret)

	// Log the attempt
	method := "totp"
	attemptType := "verification"
	var failureReason string
	if !valid {
		failureReason = "invalid_code"
	}

	err = m.LogMFAAttempt(ctx, userID, method, attemptType, valid, failureReason, "", "", "")
	if err != nil {
		// Don't fail verification due to logging error, just log it
		fmt.Printf("Warning: failed to log MFA attempt: %v\n", err)
	}

	if valid {
		// Update last used timestamp
		_, err = m.db.Exec(ctx,
			"UPDATE user_mfa_settings SET last_used_at = NOW() WHERE user_id = $1",
			userID)
		if err != nil {
			fmt.Printf("Warning: failed to update last_used_at: %v\n", err)
		}
	}

	return valid, nil
}

// GetTOTPQRCode generates a QR code URL for TOTP setup
func (m *mfaService) GetTOTPQRCode(ctx context.Context, userID string, issuer string) (string, error) {
	// Get user's email for the QR code
	var email string
	err := m.db.QueryRow(ctx, "SELECT email FROM users WHERE id = $1", userID).Scan(&email)
	if err != nil {
		return "", fmt.Errorf("failed to get user email: %w", err)
	}

	// Get TOTP secret
	var secret string
	err = m.db.QueryRow(ctx, "SELECT totp_secret FROM user_mfa_settings WHERE user_id = $1", userID).Scan(&secret)
	if err != nil {
		return "", fmt.Errorf("failed to get TOTP secret: %w", err)
	}

	// Generate QR code URL
	key, err := otp.NewKeyFromURL(fmt.Sprintf("otpauth://totp/%s:%s?secret=%s&issuer=%s",
		issuer, email, secret, issuer))
	if err != nil {
		return "", fmt.Errorf("failed to create TOTP key: %w", err)
	}

	return key.URL(), nil
}

// VerifyBackupCode verifies a backup code for a user
func (m *mfaService) VerifyBackupCode(ctx context.Context, userID string, code string) (bool, error) {
	// Get user's backup codes
	var backupCodes []string
	err := m.db.QueryRow(ctx, "SELECT backup_codes FROM user_mfa_settings WHERE user_id = $1 AND is_enabled = TRUE", userID).Scan(&backupCodes)
	if err != nil {
		if err == pgx.ErrNoRows {
			return false, nil
		}
		return false, fmt.Errorf("failed to get backup codes: %w", err)
	}

	// Check each backup code
	validCodeIndex := -1
	for i, hashedCode := range backupCodes {
		err := bcrypt.CompareHashAndPassword([]byte(hashedCode), []byte(code))
		if err == nil {
			validCodeIndex = i
			break
		}
	}

	valid := validCodeIndex >= 0

	// Log the attempt
	method := "backup_code"
	attemptType := "verification"
	var failureReason string
	if !valid {
		failureReason = "invalid_code"
	}

	err = m.LogMFAAttempt(ctx, userID, method, attemptType, valid, failureReason, "", "", "")
	if err != nil {
		fmt.Printf("Warning: failed to log MFA attempt: %v\n", err)
	}

	if valid {
		// Remove the used backup code
		newBackupCodes := make([]string, 0, len(backupCodes)-1)
		for i, code := range backupCodes {
			if i != validCodeIndex {
				newBackupCodes = append(newBackupCodes, code)
			}
		}

		// Update backup codes and timestamp
		_, err = m.db.Exec(ctx,
			"UPDATE user_mfa_settings SET backup_codes = $2, last_backup_used_at = NOW() WHERE user_id = $1",
			userID, newBackupCodes)
		if err != nil {
			return false, fmt.Errorf("failed to update backup codes: %w", err)
		}
	}

	return valid, nil
}

// RegenerateBackupCodes generates new backup codes for a user
func (m *mfaService) RegenerateBackupCodes(ctx context.Context, userID string) ([]string, error) {
	// Generate new backup codes
	backupCodes, err := m.generateBackupCodes(10)
	if err != nil {
		return nil, fmt.Errorf("failed to generate backup codes: %w", err)
	}

	// Hash backup codes for storage
	hashedBackupCodes := make([]string, len(backupCodes))
	for i, code := range backupCodes {
		hash, err := bcrypt.GenerateFromPassword([]byte(code), m.bcryptCost)
		if err != nil {
			return nil, fmt.Errorf("failed to hash backup code: %w", err)
		}
		hashedBackupCodes[i] = string(hash)
	}

	// Update backup codes
	_, err = m.db.Exec(ctx,
		"UPDATE user_mfa_settings SET backup_codes = $2, updated_at = NOW() WHERE user_id = $1",
		userID, hashedBackupCodes)
	if err != nil {
		return nil, fmt.Errorf("failed to update backup codes: %w", err)
	}

	return backupCodes, nil
}

// EnableMFA enables MFA for a user after verifying a TOTP code
func (m *mfaService) EnableMFA(ctx context.Context, userID string, totpCode string) error {
	// Verify the TOTP code first
	valid, err := m.VerifyTOTP(ctx, userID, totpCode)
	if err != nil {
		return fmt.Errorf("failed to verify TOTP code: %w", err)
	}
	if !valid {
		return fmt.Errorf("invalid TOTP code")
	}

	// Enable MFA
	_, err = m.db.Exec(ctx,
		"UPDATE user_mfa_settings SET is_enabled = TRUE, setup_completed_at = NOW(), updated_at = NOW() WHERE user_id = $1",
		userID)
	if err != nil {
		return fmt.Errorf("failed to enable MFA: %w", err)
	}

	return nil
}

// DisableMFA disables MFA for a user after verifying a TOTP code
func (m *mfaService) DisableMFA(ctx context.Context, userID string, totpCode string) error {
	// Check if MFA is enforced for this user
	var isEnforced bool
	err := m.db.QueryRow(ctx, "SELECT is_enforced FROM user_mfa_settings WHERE user_id = $1", userID).Scan(&isEnforced)
	if err != nil && err != pgx.ErrNoRows {
		return fmt.Errorf("failed to check MFA enforcement: %w", err)
	}

	if isEnforced {
		return fmt.Errorf("MFA is enforced for this user and cannot be disabled")
	}

	// Verify the TOTP code first
	valid, err := m.VerifyTOTP(ctx, userID, totpCode)
	if err != nil {
		return fmt.Errorf("failed to verify TOTP code: %w", err)
	}
	if !valid {
		return fmt.Errorf("invalid TOTP code")
	}

	// Disable MFA
	_, err = m.db.Exec(ctx,
		"UPDATE user_mfa_settings SET is_enabled = FALSE, updated_at = NOW() WHERE user_id = $1",
		userID)
	if err != nil {
		return fmt.Errorf("failed to disable MFA: %w", err)
	}

	// Revoke all trusted devices
	_, err = m.db.Exec(ctx,
		"UPDATE mfa_trusted_devices SET is_active = FALSE WHERE user_id = $1",
		userID)
	if err != nil {
		fmt.Printf("Warning: failed to revoke trusted devices: %v\n", err)
	}

	return nil
}

// GetMFAStatus returns the MFA status for a user
func (m *mfaService) GetMFAStatus(ctx context.Context, userID string) (*MFASettings, error) {
	var settings MFASettings
	err := m.db.QueryRow(ctx, "SELECT id, user_id, is_enabled, is_enforced, method, phone_verified, email_verified, last_used_at, last_backup_used_at, setup_completed_at, created_at, updated_at FROM user_mfa_settings WHERE user_id = $1", userID).Scan(
		&settings.ID, &settings.UserID, &settings.IsEnabled, &settings.IsEnforced,
		&settings.Method, &settings.PhoneVerified, &settings.EmailVerified,
		&settings.LastUsedAt, &settings.LastBackupUsedAt, &settings.SetupCompletedAt,
		&settings.CreatedAt, &settings.UpdatedAt)
	if err != nil {
		if err == pgx.ErrNoRows {
			return &MFASettings{
				UserID:    userID,
				IsEnabled: false,
			}, nil
		}
		return nil, fmt.Errorf("failed to get MFA status: %w", err)
	}

	// Don't expose sensitive data
	settings.TOTPSecret = ""
	settings.BackupCodes = nil
	settings.RecoveryCodes = nil

	return &settings, nil
}

// CreateBypassToken creates an emergency bypass token for MFA
func (m *mfaService) CreateBypassToken(ctx context.Context, userID string, reason string, createdBy string, expiresIn time.Duration) (string, error) {
	// Generate random token
	tokenBytes := make([]byte, 32)
	_, err := rand.Read(tokenBytes)
	if err != nil {
		return "", fmt.Errorf("failed to generate bypass token: %w", err)
	}

	token := hex.EncodeToString(tokenBytes)
	tokenHash := sha256.Sum256([]byte(token))
	tokenHashStr := hex.EncodeToString(tokenHash[:])

	// Store bypass token
	expiresAt := time.Now().Add(expiresIn)
	_, err = m.db.Exec(ctx, `
		INSERT INTO mfa_bypass_tokens (user_id, token_hash, reason, created_by, expires_at)
		VALUES ($1, $2, $3, $4, $5)
	`, userID, tokenHashStr, reason, createdBy, expiresAt)
	if err != nil {
		return "", fmt.Errorf("failed to store bypass token: %w", err)
	}

	return token, nil
}

// VerifyBypassToken verifies and consumes a bypass token
func (m *mfaService) VerifyBypassToken(ctx context.Context, userID string, token string) (bool, error) {
	tokenHash := sha256.Sum256([]byte(token))
	tokenHashStr := hex.EncodeToString(tokenHash[:])

	// Check if token exists and is valid
	var tokenID string
	err := m.db.QueryRow(ctx, `
		SELECT id FROM mfa_bypass_tokens
		WHERE user_id = $1 AND token_hash = $2
		AND expires_at > NOW()
		AND (is_single_use = FALSE OR used_at IS NULL)
	`, userID, tokenHashStr).Scan(&tokenID)
	if err != nil {
		if err == pgx.ErrNoRows {
			return false, nil
		}
		return false, fmt.Errorf("failed to verify bypass token: %w", err)
	}

	// Mark token as used
	_, err = m.db.Exec(ctx, `
		UPDATE mfa_bypass_tokens
		SET used_at = NOW(), usage_count = usage_count + 1
		WHERE id = $1
	`, tokenID)
	if err != nil {
		return false, fmt.Errorf("failed to mark bypass token as used: %w", err)
	}

	return true, nil
}

// TrustDevice adds a device to the trusted devices list
func (m *mfaService) TrustDevice(ctx context.Context, userID string, deviceFingerprint string, deviceName string, trustDuration time.Duration) error {
	expiresAt := time.Now().Add(trustDuration)

	_, err := m.db.Exec(ctx, `
		INSERT INTO mfa_trusted_devices (user_id, device_fingerprint, device_name, trust_expires_at)
		VALUES ($1, $2, $3, $4)
		ON CONFLICT (user_id, device_fingerprint) DO UPDATE SET
			device_name = EXCLUDED.device_name,
			trust_expires_at = EXCLUDED.trust_expires_at,
			is_active = TRUE,
			updated_at = NOW()
	`, userID, deviceFingerprint, deviceName, expiresAt)
	if err != nil {
		return fmt.Errorf("failed to trust device: %w", err)
	}

	return nil
}

// IsTrustedDevice checks if a device is trusted
func (m *mfaService) IsTrustedDevice(ctx context.Context, userID string, deviceFingerprint string) (bool, error) {
	var exists bool
	err := m.db.QueryRow(ctx, `
		SELECT EXISTS(
			SELECT 1 FROM mfa_trusted_devices
			WHERE user_id = $1 AND device_fingerprint = $2
			AND is_active = TRUE
			AND (trust_expires_at IS NULL OR trust_expires_at > NOW())
		)
	`, userID, deviceFingerprint).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("failed to check trusted device: %w", err)
	}

	if exists {
		// Update last used timestamp
		_, err = m.db.Exec(ctx, `
			UPDATE mfa_trusted_devices
			SET last_used_at = NOW()
			WHERE user_id = $1 AND device_fingerprint = $2
		`, userID, deviceFingerprint)
		if err != nil {
			fmt.Printf("Warning: failed to update device last_used_at: %v\n", err)
		}
	}

	return exists, nil
}

// RevokeTrustedDevice removes a device from trusted devices
func (m *mfaService) RevokeTrustedDevice(ctx context.Context, userID string, deviceFingerprint string) error {
	_, err := m.db.Exec(ctx, `
		UPDATE mfa_trusted_devices
		SET is_active = FALSE, updated_at = NOW()
		WHERE user_id = $1 AND device_fingerprint = $2
	`, userID, deviceFingerprint)
	if err != nil {
		return fmt.Errorf("failed to revoke trusted device: %w", err)
	}

	return nil
}

// LogMFAAttempt logs an MFA attempt for security monitoring
func (m *mfaService) LogMFAAttempt(ctx context.Context, userID string, method string, attemptType string, success bool, failureReason string, sessionID string, ipAddress string, userAgent string) error {
	_, err := m.db.Exec(ctx, `
		INSERT INTO mfa_attempts (user_id, session_id, method, attempt_type, success, failure_reason, ip_address, user_agent)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
	`, userID, sessionID, method, attemptType, success, failureReason, ipAddress, userAgent)
	if err != nil {
		return fmt.Errorf("failed to log MFA attempt: %w", err)
	}

	return nil
}

// CheckMFAAttemptLimits checks if user has exceeded MFA attempt limits
func (m *mfaService) CheckMFAAttemptLimits(ctx context.Context, userID string) (bool, error) {
	var failedAttempts int
	err := m.db.QueryRow(ctx, `
		SELECT COUNT(*) FROM mfa_attempts
		WHERE user_id = $1
		AND success = FALSE
		AND created_at > NOW() - INTERVAL '15 minutes'
	`, userID).Scan(&failedAttempts)
	if err != nil {
		return false, fmt.Errorf("failed to check MFA attempt limits: %w", err)
	}

	// Allow up to 5 failed attempts in 15 minutes
	return failedAttempts >= 5, nil
}

// generateBackupCodes generates a specified number of backup codes
func (m *mfaService) generateBackupCodes(count int) ([]string, error) {
	codes := make([]string, count)

	for i := 0; i < count; i++ {
		// Generate 8 random bytes
		bytes := make([]byte, 8)
		_, err := rand.Read(bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to generate random bytes: %w", err)
		}

		// Convert to base32 and format as backup code
		code := base32.StdEncoding.EncodeToString(bytes)
		code = strings.TrimRight(code, "=") // Remove padding
		code = strings.ToLower(code)

		// Format as XXXX-XXXX for readability
		if len(code) >= 8 {
			codes[i] = fmt.Sprintf("%s-%s", code[:4], code[4:8])
		} else {
			codes[i] = code
		}
	}

	return codes, nil
}

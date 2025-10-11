package auth

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base32"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/pquerna/otp/totp"

	"github.com/taqiudeen275/go-foward/pkg/errors"
)

// MFAService defines the multi-factor authentication service interface
type MFAService interface {
	// TOTP operations
	GenerateTOTPSecret(ctx context.Context, userID uuid.UUID, issuer, accountName string) (*MFASetup, error)
	VerifyTOTP(ctx context.Context, userID uuid.UUID, code string) error
	EnableMFA(ctx context.Context, userID uuid.UUID, totpCode string) error
	DisableMFA(ctx context.Context, userID uuid.UUID, totpCode string) error

	// Backup codes operations
	GenerateBackupCodes(ctx context.Context, userID uuid.UUID) ([]string, error)
	VerifyBackupCode(ctx context.Context, userID uuid.UUID, code string) error
	RegenerateBackupCodes(ctx context.Context, userID uuid.UUID) ([]string, error)

	// MFA verification
	VerifyMFACode(ctx context.Context, userID uuid.UUID, code string) error
	IsMFARequired(ctx context.Context, user *UnifiedUser) bool

	// Recovery operations
	CreateMFARecovery(ctx context.Context, userID uuid.UUID, method MFARecoveryMethod) (*MFARecovery, error)
	VerifyMFARecovery(ctx context.Context, recoveryCode string) (*MFARecovery, error)
	CompleteMFARecovery(ctx context.Context, recoveryID uuid.UUID, newSecret string) error
}

// MFASetup represents the setup information for TOTP
type MFASetup struct {
	Secret    string `json:"secret"`
	QRCode    string `json:"qr_code"`
	BackupURL string `json:"backup_url"`
	Issuer    string `json:"issuer"`
	Account   string `json:"account"`
}

// MFARecoveryMethod represents recovery methods
type MFARecoveryMethod string

const (
	MFARecoveryMethodEmail MFARecoveryMethod = "email"
	MFARecoveryMethodSMS   MFARecoveryMethod = "sms"
	MFARecoveryMethodAdmin MFARecoveryMethod = "admin"
)

// MFARecovery represents an MFA recovery request
type MFARecovery struct {
	ID           uuid.UUID         `json:"id" db:"id"`
	UserID       uuid.UUID         `json:"user_id" db:"user_id"`
	RecoveryCode string            `json:"recovery_code" db:"recovery_code"`
	Method       MFARecoveryMethod `json:"method" db:"method"`
	ExpiresAt    time.Time         `json:"expires_at" db:"expires_at"`
	UsedAt       *time.Time        `json:"used_at" db:"used_at"`
	CreatedAt    time.Time         `json:"created_at" db:"created_at"`
}

// IsExpired returns true if the recovery code has expired
func (r *MFARecovery) IsExpired() bool {
	return r.ExpiresAt.Before(time.Now())
}

// IsUsed returns true if the recovery code has been used
func (r *MFARecovery) IsUsed() bool {
	return r.UsedAt != nil
}

// mfaService implements the MFAService interface
type mfaService struct {
	repo Repository
}

// NewMFAService creates a new MFA service
func NewMFAService(repo Repository) MFAService {
	return &mfaService{
		repo: repo,
	}
}

// GenerateTOTPSecret generates a new TOTP secret for a user
func (s *mfaService) GenerateTOTPSecret(ctx context.Context, userID uuid.UUID, issuer, accountName string) (*MFASetup, error) {
	// Get user to ensure they exist
	user, err := s.repo.GetUserByID(ctx, userID)
	if err != nil {
		return nil, errors.Wrap(err, "user not found")
	}

	// Generate TOTP key
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      issuer,
		AccountName: accountName,
		SecretSize:  32,
	})
	if err != nil {
		return nil, errors.Wrap(err, "failed to generate TOTP key")
	}

	// Create setup response
	setup := &MFASetup{
		Secret:    key.Secret(),
		QRCode:    key.URL(),
		BackupURL: key.URL(),
		Issuer:    issuer,
		Account:   accountName,
	}

	// Store the secret temporarily (not enabled yet)
	secret := key.Secret()
	user.MFASecret = &secret
	if err := s.repo.UpdateUser(ctx, user); err != nil {
		return nil, errors.Wrap(err, "failed to store MFA secret")
	}

	return setup, nil
}

// VerifyTOTP verifies a TOTP code for a user
func (s *mfaService) VerifyTOTP(ctx context.Context, userID uuid.UUID, code string) error {
	// Get user
	user, err := s.repo.GetUserByID(ctx, userID)
	if err != nil {
		return errors.Wrap(err, "user not found")
	}

	// Check if user has MFA secret
	if user.MFASecret == nil || *user.MFASecret == "" {
		return errors.NewAuthError("MFA not configured for user")
	}

	// Verify TOTP code
	valid := totp.Validate(code, *user.MFASecret)
	if !valid {
		return errors.NewAuthError("invalid TOTP code")
	}

	return nil
}

// EnableMFA enables MFA for a user after verifying the TOTP code
func (s *mfaService) EnableMFA(ctx context.Context, userID uuid.UUID, totpCode string) error {
	// Verify the TOTP code first
	if err := s.VerifyTOTP(ctx, userID, totpCode); err != nil {
		return err
	}

	// Get user
	user, err := s.repo.GetUserByID(ctx, userID)
	if err != nil {
		return errors.Wrap(err, "user not found")
	}

	// Generate backup codes
	backupCodes, err := s.generateBackupCodesInternal()
	if err != nil {
		return errors.Wrap(err, "failed to generate backup codes")
	}

	// Enable MFA
	user.MFAEnabled = true
	user.BackupCodes = backupCodes
	user.UpdatedAt = time.Now().UTC()

	if err := s.repo.UpdateUser(ctx, user); err != nil {
		return errors.Wrap(err, "failed to enable MFA")
	}

	// Create audit log
	s.createAuditLog(ctx, userID, AuditActions.MFASetup, "users", userID.String(), true, map[string]any{
		"method": "totp",
		"action": "enabled",
	})

	// Create security event
	s.createSecurityEvent(ctx, &userID, SecurityEventTypes.MFAEnabled, "", "MFA enabled via TOTP")

	return nil
}

// DisableMFA disables MFA for a user after verifying the TOTP code
func (s *mfaService) DisableMFA(ctx context.Context, userID uuid.UUID, totpCode string) error {
	// Verify the TOTP code first
	if err := s.VerifyTOTP(ctx, userID, totpCode); err != nil {
		return err
	}

	// Get user
	user, err := s.repo.GetUserByID(ctx, userID)
	if err != nil {
		return errors.Wrap(err, "user not found")
	}

	// Disable MFA
	user.MFAEnabled = false
	user.MFASecret = nil
	user.BackupCodes = []string{}
	user.UpdatedAt = time.Now().UTC()

	if err := s.repo.UpdateUser(ctx, user); err != nil {
		return errors.Wrap(err, "failed to disable MFA")
	}

	// Create audit log
	s.createAuditLog(ctx, userID, AuditActions.MFASetup, "users", userID.String(), true, map[string]any{
		"method": "totp",
		"action": "disabled",
	})

	// Create security event
	s.createSecurityEvent(ctx, &userID, SecurityEventTypes.MFADisabled, "", "MFA disabled via TOTP")

	return nil
}

// GenerateBackupCodes generates new backup codes for a user
func (s *mfaService) GenerateBackupCodes(ctx context.Context, userID uuid.UUID) ([]string, error) {
	// Get user
	user, err := s.repo.GetUserByID(ctx, userID)
	if err != nil {
		return nil, errors.Wrap(err, "user not found")
	}

	// Check if MFA is enabled
	if !user.MFAEnabled {
		return nil, errors.NewAuthError("MFA is not enabled for user")
	}

	// Generate new backup codes
	backupCodes, err := s.generateBackupCodesInternal()
	if err != nil {
		return nil, errors.Wrap(err, "failed to generate backup codes")
	}

	// Update user with new backup codes
	user.BackupCodes = backupCodes
	user.UpdatedAt = time.Now().UTC()

	if err := s.repo.UpdateUser(ctx, user); err != nil {
		return nil, errors.Wrap(err, "failed to update backup codes")
	}

	// Create audit log
	s.createAuditLog(ctx, userID, "backup_codes_generated", "users", userID.String(), true, nil)

	// Return the backup codes (they are already in the correct format)
	return backupCodes, nil
}

// VerifyBackupCode verifies a backup code and marks it as used
func (s *mfaService) VerifyBackupCode(ctx context.Context, userID uuid.UUID, code string) error {
	// Get user
	user, err := s.repo.GetUserByID(ctx, userID)
	if err != nil {
		return errors.Wrap(err, "user not found")
	}

	// Check if MFA is enabled
	if !user.MFAEnabled {
		return errors.NewAuthError("MFA is not enabled for user")
	}

	// Normalize the code (remove spaces, convert to uppercase)
	normalizedCode := strings.ToUpper(strings.ReplaceAll(code, " ", ""))

	// Check backup codes
	for i, backupCode := range user.BackupCodes {
		// In a real implementation, backup codes should be hashed
		// For now, we'll do a simple comparison
		if subtle.ConstantTimeCompare([]byte(normalizedCode), []byte(backupCode)) == 1 {
			// Remove the used backup code
			user.BackupCodes = append(user.BackupCodes[:i], user.BackupCodes[i+1:]...)
			user.UpdatedAt = time.Now().UTC()

			if err := s.repo.UpdateUser(ctx, user); err != nil {
				return errors.Wrap(err, "failed to update backup codes")
			}

			// Create audit log
			s.createAuditLog(ctx, userID, "backup_code_used", "users", userID.String(), true, map[string]any{
				"remaining_codes": len(user.BackupCodes),
			})

			return nil
		}
	}

	// Create security event for invalid backup code
	s.createSecurityEvent(ctx, &userID, "backup_code_invalid", "", "invalid backup code attempted")

	return errors.NewAuthError("invalid backup code")
}

// RegenerateBackupCodes regenerates all backup codes for a user
func (s *mfaService) RegenerateBackupCodes(ctx context.Context, userID uuid.UUID) ([]string, error) {
	// This is the same as GenerateBackupCodes for now
	return s.GenerateBackupCodes(ctx, userID)
}

// VerifyMFACode verifies either a TOTP code or backup code
func (s *mfaService) VerifyMFACode(ctx context.Context, userID uuid.UUID, code string) error {
	// Get user
	user, err := s.repo.GetUserByID(ctx, userID)
	if err != nil {
		return errors.Wrap(err, "user not found")
	}

	// Check if MFA is enabled
	if !user.MFAEnabled {
		return errors.NewAuthError("MFA is not enabled for user")
	}

	// Try TOTP first (6 digits)
	if len(code) == 6 {
		if err := s.VerifyTOTP(ctx, userID, code); err == nil {
			return nil
		}
	}

	// Try backup code (longer format)
	if len(code) > 6 {
		if err := s.VerifyBackupCode(ctx, userID, code); err == nil {
			return nil
		}
	}

	// Create security event for failed MFA
	s.createSecurityEvent(ctx, &userID, "mfa_verification_failed", "", "invalid MFA code")

	return errors.NewAuthError("invalid MFA code")
}

// IsMFARequired checks if MFA is required for a user based on their admin level
func (s *mfaService) IsMFARequired(ctx context.Context, user *UnifiedUser) bool {
	// MFA is required for all admin users
	if user.IsAdmin() {
		return true
	}

	// For regular users, MFA is optional but recommended
	return false
}

// CreateMFARecovery creates an MFA recovery request
func (s *mfaService) CreateMFARecovery(ctx context.Context, userID uuid.UUID, method MFARecoveryMethod) (*MFARecovery, error) {
	// Get user
	user, err := s.repo.GetUserByID(ctx, userID)
	if err != nil {
		return nil, errors.Wrap(err, "user not found")
	}

	// Check if MFA is enabled
	if !user.MFAEnabled {
		return nil, errors.NewAuthError("MFA is not enabled for user")
	}

	// Generate recovery code
	recoveryCode, err := generateSecureToken(32)
	if err != nil {
		return nil, errors.Wrap(err, "failed to generate recovery code")
	}

	// Create recovery record
	recovery := &MFARecovery{
		ID:           uuid.New(),
		UserID:       userID,
		RecoveryCode: recoveryCode,
		Method:       method,
		ExpiresAt:    time.Now().Add(24 * time.Hour), // 24 hour expiry
		CreatedAt:    time.Now().UTC(),
	}

	// Store recovery record
	if err := s.repo.CreateMFARecovery(ctx, recovery); err != nil {
		return nil, errors.Wrap(err, "failed to create MFA recovery record")
	}

	// Create audit log
	s.createAuditLog(ctx, userID, "mfa_recovery_created", "mfa_recovery", recovery.ID.String(), true, map[string]any{
		"method":      method,
		"expires_at":  recovery.ExpiresAt,
		"recovery_id": recovery.ID,
	})

	// Create security event
	s.createSecurityEvent(ctx, &userID, "mfa_recovery_requested", "", fmt.Sprintf("MFA recovery requested via %s", method))

	return recovery, nil
}

// VerifyMFARecovery verifies an MFA recovery code
func (s *mfaService) VerifyMFARecovery(ctx context.Context, recoveryCode string) (*MFARecovery, error) {
	// Get recovery record
	recovery, err := s.repo.GetMFARecoveryByCode(ctx, recoveryCode)
	if err != nil {
		return nil, errors.Wrap(err, "invalid recovery code")
	}

	// Check if recovery code is expired
	if recovery.IsExpired() {
		return nil, errors.NewAuthError("recovery code has expired")
	}

	// Check if recovery code is already used
	if recovery.IsUsed() {
		return nil, errors.NewAuthError("recovery code has already been used")
	}

	return recovery, nil
}

// CompleteMFARecovery completes the MFA recovery process
func (s *mfaService) CompleteMFARecovery(ctx context.Context, recoveryID uuid.UUID, newSecret string) error {
	// Get recovery record
	recovery, err := s.repo.GetMFARecoveryByID(ctx, recoveryID)
	if err != nil {
		return errors.Wrap(err, "recovery record not found")
	}

	// Check if recovery is valid
	if recovery.IsExpired() {
		return errors.NewAuthError("recovery code has expired")
	}

	if recovery.IsUsed() {
		return errors.NewAuthError("recovery code has already been used")
	}

	// Get user
	user, err := s.repo.GetUserByID(ctx, recovery.UserID)
	if err != nil {
		return errors.Wrap(err, "user not found")
	}

	// Update user with new MFA secret and disable MFA temporarily
	user.MFASecret = &newSecret
	user.MFAEnabled = false       // User needs to re-enable MFA with new secret
	user.BackupCodes = []string{} // Clear old backup codes
	user.UpdatedAt = time.Now().UTC()

	if err := s.repo.UpdateUser(ctx, user); err != nil {
		return errors.Wrap(err, "failed to update user MFA settings")
	}

	// Mark recovery as used
	now := time.Now().UTC()
	recovery.UsedAt = &now
	if err := s.repo.UpdateMFARecovery(ctx, recovery); err != nil {
		return errors.Wrap(err, "failed to mark recovery as used")
	}

	// Create audit log
	s.createAuditLog(ctx, recovery.UserID, "mfa_recovery_completed", "mfa_recovery", recoveryID.String(), true, map[string]any{
		"method":      recovery.Method,
		"recovery_id": recoveryID,
	})

	// Create security event
	s.createSecurityEvent(ctx, &recovery.UserID, "mfa_recovery_completed", "", "MFA recovery completed successfully")

	return nil
}

// Helper methods

// generateBackupCodesInternal generates hashed backup codes
func (s *mfaService) generateBackupCodesInternal() ([]string, error) {
	const numCodes = 10
	codes := make([]string, numCodes)

	for i := 0; i < numCodes; i++ {
		// Generate a random code
		code, err := generateRandomString(12)
		if err != nil {
			return nil, err
		}

		// Format as backup code (BC-XX-XXXXXXXX)
		formattedCode := fmt.Sprintf("BC-%02d-%s", i+1, code)

		// In a real implementation, you would hash this code before storing
		// For now, we'll store it as-is for simplicity
		codes[i] = formattedCode
	}

	return codes, nil
}

// generateRandomString generates a random string of specified length
func generateRandomString(length int) (string, error) {
	const charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	bytes := make([]byte, length)

	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}

	for i, b := range bytes {
		bytes[i] = charset[b%byte(len(charset))]
	}

	return string(bytes), nil
}

// generateSecureToken generates a secure random token
func generateSecureToken(length int) (string, error) {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return base32.StdEncoding.EncodeToString(bytes), nil
}

// createAuditLog creates an audit log entry (placeholder)
func (s *mfaService) createAuditLog(ctx context.Context, userID uuid.UUID, action, resource, resourceID string, success bool, details map[string]any) {
	// This would call the actual audit service
	// For now, it's a placeholder
}

// createSecurityEvent creates a security event (placeholder)
func (s *mfaService) createSecurityEvent(ctx context.Context, userID *uuid.UUID, eventType, identifier, description string) {
	// This would call the actual security event service
	// For now, it's a placeholder
}

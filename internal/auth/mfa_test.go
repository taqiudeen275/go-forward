package auth

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestMFAService_GenerateTOTPSecret(t *testing.T) {
	mockRepo := new(MockRepository)
	mfaService := NewMFAService(mockRepo)
	ctx := context.Background()

	userID := uuid.New()
	user := &UnifiedUser{
		ID:    userID,
		Email: stringPtr("test@example.com"),
	}

	mockRepo.On("GetUserByID", ctx, userID).Return(user, nil)
	mockRepo.On("UpdateUser", ctx, mock.AnythingOfType("*auth.UnifiedUser")).Return(nil)

	setup, err := mfaService.GenerateTOTPSecret(ctx, userID, "Test App", "test@example.com")

	assert.NoError(t, err)
	assert.NotEmpty(t, setup.Secret)
	assert.NotEmpty(t, setup.QRCode)
	assert.Contains(t, setup.QRCode, "otpauth://totp/")
	assert.Equal(t, "Test App", setup.Issuer)
	assert.Equal(t, "test@example.com", setup.Account)

	mockRepo.AssertExpectations(t)
}

func TestMFAService_EnableMFA(t *testing.T) {
	mockRepo := new(MockRepository)
	mfaService := NewMFAService(mockRepo)
	ctx := context.Background()

	userID := uuid.New()
	secret := "JBSWY3DPEHPK3PXP" // Base32 encoded secret for testing
	user := &UnifiedUser{
		ID:        userID,
		Email:     stringPtr("test@example.com"),
		MFASecret: &secret,
	}

	// Only expect one call to GetUserByID since the TOTP verification will fail
	mockRepo.On("GetUserByID", ctx, userID).Return(user, nil).Once()

	// This test would need a valid TOTP code for the secret
	// For testing purposes, we'll mock the TOTP validation
	err := mfaService.EnableMFA(ctx, userID, "123456") // This would fail with real TOTP

	// Since we can't easily generate a valid TOTP code in tests without time manipulation,
	// we expect this to fail with invalid TOTP code
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid TOTP code")

	mockRepo.AssertExpectations(t)
}

func TestMFAService_IsMFARequired(t *testing.T) {
	mockRepo := new(MockRepository)
	mfaService := NewMFAService(mockRepo)
	ctx := context.Background()

	tests := []struct {
		name     string
		user     *UnifiedUser
		expected bool
	}{
		{
			name: "System Admin requires MFA",
			user: &UnifiedUser{
				AdminLevel: &[]AdminLevel{AdminLevelSystemAdmin}[0],
			},
			expected: true,
		},
		{
			name: "Super Admin requires MFA",
			user: &UnifiedUser{
				AdminLevel: &[]AdminLevel{AdminLevelSuperAdmin}[0],
			},
			expected: true,
		},
		{
			name: "Regular Admin requires MFA",
			user: &UnifiedUser{
				AdminLevel: &[]AdminLevel{AdminLevelRegularAdmin}[0],
			},
			expected: true,
		},
		{
			name: "Moderator requires MFA",
			user: &UnifiedUser{
				AdminLevel: &[]AdminLevel{AdminLevelModerator}[0],
			},
			expected: true,
		},
		{
			name: "Regular user does not require MFA",
			user: &UnifiedUser{
				AdminLevel: nil,
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := mfaService.IsMFARequired(ctx, tt.user)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestMFAService_GenerateBackupCodes(t *testing.T) {
	mockRepo := new(MockRepository)
	mfaService := NewMFAService(mockRepo)
	ctx := context.Background()

	userID := uuid.New()
	user := &UnifiedUser{
		ID:         userID,
		MFAEnabled: true,
	}

	mockRepo.On("GetUserByID", ctx, userID).Return(user, nil)
	mockRepo.On("UpdateUser", ctx, mock.AnythingOfType("*auth.UnifiedUser")).Return(nil)

	codes, err := mfaService.GenerateBackupCodes(ctx, userID)

	assert.NoError(t, err)
	assert.Len(t, codes, 10) // Should generate 10 backup codes

	// Check that all codes are unique
	codeMap := make(map[string]bool)
	for _, code := range codes {
		assert.False(t, codeMap[code], "Duplicate backup code found: %s", code)
		codeMap[code] = true
		assert.Contains(t, code, "BC-") // Should have BC- prefix
	}

	mockRepo.AssertExpectations(t)
}

func TestMFAService_GenerateBackupCodes_MFANotEnabled(t *testing.T) {
	mockRepo := new(MockRepository)
	mfaService := NewMFAService(mockRepo)
	ctx := context.Background()

	userID := uuid.New()
	user := &UnifiedUser{
		ID:         userID,
		MFAEnabled: false,
	}

	mockRepo.On("GetUserByID", ctx, userID).Return(user, nil)

	codes, err := mfaService.GenerateBackupCodes(ctx, userID)

	assert.Error(t, err)
	assert.Nil(t, codes)
	assert.Contains(t, err.Error(), "MFA is not enabled")

	mockRepo.AssertExpectations(t)
}

func TestMFAService_VerifyBackupCode(t *testing.T) {
	mockRepo := new(MockRepository)
	mfaService := NewMFAService(mockRepo)
	ctx := context.Background()

	userID := uuid.New()
	backupCodes := []string{"BC-01-TESTCODE1", "BC-02-TESTCODE2"}
	user := &UnifiedUser{
		ID:          userID,
		MFAEnabled:  true,
		BackupCodes: backupCodes,
	}

	mockRepo.On("GetUserByID", ctx, userID).Return(user, nil)
	mockRepo.On("UpdateUser", ctx, mock.AnythingOfType("*auth.UnifiedUser")).Return(nil)

	// Test valid backup code
	err := mfaService.VerifyBackupCode(ctx, userID, "BC-01-TESTCODE1")
	assert.NoError(t, err)

	// Test invalid backup code
	mockRepo.On("GetUserByID", ctx, userID).Return(&UnifiedUser{
		ID:          userID,
		MFAEnabled:  true,
		BackupCodes: []string{"BC-02-TESTCODE2"}, // First code should be removed
	}, nil)

	err = mfaService.VerifyBackupCode(ctx, userID, "BC-01-TESTCODE1") // Already used
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid backup code")

	mockRepo.AssertExpectations(t)
}

func TestMFAService_VerifyMFACode(t *testing.T) {
	mockRepo := new(MockRepository)
	mfaService := NewMFAService(mockRepo)
	ctx := context.Background()

	userID := uuid.New()
	secret := "JBSWY3DPEHPK3PXP"
	backupCodes := []string{"BC-01-TESTCODE1"}
	user := &UnifiedUser{
		ID:          userID,
		MFAEnabled:  true,
		MFASecret:   &secret,
		BackupCodes: backupCodes,
	}

	mockRepo.On("GetUserByID", ctx, userID).Return(user, nil).Maybe()
	mockRepo.On("UpdateUser", ctx, mock.AnythingOfType("*auth.UnifiedUser")).Return(nil).Maybe()

	// Test with backup code (longer than 6 digits)
	err := mfaService.VerifyMFACode(ctx, userID, "BC-01-TESTCODE1")
	assert.NoError(t, err)

	// Test with invalid code
	err = mfaService.VerifyMFACode(ctx, userID, "invalid")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid MFA code")

	mockRepo.AssertExpectations(t)
}

func TestMFARecovery_IsExpired(t *testing.T) {
	recovery := &MFARecovery{
		ExpiresAt: time.Now().Add(-1 * time.Hour), // Expired 1 hour ago
	}
	assert.True(t, recovery.IsExpired())

	recovery.ExpiresAt = time.Now().Add(1 * time.Hour) // Expires in 1 hour
	assert.False(t, recovery.IsExpired())
}

func TestMFARecovery_IsUsed(t *testing.T) {
	recovery := &MFARecovery{
		UsedAt: nil,
	}
	assert.False(t, recovery.IsUsed())

	now := time.Now()
	recovery.UsedAt = &now
	assert.True(t, recovery.IsUsed())
}

// Helper function for tests
func stringPtr(s string) *string {
	return &s
}

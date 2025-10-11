package auth

import (
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestUnifiedUser_IsAdmin(t *testing.T) {
	tests := []struct {
		name     string
		user     *UnifiedUser
		expected bool
	}{
		{
			name: "user with system admin level",
			user: &UnifiedUser{
				AdminLevel: &[]AdminLevel{AdminLevelSystemAdmin}[0],
			},
			expected: true,
		},
		{
			name: "user with no admin level",
			user: &UnifiedUser{
				AdminLevel: nil,
			},
			expected: false,
		},
		{
			name: "user with moderator level",
			user: &UnifiedUser{
				AdminLevel: &[]AdminLevel{AdminLevelModerator}[0],
			},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.user.IsAdmin(); got != tt.expected {
				t.Errorf("UnifiedUser.IsAdmin() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestUnifiedUser_IsSystemAdmin(t *testing.T) {
	tests := []struct {
		name     string
		user     *UnifiedUser
		expected bool
	}{
		{
			name: "system admin user",
			user: &UnifiedUser{
				AdminLevel: &[]AdminLevel{AdminLevelSystemAdmin}[0],
			},
			expected: true,
		},
		{
			name: "super admin user",
			user: &UnifiedUser{
				AdminLevel: &[]AdminLevel{AdminLevelSuperAdmin}[0],
			},
			expected: false,
		},
		{
			name: "regular user",
			user: &UnifiedUser{
				AdminLevel: nil,
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.user.IsSystemAdmin(); got != tt.expected {
				t.Errorf("UnifiedUser.IsSystemAdmin() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestUnifiedUser_IsLocked(t *testing.T) {
	future := time.Now().Add(1 * time.Hour)
	past := time.Now().Add(-1 * time.Hour)

	tests := []struct {
		name     string
		user     *UnifiedUser
		expected bool
	}{
		{
			name: "user locked until future",
			user: &UnifiedUser{
				LockedUntil: &future,
			},
			expected: true,
		},
		{
			name: "user locked until past",
			user: &UnifiedUser{
				LockedUntil: &past,
			},
			expected: false,
		},
		{
			name: "user not locked",
			user: &UnifiedUser{
				LockedUntil: nil,
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.user.IsLocked(); got != tt.expected {
				t.Errorf("UnifiedUser.IsLocked() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestGetDefaultCapabilities(t *testing.T) {
	tests := []struct {
		name     string
		level    AdminLevel
		expected AdminCapabilities
	}{
		{
			name:  "system admin capabilities",
			level: AdminLevelSystemAdmin,
			expected: AdminCapabilities{
				CanAccessSQL:            true,
				CanManageDatabase:       true,
				CanManageSystem:         true,
				CanCreateSuperAdmin:     true,
				CanInstallPlugins:       true,
				CanModifySecurityConfig: true,
				CanCreateAdmins:         true,
				CanManageAllTables:      true,
				CanManageAuth:           true,
				CanManageStorage:        true,
				CanViewAllLogs:          true,
				CanManageTemplates:      true,
				CanManageCronJobs:       true,
				CanManageUsers:          true,
				CanManageContent:        true,
				CanExportData:           true,
				CanViewReports:          true,
				CanModerateContent:      true,
				CanViewBasicLogs:        true,
				CanViewDashboard:        true,
				CanUpdateProfile:        true,
			},
		},
		{
			name:  "moderator capabilities",
			level: AdminLevelModerator,
			expected: AdminCapabilities{
				CanViewReports:     true,
				CanModerateContent: true,
				CanViewBasicLogs:   true,
				CanViewDashboard:   true,
				CanUpdateProfile:   true,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := GetDefaultCapabilities(tt.level)

			// Check key capabilities
			if got.CanAccessSQL != tt.expected.CanAccessSQL {
				t.Errorf("GetDefaultCapabilities().CanAccessSQL = %v, want %v", got.CanAccessSQL, tt.expected.CanAccessSQL)
			}
			if got.CanViewDashboard != tt.expected.CanViewDashboard {
				t.Errorf("GetDefaultCapabilities().CanViewDashboard = %v, want %v", got.CanViewDashboard, tt.expected.CanViewDashboard)
			}
		})
	}
}

func TestValidateAdminPromotion(t *testing.T) {
	systemAdmin := &UnifiedUser{
		ID:         uuid.New(),
		AdminLevel: &[]AdminLevel{AdminLevelSystemAdmin}[0],
	}

	superAdmin := &UnifiedUser{
		ID:         uuid.New(),
		AdminLevel: &[]AdminLevel{AdminLevelSuperAdmin}[0],
	}

	regularUser := &UnifiedUser{
		ID:         uuid.New(),
		AdminLevel: nil,
	}

	tests := []struct {
		name        string
		promoter    *UnifiedUser
		targetLevel AdminLevel
		wantError   bool
	}{
		{
			name:        "system admin can promote to system admin",
			promoter:    systemAdmin,
			targetLevel: AdminLevelSystemAdmin,
			wantError:   false,
		},
		{
			name:        "super admin cannot promote to system admin",
			promoter:    superAdmin,
			targetLevel: AdminLevelSystemAdmin,
			wantError:   true,
		},
		{
			name:        "regular user cannot promote anyone",
			promoter:    regularUser,
			targetLevel: AdminLevelModerator,
			wantError:   true,
		},
		{
			name:        "system admin can promote to super admin",
			promoter:    systemAdmin,
			targetLevel: AdminLevelSuperAdmin,
			wantError:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateAdminPromotion(tt.promoter, tt.targetLevel)
			if (err != nil) != tt.wantError {
				t.Errorf("ValidateAdminPromotion() error = %v, wantError %v", err, tt.wantError)
			}
		})
	}
}

func TestAdminLevel_GetHierarchy(t *testing.T) {
	tests := []struct {
		name     string
		level    AdminLevel
		expected int
	}{
		{
			name:     "system admin hierarchy",
			level:    AdminLevelSystemAdmin,
			expected: 4,
		},
		{
			name:     "super admin hierarchy",
			level:    AdminLevelSuperAdmin,
			expected: 3,
		},
		{
			name:     "regular admin hierarchy",
			level:    AdminLevelRegularAdmin,
			expected: 2,
		},
		{
			name:     "moderator hierarchy",
			level:    AdminLevelModerator,
			expected: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.level.GetHierarchy(); got != tt.expected {
				t.Errorf("AdminLevel.GetHierarchy() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestOTPCode_IsExpired(t *testing.T) {
	future := time.Now().Add(1 * time.Hour)
	past := time.Now().Add(-1 * time.Hour)

	tests := []struct {
		name     string
		otp      *OTPCode
		expected bool
	}{
		{
			name: "expired OTP",
			otp: &OTPCode{
				ExpiresAt: past,
			},
			expected: true,
		},
		{
			name: "valid OTP",
			otp: &OTPCode{
				ExpiresAt: future,
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.otp.IsExpired(); got != tt.expected {
				t.Errorf("OTPCode.IsExpired() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestOTPCode_CanAttempt(t *testing.T) {
	tests := []struct {
		name     string
		otp      *OTPCode
		expected bool
	}{
		{
			name: "can attempt more",
			otp: &OTPCode{
				Attempts:    2,
				MaxAttempts: 3,
			},
			expected: true,
		},
		{
			name: "max attempts reached",
			otp: &OTPCode{
				Attempts:    3,
				MaxAttempts: 3,
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.otp.CanAttempt(); got != tt.expected {
				t.Errorf("OTPCode.CanAttempt() = %v, want %v", got, tt.expected)
			}
		})
	}
}

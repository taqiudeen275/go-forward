package auth

import (
	"database/sql/driver"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// AdminLevel represents the hierarchical admin levels
type AdminLevel string

const (
	AdminLevelSystemAdmin  AdminLevel = "system_admin"
	AdminLevelSuperAdmin   AdminLevel = "super_admin"
	AdminLevelRegularAdmin AdminLevel = "regular_admin"
	AdminLevelModerator    AdminLevel = "moderator"
)

// MFAMethod represents multi-factor authentication methods
type MFAMethod string

const (
	MFAMethodTOTP        MFAMethod = "totp"
	MFAMethodBackupCodes MFAMethod = "backup_codes"
	MFAMethodSMS         MFAMethod = "sms"
	MFAMethodEmail       MFAMethod = "email"
)

// TemplateType represents communication template types
type TemplateType string

const (
	TemplateTypeEmail TemplateType = "email"
	TemplateTypeSMS   TemplateType = "sms"
)

// AuditSeverity represents audit log severity levels
type AuditSeverity string

const (
	AuditSeverityLow      AuditSeverity = "low"
	AuditSeverityMedium   AuditSeverity = "medium"
	AuditSeverityHigh     AuditSeverity = "high"
	AuditSeverityCritical AuditSeverity = "critical"
)

// AdminCapabilities defines comprehensive admin permissions
type AdminCapabilities struct {
	// System-level capabilities (System Admin only)
	CanAccessSQL            bool `json:"can_access_sql"`
	CanManageDatabase       bool `json:"can_manage_database"`
	CanManageSystem         bool `json:"can_manage_system"`
	CanCreateSuperAdmin     bool `json:"can_create_super_admin"`
	CanInstallPlugins       bool `json:"can_install_plugins"`
	CanModifySecurityConfig bool `json:"can_modify_security_config"`

	// Super admin capabilities
	CanCreateAdmins    bool `json:"can_create_admins"`
	CanManageAllTables bool `json:"can_manage_all_tables"`
	CanManageAuth      bool `json:"can_manage_auth"`
	CanManageStorage   bool `json:"can_manage_storage"`
	CanViewAllLogs     bool `json:"can_view_all_logs"`
	CanManageTemplates bool `json:"can_manage_templates"`
	CanManageCronJobs  bool `json:"can_manage_cron_jobs"`

	// Regular admin capabilities
	CanManageUsers     bool     `json:"can_manage_users"`
	CanManageContent   bool     `json:"can_manage_content"`
	AssignedTables     []string `json:"assigned_tables"`
	AssignedUserGroups []string `json:"assigned_user_groups"`
	CanExportData      bool     `json:"can_export_data"`

	// Moderator capabilities
	CanViewReports     bool `json:"can_view_reports"`
	CanModerateContent bool `json:"can_moderate_content"`
	CanViewBasicLogs   bool `json:"can_view_basic_logs"`

	// Common capabilities
	CanViewDashboard bool `json:"can_view_dashboard"`
	CanUpdateProfile bool `json:"can_update_profile"`
}

// Scan implements the sql.Scanner interface for AdminCapabilities
func (ac *AdminCapabilities) Scan(value interface{}) error {
	if value == nil {
		*ac = AdminCapabilities{}
		return nil
	}

	bytes, ok := value.([]byte)
	if !ok {
		return fmt.Errorf("cannot scan %T into AdminCapabilities", value)
	}

	return json.Unmarshal(bytes, ac)
}

// Value implements the driver.Valuer interface for AdminCapabilities
func (ac AdminCapabilities) Value() (driver.Value, error) {
	return json.Marshal(ac)
}

// UnifiedUser represents a user with admin capabilities
type UnifiedUser struct {
	ID            uuid.UUID `json:"id" db:"id"`
	Email         *string   `json:"email" db:"email"`
	Phone         *string   `json:"phone" db:"phone"`
	Username      *string   `json:"username" db:"username"`
	PasswordHash  string    `json:"-" db:"password_hash"`
	EmailVerified bool      `json:"email_verified" db:"email_verified"`
	PhoneVerified bool      `json:"phone_verified" db:"phone_verified"`

	// Admin fields
	AdminLevel     *AdminLevel        `json:"admin_level" db:"admin_level"`
	Capabilities   *AdminCapabilities `json:"capabilities" db:"capabilities"`
	AssignedTables []string           `json:"assigned_tables" db:"assigned_tables"`

	// Security fields
	MFAEnabled     bool       `json:"mfa_enabled" db:"mfa_enabled"`
	MFASecret      *string    `json:"-" db:"mfa_secret"`
	BackupCodes    []string   `json:"-" db:"backup_codes"`
	LastLogin      *time.Time `json:"last_login" db:"last_login"`
	FailedAttempts int        `json:"failed_attempts" db:"failed_attempts"`
	LockedUntil    *time.Time `json:"locked_until" db:"locked_until"`

	// Standard fields
	Metadata  map[string]interface{} `json:"metadata" db:"metadata"`
	CreatedAt time.Time              `json:"created_at" db:"created_at"`
	UpdatedAt time.Time              `json:"updated_at" db:"updated_at"`
	CreatedBy *uuid.UUID             `json:"created_by" db:"created_by"`
	UpdatedBy *uuid.UUID             `json:"updated_by" db:"updated_by"`
}

// IsAdmin returns true if the user has any admin level
func (u *UnifiedUser) IsAdmin() bool {
	return u.AdminLevel != nil
}

// IsSystemAdmin returns true if the user is a system admin
func (u *UnifiedUser) IsSystemAdmin() bool {
	return u.AdminLevel != nil && *u.AdminLevel == AdminLevelSystemAdmin
}

// IsSuperAdmin returns true if the user is a super admin or higher
func (u *UnifiedUser) IsSuperAdmin() bool {
	return u.AdminLevel != nil && (*u.AdminLevel == AdminLevelSystemAdmin || *u.AdminLevel == AdminLevelSuperAdmin)
}

// IsRegularAdmin returns true if the user is a regular admin or higher
func (u *UnifiedUser) IsRegularAdmin() bool {
	return u.AdminLevel != nil && (*u.AdminLevel == AdminLevelSystemAdmin ||
		*u.AdminLevel == AdminLevelSuperAdmin || *u.AdminLevel == AdminLevelRegularAdmin)
}

// IsModerator returns true if the user has any admin privileges
func (u *UnifiedUser) IsModerator() bool {
	return u.IsAdmin()
}

// IsLocked returns true if the user account is currently locked
func (u *UnifiedUser) IsLocked() bool {
	return u.LockedUntil != nil && u.LockedUntil.After(time.Now())
}

// GetDefaultCapabilities returns default capabilities for an admin level
func GetDefaultCapabilities(level AdminLevel) AdminCapabilities {
	switch level {
	case AdminLevelSystemAdmin:
		return AdminCapabilities{
			// System-level capabilities
			CanAccessSQL:            true,
			CanManageDatabase:       true,
			CanManageSystem:         true,
			CanCreateSuperAdmin:     true,
			CanInstallPlugins:       true,
			CanModifySecurityConfig: true,
			// Super admin capabilities
			CanCreateAdmins:    true,
			CanManageAllTables: true,
			CanManageAuth:      true,
			CanManageStorage:   true,
			CanViewAllLogs:     true,
			CanManageTemplates: true,
			CanManageCronJobs:  true,
			// Regular admin capabilities
			CanManageUsers:   true,
			CanManageContent: true,
			CanExportData:    true,
			// Moderator capabilities
			CanViewReports:     true,
			CanModerateContent: true,
			CanViewBasicLogs:   true,
			// Common capabilities
			CanViewDashboard: true,
			CanUpdateProfile: true,
		}
	case AdminLevelSuperAdmin:
		return AdminCapabilities{
			// Super admin capabilities
			CanCreateAdmins:    true,
			CanManageAllTables: true,
			CanManageAuth:      true,
			CanManageStorage:   true,
			CanViewAllLogs:     true,
			CanManageTemplates: true,
			CanManageCronJobs:  true,
			// Regular admin capabilities
			CanManageUsers:   true,
			CanManageContent: true,
			CanExportData:    true,
			// Moderator capabilities
			CanViewReports:     true,
			CanModerateContent: true,
			CanViewBasicLogs:   true,
			// Common capabilities
			CanViewDashboard: true,
			CanUpdateProfile: true,
		}
	case AdminLevelRegularAdmin:
		return AdminCapabilities{
			// Regular admin capabilities
			CanManageUsers:   true,
			CanManageContent: true,
			CanExportData:    true,
			// Moderator capabilities
			CanViewReports:     true,
			CanModerateContent: true,
			CanViewBasicLogs:   true,
			// Common capabilities
			CanViewDashboard: true,
			CanUpdateProfile: true,
		}
	case AdminLevelModerator:
		return AdminCapabilities{
			// Moderator capabilities
			CanViewReports:     true,
			CanModerateContent: true,
			CanViewBasicLogs:   true,
			// Common capabilities
			CanViewDashboard: true,
			CanUpdateProfile: true,
		}
	default:
		return AdminCapabilities{
			CanUpdateProfile: true,
		}
	}
}

// AdminSession represents an admin session with security tracking
type AdminSession struct {
	ID           uuid.UUID `json:"id" db:"id"`
	UserID       uuid.UUID `json:"user_id" db:"user_id"`
	SessionToken string    `json:"session_token" db:"session_token"`
	RefreshToken *string   `json:"refresh_token" db:"refresh_token"`
	IPAddress    *string   `json:"ip_address" db:"ip_address"`
	UserAgent    *string   `json:"user_agent" db:"user_agent"`
	ExpiresAt    time.Time `json:"expires_at" db:"expires_at"`
	CreatedAt    time.Time `json:"created_at" db:"created_at"`
	LastActivity time.Time `json:"last_activity" db:"last_activity"`
}

// IsExpired returns true if the session has expired
func (s *AdminSession) IsExpired() bool {
	return s.ExpiresAt.Before(time.Now())
}

// APIKey represents an API key for service authentication
type APIKey struct {
	ID          uuid.UUID              `json:"id" db:"id"`
	UserID      uuid.UUID              `json:"user_id" db:"user_id"`
	Name        string                 `json:"name" db:"name"`
	KeyHash     string                 `json:"-" db:"key_hash"`
	Permissions map[string]interface{} `json:"permissions" db:"permissions"`
	LastUsed    *time.Time             `json:"last_used" db:"last_used"`
	ExpiresAt   *time.Time             `json:"expires_at" db:"expires_at"`
	CreatedAt   time.Time              `json:"created_at" db:"created_at"`
	CreatedBy   uuid.UUID              `json:"created_by" db:"created_by"`
}

// IsExpired returns true if the API key has expired
func (k *APIKey) IsExpired() bool {
	return k.ExpiresAt != nil && k.ExpiresAt.Before(time.Now())
}

// OTPCode represents a one-time password code
type OTPCode struct {
	ID          uuid.UUID  `json:"id" db:"id"`
	UserID      *uuid.UUID `json:"user_id" db:"user_id"`
	Email       *string    `json:"email" db:"email"`
	Phone       *string    `json:"phone" db:"phone"`
	Code        string     `json:"-" db:"code"`
	Purpose     string     `json:"purpose" db:"purpose"`
	Attempts    int        `json:"attempts" db:"attempts"`
	MaxAttempts int        `json:"max_attempts" db:"max_attempts"`
	ExpiresAt   time.Time  `json:"expires_at" db:"expires_at"`
	UsedAt      *time.Time `json:"used_at" db:"used_at"`
	CreatedAt   time.Time  `json:"created_at" db:"created_at"`
}

// IsExpired returns true if the OTP code has expired
func (o *OTPCode) IsExpired() bool {
	return o.ExpiresAt.Before(time.Now())
}

// IsUsed returns true if the OTP code has been used
func (o *OTPCode) IsUsed() bool {
	return o.UsedAt != nil
}

// CanAttempt returns true if more attempts are allowed
func (o *OTPCode) CanAttempt() bool {
	return o.Attempts < o.MaxAttempts
}

// TemplateVariable represents available variables for templates
type TemplateVariable struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Type        string `json:"type"` // string, number, date, boolean
	Required    bool   `json:"required"`
	Example     string `json:"example"`
}

// Template represents customizable communication templates
type Template struct {
	ID        uuid.UUID          `json:"id" db:"id"`
	Type      TemplateType       `json:"type" db:"type"`
	Purpose   string             `json:"purpose" db:"purpose"`
	Language  string             `json:"language" db:"language"`
	Subject   *string            `json:"subject" db:"subject"`
	Content   string             `json:"content" db:"content"`
	Variables []TemplateVariable `json:"variables" db:"variables"`
	IsDefault bool               `json:"is_default" db:"is_default"`
	IsActive  bool               `json:"is_active" db:"is_active"`
	CreatedBy uuid.UUID          `json:"created_by" db:"created_by"`
	CreatedAt time.Time          `json:"created_at" db:"created_at"`
	UpdatedBy uuid.UUID          `json:"updated_by" db:"updated_by"`
	UpdatedAt time.Time          `json:"updated_at" db:"updated_at"`
}

// AuditLog represents audit log entries
type AuditLog struct {
	ID         uuid.UUID              `json:"id" db:"id"`
	UserID     *uuid.UUID             `json:"user_id" db:"user_id"`
	Action     string                 `json:"action" db:"action"`
	Resource   *string                `json:"resource" db:"resource"`
	ResourceID *string                `json:"resource_id" db:"resource_id"`
	Details    map[string]interface{} `json:"details" db:"details"`
	IPAddress  *string                `json:"ip_address" db:"ip_address"`
	UserAgent  *string                `json:"user_agent" db:"user_agent"`
	RequestID  *string                `json:"request_id" db:"request_id"`
	Success    bool                   `json:"success" db:"success"`
	ErrorCode  *string                `json:"error_code" db:"error_code"`
	Severity   AuditSeverity          `json:"severity" db:"severity"`
	CreatedAt  time.Time              `json:"created_at" db:"created_at"`
}

// SecurityEvent represents security events
type SecurityEvent struct {
	ID         uuid.UUID              `json:"id" db:"id"`
	EventType  string                 `json:"event_type" db:"event_type"`
	UserID     *uuid.UUID             `json:"user_id" db:"user_id"`
	IPAddress  *string                `json:"ip_address" db:"ip_address"`
	UserAgent  *string                `json:"user_agent" db:"user_agent"`
	Details    map[string]interface{} `json:"details" db:"details"`
	Severity   AuditSeverity          `json:"severity" db:"severity"`
	Resolved   bool                   `json:"resolved" db:"resolved"`
	ResolvedBy *uuid.UUID             `json:"resolved_by" db:"resolved_by"`
	ResolvedAt *time.Time             `json:"resolved_at" db:"resolved_at"`
	CreatedAt  time.Time              `json:"created_at" db:"created_at"`
}

// RateLimit represents rate limiting entries
type RateLimit struct {
	ID          uuid.UUID `json:"id" db:"id"`
	Key         string    `json:"key" db:"key"`
	Count       int       `json:"count" db:"count"`
	WindowStart time.Time `json:"window_start" db:"window_start"`
	ExpiresAt   time.Time `json:"expires_at" db:"expires_at"`
}

// IsExpired returns true if the rate limit window has expired
func (r *RateLimit) IsExpired() bool {
	return r.ExpiresAt.Before(time.Now())
}

// ValidateAdminPromotion validates if a user can be promoted to a specific admin level
func ValidateAdminPromotion(promoter *UnifiedUser, targetLevel AdminLevel) error {
	if promoter == nil || !promoter.IsAdmin() {
		return fmt.Errorf("promoter must be an admin")
	}

	switch targetLevel {
	case AdminLevelSystemAdmin:
		if !promoter.IsSystemAdmin() {
			return fmt.Errorf("only system admins can create other system admins")
		}
	case AdminLevelSuperAdmin:
		if !promoter.IsSystemAdmin() {
			return fmt.Errorf("only system admins can create super admins")
		}
	case AdminLevelRegularAdmin:
		if !promoter.IsSuperAdmin() {
			return fmt.Errorf("only super admins and above can create regular admins")
		}
	case AdminLevelModerator:
		if !promoter.IsRegularAdmin() {
			return fmt.Errorf("only regular admins and above can create moderators")
		}
	default:
		return fmt.Errorf("invalid admin level: %s", targetLevel)
	}

	return nil
}

// CanManageUser checks if an admin can manage a specific user
func (u *UnifiedUser) CanManageUser(targetUser *UnifiedUser) bool {
	if !u.IsAdmin() {
		return false
	}

	// System admins can manage anyone
	if u.IsSystemAdmin() {
		return true
	}

	// Super admins can manage non-system-admins
	if u.IsSuperAdmin() {
		return targetUser.AdminLevel == nil || *targetUser.AdminLevel != AdminLevelSystemAdmin
	}

	// Regular admins can manage non-admins and moderators
	if u.IsRegularAdmin() {
		return targetUser.AdminLevel == nil || *targetUser.AdminLevel == AdminLevelModerator
	}

	// Moderators cannot manage other users
	return false
}

// HasCapability checks if the user has a specific capability
func (u *UnifiedUser) HasCapability(capability string) bool {
	if u.Capabilities == nil {
		return false
	}

	switch capability {
	case "can_access_sql":
		return u.Capabilities.CanAccessSQL
	case "can_manage_database":
		return u.Capabilities.CanManageDatabase
	case "can_manage_system":
		return u.Capabilities.CanManageSystem
	case "can_create_super_admin":
		return u.Capabilities.CanCreateSuperAdmin
	case "can_install_plugins":
		return u.Capabilities.CanInstallPlugins
	case "can_modify_security_config":
		return u.Capabilities.CanModifySecurityConfig
	case "can_create_admins":
		return u.Capabilities.CanCreateAdmins
	case "can_manage_all_tables":
		return u.Capabilities.CanManageAllTables
	case "can_manage_auth":
		return u.Capabilities.CanManageAuth
	case "can_manage_storage":
		return u.Capabilities.CanManageStorage
	case "can_view_all_logs":
		return u.Capabilities.CanViewAllLogs
	case "can_manage_templates":
		return u.Capabilities.CanManageTemplates
	case "can_manage_cron_jobs":
		return u.Capabilities.CanManageCronJobs
	case "can_manage_users":
		return u.Capabilities.CanManageUsers
	case "can_manage_content":
		return u.Capabilities.CanManageContent
	case "can_export_data":
		return u.Capabilities.CanExportData
	case "can_view_reports":
		return u.Capabilities.CanViewReports
	case "can_moderate_content":
		return u.Capabilities.CanModerateContent
	case "can_view_basic_logs":
		return u.Capabilities.CanViewBasicLogs
	case "can_view_dashboard":
		return u.Capabilities.CanViewDashboard
	case "can_update_profile":
		return u.Capabilities.CanUpdateProfile
	default:
		return false
	}
}

// CanAccessTable checks if the user can access a specific table
func (u *UnifiedUser) CanAccessTable(tableName string) bool {
	if !u.IsAdmin() {
		return false
	}

	// System and super admins can access all tables
	if u.IsSuperAdmin() {
		return true
	}

	// Regular admins and moderators can only access assigned tables
	for _, assignedTable := range u.AssignedTables {
		if assignedTable == tableName {
			return true
		}
	}

	return false
}

// GetAdminLevelHierarchy returns the numeric hierarchy level for comparison
func (level AdminLevel) GetHierarchy() int {
	switch level {
	case AdminLevelSystemAdmin:
		return 4
	case AdminLevelSuperAdmin:
		return 3
	case AdminLevelRegularAdmin:
		return 2
	case AdminLevelModerator:
		return 1
	default:
		return 0
	}
}

// IsHigherThan checks if this admin level is higher than another
func (level AdminLevel) IsHigherThan(other AdminLevel) bool {
	return level.GetHierarchy() > other.GetHierarchy()
}

// IsHigherOrEqual checks if this admin level is higher than or equal to another
func (level AdminLevel) IsHigherOrEqual(other AdminLevel) bool {
	return level.GetHierarchy() >= other.GetHierarchy()
}

// ValidateTemplateVariables validates that all required variables are present
func (t *Template) ValidateTemplateVariables(variables map[string]interface{}) error {
	for _, templateVar := range t.Variables {
		if templateVar.Required {
			if _, exists := variables[templateVar.Name]; !exists {
				return fmt.Errorf("required template variable '%s' is missing", templateVar.Name)
			}
		}
	}
	return nil
}

// GetAvailableVariables returns the available variables for a template purpose
func GetAvailableVariables(purpose string) []TemplateVariable {
	baseVariables := []TemplateVariable{
		{
			Name:        "code",
			Description: "The OTP or verification code",
			Type:        "string",
			Required:    true,
			Example:     "123456",
		},
		{
			Name:        "expiration",
			Description: "Code expiration time in minutes",
			Type:        "number",
			Required:    false,
			Example:     "15",
		},
	}

	switch purpose {
	case "login":
		return append(baseVariables, []TemplateVariable{
			{
				Name:        "user_name",
				Description: "User's display name or email",
				Type:        "string",
				Required:    false,
				Example:     "john@example.com",
			},
			{
				Name:        "ip_address",
				Description: "Login attempt IP address",
				Type:        "string",
				Required:    false,
				Example:     "192.168.1.1",
			},
		}...)
	case "registration":
		return append(baseVariables, []TemplateVariable{
			{
				Name:        "user_name",
				Description: "User's display name or email",
				Type:        "string",
				Required:    false,
				Example:     "john@example.com",
			},
			{
				Name:        "welcome_message",
				Description: "Welcome message for new users",
				Type:        "string",
				Required:    false,
				Example:     "Welcome to our platform!",
			},
		}...)
	case "password_reset":
		return append(baseVariables, []TemplateVariable{
			{
				Name:        "user_name",
				Description: "User's display name or email",
				Type:        "string",
				Required:    false,
				Example:     "john@example.com",
			},
			{
				Name:        "reset_url",
				Description: "Password reset URL",
				Type:        "string",
				Required:    false,
				Example:     "https://example.com/reset-password",
			},
		}...)
	case "verification":
		return append(baseVariables, []TemplateVariable{
			{
				Name:        "user_name",
				Description: "User's display name or email",
				Type:        "string",
				Required:    false,
				Example:     "john@example.com",
			},
			{
				Name:        "verification_type",
				Description: "Type of verification (email/phone)",
				Type:        "string",
				Required:    false,
				Example:     "email",
			},
		}...)
	default:
		return baseVariables
	}
}

// SecurityEventTypes defines common security event types
var SecurityEventTypes = struct {
	LoginFailure        string
	LoginSuccess        string
	PasswordReset       string
	AdminPromotion      string
	AdminDemotion       string
	UnauthorizedAccess  string
	SuspiciousActivity  string
	AccountLockout      string
	MFAEnabled          string
	MFADisabled         string
	APIKeyCreated       string
	APIKeyDeleted       string
	TemplateModified    string
	ConfigurationChange string
}{
	LoginFailure:        "login_failure",
	LoginSuccess:        "login_success",
	PasswordReset:       "password_reset",
	AdminPromotion:      "admin_promotion",
	AdminDemotion:       "admin_demotion",
	UnauthorizedAccess:  "unauthorized_access",
	SuspiciousActivity:  "suspicious_activity",
	AccountLockout:      "account_lockout",
	MFAEnabled:          "mfa_enabled",
	MFADisabled:         "mfa_disabled",
	APIKeyCreated:       "api_key_created",
	APIKeyDeleted:       "api_key_deleted",
	TemplateModified:    "template_modified",
	ConfigurationChange: "configuration_change",
}

// AuditActions defines common audit actions
var AuditActions = struct {
	UserCreate     string
	UserUpdate     string
	UserDelete     string
	AdminPromote   string
	AdminDemote    string
	Login          string
	Logout         string
	PasswordChange string
	MFASetup       string
	APIKeyCreate   string
	APIKeyDelete   string
	TemplateCreate string
	TemplateUpdate string
	TemplateDelete string
	ConfigUpdate   string
}{
	UserCreate:     "user_create",
	UserUpdate:     "user_update",
	UserDelete:     "user_delete",
	AdminPromote:   "admin_promote",
	AdminDemote:    "admin_demote",
	Login:          "login",
	Logout:         "logout",
	PasswordChange: "password_change",
	MFASetup:       "mfa_setup",
	APIKeyCreate:   "api_key_create",
	APIKeyDelete:   "api_key_delete",
	TemplateCreate: "template_create",
	TemplateUpdate: "template_update",
	TemplateDelete: "template_delete",
	ConfigUpdate:   "config_update",
}

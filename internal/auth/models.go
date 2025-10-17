package auth

import (
	"time"
)

// User represents a system user
type User struct {
	ID            string                 `json:"id" db:"id"`
	Email         *string                `json:"email" db:"email"`
	Phone         *string                `json:"phone" db:"phone"`
	Username      *string                `json:"username" db:"username"`
	PasswordHash  string                 `json:"-" db:"password_hash"`
	EmailVerified bool                   `json:"email_verified" db:"email_verified"`
	PhoneVerified bool                   `json:"phone_verified" db:"phone_verified"`
	Metadata      map[string]interface{} `json:"metadata" db:"metadata"`
	CreatedAt     time.Time              `json:"created_at" db:"created_at"`
	UpdatedAt     time.Time              `json:"updated_at" db:"updated_at"`
}

// CreateUserRequest represents a request to create a new user
type CreateUserRequest struct {
	Email    *string                `json:"email" validate:"omitempty,email"`
	Phone    *string                `json:"phone" validate:"omitempty,e164"`
	Username *string                `json:"username" validate:"omitempty,min=3,max=100"`
	Password string                 `json:"password" validate:"required,min=8"`
	Metadata map[string]interface{} `json:"metadata,omitempty"`
}

// UpdateUserRequest represents a request to update a user
type UpdateUserRequest struct {
	Email         *string                `json:"email" validate:"omitempty,email"`
	Phone         *string                `json:"phone" validate:"omitempty,e164"`
	Username      *string                `json:"username" validate:"omitempty,min=3,max=100"`
	EmailVerified *bool                  `json:"email_verified"`
	PhoneVerified *bool                  `json:"phone_verified"`
	Metadata      map[string]interface{} `json:"metadata,omitempty"`
}

// LoginRequest represents a login request
type LoginRequest struct {
	Identifier string `json:"identifier" validate:"required"` // email, phone, or username
	Password   string `json:"password" validate:"required"`
}

// AuthResponse represents authentication response
type AuthResponse struct {
	User         *User  `json:"user"`
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int    `json:"expires_in"`
}

// UserFilter represents filters for querying users
type UserFilter struct {
	Email         *string `json:"email"`
	Phone         *string `json:"phone"`
	Username      *string `json:"username"`
	EmailVerified *bool   `json:"email_verified"`
	PhoneVerified *bool   `json:"phone_verified"`
	Limit         int     `json:"limit"`
	Offset        int     `json:"offset"`
}

// PasswordResetRequest represents a password reset request
type PasswordResetRequest struct {
	Identifier string `json:"identifier" validate:"required"` // email, phone, or username
}

// PasswordResetConfirmRequest represents a password reset confirmation request
type PasswordResetConfirmRequest struct {
	Identifier  string `json:"identifier" validate:"required"` // email, phone, or username
	OTPCode     string `json:"otp_code" validate:"required,len=6"`
	NewPassword string `json:"new_password" validate:"required,min=8"`
}

// PasswordResetToken represents a password reset token
type PasswordResetToken struct {
	ID        string    `json:"id" db:"id"`
	UserID    string    `json:"user_id" db:"user_id"`
	Token     string    `json:"token" db:"token"`
	ExpiresAt time.Time `json:"expires_at" db:"expires_at"`
	Used      bool      `json:"used" db:"used"`
	CreatedAt time.Time `json:"created_at" db:"created_at"`
}

// OTPType represents the type of OTP delivery method
type OTPType string

const (
	OTPTypeEmail OTPType = "email"
	OTPTypeSMS   OTPType = "sms"
)

// OTP represents a one-time password
type OTP struct {
	ID          string     `json:"id" db:"id"`
	UserID      *string    `json:"user_id" db:"user_id"` // Can be null for registration OTPs
	CodeHash    string     `json:"-" db:"code_hash"`     // Hashed OTP code (never expose in JSON)
	Type        OTPType    `json:"type" db:"type"`
	Purpose     OTPPurpose `json:"purpose" db:"purpose"`
	Recipient   string     `json:"recipient" db:"recipient"` // email or phone number
	ExpiresAt   time.Time  `json:"expires_at" db:"expires_at"`
	Used        bool       `json:"used" db:"used"`
	Attempts    int        `json:"attempts" db:"attempts"`
	MaxAttempts int        `json:"max_attempts" db:"max_attempts"`
	CreatedAt   time.Time  `json:"created_at" db:"created_at"`

	// Transient field for plain text code (not stored in DB)
	Code string `json:"code,omitempty" db:"-"`
}

// OTPPurpose represents the purpose of an OTP
type OTPPurpose string

const (
	OTPPurposeLogin        OTPPurpose = "login"
	OTPPurposeRegistration OTPPurpose = "registration"
	OTPPurposeVerification OTPPurpose = "verification"
)

// OTPRequest represents a request to send an OTP
type OTPRequest struct {
	Type      OTPType    `json:"type" validate:"required,oneof=email sms"`
	Recipient string     `json:"recipient" validate:"required"`
	Purpose   OTPPurpose `json:"purpose" validate:"required,oneof=login registration verification"`
}

// VerifyOTPRequest represents a request to verify an OTP
type VerifyOTPRequest struct {
	Type      OTPType `json:"type" validate:"required,oneof=email sms"`
	Recipient string  `json:"recipient" validate:"required"`
	Code      string  `json:"code" validate:"required,len=6"`
}

// CustomAuthRequest represents a request for custom authentication
type CustomAuthRequest struct {
	Provider    string                 `json:"provider" validate:"required"`
	Credentials map[string]interface{} `json:"credentials" validate:"required"`
}

// AdminRole represents an administrative role
type AdminRole struct {
	ID          string                 `json:"id" db:"id"`
	Name        string                 `json:"name" db:"name"`
	Level       int                    `json:"level" db:"level"`
	Description string                 `json:"description" db:"description"`
	Permissions map[string]interface{} `json:"permissions" db:"permissions"`
	IsActive    bool                   `json:"is_active" db:"is_active"`
	CreatedAt   time.Time              `json:"created_at" db:"created_at"`
	UpdatedAt   time.Time              `json:"updated_at" db:"updated_at"`
}

// UserAdminRole represents a user's admin role assignment
type UserAdminRole struct {
	ID        string                 `json:"id" db:"id"`
	UserID    string                 `json:"user_id" db:"user_id"`
	RoleID    string                 `json:"role_id" db:"role_id"`
	GrantedBy *string                `json:"granted_by" db:"granted_by"`
	GrantedAt time.Time              `json:"granted_at" db:"granted_at"`
	ExpiresAt *time.Time             `json:"expires_at" db:"expires_at"`
	IsActive  bool                   `json:"is_active" db:"is_active"`
	Metadata  map[string]interface{} `json:"metadata" db:"metadata"`
	CreatedAt time.Time              `json:"created_at" db:"created_at"`
	UpdatedAt time.Time              `json:"updated_at" db:"updated_at"`

	// Joined fields
	Role *AdminRole `json:"role,omitempty" db:"-"`
	User *User      `json:"user,omitempty" db:"-"`
}

// MFASettings represents multi-factor authentication settings
type MFASettings struct {
	ID               string     `json:"id" db:"id"`
	UserID           string     `json:"user_id" db:"user_id"`
	TOTPSecret       string     `json:"-" db:"totp_secret"`    // Never expose in JSON
	BackupCodes      []string   `json:"-" db:"backup_codes"`   // Never expose in JSON
	RecoveryCodes    []string   `json:"-" db:"recovery_codes"` // Never expose in JSON
	IsEnabled        bool       `json:"is_enabled" db:"is_enabled"`
	IsEnforced       bool       `json:"is_enforced" db:"is_enforced"`
	Method           string     `json:"method" db:"method"`
	PhoneVerified    bool       `json:"phone_verified" db:"phone_verified"`
	EmailVerified    bool       `json:"email_verified" db:"email_verified"`
	LastUsedAt       *time.Time `json:"last_used_at" db:"last_used_at"`
	LastBackupUsedAt *time.Time `json:"last_backup_used_at" db:"last_backup_used_at"`
	SetupCompletedAt *time.Time `json:"setup_completed_at" db:"setup_completed_at"`
	CreatedAt        time.Time  `json:"created_at" db:"created_at"`
	UpdatedAt        time.Time  `json:"updated_at" db:"updated_at"`
}

// AdminAccessLog represents an administrative action log entry
type AdminAccessLog struct {
	ID              string                 `json:"id" db:"id"`
	UserID          *string                `json:"user_id" db:"user_id"`
	AdminRoleID     *string                `json:"admin_role_id" db:"admin_role_id"`
	SessionID       *string                `json:"session_id" db:"session_id"`
	Action          string                 `json:"action" db:"action"`
	ResourceType    *string                `json:"resource_type" db:"resource_type"`
	ResourceID      *string                `json:"resource_id" db:"resource_id"`
	ResourceName    *string                `json:"resource_name" db:"resource_name"`
	Details         map[string]interface{} `json:"details" db:"details"`
	IPAddress       *string                `json:"ip_address" db:"ip_address"`
	UserAgent       *string                `json:"user_agent" db:"user_agent"`
	RequestMethod   *string                `json:"request_method" db:"request_method"`
	RequestPath     *string                `json:"request_path" db:"request_path"`
	Success         bool                   `json:"success" db:"success"`
	ErrorMessage    *string                `json:"error_message" db:"error_message"`
	ExecutionTimeMs *int                   `json:"execution_time_ms" db:"execution_time_ms"`
	CreatedAt       time.Time              `json:"created_at" db:"created_at"`

	// Joined fields
	User      *User      `json:"user,omitempty" db:"-"`
	AdminRole *AdminRole `json:"admin_role,omitempty" db:"-"`
}

// SecurityEvent represents a security incident or event
type SecurityEvent struct {
	ID                string                 `json:"id" db:"id"`
	EventType         string                 `json:"event_type" db:"event_type"`
	EventCategory     string                 `json:"event_category" db:"event_category"`
	Severity          string                 `json:"severity" db:"severity"`
	UserID            *string                `json:"user_id" db:"user_id"`
	AffectedUserID    *string                `json:"affected_user_id" db:"affected_user_id"`
	SessionID         *string                `json:"session_id" db:"session_id"`
	Title             string                 `json:"title" db:"title"`
	Description       *string                `json:"description" db:"description"`
	Details           map[string]interface{} `json:"details" db:"details"`
	IPAddress         *string                `json:"ip_address" db:"ip_address"`
	UserAgent         *string                `json:"user_agent" db:"user_agent"`
	RequestPath       *string                `json:"request_path" db:"request_path"`
	AutomatedResponse map[string]interface{} `json:"automated_response" db:"automated_response"`
	Resolved          bool                   `json:"resolved" db:"resolved"`
	ResolvedBy        *string                `json:"resolved_by" db:"resolved_by"`
	ResolvedAt        *time.Time             `json:"resolved_at" db:"resolved_at"`
	ResolutionNotes   *string                `json:"resolution_notes" db:"resolution_notes"`
	FalsePositive     bool                   `json:"false_positive" db:"false_positive"`
	CreatedAt         time.Time              `json:"created_at" db:"created_at"`

	// Joined fields
	User           *User `json:"user,omitempty" db:"-"`
	AffectedUser   *User `json:"affected_user,omitempty" db:"-"`
	ResolvedByUser *User `json:"resolved_by_user,omitempty" db:"-"`
}

// CreateAdminUserRequest represents a request to create a new admin user
type CreateAdminUserRequest struct {
	Email     *string                `json:"email" validate:"omitempty,email"`
	Phone     *string                `json:"phone" validate:"omitempty,e164"`
	Username  *string                `json:"username" validate:"omitempty,min=3,max=100"`
	Password  string                 `json:"password" validate:"required,min=8"`
	RoleName  string                 `json:"role_name" validate:"required,oneof=system_admin super_admin admin moderator"`
	Metadata  map[string]interface{} `json:"metadata,omitempty"`
	EnableMFA bool                   `json:"enable_mfa" validate:"omitempty"`
}

// AdminUserFilter represents filters for querying admin users
type AdminUserFilter struct {
	RoleName      *string `json:"role_name"`
	RoleLevel     *int    `json:"role_level"`
	IsActive      *bool   `json:"is_active"`
	MFAEnabled    *bool   `json:"mfa_enabled"`
	EmailVerified *bool   `json:"email_verified"`
	Limit         int     `json:"limit"`
	Offset        int     `json:"offset"`
}

// MFASetupRequest represents a request to setup MFA
type MFASetupRequest struct {
	Method string `json:"method" validate:"required,oneof=totp sms email"`
	Code   string `json:"code" validate:"required,len=6"`
}

// MFAVerifyRequest represents a request to verify MFA
type MFAVerifyRequest struct {
	Code string `json:"code" validate:"required"`
	Type string `json:"type" validate:"required,oneof=totp backup_code recovery_code"`
}

// LoginWithMFARequest represents a login request with MFA
type LoginWithMFARequest struct {
	LoginRequest
	MFACode           string `json:"mfa_code" validate:"required"`
	TrustDevice       bool   `json:"trust_device"`
	DeviceFingerprint string `json:"device_fingerprint"`
}

// AuthResponseWithMFA extends AuthResponse with MFA information
type AuthResponseWithMFA struct {
	AuthResponse
	RequiresMFA      bool `json:"requires_mfa"`
	MFAEnabled       bool `json:"mfa_enabled"`
	MFASetupRequired bool `json:"mfa_setup_required"`
	BackupCodesCount int  `json:"backup_codes_count"`
	TrustedDevice    bool `json:"trusted_device"`
}

// TableSecurityConfig represents security configuration for a table
type TableSecurityConfig struct {
	ID              string                 `json:"id" db:"id"`
	TableName       string                 `json:"table_name" db:"table_name"`
	SchemaName      string                 `json:"schema_name" db:"schema_name"`
	AuthRequired    bool                   `json:"auth_required" db:"auth_required"`
	OwnershipColumn *string                `json:"ownership_column" db:"ownership_column"`
	AllowedRoles    []string               `json:"allowed_roles" db:"allowed_roles"`
	APIPermissions  map[string]interface{} `json:"api_permissions" db:"api_permissions"`
	CustomFilters   map[string]interface{} `json:"custom_filters" db:"custom_filters"`
	RateLimitConfig map[string]interface{} `json:"rate_limit_config" db:"rate_limit_config"`
	IsActive        bool                   `json:"is_active" db:"is_active"`
	CreatedAt       time.Time              `json:"created_at" db:"created_at"`
	UpdatedAt       time.Time              `json:"updated_at" db:"updated_at"`
}

package template

import (
	"time"
)

// TemplateType represents the type of template
type TemplateType string

const (
	TemplateTypeEmail TemplateType = "email"
	TemplateTypeSMS   TemplateType = "sms"
)

// TemplatePurpose represents the purpose of the template
type TemplatePurpose string

const (
	PurposeLogin          TemplatePurpose = "login"
	PurposeRegistration   TemplatePurpose = "registration"
	PurposeVerification   TemplatePurpose = "verification"
	PurposePasswordReset  TemplatePurpose = "password_reset"
	PurposeMFASetup       TemplatePurpose = "mfa_setup"
	PurposeAccountLockout TemplatePurpose = "account_lockout"
	PurposeWelcome        TemplatePurpose = "welcome"
	PurposeSecurityAlert  TemplatePurpose = "security_alert"
)

// Template represents a communication template
type Template struct {
	ID        string                 `json:"id" db:"id"`
	Type      TemplateType           `json:"type" db:"type"`
	Purpose   TemplatePurpose        `json:"purpose" db:"purpose"`
	Language  string                 `json:"language" db:"language"`
	Version   int                    `json:"version" db:"version"`
	Subject   *string                `json:"subject" db:"subject"` // For email templates
	Content   string                 `json:"content" db:"content"`
	Variables []TemplateVariable     `json:"variables" db:"variables"`
	IsDefault bool                   `json:"is_default" db:"is_default"`
	IsActive  bool                   `json:"is_active" db:"is_active"`
	CreatedBy string                 `json:"created_by" db:"created_by"`
	CreatedAt time.Time              `json:"created_at" db:"created_at"`
	UpdatedBy string                 `json:"updated_by" db:"updated_by"`
	UpdatedAt time.Time              `json:"updated_at" db:"updated_at"`
	Metadata  map[string]interface{} `json:"metadata" db:"metadata"`
}

// TemplateVariable represents available variables for templates
type TemplateVariable struct {
	Name        string      `json:"name"`
	Description string      `json:"description"`
	Type        string      `json:"type"` // string, number, date, boolean
	Required    bool        `json:"required"`
	Example     interface{} `json:"example"`
}

// TemplateVersion represents a version of a template
type TemplateVersion struct {
	ID         string             `json:"id" db:"id"`
	TemplateID string             `json:"template_id" db:"template_id"`
	Version    int                `json:"version" db:"version"`
	Subject    *string            `json:"subject" db:"subject"`
	Content    string             `json:"content" db:"content"`
	Variables  []TemplateVariable `json:"variables" db:"variables"`
	CreatedBy  string             `json:"created_by" db:"created_by"`
	CreatedAt  time.Time          `json:"created_at" db:"created_at"`
	ChangeLog  string             `json:"change_log" db:"change_log"`
}

// TemplateRequest represents a request to create or update a template
type TemplateRequest struct {
	Type      TemplateType           `json:"type" validate:"required,oneof=email sms"`
	Purpose   TemplatePurpose        `json:"purpose" validate:"required"`
	Language  string                 `json:"language" validate:"required,min=2,max=5"`
	Subject   *string                `json:"subject"`
	Content   string                 `json:"content" validate:"required"`
	Variables []TemplateVariable     `json:"variables"`
	IsDefault bool                   `json:"is_default"`
	IsActive  bool                   `json:"is_active"`
	Metadata  map[string]interface{} `json:"metadata"`
}

// TemplateUpdateRequest represents a request to update a template
type TemplateUpdateRequest struct {
	Subject   *string                `json:"subject"`
	Content   *string                `json:"content"`
	Variables []TemplateVariable     `json:"variables"`
	IsActive  *bool                  `json:"is_active"`
	Metadata  map[string]interface{} `json:"metadata"`
	ChangeLog string                 `json:"change_log"`
}

// TemplateFilter represents filters for template queries
type TemplateFilter struct {
	Type      *TemplateType    `json:"type"`
	Purpose   *TemplatePurpose `json:"purpose"`
	Language  *string          `json:"language"`
	IsDefault *bool            `json:"is_default"`
	IsActive  *bool            `json:"is_active"`
	CreatedBy *string          `json:"created_by"`
	Limit     int              `json:"limit"`
	Offset    int              `json:"offset"`
}

// RenderRequest represents a request to render a template
type RenderRequest struct {
	TemplateID string                 `json:"template_id" validate:"required"`
	Variables  map[string]interface{} `json:"variables" validate:"required"`
}

// RenderResult represents the result of template rendering
type RenderResult struct {
	Subject    *string                `json:"subject"`
	Content    string                 `json:"content"`
	RenderedAt time.Time              `json:"rendered_at"`
	TemplateID string                 `json:"template_id"`
	Variables  map[string]interface{} `json:"variables"`
}

// PreviewRequest represents a request to preview a template
type PreviewRequest struct {
	Type      TemplateType           `json:"type" validate:"required"`
	Purpose   TemplatePurpose        `json:"purpose" validate:"required"`
	Language  string                 `json:"language" validate:"required"`
	Subject   *string                `json:"subject"`
	Content   string                 `json:"content" validate:"required"`
	Variables map[string]interface{} `json:"variables"`
}

// ValidationResult represents template validation results
type ValidationResult struct {
	Valid        bool     `json:"valid"`
	Errors       []string `json:"errors"`
	Warnings     []string `json:"warnings"`
	MissingVars  []string `json:"missing_variables"`
	UnknownVars  []string `json:"unknown_variables"`
	RequiredVars []string `json:"required_variables"`
}

// TemplateStats represents template usage statistics
type TemplateStats struct {
	TemplateID   string     `json:"template_id"`
	UsageCount   int64      `json:"usage_count"`
	LastUsed     *time.Time `json:"last_used"`
	SuccessRate  float64    `json:"success_rate"`
	FailureCount int64      `json:"failure_count"`
}

// GetAvailableVariables returns available variables for a specific purpose
func GetAvailableVariables(purpose TemplatePurpose) []TemplateVariable {
	baseVars := []TemplateVariable{
		{
			Name:        "user_name",
			Description: "User's display name or username",
			Type:        "string",
			Required:    false,
			Example:     "John Doe",
		},
		{
			Name:        "user_email",
			Description: "User's email address",
			Type:        "string",
			Required:    false,
			Example:     "john.doe@example.com",
		},
		{
			Name:        "app_name",
			Description: "Application name",
			Type:        "string",
			Required:    false,
			Example:     "Go Forward Framework",
		},
		{
			Name:        "app_url",
			Description: "Application URL",
			Type:        "string",
			Required:    false,
			Example:     "https://app.example.com",
		},
		{
			Name:        "timestamp",
			Description: "Current timestamp",
			Type:        "date",
			Required:    false,
			Example:     time.Now(),
		},
	}

	switch purpose {
	case PurposeLogin, PurposeRegistration, PurposeVerification:
		return append(baseVars, []TemplateVariable{
			{
				Name:        "otp_code",
				Description: "One-time password code",
				Type:        "string",
				Required:    true,
				Example:     "123456",
			},
			{
				Name:        "expiry_minutes",
				Description: "OTP expiry time in minutes",
				Type:        "number",
				Required:    false,
				Example:     10,
			},
		}...)

	case PurposePasswordReset:
		return append(baseVars, []TemplateVariable{
			{
				Name:        "reset_token",
				Description: "Password reset token",
				Type:        "string",
				Required:    true,
				Example:     "abc123def456",
			},
			{
				Name:        "reset_url",
				Description: "Password reset URL",
				Type:        "string",
				Required:    true,
				Example:     "https://app.example.com/reset?token=abc123",
			},
			{
				Name:        "expiry_hours",
				Description: "Reset token expiry time in hours",
				Type:        "number",
				Required:    false,
				Example:     24,
			},
		}...)

	case PurposeMFASetup:
		return append(baseVars, []TemplateVariable{
			{
				Name:        "qr_code_url",
				Description: "QR code URL for MFA setup",
				Type:        "string",
				Required:    false,
				Example:     "https://app.example.com/qr/abc123",
			},
			{
				Name:        "backup_codes",
				Description: "MFA backup codes",
				Type:        "string",
				Required:    false,
				Example:     "12345678, 87654321",
			},
		}...)

	case PurposeAccountLockout:
		return append(baseVars, []TemplateVariable{
			{
				Name:        "lockout_reason",
				Description: "Reason for account lockout",
				Type:        "string",
				Required:    true,
				Example:     "Too many failed login attempts",
			},
			{
				Name:        "unlock_time",
				Description: "When the account will be unlocked",
				Type:        "date",
				Required:    false,
				Example:     time.Now().Add(15 * time.Minute),
			},
		}...)

	case PurposeSecurityAlert:
		return append(baseVars, []TemplateVariable{
			{
				Name:        "alert_type",
				Description: "Type of security alert",
				Type:        "string",
				Required:    true,
				Example:     "Suspicious login attempt",
			},
			{
				Name:        "ip_address",
				Description: "IP address of the security event",
				Type:        "string",
				Required:    false,
				Example:     "192.168.1.1",
			},
			{
				Name:        "location",
				Description: "Geographic location of the event",
				Type:        "string",
				Required:    false,
				Example:     "New York, USA",
			},
		}...)

	default:
		return baseVars
	}
}

// GetDefaultTemplate returns the default template content for a purpose and type
func GetDefaultTemplate(templateType TemplateType, purpose TemplatePurpose) (subject *string, content string) {
	switch templateType {
	case TemplateTypeEmail:
		return getDefaultEmailTemplate(purpose)
	case TemplateTypeSMS:
		return getDefaultSMSTemplate(purpose)
	default:
		return nil, ""
	}
}

func getDefaultEmailTemplate(purpose TemplatePurpose) (subject *string, content string) {
	switch purpose {
	case PurposeLogin:
		subj := "Login Verification Code - {{app_name}}"
		content := `Hello {{user_name}},

Your login verification code is: {{otp_code}}

This code will expire in {{expiry_minutes}} minutes.

If you didn't request this code, please ignore this email.

Best regards,
{{app_name}} Team`
		return &subj, content

	case PurposeRegistration:
		subj := "Welcome to {{app_name}} - Verify Your Account"
		content := `Welcome {{user_name}},

Thank you for registering with {{app_name}}!

Your verification code is: {{otp_code}}

This code will expire in {{expiry_minutes}} minutes.

Best regards,
{{app_name}} Team`
		return &subj, content

	case PurposePasswordReset:
		subj := "Password Reset Request - {{app_name}}"
		content := `Hello {{user_name}},

You requested a password reset for your account.

Click the link below to reset your password:
{{reset_url}}

This link will expire in {{expiry_hours}} hours.

If you didn't request this reset, please ignore this email.

Best regards,
{{app_name}} Team`
		return &subj, content

	default:
		subj := "Notification from {{app_name}}"
		content := `Hello {{user_name}},

This is a notification from {{app_name}}.

Best regards,
{{app_name}} Team`
		return &subj, content
	}
}

func getDefaultSMSTemplate(purpose TemplatePurpose) (subject *string, content string) {
	switch purpose {
	case PurposeLogin, PurposeRegistration, PurposeVerification:
		return nil, "Your {{app_name}} verification code is: {{otp_code}}. Valid for {{expiry_minutes}} minutes."

	case PurposePasswordReset:
		return nil, "{{app_name}}: Reset your password using this link: {{reset_url}} (expires in {{expiry_hours}}h)"

	case PurposeSecurityAlert:
		return nil, "{{app_name}} Security Alert: {{alert_type}} from {{ip_address}}. If this wasn't you, secure your account immediately."

	default:
		return nil, "{{app_name}}: You have a new notification."
	}
}

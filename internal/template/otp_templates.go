package template

import (
	"context"
	"fmt"

	"github.com/taqiudeen275/go-foward/pkg/errors"
)

// CreateDefaultOTPTemplates creates default OTP templates for email and SMS
func (s *Service) CreateDefaultOTPTemplates(ctx context.Context) error {
	templates := []struct {
		templateType TemplateType
		purpose      TemplatePurpose
		language     string
		subject      *string
		content      string
	}{
		// Email templates
		{
			templateType: TemplateTypeEmail,
			purpose:      PurposeLogin,
			language:     "en",
			subject:      stringPointer("Login Verification Code - {{app_name}}"),
			content: `Hello {{user_name}},

Your login verification code is: {{otp_code}}

This code will expire in {{expiry_minutes}} minutes.

If you didn't request this code, please ignore this email.

Best regards,
{{app_name}} Team`,
		},
		{
			templateType: TemplateTypeEmail,
			purpose:      PurposeRegistration,
			language:     "en",
			subject:      stringPointer("Welcome to {{app_name}} - Verify Your Account"),
			content: `Welcome {{user_name}},

Thank you for registering with {{app_name}}!

Your verification code is: {{otp_code}}

This code will expire in {{expiry_minutes}} minutes.

Best regards,
{{app_name}} Team`,
		},
		{
			templateType: TemplateTypeEmail,
			purpose:      PurposeVerification,
			language:     "en",
			subject:      stringPointer("Email Verification - {{app_name}}"),
			content: `Hello {{user_name}},

Please verify your email address with the following code: {{otp_code}}

This code will expire in {{expiry_minutes}} minutes.

Best regards,
{{app_name}} Team`,
		},
		{
			templateType: TemplateTypeEmail,
			purpose:      PurposePasswordReset,
			language:     "en",
			subject:      stringPointer("Password Reset Code - {{app_name}}"),
			content: `Hello {{user_name}},

You requested a password reset for your account.

Your password reset code is: {{otp_code}}

This code will expire in {{expiry_minutes}} minutes.

If you didn't request this reset, please ignore this email.

Best regards,
{{app_name}} Team`,
		},

		// SMS templates
		{
			templateType: TemplateTypeSMS,
			purpose:      PurposeLogin,
			language:     "en",
			subject:      nil,
			content:      "Your {{app_name}} login code is: {{otp_code}}. Valid for {{expiry_minutes}} minutes.",
		},
		{
			templateType: TemplateTypeSMS,
			purpose:      PurposeRegistration,
			language:     "en",
			subject:      nil,
			content:      "Welcome to {{app_name}}! Your verification code is: {{otp_code}}. Valid for {{expiry_minutes}} minutes.",
		},
		{
			templateType: TemplateTypeSMS,
			purpose:      PurposeVerification,
			language:     "en",
			subject:      nil,
			content:      "Your {{app_name}} verification code is: {{otp_code}}. Valid for {{expiry_minutes}} minutes.",
		},
		{
			templateType: TemplateTypeSMS,
			purpose:      PurposePasswordReset,
			language:     "en",
			subject:      nil,
			content:      "Your {{app_name}} password reset code is: {{otp_code}}. Valid for {{expiry_minutes}} minutes.",
		},
	}

	for _, tmpl := range templates {
		// Check if template already exists
		existing, err := s.GetTemplateForPurpose(ctx, tmpl.templateType, tmpl.purpose, tmpl.language)
		if err == nil && existing != nil {
			// Template already exists, skip
			continue
		}

		// Create template request
		req := &TemplateRequest{
			Type:      tmpl.templateType,
			Purpose:   tmpl.purpose,
			Language:  tmpl.language,
			Subject:   tmpl.subject,
			Content:   tmpl.content,
			Variables: GetAvailableVariables(tmpl.purpose),
			IsDefault: true,
			IsActive:  true,
			Metadata: map[string]interface{}{
				"auto_generated": true,
				"template_type":  "otp",
			},
		}

		// Create template
		_, err = s.CreateTemplate(ctx, req, "system")
		if err != nil {
			return errors.Wrap(err, fmt.Sprintf("failed to create default %s template for %s", tmpl.templateType, tmpl.purpose))
		}
	}

	return nil
}

// EnsureOTPTemplatesExist ensures that OTP templates exist, creating defaults if needed
func (s *Service) EnsureOTPTemplatesExist(ctx context.Context) error {
	purposes := []TemplatePurpose{
		PurposeLogin,
		PurposeRegistration,
		PurposeVerification,
		PurposePasswordReset,
	}

	types := []TemplateType{
		TemplateTypeEmail,
		TemplateTypeSMS,
	}

	missingTemplates := false

	for _, templateType := range types {
		for _, purpose := range purposes {
			_, err := s.GetTemplateForPurpose(ctx, templateType, purpose, "en")
			if err != nil {
				missingTemplates = true
				break
			}
		}
		if missingTemplates {
			break
		}
	}

	if missingTemplates {
		return s.CreateDefaultOTPTemplates(ctx)
	}

	return nil
}

// GetOTPTemplateVariables returns the standard variables available for OTP templates
func GetOTPTemplateVariables() []TemplateVariable {
	return []TemplateVariable{
		{
			Name:        "otp_code",
			Description: "The OTP verification code",
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
		{
			Name:        "user_name",
			Description: "User's display name or email",
			Type:        "string",
			Required:    false,
			Example:     "john@example.com",
		},
		{
			Name:        "user_email",
			Description: "User's email address",
			Type:        "string",
			Required:    false,
			Example:     "john@example.com",
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
			Example:     "2024-01-15 10:30:00",
		},
	}
}

// ValidateOTPTemplate validates an OTP template
func (s *Service) ValidateOTPTemplate(ctx context.Context, template *Template) *ValidationResult {
	result := s.renderer.ValidateTemplate(template)

	// Additional OTP-specific validations
	if template.Type == TemplateTypeSMS {
		if len(template.Content) > 160 {
			result.Warnings = append(result.Warnings, "SMS content exceeds 160 characters and may be split into multiple messages")
		}
	}

	// Check for required OTP variables
	requiredVars := []string{"otp_code"}
	for _, requiredVar := range requiredVars {
		found := false
		for _, variable := range template.Variables {
			if variable.Name == requiredVar {
				found = true
				break
			}
		}
		if !found {
			result.Errors = append(result.Errors, fmt.Sprintf("Required OTP variable missing: %s", requiredVar))
			result.Valid = false
		}
	}

	return result
}

// Helper function to create string pointer
func stringPointer(s string) *string {
	return &s
}

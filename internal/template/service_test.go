package template

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/taqiudeen275/go-foward/internal/config"
)

func TestTemplateService(t *testing.T) {
	// This would require a test database setup
	// For now, we'll test the core logic without database

	t.Run("ValidateTemplateRequest", func(t *testing.T) {
		service := &Service{}

		tests := []struct {
			name    string
			req     *TemplateRequest
			wantErr bool
		}{
			{
				name: "valid email template",
				req: &TemplateRequest{
					Type:     TemplateTypeEmail,
					Purpose:  PurposeLogin,
					Language: "en",
					Subject:  stringPtr("Test Subject"),
					Content:  "Test content with {{otp_code}}",
					IsActive: true,
				},
				wantErr: false,
			},
			{
				name: "valid SMS template",
				req: &TemplateRequest{
					Type:     TemplateTypeSMS,
					Purpose:  PurposeLogin,
					Language: "en",
					Content:  "Your code: {{otp_code}}",
					IsActive: true,
				},
				wantErr: false,
			},
			{
				name: "missing type",
				req: &TemplateRequest{
					Purpose:  PurposeLogin,
					Language: "en",
					Content:  "Test content",
				},
				wantErr: true,
			},
			{
				name: "missing purpose",
				req: &TemplateRequest{
					Type:     TemplateTypeEmail,
					Language: "en",
					Content:  "Test content",
				},
				wantErr: true,
			},
			{
				name: "missing language",
				req: &TemplateRequest{
					Type:    TemplateTypeEmail,
					Purpose: PurposeLogin,
					Content: "Test content",
				},
				wantErr: true,
			},
			{
				name: "missing content",
				req: &TemplateRequest{
					Type:     TemplateTypeEmail,
					Purpose:  PurposeLogin,
					Language: "en",
				},
				wantErr: true,
			},
			{
				name: "email without subject",
				req: &TemplateRequest{
					Type:     TemplateTypeEmail,
					Purpose:  PurposeLogin,
					Language: "en",
					Content:  "Test content",
				},
				wantErr: true,
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				err := service.validateTemplateRequest(tt.req)
				if tt.wantErr {
					assert.Error(t, err)
				} else {
					assert.NoError(t, err)
				}
			})
		}
	})
}

func TestRenderer(t *testing.T) {
	renderer := NewRenderer()

	t.Run("RenderTemplate", func(t *testing.T) {
		template := &Template{
			ID:      "test-id",
			Type:    TemplateTypeEmail,
			Purpose: PurposeLogin,
			Subject: stringPtr("Login Code - {{app_name}}"),
			Content: "Hello {{user_name}}, your code is {{otp_code}}",
			Variables: []TemplateVariable{
				{Name: "user_name", Required: false},
				{Name: "otp_code", Required: true},
				{Name: "app_name", Required: false},
			},
		}

		variables := map[string]interface{}{
			"user_name": "John Doe",
			"otp_code":  "123456",
			"app_name":  "Test App",
		}

		result, err := renderer.Render(template, variables)
		require.NoError(t, err)

		assert.Equal(t, "Login Code - Test App", *result.Subject)
		assert.Equal(t, "Hello John Doe, your code is 123456", result.Content)
		assert.Equal(t, template.ID, result.TemplateID)
		assert.Equal(t, variables, result.Variables)
	})

	t.Run("RenderTemplate_MissingRequiredVariable", func(t *testing.T) {
		template := &Template{
			Type:    TemplateTypeEmail,
			Purpose: PurposeLogin,
			Content: "Your code is {{otp_code}}",
			Variables: []TemplateVariable{
				{Name: "otp_code", Required: true},
			},
		}

		variables := map[string]interface{}{
			"user_name": "John Doe",
		}

		_, err := renderer.Render(template, variables)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "Required variable missing: otp_code")
	})

	t.Run("ValidateTemplate", func(t *testing.T) {
		tests := []struct {
			name     string
			template *Template
			wantErr  bool
		}{
			{
				name: "valid template",
				template: &Template{
					Type:    TemplateTypeEmail,
					Purpose: PurposeLogin,
					Subject: stringPtr("Test Subject"),
					Content: "Hello {{user_name}}, your code is {{otp_code}}",
				},
				wantErr: false,
			},
			{
				name: "unmatched braces",
				template: &Template{
					Type:    TemplateTypeEmail,
					Purpose: PurposeLogin,
					Subject: stringPtr("Test Subject"),
					Content: "Hello {{user_name}, your code is {{otp_code}}",
				},
				wantErr: true,
			},
			{
				name: "nested braces",
				template: &Template{
					Type:    TemplateTypeEmail,
					Purpose: PurposeLogin,
					Subject: stringPtr("Test Subject"),
					Content: "Hello {{{user_name}}}, your code is {{otp_code}}",
				},
				wantErr: true,
			},
			{
				name: "empty variable",
				template: &Template{
					Type:    TemplateTypeEmail,
					Purpose: PurposeLogin,
					Subject: stringPtr("Test Subject"),
					Content: "Hello {{}}, your code is {{otp_code}}",
				},
				wantErr: true,
			},
			{
				name: "email without subject",
				template: &Template{
					Type:    TemplateTypeEmail,
					Purpose: PurposeLogin,
					Content: "Hello {{user_name}}, your code is {{otp_code}}",
				},
				wantErr: true,
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				result := renderer.ValidateTemplate(tt.template)
				if tt.wantErr {
					assert.False(t, result.Valid)
					assert.NotEmpty(t, result.Errors)
				} else {
					assert.True(t, result.Valid)
					assert.Empty(t, result.Errors)
				}
			})
		}
	})

	t.Run("RenderPreview", func(t *testing.T) {
		req := &PreviewRequest{
			Type:     TemplateTypeEmail,
			Purpose:  PurposeLogin,
			Language: "en",
			Subject:  stringPtr("Login Code - {{app_name}}"),
			Content:  "Hello {{user_name}}, your code is {{otp_code}}",
		}

		result, err := renderer.RenderPreview(req)
		require.NoError(t, err)

		assert.Contains(t, *result.Subject, "Login Code -")
		assert.Contains(t, result.Content, "Hello")
		assert.Contains(t, result.Content, "your code is")
	})

	t.Run("ExtractVariables", func(t *testing.T) {
		text := "Hello {{user_name}}, your code is {{otp_code}} from {{app_name}}"
		variables := renderer.extractVariables(text)

		expected := []string{"user_name", "otp_code", "app_name"}
		assert.Equal(t, expected, variables)
	})

	t.Run("FormatValue", func(t *testing.T) {
		tests := []struct {
			name     string
			value    interface{}
			expected string
		}{
			{"string", "hello", "hello"},
			{"int", 42, "42"},
			{"float", 3.14, "3.14"},
			{"bool_true", true, "true"},
			{"bool_false", false, "false"},
			{"time", time.Date(2023, 1, 1, 12, 0, 0, 0, time.UTC), "2023-01-01 12:00:00"},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				result := renderer.formatValue(tt.value)
				assert.Equal(t, tt.expected, result)
			})
		}
	})
}

func TestGetAvailableVariables(t *testing.T) {
	tests := []struct {
		name     string
		purpose  TemplatePurpose
		expected []string
	}{
		{
			name:     "login purpose",
			purpose:  PurposeLogin,
			expected: []string{"user_name", "user_email", "app_name", "app_url", "timestamp", "otp_code", "expiry_minutes"},
		},
		{
			name:     "password reset purpose",
			purpose:  PurposePasswordReset,
			expected: []string{"user_name", "user_email", "app_name", "app_url", "timestamp", "reset_token", "reset_url", "expiry_hours"},
		},
		{
			name:     "security alert purpose",
			purpose:  PurposeSecurityAlert,
			expected: []string{"user_name", "user_email", "app_name", "app_url", "timestamp", "alert_type", "ip_address", "location"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			variables := GetAvailableVariables(tt.purpose)

			var names []string
			for _, v := range variables {
				names = append(names, v.Name)
			}

			for _, expected := range tt.expected {
				assert.Contains(t, names, expected)
			}
		})
	}
}

func TestGetDefaultTemplate(t *testing.T) {
	tests := []struct {
		name         string
		templateType TemplateType
		purpose      TemplatePurpose
		wantSubject  bool
		wantContent  bool
	}{
		{
			name:         "email login template",
			templateType: TemplateTypeEmail,
			purpose:      PurposeLogin,
			wantSubject:  true,
			wantContent:  true,
		},
		{
			name:         "sms login template",
			templateType: TemplateTypeSMS,
			purpose:      PurposeLogin,
			wantSubject:  false,
			wantContent:  true,
		},
		{
			name:         "email password reset template",
			templateType: TemplateTypeEmail,
			purpose:      PurposePasswordReset,
			wantSubject:  true,
			wantContent:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			subject, content := GetDefaultTemplate(tt.templateType, tt.purpose)

			if tt.wantSubject {
				assert.NotNil(t, subject)
				assert.NotEmpty(t, *subject)
			} else {
				assert.Nil(t, subject)
			}

			if tt.wantContent {
				assert.NotEmpty(t, content)
			}
		})
	}
}

func TestEmailService(t *testing.T) {
	config := &config.EmailConfig{
		Provider:  "smtp",
		SMTPHost:  "localhost",
		SMTPPort:  587,
		SMTPUser:  "test@example.com",
		SMTPPass:  "password",
		FromEmail: "test@example.com",
		FromName:  "Test App",
		EnableTLS: true,
	}

	renderer := NewRenderer()
	service, err := NewEmailService(config, renderer)
	require.NoError(t, err)

	t.Run("ValidateProvider", func(t *testing.T) {
		err := service.ValidateProvider()
		assert.NoError(t, err)
	})

	t.Run("ValidateProvider_MissingConfig", func(t *testing.T) {
		invalidConfig := &config.EmailConfig{
			Provider: "smtp",
		}

		invalidService, err := NewEmailService(invalidConfig, renderer)
		require.NoError(t, err)

		err = invalidService.ValidateProvider()
		assert.Error(t, err)
	})
}

func TestSMSService(t *testing.T) {
	config := &config.SMSConfig{
		Provider: "arkesel",
		APIKey:   "test-api-key",
		From:     "TestApp",
	}

	renderer := NewRenderer()
	service, err := NewSMSService(config, renderer)
	require.NoError(t, err)

	t.Run("ValidateProvider", func(t *testing.T) {
		err := service.ValidateProvider()
		assert.NoError(t, err)
	})

	t.Run("GetProviderInfo", func(t *testing.T) {
		info := service.GetProviderInfo()
		assert.Equal(t, "arkesel", info["provider"])
		assert.True(t, info["api_key_set"].(bool))
	})

	t.Run("ValidateProvider_MissingConfig", func(t *testing.T) {
		invalidConfig := &config.SMSConfig{
			Provider: "arkesel",
		}

		invalidService, err := NewSMSService(invalidConfig, renderer)
		require.NoError(t, err)

		err = invalidService.ValidateProvider()
		assert.Error(t, err)
	})
}

// Helper function to create string pointer
func stringPtr(s string) *string {
	return &s
}

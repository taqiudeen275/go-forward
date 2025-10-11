package template

import (
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/taqiudeen275/go-foward/pkg/errors"
)

// Renderer handles template rendering with variable substitution
type Renderer struct {
	variablePattern *regexp.Regexp
}

// NewRenderer creates a new template renderer
func NewRenderer() *Renderer {
	return &Renderer{
		variablePattern: regexp.MustCompile(`\{\{([^}]+)\}\}`),
	}
}

// Render renders a template with the provided variables
func (r *Renderer) Render(template *Template, variables map[string]interface{}) (*RenderResult, error) {
	// Validate required variables
	if err := r.validateVariables(template, variables); err != nil {
		return nil, err
	}

	// Render content
	renderedContent, err := r.renderText(template.Content, variables)
	if err != nil {
		return nil, errors.NewValidationError(fmt.Sprintf("Failed to render content: %v", err))
	}

	// Render subject if it exists
	var renderedSubject *string
	if template.Subject != nil {
		subject, err := r.renderText(*template.Subject, variables)
		if err != nil {
			return nil, errors.NewValidationError(fmt.Sprintf("Failed to render subject: %v", err))
		}
		renderedSubject = &subject
	}

	return &RenderResult{
		Subject:    renderedSubject,
		Content:    renderedContent,
		RenderedAt: time.Now(),
		TemplateID: template.ID,
		Variables:  variables,
	}, nil
}

// RenderPreview renders a template preview with sample data
func (r *Renderer) RenderPreview(req *PreviewRequest) (*RenderResult, error) {
	// Create a temporary template for rendering
	template := &Template{
		ID:        "preview",
		Type:      req.Type,
		Purpose:   req.Purpose,
		Language:  req.Language,
		Subject:   req.Subject,
		Content:   req.Content,
		Variables: GetAvailableVariables(req.Purpose),
	}

	// Use provided variables or generate sample data
	variables := req.Variables
	if variables == nil {
		variables = r.generateSampleVariables(req.Purpose)
	}

	return r.Render(template, variables)
}

// ValidateTemplate validates a template's syntax and variables
func (r *Renderer) ValidateTemplate(template *Template) *ValidationResult {
	result := &ValidationResult{
		Valid:        true,
		Errors:       []string{},
		Warnings:     []string{},
		MissingVars:  []string{},
		UnknownVars:  []string{},
		RequiredVars: []string{},
	}

	// Get available variables for this purpose
	availableVars := GetAvailableVariables(template.Purpose)
	availableVarMap := make(map[string]TemplateVariable)
	for _, v := range availableVars {
		availableVarMap[v.Name] = v
	}

	// Find all variables used in the template
	usedVars := r.extractVariables(template.Content)
	if template.Subject != nil {
		subjectVars := r.extractVariables(*template.Subject)
		usedVars = append(usedVars, subjectVars...)
	}

	// Remove duplicates
	usedVarMap := make(map[string]bool)
	for _, v := range usedVars {
		usedVarMap[v] = true
	}

	// Check for unknown variables
	for varName := range usedVarMap {
		if _, exists := availableVarMap[varName]; !exists {
			result.UnknownVars = append(result.UnknownVars, varName)
			result.Warnings = append(result.Warnings, fmt.Sprintf("Unknown variable: %s", varName))
		}
	}

	// Check for required variables
	for _, availableVar := range availableVars {
		if availableVar.Required {
			result.RequiredVars = append(result.RequiredVars, availableVar.Name)
			if _, used := usedVarMap[availableVar.Name]; !used {
				result.MissingVars = append(result.MissingVars, availableVar.Name)
				result.Errors = append(result.Errors, fmt.Sprintf("Required variable missing: %s", availableVar.Name))
				result.Valid = false
			}
		}
	}

	// Validate template syntax
	if err := r.validateSyntax(template.Content); err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("Content syntax error: %v", err))
		result.Valid = false
	}

	if template.Subject != nil {
		if err := r.validateSyntax(*template.Subject); err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("Subject syntax error: %v", err))
			result.Valid = false
		}
	}

	// Type-specific validations
	switch template.Type {
	case TemplateTypeEmail:
		if template.Subject == nil || strings.TrimSpace(*template.Subject) == "" {
			result.Errors = append(result.Errors, "Email templates must have a subject")
			result.Valid = false
		}
	case TemplateTypeSMS:
		if len(template.Content) > 160 {
			result.Warnings = append(result.Warnings, "SMS content exceeds 160 characters and may be split into multiple messages")
		}
	}

	return result
}

// renderText renders text with variable substitution
func (r *Renderer) renderText(text string, variables map[string]interface{}) (string, error) {
	return r.variablePattern.ReplaceAllStringFunc(text, func(match string) string {
		// Extract variable name (remove {{ and }})
		varName := strings.TrimSpace(match[2 : len(match)-2])

		if value, exists := variables[varName]; exists {
			return r.formatValue(value)
		}

		// Return original if variable not found (will be caught in validation)
		return match
	}), nil
}

// validateVariables validates that all required variables are provided
func (r *Renderer) validateVariables(template *Template, variables map[string]interface{}) error {
	availableVars := GetAvailableVariables(template.Purpose)

	for _, availableVar := range availableVars {
		if availableVar.Required {
			if _, exists := variables[availableVar.Name]; !exists {
				return errors.NewValidationError(fmt.Sprintf("Required variable missing: %s", availableVar.Name))
			}
		}
	}

	return nil
}

// validateSyntax validates template syntax
func (r *Renderer) validateSyntax(text string) error {
	// Check for unmatched braces
	openCount := strings.Count(text, "{{")
	closeCount := strings.Count(text, "}}")

	if openCount != closeCount {
		return errors.NewValidationError("Unmatched template braces")
	}

	// Check for nested braces
	if strings.Contains(text, "{{{") || strings.Contains(text, "}}}") {
		return errors.NewValidationError("Nested template braces are not allowed")
	}

	// Check for empty variables
	if strings.Contains(text, "{{}}") || strings.Contains(text, "{{ }}") {
		return errors.NewValidationError("Empty variable placeholders are not allowed")
	}

	return nil
}

// extractVariables extracts all variable names from text
func (r *Renderer) extractVariables(text string) []string {
	matches := r.variablePattern.FindAllStringSubmatch(text, -1)
	var variables []string

	for _, match := range matches {
		if len(match) > 1 {
			varName := strings.TrimSpace(match[1])
			variables = append(variables, varName)
		}
	}

	return variables
}

// formatValue formats a variable value for display
func (r *Renderer) formatValue(value interface{}) string {
	switch v := value.(type) {
	case string:
		return v
	case int, int32, int64:
		return fmt.Sprintf("%d", v)
	case float32, float64:
		return fmt.Sprintf("%.2f", v)
	case bool:
		if v {
			return "true"
		}
		return "false"
	case time.Time:
		return v.Format("2006-01-02 15:04:05")
	case *time.Time:
		if v != nil {
			return v.Format("2006-01-02 15:04:05")
		}
		return ""
	default:
		return fmt.Sprintf("%v", v)
	}
}

// generateSampleVariables generates sample variables for preview
func (r *Renderer) generateSampleVariables(purpose TemplatePurpose) map[string]interface{} {
	variables := map[string]interface{}{
		"user_name":  "John Doe",
		"user_email": "john.doe@example.com",
		"app_name":   "Go Forward Framework",
		"app_url":    "https://app.example.com",
		"timestamp":  time.Now(),
	}

	switch purpose {
	case PurposeLogin, PurposeRegistration, PurposeVerification:
		variables["otp_code"] = "123456"
		variables["expiry_minutes"] = 10

	case PurposePasswordReset:
		variables["reset_token"] = "abc123def456ghi789"
		variables["reset_url"] = "https://app.example.com/reset?token=abc123def456ghi789"
		variables["expiry_hours"] = 24

	case PurposeMFASetup:
		variables["qr_code_url"] = "https://app.example.com/qr/abc123"
		variables["backup_codes"] = "12345678, 87654321, 11223344, 55667788"

	case PurposeAccountLockout:
		variables["lockout_reason"] = "Too many failed login attempts"
		variables["unlock_time"] = time.Now().Add(15 * time.Minute)

	case PurposeSecurityAlert:
		variables["alert_type"] = "Suspicious login attempt"
		variables["ip_address"] = "192.168.1.100"
		variables["location"] = "New York, USA"
	}

	return variables
}

// GetVariableHelp returns help text for template variables
func (r *Renderer) GetVariableHelp(purpose TemplatePurpose) string {
	variables := GetAvailableVariables(purpose)

	var help strings.Builder
	help.WriteString("Available variables for this template:\n\n")

	for _, v := range variables {
		help.WriteString(fmt.Sprintf("{{%s}} - %s", v.Name, v.Description))
		if v.Required {
			help.WriteString(" (Required)")
		}
		help.WriteString(fmt.Sprintf("\n  Type: %s, Example: %v\n\n", v.Type, v.Example))
	}

	return help.String()
}

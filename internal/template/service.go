package template

import (
	"context"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/taqiudeen275/go-foward/internal/config"
	"github.com/taqiudeen275/go-foward/pkg/errors"
)

// Service provides template management functionality
type Service struct {
	repo         *Repository
	renderer     *Renderer
	emailService *EmailService
	smsService   *SMSService
	config       *config.Config
}

// NewService creates a new template service
func NewService(db *pgxpool.Pool, cfg *config.Config) (*Service, error) {
	repo := NewRepository(db)
	renderer := NewRenderer()

	// Initialize email service
	emailService, err := NewEmailService(&cfg.Email, renderer)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize email service: %w", err)
	}

	// Initialize SMS service
	smsService, err := NewSMSService(&cfg.SMS, renderer)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize SMS service: %w", err)
	}

	return &Service{
		repo:         repo,
		renderer:     renderer,
		emailService: emailService,
		smsService:   smsService,
		config:       cfg,
	}, nil
}

// CreateTemplate creates a new template
func (s *Service) CreateTemplate(ctx context.Context, req *TemplateRequest, createdBy string) (*Template, error) {
	// Validate request
	if err := s.validateTemplateRequest(req); err != nil {
		return nil, err
	}

	// Create template
	template := &Template{
		Type:      req.Type,
		Purpose:   req.Purpose,
		Language:  strings.ToLower(req.Language),
		Subject:   req.Subject,
		Content:   req.Content,
		Variables: req.Variables,
		IsDefault: req.IsDefault,
		IsActive:  req.IsActive,
		CreatedBy: createdBy,
		UpdatedBy: createdBy,
		Metadata:  req.Metadata,
	}

	// If no variables provided, use default ones
	if len(template.Variables) == 0 {
		template.Variables = GetAvailableVariables(template.Purpose)
	}

	// Validate template
	validation := s.renderer.ValidateTemplate(template)
	if !validation.Valid {
		return nil, errors.NewValidationError(fmt.Sprintf("Template validation failed: %s", strings.Join(validation.Errors, ", ")))
	}

	// If this is set as default, unset other defaults
	if template.IsDefault {
		if err := s.unsetDefaultTemplates(ctx, template.Type, template.Purpose, template.Language); err != nil {
			return nil, err
		}
	}

	// Create template
	if err := s.repo.Create(ctx, template); err != nil {
		return nil, err
	}

	return template, nil
}

// GetTemplate retrieves a template by ID
func (s *Service) GetTemplate(ctx context.Context, id string) (*Template, error) {
	return s.repo.GetByID(ctx, id)
}

// GetTemplateForPurpose retrieves the best template for a specific purpose
func (s *Service) GetTemplateForPurpose(ctx context.Context, templateType TemplateType, purpose TemplatePurpose, language string) (*Template, error) {
	if language == "" {
		language = "en"
	}

	template, err := s.repo.GetByTypeAndPurpose(ctx, templateType, purpose, strings.ToLower(language))
	if err != nil {
		// If no template found, create a default one
		if errors.IsNotFoundError(err) {
			return s.createDefaultTemplate(ctx, templateType, purpose, language)
		}
		return nil, err
	}

	return template, nil
}

// ListTemplates lists templates with filtering
func (s *Service) ListTemplates(ctx context.Context, filter *TemplateFilter) ([]*Template, error) {
	if filter.Language != nil {
		lang := strings.ToLower(*filter.Language)
		filter.Language = &lang
	}

	return s.repo.List(ctx, filter)
}

// UpdateTemplate updates an existing template
func (s *Service) UpdateTemplate(ctx context.Context, id string, req *TemplateUpdateRequest, updatedBy string) (*Template, error) {
	// Get existing template
	existing, err := s.repo.GetByID(ctx, id)
	if err != nil {
		return nil, err
	}

	// Create a copy for validation
	testTemplate := *existing
	if req.Subject != nil {
		testTemplate.Subject = req.Subject
	}
	if req.Content != nil {
		testTemplate.Content = *req.Content
	}
	if req.Variables != nil {
		testTemplate.Variables = req.Variables
	}

	// Validate updated template
	validation := s.renderer.ValidateTemplate(&testTemplate)
	if !validation.Valid {
		return nil, errors.NewValidationError(fmt.Sprintf("Template validation failed: %s", strings.Join(validation.Errors, ", ")))
	}

	// Update template
	return s.repo.Update(ctx, id, req, updatedBy)
}

// DeleteTemplate deletes a template
func (s *Service) DeleteTemplate(ctx context.Context, id string) error {
	return s.repo.Delete(ctx, id)
}

// RenderTemplate renders a template with variables
func (s *Service) RenderTemplate(ctx context.Context, req *RenderRequest) (*RenderResult, error) {
	template, err := s.repo.GetByID(ctx, req.TemplateID)
	if err != nil {
		return nil, err
	}

	result, err := s.renderer.Render(template, req.Variables)
	if err != nil {
		return nil, err
	}

	// Record usage
	s.repo.RecordUsage(ctx, req.TemplateID, true)

	return result, nil
}

// PreviewTemplate previews a template with sample data
func (s *Service) PreviewTemplate(ctx context.Context, req *PreviewRequest) (*RenderResult, error) {
	return s.renderer.RenderPreview(req)
}

// ValidateTemplate validates a template
func (s *Service) ValidateTemplate(ctx context.Context, template *Template) *ValidationResult {
	return s.renderer.ValidateTemplate(template)
}

// GetTemplateVersions retrieves all versions of a template
func (s *Service) GetTemplateVersions(ctx context.Context, templateID string) ([]*TemplateVersion, error) {
	return s.repo.GetVersions(ctx, templateID)
}

// GetTemplateVersion retrieves a specific version of a template
func (s *Service) GetTemplateVersion(ctx context.Context, templateID string, version int) (*TemplateVersion, error) {
	return s.repo.GetVersion(ctx, templateID, version)
}

// GetTemplateStats retrieves template usage statistics
func (s *Service) GetTemplateStats(ctx context.Context, templateID string) (*TemplateStats, error) {
	return s.repo.GetStats(ctx, templateID)
}

// SendEmail sends an email using a template
func (s *Service) SendEmail(ctx context.Context, templateType TemplateType, purpose TemplatePurpose, language string, variables map[string]interface{}, to []string) error {
	template, err := s.GetTemplateForPurpose(ctx, templateType, purpose, language)
	if err != nil {
		return err
	}

	err = s.emailService.SendTemplatedEmail(ctx, template, variables, to)
	if err != nil {
		s.repo.RecordUsage(ctx, template.ID, false)
		return err
	}

	s.repo.RecordUsage(ctx, template.ID, true)
	return nil
}

// SendSMS sends an SMS using a template
func (s *Service) SendSMS(ctx context.Context, purpose TemplatePurpose, language string, variables map[string]interface{}, to string) error {
	template, err := s.GetTemplateForPurpose(ctx, TemplateTypeSMS, purpose, language)
	if err != nil {
		return err
	}

	err = s.smsService.SendTemplatedSMS(ctx, template, variables, to)
	if err != nil {
		s.repo.RecordUsage(ctx, template.ID, false)
		return err
	}

	s.repo.RecordUsage(ctx, template.ID, true)
	return nil
}

// GetAvailableVariables returns available variables for a purpose
func (s *Service) GetAvailableVariables(purpose TemplatePurpose) []TemplateVariable {
	return GetAvailableVariables(purpose)
}

// GetVariableHelp returns help text for template variables
func (s *Service) GetVariableHelp(purpose TemplatePurpose) string {
	return s.renderer.GetVariableHelp(purpose)
}

// ValidateProviders validates email and SMS provider configurations
func (s *Service) ValidateProviders() map[string]error {
	results := make(map[string]error)

	if err := s.emailService.ValidateProvider(); err != nil {
		results["email"] = err
	}

	if err := s.smsService.ValidateProvider(); err != nil {
		results["sms"] = err
	}

	return results
}

// GetProviderInfo returns information about configured providers
func (s *Service) GetProviderInfo() map[string]interface{} {
	return map[string]interface{}{
		"email": map[string]interface{}{
			"provider": s.config.Email.Provider,
			"from":     s.config.Email.FromEmail,
		},
		"sms": s.smsService.GetProviderInfo(),
	}
}

// validateTemplateRequest validates a template creation request
func (s *Service) validateTemplateRequest(req *TemplateRequest) error {
	if req.Type == "" {
		return errors.NewValidationError("Template type is required")
	}

	if req.Purpose == "" {
		return errors.NewValidationError("Template purpose is required")
	}

	if req.Language == "" {
		return errors.NewValidationError("Template language is required")
	}

	if req.Content == "" {
		return errors.NewValidationError("Template content is required")
	}

	// Email templates must have a subject
	if req.Type == TemplateTypeEmail && (req.Subject == nil || strings.TrimSpace(*req.Subject) == "") {
		return errors.NewValidationError("Email templates must have a subject")
	}

	return nil
}

// unsetDefaultTemplates unsets other default templates of the same type/purpose/language
func (s *Service) unsetDefaultTemplates(ctx context.Context, templateType TemplateType, purpose TemplatePurpose, language string) error {
	// This would require a repository method to update default flags
	// For now, we'll implement it as a simple query
	query := `
		UPDATE templates 
		SET is_default = false, updated_at = NOW()
		WHERE type = $1 AND purpose = $2 AND language = $3 AND is_default = true`

	_, err := s.repo.db.Exec(ctx, query, templateType, purpose, language)
	if err != nil {
		return errors.NewDatabaseError(fmt.Sprintf("Failed to unset default templates: %v", err))
	}

	return nil
}

// createDefaultTemplate creates a default template if none exists
func (s *Service) createDefaultTemplate(ctx context.Context, templateType TemplateType, purpose TemplatePurpose, language string) (*Template, error) {
	subject, content := GetDefaultTemplate(templateType, purpose)

	template := &Template{
		Type:      templateType,
		Purpose:   purpose,
		Language:  strings.ToLower(language),
		Subject:   subject,
		Content:   content,
		Variables: GetAvailableVariables(purpose),
		IsDefault: true,
		IsActive:  true,
		CreatedBy: "system",
		UpdatedBy: "system",
		Metadata:  map[string]interface{}{"auto_generated": true},
	}

	if err := s.repo.Create(ctx, template); err != nil {
		return nil, err
	}

	return template, nil
}

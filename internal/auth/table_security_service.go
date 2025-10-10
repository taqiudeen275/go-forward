package auth

import (
	"fmt"
	"time"
)

// TableSecurityService handles business logic for table security configurations
type TableSecurityService struct {
	repo         *TableSecurityRepository
	auditService AuditService
}

// AuditService interface for audit logging
type AuditService interface {
	LogAdminAction(userID, action, resource string, details map[string]interface{}) error
}

// NewTableSecurityService creates a new table security service
func NewTableSecurityService(repo *TableSecurityRepository, auditService AuditService) *TableSecurityService {
	return &TableSecurityService{
		repo:         repo,
		auditService: auditService,
	}
}

// CreateTableSecurityConfig creates a new table security configuration
func (s *TableSecurityService) CreateTableSecurityConfig(req *CreateTableSecurityConfigRequest, createdBy string) (*TableSecurityConfig, error) {
	// Create config from request
	config := &TableSecurityConfig{
		TableName:   req.TableName,
		SchemaName:  req.SchemaName,
		DisplayName: getStringValue(req.DisplayName),
		Description: getStringValue(req.Description),
		CreatedBy:   createdBy,
		IsActive:    true,
	}

	// Set default schema if not provided
	if config.SchemaName == "" {
		config.SchemaName = "public"
	}

	// Apply API security config
	if req.Config != nil {
		config.APIConfig = *req.Config
	} else {
		// Apply default secure configuration
		s.applyDefaultSecureConfig(config)
	}

	// Validate configuration
	validation := s.repo.ValidateTableSecurityConfig(config)
	if !validation.IsValid {
		return nil, fmt.Errorf("configuration validation failed: %v", validation.Errors)
	}

	// Create configuration
	err := s.repo.CreateTableSecurityConfig(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create table security config: %w", err)
	}

	// Log audit event
	s.auditService.LogAdminAction(createdBy, "CREATE_TABLE_CONFIG",
		fmt.Sprintf("%s.%s", config.SchemaName, config.TableName),
		map[string]interface{}{
			"config_id":    config.ID,
			"table_name":   config.TableName,
			"schema_name":  config.SchemaName,
			"require_auth": config.APIConfig.RequireAuth,
		})

	return config, nil
}

// GetTableSecurityConfig retrieves a table security configuration
func (s *TableSecurityService) GetTableSecurityConfig(tableName, schemaName string) (*TableSecurityConfig, error) {
	if schemaName == "" {
		schemaName = "public"
	}

	config, err := s.repo.GetTableSecurityConfig(tableName, schemaName)
	if err != nil {
		return nil, fmt.Errorf("failed to get table security config: %w", err)
	}

	// Generate current config hash for change detection
	_, err = s.repo.GenerateConfigHash(config)
	// Note: ConfigHash field not available in this TableSecurityConfig structure

	return config, nil
}

// UpdateTableSecurityConfig updates an existing table security configuration
func (s *TableSecurityService) UpdateTableSecurityConfig(id string, req *UpdateTableSecurityConfigRequest, updatedBy string) (*TableSecurityConfig, error) {
	// Get existing configuration
	existingConfig, err := s.repo.GetTableSecurityConfigByID(id)
	if err != nil {
		return nil, fmt.Errorf("failed to get existing config: %w", err)
	}

	// Create updated config
	updatedConfig := *existingConfig

	if req.DisplayName != nil {
		updatedConfig.DisplayName = getStringValue(req.DisplayName)
	}

	if req.Description != nil {
		updatedConfig.Description = getStringValue(req.Description)
	}

	if req.Config != nil {
		updatedConfig.APIConfig = *req.Config
	}

	// Note: Version field not available in this TableSecurityConfig structure

	// Validate updated configuration
	validation := s.repo.ValidateTableSecurityConfig(&updatedConfig)
	if !validation.IsValid {
		return nil, fmt.Errorf("configuration validation failed: %v", validation.Errors)
	}

	// Note: Version management not implemented in this simplified version

	// Update configuration
	err = s.repo.UpdateTableSecurityConfig(id, &updatedConfig, updatedBy)
	if err != nil {
		return nil, fmt.Errorf("failed to update table security config: %w", err)
	}

	// Log audit event
	s.auditService.LogAdminAction(updatedBy, "UPDATE_TABLE_CONFIG",
		fmt.Sprintf("%s.%s", updatedConfig.SchemaName, updatedConfig.TableName),
		map[string]interface{}{
			"config_id":      id,
			"change_reason":  req.ChangeReason,
			"create_version": req.CreateVersion,
		})

	// Return updated config
	return s.repo.GetTableSecurityConfigByID(id)
}

// DeleteTableSecurityConfig soft deletes a table security configuration
func (s *TableSecurityService) DeleteTableSecurityConfig(id string, deletedBy string) error {
	// Get config for audit logging
	config, err := s.repo.GetTableSecurityConfigByID(id)
	if err != nil {
		return fmt.Errorf("failed to get config for deletion: %w", err)
	}

	// Delete configuration
	err = s.repo.DeleteTableSecurityConfig(id, deletedBy)
	if err != nil {
		return fmt.Errorf("failed to delete table security config: %w", err)
	}

	// Log audit event
	s.auditService.LogAdminAction(deletedBy, "DELETE_TABLE_CONFIG",
		fmt.Sprintf("%s.%s", config.SchemaName, config.TableName),
		map[string]interface{}{
			"config_id":   id,
			"table_name":  config.TableName,
			"schema_name": config.SchemaName,
		})

	return nil
}

// ListTableSecurityConfigs retrieves table security configurations with filtering
func (s *TableSecurityService) ListTableSecurityConfigs(filter *TableSecurityConfigFilter) ([]*TableSecurityConfig, error) {
	configs, err := s.repo.ListTableSecurityConfigs(filter)
	if err != nil {
		return nil, fmt.Errorf("failed to list table security configs: %w", err)
	}

	// Generate config hashes for change detection (ConfigHash field not available)
	for _, config := range configs {
		_, _ = s.repo.GenerateConfigHash(config)
		// Note: ConfigHash field not available in this TableSecurityConfig structure
	}

	return configs, nil
}

// CreateFromTemplate creates a table security configuration from a template
func (s *TableSecurityService) CreateFromTemplate(templateID, tableName, schemaName string, createdBy string) (*TableSecurityConfig, error) {
	// Get templates to find the specified one
	templates, err := s.repo.GetConfigurationTemplates("")
	if err != nil {
		return nil, fmt.Errorf("failed to get templates: %w", err)
	}

	var selectedTemplate *TableConfigurationTemplate
	for _, template := range templates {
		if template.ID == templateID {
			selectedTemplate = template
			break
		}
	}

	if selectedTemplate == nil {
		return nil, fmt.Errorf("template not found with id %s", templateID)
	}

	// Create configuration from template
	config := *selectedTemplate.Config
	config.ID = "" // Clear ID for new config
	config.TableName = tableName
	config.SchemaName = schemaName
	config.CreatedBy = createdBy
	config.CreatedAt = time.Time{}
	config.UpdatedAt = time.Time{}
	config.IsActive = true

	// Set default schema if not provided
	if config.SchemaName == "" {
		config.SchemaName = "public"
	}

	// Validate configuration
	validation := s.repo.ValidateTableSecurityConfig(&config)
	if !validation.IsValid {
		return nil, fmt.Errorf("template configuration validation failed: %v", validation.Errors)
	}

	// Create configuration
	err = s.repo.CreateTableSecurityConfig(&config)
	if err != nil {
		return nil, fmt.Errorf("failed to create config from template: %w", err)
	}

	// Log audit event
	s.auditService.LogAdminAction(createdBy, "CREATE_TABLE_CONFIG_FROM_TEMPLATE",
		fmt.Sprintf("%s.%s", config.SchemaName, config.TableName),
		map[string]interface{}{
			"config_id":     config.ID,
			"template_id":   templateID,
			"template_name": selectedTemplate.Name,
			"table_name":    config.TableName,
			"schema_name":   config.SchemaName,
		})

	return &config, nil
}

// GetConfigurationTemplates retrieves configuration templates
func (s *TableSecurityService) GetConfigurationTemplates(category string) ([]*TableConfigurationTemplate, error) {
	return s.repo.GetConfigurationTemplates(category)
}

// GetConfigurationVersions retrieves version history for a configuration
func (s *TableSecurityService) GetConfigurationVersions(configID string) ([]*TableConfigurationVersion, error) {
	return s.repo.GetConfigurationVersions(configID)
}

// RollbackToVersion rolls back a configuration to a specific version
func (s *TableSecurityService) RollbackToVersion(configID string, version int, rolledBackBy string) error {
	// Get config for audit logging
	config, err := s.repo.GetTableSecurityConfigByID(configID)
	if err != nil {
		return fmt.Errorf("failed to get config for rollback: %w", err)
	}

	// Perform rollback
	err = s.repo.RollbackToVersion(configID, version, rolledBackBy)
	if err != nil {
		return fmt.Errorf("failed to rollback configuration: %w", err)
	}

	// Log audit event
	s.auditService.LogAdminAction(rolledBackBy, "ROLLBACK_TABLE_CONFIG",
		fmt.Sprintf("%s.%s", config.SchemaName, config.TableName),
		map[string]interface{}{
			"config_id":        configID,
			"rollback_version": version,
		})

	return nil
}

// ValidateTableSecurityConfig validates a table security configuration
func (s *TableSecurityService) ValidateTableSecurityConfig(config *TableSecurityConfig) *ValidationResult {
	return s.repo.ValidateTableSecurityConfig(config)
}

// GetSecurityConfigForTable retrieves the effective security configuration for a table
func (s *TableSecurityService) GetSecurityConfigForTable(tableName, schemaName string) (*APISecurityConfig, error) {
	if schemaName == "" {
		schemaName = "public"
	}

	config, err := s.repo.GetTableSecurityConfig(tableName, schemaName)
	if err != nil {
		// Return default secure configuration if no config exists
		return s.getDefaultSecureAPIConfig(), nil
	}

	return &config.APIConfig, nil
}

// applyDefaultSecureConfig applies a default secure configuration
func (s *TableSecurityService) applyDefaultSecureConfig(config *TableSecurityConfig) {
	config.APIConfig = APISecurityConfig{
		RequireAuth:      true,
		RequireVerified:  true,
		AllowedRoles:     []string{},
		RequireOwnership: false,
		PublicRead:       false,
		PublicWrite:      false,
		RequireMFA:       false,
		IPWhitelist:      []string{},
		RateLimit: &RateLimitConfig{
			RequestsPerMinute: 60,
			RequestsPerHour:   500,
			BurstSize:         5,
		},
		AuditActions:    true,
		ReadableFields:  []string{},
		WritableFields:  []string{},
		HiddenFields:    []string{},
		CustomFilters:   map[string]string{},
		TimeBasedAccess: nil,
	}
}

// getDefaultSecureAPIConfig returns a default secure API configuration
func (s *TableSecurityService) getDefaultSecureAPIConfig() *APISecurityConfig {
	return &APISecurityConfig{
		RequireAuth:      true,
		RequireVerified:  true,
		AllowedRoles:     []string{},
		RequireOwnership: false,
		PublicRead:       false,
		PublicWrite:      false,
		RequireMFA:       false,
		IPWhitelist:      []string{},
		RateLimit: &RateLimitConfig{
			RequestsPerMinute: 60,
			RequestsPerHour:   500,
			BurstSize:         5,
		},
		AuditActions:    true,
		ReadableFields:  []string{},
		WritableFields:  []string{},
		HiddenFields:    []string{},
		CustomFilters:   map[string]string{},
		TimeBasedAccess: nil,
	}
}

// Note: getStringValue is already defined in adapter.go

// hasSignificantChanges checks if the configuration changes are significant enough to require versioning
func (s *TableSecurityService) hasSignificantChanges(old, new *TableSecurityConfig) bool {
	// Security-related changes that should trigger versioning
	securityChanges := []bool{
		old.APIConfig.RequireAuth != new.APIConfig.RequireAuth,
		old.APIConfig.RequireVerified != new.APIConfig.RequireVerified,
		old.APIConfig.RequireOwnership != new.APIConfig.RequireOwnership,
		old.APIConfig.PublicRead != new.APIConfig.PublicRead,
		old.APIConfig.PublicWrite != new.APIConfig.PublicWrite,
		old.APIConfig.RequireMFA != new.APIConfig.RequireMFA,
		old.APIConfig.AuditActions != new.APIConfig.AuditActions,
	}

	for _, changed := range securityChanges {
		if changed {
			return true
		}
	}

	// Check ownership column changes
	if old.APIConfig.OwnershipColumn != new.APIConfig.OwnershipColumn {
		return true
	}

	// Check JSONB field changes (simplified check)
	oldHash, _ := s.repo.GenerateConfigHash(old)
	newHash, _ := s.repo.GenerateConfigHash(new)

	return oldHash != newHash
}

// GetTableSecuritySummary returns a summary of security configurations
func (s *TableSecurityService) GetTableSecuritySummary() (map[string]interface{}, error) {
	// Get all active configurations
	filter := &TableSecurityConfigFilter{
		IsActive: &[]bool{true}[0],
		Limit:    1000, // Reasonable limit for summary
	}

	configs, err := s.ListTableSecurityConfigs(filter)
	if err != nil {
		return nil, fmt.Errorf("failed to get configs for summary: %w", err)
	}

	// Calculate summary statistics
	summary := map[string]interface{}{
		"total_configurations":      len(configs),
		"require_auth_count":        0,
		"require_mfa_count":         0,
		"require_ownership_count":   0,
		"public_read_count":         0,
		"public_write_count":        0,
		"with_rate_limits_count":    0,
		"with_ip_whitelist_count":   0,
		"with_custom_filters_count": 0,
		"tables_by_schema":          make(map[string]int),
		"security_levels":           make(map[string]int),
	}

	schemaCount := make(map[string]int)
	securityLevels := make(map[string]int)

	for _, config := range configs {
		// Count by schema
		schemaCount[config.SchemaName]++

		// Count security features
		if config.APIConfig.RequireAuth {
			summary["require_auth_count"] = summary["require_auth_count"].(int) + 1
		}
		if config.APIConfig.RequireMFA {
			summary["require_mfa_count"] = summary["require_mfa_count"].(int) + 1
		}
		if config.APIConfig.RequireOwnership {
			summary["require_ownership_count"] = summary["require_ownership_count"].(int) + 1
		}
		if config.APIConfig.PublicRead {
			summary["public_read_count"] = summary["public_read_count"].(int) + 1
		}
		if config.APIConfig.PublicWrite {
			summary["public_write_count"] = summary["public_write_count"].(int) + 1
		}

		// Check for rate limits
		if config.APIConfig.RateLimit != nil {
			summary["with_rate_limits_count"] = summary["with_rate_limits_count"].(int) + 1
		}

		// Check for IP whitelist
		if len(config.APIConfig.IPWhitelist) > 0 {
			summary["with_ip_whitelist_count"] = summary["with_ip_whitelist_count"].(int) + 1
		}

		// Check for custom filters
		if len(config.APIConfig.CustomFilters) > 0 {
			summary["with_custom_filters_count"] = summary["with_custom_filters_count"].(int) + 1
		}

		// Determine security level
		securityLevel := s.determineSecurityLevel(config)
		securityLevels[securityLevel]++
	}

	summary["tables_by_schema"] = schemaCount
	summary["security_levels"] = securityLevels

	return summary, nil
}

// determineSecurityLevel determines the security level of a configuration
func (s *TableSecurityService) determineSecurityLevel(config *TableSecurityConfig) string {
	if config.APIConfig.PublicWrite {
		return "low"
	}

	if config.APIConfig.PublicRead && !config.APIConfig.RequireAuth {
		return "low"
	}

	if !config.APIConfig.RequireAuth {
		return "medium"
	}

	if config.APIConfig.RequireMFA {
		return "high"
	}

	hasIPRestrictions := len(config.APIConfig.IPWhitelist) > 0
	hasRoleRestrictions := len(config.APIConfig.AllowedRoles) > 0

	if hasIPRestrictions || hasRoleRestrictions {
		return "high"
	}

	return "medium"
}

package auth

import (
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/google/uuid"
)

// TableSecurityRepository handles table security configuration operations
type TableSecurityRepository struct {
	db *sql.DB
}

// NewTableSecurityRepository creates a new table security repository
func NewTableSecurityRepository(db *sql.DB) *TableSecurityRepository {
	return &TableSecurityRepository{
		db: db,
	}
}

// CreateTableSecurityConfig creates a new table security configuration
func (r *TableSecurityRepository) CreateTableSecurityConfig(config *TableSecurityConfig) error {
	// Generate ID if not provided
	if config.ID == "" {
		config.ID = uuid.New().String()
	}

	// Set timestamps
	now := time.Now()
	config.CreatedAt = now
	config.UpdatedAt = now

	// Check if configuration already exists
	var existingID string
	checkQuery := `
		SELECT id FROM table_configurations 
		WHERE table_name = $1 AND schema_name = $2 AND is_active = true
	`
	err := r.db.QueryRow(checkQuery, config.TableName, config.SchemaName).Scan(&existingID)
	if err == nil {
		return fmt.Errorf("table configuration already exists for %s.%s", config.SchemaName, config.TableName)
	} else if err != sql.ErrNoRows {
		return fmt.Errorf("failed to check existing configuration: %w", err)
	}

	// Serialize JSON fields
	apiConfigJSON, err := json.Marshal(config.APIConfig)
	if err != nil {
		return fmt.Errorf("failed to marshal API config: %w", err)
	}

	adminConfigJSON, err := json.Marshal(config.AdminConfig)
	if err != nil {
		return fmt.Errorf("failed to marshal admin config: %w", err)
	}

	fieldPermissionsJSON, err := json.Marshal(config.FieldPermissions)
	if err != nil {
		return fmt.Errorf("failed to marshal field permissions: %w", err)
	}

	auditConfigJSON, err := json.Marshal(config.AuditConfig)
	if err != nil {
		return fmt.Errorf("failed to marshal audit config: %w", err)
	}

	// Insert configuration
	insertQuery := `
		INSERT INTO table_configurations (
			id, table_name, schema_name, display_name, description,
			api_config, admin_config, field_permissions, audit_config,
			created_by, created_at, updated_by, updated_at, is_active
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
	`

	_, err = r.db.Exec(insertQuery,
		config.ID, config.TableName, config.SchemaName, config.DisplayName, config.Description,
		apiConfigJSON, adminConfigJSON, fieldPermissionsJSON, auditConfigJSON,
		config.CreatedBy, config.CreatedAt, config.UpdatedBy, config.UpdatedAt, config.IsActive,
	)

	if err != nil {
		return fmt.Errorf("failed to insert table security config: %w", err)
	}

	return nil
}

// GetTableSecurityConfig retrieves a table security configuration by table and schema name
func (r *TableSecurityRepository) GetTableSecurityConfig(tableName, schemaName string) (*TableSecurityConfig, error) {
	query := `
		SELECT id, table_name, schema_name, display_name, description,
			   api_config, admin_config, field_permissions, audit_config,
			   created_by, created_at, updated_by, updated_at, is_active
		FROM table_configurations 
		WHERE table_name = $1 AND schema_name = $2 AND is_active = true
	`

	var config TableSecurityConfig
	var apiConfigJSON, adminConfigJSON, fieldPermissionsJSON, auditConfigJSON []byte

	err := r.db.QueryRow(query, tableName, schemaName).Scan(
		&config.ID, &config.TableName, &config.SchemaName, &config.DisplayName, &config.Description,
		&apiConfigJSON, &adminConfigJSON, &fieldPermissionsJSON, &auditConfigJSON,
		&config.CreatedBy, &config.CreatedAt, &config.UpdatedBy, &config.UpdatedAt, &config.IsActive,
	)

	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("table security config not found for %s.%s", schemaName, tableName)
	} else if err != nil {
		return nil, fmt.Errorf("failed to get table security config: %w", err)
	}

	// Deserialize JSON fields
	if err := json.Unmarshal(apiConfigJSON, &config.APIConfig); err != nil {
		return nil, fmt.Errorf("failed to unmarshal API config: %w", err)
	}

	if err := json.Unmarshal(adminConfigJSON, &config.AdminConfig); err != nil {
		return nil, fmt.Errorf("failed to unmarshal admin config: %w", err)
	}

	if err := json.Unmarshal(fieldPermissionsJSON, &config.FieldPermissions); err != nil {
		return nil, fmt.Errorf("failed to unmarshal field permissions: %w", err)
	}

	if err := json.Unmarshal(auditConfigJSON, &config.AuditConfig); err != nil {
		return nil, fmt.Errorf("failed to unmarshal audit config: %w", err)
	}

	return &config, nil
}

// GetTableSecurityConfigByID retrieves a table security configuration by ID
func (r *TableSecurityRepository) GetTableSecurityConfigByID(id string) (*TableSecurityConfig, error) {
	query := `
		SELECT id, table_name, schema_name, display_name, description,
			   api_config, admin_config, field_permissions, audit_config,
			   created_by, created_at, updated_by, updated_at, is_active
		FROM table_configurations 
		WHERE id = $1
	`

	var config TableSecurityConfig
	var apiConfigJSON, adminConfigJSON, fieldPermissionsJSON, auditConfigJSON []byte

	err := r.db.QueryRow(query, id).Scan(
		&config.ID, &config.TableName, &config.SchemaName, &config.DisplayName, &config.Description,
		&apiConfigJSON, &adminConfigJSON, &fieldPermissionsJSON, &auditConfigJSON,
		&config.CreatedBy, &config.CreatedAt, &config.UpdatedBy, &config.UpdatedAt, &config.IsActive,
	)

	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("table security config not found with id %s", id)
	} else if err != nil {
		return nil, fmt.Errorf("failed to get table security config: %w", err)
	}

	// Deserialize JSON fields
	if err := json.Unmarshal(apiConfigJSON, &config.APIConfig); err != nil {
		return nil, fmt.Errorf("failed to unmarshal API config: %w", err)
	}

	if err := json.Unmarshal(adminConfigJSON, &config.AdminConfig); err != nil {
		return nil, fmt.Errorf("failed to unmarshal admin config: %w", err)
	}

	if err := json.Unmarshal(fieldPermissionsJSON, &config.FieldPermissions); err != nil {
		return nil, fmt.Errorf("failed to unmarshal field permissions: %w", err)
	}

	if err := json.Unmarshal(auditConfigJSON, &config.AuditConfig); err != nil {
		return nil, fmt.Errorf("failed to unmarshal audit config: %w", err)
	}

	return &config, nil
}

// UpdateTableSecurityConfig updates an existing table security configuration
func (r *TableSecurityRepository) UpdateTableSecurityConfig(id string, config *TableSecurityConfig, updatedBy string) error {
	// Set update metadata
	config.ID = id
	config.UpdatedBy = updatedBy
	config.UpdatedAt = time.Now()

	// Serialize JSON fields
	apiConfigJSON, err := json.Marshal(config.APIConfig)
	if err != nil {
		return fmt.Errorf("failed to marshal API config: %w", err)
	}

	adminConfigJSON, err := json.Marshal(config.AdminConfig)
	if err != nil {
		return fmt.Errorf("failed to marshal admin config: %w", err)
	}

	fieldPermissionsJSON, err := json.Marshal(config.FieldPermissions)
	if err != nil {
		return fmt.Errorf("failed to marshal field permissions: %w", err)
	}

	auditConfigJSON, err := json.Marshal(config.AuditConfig)
	if err != nil {
		return fmt.Errorf("failed to marshal audit config: %w", err)
	}

	// Update configuration
	updateQuery := `
		UPDATE table_configurations SET
			table_name = $2, schema_name = $3, display_name = $4, description = $5,
			api_config = $6, admin_config = $7, field_permissions = $8, audit_config = $9,
			updated_by = $10, updated_at = $11, is_active = $12
		WHERE id = $1
	`

	result, err := r.db.Exec(updateQuery,
		id, config.TableName, config.SchemaName, config.DisplayName, config.Description,
		apiConfigJSON, adminConfigJSON, fieldPermissionsJSON, auditConfigJSON,
		config.UpdatedBy, config.UpdatedAt, config.IsActive,
	)

	if err != nil {
		return fmt.Errorf("failed to update table security config: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("table security config not found with id %s", id)
	}

	return nil
}

// DeleteTableSecurityConfig soft deletes a table security configuration
func (r *TableSecurityRepository) DeleteTableSecurityConfig(id string, deletedBy string) error {
	updateQuery := `
		UPDATE table_configurations SET
			is_active = false,
			updated_by = $2,
			updated_at = $3
		WHERE id = $1 AND is_active = true
	`

	result, err := r.db.Exec(updateQuery, id, deletedBy, time.Now())
	if err != nil {
		return fmt.Errorf("failed to delete table security config: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("table security config not found with id %s", id)
	}

	return nil
}

// ListTableSecurityConfigs retrieves table security configurations with filtering
func (r *TableSecurityRepository) ListTableSecurityConfigs(filter *TableSecurityConfigFilter) ([]*TableSecurityConfig, error) {
	// Build query with filters
	query := `
		SELECT id, table_name, schema_name, display_name, description,
			   api_config, admin_config, field_permissions, audit_config,
			   created_by, created_at, updated_by, updated_at, is_active
		FROM table_configurations 
		WHERE 1=1
	`
	args := []interface{}{}
	argIndex := 1

	// Apply filters
	if filter.TableName != nil {
		query += fmt.Sprintf(" AND table_name = $%d", argIndex)
		args = append(args, *filter.TableName)
		argIndex++
	}

	if filter.SchemaName != nil {
		query += fmt.Sprintf(" AND schema_name = $%d", argIndex)
		args = append(args, *filter.SchemaName)
		argIndex++
	}

	if filter.IsActive != nil {
		query += fmt.Sprintf(" AND is_active = $%d", argIndex)
		args = append(args, *filter.IsActive)
		argIndex++
	}

	if filter.CreatedBy != nil {
		query += fmt.Sprintf(" AND created_by = $%d", argIndex)
		args = append(args, *filter.CreatedBy)
		argIndex++
	}

	if filter.RequireAuth != nil {
		query += fmt.Sprintf(" AND (api_config->>'require_auth')::boolean = $%d", argIndex)
		args = append(args, *filter.RequireAuth)
		argIndex++
	}

	// Add ordering
	query += " ORDER BY created_at DESC"

	// Add limit and offset
	if filter.Limit > 0 {
		query += fmt.Sprintf(" LIMIT $%d", argIndex)
		args = append(args, filter.Limit)
		argIndex++
	}

	if filter.Offset > 0 {
		query += fmt.Sprintf(" OFFSET $%d", argIndex)
		args = append(args, filter.Offset)
		argIndex++
	}

	rows, err := r.db.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to query table security configs: %w", err)
	}
	defer rows.Close()

	var configs []*TableSecurityConfig

	for rows.Next() {
		var config TableSecurityConfig
		var apiConfigJSON, adminConfigJSON, fieldPermissionsJSON, auditConfigJSON []byte

		err := rows.Scan(
			&config.ID, &config.TableName, &config.SchemaName, &config.DisplayName, &config.Description,
			&apiConfigJSON, &adminConfigJSON, &fieldPermissionsJSON, &auditConfigJSON,
			&config.CreatedBy, &config.CreatedAt, &config.UpdatedBy, &config.UpdatedAt, &config.IsActive,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan table security config: %w", err)
		}

		// Deserialize JSON fields
		if err := json.Unmarshal(apiConfigJSON, &config.APIConfig); err != nil {
			return nil, fmt.Errorf("failed to unmarshal API config: %w", err)
		}

		if err := json.Unmarshal(adminConfigJSON, &config.AdminConfig); err != nil {
			return nil, fmt.Errorf("failed to unmarshal admin config: %w", err)
		}

		if err := json.Unmarshal(fieldPermissionsJSON, &config.FieldPermissions); err != nil {
			return nil, fmt.Errorf("failed to unmarshal field permissions: %w", err)
		}

		if err := json.Unmarshal(auditConfigJSON, &config.AuditConfig); err != nil {
			return nil, fmt.Errorf("failed to unmarshal audit config: %w", err)
		}

		configs = append(configs, &config)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating table security configs: %w", err)
	}

	return configs, nil
}

// ValidateTableSecurityConfig validates a table security configuration
func (r *TableSecurityRepository) ValidateTableSecurityConfig(config *TableSecurityConfig) *ValidationResult {
	result := &ValidationResult{
		IsValid:   true,
		Errors:    []ValidationError{},
		Warnings:  []ValidationWarning{},
		Conflicts: []ConfigurationConflict{},
	}

	// Validate table name
	if config.TableName == "" {
		result.Errors = append(result.Errors, ValidationError{
			Field:   "table_name",
			Code:    "REQUIRED",
			Message: "Table name is required",
		})
		result.IsValid = false
	}

	// Validate schema name
	if config.SchemaName == "" {
		config.SchemaName = "public" // Default to public schema
	}

	// Validate API configuration
	if err := r.validateAPIConfig(&config.APIConfig, result); err != nil {
		result.IsValid = false
	}

	// Validate field permissions
	if err := r.validateFieldPermissions(config.FieldPermissions, result); err != nil {
		result.IsValid = false
	}

	// Check for configuration conflicts
	r.checkConfigurationConflicts(config, result)

	// Add security warnings
	r.addSecurityWarnings(config, result)

	return result
}

// validateAPIConfig validates API security configuration
func (r *TableSecurityRepository) validateAPIConfig(apiConfig *APISecurityConfig, result *ValidationResult) error {
	// Validate ownership configuration
	if apiConfig.RequireOwnership && apiConfig.OwnershipColumn == "" {
		result.Errors = append(result.Errors, ValidationError{
			Field:   "api_config.ownership_column",
			Code:    "REQUIRED_WHEN_OWNERSHIP",
			Message: "Ownership column is required when ownership is enforced",
		})
		return fmt.Errorf("ownership column required")
	}

	// Validate rate limit configuration
	if apiConfig.RateLimit != nil {
		if apiConfig.RateLimit.RequestsPerMinute <= 0 {
			result.Errors = append(result.Errors, ValidationError{
				Field:   "api_config.rate_limit.requests_per_minute",
				Code:    "INVALID_VALUE",
				Message: "Requests per minute must be greater than 0",
			})
			return fmt.Errorf("invalid rate limit")
		}

		if apiConfig.RateLimit.BurstSize <= 0 {
			result.Errors = append(result.Errors, ValidationError{
				Field:   "api_config.rate_limit.burst_size",
				Code:    "INVALID_VALUE",
				Message: "Burst size must be greater than 0",
			})
			return fmt.Errorf("invalid burst size")
		}
	}

	// Validate IP whitelist format
	for i, ip := range apiConfig.IPWhitelist {
		if !r.isValidIPOrCIDR(ip) {
			result.Errors = append(result.Errors, ValidationError{
				Field:   fmt.Sprintf("api_config.ip_whitelist[%d]", i),
				Code:    "INVALID_IP_FORMAT",
				Message: fmt.Sprintf("Invalid IP address or CIDR format: %s", ip),
			})
			return fmt.Errorf("invalid IP format")
		}
	}

	// Validate time-based access configuration
	if apiConfig.TimeBasedAccess != nil {
		if err := r.validateTimeBasedAccess(apiConfig.TimeBasedAccess, result); err != nil {
			return err
		}
	}

	return nil
}

// validateFieldPermissions validates field-level permissions
func (r *TableSecurityRepository) validateFieldPermissions(permissions map[string]FieldPermission, result *ValidationResult) error {
	for fieldName, permission := range permissions {
		// Validate field name
		if fieldName == "" {
			result.Errors = append(result.Errors, ValidationError{
				Field:   "field_permissions",
				Code:    "EMPTY_FIELD_NAME",
				Message: "Field name cannot be empty",
			})
			return fmt.Errorf("empty field name")
		}

		// Validate roles if specified
		for i, role := range permission.Roles {
			if role == "" {
				result.Errors = append(result.Errors, ValidationError{
					Field:   fmt.Sprintf("field_permissions.%s.roles[%d]", fieldName, i),
					Code:    "EMPTY_ROLE",
					Message: "Role name cannot be empty",
				})
				return fmt.Errorf("empty role name")
			}
		}

		// Validate condition syntax if specified
		if permission.Condition != "" {
			if err := r.validateConditionSyntax(permission.Condition); err != nil {
				result.Errors = append(result.Errors, ValidationError{
					Field:   fmt.Sprintf("field_permissions.%s.condition", fieldName),
					Code:    "INVALID_CONDITION",
					Message: fmt.Sprintf("Invalid condition syntax: %v", err),
				})
				return fmt.Errorf("invalid condition")
			}
		}
	}

	return nil
}

// validateTimeBasedAccess validates time-based access configuration
func (r *TableSecurityRepository) validateTimeBasedAccess(config *TimeBasedAccessConfig, result *ValidationResult) error {
	// Validate allowed hours
	for i, hour := range config.AllowedHours {
		if hour < 0 || hour > 23 {
			result.Errors = append(result.Errors, ValidationError{
				Field:   fmt.Sprintf("api_config.time_based_access.allowed_hours[%d]", i),
				Code:    "INVALID_HOUR",
				Message: fmt.Sprintf("Hour must be between 0 and 23, got %d", hour),
			})
			return fmt.Errorf("invalid hour")
		}
	}

	// Validate allowed days
	for i, day := range config.AllowedDays {
		if day < 0 || day > 6 {
			result.Errors = append(result.Errors, ValidationError{
				Field:   fmt.Sprintf("api_config.time_based_access.allowed_days[%d]", i),
				Code:    "INVALID_DAY",
				Message: fmt.Sprintf("Day must be between 0 and 6, got %d", day),
			})
			return fmt.Errorf("invalid day")
		}
	}

	// Validate timezone
	if config.Timezone != "" {
		if _, err := time.LoadLocation(config.Timezone); err != nil {
			result.Errors = append(result.Errors, ValidationError{
				Field:   "api_config.time_based_access.timezone",
				Code:    "INVALID_TIMEZONE",
				Message: fmt.Sprintf("Invalid timezone: %s", config.Timezone),
			})
			return fmt.Errorf("invalid timezone")
		}
	}

	return nil
}

// checkConfigurationConflicts checks for configuration conflicts
func (r *TableSecurityRepository) checkConfigurationConflicts(config *TableSecurityConfig, result *ValidationResult) {
	// Check for conflicting public access and authentication requirements
	if config.APIConfig.PublicRead && config.APIConfig.RequireAuth {
		result.Conflicts = append(result.Conflicts, ConfigurationConflict{
			Type:        "CONFLICTING_ACCESS",
			Description: "Public read access conflicts with authentication requirement",
			Severity:    "MEDIUM",
			Resolution:  "Either disable public read or remove authentication requirement",
		})
	}

	if config.APIConfig.PublicWrite && config.APIConfig.RequireAuth {
		result.Conflicts = append(result.Conflicts, ConfigurationConflict{
			Type:        "CONFLICTING_ACCESS",
			Description: "Public write access conflicts with authentication requirement",
			Severity:    "HIGH",
			Resolution:  "Either disable public write or remove authentication requirement",
		})
	}

	// Check for MFA requirement without authentication
	if config.APIConfig.RequireMFA && !config.APIConfig.RequireAuth {
		result.Conflicts = append(result.Conflicts, ConfigurationConflict{
			Type:        "INVALID_MFA_CONFIG",
			Description: "MFA requirement without authentication requirement",
			Severity:    "HIGH",
			Resolution:  "Enable authentication requirement when MFA is required",
		})
	}

	// Check for ownership requirement without authentication
	if config.APIConfig.RequireOwnership && !config.APIConfig.RequireAuth {
		result.Conflicts = append(result.Conflicts, ConfigurationConflict{
			Type:        "INVALID_OWNERSHIP_CONFIG",
			Description: "Ownership requirement without authentication requirement",
			Severity:    "HIGH",
			Resolution:  "Enable authentication requirement when ownership is required",
		})
	}
}

// addSecurityWarnings adds security-related warnings
func (r *TableSecurityRepository) addSecurityWarnings(config *TableSecurityConfig, result *ValidationResult) {
	// Warn about public write access
	if config.APIConfig.PublicWrite {
		result.Warnings = append(result.Warnings, ValidationWarning{
			Field:   "api_config.public_write",
			Code:    "SECURITY_RISK",
			Message: "Public write access poses security risks - consider requiring authentication",
		})
	}

	// Warn about missing rate limits
	if config.APIConfig.RateLimit == nil {
		result.Warnings = append(result.Warnings, ValidationWarning{
			Field:   "api_config.rate_limit",
			Code:    "MISSING_RATE_LIMIT",
			Message: "No rate limiting configured - consider adding rate limits for better security",
		})
	}

	// Warn about missing audit logging
	if !config.APIConfig.AuditActions {
		result.Warnings = append(result.Warnings, ValidationWarning{
			Field:   "api_config.audit_actions",
			Code:    "MISSING_AUDIT",
			Message: "Audit logging is disabled - consider enabling for compliance and security monitoring",
		})
	}

	// Warn about empty IP whitelist when authentication is not required
	if !config.APIConfig.RequireAuth && len(config.APIConfig.IPWhitelist) == 0 {
		result.Warnings = append(result.Warnings, ValidationWarning{
			Field:   "api_config.ip_whitelist",
			Code:    "MISSING_IP_RESTRICTION",
			Message: "No IP restrictions configured for unauthenticated access - consider adding IP whitelist",
		})
	}
}

// Helper methods

// isValidIPOrCIDR validates IP address or CIDR notation
func (r *TableSecurityRepository) isValidIPOrCIDR(ipStr string) bool {
	// Try parsing as CIDR first
	if _, _, err := net.ParseCIDR(ipStr); err == nil {
		return true
	}

	// Try parsing as IP address
	if net.ParseIP(ipStr) != nil {
		return true
	}

	return false
}

// validateConditionSyntax validates condition syntax (simplified)
func (r *TableSecurityRepository) validateConditionSyntax(condition string) error {
	// Basic validation - in production, use a proper expression parser
	if condition == "" {
		return fmt.Errorf("condition cannot be empty")
	}

	// Check for basic SQL injection patterns
	dangerousPatterns := []string{
		"DROP", "DELETE", "INSERT", "UPDATE", "ALTER", "CREATE",
		"--", "/*", "*/", ";",
	}

	upperCondition := strings.ToUpper(condition)
	for _, pattern := range dangerousPatterns {
		if strings.Contains(upperCondition, pattern) {
			return fmt.Errorf("condition contains potentially dangerous pattern: %s", pattern)
		}
	}

	return nil
}

// CreateConfigurationTemplate creates a new configuration template
func (r *TableSecurityRepository) CreateConfigurationTemplate(template *TableConfigurationTemplate) error {
	// Generate ID if not provided
	if template.ID == "" {
		template.ID = uuid.New().String()
	}

	// Set timestamp
	template.CreatedAt = time.Now()

	// Serialize config
	configJSON, err := json.Marshal(template.Config)
	if err != nil {
		return fmt.Errorf("failed to marshal template config: %w", err)
	}

	// Insert template
	insertQuery := `
		INSERT INTO table_configuration_templates (
			id, name, description, category, config, is_built_in, created_by, created_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
	`

	_, err = r.db.Exec(insertQuery,
		template.ID, template.Name, template.Description, template.Category,
		configJSON, template.IsBuiltIn, template.CreatedBy, template.CreatedAt,
	)

	if err != nil {
		return fmt.Errorf("failed to insert configuration template: %w", err)
	}

	return nil
}

// GetConfigurationTemplates retrieves configuration templates
func (r *TableSecurityRepository) GetConfigurationTemplates(category string) ([]*TableConfigurationTemplate, error) {
	// Build query with optional category filter
	query := `
		SELECT id, name, description, category, config, is_built_in, created_by, created_at
		FROM table_configuration_templates
		WHERE 1=1
	`
	args := []interface{}{}

	if category != "" {
		query += " AND category = $1"
		args = append(args, category)
	}

	query += " ORDER BY is_built_in DESC, name ASC"

	rows, err := r.db.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to query configuration templates: %w", err)
	}
	defer rows.Close()

	var templates []*TableConfigurationTemplate

	for rows.Next() {
		var template TableConfigurationTemplate
		var configJSON []byte

		err := rows.Scan(
			&template.ID, &template.Name, &template.Description, &template.Category,
			&configJSON, &template.IsBuiltIn, &template.CreatedBy, &template.CreatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan configuration template: %w", err)
		}

		// Deserialize config
		if err := json.Unmarshal(configJSON, &template.Config); err != nil {
			return nil, fmt.Errorf("failed to unmarshal template config: %w", err)
		}

		templates = append(templates, &template)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating configuration templates: %w", err)
	}

	// If no templates found and no category filter, return built-in templates
	if len(templates) == 0 && category == "" {
		return r.getBuiltInTemplates(), nil
	}

	return templates, nil
}

// getBuiltInTemplates returns built-in configuration templates
func (r *TableSecurityRepository) getBuiltInTemplates() []*TableConfigurationTemplate {
	return []*TableConfigurationTemplate{
		{
			ID:          "public-read-only",
			Name:        "Public Read Only",
			Description: "Allow public read access with no authentication required",
			Category:    "Basic",
			IsBuiltIn:   true,
			Config: &TableSecurityConfig{
				APIConfig: APISecurityConfig{
					RequireAuth:     false,
					RequireVerified: false,
					PublicRead:      true,
					PublicWrite:     false,
					AuditActions:    true,
					RateLimit: &RateLimitConfig{
						RequestsPerMinute: 100,
						RequestsPerHour:   1000,
						BurstSize:         10,
					},
				},
				AuditConfig: AuditConfig{
					LogReads:   true,
					LogWrites:  true,
					LogDeletes: true,
				},
			},
		},
		{
			ID:          "authenticated-users",
			Name:        "Authenticated Users Only",
			Description: "Require authentication for all access",
			Category:    "Basic",
			IsBuiltIn:   true,
			Config: &TableSecurityConfig{
				APIConfig: APISecurityConfig{
					RequireAuth:     true,
					RequireVerified: true,
					PublicRead:      false,
					PublicWrite:     false,
					AuditActions:    true,
					RateLimit: &RateLimitConfig{
						RequestsPerMinute: 60,
						RequestsPerHour:   500,
						BurstSize:         5,
					},
				},
				AuditConfig: AuditConfig{
					LogReads:   true,
					LogWrites:  true,
					LogDeletes: true,
				},
			},
		},
		{
			ID:          "owner-only-access",
			Name:        "Owner Only Access",
			Description: "Require authentication and ownership for all access",
			Category:    "Security",
			IsBuiltIn:   true,
			Config: &TableSecurityConfig{
				APIConfig: APISecurityConfig{
					RequireAuth:      true,
					RequireVerified:  true,
					RequireOwnership: true,
					OwnershipColumn:  "user_id",
					PublicRead:       false,
					PublicWrite:      false,
					AuditActions:     true,
					RateLimit: &RateLimitConfig{
						RequestsPerMinute: 30,
						RequestsPerHour:   200,
						BurstSize:         3,
					},
				},
				AuditConfig: AuditConfig{
					LogReads:   true,
					LogWrites:  true,
					LogDeletes: true,
				},
			},
		},
		{
			ID:          "high-security",
			Name:        "High Security",
			Description: "Maximum security with MFA, IP restrictions, and comprehensive auditing",
			Category:    "Security",
			IsBuiltIn:   true,
			Config: &TableSecurityConfig{
				APIConfig: APISecurityConfig{
					RequireAuth:      true,
					RequireVerified:  true,
					RequireOwnership: true,
					RequireMFA:       true,
					OwnershipColumn:  "user_id",
					PublicRead:       false,
					PublicWrite:      false,
					AuditActions:     true,
					RateLimit: &RateLimitConfig{
						RequestsPerMinute: 20,
						RequestsPerHour:   100,
						BurstSize:         2,
					},
				},
				AuditConfig: AuditConfig{
					LogReads:   true,
					LogWrites:  true,
					LogDeletes: true,
				},
			},
		},
	}
}

// GetConfigurationVersions retrieves version history for a configuration
func (r *TableSecurityRepository) GetConfigurationVersions(configID string) ([]*TableConfigurationVersion, error) {
	query := `
		SELECT id, config_id, version, config, change_reason, changed_by, created_at
		FROM table_configuration_versions
		WHERE config_id = $1
		ORDER BY version DESC
	`

	rows, err := r.db.Query(query, configID)
	if err != nil {
		return nil, fmt.Errorf("failed to query configuration versions: %w", err)
	}
	defer rows.Close()

	var versions []*TableConfigurationVersion

	for rows.Next() {
		var version TableConfigurationVersion
		var configJSON []byte

		err := rows.Scan(
			&version.ID, &version.ConfigID, &version.Version,
			&configJSON, &version.ChangeReason, &version.ChangedBy, &version.CreatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan configuration version: %w", err)
		}

		// Deserialize config
		if err := json.Unmarshal(configJSON, &version.Config); err != nil {
			return nil, fmt.Errorf("failed to unmarshal version config: %w", err)
		}

		versions = append(versions, &version)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating configuration versions: %w", err)
	}

	return versions, nil
}

// RollbackToVersion rolls back a configuration to a specific version
func (r *TableSecurityRepository) RollbackToVersion(configID string, version int, rolledBackBy string) error {
	// Get the version to rollback to
	getVersionQuery := `
		SELECT config FROM table_configuration_versions
		WHERE config_id = $1 AND version = $2
	`

	var configJSON []byte
	err := r.db.QueryRow(getVersionQuery, configID, version).Scan(&configJSON)
	if err == sql.ErrNoRows {
		return fmt.Errorf("version %d not found for config %s", version, configID)
	} else if err != nil {
		return fmt.Errorf("failed to get version config: %w", err)
	}

	// Deserialize the version config
	var versionConfig TableSecurityConfig
	if err := json.Unmarshal(configJSON, &versionConfig); err != nil {
		return fmt.Errorf("failed to unmarshal version config: %w", err)
	}

	// Create a new version entry for the rollback
	createVersionQuery := `
		INSERT INTO table_configuration_versions (
			id, config_id, version, config, change_reason, changed_by, created_at
		)
		SELECT 
			$1, 
			$2, 
			COALESCE(MAX(version), 0) + 1,
			$3,
			$4,
			$5,
			$6
		FROM table_configuration_versions
		WHERE config_id = $2
	`

	newVersionID := uuid.New().String()
	changeReason := fmt.Sprintf("Rollback to version %d", version)
	now := time.Now()

	_, err = r.db.Exec(createVersionQuery,
		newVersionID, configID, configJSON, changeReason, rolledBackBy, now,
	)
	if err != nil {
		return fmt.Errorf("failed to create rollback version: %w", err)
	}

	// Update the main configuration with the rolled back version
	return r.UpdateTableSecurityConfig(configID, &versionConfig, rolledBackBy)
}

// GenerateConfigHash generates a hash for configuration change detection
func (r *TableSecurityRepository) GenerateConfigHash(config *TableSecurityConfig) (string, error) {
	// Create a normalized representation for hashing
	hashData := struct {
		TableName        string                     `json:"table_name"`
		SchemaName       string                     `json:"schema_name"`
		APIConfig        APISecurityConfig          `json:"api_config"`
		AdminConfig      AdminPanelConfig           `json:"admin_config"`
		FieldPermissions map[string]FieldPermission `json:"field_permissions"`
		AuditConfig      AuditConfig                `json:"audit_config"`
	}{
		TableName:        config.TableName,
		SchemaName:       config.SchemaName,
		APIConfig:        config.APIConfig,
		AdminConfig:      config.AdminConfig,
		FieldPermissions: config.FieldPermissions,
		AuditConfig:      config.AuditConfig,
	}

	// Serialize to JSON for consistent hashing
	jsonData, err := json.Marshal(hashData)
	if err != nil {
		return "", fmt.Errorf("failed to marshal config for hashing: %w", err)
	}

	// Generate SHA-256 hash
	hash := sha256.Sum256(jsonData)
	return fmt.Sprintf("%x", hash), nil
}

// CreateConfigurationVersion creates a new version entry for a configuration
func (r *TableSecurityRepository) CreateConfigurationVersion(configID string, config *TableSecurityConfig, changeReason, changedBy string) error {
	// Get the next version number
	getMaxVersionQuery := `
		SELECT COALESCE(MAX(version), 0) FROM table_configuration_versions
		WHERE config_id = $1
	`

	var maxVersion int
	err := r.db.QueryRow(getMaxVersionQuery, configID).Scan(&maxVersion)
	if err != nil {
		return fmt.Errorf("failed to get max version: %w", err)
	}

	nextVersion := maxVersion + 1

	// Serialize config
	configJSON, err := json.Marshal(config)
	if err != nil {
		return fmt.Errorf("failed to marshal config for versioning: %w", err)
	}

	// Insert version
	insertVersionQuery := `
		INSERT INTO table_configuration_versions (
			id, config_id, version, config, change_reason, changed_by, created_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7)
	`

	versionID := uuid.New().String()
	_, err = r.db.Exec(insertVersionQuery,
		versionID, configID, nextVersion, configJSON, changeReason, changedBy, time.Now(),
	)

	if err != nil {
		return fmt.Errorf("failed to create configuration version: %w", err)
	}

	return nil
}

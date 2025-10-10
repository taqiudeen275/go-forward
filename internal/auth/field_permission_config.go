package auth

import (
	"fmt"
	"strings"
	"time"
)

// FieldPermissionConfig represents field-level permission configuration
type FieldPermissionConfig struct {
	ID          string               `json:"id" db:"id"`
	TableName   string               `json:"table_name" db:"table_name"`
	SchemaName  string               `json:"schema_name" db:"schema_name"`
	FieldName   string               `json:"field_name" db:"field_name"`
	Permissions FieldPermissionRules `json:"permissions" db:"permissions"`
	CreatedBy   string               `json:"created_by" db:"created_by"`
	CreatedAt   time.Time            `json:"created_at" db:"created_at"`
	UpdatedAt   time.Time            `json:"updated_at" db:"updated_at"`
	IsActive    bool                 `json:"is_active" db:"is_active"`
}

// FieldPermissionRules defines the permission rules for a field
type FieldPermissionRules struct {
	ReadRoles      []string               `json:"read_roles"`
	WriteRoles     []string               `json:"write_roles"`
	MaskPII        bool                   `json:"mask_pii"`
	Encrypted      bool                   `json:"encrypted"`
	Validation     *FieldValidationRules  `json:"validation,omitempty"`
	Transformation *FieldTransformation   `json:"transformation,omitempty"`
	Conditions     []FieldAccessCondition `json:"conditions,omitempty"`
}

// FieldValidationRules defines validation rules for a field
type FieldValidationRules struct {
	Required    bool                   `json:"required"`
	MinLength   *int                   `json:"min_length,omitempty"`
	MaxLength   *int                   `json:"max_length,omitempty"`
	Pattern     string                 `json:"pattern,omitempty"`
	Format      string                 `json:"format,omitempty"` // email, phone, url, etc.
	CustomRules map[string]interface{} `json:"custom_rules,omitempty"`
}

// FieldTransformation defines how field values should be transformed
type FieldTransformation struct {
	OnRead  []TransformationRule `json:"on_read,omitempty"`
	OnWrite []TransformationRule `json:"on_write,omitempty"`
}

// TransformationRule defines a single transformation rule
type TransformationRule struct {
	Type       string                 `json:"type"` // mask, encrypt, hash, format, etc.
	Parameters map[string]interface{} `json:"parameters,omitempty"`
	Condition  string                 `json:"condition,omitempty"` // When to apply this rule
}

// FieldAccessCondition defines conditional access to fields
type FieldAccessCondition struct {
	Type       string                 `json:"type"`      // time, ip, role, custom
	Condition  string                 `json:"condition"` // The condition expression
	Action     string                 `json:"action"`    // allow, deny, mask, encrypt
	Parameters map[string]interface{} `json:"parameters,omitempty"`
}

// FieldPermissionRepository handles field permission data operations
type FieldPermissionRepository struct {
	// This would be implemented with database operations
	// For now, it's a placeholder
}

// NewFieldPermissionRepository creates a new field permission repository
func NewFieldPermissionRepository() *FieldPermissionRepository {
	return &FieldPermissionRepository{}
}

// CreateFieldPermission creates a new field permission configuration
func (r *FieldPermissionRepository) CreateFieldPermission(config *FieldPermissionConfig) error {
	// Placeholder implementation
	return nil
}

// GetFieldPermission retrieves field permission configuration
func (r *FieldPermissionRepository) GetFieldPermission(tableName, schemaName, fieldName string) (*FieldPermissionConfig, error) {
	// Placeholder implementation
	return nil, fmt.Errorf("not implemented")
}

// UpdateFieldPermission updates field permission configuration
func (r *FieldPermissionRepository) UpdateFieldPermission(id string, config *FieldPermissionConfig) error {
	// Placeholder implementation
	return nil
}

// DeleteFieldPermission deletes field permission configuration
func (r *FieldPermissionRepository) DeleteFieldPermission(id string) error {
	// Placeholder implementation
	return nil
}

// ListFieldPermissions lists field permissions for a table
func (r *FieldPermissionRepository) ListFieldPermissions(tableName, schemaName string) ([]*FieldPermissionConfig, error) {
	// Placeholder implementation
	return nil, nil
}

// FieldPermissionService handles field permission business logic
type FieldPermissionService struct {
	repo         *FieldPermissionRepository
	auditService AuditService
}

// NewFieldPermissionService creates a new field permission service
func NewFieldPermissionService(repo *FieldPermissionRepository, auditService AuditService) *FieldPermissionService {
	return &FieldPermissionService{
		repo:         repo,
		auditService: auditService,
	}
}

// CreateFieldPermission creates a new field permission configuration
func (s *FieldPermissionService) CreateFieldPermission(config *FieldPermissionConfig, createdBy string) error {
	config.CreatedBy = createdBy
	config.CreatedAt = time.Now()
	config.UpdatedAt = time.Now()
	config.IsActive = true

	// Validate configuration
	if err := s.validateFieldPermissionConfig(config); err != nil {
		return fmt.Errorf("validation failed: %w", err)
	}

	// Create configuration
	err := s.repo.CreateFieldPermission(config)
	if err != nil {
		return fmt.Errorf("failed to create field permission: %w", err)
	}

	// Log audit event
	s.auditService.LogAdminAction(
		createdBy,
		"CREATE_FIELD_PERMISSION",
		fmt.Sprintf("%s.%s.%s", config.SchemaName, config.TableName, config.FieldName),
		map[string]interface{}{
			"config_id":   config.ID,
			"table_name":  config.TableName,
			"schema_name": config.SchemaName,
			"field_name":  config.FieldName,
		},
	)

	return nil
}

// GetFieldPermission retrieves field permission configuration
func (s *FieldPermissionService) GetFieldPermission(tableName, schemaName, fieldName string) (*FieldPermissionConfig, error) {
	return s.repo.GetFieldPermission(tableName, schemaName, fieldName)
}

// UpdateFieldPermission updates field permission configuration
func (s *FieldPermissionService) UpdateFieldPermission(id string, config *FieldPermissionConfig, updatedBy string) error {
	config.UpdatedAt = time.Now()

	// Validate configuration
	if err := s.validateFieldPermissionConfig(config); err != nil {
		return fmt.Errorf("validation failed: %w", err)
	}

	// Update configuration
	err := s.repo.UpdateFieldPermission(id, config)
	if err != nil {
		return fmt.Errorf("failed to update field permission: %w", err)
	}

	// Log audit event
	s.auditService.LogAdminAction(
		updatedBy,
		"UPDATE_FIELD_PERMISSION",
		fmt.Sprintf("%s.%s.%s", config.SchemaName, config.TableName, config.FieldName),
		map[string]interface{}{
			"config_id":   id,
			"table_name":  config.TableName,
			"schema_name": config.SchemaName,
			"field_name":  config.FieldName,
		},
	)

	return nil
}

// DeleteFieldPermission deletes field permission configuration
func (s *FieldPermissionService) DeleteFieldPermission(id string, deletedBy string) error {
	// Get config for audit logging
	// This would require getting the config first in a real implementation

	err := s.repo.DeleteFieldPermission(id)
	if err != nil {
		return fmt.Errorf("failed to delete field permission: %w", err)
	}

	// Log audit event
	s.auditService.LogAdminAction(
		deletedBy,
		"DELETE_FIELD_PERMISSION",
		"field_permission",
		map[string]interface{}{
			"config_id": id,
		},
	)

	return nil
}

// ListFieldPermissions lists field permissions for a table
func (s *FieldPermissionService) ListFieldPermissions(tableName, schemaName string) ([]*FieldPermissionConfig, error) {
	return s.repo.ListFieldPermissions(tableName, schemaName)
}

// validateFieldPermissionConfig validates field permission configuration
func (s *FieldPermissionService) validateFieldPermissionConfig(config *FieldPermissionConfig) error {
	if config.TableName == "" {
		return fmt.Errorf("table name is required")
	}

	if config.FieldName == "" {
		return fmt.Errorf("field name is required")
	}

	if config.SchemaName == "" {
		config.SchemaName = "public"
	}

	// Validate roles exist (this would check against actual roles in a real implementation)
	if err := s.validateRoles(config.Permissions.ReadRoles); err != nil {
		return fmt.Errorf("invalid read roles: %w", err)
	}

	if err := s.validateRoles(config.Permissions.WriteRoles); err != nil {
		return fmt.Errorf("invalid write roles: %w", err)
	}

	// Validate transformation rules
	if config.Permissions.Transformation != nil {
		if err := s.validateTransformationRules(config.Permissions.Transformation); err != nil {
			return fmt.Errorf("invalid transformation rules: %w", err)
		}
	}

	// Validate access conditions
	if err := s.validateAccessConditions(config.Permissions.Conditions); err != nil {
		return fmt.Errorf("invalid access conditions: %w", err)
	}

	return nil
}

// validateRoles validates that roles exist and are valid
func (s *FieldPermissionService) validateRoles(roles []string) error {
	// This would check against actual roles in a real implementation
	validRoles := map[string]bool{
		"System Admin":  true,
		"Super Admin":   true,
		"Regular Admin": true,
		"Moderator":     true,
		"User":          true,
	}

	for _, role := range roles {
		if !validRoles[role] {
			return fmt.Errorf("invalid role: %s", role)
		}
	}

	return nil
}

// validateTransformationRules validates transformation rules
func (s *FieldPermissionService) validateTransformationRules(transformation *FieldTransformation) error {
	validTypes := map[string]bool{
		"mask":    true,
		"encrypt": true,
		"hash":    true,
		"format":  true,
		"upper":   true,
		"lower":   true,
		"trim":    true,
	}

	allRules := append(transformation.OnRead, transformation.OnWrite...)
	for _, rule := range allRules {
		if !validTypes[rule.Type] {
			return fmt.Errorf("invalid transformation type: %s", rule.Type)
		}
	}

	return nil
}

// validateAccessConditions validates access conditions
func (s *FieldPermissionService) validateAccessConditions(conditions []FieldAccessCondition) error {
	validTypes := map[string]bool{
		"time":   true,
		"ip":     true,
		"role":   true,
		"custom": true,
	}

	validActions := map[string]bool{
		"allow":   true,
		"deny":    true,
		"mask":    true,
		"encrypt": true,
	}

	for _, condition := range conditions {
		if !validTypes[condition.Type] {
			return fmt.Errorf("invalid condition type: %s", condition.Type)
		}

		if !validActions[condition.Action] {
			return fmt.Errorf("invalid condition action: %s", condition.Action)
		}

		if condition.Condition == "" {
			return fmt.Errorf("condition expression is required")
		}
	}

	return nil
}

// ApplyFieldTransformations applies transformations to field values
func (s *FieldPermissionService) ApplyFieldTransformations(tableName, schemaName string, data map[string]interface{}, operation string) (map[string]interface{}, error) {
	transformedData := make(map[string]interface{})

	for fieldName, value := range data {
		// Get field permission configuration
		config, err := s.GetFieldPermission(tableName, schemaName, fieldName)
		if err != nil {
			// If no configuration exists, use original value
			transformedData[fieldName] = value
			continue
		}

		// Apply transformations based on operation
		var rules []TransformationRule
		if operation == "read" && config.Permissions.Transformation != nil {
			rules = config.Permissions.Transformation.OnRead
		} else if operation == "write" && config.Permissions.Transformation != nil {
			rules = config.Permissions.Transformation.OnWrite
		}

		transformedValue := value
		for _, rule := range rules {
			transformedValue = s.applyTransformationRule(transformedValue, rule)
		}

		transformedData[fieldName] = transformedValue
	}

	return transformedData, nil
}

// applyTransformationRule applies a single transformation rule
func (s *FieldPermissionService) applyTransformationRule(value interface{}, rule TransformationRule) interface{} {
	strValue, ok := value.(string)
	if !ok {
		return value
	}

	switch rule.Type {
	case "mask":
		return s.maskValue(strValue, rule.Parameters)
	case "encrypt":
		// This would use proper encryption in a real implementation
		return "***ENCRYPTED***"
	case "hash":
		// This would use proper hashing in a real implementation
		return "***HASHED***"
	case "upper":
		return strings.ToUpper(strValue)
	case "lower":
		return strings.ToLower(strValue)
	case "trim":
		return strings.TrimSpace(strValue)
	default:
		return value
	}
}

// maskValue masks a value based on parameters
func (s *FieldPermissionService) maskValue(value string, parameters map[string]interface{}) string {
	maskType, ok := parameters["type"].(string)
	if !ok {
		maskType = "generic"
	}

	switch maskType {
	case "email":
		return s.maskEmail(value)
	case "phone":
		return s.maskPhone(value)
	case "partial":
		keepStart, _ := parameters["keep_start"].(float64)
		keepEnd, _ := parameters["keep_end"].(float64)
		return s.maskPartial(value, int(keepStart), int(keepEnd))
	default:
		return s.maskGeneric(value)
	}
}

// maskEmail masks an email address
func (s *FieldPermissionService) maskEmail(email string) string {
	parts := strings.Split(email, "@")
	if len(parts) != 2 {
		return "***"
	}

	username := parts[0]
	domain := parts[1]

	if len(username) <= 2 {
		return "**@" + domain
	}

	return username[:1] + strings.Repeat("*", len(username)-2) + username[len(username)-1:] + "@" + domain
}

// maskPhone masks a phone number
func (s *FieldPermissionService) maskPhone(phone string) string {
	if len(phone) <= 4 {
		return strings.Repeat("*", len(phone))
	}
	return strings.Repeat("*", len(phone)-4) + phone[len(phone)-4:]
}

// maskPartial masks part of a string, keeping specified characters at start and end
func (s *FieldPermissionService) maskPartial(value string, keepStart, keepEnd int) string {
	if len(value) <= keepStart+keepEnd {
		return strings.Repeat("*", len(value))
	}

	start := value[:keepStart]
	end := value[len(value)-keepEnd:]
	middle := strings.Repeat("*", len(value)-keepStart-keepEnd)

	return start + middle + end
}

// maskGeneric provides generic masking
func (s *FieldPermissionService) maskGeneric(value string) string {
	if len(value) <= 2 {
		return strings.Repeat("*", len(value))
	}
	return value[:1] + strings.Repeat("*", len(value)-2) + value[len(value)-1:]
}

// EvaluateFieldAccess evaluates field access based on conditions
func (s *FieldPermissionService) EvaluateFieldAccess(tableName, schemaName, fieldName string, userContext *APISecurityContext) (*FieldAccessResult, error) {
	config, err := s.GetFieldPermission(tableName, schemaName, fieldName)
	if err != nil {
		// If no configuration exists, allow access
		return &FieldAccessResult{
			CanRead:  true,
			CanWrite: true,
			Action:   "allow",
		}, nil
	}

	result := &FieldAccessResult{
		CanRead:  s.hasRoleAccess(userContext.UserRoles, config.Permissions.ReadRoles),
		CanWrite: s.hasRoleAccess(userContext.UserRoles, config.Permissions.WriteRoles),
		Action:   "allow",
	}

	// Evaluate access conditions
	for _, condition := range config.Permissions.Conditions {
		if s.evaluateCondition(condition, userContext) {
			switch condition.Action {
			case "deny":
				result.CanRead = false
				result.CanWrite = false
				result.Action = "deny"
			case "mask":
				result.Action = "mask"
			case "encrypt":
				result.Action = "encrypt"
			}
		}
	}

	return result, nil
}

// FieldAccessResult represents the result of field access evaluation
type FieldAccessResult struct {
	CanRead  bool   `json:"can_read"`
	CanWrite bool   `json:"can_write"`
	Action   string `json:"action"` // allow, deny, mask, encrypt
}

// hasRoleAccess checks if user roles have access
func (s *FieldPermissionService) hasRoleAccess(userRoles, requiredRoles []string) bool {
	if len(requiredRoles) == 0 {
		return true // No restrictions
	}

	for _, userRole := range userRoles {
		for _, requiredRole := range requiredRoles {
			if userRole == requiredRole {
				return true
			}
		}
	}

	return false
}

// evaluateCondition evaluates an access condition
func (s *FieldPermissionService) evaluateCondition(condition FieldAccessCondition, userContext *APISecurityContext) bool {
	switch condition.Type {
	case "time":
		return s.evaluateTimeCondition(condition.Condition, userContext)
	case "ip":
		return s.evaluateIPCondition(condition.Condition, userContext)
	case "role":
		return s.evaluateRoleCondition(condition.Condition, userContext)
	case "custom":
		return s.evaluateCustomCondition(condition.Condition, userContext)
	default:
		return false
	}
}

// evaluateTimeCondition evaluates time-based conditions
func (s *FieldPermissionService) evaluateTimeCondition(condition string, userContext *APISecurityContext) bool {
	// This would implement time-based condition evaluation
	// For now, return false as placeholder
	return false
}

// evaluateIPCondition evaluates IP-based conditions
func (s *FieldPermissionService) evaluateIPCondition(condition string, userContext *APISecurityContext) bool {
	// This would implement IP-based condition evaluation
	// For now, return false as placeholder
	return false
}

// evaluateRoleCondition evaluates role-based conditions
func (s *FieldPermissionService) evaluateRoleCondition(condition string, userContext *APISecurityContext) bool {
	// This would implement role-based condition evaluation
	// For now, return false as placeholder
	return false
}

// evaluateCustomCondition evaluates custom conditions
func (s *FieldPermissionService) evaluateCustomCondition(condition string, userContext *APISecurityContext) bool {
	// This would implement custom condition evaluation using an expression engine
	// For now, return false as placeholder
	return false
}

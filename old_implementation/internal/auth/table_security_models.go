package auth

import (
	"encoding/json"
	"time"
)

// Note: UserAdminRole is defined in rbac_engine.go
// Note: TableSecurityConfig is defined in policy_engine.go
// Note: APISecurityConfig is defined in policy_engine.go
// Note: RateLimitConfig is defined in policy_engine.go
// Note: TimeBasedAccessConfig is defined in policy_engine.go
// Note: FieldPermission is defined in policy_engine.go

// AdminCapability represents individual capability assignments
type AdminCapability struct {
	ID              string    `json:"id" db:"id"`
	RoleID          string    `json:"role_id" db:"role_id"`
	CapabilityName  string    `json:"capability_name" db:"capability_name"`
	CapabilityValue bool      `json:"capability_value" db:"capability_value"`
	ResourceScope   JSONBMap  `json:"resource_scope" db:"resource_scope"`
	CreatedAt       time.Time `json:"created_at" db:"created_at"`
	UpdatedAt       time.Time `json:"updated_at" db:"updated_at"`
}

// TableConfigurationTemplate represents predefined security templates
type TableConfigurationTemplate struct {
	ID          string               `json:"id"`
	Name        string               `json:"name"`
	Description string               `json:"description"`
	Category    string               `json:"category"`
	Config      *TableSecurityConfig `json:"config"`
	IsBuiltIn   bool                 `json:"is_built_in"`
	CreatedBy   *string              `json:"created_by"`
	CreatedAt   time.Time            `json:"created_at"`
}

// TableConfigurationVersion represents configuration versioning
type TableConfigurationVersion struct {
	ID           string               `json:"id"`
	ConfigID     string               `json:"config_id"`
	Version      int                  `json:"version"`
	Config       *TableSecurityConfig `json:"config"`
	ChangeReason string               `json:"change_reason"`
	ChangedBy    string               `json:"changed_by"`
	CreatedAt    time.Time            `json:"created_at"`
}

// CreateTableSecurityConfigRequest represents a request to create table security config
type CreateTableSecurityConfigRequest struct {
	TableName   string             `json:"table_name" validate:"required"`
	SchemaName  string             `json:"schema_name"`
	DisplayName *string            `json:"display_name"`
	Description *string            `json:"description"`
	Config      *APISecurityConfig `json:"config" validate:"required"`
}

// UpdateTableSecurityConfigRequest represents a request to update table security config
type UpdateTableSecurityConfigRequest struct {
	DisplayName   *string            `json:"display_name"`
	Description   *string            `json:"description"`
	Config        *APISecurityConfig `json:"config"`
	ChangeReason  string             `json:"change_reason"`
	CreateVersion bool               `json:"create_version"`
}

// TableSecurityConfigFilter represents filters for querying table configurations
type TableSecurityConfigFilter struct {
	TableName   *string `json:"table_name"`
	SchemaName  *string `json:"schema_name"`
	IsActive    *bool   `json:"is_active"`
	CreatedBy   *string `json:"created_by"`
	RequireAuth *bool   `json:"require_auth"`
	Limit       int     `json:"limit"`
	Offset      int     `json:"offset"`
}

// ValidationResult represents the result of configuration validation
type ValidationResult struct {
	IsValid   bool                    `json:"is_valid"`
	Errors    []ValidationError       `json:"errors"`
	Warnings  []ValidationWarning     `json:"warnings"`
	Conflicts []ConfigurationConflict `json:"conflicts"`
}

// ValidationError represents a validation error
type ValidationError struct {
	Field   string `json:"field"`
	Code    string `json:"code"`
	Message string `json:"message"`
}

// ValidationWarning represents a validation warning
type ValidationWarning struct {
	Field   string `json:"field"`
	Code    string `json:"code"`
	Message string `json:"message"`
}

// ConfigurationConflict represents a configuration conflict
type ConfigurationConflict struct {
	Type        string `json:"type"`
	Description string `json:"description"`
	Severity    string `json:"severity"`
	Resolution  string `json:"resolution"`
}

// JSONBMap is a helper type for JSONB fields
type JSONBMap map[string]interface{}

// Scan implements the sql.Scanner interface for JSONBMap
func (j *JSONBMap) Scan(value interface{}) error {
	if value == nil {
		*j = make(map[string]interface{})
		return nil
	}

	switch v := value.(type) {
	case []byte:
		return json.Unmarshal(v, j)
	case string:
		return json.Unmarshal([]byte(v), j)
	default:
		*j = make(map[string]interface{})
		return nil
	}
}

// Value implements the driver.Valuer interface for JSONBMap
func (j JSONBMap) Value() (interface{}, error) {
	if j == nil {
		return "{}", nil
	}
	return json.Marshal(j)
}

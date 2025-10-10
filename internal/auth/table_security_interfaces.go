package auth

import "time"

// TableSecurityConfigRepository interface for table security configuration data access
type TableSecurityConfigRepository interface {
	// Configuration CRUD operations
	CreateTableSecurityConfig(config *TableSecurityConfig) error
	GetTableSecurityConfig(tableName, schemaName string) (*TableSecurityConfig, error)
	GetTableSecurityConfigByID(id string) (*TableSecurityConfig, error)
	UpdateTableSecurityConfig(id string, config *TableSecurityConfig, updatedBy string) error
	DeleteTableSecurityConfig(id string, deletedBy string) error
	ListTableSecurityConfigs(filter *TableSecurityConfigFilter) ([]*TableSecurityConfig, error)

	// Validation and conflict detection
	ValidateTableSecurityConfig(config *TableSecurityConfig) *ValidationResult

	// Template management
	CreateConfigurationTemplate(template *TableConfigurationTemplate) error
	GetConfigurationTemplates(category string) ([]*TableConfigurationTemplate, error)

	// Version management
	GetConfigurationVersions(configID string) ([]*TableConfigurationVersion, error)
	RollbackToVersion(configID string, version int, rolledBackBy string) error

	// Utility functions
	GenerateConfigHash(config *TableSecurityConfig) (string, error)
}

// TableSecurityConfigService interface for table security configuration business logic
type TableSecurityConfigService interface {
	// Configuration management
	CreateTableSecurityConfig(req *CreateTableSecurityConfigRequest, createdBy string) (*TableSecurityConfig, error)
	GetTableSecurityConfig(tableName, schemaName string) (*TableSecurityConfig, error)
	UpdateTableSecurityConfig(id string, req *UpdateTableSecurityConfigRequest, updatedBy string) (*TableSecurityConfig, error)
	DeleteTableSecurityConfig(id string, deletedBy string) error
	ListTableSecurityConfigs(filter *TableSecurityConfigFilter) ([]*TableSecurityConfig, error)

	// Template operations
	CreateFromTemplate(templateID, tableName, schemaName string, createdBy string) (*TableSecurityConfig, error)
	GetConfigurationTemplates(category string) ([]*TableConfigurationTemplate, error)

	// Version management
	GetConfigurationVersions(configID string) ([]*TableConfigurationVersion, error)
	RollbackToVersion(configID string, version int, rolledBackBy string) error

	// Validation and utilities
	ValidateTableSecurityConfig(config *TableSecurityConfig) *ValidationResult
	GetSecurityConfigForTable(tableName, schemaName string) (*APISecurityConfig, error)
	GetTableSecuritySummary() (map[string]interface{}, error)
}

// APISecurityEnforcer interface for enforcing API security policies
type APISecurityEnforcer interface {
	// Request validation
	ValidateRequest(tableName, schemaName, method string, userContext *APISecurityContext) (*SecurityDecision, error)

	// Field-level security
	FilterReadableFields(tableName, schemaName string, data map[string]interface{}, userContext *APISecurityContext) (map[string]interface{}, error)
	ValidateWritableFields(tableName, schemaName string, data map[string]interface{}, userContext *APISecurityContext) error

	// Ownership validation
	ValidateOwnership(tableName, schemaName string, resourceID string, userContext *APISecurityContext) error

	// Custom filters
	ApplyCustomFilters(tableName, schemaName string, query *SQLQuery, userContext *APISecurityContext) (*SQLQuery, error)

	// Rate limiting
	CheckRateLimit(tableName, schemaName string, userContext *APISecurityContext) error

	// IP and time-based access
	ValidateIPAccess(tableName, schemaName string, ipAddress string) error
	ValidateTimeBasedAccess(tableName, schemaName string) error
}

// FieldPermissionManager interface for field-level permissions
type FieldPermissionManager interface {
	// Field visibility
	GetReadableFields(tableName, schemaName string, userRoles []string) ([]string, error)
	GetWritableFields(tableName, schemaName string, userRoles []string) ([]string, error)
	GetHiddenFields(tableName, schemaName string, userRoles []string) ([]string, error)

	// Field masking and encryption
	MaskPIIFields(tableName, schemaName string, data map[string]interface{}, userRoles []string) (map[string]interface{}, error)
	EncryptSensitiveFields(tableName, schemaName string, data map[string]interface{}) (map[string]interface{}, error)
	DecryptSensitiveFields(tableName, schemaName string, data map[string]interface{}, userRoles []string) (map[string]interface{}, error)

	// Dynamic field permissions
	EvaluateFieldPermission(tableName, schemaName, fieldName string, operation string, userContext *APISecurityContext) (bool, error)
}

// Note: SecurityContext is defined in admin_auth_core.go

// SecurityDecision represents the result of a security evaluation
type SecurityDecision struct {
	Allowed       bool                   `json:"allowed"`
	Reason        string                 `json:"reason"`
	RequiredRoles []string               `json:"required_roles,omitempty"`
	RequiresMFA   bool                   `json:"requires_mfa"`
	RateLimited   bool                   `json:"rate_limited"`
	Restrictions  map[string]interface{} `json:"restrictions,omitempty"`
	Warnings      []string               `json:"warnings,omitempty"`
}

// Note: SQLQuery is defined in policy_engine.go

// TableMetadata represents metadata about a database table
type TableMetadata struct {
	TableName   string               `json:"table_name"`
	SchemaName  string               `json:"schema_name"`
	Columns     []ColumnMetadata     `json:"columns"`
	Indexes     []IndexMetadata      `json:"indexes"`
	Constraints []ConstraintMetadata `json:"constraints"`
	Permissions []PermissionMetadata `json:"permissions"`
}

// ColumnMetadata represents metadata about a table column
type ColumnMetadata struct {
	ColumnName   string `json:"column_name"`
	DataType     string `json:"data_type"`
	IsNullable   bool   `json:"is_nullable"`
	DefaultValue string `json:"default_value,omitempty"`
	IsPrimaryKey bool   `json:"is_primary_key"`
	IsForeignKey bool   `json:"is_foreign_key"`
	IsUnique     bool   `json:"is_unique"`
	MaxLength    int    `json:"max_length,omitempty"`
}

// IndexMetadata represents metadata about a table index
type IndexMetadata struct {
	IndexName string   `json:"index_name"`
	Columns   []string `json:"columns"`
	IsUnique  bool     `json:"is_unique"`
	IndexType string   `json:"index_type"`
}

// ConstraintMetadata represents metadata about table constraints
type ConstraintMetadata struct {
	ConstraintName    string   `json:"constraint_name"`
	ConstraintType    string   `json:"constraint_type"`
	Columns           []string `json:"columns"`
	ReferencedTable   string   `json:"referenced_table,omitempty"`
	ReferencedColumns []string `json:"referenced_columns,omitempty"`
}

// PermissionMetadata represents metadata about table permissions
type PermissionMetadata struct {
	Grantee     string   `json:"grantee"`
	Privileges  []string `json:"privileges"`
	Grantor     string   `json:"grantor"`
	IsGrantable bool     `json:"is_grantable"`
}

// ConfigurationValidator interface for validating table security configurations
type ConfigurationValidator interface {
	ValidateConfiguration(config *TableSecurityConfig) *ValidationResult
	ValidateFieldPermissions(tableName, schemaName string, permissions map[string]FieldPermission) *ValidationResult
	ValidateRateLimitConfig(config *RateLimitConfig) *ValidationResult
	ValidateTimeBasedAccessConfig(config *TimeBasedAccessConfig) *ValidationResult
	ValidateCustomFilters(filters map[string]string) *ValidationResult
	CheckConfigurationConflicts(config *TableSecurityConfig) []ConfigurationConflict
}

// SecurityPolicyEngine interface for dynamic security policy evaluation
type SecurityPolicyEngine interface {
	EvaluatePolicy(policyName string, context *SecurityContext, resource map[string]interface{}) (*SecurityDecision, error)
	CreatePolicy(policy *SecurityPolicy) error
	UpdatePolicy(policyID string, policy *SecurityPolicy) error
	DeletePolicy(policyID string) error
	ListPolicies(filter *PolicyFilter) ([]*SecurityPolicy, error)
	TestPolicy(policy *SecurityPolicy, testCases []*PolicyTestCase) ([]*PolicyTestResult, error)
}

// Note: SecurityPolicy is defined in rbac_engine.go

// SecurityRule represents a rule within a security policy
type SecurityRule struct {
	ID         string                 `json:"id"`
	Name       string                 `json:"name"`
	Condition  string                 `json:"condition"` // Expression to evaluate
	Action     string                 `json:"action"`    // ALLOW, DENY, REQUIRE_MFA, etc.
	Parameters map[string]interface{} `json:"parameters"`
	Priority   int                    `json:"priority"`
	IsActive   bool                   `json:"is_active"`
}

// PolicyFilter represents filters for querying security policies
type PolicyFilter struct {
	Type     *string `json:"type"`
	Scope    *string `json:"scope"`
	IsActive *bool   `json:"is_active"`
	Limit    int     `json:"limit"`
	Offset   int     `json:"offset"`
}

// PolicyTestCase represents a test case for policy validation
type PolicyTestCase struct {
	Name        string                 `json:"name"`
	Context     *SecurityContext       `json:"context"`
	Resource    map[string]interface{} `json:"resource"`
	Expected    *SecurityDecision      `json:"expected"`
	Description string                 `json:"description"`
}

// PolicyTestResult represents the result of a policy test
type PolicyTestResult struct {
	TestCase *PolicyTestCase   `json:"test_case"`
	Actual   *SecurityDecision `json:"actual"`
	Passed   bool              `json:"passed"`
	Error    string            `json:"error,omitempty"`
}

// TableSecurityManager interface for comprehensive table security management
type TableSecurityManager interface {
	// Configuration management
	TableSecurityConfigService

	// Security enforcement
	APISecurityEnforcer

	// Field-level permissions
	FieldPermissionManager

	// Policy management
	SecurityPolicyEngine

	// Validation
	ConfigurationValidator

	// Metadata and introspection
	GetTableMetadata(tableName, schemaName string) (*TableMetadata, error)
	GetSecurityStatus(tableName, schemaName string) (map[string]interface{}, error)
	GetSecurityRecommendations(tableName, schemaName string) ([]SecurityRecommendation, error)
}

// SecurityRecommendation represents a security recommendation for a table
type SecurityRecommendation struct {
	Type        string `json:"type"`     // SECURITY, PERFORMANCE, COMPLIANCE
	Severity    string `json:"severity"` // LOW, MEDIUM, HIGH, CRITICAL
	Title       string `json:"title"`
	Description string `json:"description"`
	Action      string `json:"action"`
	Impact      string `json:"impact"`
	Effort      string `json:"effort"` // LOW, MEDIUM, HIGH
}

// SecurityMetrics interface for security metrics and monitoring
type SecurityMetrics interface {
	RecordSecurityEvent(event *SecurityEvent) error
	GetSecurityMetrics(filter *MetricsFilter) (*SecurityMetricsData, error)
	GetSecurityTrends(period string) (*SecurityTrendsData, error)
	GetTopSecurityIssues(limit int) ([]*SecurityIssue, error)
	GenerateSecurityReport(reportType string, parameters map[string]interface{}) (*SecurityReport, error)
}

// SecurityEvent represents a security-related event
type SecurityEvent struct {
	ID         string                 `json:"id"`
	Type       string                 `json:"type"`
	Severity   string                 `json:"severity"`
	TableName  string                 `json:"table_name"`
	SchemaName string                 `json:"schema_name"`
	UserID     string                 `json:"user_id"`
	Action     string                 `json:"action"`
	Resource   string                 `json:"resource"`
	IPAddress  string                 `json:"ip_address"`
	UserAgent  string                 `json:"user_agent"`
	Details    map[string]interface{} `json:"details"`
	Timestamp  time.Time              `json:"timestamp"`
}

// MetricsFilter represents filters for security metrics queries
type MetricsFilter struct {
	StartTime  *time.Time `json:"start_time"`
	EndTime    *time.Time `json:"end_time"`
	TableName  *string    `json:"table_name"`
	SchemaName *string    `json:"schema_name"`
	EventType  *string    `json:"event_type"`
	Severity   *string    `json:"severity"`
	UserID     *string    `json:"user_id"`
	Limit      int        `json:"limit"`
	Offset     int        `json:"offset"`
}

// SecurityMetricsData represents aggregated security metrics
type SecurityMetricsData struct {
	TotalEvents      int                      `json:"total_events"`
	EventsByType     map[string]int           `json:"events_by_type"`
	EventsBySeverity map[string]int           `json:"events_by_severity"`
	EventsByTable    map[string]int           `json:"events_by_table"`
	TopUsers         []UserMetric             `json:"top_users"`
	TopTables        []TableMetric            `json:"top_tables"`
	SecurityScore    float64                  `json:"security_score"`
	Recommendations  []SecurityRecommendation `json:"recommendations"`
}

// SecurityTrendsData represents security trends over time
type SecurityTrendsData struct {
	Period     string                 `json:"period"`
	DataPoints []TrendDataPoint       `json:"data_points"`
	Summary    map[string]interface{} `json:"summary"`
}

// TrendDataPoint represents a single data point in a trend
type TrendDataPoint struct {
	Timestamp time.Time              `json:"timestamp"`
	Metrics   map[string]interface{} `json:"metrics"`
}

// UserMetric represents user-specific security metrics
type UserMetric struct {
	UserID       string    `json:"user_id"`
	EventCount   int       `json:"event_count"`
	RiskScore    float64   `json:"risk_score"`
	LastActivity time.Time `json:"last_activity"`
}

// TableMetric represents table-specific security metrics
type TableMetric struct {
	TableName   string  `json:"table_name"`
	SchemaName  string  `json:"schema_name"`
	EventCount  int     `json:"event_count"`
	RiskScore   float64 `json:"risk_score"`
	ConfigScore float64 `json:"config_score"`
}

// SecurityIssue represents a security issue or vulnerability
type SecurityIssue struct {
	ID          string                 `json:"id"`
	Type        string                 `json:"type"`
	Severity    string                 `json:"severity"`
	Title       string                 `json:"title"`
	Description string                 `json:"description"`
	TableName   string                 `json:"table_name"`
	SchemaName  string                 `json:"schema_name"`
	Count       int                    `json:"count"`
	FirstSeen   time.Time              `json:"first_seen"`
	LastSeen    time.Time              `json:"last_seen"`
	Status      string                 `json:"status"` // OPEN, INVESTIGATING, RESOLVED, IGNORED
	AssignedTo  string                 `json:"assigned_to"`
	Resolution  string                 `json:"resolution"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// SecurityReport represents a generated security report
type SecurityReport struct {
	ID          string                 `json:"id"`
	Type        string                 `json:"type"`
	Title       string                 `json:"title"`
	Description string                 `json:"description"`
	GeneratedAt time.Time              `json:"generated_at"`
	GeneratedBy string                 `json:"generated_by"`
	Period      string                 `json:"period"`
	Data        map[string]interface{} `json:"data"`
	Format      string                 `json:"format"` // JSON, PDF, CSV, etc.
	Status      string                 `json:"status"` // GENERATING, COMPLETED, FAILED
}

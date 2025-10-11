package database

import (
	"time"
)

// SQLSecurityService provides comprehensive SQL security validation and execution
type SQLSecurityService interface {
	ValidateQuery(query string, userRoles []string, context SecurityContext) (*ValidationResult, error)
	ExecuteSecureQuery(query string, userID string, timeout time.Duration) (*SQLQueryResult, error)
	CheckQueryPermissions(query string, userCapabilities AdminCapabilities) error
	AnalyzeQuery(query string) (*QueryAnalysis, error)
	DetectDangerousOperations(query string) ([]SecurityWarning, error)
	EstimateQueryImpact(query string) (*ImpactAssessment, error)
}

// SQLValidator handles SQL query parsing and validation
type SQLValidator interface {
	ParseQuery(query string) (*ParsedQuery, error)
	ValidateOperations(operations []SQLOperation, allowedOps []string) error
	CheckForbiddenPatterns(query string, patterns []string) ([]PatternMatch, error)
	ValidateTableAccess(tables []string, userPermissions []TablePermission) error
}

// QueryExecutor handles secure SQL query execution
type QueryExecutor interface {
	ExecuteWithTimeout(query string, timeout time.Duration) (*SQLQueryResult, error)
	ExecuteTransaction(queries []string, timeout time.Duration) (*TransactionResult, error)
	CancelQuery(queryID string) error
	GetRunningQueries(userID string) ([]RunningQuery, error)
}

// SecurityContext provides context for security decisions
type SecurityContext struct {
	UserID    string
	IPAddress string
	UserAgent string
	SessionID string
	RequestID string
	Timestamp time.Time
}

// AdminCapabilities defines what an admin can do
type AdminCapabilities struct {
	CanAccessSQL        bool     `json:"can_access_sql"`
	CanManageDatabase   bool     `json:"can_manage_database"`
	CanManageSystem     bool     `json:"can_manage_system"`
	CanCreateSuperAdmin bool     `json:"can_create_super_admin"`
	CanCreateAdmins     bool     `json:"can_create_admins"`
	CanManageAllTables  bool     `json:"can_manage_all_tables"`
	CanManageAuth       bool     `json:"can_manage_auth"`
	CanManageStorage    bool     `json:"can_manage_storage"`
	CanViewAllLogs      bool     `json:"can_view_all_logs"`
	CanManageUsers      bool     `json:"can_manage_users"`
	CanManageContent    bool     `json:"can_manage_content"`
	AssignedTables      []string `json:"assigned_tables"`
	AssignedUserGroups  []string `json:"assigned_user_groups"`
	CanViewReports      bool     `json:"can_view_reports"`
	CanModerateContent  bool     `json:"can_moderate_content"`
	CanViewBasicLogs    bool     `json:"can_view_basic_logs"`
	CanViewDashboard    bool     `json:"can_view_dashboard"`
	CanExportData       bool     `json:"can_export_data"`
}

// ValidationResult contains the result of SQL validation
type ValidationResult struct {
	IsValid          bool              `json:"is_valid"`
	Errors           []ValidationError `json:"errors,omitempty"`
	Warnings         []SecurityWarning `json:"warnings,omitempty"`
	RequiresMFA      bool              `json:"requires_mfa"`
	RequiresApproval bool              `json:"requires_approval"`
	RiskLevel        RiskLevel         `json:"risk_level"`
	EstimatedImpact  *ImpactAssessment `json:"estimated_impact,omitempty"`
}

// ValidationError represents a validation error
type ValidationError struct {
	Code       string                 `json:"code"`
	Message    string                 `json:"message"`
	Position   int                    `json:"position,omitempty"`
	Suggestion string                 `json:"suggestion,omitempty"`
	Details    map[string]interface{} `json:"details,omitempty"`
}

// SecurityWarning represents a security warning
type SecurityWarning struct {
	Type       WarningType            `json:"type"`
	Severity   SecuritySeverity       `json:"severity"`
	Message    string                 `json:"message"`
	Position   int                    `json:"position,omitempty"`
	Suggestion string                 `json:"suggestion,omitempty"`
	Details    map[string]interface{} `json:"details,omitempty"`
}

// SQLQueryResult contains the result of query execution
type SQLQueryResult struct {
	QueryID       string                   `json:"query_id"`
	Success       bool                     `json:"success"`
	RowsAffected  int64                    `json:"rows_affected"`
	ExecutionTime time.Duration            `json:"execution_time"`
	Data          []map[string]interface{} `json:"data,omitempty"`
	Error         string                   `json:"error,omitempty"`
	Metadata      QueryMetadata            `json:"metadata"`
}

// QueryMetadata contains metadata about query execution
type QueryMetadata struct {
	TablesAccessed []string  `json:"tables_accessed"`
	OperationType  string    `json:"operation_type"`
	StartTime      time.Time `json:"start_time"`
	EndTime        time.Time `json:"end_time"`
	UserID         string    `json:"user_id"`
	IPAddress      string    `json:"ip_address"`
}

// TransactionResult contains the result of transaction execution
type TransactionResult struct {
	TransactionID string           `json:"transaction_id"`
	Success       bool             `json:"success"`
	Results       []SQLQueryResult `json:"results"`
	ExecutionTime time.Duration    `json:"execution_time"`
	Error         string           `json:"error,omitempty"`
}

// ParsedQuery represents a parsed SQL query
type ParsedQuery struct {
	OriginalQuery string         `json:"original_query"`
	QueryType     QueryType      `json:"query_type"`
	Operations    []SQLOperation `json:"operations"`
	Tables        []string       `json:"tables"`
	Columns       []string       `json:"columns"`
	Conditions    []string       `json:"conditions"`
	HasSubqueries bool           `json:"has_subqueries"`
	IsDangerous   bool           `json:"is_dangerous"`
}

// SQLOperation represents a SQL operation
type SQLOperation struct {
	Type        OperationType `json:"type"`
	Target      string        `json:"target"`
	Action      string        `json:"action"`
	RiskLevel   RiskLevel     `json:"risk_level"`
	Description string        `json:"description"`
}

// PatternMatch represents a forbidden pattern match
type PatternMatch struct {
	Pattern     string           `json:"pattern"`
	Match       string           `json:"match"`
	Position    int              `json:"position"`
	Severity    SecuritySeverity `json:"severity"`
	Description string           `json:"description"`
}

// TablePermission represents table-level permissions
type TablePermission struct {
	TableName   string                 `json:"table_name"`
	SchemaName  string                 `json:"schema_name"`
	Operations  []string               `json:"operations"`
	Conditions  []string               `json:"conditions,omitempty"`
	FieldAccess map[string]FieldAccess `json:"field_access,omitempty"`
}

// FieldAccess represents field-level access permissions
type FieldAccess struct {
	CanRead  bool `json:"can_read"`
	CanWrite bool `json:"can_write"`
}

// QueryAnalysis contains detailed query analysis
type QueryAnalysis struct {
	Complexity     ComplexityLevel     `json:"complexity"`
	EstimatedCost  int64               `json:"estimated_cost"`
	TablesAccessed []string            `json:"tables_accessed"`
	IndexesUsed    []string            `json:"indexes_used"`
	Joins          []JoinInfo          `json:"joins"`
	Aggregations   []string            `json:"aggregations"`
	SecurityRisks  []SecurityRisk      `json:"security_risks"`
	Performance    PerformanceAnalysis `json:"performance"`
}

// ImpactAssessment represents the potential impact of a query
type ImpactAssessment struct {
	DataImpact        DataImpactLevel        `json:"data_impact"`
	PerformanceImpact PerformanceImpactLevel `json:"performance_impact"`
	SecurityImpact    SecurityImpactLevel    `json:"security_impact"`
	EstimatedRows     int64                  `json:"estimated_rows"`
	AffectedTables    []string               `json:"affected_tables"`
	RequiresBackup    bool                   `json:"requires_backup"`
	Reversible        bool                   `json:"reversible"`
}

// RunningQuery represents a currently executing query
type RunningQuery struct {
	QueryID     string        `json:"query_id"`
	UserID      string        `json:"user_id"`
	Query       string        `json:"query"`
	StartTime   time.Time     `json:"start_time"`
	ElapsedTime time.Duration `json:"elapsed_time"`
	Status      QueryStatus   `json:"status"`
	CanCancel   bool          `json:"can_cancel"`
}

// Enums and constants
type QueryType string

const (
	QueryTypeSelect QueryType = "SELECT"
	QueryTypeInsert QueryType = "INSERT"
	QueryTypeUpdate QueryType = "UPDATE"
	QueryTypeDelete QueryType = "DELETE"
	QueryTypeCreate QueryType = "CREATE"
	QueryTypeDrop   QueryType = "DROP"
	QueryTypeAlter  QueryType = "ALTER"
	QueryTypeGrant  QueryType = "GRANT"
	QueryTypeRevoke QueryType = "REVOKE"
	QueryTypeOther  QueryType = "OTHER"
)

type OperationType string

const (
	OpTypeRead   OperationType = "READ"
	OpTypeWrite  OperationType = "WRITE"
	OpTypeSchema OperationType = "SCHEMA"
	OpTypeAdmin  OperationType = "ADMIN"
)

type RiskLevel string

const (
	RiskLevelLow      RiskLevel = "LOW"
	RiskLevelMedium   RiskLevel = "MEDIUM"
	RiskLevelHigh     RiskLevel = "HIGH"
	RiskLevelCritical RiskLevel = "CRITICAL"
)

type SecuritySeverity string

const (
	SeverityLow      SecuritySeverity = "LOW"
	SeverityMedium   SecuritySeverity = "MEDIUM"
	SeverityHigh     SecuritySeverity = "HIGH"
	SeverityCritical SecuritySeverity = "CRITICAL"
)

type WarningType string

const (
	WarningTypeDangerous   WarningType = "DANGEROUS_OPERATION"
	WarningTypePerformance WarningType = "PERFORMANCE_RISK"
	WarningTypeSecurity    WarningType = "SECURITY_RISK"
	WarningTypeCompliance  WarningType = "COMPLIANCE_RISK"
)

type ComplexityLevel string

const (
	ComplexityLow    ComplexityLevel = "LOW"
	ComplexityMedium ComplexityLevel = "MEDIUM"
	ComplexityHigh   ComplexityLevel = "HIGH"
)

type DataImpactLevel string

const (
	DataImpactNone   DataImpactLevel = "NONE"
	DataImpactLow    DataImpactLevel = "LOW"
	DataImpactMedium DataImpactLevel = "MEDIUM"
	DataImpactHigh   DataImpactLevel = "HIGH"
)

type PerformanceImpactLevel string

const (
	PerformanceImpactNone   PerformanceImpactLevel = "NONE"
	PerformanceImpactLow    PerformanceImpactLevel = "LOW"
	PerformanceImpactMedium PerformanceImpactLevel = "MEDIUM"
	PerformanceImpactHigh   PerformanceImpactLevel = "HIGH"
)

type SecurityImpactLevel string

const (
	SecurityImpactNone   SecurityImpactLevel = "NONE"
	SecurityImpactLow    SecurityImpactLevel = "LOW"
	SecurityImpactMedium SecurityImpactLevel = "MEDIUM"
	SecurityImpactHigh   SecurityImpactLevel = "HIGH"
)

type QueryStatus string

const (
	QueryStatusRunning   QueryStatus = "RUNNING"
	QueryStatusCompleted QueryStatus = "COMPLETED"
	QueryStatusFailed    QueryStatus = "FAILED"
	QueryStatusCancelled QueryStatus = "CANCELLED"
)

// Additional supporting types
type JoinInfo struct {
	Type   string   `json:"type"`
	Tables []string `json:"tables"`
}

type SecurityRisk struct {
	Type        string           `json:"type"`
	Severity    SecuritySeverity `json:"severity"`
	Description string           `json:"description"`
}

type PerformanceAnalysis struct {
	EstimatedExecutionTime time.Duration `json:"estimated_execution_time"`
	MemoryUsage            int64         `json:"memory_usage"`
	CPUIntensive           bool          `json:"cpu_intensive"`
	IOIntensive            bool          `json:"io_intensive"`
}

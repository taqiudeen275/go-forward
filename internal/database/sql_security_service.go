package database

import (
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

// sqlSecurityService implements the SQLSecurityService interface
type sqlSecurityService struct {
	db        *sql.DB
	validator SQLValidator
	executor  QueryExecutor
	auditLog  AuditLogger
	config    *SQLSecurityConfig
}

// SQLSecurityConfig contains configuration for SQL security
type SQLSecurityConfig struct {
	MaxQueryTimeout      time.Duration       `json:"max_query_timeout"`
	MaxConcurrentQueries int                 `json:"max_concurrent_queries"`
	EnableAuditLogging   bool                `json:"enable_audit_logging"`
	RequireMFAForDDL     bool                `json:"require_mfa_for_ddl"`
	AllowedOperations    map[string][]string `json:"allowed_operations"` // role -> operations
	ForbiddenPatterns    []string            `json:"forbidden_patterns"`
	SystemTablesAccess   map[string]bool     `json:"system_tables_access"` // role -> allowed
}

// AuditLogger interface for SQL audit logging
type AuditLogger interface {
	LogSQLExecution(event SQLAuditEvent) error
	LogSecurityViolation(event SecurityViolationEvent) error
}

// SQLAuditEvent represents a SQL execution audit event
type SQLAuditEvent struct {
	EventID        string                 `json:"event_id"`
	UserID         string                 `json:"user_id"`
	Query          string                 `json:"query"`
	QueryType      QueryType              `json:"query_type"`
	TablesAccessed []string               `json:"tables_accessed"`
	Success        bool                   `json:"success"`
	ExecutionTime  time.Duration          `json:"execution_time"`
	RowsAffected   int64                  `json:"rows_affected"`
	Error          string                 `json:"error,omitempty"`
	IPAddress      string                 `json:"ip_address"`
	UserAgent      string                 `json:"user_agent"`
	SessionID      string                 `json:"session_id"`
	Timestamp      time.Time              `json:"timestamp"`
	RiskLevel      RiskLevel              `json:"risk_level"`
	Metadata       map[string]interface{} `json:"metadata,omitempty"`
}

// SecurityViolationEvent represents a security violation
type SecurityViolationEvent struct {
	EventID       string                 `json:"event_id"`
	UserID        string                 `json:"user_id"`
	ViolationType string                 `json:"violation_type"`
	Query         string                 `json:"query"`
	Reason        string                 `json:"reason"`
	Severity      SecuritySeverity       `json:"severity"`
	IPAddress     string                 `json:"ip_address"`
	UserAgent     string                 `json:"user_agent"`
	SessionID     string                 `json:"session_id"`
	Timestamp     time.Time              `json:"timestamp"`
	Metadata      map[string]interface{} `json:"metadata,omitempty"`
}

// NewSQLSecurityService creates a new SQL security service
func NewSQLSecurityService(db *sql.DB, config *SQLSecurityConfig, auditLog AuditLogger) SQLSecurityService {
	return &sqlSecurityService{
		db:        db,
		validator: NewSQLValidator(),
		executor:  NewQueryExecutor(db),
		auditLog:  auditLog,
		config:    config,
	}
}

// ValidateQuery validates a SQL query against security policies
func (s *sqlSecurityService) ValidateQuery(query string, userRoles []string, context SecurityContext) (*ValidationResult, error) {
	result := &ValidationResult{
		IsValid:   true,
		Errors:    []ValidationError{},
		Warnings:  []SecurityWarning{},
		RiskLevel: RiskLevelLow,
	}

	// Parse the query
	parsed, err := s.validator.ParseQuery(query)
	if err != nil {
		result.IsValid = false
		result.Errors = append(result.Errors, ValidationError{
			Code:    "PARSE_ERROR",
			Message: fmt.Sprintf("Failed to parse query: %v", err),
		})
		return result, nil
	}

	// Check forbidden patterns
	patterns, err := s.validator.CheckForbiddenPatterns(query, s.config.ForbiddenPatterns)
	if err != nil {
		return nil, fmt.Errorf("error checking forbidden patterns: %v", err)
	}

	for _, pattern := range patterns {
		if pattern.Severity == SeverityCritical || pattern.Severity == SeverityHigh {
			result.IsValid = false
			result.Errors = append(result.Errors, ValidationError{
				Code:       "FORBIDDEN_PATTERN",
				Message:    pattern.Description,
				Position:   pattern.Position,
				Suggestion: "Remove or modify the forbidden operation",
			})
		} else {
			result.Warnings = append(result.Warnings, SecurityWarning{
				Type:       WarningTypeSecurity,
				Severity:   pattern.Severity,
				Message:    pattern.Description,
				Position:   pattern.Position,
				Suggestion: "Consider alternative approach",
			})
		}
	}

	// Validate operations against user roles
	allowedOps := s.getAllowedOperations(userRoles)
	if err := s.validator.ValidateOperations(parsed.Operations, allowedOps); err != nil {
		result.IsValid = false
		result.Errors = append(result.Errors, ValidationError{
			Code:    "OPERATION_NOT_ALLOWED",
			Message: err.Error(),
		})
	}

	// Check table access permissions
	userPermissions := s.getUserTablePermissions(userRoles)
	if err := s.validator.ValidateTableAccess(parsed.Tables, userPermissions); err != nil {
		result.IsValid = false
		result.Errors = append(result.Errors, ValidationError{
			Code:    "TABLE_ACCESS_DENIED",
			Message: err.Error(),
		})
	}

	// Assess risk level
	result.RiskLevel = s.assessQueryRiskLevel(parsed)

	// Check if MFA is required for high-risk operations
	if s.config.RequireMFAForDDL && s.isDDLOperation(parsed.QueryType) {
		result.RequiresMFA = true
	}

	// Check if approval is required for critical operations
	if result.RiskLevel == RiskLevelCritical {
		result.RequiresApproval = true
	}

	// Estimate query impact
	impact, err := s.EstimateQueryImpact(query)
	if err == nil {
		result.EstimatedImpact = impact
	}

	return result, nil
}

// ExecuteSecureQuery executes a SQL query with security controls
func (s *sqlSecurityService) ExecuteSecureQuery(query string, userID string, timeout time.Duration) (*SQLQueryResult, error) {
	queryID := uuid.New().String()
	startTime := time.Now()

	// Apply timeout limit
	if timeout > s.config.MaxQueryTimeout {
		timeout = s.config.MaxQueryTimeout
	}

	// Execute query
	result, err := s.executor.ExecuteWithTimeout(query, timeout)
	if err != nil {
		// Log failed execution
		if s.config.EnableAuditLogging {
			auditEvent := SQLAuditEvent{
				EventID:       queryID,
				UserID:        userID,
				Query:         query,
				Success:       false,
				ExecutionTime: time.Since(startTime),
				Error:         err.Error(),
				Timestamp:     startTime,
				RiskLevel:     s.assessQueryRiskLevelFromString(query),
			}
			s.auditLog.LogSQLExecution(auditEvent)
		}
		return nil, fmt.Errorf("query execution failed: %v", err)
	}

	// Update result with metadata
	result.QueryID = queryID
	result.Metadata = QueryMetadata{
		StartTime: startTime,
		EndTime:   time.Now(),
		UserID:    userID,
	}

	// Log successful execution
	if s.config.EnableAuditLogging {
		auditEvent := SQLAuditEvent{
			EventID:       queryID,
			UserID:        userID,
			Query:         query,
			Success:       true,
			ExecutionTime: result.ExecutionTime,
			RowsAffected:  result.RowsAffected,
			Timestamp:     startTime,
			RiskLevel:     s.assessQueryRiskLevelFromString(query),
		}
		s.auditLog.LogSQLExecution(auditEvent)
	}

	return result, nil
}

// CheckQueryPermissions checks if user has permissions for the query
func (s *sqlSecurityService) CheckQueryPermissions(query string, userCapabilities AdminCapabilities) error {
	parsed, err := s.validator.ParseQuery(query)
	if err != nil {
		return fmt.Errorf("failed to parse query: %v", err)
	}

	// Check SQL access capability
	if !userCapabilities.CanAccessSQL {
		return fmt.Errorf("user does not have SQL access capability")
	}

	// Check specific operation permissions
	for _, operation := range parsed.Operations {
		switch operation.Type {
		case OpTypeSchema:
			if !userCapabilities.CanManageDatabase {
				return fmt.Errorf("user does not have database management capability for %s operation", operation.Action)
			}
		case OpTypeAdmin:
			if !userCapabilities.CanManageSystem {
				return fmt.Errorf("user does not have system management capability for %s operation", operation.Action)
			}
		case OpTypeWrite:
			if operation.RiskLevel == RiskLevelCritical && !userCapabilities.CanManageDatabase {
				return fmt.Errorf("user does not have capability for critical write operation: %s", operation.Action)
			}
		}
	}

	// Check table-specific permissions
	if len(userCapabilities.AssignedTables) > 0 {
		for _, table := range parsed.Tables {
			allowed := false
			for _, assignedTable := range userCapabilities.AssignedTables {
				if table == assignedTable || strings.HasSuffix(table, "."+assignedTable) {
					allowed = true
					break
				}
			}
			if !allowed {
				return fmt.Errorf("user does not have access to table: %s", table)
			}
		}
	}

	return nil
}

// AnalyzeQuery performs detailed analysis of a SQL query
func (s *sqlSecurityService) AnalyzeQuery(query string) (*QueryAnalysis, error) {
	parsed, err := s.validator.ParseQuery(query)
	if err != nil {
		return nil, fmt.Errorf("failed to parse query: %v", err)
	}

	analysis := &QueryAnalysis{
		Complexity:     s.assessComplexity(parsed),
		TablesAccessed: parsed.Tables,
		SecurityRisks:  s.identifySecurityRisks(parsed),
		Performance:    s.analyzePerformance(parsed),
	}

	// Estimate cost (simplified)
	analysis.EstimatedCost = int64(len(parsed.Tables) * 100)
	if parsed.HasSubqueries {
		analysis.EstimatedCost *= 2
	}

	return analysis, nil
}

// DetectDangerousOperations detects potentially dangerous operations
func (s *sqlSecurityService) DetectDangerousOperations(query string) ([]SecurityWarning, error) {
	var warnings []SecurityWarning

	parsed, err := s.validator.ParseQuery(query)
	if err != nil {
		return warnings, fmt.Errorf("failed to parse query: %v", err)
	}

	// Check for dangerous operations
	for _, operation := range parsed.Operations {
		if operation.RiskLevel == RiskLevelHigh || operation.RiskLevel == RiskLevelCritical {
			warnings = append(warnings, SecurityWarning{
				Type:     WarningTypeDangerous,
				Severity: s.riskLevelToSeverity(operation.RiskLevel),
				Message:  fmt.Sprintf("Dangerous operation detected: %s", operation.Action),
				Details: map[string]interface{}{
					"operation": operation.Action,
					"target":    operation.Target,
					"risk":      operation.RiskLevel,
				},
			})
		}
	}

	// Check for operations without WHERE clause
	upperQuery := strings.ToUpper(query)
	if (strings.Contains(upperQuery, "DELETE") || strings.Contains(upperQuery, "UPDATE")) &&
		!strings.Contains(upperQuery, "WHERE") {
		warnings = append(warnings, SecurityWarning{
			Type:       WarningTypeDangerous,
			Severity:   SeverityCritical,
			Message:    "Operation without WHERE clause affects all rows",
			Suggestion: "Add WHERE clause to limit scope",
		})
	}

	return warnings, nil
}

// EstimateQueryImpact estimates the potential impact of a query
func (s *sqlSecurityService) EstimateQueryImpact(query string) (*ImpactAssessment, error) {
	parsed, err := s.validator.ParseQuery(query)
	if err != nil {
		return nil, fmt.Errorf("failed to parse query: %v", err)
	}

	impact := &ImpactAssessment{
		AffectedTables: parsed.Tables,
		Reversible:     s.isReversible(parsed.QueryType),
	}

	// Assess data impact
	switch parsed.QueryType {
	case QueryTypeSelect:
		impact.DataImpact = DataImpactNone
	case QueryTypeInsert:
		impact.DataImpact = DataImpactLow
	case QueryTypeUpdate:
		impact.DataImpact = DataImpactMedium
	case QueryTypeDelete:
		if strings.Contains(strings.ToUpper(query), "WHERE") {
			impact.DataImpact = DataImpactMedium
		} else {
			impact.DataImpact = DataImpactHigh
		}
	case QueryTypeDrop, QueryTypeAlter:
		impact.DataImpact = DataImpactHigh
		impact.RequiresBackup = true
	}

	// Assess performance impact
	if parsed.HasSubqueries || len(parsed.Tables) > 3 {
		impact.PerformanceImpact = PerformanceImpactMedium
	} else {
		impact.PerformanceImpact = PerformanceImpactLow
	}

	// Assess security impact
	riskLevel := s.assessQueryRiskLevel(parsed)
	switch riskLevel {
	case RiskLevelLow:
		impact.SecurityImpact = SecurityImpactLow
	case RiskLevelMedium:
		impact.SecurityImpact = SecurityImpactMedium
	case RiskLevelHigh, RiskLevelCritical:
		impact.SecurityImpact = SecurityImpactHigh
	}

	return impact, nil
}

// Helper methods

func (s *sqlSecurityService) getAllowedOperations(userRoles []string) []string {
	var allowedOps []string
	opMap := make(map[string]bool)

	for _, role := range userRoles {
		if ops, exists := s.config.AllowedOperations[role]; exists {
			for _, op := range ops {
				if !opMap[op] {
					allowedOps = append(allowedOps, op)
					opMap[op] = true
				}
			}
		}
	}

	return allowedOps
}

func (s *sqlSecurityService) getUserTablePermissions(userRoles []string) []TablePermission {
	// This would typically fetch from database based on user roles
	// For now, return empty slice - implement based on your permission system
	return []TablePermission{}
}

func (s *sqlSecurityService) assessQueryRiskLevel(parsed *ParsedQuery) RiskLevel {
	maxRisk := RiskLevelLow

	for _, operation := range parsed.Operations {
		if operation.RiskLevel > maxRisk {
			maxRisk = operation.RiskLevel
		}
	}

	if parsed.IsDangerous {
		if maxRisk < RiskLevelHigh {
			maxRisk = RiskLevelHigh
		}
	}

	return maxRisk
}

func (s *sqlSecurityService) assessQueryRiskLevelFromString(query string) RiskLevel {
	parsed, err := s.validator.ParseQuery(query)
	if err != nil {
		return RiskLevelMedium // Default for unparseable queries
	}
	return s.assessQueryRiskLevel(parsed)
}

func (s *sqlSecurityService) isDDLOperation(queryType QueryType) bool {
	return queryType == QueryTypeCreate || queryType == QueryTypeDrop || queryType == QueryTypeAlter
}

func (s *sqlSecurityService) assessComplexity(parsed *ParsedQuery) ComplexityLevel {
	score := 0

	// Base complexity
	score += len(parsed.Tables)
	score += len(parsed.Operations)

	if parsed.HasSubqueries {
		score += 5
	}

	if len(parsed.Conditions) > 0 {
		score += 2
	}

	switch {
	case score <= 3:
		return ComplexityLow
	case score <= 7:
		return ComplexityMedium
	default:
		return ComplexityHigh
	}
}

func (s *sqlSecurityService) identifySecurityRisks(parsed *ParsedQuery) []SecurityRisk {
	var risks []SecurityRisk

	for _, operation := range parsed.Operations {
		if operation.RiskLevel == RiskLevelHigh || operation.RiskLevel == RiskLevelCritical {
			risks = append(risks, SecurityRisk{
				Type:        "DANGEROUS_OPERATION",
				Severity:    s.riskLevelToSeverity(operation.RiskLevel),
				Description: fmt.Sprintf("Operation %s has %s risk level", operation.Action, operation.RiskLevel),
			})
		}
	}

	return risks
}

func (s *sqlSecurityService) analyzePerformance(parsed *ParsedQuery) PerformanceAnalysis {
	analysis := PerformanceAnalysis{
		CPUIntensive: parsed.HasSubqueries || len(parsed.Tables) > 2,
		IOIntensive:  parsed.QueryType != QueryTypeSelect,
	}

	// Estimate execution time based on complexity
	baseTime := 100 * time.Millisecond
	if parsed.HasSubqueries {
		baseTime *= 3
	}
	baseTime *= time.Duration(len(parsed.Tables))

	analysis.EstimatedExecutionTime = baseTime

	return analysis
}

func (s *sqlSecurityService) isReversible(queryType QueryType) bool {
	switch queryType {
	case QueryTypeSelect:
		return true
	case QueryTypeInsert:
		return true // Can be deleted
	case QueryTypeUpdate:
		return false // Original values lost
	case QueryTypeDelete:
		return false // Data lost
	case QueryTypeCreate:
		return true // Can be dropped
	case QueryTypeDrop:
		return false // Structure and data lost
	case QueryTypeAlter:
		return false // Original structure lost
	default:
		return false
	}
}

func (s *sqlSecurityService) riskLevelToSeverity(risk RiskLevel) SecuritySeverity {
	switch risk {
	case RiskLevelLow:
		return SeverityLow
	case RiskLevelMedium:
		return SeverityMedium
	case RiskLevelHigh:
		return SeverityHigh
	case RiskLevelCritical:
		return SeverityCritical
	default:
		return SeverityMedium
	}
}

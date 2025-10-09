package database

import (
	"database/sql"
	"fmt"
	"time"
)

// SQLSecurityManager coordinates all SQL security components
type SQLSecurityManager struct {
	securityService SQLSecurityService
	auditSystem     SQLAuditSystem
	validator       SQLValidator
	executor        QueryExecutor
	config          *SQLSecurityManagerConfig
}

// SQLSecurityManagerConfig contains configuration for the security manager
type SQLSecurityManagerConfig struct {
	SecurityConfig *SQLSecurityConfig   `json:"security_config"`
	AuditConfig    *AuditConfig         `json:"audit_config"`
	ExecutorConfig *QueryExecutorConfig `json:"executor_config"`
}

// NewSQLSecurityManager creates a new SQL security manager
func NewSQLSecurityManager(db *sql.DB, config *SQLSecurityManagerConfig) (*SQLSecurityManager, error) {
	// Create audit system
	auditSystem := NewSQLAuditSystem(db, config.AuditConfig)

	// Create security service
	securityService := NewSQLSecurityService(db, config.SecurityConfig, auditSystem)

	// Create validator
	validator := NewSQLValidator()

	// Create executor
	executor := NewQueryExecutorWithConfig(db, config.ExecutorConfig)

	manager := &SQLSecurityManager{
		securityService: securityService,
		auditSystem:     auditSystem,
		validator:       validator,
		executor:        executor,
		config:          config,
	}

	// Start real-time monitoring if enabled
	if config.AuditConfig.EnableRealTimeMonitoring {
		if err := auditSystem.StartRealTimeMonitoring(); err != nil {
			return nil, fmt.Errorf("failed to start real-time monitoring: %v", err)
		}
	}

	return manager, nil
}

// ValidateAndExecuteQuery validates and executes a SQL query with full security controls
func (m *SQLSecurityManager) ValidateAndExecuteQuery(
	query string,
	userID string,
	userRoles []string,
	userCapabilities AdminCapabilities,
	context SecurityContext,
	timeout time.Duration,
) (*SQLQueryResult, error) {

	// Step 1: Validate query syntax and security
	validationResult, err := m.securityService.ValidateQuery(query, userRoles, context)
	if err != nil {
		// Log security violation
		violation := SecurityViolationEvent{
			EventID:       context.RequestID,
			UserID:        userID,
			ViolationType: "VALIDATION_ERROR",
			Query:         query,
			Reason:        fmt.Sprintf("Query validation failed: %v", err),
			Severity:      SeverityHigh,
			IPAddress:     context.IPAddress,
			UserAgent:     context.UserAgent,
			SessionID:     context.SessionID,
			Timestamp:     time.Now(),
		}
		m.auditSystem.LogSecurityViolation(violation)
		return nil, fmt.Errorf("query validation failed: %v", err)
	}

	if !validationResult.IsValid {
		// Log security violation for invalid query
		violation := SecurityViolationEvent{
			EventID:       context.RequestID,
			UserID:        userID,
			ViolationType: "INVALID_QUERY",
			Query:         query,
			Reason:        "Query failed security validation",
			Severity:      SeverityMedium,
			IPAddress:     context.IPAddress,
			UserAgent:     context.UserAgent,
			SessionID:     context.SessionID,
			Timestamp:     time.Now(),
			Metadata: map[string]interface{}{
				"validation_errors": validationResult.Errors,
				"risk_level":        validationResult.RiskLevel,
			},
		}
		m.auditSystem.LogSecurityViolation(violation)
		return nil, fmt.Errorf("query validation failed: %v", validationResult.Errors)
	}

	// Step 2: Check user permissions
	if err := m.securityService.CheckQueryPermissions(query, userCapabilities); err != nil {
		// Log permission violation
		violation := SecurityViolationEvent{
			EventID:       context.RequestID,
			UserID:        userID,
			ViolationType: "PERMISSION_DENIED",
			Query:         query,
			Reason:        fmt.Sprintf("Insufficient permissions: %v", err),
			Severity:      SeverityHigh,
			IPAddress:     context.IPAddress,
			UserAgent:     context.UserAgent,
			SessionID:     context.SessionID,
			Timestamp:     time.Now(),
		}
		m.auditSystem.LogSecurityViolation(violation)
		return nil, fmt.Errorf("permission denied: %v", err)
	}

	// Step 3: Handle MFA requirement
	if validationResult.RequiresMFA {
		return nil, fmt.Errorf("multi-factor authentication required for this operation")
	}

	// Step 4: Handle approval requirement
	if validationResult.RequiresApproval {
		return nil, fmt.Errorf("administrative approval required for this operation")
	}

	// Step 5: Execute query with security controls
	startTime := time.Now()
	result, err := m.securityService.ExecuteSecureQuery(query, userID, timeout)

	// Step 6: Log execution (success or failure)
	auditEvent := SQLAuditEvent{
		EventID:       context.RequestID,
		UserID:        userID,
		Query:         query,
		Success:       err == nil,
		ExecutionTime: time.Since(startTime),
		IPAddress:     context.IPAddress,
		UserAgent:     context.UserAgent,
		SessionID:     context.SessionID,
		Timestamp:     startTime,
		RiskLevel:     validationResult.RiskLevel,
	}

	if result != nil {
		auditEvent.QueryType = m.determineQueryType(query)
		auditEvent.RowsAffected = result.RowsAffected
		auditEvent.TablesAccessed = m.extractTablesFromQuery(query)
	}

	if err != nil {
		auditEvent.Error = err.Error()
	}

	if auditErr := m.auditSystem.LogSQLExecution(auditEvent); auditErr != nil {
		// Log audit failure but don't fail the operation
		fmt.Printf("Failed to log SQL execution: %v\n", auditErr)
	}

	return result, err
}

// GetSecurityService returns the security service
func (m *SQLSecurityManager) GetSecurityService() SQLSecurityService {
	return m.securityService
}

// GetAuditSystem returns the audit system
func (m *SQLSecurityManager) GetAuditSystem() SQLAuditSystem {
	return m.auditSystem
}

// GetValidator returns the validator
func (m *SQLSecurityManager) GetValidator() SQLValidator {
	return m.validator
}

// GetExecutor returns the executor
func (m *SQLSecurityManager) GetExecutor() QueryExecutor {
	return m.executor
}

// Shutdown gracefully shuts down the security manager
func (m *SQLSecurityManager) Shutdown() error {
	if m.config.AuditConfig.EnableRealTimeMonitoring {
		if err := m.auditSystem.StopRealTimeMonitoring(); err != nil {
			return fmt.Errorf("failed to stop real-time monitoring: %v", err)
		}
	}
	return nil
}

// Helper methods

func (m *SQLSecurityManager) determineQueryType(query string) QueryType {
	parsed, err := m.validator.ParseQuery(query)
	if err != nil {
		return QueryTypeOther
	}
	return parsed.QueryType
}

func (m *SQLSecurityManager) extractTablesFromQuery(query string) []string {
	parsed, err := m.validator.ParseQuery(query)
	if err != nil {
		return []string{}
	}
	return parsed.Tables
}

// DefaultSQLSecurityManagerConfig returns a default configuration
func DefaultSQLSecurityManagerConfig() *SQLSecurityManagerConfig {
	return &SQLSecurityManagerConfig{
		SecurityConfig: &SQLSecurityConfig{
			MaxQueryTimeout:      5 * time.Minute,
			MaxConcurrentQueries: 10,
			EnableAuditLogging:   true,
			RequireMFAForDDL:     true,
			AllowedOperations: map[string][]string{
				"system_admin": {"SELECT", "INSERT", "UPDATE", "DELETE", "CREATE", "DROP", "ALTER", "GRANT", "REVOKE"},
				"super_admin":  {"SELECT", "INSERT", "UPDATE", "DELETE", "CREATE", "ALTER"},
				"admin":        {"SELECT", "INSERT", "UPDATE", "DELETE"},
				"moderator":    {"SELECT"},
			},
			ForbiddenPatterns: []string{
				`DROP\s+DATABASE`,
				`DELETE\s+FROM\s+\w+\s*(?:;|$)`,
				`UPDATE\s+\w+\s+SET\s+.*?(?:;|$)(?!.*WHERE)`,
			},
			SystemTablesAccess: map[string]bool{
				"system_admin": true,
				"super_admin":  false,
				"admin":        false,
				"moderator":    false,
			},
		},
		AuditConfig: &AuditConfig{
			EnableRealTimeMonitoring:  true,
			RetentionPeriod:           90 * 24 * time.Hour, // 90 days
			MaxLogSize:                1024 * 1024 * 1024,  // 1GB
			MonitoringInterval:        30 * time.Second,
			EnablePerformanceTracking: true,
			EnableSecurityAnalysis:    true,
			AlertThresholds: AlertThresholds{
				MaxQueriesPerMinute:     100,
				MaxFailedQueries:        10,
				MaxExecutionTime:        30 * time.Second,
				MaxConcurrentQueries:    20,
				DangerousOperationCount: 5,
			},
		},
		ExecutorConfig: &QueryExecutorConfig{
			MaxConcurrentQueries: 10,
			DefaultTimeout:       30 * time.Second,
			MaxTimeout:           5 * time.Minute,
			MaxConnections:       20,
			QueryBufferSize:      100,
		},
	}
}

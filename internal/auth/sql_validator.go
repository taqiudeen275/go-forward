package auth

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// SQLValidationResult represents the result of SQL validation
type SQLValidationResult struct {
	Valid              bool     `json:"valid"`
	RiskLevel          string   `json:"risk_level"` // low, medium, high, critical
	Errors             []string `json:"errors,omitempty"`
	Warnings           []string `json:"warnings,omitempty"`
	RequiresApproval   bool     `json:"requires_approval"`
	QueryType          string   `json:"query_type"`
	AffectedTables     []string `json:"affected_tables"`
	QueryHash          string   `json:"query_hash"`
	NormalizedQuery    string   `json:"normalized_query"`
	EstimatedRows      int64    `json:"estimated_rows"`
	ExecutionTimeLimit int      `json:"execution_time_limit_ms"`
}

// SQLExecutionContext contains context for SQL execution
type SQLExecutionContext struct {
	UserID         string                 `json:"user_id"`
	SessionID      string                 `json:"session_id"`
	AdminRole      string                 `json:"admin_role"`
	IPAddress      string                 `json:"ip_address"`
	UserAgent      string                 `json:"user_agent"`
	RequestPath    string                 `json:"request_path"`
	AdditionalData map[string]interface{} `json:"additional_data"`
}

// SQLSecurityValidator handles SQL query security validation and execution
type SQLSecurityValidator interface {
	ValidateQuery(ctx context.Context, query string, execCtx SQLExecutionContext) (*SQLValidationResult, error)
	ExecuteQuery(ctx context.Context, query string, execCtx SQLExecutionContext, approved bool) (*SQLExecutionResult, error)
	LogExecution(ctx context.Context, query string, execCtx SQLExecutionContext, result *SQLExecutionResult, validationResult *SQLValidationResult) error
	GetExecutionHistory(ctx context.Context, userID string, limit int) ([]*SQLExecutionLog, error)
	CheckQueryApproval(ctx context.Context, queryHash string) (*QueryApproval, error)
	RequestQueryApproval(ctx context.Context, queryHash string, query string, execCtx SQLExecutionContext) error
}

// SQLExecutionResult represents the result of SQL execution
type SQLExecutionResult struct {
	Success         bool       `json:"success"`
	Rows            [][]string `json:"rows,omitempty"`
	Columns         []string   `json:"columns,omitempty"`
	RowsAffected    int64      `json:"rows_affected"`
	RowsReturned    int64      `json:"rows_returned"`
	ExecutionTimeMs int64      `json:"execution_time_ms"`
	Error           string     `json:"error,omitempty"`
	ErrorCode       string     `json:"error_code,omitempty"`
	QueryType       string     `json:"query_type"`
}

// SQLExecutionLog represents a logged SQL execution
type SQLExecutionLog struct {
	ID               string                 `json:"id"`
	UserID           string                 `json:"user_id"`
	SessionID        string                 `json:"session_id"`
	QueryText        string                 `json:"query_text"`
	QueryHash        string                 `json:"query_hash"`
	QueryType        string                 `json:"query_type"`
	AffectedTables   []string               `json:"affected_tables"`
	ExecutionTimeMs  int                    `json:"execution_time_ms"`
	RowsAffected     int                    `json:"rows_affected"`
	RowsReturned     int                    `json:"rows_returned"`
	Success          bool                   `json:"success"`
	ErrorMessage     string                 `json:"error_message,omitempty"`
	RiskLevel        string                 `json:"risk_level"`
	RequiresApproval bool                   `json:"requires_approval"`
	ApprovedBy       string                 `json:"approved_by,omitempty"`
	ApprovedAt       *time.Time             `json:"approved_at,omitempty"`
	IPAddress        string                 `json:"ip_address"`
	UserAgent        string                 `json:"user_agent"`
	AdditionalData   map[string]interface{} `json:"additional_data"`
	CreatedAt        time.Time              `json:"created_at"`
}

// QueryApproval represents an approval for a risky query
type QueryApproval struct {
	ID          string    `json:"id"`
	QueryHash   string    `json:"query_hash"`
	Query       string    `json:"query"`
	RequestedBy string    `json:"requested_by"`
	ApprovedBy  string    `json:"approved_by"`
	Status      string    `json:"status"` // pending, approved, denied
	Reason      string    `json:"reason"`
	ExpiresAt   time.Time `json:"expires_at"`
	CreatedAt   time.Time `json:"created_at"`
	ApprovedAt  time.Time `json:"approved_at"`
}

// sqlSecurityValidator implements SQLSecurityValidator
type sqlSecurityValidator struct {
	db         *pgxpool.Pool
	rbacEngine RBACEngine
}

// NewSQLSecurityValidator creates a new SQL security validator
func NewSQLSecurityValidator(db *pgxpool.Pool, rbacEngine RBACEngine) SQLSecurityValidator {
	return &sqlSecurityValidator{
		db:         db,
		rbacEngine: rbacEngine,
	}
}

// ValidateQuery validates a SQL query for security risks
func (v *sqlSecurityValidator) ValidateQuery(ctx context.Context, query string, execCtx SQLExecutionContext) (*SQLValidationResult, error) {
	result := &SQLValidationResult{
		Valid:              true,
		RiskLevel:          "low",
		Errors:             []string{},
		Warnings:           []string{},
		RequiresApproval:   false,
		ExecutionTimeLimit: 30000, // 30 seconds default
	}

	// Normalize and hash the query
	normalizedQuery := v.normalizeQuery(query)
	result.NormalizedQuery = normalizedQuery
	result.QueryHash = v.hashQuery(normalizedQuery)

	// Determine query type
	queryType := v.getQueryType(normalizedQuery)
	result.QueryType = queryType

	// Extract affected tables
	tables := v.extractTables(normalizedQuery)
	result.AffectedTables = tables

	// Check basic SQL syntax and security patterns
	if err := v.validateSQLSyntax(normalizedQuery, result); err != nil {
		result.Valid = false
		result.Errors = append(result.Errors, err.Error())
		return result, nil
	}

	// Check for dangerous patterns
	v.checkDangerousPatterns(normalizedQuery, result)

	// Check table access permissions
	if err := v.checkTablePermissions(ctx, execCtx.UserID, tables, queryType, result); err != nil {
		result.Valid = false
		result.Errors = append(result.Errors, err.Error())
		return result, nil
	}

	// Estimate query complexity and resource usage
	v.estimateQueryComplexity(normalizedQuery, result)

	// Determine if approval is required
	v.determineApprovalRequirement(result)

	return result, nil
}

// ExecuteQuery executes a validated SQL query
func (v *sqlSecurityValidator) ExecuteQuery(ctx context.Context, query string, execCtx SQLExecutionContext, approved bool) (*SQLExecutionResult, error) {
	startTime := time.Now()

	// Validate query first
	validation, err := v.ValidateQuery(ctx, query, execCtx)
	if err != nil {
		return &SQLExecutionResult{
			Success:         false,
			Error:           fmt.Sprintf("Validation error: %v", err),
			ExecutionTimeMs: time.Since(startTime).Milliseconds(),
		}, err
	}

	if !validation.Valid {
		return &SQLExecutionResult{
			Success:         false,
			Error:           fmt.Sprintf("Query validation failed: %s", strings.Join(validation.Errors, ", ")),
			ExecutionTimeMs: time.Since(startTime).Milliseconds(),
		}, fmt.Errorf("query validation failed")
	}

	// Check if approval is required and granted
	if validation.RequiresApproval && !approved {
		approval, err := v.CheckQueryApproval(ctx, validation.QueryHash)
		if err != nil || approval == nil || approval.Status != "approved" {
			return &SQLExecutionResult{
				Success:         false,
				Error:           "Query requires approval from a system administrator",
				ExecutionTimeMs: time.Since(startTime).Milliseconds(),
			}, fmt.Errorf("query requires approval")
		}
	}

	// Execute the query with timeout
	timeout := time.Duration(validation.ExecutionTimeLimit) * time.Millisecond
	queryCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	result := &SQLExecutionResult{
		QueryType: validation.QueryType,
	}

	// Execute based on query type
	switch strings.ToUpper(validation.QueryType) {
	case "SELECT":
		err = v.executeSelectQuery(queryCtx, query, result)
	case "INSERT", "UPDATE", "DELETE":
		err = v.executeModifyQuery(queryCtx, query, result)
	default:
		err = v.executeGeneralQuery(queryCtx, query, result)
	}

	result.ExecutionTimeMs = time.Since(startTime).Milliseconds()
	result.Success = err == nil

	if err != nil {
		result.Error = err.Error()
		// Extract PostgreSQL error code if available
		if pgErr, ok := err.(*pgconn.PgError); ok {
			result.ErrorCode = pgErr.Code
		}
	}

	// Log the execution
	if logErr := v.LogExecution(ctx, query, execCtx, result, validation); logErr != nil {
		// Don't fail the execution due to logging errors, but log the error
		fmt.Printf("Failed to log SQL execution: %v\n", logErr)
	}

	return result, err
}

// LogExecution logs a SQL execution for audit purposes
func (v *sqlSecurityValidator) LogExecution(ctx context.Context, query string, execCtx SQLExecutionContext, result *SQLExecutionResult, validation *SQLValidationResult) error {
	logQuery := `
		INSERT INTO sql_execution_logs (
			user_id, admin_role_id, session_id, query_text, query_hash, query_type,
			affected_tables, execution_time_ms, rows_affected, rows_returned,
			success, error_message, error_code, ip_address, user_agent,
			risk_level, requires_approval
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17)`

	_, err := v.db.Exec(ctx, logQuery,
		execCtx.UserID,
		nil, // admin_role_id - would need to look up based on execCtx.AdminRole
		execCtx.SessionID,
		query,
		validation.QueryHash,
		validation.QueryType,
		validation.AffectedTables,
		result.ExecutionTimeMs,
		result.RowsAffected,
		result.RowsReturned,
		result.Success,
		result.Error,
		result.ErrorCode,
		execCtx.IPAddress,
		execCtx.UserAgent,
		validation.RiskLevel,
		validation.RequiresApproval,
	)

	return err
}

// GetExecutionHistory retrieves SQL execution history for a user
func (v *sqlSecurityValidator) GetExecutionHistory(ctx context.Context, userID string, limit int) ([]*SQLExecutionLog, error) {
	query := `
		SELECT id, user_id, session_id, query_text, query_hash, query_type,
			   affected_tables, execution_time_ms, rows_affected, rows_returned,
			   success, error_message, risk_level, requires_approval,
			   ip_address, user_agent, created_at
		FROM sql_execution_logs
		WHERE user_id = $1
		ORDER BY created_at DESC
		LIMIT $2`

	rows, err := v.db.Query(ctx, query, userID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var logs []*SQLExecutionLog
	for rows.Next() {
		log := &SQLExecutionLog{}
		err := rows.Scan(
			&log.ID, &log.UserID, &log.SessionID, &log.QueryText, &log.QueryHash,
			&log.QueryType, &log.AffectedTables, &log.ExecutionTimeMs,
			&log.RowsAffected, &log.RowsReturned, &log.Success, &log.ErrorMessage,
			&log.RiskLevel, &log.RequiresApproval, &log.IPAddress, &log.UserAgent,
			&log.CreatedAt,
		)
		if err != nil {
			return nil, err
		}
		logs = append(logs, log)
	}

	return logs, rows.Err()
}

// CheckQueryApproval checks if a query has been approved
func (v *sqlSecurityValidator) CheckQueryApproval(ctx context.Context, queryHash string) (*QueryApproval, error) {
	query := `
		SELECT id, query_hash, query, requested_by, approved_by, status,
			   reason, expires_at, created_at, approved_at
		FROM query_approvals
		WHERE query_hash = $1 AND status = 'approved' AND expires_at > NOW()
		ORDER BY approved_at DESC
		LIMIT 1`

	approval := &QueryApproval{}
	err := v.db.QueryRow(ctx, query, queryHash).Scan(
		&approval.ID, &approval.QueryHash, &approval.Query, &approval.RequestedBy,
		&approval.ApprovedBy, &approval.Status, &approval.Reason,
		&approval.ExpiresAt, &approval.CreatedAt, &approval.ApprovedAt,
	)

	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}

	return approval, nil
}

// RequestQueryApproval requests approval for a risky query
func (v *sqlSecurityValidator) RequestQueryApproval(ctx context.Context, queryHash string, query string, execCtx SQLExecutionContext) error {
	approvalQuery := `
		INSERT INTO query_approvals (query_hash, query, requested_by, status, expires_at)
		VALUES ($1, $2, $3, 'pending', NOW() + INTERVAL '24 hours')
		ON CONFLICT (query_hash, requested_by) DO UPDATE SET
			created_at = NOW(),
			expires_at = NOW() + INTERVAL '24 hours'`

	_, err := v.db.Exec(ctx, approvalQuery, queryHash, query, execCtx.UserID)
	return err
}

// Helper methods

func (v *sqlSecurityValidator) normalizeQuery(query string) string {
	// Remove comments
	query = regexp.MustCompile(`--[^\n]*`).ReplaceAllString(query, "")
	query = regexp.MustCompile(`/\*.*?\*/`).ReplaceAllString(query, "")

	// Normalize whitespace
	query = regexp.MustCompile(`\s+`).ReplaceAllString(query, " ")

	// Trim and convert to lowercase for analysis
	return strings.TrimSpace(strings.ToLower(query))
}

func (v *sqlSecurityValidator) hashQuery(query string) string {
	hash := sha256.Sum256([]byte(query))
	return hex.EncodeToString(hash[:])
}

func (v *sqlSecurityValidator) getQueryType(query string) string {
	query = strings.TrimSpace(strings.ToUpper(query))

	if strings.HasPrefix(query, "SELECT") {
		return "SELECT"
	} else if strings.HasPrefix(query, "INSERT") {
		return "INSERT"
	} else if strings.HasPrefix(query, "UPDATE") {
		return "UPDATE"
	} else if strings.HasPrefix(query, "DELETE") {
		return "DELETE"
	} else if strings.HasPrefix(query, "CREATE") {
		return "CREATE"
	} else if strings.HasPrefix(query, "ALTER") {
		return "ALTER"
	} else if strings.HasPrefix(query, "DROP") {
		return "DROP"
	} else if strings.HasPrefix(query, "TRUNCATE") {
		return "TRUNCATE"
	}

	return "OTHER"
}

func (v *sqlSecurityValidator) extractTables(query string) []string {
	tables := []string{}

	// Basic table extraction - this could be much more sophisticated
	patterns := []string{
		`from\s+([a-zA-Z_][a-zA-Z0-9_]*(?:\.[a-zA-Z_][a-zA-Z0-9_]*)?)`,
		`join\s+([a-zA-Z_][a-zA-Z0-9_]*(?:\.[a-zA-Z_][a-zA-Z0-9_]*)?)`,
		`update\s+([a-zA-Z_][a-zA-Z0-9_]*(?:\.[a-zA-Z_][a-zA-Z0-9_]*)?)`,
		`insert\s+into\s+([a-zA-Z_][a-zA-Z0-9_]*(?:\.[a-zA-Z_][a-zA-Z0-9_]*)?)`,
		`delete\s+from\s+([a-zA-Z_][a-zA-Z0-9_]*(?:\.[a-zA-Z_][a-zA-Z0-9_]*)?)`,
	}

	for _, pattern := range patterns {
		re := regexp.MustCompile(pattern)
		matches := re.FindAllStringSubmatch(query, -1)
		for _, match := range matches {
			if len(match) > 1 {
				table := strings.TrimSpace(match[1])
				// Remove schema prefix if present
				if parts := strings.Split(table, "."); len(parts) > 1 {
					table = parts[1]
				}
				tables = append(tables, table)
			}
		}
	}

	// Remove duplicates
	unique := make(map[string]bool)
	result := []string{}
	for _, table := range tables {
		if !unique[table] {
			unique[table] = true
			result = append(result, table)
		}
	}

	return result
}

func (v *sqlSecurityValidator) validateSQLSyntax(query string, result *SQLValidationResult) error {
	// Check for SQL injection patterns
	dangerousPatterns := []string{
		`union\s+select`,
		`information_schema`,
		`pg_catalog`,
		`pg_user`,
		`pg_shadow`,
		`pg_roles`,
		`\bxp_cmdshell\b`,
		`\bsp_execute\b`,
		`\bexec\s*\(`,
		`\bevalu?ate\s*\(`,
	}

	for _, pattern := range dangerousPatterns {
		if matched, _ := regexp.MatchString(pattern, query); matched {
			return fmt.Errorf("potentially dangerous SQL pattern detected: %s", pattern)
		}
	}

	return nil
}

func (v *sqlSecurityValidator) checkDangerousPatterns(query string, result *SQLValidationResult) {
	// Check for potentially risky operations
	riskPatterns := map[string]string{
		`delete\s+from\s+\w+\s*(where|$)`:  "DELETE operations can be destructive",
		`update\s+\w+\s+set.*where\s*$`:    "UPDATE without WHERE clause affects all rows",
		`delete\s+from\s+\w+\s*$`:          "DELETE without WHERE clause affects all rows",
		`drop\s+(table|database|schema)`:   "DROP operations are destructive",
		`truncate\s+table`:                 "TRUNCATE operations delete all data",
		`alter\s+(table|database|schema)`:  "ALTER operations modify schema structure",
		`create\s+(table|database|schema)`: "CREATE operations modify schema structure",
		`grant\s+`:                         "GRANT operations modify permissions",
		`revoke\s+`:                        "REVOKE operations modify permissions",
	}

	for pattern, warning := range riskPatterns {
		if matched, _ := regexp.MatchString(pattern, query); matched {
			result.Warnings = append(result.Warnings, warning)
			if result.RiskLevel == "low" {
				result.RiskLevel = "medium"
			}
		}
	}

	// Check for very high-risk operations
	criticalPatterns := []string{
		`drop\s+database`,
		`drop\s+schema`,
		`delete\s+from\s+users`,
		`delete\s+from\s+admin_roles`,
		`update\s+users\s+set`,
		`truncate\s+table\s+users`,
	}

	for _, pattern := range criticalPatterns {
		if matched, _ := regexp.MatchString(pattern, query); matched {
			result.RiskLevel = "critical"
			result.Warnings = append(result.Warnings, "CRITICAL: Operation affects core system data")
			break
		}
	}
}

func (v *sqlSecurityValidator) checkTablePermissions(ctx context.Context, userID string, tables []string, queryType string, result *SQLValidationResult) error {
	for _, table := range tables {
		canAccess, err := v.rbacEngine.CanAccessTable(ctx, userID, table, queryType)
		if err != nil {
			return fmt.Errorf("error checking table permissions for %s: %v", table, err)
		}

		if !canAccess {
			return fmt.Errorf("access denied to table '%s' for operation '%s'", table, queryType)
		}
	}

	return nil
}

func (v *sqlSecurityValidator) estimateQueryComplexity(query string, result *SQLValidationResult) {
	// Simple complexity estimation based on query patterns
	complexity := 0

	// Count joins
	joinCount := len(regexp.MustCompile(`join\s+`).FindAllString(query, -1))
	complexity += joinCount * 10

	// Count subqueries
	subqueryCount := strings.Count(query, "(select")
	complexity += subqueryCount * 15

	// Count wildcards
	wildcardCount := strings.Count(query, "*")
	complexity += wildcardCount * 5

	// Adjust execution time limit based on complexity
	if complexity > 100 {
		result.ExecutionTimeLimit = 120000 // 2 minutes
		result.RiskLevel = "high"
	} else if complexity > 50 {
		result.ExecutionTimeLimit = 60000 // 1 minute
		if result.RiskLevel == "low" {
			result.RiskLevel = "medium"
		}
	}

	// Estimate rows (very rough)
	if strings.Contains(query, "limit") {
		limitMatch := regexp.MustCompile(`limit\s+(\d+)`).FindStringSubmatch(query)
		if len(limitMatch) > 1 {
			if limit, err := strconv.ParseInt(limitMatch[1], 10, 64); err == nil {
				result.EstimatedRows = limit
			}
		}
	} else {
		result.EstimatedRows = 1000 // Default estimate
	}
}

func (v *sqlSecurityValidator) determineApprovalRequirement(result *SQLValidationResult) {
	// Require approval for high-risk operations
	if result.RiskLevel == "critical" || result.RiskLevel == "high" {
		result.RequiresApproval = true
	}

	// Require approval for operations affecting many rows
	if result.EstimatedRows > 10000 {
		result.RequiresApproval = true
	}

	// Require approval for schema changes
	schemaOps := []string{"CREATE", "ALTER", "DROP", "TRUNCATE"}
	for _, op := range schemaOps {
		if result.QueryType == op {
			result.RequiresApproval = true
			break
		}
	}
}

func (v *sqlSecurityValidator) executeSelectQuery(ctx context.Context, query string, result *SQLExecutionResult) error {
	rows, err := v.db.Query(ctx, query)
	if err != nil {
		return err
	}
	defer rows.Close()

	// Get column names
	fieldDescriptions := rows.FieldDescriptions()
	columns := make([]string, len(fieldDescriptions))
	for i, desc := range fieldDescriptions {
		columns[i] = string(desc.Name)
	}
	result.Columns = columns

	// Read all rows
	var resultRows [][]string
	for rows.Next() {
		values, err := rows.Values()
		if err != nil {
			return err
		}

		row := make([]string, len(values))
		for i, val := range values {
			if val == nil {
				row[i] = ""
			} else {
				row[i] = fmt.Sprintf("%v", val)
			}
		}
		resultRows = append(resultRows, row)
	}

	result.Rows = resultRows
	result.RowsReturned = int64(len(resultRows))

	return rows.Err()
}

func (v *sqlSecurityValidator) executeModifyQuery(ctx context.Context, query string, result *SQLExecutionResult) error {
	commandTag, err := v.db.Exec(ctx, query)
	if err != nil {
		return err
	}

	result.RowsAffected = commandTag.RowsAffected()
	return nil
}

func (v *sqlSecurityValidator) executeGeneralQuery(ctx context.Context, query string, result *SQLExecutionResult) error {
	// For DDL and other operations
	_, err := v.db.Exec(ctx, query)
	return err
}

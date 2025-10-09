package database

import (
	"fmt"
	"regexp"
	"strings"
)

// sqlValidator implements the SQLValidator interface
type sqlValidator struct {
	forbiddenPatterns []ForbiddenPattern
	dangerousOps      map[string]RiskLevel
	systemTables      []string
}

// ForbiddenPattern represents a forbidden SQL pattern
type ForbiddenPattern struct {
	Pattern     *regexp.Regexp
	Name        string
	Severity    SecuritySeverity
	Description string
	Suggestion  string
}

// NewSQLValidator creates a new SQL validator instance
func NewSQLValidator() SQLValidator {
	validator := &sqlValidator{
		forbiddenPatterns: initializeForbiddenPatterns(),
		dangerousOps:      initializeDangerousOperations(),
		systemTables:      initializeSystemTables(),
	}
	return validator
}

// ParseQuery parses a SQL query and extracts its components
func (v *sqlValidator) ParseQuery(query string) (*ParsedQuery, error) {
	if strings.TrimSpace(query) == "" {
		return nil, fmt.Errorf("empty query")
	}

	// Normalize the query
	normalizedQuery := v.normalizeQuery(query)

	// Determine query type
	queryType := v.determineQueryType(normalizedQuery)

	// Extract operations
	operations := v.extractOperations(normalizedQuery, queryType)

	// Extract tables
	tables := v.extractTables(normalizedQuery, queryType)

	// Extract columns
	columns := v.extractColumns(normalizedQuery, queryType)

	// Extract conditions
	conditions := v.extractConditions(normalizedQuery)

	// Check for subqueries
	hasSubqueries := v.hasSubqueries(normalizedQuery)

	// Assess if query is dangerous
	isDangerous := v.assessDangerLevel(operations, tables)

	parsed := &ParsedQuery{
		OriginalQuery: query,
		QueryType:     queryType,
		Operations:    operations,
		Tables:        tables,
		Columns:       columns,
		Conditions:    conditions,
		HasSubqueries: hasSubqueries,
		IsDangerous:   isDangerous,
	}

	return parsed, nil
}

// ValidateOperations validates SQL operations against allowed operations
func (v *sqlValidator) ValidateOperations(operations []SQLOperation, allowedOps []string) error {
	allowedMap := make(map[string]bool)
	for _, op := range allowedOps {
		allowedMap[strings.ToUpper(op)] = true
	}

	for _, operation := range operations {
		if !allowedMap[string(operation.Type)] {
			return fmt.Errorf("operation %s is not allowed", operation.Type)
		}

		// Check risk level
		if operation.RiskLevel == RiskLevelCritical {
			return fmt.Errorf("critical risk operation %s is not permitted", operation.Action)
		}
	}

	return nil
}

// CheckForbiddenPatterns checks for forbidden patterns in the query
func (v *sqlValidator) CheckForbiddenPatterns(query string, patterns []string) ([]PatternMatch, error) {
	var matches []PatternMatch
	normalizedQuery := strings.ToUpper(strings.TrimSpace(query))

	// Check built-in forbidden patterns
	for _, pattern := range v.forbiddenPatterns {
		if pattern.Pattern.MatchString(normalizedQuery) {
			match := PatternMatch{
				Pattern:     pattern.Name,
				Match:       pattern.Pattern.FindString(normalizedQuery),
				Position:    pattern.Pattern.FindStringIndex(normalizedQuery)[0],
				Severity:    pattern.Severity,
				Description: pattern.Description,
			}
			matches = append(matches, match)
		}
	}

	// Check custom patterns
	for _, patternStr := range patterns {
		pattern, err := regexp.Compile(strings.ToUpper(patternStr))
		if err != nil {
			continue // Skip invalid patterns
		}

		if pattern.MatchString(normalizedQuery) {
			match := PatternMatch{
				Pattern:     patternStr,
				Match:       pattern.FindString(normalizedQuery),
				Position:    pattern.FindStringIndex(normalizedQuery)[0],
				Severity:    SeverityMedium,
				Description: "Custom forbidden pattern detected",
			}
			matches = append(matches, match)
		}
	}

	return matches, nil
}

// ValidateTableAccess validates table access permissions
func (v *sqlValidator) ValidateTableAccess(tables []string, userPermissions []TablePermission) error {
	permissionMap := make(map[string]TablePermission)
	for _, perm := range userPermissions {
		key := fmt.Sprintf("%s.%s", perm.SchemaName, perm.TableName)
		permissionMap[key] = perm
		// Also add without schema for default schema
		permissionMap[perm.TableName] = perm
	}

	for _, table := range tables {
		// Check if it's a system table
		if v.isSystemTable(table) {
			return fmt.Errorf("access to system table %s is not allowed", table)
		}

		// Check user permissions
		if _, exists := permissionMap[table]; exists {
			// User has some permission to this table
			continue
		} else {
			return fmt.Errorf("no permission to access table %s", table)
		}
	}

	return nil
}

// Helper methods

func (v *sqlValidator) normalizeQuery(query string) string {
	// Remove extra whitespace and normalize
	query = strings.TrimSpace(query)
	query = regexp.MustCompile(`\s+`).ReplaceAllString(query, " ")
	return query
}

func (v *sqlValidator) determineQueryType(query string) QueryType {
	upperQuery := strings.ToUpper(strings.TrimSpace(query))

	switch {
	case strings.HasPrefix(upperQuery, "SELECT"):
		return QueryTypeSelect
	case strings.HasPrefix(upperQuery, "INSERT"):
		return QueryTypeInsert
	case strings.HasPrefix(upperQuery, "UPDATE"):
		return QueryTypeUpdate
	case strings.HasPrefix(upperQuery, "DELETE"):
		return QueryTypeDelete
	case strings.HasPrefix(upperQuery, "CREATE"):
		return QueryTypeCreate
	case strings.HasPrefix(upperQuery, "DROP"):
		return QueryTypeDrop
	case strings.HasPrefix(upperQuery, "ALTER"):
		return QueryTypeAlter
	case strings.HasPrefix(upperQuery, "GRANT"):
		return QueryTypeGrant
	case strings.HasPrefix(upperQuery, "REVOKE"):
		return QueryTypeRevoke
	default:
		return QueryTypeOther
	}
}

func (v *sqlValidator) extractOperations(query string, queryType QueryType) []SQLOperation {
	var operations []SQLOperation
	upperQuery := strings.ToUpper(query)

	switch queryType {
	case QueryTypeSelect:
		operations = append(operations, SQLOperation{
			Type:        OpTypeRead,
			Target:      "table",
			Action:      "SELECT",
			RiskLevel:   RiskLevelLow,
			Description: "Read operation",
		})
	case QueryTypeInsert:
		operations = append(operations, SQLOperation{
			Type:        OpTypeWrite,
			Target:      "table",
			Action:      "INSERT",
			RiskLevel:   RiskLevelMedium,
			Description: "Insert operation",
		})
	case QueryTypeUpdate:
		operations = append(operations, SQLOperation{
			Type:        OpTypeWrite,
			Target:      "table",
			Action:      "UPDATE",
			RiskLevel:   RiskLevelMedium,
			Description: "Update operation",
		})
	case QueryTypeDelete:
		riskLevel := RiskLevelHigh
		if strings.Contains(upperQuery, "WHERE") {
			riskLevel = RiskLevelMedium
		} else {
			riskLevel = RiskLevelCritical // DELETE without WHERE
		}
		operations = append(operations, SQLOperation{
			Type:        OpTypeWrite,
			Target:      "table",
			Action:      "DELETE",
			RiskLevel:   riskLevel,
			Description: "Delete operation",
		})
	case QueryTypeDrop:
		operations = append(operations, SQLOperation{
			Type:        OpTypeSchema,
			Target:      "schema",
			Action:      "DROP",
			RiskLevel:   RiskLevelCritical,
			Description: "Drop operation",
		})
	case QueryTypeCreate:
		operations = append(operations, SQLOperation{
			Type:        OpTypeSchema,
			Target:      "schema",
			Action:      "CREATE",
			RiskLevel:   RiskLevelMedium,
			Description: "Create operation",
		})
	case QueryTypeAlter:
		operations = append(operations, SQLOperation{
			Type:        OpTypeSchema,
			Target:      "schema",
			Action:      "ALTER",
			RiskLevel:   RiskLevelHigh,
			Description: "Alter operation",
		})
	case QueryTypeGrant, QueryTypeRevoke:
		operations = append(operations, SQLOperation{
			Type:        OpTypeAdmin,
			Target:      "permissions",
			Action:      string(queryType),
			RiskLevel:   RiskLevelCritical,
			Description: "Permission operation",
		})
	}

	return operations
}

func (v *sqlValidator) extractTables(query string, queryType QueryType) []string {
	var tables []string
	upperQuery := strings.ToUpper(query)

	// Simple table extraction patterns
	patterns := map[QueryType]*regexp.Regexp{
		QueryTypeSelect: regexp.MustCompile(`FROM\s+([a-zA-Z_][a-zA-Z0-9_]*(?:\.[a-zA-Z_][a-zA-Z0-9_]*)?)`),
		QueryTypeInsert: regexp.MustCompile(`INSERT\s+INTO\s+([a-zA-Z_][a-zA-Z0-9_]*(?:\.[a-zA-Z_][a-zA-Z0-9_]*)?)`),
		QueryTypeUpdate: regexp.MustCompile(`UPDATE\s+([a-zA-Z_][a-zA-Z0-9_]*(?:\.[a-zA-Z_][a-zA-Z0-9_]*)?)`),
		QueryTypeDelete: regexp.MustCompile(`DELETE\s+FROM\s+([a-zA-Z_][a-zA-Z0-9_]*(?:\.[a-zA-Z_][a-zA-Z0-9_]*)?)`),
		QueryTypeDrop:   regexp.MustCompile(`DROP\s+TABLE\s+(?:IF\s+EXISTS\s+)?([a-zA-Z_][a-zA-Z0-9_]*(?:\.[a-zA-Z_][a-zA-Z0-9_]*)?)`),
		QueryTypeCreate: regexp.MustCompile(`CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?([a-zA-Z_][a-zA-Z0-9_]*(?:\.[a-zA-Z_][a-zA-Z0-9_]*)?)`),
		QueryTypeAlter:  regexp.MustCompile(`ALTER\s+TABLE\s+([a-zA-Z_][a-zA-Z0-9_]*(?:\.[a-zA-Z_][a-zA-Z0-9_]*)?)`),
	}

	if pattern, exists := patterns[queryType]; exists {
		matches := pattern.FindAllStringSubmatch(upperQuery, -1)
		for _, match := range matches {
			if len(match) > 1 {
				tables = append(tables, strings.ToLower(match[1]))
			}
		}
	}

	// Also check for JOIN tables in SELECT queries
	if queryType == QueryTypeSelect {
		joinPattern := regexp.MustCompile(`JOIN\s+([a-zA-Z_][a-zA-Z0-9_]*(?:\.[a-zA-Z_][a-zA-Z0-9_]*)?)\s+`)
		joinMatches := joinPattern.FindAllStringSubmatch(upperQuery, -1)
		for _, match := range joinMatches {
			if len(match) > 1 {
				tables = append(tables, strings.ToLower(match[1]))
			}
		}
	}

	return v.removeDuplicates(tables)
}

func (v *sqlValidator) extractColumns(query string, queryType QueryType) []string {
	var columns []string

	// Simple column extraction for SELECT queries
	if queryType == QueryTypeSelect {
		selectPattern := regexp.MustCompile(`SELECT\s+(.*?)\s+FROM`)
		matches := selectPattern.FindStringSubmatch(strings.ToUpper(query))
		if len(matches) > 1 {
			columnStr := matches[1]
			if columnStr != "*" {
				// Split by comma and clean up
				cols := strings.Split(columnStr, ",")
				for _, col := range cols {
					col = strings.TrimSpace(col)
					// Remove aliases (AS keyword)
					if asIndex := strings.Index(strings.ToUpper(col), " AS "); asIndex != -1 {
						col = col[:asIndex]
					}
					columns = append(columns, strings.ToLower(col))
				}
			}
		}
	}

	return v.removeDuplicates(columns)
}

func (v *sqlValidator) extractConditions(query string) []string {
	var conditions []string
	upperQuery := strings.ToUpper(query)

	// Extract WHERE conditions
	wherePattern := regexp.MustCompile(`WHERE\s+(.*?)(?:\s+(?:GROUP|ORDER|LIMIT|HAVING|$))`)
	matches := wherePattern.FindStringSubmatch(upperQuery)
	if len(matches) > 1 {
		conditions = append(conditions, strings.TrimSpace(matches[1]))
	}

	return conditions
}

func (v *sqlValidator) hasSubqueries(query string) bool {
	// Simple check for subqueries
	upperQuery := strings.ToUpper(query)

	// Count parentheses that might contain SELECT
	selectInParens := regexp.MustCompile(`\(\s*SELECT`)
	return selectInParens.MatchString(upperQuery)
}

func (v *sqlValidator) assessDangerLevel(operations []SQLOperation, tables []string) bool {
	for _, op := range operations {
		if op.RiskLevel == RiskLevelCritical || op.RiskLevel == RiskLevelHigh {
			return true
		}
	}

	// Check if accessing system tables
	for _, table := range tables {
		if v.isSystemTable(table) {
			return true
		}
	}

	return false
}

func (v *sqlValidator) isSystemTable(tableName string) bool {
	lowerTable := strings.ToLower(tableName)
	for _, sysTable := range v.systemTables {
		if lowerTable == sysTable || strings.HasPrefix(lowerTable, sysTable+".") {
			return true
		}
	}
	return false
}

func (v *sqlValidator) removeDuplicates(slice []string) []string {
	keys := make(map[string]bool)
	var result []string

	for _, item := range slice {
		if !keys[item] {
			keys[item] = true
			result = append(result, item)
		}
	}

	return result
}

// Initialize forbidden patterns
func initializeForbiddenPatterns() []ForbiddenPattern {
	patterns := []ForbiddenPattern{
		{
			Pattern:     regexp.MustCompile(`DROP\s+DATABASE`),
			Name:        "DROP_DATABASE",
			Severity:    SeverityCritical,
			Description: "Dropping entire database is forbidden",
			Suggestion:  "Use DROP TABLE for specific tables instead",
		},
		{
			Pattern:     regexp.MustCompile(`DELETE\s+FROM\s+[a-zA-Z_][a-zA-Z0-9_]*\s*(?:;|$)`),
			Name:        "DELETE_WITHOUT_WHERE",
			Severity:    SeverityCritical,
			Description: "DELETE without WHERE clause will remove all data",
			Suggestion:  "Add WHERE clause to limit deletion scope",
		},
		{
			Pattern:     regexp.MustCompile(`UPDATE\s+[a-zA-Z_][a-zA-Z0-9_]*\s+SET\s+.*?(?:;|$)(?!.*WHERE)`),
			Name:        "UPDATE_WITHOUT_WHERE",
			Severity:    SeverityHigh,
			Description: "UPDATE without WHERE clause will modify all rows",
			Suggestion:  "Add WHERE clause to limit update scope",
		},
		{
			Pattern:     regexp.MustCompile(`TRUNCATE\s+TABLE`),
			Name:        "TRUNCATE_TABLE",
			Severity:    SeverityHigh,
			Description: "TRUNCATE removes all data and cannot be rolled back",
			Suggestion:  "Use DELETE with WHERE clause for safer data removal",
		},
		{
			Pattern:     regexp.MustCompile(`ALTER\s+TABLE.*DROP\s+COLUMN`),
			Name:        "DROP_COLUMN",
			Severity:    SeverityHigh,
			Description: "Dropping columns permanently removes data",
			Suggestion:  "Consider renaming or marking column as deprecated first",
		},
		{
			Pattern:     regexp.MustCompile(`GRANT\s+ALL`),
			Name:        "GRANT_ALL_PRIVILEGES",
			Severity:    SeverityHigh,
			Description: "Granting all privileges creates security risk",
			Suggestion:  "Grant only specific required privileges",
		},
		{
			Pattern:     regexp.MustCompile(`--.*(?:DROP|DELETE|TRUNCATE)`),
			Name:        "COMMENTED_DANGEROUS_OPS",
			Severity:    SeverityMedium,
			Description: "Commented dangerous operations detected",
			Suggestion:  "Remove commented dangerous operations",
		},
		{
			Pattern:     regexp.MustCompile(`/\*.*(?:DROP|DELETE|TRUNCATE).*\*/`),
			Name:        "BLOCK_COMMENTED_DANGEROUS_OPS",
			Severity:    SeverityMedium,
			Description: "Block commented dangerous operations detected",
			Suggestion:  "Remove commented dangerous operations",
		},
	}

	return patterns
}

// Initialize dangerous operations mapping
func initializeDangerousOperations() map[string]RiskLevel {
	return map[string]RiskLevel{
		"DROP DATABASE": RiskLevelCritical,
		"DROP TABLE":    RiskLevelCritical,
		"TRUNCATE":      RiskLevelHigh,
		"DELETE":        RiskLevelHigh,
		"UPDATE":        RiskLevelMedium,
		"ALTER TABLE":   RiskLevelHigh,
		"CREATE USER":   RiskLevelHigh,
		"DROP USER":     RiskLevelHigh,
		"GRANT":         RiskLevelHigh,
		"REVOKE":        RiskLevelHigh,
		"SET":           RiskLevelMedium,
		"RESET":         RiskLevelMedium,
	}
}

// Initialize system tables list
func initializeSystemTables() []string {
	return []string{
		"information_schema",
		"pg_catalog",
		"pg_class",
		"pg_tables",
		"pg_user",
		"pg_roles",
		"pg_database",
		"pg_namespace",
		"pg_attribute",
		"pg_index",
		"pg_constraint",
		"pg_proc",
		"pg_type",
		"pg_stat_user_tables",
		"pg_stat_activity",
		"mysql.user",
		"mysql.db",
		"mysql.tables_priv",
		"mysql.columns_priv",
		"sys",
		"performance_schema",
	}
}

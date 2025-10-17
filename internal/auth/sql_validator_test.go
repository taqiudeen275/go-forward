package auth

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// MockRBACEngine for testing
type MockRBACEngine struct {
	mock.Mock
}

func (m *MockRBACEngine) GetUserRoles(ctx context.Context, userID string) ([]UserAdminRole, error) {
	args := m.Called(ctx, userID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]UserAdminRole), args.Error(1)
}

func (m *MockRBACEngine) HasRole(ctx context.Context, userID, roleName string) (bool, error) {
	args := m.Called(ctx, userID, roleName)
	return args.Bool(0), args.Error(1)
}

func (m *MockRBACEngine) GetRoleByID(ctx context.Context, roleID string) (*AdminRole, error) {
	args := m.Called(ctx, roleID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*AdminRole), args.Error(1)
}

func (m *MockRBACEngine) GetHighestRole(ctx context.Context, userID string) (*AdminRole, error) {
	args := m.Called(ctx, userID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*AdminRole), args.Error(1)
}

func (m *MockRBACEngine) GrantRole(ctx context.Context, userID, roleName, grantedBy string) error {
	args := m.Called(ctx, userID, roleName, grantedBy)
	return args.Error(0)
}

func (m *MockRBACEngine) RevokeRole(ctx context.Context, userID, roleName, revokedBy string) error {
	args := m.Called(ctx, userID, roleName, revokedBy)
	return args.Error(0)
}

func (m *MockRBACEngine) HasPermission(ctx context.Context, userID, permission string) (bool, error) {
	args := m.Called(ctx, userID, permission)
	return args.Bool(0), args.Error(1)
}

func (m *MockRBACEngine) CanAccessTable(ctx context.Context, userID, tableName, operation string) (bool, error) {
	args := m.Called(ctx, userID, tableName, operation)
	return args.Bool(0), args.Error(1)
}

func (m *MockRBACEngine) GetTableFilters(ctx context.Context, userID, tableName string) (map[string]interface{}, error) {
	args := m.Called(ctx, userID, tableName)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(map[string]interface{}), args.Error(1)
}

func (m *MockRBACEngine) CanManageUser(ctx context.Context, managerID, targetUserID string) (bool, error) {
	args := m.Called(ctx, managerID, targetUserID)
	return args.Bool(0), args.Error(1)
}

func (m *MockRBACEngine) GetAccessibleTables(ctx context.Context, userID string) ([]string, error) {
	args := m.Called(ctx, userID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]string), args.Error(1)
}

func (m *MockRBACEngine) GetUserAdminLevel(ctx context.Context, userID string) (int, error) {
	args := m.Called(ctx, userID)
	return args.Int(0), args.Error(1)
}

func (m *MockRBACEngine) HasCapability(ctx context.Context, userID, capability, resource string) (bool, error) {
	args := m.Called(ctx, userID, capability, resource)
	return args.Bool(0), args.Error(1)
}

func (m *MockRBACEngine) GetUserCapabilities(ctx context.Context, userID string) ([]string, error) {
	args := m.Called(ctx, userID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]string), args.Error(1)
}

// Test fixtures
func createTestExecutionContext() SQLExecutionContext {
	return SQLExecutionContext{
		UserID:      "test-user-123",
		SessionID:   "test-session-456",
		AdminRole:   "system_admin",
		IPAddress:   "192.168.1.100",
		UserAgent:   "TestAgent/1.0",
		RequestPath: "/api/admin/sql/execute",
		AdditionalData: map[string]interface{}{
			"request_reason": "Testing SQL validator",
		},
	}
}

func TestSQLValidator_ValidateQuery(t *testing.T) {
	tests := []struct {
		name           string
		query          string
		setupMocks     func(*MockRBACEngine)
		expectedValid  bool
		expectedRisk   string
		expectedErrors int
	}{
		{
			name:  "Valid SELECT query",
			query: "SELECT id, name FROM users WHERE status = 'active' LIMIT 10",
			setupMocks: func(rbac *MockRBACEngine) {
				rbac.On("CanAccessTable", mock.Anything, "test-user-123", "users", "SELECT").Return(true, nil)
			},
			expectedValid:  true,
			expectedRisk:   "low",
			expectedErrors: 0,
		},
		{
			name:  "High-risk DELETE query",
			query: "DELETE FROM users WHERE created_at < '2020-01-01'",
			setupMocks: func(rbac *MockRBACEngine) {
				rbac.On("CanAccessTable", mock.Anything, "test-user-123", "users", "DELETE").Return(true, nil)
			},
			expectedValid:  true,
			expectedRisk:   "medium",
			expectedErrors: 0,
		},
		{
			name:  "Critical DELETE all users",
			query: "DELETE FROM users",
			setupMocks: func(rbac *MockRBACEngine) {
				rbac.On("CanAccessTable", mock.Anything, "test-user-123", "users", "DELETE").Return(true, nil)
			},
			expectedValid:  true,
			expectedRisk:   "critical",
			expectedErrors: 0,
		},
		{
			name:  "SQL injection attempt",
			query: "SELECT * FROM users UNION SELECT * FROM information_schema.tables",
			setupMocks: func(rbac *MockRBACEngine) {
				// This should fail validation before table access check
			},
			expectedValid:  false,
			expectedRisk:   "low",
			expectedErrors: 1,
		},
		{
			name:  "Access denied to table",
			query: "SELECT * FROM sensitive_data",
			setupMocks: func(rbac *MockRBACEngine) {
				rbac.On("CanAccessTable", mock.Anything, "test-user-123", "sensitive_data", "SELECT").Return(false, nil)
			},
			expectedValid:  false,
			expectedRisk:   "low",
			expectedErrors: 1,
		},
		{
			name:  "Complex JOIN query",
			query: "SELECT u.id, p.name FROM users u JOIN profiles p ON u.id = p.user_id JOIN orders o ON u.id = o.user_id WHERE u.status = 'active'",
			setupMocks: func(rbac *MockRBACEngine) {
				rbac.On("CanAccessTable", mock.Anything, "test-user-123", "users", "SELECT").Return(true, nil)
				rbac.On("CanAccessTable", mock.Anything, "test-user-123", "profiles", "SELECT").Return(true, nil)
				rbac.On("CanAccessTable", mock.Anything, "test-user-123", "orders", "SELECT").Return(true, nil)
			},
			expectedValid:  true,
			expectedRisk:   "medium", // Due to complexity
			expectedErrors: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockRBAC := new(MockRBACEngine)
			tt.setupMocks(mockRBAC)

			// Create validator with nil db pool since we're testing validation logic only
			validator := NewSQLSecurityValidator(nil, mockRBAC)
			execCtx := createTestExecutionContext()

			result, err := validator.ValidateQuery(context.Background(), tt.query, execCtx)

			require.NoError(t, err)
			assert.Equal(t, tt.expectedValid, result.Valid)
			assert.Equal(t, tt.expectedRisk, result.RiskLevel)
			assert.Equal(t, tt.expectedErrors, len(result.Errors))

			mockRBAC.AssertExpectations(t)
		})
	}
}

func TestSQLValidator_NormalizeQuery(t *testing.T) {
	validator := &sqlSecurityValidator{}

	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "Remove comments and normalize whitespace",
			input:    "SELECT * FROM users -- This is a comment\n   WHERE id = 1",
			expected: "select * from users where id = 1",
		},
		{
			name:     "Remove block comments",
			input:    "SELECT /* comment */ * FROM users",
			expected: "select * from users",
		},
		{
			name:     "Normalize multiple spaces",
			input:    "SELECT    *    FROM     users",
			expected: "select * from users",
		},
		{
			name:     "Trim whitespace",
			input:    "   SELECT * FROM users   ",
			expected: "select * from users",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := validator.normalizeQuery(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestSQLValidator_GetQueryType(t *testing.T) {
	validator := &sqlSecurityValidator{}

	tests := []struct {
		query    string
		expected string
	}{
		{"SELECT * FROM users", "SELECT"},
		{"INSERT INTO users VALUES (1, 'test')", "INSERT"},
		{"UPDATE users SET name = 'test'", "UPDATE"},
		{"DELETE FROM users WHERE id = 1", "DELETE"},
		{"CREATE TABLE test (id INT)", "CREATE"},
		{"ALTER TABLE users ADD COLUMN age INT", "ALTER"},
		{"DROP TABLE test", "DROP"},
		{"TRUNCATE TABLE users", "TRUNCATE"},
		{"GRANT SELECT ON users TO role", "OTHER"},
	}

	for _, tt := range tests {
		t.Run(tt.query, func(t *testing.T) {
			result := validator.getQueryType(tt.query)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestSQLValidator_ExtractTables(t *testing.T) {
	validator := &sqlSecurityValidator{}

	tests := []struct {
		name     string
		query    string
		expected []string
	}{
		{
			name:     "Simple SELECT",
			query:    "select * from users",
			expected: []string{"users"},
		},
		{
			name:     "SELECT with JOIN",
			query:    "select * from users u join profiles p on u.id = p.user_id",
			expected: []string{"users", "profiles"},
		},
		{
			name:     "INSERT statement",
			query:    "insert into users (name) values ('test')",
			expected: []string{"users"},
		},
		{
			name:     "UPDATE statement",
			query:    "update users set name = 'test' where id = 1",
			expected: []string{"users"},
		},
		{
			name:     "DELETE statement",
			query:    "delete from users where id = 1",
			expected: []string{"users"},
		},
		{
			name:     "Multiple tables with schema",
			query:    "select * from public.users join public.orders on users.id = orders.user_id",
			expected: []string{"users", "orders"},
		},
		{
			name:     "No tables",
			query:    "select 1 + 1",
			expected: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := validator.extractTables(tt.query)
			assert.ElementsMatch(t, tt.expected, result)
		})
	}
}

func TestSQLValidator_ValidateSQLSyntax(t *testing.T) {
	validator := &sqlSecurityValidator{}
	result := &SQLValidationResult{}

	tests := []struct {
		name        string
		query       string
		shouldError bool
	}{
		{
			name:        "Safe query",
			query:       "select * from users where id = 1",
			shouldError: false,
		},
		{
			name:        "SQL injection attempt - UNION",
			query:       "select * from users union select * from admin_users",
			shouldError: true,
		},
		{
			name:        "Information schema access",
			query:       "select * from information_schema.tables",
			shouldError: true,
		},
		{
			name:        "PostgreSQL catalog access",
			query:       "select * from pg_catalog.pg_tables",
			shouldError: true,
		},
		{
			name:        "PostgreSQL user access",
			query:       "select * from pg_user",
			shouldError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validator.validateSQLSyntax(tt.query, result)
			if tt.shouldError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestSQLValidator_CheckDangerousPatterns(t *testing.T) {
	validator := &sqlSecurityValidator{}

	tests := []struct {
		name             string
		query            string
		expectedRisk     string
		expectedWarnings int
	}{
		{
			name:             "Safe SELECT",
			query:            "select * from users where id = 1",
			expectedRisk:     "low",
			expectedWarnings: 0,
		},
		{
			name:             "DELETE with WHERE",
			query:            "delete from users where id = 1",
			expectedRisk:     "medium",
			expectedWarnings: 1,
		},
		{
			name:             "DELETE all records",
			query:            "delete from users",
			expectedRisk:     "medium",
			expectedWarnings: 1,
		},
		{
			name:             "UPDATE without WHERE",
			query:            "update users set status = 'inactive'",
			expectedRisk:     "medium",
			expectedWarnings: 1,
		},
		{
			name:             "DROP TABLE",
			query:            "drop table old_data",
			expectedRisk:     "medium",
			expectedWarnings: 1,
		},
		{
			name:             "TRUNCATE",
			query:            "truncate table logs",
			expectedRisk:     "medium",
			expectedWarnings: 1,
		},
		{
			name:             "Critical - DELETE from users",
			query:            "delete from users where status = 'inactive'",
			expectedRisk:     "critical",
			expectedWarnings: 2, // DELETE operation + affects core system data
		},
		{
			name:             "Critical - UPDATE users",
			query:            "update users set role = 'admin'",
			expectedRisk:     "critical",
			expectedWarnings: 2, // UPDATE without WHERE + affects core system data
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := &SQLValidationResult{
				RiskLevel: "low",
				Warnings:  []string{},
			}

			validator.checkDangerousPatterns(tt.query, result)

			assert.Equal(t, tt.expectedRisk, result.RiskLevel)
			assert.Equal(t, tt.expectedWarnings, len(result.Warnings))
		})
	}
}

func TestSQLValidator_EstimateQueryComplexity(t *testing.T) {
	validator := &sqlSecurityValidator{}

	tests := []struct {
		name              string
		query             string
		expectedRisk      string
		expectedTimeLimit int
		expectedEstRows   int64
	}{
		{
			name:              "Simple SELECT",
			query:             "select * from users limit 10",
			expectedRisk:      "low",
			expectedTimeLimit: 30000,
			expectedEstRows:   10,
		},
		{
			name:              "Complex query with joins",
			query:             "select * from users u join orders o on u.id = o.user_id join products p on o.product_id = p.id",
			expectedRisk:      "medium",
			expectedTimeLimit: 60000,
			expectedEstRows:   1000,
		},
		{
			name:              "Very complex query",
			query:             "select * from users u join orders o on u.id = o.user_id join products p on o.product_id = p.id join (select * from reviews) r on p.id = r.product_id",
			expectedRisk:      "high",
			expectedTimeLimit: 120000,
			expectedEstRows:   1000,
		},
		{
			name:              "Query with wildcards",
			query:             "select * from users where name like '%test%' and email like '%@example.com'",
			expectedRisk:      "low",
			expectedTimeLimit: 30000,
			expectedEstRows:   1000,
		},
		{
			name:              "Query with limit",
			query:             "select * from users limit 5000",
			expectedRisk:      "low",
			expectedTimeLimit: 30000,
			expectedEstRows:   5000,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := &SQLValidationResult{
				RiskLevel:          "low",
				ExecutionTimeLimit: 30000,
			}

			validator.estimateQueryComplexity(tt.query, result)

			assert.Equal(t, tt.expectedRisk, result.RiskLevel)
			assert.Equal(t, tt.expectedTimeLimit, result.ExecutionTimeLimit)
			assert.Equal(t, tt.expectedEstRows, result.EstimatedRows)
		})
	}
}

func TestSQLValidator_DetermineApprovalRequirement(t *testing.T) {
	validator := &sqlSecurityValidator{}

	tests := []struct {
		name             string
		riskLevel        string
		queryType        string
		estimatedRows    int64
		expectedApproval bool
	}{
		{
			name:             "Low risk SELECT",
			riskLevel:        "low",
			queryType:        "SELECT",
			estimatedRows:    100,
			expectedApproval: false,
		},
		{
			name:             "High risk query",
			riskLevel:        "high",
			queryType:        "DELETE",
			estimatedRows:    100,
			expectedApproval: true,
		},
		{
			name:             "Critical risk query",
			riskLevel:        "critical",
			queryType:        "UPDATE",
			estimatedRows:    100,
			expectedApproval: true,
		},
		{
			name:             "Many rows affected",
			riskLevel:        "low",
			queryType:        "SELECT",
			estimatedRows:    15000,
			expectedApproval: true,
		},
		{
			name:             "Schema change - CREATE",
			riskLevel:        "low",
			queryType:        "CREATE",
			estimatedRows:    0,
			expectedApproval: true,
		},
		{
			name:             "Schema change - ALTER",
			riskLevel:        "low",
			queryType:        "ALTER",
			estimatedRows:    0,
			expectedApproval: true,
		},
		{
			name:             "Schema change - DROP",
			riskLevel:        "low",
			queryType:        "DROP",
			estimatedRows:    0,
			expectedApproval: true,
		},
		{
			name:             "TRUNCATE operation",
			riskLevel:        "low",
			queryType:        "TRUNCATE",
			estimatedRows:    0,
			expectedApproval: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := &SQLValidationResult{
				RiskLevel:        tt.riskLevel,
				QueryType:        tt.queryType,
				EstimatedRows:    tt.estimatedRows,
				RequiresApproval: false,
			}

			validator.determineApprovalRequirement(result)

			assert.Equal(t, tt.expectedApproval, result.RequiresApproval)
		})
	}
}

func TestSQLValidator_HashQuery(t *testing.T) {
	validator := &sqlSecurityValidator{}

	query1 := "SELECT * FROM users WHERE id = 1"
	query2 := "SELECT * FROM users WHERE id = 2"
	query3 := "SELECT * FROM users WHERE id = 1" // Same as query1

	hash1 := validator.hashQuery(query1)
	hash2 := validator.hashQuery(query2)
	hash3 := validator.hashQuery(query3)

	// Hash should be deterministic
	assert.Equal(t, hash1, hash3)
	// Different queries should have different hashes
	assert.NotEqual(t, hash1, hash2)
	// Hash should be 64 characters (SHA256 hex)
	assert.Equal(t, 64, len(hash1))
}

func TestSQLValidator_Integration(t *testing.T) {
	// This test would require a real database connection
	// For now, we'll skip it unless integration tests are enabled
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	// Integration test setup would go here:
	// - Create test database
	// - Set up tables and permissions
	// - Test actual query execution
	// - Clean up test data
}

// Benchmark tests
func BenchmarkSQLValidator_ValidateQuery(b *testing.B) {
	mockRBAC := new(MockRBACEngine)
	mockRBAC.On("CanAccessTable", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(true, nil)

	validator := NewSQLSecurityValidator(nil, mockRBAC)
	execCtx := createTestExecutionContext()
	query := "SELECT u.id, u.name, p.email FROM users u JOIN profiles p ON u.id = p.user_id WHERE u.status = 'active' LIMIT 100"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := validator.ValidateQuery(context.Background(), query, execCtx)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkSQLValidator_NormalizeQuery(b *testing.B) {
	validator := &sqlSecurityValidator{}
	query := `
		SELECT u.id, u.name, p.email -- Get user info
		FROM users u
		JOIN profiles p ON u.id = p.user_id /* Join with profiles */
		WHERE u.status = 'active'
		   AND u.created_at > '2023-01-01'
		ORDER BY u.created_at DESC
		LIMIT 100
	`

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = validator.normalizeQuery(query)
	}
}

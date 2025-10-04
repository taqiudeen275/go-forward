package api

import (
	"context"
	"fmt"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/taqiudeen275/go-foward/internal/auth"
	"github.com/taqiudeen275/go-foward/pkg/interfaces"
)

// AuthConfig represents authentication configuration for API endpoints
type AuthConfig struct {
	RequireAuth      bool     `json:"require_auth"`
	RequireVerified  bool     `json:"require_verified"`
	AllowedRoles     []string `json:"allowed_roles"`
	RequireOwnership bool     `json:"require_ownership"`
	OwnershipColumn  string   `json:"ownership_column"`
	PublicRead       bool     `json:"public_read"`
	PublicWrite      bool     `json:"public_write"`
}

// RLSPolicyManager handles Row Level Security policy enforcement
type RLSPolicyManager struct {
	policies map[string]*RLSPolicy
}

// RLSPolicy represents a Row Level Security policy
type RLSPolicy struct {
	TableName  string            `json:"table_name"`
	PolicyName string            `json:"policy_name"`
	Operation  string            `json:"operation"` // SELECT, INSERT, UPDATE, DELETE, ALL
	Expression string            `json:"expression"`
	Roles      []string          `json:"roles"`
	Conditions map[string]string `json:"conditions"`
}

// NewRLSPolicyManager creates a new RLS policy manager
func NewRLSPolicyManager() *RLSPolicyManager {
	return &RLSPolicyManager{
		policies: make(map[string]*RLSPolicy),
	}
}

// AddPolicy adds an RLS policy
func (rpm *RLSPolicyManager) AddPolicy(policy *RLSPolicy) {
	key := fmt.Sprintf("%s_%s_%s", policy.TableName, policy.Operation, policy.PolicyName)
	rpm.policies[key] = policy
}

// GetPolicies returns all policies for a table and operation
func (rpm *RLSPolicyManager) GetPolicies(tableName, operation string) []*RLSPolicy {
	var policies []*RLSPolicy

	for key, policy := range rpm.policies {
		if strings.HasPrefix(key, tableName+"_") &&
			(policy.Operation == operation || policy.Operation == "ALL") {
			policies = append(policies, policy)
		}
	}

	return policies
}

// ApplyRLSPolicies applies Row Level Security policies to a query
func (s *Service) ApplyRLSPolicies(ctx context.Context, userID string, query interfaces.Query) interfaces.Query {
	// If no user context, return query as-is for now
	// In production, you might want to apply anonymous user policies
	if userID == "" {
		return query
	}

	// For now, return the query as-is
	// TODO: Implement actual RLS policy application based on table configuration
	return query
}

// AuthMiddleware creates authentication middleware for API endpoints
func (s *Service) AuthMiddleware(authMiddleware *auth.Middleware, config *AuthConfig) gin.HandlerFunc {
	return func(c *gin.Context) {
		// If no auth required, continue
		if !config.RequireAuth {
			c.Next()
			return
		}

		// Apply authentication middleware
		authMiddleware.RequireAuth()(c)
		if c.IsAborted() {
			return
		}

		// Get user from context
		user := authMiddleware.GetUserFromContext(c)
		if user == nil {
			c.JSON(401, gin.H{"error": "Authentication required"})
			c.Abort()
			return
		}

		// Check verification requirements
		if config.RequireVerified {
			if !user.EmailVerified && !user.PhoneVerified {
				c.JSON(403, gin.H{"error": "Account verification required"})
				c.Abort()
				return
			}
		}

		// Check role requirements
		if len(config.AllowedRoles) > 0 {
			userRole, hasRole := user.Metadata["role"]
			if !hasRole {
				c.JSON(403, gin.H{"error": "Insufficient permissions"})
				c.Abort()
				return
			}

			userRoleStr, ok := userRole.(string)
			if !ok {
				c.JSON(403, gin.H{"error": "Invalid role format"})
				c.Abort()
				return
			}

			allowed := false
			for _, role := range config.AllowedRoles {
				if userRoleStr == role {
					allowed = true
					break
				}
			}

			if !allowed {
				c.JSON(403, gin.H{"error": "Insufficient permissions"})
				c.Abort()
				return
			}
		}

		c.Next()
	}
}

// CreateAuthenticatedEndpoints creates endpoints with authentication
func (s *Service) CreateAuthenticatedEndpoints(table *interfaces.Table, authMiddleware *auth.Middleware, config *AuthConfig) {
	basePath := fmt.Sprintf("/api/v1/%s", strings.ToLower(table.Name))

	// Create endpoint configuration
	endpointConfig := &EndpointConfig{
		Table:       table,
		Path:        basePath,
		Methods:     []string{"GET", "POST", "PUT", "DELETE"},
		Handlers:    make(map[string]gin.HandlerFunc),
		IsGenerated: true,
	}

	// Create authenticated handlers
	endpointConfig.Handlers["GET"] = s.createAuthenticatedGetHandler(table, authMiddleware, config)
	endpointConfig.Handlers["POST"] = s.createAuthenticatedPostHandler(table, authMiddleware, config)
	endpointConfig.Handlers["PUT"] = s.createAuthenticatedPutHandler(table, authMiddleware, config)
	endpointConfig.Handlers["DELETE"] = s.createAuthenticatedDeleteHandler(table, authMiddleware, config)

	// Register routes with authentication middleware
	s.registerAuthenticatedRoutes(endpointConfig, authMiddleware, config)

	// Store endpoint configuration
	s.endpoints[table.Name] = endpointConfig
}

// registerAuthenticatedRoutes registers routes with authentication middleware
func (s *Service) registerAuthenticatedRoutes(config *EndpointConfig, authMiddleware *auth.Middleware, authConfig *AuthConfig) {
	basePath := config.Path

	// Apply authentication middleware based on configuration
	var middleware gin.HandlerFunc
	if authConfig.RequireAuth {
		middleware = s.AuthMiddleware(authMiddleware, authConfig)
	} else {
		middleware = authMiddleware.OptionalAuth()
	}

	// GET /api/v1/table - List all records
	if authConfig.PublicRead || authConfig.RequireAuth {
		s.router.GET(basePath, middleware, config.Handlers["GET"])
	}

	// GET /api/v1/table/:id - Get single record
	if authConfig.PublicRead || authConfig.RequireAuth {
		s.router.GET(basePath+"/:id", middleware, s.createAuthenticatedGetByIdHandler(config.Table, authMiddleware, authConfig))
	}

	// POST /api/v1/table - Create new record
	if authConfig.PublicWrite || authConfig.RequireAuth {
		s.router.POST(basePath, middleware, config.Handlers["POST"])
	}

	// PUT /api/v1/table/:id - Update record
	if authConfig.RequireAuth {
		s.router.PUT(basePath+"/:id", middleware, config.Handlers["PUT"])
	}

	// DELETE /api/v1/table/:id - Delete record
	if authConfig.RequireAuth {
		s.router.DELETE(basePath+"/:id", middleware, config.Handlers["DELETE"])
	}
}

// Authenticated handler creators

func (s *Service) createAuthenticatedGetHandler(table *interfaces.Table, authMiddleware *auth.Middleware, config *AuthConfig) gin.HandlerFunc {
	return func(c *gin.Context) {
		ctx := c.Request.Context()

		// Parse query parameters
		parser := NewQueryParameterParser(table)
		queryBuilder := parser.ParseQueryParameters(c)

		// Apply RLS policies if user is authenticated
		user := authMiddleware.GetUserFromContext(c)
		if user != nil && config.RequireOwnership && config.OwnershipColumn != "" {
			// Add ownership filter
			condition := fmt.Sprintf("%s = $%d", config.OwnershipColumn, queryBuilder.argIndex)
			queryBuilder.Where(condition, user.ID)
		}

		// Build and execute query
		query := queryBuilder.BuildQuery()
		result, err := s.metaService.ExecuteSQL(ctx, query.SQL, query.Args...)
		if err != nil {
			c.JSON(500, gin.H{"error": "Failed to fetch records"})
			return
		}

		// Get total count for pagination
		var totalCount int64
		if queryBuilder.limitVal > 0 || queryBuilder.offsetVal > 0 {
			countQuery := queryBuilder.BuildCountQuery()
			countResult, err := s.metaService.ExecuteSQL(ctx, countQuery.SQL, countQuery.Args...)
			if err == nil && len(countResult.Rows) > 0 {
				if count, ok := countResult.Rows[0]["count"].(int64); ok {
					totalCount = count
				}
			}
		} else {
			totalCount = int64(len(result.Rows))
		}

		// Build response
		response := gin.H{
			"data":  result.Rows,
			"count": len(result.Rows),
		}

		if queryBuilder.limitVal > 0 || queryBuilder.offsetVal > 0 {
			response["total_count"] = totalCount
			response["limit"] = queryBuilder.limitVal
			response["offset"] = queryBuilder.offsetVal

			if queryBuilder.limitVal > 0 {
				response["has_more"] = totalCount > int64(queryBuilder.offsetVal+len(result.Rows))
				response["page"] = (queryBuilder.offsetVal / queryBuilder.limitVal) + 1
				response["total_pages"] = (totalCount + int64(queryBuilder.limitVal) - 1) / int64(queryBuilder.limitVal)
			}
		}

		c.JSON(200, response)
	}
}

func (s *Service) createAuthenticatedGetByIdHandler(table *interfaces.Table, authMiddleware *auth.Middleware, config *AuthConfig) gin.HandlerFunc {
	return func(c *gin.Context) {
		ctx := c.Request.Context()
		id := c.Param("id")

		if id == "" {
			c.JSON(400, gin.H{"error": "ID parameter is required"})
			return
		}

		// Find primary key column
		pkColumn := s.getPrimaryKeyColumn(table)
		if pkColumn == nil {
			c.JSON(500, gin.H{"error": "Table has no primary key"})
			return
		}

		// Build base query
		queryBuilder := NewQueryBuilder(table)
		queryBuilder.Where(fmt.Sprintf("%s = $%d", pkColumn.Name, queryBuilder.argIndex), id)

		// Apply ownership filter if required
		user := authMiddleware.GetUserFromContext(c)
		if user != nil && config.RequireOwnership && config.OwnershipColumn != "" {
			condition := fmt.Sprintf("%s = $%d", config.OwnershipColumn, queryBuilder.argIndex)
			queryBuilder.Where(condition, user.ID)
		}

		// Execute query
		query := queryBuilder.BuildQuery()
		result, err := s.metaService.ExecuteSQL(ctx, query.SQL, query.Args...)
		if err != nil {
			c.JSON(500, gin.H{"error": "Failed to fetch record"})
			return
		}

		if len(result.Rows) == 0 {
			c.JSON(404, gin.H{"error": "Record not found"})
			return
		}

		c.JSON(200, gin.H{"data": result.Rows[0]})
	}
}

func (s *Service) createAuthenticatedPostHandler(table *interfaces.Table, authMiddleware *auth.Middleware, config *AuthConfig) gin.HandlerFunc {
	return func(c *gin.Context) {
		ctx := c.Request.Context()

		// Parse request body
		var requestData map[string]interface{}
		if err := c.ShouldBindJSON(&requestData); err != nil {
			c.JSON(400, gin.H{"error": "Invalid JSON data"})
			return
		}

		// Add ownership if required
		user := authMiddleware.GetUserFromContext(c)
		if user != nil && config.RequireOwnership && config.OwnershipColumn != "" {
			requestData[config.OwnershipColumn] = user.ID
		}

		// Validate request data
		if err := s.validateCreateData(table, requestData); err != nil {
			c.JSON(400, gin.H{"error": err.Error()})
			return
		}

		// Build and execute insert query
		query, err := s.buildInsertQuery(table, requestData)
		if err != nil {
			c.JSON(500, gin.H{"error": "Failed to build query"})
			return
		}

		result, err := s.metaService.ExecuteSQL(ctx, query.SQL, query.Args...)
		if err != nil {
			c.JSON(500, gin.H{"error": "Failed to create record"})
			return
		}

		if len(result.Rows) > 0 {
			c.JSON(201, gin.H{"data": result.Rows[0]})
		} else {
			c.JSON(201, gin.H{"message": "Record created successfully"})
		}
	}
}

func (s *Service) createAuthenticatedPutHandler(table *interfaces.Table, authMiddleware *auth.Middleware, config *AuthConfig) gin.HandlerFunc {
	return func(c *gin.Context) {
		ctx := c.Request.Context()
		id := c.Param("id")

		if id == "" {
			c.JSON(400, gin.H{"error": "ID parameter is required"})
			return
		}

		// Parse request body
		var requestData map[string]interface{}
		if err := c.ShouldBindJSON(&requestData); err != nil {
			c.JSON(400, gin.H{"error": "Invalid JSON data"})
			return
		}

		// Find primary key column
		pkColumn := s.getPrimaryKeyColumn(table)
		if pkColumn == nil {
			c.JSON(500, gin.H{"error": "Table has no primary key"})
			return
		}

		// Validate request data
		if err := s.validateUpdateData(table, requestData); err != nil {
			c.JSON(400, gin.H{"error": err.Error()})
			return
		}

		// Build update query with ownership check
		queryBuilder := NewQueryBuilder(table)

		// Add WHERE conditions
		queryBuilder.Where(fmt.Sprintf("%s = $%d", pkColumn.Name, queryBuilder.argIndex), id)

		// Add ownership filter if required
		user := authMiddleware.GetUserFromContext(c)
		if user != nil && config.RequireOwnership && config.OwnershipColumn != "" {
			condition := fmt.Sprintf("%s = $%d", config.OwnershipColumn, queryBuilder.argIndex)
			queryBuilder.Where(condition, user.ID)
		}

		// Build update query
		query, err := s.buildUpdateQueryWithOwnership(table, pkColumn.Name, id, requestData, user, config)
		if err != nil {
			c.JSON(500, gin.H{"error": "Failed to build query"})
			return
		}

		result, err := s.metaService.ExecuteSQL(ctx, query.SQL, query.Args...)
		if err != nil {
			c.JSON(500, gin.H{"error": "Failed to update record"})
			return
		}

		if len(result.Rows) > 0 {
			c.JSON(200, gin.H{"data": result.Rows[0]})
		} else {
			c.JSON(200, gin.H{"message": "Record updated successfully"})
		}
	}
}

func (s *Service) createAuthenticatedDeleteHandler(table *interfaces.Table, authMiddleware *auth.Middleware, config *AuthConfig) gin.HandlerFunc {
	return func(c *gin.Context) {
		ctx := c.Request.Context()
		id := c.Param("id")

		if id == "" {
			c.JSON(400, gin.H{"error": "ID parameter is required"})
			return
		}

		// Find primary key column
		pkColumn := s.getPrimaryKeyColumn(table)
		if pkColumn == nil {
			c.JSON(500, gin.H{"error": "Table has no primary key"})
			return
		}

		// Build delete query with ownership check
		queryBuilder := NewQueryBuilder(table)
		queryBuilder.Where(fmt.Sprintf("%s = $%d", pkColumn.Name, queryBuilder.argIndex), id)

		// Add ownership filter if required
		user := authMiddleware.GetUserFromContext(c)
		if user != nil && config.RequireOwnership && config.OwnershipColumn != "" {
			condition := fmt.Sprintf("%s = $%d", config.OwnershipColumn, queryBuilder.argIndex)
			queryBuilder.Where(condition, user.ID)
		}

		// Build final delete query
		query := s.buildDeleteQueryWithOwnership(table, pkColumn.Name, id, user, config)

		_, err := s.metaService.ExecuteSQL(ctx, query.SQL, query.Args...)
		if err != nil {
			c.JSON(500, gin.H{"error": "Failed to delete record"})
			return
		}

		c.JSON(200, gin.H{"message": "Record deleted successfully"})
	}
}

// Helper methods for building queries with ownership

func (s *Service) buildUpdateQueryWithOwnership(table *interfaces.Table, pkColumn, id string, data map[string]interface{}, user *auth.User, config *AuthConfig) (interfaces.Query, error) {
	var setClauses []string
	var args []interface{}
	argIndex := 1

	for _, col := range table.Columns {
		if value, exists := data[col.Name]; exists && !col.IsPrimaryKey {
			setClauses = append(setClauses, fmt.Sprintf("%s = $%d", col.Name, argIndex))
			args = append(args, value)
			argIndex++
		}
	}

	if len(setClauses) == 0 {
		return interfaces.Query{}, fmt.Errorf("no valid columns to update")
	}

	// Build WHERE clause
	whereClause := fmt.Sprintf("%s = $%d", pkColumn, argIndex)
	args = append(args, id)
	argIndex++

	// Add ownership check if required
	if user != nil && config.RequireOwnership && config.OwnershipColumn != "" {
		whereClause += fmt.Sprintf(" AND %s = $%d", config.OwnershipColumn, argIndex)
		args = append(args, user.ID)
	}

	query := fmt.Sprintf(
		"UPDATE %s.%s SET %s WHERE %s RETURNING *",
		table.Schema,
		table.Name,
		strings.Join(setClauses, ", "),
		whereClause,
	)

	return interfaces.Query{
		SQL:  query,
		Args: args,
	}, nil
}

func (s *Service) buildDeleteQueryWithOwnership(table *interfaces.Table, pkColumn, id string, user *auth.User, config *AuthConfig) interfaces.Query {
	var args []interface{}
	argIndex := 1

	// Build WHERE clause
	whereClause := fmt.Sprintf("%s = $%d", pkColumn, argIndex)
	args = append(args, id)
	argIndex++

	// Add ownership check if required
	if user != nil && config.RequireOwnership && config.OwnershipColumn != "" {
		whereClause += fmt.Sprintf(" AND %s = $%d", config.OwnershipColumn, argIndex)
		args = append(args, user.ID)
	}

	query := fmt.Sprintf("DELETE FROM %s.%s WHERE %s", table.Schema, table.Name, whereClause)

	return interfaces.Query{
		SQL:  query,
		Args: args,
	}
}

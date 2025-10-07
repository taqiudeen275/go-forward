package api

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/taqiudeen275/go-foward/internal/auth"
	"github.com/taqiudeen275/go-foward/pkg/interfaces"
)

// Service implements the APIService interface for auto-generated REST endpoints
type Service struct {
	metaService  interfaces.MetaService
	endpoints    map[string]*EndpointConfig
	router       *gin.Engine
	rlsPolicyMgr *RLSPolicyManager
	authConfigs  map[string]*AuthConfig
}

// EndpointConfig represents configuration for a generated endpoint
type EndpointConfig struct {
	Table       *interfaces.Table
	Path        string
	Methods     []string
	Handlers    map[string]gin.HandlerFunc
	IsGenerated bool
}

// NewService creates a new API service instance
func NewService(metaService interfaces.MetaService) *Service {
	return &Service{
		metaService:  metaService,
		endpoints:    make(map[string]*EndpointConfig),
		router:       gin.New(),
		rlsPolicyMgr: NewRLSPolicyManager(),
		authConfigs:  make(map[string]*AuthConfig),
	}
}

// GenerateEndpoints automatically creates CRUD endpoints from database schema
func (s *Service) GenerateEndpoints(ctx context.Context, schema interfaces.DatabaseSchema) error {
	for _, table := range schema.Tables {
		if err := s.generateTableEndpoints(ctx, table); err != nil {
			return fmt.Errorf("failed to generate endpoints for table %s: %w", table.Name, err)
		}
	}
	return nil
}

// generateTableEndpoints creates CRUD endpoints for a specific table
func (s *Service) generateTableEndpoints(ctx context.Context, table *interfaces.Table) error {
	// Skip system tables
	if s.isSystemTable(table.Name) {
		return nil
	}

	basePath := fmt.Sprintf("/api/v1/%s", strings.ToLower(table.Name))

	config := &EndpointConfig{
		Table:       table,
		Path:        basePath,
		Methods:     []string{"GET", "POST", "PUT", "DELETE"},
		Handlers:    make(map[string]gin.HandlerFunc),
		IsGenerated: true,
	}

	// Generate handlers for each HTTP method
	config.Handlers["GET"] = s.createGetHandler(table)
	config.Handlers["POST"] = s.createPostHandler(table)
	config.Handlers["PUT"] = s.createPutHandler(table)
	config.Handlers["DELETE"] = s.createDeleteHandler(table)

	// Register routes
	s.registerTableRoutes(config)

	// Store endpoint configuration
	s.endpoints[table.Name] = config

	return nil
}

// registerTableRoutes registers HTTP routes for a table
func (s *Service) registerTableRoutes(config *EndpointConfig) {
	basePath := config.Path

	// GET /api/v1/table - List all records
	s.router.GET(basePath, config.Handlers["GET"])

	// GET /api/v1/table/:id - Get single record
	s.router.GET(basePath+"/:id", s.createGetByIdHandler(config.Table))

	// POST /api/v1/table - Create new record
	s.router.POST(basePath, config.Handlers["POST"])

	// PUT /api/v1/table/:id - Update record
	s.router.PUT(basePath+"/:id", config.Handlers["PUT"])

	// DELETE /api/v1/table/:id - Delete record
	s.router.DELETE(basePath+"/:id", config.Handlers["DELETE"])
}

// RegisterCustomEndpoint allows registration of custom endpoints
func (s *Service) RegisterCustomEndpoint(path string, handler http.HandlerFunc) {
	// Convert http.HandlerFunc to gin.HandlerFunc
	ginHandler := gin.WrapH(handler)
	s.router.Any(path, ginHandler)
}

// GetEndpoints returns information about all registered endpoints
func (s *Service) GetEndpoints() []interfaces.EndpointInfo {
	var endpoints []interfaces.EndpointInfo

	for _, config := range s.endpoints {
		for _, method := range config.Methods {
			endpoint := interfaces.EndpointInfo{
				Path:        config.Path,
				Method:      method,
				Description: fmt.Sprintf("%s operation for %s table", method, config.Table.Name),
				Parameters:  s.getEndpointParameters(config.Table, method),
				IsGenerated: config.IsGenerated,
			}
			endpoints = append(endpoints, endpoint)
		}
	}

	return endpoints
}

// GetRouter returns the Gin router for integration with the gateway
func (s *Service) GetRouter() *gin.Engine {
	return s.router
}

// RegisterRoutes registers API service routes with the gateway
func (s *Service) RegisterRoutes(router gin.IRouter) {
	// Register all routes from the internal router to the gateway router
	// This handles both authenticated and non-authenticated endpoints
	for _, route := range s.router.Routes() {
		// The internal router already has the correct paths (e.g., /api/v1/products)
		// Register them directly with the gateway router
		switch route.Method {
		case "GET":
			router.GET(route.Path, route.HandlerFunc)
		case "POST":
			router.POST(route.Path, route.HandlerFunc)
		case "PUT":
			router.PUT(route.Path, route.HandlerFunc)
		case "DELETE":
			router.DELETE(route.Path, route.HandlerFunc)
		case "PATCH":
			router.PATCH(route.Path, route.HandlerFunc)
		}
	}
}

// Name returns the service name
func (s *Service) Name() string {
	return "api"
}

// Helper methods

// isSystemTable checks if a table should be excluded from API generation
func (s *Service) isSystemTable(tableName string) bool {
	systemTables := map[string]bool{
		"schema_migrations":     true,
		"goose_db_version":      true,
		"flyway_schema_history": true,
		"users":                 true, // Handled by auth service
		"user_sessions":         true, // Handled by auth service
		"otps":                  true, // Handled by auth service
	}
	return systemTables[tableName]
}

// getEndpointParameters returns parameter information for an endpoint
func (s *Service) getEndpointParameters(table *interfaces.Table, method string) map[string]string {
	params := make(map[string]string)

	switch method {
	case "GET":
		params["limit"] = "Maximum number of records to return"
		params["offset"] = "Number of records to skip"
		params["order"] = "Column to order by"
		params["select"] = "Columns to select (comma-separated)"

		// Add filterable columns
		for _, col := range table.Columns {
			params[col.Name] = fmt.Sprintf("Filter by %s", col.Name)
		}

	case "POST":
		for _, col := range table.Columns {
			if !col.IsPrimaryKey && col.DefaultValue == nil {
				params[col.Name] = fmt.Sprintf("Value for %s column", col.Name)
			}
		}

	case "PUT":
		params["id"] = "Record ID to update"
		for _, col := range table.Columns {
			if !col.IsPrimaryKey {
				params[col.Name] = fmt.Sprintf("New value for %s column", col.Name)
			}
		}

	case "DELETE":
		params["id"] = "Record ID to delete"
	}

	return params
}

// SetTableAuthConfig sets authentication configuration for a table
func (s *Service) SetTableAuthConfig(tableName string, config *AuthConfig) {
	s.authConfigs[tableName] = config
}

// GetTableAuthConfig gets authentication configuration for a table
func (s *Service) GetTableAuthConfig(tableName string) *AuthConfig {
	if config, exists := s.authConfigs[tableName]; exists {
		return config
	}

	// Return default configuration
	return &AuthConfig{
		RequireAuth:      false,
		RequireVerified:  false,
		AllowedRoles:     []string{},
		RequireOwnership: false,
		OwnershipColumn:  "",
		PublicRead:       true,
		PublicWrite:      false,
	}
}

// AddRLSPolicy adds a Row Level Security policy
func (s *Service) AddRLSPolicy(policy *RLSPolicy) {
	s.rlsPolicyMgr.AddPolicy(policy)
}

// GenerateEndpointsWithAuth generates endpoints with authentication support
func (s *Service) GenerateEndpointsWithAuth(ctx context.Context, schema interfaces.DatabaseSchema, authMiddleware *auth.Middleware) error {
	for _, table := range schema.Tables {
		if err := s.generateTableEndpointsWithAuth(ctx, table, authMiddleware); err != nil {
			return fmt.Errorf("failed to generate endpoints for table %s: %w", table.Name, err)
		}
	}
	return nil
}

// generateTableEndpointsWithAuth creates CRUD endpoints with authentication for a specific table
func (s *Service) generateTableEndpointsWithAuth(ctx context.Context, table *interfaces.Table, authMiddleware *auth.Middleware) error {
	// Skip system tables
	if s.isSystemTable(table.Name) {
		return nil
	}

	// Get authentication configuration for this table
	authConfig := s.GetTableAuthConfig(table.Name)

	// Create authenticated endpoints
	s.CreateAuthenticatedEndpoints(table, authMiddleware, authConfig)

	return nil
}

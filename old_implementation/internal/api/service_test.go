package api

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/taqiudeen275/go-foward/pkg/interfaces"
)

// MockMetaService is a mock implementation of MetaService
type MockMetaService struct {
	mock.Mock
}

func (m *MockMetaService) GetTables(ctx context.Context, schema string) ([]*interfaces.Table, error) {
	args := m.Called(ctx, schema)
	return args.Get(0).([]*interfaces.Table), args.Error(1)
}

func (m *MockMetaService) GetTable(ctx context.Context, schema string, tableName string) (*interfaces.Table, error) {
	args := m.Called(ctx, schema, tableName)
	return args.Get(0).(*interfaces.Table), args.Error(1)
}

func (m *MockMetaService) CreateTable(ctx context.Context, table interfaces.TableDefinition) error {
	args := m.Called(ctx, table)
	return args.Error(0)
}

func (m *MockMetaService) UpdateTable(ctx context.Context, tableName string, changes interfaces.TableChanges) error {
	args := m.Called(ctx, tableName, changes)
	return args.Error(0)
}

func (m *MockMetaService) DeleteTable(ctx context.Context, tableName string) error {
	args := m.Called(ctx, tableName)
	return args.Error(0)
}

func (m *MockMetaService) ExecuteSQL(ctx context.Context, query string, args ...interface{}) (*interfaces.QueryResult, error) {
	mockArgs := m.Called(ctx, query, args)
	return mockArgs.Get(0).(*interfaces.QueryResult), mockArgs.Error(1)
}

func (m *MockMetaService) GetSchemas(ctx context.Context) ([]string, error) {
	args := m.Called(ctx)
	return args.Get(0).([]string), args.Error(1)
}

func (m *MockMetaService) CreateSchema(ctx context.Context, schemaName string) error {
	args := m.Called(ctx, schemaName)
	return args.Error(0)
}

func (m *MockMetaService) DeleteSchema(ctx context.Context, schemaName string) error {
	args := m.Called(ctx, schemaName)
	return args.Error(0)
}

func TestNewService(t *testing.T) {
	mockMeta := &MockMetaService{}
	service := NewService(mockMeta)

	assert.NotNil(t, service)
	assert.Equal(t, mockMeta, service.metaService)
	assert.NotNil(t, service.endpoints)
	assert.NotNil(t, service.router)
}

func TestGenerateEndpoints(t *testing.T) {
	mockMeta := &MockMetaService{}
	service := NewService(mockMeta)

	// Create test schema with a simple table
	schema := interfaces.DatabaseSchema{
		Tables: []*interfaces.Table{
			{
				Name:   "products",
				Schema: "public",
				Columns: []*interfaces.Column{
					{
						Name:         "id",
						Type:         "integer",
						IsPrimaryKey: true,
						Nullable:     false,
					},
					{
						Name:     "name",
						Type:     "varchar",
						Nullable: false,
					},
					{
						Name:     "price",
						Type:     "decimal",
						Nullable: true,
					},
				},
			},
		},
	}

	ctx := context.Background()
	err := service.GenerateEndpoints(ctx, schema)

	assert.NoError(t, err)
	assert.Len(t, service.endpoints, 1)
	assert.Contains(t, service.endpoints, "products")

	config := service.endpoints["products"]
	assert.Equal(t, "/api/v1/products", config.Path)
	assert.Equal(t, []string{"GET", "POST", "PUT", "DELETE"}, config.Methods)
	assert.True(t, config.IsGenerated)
	assert.Len(t, config.Handlers, 4)
}

func TestGenerateEndpoints_SkipsSystemTables(t *testing.T) {
	mockMeta := &MockMetaService{}
	service := NewService(mockMeta)

	// Create schema with system tables
	schema := interfaces.DatabaseSchema{
		Tables: []*interfaces.Table{
			{
				Name:   "users", // System table - handled by auth service
				Schema: "public",
				Columns: []*interfaces.Column{
					{Name: "id", Type: "integer", IsPrimaryKey: true},
				},
			},
			{
				Name:   "schema_migrations", // System table
				Schema: "public",
				Columns: []*interfaces.Column{
					{Name: "version", Type: "varchar", IsPrimaryKey: true},
				},
			},
			{
				Name:   "products", // Regular table
				Schema: "public",
				Columns: []*interfaces.Column{
					{Name: "id", Type: "integer", IsPrimaryKey: true},
				},
			},
		},
	}

	ctx := context.Background()
	err := service.GenerateEndpoints(ctx, schema)

	assert.NoError(t, err)
	assert.Len(t, service.endpoints, 1) // Only products table should be processed
	assert.Contains(t, service.endpoints, "products")
	assert.NotContains(t, service.endpoints, "users")
	assert.NotContains(t, service.endpoints, "schema_migrations")
}

func TestGetEndpoints(t *testing.T) {
	mockMeta := &MockMetaService{}
	service := NewService(mockMeta)

	// Add a test endpoint configuration
	table := &interfaces.Table{
		Name:   "products",
		Schema: "public",
		Columns: []*interfaces.Column{
			{Name: "id", Type: "integer", IsPrimaryKey: true},
			{Name: "name", Type: "varchar"},
		},
	}

	config := &EndpointConfig{
		Table:       table,
		Path:        "/api/v1/products",
		Methods:     []string{"GET", "POST"},
		IsGenerated: true,
	}

	service.endpoints["products"] = config

	endpoints := service.GetEndpoints()

	assert.Len(t, endpoints, 2) // GET and POST

	for _, endpoint := range endpoints {
		assert.Equal(t, "/api/v1/products", endpoint.Path)
		assert.Contains(t, []string{"GET", "POST"}, endpoint.Method)
		assert.True(t, endpoint.IsGenerated)
		assert.Contains(t, endpoint.Description, "products table")
		assert.NotEmpty(t, endpoint.Parameters)
	}
}

func TestIsSystemTable(t *testing.T) {
	service := &Service{}

	testCases := []struct {
		tableName string
		expected  bool
	}{
		{"users", true},
		{"user_sessions", true},
		{"otps", true},
		{"schema_migrations", true},
		{"goose_db_version", true},
		{"flyway_schema_history", true},
		{"products", false},
		{"orders", false},
		{"customers", false},
	}

	for _, tc := range testCases {
		t.Run(tc.tableName, func(t *testing.T) {
			result := service.isSystemTable(tc.tableName)
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestGetPrimaryKeyColumn(t *testing.T) {
	service := &Service{}

	table := &interfaces.Table{
		Columns: []*interfaces.Column{
			{Name: "name", Type: "varchar", IsPrimaryKey: false},
			{Name: "id", Type: "integer", IsPrimaryKey: true},
			{Name: "email", Type: "varchar", IsPrimaryKey: false},
		},
	}

	pkCol := service.getPrimaryKeyColumn(table)

	assert.NotNil(t, pkCol)
	assert.Equal(t, "id", pkCol.Name)
	assert.True(t, pkCol.IsPrimaryKey)
}

func TestGetPrimaryKeyColumn_NoPrimaryKey(t *testing.T) {
	service := &Service{}

	table := &interfaces.Table{
		Columns: []*interfaces.Column{
			{Name: "name", Type: "varchar", IsPrimaryKey: false},
			{Name: "email", Type: "varchar", IsPrimaryKey: false},
		},
	}

	pkCol := service.getPrimaryKeyColumn(table)

	assert.Nil(t, pkCol)
}

func TestIsValidColumn(t *testing.T) {
	service := &Service{}

	table := &interfaces.Table{
		Columns: []*interfaces.Column{
			{Name: "id", Type: "integer"},
			{Name: "name", Type: "varchar"},
			{Name: "email", Type: "varchar"},
		},
	}

	testCases := []struct {
		columnName string
		expected   bool
	}{
		{"id", true},
		{"name", true},
		{"email", true},
		{"invalid_column", false},
		{"", false},
	}

	for _, tc := range testCases {
		t.Run(tc.columnName, func(t *testing.T) {
			result := service.isValidColumn(table, tc.columnName)
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestGetEndpointParameters(t *testing.T) {
	service := &Service{}

	table := &interfaces.Table{
		Name: "products",
		Columns: []*interfaces.Column{
			{Name: "id", Type: "integer", IsPrimaryKey: true},
			{Name: "name", Type: "varchar"},
			{Name: "price", Type: "decimal"},
		},
	}

	// Test GET parameters
	getParams := service.getEndpointParameters(table, "GET")
	assert.Contains(t, getParams, "limit")
	assert.Contains(t, getParams, "offset")
	assert.Contains(t, getParams, "order")
	assert.Contains(t, getParams, "select")
	assert.Contains(t, getParams, "id")
	assert.Contains(t, getParams, "name")
	assert.Contains(t, getParams, "price")

	// Test POST parameters
	postParams := service.getEndpointParameters(table, "POST")
	assert.Contains(t, postParams, "name")
	assert.Contains(t, postParams, "price")
	assert.NotContains(t, postParams, "id") // Primary key not included

	// Test PUT parameters
	putParams := service.getEndpointParameters(table, "PUT")
	assert.Contains(t, putParams, "id")
	assert.Contains(t, putParams, "name")
	assert.Contains(t, putParams, "price")

	// Test DELETE parameters
	deleteParams := service.getEndpointParameters(table, "DELETE")
	assert.Contains(t, deleteParams, "id")
	assert.Len(t, deleteParams, 1) // Only ID parameter
}

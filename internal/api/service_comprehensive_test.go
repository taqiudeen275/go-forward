package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/taqiudeen275/go-foward/pkg/interfaces"
)

// TestEndpointGeneration tests the automatic generation and registration of CRUD endpoints
func TestEndpointGeneration(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tests := []struct {
		name           string
		schema         interfaces.DatabaseSchema
		expectedTables int
		expectedRoutes []string
	}{
		{
			name: "single table endpoint generation",
			schema: interfaces.DatabaseSchema{
				Tables: []*interfaces.Table{
					createTestTable("products", []interfaces.Column{
						{Name: "id", Type: "integer", IsPrimaryKey: true, Nullable: false},
						{Name: "name", Type: "varchar", Nullable: false, MaxLength: 255},
						{Name: "price", Type: "decimal", Nullable: true},
						{Name: "active", Type: "boolean", Nullable: false},
					}),
				},
			},
			expectedTables: 1,
			expectedRoutes: []string{
				"GET /api/v1/products",
				"POST /api/v1/products",
				"PUT /api/v1/products",
				"DELETE /api/v1/products",
			},
		},
		{
			name: "multiple tables endpoint generation",
			schema: interfaces.DatabaseSchema{
				Tables: []*interfaces.Table{
					createTestTable("products", []interfaces.Column{
						{Name: "id", Type: "integer", IsPrimaryKey: true},
						{Name: "name", Type: "varchar"},
					}),
					createTestTable("categories", []interfaces.Column{
						{Name: "id", Type: "integer", IsPrimaryKey: true},
						{Name: "title", Type: "varchar"},
					}),
				},
			},
			expectedTables: 2,
			expectedRoutes: []string{
				"GET /api/v1/products",
				"POST /api/v1/products",
				"GET /api/v1/categories",
				"POST /api/v1/categories",
			},
		},
		{
			name: "system tables are skipped",
			schema: interfaces.DatabaseSchema{
				Tables: []*interfaces.Table{
					createTestTable("users", []interfaces.Column{
						{Name: "id", Type: "integer", IsPrimaryKey: true},
					}),
					createTestTable("schema_migrations", []interfaces.Column{
						{Name: "version", Type: "varchar", IsPrimaryKey: true},
					}),
					createTestTable("products", []interfaces.Column{
						{Name: "id", Type: "integer", IsPrimaryKey: true},
					}),
				},
			},
			expectedTables: 1, // Only products should be processed
			expectedRoutes: []string{
				"GET /api/v1/products",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockMeta := &MockMetaService{}
			service := NewService(mockMeta)

			ctx := context.Background()
			err := service.GenerateEndpoints(ctx, tt.schema)

			assert.NoError(t, err)
			assert.Len(t, service.endpoints, tt.expectedTables)

			// Verify endpoint information
			endpoints := service.GetEndpoints()
			for _, expectedRoute := range tt.expectedRoutes {
				found := false
				for _, endpoint := range endpoints {
					routeStr := fmt.Sprintf("%s %s", endpoint.Method, endpoint.Path)
					if routeStr == expectedRoute {
						found = true
						break
					}
				}
				assert.True(t, found, "Expected route %s not found", expectedRoute)
			}
		})
	}
}

// TestCRUDOperationsWithDataTypes tests CRUD operations with various PostgreSQL data types
func TestCRUDOperationsWithDataTypes(t *testing.T) {
	gin.SetMode(gin.TestMode)

	// Create a comprehensive test table with various data types
	table := createTestTable("test_table", []interfaces.Column{
		{Name: "id", Type: "integer", IsPrimaryKey: true, Nullable: false},
		{Name: "name", Type: "varchar", Nullable: false, MaxLength: 255},
		{Name: "description", Type: "text", Nullable: true},
		{Name: "price", Type: "decimal", Nullable: true, Precision: 10, Scale: 2},
		{Name: "quantity", Type: "integer", Nullable: false},
		{Name: "weight", Type: "real", Nullable: true},
		{Name: "is_active", Type: "boolean", Nullable: false},
		{Name: "created_at", Type: "timestamp", Nullable: false},
		{Name: "metadata", Type: "jsonb", Nullable: true},
		{Name: "tags", Type: "text[]", Nullable: true},
		{Name: "uuid_field", Type: "uuid", Nullable: true},
	})

	tests := []struct {
		name         string
		method       string
		path         string
		requestBody  map[string]interface{}
		mockResponse *interfaces.QueryResult
		expectedCode int
		expectedData map[string]interface{}
	}{
		{
			name:   "CREATE with various data types",
			method: "POST",
			path:   "/api/v1/test_table",
			requestBody: map[string]interface{}{
				"name":        "Test Product",
				"description": "A test product description",
				"price":       99.99,
				"quantity":    10,
				"weight":      1.5,
				"is_active":   true,
				"created_at":  "2023-01-01T00:00:00Z",
				"metadata":    map[string]interface{}{"color": "red", "size": "large"},
				"uuid_field":  "123e4567-e89b-12d3-a456-426614174000",
			},
			mockResponse: &interfaces.QueryResult{
				Columns: []string{"id", "name", "price", "is_active"},
				Rows: []map[string]interface{}{
					{
						"id":        1,
						"name":      "Test Product",
						"price":     99.99,
						"is_active": true,
					},
				},
			},
			expectedCode: 201,
			expectedData: map[string]interface{}{
				"id":        float64(1),
				"name":      "Test Product",
				"price":     99.99,
				"is_active": true,
			},
		},
		{
			name:   "READ single record",
			method: "GET",
			path:   "/api/v1/test_table/1",
			mockResponse: &interfaces.QueryResult{
				Columns: []string{"id", "name", "price", "is_active"},
				Rows: []map[string]interface{}{
					{
						"id":        1,
						"name":      "Test Product",
						"price":     99.99,
						"is_active": true,
					},
				},
			},
			expectedCode: 200,
			expectedData: map[string]interface{}{
				"id":        float64(1),
				"name":      "Test Product",
				"price":     99.99,
				"is_active": true,
			},
		},
		{
			name:   "UPDATE with partial data",
			method: "PUT",
			path:   "/api/v1/test_table/1",
			requestBody: map[string]interface{}{
				"name":      "Updated Product",
				"price":     149.99,
				"is_active": false,
			},
			mockResponse: &interfaces.QueryResult{
				Columns: []string{"id", "name", "price", "is_active"},
				Rows: []map[string]interface{}{
					{
						"id":        1,
						"name":      "Updated Product",
						"price":     149.99,
						"is_active": false,
					},
				},
			},
			expectedCode: 200,
			expectedData: map[string]interface{}{
				"id":        float64(1),
				"name":      "Updated Product",
				"price":     149.99,
				"is_active": false,
			},
		},
		{
			name:         "DELETE record",
			method:       "DELETE",
			path:         "/api/v1/test_table/1",
			mockResponse: &interfaces.QueryResult{Rows: []map[string]interface{}{}},
			expectedCode: 200,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockMeta := &MockMetaService{}
			service := NewService(mockMeta)

			// Generate endpoints for the test table
			schema := interfaces.DatabaseSchema{Tables: []*interfaces.Table{table}}
			err := service.GenerateEndpoints(context.Background(), schema)
			assert.NoError(t, err)

			// Setup mock expectations
			mockMeta.On("ExecuteSQL", mock.Anything, mock.AnythingOfType("string"), mock.Anything).
				Return(tt.mockResponse, nil)

			// Create test request
			var req *http.Request
			if tt.requestBody != nil {
				body, _ := json.Marshal(tt.requestBody)
				req = httptest.NewRequest(tt.method, tt.path, bytes.NewBuffer(body))
				req.Header.Set("Content-Type", "application/json")
			} else {
				req = httptest.NewRequest(tt.method, tt.path, nil)
			}

			// Execute request
			w := httptest.NewRecorder()
			service.router.ServeHTTP(w, req)

			// Verify response
			assert.Equal(t, tt.expectedCode, w.Code)

			if tt.expectedData != nil {
				var response map[string]interface{}
				err := json.Unmarshal(w.Body.Bytes(), &response)
				assert.NoError(t, err)

				data, exists := response["data"]
				assert.True(t, exists)

				dataMap, ok := data.(map[string]interface{})
				assert.True(t, ok)

				for key, expectedValue := range tt.expectedData {
					assert.Equal(t, expectedValue, dataMap[key])
				}
			}

			mockMeta.AssertExpectations(t)
		})
	}
}

// TestQueryParametersAndFiltering tests various query parameters and filtering options
func TestQueryParametersAndFiltering(t *testing.T) {
	gin.SetMode(gin.TestMode)

	table := createTestTable("products", []interfaces.Column{
		{Name: "id", Type: "integer", IsPrimaryKey: true},
		{Name: "name", Type: "varchar", MaxLength: 255},
		{Name: "price", Type: "decimal", Precision: 10, Scale: 2},
		{Name: "category", Type: "varchar", MaxLength: 100},
		{Name: "is_active", Type: "boolean"},
		{Name: "created_at", Type: "timestamp"},
		{Name: "rating", Type: "real"},
	})

	tests := []struct {
		name            string
		queryParams     string
		expectedSQL     []string // SQL patterns that should be present
		expectedArgs    []interface{}
		mockResponse    *interfaces.QueryResult
		expectedResults int
	}{
		{
			name:        "basic pagination",
			queryParams: "limit=10&offset=20",
			expectedSQL: []string{"LIMIT 10", "OFFSET 20"},
			mockResponse: &interfaces.QueryResult{
				Rows: []map[string]interface{}{
					{"id": 1, "name": "Product 1"},
					{"id": 2, "name": "Product 2"},
				},
			},
			expectedResults: 2,
		},
		{
			name:        "column selection",
			queryParams: "select=id,name,price",
			expectedSQL: []string{"SELECT id, name, price"},
			mockResponse: &interfaces.QueryResult{
				Rows: []map[string]interface{}{
					{"id": 1, "name": "Product 1", "price": 99.99},
				},
			},
			expectedResults: 1,
		},
		{
			name:         "equality filtering",
			queryParams:  "category=electronics&is_active=true",
			expectedSQL:  []string{"WHERE", "category = $", "is_active = $"},
			expectedArgs: []interface{}{"electronics", "true"},
			mockResponse: &interfaces.QueryResult{
				Rows: []map[string]interface{}{
					{"id": 1, "name": "Laptop", "category": "electronics"},
				},
			},
			expectedResults: 1,
		},
		{
			name:         "range filtering",
			queryParams:  "price_gt=50&price_lt=200",
			expectedSQL:  []string{"WHERE", "price > $", "price < $"},
			expectedArgs: []interface{}{"50", "200"},
			mockResponse: &interfaces.QueryResult{
				Rows: []map[string]interface{}{
					{"id": 1, "name": "Product 1", "price": 99.99},
				},
			},
			expectedResults: 1,
		},
		{
			name:         "string pattern matching",
			queryParams:  "name_like=laptop&category_starts=elec",
			expectedSQL:  []string{"WHERE", "LOWER(name) LIKE LOWER($", "category ILIKE $"},
			expectedArgs: []interface{}{"%laptop%", "elec%"},
			mockResponse: &interfaces.QueryResult{
				Rows: []map[string]interface{}{
					{"id": 1, "name": "Gaming Laptop", "category": "electronics"},
				},
			},
			expectedResults: 1,
		},
		{
			name:         "IN filtering",
			queryParams:  "id_in=1,2,3&category_in=electronics,books",
			expectedSQL:  []string{"WHERE", "id IN ($", "category IN ($"},
			expectedArgs: []interface{}{"1", "2", "3", "electronics", "books"},
			mockResponse: &interfaces.QueryResult{
				Rows: []map[string]interface{}{
					{"id": 1, "name": "Product 1"},
					{"id": 2, "name": "Product 2"},
				},
			},
			expectedResults: 2,
		},
		{
			name:        "null filtering",
			queryParams: "rating_null=false",
			expectedSQL: []string{"WHERE", "rating IS NOT NULL"},
			mockResponse: &interfaces.QueryResult{
				Rows: []map[string]interface{}{
					{"id": 1, "name": "Product 1", "rating": 4.5},
				},
			},
			expectedResults: 1,
		},
		{
			name:        "ordering",
			queryParams: "order=name&desc=true",
			expectedSQL: []string{"ORDER BY name DESC"},
			mockResponse: &interfaces.QueryResult{
				Rows: []map[string]interface{}{
					{"id": 2, "name": "Product Z"},
					{"id": 1, "name": "Product A"},
				},
			},
			expectedResults: 2,
		},
		{
			name:        "multiple column ordering",
			queryParams: "order_by=category%20ASC,price%20DESC",
			expectedSQL: []string{"ORDER BY category ASC, price DESC"},
			mockResponse: &interfaces.QueryResult{
				Rows: []map[string]interface{}{
					{"id": 1, "name": "Product 1"},
				},
			},
			expectedResults: 1,
		},
		{
			name:        "complex combined filtering",
			queryParams: "select=id,name,price&category=electronics&price_gte=100&is_active=true&order=price&limit=5",
			expectedSQL: []string{
				"SELECT id, name, price",
				"WHERE",
				"category = $",
				"price >= $",
				"is_active = $",
				"ORDER BY price ASC",
				"LIMIT 5",
			},
			expectedArgs: []interface{}{"electronics", "100", "true"},
			mockResponse: &interfaces.QueryResult{
				Rows: []map[string]interface{}{
					{"id": 1, "name": "Laptop", "price": 999.99},
				},
			},
			expectedResults: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockMeta := &MockMetaService{}
			service := NewService(mockMeta)

			// Generate endpoints
			schema := interfaces.DatabaseSchema{Tables: []*interfaces.Table{table}}
			err := service.GenerateEndpoints(context.Background(), schema)
			assert.NoError(t, err)

			// Setup mock expectations - capture the SQL query
			var capturedSQL string
			var capturedArgs []interface{}
			var callCount int
			mockMeta.On("ExecuteSQL", mock.Anything, mock.AnythingOfType("string"), mock.Anything).
				Run(func(args mock.Arguments) {
					sql := args.Get(1).(string)
					// Capture the main query (not the count query)
					if !strings.Contains(sql, "COUNT(*)") {
						capturedSQL = sql
						capturedArgs = args.Get(2).([]interface{})
					}
					callCount++
				}).
				Return(tt.mockResponse, nil)

			// For pagination tests, also mock the count query
			if tt.queryParams == "limit=10&offset=20" {
				countResponse := &interfaces.QueryResult{
					Rows: []map[string]interface{}{{"count": int64(100)}},
				}
				mockMeta.On("ExecuteSQL", mock.Anything, mock.MatchedBy(func(sql string) bool {
					return strings.Contains(sql, "COUNT(*)")
				}), mock.Anything).Return(countResponse, nil)
			}

			// Create and execute request
			url := fmt.Sprintf("/api/v1/products?%s", tt.queryParams)
			req := httptest.NewRequest("GET", url, nil)
			w := httptest.NewRecorder()

			service.router.ServeHTTP(w, req)

			// Verify response code
			assert.Equal(t, 200, w.Code)

			// Verify SQL patterns
			for _, expectedPattern := range tt.expectedSQL {
				assert.Contains(t, capturedSQL, expectedPattern,
					"Expected SQL pattern '%s' not found in: %s", expectedPattern, capturedSQL)
			}

			// Verify arguments if specified
			if tt.expectedArgs != nil {
				assert.Equal(t, len(tt.expectedArgs), len(capturedArgs))
				// For complex queries, just check that all expected args are present
				if len(tt.expectedArgs) > 2 {
					for _, expectedArg := range tt.expectedArgs {
						found := false
						for _, actualArg := range capturedArgs {
							if expectedArg == actualArg {
								found = true
								break
							}
						}
						assert.True(t, found, "Expected argument %v not found in %v", expectedArg, capturedArgs)
					}
				} else {
					// For simple queries, check exact order
					for i, expectedArg := range tt.expectedArgs {
						if i < len(capturedArgs) {
							assert.Equal(t, expectedArg, capturedArgs[i])
						}
					}
				}
			}

			// Verify response structure
			var response map[string]interface{}
			err = json.Unmarshal(w.Body.Bytes(), &response)
			assert.NoError(t, err)

			data, exists := response["data"]
			assert.True(t, exists)

			dataArray, ok := data.([]interface{})
			assert.True(t, ok)
			assert.Len(t, dataArray, tt.expectedResults)

			mockMeta.AssertExpectations(t)
		})
	}
}

// TestDataValidation tests request data validation for different data types
func TestDataValidation(t *testing.T) {
	gin.SetMode(gin.TestMode)

	table := createTestTable("validation_test", []interfaces.Column{
		{Name: "id", Type: "integer", IsPrimaryKey: true, Nullable: false},
		{Name: "name", Type: "varchar", Nullable: false, MaxLength: 10},
		{Name: "email", Type: "varchar", Nullable: false, MaxLength: 255},
		{Name: "age", Type: "integer", Nullable: true},
		{Name: "price", Type: "decimal", Nullable: true},
		{Name: "is_active", Type: "boolean", Nullable: false},
		{Name: "created_at", Type: "timestamp", Nullable: true},
		{Name: "metadata", Type: "jsonb", Nullable: true},
	})

	tests := []struct {
		name          string
		method        string
		requestBody   map[string]interface{}
		expectedCode  int
		expectedError string
	}{
		{
			name:   "valid create request",
			method: "POST",
			requestBody: map[string]interface{}{
				"name":       "John",
				"email":      "john@example.com",
				"age":        25,
				"price":      99.99,
				"is_active":  true,
				"created_at": "2023-01-01T00:00:00Z",
				"metadata":   map[string]interface{}{"role": "user"},
			},
			expectedCode: 201,
		},
		{
			name:   "missing required field",
			method: "POST",
			requestBody: map[string]interface{}{
				"email":     "john@example.com",
				"is_active": true,
			},
			expectedCode:  400,
			expectedError: "field 'name' is required",
		},
		{
			name:   "string too long",
			method: "POST",
			requestBody: map[string]interface{}{
				"name":      "ThisNameIsTooLong",
				"email":     "john@example.com",
				"is_active": true,
			},
			expectedCode:  400,
			expectedError: "exceeds maximum length",
		},
		{
			name:   "invalid data type",
			method: "POST",
			requestBody: map[string]interface{}{
				"name":      "John",
				"email":     "john@example.com",
				"age":       "not_a_number",
				"is_active": true,
			},
			expectedCode:  400,
			expectedError: "expected integer value",
		},
		{
			name:   "update with primary key",
			method: "PUT",
			requestBody: map[string]interface{}{
				"id":   123,
				"name": "John",
			},
			expectedCode:  400,
			expectedError: "cannot update primary key",
		},
		{
			name:   "unknown field",
			method: "POST",
			requestBody: map[string]interface{}{
				"name":          "John",
				"email":         "john@example.com",
				"is_active":     true,
				"unknown_field": "value",
			},
			expectedCode:  400,
			expectedError: "unknown field",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockMeta := &MockMetaService{}
			service := NewService(mockMeta)

			// Generate endpoints
			schema := interfaces.DatabaseSchema{Tables: []*interfaces.Table{table}}
			err := service.GenerateEndpoints(context.Background(), schema)
			assert.NoError(t, err)

			// For successful requests, mock the database response
			if tt.expectedCode < 400 {
				mockResponse := &interfaces.QueryResult{
					Rows: []map[string]interface{}{
						{"id": 1, "name": "John", "email": "john@example.com"},
					},
				}
				mockMeta.On("ExecuteSQL", mock.Anything, mock.AnythingOfType("string"), mock.Anything).
					Return(mockResponse, nil)
			}

			// Create request
			body, _ := json.Marshal(tt.requestBody)
			var path string
			if tt.method == "PUT" {
				path = "/api/v1/validation_test/1"
			} else {
				path = "/api/v1/validation_test"
			}
			req := httptest.NewRequest(tt.method, path, bytes.NewBuffer(body))
			req.Header.Set("Content-Type", "application/json")

			// Execute request
			w := httptest.NewRecorder()
			service.router.ServeHTTP(w, req)

			// Verify response
			assert.Equal(t, tt.expectedCode, w.Code)

			if tt.expectedError != "" {
				var response map[string]interface{}
				err := json.Unmarshal(w.Body.Bytes(), &response)
				assert.NoError(t, err)

				errorMsg, exists := response["error"]
				assert.True(t, exists)
				assert.Contains(t, errorMsg.(string), tt.expectedError)
			}

			if tt.expectedCode < 400 {
				mockMeta.AssertExpectations(t)
			}
		})
	}
}

// TestErrorHandling tests various error scenarios
func TestErrorHandling(t *testing.T) {
	gin.SetMode(gin.TestMode)

	table := createTestTable("error_test", []interfaces.Column{
		{Name: "id", Type: "integer", IsPrimaryKey: true},
		{Name: "name", Type: "varchar"},
	})

	tests := []struct {
		name         string
		method       string
		path         string
		mockError    error
		expectedCode int
		expectedMsg  string
	}{
		{
			name:         "database connection error",
			method:       "GET",
			path:         "/api/v1/error_test",
			mockError:    fmt.Errorf("connection failed"),
			expectedCode: 500,
			expectedMsg:  "Failed to fetch records",
		},
		{
			name:         "record not found",
			method:       "GET",
			path:         "/api/v1/error_test/999",
			mockError:    nil,
			expectedCode: 404,
			expectedMsg:  "Record not found",
		},
		{
			name:         "missing ID parameter",
			method:       "GET",
			path:         "/api/v1/error_test/invalid",
			mockError:    nil,
			expectedCode: 404,
			expectedMsg:  "Record not found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockMeta := &MockMetaService{}
			service := NewService(mockMeta)

			// Generate endpoints
			schema := interfaces.DatabaseSchema{Tables: []*interfaces.Table{table}}
			err := service.GenerateEndpoints(context.Background(), schema)
			assert.NoError(t, err)

			// Setup mock expectations
			if tt.mockError != nil {
				mockMeta.On("ExecuteSQL", mock.Anything, mock.AnythingOfType("string"), mock.Anything).
					Return((*interfaces.QueryResult)(nil), tt.mockError)
			} else if tt.expectedMsg == "Record not found" {
				// Return empty result for not found test
				mockMeta.On("ExecuteSQL", mock.Anything, mock.AnythingOfType("string"), mock.Anything).
					Return(&interfaces.QueryResult{Rows: []map[string]interface{}{}}, nil)
			}

			// Execute request
			req := httptest.NewRequest(tt.method, tt.path, nil)
			w := httptest.NewRecorder()
			service.router.ServeHTTP(w, req)

			// Verify response
			assert.Equal(t, tt.expectedCode, w.Code)

			if tt.expectedMsg != "" {
				var response map[string]interface{}
				err := json.Unmarshal(w.Body.Bytes(), &response)
				assert.NoError(t, err)

				errorMsg, exists := response["error"]
				assert.True(t, exists)
				assert.Contains(t, errorMsg.(string), tt.expectedMsg)
			}

			if tt.mockError != nil || tt.expectedMsg == "Record not found" {
				mockMeta.AssertExpectations(t)
			}
		})
	}
}

// Helper function to create test tables
func createTestTable(name string, columns []interfaces.Column) *interfaces.Table {
	var cols []*interfaces.Column
	for _, col := range columns {
		cols = append(cols, &interfaces.Column{
			Name:         col.Name,
			Type:         col.Type,
			Nullable:     col.Nullable,
			DefaultValue: col.DefaultValue,
			IsPrimaryKey: col.IsPrimaryKey,
			IsForeignKey: col.IsForeignKey,
			IsUnique:     col.IsUnique,
			MaxLength:    col.MaxLength,
			Precision:    col.Precision,
			Scale:        col.Scale,
		})
	}

	return &interfaces.Table{
		Name:    name,
		Schema:  "public",
		Columns: cols,
	}
}

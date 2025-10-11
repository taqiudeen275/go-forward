package api

import (
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/taqiudeen275/go-foward/pkg/interfaces"
)

func TestNewQueryBuilder(t *testing.T) {
	table := &interfaces.Table{
		Name:   "products",
		Schema: "public",
		Columns: []*interfaces.Column{
			{Name: "id", Type: "integer", IsPrimaryKey: true},
			{Name: "name", Type: "varchar"},
		},
	}

	qb := NewQueryBuilder(table)

	assert.NotNil(t, qb)
	assert.Equal(t, table, qb.table)
	assert.Equal(t, 1, qb.argIndex)
}

func TestQueryBuilder_Select(t *testing.T) {
	table := &interfaces.Table{
		Name:   "products",
		Schema: "public",
		Columns: []*interfaces.Column{
			{Name: "id", Type: "integer"},
			{Name: "name", Type: "varchar"},
			{Name: "price", Type: "decimal"},
		},
	}

	qb := NewQueryBuilder(table)
	result := qb.Select("id", "name", "invalid_column")

	assert.Equal(t, qb, result)                            // Should return self for chaining
	assert.Equal(t, []string{"id", "name"}, qb.selectCols) // Invalid column should be filtered out
}

func TestQueryBuilder_Where(t *testing.T) {
	table := &interfaces.Table{
		Name:   "products",
		Schema: "public",
		Columns: []*interfaces.Column{
			{Name: "id", Type: "integer"},
		},
	}

	qb := NewQueryBuilder(table)
	result := qb.Where("id = $1", 123)

	assert.Equal(t, qb, result)
	assert.Equal(t, []string{"id = $1"}, qb.whereConds)
	assert.Equal(t, []interface{}{123}, qb.args)
	assert.Equal(t, 2, qb.argIndex)
}

func TestQueryBuilder_OrderBy(t *testing.T) {
	table := &interfaces.Table{
		Name:   "products",
		Schema: "public",
		Columns: []*interfaces.Column{
			{Name: "id", Type: "integer"},
			{Name: "name", Type: "varchar"},
		},
	}

	qb := NewQueryBuilder(table)

	// Test valid column with ASC
	qb.OrderBy("name", "ASC")
	assert.Equal(t, []string{"name ASC"}, qb.orderByCols)

	// Test valid column with DESC
	qb.OrderBy("id", "DESC")
	assert.Equal(t, []string{"name ASC", "id DESC"}, qb.orderByCols)

	// Test invalid direction (should default to ASC)
	qb.OrderBy("name", "INVALID")
	assert.Equal(t, []string{"name ASC", "id DESC", "name ASC"}, qb.orderByCols)

	// Test invalid column (should be ignored)
	initialLen := len(qb.orderByCols)
	qb.OrderBy("invalid_column", "ASC")
	assert.Equal(t, initialLen, len(qb.orderByCols))
}

func TestQueryBuilder_LimitOffset(t *testing.T) {
	table := &interfaces.Table{Name: "products", Schema: "public"}
	qb := NewQueryBuilder(table)

	// Test valid limit
	qb.Limit(50)
	assert.Equal(t, 50, qb.limitVal)

	// Test limit too high (should be ignored)
	qb.Limit(2000)
	assert.Equal(t, 50, qb.limitVal) // Should remain unchanged

	// Test valid offset
	qb.Offset(100)
	assert.Equal(t, 100, qb.offsetVal)

	// Test negative offset (should be ignored)
	qb.Offset(-10)
	assert.Equal(t, 100, qb.offsetVal) // Should remain unchanged
}

func TestQueryBuilder_BuildQuery(t *testing.T) {
	table := &interfaces.Table{
		Name:   "products",
		Schema: "public",
		Columns: []*interfaces.Column{
			{Name: "id", Type: "integer"},
			{Name: "name", Type: "varchar"},
			{Name: "price", Type: "decimal"},
		},
	}

	qb := NewQueryBuilder(table)
	qb.Select("id", "name").
		Where("price > $1", 100).
		OrderBy("name", "ASC").
		Limit(10).
		Offset(20)

	query := qb.BuildQuery()

	expectedSQL := "SELECT id, name FROM public.products WHERE price > $1 ORDER BY name ASC LIMIT 10 OFFSET 20"
	assert.Equal(t, expectedSQL, query.SQL)
	assert.Equal(t, []interface{}{100}, query.Args)
}

func TestQueryBuilder_BuildCountQuery(t *testing.T) {
	table := &interfaces.Table{
		Name:   "products",
		Schema: "public",
		Columns: []*interfaces.Column{
			{Name: "id", Type: "integer"},
			{Name: "name", Type: "varchar"},
		},
	}

	qb := NewQueryBuilder(table)
	qb.Where("name LIKE $1", "%test%")

	countQuery := qb.BuildCountQuery()

	expectedSQL := "SELECT COUNT(*) FROM public.products WHERE name LIKE $1"
	assert.Equal(t, expectedSQL, countQuery.SQL)
	assert.Equal(t, []interface{}{"%test%"}, countQuery.Args)
}

func TestNewQueryParameterParser(t *testing.T) {
	table := &interfaces.Table{Name: "products", Schema: "public"}
	parser := NewQueryParameterParser(table)

	assert.NotNil(t, parser)
	assert.Equal(t, table, parser.table)
}

func TestQueryParameterParser_ParseQueryParameters(t *testing.T) {
	table := &interfaces.Table{
		Name:   "products",
		Schema: "public",
		Columns: []*interfaces.Column{
			{Name: "id", Type: "integer"},
			{Name: "name", Type: "varchar"},
			{Name: "price", Type: "decimal"},
			{Name: "created_at", Type: "timestamp"},
		},
	}

	// Create a test HTTP request with query parameters
	req := httptest.NewRequest("GET", "/products?select=id,name&name=test&price_gt=100&order=name&desc=true&limit=20&offset=10", nil)
	w := httptest.NewRecorder()

	gin.SetMode(gin.TestMode)
	c, _ := gin.CreateTestContext(w)
	c.Request = req

	parser := NewQueryParameterParser(table)
	qb := parser.ParseQueryParameters(c)

	// Build the query to test the results
	query := qb.BuildQuery()

	// Check that the query contains expected elements
	assert.Contains(t, query.SQL, "SELECT id, name")
	assert.Contains(t, query.SQL, "FROM public.products")
	assert.Contains(t, query.SQL, "ORDER BY name DESC")
	assert.Contains(t, query.SQL, "LIMIT 20")
	assert.Contains(t, query.SQL, "OFFSET 10")

	// Check arguments
	assert.Contains(t, query.Args, "test")
	assert.Contains(t, query.Args, "100")
}

func TestQueryParameterParser_ParseWhereConditions(t *testing.T) {
	table := &interfaces.Table{
		Name:   "products",
		Schema: "public",
		Columns: []*interfaces.Column{
			{Name: "id", Type: "integer"},
			{Name: "name", Type: "varchar"},
			{Name: "price", Type: "decimal"},
			{Name: "active", Type: "boolean"},
		},
	}

	// Test various filter types
	testCases := []struct {
		name         string
		queryString  string
		expectedSQL  []string
		expectedArgs []interface{}
	}{
		{
			name:         "equality filter",
			queryString:  "name=test",
			expectedSQL:  []string{"name = $"},
			expectedArgs: []interface{}{"test"},
		},
		{
			name:         "greater than filter",
			queryString:  "price_gt=100",
			expectedSQL:  []string{"price > $"},
			expectedArgs: []interface{}{"100"},
		},
		{
			name:         "like filter",
			queryString:  "name_like=prod",
			expectedSQL:  []string{"LOWER(name) LIKE LOWER($"},
			expectedArgs: []interface{}{"%prod%"},
		},
		{
			name:         "in filter",
			queryString:  "id_in=1,2,3",
			expectedSQL:  []string{"id IN ($"},
			expectedArgs: []interface{}{"1", "2", "3"},
		},
		{
			name:         "null filter",
			queryString:  "active_null=true",
			expectedSQL:  []string{"active IS NULL"},
			expectedArgs: []interface{}{},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/products?"+tc.queryString, nil)
			w := httptest.NewRecorder()

			gin.SetMode(gin.TestMode)
			c, _ := gin.CreateTestContext(w)
			c.Request = req

			parser := NewQueryParameterParser(table)
			qb := parser.ParseQueryParameters(c)
			query := qb.BuildQuery()

			// Check that expected SQL patterns are present
			for _, expectedSQL := range tc.expectedSQL {
				assert.Contains(t, query.SQL, expectedSQL)
			}

			// Check arguments (length should match)
			if len(tc.expectedArgs) > 0 {
				assert.Equal(t, len(tc.expectedArgs), len(query.Args))
			}
		})
	}
}

func TestQueryParameterParser_IsNumericOrDateColumn(t *testing.T) {
	parser := &QueryParameterParser{}

	testCases := []struct {
		columnType string
		expected   bool
	}{
		{"integer", true},
		{"bigint", true},
		{"decimal", true},
		{"timestamp", true},
		{"date", true},
		{"varchar", false},
		{"text", false},
		{"boolean", false},
	}

	for _, tc := range testCases {
		t.Run(tc.columnType, func(t *testing.T) {
			col := &interfaces.Column{Type: tc.columnType}
			result := parser.isNumericOrDateColumn(col)
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestQueryParameterParser_IsStringColumn(t *testing.T) {
	parser := &QueryParameterParser{}

	testCases := []struct {
		columnType string
		expected   bool
	}{
		{"varchar", true},
		{"text", true},
		{"char", true},
		{"integer", false},
		{"boolean", false},
		{"timestamp", false},
	}

	for _, tc := range testCases {
		t.Run(tc.columnType, func(t *testing.T) {
			col := &interfaces.Column{Type: tc.columnType}
			result := parser.isStringColumn(col)
			assert.Equal(t, tc.expected, result)
		})
	}
}

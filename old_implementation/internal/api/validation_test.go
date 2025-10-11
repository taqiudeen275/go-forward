package api

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/taqiudeen275/go-foward/pkg/interfaces"
)

// TestRequestValidator tests the request validation functionality
func TestRequestValidator(t *testing.T) {
	table := &interfaces.Table{
		Name:   "test_table",
		Schema: "public",
		Columns: []*interfaces.Column{
			{Name: "id", Type: "integer", IsPrimaryKey: true, Nullable: false},
			{Name: "name", Type: "varchar", Nullable: false, MaxLength: 50},
			{Name: "email", Type: "varchar", Nullable: false, MaxLength: 255},
			{Name: "age", Type: "integer", Nullable: true},
			{Name: "price", Type: "decimal", Nullable: true, Precision: 10, Scale: 2},
			{Name: "is_active", Type: "boolean", Nullable: false},
			{Name: "created_at", Type: "timestamp", Nullable: true},
			{Name: "metadata", Type: "jsonb", Nullable: true},
			{Name: "uuid_field", Type: "uuid", Nullable: true},
			{Name: "ip_address", Type: "inet", Nullable: true},
			{Name: "data", Type: "bytea", Nullable: true},
		},
	}

	validator := NewRequestValidator(table)

	t.Run("ValidateCreateRequest", func(t *testing.T) {
		tests := []struct {
			name        string
			data        map[string]interface{}
			expectError bool
			errorMsg    string
		}{
			{
				name: "valid create request",
				data: map[string]interface{}{
					"name":       "John Doe",
					"email":      "john@example.com",
					"age":        25,
					"price":      99.99,
					"is_active":  true,
					"created_at": "2023-01-01T00:00:00Z",
					"metadata":   map[string]interface{}{"role": "user"},
					"uuid_field": "123e4567-e89b-12d3-a456-426614174000",
					"ip_address": "192.168.1.1",
					"data":       "base64encodeddata",
				},
				expectError: false,
			},
			{
				name: "missing required field",
				data: map[string]interface{}{
					"email":     "john@example.com",
					"is_active": true,
				},
				expectError: true,
				errorMsg:    "field 'name' is required",
			},
			{
				name: "unknown field",
				data: map[string]interface{}{
					"name":          "John Doe",
					"email":         "john@example.com",
					"is_active":     true,
					"unknown_field": "value",
				},
				expectError: true,
				errorMsg:    "unknown field 'unknown_field'",
			},
			{
				name: "string too long",
				data: map[string]interface{}{
					"name":      "This name is way too long for the field constraint and should fail",
					"email":     "john@example.com",
					"is_active": true,
				},
				expectError: true,
				errorMsg:    "string exceeds maximum length",
			},
			{
				name: "invalid integer",
				data: map[string]interface{}{
					"name":      "John Doe",
					"email":     "john@example.com",
					"age":       "not_a_number",
					"is_active": true,
				},
				expectError: true,
				errorMsg:    "invalid integer format",
			},
			{
				name: "invalid boolean",
				data: map[string]interface{}{
					"name":      "John Doe",
					"email":     "john@example.com",
					"is_active": "maybe",
				},
				expectError: true,
				errorMsg:    "invalid boolean format",
			},
			{
				name: "invalid UUID",
				data: map[string]interface{}{
					"name":       "John Doe",
					"email":      "john@example.com",
					"is_active":  true,
					"uuid_field": "invalid-uuid",
				},
				expectError: true,
				errorMsg:    "invalid UUID format",
			},
			{
				name: "invalid IP address",
				data: map[string]interface{}{
					"name":       "John Doe",
					"email":      "john@example.com",
					"is_active":  true,
					"ip_address": "invalid.ip.address",
				},
				expectError: true,
				errorMsg:    "invalid IP address format",
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				err := validator.ValidateCreateRequest(tt.data)

				if tt.expectError {
					assert.Error(t, err)
					if tt.errorMsg != "" {
						assert.Contains(t, err.Error(), tt.errorMsg)
					}
				} else {
					assert.NoError(t, err)
				}
			})
		}
	})

	t.Run("ValidateUpdateRequest", func(t *testing.T) {
		tests := []struct {
			name        string
			data        map[string]interface{}
			expectError bool
			errorMsg    string
		}{
			{
				name: "valid update request",
				data: map[string]interface{}{
					"name":  "Updated Name",
					"email": "updated@example.com",
					"age":   30,
				},
				expectError: false,
			},
			{
				name: "update with primary key",
				data: map[string]interface{}{
					"id":   123,
					"name": "Updated Name",
				},
				expectError: true,
				errorMsg:    "cannot update primary key field 'id'",
			},
			{
				name: "partial update",
				data: map[string]interface{}{
					"name": "Only Name Updated",
				},
				expectError: false,
			},
			{
				name: "unknown field in update",
				data: map[string]interface{}{
					"name":          "Updated Name",
					"unknown_field": "value",
				},
				expectError: true,
				errorMsg:    "unknown field 'unknown_field'",
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				err := validator.ValidateUpdateRequest(tt.data)

				if tt.expectError {
					assert.Error(t, err)
					if tt.errorMsg != "" {
						assert.Contains(t, err.Error(), tt.errorMsg)
					}
				} else {
					assert.NoError(t, err)
				}
			})
		}
	})
}

// TestDataTypeValidation tests validation of specific data types
func TestDataTypeValidation(t *testing.T) {
	table := &interfaces.Table{
		Name:   "type_test",
		Schema: "public",
		Columns: []*interfaces.Column{
			{Name: "int_field", Type: "integer", Nullable: true},
			{Name: "bigint_field", Type: "bigint", Nullable: true},
			{Name: "smallint_field", Type: "smallint", Nullable: true},
			{Name: "decimal_field", Type: "decimal", Nullable: true},
			{Name: "real_field", Type: "real", Nullable: true},
			{Name: "double_field", Type: "double", Nullable: true},
			{Name: "text_field", Type: "text", Nullable: true},
			{Name: "varchar_field", Type: "varchar", MaxLength: 10, Nullable: true},
			{Name: "bool_field", Type: "boolean", Nullable: true},
			{Name: "date_field", Type: "date", Nullable: true},
			{Name: "time_field", Type: "time", Nullable: true},
			{Name: "timestamp_field", Type: "timestamp", Nullable: true},
			{Name: "json_field", Type: "jsonb", Nullable: true},
			{Name: "uuid_field", Type: "uuid", Nullable: true},
			{Name: "inet_field", Type: "inet", Nullable: true},
			{Name: "bytea_field", Type: "bytea", Nullable: true},
		},
	}

	validator := NewRequestValidator(table)

	tests := []struct {
		fieldName     string
		validValues   []interface{}
		invalidValues []interface{}
	}{
		{
			fieldName:     "int_field",
			validValues:   []interface{}{123, 0, -456, "789", float64(123)},
			invalidValues: []interface{}{"not_a_number", true, map[string]interface{}{}},
		},
		{
			fieldName:     "bigint_field",
			validValues:   []interface{}{int64(123456789), "123456789", float64(123)},
			invalidValues: []interface{}{"not_a_number", true, []interface{}{}},
		},
		{
			fieldName:     "smallint_field",
			validValues:   []interface{}{123, -456, "789"},
			invalidValues: []interface{}{"not_a_number", 100000}, // Out of smallint range
		},
		{
			fieldName:     "decimal_field",
			validValues:   []interface{}{123.45, "678.90", 100},
			invalidValues: []interface{}{"not_a_number", true},
		},
		{
			fieldName:     "real_field",
			validValues:   []interface{}{123.45, "678.90", 100},
			invalidValues: []interface{}{"not_a_number", []interface{}{}},
		},
		{
			fieldName:     "double_field",
			validValues:   []interface{}{123.45, "678.90", 100},
			invalidValues: []interface{}{"not_a_number", map[string]interface{}{}},
		},
		{
			fieldName:     "text_field",
			validValues:   []interface{}{"hello", "world", ""},
			invalidValues: []interface{}{123, true, []interface{}{}},
		},
		{
			fieldName:     "varchar_field",
			validValues:   []interface{}{"short", ""},
			invalidValues: []interface{}{"this_is_too_long", 123},
		},
		{
			fieldName:     "bool_field",
			validValues:   []interface{}{true, false, "true", "false", "t", "f", "yes", "no", "y", "n", "1", "0", 1, 0, 1.0, 0.0},
			invalidValues: []interface{}{"maybe", "invalid", 2, 1.5},
		},
		{
			fieldName:     "date_field",
			validValues:   []interface{}{"2023-01-01", "2023/01/01", "01/01/2023"},
			invalidValues: []interface{}{"invalid-date", 123, true},
		},
		{
			fieldName:     "time_field",
			validValues:   []interface{}{"15:04:05", "15:04", "3:04:05 PM"},
			invalidValues: []interface{}{"invalid-time", 123, true},
		},
		{
			fieldName:     "timestamp_field",
			validValues:   []interface{}{"2023-01-01T15:04:05Z", "2023-01-01 15:04:05", "2023-01-01T15:04:05.000000Z"},
			invalidValues: []interface{}{"invalid-timestamp", 123, true},
		},
		{
			fieldName:     "json_field",
			validValues:   []interface{}{map[string]interface{}{"key": "value"}, []interface{}{1, 2, 3}, "string", 123, true, nil},
			invalidValues: []interface{}{}, // JSON can accept most types
		},
		{
			fieldName:     "uuid_field",
			validValues:   []interface{}{"123e4567-e89b-12d3-a456-426614174000", "550e8400-e29b-41d4-a716-446655440000"},
			invalidValues: []interface{}{"invalid-uuid", "123-456", 123, true},
		},
		{
			fieldName:     "inet_field",
			validValues:   []interface{}{"192.168.1.1", "10.0.0.1/24"},
			invalidValues: []interface{}{"invalid.ip", "999.999.999.999", 123, true},
		},
		{
			fieldName:     "bytea_field",
			validValues:   []interface{}{"base64data", []byte{1, 2, 3}},
			invalidValues: []interface{}{123, true, map[string]interface{}{}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.fieldName, func(t *testing.T) {
			// Test valid values
			for _, validValue := range tt.validValues {
				data := map[string]interface{}{tt.fieldName: validValue}
				err := validator.ValidateCreateRequest(data)
				assert.NoError(t, err, "Expected %v to be valid for %s", validValue, tt.fieldName)
			}

			// Test invalid values
			for _, invalidValue := range tt.invalidValues {
				data := map[string]interface{}{tt.fieldName: invalidValue}
				err := validator.ValidateCreateRequest(data)
				assert.Error(t, err, "Expected %v to be invalid for %s", invalidValue, tt.fieldName)
			}
		})
	}
}

// TestNormalizeType tests the type normalization functionality
func TestNormalizeType(t *testing.T) {
	validator := &RequestValidator{}

	tests := []struct {
		pgType     string
		normalized string
	}{
		{"int4", "integer"},
		{"int", "integer"},
		{"serial", "integer"},
		{"int8", "bigint"},
		{"bigserial", "bigint"},
		{"int2", "smallint"},
		{"smallserial", "smallint"},
		{"float4", "real"},
		{"float8", "double"},
		{"varchar(255)", "varchar"},
		{"char(10)", "char"},
		{"text", "text"},
		{"bool", "boolean"},
		{"timestamptz", "timestamp"},
		{"timetz", "time"},
		{"numeric(10,2)", "numeric"},
		{"unknown_type", "unknown_type"},
	}

	for _, tt := range tests {
		t.Run(tt.pgType, func(t *testing.T) {
			result := validator.normalizeType(tt.pgType)
			assert.Equal(t, tt.normalized, result)
		})
	}
}

// TestValidFieldCheck tests the field validation functionality
func TestValidFieldCheck(t *testing.T) {
	table := &interfaces.Table{
		Columns: []*interfaces.Column{
			{Name: "id"},
			{Name: "name"},
			{Name: "email"},
		},
	}

	validator := NewRequestValidator(table)

	tests := []struct {
		fieldName string
		expected  bool
	}{
		{"id", true},
		{"name", true},
		{"email", true},
		{"unknown_field", false},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.fieldName, func(t *testing.T) {
			result := validator.isValidField(tt.fieldName)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestNullValueHandling tests handling of null values
func TestNullValueHandling(t *testing.T) {
	table := &interfaces.Table{
		Columns: []*interfaces.Column{
			{Name: "nullable_field", Type: "varchar", Nullable: true},
			{Name: "required_field", Type: "varchar", Nullable: false},
		},
	}

	validator := NewRequestValidator(table)

	tests := []struct {
		name        string
		data        map[string]interface{}
		expectError bool
		errorMsg    string
	}{
		{
			name: "null value in nullable field",
			data: map[string]interface{}{
				"nullable_field": nil,
				"required_field": "value",
			},
			expectError: false,
		},
		{
			name: "null value in required field",
			data: map[string]interface{}{
				"nullable_field": "value",
				"required_field": nil,
			},
			expectError: true,
			errorMsg:    "field cannot be null",
		},
		{
			name: "missing nullable field",
			data: map[string]interface{}{
				"required_field": "value",
			},
			expectError: false,
		},
		{
			name: "missing required field",
			data: map[string]interface{}{
				"nullable_field": "value",
			},
			expectError: true,
			errorMsg:    "field 'required_field' is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validator.ValidateCreateRequest(tt.data)

			if tt.expectError {
				assert.Error(t, err)
				if tt.errorMsg != "" {
					assert.Contains(t, err.Error(), tt.errorMsg)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

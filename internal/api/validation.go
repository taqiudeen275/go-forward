package api

import (
	"fmt"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/taqiudeen275/go-foward/pkg/interfaces"
)

// RequestValidator handles validation of API requests
type RequestValidator struct {
	table *interfaces.Table
}

// NewRequestValidator creates a new request validator for a table
func NewRequestValidator(table *interfaces.Table) *RequestValidator {
	return &RequestValidator{
		table: table,
	}
}

// ValidateCreateRequest validates a create request payload
func (v *RequestValidator) ValidateCreateRequest(data map[string]interface{}) error {
	return v.validateData(data, false)
}

// ValidateUpdateRequest validates an update request payload
func (v *RequestValidator) ValidateUpdateRequest(data map[string]interface{}) error {
	return v.validateData(data, true)
}

// validateData performs comprehensive data validation
func (v *RequestValidator) validateData(data map[string]interface{}, isUpdate bool) error {
	// Check for unknown fields
	for fieldName := range data {
		if !v.isValidField(fieldName) {
			return fmt.Errorf("unknown field '%s'", fieldName)
		}
	}

	// Validate each column
	for _, col := range v.table.Columns {
		value, exists := data[col.Name]

		// Skip primary key validation for updates
		if col.IsPrimaryKey && isUpdate {
			if exists {
				return fmt.Errorf("cannot update primary key field '%s'", col.Name)
			}
			continue
		}

		// Skip primary key validation for creates (usually auto-generated)
		if col.IsPrimaryKey && !isUpdate {
			continue
		}

		// Check required fields for creates
		if !isUpdate && !col.Nullable && !exists && col.DefaultValue == nil {
			return fmt.Errorf("field '%s' is required", col.Name)
		}

		// Validate field value if present
		if exists {
			if err := v.validateFieldValue(col, value); err != nil {
				return fmt.Errorf("validation failed for field '%s': %w", col.Name, err)
			}
		}
	}

	return nil
}

// validateFieldValue validates a single field value against column constraints
func (v *RequestValidator) validateFieldValue(col *interfaces.Column, value interface{}) error {
	// Handle null values
	if value == nil {
		if !col.Nullable {
			return fmt.Errorf("field cannot be null")
		}
		return nil
	}

	// Type-specific validation
	switch v.normalizeType(col.Type) {
	case "integer":
		return v.validateInteger(col, value)
	case "bigint":
		return v.validateBigInt(col, value)
	case "smallint":
		return v.validateSmallInt(col, value)
	case "decimal", "numeric":
		return v.validateDecimal(col, value)
	case "real", "float4":
		return v.validateFloat(col, value)
	case "double", "float8":
		return v.validateDouble(col, value)
	case "text", "varchar", "char":
		return v.validateString(col, value)
	case "boolean":
		return v.validateBoolean(col, value)
	case "date":
		return v.validateDate(col, value)
	case "time":
		return v.validateTime(col, value)
	case "timestamp":
		return v.validateTimestamp(col, value)
	case "json", "jsonb":
		return v.validateJSON(col, value)
	case "uuid":
		return v.validateUUID(col, value)
	case "inet":
		return v.validateInet(col, value)
	case "bytea":
		return v.validateBytea(col, value)
	default:
		// For unknown types, just check if it's a string
		if _, ok := value.(string); !ok {
			return fmt.Errorf("expected string value for type %s", col.Type)
		}
	}

	return nil
}

// Type validation methods

func (v *RequestValidator) validateInteger(col *interfaces.Column, value interface{}) error {
	var intVal int64

	switch v := value.(type) {
	case float64:
		intVal = int64(v)
	case int:
		intVal = int64(v)
	case int32:
		intVal = int64(v)
	case int64:
		intVal = v
	case string:
		var err error
		intVal, err = strconv.ParseInt(v, 10, 32)
		if err != nil {
			return fmt.Errorf("invalid integer format")
		}
	default:
		return fmt.Errorf("expected integer value")
	}

	// Check range for 32-bit integer
	if intVal < -2147483648 || intVal > 2147483647 {
		return fmt.Errorf("integer value out of range")
	}

	return nil
}

func (v *RequestValidator) validateBigInt(col *interfaces.Column, value interface{}) error {
	switch v := value.(type) {
	case float64:
		// Check if it's within int64 range
		if v < -9223372036854775808 || v > 9223372036854775807 {
			return fmt.Errorf("bigint value out of range")
		}
	case int, int32, int64:
		// These are all valid
	case string:
		if _, err := strconv.ParseInt(v, 10, 64); err != nil {
			return fmt.Errorf("invalid bigint format")
		}
	default:
		return fmt.Errorf("expected bigint value")
	}

	return nil
}

func (v *RequestValidator) validateSmallInt(col *interfaces.Column, value interface{}) error {
	var intVal int64

	switch v := value.(type) {
	case float64:
		intVal = int64(v)
	case int:
		intVal = int64(v)
	case int16:
		intVal = int64(v)
	case int32:
		intVal = int64(v)
	case int64:
		intVal = v
	case string:
		var err error
		intVal, err = strconv.ParseInt(v, 10, 16)
		if err != nil {
			return fmt.Errorf("invalid smallint format")
		}
	default:
		return fmt.Errorf("expected smallint value")
	}

	// Check range for 16-bit integer
	if intVal < -32768 || intVal > 32767 {
		return fmt.Errorf("smallint value out of range")
	}

	return nil
}

func (v *RequestValidator) validateDecimal(col *interfaces.Column, value interface{}) error {
	switch v := value.(type) {
	case float64, float32:
		// Valid numeric types
	case int, int32, int64:
		// Integers are valid for decimal columns
	case string:
		if _, err := strconv.ParseFloat(v, 64); err != nil {
			return fmt.Errorf("invalid decimal format")
		}
	default:
		return fmt.Errorf("expected numeric value")
	}

	return nil
}

func (v *RequestValidator) validateFloat(col *interfaces.Column, value interface{}) error {
	switch v := value.(type) {
	case float64, float32:
		// Valid
	case int, int32, int64:
		// Integers can be converted to float
	case string:
		if _, err := strconv.ParseFloat(v, 32); err != nil {
			return fmt.Errorf("invalid float format")
		}
	default:
		return fmt.Errorf("expected float value")
	}

	return nil
}

func (v *RequestValidator) validateDouble(col *interfaces.Column, value interface{}) error {
	switch v := value.(type) {
	case float64, float32:
		// Valid
	case int, int32, int64:
		// Integers can be converted to double
	case string:
		if _, err := strconv.ParseFloat(v, 64); err != nil {
			return fmt.Errorf("invalid double format")
		}
	default:
		return fmt.Errorf("expected double value")
	}

	return nil
}

func (v *RequestValidator) validateString(col *interfaces.Column, value interface{}) error {
	str, ok := value.(string)
	if !ok {
		return fmt.Errorf("expected string value")
	}

	// Check maximum length
	if col.MaxLength > 0 && len(str) > col.MaxLength {
		return fmt.Errorf("string exceeds maximum length of %d characters", col.MaxLength)
	}

	return nil
}

func (v *RequestValidator) validateBoolean(col *interfaces.Column, value interface{}) error {
	switch v := value.(type) {
	case bool:
		// Valid
	case string:
		// Accept string representations
		lower := strings.ToLower(v)
		if lower != "true" && lower != "false" && lower != "t" && lower != "f" &&
			lower != "yes" && lower != "no" && lower != "y" && lower != "n" &&
			lower != "1" && lower != "0" {
			return fmt.Errorf("invalid boolean format")
		}
	case int, int32, int64:
		// Accept 0/1 as boolean
		if intVal := reflect.ValueOf(v).Int(); intVal != 0 && intVal != 1 {
			return fmt.Errorf("integer boolean value must be 0 or 1")
		}
	case float64:
		// Accept 0.0/1.0 as boolean
		if v != 0.0 && v != 1.0 {
			return fmt.Errorf("float boolean value must be 0.0 or 1.0")
		}
	default:
		return fmt.Errorf("expected boolean value")
	}

	return nil
}

func (v *RequestValidator) validateDate(col *interfaces.Column, value interface{}) error {
	str, ok := value.(string)
	if !ok {
		return fmt.Errorf("expected date string")
	}

	// Try parsing common date formats
	formats := []string{
		"2006-01-02",
		"2006/01/02",
		"01/02/2006",
		"02-01-2006",
	}

	for _, format := range formats {
		if _, err := time.Parse(format, str); err == nil {
			return nil
		}
	}

	return fmt.Errorf("invalid date format, expected YYYY-MM-DD")
}

func (v *RequestValidator) validateTime(col *interfaces.Column, value interface{}) error {
	str, ok := value.(string)
	if !ok {
		return fmt.Errorf("expected time string")
	}

	// Try parsing common time formats
	formats := []string{
		"15:04:05",
		"15:04",
		"3:04:05 PM",
		"3:04 PM",
	}

	for _, format := range formats {
		if _, err := time.Parse(format, str); err == nil {
			return nil
		}
	}

	return fmt.Errorf("invalid time format, expected HH:MM:SS")
}

func (v *RequestValidator) validateTimestamp(col *interfaces.Column, value interface{}) error {
	str, ok := value.(string)
	if !ok {
		return fmt.Errorf("expected timestamp string")
	}

	// Try parsing common timestamp formats
	formats := []string{
		time.RFC3339,
		time.RFC3339Nano,
		"2006-01-02 15:04:05",
		"2006-01-02T15:04:05",
		"2006-01-02 15:04:05.000000",
		"2006-01-02T15:04:05.000000Z",
	}

	for _, format := range formats {
		if _, err := time.Parse(format, str); err == nil {
			return nil
		}
	}

	return fmt.Errorf("invalid timestamp format, expected RFC3339 or YYYY-MM-DD HH:MM:SS")
}

func (v *RequestValidator) validateJSON(col *interfaces.Column, value interface{}) error {
	// JSON can be any valid JSON type: object, array, string, number, boolean, null
	switch value.(type) {
	case map[string]interface{}, []interface{}, string, float64, bool, nil:
		return nil
	default:
		return fmt.Errorf("invalid JSON value")
	}
}

func (v *RequestValidator) validateUUID(col *interfaces.Column, value interface{}) error {
	str, ok := value.(string)
	if !ok {
		return fmt.Errorf("expected UUID string")
	}

	// UUID regex pattern
	uuidPattern := `^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`
	matched, err := regexp.MatchString(uuidPattern, str)
	if err != nil {
		return fmt.Errorf("error validating UUID format")
	}

	if !matched {
		return fmt.Errorf("invalid UUID format")
	}

	return nil
}

func (v *RequestValidator) validateInet(col *interfaces.Column, value interface{}) error {
	str, ok := value.(string)
	if !ok {
		return fmt.Errorf("expected IP address string")
	}

	// Basic IP address validation (IPv4 and IPv6)
	ipv4Pattern := `^(\d{1,3}\.){3}\d{1,3}(\/\d{1,2})?$`
	ipv6Pattern := `^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}(\/\d{1,3})?$`

	ipv4Match, _ := regexp.MatchString(ipv4Pattern, str)
	ipv6Match, _ := regexp.MatchString(ipv6Pattern, str)

	if !ipv4Match && !ipv6Match {
		return fmt.Errorf("invalid IP address format")
	}

	return nil
}

func (v *RequestValidator) validateBytea(col *interfaces.Column, value interface{}) error {
	switch value.(type) {
	case string:
		// Accept base64 encoded strings
		return nil
	case []byte:
		// Accept byte arrays
		return nil
	default:
		return fmt.Errorf("expected string or byte array for bytea field")
	}
}

// Helper methods

// normalizeType normalizes PostgreSQL type names to standard forms
func (v *RequestValidator) normalizeType(pgType string) string {
	// Remove precision/scale information
	baseType := strings.Split(pgType, "(")[0]
	baseType = strings.ToLower(strings.TrimSpace(baseType))

	// Map PostgreSQL types to normalized forms
	typeMap := map[string]string{
		"int4":        "integer",
		"int":         "integer",
		"serial":      "integer",
		"int8":        "bigint",
		"bigserial":   "bigint",
		"int2":        "smallint",
		"smallserial": "smallint",
		"float4":      "real",
		"float8":      "double",
		"varchar":     "varchar",
		"char":        "char",
		"text":        "text",
		"bool":        "boolean",
		"timestamptz": "timestamp",
		"timetz":      "time",
	}

	if normalized, exists := typeMap[baseType]; exists {
		return normalized
	}

	return baseType
}

// isValidField checks if a field name corresponds to a valid column
func (v *RequestValidator) isValidField(fieldName string) bool {
	for _, col := range v.table.Columns {
		if col.Name == fieldName {
			return true
		}
	}
	return false
}

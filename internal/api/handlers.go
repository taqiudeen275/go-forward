package api

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/taqiudeen275/go-foward/pkg/interfaces"
)

// createGetHandler creates a handler for GET requests (list records)
func (s *Service) createGetHandler(table *interfaces.Table) gin.HandlerFunc {
	return func(c *gin.Context) {
		ctx := c.Request.Context()

		// Parse query parameters using the new query builder
		parser := NewQueryParameterParser(table)
		queryBuilder := parser.ParseQueryParameters(c)

		// Build main query
		query := queryBuilder.BuildQuery()

		// Execute main query
		result, err := s.metaService.ExecuteSQL(ctx, query.SQL, query.Args...)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch records"})
			return
		}

		// Get total count if pagination is used
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

		// Return results with pagination info
		response := gin.H{
			"data":  result.Rows,
			"count": len(result.Rows),
		}

		// Add pagination metadata if applicable
		if queryBuilder.limitVal > 0 || queryBuilder.offsetVal > 0 {
			response["total_count"] = totalCount
			response["limit"] = queryBuilder.limitVal
			response["offset"] = queryBuilder.offsetVal

			// Calculate pagination info
			if queryBuilder.limitVal > 0 {
				response["has_more"] = totalCount > int64(queryBuilder.offsetVal+len(result.Rows))
				response["page"] = (queryBuilder.offsetVal / queryBuilder.limitVal) + 1
				response["total_pages"] = (totalCount + int64(queryBuilder.limitVal) - 1) / int64(queryBuilder.limitVal)
			}
		}

		c.JSON(http.StatusOK, response)
	}
}

// createGetByIdHandler creates a handler for GET requests by ID
func (s *Service) createGetByIdHandler(table *interfaces.Table) gin.HandlerFunc {
	return func(c *gin.Context) {
		ctx := c.Request.Context()
		id := c.Param("id")

		if id == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "ID parameter is required"})
			return
		}

		// Find primary key column
		pkColumn := s.getPrimaryKeyColumn(table)
		if pkColumn == nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Table has no primary key"})
			return
		}

		// Build query
		query := interfaces.Query{
			SQL:  fmt.Sprintf("SELECT * FROM %s.%s WHERE %s = $1", table.Schema, table.Name, pkColumn.Name),
			Args: []interface{}{id},
		}

		// Execute query
		result, err := s.metaService.ExecuteSQL(ctx, query.SQL, query.Args...)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch record"})
			return
		}

		if len(result.Rows) == 0 {
			c.JSON(http.StatusNotFound, gin.H{"error": "Record not found"})
			return
		}

		c.JSON(http.StatusOK, gin.H{"data": result.Rows[0]})
	}
}

// createPostHandler creates a handler for POST requests (create record)
func (s *Service) createPostHandler(table *interfaces.Table) gin.HandlerFunc {
	return func(c *gin.Context) {
		ctx := c.Request.Context()

		// Parse request body
		var requestData map[string]interface{}
		if err := c.ShouldBindJSON(&requestData); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid JSON data"})
			return
		}

		// Validate request data
		if err := s.validateCreateData(table, requestData); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		// Build insert query
		query, err := s.buildInsertQuery(table, requestData)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to build query"})
			return
		}

		// Execute query
		result, err := s.metaService.ExecuteSQL(ctx, query.SQL, query.Args...)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create record"})
			return
		}

		// Return created record
		if len(result.Rows) > 0 {
			c.JSON(http.StatusCreated, gin.H{"data": result.Rows[0]})
		} else {
			c.JSON(http.StatusCreated, gin.H{"message": "Record created successfully"})
		}
	}
}

// createPutHandler creates a handler for PUT requests (update record)
func (s *Service) createPutHandler(table *interfaces.Table) gin.HandlerFunc {
	return func(c *gin.Context) {
		ctx := c.Request.Context()
		id := c.Param("id")

		if id == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "ID parameter is required"})
			return
		}

		// Parse request body
		var requestData map[string]interface{}
		if err := c.ShouldBindJSON(&requestData); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid JSON data"})
			return
		}

		// Find primary key column
		pkColumn := s.getPrimaryKeyColumn(table)
		if pkColumn == nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Table has no primary key"})
			return
		}

		// Validate request data
		if err := s.validateUpdateData(table, requestData); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		// Build update query
		query, err := s.buildUpdateQuery(table, pkColumn.Name, id, requestData)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to build query"})
			return
		}

		// Execute query
		result, err := s.metaService.ExecuteSQL(ctx, query.SQL, query.Args...)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update record"})
			return
		}

		// Return updated record
		if len(result.Rows) > 0 {
			c.JSON(http.StatusOK, gin.H{"data": result.Rows[0]})
		} else {
			c.JSON(http.StatusOK, gin.H{"message": "Record updated successfully"})
		}
	}
}

// createDeleteHandler creates a handler for DELETE requests
func (s *Service) createDeleteHandler(table *interfaces.Table) gin.HandlerFunc {
	return func(c *gin.Context) {
		ctx := c.Request.Context()
		id := c.Param("id")

		if id == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "ID parameter is required"})
			return
		}

		// Find primary key column
		pkColumn := s.getPrimaryKeyColumn(table)
		if pkColumn == nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Table has no primary key"})
			return
		}

		// Build delete query
		query := interfaces.Query{
			SQL:  fmt.Sprintf("DELETE FROM %s.%s WHERE %s = $1", table.Schema, table.Name, pkColumn.Name),
			Args: []interface{}{id},
		}

		// Execute query
		_, err := s.metaService.ExecuteSQL(ctx, query.SQL, query.Args...)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete record"})
			return
		}

		c.JSON(http.StatusOK, gin.H{"message": "Record deleted successfully"})
	}
}

// Helper methods for query building and validation

// buildInsertQuery builds an INSERT query
func (s *Service) buildInsertQuery(table *interfaces.Table, data map[string]interface{}) (interfaces.Query, error) {
	var columns []string
	var placeholders []string
	var args []interface{}
	argIndex := 1

	for _, col := range table.Columns {
		if value, exists := data[col.Name]; exists && !col.IsPrimaryKey {
			columns = append(columns, col.Name)
			placeholders = append(placeholders, fmt.Sprintf("$%d", argIndex))
			args = append(args, value)
			argIndex++
		}
	}

	if len(columns) == 0 {
		return interfaces.Query{}, fmt.Errorf("no valid columns to insert")
	}

	query := fmt.Sprintf(
		"INSERT INTO %s.%s (%s) VALUES (%s) RETURNING *",
		table.Schema,
		table.Name,
		strings.Join(columns, ", "),
		strings.Join(placeholders, ", "),
	)

	return interfaces.Query{
		SQL:  query,
		Args: args,
	}, nil
}

// buildUpdateQuery builds an UPDATE query
func (s *Service) buildUpdateQuery(table *interfaces.Table, pkColumn, id string, data map[string]interface{}) (interfaces.Query, error) {
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

	// Add WHERE clause for primary key
	args = append(args, id)

	query := fmt.Sprintf(
		"UPDATE %s.%s SET %s WHERE %s = $%d RETURNING *",
		table.Schema,
		table.Name,
		strings.Join(setClauses, ", "),
		pkColumn,
		argIndex,
	)

	return interfaces.Query{
		SQL:  query,
		Args: args,
	}, nil
}

// getPrimaryKeyColumn finds the primary key column of a table
func (s *Service) getPrimaryKeyColumn(table *interfaces.Table) *interfaces.Column {
	for _, col := range table.Columns {
		if col.IsPrimaryKey {
			return col
		}
	}
	return nil
}

// isValidColumn checks if a column name is valid for the table
func (s *Service) isValidColumn(table *interfaces.Table, columnName string) bool {
	for _, col := range table.Columns {
		if col.Name == columnName {
			return true
		}
	}
	return false
}

// validateCreateData validates data for record creation
func (s *Service) validateCreateData(table *interfaces.Table, data map[string]interface{}) error {
	// Check for unknown fields
	for fieldName := range data {
		var found bool
		for _, col := range table.Columns {
			if col.Name == fieldName {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("unknown field '%s'", fieldName)
		}
	}

	// Validate each column
	for _, col := range table.Columns {
		value, exists := data[col.Name]

		// Skip primary key columns (usually auto-generated)
		if col.IsPrimaryKey {
			continue
		}

		// Check required fields
		if !col.Nullable && !exists && col.DefaultValue == nil {
			return fmt.Errorf("field '%s' is required", col.Name)
		}

		// Validate data types
		if exists && value != nil {
			if err := s.validateColumnValue(col, value); err != nil {
				return fmt.Errorf("invalid value for field '%s': %w", col.Name, err)
			}
		}
	}

	return nil
}

// validateUpdateData validates data for record updates
func (s *Service) validateUpdateData(table *interfaces.Table, data map[string]interface{}) error {
	for fieldName, value := range data {
		// Find column
		var col *interfaces.Column
		for _, c := range table.Columns {
			if c.Name == fieldName {
				col = c
				break
			}
		}

		if col == nil {
			return fmt.Errorf("unknown field '%s'", fieldName)
		}

		// Skip primary key updates
		if col.IsPrimaryKey {
			return fmt.Errorf("cannot update primary key field '%s'", fieldName)
		}

		// Validate data types
		if value != nil {
			if err := s.validateColumnValue(col, value); err != nil {
				return fmt.Errorf("invalid value for field '%s': %w", fieldName, err)
			}
		}
	}

	return nil
}

// validateColumnValue validates a value against column constraints
func (s *Service) validateColumnValue(col *interfaces.Column, value interface{}) error {
	// Basic type validation based on PostgreSQL types
	switch strings.ToLower(col.Type) {
	case "integer", "int", "int4", "serial":
		if _, ok := value.(float64); !ok {
			if _, ok := value.(int); !ok {
				return fmt.Errorf("expected integer value")
			}
		}
	case "bigint", "int8", "bigserial":
		if _, ok := value.(float64); !ok {
			if _, ok := value.(int64); !ok {
				return fmt.Errorf("expected bigint value")
			}
		}
	case "text", "varchar", "char":
		if _, ok := value.(string); !ok {
			return fmt.Errorf("expected string value")
		}
		// Check max length if specified
		if col.MaxLength > 0 {
			if str, ok := value.(string); ok && len(str) > col.MaxLength {
				return fmt.Errorf("value exceeds maximum length of %d", col.MaxLength)
			}
		}
	case "boolean", "bool":
		if _, ok := value.(bool); !ok {
			return fmt.Errorf("expected boolean value")
		}
	case "timestamp", "timestamptz", "date", "time":
		if _, ok := value.(string); !ok {
			return fmt.Errorf("expected timestamp string value")
		}
	case "json", "jsonb":
		// JSON values can be objects, arrays, or primitives
		// No specific validation needed here
	}

	return nil
}

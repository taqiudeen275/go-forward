package api

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/taqiudeen275/go-foward/pkg/interfaces"
)

// QueryBuilder implements the interfaces.QueryBuilder interface
type QueryBuilder struct {
	table       *interfaces.Table
	selectCols  []string
	whereConds  []string
	orderByCols []string
	limitVal    int
	offsetVal   int
	args        []interface{}
	argIndex    int
}

// NewQueryBuilder creates a new query builder for a table
func NewQueryBuilder(table *interfaces.Table) *QueryBuilder {
	return &QueryBuilder{
		table:    table,
		argIndex: 1,
	}
}

// Select specifies which columns to select
func (qb *QueryBuilder) Select(columns ...string) interfaces.QueryBuilder {
	// Validate columns
	var validColumns []string
	for _, col := range columns {
		if qb.isValidColumn(col) {
			validColumns = append(validColumns, col)
		}
	}
	qb.selectCols = validColumns
	return qb
}

// Where adds a WHERE condition
func (qb *QueryBuilder) Where(condition string, args ...interface{}) interfaces.QueryBuilder {
	qb.whereConds = append(qb.whereConds, condition)
	qb.args = append(qb.args, args...)
	qb.argIndex += len(args)
	return qb
}

// OrderBy adds an ORDER BY clause
func (qb *QueryBuilder) OrderBy(column string, direction string) interfaces.QueryBuilder {
	if qb.isValidColumn(column) {
		direction = strings.ToUpper(direction)
		if direction != "ASC" && direction != "DESC" {
			direction = "ASC"
		}
		qb.orderByCols = append(qb.orderByCols, fmt.Sprintf("%s %s", column, direction))
	}
	return qb
}

// Limit sets the LIMIT clause
func (qb *QueryBuilder) Limit(limit int) interfaces.QueryBuilder {
	if limit > 0 && limit <= 1000 { // Max limit of 1000
		qb.limitVal = limit
	}
	return qb
}

// Offset sets the OFFSET clause
func (qb *QueryBuilder) Offset(offset int) interfaces.QueryBuilder {
	if offset >= 0 {
		qb.offsetVal = offset
	}
	return qb
}

// Execute builds and executes the query (placeholder - actual execution handled by service)
func (qb *QueryBuilder) Execute(ctx context.Context) ([]map[string]interface{}, error) {
	// This method is implemented by the service layer
	return nil, fmt.Errorf("execute method should be called through the service")
}

// Count builds and executes a count query (placeholder - actual execution handled by service)
func (qb *QueryBuilder) Count(ctx context.Context) (int64, error) {
	// This method is implemented by the service layer
	return 0, fmt.Errorf("count method should be called through the service")
}

// BuildQuery constructs the final SQL query
func (qb *QueryBuilder) BuildQuery() interfaces.Query {
	var query strings.Builder

	// SELECT clause
	if len(qb.selectCols) > 0 {
		query.WriteString(fmt.Sprintf("SELECT %s", strings.Join(qb.selectCols, ", ")))
	} else {
		query.WriteString("SELECT *")
	}

	// FROM clause
	query.WriteString(fmt.Sprintf(" FROM %s.%s", qb.table.Schema, qb.table.Name))

	// WHERE clause
	if len(qb.whereConds) > 0 {
		query.WriteString(" WHERE ")
		query.WriteString(strings.Join(qb.whereConds, " AND "))
	}

	// ORDER BY clause
	if len(qb.orderByCols) > 0 {
		query.WriteString(" ORDER BY ")
		query.WriteString(strings.Join(qb.orderByCols, ", "))
	}

	// LIMIT clause
	if qb.limitVal > 0 {
		query.WriteString(fmt.Sprintf(" LIMIT %d", qb.limitVal))
	}

	// OFFSET clause
	if qb.offsetVal > 0 {
		query.WriteString(fmt.Sprintf(" OFFSET %d", qb.offsetVal))
	}

	return interfaces.Query{
		SQL:  query.String(),
		Args: qb.args,
	}
}

// BuildCountQuery constructs a count query
func (qb *QueryBuilder) BuildCountQuery() interfaces.Query {
	var query strings.Builder

	// SELECT COUNT(*)
	query.WriteString("SELECT COUNT(*)")

	// FROM clause
	query.WriteString(fmt.Sprintf(" FROM %s.%s", qb.table.Schema, qb.table.Name))

	// WHERE clause (same as main query)
	if len(qb.whereConds) > 0 {
		query.WriteString(" WHERE ")
		query.WriteString(strings.Join(qb.whereConds, " AND "))
	}

	return interfaces.Query{
		SQL:  query.String(),
		Args: qb.args,
	}
}

// isValidColumn checks if a column exists in the table
func (qb *QueryBuilder) isValidColumn(columnName string) bool {
	for _, col := range qb.table.Columns {
		if col.Name == columnName {
			return true
		}
	}
	return false
}

// QueryParameterParser handles parsing of HTTP query parameters
type QueryParameterParser struct {
	table *interfaces.Table
}

// NewQueryParameterParser creates a new query parameter parser
func NewQueryParameterParser(table *interfaces.Table) *QueryParameterParser {
	return &QueryParameterParser{
		table: table,
	}
}

// ParseQueryParameters parses HTTP query parameters into a QueryBuilder
func (qpp *QueryParameterParser) ParseQueryParameters(c *gin.Context) *QueryBuilder {
	qb := NewQueryBuilder(qpp.table)

	// Parse SELECT columns
	if selectCols := c.Query("select"); selectCols != "" {
		columns := strings.Split(selectCols, ",")
		var cleanColumns []string
		for _, col := range columns {
			cleanColumns = append(cleanColumns, strings.TrimSpace(col))
		}
		qb.Select(cleanColumns...)
	}

	// Parse WHERE conditions from column filters
	qpp.parseWhereConditions(c, qb)

	// Parse ORDER BY
	qpp.parseOrderBy(c, qb)

	// Parse LIMIT
	if limitStr := c.Query("limit"); limitStr != "" {
		if limit, err := strconv.Atoi(limitStr); err == nil {
			qb.Limit(limit)
		}
	}

	// Parse OFFSET
	if offsetStr := c.Query("offset"); offsetStr != "" {
		if offset, err := strconv.Atoi(offsetStr); err == nil {
			qb.Offset(offset)
		}
	}

	return qb
}

// parseWhereConditions parses column-based filtering parameters
func (qpp *QueryParameterParser) parseWhereConditions(c *gin.Context, qb *QueryBuilder) {
	for _, col := range qpp.table.Columns {
		// Simple equality filter
		if value := c.Query(col.Name); value != "" {
			condition := fmt.Sprintf("%s = $%d", col.Name, qb.argIndex)
			qb.Where(condition, value)
		}

		// Range filters for numeric/date columns
		if qpp.isNumericOrDateColumn(col) {
			// Greater than filter
			if value := c.Query(col.Name + "_gt"); value != "" {
				condition := fmt.Sprintf("%s > $%d", col.Name, qb.argIndex)
				qb.Where(condition, value)
			}

			// Greater than or equal filter
			if value := c.Query(col.Name + "_gte"); value != "" {
				condition := fmt.Sprintf("%s >= $%d", col.Name, qb.argIndex)
				qb.Where(condition, value)
			}

			// Less than filter
			if value := c.Query(col.Name + "_lt"); value != "" {
				condition := fmt.Sprintf("%s < $%d", col.Name, qb.argIndex)
				qb.Where(condition, value)
			}

			// Less than or equal filter
			if value := c.Query(col.Name + "_lte"); value != "" {
				condition := fmt.Sprintf("%s <= $%d", col.Name, qb.argIndex)
				qb.Where(condition, value)
			}
		}

		// String-specific filters
		if qpp.isStringColumn(col) {
			// LIKE filter (case-insensitive)
			if value := c.Query(col.Name + "_like"); value != "" {
				condition := fmt.Sprintf("LOWER(%s) LIKE LOWER($%d)", col.Name, qb.argIndex)
				qb.Where(condition, "%"+value+"%")
			}

			// ILIKE filter (PostgreSQL case-insensitive LIKE)
			if value := c.Query(col.Name + "_ilike"); value != "" {
				condition := fmt.Sprintf("%s ILIKE $%d", col.Name, qb.argIndex)
				qb.Where(condition, "%"+value+"%")
			}

			// Starts with filter
			if value := c.Query(col.Name + "_starts"); value != "" {
				condition := fmt.Sprintf("%s ILIKE $%d", col.Name, qb.argIndex)
				qb.Where(condition, value+"%")
			}

			// Ends with filter
			if value := c.Query(col.Name + "_ends"); value != "" {
				condition := fmt.Sprintf("%s ILIKE $%d", col.Name, qb.argIndex)
				qb.Where(condition, "%"+value)
			}
		}

		// IN filter for multiple values
		if value := c.Query(col.Name + "_in"); value != "" {
			values := strings.Split(value, ",")
			if len(values) > 0 {
				placeholders := make([]string, len(values))
				args := make([]interface{}, len(values))
				for i, v := range values {
					placeholders[i] = fmt.Sprintf("$%d", qb.argIndex+i)
					args[i] = strings.TrimSpace(v)
				}
				condition := fmt.Sprintf("%s IN (%s)", col.Name, strings.Join(placeholders, ", "))
				qb.Where(condition, args...)
			}
		}

		// NOT NULL / IS NULL filters
		if c.Query(col.Name+"_null") == "false" {
			qb.Where(fmt.Sprintf("%s IS NOT NULL", col.Name))
		} else if c.Query(col.Name+"_null") == "true" {
			qb.Where(fmt.Sprintf("%s IS NULL", col.Name))
		}
	}
}

// parseOrderBy parses ORDER BY parameters
func (qpp *QueryParameterParser) parseOrderBy(c *gin.Context, qb *QueryBuilder) {
	// Single column ordering
	if orderBy := c.Query("order"); orderBy != "" {
		direction := "ASC"
		if c.Query("desc") == "true" {
			direction = "DESC"
		}
		qb.OrderBy(orderBy, direction)
	}

	// Multiple column ordering
	if orderBy := c.Query("order_by"); orderBy != "" {
		orders := strings.Split(orderBy, ",")
		for _, order := range orders {
			parts := strings.Fields(strings.TrimSpace(order))
			if len(parts) >= 1 {
				column := parts[0]
				direction := "ASC"
				if len(parts) >= 2 {
					direction = strings.ToUpper(parts[1])
				}
				qb.OrderBy(column, direction)
			}
		}
	}
}

// isNumericOrDateColumn checks if a column is numeric or date type
func (qpp *QueryParameterParser) isNumericOrDateColumn(col *interfaces.Column) bool {
	numericTypes := map[string]bool{
		"integer":     true,
		"bigint":      true,
		"smallint":    true,
		"decimal":     true,
		"numeric":     true,
		"real":        true,
		"double":      true,
		"float4":      true,
		"float8":      true,
		"int":         true,
		"int2":        true,
		"int4":        true,
		"int8":        true,
		"serial":      true,
		"bigserial":   true,
		"date":        true,
		"time":        true,
		"timestamp":   true,
		"timestamptz": true,
	}

	baseType := strings.Split(strings.ToLower(col.Type), "(")[0]
	return numericTypes[baseType]
}

// isStringColumn checks if a column is a string type
func (qpp *QueryParameterParser) isStringColumn(col *interfaces.Column) bool {
	stringTypes := map[string]bool{
		"text":    true,
		"varchar": true,
		"char":    true,
		"bpchar":  true,
	}

	baseType := strings.Split(strings.ToLower(col.Type), "(")[0]
	return stringTypes[baseType]
}

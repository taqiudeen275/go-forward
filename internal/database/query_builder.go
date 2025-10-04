package database

import (
	"context"
	"fmt"
	"strings"
)

// QueryBuilder provides a fluent interface for building SQL queries
type QueryBuilder struct {
	db          *DB
	tableName   string
	selectCols  []string
	whereConds  []whereCondition
	orderByCols []orderByColumn
	limitVal    *int
	offsetVal   *int
	joinClauses []joinClause
}

type whereCondition struct {
	condition string
	args      []interface{}
}

type orderByColumn struct {
	column    string
	direction string
}

type joinClause struct {
	joinType  string
	table     string
	condition string
}

// NewQueryBuilder creates a new query builder
func NewQueryBuilder(db *DB) *QueryBuilder {
	return &QueryBuilder{
		db: db,
	}
}

// Table sets the table name for the query
func (qb *QueryBuilder) Table(tableName string) *QueryBuilder {
	qb.tableName = tableName
	return qb
}

// Select sets the columns to select
func (qb *QueryBuilder) Select(columns ...string) *QueryBuilder {
	qb.selectCols = columns
	return qb
}

// Where adds a WHERE condition
func (qb *QueryBuilder) Where(condition string, args ...interface{}) *QueryBuilder {
	qb.whereConds = append(qb.whereConds, whereCondition{
		condition: condition,
		args:      args,
	})
	return qb
}

// OrderBy adds an ORDER BY clause
func (qb *QueryBuilder) OrderBy(column string, direction string) *QueryBuilder {
	if direction != "ASC" && direction != "DESC" {
		direction = "ASC"
	}
	qb.orderByCols = append(qb.orderByCols, orderByColumn{
		column:    column,
		direction: direction,
	})
	return qb
}

// Limit sets the LIMIT clause
func (qb *QueryBuilder) Limit(limit int) *QueryBuilder {
	qb.limitVal = &limit
	return qb
}

// Offset sets the OFFSET clause
func (qb *QueryBuilder) Offset(offset int) *QueryBuilder {
	qb.offsetVal = &offset
	return qb
}

// Join adds a JOIN clause
func (qb *QueryBuilder) Join(table, condition string) *QueryBuilder {
	qb.joinClauses = append(qb.joinClauses, joinClause{
		joinType:  "JOIN",
		table:     table,
		condition: condition,
	})
	return qb
}

// LeftJoin adds a LEFT JOIN clause
func (qb *QueryBuilder) LeftJoin(table, condition string) *QueryBuilder {
	qb.joinClauses = append(qb.joinClauses, joinClause{
		joinType:  "LEFT JOIN",
		table:     table,
		condition: condition,
	})
	return qb
}

// RightJoin adds a RIGHT JOIN clause
func (qb *QueryBuilder) RightJoin(table, condition string) *QueryBuilder {
	qb.joinClauses = append(qb.joinClauses, joinClause{
		joinType:  "RIGHT JOIN",
		table:     table,
		condition: condition,
	})
	return qb
}

// Build constructs the SQL query and returns it with arguments
func (qb *QueryBuilder) Build() (string, []interface{}) {
	var query strings.Builder
	var args []interface{}
	argIndex := 1

	// SELECT clause
	query.WriteString("SELECT ")
	if len(qb.selectCols) > 0 {
		query.WriteString(strings.Join(qb.selectCols, ", "))
	} else {
		query.WriteString("*")
	}

	// FROM clause
	query.WriteString(" FROM ")
	query.WriteString(qb.tableName)

	// JOIN clauses
	for _, join := range qb.joinClauses {
		query.WriteString(fmt.Sprintf(" %s %s ON %s", join.joinType, join.table, join.condition))
	}

	// WHERE clause
	if len(qb.whereConds) > 0 {
		query.WriteString(" WHERE ")
		var conditions []string
		for _, cond := range qb.whereConds {
			// Replace ? placeholders with $1, $2, etc.
			condition := cond.condition
			for range cond.args {
				condition = strings.Replace(condition, "?", fmt.Sprintf("$%d", argIndex), 1)
				argIndex++
			}
			conditions = append(conditions, condition)
			args = append(args, cond.args...)
		}
		query.WriteString(strings.Join(conditions, " AND "))
	}

	// ORDER BY clause
	if len(qb.orderByCols) > 0 {
		query.WriteString(" ORDER BY ")
		var orderCols []string
		for _, col := range qb.orderByCols {
			orderCols = append(orderCols, fmt.Sprintf("%s %s", col.column, col.direction))
		}
		query.WriteString(strings.Join(orderCols, ", "))
	}

	// LIMIT clause
	if qb.limitVal != nil {
		query.WriteString(fmt.Sprintf(" LIMIT $%d", argIndex))
		args = append(args, *qb.limitVal)
		argIndex++
	}

	// OFFSET clause
	if qb.offsetVal != nil {
		query.WriteString(fmt.Sprintf(" OFFSET $%d", argIndex))
		args = append(args, *qb.offsetVal)
		argIndex++
	}

	return query.String(), args
}

// Execute executes the query and returns the results
func (qb *QueryBuilder) Execute(ctx context.Context) ([]map[string]interface{}, error) {
	query, args := qb.Build()

	rows, err := qb.db.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to execute query: %w", err)
	}
	defer rows.Close()

	var results []map[string]interface{}

	// Get column descriptions
	fieldDescriptions := rows.FieldDescriptions()

	for rows.Next() {
		// Create a slice to hold the values
		values := make([]interface{}, len(fieldDescriptions))
		valuePtrs := make([]interface{}, len(fieldDescriptions))

		for i := range values {
			valuePtrs[i] = &values[i]
		}

		// Scan the row
		if err := rows.Scan(valuePtrs...); err != nil {
			return nil, fmt.Errorf("failed to scan row: %w", err)
		}

		// Create result map
		result := make(map[string]interface{})
		for i, desc := range fieldDescriptions {
			result[desc.Name] = values[i]
		}

		results = append(results, result)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating rows: %w", err)
	}

	return results, nil
}

// Count executes a COUNT query
func (qb *QueryBuilder) Count(ctx context.Context) (int64, error) {
	// Create a new query builder for count
	countQB := &QueryBuilder{
		db:          qb.db,
		tableName:   qb.tableName,
		selectCols:  []string{"COUNT(*)"},
		whereConds:  qb.whereConds,
		joinClauses: qb.joinClauses,
	}

	query, args := countQB.Build()

	var count int64
	err := qb.db.QueryRow(ctx, query, args...).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("failed to execute count query: %w", err)
	}

	return count, nil
}

// First executes the query and returns the first result
func (qb *QueryBuilder) First(ctx context.Context) (map[string]interface{}, error) {
	qb.Limit(1)
	results, err := qb.Execute(ctx)
	if err != nil {
		return nil, err
	}

	if len(results) == 0 {
		return nil, fmt.Errorf("no results found")
	}

	return results[0], nil
}

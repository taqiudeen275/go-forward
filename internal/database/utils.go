package database

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// TableInfo represents database table information
type TableInfo struct {
	Name      string        `json:"name"`
	Schema    string        `json:"schema"`
	Type      string        `json:"type"`
	Comment   string        `json:"comment"`
	Columns   []*ColumnInfo `json:"columns"`
	CreatedAt time.Time     `json:"created_at"`
	UpdatedAt time.Time     `json:"updated_at"`
}

// ColumnInfo represents database column information
type ColumnInfo struct {
	Name            string  `json:"name"`
	DataType        string  `json:"data_type"`
	IsNullable      bool    `json:"is_nullable"`
	ColumnDefault   *string `json:"column_default"`
	IsPrimaryKey    bool    `json:"is_primary_key"`
	IsForeignKey    bool    `json:"is_foreign_key"`
	ForeignTable    *string `json:"foreign_table"`
	ForeignColumn   *string `json:"foreign_column"`
	OrdinalPosition int     `json:"ordinal_position"`
	Comment         *string `json:"comment"`
}

// DatabaseUtils provides utility functions for database operations
type DatabaseUtils struct {
	db *DB
}

// NewDatabaseUtils creates a new database utils instance
func NewDatabaseUtils(db *DB) *DatabaseUtils {
	return &DatabaseUtils{db: db}
}

// GetTables returns all tables in the specified schema
func (du *DatabaseUtils) GetTables(ctx context.Context, schema string) ([]*TableInfo, error) {
	if schema == "" {
		schema = "public"
	}

	query := `
		SELECT 
			t.table_name,
			t.table_schema,
			t.table_type,
			COALESCE(obj_description(c.oid), '') as comment
		FROM information_schema.tables t
		LEFT JOIN pg_class c ON c.relname = t.table_name
		LEFT JOIN pg_namespace n ON n.oid = c.relnamespace AND n.nspname = t.table_schema
		WHERE t.table_schema = $1
		AND t.table_type = 'BASE TABLE'
		ORDER BY t.table_name
	`

	rows, err := du.db.Query(ctx, query, schema)
	if err != nil {
		return nil, fmt.Errorf("failed to query tables: %w", err)
	}
	defer rows.Close()

	var tables []*TableInfo
	for rows.Next() {
		var table TableInfo
		err := rows.Scan(&table.Name, &table.Schema, &table.Type, &table.Comment)
		if err != nil {
			return nil, fmt.Errorf("failed to scan table row: %w", err)
		}

		// Get columns for this table
		columns, err := du.GetColumns(ctx, schema, table.Name)
		if err != nil {
			return nil, fmt.Errorf("failed to get columns for table %s: %w", table.Name, err)
		}
		table.Columns = columns

		tables = append(tables, &table)
	}

	return tables, nil
}

// GetColumns returns all columns for a specific table
func (du *DatabaseUtils) GetColumns(ctx context.Context, schema, tableName string) ([]*ColumnInfo, error) {
	query := `
		SELECT 
			c.column_name,
			c.data_type,
			c.is_nullable = 'YES' as is_nullable,
			c.column_default,
			c.ordinal_position,
			COALESCE(col_description(pgc.oid, c.ordinal_position), '') as comment,
			CASE WHEN pk.column_name IS NOT NULL THEN true ELSE false END as is_primary_key,
			CASE WHEN fk.column_name IS NOT NULL THEN true ELSE false END as is_foreign_key,
			fk.foreign_table_name,
			fk.foreign_column_name
		FROM information_schema.columns c
		LEFT JOIN pg_class pgc ON pgc.relname = c.table_name
		LEFT JOIN pg_namespace pgn ON pgn.oid = pgc.relnamespace AND pgn.nspname = c.table_schema
		LEFT JOIN (
			SELECT ku.column_name, ku.table_name, ku.table_schema
			FROM information_schema.table_constraints tc
			JOIN information_schema.key_column_usage ku ON tc.constraint_name = ku.constraint_name
			WHERE tc.constraint_type = 'PRIMARY KEY'
		) pk ON pk.column_name = c.column_name AND pk.table_name = c.table_name AND pk.table_schema = c.table_schema
		LEFT JOIN (
			SELECT 
				ku.column_name,
				ku.table_name,
				ku.table_schema,
				ccu.table_name as foreign_table_name,
				ccu.column_name as foreign_column_name
			FROM information_schema.table_constraints tc
			JOIN information_schema.key_column_usage ku ON tc.constraint_name = ku.constraint_name
			JOIN information_schema.constraint_column_usage ccu ON tc.constraint_name = ccu.constraint_name
			WHERE tc.constraint_type = 'FOREIGN KEY'
		) fk ON fk.column_name = c.column_name AND fk.table_name = c.table_name AND fk.table_schema = c.table_schema
		WHERE c.table_schema = $1 AND c.table_name = $2
		ORDER BY c.ordinal_position
	`

	rows, err := du.db.Query(ctx, query, schema, tableName)
	if err != nil {
		return nil, fmt.Errorf("failed to query columns: %w", err)
	}
	defer rows.Close()

	var columns []*ColumnInfo
	for rows.Next() {
		var col ColumnInfo
		var comment, foreignTable, foreignColumn *string

		err := rows.Scan(
			&col.Name,
			&col.DataType,
			&col.IsNullable,
			&col.ColumnDefault,
			&col.OrdinalPosition,
			&comment,
			&col.IsPrimaryKey,
			&col.IsForeignKey,
			&foreignTable,
			&foreignColumn,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan column row: %w", err)
		}

		col.Comment = comment
		col.ForeignTable = foreignTable
		col.ForeignColumn = foreignColumn

		columns = append(columns, &col)
	}

	return columns, nil
}

// TableExists checks if a table exists in the specified schema
func (du *DatabaseUtils) TableExists(ctx context.Context, schema, tableName string) (bool, error) {
	query := `
		SELECT EXISTS (
			SELECT 1 FROM information_schema.tables 
			WHERE table_schema = $1 AND table_name = $2
		)
	`

	var exists bool
	err := du.db.QueryRow(ctx, query, schema, tableName).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("failed to check table existence: %w", err)
	}

	return exists, nil
}

// CreateTable creates a new table with the specified columns
func (du *DatabaseUtils) CreateTable(ctx context.Context, schema, tableName string, columns []*ColumnInfo) error {
	if len(columns) == 0 {
		return fmt.Errorf("cannot create table without columns")
	}

	var columnDefs []string
	var primaryKeys []string

	for _, col := range columns {
		colDef := fmt.Sprintf("%s %s", col.Name, col.DataType)

		if !col.IsNullable {
			colDef += " NOT NULL"
		}

		if col.ColumnDefault != nil && *col.ColumnDefault != "" {
			colDef += fmt.Sprintf(" DEFAULT %s", *col.ColumnDefault)
		}

		columnDefs = append(columnDefs, colDef)

		if col.IsPrimaryKey {
			primaryKeys = append(primaryKeys, col.Name)
		}
	}

	// Add primary key constraint if any
	if len(primaryKeys) > 0 {
		columnDefs = append(columnDefs, fmt.Sprintf("PRIMARY KEY (%s)", strings.Join(primaryKeys, ", ")))
	}

	query := fmt.Sprintf("CREATE TABLE %s.%s (%s)", schema, tableName, strings.Join(columnDefs, ", "))

	err := du.db.Exec(ctx, query)
	if err != nil {
		return fmt.Errorf("failed to create table: %w", err)
	}

	return nil
}

// DropTable drops a table from the specified schema
func (du *DatabaseUtils) DropTable(ctx context.Context, schema, tableName string) error {
	query := fmt.Sprintf("DROP TABLE IF EXISTS %s.%s", schema, tableName)

	err := du.db.Exec(ctx, query)
	if err != nil {
		return fmt.Errorf("failed to drop table: %w", err)
	}

	return nil
}

// ExecuteSQL executes raw SQL and returns the results
func (du *DatabaseUtils) ExecuteSQL(ctx context.Context, sql string, args ...interface{}) ([]map[string]interface{}, error) {
	// Determine if this is a SELECT query or not
	trimmedSQL := strings.TrimSpace(strings.ToUpper(sql))
	isSelect := strings.HasPrefix(trimmedSQL, "SELECT") ||
		strings.HasPrefix(trimmedSQL, "WITH") ||
		strings.HasPrefix(trimmedSQL, "SHOW")

	if !isSelect {
		// For non-SELECT queries, just execute
		err := du.db.Exec(ctx, sql, args...)
		if err != nil {
			return nil, fmt.Errorf("failed to execute SQL: %w", err)
		}
		return []map[string]interface{}{{"message": "Query executed successfully"}}, nil
	}

	// For SELECT queries, return results
	rows, err := du.db.Query(ctx, sql, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to execute SQL query: %w", err)
	}
	defer rows.Close()

	var results []map[string]interface{}
	fieldDescriptions := rows.FieldDescriptions()

	for rows.Next() {
		values := make([]interface{}, len(fieldDescriptions))
		valuePtrs := make([]interface{}, len(fieldDescriptions))

		for i := range values {
			valuePtrs[i] = &values[i]
		}

		if err := rows.Scan(valuePtrs...); err != nil {
			return nil, fmt.Errorf("failed to scan row: %w", err)
		}

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

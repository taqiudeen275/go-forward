package database

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// MetaService provides database introspection and management capabilities
type MetaService struct {
	db *DB
}

// quoteLiteral safely quotes a string literal for SQL
func quoteLiteral(s string) string {
	// Escape single quotes by doubling them and wrap in single quotes
	escaped := strings.ReplaceAll(s, "'", "''")
	return fmt.Sprintf("'%s'", escaped)
}

// NewMetaService creates a new database meta service
func NewMetaService(db *DB) *MetaService {
	return &MetaService{
		db: db,
	}
}

// Table represents database table metadata
type Table struct {
	Name        string        `json:"name"`
	Schema      string        `json:"schema"`
	Columns     []*Column     `json:"columns"`
	Indexes     []*Index      `json:"indexes"`
	Constraints []*Constraint `json:"constraints"`
	RLSEnabled  bool          `json:"rls_enabled"`
	Comment     string        `json:"comment,omitempty"`
	CreatedAt   *time.Time    `json:"created_at,omitempty"`
}

// Column represents database column metadata
type Column struct {
	Name             string `json:"name"`
	Type             string `json:"type"`
	Nullable         bool   `json:"nullable"`
	DefaultValue     string `json:"default_value,omitempty"`
	IsPrimaryKey     bool   `json:"is_primary_key"`
	IsForeignKey     bool   `json:"is_foreign_key"`
	IsUnique         bool   `json:"is_unique"`
	MaxLength        *int   `json:"max_length,omitempty"`
	NumericScale     *int   `json:"numeric_scale,omitempty"`
	NumericPrecision *int   `json:"numeric_precision,omitempty"`
	Comment          string `json:"comment,omitempty"`
	OrdinalPosition  int    `json:"ordinal_position"`
}

// Index represents database index metadata
type Index struct {
	Name       string   `json:"name"`
	TableName  string   `json:"table_name"`
	Columns    []string `json:"columns"`
	IsUnique   bool     `json:"is_unique"`
	IsPrimary  bool     `json:"is_primary"`
	IndexType  string   `json:"index_type"`
	Definition string   `json:"definition,omitempty"`
}

// Constraint represents database constraint metadata
type Constraint struct {
	Name              string   `json:"name"`
	Type              string   `json:"type"` // PRIMARY KEY, FOREIGN KEY, UNIQUE, CHECK
	TableName         string   `json:"table_name"`
	Columns           []string `json:"columns"`
	ReferencedTable   string   `json:"referenced_table,omitempty"`
	ReferencedColumns []string `json:"referenced_columns,omitempty"`
	Definition        string   `json:"definition,omitempty"`
	OnUpdate          string   `json:"on_update,omitempty"`
	OnDelete          string   `json:"on_delete,omitempty"`
}

// GetTables retrieves all tables from the specified schema(s)
func (ms *MetaService) GetTables(ctx context.Context, schemas ...string) ([]*Table, error) {
	if len(schemas) == 0 {
		schemas = []string{"public"}
	}

	// Build schema filter
	schemaPlaceholders := make([]string, len(schemas))
	schemaArgs := make([]interface{}, len(schemas))
	for i, schema := range schemas {
		schemaPlaceholders[i] = fmt.Sprintf("$%d", i+1)
		schemaArgs[i] = schema
	}

	query := `
		SELECT 
			t.table_name,
			t.table_schema,
			COALESCE(obj_description(c.oid), '') as comment,
			CASE WHEN COUNT(p.policyname) > 0 THEN true ELSE false END as rls_enabled
		FROM information_schema.tables t
		LEFT JOIN pg_class c ON c.relname = t.table_name
		LEFT JOIN pg_namespace n ON n.oid = c.relnamespace AND n.nspname = t.table_schema
		LEFT JOIN pg_policies p ON p.tablename = t.table_name AND p.schemaname = t.table_schema
		WHERE t.table_type = 'BASE TABLE'
		AND t.table_schema IN (` + strings.Join(schemaPlaceholders, ",") + `)
		GROUP BY t.table_name, t.table_schema, c.oid
		ORDER BY t.table_schema, t.table_name`

	rows, err := ms.db.Query(ctx, query, schemaArgs...)
	if err != nil {
		return nil, fmt.Errorf("failed to query tables: %w", err)
	}
	defer rows.Close()

	var tables []*Table
	for rows.Next() {
		var table Table
		var rlsEnabled bool

		err := rows.Scan(&table.Name, &table.Schema, &table.Comment, &rlsEnabled)
		if err != nil {
			return nil, fmt.Errorf("failed to scan table row: %w", err)
		}

		table.RLSEnabled = rlsEnabled
		tables = append(tables, &table)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating table rows: %w", err)
	}

	// Load columns, indexes, and constraints for each table
	for _, table := range tables {
		if err := ms.loadTableDetails(ctx, table); err != nil {
			return nil, fmt.Errorf("failed to load details for table %s.%s: %w", table.Schema, table.Name, err)
		}
	}

	return tables, nil
}

// GetTable retrieves a specific table with all its metadata
func (ms *MetaService) GetTable(ctx context.Context, schema, tableName string) (*Table, error) {
	tables, err := ms.GetTables(ctx, schema)
	if err != nil {
		return nil, err
	}

	for _, table := range tables {
		if table.Name == tableName {
			return table, nil
		}
	}

	return nil, fmt.Errorf("table %s.%s not found", schema, tableName)
}

// loadTableDetails loads columns, indexes, and constraints for a table
func (ms *MetaService) loadTableDetails(ctx context.Context, table *Table) error {
	// Load columns
	columns, err := ms.getTableColumns(ctx, table.Schema, table.Name)
	if err != nil {
		return fmt.Errorf("failed to load columns: %w", err)
	}
	table.Columns = columns

	// Load indexes
	indexes, err := ms.getTableIndexes(ctx, table.Schema, table.Name)
	if err != nil {
		return fmt.Errorf("failed to load indexes: %w", err)
	}
	table.Indexes = indexes

	// Load constraints
	constraints, err := ms.getTableConstraints(ctx, table.Schema, table.Name)
	if err != nil {
		return fmt.Errorf("failed to load constraints: %w", err)
	}
	table.Constraints = constraints

	return nil
}

// getTableColumns retrieves column metadata for a specific table
func (ms *MetaService) getTableColumns(ctx context.Context, schema, tableName string) ([]*Column, error) {
	query := `
		SELECT 
			c.column_name,
			c.data_type,
			c.is_nullable = 'YES' as nullable,
			COALESCE(c.column_default, '') as default_value,
			c.character_maximum_length,
			c.numeric_precision,
			c.numeric_scale,
			c.ordinal_position,
			COALESCE(col_description(pgc.oid, c.ordinal_position), '') as comment,
			CASE WHEN pk.column_name IS NOT NULL THEN true ELSE false END as is_primary_key,
			CASE WHEN fk.column_name IS NOT NULL THEN true ELSE false END as is_foreign_key,
			CASE WHEN uk.column_name IS NOT NULL THEN true ELSE false END as is_unique
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
			SELECT ku.column_name, ku.table_name, ku.table_schema
			FROM information_schema.table_constraints tc
			JOIN information_schema.key_column_usage ku ON tc.constraint_name = ku.constraint_name
			WHERE tc.constraint_type = 'FOREIGN KEY'
		) fk ON fk.column_name = c.column_name AND fk.table_name = c.table_name AND fk.table_schema = c.table_schema
		LEFT JOIN (
			SELECT ku.column_name, ku.table_name, ku.table_schema
			FROM information_schema.table_constraints tc
			JOIN information_schema.key_column_usage ku ON tc.constraint_name = ku.constraint_name
			WHERE tc.constraint_type = 'UNIQUE'
		) uk ON uk.column_name = c.column_name AND uk.table_name = c.table_name AND uk.table_schema = c.table_schema
		WHERE c.table_schema = $1 AND c.table_name = $2
		ORDER BY c.ordinal_position`

	rows, err := ms.db.Query(ctx, query, schema, tableName)
	if err != nil {
		return nil, fmt.Errorf("failed to query columns: %w", err)
	}
	defer rows.Close()

	var columns []*Column
	for rows.Next() {
		var column Column
		var maxLength, numericPrecision, numericScale *int

		err := rows.Scan(
			&column.Name,
			&column.Type,
			&column.Nullable,
			&column.DefaultValue,
			&maxLength,
			&numericPrecision,
			&numericScale,
			&column.OrdinalPosition,
			&column.Comment,
			&column.IsPrimaryKey,
			&column.IsForeignKey,
			&column.IsUnique,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan column row: %w", err)
		}

		column.MaxLength = maxLength
		column.NumericPrecision = numericPrecision
		column.NumericScale = numericScale

		columns = append(columns, &column)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating column rows: %w", err)
	}

	return columns, nil
}

// getTableIndexes retrieves index metadata for a specific table
func (ms *MetaService) getTableIndexes(ctx context.Context, schema, tableName string) ([]*Index, error) {
	query := `
		SELECT 
			i.indexname as index_name,
			i.tablename as table_name,
			i.indexdef as definition,
			CASE WHEN i.indexname LIKE '%_pkey' THEN true ELSE false END as is_primary,
			CASE WHEN ix.indisunique THEN true ELSE false END as is_unique,
			am.amname as index_type,
			array_agg(a.attname ORDER BY a.attnum) as columns
		FROM pg_indexes i
		JOIN pg_class c ON c.relname = i.tablename
		JOIN pg_namespace n ON n.oid = c.relnamespace AND n.nspname = i.schemaname
		JOIN pg_index ix ON ix.indexrelid = (
			SELECT oid FROM pg_class WHERE relname = i.indexname AND relnamespace = n.oid
		)
		JOIN pg_class ic ON ic.oid = ix.indexrelid
		JOIN pg_am am ON am.oid = ic.relam
		JOIN pg_attribute a ON a.attrelid = c.oid AND a.attnum = ANY(ix.indkey)
		WHERE i.schemaname = $1 AND i.tablename = $2
		GROUP BY i.indexname, i.tablename, i.indexdef, ix.indisunique, am.amname
		ORDER BY i.indexname`

	rows, err := ms.db.Query(ctx, query, schema, tableName)
	if err != nil {
		return nil, fmt.Errorf("failed to query indexes: %w", err)
	}
	defer rows.Close()

	var indexes []*Index
	for rows.Next() {
		var index Index
		var columns []string

		err := rows.Scan(
			&index.Name,
			&index.TableName,
			&index.Definition,
			&index.IsPrimary,
			&index.IsUnique,
			&index.IndexType,
			&columns,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan index row: %w", err)
		}

		index.Columns = columns
		indexes = append(indexes, &index)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating index rows: %w", err)
	}

	return indexes, nil
}

// getTableConstraints retrieves constraint metadata for a specific table
func (ms *MetaService) getTableConstraints(ctx context.Context, schema, tableName string) ([]*Constraint, error) {
	query := `
		SELECT 
			tc.constraint_name,
			tc.constraint_type,
			tc.table_name,
			COALESCE(string_agg(kcu.column_name, ',' ORDER BY kcu.ordinal_position), '') as columns,
			COALESCE(ccu.table_name, '') as referenced_table,
			COALESCE(string_agg(ccu.column_name, ',' ORDER BY kcu.ordinal_position), '') as referenced_columns,
			COALESCE(rc.update_rule, '') as on_update,
			COALESCE(rc.delete_rule, '') as on_delete,
			COALESCE(cc.check_clause, '') as definition
		FROM information_schema.table_constraints tc
		LEFT JOIN information_schema.key_column_usage kcu 
			ON tc.constraint_name = kcu.constraint_name 
			AND tc.table_schema = kcu.table_schema
		LEFT JOIN information_schema.constraint_column_usage ccu 
			ON tc.constraint_name = ccu.constraint_name 
			AND tc.table_schema = ccu.table_schema
		LEFT JOIN information_schema.referential_constraints rc 
			ON tc.constraint_name = rc.constraint_name 
			AND tc.table_schema = rc.constraint_schema
		LEFT JOIN information_schema.check_constraints cc 
			ON tc.constraint_name = cc.constraint_name 
			AND tc.table_schema = cc.constraint_schema
		WHERE tc.table_schema = $1 AND tc.table_name = $2
		GROUP BY tc.constraint_name, tc.constraint_type, tc.table_name, ccu.table_name, rc.update_rule, rc.delete_rule, cc.check_clause
		ORDER BY tc.constraint_name`

	rows, err := ms.db.Query(ctx, query, schema, tableName)
	if err != nil {
		return nil, fmt.Errorf("failed to query constraints: %w", err)
	}
	defer rows.Close()

	var constraints []*Constraint
	for rows.Next() {
		var constraint Constraint
		var columnsStr, referencedColumnsStr string

		err := rows.Scan(
			&constraint.Name,
			&constraint.Type,
			&constraint.TableName,
			&columnsStr,
			&constraint.ReferencedTable,
			&referencedColumnsStr,
			&constraint.OnUpdate,
			&constraint.OnDelete,
			&constraint.Definition,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan constraint row: %w", err)
		}

		// Convert comma-separated strings to slices
		if columnsStr != "" {
			constraint.Columns = strings.Split(columnsStr, ",")
		} else {
			constraint.Columns = []string{}
		}

		if referencedColumnsStr != "" {
			constraint.ReferencedColumns = strings.Split(referencedColumnsStr, ",")
		} else {
			constraint.ReferencedColumns = []string{}
		}
		constraints = append(constraints, &constraint)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating constraint rows: %w", err)
	}

	return constraints, nil
}

// GetSchemas retrieves all available schemas
func (ms *MetaService) GetSchemas(ctx context.Context) ([]string, error) {
	query := `
		SELECT schema_name 
		FROM information_schema.schemata 
		WHERE schema_name NOT IN ('information_schema', 'pg_catalog', 'pg_toast')
		ORDER BY schema_name`

	rows, err := ms.db.Query(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed to query schemas: %w", err)
	}
	defer rows.Close()

	var schemas []string
	for rows.Next() {
		var schema string
		if err := rows.Scan(&schema); err != nil {
			return nil, fmt.Errorf("failed to scan schema row: %w", err)
		}
		schemas = append(schemas, schema)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating schema rows: %w", err)
	}

	return schemas, nil
}

// TableDefinition represents a table definition for creation
type TableDefinition struct {
	Name    string              `json:"name"`
	Schema  string              `json:"schema"`
	Columns []*ColumnDefinition `json:"columns"`
	Comment string              `json:"comment,omitempty"`
}

// ColumnDefinition represents a column definition for table creation
type ColumnDefinition struct {
	Name         string `json:"name"`
	Type         string `json:"type"`
	Nullable     bool   `json:"nullable"`
	DefaultValue string `json:"default_value,omitempty"`
	IsPrimaryKey bool   `json:"is_primary_key"`
	IsUnique     bool   `json:"is_unique"`
	Comment      string `json:"comment,omitempty"`
}

// TableChanges represents changes to be made to a table
type TableChanges struct {
	AddColumns    []*ColumnDefinition   `json:"add_columns,omitempty"`
	DropColumns   []string              `json:"drop_columns,omitempty"`
	ModifyColumns []*ColumnModification `json:"modify_columns,omitempty"`
	RenameColumns map[string]string     `json:"rename_columns,omitempty"`
	SetComment    *string               `json:"set_comment,omitempty"`
}

// ColumnModification represents a column modification
type ColumnModification struct {
	Name        string  `json:"name"`
	NewType     *string `json:"new_type,omitempty"`
	SetNullable *bool   `json:"set_nullable,omitempty"`
	SetDefault  *string `json:"set_default,omitempty"`
	DropDefault bool    `json:"drop_default,omitempty"`
	SetComment  *string `json:"set_comment,omitempty"`
}

// CreateTable creates a new table with the specified definition
func (ms *MetaService) CreateTable(ctx context.Context, tableDef *TableDefinition) error {
	if tableDef.Schema == "" {
		tableDef.Schema = "public"
	}

	// Validate table definition
	if err := ms.validateTableDefinition(tableDef); err != nil {
		return fmt.Errorf("invalid table definition: %w", err)
	}

	// Check if table already exists
	exists, err := ms.tableExists(ctx, tableDef.Schema, tableDef.Name)
	if err != nil {
		return fmt.Errorf("failed to check if table exists: %w", err)
	}
	if exists {
		return fmt.Errorf("table %s.%s already exists", tableDef.Schema, tableDef.Name)
	}

	// Build CREATE TABLE statement
	query, err := ms.buildCreateTableQuery(tableDef)
	if err != nil {
		return fmt.Errorf("failed to build create table query: %w", err)
	}

	// Execute the query
	if err := ms.db.Exec(ctx, query); err != nil {
		return fmt.Errorf("failed to create table: %w", err)
	}

	// Add table comment if specified
	if tableDef.Comment != "" {
		commentQuery := fmt.Sprintf("COMMENT ON TABLE %q.%q IS %s", tableDef.Schema, tableDef.Name, quoteLiteral(tableDef.Comment))
		if err := ms.db.Exec(ctx, commentQuery); err != nil {
			return fmt.Errorf("failed to add table comment: %w", err)
		}
	}

	// Add column comments if specified
	for _, col := range tableDef.Columns {
		if col.Comment != "" {
			commentQuery := fmt.Sprintf("COMMENT ON COLUMN %q.%q.%q IS %s", tableDef.Schema, tableDef.Name, col.Name, quoteLiteral(col.Comment))
			if err := ms.db.Exec(ctx, commentQuery); err != nil {
				return fmt.Errorf("failed to add column comment for %s: %w", col.Name, err)
			}
		}
	}

	return nil
}

// UpdateTable modifies an existing table according to the specified changes
func (ms *MetaService) UpdateTable(ctx context.Context, schema, tableName string, changes *TableChanges) error {
	if schema == "" {
		schema = "public"
	}

	// Check if table exists
	exists, err := ms.tableExists(ctx, schema, tableName)
	if err != nil {
		return fmt.Errorf("failed to check if table exists: %w", err)
	}
	if !exists {
		return fmt.Errorf("table %s.%s does not exist", schema, tableName)
	}

	// Execute changes in transaction
	tx, err := ms.db.Begin(ctx)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback(ctx)

	// Add columns
	for _, col := range changes.AddColumns {
		if err := ms.addColumn(ctx, tx, schema, tableName, col); err != nil {
			return fmt.Errorf("failed to add column %s: %w", col.Name, err)
		}
	}

	// Drop columns
	for _, colName := range changes.DropColumns {
		if err := ms.dropColumn(ctx, tx, schema, tableName, colName); err != nil {
			return fmt.Errorf("failed to drop column %s: %w", colName, err)
		}
	}

	// Modify columns
	for _, mod := range changes.ModifyColumns {
		if err := ms.modifyColumn(ctx, tx, schema, tableName, mod); err != nil {
			return fmt.Errorf("failed to modify column %s: %w", mod.Name, err)
		}
	}

	// Rename columns
	for oldName, newName := range changes.RenameColumns {
		if err := ms.renameColumn(ctx, tx, schema, tableName, oldName, newName); err != nil {
			return fmt.Errorf("failed to rename column %s to %s: %w", oldName, newName, err)
		}
	}

	// Set table comment
	if changes.SetComment != nil {
		commentQuery := fmt.Sprintf("COMMENT ON TABLE %q.%q IS %s", schema, tableName, quoteLiteral(*changes.SetComment))
		if _, err := tx.Exec(ctx, commentQuery); err != nil {
			return fmt.Errorf("failed to set table comment: %w", err)
		}
	}

	// Commit transaction
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	return nil
}

// DropTable drops a table with safety checks
func (ms *MetaService) DropTable(ctx context.Context, schema, tableName string, cascade bool) error {
	if schema == "" {
		schema = "public"
	}

	// Check if table exists
	exists, err := ms.tableExists(ctx, schema, tableName)
	if err != nil {
		return fmt.Errorf("failed to check if table exists: %w", err)
	}
	if !exists {
		return fmt.Errorf("table %s.%s does not exist", schema, tableName)
	}

	// Safety check: prevent dropping system tables
	if ms.isSystemTable(schema, tableName) {
		return fmt.Errorf("cannot drop system table %s.%s", schema, tableName)
	}

	// Check for dependencies if not cascading
	if !cascade {
		hasDependencies, err := ms.tableHasDependencies(ctx, schema, tableName)
		if err != nil {
			return fmt.Errorf("failed to check table dependencies: %w", err)
		}
		if hasDependencies {
			return fmt.Errorf("table %s.%s has dependencies, use cascade=true to force drop", schema, tableName)
		}
	}

	// Build DROP TABLE statement
	query := fmt.Sprintf("DROP TABLE %q.%q", schema, tableName)
	if cascade {
		query += " CASCADE"
	}

	// Execute the query
	if err := ms.db.Exec(ctx, query); err != nil {
		return fmt.Errorf("failed to drop table: %w", err)
	}

	return nil
}

// Helper functions for table management operations

// validateTableDefinition validates a table definition
func (ms *MetaService) validateTableDefinition(tableDef *TableDefinition) error {
	if tableDef.Name == "" {
		return fmt.Errorf("table name cannot be empty")
	}

	if len(tableDef.Columns) == 0 {
		return fmt.Errorf("table must have at least one column")
	}

	// Validate column names are unique
	columnNames := make(map[string]bool)
	primaryKeyCount := 0

	for _, col := range tableDef.Columns {
		if col.Name == "" {
			return fmt.Errorf("column name cannot be empty")
		}

		if columnNames[col.Name] {
			return fmt.Errorf("duplicate column name: %s", col.Name)
		}
		columnNames[col.Name] = true

		if col.Type == "" {
			return fmt.Errorf("column %s must have a type", col.Name)
		}

		if col.IsPrimaryKey {
			primaryKeyCount++
		}
	}

	if primaryKeyCount > 1 {
		return fmt.Errorf("table can have at most one primary key column (use composite primary key constraints for multiple columns)")
	}

	return nil
}

// tableExists checks if a table exists
func (ms *MetaService) tableExists(ctx context.Context, schema, tableName string) (bool, error) {
	query := `
		SELECT EXISTS (
			SELECT 1 FROM information_schema.tables 
			WHERE table_schema = $1 AND table_name = $2
		)`

	var exists bool
	err := ms.db.QueryRow(ctx, query, schema, tableName).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("failed to check table existence: %w", err)
	}

	return exists, nil
}

// buildCreateTableQuery builds a CREATE TABLE SQL statement
func (ms *MetaService) buildCreateTableQuery(tableDef *TableDefinition) (string, error) {
	var query strings.Builder

	query.WriteString(fmt.Sprintf("CREATE TABLE %q.%q (\n", tableDef.Schema, tableDef.Name))

	var columnDefs []string
	var primaryKeyCol string

	for _, col := range tableDef.Columns {
		var colDef strings.Builder
		colDef.WriteString(fmt.Sprintf("  %q %s", col.Name, col.Type))

		if !col.Nullable {
			colDef.WriteString(" NOT NULL")
		}

		if col.DefaultValue != "" {
			colDef.WriteString(fmt.Sprintf(" DEFAULT %s", col.DefaultValue))
		}

		if col.IsUnique {
			colDef.WriteString(" UNIQUE")
		}

		if col.IsPrimaryKey {
			primaryKeyCol = col.Name
		}

		columnDefs = append(columnDefs, colDef.String())
	}

	query.WriteString(strings.Join(columnDefs, ",\n"))

	// Add primary key constraint if specified
	if primaryKeyCol != "" {
		query.WriteString(fmt.Sprintf(",\n  PRIMARY KEY (%q)", primaryKeyCol))
	}

	query.WriteString("\n)")

	return query.String(), nil
}

// addColumn adds a column to an existing table
func (ms *MetaService) addColumn(ctx context.Context, tx pgx.Tx, schema, tableName string, col *ColumnDefinition) error {
	var query strings.Builder
	query.WriteString(fmt.Sprintf("ALTER TABLE %q.%q ADD COLUMN %q %s", schema, tableName, col.Name, col.Type))

	if !col.Nullable {
		query.WriteString(" NOT NULL")
	}

	if col.DefaultValue != "" {
		query.WriteString(fmt.Sprintf(" DEFAULT %s", col.DefaultValue))
	}

	if col.IsUnique {
		query.WriteString(" UNIQUE")
	}

	fmt.Printf("DEBUG: Executing ALTER TABLE query: %s\n", query.String())
	if _, err := tx.Exec(ctx, query.String()); err != nil {
		fmt.Printf("DEBUG: ALTER TABLE query failed with error: %v\n", err)
		return fmt.Errorf("ALTER TABLE failed: %w", err)
	}

	// Add column comment if specified
	if col.Comment != "" {
		// Use direct string interpolation for the comment to avoid parameter issues
		commentQuery := fmt.Sprintf("COMMENT ON COLUMN %q.%q.%q IS %s", schema, tableName, col.Name, quoteLiteral(col.Comment))
		fmt.Printf("DEBUG: Executing comment query: %s\n", commentQuery)
		if _, err := tx.Exec(ctx, commentQuery); err != nil {
			fmt.Printf("DEBUG: Comment query failed with error: %v\n", err)
			return fmt.Errorf("comment query failed: %w", err)
		}
	}

	return nil
}

// dropColumn drops a column from an existing table
func (ms *MetaService) dropColumn(ctx context.Context, tx pgx.Tx, schema, tableName, columnName string) error {
	query := fmt.Sprintf("ALTER TABLE %q.%q DROP COLUMN %q", schema, tableName, columnName)
	_, err := tx.Exec(ctx, query)
	return err
}

// modifyColumn modifies an existing column
func (ms *MetaService) modifyColumn(ctx context.Context, tx pgx.Tx, schema, tableName string, mod *ColumnModification) error {
	// Change column type
	if mod.NewType != nil {
		query := fmt.Sprintf("ALTER TABLE %q.%q ALTER COLUMN %q TYPE %s", schema, tableName, mod.Name, *mod.NewType)
		if _, err := tx.Exec(ctx, query); err != nil {
			return err
		}
	}

	// Change nullable constraint
	if mod.SetNullable != nil {
		var constraint string
		if *mod.SetNullable {
			constraint = "DROP NOT NULL"
		} else {
			constraint = "SET NOT NULL"
		}
		query := fmt.Sprintf("ALTER TABLE %q.%q ALTER COLUMN %q %s", schema, tableName, mod.Name, constraint)
		if _, err := tx.Exec(ctx, query); err != nil {
			return err
		}
	}

	// Set default value
	if mod.SetDefault != nil {
		query := fmt.Sprintf("ALTER TABLE %q.%q ALTER COLUMN %q SET DEFAULT %s", schema, tableName, mod.Name, *mod.SetDefault)
		if _, err := tx.Exec(ctx, query); err != nil {
			return err
		}
	}

	// Drop default value
	if mod.DropDefault {
		query := fmt.Sprintf("ALTER TABLE %q.%q ALTER COLUMN %q DROP DEFAULT", schema, tableName, mod.Name)
		if _, err := tx.Exec(ctx, query); err != nil {
			return err
		}
	}

	// Set column comment
	if mod.SetComment != nil {
		commentQuery := fmt.Sprintf("COMMENT ON COLUMN %q.%q.%q IS %s", schema, tableName, mod.Name, quoteLiteral(*mod.SetComment))
		if _, err := tx.Exec(ctx, commentQuery); err != nil {
			return err
		}
	}

	return nil
}

// renameColumn renames a column
func (ms *MetaService) renameColumn(ctx context.Context, tx pgx.Tx, schema, tableName, oldName, newName string) error {
	query := fmt.Sprintf("ALTER TABLE %q.%q RENAME COLUMN %q TO %q", schema, tableName, oldName, newName)
	_, err := tx.Exec(ctx, query)
	return err
}

// isSystemTable checks if a table is a system table that shouldn't be dropped
func (ms *MetaService) isSystemTable(schema, tableName string) bool {
	systemSchemas := map[string]bool{
		"information_schema": true,
		"pg_catalog":         true,
		"pg_toast":           true,
	}

	if systemSchemas[schema] {
		return true
	}

	// Check for common system tables in public schema
	systemTables := map[string]bool{
		"schema_migrations":     true,
		"goose_db_version":      true,
		"flyway_schema_history": true,
	}

	return systemTables[tableName]
}

// tableHasDependencies checks if a table has foreign key dependencies
func (ms *MetaService) tableHasDependencies(ctx context.Context, schema, tableName string) (bool, error) {
	query := `
		SELECT EXISTS (
			SELECT 1 FROM information_schema.table_constraints tc
			JOIN information_schema.constraint_column_usage ccu ON tc.constraint_name = ccu.constraint_name
			WHERE tc.constraint_type = 'FOREIGN KEY'
			AND ccu.table_schema = $1 AND ccu.table_name = $2
		)`

	var hasDependencies bool
	err := ms.db.QueryRow(ctx, query, schema, tableName).Scan(&hasDependencies)
	if err != nil {
		return false, fmt.Errorf("failed to check table dependencies: %w", err)
	}

	return hasDependencies, nil
}

// QueryResult represents the result of a SQL query execution
type QueryResult struct {
	Columns       []string                 `json:"columns"`
	Rows          []map[string]interface{} `json:"rows"`
	RowsAffected  int64                    `json:"rows_affected"`
	ExecutionTime time.Duration            `json:"execution_time"`
	QueryType     string                   `json:"query_type"` // SELECT, INSERT, UPDATE, DELETE, etc.
}

// SQLExecutionOptions represents options for SQL execution
type SQLExecutionOptions struct {
	MaxRows     int           `json:"max_rows,omitempty"`    // Limit number of rows returned
	Timeout     time.Duration `json:"timeout,omitempty"`     // Query timeout
	ReadOnly    bool          `json:"read_only,omitempty"`   // Only allow read operations
	Transaction bool          `json:"transaction,omitempty"` // Execute in transaction
}

// ExecuteSQL executes a SQL query with proper validation and error handling
func (ms *MetaService) ExecuteSQL(ctx context.Context, query string, args []interface{}, options *SQLExecutionOptions) (*QueryResult, error) {
	if options == nil {
		options = &SQLExecutionOptions{
			MaxRows: 1000, // Default limit
			Timeout: 30 * time.Second,
		}
	}

	// Apply timeout if specified
	if options.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, options.Timeout)
		defer cancel()
	}

	// Validate SQL query
	if err := ms.validateSQL(query, options.ReadOnly); err != nil {
		return nil, fmt.Errorf("SQL validation failed: %w", err)
	}

	// Determine query type
	queryType := ms.getQueryType(query)

	// Record execution start time
	startTime := time.Now()

	var result *QueryResult
	var err error

	// Execute based on query type and options
	if options.Transaction && (queryType != "SELECT") {
		result, err = ms.executeInTransaction(ctx, query, args, options, queryType)
	} else {
		result, err = ms.executeQuery(ctx, query, args, options, queryType)
	}

	if err != nil {
		return nil, err
	}

	// Set execution time
	result.ExecutionTime = time.Since(startTime)
	result.QueryType = queryType

	return result, nil
}

// ExecuteSQLBatch executes multiple SQL statements in a transaction
func (ms *MetaService) ExecuteSQLBatch(ctx context.Context, queries []string, options *SQLExecutionOptions) ([]*QueryResult, error) {
	if options == nil {
		options = &SQLExecutionOptions{
			MaxRows: 1000,
			Timeout: 60 * time.Second,
		}
	}

	// Apply timeout if specified
	if options.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, options.Timeout)
		defer cancel()
	}

	// Validate all queries first
	for i, query := range queries {
		if err := ms.validateSQL(query, options.ReadOnly); err != nil {
			return nil, fmt.Errorf("SQL validation failed for query %d: %w", i+1, err)
		}
	}

	// Execute in transaction
	tx, err := ms.db.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback(ctx)

	var results []*QueryResult
	for i, query := range queries {
		startTime := time.Now()
		queryType := ms.getQueryType(query)

		var result *QueryResult
		if queryType == "SELECT" {
			result, err = ms.executeSelectInTx(ctx, tx, query, nil, options)
		} else {
			result, err = ms.executeNonSelectInTx(ctx, tx, query, nil)
		}

		if err != nil {
			return nil, fmt.Errorf("failed to execute query %d: %w", i+1, err)
		}

		result.ExecutionTime = time.Since(startTime)
		result.QueryType = queryType
		results = append(results, result)
	}

	// Commit transaction
	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("failed to commit transaction: %w", err)
	}

	return results, nil
}

// validateSQL performs basic SQL validation and security checks
func (ms *MetaService) validateSQL(query string, readOnly bool) error {
	if strings.TrimSpace(query) == "" {
		return fmt.Errorf("query cannot be empty")
	}

	// Convert to uppercase for checking
	upperQuery := strings.ToUpper(strings.TrimSpace(query))

	// Check for dangerous operations
	dangerousOperations := []string{
		"DROP DATABASE",
		"DROP SCHEMA",
		"TRUNCATE",
		"DELETE FROM INFORMATION_SCHEMA",
		"DELETE FROM PG_",
		"UPDATE INFORMATION_SCHEMA",
		"UPDATE PG_",
	}

	for _, dangerous := range dangerousOperations {
		if strings.Contains(upperQuery, dangerous) {
			return fmt.Errorf("dangerous operation not allowed: %s", dangerous)
		}
	}

	// If read-only mode, only allow SELECT statements
	if readOnly {
		allowedReadOperations := []string{"SELECT", "WITH", "EXPLAIN", "SHOW"}
		isAllowed := false
		for _, allowed := range allowedReadOperations {
			if strings.HasPrefix(upperQuery, allowed) {
				isAllowed = true
				break
			}
		}
		if !isAllowed {
			return fmt.Errorf("only read operations are allowed in read-only mode")
		}
	}

	// Basic syntax validation (check for balanced parentheses)
	if err := ms.validateParentheses(query); err != nil {
		return fmt.Errorf("syntax error: %w", err)
	}

	return nil
}

// validateParentheses checks for balanced parentheses in SQL
func (ms *MetaService) validateParentheses(query string) error {
	count := 0
	inString := false
	var stringChar rune

	for i, char := range query {
		switch char {
		case '\'', '"':
			if !inString {
				inString = true
				stringChar = char
			} else if char == stringChar {
				// Check if it's escaped
				if i > 0 && rune(query[i-1]) != '\\' {
					inString = false
				}
			}
		case '(':
			if !inString {
				count++
			}
		case ')':
			if !inString {
				count--
				if count < 0 {
					return fmt.Errorf("unmatched closing parenthesis")
				}
			}
		}
	}

	if count != 0 {
		return fmt.Errorf("unmatched parentheses")
	}

	return nil
}

// getQueryType determines the type of SQL query
func (ms *MetaService) getQueryType(query string) string {
	upperQuery := strings.ToUpper(strings.TrimSpace(query))

	queryTypes := []string{
		"SELECT", "INSERT", "UPDATE", "DELETE", "CREATE", "ALTER", "DROP",
		"TRUNCATE", "GRANT", "REVOKE", "WITH", "EXPLAIN", "SHOW", "DESCRIBE",
	}

	for _, queryType := range queryTypes {
		if strings.HasPrefix(upperQuery, queryType) {
			return queryType
		}
	}

	return "UNKNOWN"
}

// executeQuery executes a single query
func (ms *MetaService) executeQuery(ctx context.Context, query string, args []interface{}, options *SQLExecutionOptions, queryType string) (*QueryResult, error) {
	if queryType == "SELECT" || strings.HasPrefix(queryType, "WITH") || queryType == "EXPLAIN" || queryType == "SHOW" {
		return ms.executeSelect(ctx, query, args, options)
	} else {
		return ms.executeNonSelect(ctx, query, args)
	}
}

// executeInTransaction executes a query within a transaction
func (ms *MetaService) executeInTransaction(ctx context.Context, query string, args []interface{}, options *SQLExecutionOptions, queryType string) (*QueryResult, error) {
	tx, err := ms.db.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback(ctx)

	var result *QueryResult
	if queryType == "SELECT" || strings.HasPrefix(queryType, "WITH") || queryType == "EXPLAIN" || queryType == "SHOW" {
		result, err = ms.executeSelectInTx(ctx, tx, query, args, options)
	} else {
		result, err = ms.executeNonSelectInTx(ctx, tx, query, args)
	}

	if err != nil {
		return nil, err
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("failed to commit transaction: %w", err)
	}

	return result, nil
}

// executeSelect executes a SELECT query
func (ms *MetaService) executeSelect(ctx context.Context, query string, args []interface{}, options *SQLExecutionOptions) (*QueryResult, error) {
	rows, err := ms.db.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to execute query: %w", err)
	}
	defer rows.Close()

	return ms.processSelectResult(rows, options)
}

// executeSelectInTx executes a SELECT query within a transaction
func (ms *MetaService) executeSelectInTx(ctx context.Context, tx pgx.Tx, query string, args []interface{}, options *SQLExecutionOptions) (*QueryResult, error) {
	rows, err := tx.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to execute query: %w", err)
	}
	defer rows.Close()

	return ms.processSelectResult(rows, options)
}

// executeNonSelect executes a non-SELECT query
func (ms *MetaService) executeNonSelect(ctx context.Context, query string, args []interface{}) (*QueryResult, error) {
	commandTag, err := ms.db.Pool.Exec(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to execute query: %w", err)
	}

	return &QueryResult{
		Columns:      []string{},
		Rows:         []map[string]interface{}{},
		RowsAffected: commandTag.RowsAffected(),
	}, nil
}

// executeNonSelectInTx executes a non-SELECT query within a transaction
func (ms *MetaService) executeNonSelectInTx(ctx context.Context, tx pgx.Tx, query string, args []interface{}) (*QueryResult, error) {
	commandTag, err := tx.Exec(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to execute query: %w", err)
	}

	return &QueryResult{
		Columns:      []string{},
		Rows:         []map[string]interface{}{},
		RowsAffected: commandTag.RowsAffected(),
	}, nil
}

// processSelectResult processes the result of a SELECT query
func (ms *MetaService) processSelectResult(rows pgx.Rows, options *SQLExecutionOptions) (*QueryResult, error) {
	// Get column descriptions
	fieldDescriptions := rows.FieldDescriptions()
	columns := make([]string, len(fieldDescriptions))
	for i, desc := range fieldDescriptions {
		columns[i] = desc.Name
	}

	var resultRows []map[string]interface{}
	rowCount := 0

	for rows.Next() {
		// Check max rows limit
		if options.MaxRows > 0 && rowCount >= options.MaxRows {
			break
		}

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

		resultRows = append(resultRows, result)
		rowCount++
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating rows: %w", err)
	}

	return &QueryResult{
		Columns:      columns,
		Rows:         resultRows,
		RowsAffected: int64(rowCount),
	}, nil
}

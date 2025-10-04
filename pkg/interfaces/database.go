package interfaces

import (
	"context"
	"time"
)

// MetaService defines the database meta service interface
type MetaService interface {
	GetTables(ctx context.Context, schema string) ([]*Table, error)
	GetTable(ctx context.Context, schema string, tableName string) (*Table, error)
	CreateTable(ctx context.Context, table TableDefinition) error
	UpdateTable(ctx context.Context, tableName string, changes TableChanges) error
	DeleteTable(ctx context.Context, tableName string) error
	ExecuteSQL(ctx context.Context, query string, args ...interface{}) (*QueryResult, error)
	GetSchemas(ctx context.Context) ([]string, error)
	CreateSchema(ctx context.Context, schemaName string) error
	DeleteSchema(ctx context.Context, schemaName string) error
}

// MigrationService defines the migration service interface
type MigrationService interface {
	CreateMigration(ctx context.Context, name string, up string, down string) (*Migration, error)
	ApplyMigration(ctx context.Context, migrationID string) error
	RollbackMigration(ctx context.Context, migrationID string) error
	GetMigrationHistory(ctx context.Context) ([]*Migration, error)
	GetPendingMigrations(ctx context.Context) ([]*Migration, error)
	GenerateMigration(ctx context.Context, name string, changes []SchemaChange) (*Migration, error)
}

// Table represents database table metadata
type Table struct {
	Name        string        `json:"name"`
	Schema      string        `json:"schema"`
	Columns     []*Column     `json:"columns"`
	Indexes     []*Index      `json:"indexes"`
	Constraints []*Constraint `json:"constraints"`
	RLSEnabled  bool          `json:"rls_enabled"`
	RowCount    int64         `json:"row_count"`
	CreatedAt   time.Time     `json:"created_at"`
	UpdatedAt   time.Time     `json:"updated_at"`
}

// Column represents database column metadata
type Column struct {
	Name         string      `json:"name"`
	Type         string      `json:"type"`
	Nullable     bool        `json:"nullable"`
	DefaultValue interface{} `json:"default_value"`
	IsPrimaryKey bool        `json:"is_primary_key"`
	IsForeignKey bool        `json:"is_foreign_key"`
	IsUnique     bool        `json:"is_unique"`
	MaxLength    int         `json:"max_length"`
	Precision    int         `json:"precision"`
	Scale        int         `json:"scale"`
}

// Index represents database index metadata
type Index struct {
	Name      string   `json:"name"`
	Columns   []string `json:"columns"`
	IsUnique  bool     `json:"is_unique"`
	IsPrimary bool     `json:"is_primary"`
	Type      string   `json:"type"`
}

// Constraint represents database constraint metadata
type Constraint struct {
	Name              string   `json:"name"`
	Type              string   `json:"type"` // PRIMARY KEY, FOREIGN KEY, UNIQUE, CHECK
	Columns           []string `json:"columns"`
	ReferencedTable   string   `json:"referenced_table"`
	ReferencedColumns []string `json:"referenced_columns"`
	Definition        string   `json:"definition"`
}

// TableDefinition represents table creation definition
type TableDefinition struct {
	Name        string                  `json:"name"`
	Schema      string                  `json:"schema"`
	Columns     []*ColumnDefinition     `json:"columns"`
	Indexes     []*IndexDefinition      `json:"indexes"`
	Constraints []*ConstraintDefinition `json:"constraints"`
	RLSEnabled  bool                    `json:"rls_enabled"`
}

// ColumnDefinition represents column creation definition
type ColumnDefinition struct {
	Name         string      `json:"name"`
	Type         string      `json:"type"`
	Nullable     bool        `json:"nullable"`
	DefaultValue interface{} `json:"default_value"`
	IsPrimaryKey bool        `json:"is_primary_key"`
	IsUnique     bool        `json:"is_unique"`
	MaxLength    int         `json:"max_length"`
	Precision    int         `json:"precision"`
	Scale        int         `json:"scale"`
}

// IndexDefinition represents index creation definition
type IndexDefinition struct {
	Name     string   `json:"name"`
	Columns  []string `json:"columns"`
	IsUnique bool     `json:"is_unique"`
	Type     string   `json:"type"`
}

// ConstraintDefinition represents constraint creation definition
type ConstraintDefinition struct {
	Name              string   `json:"name"`
	Type              string   `json:"type"`
	Columns           []string `json:"columns"`
	ReferencedTable   string   `json:"referenced_table"`
	ReferencedColumns []string `json:"referenced_columns"`
	Definition        string   `json:"definition"`
}

// TableChanges represents table modification changes
type TableChanges struct {
	AddColumns      []*ColumnDefinition     `json:"add_columns"`
	DropColumns     []string                `json:"drop_columns"`
	ModifyColumns   []*ColumnModification   `json:"modify_columns"`
	AddIndexes      []*IndexDefinition      `json:"add_indexes"`
	DropIndexes     []string                `json:"drop_indexes"`
	AddConstraints  []*ConstraintDefinition `json:"add_constraints"`
	DropConstraints []string                `json:"drop_constraints"`
}

// ColumnModification represents column modification
type ColumnModification struct {
	Name        string      `json:"name"`
	NewName     string      `json:"new_name"`
	NewType     string      `json:"new_type"`
	NewNullable *bool       `json:"new_nullable"`
	NewDefault  interface{} `json:"new_default"`
}

// Migration represents database migration
type Migration struct {
	ID        string     `json:"id"`
	Name      string     `json:"name"`
	Version   string     `json:"version"`
	UpSQL     string     `json:"up_sql"`
	DownSQL   string     `json:"down_sql"`
	AppliedAt *time.Time `json:"applied_at"`
	CreatedAt time.Time  `json:"created_at"`
}

// QueryResult represents SQL query result
type QueryResult struct {
	Columns []string                 `json:"columns"`
	Rows    []map[string]interface{} `json:"rows"`
	Count   int64                    `json:"count"`
}

// SchemaChange represents a schema change for migration generation
type SchemaChange struct {
	Type   string      `json:"type"` // CREATE_TABLE, DROP_TABLE, ADD_COLUMN, etc.
	Target string      `json:"target"`
	Data   interface{} `json:"data"`
}

// DatabaseSchema represents complete database schema
type DatabaseSchema struct {
	Tables []*Table `json:"tables"`
	Views  []*View  `json:"views"`
}

// View represents database view metadata
type View struct {
	Name       string `json:"name"`
	Schema     string `json:"schema"`
	Definition string `json:"definition"`
}

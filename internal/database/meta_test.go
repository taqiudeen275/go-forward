package database

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMetaService_GetSchemas(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	metaService := NewMetaService(db)

	schemas, err := metaService.GetSchemas(context.Background())
	require.NoError(t, err)
	assert.Contains(t, schemas, "public")

	// Should not contain system schemas
	assert.NotContains(t, schemas, "information_schema")
	assert.NotContains(t, schemas, "pg_catalog")
	assert.NotContains(t, schemas, "pg_toast")
}

func TestMetaService_GetTables(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	metaService := NewMetaService(db)
	ctx := context.Background()

	// Create a test table first
	tableDef := &TableDefinition{
		Name:   "test_get_tables",
		Schema: "public",
		Columns: []*ColumnDefinition{
			{
				Name:         "id",
				Type:         "SERIAL",
				Nullable:     false,
				IsPrimaryKey: true,
			},
			{
				Name:     "name",
				Type:     "VARCHAR(100)",
				Nullable: false,
			},
		},
		Comment: "Test table for GetTables",
	}

	err := metaService.CreateTable(ctx, tableDef)
	require.NoError(t, err)

	// Test getting tables from public schema
	tables, err := metaService.GetTables(ctx, "public")
	require.NoError(t, err)

	// Find our test table
	var testTable *Table
	for _, table := range tables {
		if table.Name == "test_get_tables" {
			testTable = table
			break
		}
	}

	require.NotNil(t, testTable, "test table should be found")
	assert.Equal(t, "test_get_tables", testTable.Name)
	assert.Equal(t, "public", testTable.Schema)
	assert.Equal(t, "Test table for GetTables", testTable.Comment)
	assert.Len(t, testTable.Columns, 2)
	assert.NotNil(t, testTable.Indexes)
	assert.NotNil(t, testTable.Constraints)

	// Test getting tables with no schema specified (should default to public)
	tablesDefault, err := metaService.GetTables(ctx)
	require.NoError(t, err)
	assert.True(t, len(tablesDefault) > 0)

	// Clean up
	err = metaService.DropTable(ctx, "public", "test_get_tables", false)
	require.NoError(t, err)
}

func TestMetaService_GetTable(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	metaService := NewMetaService(db)
	ctx := context.Background()

	// Create a test table with various column types and constraints
	tableDef := &TableDefinition{
		Name:   "test_get_table_detailed",
		Schema: "public",
		Columns: []*ColumnDefinition{
			{
				Name:         "id",
				Type:         "SERIAL",
				Nullable:     false,
				IsPrimaryKey: true,
				Comment:      "Primary key",
			},
			{
				Name:     "email",
				Type:     "VARCHAR(255)",
				Nullable: false,
				IsUnique: true,
				Comment:  "User email address",
			},
			{
				Name:         "name",
				Type:         "VARCHAR(100)",
				Nullable:     true,
				DefaultValue: "'Unknown'",
				Comment:      "User full name",
			},
			{
				Name:     "age",
				Type:     "INTEGER",
				Nullable: true,
			},
			{
				Name:         "created_at",
				Type:         "TIMESTAMP",
				Nullable:     false,
				DefaultValue: "CURRENT_TIMESTAMP",
			},
		},
		Comment: "Detailed test table",
	}

	err := metaService.CreateTable(ctx, tableDef)
	require.NoError(t, err)

	// Get the table and verify all details
	table, err := metaService.GetTable(ctx, "public", "test_get_table_detailed")
	require.NoError(t, err)

	assert.Equal(t, "test_get_table_detailed", table.Name)
	assert.Equal(t, "public", table.Schema)
	assert.Equal(t, "Detailed test table", table.Comment)
	assert.Len(t, table.Columns, 5)

	// Verify specific columns
	idCol := findColumn(table.Columns, "id")
	require.NotNil(t, idCol)
	assert.True(t, idCol.IsPrimaryKey)
	assert.False(t, idCol.Nullable)
	assert.Equal(t, "Primary key", idCol.Comment)
	assert.Equal(t, 1, idCol.OrdinalPosition)

	emailCol := findColumn(table.Columns, "email")
	require.NotNil(t, emailCol)
	assert.True(t, emailCol.IsUnique)
	assert.False(t, emailCol.Nullable)
	assert.Equal(t, "User email address", emailCol.Comment)

	nameCol := findColumn(table.Columns, "name")
	require.NotNil(t, nameCol)
	assert.True(t, nameCol.Nullable)
	assert.Contains(t, nameCol.DefaultValue, "Unknown")
	assert.Equal(t, "User full name", nameCol.Comment)

	// Verify indexes exist (at least primary key index)
	assert.True(t, len(table.Indexes) > 0)

	// Verify constraints exist (at least primary key constraint)
	assert.True(t, len(table.Constraints) > 0)

	// Test getting non-existent table
	_, err = metaService.GetTable(ctx, "public", "non_existent_table")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")

	// Clean up
	err = metaService.DropTable(ctx, "public", "test_get_table_detailed", false)
	require.NoError(t, err)
}

func TestMetaService_CreateTable(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	metaService := NewMetaService(db)
	ctx := context.Background()

	t.Run("successful table creation", func(t *testing.T) {
		tableDef := &TableDefinition{
			Name:   "test_create_success",
			Schema: "public",
			Columns: []*ColumnDefinition{
				{
					Name:         "id",
					Type:         "SERIAL",
					Nullable:     false,
					IsPrimaryKey: true,
					Comment:      "User ID",
				},
				{
					Name:     "email",
					Type:     "VARCHAR(255)",
					Nullable: false,
					IsUnique: true,
					Comment:  "User email",
				},
				{
					Name:         "name",
					Type:         "VARCHAR(100)",
					Nullable:     true,
					DefaultValue: "''",
					Comment:      "User name",
				},
				{
					Name:         "created_at",
					Type:         "TIMESTAMP",
					Nullable:     false,
					DefaultValue: "CURRENT_TIMESTAMP",
				},
			},
			Comment: "Test users table",
		}

		err := metaService.CreateTable(ctx, tableDef)
		require.NoError(t, err)

		// Verify table was created
		table, err := metaService.GetTable(ctx, "public", "test_create_success")
		require.NoError(t, err)
		assert.Equal(t, "test_create_success", table.Name)
		assert.Equal(t, "Test users table", table.Comment)

		// Clean up
		err = metaService.DropTable(ctx, "public", "test_create_success", false)
		require.NoError(t, err)
	})

	t.Run("table already exists", func(t *testing.T) {
		tableDef := &TableDefinition{
			Name:   "test_duplicate",
			Schema: "public",
			Columns: []*ColumnDefinition{
				{
					Name:         "id",
					Type:         "SERIAL",
					Nullable:     false,
					IsPrimaryKey: true,
				},
			},
		}

		// Create table first time
		err := metaService.CreateTable(ctx, tableDef)
		require.NoError(t, err)

		// Try to create same table again
		err = metaService.CreateTable(ctx, tableDef)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "already exists")

		// Clean up
		err = metaService.DropTable(ctx, "public", "test_duplicate", false)
		require.NoError(t, err)
	})

	t.Run("invalid table definition", func(t *testing.T) {
		// Empty table name
		tableDef := &TableDefinition{
			Name:   "",
			Schema: "public",
			Columns: []*ColumnDefinition{
				{Name: "id", Type: "SERIAL"},
			},
		}
		err := metaService.CreateTable(ctx, tableDef)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "table name cannot be empty")

		// No columns
		tableDef = &TableDefinition{
			Name:    "test_no_columns",
			Schema:  "public",
			Columns: []*ColumnDefinition{},
		}
		err = metaService.CreateTable(ctx, tableDef)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "must have at least one column")

		// Duplicate column names
		tableDef = &TableDefinition{
			Name:   "test_duplicate_columns",
			Schema: "public",
			Columns: []*ColumnDefinition{
				{Name: "id", Type: "SERIAL"},
				{Name: "id", Type: "VARCHAR(50)"},
			},
		}
		err = metaService.CreateTable(ctx, tableDef)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "duplicate column name")

		// Multiple primary keys
		tableDef = &TableDefinition{
			Name:   "test_multiple_pk",
			Schema: "public",
			Columns: []*ColumnDefinition{
				{Name: "id1", Type: "SERIAL", IsPrimaryKey: true},
				{Name: "id2", Type: "SERIAL", IsPrimaryKey: true},
			},
		}
		err = metaService.CreateTable(ctx, tableDef)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "at most one primary key")
	})
}

func TestMetaService_UpdateTable(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	metaService := NewMetaService(db)
	ctx := context.Background()

	// Create initial table
	tableDef := &TableDefinition{
		Name:   "test_update_table",
		Schema: "public",
		Columns: []*ColumnDefinition{
			{
				Name:         "id",
				Type:         "SERIAL",
				Nullable:     false,
				IsPrimaryKey: true,
			},
			{
				Name:     "name",
				Type:     "VARCHAR(50)",
				Nullable: true,
			},
			{
				Name:     "old_column",
				Type:     "TEXT",
				Nullable: true,
			},
		},
	}

	err := metaService.CreateTable(ctx, tableDef)
	require.NoError(t, err)

	t.Run("add columns", func(t *testing.T) {
		changes := &TableChanges{
			AddColumns: []*ColumnDefinition{
				{
					Name:     "email",
					Type:     "VARCHAR(255)",
					Nullable: false,
					IsUnique: true,
					Comment:  "User email address",
				},
				{
					Name:         "created_at",
					Type:         "TIMESTAMP",
					Nullable:     false,
					DefaultValue: "CURRENT_TIMESTAMP",
				},
			},
		}

		err := metaService.UpdateTable(ctx, "public", "test_update_table", changes)
		require.NoError(t, err)

		// Verify columns were added
		table, err := metaService.GetTable(ctx, "public", "test_update_table")
		require.NoError(t, err)
		assert.Len(t, table.Columns, 5) // original 3 + 2 new

		emailCol := findColumn(table.Columns, "email")
		require.NotNil(t, emailCol)
		assert.True(t, emailCol.IsUnique)
		assert.Equal(t, "User email address", emailCol.Comment)
	})

	t.Run("modify columns", func(t *testing.T) {
		changes := &TableChanges{
			ModifyColumns: []*ColumnModification{
				{
					Name:        "name",
					NewType:     stringPtr("VARCHAR(100)"),
					SetNullable: boolPtr(false),
					SetComment:  stringPtr("Updated name field"),
				},
			},
		}

		err := metaService.UpdateTable(ctx, "public", "test_update_table", changes)
		require.NoError(t, err)

		// Verify column was modified
		table, err := metaService.GetTable(ctx, "public", "test_update_table")
		require.NoError(t, err)

		nameCol := findColumn(table.Columns, "name")
		require.NotNil(t, nameCol)
		assert.False(t, nameCol.Nullable)
		assert.Equal(t, "Updated name field", nameCol.Comment)
	})

	t.Run("rename columns", func(t *testing.T) {
		changes := &TableChanges{
			RenameColumns: map[string]string{
				"old_column": "new_column",
			},
		}

		err := metaService.UpdateTable(ctx, "public", "test_update_table", changes)
		require.NoError(t, err)

		// Verify column was renamed
		table, err := metaService.GetTable(ctx, "public", "test_update_table")
		require.NoError(t, err)

		oldCol := findColumn(table.Columns, "old_column")
		assert.Nil(t, oldCol)

		newCol := findColumn(table.Columns, "new_column")
		assert.NotNil(t, newCol)
	})

	t.Run("drop columns", func(t *testing.T) {
		changes := &TableChanges{
			DropColumns: []string{"new_column"},
		}

		err := metaService.UpdateTable(ctx, "public", "test_update_table", changes)
		require.NoError(t, err)

		// Verify column was dropped
		table, err := metaService.GetTable(ctx, "public", "test_update_table")
		require.NoError(t, err)

		droppedCol := findColumn(table.Columns, "new_column")
		assert.Nil(t, droppedCol)
	})

	t.Run("set table comment", func(t *testing.T) {
		changes := &TableChanges{
			SetComment: stringPtr("Updated test table with comment"),
		}

		err := metaService.UpdateTable(ctx, "public", "test_update_table", changes)
		require.NoError(t, err)

		// Verify comment was set
		table, err := metaService.GetTable(ctx, "public", "test_update_table")
		require.NoError(t, err)
		assert.Equal(t, "Updated test table with comment", table.Comment)
	})

	t.Run("table does not exist", func(t *testing.T) {
		changes := &TableChanges{
			SetComment: stringPtr("This should fail"),
		}

		err := metaService.UpdateTable(ctx, "public", "non_existent_table", changes)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "does not exist")
	})

	// Clean up
	err = metaService.DropTable(ctx, "public", "test_update_table", false)
	require.NoError(t, err)
}

func TestMetaService_DropTable(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	metaService := NewMetaService(db)
	ctx := context.Background()

	t.Run("successful drop", func(t *testing.T) {
		// Create table to drop
		tableDef := &TableDefinition{
			Name:   "test_drop_success",
			Schema: "public",
			Columns: []*ColumnDefinition{
				{Name: "id", Type: "SERIAL", IsPrimaryKey: true},
			},
		}

		err := metaService.CreateTable(ctx, tableDef)
		require.NoError(t, err)

		// Drop the table
		err = metaService.DropTable(ctx, "public", "test_drop_success", false)
		require.NoError(t, err)

		// Verify table was dropped
		_, err = metaService.GetTable(ctx, "public", "test_drop_success")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "not found")
	})

	t.Run("table does not exist", func(t *testing.T) {
		err := metaService.DropTable(ctx, "public", "non_existent_table", false)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "does not exist")
	})

	t.Run("system table protection", func(t *testing.T) {
		// Try to drop a system table (this should be prevented)
		err := metaService.DropTable(ctx, "information_schema", "tables", false)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "cannot drop system table")
	})

	t.Run("cascade drop", func(t *testing.T) {
		// Create parent table
		parentDef := &TableDefinition{
			Name:   "test_parent",
			Schema: "public",
			Columns: []*ColumnDefinition{
				{Name: "id", Type: "SERIAL", IsPrimaryKey: true},
				{Name: "name", Type: "VARCHAR(50)"},
			},
		}
		err := metaService.CreateTable(ctx, parentDef)
		require.NoError(t, err)

		// Create child table with foreign key
		childDef := &TableDefinition{
			Name:   "test_child",
			Schema: "public",
			Columns: []*ColumnDefinition{
				{Name: "id", Type: "SERIAL", IsPrimaryKey: true},
				{Name: "parent_id", Type: "INTEGER"},
			},
		}
		err = metaService.CreateTable(ctx, childDef)
		require.NoError(t, err)

		// Add foreign key constraint
		_, err = metaService.ExecuteSQL(ctx,
			"ALTER TABLE public.test_child ADD CONSTRAINT fk_parent FOREIGN KEY (parent_id) REFERENCES public.test_parent(id)",
			nil, nil)
		require.NoError(t, err)

		// Try to drop parent without cascade (should fail)
		err = metaService.DropTable(ctx, "public", "test_parent", false)
		assert.Error(t, err)

		// Drop with cascade should work
		err = metaService.DropTable(ctx, "public", "test_parent", true)
		require.NoError(t, err)

		// Child table should also be dropped due to cascade
		_, err = metaService.GetTable(ctx, "public", "test_child")
		assert.Error(t, err)
	})
}

func TestMetaService_ExecuteSQL(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	metaService := NewMetaService(db)
	ctx := context.Background()

	t.Run("SELECT query", func(t *testing.T) {
		result, err := metaService.ExecuteSQL(ctx, "SELECT 1 as test_col, 'hello' as message", nil, nil)
		require.NoError(t, err)

		assert.Equal(t, "SELECT", result.QueryType)
		assert.Len(t, result.Columns, 2)
		assert.Contains(t, result.Columns, "test_col")
		assert.Contains(t, result.Columns, "message")
		assert.Len(t, result.Rows, 1)
		assert.Equal(t, int32(1), result.Rows[0]["test_col"])
		assert.Equal(t, "hello", result.Rows[0]["message"])
		assert.True(t, result.ExecutionTime > 0)
		assert.Equal(t, int64(1), result.RowsAffected)
	})

	t.Run("INSERT query", func(t *testing.T) {
		// Create temporary table
		_, err := metaService.ExecuteSQL(ctx,
			"CREATE TEMPORARY TABLE test_insert (id SERIAL PRIMARY KEY, name VARCHAR(50))",
			nil, nil)
		require.NoError(t, err)

		// Test INSERT
		result, err := metaService.ExecuteSQL(ctx,
			"INSERT INTO test_insert (name) VALUES ('test1'), ('test2')",
			nil, nil)
		require.NoError(t, err)

		assert.Equal(t, "INSERT", result.QueryType)
		assert.Equal(t, int64(2), result.RowsAffected)
		assert.Len(t, result.Rows, 0) // INSERT doesn't return rows
		assert.True(t, result.ExecutionTime > 0)
	})

	t.Run("UPDATE query", func(t *testing.T) {
		// Create and populate temporary table
		_, err := metaService.ExecuteSQL(ctx,
			"CREATE TEMPORARY TABLE test_update (id SERIAL PRIMARY KEY, name VARCHAR(50))",
			nil, nil)
		require.NoError(t, err)

		_, err = metaService.ExecuteSQL(ctx,
			"INSERT INTO test_update (name) VALUES ('old1'), ('old2'), ('old3')",
			nil, nil)
		require.NoError(t, err)

		// Test UPDATE
		result, err := metaService.ExecuteSQL(ctx,
			"UPDATE test_update SET name = 'updated' WHERE id <= 2",
			nil, nil)
		require.NoError(t, err)

		assert.Equal(t, "UPDATE", result.QueryType)
		assert.Equal(t, int64(2), result.RowsAffected)
		assert.Len(t, result.Rows, 0)
	})

	t.Run("DELETE query", func(t *testing.T) {
		// Create and populate temporary table
		_, err := metaService.ExecuteSQL(ctx,
			"CREATE TEMPORARY TABLE test_delete (id SERIAL PRIMARY KEY, name VARCHAR(50))",
			nil, nil)
		require.NoError(t, err)

		_, err = metaService.ExecuteSQL(ctx,
			"INSERT INTO test_delete (name) VALUES ('delete1'), ('delete2'), ('keep')",
			nil, nil)
		require.NoError(t, err)

		// Test DELETE
		result, err := metaService.ExecuteSQL(ctx,
			"DELETE FROM test_delete WHERE name LIKE 'delete%'",
			nil, nil)
		require.NoError(t, err)

		assert.Equal(t, "DELETE", result.QueryType)
		assert.Equal(t, int64(2), result.RowsAffected)
		assert.Len(t, result.Rows, 0)
	})

	t.Run("query with parameters", func(t *testing.T) {
		result, err := metaService.ExecuteSQL(ctx,
			"SELECT $1 as param1, $2 as param2",
			[]interface{}{"test_value", 42}, nil)
		require.NoError(t, err)

		assert.Equal(t, "SELECT", result.QueryType)
		assert.Len(t, result.Rows, 1)
		assert.Equal(t, "test_value", result.Rows[0]["param1"])
		assert.Equal(t, int32(42), result.Rows[0]["param2"])
	})

	t.Run("query with options", func(t *testing.T) {
		options := &SQLExecutionOptions{
			MaxRows: 2,
			Timeout: 5 * time.Second,
		}

		result, err := metaService.ExecuteSQL(ctx,
			"SELECT generate_series(1, 10) as num",
			nil, options)
		require.NoError(t, err)

		assert.Len(t, result.Rows, 2) // Limited by MaxRows
		assert.Equal(t, int64(2), result.RowsAffected)
	})

	t.Run("read-only mode", func(t *testing.T) {
		options := &SQLExecutionOptions{
			ReadOnly: true,
		}

		// SELECT should work
		_, err := metaService.ExecuteSQL(ctx, "SELECT 1", nil, options)
		assert.NoError(t, err)

		// INSERT should fail
		_, err = metaService.ExecuteSQL(ctx,
			"INSERT INTO test_table VALUES (1)",
			nil, options)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "read operations are allowed")
	})

	t.Run("transaction mode", func(t *testing.T) {
		// Create temporary table
		_, err := metaService.ExecuteSQL(ctx,
			"CREATE TEMPORARY TABLE test_transaction (id SERIAL PRIMARY KEY, name VARCHAR(50))",
			nil, nil)
		require.NoError(t, err)

		options := &SQLExecutionOptions{
			Transaction: true,
		}

		result, err := metaService.ExecuteSQL(ctx,
			"INSERT INTO test_transaction (name) VALUES ('tx_test')",
			nil, options)
		require.NoError(t, err)
		assert.Equal(t, int64(1), result.RowsAffected)
	})

	t.Run("invalid SQL", func(t *testing.T) {
		_, err := metaService.ExecuteSQL(ctx, "INVALID SQL STATEMENT", nil, nil)
		assert.Error(t, err)
	})

	t.Run("timeout", func(t *testing.T) {
		options := &SQLExecutionOptions{
			Timeout: 1 * time.Millisecond, // Very short timeout
		}

		_, err := metaService.ExecuteSQL(ctx,
			"SELECT pg_sleep(1)", // Sleep for 1 second
			nil, options)
		assert.Error(t, err)
		// Should be a timeout error, but exact error depends on driver
	})
}

func TestMetaService_ExecuteSQLBatch(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	metaService := NewMetaService(db)
	ctx := context.Background()

	t.Run("successful batch execution", func(t *testing.T) {
		queries := []string{
			"CREATE TEMPORARY TABLE batch_test (id SERIAL PRIMARY KEY, name VARCHAR(50))",
			"INSERT INTO batch_test (name) VALUES ('test1'), ('test2')",
			"UPDATE batch_test SET name = 'updated' WHERE id = 1",
			"SELECT COUNT(*) as count FROM batch_test",
			"DELETE FROM batch_test WHERE id = 2",
		}

		results, err := metaService.ExecuteSQLBatch(ctx, queries, nil)
		require.NoError(t, err)
		assert.Len(t, results, 5)

		// Verify each result
		assert.Equal(t, "CREATE", results[0].QueryType)
		assert.Equal(t, int64(0), results[0].RowsAffected)

		assert.Equal(t, "INSERT", results[1].QueryType)
		assert.Equal(t, int64(2), results[1].RowsAffected)

		assert.Equal(t, "UPDATE", results[2].QueryType)
		assert.Equal(t, int64(1), results[2].RowsAffected)

		assert.Equal(t, "SELECT", results[3].QueryType)
		assert.Len(t, results[3].Rows, 1)
		assert.Equal(t, int64(2), results[3].Rows[0]["count"])

		assert.Equal(t, "DELETE", results[4].QueryType)
		assert.Equal(t, int64(1), results[4].RowsAffected)

		// All should have execution times
		for i, result := range results {
			assert.True(t, result.ExecutionTime > 0, "Result %d should have execution time", i)
		}
	})

	t.Run("batch with invalid query", func(t *testing.T) {
		queries := []string{
			"SELECT 1",
			"INVALID SQL STATEMENT",
			"SELECT 2",
		}

		_, err := metaService.ExecuteSQLBatch(ctx, queries, nil)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to execute query 2")
	})

	t.Run("batch with validation error", func(t *testing.T) {
		queries := []string{
			"SELECT 1",
			"DROP DATABASE test", // Dangerous operation
		}

		_, err := metaService.ExecuteSQLBatch(ctx, queries, nil)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "SQL validation failed")
	})

	t.Run("batch with options", func(t *testing.T) {
		options := &SQLExecutionOptions{
			MaxRows: 1,
			Timeout: 10 * time.Second,
		}

		queries := []string{
			"SELECT generate_series(1, 5) as num",
		}

		results, err := metaService.ExecuteSQLBatch(ctx, queries, options)
		require.NoError(t, err)
		assert.Len(t, results, 1)
		assert.Len(t, results[0].Rows, 1) // Limited by MaxRows
	})
}

func TestMetaService_ValidateSQL(t *testing.T) {
	metaService := &MetaService{}

	tests := []struct {
		name     string
		query    string
		readOnly bool
		wantErr  bool
		errMsg   string
	}{
		{
			name:     "valid select",
			query:    "SELECT * FROM users",
			readOnly: true,
			wantErr:  false,
		},
		{
			name:     "valid select with joins",
			query:    "SELECT u.name, p.title FROM users u JOIN posts p ON u.id = p.user_id",
			readOnly: true,
			wantErr:  false,
		},
		{
			name:     "valid with clause",
			query:    "WITH user_stats AS (SELECT COUNT(*) FROM users) SELECT * FROM user_stats",
			readOnly: true,
			wantErr:  false,
		},
		{
			name:     "valid explain",
			query:    "EXPLAIN SELECT * FROM users",
			readOnly: true,
			wantErr:  false,
		},
		{
			name:     "valid show",
			query:    "SHOW TABLES",
			readOnly: true,
			wantErr:  false,
		},
		{
			name:     "insert in read-only mode",
			query:    "INSERT INTO users (name) VALUES ('test')",
			readOnly: true,
			wantErr:  true,
			errMsg:   "read operations are allowed",
		},
		{
			name:     "update in read-only mode",
			query:    "UPDATE users SET name = 'test'",
			readOnly: true,
			wantErr:  true,
			errMsg:   "read operations are allowed",
		},
		{
			name:     "delete in read-only mode",
			query:    "DELETE FROM users",
			readOnly: true,
			wantErr:  true,
			errMsg:   "read operations are allowed",
		},
		{
			name:     "dangerous drop database",
			query:    "DROP DATABASE test",
			readOnly: false,
			wantErr:  true,
			errMsg:   "dangerous operation",
		},
		{
			name:     "dangerous drop schema",
			query:    "DROP SCHEMA public CASCADE",
			readOnly: false,
			wantErr:  true,
			errMsg:   "dangerous operation",
		},
		{
			name:     "dangerous truncate",
			query:    "TRUNCATE TABLE users",
			readOnly: false,
			wantErr:  true,
			errMsg:   "dangerous operation",
		},
		{
			name:     "dangerous delete from system table",
			query:    "DELETE FROM information_schema.tables",
			readOnly: false,
			wantErr:  true,
			errMsg:   "dangerous operation",
		},
		{
			name:     "dangerous update system table",
			query:    "UPDATE pg_class SET relname = 'hacked'",
			readOnly: false,
			wantErr:  true,
			errMsg:   "dangerous operation",
		},
		{
			name:     "empty query",
			query:    "",
			readOnly: false,
			wantErr:  true,
			errMsg:   "cannot be empty",
		},
		{
			name:     "whitespace only query",
			query:    "   \n\t  ",
			readOnly: false,
			wantErr:  true,
			errMsg:   "cannot be empty",
		},
		{
			name:     "unbalanced parentheses - missing closing",
			query:    "SELECT * FROM users WHERE (id = 1",
			readOnly: false,
			wantErr:  true,
			errMsg:   "unmatched parentheses",
		},
		{
			name:     "unbalanced parentheses - extra closing",
			query:    "SELECT * FROM users WHERE id = 1)",
			readOnly: false,
			wantErr:  true,
			errMsg:   "unmatched closing parenthesis",
		},
		{
			name:     "balanced parentheses",
			query:    "SELECT * FROM users WHERE (id = 1 AND (name = 'test' OR email = 'test@example.com'))",
			readOnly: false,
			wantErr:  false,
		},
		{
			name:     "parentheses in strings should be ignored",
			query:    "SELECT * FROM users WHERE name = 'test (with parens)'",
			readOnly: false,
			wantErr:  false,
		},
		{
			name:     "valid insert",
			query:    "INSERT INTO users (name, email) VALUES ('John', 'john@example.com')",
			readOnly: false,
			wantErr:  false,
		},
		{
			name:     "valid update",
			query:    "UPDATE users SET name = 'Updated' WHERE id = 1",
			readOnly: false,
			wantErr:  false,
		},
		{
			name:     "valid delete",
			query:    "DELETE FROM users WHERE id = 1",
			readOnly: false,
			wantErr:  false,
		},
		{
			name:     "valid create table",
			query:    "CREATE TABLE test (id SERIAL PRIMARY KEY, name VARCHAR(50))",
			readOnly: false,
			wantErr:  false,
		},
		{
			name:     "valid alter table",
			query:    "ALTER TABLE users ADD COLUMN age INTEGER",
			readOnly: false,
			wantErr:  false,
		},
		{
			name:     "valid drop table",
			query:    "DROP TABLE test_table",
			readOnly: false,
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := metaService.validateSQL(tt.query, tt.readOnly)
			if tt.wantErr {
				assert.Error(t, err)
				if tt.errMsg != "" && err != nil {
					assert.Contains(t, err.Error(), tt.errMsg)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestMetaService_GetQueryType(t *testing.T) {
	metaService := &MetaService{}

	tests := []struct {
		query    string
		expected string
	}{
		{"SELECT * FROM users", "SELECT"},
		{"  select * from users  ", "SELECT"}, // Case insensitive and trimmed
		{"INSERT INTO users VALUES (1, 'test')", "INSERT"},
		{"UPDATE users SET name = 'test'", "UPDATE"},
		{"DELETE FROM users WHERE id = 1", "DELETE"},
		{"CREATE TABLE test (id INT)", "CREATE"},
		{"ALTER TABLE users ADD COLUMN age INT", "ALTER"},
		{"DROP TABLE test", "DROP"},
		{"TRUNCATE TABLE users", "TRUNCATE"},
		{"GRANT SELECT ON users TO role", "GRANT"},
		{"REVOKE SELECT ON users FROM role", "REVOKE"},
		{"WITH cte AS (SELECT 1) SELECT * FROM cte", "WITH"},
		{"EXPLAIN SELECT * FROM users", "EXPLAIN"},
		{"SHOW TABLES", "SHOW"},
		{"DESCRIBE users", "DESCRIBE"},
		{"SOME_UNKNOWN_COMMAND", "UNKNOWN"},
		{"", "UNKNOWN"},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("query_%s", tt.expected), func(t *testing.T) {
			result := metaService.getQueryType(tt.query)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestMetaService_ValidateParentheses(t *testing.T) {
	metaService := &MetaService{}

	tests := []struct {
		name    string
		query   string
		wantErr bool
	}{
		{
			name:    "balanced parentheses",
			query:   "SELECT * FROM users WHERE (id = 1 AND (name = 'test'))",
			wantErr: false,
		},
		{
			name:    "no parentheses",
			query:   "SELECT * FROM users",
			wantErr: false,
		},
		{
			name:    "unmatched opening",
			query:   "SELECT * FROM users WHERE (id = 1",
			wantErr: true,
		},
		{
			name:    "unmatched closing",
			query:   "SELECT * FROM users WHERE id = 1)",
			wantErr: true,
		},
		{
			name:    "multiple unmatched opening",
			query:   "SELECT * FROM users WHERE ((id = 1",
			wantErr: true,
		},
		{
			name:    "parentheses in single quotes",
			query:   "SELECT * FROM users WHERE name = 'test (with parens)'",
			wantErr: false,
		},
		{
			name:    "parentheses in double quotes",
			query:   `SELECT * FROM users WHERE name = "test (with parens)"`,
			wantErr: false,
		},
		{
			name:    "mixed quotes and parentheses",
			query:   `SELECT * FROM users WHERE (name = 'test' AND description = "has (parens)")`,
			wantErr: false,
		},
		{
			name:    "escaped quotes",
			query:   `SELECT * FROM users WHERE name = 'test\'s (value)'`,
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := metaService.validateParentheses(tt.query)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestMetaService_TableIntrospection(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	metaService := NewMetaService(db)
	ctx := context.Background()

	// Create a complex table with various constraints and indexes
	queries := []string{
		`CREATE TABLE test_introspection (
			id SERIAL PRIMARY KEY,
			email VARCHAR(255) UNIQUE NOT NULL,
			name VARCHAR(100) NOT NULL DEFAULT 'Unknown',
			age INTEGER CHECK (age >= 0),
			created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMP
		)`,
		`COMMENT ON TABLE test_introspection IS 'Test table for introspection'`,
		`COMMENT ON COLUMN test_introspection.email IS 'User email address'`,
		`COMMENT ON COLUMN test_introspection.name IS 'User full name'`,
		`CREATE INDEX idx_test_introspection_name ON test_introspection(name)`,
		`CREATE INDEX idx_test_introspection_created_at ON test_introspection(created_at DESC)`,
	}

	for _, query := range queries {
		_, err := metaService.ExecuteSQL(ctx, query, nil, nil)
		require.NoError(t, err)
	}

	// Test table introspection
	table, err := metaService.GetTable(ctx, "public", "test_introspection")
	require.NoError(t, err)

	// Verify table metadata
	assert.Equal(t, "test_introspection", table.Name)
	assert.Equal(t, "public", table.Schema)
	assert.Equal(t, "Test table for introspection", table.Comment)

	// Verify columns
	assert.Len(t, table.Columns, 6)

	// Check ID column
	idCol := findColumn(table.Columns, "id")
	require.NotNil(t, idCol)
	assert.True(t, idCol.IsPrimaryKey)
	assert.False(t, idCol.Nullable)
	assert.Equal(t, 1, idCol.OrdinalPosition)

	// Check email column
	emailCol := findColumn(table.Columns, "email")
	require.NotNil(t, emailCol)
	assert.True(t, emailCol.IsUnique)
	assert.False(t, emailCol.Nullable)
	assert.Equal(t, "User email address", emailCol.Comment)
	assert.NotNil(t, emailCol.MaxLength)
	assert.Equal(t, 255, *emailCol.MaxLength)

	// Check name column
	nameCol := findColumn(table.Columns, "name")
	require.NotNil(t, nameCol)
	assert.False(t, nameCol.Nullable)
	assert.Contains(t, nameCol.DefaultValue, "Unknown")
	assert.Equal(t, "User full name", nameCol.Comment)

	// Check age column
	ageCol := findColumn(table.Columns, "age")
	require.NotNil(t, ageCol)
	assert.True(t, ageCol.Nullable)

	// Verify indexes
	assert.True(t, len(table.Indexes) >= 3) // Primary key + unique + custom indexes

	// Find specific indexes
	var primaryIndex, uniqueIndex, nameIndex *Index
	for _, idx := range table.Indexes {
		if idx.IsPrimary {
			primaryIndex = idx
		} else if strings.Contains(idx.Name, "email") {
			uniqueIndex = idx
		} else if strings.Contains(idx.Name, "name") {
			nameIndex = idx
		}
	}

	assert.NotNil(t, primaryIndex)
	assert.True(t, primaryIndex.IsPrimary)
	assert.Contains(t, primaryIndex.Columns, "id")

	if uniqueIndex != nil {
		assert.True(t, uniqueIndex.IsUnique)
		assert.Contains(t, uniqueIndex.Columns, "email")
	}

	if nameIndex != nil {
		assert.False(t, nameIndex.IsUnique)
		assert.Contains(t, nameIndex.Columns, "name")
	}

	// Verify constraints
	assert.True(t, len(table.Constraints) > 0)

	// Find primary key constraint
	var pkConstraint *Constraint
	for _, constraint := range table.Constraints {
		if constraint.Type == "PRIMARY KEY" {
			pkConstraint = constraint
			break
		}
	}

	assert.NotNil(t, pkConstraint)
	assert.Equal(t, "PRIMARY KEY", pkConstraint.Type)
	assert.Contains(t, pkConstraint.Columns, "id")

	// Clean up
	err = metaService.DropTable(ctx, "public", "test_introspection", false)
	require.NoError(t, err)
}

// Helper functions

func findColumn(columns []*Column, name string) *Column {
	for _, col := range columns {
		if col.Name == name {
			return col
		}
	}
	return nil
}

func stringPtr(s string) *string {
	return &s
}

func boolPtr(b bool) *bool {
	return &b
}

func setupTestDB(t *testing.T) *DB {
	config := &Config{
		Host:     "localhost",
		Port:     5432,
		Name:     "test_db",
		User:     "test_user",
		Password: "test_password",
		SSLMode:  "disable",
		MaxConns: 10,
		MinConns: 1,
	}

	db, err := New(config)
	if err != nil {
		t.Skipf("Skipping test: could not connect to test database: %v", err)
	}

	return db
}

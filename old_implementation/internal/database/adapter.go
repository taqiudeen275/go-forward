package database

import (
	"context"
	"fmt"

	"github.com/taqiudeen275/go-foward/pkg/interfaces"
)

// MetaServiceAdapter adapts the concrete MetaService to the interfaces.MetaService interface
type MetaServiceAdapter struct {
	metaService *MetaService
}

// NewMetaServiceAdapter creates a new adapter for the MetaService
func NewMetaServiceAdapter(metaService *MetaService) interfaces.MetaService {
	return &MetaServiceAdapter{
		metaService: metaService,
	}
}

// GetTables adapts the GetTables method
func (a *MetaServiceAdapter) GetTables(ctx context.Context, schema string) ([]*interfaces.Table, error) {
	tables, err := a.metaService.GetTables(ctx, schema)
	if err != nil {
		return nil, err
	}

	// Convert from concrete types to interface types
	var result []*interfaces.Table
	for _, table := range tables {
		interfaceTable := &interfaces.Table{
			Name:        table.Name,
			Schema:      table.Schema,
			Columns:     convertColumns(table.Columns),
			Indexes:     convertIndexes(table.Indexes),
			Constraints: convertConstraints(table.Constraints),
			RLSEnabled:  table.RLSEnabled,
		}
		result = append(result, interfaceTable)
	}

	return result, nil
}

// GetTable adapts the GetTable method
func (a *MetaServiceAdapter) GetTable(ctx context.Context, schema string, tableName string) (*interfaces.Table, error) {
	table, err := a.metaService.GetTable(ctx, schema, tableName)
	if err != nil {
		return nil, err
	}

	return &interfaces.Table{
		Name:        table.Name,
		Schema:      table.Schema,
		Columns:     convertColumns(table.Columns),
		Indexes:     convertIndexes(table.Indexes),
		Constraints: convertConstraints(table.Constraints),
		RLSEnabled:  table.RLSEnabled,
	}, nil
}

// CreateTable adapts the CreateTable method
func (a *MetaServiceAdapter) CreateTable(ctx context.Context, tableDef interfaces.TableDefinition) error {
	// Convert from interface type to concrete type
	concreteDef := &TableDefinition{
		Name:    tableDef.Name,
		Schema:  tableDef.Schema,
		Columns: convertColumnDefinitions(tableDef.Columns),
	}

	return a.metaService.CreateTable(ctx, concreteDef)
}

// UpdateTable adapts the UpdateTable method
func (a *MetaServiceAdapter) UpdateTable(ctx context.Context, tableName string, changes interfaces.TableChanges) error {
	// Convert from interface type to concrete type
	concreteChanges := &TableChanges{
		AddColumns:    convertColumnDefinitions(changes.AddColumns),
		DropColumns:   changes.DropColumns,
		ModifyColumns: convertColumnModifications(changes.ModifyColumns),
	}

	// Use default schema since the interface doesn't specify it
	return a.metaService.UpdateTable(ctx, "public", tableName, concreteChanges)
}

// DeleteTable adapts the DeleteTable method
func (a *MetaServiceAdapter) DeleteTable(ctx context.Context, tableName string) error {
	// Use default schema and no cascade since the interface doesn't specify these options
	return a.metaService.DropTable(ctx, "public", tableName, false)
}

// ExecuteSQL adapts the ExecuteSQL method
func (a *MetaServiceAdapter) ExecuteSQL(ctx context.Context, query string, args ...interface{}) (*interfaces.QueryResult, error) {
	result, err := a.metaService.ExecuteSQL(ctx, query, args, nil)
	if err != nil {
		return nil, err
	}

	return &interfaces.QueryResult{
		Columns: result.Columns,
		Rows:    result.Rows,
		Count:   int64(len(result.Rows)),
	}, nil
}

// GetSchemas adapts the GetSchemas method
func (a *MetaServiceAdapter) GetSchemas(ctx context.Context) ([]string, error) {
	return a.metaService.GetSchemas(ctx)
}

// CreateSchema creates a new database schema
func (a *MetaServiceAdapter) CreateSchema(ctx context.Context, schemaName string) error {
	query := fmt.Sprintf("CREATE SCHEMA IF NOT EXISTS %s", schemaName)
	_, err := a.metaService.ExecuteSQL(ctx, query, nil, nil)
	return err
}

// DeleteSchema deletes a database schema
func (a *MetaServiceAdapter) DeleteSchema(ctx context.Context, schemaName string) error {
	// Safety check: prevent dropping system schemas
	systemSchemas := map[string]bool{
		"information_schema": true,
		"pg_catalog":         true,
		"pg_toast":           true,
		"public":             true, // Prevent dropping public schema by default
	}

	if systemSchemas[schemaName] {
		return fmt.Errorf("cannot drop system schema: %s", schemaName)
	}

	query := fmt.Sprintf("DROP SCHEMA %s CASCADE", schemaName)
	_, err := a.metaService.ExecuteSQL(ctx, query, nil, nil)
	return err
}

// Helper functions to convert between concrete and interface types

func convertColumns(columns []*Column) []*interfaces.Column {
	var result []*interfaces.Column
	for _, col := range columns {
		interfaceCol := &interfaces.Column{
			Name:         col.Name,
			Type:         col.Type,
			Nullable:     col.Nullable,
			DefaultValue: col.DefaultValue,
			IsPrimaryKey: col.IsPrimaryKey,
			IsForeignKey: col.IsForeignKey,
			IsUnique:     col.IsUnique,
		}

		if col.MaxLength != nil {
			interfaceCol.MaxLength = *col.MaxLength
		}
		if col.NumericPrecision != nil {
			interfaceCol.Precision = *col.NumericPrecision
		}
		if col.NumericScale != nil {
			interfaceCol.Scale = *col.NumericScale
		}

		result = append(result, interfaceCol)
	}
	return result
}

func convertIndexes(indexes []*Index) []*interfaces.Index {
	var result []*interfaces.Index
	for _, idx := range indexes {
		interfaceIdx := &interfaces.Index{
			Name:      idx.Name,
			Columns:   idx.Columns,
			IsUnique:  idx.IsUnique,
			IsPrimary: idx.IsPrimary,
			Type:      idx.IndexType,
		}
		result = append(result, interfaceIdx)
	}
	return result
}

func convertConstraints(constraints []*Constraint) []*interfaces.Constraint {
	var result []*interfaces.Constraint
	for _, cons := range constraints {
		interfaceCons := &interfaces.Constraint{
			Name:              cons.Name,
			Type:              cons.Type,
			Columns:           cons.Columns,
			ReferencedTable:   cons.ReferencedTable,
			ReferencedColumns: cons.ReferencedColumns,
			Definition:        cons.Definition,
		}
		result = append(result, interfaceCons)
	}
	return result
}

func convertColumnDefinitions(columns []*interfaces.ColumnDefinition) []*ColumnDefinition {
	var result []*ColumnDefinition
	for _, col := range columns {
		concreteDef := &ColumnDefinition{
			Name:         col.Name,
			Type:         col.Type,
			Nullable:     col.Nullable,
			DefaultValue: fmt.Sprintf("%v", col.DefaultValue),
			IsPrimaryKey: col.IsPrimaryKey,
			IsUnique:     col.IsUnique,
		}
		result = append(result, concreteDef)
	}
	return result
}

func convertColumnModifications(modifications []*interfaces.ColumnModification) []*ColumnModification {
	var result []*ColumnModification
	for _, mod := range modifications {
		concreteMod := &ColumnModification{
			Name: mod.Name,
		}

		if mod.NewName != "" {
			// Handle column renaming - this would need to be implemented in the concrete service
		}
		if mod.NewType != "" {
			concreteMod.NewType = &mod.NewType
		}
		if mod.NewNullable != nil {
			concreteMod.SetNullable = mod.NewNullable
		}
		if mod.NewDefault != nil {
			defaultStr := fmt.Sprintf("%v", mod.NewDefault)
			concreteMod.SetDefault = &defaultStr
		}

		result = append(result, concreteMod)
	}
	return result
}

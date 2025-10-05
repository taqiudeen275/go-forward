package database

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

// Handlers provides HTTP handlers for database meta operations
type Handlers struct {
	metaService *MetaService
}

// NewHandlers creates new database meta handlers
func NewHandlers(metaService *MetaService) *Handlers {
	return &Handlers{
		metaService: metaService,
	}
}

// GetSchemas handles listing all database schemas
func (h *Handlers) GetSchemas(c *gin.Context) {
	schemas, err := h.metaService.GetSchemas(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"schemas": schemas,
		"count":   len(schemas),
	})
}

// GetTables handles listing tables in specified schemas
func (h *Handlers) GetTables(c *gin.Context) {
	// Get schemas from query parameter (comma-separated)
	schemasParam := c.DefaultQuery("schemas", "public")
	schemas := strings.Split(schemasParam, ",")

	// Trim whitespace from schema names
	for i, schema := range schemas {
		schemas[i] = strings.TrimSpace(schema)
	}

	tables, err := h.metaService.GetTables(c.Request.Context(), schemas...)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"tables": tables,
		"count":  len(tables),
	})
}

// GetTable handles getting a specific table with all metadata
func (h *Handlers) GetTable(c *gin.Context) {
	schema := c.Param("schema")
	if schema == "" {
		schema = "public"
	}
	tableName := c.Param("table")

	if tableName == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "table name is required"})
		return
	}

	table, err := h.metaService.GetTable(c.Request.Context(), schema, tableName)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"table": table})
}

// CreateTable handles table creation
func (h *Handlers) CreateTable(c *gin.Context) {
	var tableDef TableDefinition
	if err := c.ShouldBindJSON(&tableDef); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid table definition"})
		return
	}

	// Set default schema if not provided
	if tableDef.Schema == "" {
		tableDef.Schema = "public"
	}

	err := h.metaService.CreateTable(c.Request.Context(), &tableDef)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusCreated, gin.H{
		"message": "Table created successfully",
		"table":   tableDef.Name,
		"schema":  tableDef.Schema,
	})
}

// UpdateTable handles table modifications
func (h *Handlers) UpdateTable(c *gin.Context) {
	schema := c.Param("schema")
	if schema == "" {
		schema = "public"
	}
	tableName := c.Param("table")

	if tableName == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "table name is required"})
		return
	}

	var changes TableChanges
	if err := c.ShouldBindJSON(&changes); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid table changes"})
		return
	}

	err := h.metaService.UpdateTable(c.Request.Context(), schema, tableName, &changes)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Table updated successfully",
		"table":   tableName,
		"schema":  schema,
	})
}

// DropTable handles table deletion
func (h *Handlers) DropTable(c *gin.Context) {
	schema := c.Param("schema")
	if schema == "" {
		schema = "public"
	}
	tableName := c.Param("table")

	if tableName == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "table name is required"})
		return
	}

	// Check for cascade parameter
	cascade := c.DefaultQuery("cascade", "false") == "true"

	err := h.metaService.DropTable(c.Request.Context(), schema, tableName, cascade)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Table dropped successfully",
		"table":   tableName,
		"schema":  schema,
	})
}

// ExecuteSQL handles SQL query execution
func (h *Handlers) ExecuteSQL(c *gin.Context) {
	var req struct {
		Query   string               `json:"query" binding:"required"`
		Args    []interface{}        `json:"args,omitempty"`
		Options *SQLExecutionOptions `json:"options,omitempty"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid SQL request"})
		return
	}

	// Set default options if not provided
	if req.Options == nil {
		req.Options = &SQLExecutionOptions{
			MaxRows:  1000,
			ReadOnly: false,
		}
	}

	result, err := h.metaService.ExecuteSQL(c.Request.Context(), req.Query, req.Args, req.Options)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, result)
}

// ExecuteSQLBatch handles batch SQL execution
func (h *Handlers) ExecuteSQLBatch(c *gin.Context) {
	var req struct {
		Queries []string             `json:"queries" binding:"required"`
		Options *SQLExecutionOptions `json:"options,omitempty"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid batch SQL request"})
		return
	}

	// Set default options if not provided
	if req.Options == nil {
		req.Options = &SQLExecutionOptions{
			MaxRows:     1000,
			ReadOnly:    false,
			Transaction: true, // Default to transaction for batch operations
		}
	}

	results, err := h.metaService.ExecuteSQLBatch(c.Request.Context(), req.Queries, req.Options)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"results": results,
		"count":   len(results),
	})
}

// GetTableStats handles getting table statistics
func (h *Handlers) GetTableStats(c *gin.Context) {
	schema := c.Param("schema")
	if schema == "" {
		schema = "public"
	}
	tableName := c.Param("table")

	if tableName == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "table name is required"})
		return
	}

	// Get basic table info
	table, err := h.metaService.GetTable(c.Request.Context(), schema, tableName)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}

	// Get row count
	countQuery := "SELECT COUNT(*) FROM " + schema + "." + tableName
	countResult, err := h.metaService.ExecuteSQL(c.Request.Context(), countQuery, nil, &SQLExecutionOptions{
		ReadOnly: true,
		MaxRows:  1,
	})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get row count"})
		return
	}

	var rowCount int64
	if len(countResult.Rows) > 0 {
		if count, ok := countResult.Rows[0]["count"].(int64); ok {
			rowCount = count
		}
	}

	// Get table size
	sizeQuery := `
		SELECT 
			pg_size_pretty(pg_total_relation_size($1)) as total_size,
			pg_size_pretty(pg_relation_size($1)) as table_size,
			pg_size_pretty(pg_total_relation_size($1) - pg_relation_size($1)) as index_size
	`
	sizeResult, err := h.metaService.ExecuteSQL(c.Request.Context(), sizeQuery, []interface{}{schema + "." + tableName}, &SQLExecutionOptions{
		ReadOnly: true,
		MaxRows:  1,
	})

	var tableSize, indexSize, totalSize string
	if err == nil && len(sizeResult.Rows) > 0 {
		row := sizeResult.Rows[0]
		if ts, ok := row["table_size"].(string); ok {
			tableSize = ts
		}
		if is, ok := row["index_size"].(string); ok {
			indexSize = is
		}
		if tots, ok := row["total_size"].(string); ok {
			totalSize = tots
		}
	}

	stats := gin.H{
		"table":            table,
		"row_count":        rowCount,
		"table_size":       tableSize,
		"index_size":       indexSize,
		"total_size":       totalSize,
		"column_count":     len(table.Columns),
		"index_count":      len(table.Indexes),
		"constraint_count": len(table.Constraints),
	}

	c.JSON(http.StatusOK, stats)
}

// ValidateSQL handles SQL validation without execution
func (h *Handlers) ValidateSQL(c *gin.Context) {
	var req struct {
		Query    string `json:"query" binding:"required"`
		ReadOnly bool   `json:"read_only,omitempty"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid validation request"})
		return
	}

	// Use EXPLAIN to validate the query without executing it
	explainQuery := "EXPLAIN " + req.Query
	_, err := h.metaService.ExecuteSQL(c.Request.Context(), explainQuery, nil, &SQLExecutionOptions{
		ReadOnly: true,
		MaxRows:  100,
	})

	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"valid": false,
			"error": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"valid":   true,
		"message": "SQL query is valid",
	})
}

// RegisterRoutes registers database meta routes with the gateway
func (h *Handlers) RegisterRoutes(router gin.IRouter) {
	// Create database group
	dbGroup := router.Group("/database")
	h.registerDatabaseRoutes(dbGroup)
}

// Name returns the service name
func (h *Handlers) Name() string {
	return "database"
}

// registerDatabaseRoutes registers all database routes
func (h *Handlers) registerDatabaseRoutes(router *gin.RouterGroup) {
	// Schema operations
	router.GET("/schemas", h.GetSchemas)

	// Table operations
	router.GET("/tables", h.GetTables)
	router.POST("/tables", h.CreateTable)
	router.GET("/tables/:schema/:table", h.GetTable)
	router.PUT("/tables/:schema/:table", h.UpdateTable)
	router.DELETE("/tables/:schema/:table", h.DropTable)

	// Table statistics
	router.GET("/tables/:schema/:table/stats", h.GetTableStats)

	// SQL execution
	router.POST("/sql/execute", h.ExecuteSQL)
	router.POST("/sql/batch", h.ExecuteSQLBatch)
	router.POST("/sql/validate", h.ValidateSQL)
}

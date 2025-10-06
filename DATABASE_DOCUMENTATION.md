# GoForward Database System Documentation

## Overview

The GoForward database system provides comprehensive PostgreSQL database management with connection pooling, migrations, schema introspection, query building, and SQL execution capabilities. It offers both programmatic APIs and HTTP endpoints for database operations.

## Key Features

- **Connection Management**: PostgreSQL connection pooling with pgx driver
- **Migration System**: Up/down migration support with version tracking
- **Schema Introspection**: Complete database metadata and table information
- **Query Builder**: Fluent interface for building complex SQL queries
- **SQL Execution**: Safe SQL execution with validation and result formatting
- **Table Management**: Create, modify, and drop tables with full metadata
- **Statistics & Analytics**: Table statistics, row counts, and size information
- **Security**: SQL validation, read-only modes, and transaction support

## Database Endpoints

### 1. Schema Operations

#### List All Schemas
```http
GET /database/schemas
```

**Response:**
```json
{
  "schemas": ["public", "auth", "analytics"],
  "count": 3
}
```

#### List Tables in Schemas
```http
GET /database/tables?schemas=public,auth
```

**Query Parameters:**
- `schemas` (optional): Comma-separated list of schemas (default: "public")

**Response:**
```json
{
  "tables": [
    {
      "name": "users",
      "schema": "public",
      "columns": [...],
      "indexes": [...],
      "constraints": [...],
      "rls_enabled": false,
      "comment": "User accounts table"
    }
  ],
  "count": 1
}
```

### 2. Table Operations

#### Get Specific Table
```http
GET /database/tables/:schema/:table
```

**Example:**
```http
GET /database/tables/public/users
```

**Response:**
```json
{
  "table": {
    "name": "users",
    "schema": "public",
    "columns": [
      {
        "name": "id",
        "type": "uuid",
        "nullable": false,
        "default_value": "gen_random_uuid()",
        "is_primary_key": true,
        "is_foreign_key": false,
        "is_unique": false,
        "ordinal_position": 1,
        "comment": "Primary key"
      },
      {
        "name": "email",
        "type": "character varying",
        "nullable": true,
        "max_length": 255,
        "is_primary_key": false,
        "is_foreign_key": false,
        "is_unique": true,
        "ordinal_position": 2
      }
    ],
    "indexes": [
      {
        "name": "users_pkey",
        "table_name": "users",
        "columns": ["id"],
        "is_unique": true,
        "is_primary": true,
        "index_type": "btree"
      }
    ],
    "constraints": [
      {
        "name": "users_pkey",
        "type": "PRIMARY KEY",
        "table_name": "users",
        "columns": ["id"]
      }
    ],
    "rls_enabled": false,
    "comment": "User accounts table"
  }
}
```

#### Create Table
```http
POST /database/tables
Content-Type: application/json

{
  "name": "products",
  "schema": "public",
  "comment": "Product catalog table",
  "columns": [
    {
      "name": "id",
      "type": "uuid",
      "nullable": false,
      "default_value": "gen_random_uuid()",
      "is_primary_key": true,
      "comment": "Product ID"
    },
    {
      "name": "name",
      "type": "varchar(255)",
      "nullable": false,
      "comment": "Product name"
    },
    {
      "name": "price",
      "type": "decimal(10,2)",
      "nullable": false,
      "comment": "Product price"
    },
    {
      "name": "created_at",
      "type": "timestamp",
      "nullable": false,
      "default_value": "NOW()"
    }
  ]
}
```

**Response:**
```json
{
  "message": "Table created successfully",
  "table": "products",
  "schema": "public"
}
```

#### Update Table
```http
PUT /database/tables/:schema/:table
Content-Type: application/json

{
  "add_columns": [
    {
      "name": "description",
      "type": "text",
      "nullable": true,
      "comment": "Product description"
    }
  ],
  "drop_columns": ["old_column"],
  "modify_columns": [
    {
      "name": "price",
      "new_type": "decimal(12,2)",
      "set_comment": "Updated price with higher precision"
    }
  ],
  "rename_columns": {
    "old_name": "new_name"
  },
  "set_comment": "Updated product catalog table"
}
```

**Response:**
```json
{
  "message": "Table updated successfully",
  "table": "products",
  "schema": "public"
}
```

#### Drop Table
```http
DELETE /database/tables/:schema/:table?cascade=false
```

**Query Parameters:**
- `cascade` (optional): Set to "true" to cascade delete (default: "false")

**Response:**
```json
{
  "message": "Table dropped successfully",
  "table": "products",
  "schema": "public"
}
```

### 3. Table Statistics

#### Get Table Statistics
```http
GET /database/tables/:schema/:table/stats
```

**Response:**
```json
{
  "table": {
    "name": "users",
    "schema": "public",
    "columns": [...],
    "indexes": [...],
    "constraints": [...]
  },
  "row_count": 1250,
  "table_size": "128 kB",
  "index_size": "64 kB", 
  "total_size": "192 kB",
  "column_count": 8,
  "index_count": 3,
  "constraint_count": 2
}
```

### 4. SQL Execution

#### Execute SQL Query
```http
POST /database/sql/execute
Content-Type: application/json

{
  "query": "SELECT id, email, created_at FROM users WHERE created_at > $1 ORDER BY created_at DESC LIMIT $2",
  "args": ["2024-01-01T00:00:00Z", 10],
  "options": {
    "max_rows": 100,
    "timeout": "30s",
    "read_only": false,
    "transaction": false
  }
}
```

**Response:**
```json
{
  "columns": ["id", "email", "created_at"],
  "rows": [
    {
      "id": "123e4567-e89b-12d3-a456-426614174000",
      "email": "user@example.com",
      "created_at": "2024-01-15T10:30:00Z"
    }
  ],
  "rows_affected": 0,
  "execution_time": "15ms",
  "query_type": "SELECT"
}
```

#### Execute SQL Batch
```http
POST /database/sql/batch
Content-Type: application/json

{
  "queries": [
    "CREATE TEMP TABLE temp_data (id int, name text);",
    "INSERT INTO temp_data VALUES (1, 'test');",
    "SELECT * FROM temp_data;"
  ],
  "options": {
    "max_rows": 1000,
    "read_only": false,
    "transaction": true
  }
}
```

**Response:**
```json
{
  "results": [
    {
      "columns": [],
      "rows": [{"message": "Query executed successfully"}],
      "rows_affected": 0,
      "execution_time": "5ms",
      "query_type": "CREATE"
    },
    {
      "columns": [],
      "rows": [{"message": "Query executed successfully"}],
      "rows_affected": 1,
      "execution_time": "3ms", 
      "query_type": "INSERT"
    },
    {
      "columns": ["id", "name"],
      "rows": [{"id": 1, "name": "test"}],
      "rows_affected": 0,
      "execution_time": "2ms",
      "query_type": "SELECT"
    }
  ],
  "count": 3
}
```

#### Validate SQL Query
```http
POST /database/sql/validate
Content-Type: application/json

{
  "query": "SELECT * FROM users WHERE email = $1",
  "read_only": true
}
```

**Response (Valid):**
```json
{
  "valid": true,
  "message": "SQL query is valid"
}
```

**Response (Invalid):**
```json
{
  "valid": false,
  "error": "relation \"nonexistent_table\" does not exist"
}
```

## Query Builder API

### Programmatic Usage

```go
package main

import (
    "context"
    "github.com/yourorg/goforward/internal/database"
)

func main() {
    // Initialize database service
    config := &database.Config{
        Host:     "localhost",
        Port:     5432,
        Name:     "goforward",
        User:     "postgres",
        Password: "password",
    }
    
    service, err := database.NewService(config)
    if err != nil {
        panic(err)
    }
    defer service.Close()
    
    // Build and execute query
    qb := database.NewQueryBuilder(service.DB)
    
    results, err := qb.Table("users").
        Select("id", "email", "username").
        Where("email_verified = ?", true).
        Where("created_at > ?", "2024-01-01").
        OrderBy("created_at", "DESC").
        Limit(10).
        Execute(context.Background())
    
    if err != nil {
        panic(err)
    }
    
    // Process results
    for _, row := range results {
        fmt.Printf("User: %v\n", row)
    }
}
```

### Query Builder Methods

#### Basic Operations
```go
// Table selection
qb.Table("users")

// Column selection
qb.Select("id", "email", "username")
qb.Select("*") // All columns

// WHERE conditions
qb.Where("email = ?", "user@example.com")
qb.Where("age > ?", 18)
qb.Where("status IN (?, ?)", "active", "pending")

// ORDER BY
qb.OrderBy("created_at", "DESC")
qb.OrderBy("email", "ASC")

// LIMIT and OFFSET
qb.Limit(10)
qb.Offset(20)
```

#### JOIN Operations
```go
// INNER JOIN
qb.Join("profiles", "profiles.user_id = users.id")

// LEFT JOIN
qb.LeftJoin("orders", "orders.user_id = users.id")

// RIGHT JOIN  
qb.RightJoin("categories", "categories.id = products.category_id")
```

#### Execution Methods
```go
// Execute and get all results
results, err := qb.Execute(ctx)

// Get count
count, err := qb.Count(ctx)

// Get first result only
first, err := qb.First(ctx)

// Build query without executing
query, args := qb.Build()
```

## Migration System

### Creating Migrations

```go
// Create a new migration
migrationService := database.NewMigrationService(db, "migrations")

migration, err := migrationService.CreateMigration(
    "add_user_profiles",
    `CREATE TABLE user_profiles (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        user_id UUID NOT NULL REFERENCES users(id),
        first_name VARCHAR(100),
        last_name VARCHAR(100),
        bio TEXT,
        avatar_url VARCHAR(500),
        created_at TIMESTAMP DEFAULT NOW(),
        updated_at TIMESTAMP DEFAULT NOW()
    );
    
    CREATE INDEX idx_user_profiles_user_id ON user_profiles(user_id);`,
    `DROP TABLE IF EXISTS user_profiles;`,
)
```

### Migration Operations

```go
// Apply all pending migrations
err := migrationService.ApplyMigrations()

// Apply specific migration
err := migrationService.ApplyMigration(20240115123000)

// Rollback to specific version
err := migrationService.RollbackMigration(20240115122000)

// Rollback one migration
err := migrationService.RollbackOne()

// Get current version
version, dirty, err := migrationService.GetCurrentVersion()

// Get migration history
history, err := migrationService.GetMigrationHistory(ctx)
```

### Migration File Structure

```
migrations/
├── 20240115120000_create_users_table.up.sql
├── 20240115120000_create_users_table.down.sql
├── 20240115121000_add_user_indexes.up.sql
├── 20240115121000_add_user_indexes.down.sql
├── 20240115122000_create_profiles_table.up.sql
└── 20240115122000_create_profiles_table.down.sql
```

## Database Utilities

### Schema Introspection

```go
utils := database.NewDatabaseUtils(db)

// Get all tables in schema
tables, err := utils.GetTables(ctx, "public")

// Get columns for specific table
columns, err := utils.GetColumns(ctx, "public", "users")

// Check if table exists
exists, err := utils.TableExists(ctx, "public", "users")

// Create table programmatically
columnDefs := []*database.ColumnInfo{
    {
        Name:         "id",
        DataType:     "uuid",
        IsNullable:   false,
        IsPrimaryKey: true,
        ColumnDefault: stringPtr("gen_random_uuid()"),
    },
    {
        Name:       "email",
        DataType:   "varchar(255)",
        IsNullable: false,
    },
}

err := utils.CreateTable(ctx, "public", "new_table", columnDefs)

// Drop table
err := utils.DropTable(ctx, "public", "old_table")

// Execute raw SQL
results, err := utils.ExecuteSQL(ctx, "SELECT COUNT(*) FROM users")
```

## Meta Service Features

### Table Metadata

The Meta Service provides comprehensive table information:

```go
metaService := database.NewMetaService(db)

// Get table with full metadata
table, err := metaService.GetTable(ctx, "public", "users")

// Table includes:
// - Basic info (name, schema, comment)
// - All columns with types, constraints, defaults
// - All indexes with types and columns
// - All constraints (PK, FK, unique, check)
// - RLS (Row Level Security) status
```

### Column Information

Each column includes:
- Name and data type
- Nullable status
- Default value
- Primary key status
- Foreign key relationships
- Unique constraints
- Ordinal position
- Comments

### Index Information

Each index includes:
- Index name and type (btree, hash, gin, etc.)
- Columns included
- Unique and primary key status
- Index definition

### Constraint Information

Each constraint includes:
- Constraint name and type
- Columns involved
- Referenced table/columns (for foreign keys)
- Update/delete rules
- Check constraint definitions

## SQL Execution Options

### Execution Options

```go
options := &database.SQLExecutionOptions{
    MaxRows:     1000,           // Limit result rows
    Timeout:     30 * time.Second, // Query timeout
    ReadOnly:    true,           // Only allow SELECT queries
    Transaction: false,          // Execute in transaction
}

result, err := metaService.ExecuteSQL(ctx, query, args, options)
```

### Query Result Structure

```go
type QueryResult struct {
    Columns       []string                 `json:"columns"`
    Rows          []map[string]interface{} `json:"rows"`
    RowsAffected  int64                    `json:"rows_affected"`
    ExecutionTime time.Duration            `json:"execution_time"`
    QueryType     string                   `json:"query_type"`
}
```

### Supported Query Types

- **SELECT**: Returns data rows
- **INSERT**: Returns rows affected
- **UPDATE**: Returns rows affected  
- **DELETE**: Returns rows affected
- **CREATE**: Schema modification
- **ALTER**: Schema modification
- **DROP**: Schema modification

## Error Handling

### Common Error Responses

#### Table Not Found
```json
{
  "error": "table public.nonexistent not found"
}
```

#### Invalid SQL
```json
{
  "error": "syntax error at or near \"SELCT\""
}
```

#### Permission Denied
```json
{
  "error": "permission denied for table users"
}
```

#### Connection Error
```json
{
  "error": "failed to connect to database: connection refused"
}
```

#### Validation Error
```json
{
  "error": "table name cannot be empty"
}
```

#### Constraint Violation
```json
{
  "error": "duplicate key value violates unique constraint \"users_email_key\""
}
```

#### Transaction Error
```json
{
  "error": "current transaction is aborted, commands ignored until end of transaction block"
}
```

## Configuration

### Database Configuration

```yaml
database:
  host: "localhost"
  port: 5432
  name: "goforward"
  user: "postgres"
  password: "password"
  ssl_mode: "disable"
  max_connections: 25
  min_connections: 5
  max_conn_lifetime: "1h"
  max_conn_idle_time: "30m"
```

### Environment Variables

```bash
# Database connection
DB_HOST=localhost
DB_PORT=5432
DB_NAME=goforward
DB_USER=postgres
DB_PASSWORD=password
DB_SSL_MODE=disable

# Connection pooling
DB_MAX_CONNECTIONS=25
DB_MIN_CONNECTIONS=5
DB_MAX_CONN_LIFETIME=1h
DB_MAX_CONN_IDLE_TIME=30m

# Migration settings
MIGRATIONS_PATH=./migrations
```

## Security Best Practices

### 🔐 SQL Injection Prevention

1. **Parameterized Queries**: Always use parameter placeholders ($1, $2, etc.)
2. **Input Validation**: Validate all user inputs before query execution
3. **Query Whitelisting**: Use query builder for dynamic queries
4. **Prepared Statements**: Leverage pgx prepared statement support

```go
// ✅ Safe - parameterized query
results, err := db.Query(ctx, "SELECT * FROM users WHERE email = $1", email)

// ❌ Unsafe - string concatenation
query := "SELECT * FROM users WHERE email = '" + email + "'"
```

### 🛡️ Access Control

1. **Read-Only Mode**: Use read-only options for SELECT queries
2. **Schema Validation**: Validate schema and table names
3. **Permission Checks**: Implement role-based access control
4. **Query Timeouts**: Set reasonable query timeouts

### 🔒 Connection Security

1. **SSL/TLS**: Use SSL connections in production
2. **Connection Pooling**: Limit concurrent connections
3. **Credential Management**: Use environment variables for credentials
4. **Network Security**: Restrict database network access

## Database Schema

### Core Tables

#### Users Table
```sql
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email VARCHAR(255) UNIQUE,
    phone VARCHAR(20) UNIQUE,
    username VARCHAR(100) UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    email_verified BOOLEAN DEFAULT FALSE,
    phone_verified BOOLEAN DEFAULT FALSE,
    metadata JSONB,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_users_email ON users(email) WHERE email IS NOT NULL;
CREATE INDEX idx_users_phone ON users(phone) WHERE phone IS NOT NULL;
CREATE INDEX idx_users_username ON users(username) WHERE username IS NOT NULL;
```

#### Schema Migrations Table
```sql
CREATE TABLE schema_migrations (
    version BIGINT PRIMARY KEY,
    dirty BOOLEAN NOT NULL DEFAULT FALSE
);
```

### System Tables

The database system automatically creates and manages several system tables for metadata and tracking:

- `schema_migrations`: Migration version tracking
- `pg_*`: PostgreSQL system catalogs (read-only)
- `information_schema.*`: SQL standard metadata views

## Performance Optimization

### Connection Pool Tuning

```go
config := &database.Config{
    MaxConns:        25,                    // Max concurrent connections
    MinConns:        5,                     // Min idle connections
    MaxConnLifetime: time.Hour,             // Connection lifetime
    MaxConnIdleTime: 30 * time.Minute,     // Idle connection timeout
}
```

### Query Optimization

```go
// Use indexes effectively
qb.Table("users").
    Where("email = ?", email).              // Uses email index
    Where("created_at > ?", date).          // Consider adding index
    OrderBy("created_at", "DESC").          // Uses index for sorting
    Limit(10)                               // Limits result set

// Avoid N+1 queries with joins
qb.Table("users").
    Select("users.*, profiles.first_name").
    LeftJoin("profiles", "profiles.user_id = users.id").
    Where("users.active = ?", true)
```

### Monitoring & Statistics

```go
// Get connection pool stats
stats := db.Stats()
fmt.Printf("Active connections: %d\n", stats.AcquiredConns())
fmt.Printf("Idle connections: %d\n", stats.IdleConns())
fmt.Printf("Total connections: %d\n", stats.TotalConns())

// Monitor query performance
start := time.Now()
results, err := qb.Execute(ctx)
duration := time.Since(start)
fmt.Printf("Query took: %v\n", duration)
```

## Testing Examples

### Basic Operations
```bash
# Create a test table
curl -X POST http://localhost:8080/database/tables \
  -H "Content-Type: application/json" \
  -d '{
    "name": "test_table",
    "schema": "public",
    "columns": [
      {
        "name": "id",
        "type": "serial",
        "is_primary_key": true
      },
      {
        "name": "name",
        "type": "varchar(100)",
        "nullable": false
      }
    ]
  }'

# Insert test data
curl -X POST http://localhost:8080/database/sql/execute \
  -H "Content-Type: application/json" \
  -d '{
    "query": "INSERT INTO test_table (name) VALUES ($1), ($2)",
    "args": ["Test 1", "Test 2"]
  }'

# Query test data
curl -X POST http://localhost:8080/database/sql/execute \
  -H "Content-Type: application/json" \
  -d '{
    "query": "SELECT * FROM test_table ORDER BY id",
    "options": {"read_only": true}
  }'

# Get table statistics
curl -X GET http://localhost:8080/database/tables/public/test_table/stats

# Drop test table
curl -X DELETE http://localhost:8080/database/tables/public/test_table
```

### Migration Testing
```bash
# Check current migration version
curl -X GET http://localhost:8080/database/migrations/current

# Apply migrations
curl -X POST http://localhost:8080/database/migrations/apply

# Get migration history
curl -X GET http://localhost:8080/database/migrations/history
```

This comprehensive database documentation covers all aspects of the GoForward database system, providing both HTTP API endpoints and programmatic usage examples for complete database management capabilities.
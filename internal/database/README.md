# Database Package

This package provides comprehensive database functionality for the Go Forward framework, including PostgreSQL connection management, migrations, query building, and database utilities.

## Features

- **Connection Management**: PostgreSQL connection pooling with pgx driver
- **Migration System**: Up/down migration support with golang-migrate
- **Query Builder**: Fluent interface for building SQL queries
- **Database Utilities**: Schema introspection and table management
- **Initial Schema**: Pre-defined tables for users, migrations, and metadata

## Components

### 1. Database Connection (`connection.go`)

Provides connection pooling and basic database operations:

```go
config := &database.Config{
    Host:     "localhost",
    Port:     5432,
    Name:     "goforward",
    User:     "postgres",
    Password: "password",
    SSLMode:  "disable",
    MaxConns: 25,
}

db, err := database.New(config)
if err != nil {
    log.Fatal(err)
}
defer db.Close()
```

### 2. Migration System (`migration.go`)

Handles database schema migrations:

```go
migrationService := database.NewMigrationService(db, "migrations")

// Apply all pending migrations
err := migrationService.ApplyMigrations()

// Create a new migration
migration, err := migrationService.CreateMigration(
    "add_user_table",
    "CREATE TABLE users (id UUID PRIMARY KEY);",
    "DROP TABLE users;",
)
```

### 3. Query Builder (`query_builder.go`)

Fluent interface for building SQL queries:

```go
qb := database.NewQueryBuilder(db)

results, err := qb.Table("users").
    Select("id", "email", "username").
    Where("email_verified = ?", true).
    Where("created_at > ?", time.Now().AddDate(0, -1, 0)).
    OrderBy("created_at", "DESC").
    Limit(10).
    Execute(ctx)
```

### 4. Database Utilities (`utils.go`)

Schema introspection and table management:

```go
utils := database.NewDatabaseUtils(db)

// Get all tables in a schema
tables, err := utils.GetTables(ctx, "public")

// Check if table exists
exists, err := utils.TableExists(ctx, "public", "users")

// Execute raw SQL
results, err := utils.ExecuteSQL(ctx, "SELECT * FROM users LIMIT 5")
```

### 5. Database Service (`database.go`)

Main service that combines all components:

```go
service, err := database.NewService(config)
if err != nil {
    log.Fatal(err)
}
defer service.Close()

// Initialize with migrations
err = service.Initialize(ctx)

// Access components
db := service.DB
migrations := service.Migration
utils := service.Utils
```

## Initial Schema

The package includes initial migrations that create:

1. **users table**: Core user information with email, phone, username
2. **migrations_metadata table**: Custom migration tracking
3. **table_metadata table**: Database schema metadata
4. **column_metadata table**: Column information for introspection

## Configuration

Database configuration supports:

- Connection pooling settings (max/min connections, timeouts)
- SSL mode configuration
- Environment variable overrides
- Default values for development

## Testing

Run tests with:

```bash
go test ./internal/database -v
```

Tests include:
- Configuration validation
- Connection string generation
- Query builder functionality
- Utility function testing

## Requirements Satisfied

This implementation satisfies the following requirements:

- **Requirement 2.1**: PostgreSQL database connection with real-time capabilities
- **Requirement 7.1**: Migration file creation and management
- **Requirement 7.3**: Migration execution and tracking

## Usage Example

See `examples/database_example.go` for a complete usage example.
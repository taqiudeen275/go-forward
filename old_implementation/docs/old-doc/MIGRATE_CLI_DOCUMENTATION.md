# GoForward Migration CLI Documentation

## Overview

The GoForward Migration CLI is a comprehensive database migration management tool that provides safe, version-controlled database schema changes. It supports PostgreSQL databases and offers both up and down migrations with transaction safety, validation, and template-based migration generation.

## Installation & Setup

### Prerequisites

- PostgreSQL database
- Go 1.19+ (for building from source)
- Valid `config.yaml` file in the project root

### Configuration

The CLI reads database configuration from `config.yaml`:

```yaml
database:
  host: "localhost"
  port: 5432
  name: "goforward"
  user: "postgres"
  password: "password"
  ssl_mode: "disable"
  max_connections: 25
  max_lifetime: "1h"
```

### Environment Variables

You can also use environment variables:

```bash
export DB_HOST=localhost
export DB_PORT=5432
export DB_NAME=goforward
export DB_USER=postgres
export DB_PASSWORD=password
export DB_SSL_MODE=disable
```

## Usage

### Basic Syntax

```bash
migrate [command] [options] [arguments]
```

### Global Options

- `-migrations string`: Path to migrations directory (default: "./migrations")
- `-format string`: Output format: table, json (default: "table")
- `-verbose`: Enable verbose output
- `-dry-run`: Show what would be done without executing
- `-help`: Show help information

## Commands

### 1. Migration Application

#### Apply All Pending Migrations

```bash
migrate up
```

Applies all pending migrations in sequential order.

**Example:**
```bash
# Apply all pending migrations
migrate up

# Apply with verbose output
migrate -verbose up

# Dry run to see what would be applied
migrate -dry-run up
```

**Output:**
```
✓ Applied migration 000001_initial_schema (took 45ms)
✓ Applied migration 000002_add_password_reset_tokens (took 23ms)
✓ Applied migration 000003_add_otp_table (took 67ms)
```

#### Migrate to Specific Version

```bash
migrate to <version>
```

Migrates to a specific version (can go up or down).

**Examples:**
```bash
# Migrate to version 5
migrate to 5

# Migrate to version 3 (rollback if current > 3)
migrate to 3

# Dry run to see what would happen
migrate -dry-run to 10
```

### 2. Migration Rollback

#### Rollback One Migration

```bash
migrate down
```

Rolls back the most recent migration.

**Example:**
```bash
# Rollback one migration
migrate down

# Dry run to see what would be rolled back
migrate -dry-run down
```

#### Rollback to Specific Version

```bash
migrate rollback <version>
```

Rolls back to a specific version with validation.

**Examples:**
```bash
# Rollback to version 3
migrate rollback 3

# Rollback with verbose output
migrate -verbose rollback 2
```

**Safety Features:**
- Validates rollback is safe before execution
- Checks for dirty state
- Ensures all intermediate migrations have down files
- Prevents rollback to higher versions

### 3. Migration Creation

#### Create Empty Migration

```bash
migrate create <name>
```

Creates a new migration with empty up/down SQL files.

**Examples:**
```bash
# Create a new migration
migrate create add_users_table

# Creates files:
# 000004_add_users_table.up.sql
# 000004_add_users_table.down.sql
```

**Generated Files:**
```sql
-- 000004_add_users_table.up.sql
-- Add your migration SQL here

-- 000004_add_users_table.down.sql  
-- Add your rollback SQL here
```

#### Create Migration from Template

```bash
migrate create-from-template <name> <template> [params]
```

Creates a migration using predefined templates with parameters.

**Available Templates:**
- `create_table`: Create a new table with standard columns
- `add_column`: Add a column to existing table
- `create_index`: Create an index on a table
- `empty`: Empty migration template

**Examples:**

**Create Table Template:**
```bash
migrate create-from-template add_products_table create_table TableName=products
```

**Generated SQL:**
```sql
-- Up migration
CREATE TABLE IF NOT EXISTS products (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_products_created_at ON products(created_at);

CREATE TRIGGER update_products_updated_at 
    BEFORE UPDATE ON products 
    FOR EACH ROW 
    EXECUTE FUNCTION update_updated_at_column();

-- Down migration
DROP TRIGGER IF EXISTS update_products_updated_at ON products;
DROP INDEX IF EXISTS idx_products_created_at;
DROP TABLE IF EXISTS products;
```

**Add Column Template:**
```bash
migrate create-from-template add_email_column add_column TableName=users ColumnName=email ColumnType="VARCHAR(255)" NotNull=true CreateIndex=true
```

**Create Index Template:**
```bash
migrate create-from-template add_email_index create_index TableName=users IndexName=idx_users_email Columns=email Unique=true
```

### 4. Migration Status & Information

#### Show Migration Status

```bash
migrate status
```

Shows the status of all migrations (applied/pending).

**Example Output (Table Format):**
```
VERSION  NAME                           STATUS   APPLIED AT
-------  ----                           ------   ----------
000001   initial_schema                 applied  2024-01-15 10:30:00
000002   add_password_reset_tokens      applied  2024-01-15 10:31:15
000003   add_otp_table                  applied  2024-01-15 10:32:45
000004   add_storage_tables             pending  -
000005   add_otp_purpose                pending  -
```

**JSON Format:**
```bash
migrate -format=json status
```

```json
[
  {
    "version": 1,
    "name": "initial_schema",
    "applied": true,
    "applied_at": "2024-01-15T10:30:00Z"
  },
  {
    "version": 2,
    "name": "add_password_reset_tokens", 
    "applied": true,
    "applied_at": "2024-01-15T10:31:15Z"
  },
  {
    "version": 3,
    "name": "add_otp_table",
    "applied": false,
    "applied_at": null
  }
]
```

#### Show Migration History

```bash
migrate history
```

Shows detailed migration history including dirty state information.

**Example Output:**
```
VERSION  NAME                           STATUS   APPLIED AT           DIRTY
-------  ----                           ------   ----------           -----
000003   add_otp_table                  applied  2024-01-15 10:32:45  
000002   add_password_reset_tokens      applied  2024-01-15 10:31:15  
000001   initial_schema                 applied  2024-01-15 10:30:00  
```

#### Show Current Version

```bash
migrate version
```

Shows the current migration version and dirty state.

**Example Output:**
```
Current migration version: 3
```

**With Dirty State:**
```
Current migration version: 3 (dirty)
```

### 5. Migration Validation & Repair

#### Validate Migration Files

```bash
migrate validate
```

Validates that all migration files are properly paired (up/down files exist).

**Example Output:**
```
All migration files are valid
```

**Error Example:**
```
migration validation failed:
missing down file for migration 000004_add_storage_tables
missing up file for migration 000005_incomplete_migration
```

#### Repair Dirty State

```bash
migrate repair
```

Repairs a dirty migration state (when a migration fails mid-execution).

**Example:**
```bash
# Check if repair is needed
migrate version
# Output: Current migration version: 3 (dirty)

# Repair the dirty state
migrate repair
# Output: Dirty state repaired successfully

# Verify repair
migrate version  
# Output: Current migration version: 3
```

**Safety Notes:**
- Only use repair when you're certain the migration completed successfully
- Review the database state before repairing
- Consider manual cleanup if needed

### 6. Template Management

#### List Available Templates

```bash
migrate templates
```

Shows all available migration templates.

**Example Output:**
```
NAME          DESCRIPTION
----          -----------
create_table  Create a new table
add_column    Add a column to an existing table
create_index  Create an index on a table
empty         Empty migration template
```

## Migration File Structure

### Directory Layout

```
migrations/
├── 000001_initial_schema.up.sql
├── 000001_initial_schema.down.sql
├── 000002_add_password_reset_tokens.up.sql
├── 000002_add_password_reset_tokens.down.sql
├── 000003_add_otp_table.up.sql
├── 000003_add_otp_table.down.sql
├── 000004_add_storage_tables.up.sql
├── 000004_add_storage_tables.down.sql
├── 000005_add_otp_purpose.up.sql
└── 000005_add_otp_purpose.down.sql
```

### File Naming Convention

- **Format**: `XXXXXX_migration_name.{up|down}.sql`
- **Version**: 6-digit zero-padded number (000001, 000002, etc.)
- **Name**: Snake_case description of the migration
- **Direction**: `up` for forward migration, `down` for rollback

### Migration File Content

#### Up Migration Example
```sql
-- 000003_add_otp_table.up.sql
-- Create OTP verification table

CREATE TABLE IF NOT EXISTS otp_codes (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    identifier VARCHAR(255) NOT NULL, -- email or phone
    code VARCHAR(10) NOT NULL,
    purpose VARCHAR(50) NOT NULL DEFAULT 'verification',
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    used_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Create indexes for efficient lookups
CREATE INDEX IF NOT EXISTS idx_otp_codes_identifier ON otp_codes(identifier);
CREATE INDEX IF NOT EXISTS idx_otp_codes_expires_at ON otp_codes(expires_at);
CREATE INDEX IF NOT EXISTS idx_otp_codes_purpose ON otp_codes(purpose);

-- Create composite index for active OTP lookup
CREATE INDEX IF NOT EXISTS idx_otp_codes_active 
ON otp_codes(identifier, purpose, expires_at) 
WHERE used_at IS NULL;
```

#### Down Migration Example
```sql
-- 000003_add_otp_table.down.sql
-- Remove OTP verification table

DROP INDEX IF EXISTS idx_otp_codes_active;
DROP INDEX IF EXISTS idx_otp_codes_purpose;
DROP INDEX IF EXISTS idx_otp_codes_expires_at;
DROP INDEX IF EXISTS idx_otp_codes_identifier;
DROP TABLE IF EXISTS otp_codes;
```

## Advanced Usage

### Batch Operations

#### Apply Multiple Migrations with Callback

```bash
# Apply all pending migrations with verbose output
migrate -verbose up
```

The CLI provides real-time feedback during batch operations:

```
Applying all pending migrations...
✓ Applied migration 000004_add_storage_tables (took 156ms)
✓ Applied migration 000005_add_otp_purpose (took 89ms)
✓ Applied migration 000006_secure_otp_hashing (took 234ms)
```

#### Rollback Multiple Migrations

```bash
# Rollback to version 2 (will rollback versions 5, 4, 3)
migrate rollback 2
```

### Transaction Safety

All migration operations are executed within database transactions:

- **Atomic Operations**: Each migration runs in its own transaction
- **Rollback on Failure**: Failed migrations are automatically rolled back
- **State Consistency**: Database state remains consistent even on failures
- **Dirty State Detection**: Failed migrations are marked as "dirty" for manual review

### Dry Run Mode

Use dry run mode to preview changes without executing them:

```bash
# See what migrations would be applied
migrate -dry-run up

# See what would be rolled back
migrate -dry-run down

# Preview migration to specific version
migrate -dry-run to 5
```

**Example Dry Run Output:**
```
Migrations that would be applied:
  000004_add_storage_tables
  000005_add_otp_purpose
  000006_secure_otp_hashing
```

### Custom Migration Paths

```bash
# Use custom migrations directory
migrate -migrations ./custom/migrations up

# Use relative path
migrate -migrations ../shared-migrations status

# Use absolute path (Windows)
migrate -migrations "C:\projects\migrations" validate
```

## Template System

### Built-in Templates

#### 1. Create Table Template

**Usage:**
```bash
migrate create-from-template create_users_table create_table TableName=users
```

**Parameters:**
- `TableName` (required): Name of the table to create

**Generated Structure:**
- UUID primary key with `gen_random_uuid()`
- `created_at` and `updated_at` timestamp columns
- Automatic `updated_at` trigger
- Index on `created_at`

#### 2. Add Column Template

**Usage:**
```bash
migrate create-from-template add_email_to_users add_column TableName=users ColumnName=email ColumnType="VARCHAR(255)" NotNull=true DefaultValue="''" CreateIndex=true
```

**Parameters:**
- `TableName` (required): Target table name
- `ColumnName` (required): New column name
- `ColumnType` (required): Column data type
- `NotNull` (optional): Set NOT NULL constraint
- `DefaultValue` (optional): Default value for the column
- `CreateIndex` (optional): Create index on the new column

#### 3. Create Index Template

**Usage:**
```bash
migrate create-from-template add_user_email_index create_index TableName=users IndexName=idx_users_email Columns=email Unique=true IndexType=btree
```

**Parameters:**
- `TableName` (required): Target table name
- `IndexName` (required): Name of the index
- `Columns` (required): Comma-separated list of columns
- `Unique` (optional): Create unique index
- `IndexType` (optional): Index type (btree, hash, gin, gist)

### Template Conditionals

Templates support simple conditional logic:

```sql
-- Example template with conditionals
ALTER TABLE {{.TableName}} ADD COLUMN {{.ColumnName}} {{.ColumnType}}
{{if .NotNull}} NOT NULL{{end}}
{{if .DefaultValue}} DEFAULT {{.DefaultValue}}{{end}};

{{if .CreateIndex}}
CREATE INDEX IF NOT EXISTS idx_{{.TableName}}_{{.ColumnName}} 
ON {{.TableName}}({{.ColumnName}});
{{end}}
```

## Error Handling

### Common Errors and Solutions

#### 1. Configuration Errors

**Error:**
```
Failed to load configuration: config file not found
```

**Solution:**
- Ensure `config.yaml` exists in the current directory
- Check file permissions
- Verify YAML syntax

#### 2. Database Connection Errors

**Error:**
```
Failed to initialize database: connection refused
```

**Solutions:**
- Verify database is running
- Check connection parameters in config
- Ensure network connectivity
- Verify credentials

#### 3. Migration File Errors

**Error:**
```
migration validation failed:
missing down file for migration 000004_add_storage_tables
```

**Solution:**
- Create the missing down migration file
- Ensure file naming follows convention
- Check file permissions

#### 4. Dirty State Errors

**Error:**
```
database is in dirty state, cannot rollback safely
```

**Solutions:**
1. Review the failed migration manually
2. Fix any issues in the database
3. Use `migrate repair` to clear dirty state
4. Or manually fix the `schema_migrations` table

#### 5. Version Conflicts

**Error:**
```
cannot rollback to version 5, current version is 3
```

**Solution:**
- Check current version with `migrate version`
- Use correct target version (must be less than current)
- Use `migrate to X` instead of `migrate rollback X`

### Debugging Tips

#### Enable Verbose Output

```bash
migrate -verbose up
```

Provides detailed information about:
- Migration execution time
- SQL statements being executed
- Transaction boundaries
- Error details

#### Use Dry Run Mode

```bash
migrate -dry-run up
```

Preview changes without executing them to:
- Verify migration order
- Check for potential issues
- Understand impact before execution

#### Check Migration Status

```bash
migrate status
migrate history
migrate version
```

Get comprehensive information about:
- Current database state
- Applied migrations
- Pending migrations
- Dirty state status

## Best Practices

### 1. Migration Design

#### ✅ Do's

- **Atomic Changes**: Keep migrations focused on single logical changes
- **Reversible**: Always provide down migrations
- **Idempotent**: Use `IF EXISTS` and `IF NOT EXISTS` clauses
- **Data Safety**: Use transactions for data migrations
- **Testing**: Test both up and down migrations

**Example:**
```sql
-- Good: Atomic, reversible, idempotent
CREATE TABLE IF NOT EXISTS user_profiles (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    first_name VARCHAR(100),
    last_name VARCHAR(100),
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_user_profiles_user_id ON user_profiles(user_id);
```

#### ❌ Don'ts

- **Multiple Concerns**: Don't mix unrelated changes in one migration
- **Irreversible Changes**: Avoid data loss in down migrations
- **Hardcoded Values**: Don't use environment-specific values
- **Large Data Changes**: Avoid massive data migrations without batching

### 2. File Organization

#### Naming Conventions

```bash
# Good naming
000001_create_users_table
000002_add_user_indexes  
000003_create_profiles_table
000004_add_profile_constraints

# Poor naming
000001_misc_changes
000002_fix_stuff
000003_update
```

#### Directory Structure

```
migrations/
├── README.md                    # Migration documentation
├── 000001_initial_schema.up.sql
├── 000001_initial_schema.down.sql
├── 000002_add_auth_tables.up.sql
├── 000002_add_auth_tables.down.sql
└── templates/                   # Custom templates (optional)
    ├── create_audit_table.sql
    └── add_audit_columns.sql
```

### 3. Development Workflow

#### Local Development

```bash
# 1. Create migration
migrate create add_new_feature

# 2. Edit migration files
# Edit 000XXX_add_new_feature.up.sql
# Edit 000XXX_add_new_feature.down.sql

# 3. Test migration
migrate -dry-run up
migrate up

# 4. Test rollback
migrate -dry-run down
migrate down

# 5. Re-apply for final test
migrate up
```

#### Team Collaboration

1. **Sequential Numbering**: Coordinate migration numbers across team
2. **Code Reviews**: Review migration SQL in pull requests
3. **Testing**: Test migrations on staging before production
4. **Documentation**: Document complex migrations

#### Production Deployment

```bash
# 1. Backup database
pg_dump -h localhost -U postgres goforward > backup.sql

# 2. Dry run in production
migrate -dry-run up

# 3. Apply migrations
migrate up

# 4. Verify application
migrate status
migrate version

# 5. Monitor application health
```

### 4. Performance Considerations

#### Large Table Migrations

For large tables, consider:

```sql
-- Add column with default (can be slow on large tables)
-- Better: Add column without default, then update in batches
ALTER TABLE large_table ADD COLUMN new_column VARCHAR(255);

-- Update in batches
UPDATE large_table SET new_column = 'default_value' 
WHERE id IN (
    SELECT id FROM large_table 
    WHERE new_column IS NULL 
    LIMIT 1000
);

-- Then add NOT NULL constraint if needed
ALTER TABLE large_table ALTER COLUMN new_column SET NOT NULL;
```

#### Index Creation

```sql
-- Create indexes concurrently to avoid blocking
CREATE INDEX CONCURRENTLY idx_users_email ON users(email);

-- Note: CONCURRENTLY cannot be used in transactions
-- Consider separate migration for concurrent index creation
```

## Integration Examples

### CI/CD Pipeline

#### GitHub Actions Example

```yaml
name: Database Migration
on:
  push:
    branches: [main]
    paths: ['migrations/**']

jobs:
  migrate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Setup Go
        uses: actions/setup-go@v3
        with:
          go-version: '1.19'
          
      - name: Build migrate CLI
        run: go build -o migrate ./cmd/migrate
        
      - name: Run migrations (dry-run)
        run: ./migrate -dry-run up
        env:
          DB_HOST: ${{ secrets.DB_HOST }}
          DB_USER: ${{ secrets.DB_USER }}
          DB_PASSWORD: ${{ secrets.DB_PASSWORD }}
          
      - name: Apply migrations
        run: ./migrate up
        env:
          DB_HOST: ${{ secrets.DB_HOST }}
          DB_USER: ${{ secrets.DB_USER }}
          DB_PASSWORD: ${{ secrets.DB_PASSWORD }}
```

#### Docker Integration

```dockerfile
# Dockerfile for migration container
FROM golang:1.19-alpine AS builder
WORKDIR /app
COPY . .
RUN go build -o migrate ./cmd/migrate

FROM alpine:latest
RUN apk --no-cache add ca-certificates
WORKDIR /root/
COPY --from=builder /app/migrate .
COPY --from=builder /app/migrations ./migrations
COPY --from=builder /app/config.yaml .

CMD ["./migrate", "up"]
```

### Application Integration

#### Go Application Example

```go
package main

import (
    "log"
    "github.com/yourorg/goforward/internal/database"
)

func main() {
    // Load configuration
    cfg, err := config.Load()
    if err != nil {
        log.Fatal(err)
    }
    
    // Initialize database
    db, err := database.New(&cfg.Database)
    if err != nil {
        log.Fatal(err)
    }
    defer db.Close()
    
    // Run migrations programmatically
    migrationService := database.NewMigrationService(db, "./migrations")
    
    // Check if migrations are needed
    currentVersion, dirty, err := migrationService.GetCurrentVersion()
    if err != nil {
        log.Fatal(err)
    }
    
    if dirty {
        log.Fatal("Database is in dirty state, manual intervention required")
    }
    
    // Apply pending migrations
    results, err := migrationService.ApplyMigrations()
    if err != nil {
        log.Fatal(err)
    }
    
    for _, result := range results {
        if result.Success {
            log.Printf("Applied migration %d_%s", result.Version, result.Name)
        } else {
            log.Fatalf("Migration failed: %s", result.Error)
        }
    }
    
    // Start application...
}
```

## Troubleshooting

### Common Issues

#### 1. Permission Denied

**Symptoms:**
```
permission denied for relation schema_migrations
```

**Solutions:**
- Grant necessary permissions to database user
- Use superuser for initial setup
- Check database connection parameters

#### 2. Lock Timeout

**Symptoms:**
```
canceling statement due to lock timeout
```

**Solutions:**
- Ensure no long-running transactions
- Check for blocking queries
- Consider maintenance window for migrations

#### 3. Out of Order Migrations

**Symptoms:**
```
migration 000005 cannot be applied, missing migration 000004
```

**Solutions:**
- Apply missing migrations first
- Check migration file numbering
- Coordinate with team on migration order

#### 4. Template Parameter Errors

**Symptoms:**
```
template parameter 'TableName' is required
```

**Solutions:**
- Provide all required parameters
- Check parameter spelling and case
- Use `migrate templates` to see available templates

### Recovery Procedures

#### Dirty State Recovery

1. **Identify the Issue:**
   ```bash
   migrate version
   # Output: Current migration version: 5 (dirty)
   ```

2. **Review Database State:**
   ```sql
   -- Check what was partially applied
   SELECT * FROM schema_migrations;
   
   -- Check for partially created objects
   \dt  -- List tables
   \di  -- List indexes
   ```

3. **Manual Cleanup (if needed):**
   ```sql
   -- Remove partially created objects
   DROP TABLE IF EXISTS incomplete_table;
   DROP INDEX IF EXISTS incomplete_index;
   ```

4. **Repair Dirty State:**
   ```bash
   migrate repair
   ```

5. **Verify and Continue:**
   ```bash
   migrate version
   migrate status
   migrate up
   ```

#### Failed Migration Recovery

1. **Review Error Logs:**
   ```bash
   migrate -verbose up
   ```

2. **Fix Migration File:**
   - Edit the problematic migration file
   - Fix SQL syntax or logic errors
   - Test SQL manually if needed

3. **Rollback and Retry:**
   ```bash
   migrate down  # Rollback failed migration
   migrate up    # Retry with fixed migration
   ```

## Monitoring and Logging

### Migration Logging

The CLI provides comprehensive logging:

```bash
# Enable verbose logging
migrate -verbose up

# Example output:
Applying all pending migrations...
✓ Applied migration 000004_add_storage_tables (took 156ms)
  - Created table: storage_objects
  - Created table: storage_buckets  
  - Created indexes: 3
  - Execution time: 156ms
✓ Applied migration 000005_add_otp_purpose (took 89ms)
  - Added column: purpose to otp_codes
  - Updated existing records: 1,247
  - Execution time: 89ms
```

### Database Monitoring

Monitor migration impact:

```sql
-- Check migration history
SELECT version, dirty FROM schema_migrations ORDER BY version;

-- Monitor table sizes after migrations
SELECT 
    schemaname,
    tablename,
    pg_size_pretty(pg_total_relation_size(schemaname||'.'||tablename)) as size
FROM pg_tables 
WHERE schemaname = 'public'
ORDER BY pg_total_relation_size(schemaname||'.'||tablename) DESC;

-- Check for long-running queries during migrations
SELECT 
    pid,
    now() - pg_stat_activity.query_start AS duration,
    query 
FROM pg_stat_activity 
WHERE (now() - pg_stat_activity.query_start) > interval '5 minutes';
```

## Conclusion

The GoForward Migration CLI provides a robust, safe, and feature-rich solution for database schema management. With its comprehensive command set, template system, transaction safety, and extensive validation features, it enables teams to manage database changes confidently in any environment.

Key benefits:
- **Safety First**: Transaction-based migrations with rollback support
- **Developer Friendly**: Rich CLI interface with dry-run and verbose modes
- **Template System**: Accelerated migration creation with built-in templates
- **Validation**: Comprehensive validation and repair capabilities
- **Integration Ready**: Easy integration with CI/CD pipelines and applications

For additional support or advanced use cases, refer to the source code in `cmd/migrate/main.go` and `internal/database/migration.go`.
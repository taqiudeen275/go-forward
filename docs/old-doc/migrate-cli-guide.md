# Go Forward Framework - Migration CLI Guide

## Table of Contents
1. [Introduction](#introduction)
2. [What are Database Migrations?](#what-are-database-migrations)
3. [Getting Started](#getting-started)
4. [Basic Commands](#basic-commands)
5. [Advanced Commands](#advanced-commands)
6. [Migration Templates](#migration-templates)
7. [Best Practices](#best-practices)
8. [Troubleshooting](#troubleshooting)
9. [Examples and Use Cases](#examples-and-use-cases)
10. [Command Reference](#command-reference)

---

## Introduction

The Go Forward Framework Migration CLI is a powerful tool that helps you manage your database schema changes in a controlled, versioned, and reversible way. Think of it as "version control for your database" - just like Git tracks changes to your code, migrations track changes to your database structure.

### Why Use Migrations?

- **Version Control**: Track all database changes alongside your code
- **Team Collaboration**: Share database changes with your team safely
- **Deployment Safety**: Apply changes consistently across environments
- **Rollback Capability**: Undo changes if something goes wrong
- **Audit Trail**: See exactly what changed and when

---

## What are Database Migrations?

### The Concept

A **migration** is a set of instructions that tells your database how to change its structure. Each migration has two parts:

1. **Up Migration** (`*.up.sql`): Instructions to apply the change
2. **Down Migration** (`*.down.sql`): Instructions to undo the change

### Example: Adding a New Table

**Up Migration** (creates the table):
```sql
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email VARCHAR(255) UNIQUE NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);
```

**Down Migration** (removes the table):
```sql
DROP TABLE IF EXISTS users;
```

### Migration Versioning

Migrations are numbered sequentially:
- `000001_initial_schema.up.sql`
- `000002_add_users_table.up.sql`
- `000003_add_password_field.up.sql`

This ensures they're applied in the correct order.

---

## Getting Started

### Prerequisites

1. **Go Forward Framework** installed and configured
2. **Database connection** configured in your `config.yaml`
3. **Migration CLI** built and available

### Building the Migration CLI

```bash
# From your project root
go build -o migrate.exe ./cmd/migrate
```

### Basic Setup

1. **Create migrations directory** (if it doesn't exist):
```bash
mkdir migrations
```

2. **Check CLI is working**:
```bash
./migrate.exe --help
```

3. **Check current status**:
```bash
./migrate.exe status
```

---

## Basic Commands

### 1. Checking Migration Status

**What it does**: Shows which migrations have been applied and which are pending.

```bash
./migrate.exe status
```

**Example Output**:
```
VERSION  NAME                    STATUS   APPLIED AT
-------  ----                    ------   ----------
000001   initial_schema          applied  2024-01-15 10:30:00
000002   add_users_table         applied  2024-01-15 10:31:00
000003   add_password_field      pending  -
```

**Understanding the Output**:
- **VERSION**: Sequential number of the migration
- **NAME**: Descriptive name of what the migration does
- **STATUS**: 
  - `applied` = Migration has been run
  - `pending` = Migration hasn't been run yet
- **APPLIED AT**: When the migration was applied (if applicable)

### 2. Applying Migrations

**What it does**: Runs all pending migrations to bring your database up to date.

```bash
./migrate.exe up
```

**Example Output**:
```
✓ Up migration 3_add_password_field (took 45ms)
✓ Up migration 4_add_indexes (took 120ms)
```

**When to use**: 
- After pulling new code with database changes
- When setting up a new environment
- During deployment

### 3. Rolling Back Migrations

**What it does**: Undoes the most recent migration.

```bash
./migrate.exe down
```

**Example Output**:
```
✓ Down migration 4_add_indexes (took 80ms)
```

**⚠️ Important**: Only use this when you're sure! Rolling back can cause data loss.

### 4. Checking Current Version

**What it does**: Shows which migration version your database is currently at.

```bash
./migrate.exe version
```

**Example Output**:
```
Current migration version: 3
```

### 5. Creating New Migrations

**What it does**: Creates a new migration file pair (up and down).

```bash
./migrate.exe create add_user_profiles
```

**Example Output**:
```
Created migration: 550e8400-e29b-41d4-a716-446655440000
```

**What gets created**:
- `000004_add_user_profiles.up.sql`
- `000004_add_user_profiles.down.sql`

---

## Advanced Commands

### 1. Migrating to Specific Version

**What it does**: Migrates your database to a specific version (can go up or down).

```bash
# Migrate to version 5
./migrate.exe to 5

# Migrate to version 2 (rolls back from higher version)
./migrate.exe to 2
```

**Use cases**:
- Testing specific database states
- Debugging migration issues
- Preparing for hotfixes

### 2. Rolling Back to Specific Version

**What it does**: Safely rolls back to a specific version with validation.

```bash
./migrate.exe rollback 3
```

**Safety features**:
- Validates rollback is possible
- Checks for missing down migrations
- Prevents data loss scenarios

### 3. Viewing Migration History

**What it does**: Shows detailed history of all migrations.

```bash
./migrate.exe history
```

**Example Output**:
```
VERSION  NAME                STATUS   APPLIED AT           DIRTY
-------  ----                ------   ----------           -----
000004   add_indexes         applied  2024-01-15 11:00:00  
000003   add_password_field  applied  2024-01-15 10:45:00  
000002   add_users_table     applied  2024-01-15 10:31:00  
000001   initial_schema      applied  2024-01-15 10:30:00  
```

### 4. Validating Migrations

**What it does**: Checks that all migration files are properly paired and valid.

```bash
./migrate.exe validate
```

**What it checks**:
- Every `.up.sql` has a corresponding `.down.sql`
- File naming follows conventions
- No missing migrations in sequence

### 5. Repairing Dirty State

**What it does**: Fixes database when a migration fails partway through.

```bash
./migrate.exe repair
```

**When to use**:
- After a migration fails
- When you see "dirty" status
- Database is in inconsistent state

---

## Migration Templates

Templates help you create common migration patterns quickly and correctly.

### Available Templates

```bash
./migrate.exe templates
```

**Output**:
```
NAME          DESCRIPTION
----          -----------
create_table  Create a new table
add_column    Add a column to an existing table
create_index  Create an index on a table
empty         Empty migration template
```

### Using Templates

#### 1. Creating a New Table

```bash
./migrate.exe create-from-template create_user_profiles create_table TableName=user_profiles
```

**Generated Up Migration**:
```sql
-- Create user_profiles table
CREATE TABLE IF NOT EXISTS user_profiles (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Create indexes for user_profiles table
CREATE INDEX IF NOT EXISTS idx_user_profiles_created_at ON user_profiles(created_at);

-- Create trigger for user_profiles table
CREATE TRIGGER update_user_profiles_updated_at 
    BEFORE UPDATE ON user_profiles 
    FOR EACH ROW 
    EXECUTE FUNCTION update_updated_at_column();
```

**Generated Down Migration**:
```sql
-- Drop user_profiles table
DROP TRIGGER IF EXISTS update_user_profiles_updated_at ON user_profiles;
DROP INDEX IF EXISTS idx_user_profiles_created_at;
DROP TABLE IF EXISTS user_profiles;
```

#### 2. Adding a Column

```bash
./migrate.exe create-from-template add_email_column add_column TableName=users ColumnName=email ColumnType="VARCHAR(255)" NotNull=true CreateIndex=true
```

#### 3. Creating an Index

```bash
./migrate.exe create-from-template add_email_index create_index TableName=users IndexName=idx_users_email Columns=email Unique=true
```

---

## Best Practices

### 1. Migration Naming

**Good Names** (descriptive and clear):
- `add_users_table`
- `add_email_index_to_users`
- `remove_deprecated_status_column`
- `create_audit_log_table`

**Bad Names** (vague or unclear):
- `fix_stuff`
- `update_db`
- `changes`
- `migration1`

### 2. Writing Safe Migrations

#### Always Use IF EXISTS/IF NOT EXISTS

**Good**:
```sql
-- Up migration
CREATE TABLE IF NOT EXISTS users (...);
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);

-- Down migration  
DROP INDEX IF EXISTS idx_users_email;
DROP TABLE IF EXISTS users;
```

**Bad**:
```sql
-- Up migration
CREATE TABLE users (...);  -- Fails if table exists
CREATE INDEX idx_users_email ON users(email);  -- Fails if index exists

-- Down migration
DROP INDEX idx_users_email;  -- Fails if index doesn't exist
DROP TABLE users;  -- Fails if table doesn't exist
```

#### Handle Dependencies Correctly

**Correct Order for Creation**:
1. Tables
2. Indexes
3. Triggers
4. Functions that use the tables

**Correct Order for Deletion** (reverse):
1. Functions that use the tables
2. Triggers
3. Indexes  
4. Tables

### 3. Testing Migrations

#### Test Both Directions

```bash
# Apply the migration
./migrate.exe up

# Test your application works

# Roll back the migration
./migrate.exe down

# Test your application still works

# Apply again
./migrate.exe up
```

#### Use Dry Run for Safety

```bash
# See what would be applied without actually doing it
./migrate.exe -dry-run up
```

### 4. Data Migrations

When you need to modify existing data, be extra careful:

```sql
-- Good: Handle NULL values and edge cases
UPDATE users 
SET status = 'active' 
WHERE status IS NULL OR status = '';

-- Add NOT NULL constraint after data is clean
ALTER TABLE users 
ALTER COLUMN status SET NOT NULL;
```

### 5. Large Table Migrations

For tables with lots of data:

```sql
-- Use concurrent indexes (PostgreSQL)
CREATE INDEX CONCURRENTLY idx_users_email ON users(email);

-- Add columns with defaults carefully
ALTER TABLE users ADD COLUMN status VARCHAR(20) DEFAULT 'active';
```

---

## Troubleshooting

### Common Issues and Solutions

#### 1. "Dirty database version" Error

**Problem**: A migration failed partway through.

**Solution**:
```bash
./migrate.exe repair
```

**Prevention**: Always test migrations on a copy of production data first.

#### 2. "Migration already exists" Error

**Problem**: Trying to apply a migration that's already been applied.

**Check current status**:
```bash
./migrate.exe status
```

**Solution**: The migration is already applied, no action needed.

#### 3. "Cannot rollback" Error

**Problem**: Trying to rollback a migration without a down file.

**Solution**: Create the missing down migration file or use `force` (dangerous).

#### 4. SQL Syntax Errors

**Problem**: Migration contains invalid SQL.

**Check the migration file**:
```bash
./migrate.exe validate
```

**Common fixes**:
- Check PostgreSQL function syntax (use `$$` delimiters)
- Verify table/column names exist
- Check data types are correct

#### 5. Permission Errors

**Problem**: Database user doesn't have required permissions.

**Solution**: Ensure your database user can:
- CREATE/DROP tables
- CREATE/DROP indexes
- CREATE/DROP functions
- INSERT/UPDATE/DELETE data

### Debug Mode

Use verbose mode to see detailed output:

```bash
./migrate.exe -verbose up
```

Use JSON output for programmatic processing:

```bash
./migrate.exe -format=json status
```

---

## Examples and Use Cases

### Example 1: Setting Up a New Project

```bash
# 1. Create initial schema
./migrate.exe create initial_schema

# Edit the generated files to create your base tables
# Then apply it
./migrate.exe up

# 2. Add user authentication
./migrate.exe create-from-template add_users_table create_table TableName=users
# Edit to add email, password_hash, etc.
./migrate.exe up

# 3. Add indexes for performance
./migrate.exe create-from-template add_user_indexes create_index TableName=users IndexName=idx_users_email Columns=email Unique=true
./migrate.exe up
```

### Example 2: Adding a Feature

```bash
# You're adding a blog feature to your app

# 1. Create posts table
./migrate.exe create-from-template add_posts_table create_table TableName=posts
# Edit to add title, content, author_id, etc.

# 2. Create categories table  
./migrate.exe create-from-template add_categories_table create_table TableName=categories

# 3. Add relationship
./migrate.exe create add_post_category_relationship
# Edit to add foreign keys and junction table

# Apply all changes
./migrate.exe up
```

### Example 3: Production Deployment

```bash
# On your production server

# 1. Check current status
./migrate.exe status

# 2. See what would be applied (safety check)
./migrate.exe -dry-run up

# 3. Apply migrations
./migrate.exe -verbose up

# 4. Verify everything worked
./migrate.exe status
./migrate.exe version
```

### Example 4: Hotfix Rollback

```bash
# Something went wrong, need to rollback quickly

# 1. Check current version
./migrate.exe version
# Output: Current migration version: 15

# 2. Rollback to last known good version
./migrate.exe rollback 14

# 3. Verify rollback worked
./migrate.exe status
```

---

## Command Reference

### Basic Commands

| Command | Description | Example |
|---------|-------------|---------|
| `up` | Apply all pending migrations | `./migrate.exe up` |
| `down` | Rollback one migration | `./migrate.exe down` |
| `status` | Show migration status | `./migrate.exe status` |
| `version` | Show current version | `./migrate.exe version` |
| `create <name>` | Create new migration | `./migrate.exe create add_users` |

### Advanced Commands

| Command | Description | Example |
|---------|-------------|---------|
| `to <version>` | Migrate to specific version | `./migrate.exe to 5` |
| `rollback <version>` | Rollback to specific version | `./migrate.exe rollback 3` |
| `history` | Show migration history | `./migrate.exe history` |
| `validate` | Validate migration files | `./migrate.exe validate` |
| `repair` | Fix dirty database state | `./migrate.exe repair` |
| `templates` | List available templates | `./migrate.exe templates` |

### Template Commands

| Command | Description | Example |
|---------|-------------|---------|
| `create-from-template <name> <template> [params]` | Create from template | `./migrate.exe create-from-template add_users create_table TableName=users` |

### Options

| Option | Description | Example |
|--------|-------------|---------|
| `-migrations <path>` | Set migrations directory | `./migrate.exe -migrations ./db/migrations status` |
| `-format <format>` | Output format (table/json) | `./migrate.exe -format=json status` |
| `-verbose` | Enable verbose output | `./migrate.exe -verbose up` |
| `-dry-run` | Show what would be done | `./migrate.exe -dry-run up` |
| `-help` | Show help | `./migrate.exe -help` |

### Template Parameters

#### create_table Template
- `TableName`: Name of the table to create

#### add_column Template  
- `TableName`: Target table name
- `ColumnName`: Name of new column
- `ColumnType`: SQL data type
- `NotNull`: true/false for NOT NULL constraint
- `DefaultValue`: Default value for column
- `CreateIndex`: true/false to create index

#### create_index Template
- `TableName`: Target table name
- `IndexName`: Name of the index
- `Columns`: Comma-separated column names
- `Unique`: true/false for unique constraint
- `IndexType`: Type of index (btree, gin, etc.)

---

## Conclusion

The Migration CLI is a powerful tool that helps you manage database changes safely and systematically. Start with the basic commands, practice on development databases, and gradually work up to more advanced features.

Remember the golden rules:
1. **Always test migrations** on non-production data first
2. **Use descriptive names** for your migrations
3. **Write both up and down migrations** 
4. **Check status before and after** applying changes
5. **Use dry-run** when unsure

Happy migrating! 🚀
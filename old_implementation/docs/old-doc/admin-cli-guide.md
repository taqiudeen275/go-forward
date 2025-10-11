# Go Forward Framework - Admin CLI Complete Guide

## Table of Contents

1. [Introduction](#introduction)
2. [Installation & Setup](#installation--setup)
3. [Quick Start Guide](#quick-start-guide)
4. [Environment Management](#environment-management)
5. [Admin User Management](#admin-user-management)
6. [Bootstrap & Deployment](#bootstrap--deployment)
7. [Security Features](#security-features)
8. [Advanced Usage](#advanced-usage)
9. [Troubleshooting](#troubleshooting)
10. [Best Practices](#best-practices)
11. [API Reference](#api-reference)

---

## Introduction

The Go Forward Framework Admin CLI is a powerful command-line tool designed for managing system administrators, environment configurations, and deployment operations. It provides a secure, environment-aware interface for administrative tasks with comprehensive audit logging and security features.

### Key Features

- **Hierarchical Admin Management**: System, Super, Regular, and Moderator admin levels
- **Environment-Aware Security**: Different security policies for development, staging, and production
- **Bootstrap Operations**: Framework initialization and emergency access
- **Comprehensive Auditing**: All admin actions are logged for security compliance
- **Multi-Factor Authentication**: Built-in MFA support for enhanced security
- **Configuration Management**: Backup, restore, and validation of system configurations

### Admin Hierarchy

```
System Admin (Level 1)
├── Full system access including SQL execution
├── Can create Super Admins
└── System configuration management

Super Admin (Level 2)
├── Business-level administrative capabilities
├── Can create Regular Admins
└── Manage all tables and authentication

Regular Admin (Level 3)
├── Limited administrative access
├── Assigned table management
└── User management within scope

Moderator (Level 4)
├── Read-only access
├── Content moderation
└── Basic reporting capabilities
```

---

## Installation & Setup

### Prerequisites

- Go 1.21 or higher
- PostgreSQL database
- Valid configuration file (`config.yaml`)

### Building the CLI

```bash
# Clone the repository
git clone <repository-url>
cd go-forward

# Build the admin CLI
go build -o admin ./cmd/admin

# Make it executable (Linux/macOS)
chmod +x admin

# Verify installation
./admin --help
```

### Configuration

The CLI uses the same configuration as the main application. Ensure your `config.yaml` is properly configured:

```yaml
database:
  host: localhost
  port: 5432
  name: goforward
  user: postgres
  password: your_password
  ssl_mode: disable

auth:
  jwt_secret: your-secure-jwt-secret
  jwt_expiration: 24h
  refresh_expiration: 168h
```

### Database Setup

Ensure all migrations are applied before using the CLI:

```bash
# Run migrations
./migrate up

# Verify migration status
./migrate status
```

---

## Quick Start Guide

### 1. Environment Detection

First, check your current environment:

```bash
# Detect current environment
./admin env detect

# Output:
# Detected Environment: development
# Environment Indicators:
#   database_host: localhost
#   server_host: localhost
#   server_port: 8080
```

### 2. Create Your First System Admin

```bash
# Create a system administrator
./admin admin create-system-admin \
  --email admin@yourcompany.com \
  --username sysadmin \
  --password SecurePassword123!

# For production environments, you'll see additional security prompts
```

### 3. Validate Your Setup

```bash
# Validate deployment configuration
./admin bootstrap validate-deployment

# Check environment-specific security policies
./admin env validate
```

### 4. List Administrators

```bash
# List all administrators
./admin admin list

# List with specific filters
./admin admin list --level system_admin --show-inactive
```

---

## Environment Management

The CLI automatically detects your deployment environment and applies appropriate security policies.

### Environment Detection

```bash
# Basic environment detection
./admin env detect

# Verbose output with all indicators
./admin env detect --verbose

# JSON output for scripting
./admin env detect --format json
```

### Environment Types

#### Development Environment
- **Detection**: `localhost` database, development environment variables
- **Security**: Relaxed policies for testing
- **Features**: Simplified admin operations, basic password validation

#### Staging Environment  
- **Detection**: Staging-specific hostnames or environment variables
- **Security**: Moderate security policies
- **Features**: Production-like security testing

#### Production Environment
- **Detection**: Production hostnames, cloud service indicators
- **Security**: Strict security policies with confirmations
- **Features**: MFA requirements, comprehensive audit logging

### Environment Validation

```bash
# Validate current environment
./admin env validate

# Validate specific environment
./admin env validate --environment production

# Auto-fix configuration issues
./admin env validate --fix

# Dry run to see what would be fixed
./admin env validate --fix --dry-run
```

### Security Policies

```bash
# List security policies for current environment
./admin env list-policies

# List policies for specific environment
./admin env list-policies --environment production

# Apply security policies
./admin env apply-policies

# Apply specific policy
./admin env apply-policies --policy strong_passwords

# Force application without prompts
./admin env apply-policies --force
```

---

## Admin User Management

### Creating Administrators

#### System Administrator
```bash
# Interactive creation (prompts for details)
./admin admin create-system-admin

# Non-interactive with all parameters
./admin admin create-system-admin \
  --email sysadmin@company.com \
  --username sysadmin \
  --password SecurePassword123! \
  --force

# Dry run to see what would be created
./admin admin create-system-admin \
  --email test@company.com \
  --username testadmin \
  --dry-run
```

**System Admin Capabilities:**
- SQL execution and database management
- System configuration access
- Create other administrators
- Full framework access
- Emergency system recovery

### Promoting Users

```bash
# Promote user to admin level
./admin admin promote \
  --user-id 12345678-1234-1234-1234-123456789012 \
  --to-level super_admin \
  --reason "Business requirements"

# Available levels: moderator, regular_admin, super_admin, system_admin

# Dry run promotion
./admin admin promote \
  --user-id 12345678-1234-1234-1234-123456789012 \
  --to-level regular_admin \
  --reason "Testing promotion" \
  --dry-run
```

### Demoting Administrators

```bash
# Demote to lower admin level
./admin admin demote \
  --user-id 12345678-1234-1234-1234-123456789012 \
  --to-level moderator \
  --reason "Role adjustment"

# Remove admin privileges entirely
./admin admin demote \
  --user-id 12345678-1234-1234-1234-123456789012 \
  --reason "No longer requires admin access"

# Force demotion without confirmation
./admin admin demote \
  --user-id 12345678-1234-1234-1234-123456789012 \
  --to-level regular_admin \
  --force
```

### Listing Administrators

```bash
# List all administrators
./admin admin list

# Filter by admin level
./admin admin list --level system_admin

# Include inactive administrators
./admin admin list --show-inactive

# JSON output for processing
./admin admin list --format json

# Verbose output with capabilities
./admin admin list --verbose
```

---

## Bootstrap & Deployment

### Framework Initialization

```bash
# Initialize framework for first deployment
./admin bootstrap init \
  --admin-email admin@company.com \
  --admin-username admin \
  --admin-password SecurePassword123!

# Skip database migrations during init
./admin bootstrap init \
  --admin-email admin@company.com \
  --admin-username admin \
  --skip-migrations

# Force initialization (overwrite existing)
./admin bootstrap init \
  --admin-email admin@company.com \
  --admin-username admin \
  --force
```

### Emergency Access

```bash
# Create emergency access (1 hour default)
./admin bootstrap emergency-access \
  --email emergency@company.com \
  --reason "System recovery after outage"

# Custom duration
./admin bootstrap emergency-access \
  --email emergency@company.com \
  --reason "Database maintenance" \
  --duration 2h

# Emergency access in production (requires confirmation)
./admin bootstrap emergency-access \
  --email emergency@company.com \
  --reason "Critical system issue" \
  --duration 30m
```

### Deployment Validation

```bash
# Basic deployment validation
./admin bootstrap validate-deployment

# Comprehensive validation with performance metrics
./admin bootstrap validate-deployment --comprehensive

# Auto-fix deployment issues
./admin bootstrap validate-deployment --fix

# Dry run validation
./admin bootstrap validate-deployment --comprehensive --dry-run
```

### Configuration Management

#### Backup Configuration

```bash
# Create configuration backup
./admin bootstrap backup-config

# Custom output file
./admin bootstrap backup-config --output backup-2024-01-15.json

# Include specific sections
./admin bootstrap backup-config \
  --include config,security,admins \
  --output full-backup.json

# Verbose backup process
./admin bootstrap backup-config --verbose
```

#### Restore Configuration

```bash
# Restore from backup
./admin bootstrap restore-config --backup backup-2024-01-15.json

# Restore specific sections
./admin bootstrap restore-config \
  --backup backup-2024-01-15.json \
  --sections config,security

# Force restore without confirmation
./admin bootstrap restore-config \
  --backup backup-2024-01-15.json \
  --force

# Dry run restore
./admin bootstrap restore-config \
  --backup backup-2024-01-15.json \
  --dry-run
```

---

## Security Features

### Environment-Specific Security

#### Development Environment
```bash
# Relaxed security for development
./admin env detect
# Output: Detected Environment: development
# Security Requirements:
#   • Basic password validation
#   • Development-friendly configurations allowed
#   • Simplified admin operations for testing
```

#### Production Environment
```bash
# Set production environment
export GOFORWARD_ENVIRONMENT=production

./admin env detect
# Output: Detected Environment: production
# Security Requirements:
#   • Strong password policies must be enforced
#   • Multi-factor authentication required for system admins
#   • Database connections must use SSL/TLS
#   • JWT secrets must be cryptographically secure
#   • Rate limiting must be enabled
#   • Audit logging must be comprehensive
#   • Admin operations require confirmation
```

### Production Security Confirmations

When operating in production, the CLI requires explicit confirmations:

```bash
# Creating system admin in production
./admin admin create-system-admin \
  --email admin@company.com \
  --username admin

# Output:
# ⚠️  WARNING: Creating system admin in PRODUCTION environment
# System admins have unrestricted access to:
#   - SQL execution and database management
#   - System configuration and security settings
#   - All user data and administrative functions
# 
# Type 'CREATE SYSTEM ADMIN' to confirm: CREATE SYSTEM ADMIN
```

### Multi-Factor Authentication

```bash
# Enable MFA for system admin (future feature)
./admin mfa enable --user-id 12345678-1234-1234-1234-123456789012

# Generate backup codes
./admin mfa backup-codes --user-id 12345678-1234-1234-1234-123456789012

# Disable MFA
./admin mfa disable --user-id 12345678-1234-1234-1234-123456789012
```

---

## Advanced Usage

### Scripting and Automation

#### JSON Output for Processing

```bash
# Get environment info as JSON
./admin env detect --format json | jq '.environment'

# List admins and process with jq
./admin admin list --format json | jq '.[] | select(.admin_level == "system_admin")'

# Deployment validation results
./admin bootstrap validate-deployment --format json | jq '.is_healthy'
```

#### Batch Operations

```bash
#!/bin/bash
# Script to create multiple admins

ADMINS=(
  "john.doe@company.com:johndoe:super_admin"
  "jane.smith@company.com:janesmith:regular_admin"
  "bob.wilson@company.com:bobwilson:moderator"
)

for admin in "${ADMINS[@]}"; do
  IFS=':' read -r email username level <<< "$admin"
  
  # Create user first (using main application API)
  # Then promote to admin level
  ./admin admin promote \
    --user-id $(get_user_id_by_email "$email") \
    --to-level "$level" \
    --reason "Batch admin creation"
done
```

### Configuration File Usage

```bash
# Use custom configuration file
./admin --config /path/to/custom-config.yaml env detect

# Override with environment variables
GOFORWARD_DATABASE_HOST=prod-db.company.com ./admin env detect
```

### Verbose Logging

```bash
# Enable verbose output for debugging
./admin --verbose admin create-system-admin \
  --email debug@company.com \
  --username debugadmin

# Combine with dry-run for testing
./admin --verbose --dry-run bootstrap init \
  --admin-email test@company.com \
  --admin-username testadmin
```

### Global Flags

All commands support these global flags:

```bash
--config string     # Path to configuration file
--verbose          # Enable verbose output
--dry-run          # Show what would be done without executing
--format string    # Output format: table, json (default "table")
```

---

## Troubleshooting

### Common Issues

#### 1. Database Connection Issues

```bash
# Symptom: "failed to initialize database"
# Solution: Check database configuration and connectivity

# Validate database connection
./admin bootstrap validate-deployment

# Check configuration
./admin --verbose env detect
```

#### 2. Migration Issues

```bash
# Symptom: "admin role not found: System Admin"
# Solution: Ensure migrations are applied

# Check migration status
./migrate status

# Apply missing migrations
./migrate up
```

#### 3. Permission Issues

```bash
# Symptom: "user is not an admin"
# Solution: Verify user has admin role assigned

# Check user's admin status
./admin admin list --format json | jq '.[] | select(.email == "user@company.com")'
```

#### 4. Environment Detection Issues

```bash
# Symptom: Wrong environment detected
# Solution: Set explicit environment variable

export GOFORWARD_ENVIRONMENT=production
./admin env detect
```

### Debug Mode

```bash
# Enable maximum verbosity
./admin --verbose --dry-run admin create-system-admin \
  --email debug@test.com \
  --username debuguser

# Check configuration loading
./admin --verbose env detect
```

### Log Analysis

```bash
# Check admin access logs (requires database access)
psql -d goforward -c "
SELECT 
  timestamp,
  action,
  outcome,
  user_id,
  details
FROM admin_access_logs 
ORDER BY timestamp DESC 
LIMIT 10;
"
```

---

## Best Practices

### Security Best Practices

1. **Environment Separation**
   ```bash
   # Always verify environment before operations
   ./admin env detect
   
   # Use different configurations for each environment
   ./admin --config prod-config.yaml env detect
   ```

2. **Principle of Least Privilege**
   ```bash
   # Start with lowest required level
   ./admin admin promote --user-id $USER_ID --to-level moderator
   
   # Upgrade only when necessary
   ./admin admin promote --user-id $USER_ID --to-level regular_admin
   ```

3. **Regular Auditing**
   ```bash
   # Regular admin list review
   ./admin admin list --format json > admin-audit-$(date +%Y%m%d).json
   
   # Environment validation
   ./admin env validate --comprehensive
   ```

### Operational Best Practices

1. **Use Dry Run First**
   ```bash
   # Always test with dry-run first
   ./admin --dry-run admin create-system-admin --email test@company.com
   
   # Then execute the actual command
   ./admin admin create-system-admin --email test@company.com
   ```

2. **Backup Before Changes**
   ```bash
   # Create backup before major changes
   ./admin bootstrap backup-config --output pre-change-backup.json
   
   # Make changes
   ./admin admin promote --user-id $USER_ID --to-level super_admin
   ```

3. **Document Admin Changes**
   ```bash
   # Always provide reasons for admin changes
   ./admin admin promote \
     --user-id $USER_ID \
     --to-level super_admin \
     --reason "Promoted for Q4 project management responsibilities"
   ```

### Automation Best Practices

1. **Script Safety**
   ```bash
   #!/bin/bash
   set -euo pipefail  # Exit on error, undefined vars, pipe failures
   
   # Verify environment first
   ENV=$(./admin env detect --format json | jq -r '.environment')
   if [[ "$ENV" != "development" ]]; then
     echo "This script should only run in development"
     exit 1
   fi
   ```

2. **Error Handling**
   ```bash
   #!/bin/bash
   
   if ! ./admin admin create-system-admin --email admin@test.com --force; then
     echo "Failed to create admin, checking if already exists..."
     ./admin admin list --format json | jq '.[] | select(.email == "admin@test.com")'
   fi
   ```

---

## API Reference

### Global Commands

#### Help
```bash
./admin --help                    # Show main help
./admin admin --help              # Show admin subcommand help
./admin admin create-system-admin --help  # Show specific command help
```

#### Version
```bash
./admin version                   # Show CLI version (if implemented)
```

### Environment Commands (`./admin env`)

#### `detect`
Detect current deployment environment.

**Usage:**
```bash
./admin env detect [flags]
```

**Flags:**
- `--format string`: Output format (table, json)
- `--verbose`: Show detailed environment indicators

**Examples:**
```bash
./admin env detect
./admin env detect --format json
./admin env detect --verbose
```

#### `validate`
Validate environment configuration and security requirements.

**Usage:**
```bash
./admin env validate [flags]
```

**Flags:**
- `--environment string`: Specific environment to validate
- `--fix`: Attempt to fix configuration issues
- `--comprehensive`: Perform comprehensive validation

**Examples:**
```bash
./admin env validate
./admin env validate --environment production
./admin env validate --fix --dry-run
```

#### `list-policies`
List security policies for environment.

**Usage:**
```bash
./admin env list-policies [flags]
```

**Flags:**
- `--environment string`: Environment to list policies for

**Examples:**
```bash
./admin env list-policies
./admin env list-policies --environment production
```

#### `apply-policies`
Apply security policies to environment.

**Usage:**
```bash
./admin env apply-policies [flags]
```

**Flags:**
- `--environment string`: Target environment
- `--policy string`: Specific policy to apply
- `--force`: Skip confirmation prompts

**Examples:**
```bash
./admin env apply-policies
./admin env apply-policies --policy strong_passwords
./admin env apply-policies --force
```

### Admin Commands (`./admin admin`)

#### `create-system-admin`
Create a new system administrator.

**Usage:**
```bash
./admin admin create-system-admin [flags]
```

**Flags:**
- `--email string`: Admin email address
- `--username string`: Admin username
- `--password string`: Admin password (prompts if not provided)
- `--force`: Skip confirmation prompts

**Examples:**
```bash
./admin admin create-system-admin
./admin admin create-system-admin --email admin@company.com --username admin
./admin admin create-system-admin --email admin@company.com --username admin --force
```

#### `promote`
Promote a user to admin or upgrade admin level.

**Usage:**
```bash
./admin admin promote [flags]
```

**Flags:**
- `--user-id string`: ID of user to promote (required)
- `--to-level string`: Admin level to promote to (required)
- `--reason string`: Reason for promotion
- `--force`: Skip confirmation prompts

**Valid Levels:** `moderator`, `regular_admin`, `super_admin`, `system_admin`

**Examples:**
```bash
./admin admin promote --user-id 12345 --to-level super_admin --reason "Business needs"
./admin admin promote --user-id 12345 --to-level regular_admin --force
```

#### `demote`
Demote an admin to lower level or remove admin status.

**Usage:**
```bash
./admin admin demote [flags]
```

**Flags:**
- `--user-id string`: ID of admin to demote (required)
- `--to-level string`: Admin level to demote to (use 'user' to remove admin status)
- `--reason string`: Reason for demotion
- `--force`: Skip confirmation prompts

**Examples:**
```bash
./admin admin demote --user-id 12345 --to-level moderator --reason "Role change"
./admin admin demote --user-id 12345 --reason "No longer admin"
```

#### `list`
List all administrators.

**Usage:**
```bash
./admin admin list [flags]
```

**Flags:**
- `--level string`: Filter by admin level
- `--show-inactive`: Include inactive admins

**Examples:**
```bash
./admin admin list
./admin admin list --level system_admin
./admin admin list --show-inactive --format json
```

### Bootstrap Commands (`./admin bootstrap`)

#### `init`
Initialize the Go Forward framework.

**Usage:**
```bash
./admin bootstrap init [flags]
```

**Flags:**
- `--admin-email string`: System administrator email
- `--admin-username string`: System administrator username
- `--admin-password string`: System administrator password
- `--skip-migrations`: Skip database migrations
- `--force`: Force initialization even if already initialized

**Examples:**
```bash
./admin bootstrap init --admin-email admin@company.com --admin-username admin
./admin bootstrap init --skip-migrations --force
```

#### `emergency-access`
Create emergency access for system recovery.

**Usage:**
```bash
./admin bootstrap emergency-access [flags]
```

**Flags:**
- `--email string`: Emergency access email
- `--reason string`: Reason for emergency access (required)
- `--duration string`: Access duration (default "1h")
- `--force`: Skip confirmation prompts

**Examples:**
```bash
./admin bootstrap emergency-access --email emergency@company.com --reason "System outage"
./admin bootstrap emergency-access --email emergency@company.com --reason "Maintenance" --duration 2h
```

#### `validate-deployment`
Validate deployment configuration and health.

**Usage:**
```bash
./admin bootstrap validate-deployment [flags]
```

**Flags:**
- `--comprehensive`: Perform comprehensive validation including performance tests
- `--fix`: Attempt to automatically fix deployment issues

**Examples:**
```bash
./admin bootstrap validate-deployment
./admin bootstrap validate-deployment --comprehensive
./admin bootstrap validate-deployment --fix --dry-run
```

#### `backup-config`
Backup framework configuration and security settings.

**Usage:**
```bash
./admin bootstrap backup-config [flags]
```

**Flags:**
- `--output string`: Output file path (auto-generated if not specified)
- `--include strings`: Sections to include in backup (default [config,security,admins])

**Examples:**
```bash
./admin bootstrap backup-config
./admin bootstrap backup-config --output my-backup.json
./admin bootstrap backup-config --include config,security
```

#### `restore-config`
Restore framework configuration from backup.

**Usage:**
```bash
./admin bootstrap restore-config [flags]
```

**Flags:**
- `--backup string`: Path to backup file (required)
- `--sections strings`: Sections to restore (default [config,security,admins])
- `--force`: Skip confirmation prompts

**Examples:**
```bash
./admin bootstrap restore-config --backup my-backup.json
./admin bootstrap restore-config --backup my-backup.json --sections config,security
./admin bootstrap restore-config --backup my-backup.json --force
```

---

## Exit Codes

The CLI uses standard exit codes:

- `0`: Success
- `1`: General error
- `2`: Misuse of shell command
- `130`: Script terminated by Control-C

---

## Support and Contributing

### Getting Help

1. **Built-in Help**: Use `--help` flag with any command
2. **Verbose Mode**: Use `--verbose` for detailed output
3. **Dry Run**: Use `--dry-run` to test commands safely

### Reporting Issues

When reporting issues, include:

1. **Command executed**: Full command with flags
2. **Environment**: Output of `./admin env detect --verbose`
3. **Error message**: Complete error output
4. **Configuration**: Relevant parts of your config (sanitized)

### Contributing

1. **Testing**: Always test with `--dry-run` first
2. **Documentation**: Update this guide for new features
3. **Security**: Follow security best practices for admin operations

---

*This documentation covers the Go Forward Framework Admin CLI v1.0. For the latest updates and features, check the project repository.*
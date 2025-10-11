# CLI Admin Management System - Comprehensive Guide

## Table of Contents
1. [Overview](#overview)
2. [Installation & Setup](#installation--setup)
3. [Admin Hierarchy System](#admin-hierarchy-system)
4. [Core Commands](#core-commands)
5. [Emergency Access System](#emergency-access-system)
6. [Security Features](#security-features)
7. [Best Practices](#best-practices)
8. [Troubleshooting](#troubleshooting)
9. [API Reference](#api-reference)

---

## Overview

The CLI Admin Management System is a comprehensive command-line interface for managing administrators in the Unified Go Forward Framework. It provides secure, hierarchical admin management with emergency access capabilities, comprehensive audit logging, and production-ready security controls.

### Key Features

- **Hierarchical Admin System**: Four-tier admin hierarchy (System Admin, Super Admin, Regular Admin, Moderator)
- **Admin Promotion/Demotion**: Seamless admin level changes with proper validation
- **Emergency Access**: Time-limited emergency access with IP restrictions
- **Security-First Design**: Production environment detection and enhanced security
- **Comprehensive Audit**: Complete audit trails for all admin operations
- **Single Executable**: All functionality in one binary (`go-forward.exe`)

### Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    CLI Admin Management                     │
├─────────────────────────────────────────────────────────────┤
│  System Admin Creation  │  Admin Promotion/Demotion        │
│  Emergency Access       │  Admin Listing & Status          │
│  Audit Logging         │  Security Validation             │
└─────────────────────────────────────────────────────────────┘
```

---

## Installation & Setup

### Prerequisites

- PostgreSQL 13+ database
- Go 1.21+ (for building from source)
- Network access to database server

### Quick Start

1. **Download/Build the Binary**
   ```bash
   # Option 1: Build from source
   go build -o go-forward cmd/main.go
   
   # Option 2: Use pre-built binary
   # Download go-forward.exe from releases
   ```

2. **Configure Database Connection**
   ```yaml
   # config.yaml
   database:
     host: "localhost"
     port: 5432
     name: "goforward"
     user: "postgres"
     password: "your-password"
     ssl_mode: "disable"
   ```

3. **Run Database Migrations**
   ```bash
   ./go-forward migrate up
   ```

4. **Verify Installation**
   ```bash
   ./go-forward admin --help
   ```

### Environment Variables

```bash
# Database Configuration
export GF_DATABASE_HOST="localhost"
export GF_DATABASE_PORT="5432"
export GF_DATABASE_NAME="goforward"
export GF_DATABASE_USER="postgres"
export GF_DATABASE_PASSWORD="your-password"

# Security Configuration
export GF_AUTH_JWT_SECRET="your-jwt-secret-32-chars-min"
export GF_ENVIRONMENT="production"  # or "development"
```

---

## Admin Hierarchy System

### Hierarchy Levels

The system implements a four-tier hierarchical admin structure:

```
┌─────────────────┐
│  System Admin   │ ← Level 4 (Highest)
├─────────────────┤
│   Super Admin   │ ← Level 3
├─────────────────┤
│ Regular Admin   │ ← Level 2
├─────────────────┤
│   Moderator     │ ← Level 1
└─────────────────┘
```

### Capabilities Matrix

| Capability | System Admin | Super Admin | Regular Admin | Moderator |
|------------|--------------|-------------|---------------|-----------|
| **System Management** |
| Access SQL Editor | ✅ | ❌ | ❌ | ❌ |
| Manage Database | ✅ | ❌ | ❌ | ❌ |
| Manage System Config | ✅ | ❌ | ❌ | ❌ |
| Install Plugins | ✅ | ❌ | ❌ | ❌ |
| Modify Security Config | ✅ | ❌ | ❌ | ❌ |
| **Admin Management** |
| Create System Admins | ✅ | ❌ | ❌ | ❌ |
| Create Super Admins | ✅ | ❌ | ❌ | ❌ |
| Create Regular Admins | ✅ | ✅ | ❌ | ❌ |
| Create Moderators | ✅ | ✅ | ✅ | ❌ |
| **Content & Users** |
| Manage All Tables | ✅ | ✅ | ❌* | ❌ |
| Manage Users | ✅ | ✅ | ✅ | ❌ |
| Manage Content | ✅ | ✅ | ✅ | ❌ |
| Export Data | ✅ | ✅ | ✅ | ❌ |
| **Monitoring** |
| View All Logs | ✅ | ✅ | ❌ | ❌ |
| View Reports | ✅ | ✅ | ✅ | ✅ |
| Moderate Content | ✅ | ✅ | ✅ | ✅ |

*Regular Admins can only access assigned tables

### Promotion Rules

- **System Admins**: Can promote anyone to any level
- **Super Admins**: Can promote to Super Admin and below
- **Regular Admins**: Can promote to Regular Admin and below
- **Moderators**: Can promote to Moderator level only

---

## Core Commands

### System Admin Creation

Create system administrators with full framework access.

```bash
# Interactive mode
./go-forward admin create-system-admin

# With parameters
./go-forward admin create-system-admin \
  --email admin@company.com \
  --username admin \
  --password SecurePassword123!

# Production mode (requires --force)
./go-forward admin create-system-admin \
  --email admin@company.com \
  --force
```

**Parameters:**
- `--email, -e`: Admin email address (required)
- `--username, -u`: Admin username (optional)
- `--password, -p`: Admin password (prompts if not provided)
- `--force, -f`: Skip production environment safety checks

**Examples:**

```bash
# Create system admin interactively
$ ./go-forward admin create-system-admin
Enter admin email: admin@company.com
Enter admin username (optional): admin
Enter admin password: [hidden]
Confirm admin password: [hidden]
✅ Successfully created system admin: admin@company.com

# Promote existing user
$ ./go-forward admin create-system-admin --email existing@company.com
User with email existing@company.com exists. Promote to system admin? (y/N): y
✅ Successfully promoted user existing@company.com to system admin
```

### Admin Listing

Display all administrators with their roles and status.

```bash
# List all admins
./go-forward admin list

# Filter by admin level
./go-forward admin list --level system_admin

# Search by email/username
./go-forward admin list --search john

# Limit results
./go-forward admin list --limit 10
```

**Parameters:**
- `--level, -l`: Filter by admin level
- `--search, -s`: Search term for email/username
- `--limit`: Maximum number of results (default: 50)

**Output Format:**
```
Found 3 administrator(s):

ID                                   Email                     Level           Last Login           Status
------------------------------------------------------------------------------------------------------------------------
0bd32aba-58e9-497c-b889-07f22ae83563 admin@company.com         system_admin    2025-10-11 14:30     ✅ Active
c62278ef-86ce-4786-9dbe-8f313e2fa6af manager@company.com       super_admin     Never                ✅ Active
1356cc18-cbfb-4c7b-82bb-b77f3bd7eff4 user@company.com          regular_admin   Never                🔒 Locked
```

### Admin Promotion

Promote users to admin levels or upgrade existing admins to higher levels.

```bash
# Promote user to regular admin
./go-forward admin promote user@company.com \
  --level regular_admin \
  --reason "New team lead" \
  --tables users,posts,comments

# Upgrade existing admin
./go-forward admin promote manager@company.com \
  --level super_admin \
  --reason "Department promotion"

# Promote to system admin
./go-forward admin promote admin@company.com \
  --level system_admin \
  --reason "CTO appointment"
```

**Parameters:**
- `--level, -l`: Target admin level (default: regular_admin)
- `--reason, -r`: Reason for promotion
- `--tables, -t`: Assigned tables for regular admins

**Valid Admin Levels:**
- `system_admin`: Full system access
- `super_admin`: Business logic management
- `regular_admin`: User and content management
- `moderator`: Content moderation only

**Examples:**

```bash
# Promote new user to admin
$ ./go-forward admin promote newuser@company.com --level regular_admin --reason "Team expansion"
⬆️ Promoting user to regular_admin
✅ Successfully promoted user newuser@company.com to regular_admin

# Upgrade existing admin
$ ./go-forward admin promote manager@company.com --level super_admin --reason "Department head"
🔄 Promoting existing regular_admin to super_admin
✅ Successfully promoted admin manager@company.com to super_admin

# Error: Same level promotion
$ ./go-forward admin promote admin@company.com --level system_admin
Error: user is already at system_admin level. Use demote command to lower admin level or promote to a higher level
```

### Admin Demotion

Demote admins to lower levels or remove admin privileges entirely.

```bash
# Demote to lower level
./go-forward admin demote admin@company.com \
  --level super_admin \
  --reason "Role change"

# Remove admin privileges
./go-forward admin demote user@company.com \
  --reason "No longer needed"
```

**Parameters:**
- `--level, -l`: New admin level (leave empty to remove admin privileges)
- `--reason, -r`: Reason for demotion

**Examples:**

```bash
# Demote to lower level
$ ./go-forward admin demote admin@company.com --level super_admin --reason "Restructuring"
🔄 Demoting admin@company.com from system_admin to super_admin
✅ Successfully demoted admin admin@company.com to super_admin

# Remove admin privileges
$ ./go-forward admin demote user@company.com --reason "Role ended"
🔄 Removing admin privileges from user@company.com (current level: moderator)
✅ Successfully removed admin privileges from user@company.com

# Error: Invalid upgrade attempt
$ ./go-forward admin demote manager@company.com --level system_admin
Error: new level system_admin is not lower than current level super_admin. Use promote command for upgrades
```

---

## Emergency Access System

The Emergency Access System provides secure, time-limited administrative access for emergency situations such as system recovery, critical maintenance, or security incidents.

### Emergency Access Creation

Create time-limited emergency access tokens with optional IP restrictions.

```bash
# Basic emergency access
./go-forward admin create-emergency-access \
  --reason "Database recovery after outage" \
  --duration 2h \
  --level system_admin

# With IP restriction
./go-forward admin create-emergency-access \
  --reason "Security incident response" \
  --duration 30m \
  --level super_admin \
  --ip 192.168.1.100
```

**Parameters:**
- `--reason, -r`: Reason for emergency access (required)
- `--duration, -d`: Access duration (default: 1h, max: 24h)
- `--level, -l`: Admin level for emergency access (default: system_admin)
- `--ip`: Restrict access to specific IP address (optional)

**Duration Format:**
- `30m` - 30 minutes
- `2h` - 2 hours
- `1h30m` - 1 hour 30 minutes
- `24h` - 24 hours (maximum)

**Output:**
```bash
$ ./go-forward admin create-emergency-access --reason "System maintenance" --duration 2h
✅ Emergency access created successfully
🆔 Access ID: f0daf26c-96e9-4370-92b4-17769a0c5279
🔑 Access Token: 8176f148-ebe8-4aa9-9375-246e3e3137b9
⏰ Expires At: 2025-10-11 16:53:12 UTC
🔒 Admin Level: system_admin

⚠️  Store this access token securely. It cannot be retrieved again.
```

### Emergency Access Listing

View all emergency access entries with their status and details.

```bash
# List all emergency access
./go-forward admin list-emergency-access

# Show only active entries
./go-forward admin list-emergency-access --active

# Limit results
./go-forward admin list-emergency-access --limit 5
```

**Parameters:**
- `--active, -a`: Show only active (non-expired, non-revoked) entries
- `--limit`: Maximum number of results (default: 20)

**Output:**
```
Found 2 emergency access entr(ies):

ID                                   Level           Created              Expires              Status    
---------------------------------------------------------------------------------------------------------
ab184553-1fc1-4cbc-bd22-ecd8c9289693 super_admin     2025-10-11 14:53     2025-10-11 15:23     🟢 Active
f0daf26c-96e9-4370-92b4-17769a0c5279 system_admin    2025-10-11 14:53     2025-10-11 16:53     🚫 Revoked
```

**Status Indicators:**
- 🟢 **Active**: Valid and usable
- 🚫 **Revoked**: Manually revoked
- ⏰ **Expired**: Time limit exceeded
- ✅ **Used**: Successfully used

### Emergency Access Revocation

Immediately revoke active emergency access tokens.

```bash
# Revoke emergency access
./go-forward admin revoke-emergency-access f0daf26c-96e9-4370-92b4-17769a0c5279
```

**Parameters:**
- `access-id`: UUID of the emergency access to revoke

**Example:**
```bash
$ ./go-forward admin revoke-emergency-access f0daf26c-96e9-4370-92b4-17769a0c5279
✅ Emergency access f0daf26c-96e9-4370-92b4-17769a0c5279 has been revoked
```

### Emergency Access Security

**Security Features:**
- **Time Limits**: Maximum 24-hour duration
- **IP Restrictions**: Optional network-level access control
- **Audit Trails**: Complete logging of creation, usage, and revocation
- **System Admin Only**: Only system admins can manage emergency access
- **Unique Tokens**: UUID-based tokens prevent guessing attacks
- **Automatic Cleanup**: Expired entries are automatically marked

**Use Cases:**
- Database recovery operations
- Security incident response
- Critical system maintenance
- Emergency user account recovery
- Disaster recovery scenarios

---

## Security Features

### Environment Detection

The CLI automatically detects the environment and applies appropriate security measures:

**Development Mode:**
- Simplified admin creation
- Basic validation only
- Relaxed security policies
- Detailed error messages

**Production Mode:**
- Enhanced security validation
- Stricter password requirements
- Additional confirmation prompts
- Comprehensive audit logging
- MFA recommendations

### Authentication & Authorization

**Admin Hierarchy Enforcement:**
- Strict hierarchy validation
- Capability-based permissions
- Context-aware authorization
- Self-operation prevention

**Security Validation:**
- Password strength requirements
- Email format validation
- Uniqueness constraints
- Rate limiting protection

### Audit Logging

All admin operations are comprehensively logged:

```json
{
  "user_id": "uuid",
  "action": "admin_promote",
  "resource": "user",
  "resource_id": "target_user_uuid",
  "details": {
    "admin_level": "super_admin",
    "promoted_by": "promoter_uuid",
    "reason": "Department promotion",
    "assigned_tables": ["users", "posts"]
  },
  "ip_address": "192.168.1.100",
  "user_agent": "CLI/1.0",
  "severity": "high",
  "timestamp": "2025-10-11T14:53:12Z"
}
```

**Audit Events:**
- Admin creation/promotion/demotion
- Emergency access creation/usage/revocation
- Authentication attempts
- Permission changes
- Security violations

### Row Level Security (RLS)

Database-level security policies ensure data isolation:

```sql
-- Users can only see their own records
CREATE POLICY users_own_record ON users
    FOR ALL TO public
    USING (id = current_setting('app.current_user_id')::UUID);

-- System admins can see all users
CREATE POLICY users_system_admin ON users
    FOR ALL TO public
    USING (EXISTS (
        SELECT 1 FROM users u 
        WHERE u.id = current_setting('app.current_user_id')::UUID 
        AND u.admin_level = 'system_admin'
    ));
```

---

## Best Practices

### Admin Management

**1. Principle of Least Privilege**
```bash
# Start with lowest necessary level
./go-forward admin promote user@company.com --level moderator

# Upgrade as needed
./go-forward admin promote user@company.com --level regular_admin --reason "Increased responsibilities"
```

**2. Regular Admin Audits**
```bash
# Review all admins monthly
./go-forward admin list > admin_audit_$(date +%Y%m%d).txt

# Check for inactive admins
./go-forward admin list --search "Never" | grep "Last Login"
```

**3. Proper Documentation**
```bash
# Always provide reasons for changes
./go-forward admin promote user@company.com \
  --level super_admin \
  --reason "Promoted to Engineering Manager - Ticket #12345"
```

### Emergency Access

**1. Time-Limited Access**
```bash
# Use shortest necessary duration
./go-forward admin create-emergency-access \
  --reason "Critical database fix" \
  --duration 30m  # Not 24h
```

**2. IP Restrictions**
```bash
# Restrict to known secure locations
./go-forward admin create-emergency-access \
  --reason "Remote incident response" \
  --duration 2h \
  --ip 203.0.113.100
```

**3. Immediate Revocation**
```bash
# Revoke immediately after use
./go-forward admin revoke-emergency-access <access-id>
```

### Security

**1. Production Environment**
```bash
# Always use --force flag consciously in production
./go-forward admin create-system-admin --email admin@company.com --force

# Enable MFA for all admins
# (Done through web dashboard after CLI creation)
```

**2. Regular Cleanup**
```bash
# Review and clean emergency access
./go-forward admin list-emergency-access | grep "Expired\|Revoked"
```

**3. Backup Admin Access**
```bash
# Maintain multiple system admins
./go-forward admin list --level system_admin
# Ensure at least 2-3 system admins exist
```

---

## Troubleshooting

### Common Issues

**1. Database Connection Errors**
```bash
Error: failed to connect to database: connection refused

# Solutions:
# - Check database is running
# - Verify connection parameters
# - Check network connectivity
# - Validate credentials
```

**2. Permission Denied**
```bash
Error: insufficient privileges to promote this admin

# Solutions:
# - Check your admin level
# - Verify hierarchy rules
# - Use higher-level admin account
# - Check target admin level
```

**3. Migration Issues**
```bash
Error: relation "emergency_access" does not exist

# Solution:
./go-forward migrate up
```

**4. Production Safety Checks**
```bash
Error: Production environment detected! Use --force flag

# Solutions:
# - Add --force flag if intentional
# - Verify environment configuration
# - Use development environment for testing
```

### Diagnostic Commands

**Check System Status:**
```bash
# Verify database connection
./go-forward migrate status

# Check admin hierarchy
./go-forward admin list --level system_admin

# Review emergency access
./go-forward admin list-emergency-access --active
```

**Validate Configuration:**
```bash
# Check environment detection
echo $GF_ENVIRONMENT

# Verify database settings
./go-forward migrate status | head -5
```

### Recovery Procedures

**1. Lost System Admin Access**
```bash
# Create new system admin (requires database access)
./go-forward admin create-system-admin \
  --email recovery@company.com \
  --force

# Or use emergency access if available
./go-forward admin list-emergency-access --active
```

**2. Locked Admin Account**
```bash
# Use different system admin to unlock
./go-forward admin promote locked-admin@company.com \
  --level system_admin \
  --reason "Account recovery"
```

**3. Database Corruption**
```bash
# Rollback migrations if needed
./go-forward migrate down

# Reapply migrations
./go-forward migrate up
```

---

## API Reference

### Command Structure

```
go-forward admin <command> [arguments] [flags]
```

### Global Flags

| Flag | Description | Default |
|------|-------------|---------|
| `--help, -h` | Show help information | - |
| `--config` | Configuration file path | `./config.yaml` |

### Commands Reference

#### `create-system-admin`

Create a system administrator with full framework access.

**Syntax:**
```bash
go-forward admin create-system-admin [flags]
```

**Flags:**
| Flag | Short | Type | Required | Description |
|------|-------|------|----------|-------------|
| `--email` | `-e` | string | Yes | Admin email address |
| `--username` | `-u` | string | No | Admin username |
| `--password` | `-p` | string | No | Admin password (prompts if not provided) |
| `--force` | `-f` | bool | No | Skip production environment safety checks |

**Exit Codes:**
- `0`: Success
- `1`: Validation error or operation failed

#### `list`

Display all administrators with their roles and status.

**Syntax:**
```bash
go-forward admin list [flags]
```

**Flags:**
| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--level` | `-l` | string | - | Filter by admin level |
| `--search` | `-s` | string | - | Search term for email/username |
| `--limit` | - | int | 50 | Maximum number of results |

**Valid Levels:**
- `system_admin`
- `super_admin`
- `regular_admin`
- `moderator`

#### `promote`

Promote user to admin or upgrade admin level.

**Syntax:**
```bash
go-forward admin promote <user-id-or-email> [flags]
```

**Arguments:**
| Argument | Type | Required | Description |
|----------|------|----------|-------------|
| `user-id-or-email` | string | Yes | User UUID or email address |

**Flags:**
| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--level` | `-l` | string | `regular_admin` | Target admin level |
| `--reason` | `-r` | string | - | Reason for promotion |
| `--tables` | `-t` | []string | - | Assigned tables for regular admin |

#### `demote`

Demote admin or remove admin privileges.

**Syntax:**
```bash
go-forward admin demote <admin-id-or-email> [flags]
```

**Arguments:**
| Argument | Type | Required | Description |
|----------|------|----------|-------------|
| `admin-id-or-email` | string | Yes | Admin UUID or email address |

**Flags:**
| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--level` | `-l` | string | - | New admin level (empty = remove privileges) |
| `--reason` | `-r` | string | - | Reason for demotion |

#### `create-emergency-access`

Create emergency access with time limits.

**Syntax:**
```bash
go-forward admin create-emergency-access [flags]
```

**Flags:**
| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--reason` | `-r` | string | - | Reason for emergency access (required) |
| `--duration` | `-d` | string | `1h` | Access duration (max: 24h) |
| `--level` | `-l` | string | `system_admin` | Admin level for emergency access |
| `--ip` | - | string | - | Restrict access to specific IP |

**Duration Examples:**
- `30m` - 30 minutes
- `2h` - 2 hours
- `1h30m` - 1 hour 30 minutes
- `24h` - 24 hours (maximum)

#### `list-emergency-access`

List emergency access entries.

**Syntax:**
```bash
go-forward admin list-emergency-access [flags]
```

**Flags:**
| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--active` | `-a` | bool | false | Show only active entries |
| `--limit` | - | int | 20 | Maximum number of results |

#### `revoke-emergency-access`

Revoke emergency access.

**Syntax:**
```bash
go-forward admin revoke-emergency-access <access-id>
```

**Arguments:**
| Argument | Type | Required | Description |
|----------|------|----------|-------------|
| `access-id` | UUID | Yes | Emergency access UUID to revoke |

### Error Codes

| Code | Description | Resolution |
|------|-------------|------------|
| `INVALID_CREDENTIALS` | Authentication failed | Check credentials |
| `UNAUTHORIZED` | Insufficient permissions | Use higher-level admin |
| `RECORD_NOT_FOUND` | User/admin not found | Verify ID/email |
| `VALIDATION_ERROR` | Input validation failed | Check parameters |
| `DATABASE_CONNECTION` | Database connection failed | Check database status |
| `RATE_LIMIT_EXCEEDED` | Too many requests | Wait and retry |

### Configuration Schema

```yaml
# Database Configuration
database:
  host: string          # Database host
  port: integer         # Database port (default: 5432)
  name: string          # Database name
  user: string          # Database user
  password: string      # Database password
  ssl_mode: string      # SSL mode (default: "disable")

# Authentication Configuration
auth:
  jwt_secret: string    # JWT signing secret (min 32 chars)
  bcrypt_cost: integer  # Bcrypt cost (default: 12)
  password_min_length: integer  # Min password length (default: 8)

# Admin Configuration
admin:
  require_mfa_for_admin: boolean  # Require MFA for admins
  session_timeout: duration      # Admin session timeout

# Security Configuration
security:
  audit_retention_days: integer  # Audit log retention (default: 90)
```

---

## Conclusion

The CLI Admin Management System provides a comprehensive, secure, and user-friendly interface for managing administrators in the Unified Go Forward Framework. With its hierarchical admin structure, emergency access capabilities, and production-ready security features, it serves as the foundation for secure administrative operations.

For additional support or questions, please refer to the project documentation or contact the development team.

---

**Document Version:** 1.0  
**Last Updated:** October 11, 2025  
**Framework Version:** Unified Go Forward Framework v1.0
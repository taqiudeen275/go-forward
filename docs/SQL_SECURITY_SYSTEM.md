# SQL Security System Documentation

## Overview

The SQL Security System is a comprehensive security layer that provides validation, authorization, audit logging, and approval workflows for SQL operations within the Go-Forward application. It ensures that all SQL queries are properly validated, authorized, and logged for security and compliance purposes.

## Architecture

The system consists of several interconnected components:

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   CLI Commands  │    │   API Handlers  │    │   Middleware    │
└─────────┬───────┘    └─────────┬───────┘    └─────────┬───────┘
          │                      │                      │
          └──────────────────────┼──────────────────────┘
                                 │
                    ┌─────────────▼──────────────┐
                    │   SQL Security Validator   │
                    └─────────────┬──────────────┘
                                 │
          ┌──────────────────────┼──────────────────────┐
          │                      │                      │
┌─────────▼───────┐    ┌─────────▼───────┐    ┌─────────▼───────┐
│   RBAC Engine   │    │   MFA Service   │    │  Audit Logger   │
└─────────────────┘    └─────────────────┘    └─────────────────┘
          │                      │                      │
          └──────────────────────┼──────────────────────┘
                                 │
                    ┌─────────────▼──────────────┐
                    │      PostgreSQL DB        │
                    └───────────────────────────┘
```

## Core Components

### 1. SQL Security Validator

The main component that handles query validation, risk assessment, and execution control.

**Key Features:**
- SQL syntax validation and injection pattern detection
- Table access permission checking
- Risk level assessment (low, medium, high, critical)
- Query complexity analysis
- Approval requirement determination
- Execution time limit enforcement

**Usage:**
```go
validator := auth.NewSQLSecurityValidator(db, rbacEngine)
result, err := validator.ValidateQuery(ctx, query, executionContext)
```

### 2. RBAC Engine

Role-Based Access Control system that manages user permissions and table access.

**Key Features:**
- Role hierarchy management
- Table-level access control
- Permission inheritance
- Dynamic permission checking

**Usage:**
```go
rbac := auth.NewRBACEngine(db)
canAccess, err := rbac.CanAccessTable(ctx, userID, tableName, operation)
```

### 3. Query Approval System

Manages approval workflows for high-risk queries.

**Database Tables:**
- `query_approvals` - Approval requests and status
- `approval_notifications` - Notification tracking
- `approval_history` - Audit trail of approval actions

**Workflow:**
1. High-risk query triggers approval requirement
2. System creates approval request
3. Notifications sent to authorized approvers
4. Approver reviews and approves/denies
5. Query execution allowed/blocked based on approval

### 4. Audit and Logging System

Comprehensive logging of all SQL operations for security and compliance.

**Database Tables:**
- `sql_execution_logs` - All SQL executions
- `admin_access_logs` - Administrative actions
- `security_events` - Security-related events
- `admin_sessions` - Session tracking

## Security Features

### 1. SQL Injection Prevention

The system implements multiple layers of protection against SQL injection:

- **Pattern Detection**: Identifies common injection patterns
- **Syntax Analysis**: Validates SQL syntax and structure
- **Blacklist Filtering**: Blocks access to sensitive system tables
- **Parameter Validation**: Ensures proper parameter handling

### 2. Risk Assessment

Queries are automatically classified into risk levels:

**Low Risk:**
- Simple SELECT queries with WHERE clauses
- Limited row results (< 1000 rows)
- Read-only operations on non-sensitive tables

**Medium Risk:**
- Complex queries with multiple JOINs
- INSERT/UPDATE operations
- Queries affecting moderate number of rows (1000-10000)

**High Risk:**
- DELETE operations
- Schema modifications (ALTER, CREATE, DROP)
- Queries affecting large datasets (> 10000 rows)
- Operations without WHERE clauses

**Critical Risk:**
- Operations on core system tables (users, admin_roles)
- DROP DATABASE/SCHEMA operations
- Mass data deletion operations

### 3. Access Control

Multi-layered access control system:

**Role-Based Access:**
- `viewer` - Read-only access to assigned tables
- `admin` - Full CRUD access to business tables
- `system_admin` - Full system access including schema changes
- `security_admin` - Security monitoring and audit access

**Table-Level Security:**
- Per-table permission configuration
- Row-level security (RLS) policies
- Dynamic filtering based on user context

### 4. Approval Workflows

High-risk operations require approval:

**Automatic Approval Requirements:**
- Critical or high-risk queries
- Schema modification operations
- Queries affecting > 10,000 rows
- Operations on core system tables

**Approval Process:**
1. Query validation identifies approval requirement
2. Approval request created with risk assessment
3. Authorized approvers notified
4. Review and approval/denial with reasoning
5. Time-limited execution permission granted

## Database Schema

### Core Tables

#### admin_roles
```sql
CREATE TABLE admin_roles (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(100) UNIQUE NOT NULL,
    level INTEGER NOT NULL,
    permissions JSONB DEFAULT '{}',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);
```

#### sql_execution_logs
```sql
CREATE TABLE sql_execution_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id),
    query_text TEXT NOT NULL,
    query_hash VARCHAR(64) NOT NULL,
    query_type VARCHAR(50),
    affected_tables TEXT[],
    execution_time_ms INTEGER,
    rows_affected INTEGER,
    rows_returned INTEGER,
    success BOOLEAN DEFAULT TRUE,
    error_message TEXT,
    risk_level VARCHAR(20) DEFAULT 'low',
    requires_approval BOOLEAN DEFAULT FALSE,
    ip_address INET,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);
```

#### query_approvals
```sql
CREATE TABLE query_approvals (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    query_hash VARCHAR(64) NOT NULL,
    query TEXT NOT NULL,
    requested_by UUID REFERENCES users(id),
    approved_by UUID REFERENCES users(id),
    status VARCHAR(20) DEFAULT 'pending',
    reason TEXT,
    risk_level VARCHAR(20),
    expires_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);
```

## API Endpoints

### SQL Execution
- `POST /api/admin/sql/execute` - Execute SQL with validation
- `POST /api/admin/sql/validate` - Validate SQL without execution
- `GET /api/admin/sql/history` - Get execution history
- `GET /api/admin/sql/history/:user_id` - Get user-specific history

### Query Approvals
- `GET /api/admin/sql/approvals` - List approval requests
- `GET /api/admin/sql/approvals/:id` - Get approval details
- `POST /api/admin/sql/approvals/:id/approve` - Approve query
- `POST /api/admin/sql/approvals/:id/deny` - Deny query

### Security Monitoring
- `GET /api/admin/sql/security/events` - Security events
- `GET /api/admin/sql/security/stats` - Security statistics
- `GET /api/admin/sql/security/risk-assessment` - Risk assessment
- `POST /api/admin/sql/security/emergency-stop` - Emergency stop

## CLI Commands

The system includes comprehensive CLI commands for administration:

### SQL Execution
```bash
# Execute a query
go-forward-admin sql execute "SELECT COUNT(*) FROM users"

# Execute from file
go-forward-admin sql execute --file query.sql --reason "Monthly report"

# Interactive mode
go-forward-admin sql execute --interactive

# Validation only (dry run)
go-forward-admin sql execute --dry-run "DELETE FROM old_logs"
```

### Query Management
```bash
# View execution history
go-forward-admin sql history --limit 20

# View security events
go-forward-admin sql security --severity high

# View statistics
go-forward-admin sql stats --hours 48
```

### Approval Management
```bash
# List pending approvals
go-forward-admin sql approvals --status pending

# Approve a query
go-forward-admin sql approve abc123 --reason "Approved for maintenance"

# Deny a query
go-forward-admin sql deny abc123 --reason "Too risky for production"
```

## Configuration

### Environment Variables

```env
# SQL Security Configuration
SQL_SECURITY_ENABLED=true
SQL_APPROVAL_TIMEOUT_HOURS=24
SQL_MAX_EXECUTION_TIME_MS=300000
SQL_MAX_ROWS_WITHOUT_APPROVAL=10000

# Risk Assessment Thresholds
SQL_HIGH_RISK_COMPLEXITY_THRESHOLD=100
SQL_CRITICAL_RISK_PATTERNS="DROP DATABASE,TRUNCATE users"

# Audit Configuration
SQL_AUDIT_RETENTION_DAYS=365
SQL_SECURITY_EVENT_RETENTION_DAYS=730
```

### Database Configuration

```yaml
# config.yaml
database:
  sql_security:
    enabled: true
    audit_all_queries: true
    require_approval_for_schema_changes: true
    max_query_timeout_ms: 300000
    
security:
  rbac:
    enabled: true
    default_role: "viewer"
    
  approval:
    timeout_hours: 24
    max_executions_per_approval: 1
    notification_channels:
      - email
      - in_app
```

## Security Best Practices

### 1. Principle of Least Privilege
- Grant minimal necessary permissions
- Regularly review and audit role assignments
- Use temporary elevated permissions when needed

### 2. Defense in Depth
- Multiple validation layers
- Both preventive and detective controls
- Comprehensive audit logging

### 3. Approval Workflows
- Require approval for high-risk operations
- Implement proper segregation of duties
- Time-limited approval grants

### 4. Monitoring and Alerting
- Real-time security event monitoring
- Automated alerts for suspicious activity
- Regular security posture assessments

### 5. Audit and Compliance
- Complete audit trails for all operations
- Tamper-proof logging mechanisms
- Regular compliance reporting

## Monitoring and Alerting

### Key Metrics
- Query execution rate and patterns
- Failed query attempts
- High-risk query frequency
- Approval request volume
- Security event frequency

### Alert Conditions
- Multiple failed SQL injections from same IP
- Unauthorized access attempts
- High-risk queries outside business hours
- Emergency stop activations
- Approval backlog threshold exceeded

### Dashboards
- Real-time security monitoring
- Query performance metrics
- User activity patterns
- Risk assessment trends
- Compliance status overview

## Troubleshooting

### Common Issues

#### Query Validation Failures
```
Error: Query validation failed: potentially dangerous SQL pattern detected
```
**Solution:** Review the query for injection patterns or unsafe operations. Use parameterized queries and avoid dynamic SQL construction.

#### Access Denied Errors
```
Error: access denied to table 'sensitive_data' for operation 'SELECT'
```
**Solution:** Check user roles and table permissions. Contact system administrator for access requests.

#### Approval Required
```
Error: Query requires approval from a system administrator
```
**Solution:** Submit approval request through CLI or API. Include business justification for the operation.

#### Execution Timeout
```
Error: Query execution timeout after 300000ms
```
**Solution:** Optimize query performance, add appropriate indexes, or request extended timeout for complex operations.

### Debug Mode

Enable debug logging for detailed troubleshooting:

```bash
export SQL_SECURITY_DEBUG=true
export LOG_LEVEL=debug
```

### Log Analysis

Query execution logs for security analysis:

```sql
-- High-risk queries in last 24 hours
SELECT query_text, user_id, risk_level, created_at
FROM sql_execution_logs 
WHERE risk_level IN ('high', 'critical')
  AND created_at > NOW() - INTERVAL '24 hours';

-- Failed queries by user
SELECT user_id, COUNT(*) as failed_count
FROM sql_execution_logs 
WHERE success = false
  AND created_at > NOW() - INTERVAL '7 days'
GROUP BY user_id
ORDER BY failed_count DESC;
```

## Migration and Deployment

### Database Migrations

The system includes several migration files:

1. `000007_admin_security_foundation.up.sql` - Core RBAC tables
2. `000008_admin_audit_system.up.sql` - Audit and logging tables
3. `000009_mfa_support.up.sql` - MFA integration
4. `000010_query_approvals.up.sql` - Approval workflow tables

### Deployment Steps

1. **Database Migration**
   ```bash
   migrate -path ./migrations -database postgres://... up
   ```

2. **Service Configuration**
   ```bash
   # Update configuration files
   cp config.example.yaml config.yaml
   # Edit configuration as needed
   ```

3. **Initialize Admin User**
   ```bash
   go-forward-admin create-system-admin
   ```

4. **Verify Installation**
   ```bash
   go-forward-admin sql validate "SELECT 1"
   ```

### Rollback Procedures

If issues arise, use the provided rollback migrations:

```bash
# Rollback approval system
migrate -path ./migrations -database postgres://... down 1

# Rollback complete SQL security system
migrate -path ./migrations -database postgres://... down 4
```

## Performance Considerations

### Query Validation Performance
- Validation typically adds 1-5ms overhead
- Complex regex patterns may impact performance
- Consider caching validation results for repeated queries

### Database Impact
- Audit logging adds storage overhead
- Index maintenance for audit tables
- Periodic cleanup of old audit records

### Scalability
- Connection pooling for validator database access
- Async audit logging for high-throughput scenarios
- Distributed approval notifications

## Testing

### Unit Tests

Run the comprehensive test suite:

```bash
go test ./internal/auth/sql_validator_test.go -v
```

### Integration Tests

```bash
# Requires test database
go test ./internal/auth -tags integration
```

### Security Tests

```bash
# SQL injection tests
go test ./internal/auth -run TestSQLInjection

# Permission tests  
go test ./internal/auth -run TestPermissions
```

## Support and Maintenance

### Regular Maintenance Tasks

1. **Audit Log Cleanup**
   ```sql
   DELETE FROM sql_execution_logs 
   WHERE created_at < NOW() - INTERVAL '365 days';
   ```

2. **Permission Review**
   ```bash
   go-forward-admin list-admins --include-permissions
   ```

3. **Security Assessment**
   ```bash
   go-forward-admin sql security --risk-assessment
   ```

### Performance Monitoring

Monitor these key metrics:
- Query validation time
- Database connection pool usage
- Audit log growth rate
- Approval processing time

### Updates and Patches

The SQL Security System is designed for backward compatibility. When updating:

1. Review migration scripts
2. Test in staging environment
3. Backup existing audit data
4. Deploy during maintenance window
5. Verify functionality post-deployment

## Conclusion

The SQL Security System provides enterprise-grade security for database operations with comprehensive validation, authorization, audit logging, and approval workflows. It ensures that all SQL operations are properly secured, monitored, and compliant with security policies while maintaining operational efficiency and usability.

For additional support or feature requests, please refer to the project documentation or contact the development team.
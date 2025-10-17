# Admin Security System Implementation TODO

## Overview
This document outlines the implementation plan for the Admin Hierarchy & Security System based on the specifications in `.kiro/specs/admin-security-system/`. This system will transform Go Forward into an enterprise-grade backend with multi-tiered administrative controls, robust authentication, and advanced security policies.

## Current State Analysis

### What Exists:
- Basic user authentication system (`internal/auth/`)
- JWT token management and middleware
- OTP system for email/SMS verification
- Basic user CRUD operations
- Database migration system
- Basic API service layer

### What's Missing:
- Admin role hierarchy (System Admin → Super Admin → Regular Admin → Moderator)
- Role-based access control (RBAC) engine
- CLI admin management tools
- Enhanced security policies and audit logging
- Table-level security configuration
- SQL execution security system
- Multi-factor authentication (MFA)
- Admin panel UI
- Row Level Security (RLS) policies

## Implementation Plan

### Phase 1: Database Foundation & Security Schema

#### 1.1 Enhanced Database Schema
- [ ] **Create admin roles and permissions tables**
  ```sql
  -- Location: migrations/000007_admin_security_foundation.up.sql
  CREATE TABLE admin_roles (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(50) UNIQUE NOT NULL, -- 'system_admin', 'super_admin', 'admin', 'moderator'
    level INTEGER NOT NULL, -- Hierarchy level (1=system_admin, 4=moderator)
    description TEXT,
    permissions JSONB DEFAULT '{}', -- Role-specific permissions
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
  );

  CREATE TABLE user_admin_roles (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    role_id UUID REFERENCES admin_roles(id) ON DELETE CASCADE,
    granted_by UUID REFERENCES users(id),
    granted_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    expires_at TIMESTAMP WITH TIME ZONE, -- Optional role expiration
    is_active BOOLEAN DEFAULT TRUE,
    metadata JSONB DEFAULT '{}',
    UNIQUE(user_id, role_id)
  );

  CREATE TABLE table_security_config (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    table_name VARCHAR(255) NOT NULL,
    schema_name VARCHAR(255) DEFAULT 'public',
    auth_required BOOLEAN DEFAULT TRUE,
    ownership_column VARCHAR(255), -- Column that determines ownership
    allowed_roles TEXT[], -- Roles allowed to access this table
    api_permissions JSONB DEFAULT '{}', -- Per-role API permissions
    custom_filters JSONB DEFAULT '{}', -- Custom SQL filters per role
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    UNIQUE(table_name, schema_name)
  );
  ```

- [ ] **Create audit and security logging tables**
  ```sql
  -- Location: migrations/000008_admin_audit_system.up.sql
  CREATE TABLE admin_access_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id),
    admin_role_id UUID REFERENCES admin_roles(id),
    action VARCHAR(100) NOT NULL, -- 'login', 'sql_execute', 'user_create', etc.
    resource_type VARCHAR(100), -- 'user', 'table', 'system', etc.
    resource_id VARCHAR(255), -- ID of affected resource
    details JSONB DEFAULT '{}', -- Action-specific details
    ip_address INET,
    user_agent TEXT,
    success BOOLEAN DEFAULT TRUE,
    error_message TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
  );

  CREATE TABLE sql_execution_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id),
    admin_role_id UUID REFERENCES admin_roles(id),
    query_text TEXT NOT NULL,
    query_hash VARCHAR(64), -- SHA-256 hash of query for deduplication
    execution_time_ms INTEGER,
    rows_affected INTEGER,
    success BOOLEAN DEFAULT TRUE,
    error_message TEXT,
    ip_address INET,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
  );

  CREATE TABLE security_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    event_type VARCHAR(100) NOT NULL, -- 'failed_login', 'privilege_escalation', 'suspicious_activity'
    severity VARCHAR(20) DEFAULT 'medium', -- 'low', 'medium', 'high', 'critical'
    user_id UUID REFERENCES users(id),
    details JSONB DEFAULT '{}',
    ip_address INET,
    user_agent TEXT,
    resolved BOOLEAN DEFAULT FALSE,
    resolved_by UUID REFERENCES users(id),
    resolved_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
  );
  ```

- [ ] **Add MFA support to user model**
  ```sql
  -- Location: migrations/000009_mfa_support.up.sql
  CREATE TABLE user_mfa_settings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE UNIQUE,
    totp_secret VARCHAR(255), -- Base32 encoded TOTP secret
    backup_codes TEXT[], -- Array of hashed backup codes
    is_enabled BOOLEAN DEFAULT FALSE,
    last_used_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
  );
  ```

- [ ] **Implement Row Level Security policies**
  ```sql
  -- Enable RLS on sensitive tables
  ALTER TABLE users ENABLE ROW LEVEL SECURITY;
  ALTER TABLE user_admin_roles ENABLE ROW LEVEL SECURITY;
  ALTER TABLE admin_access_logs ENABLE ROW LEVEL SECURITY;
  
  -- Create policies for admin access
  CREATE POLICY admin_user_access ON users
    FOR ALL TO authenticated_role
    USING (
      -- System admins can see all users
      EXISTS (SELECT 1 FROM user_admin_roles uar 
              JOIN admin_roles ar ON uar.role_id = ar.id 
              WHERE uar.user_id = current_user_id() 
              AND ar.name = 'system_admin' AND uar.is_active = TRUE)
      OR
      -- Users can see their own record
      id = current_user_id()
    );
  ```

#### 1.2 Extend Auth Models
- [ ] **Update `internal/auth/models.go`**
  ```go
  // Add to existing models.go
  
  // AdminRole represents an administrative role
  type AdminRole struct {
      ID          string                 `json:"id" db:"id"`
      Name        string                 `json:"name" db:"name"`
      Level       int                    `json:"level" db:"level"`
      Description string                 `json:"description" db:"description"`
      Permissions map[string]interface{} `json:"permissions" db:"permissions"`
      CreatedAt   time.Time              `json:"created_at" db:"created_at"`
      UpdatedAt   time.Time              `json:"updated_at" db:"updated_at"`
  }

  // UserAdminRole represents a user's admin role assignment
  type UserAdminRole struct {
      ID        string     `json:"id" db:"id"`
      UserID    string     `json:"user_id" db:"user_id"`
      RoleID    string     `json:"role_id" db:"role_id"`
      GrantedBy string     `json:"granted_by" db:"granted_by"`
      GrantedAt time.Time  `json:"granted_at" db:"granted_at"`
      ExpiresAt *time.Time `json:"expires_at" db:"expires_at"`
      IsActive  bool       `json:"is_active" db:"is_active"`
      Metadata  map[string]interface{} `json:"metadata" db:"metadata"`
      
      // Joined fields
      Role *AdminRole `json:"role,omitempty" db:"-"`
  }

  // MFASettings represents multi-factor authentication settings
  type MFASettings struct {
      ID          string    `json:"id" db:"id"`
      UserID      string    `json:"user_id" db:"user_id"`
      TOTPSecret  string    `json:"-" db:"totp_secret"` // Never expose in JSON
      BackupCodes []string  `json:"-" db:"backup_codes"` // Never expose in JSON
      IsEnabled   bool      `json:"is_enabled" db:"is_enabled"`
      LastUsedAt  *time.Time `json:"last_used_at" db:"last_used_at"`
      CreatedAt   time.Time `json:"created_at" db:"created_at"`
      UpdatedAt   time.Time `json:"updated_at" db:"updated_at"`
  }
  ```

### Phase 2: Core Security Services

#### 2.1 RBAC Engine
- [ ] **Create `internal/auth/rbac.go`**
  ```go
  // RBAC Engine interface and implementation
  type RBACEngine interface {
      // Role management
      GetUserRoles(userID string) ([]UserAdminRole, error)
      HasRole(userID string, roleName string) (bool, error)
      GrantRole(userID string, roleID string, grantedBy string) error
      RevokeRole(userID string, roleID string, revokedBy string) error
      
      // Permission checking
      HasPermission(userID string, permission string) (bool, error)
      CanAccessTable(userID string, tableName string, operation string) (bool, error)
      GetTableFilters(userID string, tableName string) (map[string]interface{}, error)
      
      // Hierarchy checking
      CanManageUser(managerID string, targetUserID string) (bool, error)
      GetAccessibleTables(userID string) ([]string, error)
  }
  ```

#### 2.2 MFA Service
- [ ] **Create `internal/auth/mfa.go`**
  ```go
  // MFA service for TOTP and backup codes
  type MFAService interface {
      GenerateTOTPSecret(userID string) (string, []string, error) // secret, backup codes
      VerifyTOTP(userID string, code string) (bool, error)
      VerifyBackupCode(userID string, code string) (bool, error)
      EnableMFA(userID string, totpCode string) error
      DisableMFA(userID string, totpCode string) error
      GetMFAStatus(userID string) (*MFASettings, error)
  }
  ```

#### 2.3 Enhanced Auth Service
- [ ] **Extend `internal/auth/service.go`**
  ```go
  // Add admin-specific methods to AuthService
  
  // Admin user management
  func (s *Service) CreateAdminUser(req CreateAdminUserRequest) (*User, error)
  func (s *Service) PromoteToAdmin(userID string, roleID string, promotedBy string) error
  func (s *Service) GetAdminUsers(filter AdminUserFilter) ([]User, error)
  
  // MFA integration
  func (s *Service) LoginWithMFA(req LoginRequest, mfaCode string) (*AuthResponse, error)
  func (s *Service) RequiresMFA(userID string) (bool, error)
  ```

#### 2.4 SQL Security Validator
- [ ] **Create `internal/security/sql_validator.go`**
  ```go
  // SQL execution security and validation
  type SQLValidator interface {
      ValidateQuery(query string, userID string) (*ValidationResult, error)
      IsAllowedOperation(query string, userRole string) (bool, error)
      SanitizeQuery(query string) (string, error)
      EstimateQueryRisk(query string) (RiskLevel, error)
  }

  type ValidationResult struct {
      IsValid      bool     `json:"is_valid"`
      Errors       []string `json:"errors"`
      Warnings     []string `json:"warnings"`
      RiskLevel    RiskLevel `json:"risk_level"`
      RequiresMFA  bool     `json:"requires_mfa"`
  }

  type RiskLevel string
  const (
      RiskLevelLow      RiskLevel = "low"
      RiskLevelMedium   RiskLevel = "medium"
      RiskLevelHigh     RiskLevel = "high"
      RiskLevelCritical RiskLevel = "critical"
  )
  ```

### Phase 3: CLI Admin Management

#### 3.1 CLI Commands Structure
- [ ] **Create `cmd/admin/` directory with cobra commands**
  ```go
  // cmd/admin/main.go - Main CLI entry point
  // cmd/admin/create.go - create-system-admin command
  // cmd/admin/promote.go - promote-admin command
  // cmd/admin/list.go - list-admins command
  // cmd/admin/bootstrap.go - bootstrap command for new deployments
  ```

#### 3.2 Admin Creation Command
- [ ] **Implement `cmd/admin/create.go`**
  ```go
  // Command: go-forward admin create-system-admin
  var createSystemAdminCmd = &cobra.Command{
      Use:   "create-system-admin",
      Short: "Create a new system administrator",
      Long:  `Create a new system administrator with full framework access.`,
      RunE:  createSystemAdmin,
  }

  func createSystemAdmin(cmd *cobra.Command, args []string) error {
      // Environment detection
      env := detectEnvironment()
      
      // Production safety checks
      if env == "production" {
          return requireProductionConfirmation()
      }
      
      // Interactive prompts for admin details
      // Email validation
      // Password strength validation
      // MFA setup (if production)
      // Create user and assign system admin role
  }
  ```

#### 3.3 Bootstrap Command
- [ ] **Implement `cmd/admin/bootstrap.go`**
  ```go
  // Command: go-forward admin bootstrap
  // Sets up initial admin roles and first system admin
  // Validates database connection and schema
  // Creates default security configurations
  ```

### Phase 4: API Security Layer

#### 4.1 Admin API Endpoints
- [ ] **Create `internal/api/admin.go`**
  ```go
  // Admin-specific API endpoints
  // /admin/users - Admin user management
  // /admin/roles - Role management
  // /admin/audit - Audit log access
  // /admin/security - Security configuration
  // /admin/sql - SQL execution interface (system admins only)
  ```

#### 4.2 Enhanced Middleware
- [ ] **Extend `internal/auth/middleware.go`**
  ```go
  // Add admin-specific middleware
  func RequireAdminRole(minLevel int) gin.HandlerFunc
  func RequireMFAForSensitiveOps() gin.HandlerFunc
  func AuditLogMiddleware() gin.HandlerFunc
  func RateLimitAdminOps() gin.HandlerFunc
  ```

#### 4.3 Table Security Middleware
- [ ] **Create `internal/api/security_middleware.go`**
  ```go
  // Apply table-level security policies
  func ApplyTableSecurity() gin.HandlerFunc {
      return func(c *gin.Context) {
          // Check table access permissions
          // Apply row-level filters based on user role
          // Enforce field-level permissions
          // Log data access
      }
  }
  ```

### Phase 5: Admin Panel UI (Optional for MVP)

#### 5.1 Admin Dashboard Structure
- [ ] **Extend `dashboard/` directory**
  ```
  dashboard/admin/
  ├── components/
  │   ├── UserManagement.vue
  │   ├── RoleManagement.vue
  │   ├── SecurityConfig.vue
  │   ├── AuditLogs.vue
  │   └── SQLConsole.vue
  ├── layouts/
  │   └── AdminLayout.vue
  ├── pages/
  │   ├── Dashboard.vue
  │   ├── Users.vue
  │   ├── Security.vue
  │   └── Audit.vue
  └── router/
      └── admin.js
  ```

#### 5.2 Key UI Components
- [ ] **User Management Interface**
  - List all users with role information
  - Create/edit users with role assignment
  - Bulk operations with safety confirmations

- [ ] **Security Configuration Interface**
  - Table-level security policy management
  - API endpoint configuration
  - Rate limiting configuration

- [ ] **Audit Log Viewer**
  - Searchable, filterable audit logs
  - Export capabilities
  - Security event alerts

### Phase 6: Security Testing & Hardening

#### 6.1 Security Test Suite
- [ ] **Create comprehensive security tests**
  ```go
  // internal/auth/security_test.go
  // Test role hierarchy enforcement
  // Test permission escalation prevention
  // Test MFA bypass attempts
  // Test SQL injection prevention
  // Test audit log integrity
  ```

#### 6.2 Load Testing
- [ ] **Admin endpoint load testing**
  - Rate limiting effectiveness
  - Database performance under admin load
  - Audit logging performance impact

#### 6.3 Security Audit
- [ ] **Manual security review**
  - Code review for security vulnerabilities
  - Configuration review
  - Deployment security checklist

## Implementation Priority

### MVP (Minimum Viable Product)
1. Database schema and migrations
2. RBAC engine core functionality
3. CLI admin management
4. Basic admin API endpoints
5. Enhanced authentication with role checking

### Production Ready
6. MFA implementation
7. Comprehensive audit logging
8. SQL execution security
9. Admin panel UI
10. Security testing and hardening

### Enterprise Features
11. Advanced security policies
12. Compliance reporting
13. Advanced audit analytics
14. Integration with external security systems

## Migration Strategy

### Database Migrations
- All new tables and schemas via numbered migrations
- RLS policies applied in separate migration for safety
- Seed data for default admin roles
- Index creation for performance

### Backward Compatibility
- Existing auth system remains functional
- New admin features are additive
- Graceful degradation if admin features disabled
- Clear migration path for existing deployments

## Testing Strategy

### Unit Tests
- RBAC engine functionality
- MFA service operations
- SQL validator logic
- Permission checking algorithms

### Integration Tests
- End-to-end admin workflows
- API security enforcement
- Database security policies
- CLI command functionality

### Security Tests
- Penetration testing scenarios
- Privilege escalation attempts
- Authentication bypass attempts
- SQL injection resistance

## Documentation Requirements

### Developer Documentation
- [ ] Admin system architecture guide
- [ ] Security policy configuration guide
- [ ] CLI command reference
- [ ] API endpoint documentation

### User Documentation
- [ ] Admin panel user guide
- [ ] Security best practices
- [ ] Deployment security checklist
- [ ] Troubleshooting guide

## Risk Considerations

### Security Risks
- Privilege escalation vulnerabilities
- Admin credential compromise
- SQL injection in admin interfaces
- Audit log tampering

### Mitigation Strategies
- Comprehensive input validation
- Principle of least privilege
- Defense in depth
- Regular security audits

### Deployment Risks
- Database migration failures
- Performance impact of security features
- Configuration complexity
- User training requirements

## Success Criteria

### Functional Requirements Met
- ✅ Four-tier admin hierarchy implemented
- ✅ CLI admin management working
- ✅ Role-based access control enforced
- ✅ Audit logging comprehensive
- ✅ MFA for sensitive operations

### Security Requirements Met
- ✅ No privilege escalation possible
- ✅ All admin actions logged
- ✅ SQL execution properly secured
- ✅ Rate limiting effective
- ✅ Security tests passing

### Performance Requirements Met
- ✅ Admin operations under 2s response time
- ✅ Audit logging doesn't impact user operations
- ✅ Database queries optimized
- ✅ Memory usage within acceptable limits

This implementation plan transforms Go Forward from a basic backend framework into an enterprise-grade platform with comprehensive administrative controls and security features.
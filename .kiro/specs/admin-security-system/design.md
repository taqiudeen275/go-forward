# Design Document

## Overview

The Admin Hierarchy & Security System is a comprehensive security enhancement that transforms the Go Forward framework into an enterprise-grade backend solution with multi-tiered administrative controls, robust authentication mechanisms, and advanced security policies. The system implements a hierarchical admin structure with four distinct levels: System Admin, Super Admin, Regular Admin, and Moderator, each with carefully defined capabilities and restrictions.

The design follows security-first principles including defense in depth, principle of least privilege, and zero-trust architecture. It provides both CLI-based system administration for deployment scenarios and a comprehensive web-based admin panel for day-to-day operations. The system is designed to work seamlessly whether the framework is used as a hosted BaaS, self-hosted solution, or starter framework for custom development.

## Architecture

### High-Level Security Architecture

```mermaid
graph TB
    CLI[CLI Admin Tools] --> AuthCore[Authentication Core]
    AdminUI[Admin Panel UI] --> Gateway[Security Gateway]
    
    Gateway --> AuthCore
    Gateway --> RBAC[RBAC Engine]
    Gateway --> Audit[Audit System]
    
    AuthCore --> MFA[MFA Service]
    AuthCore --> Session[Session Manager]
    AuthCore --> TokenMgr[Token Manager]
    
    RBAC --> PolicyEngine[Policy Engine]
    RBAC --> PermissionDB[(Permission DB)]
    
    PolicyEngine --> RLS[RLS Manager]
    PolicyEngine --> APIGuard[API Guardian]
    
    Audit --> LogStore[(Audit Logs)]
    Audit --> AlertMgr[Alert Manager]
    
    subgraph "Security Services"
        AuthCore
        RBAC
        Audit
        MFA
    end
    
    subgraph "Data Layer"
        PermissionDB
        LogStore
        ConfigDB[(Security Config)]
    end
    
    subgraph "Enforcement Points"
        RLS
        APIGuard
        SQLValidator[SQL Validator]
    end
```

### Admin Hierarchy Architecture

```mermaid
graph TD
    SystemAdmin[System Admin] --> SuperAdmin[Super Admin]
    SuperAdmin --> RegularAdmin[Regular Admin]
    RegularAdmin --> Moderator[Moderator]
    
    SystemAdmin --> |Full Access| SystemFeatures[System Features]
    SystemAdmin --> |Full Access| BusinessFeatures[Business Features]
    
    SuperAdmin --> |Limited Access| BusinessFeatures
    SuperAdmin --> |No Access| SystemFeatures
    
    RegularAdmin --> |Scoped Access| AssignedTables[Assigned Tables]
    RegularAdmin --> |Limited Access| UserMgmt[User Management]
    
    Moderator --> |Read Only| Reports[Reports & Analytics]
    Moderator --> |Limited Access| ContentMod[Content Moderation]
    
    subgraph "System Level"
        SystemFeatures
        SQLEditor[SQL Editor]
        SystemConfig[System Configuration]
        AdminMgmt[Admin Management]
    end
    
    subgraph "Business Level"
        BusinessFeatures
        TableConfig[Table Configuration]
        UserMgmt
        StorageMgmt[Storage Management]
    end
```

## Components and Interfaces

### 1. Authentication Core Component

**Technology**: Go with enhanced JWT management and MFA support
**Responsibilities**:
- Multi-factor authentication (TOTP, backup codes)
- Enhanced session management with security controls
- API key management for service-to-service authentication
- Admin-specific authentication flows
- Security event detection and response

**Key Interfaces**:
```go
type AuthenticationCore interface {
    // Enhanced authentication methods
    AuthenticateAdmin(req AdminAuthRequest) (*AdminAuthResponse, error)
    EnableMFA(userID string, method MFAMethod) (*MFASetup, error)
    VerifyMFA(userID string, code string) error
    
    // Session management
    CreateAdminSession(userID string, capabilities AdminCapabilities) (*AdminSession, error)
    ValidateSession(sessionID string) (*AdminSession, error)
    InvalidateSession(sessionID string) error
    
    // API key management
    CreateAPIKey(userID string, scopes []string, expiresAt time.Time) (*APIKey, error)
    ValidateAPIKey(key string) (*APIKeyInfo, error)
    RevokeAPIKey(keyID string) error
}

type MFAService interface {
    GenerateTOTPSecret(userID string) (*TOTPSecret, error)
    ValidateTOTPCode(userID string, code string) error
    GenerateBackupCodes(userID string) ([]string, error)
    ValidateBackupCode(userID string, code string) error
}

type SecurityMonitor interface {
    RecordAuthAttempt(userID string, success bool, metadata SecurityMetadata) error
    DetectSuspiciousActivity(userID string) (*SecurityAlert, error)
    TriggerAccountLockout(userID string, reason string) error
    ClearSecurityFlags(userID string) error
}
```

### 2. RBAC Engine Component

**Technology**: Go with policy-based access control
**Responsibilities**:
- Role hierarchy management and enforcement
- Permission evaluation and caching
- Dynamic policy application
- Context-aware authorization decisions
- Integration with database RLS policies

**Key Interfaces**:
```go
type RBACEngine interface {
    // Role management
    CreateRole(role AdminRole) error
    AssignRole(userID string, roleID string, grantedBy string) error
    RevokeRole(userID string, roleID string, revokedBy string) error
    GetUserRoles(userID string) ([]AdminRole, error)
    
    // Permission evaluation
    CheckPermission(userID string, resource string, action string, context SecurityContext) (bool, error)
    GetUserCapabilities(userID string) (*AdminCapabilities, error)
    EvaluatePolicy(policy SecurityPolicy, context SecurityContext) (bool, error)
}

type PolicyEngine interface {
    CreatePolicy(policy SecurityPolicy) error
    UpdatePolicy(policyID string, updates PolicyUpdates) error
    DeletePolicy(policyID string) error
    EvaluateAccess(request AccessRequest) (*AccessDecision, error)
    
    // RLS integration
    GenerateRLSPolicy(tableConfig TableSecurityConfig) (*RLSPolicy, error)
    ApplyRLSPolicies(userID string, query SQLQuery) (*SQLQuery, error)
}

type PermissionCache interface {
    CachePermission(userID string, resource string, action string, result bool, ttl time.Duration) error
    GetCachedPermission(userID string, resource string, action string) (*bool, error)
    InvalidateUserCache(userID string) error
    InvalidateResourceCache(resource string) error
}
```

### 3. Admin Panel Security Gateway

**Technology**: Go with Gin framework and security middleware
**Responsibilities**:
- Request authentication and authorization
- Rate limiting and DDoS protection
- Input validation and sanitization
- Security header injection
- Audit logging integration

**Key Interfaces**:
```go
type SecurityGateway interface {
    // Middleware creation
    CreateAuthMiddleware(config AuthMiddlewareConfig) gin.HandlerFunc
    CreateRateLimitMiddleware(config RateLimitConfig) gin.HandlerFunc
    CreateAuditMiddleware(config AuditConfig) gin.HandlerFunc
    
    // Security enforcement
    ValidateRequest(req *http.Request) (*ValidationResult, error)
    EnforceRateLimit(userID string, endpoint string) error
    CheckIPWhitelist(ip string, context SecurityContext) (bool, error)
}

type InputValidator interface {
    ValidateJSON(data []byte, schema ValidationSchema) error
    SanitizeInput(input string, rules SanitizationRules) (string, error)
    ValidateSQL(query string, userRoles []string) error
    CheckForInjection(input string) (bool, []string)
}

type RateLimiter interface {
    CheckLimit(key string, limit RateLimit) (bool, error)
    IncrementCounter(key string, window time.Duration) error
    GetCurrentUsage(key string) (*UsageStats, error)
    ResetLimit(key string) error
}
```

### 4. SQL Execution Security Component

**Technology**: Go with SQL parsing and validation
**Responsibilities**:
- SQL query validation and sanitization
- Operation-based access control
- Query execution monitoring and limits
- Dangerous operation detection
- Audit trail for all SQL operations

**Key Interfaces**:
```go
type SQLSecurityService interface {
    ValidateQuery(query string, userRoles []string, context SecurityContext) (*ValidationResult, error)
    ExecuteSecureQuery(query string, userID string, timeout time.Duration) (*QueryResult, error)
    CheckQueryPermissions(query string, userCapabilities AdminCapabilities) error
    
    // Query analysis
    AnalyzeQuery(query string) (*QueryAnalysis, error)
    DetectDangerousOperations(query string) ([]SecurityWarning, error)
    EstimateQueryImpact(query string) (*ImpactAssessment, error)
}

type SQLValidator interface {
    ParseQuery(query string) (*ParsedQuery, error)
    ValidateOperations(operations []SQLOperation, allowedOps []string) error
    CheckForbiddenPatterns(query string, patterns []string) ([]PatternMatch, error)
    ValidateTableAccess(tables []string, userPermissions []TablePermission) error
}

type QueryExecutor interface {
    ExecuteWithTimeout(query string, timeout time.Duration) (*QueryResult, error)
    ExecuteTransaction(queries []string, timeout time.Duration) (*TransactionResult, error)
    CancelQuery(queryID string) error
    GetRunningQueries(userID string) ([]RunningQuery, error)
}
```

### 5. Audit and Monitoring System

**Technology**: Go with structured logging and alerting
**Responsibilities**:
- Comprehensive audit logging
- Security event detection and alerting
- Compliance reporting
- Log retention and archival
- Real-time monitoring and dashboards

**Key Interfaces**:
```go
type AuditSystem interface {
    // Audit logging
    LogAdminAction(action AdminAction) error
    LogSecurityEvent(event SecurityEvent) error
    LogDataAccess(access DataAccessEvent) error
    LogSystemChange(change SystemChangeEvent) error
    
    // Query and reporting
    QueryAuditLogs(filter AuditFilter) ([]AuditEntry, error)
    GenerateComplianceReport(period TimePeriod, format ReportFormat) (*ComplianceReport, error)
    ExportAuditLogs(filter AuditFilter, format ExportFormat) (io.Reader, error)
}

type AlertManager interface {
    CreateAlert(alert SecurityAlert) error
    ProcessAlert(alertID string) error
    GetActiveAlerts(filter AlertFilter) ([]SecurityAlert, error)
    ConfigureAlertRules(rules []AlertRule) error
    
    // Notification management
    SendNotification(notification SecurityNotification) error
    ConfigureNotificationChannels(channels []NotificationChannel) error
}

type MonitoringService interface {
    RecordMetric(metric SecurityMetric) error
    GetMetrics(filter MetricFilter) ([]MetricData, error)
    CreateDashboard(config DashboardConfig) (*Dashboard, error)
    GetSystemHealth() (*HealthStatus, error)
}
```

### 6. CLI Admin Management Component

**Technology**: Go with Cobra CLI framework
**Responsibilities**:
- System admin creation and management
- Environment-aware security policies
- Bootstrap operations for new deployments
- Admin promotion and demotion
- Emergency access procedures

**Key Interfaces**:
```go
type CLIAdminManager interface {
    // System admin operations
    CreateSystemAdmin(req CreateSystemAdminRequest) (*SystemAdmin, error)
    PromoteToSystemAdmin(userID string, promotedBy string) error
    ListSystemAdmins() ([]SystemAdminInfo, error)
    
    // Environment management
    DetectEnvironment() (Environment, error)
    ApplyEnvironmentPolicies(env Environment) error
    ValidateProductionRequirements() error
    
    // Emergency operations
    CreateEmergencyAccess(reason string, duration time.Duration) (*EmergencyAccess, error)
    RevokeEmergencyAccess(accessID string) error
}

type BootstrapService interface {
    InitializeFramework(config BootstrapConfig) error
    CreateInitialAdmin(admin InitialAdminConfig) error
    SetupSecurityPolicies(policies []SecurityPolicy) error
    ValidateDeployment() (*DeploymentValidation, error)
}
```

## Data Models

### Enhanced Security Models

```go
// AdminRole represents hierarchical admin roles
type AdminRole struct {
    ID           string            `json:"id" db:"id"`
    Name         string            `json:"name" db:"name"`
    Level        AdminLevel        `json:"level" db:"level"`
    Capabilities AdminCapabilities `json:"capabilities" db:"capabilities"`
    CreatedBy    string            `json:"created_by" db:"created_by"`
    CreatedAt    time.Time         `json:"created_at" db:"created_at"`
    IsSystemRole bool              `json:"is_system_role" db:"is_system_role"`
}

// AdminCapabilities defines what an admin can do
type AdminCapabilities struct {
    // System-level capabilities (System Admin only)
    CanAccessSQL         bool `json:"can_access_sql"`
    CanManageDatabase    bool `json:"can_manage_database"`
    CanManageSystem      bool `json:"can_manage_system"`
    CanCreateSuperAdmin  bool `json:"can_create_super_admin"`
    
    // Super admin capabilities
    CanCreateAdmins      bool `json:"can_create_admins"`
    CanManageAllTables   bool `json:"can_manage_all_tables"`
    CanManageAuth        bool `json:"can_manage_auth"`
    CanManageStorage     bool `json:"can_manage_storage"`
    CanViewAllLogs       bool `json:"can_view_all_logs"`
    
    // Regular admin capabilities
    CanManageUsers       bool     `json:"can_manage_users"`
    CanManageContent     bool     `json:"can_manage_content"`
    AssignedTables       []string `json:"assigned_tables"`
    AssignedUserGroups   []string `json:"assigned_user_groups"`
    
    // Moderator capabilities
    CanViewReports       bool `json:"can_view_reports"`
    CanModerateContent   bool `json:"can_moderate_content"`
    CanViewBasicLogs     bool `json:"can_view_basic_logs"`
    
    // Common capabilities
    CanViewDashboard     bool `json:"can_view_dashboard"`
    CanExportData        bool `json:"can_export_data"`
}

// TableSecurityConfig represents table-level security configuration
type TableSecurityConfig struct {
    ID              string                 `json:"id" db:"id"`
    TableName       string                 `json:"table_name" db:"table_name"`
    SchemaName      string                 `json:"schema_name" db:"schema_name"`
    DisplayName     string                 `json:"display_name" db:"display_name"`
    Description     string                 `json:"description" db:"description"`
    
    // API Security Configuration
    APIConfig       APISecurityConfig      `json:"api_config" db:"api_config"`
    
    // Admin Panel Configuration
    AdminConfig     AdminPanelConfig       `json:"admin_config" db:"admin_config"`
    
    // Field-level permissions
    FieldPermissions map[string]FieldPermission `json:"field_permissions" db:"field_permissions"`
    
    // Audit configuration
    AuditConfig     AuditConfig            `json:"audit_config" db:"audit_config"`
    
    // Metadata
    CreatedBy       string                 `json:"created_by" db:"created_by"`
    CreatedAt       time.Time              `json:"created_at" db:"created_at"`
    UpdatedBy       string                 `json:"updated_by" db:"updated_by"`
    UpdatedAt       time.Time              `json:"updated_at" db:"updated_at"`
    IsActive        bool                   `json:"is_active" db:"is_active"`
}

// APISecurityConfig defines API-level security settings
type APISecurityConfig struct {
    RequireAuth      bool                   `json:"require_auth"`
    RequireVerified  bool                   `json:"require_verified"`
    AllowedRoles     []string               `json:"allowed_roles"`
    RequireOwnership bool                   `json:"require_ownership"`
    OwnershipColumn  string                 `json:"ownership_column"`
    PublicRead       bool                   `json:"public_read"`
    PublicWrite      bool                   `json:"public_write"`
    
    // Enhanced security features
    RequireMFA       bool                   `json:"require_mfa"`
    IPWhitelist      []string               `json:"ip_whitelist"`
    RateLimit        *RateLimitConfig       `json:"rate_limit"`
    AuditActions     bool                   `json:"audit_actions"`
    
    // Field-level controls
    ReadableFields   []string               `json:"readable_fields"`
    WritableFields   []string               `json:"writable_fields"`
    HiddenFields     []string               `json:"hidden_fields"`
    
    // Advanced filters
    CustomFilters    map[string]string      `json:"custom_filters"`
    TimeBasedAccess  *TimeBasedAccessConfig `json:"time_based_access"`
}

// SecurityEvent represents security-related events for audit
type SecurityEvent struct {
    ID          string                 `json:"id" db:"id"`
    Type        SecurityEventType      `json:"type" db:"type"`
    Severity    SecuritySeverity       `json:"severity" db:"severity"`
    UserID      string                 `json:"user_id" db:"user_id"`
    Resource    string                 `json:"resource" db:"resource"`
    Action      string                 `json:"action" db:"action"`
    Details     map[string]interface{} `json:"details" db:"details"`
    IPAddress   string                 `json:"ip_address" db:"ip_address"`
    UserAgent   string                 `json:"user_agent" db:"user_agent"`
    Timestamp   time.Time              `json:"timestamp" db:"timestamp"`
    
    // Context information
    SessionID   string                 `json:"session_id" db:"session_id"`
    RequestID   string                 `json:"request_id" db:"request_id"`
    Outcome     string                 `json:"outcome" db:"outcome"`
    ErrorCode   string                 `json:"error_code,omitempty" db:"error_code"`
}

// MFAConfiguration represents multi-factor authentication setup
type MFAConfiguration struct {
    UserID          string    `json:"user_id" db:"user_id"`
    Method          MFAMethod `json:"method" db:"method"`
    Secret          string    `json:"secret" db:"secret"`
    BackupCodes     []string  `json:"backup_codes" db:"backup_codes"`
    IsEnabled       bool      `json:"is_enabled" db:"is_enabled"`
    LastUsed        *time.Time `json:"last_used" db:"last_used"`
    CreatedAt       time.Time `json:"created_at" db:"created_at"`
    UpdatedAt       time.Time `json:"updated_at" db:"updated_at"`
}

// AdminSession represents enhanced admin session management
type AdminSession struct {
    ID              string            `json:"id" db:"id"`
    UserID          string            `json:"user_id" db:"user_id"`
    AdminLevel      AdminLevel        `json:"admin_level" db:"admin_level"`
    Capabilities    AdminCapabilities `json:"capabilities" db:"capabilities"`
    IPAddress       string            `json:"ip_address" db:"ip_address"`
    UserAgent       string            `json:"user_agent" db:"user_agent"`
    CreatedAt       time.Time         `json:"created_at" db:"created_at"`
    LastActivity    time.Time         `json:"last_activity" db:"last_activity"`
    ExpiresAt       time.Time         `json:"expires_at" db:"expires_at"`
    IsActive        bool              `json:"is_active" db:"is_active"`
    
    // Security features
    RequiresMFA     bool              `json:"requires_mfa" db:"requires_mfa"`
    MFAVerified     bool              `json:"mfa_verified" db:"mfa_verified"`
    SecurityFlags   []string          `json:"security_flags" db:"security_flags"`
}
```

### Configuration Models

```go
// SecurityConfiguration represents framework-wide security settings
type SecurityConfiguration struct {
    // Authentication settings
    AuthConfig      AuthSecurityConfig     `yaml:"auth"`
    
    // Session management
    SessionConfig   SessionConfig          `yaml:"session"`
    
    // Rate limiting
    RateLimitConfig RateLimitGlobalConfig  `yaml:"rate_limit"`
    
    // Audit settings
    AuditConfig     GlobalAuditConfig      `yaml:"audit"`
    
    // MFA settings
    MFAConfig       MFAGlobalConfig        `yaml:"mfa"`
    
    // Environment-specific overrides
    EnvironmentOverrides map[string]interface{} `yaml:"environment_overrides"`
}

// AuthSecurityConfig represents authentication security settings
type AuthSecurityConfig struct {
    // Password policies
    PasswordPolicy  PasswordPolicy         `yaml:"password_policy"`
    
    // Session security
    SessionSecurity SessionSecurityConfig  `yaml:"session_security"`
    
    // Account lockout
    LockoutPolicy   AccountLockoutPolicy   `yaml:"lockout_policy"`
    
    // Admin-specific settings
    AdminAuthConfig AdminAuthConfig        `yaml:"admin_auth"`
}

// RateLimitGlobalConfig represents global rate limiting configuration
type RateLimitGlobalConfig struct {
    // Default limits
    DefaultLimits   map[string]RateLimit   `yaml:"default_limits"`
    
    // Admin-specific limits
    AdminLimits     map[string]RateLimit   `yaml:"admin_limits"`
    
    // Emergency limits
    EmergencyLimits map[string]RateLimit   `yaml:"emergency_limits"`
    
    // DDoS protection
    DDoSProtection  DDoSProtectionConfig   `yaml:"ddos_protection"`
}
```

## Error Handling

### Enhanced Security Error Handling

```go
// SecurityError represents security-specific errors
type SecurityError struct {
    Code        SecurityErrorCode      `json:"code"`
    Message     string                 `json:"message"`
    Details     map[string]interface{} `json:"details,omitempty"`
    Severity    SecuritySeverity       `json:"severity"`
    UserID      string                 `json:"user_id,omitempty"`
    Resource    string                 `json:"resource,omitempty"`
    Action      string                 `json:"action,omitempty"`
    Timestamp   time.Time              `json:"timestamp"`
    RequestID   string                 `json:"request_id,omitempty"`
    ShouldAudit bool                   `json:"-"`
    ShouldAlert bool                   `json:"-"`
}

func (e *SecurityError) Error() string {
    return fmt.Sprintf("[%s] %s", e.Code, e.Message)
}

// Security error types
var (
    ErrInsufficientPrivileges = &SecurityError{
        Code:        "INSUFFICIENT_PRIVILEGES",
        Message:     "Insufficient privileges for this operation",
        Severity:    SeverityMedium,
        ShouldAudit: true,
        ShouldAlert: false,
    }
    
    ErrMFARequired = &SecurityError{
        Code:        "MFA_REQUIRED",
        Message:     "Multi-factor authentication required",
        Severity:    SeverityLow,
        ShouldAudit: true,
        ShouldAlert: false,
    }
    
    ErrSuspiciousActivity = &SecurityError{
        Code:        "SUSPICIOUS_ACTIVITY",
        Message:     "Suspicious activity detected",
        Severity:    SeverityHigh,
        ShouldAudit: true,
        ShouldAlert: true,
    }
    
    ErrDangerousSQL = &SecurityError{
        Code:        "DANGEROUS_SQL",
        Message:     "SQL query contains dangerous operations",
        Severity:    SeverityHigh,
        ShouldAudit: true,
        ShouldAlert: true,
    }
    
    ErrRateLimitExceeded = &SecurityError{
        Code:        "RATE_LIMIT_EXCEEDED",
        Message:     "Rate limit exceeded",
        Severity:    SeverityMedium,
        ShouldAudit: true,
        ShouldAlert: false,
    }
)

// Security middleware for error handling
func SecurityErrorMiddleware(auditSystem AuditSystem, alertManager AlertManager) gin.HandlerFunc {
    return func(c *gin.Context) {
        c.Next()
        
        if len(c.Errors) > 0 {
            err := c.Errors.Last().Err
            
            var secErr *SecurityError
            if errors.As(err, &secErr) {
                // Audit security errors
                if secErr.ShouldAudit {
                    auditEvent := SecurityEvent{
                        Type:      SecurityEventTypeError,
                        Severity:  secErr.Severity,
                        UserID:    secErr.UserID,
                        Resource:  secErr.Resource,
                        Action:    secErr.Action,
                        Details:   secErr.Details,
                        IPAddress: c.ClientIP(),
                        UserAgent: c.GetHeader("User-Agent"),
                        Timestamp: time.Now(),
                        RequestID: secErr.RequestID,
                        Outcome:   "ERROR",
                        ErrorCode: string(secErr.Code),
                    }
                    auditSystem.LogSecurityEvent(auditEvent)
                }
                
                // Send alerts for high-severity errors
                if secErr.ShouldAlert {
                    alert := SecurityAlert{
                        Type:        AlertTypeSecurityViolation,
                        Severity:    secErr.Severity,
                        Title:       secErr.Message,
                        Description: fmt.Sprintf("Security error occurred: %s", secErr.Error()),
                        UserID:      secErr.UserID,
                        Resource:    secErr.Resource,
                        Metadata:    secErr.Details,
                        Timestamp:   time.Now(),
                    }
                    alertManager.CreateAlert(alert)
                }
                
                // Return appropriate HTTP response
                status := getHTTPStatusForSecurityError(secErr.Code)
                c.JSON(status, gin.H{
                    "error": secErr.Message,
                    "code":  secErr.Code,
                })
            } else {
                // Handle non-security errors normally
                c.JSON(500, gin.H{
                    "error": "Internal server error",
                    "code":  "INTERNAL_ERROR",
                })
            }
        }
    }
}
```

## Testing Strategy

### Security Testing Framework

```go
// SecurityTestSuite provides comprehensive security testing
type SecurityTestSuite struct {
    testDB          *sql.DB
    authService     AuthenticationCore
    rbacEngine      RBACEngine
    auditSystem     AuditSystem
    testUsers       map[AdminLevel]*User
    testSessions    map[AdminLevel]*AdminSession
}

func (s *SecurityTestSuite) SetupSuite() {
    // Setup test database with security schema
    s.testDB = setupSecurityTestDB()
    
    // Initialize security services
    s.authService = NewAuthenticationCore(s.testDB)
    s.rbacEngine = NewRBACEngine(s.testDB)
    s.auditSystem = NewAuditSystem(s.testDB)
    
    // Create test users for each admin level
    s.createTestUsers()
    s.createTestSessions()
}

func (s *SecurityTestSuite) TestAdminHierarchy() {
    tests := []struct {
        name        string
        userLevel   AdminLevel
        action      string
        resource    string
        expectAllow bool
    }{
        {
            name:        "SystemAdmin can access SQL editor",
            userLevel:   SystemAdmin,
            action:      "execute_sql",
            resource:    "sql_editor",
            expectAllow: true,
        },
        {
            name:        "SuperAdmin cannot access SQL editor",
            userLevel:   SuperAdmin,
            action:      "execute_sql",
            resource:    "sql_editor",
            expectAllow: false,
        },
        {
            name:        "RegularAdmin can manage assigned tables",
            userLevel:   RegularAdmin,
            action:      "manage_table",
            resource:    "assigned_table_1",
            expectAllow: true,
        },
        {
            name:        "Moderator cannot manage tables",
            userLevel:   Moderator,
            action:      "manage_table",
            resource:    "any_table",
            expectAllow: false,
        },
    }
    
    for _, tt := range tests {
        s.T().Run(tt.name, func(t *testing.T) {
            user := s.testUsers[tt.userLevel]
            context := SecurityContext{
                UserID:    user.ID,
                IPAddress: "127.0.0.1",
                UserAgent: "test-agent",
            }
            
            allowed, err := s.rbacEngine.CheckPermission(
                user.ID, tt.resource, tt.action, context,
            )
            
            assert.NoError(t, err)
            assert.Equal(t, tt.expectAllow, allowed)
        })
    }
}

func (s *SecurityTestSuite) TestSQLSecurityValidation() {
    dangerousQueries := []struct {
        query       string
        userLevel   AdminLevel
        shouldAllow bool
        reason      string
    }{
        {
            query:       "DROP TABLE users;",
            userLevel:   SystemAdmin,
            shouldAllow: true,
            reason:      "System admin can drop tables",
        },
        {
            query:       "DROP TABLE users;",
            userLevel:   SuperAdmin,
            shouldAllow: false,
            reason:      "Super admin cannot drop tables",
        },
        {
            query:       "SELECT * FROM users WHERE id = $1;",
            userLevel:   RegularAdmin,
            shouldAllow: true,
            reason:      "Regular admin can select with parameters",
        },
        {
            query:       "DELETE FROM users;",
            userLevel:   RegularAdmin,
            shouldAllow: false,
            reason:      "Regular admin cannot delete all users",
        },
    }
    
    sqlValidator := NewSQLValidator()
    
    for _, tt := range dangerousQueries {
        s.T().Run(tt.reason, func(t *testing.T) {
            user := s.testUsers[tt.userLevel]
            capabilities, _ := s.rbacEngine.GetUserCapabilities(user.ID)
            
            err := sqlValidator.ValidateQuery(tt.query, []string{string(tt.userLevel)}, SecurityContext{
                UserID: user.ID,
            })
            
            if tt.shouldAllow {
                assert.NoError(t, err, "Query should be allowed: %s", tt.reason)
            } else {
                assert.Error(t, err, "Query should be blocked: %s", tt.reason)
            }
        })
    }
}

func (s *SecurityTestSuite) TestAuditLogging() {
    // Test that security events are properly logged
    user := s.testUsers[SystemAdmin]
    
    // Perform an action that should be audited
    action := AdminAction{
        UserID:    user.ID,
        Type:      "SQL_EXECUTION",
        Resource:  "users_table",
        Details:   map[string]interface{}{"query": "SELECT COUNT(*) FROM users"},
        IPAddress: "127.0.0.1",
        UserAgent: "test-agent",
        Timestamp: time.Now(),
    }
    
    err := s.auditSystem.LogAdminAction(action)
    assert.NoError(s.T(), err)
    
    // Verify the audit log entry
    filter := AuditFilter{
        UserID:    user.ID,
        StartTime: time.Now().Add(-1 * time.Minute),
        EndTime:   time.Now().Add(1 * time.Minute),
    }
    
    logs, err := s.auditSystem.QueryAuditLogs(filter)
    assert.NoError(s.T(), err)
    assert.Len(s.T(), logs, 1)
    assert.Equal(s.T(), action.Type, logs[0].Type)
}
```

### Integration Testing

```go
// Integration tests for admin panel security
func TestAdminPanelSecurity(t *testing.T) {
    // Setup test server with security middleware
    router := setupTestRouter()
    server := httptest.NewServer(router)
    defer server.Close()
    
    // Test cases for different admin levels
    testCases := []struct {
        name           string
        adminLevel     AdminLevel
        endpoint       string
        method         string
        expectedStatus int
    }{
        {
            name:           "System admin can access SQL editor",
            adminLevel:     SystemAdmin,
            endpoint:       "/admin/sql-editor",
            method:         "GET",
            expectedStatus: 200,
        },
        {
            name:           "Super admin cannot access SQL editor",
            adminLevel:     SuperAdmin,
            endpoint:       "/admin/sql-editor",
            method:         "GET",
            expectedStatus: 403,
        },
        {
            name:           "Regular admin can access user management",
            adminLevel:     RegularAdmin,
            endpoint:       "/admin/users",
            method:         "GET",
            expectedStatus: 200,
        },
    }
    
    for _, tc := range testCases {
        t.Run(tc.name, func(t *testing.T) {
            // Create test user and session
            user := createTestUser(tc.adminLevel)
            token := createTestToken(user)
            
            // Make request with authentication
            req, _ := http.NewRequest(tc.method, server.URL+tc.endpoint, nil)
            req.Header.Set("Authorization", "Bearer "+token)
            
            resp, err := http.DefaultClient.Do(req)
            assert.NoError(t, err)
            assert.Equal(t, tc.expectedStatus, resp.StatusCode)
        })
    }
}
```

## Security Considerations

### Defense in Depth Strategy

1. **Network Layer Security**
   - IP whitelisting for admin access
   - DDoS protection and rate limiting
   - TLS encryption for all communications

2. **Application Layer Security**
   - Input validation and sanitization
   - SQL injection prevention
   - XSS protection with CSP headers

3. **Authentication Layer Security**
   - Multi-factor authentication
   - Strong password policies
   - Session management with secure cookies

4. **Authorization Layer Security**
   - Role-based access control
   - Principle of least privilege
   - Context-aware permissions

5. **Database Layer Security**
   - Row Level Security (RLS) policies
   - Encrypted connections
   - Audit logging at database level

### Threat Modeling

```go
// ThreatModel represents identified security threats
type ThreatModel struct {
    Threats []SecurityThreat `json:"threats"`
}

type SecurityThreat struct {
    ID          string           `json:"id"`
    Name        string           `json:"name"`
    Description string           `json:"description"`
    Category    ThreatCategory   `json:"category"`
    Severity    ThreatSeverity   `json:"severity"`
    Likelihood  ThreatLikelihood `json:"likelihood"`
    Impact      ThreatImpact     `json:"impact"`
    Mitigations []Mitigation     `json:"mitigations"`
}

// Common threats and mitigations
var CommonThreats = ThreatModel{
    Threats: []SecurityThreat{
        {
            ID:          "PRIV_ESCALATION",
            Name:        "Privilege Escalation",
            Description: "Unauthorized elevation of user privileges",
            Category:    ThreatCategoryAuthorization,
            Severity:    ThreatSeverityHigh,
            Likelihood:  ThreatLikelihoodMedium,
            Impact:      ThreatImpactHigh,
            Mitigations: []Mitigation{
                {Type: "RBAC", Description: "Strict role-based access control"},
                {Type: "AUDIT", Description: "Comprehensive audit logging"},
                {Type: "MFA", Description: "Multi-factor authentication for sensitive operations"},
            },
        },
        {
            ID:          "SQL_INJECTION",
            Name:        "SQL Injection",
            Description: "Malicious SQL code injection through admin interfaces",
            Category:    ThreatCategoryInjection,
            Severity:    ThreatSeverityCritical,
            Likelihood:  ThreatLikelihoodMedium,
            Impact:      ThreatImpactCritical,
            Mitigations: []Mitigation{
                {Type: "VALIDATION", Description: "SQL query validation and sanitization"},
                {Type: "PREPARED_STATEMENTS", Description: "Use prepared statements"},
                {Type: "LEAST_PRIVILEGE", Description: "Database user with minimal privileges"},
            },
        },
    },
}
```

## Performance Considerations

### Security Performance Optimization

1. **Permission Caching**
   - Cache frequently accessed permissions
   - Implement cache invalidation strategies
   - Use Redis for distributed caching

2. **Audit Log Optimization**
   - Asynchronous audit logging
   - Log aggregation and batching
   - Efficient storage and indexing

3. **Rate Limiting Efficiency**
   - Sliding window algorithms
   - Distributed rate limiting
   - Memory-efficient counters

4. **Session Management**
   - Efficient session storage
   - Session cleanup processes
   - Distributed session management

```go
// PerformanceOptimizedRBAC implements caching for better performance
type PerformanceOptimizedRBAC struct {
    rbacEngine      RBACEngine
    permissionCache PermissionCache
    cacheConfig     CacheConfig
}

func (p *PerformanceOptimizedRBAC) CheckPermission(userID, resource, action string, context SecurityContext) (bool, error) {
    // Check cache first
    cacheKey := fmt.Sprintf("%s:%s:%s", userID, resource, action)
    if cached, err := p.permissionCache.GetCachedPermission(userID, resource, action); err == nil && cached != nil {
        return *cached, nil
    }
    
    // Evaluate permission
    result, err := p.rbacEngine.CheckPermission(userID, resource, action, context)
    if err != nil {
        return false, err
    }
    
    // Cache the result
    p.permissionCache.CachePermission(userID, resource, action, result, p.cacheConfig.TTL)
    
    return result, nil
}
```

## Deployment Architecture

### Security-Enhanced Deployment

```yaml
# docker-compose.security.yml
version: '3.8'
services:
  postgres:
    image: postgres:15
    environment:
      POSTGRES_DB: goforward_secure
      POSTGRES_USER: postgres
      POSTGRES_PASSWORD: ${DB_PASSWORD}
    volumes:
      - postgres_data:/var/lib/postgresql/data
      - ./security/init.sql:/docker-entrypoint-initdb.d/init.sql
    networks:
      - secure_network
    
  redis:
    image: redis:7-alpine
    command: redis-server --requirepass ${REDIS_PASSWORD}
    networks:
      - secure_network
    
  goforward:
    build: 
      context: .
      dockerfile: Dockerfile.security
    environment:
      DATABASE_URL: postgres://postgres:${DB_PASSWORD}@postgres:5432/goforward_secure
      REDIS_URL: redis://:${REDIS_PASSWORD}@redis:6379
      JWT_SECRET: ${JWT_SECRET}
      ENCRYPTION_KEY: ${ENCRYPTION_KEY}
      ENVIRONMENT: production
    networks:
      - secure_network
    depends_on:
      - postgres
      - redis
    
  nginx:
    image: nginx:alpine
    ports:
      - "443:443"
      - "80:80"
    volumes:
      - ./nginx/nginx.conf:/etc/nginx/nginx.conf
      - ./ssl:/etc/ssl/certs
    networks:
      - secure_network
    depends_on:
      - goforward

networks:
  secure_network:
    driver: bridge
    internal: true

volumes:
  postgres_data:
```

### Security Hardening Configuration

```nginx
# nginx.conf with security headers
server {
    listen 443 ssl http2;
    server_name your-domain.com;
    
    ssl_certificate /etc/ssl/certs/cert.pem;
    ssl_certificate_key /etc/ssl/certs/key.pem;
    
    # Security headers
    add_header X-Frame-Options DENY;
    add_header X-Content-Type-Options nosniff;
    add_header X-XSS-Protection "1; mode=block";
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains";
    add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'";
    
    # Rate limiting
    limit_req_zone $binary_remote_addr zone=admin:10m rate=10r/m;
    limit_req_zone $binary_remote_addr zone=api:10m rate=100r/m;
    
    location /admin {
        limit_req zone=admin burst=5 nodelay;
        proxy_pass http://goforward:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }
    
    location /api {
        limit_req zone=api burst=20 nodelay;
        proxy_pass http://goforward:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }
}
```

This comprehensive design provides a robust foundation for implementing enterprise-grade security in the Go Forward framework while maintaining its flexibility and ease of use.
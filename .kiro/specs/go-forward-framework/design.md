# Design Document

## Overview

Go Forward is a comprehensive backend framework built in Go that provides authentication, database management with real-time capabilities, auto-generated APIs, file storage, and an admin dashboard. The framework follows Supabase's architectural patterns while being designed as a self-contained, open-source solution for personal and internal projects.

The system is designed around a microservices architecture where each component can work independently but integrates seamlessly with others. The core principle is to provide a batteries-included backend solution that requires minimal configuration while remaining highly extensible.

## Architecture

### High-Level Architecture

```mermaid
graph TB
    Client[Client Applications] --> Gateway[API Gateway]
    Dashboard[Next.js Admin Dashboard] --> Gateway
    
    Gateway --> Auth[Auth Service]
    Gateway --> API[REST API Service]
    Gateway --> Realtime[Realtime Service]
    Gateway --> Storage[Storage Service]
    Gateway --> Meta[Database Meta Service]
    
    Auth --> DB[(PostgreSQL)]
    API --> DB
    Realtime --> DB
    Storage --> FS[File System]
    Meta --> DB
    
    subgraph "Core Services"
        Auth
        API
        Realtime
        Storage
        Meta
    end
    
    subgraph "Infrastructure"
        DB
        FS
        Redis[(Redis Cache)]
    end
    
    Auth --> Redis
    Realtime --> Redis
```

### Service Architecture

The framework consists of several core services with enhanced security:

1. **API Gateway**: Routes requests and handles cross-cutting concerns (CORS, rate limiting, logging, security)
2. **Auth Service**: Handles authentication, JWT management, user operations, and admin role management
3. **REST API Service**: Auto-generates CRUD endpoints from database schema with table-level security
4. **Realtime Service**: Manages WebSocket connections and real-time data streaming
5. **Storage Service**: Handles file uploads, downloads, and access control
6. **Database Meta Service**: Provides database introspection and management APIs with security controls
7. **Migration Service**: Handles database schema migrations
8. **Security Service**: Manages audit logging, security monitoring, and policy enforcement
9. **Admin CLI Service**: Provides command-line tools for admin management and system bootstrap

## Components and Interfaces

### 1. API Gateway Component

**Technology**: Go with Gin framework
**Responsibilities**:
- Request routing and load balancing
- Authentication middleware
- Rate limiting and throttling
- CORS handling
- Request/response logging
- Health checks

**Key Interfaces**:
```go
type Gateway interface {
    RegisterService(name string, handler http.Handler)
    AddMiddleware(middleware gin.HandlerFunc)
    Start(port string) error
    Stop() error
}

type Middleware interface {
    Handle() gin.HandlerFunc
}
```

### 2. Authentication Service

**Technology**: Go with JWT-go library and enhanced security features
**Responsibilities**:
- User registration and login
- OTP generation and validation (email/SMS)
- JWT token management
- Custom auth model support
- Password hashing and validation
- Admin role management and hierarchical permissions
- Multi-factor authentication (TOTP, backup codes)
- Session management with security controls
- API key management

**Key Interfaces**:
```go
type AuthService interface {
    Register(req RegisterRequest) (*User, error)
    Login(req LoginRequest) (*AuthResponse, error)
    SendOTP(req OTPRequest) error
    VerifyOTP(req VerifyOTPRequest) (*AuthResponse, error)
    ValidateToken(token string) (*Claims, error)
    RefreshToken(refreshToken string) (*AuthResponse, error)
    
    // Admin management
    CreateAdmin(req CreateAdminRequest) (*User, error)
    AssignAdminRole(userID string, role AdminRole, assignedBy string) error
    GetUserCapabilities(userID string) (*AdminCapabilities, error)
    
    // MFA management
    EnableMFA(userID string, method MFAMethod) (*MFASetup, error)
    VerifyMFA(userID string, code string) error
    GenerateBackupCodes(userID string) ([]string, error)
    
    // Session management
    CreateAdminSession(userID string, capabilities AdminCapabilities) (*AdminSession, error)
    ValidateSession(sessionID string) (*AdminSession, error)
    InvalidateSession(sessionID string) error
}

type CustomAuthProvider interface {
    Authenticate(credentials map[string]interface{}) (*User, error)
    ValidateCredentials(credentials map[string]interface{}) error
}

type SecurityMonitor interface {
    RecordAuthAttempt(userID string, success bool, metadata SecurityMetadata) error
    DetectSuspiciousActivity(userID string) (*SecurityAlert, error)
    TriggerAccountLockout(userID string, reason string) error
}
```

### 3. REST API Service

**Technology**: Go with automatic code generation
**Responsibilities**:
- Auto-generate CRUD endpoints from database schema
- Query parameter handling (filtering, sorting, pagination)
- Request validation
- Response formatting
- RLS policy enforcement

**Key Interfaces**:
```go
type APIService interface {
    GenerateEndpoints(schema DatabaseSchema) error
    RegisterCustomEndpoint(path string, handler http.HandlerFunc)
    ApplyRLSPolicies(userID string, query Query) Query
}

type QueryBuilder interface {
    Select(columns ...string) QueryBuilder
    Where(condition string, args ...interface{}) QueryBuilder
    OrderBy(column string, direction string) QueryBuilder
    Limit(limit int) QueryBuilder
    Offset(offset int) QueryBuilder
    Execute() ([]map[string]interface{}, error)
}
```

### 4. Realtime Service

**Technology**: Go with Gorilla WebSocket
**Responsibilities**:
- WebSocket connection management
- Real-time database change streaming
- Broadcast messaging
- Presence tracking
- Channel management

**Key Interfaces**:
```go
type RealtimeService interface {
    CreateChannel(name string, config ChannelConfig) (*Channel, error)
    BroadcastMessage(channelName string, message Message) error
    SubscribeToChanges(channelName string, filter ChangeFilter) error
    TrackPresence(channelName string, userID string, state map[string]interface{}) error
}

type Channel interface {
    Subscribe(conn *websocket.Conn, userID string) error
    Unsubscribe(conn *websocket.Conn) error
    Broadcast(message Message) error
    GetPresence() map[string]interface{}
}
```

### 5. Storage Service

**Technology**: Go with local file system or S3-compatible storage
**Responsibilities**:
- File upload and download
- Access control and permissions
- File metadata management
- Image transformations (optional)
- CDN integration (optional)

**Key Interfaces**:
```go
type StorageService interface {
    Upload(bucket string, path string, file io.Reader, metadata FileMetadata) (*FileInfo, error)
    Download(bucket string, path string) (io.Reader, error)
    Delete(bucket string, path string) error
    GetFileInfo(bucket string, path string) (*FileInfo, error)
    ListFiles(bucket string, prefix string) ([]*FileInfo, error)
}

type AccessControl interface {
    CanRead(userID string, bucket string, path string) bool
    CanWrite(userID string, bucket string, path string) bool
    CanDelete(userID string, bucket string, path string) bool
}
```

### 6. Database Meta Service

**Technology**: Go with database/sql and PostgreSQL driver
**Responsibilities**:
- Database schema introspection
- Table and column management
- Index management
- RLS policy management
- Migration execution
- SQL execution security and validation

**Key Interfaces**:
```go
type MetaService interface {
    GetTables(schema string) ([]*Table, error)
    CreateTable(table TableDefinition) error
    UpdateTable(tableName string, changes TableChanges) error
    DeleteTable(tableName string) error
    ExecuteSQL(query string, args ...interface{}, options *SQLExecutionOptions) (*QueryResult, error)
    
    // Security enhancements
    ValidateSQL(query string, userRoles []string) error
    CheckQueryPermissions(query string, userCapabilities AdminCapabilities) error
}

type MigrationService interface {
    CreateMigration(name string, up string, down string) (*Migration, error)
    ApplyMigration(migrationID string) error
    RollbackMigration(migrationID string) error
    GetMigrationHistory() ([]*Migration, error)
}

type SQLSecurityService interface {
    ValidateQuery(query string, userRoles []string, context SecurityContext) (*ValidationResult, error)
    ExecuteSecureQuery(query string, userID string, timeout time.Duration) (*QueryResult, error)
    AnalyzeQuery(query string) (*QueryAnalysis, error)
    DetectDangerousOperations(query string) ([]SecurityWarning, error)
}
```

### 7. Security Service

**Technology**: Go with structured logging and security monitoring
**Responsibilities**:
- Comprehensive audit logging
- Security event detection and alerting
- Table-level security configuration
- Policy enforcement and validation
- Compliance reporting

**Key Interfaces**:
```go
type SecurityService interface {
    // Audit logging
    LogAdminAction(action AdminAction) error
    LogSecurityEvent(event SecurityEvent) error
    LogDataAccess(access DataAccessEvent) error
    
    // Security monitoring
    RecordSecurityEvent(event SecurityEvent) error
    DetectAnomalousActivity(userID string) (*SecurityAlert, error)
    GenerateComplianceReport(period TimePeriod) (*ComplianceReport, error)
    
    // Table security configuration
    ConfigureTableSecurity(tableName string, config TableSecurityConfig) error
    GetTableSecurityConfig(tableName string) (*TableSecurityConfig, error)
    ValidateTableAccess(userID string, tableName string, action string) (bool, error)
}

type AuditLogger interface {
    LogEvent(event AuditEvent) error
    QueryLogs(filter AuditFilter) ([]AuditEvent, error)
    ExportLogs(filter AuditFilter, format ExportFormat) (io.Reader, error)
}

type PolicyEngine interface {
    EvaluatePolicy(policy SecurityPolicy, context SecurityContext) (bool, error)
    CreateRLSPolicy(tableConfig TableSecurityConfig) (*RLSPolicy, error)
    ApplyFieldLevelSecurity(data map[string]interface{}, permissions FieldPermissions) map[string]interface{}
}
```

### 8. Admin CLI Service

**Technology**: Go with Cobra CLI framework
**Responsibilities**:
- System admin creation and management
- Environment-aware security policies
- Bootstrap operations for new deployments
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
    
    // Bootstrap operations
    InitializeFramework(config BootstrapConfig) error
    CreateInitialAdmin(admin InitialAdminConfig) error
}

type BootstrapService interface {
    SetupSecurityPolicies(policies []SecurityPolicy) error
    ValidateDeployment() (*DeploymentValidation, error)
    CreateEmergencyAccess(reason string, duration time.Duration) (*EmergencyAccess, error)
}
```

## Data Models

### Core Data Models

```go
// User represents a system user with admin capabilities
type User struct {
    ID          string    `json:"id" db:"id"`
    Email       string    `json:"email" db:"email"`
    Phone       string    `json:"phone" db:"phone"`
    Username    string    `json:"username" db:"username"`
    PasswordHash string   `json:"-" db:"password_hash"`
    EmailVerified bool    `json:"email_verified" db:"email_verified"`
    PhoneVerified bool    `json:"phone_verified" db:"phone_verified"`
    Metadata    JSON      `json:"metadata" db:"metadata"`
    CreatedAt   time.Time `json:"created_at" db:"created_at"`
    UpdatedAt   time.Time `json:"updated_at" db:"updated_at"`
    
    // Admin fields
    AdminLevel      AdminLevel        `json:"admin_level,omitempty" db:"admin_level"`
    Capabilities    AdminCapabilities `json:"capabilities,omitempty" db:"capabilities"`
    AssignedTables  []string          `json:"assigned_tables,omitempty" db:"assigned_tables"`
    
    // Security fields
    MFAEnabled      bool              `json:"mfa_enabled" db:"mfa_enabled"`
    MFASecret       string            `json:"-" db:"mfa_secret"`
    BackupCodes     []string          `json:"-" db:"backup_codes"`
    LastLogin       *time.Time        `json:"last_login" db:"last_login"`
    FailedAttempts  int               `json:"failed_attempts" db:"failed_attempts"`
    LockedUntil     *time.Time        `json:"locked_until" db:"locked_until"`
}

// AuthResponse represents authentication response
type AuthResponse struct {
    User         *User  `json:"user"`
    AccessToken  string `json:"access_token"`
    RefreshToken string `json:"refresh_token"`
    ExpiresIn    int    `json:"expires_in"`
}

// Table represents database table metadata
type Table struct {
    Name        string    `json:"name"`
    Schema      string    `json:"schema"`
    Columns     []*Column `json:"columns"`
    Indexes     []*Index  `json:"indexes"`
    Constraints []*Constraint `json:"constraints"`
    RLSEnabled  bool      `json:"rls_enabled"`
}

// Column represents database column metadata with advanced types
type Column struct {
    Name         string `json:"name"`
    Type         string `json:"type"`
    Nullable     bool   `json:"nullable"`
    DefaultValue string `json:"default_value"`
    IsPrimaryKey bool   `json:"is_primary_key"`
    IsForeignKey bool   `json:"is_foreign_key"`
    
    // Advanced data type support
    IsRichText       bool   `json:"is_rich_text"`
    IsFileReference  bool   `json:"is_file_reference"`
    IsJSON          bool   `json:"is_json"`
    IsArray         bool   `json:"is_array"`
    ArrayElementType string `json:"array_element_type,omitempty"`
    
    // Relationship information
    ReferencedTable  string `json:"referenced_table,omitempty"`
    ReferencedColumn string `json:"referenced_column,omitempty"`
    RelationshipType string `json:"relationship_type,omitempty"` // one_to_many, many_to_many
    JunctionTable    string `json:"junction_table,omitempty"`
}

// FileInfo represents stored file metadata
type FileInfo struct {
    ID          string            `json:"id"`
    Bucket      string            `json:"bucket"`
    Path        string            `json:"path"`
    Name        string            `json:"name"`
    Size        int64             `json:"size"`
    MimeType    string            `json:"mime_type"`
    Metadata    map[string]string `json:"metadata"`
    CreatedAt   time.Time         `json:"created_at"`
    UpdatedAt   time.Time         `json:"updated_at"`
}

// Migration represents database migration
type Migration struct {
    ID        string    `json:"id"`
    Name      string    `json:"name"`
    Version   string    `json:"version"`
    UpSQL     string    `json:"up_sql"`
    DownSQL   string    `json:"down_sql"`
    AppliedAt *time.Time `json:"applied_at"`
    CreatedAt time.Time `json:"created_at"`
}

// AdminLevel represents the hierarchical admin levels
type AdminLevel string

const (
    SystemAdmin  AdminLevel = "system_admin"
    SuperAdmin   AdminLevel = "super_admin"
    RegularAdmin AdminLevel = "regular_admin"
    Moderator    AdminLevel = "moderator"
)

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

// Relationship represents table relationships
type Relationship struct {
    ID               string           `json:"id" db:"id"`
    SourceTable      string           `json:"source_table" db:"source_table"`
    SourceColumn     string           `json:"source_column" db:"source_column"`
    TargetTable      string           `json:"target_table" db:"target_table"`
    TargetColumn     string           `json:"target_column" db:"target_column"`
    RelationshipType RelationshipType `json:"relationship_type" db:"relationship_type"`
    JunctionTable    string           `json:"junction_table,omitempty" db:"junction_table"`
    OnUpdate         string           `json:"on_update" db:"on_update"`
    OnDelete         string           `json:"on_delete" db:"on_delete"`
    CreatedAt        time.Time        `json:"created_at" db:"created_at"`
}

// RelationshipType represents the type of relationship
type RelationshipType string

const (
    OneToOne    RelationshipType = "one_to_one"
    OneToMany   RelationshipType = "one_to_many"
    ManyToMany  RelationshipType = "many_to_many"
)

// RichTextField represents rich text content
type RichTextField struct {
    HTML     string                 `json:"html"`
    Text     string                 `json:"text"`
    Metadata map[string]interface{} `json:"metadata,omitempty"`
}

// FileReference represents a reference to a stored file
type FileReference struct {
    FileID   string            `json:"file_id"`
    URL      string            `json:"url"`
    Filename string            `json:"filename"`
    Size     int64             `json:"size"`
    MimeType string            `json:"mime_type"`
    Metadata map[string]string `json:"metadata,omitempty"`
}

// FieldPermission represents field-level permissions
type FieldPermission struct {
    FieldName   string   `json:"field_name"`
    CanRead     bool     `json:"can_read"`
    CanWrite    bool     `json:"can_write"`
    AllowedRoles []string `json:"allowed_roles"`
    IsHidden    bool     `json:"is_hidden"`
    IsMasked    bool     `json:"is_masked"`
}
```

### Configuration Models

```go
// Config represents framework configuration
type Config struct {
    Server    ServerConfig    `yaml:"server"`
    Database  DatabaseConfig  `yaml:"database"`
    Auth      AuthConfig      `yaml:"auth"`
    Storage   StorageConfig   `yaml:"storage"`
    Realtime  RealtimeConfig  `yaml:"realtime"`
    Dashboard DashboardConfig `yaml:"dashboard"`
}

// ServerConfig represents server configuration
type ServerConfig struct {
    Host         string        `yaml:"host"`
    Port         int           `yaml:"port"`
    ReadTimeout  time.Duration `yaml:"read_timeout"`
    WriteTimeout time.Duration `yaml:"write_timeout"`
    CORS         CORSConfig    `yaml:"cors"`
}

// DatabaseConfig represents database configuration
type DatabaseConfig struct {
    Host     string `yaml:"host"`
    Port     int    `yaml:"port"`
    Name     string `yaml:"name"`
    User     string `yaml:"user"`
    Password string `yaml:"password"`
    SSLMode  string `yaml:"ssl_mode"`
    MaxConns int    `yaml:"max_connections"`
}
```

## Error Handling

### Error Types and Patterns

The framework implements a structured error handling system:

```go
// AppError represents application-specific errors
type AppError struct {
    Code    string `json:"code"`
    Message string `json:"message"`
    Details map[string]interface{} `json:"details,omitempty"`
    Status  int    `json:"-"`
}

func (e *AppError) Error() string {
    return e.Message
}

// Common error types
var (
    ErrUnauthorized     = &AppError{Code: "UNAUTHORIZED", Message: "Unauthorized access", Status: 401}
    ErrForbidden        = &AppError{Code: "FORBIDDEN", Message: "Access forbidden", Status: 403}
    ErrNotFound         = &AppError{Code: "NOT_FOUND", Message: "Resource not found", Status: 404}
    ErrValidation       = &AppError{Code: "VALIDATION_ERROR", Message: "Validation failed", Status: 400}
    ErrInternalServer   = &AppError{Code: "INTERNAL_ERROR", Message: "Internal server error", Status: 500}
)
```

### Error Middleware

```go
func ErrorMiddleware() gin.HandlerFunc {
    return func(c *gin.Context) {
        c.Next()
        
        if len(c.Errors) > 0 {
            err := c.Errors.Last().Err
            
            var appErr *AppError
            if errors.As(err, &appErr) {
                c.JSON(appErr.Status, appErr)
            } else {
                c.JSON(500, ErrInternalServer)
            }
        }
    }
}
```

## Testing Strategy

### Unit Testing

- **Framework**: Go's built-in testing package with testify for assertions
- **Coverage Target**: 80% minimum code coverage
- **Mock Strategy**: Use interfaces and dependency injection for easy mocking
- **Test Structure**: Follow table-driven test patterns

### Integration Testing

- **Database Testing**: Use test containers with PostgreSQL for integration tests
- **API Testing**: Test complete request/response cycles
- **Real-time Testing**: Test WebSocket connections and message broadcasting

### End-to-End Testing

- **Framework**: Use Playwright or similar for dashboard testing
- **API Testing**: Use Newman or similar for API endpoint testing
- **Performance Testing**: Use k6 for load testing

### Test Database Strategy

```go
// Test helper for database setup
func SetupTestDB(t *testing.T) *sql.DB {
    db, err := sql.Open("postgres", "postgres://test:test@localhost/test_db")
    require.NoError(t, err)
    
    // Run migrations
    err = RunMigrations(db)
    require.NoError(t, err)
    
    t.Cleanup(func() {
        db.Close()
    })
    
    return db
}
```

### Mock Interfaces

```go
//go:generate mockery --name=AuthService --output=mocks
//go:generate mockery --name=StorageService --output=mocks
//go:generate mockery --name=RealtimeService --output=mocks
```

## Security Considerations

### Authentication Security
- JWT tokens with configurable expiration
- Secure password hashing using bcrypt
- Rate limiting on authentication endpoints
- OTP with time-based expiration

### Database Security
- Row Level Security (RLS) enforcement
- Prepared statements to prevent SQL injection
- Connection pooling with secure configurations
- Audit logging for sensitive operations

### API Security
- CORS configuration
- Request validation and sanitization
- Rate limiting per user/IP
- API key authentication for service-to-service calls

### File Storage Security
- Access control based on user permissions
- File type validation
- Size limits and quotas
- Virus scanning (optional integration)

## Performance Considerations

### Database Optimization
- Connection pooling with pgxpool
- Query optimization and indexing strategies
- Read replicas for scaling reads
- Caching layer with Redis

### Real-time Performance
- WebSocket connection pooling
- Message batching for high-frequency updates
- Horizontal scaling with Redis pub/sub
- Connection cleanup and resource management

### API Performance
- Response caching for read-heavy operations
- Pagination for large datasets
- Compression for API responses
- Background job processing for heavy operations

## Deployment Architecture

### Container Strategy
```dockerfile
# Multi-stage build for Go services
FROM golang:1.21-alpine AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN go build -o main ./cmd/server

FROM alpine:latest
RUN apk --no-cache add ca-certificates
WORKDIR /root/
COPY --from=builder /app/main .
CMD ["./main"]
```

### Docker Compose Setup
```yaml
version: '3.8'
services:
  postgres:
    image: postgres:15
    environment:
      POSTGRES_DB: goforward
      POSTGRES_USER: postgres
      POSTGRES_PASSWORD: password
    volumes:
      - postgres_data:/var/lib/postgresql/data
    ports:
      - "5432:5432"

  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"

  goforward:
    build: .
    ports:
      - "8080:8080"
    depends_on:
      - postgres
      - redis
    environment:
      DATABASE_URL: postgres://postgres:password@postgres:5432/goforward
      REDIS_URL: redis://redis:6379

volumes:
  postgres_data:
``` 
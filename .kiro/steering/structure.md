# Project Structure & Organization

## Directory Layout

### Root Level Structure
```
├── cmd/                    # Application entry points
├── internal/              # Private application code (Go convention)
├── pkg/                   # Public packages (reusable components)
├── dashboard/             # SvelteKit admin dashboard
├── migrations/            # Database migration files
├── old_implementation/    # Legacy code reference
├── .kiro/                # Kiro AI configuration and specs
├── go.mod                # Go module definition
└── README.md             # Project documentation
```

## Core Application Structure

### cmd/ - Application Entry Points
- **cmd/main.go** - Single executable entry point with mode detection
- **cmd/server/** - HTTP server mode
- **cmd/admin/** - CLI admin commands
- **cmd/migrate/** - Migration management tools

### internal/ - Private Application Code
```
internal/
├── api/                   # REST API handlers and routes
├── auth/                  # Authentication service and middleware
├── config/                # Configuration management
├── database/              # Database operations and meta service
├── gateway/               # API gateway and security middleware
├── realtime/              # WebSocket and real-time features
├── storage/               # File storage service
├── email/                 # Email service and templates
├── sms/                   # SMS providers (Arkesel integration)
├── admin/                 # Admin hierarchy and RBAC
├── audit/                 # Audit logging and security monitoring
├── plugin/                # Plugin management system
├── cron/                  # Cron job management
└── server/                # HTTP server setup and routing
```

### pkg/ - Public Packages
```
pkg/
├── errors/                # Unified error handling
├── logger/                # Structured logging utilities
├── interfaces/            # Common interfaces and contracts
├── middleware/            # Reusable HTTP middleware
├── utils/                 # Utility functions
└── types/                 # Shared type definitions
```

### dashboard/ - SvelteKit Admin Interface
```
dashboard/
├── src/
│   ├── routes/           # SvelteKit routes (/_/ prefix)
│   ├── lib/              # Shared components and utilities
│   ├── stores/           # Svelte stores for state management
│   └── app.html          # Main HTML template
├── static/               # Static assets
├── package.json          # pnpm dependencies
└── svelte.config.js      # SvelteKit configuration
```

## Naming Conventions

### Go Code Conventions
- **Packages**: lowercase, single word when possible (`auth`, `storage`, `realtime`)
- **Files**: snake_case for multi-word files (`admin_service.go`, `rate_limiter.go`)
- **Types**: PascalCase (`UnifiedUser`, `AdminCapabilities`, `SecurityConfig`)
- **Functions**: camelCase (`createSystemAdmin`, `validatePermissions`)
- **Constants**: SCREAMING_SNAKE_CASE or PascalCase for exported (`MaxRetryAttempts`, `DefaultTimeout`)

### Database Conventions
- **Tables**: snake_case plural (`users`, `admin_sessions`, `audit_logs`)
- **Columns**: snake_case (`created_at`, `admin_level`, `mfa_enabled`)
- **Indexes**: `idx_tablename_columnname` (`idx_users_email`, `idx_audit_logs_timestamp`)
- **Foreign Keys**: `fk_tablename_referenced_table` (`fk_users_created_by`)

### API Conventions
- **Endpoints**: RESTful with kebab-case (`/api/admin-sessions`, `/api/audit-logs`)
- **Admin Endpoints**: Prefixed with `/_/` (`/_/users`, `/_/security-config`)
- **Query Parameters**: snake_case (`created_after`, `admin_level`, `page_size`)
- **JSON Fields**: snake_case in requests/responses (`admin_level`, `mfa_enabled`)

## File Organization Patterns

### Service Layer Pattern
Each major feature follows this structure:
```
internal/feature/
├── service.go            # Main service interface and implementation
├── models.go             # Data models and types
├── handlers.go           # HTTP handlers
├── middleware.go         # Feature-specific middleware
├── repository.go         # Database operations
├── validation.go         # Input validation
└── feature_test.go       # Comprehensive tests
```

### Configuration Structure
```
config/
├── config.go             # Main configuration struct
├── database.go           # Database configuration
├── auth.go               # Authentication configuration
├── server.go             # Server configuration
├── security.go           # Security policies configuration
└── validation.go         # Configuration validation
```

### Migration Organization
```
migrations/
├── 001_initial_schema.up.sql
├── 001_initial_schema.down.sql
├── 002_add_admin_hierarchy.up.sql
├── 002_add_admin_hierarchy.down.sql
└── schema.sql            # Complete schema for reference
```

## Import Organization

### Go Import Groups (goimports standard)
```go
import (
    // Standard library
    "context"
    "fmt"
    "time"
    
    // Third-party packages
    "github.com/gin-gonic/gin"
    "github.com/golang-jwt/jwt"
    
    // Internal packages
    "github.com/taqiudeen275/go-foward/internal/auth"
    "github.com/taqiudeen275/go-foward/pkg/errors"
)
```

## Security Considerations

### Access Control Structure
- **System Admin**: Full access to all directories and operations
- **Super Admin**: Limited to business logic in `internal/api/`, `internal/database/`
- **Regular Admin**: Scoped access based on assigned resources
- **Moderator**: Read-only access to specific audit and reporting functions

### Sensitive File Handling
- Configuration files with secrets in `.env` or environment variables
- Private keys and certificates in secure directories
- Audit logs with restricted access and integrity protection
- Plugin files with security validation before loading

## Development Workflow

### Feature Development Structure
1. **Spec Creation**: Document in `.kiro/specs/feature-name/`
2. **Implementation**: Follow service layer pattern in `internal/`
3. **Testing**: Comprehensive tests alongside implementation
4. **Documentation**: Auto-generated Swagger + manual docs
5. **Dashboard Integration**: SvelteKit components in `dashboard/src/`

### Code Organization Principles
- **Single Responsibility**: Each package has one clear purpose
- **Dependency Injection**: Services receive dependencies via constructors
- **Interface Segregation**: Small, focused interfaces in `pkg/interfaces/`
- **Error Handling**: Unified error types in `pkg/errors/`
- **Configuration**: Centralized in `internal/config/` with validation
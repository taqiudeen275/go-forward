# Technology Stack & Build System

## Core Technologies

### Backend Stack
- **Language**: Go 1.25.1+
- **Database**: PostgreSQL 13+ with Row Level Security (RLS)
- **Cache**: Redis 6+ for sessions and real-time features
- **Web Framework**: Gin HTTP framework with custom middleware
- **Authentication**: JWT tokens with bcrypt password hashing
- **Real-time**: WebSocket with PostgreSQL logical replication

### Frontend Stack (Admin Dashboard)
- **Framework**: SvelteKit with TypeScript
- **Styling**: Tailwind CSS with mobile-first responsive design
- **Package Manager**: pnpm (required for frontend dependencies)
- **Build**: Static adapter for Go binary embedding
- **Themes**: Light/dark mode with smooth transitions

### Infrastructure & Deployment
- **Containerization**: Docker with multi-stage builds
- **Database Migrations**: Custom CLI tool with rollback support
- **Configuration**: YAML with environment variable overrides
- **Logging**: Structured JSON logging with audit trails
- **Documentation**: Auto-generated Swagger/OpenAPI specs

## Build System

### Single Executable Build
```bash
# Build complete framework (server + CLI + migrations)
go build -o go-forward cmd/main.go

# Build with embedded SvelteKit dashboard
cd dashboard && pnpm install && pnpm build
go build -ldflags="-s -w" -o go-forward cmd/main.go
```

### Development Commands
```bash
# Start development server
go run cmd/main.go

# Run with admin CLI mode
go run cmd/main.go admin create-system-admin

# Run migrations
go run cmd/main.go migrate up

# Build dashboard separately
cd dashboard && pnpm dev
```

### Testing & Quality
```bash
# Run all tests with coverage
go test -cover ./...

# Run security tests
go test -tags=security ./...

# Lint code
golangci-lint run

# Format code
gofmt -s -w .
```

### Docker Development
```bash
# Start development environment
docker-compose -f docker-compose.dev.yml up -d

# Production build
docker build -t go-forward .

# Deploy production
docker-compose -f docker-compose.prod.yml up -d
```

## Key Dependencies

### Go Modules
- `github.com/gin-gonic/gin` - HTTP web framework
- `github.com/lib/pq` or `github.com/jackc/pgx` - PostgreSQL driver
- `github.com/golang-jwt/jwt` - JWT token handling
- `github.com/spf13/cobra` - CLI framework
- `github.com/spf13/viper` - Configuration management
- `golang.org/x/crypto/bcrypt` - Password hashing

### Frontend Dependencies (pnpm)
- `@sveltejs/kit` - SvelteKit framework
- `typescript` - Type safety
- `tailwindcss` - CSS framework
- `@tailwindcss/forms` - Form styling
- `lucide-svelte` - Icon library

## Configuration Management

### Environment Variables
- `DATABASE_URL` - PostgreSQL connection string
- `REDIS_URL` - Redis connection string
- `JWT_SECRET` - JWT signing secret
- `SMTP_*` - Email configuration
- `SMS_*` - SMS provider configuration (Arkesel default)

### Config File Structure
```yaml
server:
  host: "localhost"
  port: 8080
  
database:
  host: "localhost"
  port: 5432
  name: "goforward"
  
auth:
  jwt_secret: "${JWT_SECRET}"
  mfa_enabled: true
  
admin:
  dashboard_prefix: "/_/"
  
templates:
  email_provider: "smtp"
  sms_provider: "arkesel"
```
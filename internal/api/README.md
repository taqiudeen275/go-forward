# Auto-Generated REST API Service

This package implements an auto-generated REST API service that creates CRUD endpoints from database table schemas with comprehensive query parameter support and authentication/authorization integration.

## Features

### 1. Dynamic Endpoint Generation (Task 6.1)
- Automatically generates CRUD endpoints from database table schemas
- Creates HTTP handlers for GET, POST, PUT, DELETE operations
- Supports route registration with proper HTTP method mapping
- Validates request data based on column types and constraints
- Skips system tables (users, migrations, etc.) that are handled by other services

### 2. Query Parameter Support (Task 6.2)
- **Filtering**: Supports equality, range (gt, gte, lt, lte), LIKE, IN, and NULL filters
- **Sorting**: Single and multiple column ordering with ASC/DESC direction
- **Pagination**: LIMIT and OFFSET support with metadata (total count, page info)
- **Column Selection**: Specify which columns to return in responses
- **Type-aware Filtering**: Different filter types based on column data types
  - Numeric/Date columns: Range filters (gt, gte, lt, lte)
  - String columns: LIKE, ILIKE, starts_with, ends_with filters
  - All columns: IN filters, NULL checks

### 3. Authentication and Authorization (Task 6.3)
- **JWT Middleware Integration**: Works with existing auth middleware
- **Role-based Access Control**: Support for role requirements per table
- **Ownership-based Access**: Filter records by ownership column (e.g., user_id)
- **Row Level Security (RLS)**: Foundation for PostgreSQL RLS policy enforcement
- **Flexible Configuration**: Per-table authentication configuration
- **Public/Private Endpoints**: Support for public read/write operations

## Usage Examples

### Basic Endpoint Generation
```go
// Create service
metaService := database.NewMetaService(db)
apiService := api.NewService(metaService)

// Generate endpoints from schema
schema := interfaces.DatabaseSchema{Tables: tables}
err := apiService.GenerateEndpoints(ctx, schema)
```

### With Authentication
```go
// Create auth middleware
authMiddleware := auth.NewMiddleware(jwtManager, authService)

// Configure table-specific auth
apiService.SetTableAuthConfig("products", &api.AuthConfig{
    RequireAuth:      true,
    RequireOwnership: true,
    OwnershipColumn:  "user_id",
    AllowedRoles:     []string{"user", "admin"},
})

// Generate authenticated endpoints
err := apiService.GenerateEndpointsWithAuth(ctx, schema, authMiddleware)
```

### Query Examples

#### Filtering
```
GET /api/v1/products?name=laptop&price_gt=500&category_in=electronics,computers
```

#### Sorting and Pagination
```
GET /api/v1/products?order_by=price DESC,name ASC&limit=20&offset=40
```

#### Column Selection
```
GET /api/v1/products?select=id,name,price&active=true
```

## API Response Format

### List Endpoints
```json
{
  "data": [...],
  "count": 20,
  "total_count": 150,
  "limit": 20,
  "offset": 40,
  "has_more": true,
  "page": 3,
  "total_pages": 8
}
```

### Single Record Endpoints
```json
{
  "data": {...}
}
```

## Authentication Configuration

### AuthConfig Options
- `RequireAuth`: Whether authentication is required
- `RequireVerified`: Whether email/phone verification is required
- `AllowedRoles`: List of roles that can access the endpoint
- `RequireOwnership`: Whether to filter by ownership column
- `OwnershipColumn`: Column name for ownership filtering (e.g., "user_id")
- `PublicRead`: Allow public read access
- `PublicWrite`: Allow public write access

### RLS Policy Support
```go
// Add RLS policy
policy := &api.RLSPolicy{
    TableName:  "products",
    PolicyName: "owner_access",
    Operation:  "SELECT",
    Expression: "user_id = current_user_id()",
    Roles:      []string{"user"},
}
apiService.AddRLSPolicy(policy)
```

## File Structure

- `service.go`: Main service implementation and endpoint generation
- `handlers.go`: HTTP request handlers for CRUD operations
- `query_builder.go`: Query parameter parsing and SQL query building
- `validation.go`: Request data validation based on column types
- `auth.go`: Authentication and authorization integration
- `*_test.go`: Comprehensive test suites for all components

## Testing

The package includes comprehensive tests covering:
- Service initialization and configuration
- Endpoint generation and registration
- Query parameter parsing and SQL building
- Request validation for different data types
- Authentication and authorization flows
- RLS policy management

Run tests with:
```bash
go test ./internal/api/... -v
```

## Integration

The API service integrates with:
- **Database Meta Service**: For table schema introspection
- **Auth Service**: For JWT validation and user management
- **Gateway Service**: For route registration and middleware
- **PostgreSQL**: For RLS policy enforcement (future enhancement)

## Requirements Satisfied

This implementation satisfies the following requirements from the specification:

- **4.1**: Automatic CRUD endpoint creation from table schemas ✅
- **4.2**: JWT middleware integration and authorization ✅
- **4.3**: JSON response formatting and request validation ✅
- **4.4**: Query parameter support for filtering and sorting ✅
- **4.5**: Pagination with LIMIT and OFFSET ✅
- **4.6**: Permission-based access control and RLS foundation ✅
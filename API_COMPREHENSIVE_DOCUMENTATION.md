# GoForward API System - Comprehensive Documentation

## Overview

The GoForward API system provides a powerful auto-generated REST API that dynamically creates CRUD endpoints from your database schema. It features advanced query capabilities, authentication integration, and comprehensive data validation, making it easy to build robust APIs without manual endpoint creation.

## Key Features

- **🚀 Auto-Generated Endpoints**: Automatically creates CRUD endpoints from database table schemas
- **🔍 Advanced Query Support**: Comprehensive filtering, sorting, pagination, and column selection
- **🔐 Authentication & Authorization**: JWT-based auth with role-based access control and ownership filtering
- **✅ Data Validation**: Type-aware validation based on PostgreSQL column types and constraints
- **🛡️ Row Level Security**: Foundation for PostgreSQL RLS policy enforcement
- **📊 Pagination & Metadata**: Complete pagination support with count information
- **🎯 Flexible Configuration**: Per-table authentication and access control configuration
- **🔄 Real-time Integration**: Works seamlessly with the realtime system for live updates

## Architecture

### Core Components

1. **Service Layer** (`service.go`): Main orchestrator for endpoint generation and management
2. **Handlers** (`handlers.go`): HTTP request handlers for CRUD operations
3. **Query Builder** (`query_builder.go`): Advanced SQL query construction with parameter parsing
4. **Authentication** (`auth.go`): JWT middleware integration and authorization logic
5. **Validation** (`validation.go`): Comprehensive request data validation

### Integration Points

- **Database Meta Service**: For table schema introspection and SQL execution
- **Auth Service**: For JWT validation and user management
- **Gateway Service**: For route registration and middleware application
- **Realtime Service**: For database change notifications

## Auto-Generated Endpoints

### Endpoint Generation

The API service automatically generates CRUD endpoints for all non-system tables in your database:

```go
// Initialize and generate endpoints
metaService := database.NewMetaService(db)
apiService := api.NewService(metaService)

// Get database schema
schema, err := metaService.GetDatabaseSchema(ctx)
if err != nil {
    log.Fatal(err)
}

// Generate endpoints automatically
err = apiService.GenerateEndpoints(ctx, schema)
if err != nil {
    log.Fatal(err)
}
```

### Generated Endpoint Patterns

For each table (e.g., `products`), the following endpoints are automatically created:

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/v1/products` | List all records with filtering, sorting, pagination |
| `GET` | `/api/v1/products/:id` | Get a specific record by ID |
| `POST` | `/api/v1/products` | Create a new record |
| `PUT` | `/api/v1/products/:id` | Update an existing record |
| `DELETE` | `/api/v1/products/:id` | Delete a record |

### System Tables Exclusion

The following system tables are automatically excluded from API generation:
- `users` (handled by auth service)
- `user_sessions` (handled by auth service)
- `otps` (handled by auth service)
- `schema_migrations` (migration system)
- `goose_db_version` (migration system)
- `flyway_schema_history` (migration system)

## Advanced Query Features

### 1. Filtering

#### Basic Equality Filtering
```http
GET /api/v1/products?name=laptop&category=electronics
```

#### Range Filtering (Numeric/Date Columns)
```http
GET /api/v1/products?price_gt=100&price_lte=500&created_at_gte=2024-01-01
```

**Available Range Operators:**
- `_gt`: Greater than
- `_gte`: Greater than or equal
- `_lt`: Less than
- `_lte`: Less than or equal

#### String Filtering
```http
GET /api/v1/products?name_like=laptop&description_starts=gaming&brand_ends=tech
```

**Available String Operators:**
- `_like`: Case-insensitive LIKE with wildcards
- `_ilike`: PostgreSQL case-insensitive LIKE
- `_starts`: Starts with (case-insensitive)
- `_ends`: Ends with (case-insensitive)

#### IN Filtering (Multiple Values)
```http
GET /api/v1/products?category_in=electronics,computers,gaming&status_in=active,featured
```

#### NULL Filtering
```http
GET /api/v1/products?description_null=false&discount_null=true
```

### 2. Sorting

#### Single Column Sorting
```http
GET /api/v1/products?order=price&desc=true
```

#### Multiple Column Sorting
```http
GET /api/v1/products?order_by=price DESC,name ASC,created_at DESC
```

### 3. Pagination

#### Basic Pagination
```http
GET /api/v1/products?limit=20&offset=40
```

#### Response with Pagination Metadata
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

### 4. Column Selection

#### Select Specific Columns
```http
GET /api/v1/products?select=id,name,price,category
```

#### Combined Query Example
```http
GET /api/v1/products?select=id,name,price&category=electronics&price_gt=100&order_by=price ASC&limit=10&offset=0
```

## Authentication & Authorization

### Basic Authentication Setup

```go
// Create auth middleware
authMiddleware := auth.NewMiddleware(jwtManager, authService)

// Generate endpoints with authentication
err := apiService.GenerateEndpointsWithAuth(ctx, schema, authMiddleware)
```

### Authentication Configuration

#### Per-Table Configuration
```go
// Configure authentication for specific tables
apiService.SetTableAuthConfig("products", &api.AuthConfig{
    RequireAuth:      true,           // Require JWT authentication
    RequireVerified:  true,           // Require email/phone verification
    AllowedRoles:     []string{"user", "admin"}, // Allowed user roles
    RequireOwnership: true,           // Filter by ownership
    OwnershipColumn:  "user_id",      // Column for ownership filtering
    PublicRead:       false,          // Disable public read access
    PublicWrite:      false,          // Disable public write access
})

// Public table configuration
apiService.SetTableAuthConfig("categories", &api.AuthConfig{
    RequireAuth:      false,
    PublicRead:       true,
    PublicWrite:      false,
})
```

#### AuthConfig Options

| Option | Type | Description |
|--------|------|-------------|
| `RequireAuth` | `bool` | Whether JWT authentication is required |
| `RequireVerified` | `bool` | Whether email/phone verification is required |
| `AllowedRoles` | `[]string` | List of roles that can access the endpoint |
| `RequireOwnership` | `bool` | Whether to filter records by ownership |
| `OwnershipColumn` | `string` | Column name for ownership filtering (e.g., "user_id") |
| `PublicRead` | `bool` | Allow public read access without authentication |
| `PublicWrite` | `bool` | Allow public write access without authentication |

### JWT Token Usage

#### In Query Parameter
```http
GET /api/v1/products?token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

#### In Authorization Header (Recommended)
```http
GET /api/v1/products
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

### Ownership-Based Filtering

When `RequireOwnership` is enabled, the API automatically filters records based on the authenticated user:

```http
# User with ID "user123" will only see their own products
GET /api/v1/products
Authorization: Bearer <user123_token>

# Equivalent to: SELECT * FROM products WHERE user_id = 'user123'
```

### Role-Based Access Control

```go
// Admin-only access
apiService.SetTableAuthConfig("admin_settings", &api.AuthConfig{
    RequireAuth:  true,
    AllowedRoles: []string{"admin"},
})

// Multi-role access
apiService.SetTableAuthConfig("orders", &api.AuthConfig{
    RequireAuth:  true,
    AllowedRoles: []string{"user", "admin", "moderator"},
})
```

## Data Validation

### Automatic Type Validation

The API automatically validates request data based on PostgreSQL column types:

#### Numeric Types
```json
// Valid integer values
{"age": 25, "count": "42", "score": 95.0}

// Invalid - will return validation error
{"age": "not_a_number", "count": 99999999999999999999}
```

#### String Types
```json
// Valid string with length check
{"name": "Product Name", "description": "A great product"}

// Invalid - exceeds VARCHAR(50) limit
{"name": "This is a very long product name that exceeds the column limit"}
```

#### Boolean Types
```json
// Valid boolean representations
{"active": true, "featured": "true", "visible": 1, "enabled": "yes"}

// Invalid boolean
{"active": "maybe"}
```

#### Date/Time Types
```json
// Valid timestamp formats
{"created_at": "2024-01-15T10:30:00Z", "updated_at": "2024-01-15 10:30:00"}

// Invalid timestamp
{"created_at": "not-a-date"}
```

#### JSON Types
```json
// Valid JSON values
{"metadata": {"key": "value"}, "tags": ["tag1", "tag2"], "config": null}
```

#### UUID Types
```json
// Valid UUID
{"id": "123e4567-e89b-12d3-a456-426614174000"}

// Invalid UUID
{"id": "not-a-uuid"}
```

### Validation Error Responses

```json
{
  "error": "validation failed for field 'price': expected numeric value"
}
```

```json
{
  "error": "field 'name' is required"
}
```

```json
{
  "error": "string exceeds maximum length of 255 characters"
}
```

## API Endpoints Reference

### 1. List Records

#### Request
```http
GET /api/v1/{table}?[query_parameters]
Authorization: Bearer <token> (if required)
```

#### Query Parameters
| Parameter | Description | Example |
|-----------|-------------|---------|
| `select` | Columns to return | `select=id,name,price` |
| `limit` | Maximum records | `limit=20` |
| `offset` | Records to skip | `offset=40` |
| `order` | Single column sort | `order=price` |
| `desc` | Descending order | `desc=true` |
| `order_by` | Multi-column sort | `order_by=price DESC,name ASC` |
| `{column}` | Equality filter | `category=electronics` |
| `{column}_gt` | Greater than | `price_gt=100` |
| `{column}_gte` | Greater than or equal | `price_gte=100` |
| `{column}_lt` | Less than | `price_lt=500` |
| `{column}_lte` | Less than or equal | `price_lte=500` |
| `{column}_like` | String contains | `name_like=laptop` |
| `{column}_ilike` | Case-insensitive like | `name_ilike=LAPTOP` |
| `{column}_starts` | Starts with | `name_starts=gaming` |
| `{column}_ends` | Ends with | `name_ends=pro` |
| `{column}_in` | Multiple values | `category_in=electronics,computers` |
| `{column}_null` | NULL check | `description_null=false` |

#### Response
```json
{
  "data": [
    {
      "id": "123e4567-e89b-12d3-a456-426614174000",
      "name": "Gaming Laptop",
      "price": 1299.99,
      "category": "electronics",
      "created_at": "2024-01-15T10:30:00Z"
    }
  ],
  "count": 1,
  "total_count": 150,
  "limit": 20,
  "offset": 0,
  "has_more": true,
  "page": 1,
  "total_pages": 8
}
```

### 2. Get Single Record

#### Request
```http
GET /api/v1/{table}/{id}
Authorization: Bearer <token> (if required)
```

#### Response
```json
{
  "data": {
    "id": "123e4567-e89b-12d3-a456-426614174000",
    "name": "Gaming Laptop",
    "price": 1299.99,
    "category": "electronics",
    "created_at": "2024-01-15T10:30:00Z",
    "updated_at": "2024-01-15T10:30:00Z"
  }
}
```

### 3. Create Record

#### Request
```http
POST /api/v1/{table}
Content-Type: application/json
Authorization: Bearer <token> (if required)

{
  "name": "New Product",
  "price": 299.99,
  "category": "electronics",
  "description": "A great new product"
}
```

#### Response
```json
{
  "data": {
    "id": "456e7890-e89b-12d3-a456-426614174001",
    "name": "New Product",
    "price": 299.99,
    "category": "electronics",
    "description": "A great new product",
    "created_at": "2024-01-15T11:00:00Z",
    "updated_at": "2024-01-15T11:00:00Z"
  }
}
```

### 4. Update Record

#### Request
```http
PUT /api/v1/{table}/{id}
Content-Type: application/json
Authorization: Bearer <token> (if required)

{
  "name": "Updated Product Name",
  "price": 349.99
}
```

#### Response
```json
{
  "data": {
    "id": "456e7890-e89b-12d3-a456-426614174001",
    "name": "Updated Product Name",
    "price": 349.99,
    "category": "electronics",
    "description": "A great new product",
    "created_at": "2024-01-15T11:00:00Z",
    "updated_at": "2024-01-15T11:15:00Z"
  }
}
```

### 5. Delete Record

#### Request
```http
DELETE /api/v1/{table}/{id}
Authorization: Bearer <token> (if required)
```

#### Response
```json
{
  "message": "Record deleted successfully"
}
```

## Row Level Security (RLS)

### RLS Policy Configuration

```go
// Add RLS policy for user-owned records
policy := &api.RLSPolicy{
    TableName:  "products",
    PolicyName: "user_products_policy",
    Operation:  "SELECT",
    Expression: "user_id = current_user_id()",
    Roles:      []string{"user"},
    Conditions: map[string]string{
        "user_context": "authenticated",
    },
}

apiService.AddRLSPolicy(policy)
```

### RLS Policy Types

#### User Ownership Policy
```go
&api.RLSPolicy{
    TableName:  "orders",
    PolicyName: "user_orders",
    Operation:  "ALL",
    Expression: "user_id = current_user_id()",
    Roles:      []string{"user"},
}
```

#### Admin Access Policy
```go
&api.RLSPolicy{
    TableName:  "admin_logs",
    PolicyName: "admin_only",
    Operation:  "ALL",
    Expression: "true", // Admins can access all records
    Roles:      []string{"admin"},
}
```

#### Public Read Policy
```go
&api.RLSPolicy{
    TableName:  "categories",
    PolicyName: "public_read",
    Operation:  "SELECT",
    Expression: "is_public = true",
    Roles:      []string{"anonymous", "user"},
}
```

## Error Handling

### Common Error Responses

#### Authentication Errors
```json
{
  "error": "Authentication required"
}
```

```json
{
  "error": "Invalid or expired token"
}
```

#### Authorization Errors
```json
{
  "error": "Insufficient permissions"
}
```

```json
{
  "error": "Account verification required"
}
```

#### Validation Errors
```json
{
  "error": "validation failed for field 'price': expected numeric value"
}
```

```json
{
  "error": "field 'name' is required"
}
```

```json
{
  "error": "unknown field 'invalid_column'"
}
```

#### Not Found Errors
```json
{
  "error": "Record not found"
}
```

```json
{
  "error": "Table has no primary key"
}
```

#### Database Errors
```json
{
  "error": "Failed to fetch records"
}
```

```json
{
  "error": "Failed to create record"
}
```

## Configuration Examples

### Basic Setup

```go
package main

import (
    "context"
    "log"
    
    "github.com/taqiudeen275/go-foward/internal/api"
    "github.com/taqiudeen275/go-foward/internal/auth"
    "github.com/taqiudeen275/go-foward/internal/database"
)

func main() {
    // Initialize database
    db, err := database.Connect(config.Database)
    if err != nil {
        log.Fatal(err)
    }
    defer db.Close()
    
    // Initialize services
    metaService := database.NewMetaService(db)
    apiService := api.NewService(metaService)
    authService := auth.NewService(db, "jwt-secret", "24h", "168h")
    authMiddleware := auth.NewMiddleware(authService)
    
    // Get database schema
    ctx := context.Background()
    schema, err := metaService.GetDatabaseSchema(ctx)
    if err != nil {
        log.Fatal(err)
    }
    
    // Configure table authentication
    apiService.SetTableAuthConfig("products", &api.AuthConfig{
        RequireAuth:      true,
        RequireOwnership: true,
        OwnershipColumn:  "user_id",
        AllowedRoles:     []string{"user", "admin"},
    })
    
    apiService.SetTableAuthConfig("categories", &api.AuthConfig{
        RequireAuth: false,
        PublicRead:  true,
        PublicWrite: false,
    })
    
    // Generate endpoints with authentication
    err = apiService.GenerateEndpointsWithAuth(ctx, schema, authMiddleware)
    if err != nil {
        log.Fatal(err)
    }
    
    log.Println("API endpoints generated successfully")
}
```

### Advanced Configuration

```go
// Multi-tenant configuration
apiService.SetTableAuthConfig("tenant_data", &api.AuthConfig{
    RequireAuth:      true,
    RequireOwnership: true,
    OwnershipColumn:  "tenant_id",
    AllowedRoles:     []string{"tenant_admin", "tenant_user"},
})

// Admin-only configuration
apiService.SetTableAuthConfig("system_settings", &api.AuthConfig{
    RequireAuth:  true,
    AllowedRoles: []string{"admin", "super_admin"},
})

// Public API configuration
apiService.SetTableAuthConfig("public_content", &api.AuthConfig{
    RequireAuth: false,
    PublicRead:  true,
    PublicWrite: true, // Be careful with this!
})

// Read-only configuration
apiService.SetTableAuthConfig("reports", &api.AuthConfig{
    RequireAuth: true,
    PublicRead:  false,
    PublicWrite: false, // Only authenticated users can read
})
```

## Performance Optimization

### Query Optimization

#### Use Column Selection
```http
# Instead of SELECT *
GET /api/v1/products?select=id,name,price

# Reduces data transfer and improves performance
```

#### Implement Proper Indexing
```sql
-- Index commonly filtered columns
CREATE INDEX idx_products_category ON products(category);
CREATE INDEX idx_products_price ON products(price);
CREATE INDEX idx_products_user_id ON products(user_id);

-- Composite indexes for common filter combinations
CREATE INDEX idx_products_category_price ON products(category, price);
```

#### Use Pagination
```http
# Always use pagination for large datasets
GET /api/v1/products?limit=50&offset=0
```

### Caching Strategies

#### Application-Level Caching
```go
// Implement caching for frequently accessed data
type CachedAPIService struct {
    *api.Service
    cache map[string]interface{}
    ttl   time.Duration
}

func (c *CachedAPIService) GetCachedResults(key string) interface{} {
    // Implement your caching logic
    return c.cache[key]
}
```

#### Database-Level Optimization
```sql
-- Use materialized views for complex aggregations
CREATE MATERIALIZED VIEW product_stats AS
SELECT 
    category,
    COUNT(*) as product_count,
    AVG(price) as avg_price,
    MIN(price) as min_price,
    MAX(price) as max_price
FROM products 
GROUP BY category;

-- Refresh periodically
REFRESH MATERIALIZED VIEW product_stats;
```

## Security Best Practices

### 🔐 Authentication Security

1. **Use Strong JWT Secrets**: Use cryptographically secure random keys
2. **Implement Token Rotation**: Regular refresh token rotation
3. **Validate Token Claims**: Always validate user claims and permissions
4. **Use HTTPS**: Never transmit tokens over unencrypted connections

### 🛡️ Authorization Security

1. **Principle of Least Privilege**: Grant minimum necessary permissions
2. **Ownership Validation**: Always validate record ownership
3. **Role-Based Access**: Implement proper role hierarchies
4. **Input Validation**: Validate all user inputs

### 🔒 Data Security

1. **SQL Injection Prevention**: Use parameterized queries (automatically handled)
2. **Data Sanitization**: Validate and sanitize all inputs
3. **Audit Logging**: Log all data access and modifications
4. **Rate Limiting**: Implement API rate limiting

```go
// Example security configuration
apiService.SetTableAuthConfig("sensitive_data", &api.AuthConfig{
    RequireAuth:      true,
    RequireVerified:  true,
    AllowedRoles:     []string{"verified_user"},
    RequireOwnership: true,
    OwnershipColumn:  "user_id",
    PublicRead:       false,
    PublicWrite:      false,
})
```

## Testing Examples

### Unit Testing

```go
func TestAPIService_GenerateEndpoints(t *testing.T) {
    // Create test database and schema
    db := setupTestDB(t)
    defer db.Close()
    
    metaService := database.NewMetaService(db)
    apiService := api.NewService(metaService)
    
    // Create test table
    schema := interfaces.DatabaseSchema{
        Tables: []*interfaces.Table{
            {
                Name:   "test_products",
                Schema: "public",
                Columns: []*interfaces.Column{
                    {Name: "id", Type: "uuid", IsPrimaryKey: true},
                    {Name: "name", Type: "varchar(255)", Nullable: false},
                    {Name: "price", Type: "decimal(10,2)", Nullable: false},
                },
            },
        },
    }
    
    // Generate endpoints
    err := apiService.GenerateEndpoints(context.Background(), schema)
    assert.NoError(t, err)
    
    // Verify endpoints were created
    endpoints := apiService.GetEndpoints()
    assert.Len(t, endpoints, 5) // GET, GET/:id, POST, PUT, DELETE
}
```

### Integration Testing

```bash
# Test endpoint generation and basic CRUD operations
curl -X POST http://localhost:8080/api/v1/products \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"name": "Test Product", "price": 99.99}'

# Test filtering and pagination
curl -X GET "http://localhost:8080/api/v1/products?category=electronics&price_gt=50&limit=10" \
  -H "Authorization: Bearer $TOKEN"

# Test validation errors
curl -X POST http://localhost:8080/api/v1/products \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"name": "", "price": "invalid"}'
```

### Load Testing

```javascript
// Artillery.js load test configuration
module.exports = {
  config: {
    target: 'http://localhost:8080',
    phases: [
      { duration: 60, arrivalRate: 10 },
      { duration: 120, arrivalRate: 50 },
      { duration: 60, arrivalRate: 100 }
    ],
    headers: {
      'Authorization': 'Bearer {{ $randomString() }}',
      'Content-Type': 'application/json'
    }
  },
  scenarios: [
    {
      name: 'List products',
      weight: 70,
      flow: [
        { get: { url: '/api/v1/products?limit=20' } }
      ]
    },
    {
      name: 'Create product',
      weight: 20,
      flow: [
        {
          post: {
            url: '/api/v1/products',
            json: {
              name: 'Test Product {{ $randomString() }}',
              price: '{{ $randomInt(10, 1000) }}.99'
            }
          }
        }
      ]
    },
    {
      name: 'Get single product',
      weight: 10,
      flow: [
        { get: { url: '/api/v1/products/{{ $randomUUID() }}' } }
      ]
    }
  ]
};
```

## Migration and Deployment

### Database Schema Changes

When you modify your database schema, the API endpoints are automatically updated:

```sql
-- Add new column
ALTER TABLE products ADD COLUMN tags JSONB;

-- The API will automatically:
-- 1. Include 'tags' in validation
-- 2. Allow filtering by tags
-- 3. Accept tags in POST/PUT requests
```

### Deployment Considerations

#### Environment Configuration
```yaml
# config.yaml
api:
  auto_generate: true
  max_page_size: 1000
  default_page_size: 50
  enable_rls: true
  
auth:
  jwt_secret: "${JWT_SECRET}"
  jwt_expiration: "24h"
  refresh_expiration: "168h"
  
database:
  host: "${DB_HOST}"
  port: 5432
  name: "${DB_NAME}"
  user: "${DB_USER}"
  password: "${DB_PASSWORD}"
```

#### Production Checklist

- [ ] Configure strong JWT secrets
- [ ] Enable HTTPS/TLS
- [ ] Set up proper database indexes
- [ ] Configure rate limiting
- [ ] Enable audit logging
- [ ] Set up monitoring and alerting
- [ ] Configure backup strategies
- [ ] Test authentication flows
- [ ] Validate RLS policies
- [ ] Performance test with expected load

## Troubleshooting

### Common Issues

#### 1. Endpoints Not Generated
```
Error: "Table has no primary key"
```
**Solution**: Ensure all tables have a primary key column.

#### 2. Authentication Failures
```
Error: "Authentication required"
```
**Solution**: Check JWT token validity and ensure proper Authorization header.

#### 3. Validation Errors
```
Error: "validation failed for field 'price': expected numeric value"
```
**Solution**: Ensure request data matches expected column types.

#### 4. Permission Denied
```
Error: "Insufficient permissions"
```
**Solution**: Check user roles and table authentication configuration.

### Debug Mode

```go
// Enable debug logging
apiService.SetDebugMode(true)

// This will log:
// - Generated SQL queries
// - Authentication checks
// - Validation steps
// - Performance metrics
```

## Roadmap

### Upcoming Features

- **GraphQL Support**: Auto-generated GraphQL schema and resolvers
- **OpenAPI Documentation**: Automatic OpenAPI/Swagger documentation generation
- **Advanced RLS**: Full PostgreSQL RLS integration with policy management
- **Caching Layer**: Built-in Redis caching for improved performance
- **Audit Logging**: Comprehensive audit trail for all API operations
- **Webhooks**: Configurable webhooks for data change notifications
- **Bulk Operations**: Batch insert/update/delete operations
- **File Upload**: Direct file upload integration with storage service
- **API Versioning**: Support for multiple API versions
- **Custom Validators**: Plugin system for custom validation rules

### Performance Enhancements

- **Query Optimization**: Automatic query plan analysis and optimization
- **Connection Pooling**: Advanced database connection management
- **Response Compression**: Automatic response compression
- **CDN Integration**: Static asset and response caching
- **Horizontal Scaling**: Multi-instance deployment support

This comprehensive API documentation covers all aspects of the GoForward API system, providing developers with everything they need to effectively use and extend the auto-generated REST API functionality.
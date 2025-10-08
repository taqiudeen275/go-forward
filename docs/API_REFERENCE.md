# Go Forward Framework - API Reference

## Base URL
```
http://localhost:8080
```

## Authentication

Most endpoints require authentication. Include the JWT token in the Authorization header:
```
Authorization: Bearer <your_jwt_token>
```

## Response Format

All responses follow this format:
```json
{
  "success": true,
  "data": {...},
  "message": "Success message",
  "error": null
}
```

Error responses:
```json
{
  "success": false,
  "data": null,
  "message": "Error message",
  "error": "Detailed error information"
}
```

## Endpoints

### Authentication

#### Register User
```http
POST /auth/register
Content-Type: application/json

{
  "email": "user@example.com",
  "password": "password123",
  "username": "username",
  "phone": "+1234567890"
}
```

#### Login
```http
POST /auth/login
Content-Type: application/json

{
  "email": "user@example.com",
  "password": "password123"
}
```

Response:
```json
{
  "success": true,
  "data": {
    "access_token": "eyJhbGciOiJIUzI1NiIs...",
    "refresh_token": "eyJhbGciOiJIUzI1NiIs...",
    "expires_in": 86400,
    "user": {
      "id": "uuid",
      "email": "user@example.com",
      "username": "username"
    }
  }
}
```

#### Send OTP
```http
POST /auth/otp/send
Content-Type: application/json

{
  "recipient": "user@example.com",
  "type": "email"
}
```

#### Verify OTP
```http
POST /auth/otp/verify
Content-Type: application/json

{
  "recipient": "user@example.com",
  "code": "123456",
  "type": "email"
}
```

#### Refresh Token
```http
POST /auth/refresh
Content-Type: application/json

{
  "refresh_token": "eyJhbGciOiJIUzI1NiIs..."
}
```

### Database Management

#### List Tables
```http
GET /db/tables
Authorization: Bearer <token>
```

#### Create Table
```http
POST /db/tables
Authorization: Bearer <token>
Content-Type: application/json

{
  "name": "products",
  "columns": [
    {
      "name": "id",
      "type": "UUID",
      "primary_key": true,
      "default": "gen_random_uuid()"
    },
    {
      "name": "name",
      "type": "VARCHAR(255)",
      "nullable": false
    },
    {
      "name": "price",
      "type": "DECIMAL(10,2)",
      "nullable": false
    }
  ]
}
```

#### Get Table Schema
```http
GET /db/tables/{table_name}
Authorization: Bearer <token>
```

#### Execute SQL
```http
POST /db/sql
Authorization: Bearer <token>
Content-Type: application/json

{
  "query": "SELECT * FROM users LIMIT 10"
}
```

### Auto-Generated REST API

For any table in your database, the framework automatically generates CRUD endpoints:

#### List Records
```http
GET /api/{table_name}?limit=10&offset=0&sort=created_at&order=desc
Authorization: Bearer <token>
```

Query parameters:
- `limit`: Number of records to return (default: 50)
- `offset`: Number of records to skip (default: 0)
- `sort`: Column to sort by
- `order`: Sort order (asc/desc)
- `filter[column]`: Filter by column value

#### Create Record
```http
POST /api/{table_name}
Authorization: Bearer <token>
Content-Type: application/json

{
  "name": "Product Name",
  "price": 29.99,
  "description": "Product description"
}
```

#### Get Record by ID
```http
GET /api/{table_name}/{id}
Authorization: Bearer <token>
```

#### Update Record
```http
PUT /api/{table_name}/{id}
Authorization: Bearer <token>
Content-Type: application/json

{
  "name": "Updated Product Name",
  "price": 39.99
}
```

#### Delete Record
```http
DELETE /api/{table_name}/{id}
Authorization: Bearer <token>
```

### File Storage

#### Upload File
```http
POST /storage/upload
Authorization: Bearer <token>
Content-Type: multipart/form-data

file: <file_data>
bucket: public
path: optional/path/
```

#### Download File
```http
GET /storage/download/{file_id}
Authorization: Bearer <token>
```

#### List Files
```http
GET /storage/list?bucket=public&limit=10&offset=0
Authorization: Bearer <token>
```

#### Delete File
```http
DELETE /storage/{file_id}
Authorization: Bearer <token>
```

### Real-time (WebSocket)

#### Connect to WebSocket
```javascript
const ws = new WebSocket('ws://localhost:8080/realtime/ws?token=<your_jwt_token>');
```

#### Subscribe to Channel
```javascript
ws.send(JSON.stringify({
  type: 'subscribe',
  channel: 'table_name'
}));
```

#### Unsubscribe from Channel
```javascript
ws.send(JSON.stringify({
  type: 'unsubscribe',
  channel: 'table_name'
}));
```

#### Broadcast Message
```http
POST /realtime/broadcast
Authorization: Bearer <token>
Content-Type: application/json

{
  "channel": "notifications",
  "message": {
    "type": "notification",
    "title": "New Message",
    "body": "You have a new message"
  }
}
```

### System

#### Health Check
```http
GET /health
```

Response:
```json
{
  "status": "healthy",
  "timestamp": "2024-01-01T12:00:00Z",
  "version": "1.0.0",
  "database": "connected",
  "services": {
    "auth": "running",
    "api": "running",
    "storage": "running",
    "realtime": "running"
  }
}
```

#### System Metrics
```http
GET /metrics
Authorization: Bearer <token>
```

## Error Codes

| Code | Description |
|------|-------------|
| 400 | Bad Request - Invalid input data |
| 401 | Unauthorized - Missing or invalid token |
| 403 | Forbidden - Insufficient permissions |
| 404 | Not Found - Resource not found |
| 409 | Conflict - Resource already exists |
| 422 | Unprocessable Entity - Validation failed |
| 429 | Too Many Requests - Rate limit exceeded |
| 500 | Internal Server Error - Server error |

## Rate Limiting

The API implements rate limiting:
- Default: 100 requests per minute per user
- Burst: 10 requests
- Headers included in response:
  - `X-RateLimit-Limit`: Request limit
  - `X-RateLimit-Remaining`: Remaining requests
  - `X-RateLimit-Reset`: Reset time

## CORS

CORS is configured to allow:
- Origins: Configurable (default: all)
- Methods: GET, POST, PUT, DELETE, OPTIONS
- Headers: All headers allowed
- Credentials: Configurable

## Security Features

- JWT-based authentication
- Password hashing with bcrypt
- Rate limiting
- CORS protection
- SQL injection prevention
- Input validation
- Security headers
- Request ID tracking

## Examples

### Complete User Registration and Login Flow

```bash
# 1. Register a new user
curl -X POST http://localhost:8080/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "john@example.com",
    "password": "securepassword123",
    "username": "johndoe"
  }'

# 2. Login to get JWT token
curl -X POST http://localhost:8080/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "john@example.com",
    "password": "securepassword123"
  }'

# 3. Use the token for authenticated requests
curl -X GET http://localhost:8080/api/users \
  -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIs..."
```

### Working with Tables

```bash
# Create a products table
curl -X POST http://localhost:8080/db/tables \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "products",
    "columns": [
      {"name": "id", "type": "UUID", "primary_key": true, "default": "gen_random_uuid()"},
      {"name": "name", "type": "VARCHAR(255)", "nullable": false},
      {"name": "price", "type": "DECIMAL(10,2)", "nullable": false},
      {"name": "created_at", "type": "TIMESTAMP", "default": "NOW()"}
    ]
  }'

# Add a product
curl -X POST http://localhost:8080/api/products \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Laptop",
    "price": 999.99
  }'

# Get all products
curl -X GET http://localhost:8080/api/products \
  -H "Authorization: Bearer <token>"
```
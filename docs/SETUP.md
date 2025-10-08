# Go Forward Framework - Setup and Testing Guide

## Prerequisites

1. **Go 1.23+** - Make sure you have Go installed
2. **PostgreSQL** - You'll need a PostgreSQL database running
3. **Git** - For version control

## Quick Setup

### 1. Database Setup

First, you need to set up PostgreSQL. You can either:

**Option A: Use Docker (Recommended)**
```bash
# Run PostgreSQL in Docker
docker run --name goforward-postgres -e POSTGRES_PASSWORD=postgres -e POSTGRES_DB=goforward -p 5432:5432 -d postgres:15

# Wait a few seconds for the database to start
```

**Option B: Use Local PostgreSQL**
- Install PostgreSQL locally
- Create a database named `goforward`
- Update the database credentials in `config.yaml`

### 2. Configuration

The `config.yaml` file has been created with default settings. Update these key sections:

```yaml
database:
  host: "localhost"
  port: 5432
  name: "goforward"
  user: "postgres"
  password: "postgres"  # Change this to your password

auth:
  jwt_secret: "your-secret-key-change-this-in-production-make-it-very-long-and-secure"
```

### 3. Build the Application

```bash
# Install dependencies
go mod tidy

# Build the server
go build -o main.exe cmd/server/main.go

# Build the migration tool
go build -o migrate.exe cmd/migrate/main.go
```

### 4. Run Database Migrations

```bash
# Apply all migrations to set up the database schema
./migrate.exe -up
```

### 5. Start the Server

```bash
# Run the server
./main.exe
```

The server will start on `http://localhost:8080`

## Testing the Framework

### 1. Health Check

```bash
curl http://localhost:8080/health
```

### 2. User Registration

```bash
curl -X POST http://localhost:8080/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "test@example.com",
    "password": "password123",
    "username": "testuser"
  }'
```

### 3. User Login

```bash
curl -X POST http://localhost:8080/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "test@example.com",
    "password": "password123"
  }'
```

Save the JWT token from the response for authenticated requests.

### 4. Test Database API (Auto-generated endpoints)

```bash
# List all tables
curl http://localhost:8080/api/tables \
  -H "Authorization: Bearer YOUR_JWT_TOKEN"

# Get users (if you have permission)
curl http://localhost:8080/api/users \
  -H "Authorization: Bearer YOUR_JWT_TOKEN"
```

### 5. Test File Upload

```bash
# Create a test file
echo "Hello World" > test.txt

# Upload file
curl -X POST http://localhost:8080/storage/upload \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -F "file=@test.txt" \
  -F "bucket=public"
```

### 6. Test WebSocket (Real-time)

You can test WebSocket connections using a WebSocket client or browser console:

```javascript
// In browser console
const ws = new WebSocket('ws://localhost:8080/realtime/ws?token=YOUR_JWT_TOKEN');
ws.onopen = () => console.log('Connected');
ws.onmessage = (event) => console.log('Message:', event.data);
ws.send(JSON.stringify({
  type: 'subscribe',
  channel: 'users'
}));
```

## Available Endpoints

### Authentication
- `POST /auth/register` - Register new user
- `POST /auth/login` - Login user
- `POST /auth/refresh` - Refresh JWT token
- `POST /auth/logout` - Logout user
- `POST /auth/otp/send` - Send OTP via email/SMS
- `POST /auth/otp/verify` - Verify OTP

### Database Management
- `GET /db/tables` - List all tables
- `POST /db/tables` - Create new table
- `GET /db/tables/{table}` - Get table schema
- `PUT /db/tables/{table}` - Update table schema
- `DELETE /db/tables/{table}` - Drop table
- `POST /db/sql` - Execute raw SQL

### Auto-generated API
- `GET /api/{table}` - List records
- `POST /api/{table}` - Create record
- `GET /api/{table}/{id}` - Get record by ID
- `PUT /api/{table}/{id}` - Update record
- `DELETE /api/{table}/{id}` - Delete record

### File Storage
- `POST /storage/upload` - Upload file
- `GET /storage/download/{id}` - Download file
- `DELETE /storage/{id}` - Delete file
- `GET /storage/list` - List files

### Real-time
- `GET /realtime/ws` - WebSocket connection
- `POST /realtime/broadcast` - Broadcast message

### System
- `GET /health` - Health check
- `GET /metrics` - System metrics

## Environment Variables

You can override configuration using environment variables:

```bash
export SERVER_PORT=8080
export DB_HOST=localhost
export DB_PASSWORD=your_password
export JWT_SECRET=your_jwt_secret
export LOG_LEVEL=debug
```

## Development

### Running Tests

```bash
# Run all tests
go test ./...

# Run tests with coverage
go test -cover ./...

# Run specific package tests
go test ./internal/auth
```

### Adding New Features

1. Define interfaces in `pkg/interfaces/`
2. Implement services in `internal/`
3. Add handlers and register with gateway
4. Write tests
5. Update documentation

## Troubleshooting

### Database Connection Issues
- Check if PostgreSQL is running
- Verify database credentials in config.yaml
- Ensure database exists

### Port Already in Use
- Change the port in config.yaml
- Or set environment variable: `export SERVER_PORT=8081`

### Migration Errors
- Check database permissions
- Verify migration files are present
- Run migrations manually: `./migrate.exe -up`

### JWT Token Issues
- Make sure JWT_SECRET is set and consistent
- Check token expiration settings
- Verify token format in Authorization header

## Next Steps

1. ✅ **Email/SMS providers configured** - OTP functionality is ready!
2. **Configure CORS** for your frontend domain
3. **Set up SSL/TLS** for production
4. **Configure rate limiting** based on your needs
5. **Set up monitoring and logging**
6. **Build your frontend application** using the API endpoints

## Production Deployment

For production deployment:

1. Use environment variables for sensitive configuration
2. Set up proper SSL certificates
3. Use a production-grade database
4. Configure proper CORS origins
5. Set up monitoring and logging
6. Use a reverse proxy (nginx/Apache)
7. Set up backup strategies

## Support

If you encounter issues:

1. Check the logs for error messages
2. Verify your configuration
3. Test database connectivity
4. Check if all required services are running
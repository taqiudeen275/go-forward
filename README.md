# Go Forward Framework

A comprehensive backend framework built in Go that provides authentication, database management with real-time capabilities, auto-generated APIs, file storage, and an admin dashboard.

## Project Structure

```
.
├── cmd/
│   └── server/           # Application entry points
│       └── main.go       # Main server application
├── internal/             # Private application code
│   ├── config/           # Configuration management
│   └── server/           # HTTP server setup
├── pkg/                  # Public library code
│   ├── interfaces/       # Service interfaces
│   ├── logger/           # Logging utilities
│   └── errors/           # Error handling utilities
├── migrations/           # Database migration files
├── config.example.yaml   # Example configuration file
├── go.mod               # Go module definition
└── README.md            # This file
```

## Features

- **Multi-Method Authentication**: Email/SMS OTP, traditional credentials, custom auth models
- **PostgreSQL Database**: Real-time capabilities with Row Level Security (RLS)
- **Auto-Generated APIs**: RESTful CRUD endpoints from database schema
- **Real-time Updates**: WebSocket connections with database change streaming
- **File Storage**: Local or S3-compatible storage with access control
- **Admin Dashboard**: Next.js-based web interface for management
- **Migration System**: Database schema management with CLI and web interface

## Getting Started

1. **Copy the example configuration:**
   ```bash
   cp config.example.yaml config.yaml
   ```

2. **Update the configuration:**
   Edit `config.yaml` with your database credentials and other settings.

3. **Install dependencies:**
   ```bash
   go mod tidy
   ```

4. **Run the server:**
   ```bash
   go run cmd/server/main.go
   ```

## Configuration

The framework uses YAML configuration files with environment variable overrides. See `config.example.yaml` for all available options.

### Environment Variables

Key environment variables that override config file settings:

- `SERVER_HOST` - Server host (default: localhost)
- `SERVER_PORT` - Server port (default: 8080)
- `DB_HOST` - Database host
- `DB_PORT` - Database port
- `DB_NAME` - Database name
- `DB_USER` - Database user
- `DB_PASSWORD` - Database password
- `JWT_SECRET` - JWT signing secret
- `LOG_LEVEL` - Logging level (debug, info, warn, error)

## Core Interfaces

The framework is built around well-defined interfaces for each service:

- **AuthService**: Authentication and user management
- **APIService**: Auto-generated REST endpoints
- **RealtimeService**: WebSocket and real-time features
- **StorageService**: File upload and management
- **MetaService**: Database introspection and management
- **Gateway**: API routing and middleware

## Development

This project follows Go best practices:

- Clean architecture with dependency injection
- Interface-based design for testability
- Structured error handling
- Comprehensive logging
- Configuration management with validation

## License

This project is open source and available under the MIT License.
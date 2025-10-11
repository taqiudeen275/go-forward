# Authentication Example

This example demonstrates the traditional email/username/phone authentication functionality implemented in the Go Forward framework.

## Features Implemented

### 1. User Registration
- **Endpoint**: `POST /auth/register`
- **Description**: Register a new user with email, username, or phone
- **Request Body**:
  ```json
  {
    "email": "user@example.com",
    "username": "username",
    "password": "SecurePassword123!"
  }
  ```
- **Response**: Returns user information and JWT tokens

### 2. User Login
- **Endpoint**: `POST /auth/login`
- **Description**: Login with email, username, or phone number
- **Request Body**:
  ```json
  {
    "identifier": "user@example.com", // Can be email, username, or phone
    "password": "SecurePassword123!"
  }
  ```
- **Response**: Returns user information and JWT tokens

### 3. Token Refresh
- **Endpoint**: `POST /auth/refresh`
- **Description**: Refresh access token using refresh token
- **Request Body**:
  ```json
  {
    "refresh_token": "your_refresh_token_here"
  }
  ```
- **Response**: Returns new access and refresh tokens

### 4. Password Reset Request
- **Endpoint**: `POST /auth/password-reset`
- **Description**: Request a password reset token
- **Request Body**:
  ```json
  {
    "identifier": "user@example.com" // Can be email, username, or phone
  }
  ```
- **Response**: Success message (token sent via email/SMS in production)

### 5. Password Reset Confirmation
- **Endpoint**: `POST /auth/password-reset/confirm`
- **Description**: Confirm password reset with token
- **Request Body**:
  ```json
  {
    "token": "reset_token_here",
    "new_password": "NewSecurePassword123!"
  }
  ```
- **Response**: Success message

## Running the Example

1. Start the Go Forward server:
   ```bash
   go run cmd/server/main.go
   ```

2. In another terminal, run the authentication example:
   ```bash
   go run examples/auth/main.go
   ```

## Authentication Flow

1. **Registration**: User provides email/username/phone and password
2. **Login**: User provides identifier (email/username/phone) and password
3. **Token Usage**: Use access token in Authorization header for protected endpoints
4. **Token Refresh**: Use refresh token to get new access token when expired
5. **Password Reset**: Request reset token, then confirm with new password

## Security Features

- **Password Hashing**: Uses bcrypt for secure password storage
- **JWT Tokens**: Secure token-based authentication
- **Multiple Identifiers**: Support for email, username, and phone login
- **Token Expiration**: Configurable token expiration times
- **Password Validation**: Strong password requirements
- **Rate Limiting**: Protection against brute force attacks

## Database Schema

The authentication system uses the following tables:

### Users Table
```sql
CREATE TABLE users (
    id UUID PRIMARY KEY,
    email VARCHAR(255) UNIQUE,
    phone VARCHAR(20) UNIQUE,
    username VARCHAR(100) UNIQUE,
    password_hash VARCHAR(255),
    email_verified BOOLEAN DEFAULT FALSE,
    phone_verified BOOLEAN DEFAULT FALSE,
    metadata JSONB DEFAULT '{}',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);
```

### Password Reset Tokens Table
```sql
CREATE TABLE password_reset_tokens (
    id UUID PRIMARY KEY,
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    token VARCHAR(255) UNIQUE,
    expires_at TIMESTAMP WITH TIME ZONE,
    used BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);
```

## Configuration

Authentication settings can be configured in `config.yaml`:

```yaml
auth:
  jwt_secret: "your-secret-key"
  jwt_expiration: "24h"
  refresh_expiration: "168h" # 7 days
  password_min_length: 8
  enable_email_auth: true
  enable_phone_auth: true
  enable_username_auth: true
  require_verification: false
```
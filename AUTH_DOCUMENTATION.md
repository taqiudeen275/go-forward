# GoForward Authentication System Documentation

## Overview

The GoForward authentication system provides comprehensive user management with multiple authentication methods including traditional email/password, phone/password, and OTP-based authentication for login, registration, and verification.


## Key Features

- **Multiple Authentication Methods**: Email, phone, or username with password
- **OTP Authentication**: Purpose-specific OTP for login, registration, and verification
- **JWT Token Management**: Access and refresh tokens with configurable expiration
- **Email & SMS Integration**: Automated messaging with purpose-specific templates
- **User Verification**: Email and phone verification workflows
- **Password Management**: Secure hashing and password reset functionality

## Authentication Endpoints

### 1. Traditional Authentication

#### Register User
```http
POST /auth/register
Content-Type: application/json

{
  "email": "user@example.com",
  "phone": "+233123456789",
  "username": "johndoe",
  "password": "securepassword123",
  "metadata": {
    "first_name": "John",
    "last_name": "Doe"
  }
}
```

**Response:**
```json
{
  "user": {
    "id": "uuid",
    "email": "user@example.com",
    "phone": "+233123456789",
    "username": "johndoe",
    "email_verified": false,
    "phone_verified": false,
    "metadata": {...},
    "created_at": "2025-01-01T00:00:00Z",
    "updated_at": "2025-01-01T00:00:00Z"
  },
  "access_token": "jwt_access_token",
  "refresh_token": "jwt_refresh_token",
  "expires_in": 86400
}
```

#### Login User
```http
POST /auth/login
Content-Type: application/json

{
  "identifier": "user@example.com", // email, phone, or username
  "password": "securepassword123"
}
```

### 2. OTP Authentication

#### Send OTP
```http
POST /auth/otp/send
Content-Type: application/json

{
  "type": "email", // "email" or "sms"
  "recipient": "user@example.com",
  "purpose": "login" // "login", "registration", or "verification"
}
```

**Purpose-Specific Behavior:**
- **`login`**: User must exist in database
- **`registration`**: User must NOT exist in database  
- **`verification`**: User must exist in database

**Response:**
```json
{
  "message": "OTP sent successfully"
}
```

#### Verify OTP (Email/Phone Verification)
```http
POST /auth/otp/verify
Content-Type: application/json

{
  "type": "email",
  "recipient": "user@example.com", 
  "code": "123456"
}
```

**Note:** Purpose is automatically inferred as "verification" from the endpoint.

#### Login with OTP
```http
POST /auth/otp/login
Content-Type: application/json

{
  "type": "sms",
  "recipient": "+233123456789",
  "code": "123456"
}
```

**Note:** Purpose is automatically inferred as "login" from the endpoint. User must exist.

#### Register with OTP
```http
POST /auth/otp/register
Content-Type: application/json

{
  "type": "email",
  "recipient": "newuser@example.com",
  "code": "123456",
  "password": "optional_password" // Optional for phone-only registration
}
```

**Features:**
- **Phone-only registration**: If no password provided, generates secure random password
- **Auto-verification**: Email/phone automatically marked as verified after successful OTP
- **Purpose inference**: Purpose is automatically inferred as "registration" from the endpoint

### 3. Token Management

#### Refresh Token
```http
POST /auth/refresh
Content-Type: application/json

{
  "refresh_token": "jwt_refresh_token"
}
```

### 4. Password Management

#### Request Password Reset
```http
POST /auth/password-reset
Content-Type: application/json

{
  "identifier": "user@example.com" // email, phone, or username
}
```

#### Confirm Password Reset
```http
POST /auth/password-reset/confirm
Content-Type: application/json

{
  "token": "reset_token_from_email",
  "new_password": "newsecurepassword123"
}
```

## OTP System Details

### Purpose-Specific Messages

#### Email Templates

**Login OTP:**
- Subject: "{{AppName}} - Login Verification Code"
- Content: Security-focused with warning about unauthorized access
- Icon: 🔐

**Registration OTP:**
- Subject: "{{AppName}} - Complete Your Registration" 
- Content: Welcome message with next steps
- Icon: 🎉

**Verification OTP:**
- Subject: "{{AppName}} - Email Verification Required"
- Content: Benefits of verification (security, notifications, recovery)
- Icon: ✉️

#### SMS Templates

**Login OTP:**
```
🔐 AppName Login Code: 123456. This code expires in 10 minutes. If you didn't request this, please secure your account immediately.
```

**Registration OTP:**
```
🎉 Welcome to AppName! Your registration code is: 123456. This code expires in 10 minutes. Complete your signup now!
```

**Verification OTP:**
```
✉️ AppName Email Verification: 123456. This code expires in 10 minutes. Verify your email to secure your account.
```

### OTP Security Features

- **Expiration**: 10 minutes default
- **Attempt Limiting**: Maximum 3 attempts per OTP
- **Purpose Isolation**: OTPs can only be used for their intended purpose
- **Endpoint Validation**: Each endpoint only accepts specific purposes
- **Auto-cleanup**: Expired and used OTPs are automatically cleaned up

## User Registration Scenarios

### 1. Email + Password Registration
```bash
# 1. Traditional registration
curl -X POST /auth/register \
  -H "Content-Type: application/json" \
  -d '{"email":"user@example.com","password":"secure123"}'

# 2. Verify email (optional)
curl -X POST /auth/otp/send \
  -H "Content-Type: application/json" \
  -d '{"type":"email","recipient":"user@example.com","purpose":"verification"}'

curl -X POST /auth/otp/verify \
  -H "Content-Type: application/json" \
  -d '{"type":"email","recipient":"user@example.com","code":"123456"}'
```

### 2. Phone + Password Registration
```bash
# 1. Traditional registration
curl -X POST /auth/register \
  -H "Content-Type: application/json" \
  -d '{"phone":"+233123456789","password":"secure123"}'

# 2. Verify phone (optional)
curl -X POST /auth/otp/send \
  -H "Content-Type: application/json" \
  -d '{"type":"sms","recipient":"+233123456789","purpose":"verification"}'

curl -X POST /auth/otp/verify \
  -H "Content-Type: application/json" \
  -d '{"type":"sms","recipient":"+233123456789","code":"123456"}'
```

### 3. Email-Only Registration (OTP-based)
```bash
# 1. Send registration OTP
curl -X POST /auth/otp/send \
  -H "Content-Type: application/json" \
  -d '{"type":"email","recipient":"user@example.com","purpose":"registration"}'

# 2. Complete registration with OTP
curl -X POST /auth/otp/register \
  -H "Content-Type: application/json" \
  -d '{"type":"email","recipient":"user@example.com","code":"123456","password":"secure123"}'
```

### 4. Phone-Only Registration (Auto-Generated Password)
```bash
# 1. Send registration OTP
curl -X POST /auth/otp/send \
  -H "Content-Type: application/json" \
  -d '{"type":"sms","recipient":"+233123456789","purpose":"registration"}'

# 2. Complete registration with OTP (secure password auto-generated)
curl -X POST /auth/otp/register \
  -H "Content-Type: application/json" \
  -d '{"type":"sms","recipient":"+233123456789","code":"123456"}'
```

**Note**: When no password is provided, the system automatically generates a secure 12-character password that meets all validation requirements.

## Login Scenarios

### 1. Traditional Login
```bash
curl -X POST /auth/login \
  -H "Content-Type: application/json" \
  -d '{"identifier":"user@example.com","password":"secure123"}'
```

### 2. OTP Login (Email)
```bash
# 1. Send login OTP
curl -X POST /auth/otp/send \
  -H "Content-Type: application/json" \
  -d '{"type":"email","recipient":"user@example.com","purpose":"login"}'

# 2. Login with OTP
curl -X POST /auth/otp/login \
  -H "Content-Type: application/json" \
  -d '{"type":"email","recipient":"user@example.com","code":"123456"}'
```

### 3. OTP Login (SMS)
```bash
# 1. Send login OTP
curl -X POST /auth/otp/send \
  -H "Content-Type: application/json" \
  -d '{"type":"sms","recipient":"+233123456789","purpose":"login"}'

# 2. Login with OTP
curl -X POST /auth/otp/login \
  -H "Content-Type: application/json" \
  -d '{"type":"sms","recipient":"+233123456789","code":"123456"}'
```

## Error Handling

### Common Error Responses

#### User Not Found (for login/verification)
```json
{
  "error": "user not found"
}
```

#### User Already Exists (for registration)
```json
{
  "error": "user already exists"
}
```

#### Invalid OTP
```json
{
  "error": "invalid OTP code"
}
```

#### OTP Expired
```json
{
  "error": "OTP has expired"
}
```

#### Wrong Purpose/Endpoint
```json
{
  "error": "use appropriate endpoint for login OTP"
}
```

#### Max Attempts Reached
```json
{
  "error": "maximum attempts reached"
}
```

## Password Requirements

All passwords (whether provided by users or auto-generated) must meet these security requirements:

- **Minimum length**: 8 characters
- **Maximum length**: 128 characters
- **Must contain at least one**:
  - Uppercase letter (A-Z)
  - Lowercase letter (a-z)
  - Digit (0-9)
  - Special character (!@#$%^&*()_+-=[]{}|;:,.<>?)

### Auto-Generated Passwords

For phone-only registration without a provided password, the system generates a secure 12-character password that:
- Contains characters from all required categories
- Uses cryptographically secure random generation
- Is shuffled to avoid predictable patterns
- Automatically meets all validation requirements

## Configuration

### JWT Settings
```yaml
auth:
  jwt_secret: "your-secret-key-change-this-in-production"
  jwt_expiration: "24h"
  refresh_expiration: "168h" # 7 days
```

### OTP Settings
```yaml
auth:
  otp_expiration: "10m"
  password_min_length: 8
```

### Email/SMS Settings
```yaml
auth:
  enable_email_auth: true
  enable_phone_auth: true
  enable_username_auth: true
  require_verification: false
```

## Security Best Practices

1. **Purpose Isolation**: Each OTP purpose has its own validation logic
2. **Endpoint Separation**: Different endpoints for different OTP purposes
3. **User Existence Validation**: Proper checks based on purpose
4. **Attempt Limiting**: Maximum 3 attempts per OTP
5. **Time-based Expiration**: 10-minute OTP validity
6. **Secure Token Generation**: Cryptographically secure random codes
7. **Auto-cleanup**: Expired OTPs are automatically removed

## Database Schema

### Users Table
```sql
CREATE TABLE users (
    id VARCHAR(36) PRIMARY KEY,
    email VARCHAR(255) UNIQUE,
    phone VARCHAR(20) UNIQUE, 
    username VARCHAR(100) UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    email_verified BOOLEAN DEFAULT FALSE,
    phone_verified BOOLEAN DEFAULT FALSE,
    metadata JSONB,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);
```

### OTPs Table
```sql
CREATE TABLE otps (
    id VARCHAR(36) PRIMARY KEY,
    user_id VARCHAR(36) REFERENCES users(id),
    code VARCHAR(10) NOT NULL,
    type VARCHAR(10) NOT NULL, -- 'email' or 'sms'
    purpose VARCHAR(20) NOT NULL, -- 'login', 'registration', 'verification'
    recipient VARCHAR(255) NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    used BOOLEAN DEFAULT FALSE,
    attempts INTEGER DEFAULT 0,
    max_attempts INTEGER DEFAULT 3,
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_otps_recipient_type_purpose ON otps(recipient, type, purpose);
```

## Testing Examples

### Test Registration Flow
```bash
# Test that registration OTP fails for existing user
curl -X POST /auth/otp/send \
  -d '{"type":"email","recipient":"existing@example.com","purpose":"registration"}'
# Should return: {"error": "user already exists"}

# Test that login OTP fails for non-existing user  
curl -X POST /auth/otp/send \
  -d '{"type":"email","recipient":"nonexistent@example.com","purpose":"login"}'
# Should return: {"error": "user not found"}
```

### Test Purpose Validation
```bash
# Try to use login OTP on verify endpoint (will fail because purposes don't match)
curl -X POST /auth/otp/verify \
  -d '{"type":"email","recipient":"user@example.com","code":"123456"}'
# Should return: {"error": "invalid or expired OTP"} (because no verification OTP exists)
```

This documentation covers all the fixes implemented for the OTP authentication system, ensuring proper user existence validation, purpose-specific messaging, and endpoint isolation.
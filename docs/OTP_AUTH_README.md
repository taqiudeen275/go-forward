# OTP Authentication System

The Go Forward Framework includes a comprehensive One-Time Password (OTP) authentication system that supports both email and SMS delivery methods. This system provides secure, passwordless authentication and verification capabilities.

## 🎯 Features

- **Multi-Channel OTP Delivery**: Email and SMS support
- **Secure Code Generation**: 6-digit numeric codes with configurable expiration
- **Rate Limiting**: Built-in attempt limits and cooldown periods
- **User Registration**: OTP-based user registration without passwords
- **Login Authentication**: Passwordless login using OTP verification
- **Email Templates**: Professional HTML and text email templates
- **SMS Integration**: Arkesel SMS provider with easy extensibility
- **Database Storage**: Secure OTP storage with automatic cleanup
- **Validation**: Comprehensive input validation and security checks

## 📋 Table of Contents

1. [Configuration](#configuration)
2. [API Endpoints](#api-endpoints)
3. [Email OTP](#email-otp)
4. [SMS OTP](#sms-otp)
5. [Usage Examples](#usage-examples)
6. [Security Features](#security-features)
7. [Error Handling](#error-handling)
8. [Testing](#testing)
9. [Customization](#customization)

## ⚙️ Configuration

### Basic Configuration

Update your `config.yaml` file with OTP settings:

```yaml
auth:
  otp_expiration: "10m"        # OTP expiration time
  enable_email_auth: true      # Enable email OTP
  enable_phone_auth: true      # Enable SMS OTP
  
  # Email configuration (SMTP)
  smtp:
    host: "smtp.gmail.com"
    port: 587
    username: "your-email@gmail.com"
    password: "your-app-password"
    from: "noreply@yourapp.com"
    use_tls: true
  
  # SMS configuration (Arkesel)
  sms:
    provider: "arkesel"
    arkesel:
      api_key: "your-arkesel-api-key"
      sender: "YourApp"
```

### Environment Variables

You can override configuration using environment variables:

```bash
export SMTP_HOST=smtp.gmail.com
export SMTP_USERNAME=your-email@gmail.com
export SMTP_PASSWORD=your-app-password
export ARKESEL_API_KEY=your-arkesel-api-key
```

## 🔗 API Endpoints

### Send OTP

**Endpoint:** `POST /auth/otp/send`

**Request Body:**
```json
{
  "type": "email",                    // "email" or "sms"
  "recipient": "user@example.com",    // Email address or phone number
  "purpose": "login"                  // Optional: "login", "registration", "verification"
}
```

**Response:**
```json
{
  "success": true,
  "message": "OTP sent successfully"
}
```

### Verify OTP

**Endpoint:** `POST /auth/otp/verify`

**Request Body:**
```json
{
  "type": "email",
  "recipient": "user@example.com",
  "code": "123456"
}
```

**Response:**
```json
{
  "success": true,
  "message": "OTP verified successfully",
  "user": {
    "id": "uuid",
    "email": "user@example.com",
    "email_verified": true
  }
}
```

### Login with OTP

**Endpoint:** `POST /auth/otp/login`

**Request Body:**
```json
{
  "type": "email",
  "recipient": "user@example.com",
  "code": "123456"
}
```

**Response:**
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
      "email_verified": true
    }
  }
}
```

## 📧 Email OTP

### Setup Gmail SMTP

1. **Enable 2-Factor Authentication** on your Gmail account
2. **Generate App Password**:
   - Go to Google Account settings
   - Security → 2-Step Verification → App passwords
   - Generate password for "Mail"
3. **Update Configuration**:
   ```yaml
   smtp:
     host: "smtp.gmail.com"
     port: 587
     username: "your-email@gmail.com"
     password: "your-16-char-app-password"
     from: "noreply@yourapp.com"
     use_tls: true
   ```

### Email Template Features

- **Professional Design**: Clean, responsive HTML templates
- **Security Warnings**: Built-in security notices and warnings
- **Branding**: Customizable app name and styling
- **Multi-format**: Both HTML and plain text versions
- **Expiration Notice**: Clear expiration time display

### Example Email Content

```
Subject: YourApp - Your verification code

Your YourApp verification code is: 123456

Important:
- This code will expire in 10 minutes
- Do not share this code with anyone
- If you didn't request this code, please ignore this email
```

## 📱 SMS OTP

### Arkesel SMS Provider

The framework includes built-in support for Arkesel SMS service (popular in Ghana and West Africa).

**Setup:**
1. **Create Arkesel Account**: Sign up at [arkesel.com](https://arkesel.com)
2. **Get API Key**: From your dashboard
3. **Configure**:
   ```yaml
   sms:
     provider: "arkesel"
     arkesel:
       api_key: "your-api-key"
       sender: "YourApp"     # Max 11 characters
   ```

### SMS Message Format

```
Your YourApp verification code is: 123456. This code expires in 5 minutes. Do not share this code with anyone.
```

### Phone Number Format

The system automatically formats phone numbers for Ghana:
- Input: `0244123456` → Output: `233244123456`
- Input: `+233244123456` → Output: `233244123456`
- International format is supported

## 💡 Usage Examples

### 1. Email OTP Registration Flow

```bash
# Step 1: Send OTP to email
curl -X POST http://localhost:8080/auth/otp/send \
  -H "Content-Type: application/json" \
  -d '{
    "type": "email",
    "recipient": "newuser@example.com",
    "purpose": "registration"
  }'

# Step 2: User receives email with OTP code

# Step 3: Verify OTP and create account
curl -X POST http://localhost:8080/auth/otp/verify \
  -H "Content-Type: application/json" \
  -d '{
    "type": "email",
    "recipient": "newuser@example.com",
    "code": "123456"
  }'
```

### 2. SMS OTP Login Flow

```bash
# Step 1: Send OTP to phone
curl -X POST http://localhost:8080/auth/otp/send \
  -H "Content-Type: application/json" \
  -d '{
    "type": "sms",
    "recipient": "+233244123456",
    "purpose": "login"
  }'

# Step 2: Login with OTP
curl -X POST http://localhost:8080/auth/otp/login \
  -H "Content-Type: application/json" \
  -d '{
    "type": "sms",
    "recipient": "+233244123456",
    "code": "654321"
  }'
```

### 3. JavaScript Frontend Integration

```javascript
// Send OTP
async function sendOTP(type, recipient) {
  const response = await fetch('/auth/otp/send', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      type: type,        // 'email' or 'sms'
      recipient: recipient,
      purpose: 'login'
    })
  });
  
  const result = await response.json();
  if (result.success) {
    console.log('OTP sent successfully');
  }
}

// Verify OTP and login
async function loginWithOTP(type, recipient, code) {
  const response = await fetch('/auth/otp/login', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      type: type,
      recipient: recipient,
      code: code
    })
  });
  
  const result = await response.json();
  if (result.success) {
    // Store JWT token
    localStorage.setItem('access_token', result.data.access_token);
    console.log('Login successful');
  }
}
```

## 🔒 Security Features

### Code Generation
- **6-digit numeric codes** for easy user input
- **Cryptographically secure** random generation
- **Configurable expiration** (default: 10 minutes)

### Rate Limiting
- **Maximum attempts**: 3 attempts per OTP
- **Automatic lockout**: After max attempts exceeded
- **Cooldown period**: Prevents rapid OTP requests

### Database Security
- **Secure storage**: OTPs stored with expiration timestamps
- **Automatic cleanup**: Expired OTPs are automatically removed
- **Attempt tracking**: Failed attempts are logged and limited

### Validation
- **Input validation**: Email and phone number format validation
- **Type checking**: Ensures OTP type matches delivery method
- **Expiration checks**: Automatic expiration validation
- **Usage tracking**: Prevents OTP reuse

## ❌ Error Handling

### Common Error Responses

```json
// Invalid OTP type
{
  "success": false,
  "error": "invalid OTP type: must be 'email' or 'sms'"
}

// Invalid email format
{
  "success": false,
  "error": "invalid email recipient: invalid email format"
}

// OTP expired
{
  "success": false,
  "error": "invalid or expired OTP"
}

// Too many attempts
{
  "success": false,
  "error": "maximum OTP attempts exceeded"
}

// Service not configured
{
  "success": false,
  "error": "email service not configured"
}
```

### Error Codes

| HTTP Status | Error Type | Description |
|-------------|------------|-------------|
| 400 | Bad Request | Invalid input data or format |
| 401 | Unauthorized | Invalid or expired OTP |
| 429 | Too Many Requests | Rate limit exceeded |
| 500 | Internal Server Error | Service configuration or delivery error |

## 🧪 Testing

### Manual Testing

Use the provided test script:

```bash
# Run the OTP example
go run examples/otp/main.go
```

### Unit Tests

```bash
# Run OTP-related tests
go test ./internal/auth -v -run TestOTP

# Run email service tests
go test ./internal/email -v

# Run SMS service tests
go test ./internal/sms -v
```

### Integration Testing

```bash
# Test complete OTP flow
curl -X POST http://localhost:8080/auth/otp/send \
  -H "Content-Type: application/json" \
  -d '{"type":"email","recipient":"test@example.com"}'

# Check server logs for OTP code (if email not configured)
# Then verify with the code
curl -X POST http://localhost:8080/auth/otp/verify \
  -H "Content-Type: application/json" \
  -d '{"type":"email","recipient":"test@example.com","code":"123456"}'
```

## 🎨 Customization

### Custom Email Templates

Modify the email templates in `internal/email/service.go`:

```go
func (s *Service) getOTPTemplate() EmailTemplate {
    return EmailTemplate{
        Subject: "{{.AppName}} - Your verification code",
        HTMLBody: `<!-- Your custom HTML template -->`,
        TextBody: `Your custom text template`,
    }
}
```

### Custom SMS Provider

Implement the `SMSProvider` interface:

```go
type CustomSMSProvider struct {
    // Your provider fields
}

func (c *CustomSMSProvider) SendSMS(ctx context.Context, to, message string) error {
    // Your implementation
}

func (c *CustomSMSProvider) SendOTP(ctx context.Context, to, otp, appName string) error {
    // Your implementation
}
```

### Custom OTP Length and Expiration

Modify the OTP generator configuration in `internal/auth/service.go`:

```go
// Create OTP generator with custom config
otpGenerator := NewOTPGeneratorWithConfig(
    8,              // 8-digit codes
    15*time.Minute, // 15-minute expiration
    5,              // 5 maximum attempts
)
```

## 🚀 Production Deployment

### Email Service Setup

1. **Use Professional Email Service**:
   - SendGrid, Mailgun, or AWS SES for production
   - Higher delivery rates and better reputation

2. **Configure SPF/DKIM**:
   - Set up proper DNS records for email authentication
   - Improves deliverability and reduces spam classification

### SMS Service Setup

1. **Production SMS Provider**:
   - Use reliable SMS gateway (Twilio, Arkesel, etc.)
   - Consider multiple providers for redundancy

2. **Phone Number Validation**:
   - Implement proper international phone number validation
   - Consider regional SMS regulations

### Security Considerations

1. **Rate Limiting**:
   - Implement IP-based rate limiting
   - Monitor for abuse patterns

2. **Monitoring**:
   - Log OTP generation and verification attempts
   - Set up alerts for unusual activity

3. **Backup Methods**:
   - Provide alternative authentication methods
   - Consider backup codes for account recovery

## 📞 Support

### Troubleshooting

**OTP not received via email:**
- Check SMTP configuration
- Verify email credentials
- Check spam/junk folder
- Review server logs for errors

**OTP not received via SMS:**
- Verify SMS provider configuration
- Check phone number format
- Ensure sufficient SMS credits
- Review provider-specific logs

**OTP verification fails:**
- Check code expiration (default: 10 minutes)
- Verify attempt limits (default: 3 attempts)
- Ensure exact code match (case-sensitive)

### Getting Help

1. **Check Logs**: Review server logs for detailed error messages
2. **Test Configuration**: Use the example scripts to test setup
3. **Verify Credentials**: Ensure all API keys and passwords are correct
4. **Check Network**: Verify connectivity to email/SMS providers

---

**The OTP authentication system is production-ready and provides a secure, user-friendly authentication experience for your applications.**
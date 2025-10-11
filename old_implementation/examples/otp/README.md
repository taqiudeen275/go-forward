# OTP Authentication Example

This example demonstrates how to use the OTP (One-Time Password) authentication system with both email and SMS delivery methods.

## Features

- Email OTP delivery via SMTP
- SMS OTP delivery via Arkesel
- OTP generation and validation
- Integration with authentication service
- Phone number validation and formatting

## Configuration

Update your `config.yaml` file with the appropriate settings:

```yaml
auth:
  jwt_secret: "your-jwt-secret-key"
  jwt_expiration: 24h
  refresh_expiration: 168h
  otp_expiration: 10m
  
  # Email configuration
  smtp:
    host: "smtp.gmail.com"
    port: 587
    username: "your-email@gmail.com"
    password: "your-app-password"
    from: "your-email@gmail.com"
    use_tls: true
  
  # SMS configuration
  sms:
    provider: "arkesel"
    arkesel:
      api_key: "your-arkesel-api-key"
      sender: "YourApp"
```

## Usage Flow

### 1. Send OTP

```go
// Email OTP
emailOTPReq := &auth.OTPRequest{
    Type:      auth.OTPTypeEmail,
    Recipient: "user@example.com",
    Purpose:   "login",
}
err := authService.SendOTP(ctx, emailOTPReq)

// SMS OTP
smsOTPReq := &auth.OTPRequest{
    Type:      auth.OTPTypeSMS,
    Recipient: "+233123456789",
    Purpose:   "login",
}
err := authService.SendOTP(ctx, smsOTPReq)
```

### 2. Verify OTP

```go
verifyReq := &auth.VerifyOTPRequest{
    Type:      auth.OTPTypeEmail,
    Recipient: "user@example.com",
    Code:      "123456", // User input
}

user, err := authService.VerifyOTP(ctx, verifyReq)
```

### 3. Login with OTP

```go
loginReq := &auth.VerifyOTPRequest{
    Type:      auth.OTPTypeEmail,
    Recipient: "user@example.com",
    Code:      "123456", // User input
}

authResponse, err := authService.LoginWithOTP(ctx, loginReq)
// Returns JWT tokens on success
```

## OTP Properties

- **Code Length**: 6 digits
- **Expiration**: 10 minutes (configurable)
- **Max Attempts**: 3 attempts per OTP
- **Auto Cleanup**: Expired OTPs are automatically cleaned up

## Security Features

- OTPs expire after 10 minutes
- Limited to 3 verification attempts
- Secure random code generation
- Phone number validation
- Email address validation
- Rate limiting (can be implemented at service level)

## Error Handling

The system provides detailed error messages for:
- Invalid phone numbers or email addresses
- Expired OTPs
- Maximum attempts reached
- Invalid OTP codes
- Service configuration issues

## Testing

For testing without sending real emails/SMS:

```go
// Use mock services
mockEmailProvider := &email.MockEmailProvider{}
mockSMSProvider := &sms.MockSMSProvider{}

emailService := email.NewService(mockEmailProvider, "Test App")
smsService := sms.NewService(mockSMSProvider, "Test App")

authService.SetEmailService(emailService)
authService.SetSMSService(smsService)
```

## Database Schema

The OTP system uses the following database table:

```sql
CREATE TABLE otps (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    code VARCHAR(10) NOT NULL,
    type VARCHAR(10) NOT NULL CHECK (type IN ('email', 'sms')),
    recipient VARCHAR(255) NOT NULL,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    used BOOLEAN DEFAULT FALSE,
    attempts INTEGER DEFAULT 0,
    max_attempts INTEGER DEFAULT 3,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);
```

## Best Practices

1. **Rate Limiting**: Implement rate limiting to prevent OTP spam
2. **Monitoring**: Monitor OTP success/failure rates
3. **Cleanup**: Regularly clean up expired OTPs
4. **Validation**: Always validate phone numbers and email addresses
5. **Security**: Use secure random number generation
6. **User Experience**: Provide clear error messages and retry options
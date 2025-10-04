# Email Service Example

This example demonstrates how to use the email service to send OTP, password reset, and welcome emails.

## Configuration

The email service supports SMTP configuration with the following options:

```go
smtpConfig := email.SMTPConfig{
    Host:     "smtp.gmail.com",     // SMTP server host
    Port:     587,                  // SMTP server port
    Username: "your-email@gmail.com", // SMTP username
    Password: "your-app-password",  // SMTP password (use app password for Gmail)
    From:     "your-email@gmail.com", // From email address
    UseTLS:   true,                 // Use TLS encryption
}
```

## Common SMTP Providers

### Gmail
- Host: `smtp.gmail.com`
- Port: `587` (TLS) or `465` (SSL)
- Use app passwords instead of regular passwords
- Enable 2-factor authentication and generate an app password

### Outlook/Hotmail
- Host: `smtp-mail.outlook.com`
- Port: `587`
- Use your regular Outlook credentials

### SendGrid
- Host: `smtp.sendgrid.net`
- Port: `587`
- Username: `apikey`
- Password: Your SendGrid API key

### Mailgun
- Host: `smtp.mailgun.org`
- Port: `587`
- Use your Mailgun SMTP credentials

## Usage

1. Configure your SMTP settings
2. Create an SMTP provider
3. Create an email service
4. Send emails using the service methods

```go
// Create SMTP provider
smtpProvider := email.NewSMTPProvider(smtpConfig)

// Create email service
emailService := email.NewService(smtpProvider, "Your App Name")

// Send OTP email
err := emailService.SendOTP(ctx, "user@example.com", "123456", "Your App")

// Send password reset email
err := emailService.SendPasswordReset(ctx, "user@example.com", "reset-token", "Your App")

// Send welcome email
err := emailService.SendWelcome(ctx, "user@example.com", "John Doe", "Your App")
```

## Email Templates

The service includes built-in HTML and text templates for:

- **OTP Verification**: Professional-looking email with the verification code
- **Password Reset**: Email with reset link and security warnings
- **Welcome**: Welcome message for new users

All templates are responsive and include proper styling for a professional appearance.

## Security Notes

- Always use app passwords or API keys instead of regular passwords
- Enable TLS encryption for secure email transmission
- Store SMTP credentials securely (environment variables, config files)
- Validate email addresses before sending
- Implement rate limiting to prevent abuse

## Testing

To test the email functionality without sending real emails, you can use a mock provider:

```go
// Create mock provider for testing
mockProvider := &MockEmailProvider{}
emailService := email.NewService(mockProvider, "Test App")

// Set up expectations and test
mockProvider.On("SendHTMLEmail", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil)
```
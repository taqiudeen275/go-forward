# SMS Service Example

This example demonstrates how to use the SMS service to send OTP and custom messages using the Arkesel SMS provider.

## Configuration

The SMS service supports Arkesel SMS provider with the following configuration:

```go
// Create Arkesel provider
apiKey := "your-arkesel-api-key"
sender := "YourApp" // Max 11 characters for Arkesel
arkeselProvider := sms.NewArkeselProvider(apiKey, sender)

// Create SMS service
smsService := sms.NewService(arkeselProvider, "Your App Name")
```

## Arkesel Setup

1. Sign up at [Arkesel](https://arkesel.com/)
2. Get your API key from the dashboard
3. Choose a sender ID (max 11 characters)
4. Add credits to your account

### API Endpoints
- **Send SMS**: `https://sms.arkesel.com/api/v2/sms/send`
- **Check Balance**: `https://sms.arkesel.com/api/v2/clients/balance-details`

## Usage

### Send OTP SMS
```go
err := smsService.SendOTP(ctx, "+233123456789", "123456", "Your App")
if err != nil {
    log.Printf("Failed to send OTP SMS: %v", err)
}
```

### Send Custom Message
```go
err := smsService.SendMessage(ctx, "+233123456789", "Welcome to our service!")
if err != nil {
    log.Printf("Failed to send SMS: %v", err)
}
```

### Check Account Balance
```go
balance, err := smsService.GetBalance(ctx)
if err != nil {
    log.Printf("Failed to get balance: %v", err)
} else {
    fmt.Printf("Balance: %.2f %s\n", balance.Balance, balance.Currency)
}
```

## Phone Number Formatting

The service automatically formats phone numbers for Ghanaian numbers:

- `0123456789` → `+233123456789`
- `233123456789` → `+233233123456789`
- `123456789` → `+233123456789`
- `+233123456789` → `+233123456789` (no change)

## Phone Number Validation

The service validates phone numbers to ensure they:
- Are not empty
- Contain 10-15 digits after cleaning
- Are not longer than 20 characters total

## Error Handling

The service provides detailed error messages for:
- Invalid phone numbers
- API authentication failures
- Network connectivity issues
- Insufficient account balance
- Invalid sender IDs

## Testing

To test SMS functionality without sending real messages, use the mock provider:

```go
// Create mock provider for testing
mockProvider := &MockSMSProvider{}
smsService := sms.NewService(mockProvider, "Test App")

// Set up expectations and test
mockProvider.On("SendOTP", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil)
```

## Security Notes

- Store your Arkesel API key securely (environment variables, config files)
- Validate phone numbers before sending
- Implement rate limiting to prevent abuse
- Monitor your account balance to avoid service interruption
- Use appropriate sender IDs that comply with local regulations

## Cost Considerations

- Each SMS costs credits from your Arkesel account
- International SMS may cost more than local SMS
- Monitor usage to control costs
- Set up balance alerts in your Arkesel dashboard

## Supported Countries

Arkesel primarily supports:
- Ghana (233)
- Other African countries (check Arkesel documentation)

For other countries, you may need to integrate additional SMS providers.
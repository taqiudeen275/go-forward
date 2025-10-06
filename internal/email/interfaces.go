package email

import "context"

// EmailProvider defines the interface for email sending providers
type EmailProvider interface {
	SendEmail(ctx context.Context, to, subject, body string) error
	SendHTMLEmail(ctx context.Context, to, subject, htmlBody, textBody string) error
}

// EmailService defines the interface for email operations
type EmailService interface {
	SendOTP(ctx context.Context, to, otp, appName string) error
	SendOTPWithPurpose(ctx context.Context, to, otp, purpose, appName string) error
	SendPasswordReset(ctx context.Context, to, resetToken, appName string) error
	SendWelcome(ctx context.Context, to, name, appName string) error
}

// EmailTemplate represents an email template
type EmailTemplate struct {
	Subject  string
	HTMLBody string
	TextBody string
}

// TemplateData represents data for email templates
type TemplateData struct {
	AppName    string
	UserName   string
	OTP        string
	ResetToken string
	ResetURL   string
}

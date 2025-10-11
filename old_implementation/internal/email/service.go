package email

import (
	"context"
	"fmt"
	"strings"
)

// Service implements the EmailService interface
type Service struct {
	provider EmailProvider
	appName  string
}

// NewService creates a new email service
func NewService(provider EmailProvider, appName string) *Service {
	return &Service{
		provider: provider,
		appName:  appName,
	}
}

// SendOTP sends an OTP verification email
func (s *Service) SendOTP(ctx context.Context, to, otp, appName string) error {
	if appName == "" {
		appName = s.appName
	}

	template := s.getOTPTemplate()
	data := TemplateData{
		AppName: appName,
		OTP:     otp,
	}

	subject := s.renderTemplate(template.Subject, data)
	htmlBody := s.renderTemplate(template.HTMLBody, data)
	textBody := s.renderTemplate(template.TextBody, data)

	return s.provider.SendHTMLEmail(ctx, to, subject, htmlBody, textBody)
}

// SendPasswordReset sends a password reset email
func (s *Service) SendPasswordReset(ctx context.Context, to, resetToken, appName string) error {
	if appName == "" {
		appName = s.appName
	}

	template := s.getPasswordResetTemplate()
	data := TemplateData{
		AppName:    appName,
		ResetToken: resetToken,
		ResetURL:   fmt.Sprintf("https://your-app.com/reset-password?token=%s", resetToken),
	}

	subject := s.renderTemplate(template.Subject, data)
	htmlBody := s.renderTemplate(template.HTMLBody, data)
	textBody := s.renderTemplate(template.TextBody, data)

	return s.provider.SendHTMLEmail(ctx, to, subject, htmlBody, textBody)
}

// SendWelcome sends a welcome email
func (s *Service) SendWelcome(ctx context.Context, to, name, appName string) error {
	if appName == "" {
		appName = s.appName
	}

	template := s.getWelcomeTemplate()
	data := TemplateData{
		AppName:  appName,
		UserName: name,
	}

	subject := s.renderTemplate(template.Subject, data)
	htmlBody := s.renderTemplate(template.HTMLBody, data)
	textBody := s.renderTemplate(template.TextBody, data)

	return s.provider.SendHTMLEmail(ctx, to, subject, htmlBody, textBody)
}

// getOTPTemplate returns the OTP email template
func (s *Service) getOTPTemplate() EmailTemplate {
	return EmailTemplate{
		Subject: "{{.AppName}} - Your verification code",
		HTMLBody: `
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Verification Code</title>
    <style>
        body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
        .container { max-width: 600px; margin: 0 auto; padding: 20px; }
        .header { background-color: #f8f9fa; padding: 20px; text-align: center; border-radius: 5px; }
        .content { padding: 20px 0; }
        .otp-code { font-size: 32px; font-weight: bold; color: #007bff; text-align: center; 
                   background-color: #f8f9fa; padding: 20px; border-radius: 5px; margin: 20px 0; 
                   letter-spacing: 5px; }
        .footer { font-size: 12px; color: #666; text-align: center; margin-top: 30px; }
        .warning { background-color: #fff3cd; border: 1px solid #ffeaa7; padding: 15px; 
                  border-radius: 5px; margin: 20px 0; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>{{.AppName}}</h1>
            <h2>Email Verification</h2>
        </div>
        
        <div class="content">
            <p>Hello,</p>
            
            <p>You have requested a verification code for your {{.AppName}} account. Please use the following code to complete your verification:</p>
            
            <div class="otp-code">{{.OTP}}</div>
            
            <div class="warning">
                <strong>Important:</strong>
                <ul>
                    <li>This code will expire in 10 minutes</li>
                    <li>Do not share this code with anyone</li>
                    <li>If you didn't request this code, please ignore this email</li>
                </ul>
            </div>
            
            <p>If you have any questions, please contact our support team.</p>
            
            <p>Best regards,<br>The {{.AppName}} Team</p>
        </div>
        
        <div class="footer">
            <p>This is an automated message, please do not reply to this email.</p>
        </div>
    </div>
</body>
</html>`,
		TextBody: `{{.AppName}} - Email Verification

Hello,

You have requested a verification code for your {{.AppName}} account. Please use the following code to complete your verification:

Verification Code: {{.OTP}}

Important:
- This code will expire in 10 minutes
- Do not share this code with anyone
- If you didn't request this code, please ignore this email

If you have any questions, please contact our support team.

Best regards,
The {{.AppName}} Team

---
This is an automated message, please do not reply to this email.`,
	}
}

// getPasswordResetTemplate returns the password reset email template
func (s *Service) getPasswordResetTemplate() EmailTemplate {
	return EmailTemplate{
		Subject: "{{.AppName}} - Password Reset Request",
		HTMLBody: `
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Password Reset</title>
    <style>
        body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
        .container { max-width: 600px; margin: 0 auto; padding: 20px; }
        .header { background-color: #f8f9fa; padding: 20px; text-align: center; border-radius: 5px; }
        .content { padding: 20px 0; }
        .button { display: inline-block; background-color: #007bff; color: white; 
                 padding: 12px 24px; text-decoration: none; border-radius: 5px; 
                 margin: 20px 0; }
        .footer { font-size: 12px; color: #666; text-align: center; margin-top: 30px; }
        .warning { background-color: #fff3cd; border: 1px solid #ffeaa7; padding: 15px; 
                  border-radius: 5px; margin: 20px 0; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>{{.AppName}}</h1>
            <h2>Password Reset Request</h2>
        </div>
        
        <div class="content">
            <p>Hello,</p>
            
            <p>You have requested to reset your password for your {{.AppName}} account. Click the button below to reset your password:</p>
            
            <p style="text-align: center;">
                <a href="{{.ResetURL}}" class="button">Reset Password</a>
            </p>
            
            <p>If the button doesn't work, you can copy and paste this link into your browser:</p>
            <p style="word-break: break-all;">{{.ResetURL}}</p>
            
            <div class="warning">
                <strong>Important:</strong>
                <ul>
                    <li>This link will expire in 1 hour</li>
                    <li>If you didn't request this reset, please ignore this email</li>
                    <li>Your password will not be changed until you click the link above</li>
                </ul>
            </div>
            
            <p>If you have any questions, please contact our support team.</p>
            
            <p>Best regards,<br>The {{.AppName}} Team</p>
        </div>
        
        <div class="footer">
            <p>This is an automated message, please do not reply to this email.</p>
        </div>
    </div>
</body>
</html>`,
		TextBody: `{{.AppName}} - Password Reset Request

Hello,

You have requested to reset your password for your {{.AppName}} account. Please visit the following link to reset your password:

{{.ResetURL}}

Important:
- This link will expire in 1 hour
- If you didn't request this reset, please ignore this email
- Your password will not be changed until you click the link above

If you have any questions, please contact our support team.

Best regards,
The {{.AppName}} Team

---
This is an automated message, please do not reply to this email.`,
	}
}

// getWelcomeTemplate returns the welcome email template
func (s *Service) getWelcomeTemplate() EmailTemplate {
	return EmailTemplate{
		Subject: "Welcome to {{.AppName}}!",
		HTMLBody: `
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Welcome</title>
    <style>
        body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
        .container { max-width: 600px; margin: 0 auto; padding: 20px; }
        .header { background-color: #f8f9fa; padding: 20px; text-align: center; border-radius: 5px; }
        .content { padding: 20px 0; }
        .footer { font-size: 12px; color: #666; text-align: center; margin-top: 30px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Welcome to {{.AppName}}!</h1>
        </div>
        
        <div class="content">
            <p>Hello {{.UserName}},</p>
            
            <p>Welcome to {{.AppName}}! We're excited to have you on board.</p>
            
            <p>Your account has been successfully created and you can now start using all the features available.</p>
            
            <p>If you have any questions or need help getting started, please don't hesitate to contact our support team.</p>
            
            <p>Best regards,<br>The {{.AppName}} Team</p>
        </div>
        
        <div class="footer">
            <p>This is an automated message, please do not reply to this email.</p>
        </div>
    </div>
</body>
</html>`,
		TextBody: `Welcome to {{.AppName}}!

Hello {{.UserName}},

Welcome to {{.AppName}}! We're excited to have you on board.

Your account has been successfully created and you can now start using all the features available.

If you have any questions or need help getting started, please don't hesitate to contact our support team.

Best regards,
The {{.AppName}} Team

---
This is an automated message, please do not reply to this email.`,
	}
}

// renderTemplate renders a template string with the provided data
func (s *Service) renderTemplate(template string, data TemplateData) string {
	result := template

	// Simple template replacement (in production, use text/template)
	result = strings.ReplaceAll(result, "{{.AppName}}", data.AppName)
	result = strings.ReplaceAll(result, "{{.UserName}}", data.UserName)
	result = strings.ReplaceAll(result, "{{.OTP}}", data.OTP)
	result = strings.ReplaceAll(result, "{{.ResetToken}}", data.ResetToken)
	result = strings.ReplaceAll(result, "{{.ResetURL}}", data.ResetURL)

	return result
}

// SendOTPWithPurpose sends an OTP verification email with purpose-specific content
func (s *Service) SendOTPWithPurpose(ctx context.Context, to, otp, purpose, appName string) error {
	if appName == "" {
		appName = s.appName
	}

	template := s.getOTPTemplateForPurpose(purpose)
	data := TemplateData{
		AppName: appName,
		OTP:     otp,
	}

	subject := s.renderTemplate(template.Subject, data)
	htmlBody := s.renderTemplate(template.HTMLBody, data)
	textBody := s.renderTemplate(template.TextBody, data)

	return s.provider.SendHTMLEmail(ctx, to, subject, htmlBody, textBody)
}

// getOTPTemplateForPurpose returns purpose-specific OTP email templates
func (s *Service) getOTPTemplateForPurpose(purpose string) EmailTemplate {
	switch purpose {
	case "login":
		return s.getLoginOTPTemplate()
	case "registration":
		return s.getRegistrationOTPTemplate()
	case "verification":
		return s.getVerificationOTPTemplate()
	default:
		return s.getOTPTemplate() // fallback to generic template
	}
}

// getLoginOTPTemplate returns the login OTP email template
func (s *Service) getLoginOTPTemplate() EmailTemplate {
	return EmailTemplate{
		Subject: "{{.AppName}} - Login Verification Code",
		HTMLBody: `
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Login Verification</title>
    <style>
        body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
        .container { max-width: 600px; margin: 0 auto; padding: 20px; }
        .header { background-color: #007bff; color: white; padding: 20px; text-align: center; border-radius: 5px; }
        .content { padding: 20px 0; }
        .otp-code { font-size: 32px; font-weight: bold; color: #007bff; text-align: center; 
                   background-color: #f8f9fa; padding: 20px; border-radius: 5px; margin: 20px 0; 
                   letter-spacing: 5px; }
        .footer { font-size: 12px; color: #666; text-align: center; margin-top: 30px; }
        .warning { background-color: #fff3cd; border: 1px solid #ffeaa7; padding: 15px; 
                  border-radius: 5px; margin: 20px 0; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>{{.AppName}}</h1>
            <h2>🔐 Login Verification</h2>
        </div>
        
        <div class="content">
            <p>Hello,</p>
            
            <p>Someone is trying to log in to your {{.AppName}} account. Please use the following verification code to complete your login:</p>
            
            <div class="otp-code">{{.OTP}}</div>
            
            <div class="warning">
                <strong>Security Notice:</strong>
                <ul>
                    <li>This code will expire in 10 minutes</li>
                    <li>Never share this code with anyone</li>
                    <li>If you didn't request this login, please secure your account immediately</li>
                </ul>
            </div>
            
            <p>If you have any security concerns, please contact our support team immediately.</p>
            
            <p>Best regards,<br>The {{.AppName}} Security Team</p>
        </div>
        
        <div class="footer">
            <p>This is an automated security message, please do not reply to this email.</p>
        </div>
    </div>
</body>
</html>`,
		TextBody: `{{.AppName}} - Login Verification

Hello,

Someone is trying to log in to your {{.AppName}} account. Please use the following verification code to complete your login:

Login Code: {{.OTP}}

Security Notice:
- This code will expire in 10 minutes
- Never share this code with anyone
- If you didn't request this login, please secure your account immediately

If you have any security concerns, please contact our support team immediately.

Best regards,
The {{.AppName}} Security Team

---
This is an automated security message, please do not reply to this email.`,
	}
}

// getRegistrationOTPTemplate returns the registration OTP email template
func (s *Service) getRegistrationOTPTemplate() EmailTemplate {
	return EmailTemplate{
		Subject: "{{.AppName}} - Complete Your Registration",
		HTMLBody: `
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Complete Registration</title>
    <style>
        body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
        .container { max-width: 600px; margin: 0 auto; padding: 20px; }
        .header { background-color: #28a745; color: white; padding: 20px; text-align: center; border-radius: 5px; }
        .content { padding: 20px 0; }
        .otp-code { font-size: 32px; font-weight: bold; color: #28a745; text-align: center; 
                   background-color: #f8f9fa; padding: 20px; border-radius: 5px; margin: 20px 0; 
                   letter-spacing: 5px; }
        .footer { font-size: 12px; color: #666; text-align: center; margin-top: 30px; }
        .info { background-color: #d1ecf1; border: 1px solid #bee5eb; padding: 15px; 
               border-radius: 5px; margin: 20px 0; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Welcome to {{.AppName}}!</h1>
            <h2>🎉 Complete Your Registration</h2>
        </div>
        
        <div class="content">
            <p>Hello,</p>
            
            <p>Thank you for joining {{.AppName}}! To complete your registration and verify your email address, please use the following verification code:</p>
            
            <div class="otp-code">{{.OTP}}</div>
            
            <div class="info">
                <strong>What's Next:</strong>
                <ul>
                    <li>Enter this code to verify your email</li>
                    <li>Complete your account setup</li>
                    <li>Start exploring {{.AppName}}</li>
                </ul>
            </div>
            
            <p><strong>Note:</strong> This verification code will expire in 10 minutes.</p>
            
            <p>We're excited to have you on board!</p>
            
            <p>Best regards,<br>The {{.AppName}} Team</p>
        </div>
        
        <div class="footer">
            <p>This is an automated message, please do not reply to this email.</p>
        </div>
    </div>
</body>
</html>`,
		TextBody: `Welcome to {{.AppName}}!

Hello,

Thank you for joining {{.AppName}}! To complete your registration and verify your email address, please use the following verification code:

Registration Code: {{.OTP}}

What's Next:
- Enter this code to verify your email
- Complete your account setup
- Start exploring {{.AppName}}

Note: This verification code will expire in 10 minutes.

We're excited to have you on board!

Best regards,
The {{.AppName}} Team

---
This is an automated message, please do not reply to this email.`,
	}
}

// getVerificationOTPTemplate returns the verification OTP email template
func (s *Service) getVerificationOTPTemplate() EmailTemplate {
	return EmailTemplate{
		Subject: "{{.AppName}} - Email Verification Required",
		HTMLBody: `
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Email Verification</title>
    <style>
        body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
        .container { max-width: 600px; margin: 0 auto; padding: 20px; }
        .header { background-color: #17a2b8; color: white; padding: 20px; text-align: center; border-radius: 5px; }
        .content { padding: 20px 0; }
        .otp-code { font-size: 32px; font-weight: bold; color: #17a2b8; text-align: center; 
                   background-color: #f8f9fa; padding: 20px; border-radius: 5px; margin: 20px 0; 
                   letter-spacing: 5px; }
        .footer { font-size: 12px; color: #666; text-align: center; margin-top: 30px; }
        .info { background-color: #d1ecf1; border: 1px solid #bee5eb; padding: 15px; 
               border-radius: 5px; margin: 20px 0; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>{{.AppName}}</h1>
            <h2>✉️ Email Verification</h2>
        </div>
        
        <div class="content">
            <p>Hello,</p>
            
            <p>You need to verify your email address for your {{.AppName}} account. Please use the following verification code:</p>
            
            <div class="otp-code">{{.OTP}}</div>
            
            <div class="info">
                <strong>Why verify your email?</strong>
                <ul>
                    <li>Secure your account</li>
                    <li>Receive important notifications</li>
                    <li>Enable password recovery</li>
                </ul>
            </div>
            
            <p><strong>Note:</strong> This verification code will expire in 10 minutes.</p>
            
            <p>If you have any questions, please contact our support team.</p>
            
            <p>Best regards,<br>The {{.AppName}} Team</p>
        </div>
        
        <div class="footer">
            <p>This is an automated message, please do not reply to this email.</p>
        </div>
    </div>
</body>
</html>`,
		TextBody: `{{.AppName}} - Email Verification

Hello,

You need to verify your email address for your {{.AppName}} account. Please use the following verification code:

Verification Code: {{.OTP}}

Why verify your email?
- Secure your account
- Receive important notifications
- Enable password recovery

Note: This verification code will expire in 10 minutes.

If you have any questions, please contact our support team.

Best regards,
The {{.AppName}} Team

---
This is an automated message, please do not reply to this email.`,
	}
}

// SendPasswordResetOTP sends a password reset OTP email
func (s *Service) SendPasswordResetOTP(ctx context.Context, to, otp, appName string) error {
	if appName == "" {
		appName = s.appName
	}

	template := s.getPasswordResetOTPTemplate()
	data := TemplateData{
		AppName: appName,
		OTP:     otp,
	}

	subject := s.renderTemplate(template.Subject, data)
	htmlBody := s.renderTemplate(template.HTMLBody, data)
	textBody := s.renderTemplate(template.TextBody, data)

	return s.provider.SendHTMLEmail(ctx, to, subject, htmlBody, textBody)
}

// getPasswordResetOTPTemplate returns the password reset OTP email template
func (s *Service) getPasswordResetOTPTemplate() EmailTemplate {
	return EmailTemplate{
		Subject: "{{.AppName}} - Password Reset Code",
		HTMLBody: `
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Password Reset</title>
    <style>
        body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
        .container { max-width: 600px; margin: 0 auto; padding: 20px; }
        .header { background-color: #dc3545; color: white; padding: 20px; text-align: center; border-radius: 5px; }
        .content { padding: 20px 0; }
        .otp-code { font-size: 32px; font-weight: bold; color: #dc3545; text-align: center; 
                   background-color: #f8f9fa; padding: 20px; border-radius: 5px; margin: 20px 0; 
                   letter-spacing: 5px; }
        .footer { font-size: 12px; color: #666; text-align: center; margin-top: 30px; }
        .warning { background-color: #fff3cd; border: 1px solid #ffeaa7; padding: 15px; 
                  border-radius: 5px; margin: 20px 0; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>{{.AppName}}</h1>
            <h2>🔒 Password Reset</h2>
        </div>
        
        <div class="content">
            <p>Hello,</p>
            
            <p>You have requested to reset your password for your {{.AppName}} account. Please use the following verification code to complete your password reset:</p>
            
            <div class="otp-code">{{.OTP}}</div>
            
            <div class="warning">
                <strong>Security Notice:</strong>
                <ul>
                    <li>This code will expire in 10 minutes</li>
                    <li>Never share this code with anyone</li>
                    <li>If you didn't request this reset, please secure your account immediately</li>
                    <li>Your password will not be changed until you complete the reset process</li>
                </ul>
            </div>
            
            <p>If you have any security concerns, please contact our support team immediately.</p>
            
            <p>Best regards,<br>The {{.AppName}} Security Team</p>
        </div>
        
        <div class="footer">
            <p>This is an automated security message, please do not reply to this email.</p>
        </div>
    </div>
</body>
</html>`,
		TextBody: `{{.AppName}} - Password Reset

Hello,

You have requested to reset your password for your {{.AppName}} account. Please use the following verification code to complete your password reset:

Password Reset Code: {{.OTP}}

Security Notice:
- This code will expire in 10 minutes
- Never share this code with anyone
- If you didn't request this reset, please secure your account immediately
- Your password will not be changed until you complete the reset process

If you have any security concerns, please contact our support team immediately.

Best regards,
The {{.AppName}} Security Team

---
This is an automated security message, please do not reply to this email.`,
	}
}

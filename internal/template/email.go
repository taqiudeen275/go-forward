package template

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/smtp"
	"strings"

	"github.com/taqiudeen275/go-foward/internal/config"
	"github.com/taqiudeen275/go-foward/pkg/errors"
)

// EmailProvider defines the interface for email providers
type EmailProvider interface {
	SendEmail(ctx context.Context, req *EmailRequest) error
	ValidateConfig() error
}

// EmailRequest represents an email sending request
type EmailRequest struct {
	To       []string `json:"to" validate:"required,min=1"`
	CC       []string `json:"cc"`
	BCC      []string `json:"bcc"`
	Subject  string   `json:"subject" validate:"required"`
	Content  string   `json:"content" validate:"required"`
	IsHTML   bool     `json:"is_html"`
	From     string   `json:"from"`
	FromName string   `json:"from_name"`
}

// SMTPProvider implements email sending via SMTP
type SMTPProvider struct {
	config *config.EmailConfig
}

// NewSMTPProvider creates a new SMTP email provider
func NewSMTPProvider(config *config.EmailConfig) *SMTPProvider {
	return &SMTPProvider{
		config: config,
	}
}

// SendEmail sends an email via SMTP
func (p *SMTPProvider) SendEmail(ctx context.Context, req *EmailRequest) error {
	if err := p.ValidateConfig(); err != nil {
		return err
	}

	// Set default from address if not provided
	from := req.From
	if from == "" {
		from = p.config.FromEmail
	}

	fromName := req.FromName
	if fromName == "" {
		fromName = p.config.FromName
	}

	// Build message
	message, err := p.buildMessage(req, from, fromName)
	if err != nil {
		return err
	}

	// Connect to SMTP server
	auth := smtp.PlainAuth("", p.config.SMTPUser, p.config.SMTPPass, p.config.SMTPHost)

	// Create TLS config
	tlsConfig := &tls.Config{
		ServerName: p.config.SMTPHost,
	}

	// Connect to server
	addr := fmt.Sprintf("%s:%d", p.config.SMTPHost, p.config.SMTPPort)

	if p.config.EnableTLS {
		if p.config.SMTPPort == 465 {
			// Use direct TLS connection (port 465)
			conn, err := tls.Dial("tcp", addr, tlsConfig)
			if err != nil {
				return errors.NewExternalServiceError(fmt.Sprintf("Failed to connect to SMTP server: %v", err))
			}
			defer conn.Close()

			client, err := smtp.NewClient(conn, p.config.SMTPHost)
			if err != nil {
				return errors.NewExternalServiceError(fmt.Sprintf("Failed to create SMTP client: %v", err))
			}
			defer client.Quit()

			if err := client.Auth(auth); err != nil {
				return errors.NewExternalServiceError(fmt.Sprintf("SMTP authentication failed: %v", err))
			}

			return p.sendMessage(client, from, req.To, message)
		} else if p.config.SMTPPort == 587 {
			// Use STARTTLS for port 587 (Gmail)
			return p.sendWithSTARTTLS(addr, auth, from, req.To, message)
		}
	}

	// Fallback to plain SMTP
	return smtp.SendMail(addr, auth, from, req.To, []byte(message))
}

// ValidateConfig validates the SMTP configuration
func (p *SMTPProvider) ValidateConfig() error {
	if p.config.SMTPHost == "" {
		return errors.NewConfigError("SMTP host is required")
	}
	if p.config.SMTPPort == 0 {
		return errors.NewConfigError("SMTP port is required")
	}
	if p.config.SMTPUser == "" {
		return errors.NewConfigError("SMTP user is required")
	}
	if p.config.SMTPPass == "" {
		return errors.NewConfigError("SMTP password is required")
	}
	if p.config.FromEmail == "" {
		return errors.NewConfigError("From email is required")
	}
	return nil
}

// buildMessage builds the email message
func (p *SMTPProvider) buildMessage(req *EmailRequest, from, fromName string) (string, error) {
	var message strings.Builder

	// Headers
	if fromName != "" {
		message.WriteString(fmt.Sprintf("From: %s <%s>\r\n", fromName, from))
	} else {
		message.WriteString(fmt.Sprintf("From: %s\r\n", from))
	}

	message.WriteString(fmt.Sprintf("To: %s\r\n", strings.Join(req.To, ", ")))

	if len(req.CC) > 0 {
		message.WriteString(fmt.Sprintf("CC: %s\r\n", strings.Join(req.CC, ", ")))
	}

	if len(req.BCC) > 0 {
		message.WriteString(fmt.Sprintf("BCC: %s\r\n", strings.Join(req.BCC, ", ")))
	}

	message.WriteString(fmt.Sprintf("Subject: %s\r\n", req.Subject))

	if req.IsHTML {
		message.WriteString("MIME-Version: 1.0\r\n")
		message.WriteString("Content-Type: text/html; charset=UTF-8\r\n")
	} else {
		message.WriteString("Content-Type: text/plain; charset=UTF-8\r\n")
	}

	message.WriteString("\r\n")
	message.WriteString(req.Content)

	return message.String(), nil
}

// sendMessage sends the message using the SMTP client
func (p *SMTPProvider) sendMessage(client *smtp.Client, from string, to []string, message string) error {
	if err := client.Mail(from); err != nil {
		return errors.NewExternalServiceError(fmt.Sprintf("Failed to set sender: %v", err))
	}

	for _, recipient := range to {
		if err := client.Rcpt(recipient); err != nil {
			return errors.NewExternalServiceError(fmt.Sprintf("Failed to set recipient %s: %v", recipient, err))
		}
	}

	writer, err := client.Data()
	if err != nil {
		return errors.NewExternalServiceError(fmt.Sprintf("Failed to get data writer: %v", err))
	}
	defer writer.Close()

	if _, err := writer.Write([]byte(message)); err != nil {
		return errors.NewExternalServiceError(fmt.Sprintf("Failed to write message: %v", err))
	}

	return nil
}

// sendWithSTARTTLS sends email using STARTTLS (proper method for port 587)
func (p *SMTPProvider) sendWithSTARTTLS(addr string, auth smtp.Auth, from string, to []string, message string) error {
	// Connect to SMTP server without TLS first
	client, err := smtp.Dial(addr)
	if err != nil {
		return errors.NewExternalServiceError(fmt.Sprintf("Failed to connect to SMTP server: %v", err))
	}
	defer client.Quit()

	// Start TLS if supported
	if ok, _ := client.Extension("STARTTLS"); ok {
		tlsConfig := &tls.Config{
			ServerName: p.config.SMTPHost,
		}
		if err := client.StartTLS(tlsConfig); err != nil {
			return errors.NewExternalServiceError(fmt.Sprintf("Failed to start TLS: %v", err))
		}
	}

	// Authenticate if credentials provided
	if auth != nil {
		if err := client.Auth(auth); err != nil {
			return errors.NewExternalServiceError(fmt.Sprintf("SMTP authentication failed: %v", err))
		}
	}

	// Send message using the existing sendMessage method
	return p.sendMessage(client, from, to, message)
}

// EmailService manages email providers and template integration
type EmailService struct {
	provider EmailProvider
	renderer *Renderer
}

// NewEmailService creates a new email service
func NewEmailService(config *config.EmailConfig, renderer *Renderer) (*EmailService, error) {
	var provider EmailProvider

	switch config.Provider {
	case "smtp":
		provider = NewSMTPProvider(config)
	default:
		return nil, errors.NewConfigError(fmt.Sprintf("Unsupported email provider: %s", config.Provider))
	}

	return &EmailService{
		provider: provider,
		renderer: renderer,
	}, nil
}

// SendTemplatedEmail sends an email using a template
func (s *EmailService) SendTemplatedEmail(ctx context.Context, template *Template, variables map[string]interface{}, to []string) error {
	// Render template
	result, err := s.renderer.Render(template, variables)
	if err != nil {
		return errors.NewValidationError(fmt.Sprintf("Failed to render email template: %v", err))
	}

	// Create email request
	req := &EmailRequest{
		To:      to,
		Subject: *result.Subject,
		Content: result.Content,
		IsHTML:  false, // Default to plain text, can be configured per template
	}

	// Send email
	return s.provider.SendEmail(ctx, req)
}

// SendEmail sends a plain email
func (s *EmailService) SendEmail(ctx context.Context, req *EmailRequest) error {
	return s.provider.SendEmail(ctx, req)
}

// ValidateProvider validates the email provider configuration
func (s *EmailService) ValidateProvider() error {
	return s.provider.ValidateConfig()
}

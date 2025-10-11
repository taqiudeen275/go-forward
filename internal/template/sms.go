package template

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/taqiudeen275/go-foward/internal/config"
	"github.com/taqiudeen275/go-foward/pkg/errors"
)

// SMSProvider defines the interface for SMS providers
type SMSProvider interface {
	SendSMS(ctx context.Context, req *SMSRequest) error
	ValidateConfig() error
	GetBalance(ctx context.Context) (*BalanceInfo, error)
}

// SMSRequest represents an SMS sending request
type SMSRequest struct {
	To      string `json:"to" validate:"required"`
	Message string `json:"message" validate:"required,max=1600"`
	From    string `json:"from"`
}

// BalanceInfo represents account balance information
type BalanceInfo struct {
	Balance  float64 `json:"balance"`
	Currency string  `json:"currency"`
	Units    string  `json:"units"`
}

// ArkeselProvider implements SMS sending via Arkesel API
type ArkeselProvider struct {
	apiKey     string
	sender     string
	baseURL    string
	httpClient *http.Client
}

// ArkeselSMSRequest represents the Arkesel API request format
type ArkeselSMSRequest struct {
	Sender     string   `json:"sender"`
	Message    string   `json:"message"`
	Recipients []string `json:"recipients"`
}

// ArkeselSMSResponse represents the Arkesel API response format
type ArkeselSMSResponse struct {
	Status  string      `json:"status"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
}

// ArkeselBalanceResponse represents the balance response from Arkesel API
type ArkeselBalanceResponse struct {
	Status string `json:"status"`
	Data   struct {
		Balance  float64 `json:"balance"`
		Currency string  `json:"currency"`
	} `json:"data"`
	Message string `json:"message,omitempty"`
}

// NewArkeselProvider creates a new Arkesel SMS provider
func NewArkeselProvider(config *config.SMSConfig) *ArkeselProvider {
	baseURL := "https://sms.arkesel.com/api/v2"
	if url, exists := config.Settings["base_url"]; exists {
		baseURL = url
	}

	return &ArkeselProvider{
		apiKey:  config.APIKey,
		sender:  config.From,
		baseURL: baseURL,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// SendSMS sends an SMS via Arkesel API
func (p *ArkeselProvider) SendSMS(ctx context.Context, req *SMSRequest) error {
	if err := p.ValidateConfig(); err != nil {
		return err
	}

	// Set default sender if not provided
	sender := req.From
	if sender == "" {
		sender = p.sender
	}

	// Format phone number for Ghana
	formattedPhone := p.formatGhanaianNumber(req.To)

	// Create Arkesel request
	arkeselReq := ArkeselSMSRequest{
		Sender:     sender,
		Message:    req.Message,
		Recipients: []string{formattedPhone},
	}

	// Marshal request
	reqBody, err := json.Marshal(arkeselReq)
	if err != nil {
		return errors.NewValidationError(fmt.Sprintf("Failed to marshal SMS request: %v", err))
	}

	// Create HTTP request
	httpReq, err := http.NewRequestWithContext(ctx, "POST", p.baseURL+"/sms/send", bytes.NewBuffer(reqBody))
	if err != nil {
		return errors.NewExternalServiceError(fmt.Sprintf("Failed to create HTTP request: %v", err))
	}

	// Set headers
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("api-key", p.apiKey)

	// Send request
	resp, err := p.httpClient.Do(httpReq)
	if err != nil {
		return errors.NewExternalServiceError(fmt.Sprintf("Failed to send SMS request: %v", err))
	}
	defer resp.Body.Close()

	// Read response
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return errors.NewExternalServiceError(fmt.Sprintf("Failed to read SMS response: %v", err))
	}

	// Parse response
	var arkeselResp ArkeselSMSResponse
	if err := json.Unmarshal(respBody, &arkeselResp); err != nil {
		return errors.NewExternalServiceError(fmt.Sprintf("Failed to parse SMS response: %v", err))
	}

	// Check response status
	if resp.StatusCode != http.StatusOK {
		return errors.NewExternalServiceError(fmt.Sprintf("SMS API returned error: %s", arkeselResp.Message))
	}

	return nil
}

// GetBalance retrieves account balance from Arkesel API
func (p *ArkeselProvider) GetBalance(ctx context.Context) (*BalanceInfo, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", p.baseURL+"/clients/balance-details", nil)
	if err != nil {
		return nil, errors.NewExternalServiceError(fmt.Sprintf("Failed to create request: %v", err))
	}

	req.Header.Set("api-key", p.apiKey)

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return nil, errors.NewExternalServiceError(fmt.Sprintf("Failed to get balance: %v", err))
	}
	defer resp.Body.Close()

	var response ArkeselBalanceResponse
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, errors.NewExternalServiceError(fmt.Sprintf("Failed to decode response: %v", err))
	}

	if resp.StatusCode != http.StatusOK {
		return nil, errors.NewExternalServiceError(fmt.Sprintf("Arkesel API error: %s", response.Message))
	}

	return &BalanceInfo{
		Balance:  response.Data.Balance,
		Currency: response.Data.Currency,
		Units:    "SMS",
	}, nil
}

// ValidateConfig validates the Arkesel configuration
func (p *ArkeselProvider) ValidateConfig() error {
	if p.apiKey == "" {
		return errors.NewConfigError("Arkesel API key is required")
	}
	if p.sender == "" {
		return errors.NewConfigError("SMS sender ID is required")
	}
	return nil
}

// formatGhanaianNumber formats phone number for Ghanaian numbers
func (p *ArkeselProvider) formatGhanaianNumber(phoneNumber string) string {
	// Remove all non-digit characters
	re := regexp.MustCompile(`\D`)
	cleaned := re.ReplaceAllString(phoneNumber, "")

	// Handle different formats
	if strings.HasPrefix(cleaned, "233") {
		return cleaned
	} else if strings.HasPrefix(cleaned, "0") {
		return "233" + cleaned[1:]
	} else if len(cleaned) == 9 {
		return "233" + cleaned
	}

	return cleaned
}

// GenericSMSProvider implements a generic SMS provider for other services
type GenericSMSProvider struct {
	config     *config.SMSConfig
	httpClient *http.Client
}

// NewGenericSMSProvider creates a new generic SMS provider
func NewGenericSMSProvider(config *config.SMSConfig) *GenericSMSProvider {
	return &GenericSMSProvider{
		config: config,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// SendSMS sends an SMS via generic HTTP API
func (p *GenericSMSProvider) SendSMS(ctx context.Context, req *SMSRequest) error {
	// This is a placeholder for other SMS providers
	// Implementation would depend on the specific provider's API
	return errors.NewExternalServiceError("Generic SMS provider not implemented")
}

// GetBalance retrieves account balance (not implemented for generic provider)
func (p *GenericSMSProvider) GetBalance(ctx context.Context) (*BalanceInfo, error) {
	return nil, errors.NewExternalServiceError("Balance check not supported for generic provider")
}

// ValidateConfig validates the generic SMS configuration
func (p *GenericSMSProvider) ValidateConfig() error {
	if p.config.APIKey == "" {
		return errors.NewConfigError("SMS API key is required")
	}
	return nil
}

// SMSService manages SMS providers and template integration
type SMSService struct {
	provider SMSProvider
	renderer *Renderer
}

// NewSMSService creates a new SMS service
func NewSMSService(config *config.SMSConfig, renderer *Renderer) (*SMSService, error) {
	var provider SMSProvider

	switch config.Provider {
	case "arkesel":
		provider = NewArkeselProvider(config)
	case "generic":
		provider = NewGenericSMSProvider(config)
	default:
		return nil, errors.NewConfigError(fmt.Sprintf("Unsupported SMS provider: %s", config.Provider))
	}

	return &SMSService{
		provider: provider,
		renderer: renderer,
	}, nil
}

// SendTemplatedSMS sends an SMS using a template
func (s *SMSService) SendTemplatedSMS(ctx context.Context, template *Template, variables map[string]interface{}, to string) error {
	// Validate phone number
	if err := s.validatePhoneNumber(to); err != nil {
		return errors.NewValidationError(fmt.Sprintf("Invalid phone number: %v", err))
	}

	// Render template
	result, err := s.renderer.Render(template, variables)
	if err != nil {
		return errors.NewValidationError(fmt.Sprintf("Failed to render SMS template: %v", err))
	}

	// Create SMS request
	req := &SMSRequest{
		To:      to,
		Message: result.Content,
	}

	// Send SMS
	return s.provider.SendSMS(ctx, req)
}

// SendSMS sends a plain SMS
func (s *SMSService) SendSMS(ctx context.Context, req *SMSRequest) error {
	// Validate phone number
	if err := s.validatePhoneNumber(req.To); err != nil {
		return errors.NewValidationError(fmt.Sprintf("Invalid phone number: %v", err))
	}

	return s.provider.SendSMS(ctx, req)
}

// GetBalance retrieves account balance
func (s *SMSService) GetBalance(ctx context.Context) (*BalanceInfo, error) {
	return s.provider.GetBalance(ctx)
}

// ValidateProvider validates the SMS provider configuration
func (s *SMSService) ValidateProvider() error {
	return s.provider.ValidateConfig()
}

// GetProviderInfo returns information about the SMS provider
func (s *SMSService) GetProviderInfo() map[string]interface{} {
	switch provider := s.provider.(type) {
	case *ArkeselProvider:
		return map[string]interface{}{
			"provider":    "arkesel",
			"base_url":    provider.baseURL,
			"sender_id":   provider.sender,
			"api_key_set": provider.apiKey != "",
		}
	case *GenericSMSProvider:
		return map[string]interface{}{
			"provider":    "generic",
			"api_key_set": provider.config.APIKey != "",
		}
	default:
		return map[string]interface{}{
			"provider": "unknown",
		}
	}
}

// validatePhoneNumber validates a phone number format
func (s *SMSService) validatePhoneNumber(phone string) error {
	if strings.TrimSpace(phone) == "" {
		return fmt.Errorf("phone number cannot be empty")
	}

	// Remove common phone number characters for validation
	cleanPhone := strings.ReplaceAll(phone, " ", "")
	cleanPhone = strings.ReplaceAll(cleanPhone, "-", "")
	cleanPhone = strings.ReplaceAll(cleanPhone, "(", "")
	cleanPhone = strings.ReplaceAll(cleanPhone, ")", "")
	cleanPhone = strings.ReplaceAll(cleanPhone, "+", "")

	// Check if remaining characters are digits and length is appropriate
	phoneRegex := regexp.MustCompile(`^\d{10,15}$`)
	if !phoneRegex.MatchString(cleanPhone) {
		return fmt.Errorf("phone number must contain 10-15 digits")
	}

	if len(phone) > 20 {
		return fmt.Errorf("phone number too long (max 20 characters)")
	}

	return nil
}

// FormatPhoneNumber formats a phone number for international use
func (s *SMSService) FormatPhoneNumber(phone string) string {
	// This is a basic implementation - in production, use a proper phone number library
	cleanPhone := strings.ReplaceAll(phone, " ", "")
	cleanPhone = strings.ReplaceAll(cleanPhone, "-", "")
	cleanPhone = strings.ReplaceAll(cleanPhone, "(", "")
	cleanPhone = strings.ReplaceAll(cleanPhone, ")", "")

	// If it doesn't start with +, assume it needs country code
	if !strings.HasPrefix(cleanPhone, "+") {
		// Default to Ghana country code for Arkesel
		if strings.HasPrefix(cleanPhone, "0") {
			cleanPhone = "+233" + cleanPhone[1:]
		} else if !strings.HasPrefix(cleanPhone, "233") {
			cleanPhone = "+233" + cleanPhone
		} else {
			cleanPhone = "+" + cleanPhone
		}
	}

	return cleanPhone
}

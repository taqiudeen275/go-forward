package template

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/taqiudeen275/go-foward/internal/config"
	"github.com/taqiudeen275/go-foward/pkg/errors"
)

// SMSProvider defines the interface for SMS providers
type SMSProvider interface {
	SendSMS(ctx context.Context, req *SMSRequest) error
	ValidateConfig() error
}

// SMSRequest represents an SMS sending request
type SMSRequest struct {
	To      string `json:"to" validate:"required"`
	Message string `json:"message" validate:"required,max=1600"`
	From    string `json:"from"`
}

// ArkeselProvider implements SMS sending via Arkesel API
type ArkeselProvider struct {
	config     *config.SMSConfig
	httpClient *http.Client
	baseURL    string
}

// ArkeselSMSRequest represents the Arkesel API request format
type ArkeselSMSRequest struct {
	Sender     string   `json:"sender"`
	Message    string   `json:"message"`
	Recipients []string `json:"recipients"`
}

// ArkeselSMSResponse represents the Arkesel API response format
type ArkeselSMSResponse struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Data    struct {
		Recipients []struct {
			Recipient string `json:"recipient"`
			ID        string `json:"id"`
			Status    string `json:"status"`
		} `json:"recipients"`
		Summary struct {
			Total   int `json:"total"`
			Sent    int `json:"sent"`
			Failed  int `json:"failed"`
			Pending int `json:"pending"`
		} `json:"summary"`
	} `json:"data"`
}

// NewArkeselProvider creates a new Arkesel SMS provider
func NewArkeselProvider(config *config.SMSConfig) *ArkeselProvider {
	baseURL := "https://sms.arkesel.com/api/v2/sms"
	if url, exists := config.Settings["base_url"]; exists {
		baseURL = url
	}

	return &ArkeselProvider{
		config:  config,
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
		sender = p.config.From
	}

	// Create Arkesel request
	arkeselReq := ArkeselSMSRequest{
		Sender:     sender,
		Message:    req.Message,
		Recipients: []string{req.To},
	}

	// Marshal request
	reqBody, err := json.Marshal(arkeselReq)
	if err != nil {
		return errors.NewValidationError(fmt.Sprintf("Failed to marshal SMS request: %v", err))
	}

	// Create HTTP request
	httpReq, err := http.NewRequestWithContext(ctx, "POST", p.baseURL+"/send", bytes.NewBuffer(reqBody))
	if err != nil {
		return errors.NewExternalServiceError(fmt.Sprintf("Failed to create HTTP request: %v", err))
	}

	// Set headers
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("api-key", p.config.APIKey)

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
		return errors.NewExternalServiceError(fmt.Sprintf("SMS API returned error: %s - %s", arkeselResp.Code, arkeselResp.Message))
	}

	// Check if message was sent successfully
	if arkeselResp.Data.Summary.Sent == 0 {
		return errors.NewExternalServiceError(fmt.Sprintf("SMS failed to send: %s", arkeselResp.Message))
	}

	return nil
}

// ValidateConfig validates the Arkesel configuration
func (p *ArkeselProvider) ValidateConfig() error {
	if p.config.APIKey == "" {
		return errors.NewConfigError("Arkesel API key is required")
	}
	if p.config.From == "" {
		return errors.NewConfigError("SMS sender ID is required")
	}
	return nil
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
	return s.provider.SendSMS(ctx, req)
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
			"sender_id":   provider.config.From,
			"api_key_set": provider.config.APIKey != "",
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

package sms

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"
)

// ArkeselProvider implements SMS provider for Arkesel API
type ArkeselProvider struct {
	apiKey  string
	sender  string
	baseURL string
	client  *http.Client
}

// ArkeselSMSRequest represents the request payload for Arkesel SMS API
type ArkeselSMSRequest struct {
	Sender     string   `json:"sender"`
	Message    string   `json:"message"`
	Recipients []string `json:"recipients"`
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
func NewArkeselProvider(apiKey, sender string) *ArkeselProvider {
	return &ArkeselProvider{
		apiKey:  apiKey,
		sender:  sender,
		baseURL: "https://sms.arkesel.com/api/v2",
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// SendSMS sends an SMS using Arkesel API
func (a *ArkeselProvider) SendSMS(ctx context.Context, to, message string) error {
	// Format phone number for Ghana
	formattedPhone := a.formatGhanaianNumber(to)

	payload := ArkeselSMSRequest{
		Sender:     a.sender,
		Message:    message,
		Recipients: []string{formattedPhone},
	}

	jsonData, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal SMS request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", a.baseURL+"/sms/send", bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("api-key", a.apiKey)
	req.Header.Set("Content-Type", "application/json")

	resp, err := a.client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send SMS request: %w", err)
	}
	defer resp.Body.Close()

	var response SMSResponse
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return fmt.Errorf("failed to decode response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("arkesel API error: %s", response.Message)
	}

	return nil
}

// SendOTP sends an OTP SMS using Arkesel API
func (a *ArkeselProvider) SendOTP(ctx context.Context, to, otp, appName string) error {
	message := fmt.Sprintf("Your %s verification code is: %s. This code expires in 5 minutes. Do not share this code with anyone.", appName, otp)
	return a.SendSMS(ctx, to, message)
}

// GetBalance retrieves account balance from Arkesel API
func (a *ArkeselProvider) GetBalance(ctx context.Context) (*BalanceInfo, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", a.baseURL+"/clients/balance-details", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("api-key", a.apiKey)

	resp, err := a.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to get balance: %w", err)
	}
	defer resp.Body.Close()

	var response ArkeselBalanceResponse
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("arkesel API error: %s", response.Message)
	}

	return &BalanceInfo{
		Balance:  response.Data.Balance,
		Currency: response.Data.Currency,
		Units:    "SMS",
	}, nil
}

// formatGhanaianNumber formats phone number for Ghanaian numbers
func (a *ArkeselProvider) formatGhanaianNumber(phoneNumber string) string {
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

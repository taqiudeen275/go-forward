package sms

import "context"

// SMSProvider defines the interface for SMS sending providers
type SMSProvider interface {
	SendSMS(ctx context.Context, to, message string) error
	SendOTP(ctx context.Context, to, otp, appName string) error
	GetBalance(ctx context.Context) (*BalanceInfo, error)
}

// SMSService defines the interface for SMS operations
type SMSService interface {
	SendOTP(ctx context.Context, to, otp, appName string) error
	SendMessage(ctx context.Context, to, message string) error
	GetBalance(ctx context.Context) (*BalanceInfo, error)
}

// SMSResponse represents a generic SMS API response
type SMSResponse struct {
	Status  string      `json:"status"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
}

// BalanceInfo represents account balance information
type BalanceInfo struct {
	Balance  float64 `json:"balance"`
	Currency string  `json:"currency"`
	Units    string  `json:"units"`
}

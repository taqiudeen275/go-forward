package interfaces

import (
	"context"
	"time"
)

// AuthService defines the authentication service interface
type AuthService interface {
	Register(ctx context.Context, req RegisterRequest) (*User, error)
	Login(ctx context.Context, req LoginRequest) (*AuthResponse, error)
	SendOTP(ctx context.Context, req OTPRequest) error
	VerifyOTP(ctx context.Context, req VerifyOTPRequest) (*AuthResponse, error)
	ValidateToken(ctx context.Context, token string) (*Claims, error)
	RefreshToken(ctx context.Context, refreshToken string) (*AuthResponse, error)
	Logout(ctx context.Context, token string) error
}

// CustomAuthProvider defines interface for custom authentication providers
type CustomAuthProvider interface {
	Authenticate(ctx context.Context, credentials map[string]interface{}) (*User, error)
	ValidateCredentials(ctx context.Context, credentials map[string]interface{}) error
	GetProviderName() string
}

// User represents a system user
type User struct {
	ID            string                 `json:"id"`
	Email         string                 `json:"email"`
	Phone         string                 `json:"phone"`
	Username      string                 `json:"username"`
	EmailVerified bool                   `json:"email_verified"`
	PhoneVerified bool                   `json:"phone_verified"`
	Metadata      map[string]interface{} `json:"metadata"`
	CreatedAt     time.Time              `json:"created_at"`
	UpdatedAt     time.Time              `json:"updated_at"`
}

// AuthResponse represents authentication response
type AuthResponse struct {
	User         *User  `json:"user"`
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int    `json:"expires_in"`
}

// Claims represents JWT claims
type Claims struct {
	UserID    string                 `json:"user_id"`
	Email     string                 `json:"email"`
	Metadata  map[string]interface{} `json:"metadata"`
	IssuedAt  time.Time              `json:"iat"`
	ExpiresAt time.Time              `json:"exp"`
}

// RegisterRequest represents user registration request
type RegisterRequest struct {
	Email    string                 `json:"email"`
	Phone    string                 `json:"phone"`
	Username string                 `json:"username"`
	Password string                 `json:"password"`
	Metadata map[string]interface{} `json:"metadata"`
}

// LoginRequest represents user login request
type LoginRequest struct {
	Identifier string `json:"identifier"` // email, phone, or username
	Password   string `json:"password"`
}

// OTPRequest represents OTP request
type OTPRequest struct {
	Identifier string `json:"identifier"` // email or phone
	Type       string `json:"type"`       // "email" or "sms"
}

// VerifyOTPRequest represents OTP verification request
type VerifyOTPRequest struct {
	Identifier string `json:"identifier"`
	Code       string `json:"code"`
	Type       string `json:"type"`
}

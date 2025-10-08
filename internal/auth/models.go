package auth

import (
	"time"
)

// User represents a system user
type User struct {
	ID            string                 `json:"id" db:"id"`
	Email         *string                `json:"email" db:"email"`
	Phone         *string                `json:"phone" db:"phone"`
	Username      *string                `json:"username" db:"username"`
	PasswordHash  string                 `json:"-" db:"password_hash"`
	EmailVerified bool                   `json:"email_verified" db:"email_verified"`
	PhoneVerified bool                   `json:"phone_verified" db:"phone_verified"`
	Metadata      map[string]interface{} `json:"metadata" db:"metadata"`
	CreatedAt     time.Time              `json:"created_at" db:"created_at"`
	UpdatedAt     time.Time              `json:"updated_at" db:"updated_at"`
}

// CreateUserRequest represents a request to create a new user
type CreateUserRequest struct {
	Email    *string                `json:"email" validate:"omitempty,email"`
	Phone    *string                `json:"phone" validate:"omitempty,e164"`
	Username *string                `json:"username" validate:"omitempty,min=3,max=100"`
	Password string                 `json:"password" validate:"required,min=8"`
	Metadata map[string]interface{} `json:"metadata,omitempty"`
}

// UpdateUserRequest represents a request to update a user
type UpdateUserRequest struct {
	Email         *string                `json:"email" validate:"omitempty,email"`
	Phone         *string                `json:"phone" validate:"omitempty,e164"`
	Username      *string                `json:"username" validate:"omitempty,min=3,max=100"`
	EmailVerified *bool                  `json:"email_verified"`
	PhoneVerified *bool                  `json:"phone_verified"`
	Metadata      map[string]interface{} `json:"metadata,omitempty"`
}

// LoginRequest represents a login request
type LoginRequest struct {
	Identifier string `json:"identifier" validate:"required"` // email, phone, or username
	Password   string `json:"password" validate:"required"`
}

// AuthResponse represents authentication response
type AuthResponse struct {
	User         *User  `json:"user"`
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int    `json:"expires_in"`
}

// UserFilter represents filters for querying users
type UserFilter struct {
	Email         *string `json:"email"`
	Phone         *string `json:"phone"`
	Username      *string `json:"username"`
	EmailVerified *bool   `json:"email_verified"`
	PhoneVerified *bool   `json:"phone_verified"`
	Limit         int     `json:"limit"`
	Offset        int     `json:"offset"`
}

// PasswordResetRequest represents a password reset request
type PasswordResetRequest struct {
	Identifier string `json:"identifier" validate:"required"` // email, phone, or username
}

// PasswordResetConfirmRequest represents a password reset confirmation request
type PasswordResetConfirmRequest struct {
	Identifier  string `json:"identifier" validate:"required"` // email, phone, or username
	OTPCode     string `json:"otp_code" validate:"required,len=6"`
	NewPassword string `json:"new_password" validate:"required,min=8"`
}

// PasswordResetToken represents a password reset token
type PasswordResetToken struct {
	ID        string    `json:"id" db:"id"`
	UserID    string    `json:"user_id" db:"user_id"`
	Token     string    `json:"token" db:"token"`
	ExpiresAt time.Time `json:"expires_at" db:"expires_at"`
	Used      bool      `json:"used" db:"used"`
	CreatedAt time.Time `json:"created_at" db:"created_at"`
}

// OTPType represents the type of OTP delivery method
type OTPType string

const (
	OTPTypeEmail OTPType = "email"
	OTPTypeSMS   OTPType = "sms"
)

// OTP represents a one-time password
type OTP struct {
	ID          string     `json:"id" db:"id"`
	UserID      *string    `json:"user_id" db:"user_id"` // Can be null for registration OTPs
	CodeHash    string     `json:"-" db:"code_hash"`     // Hashed OTP code (never expose in JSON)
	Type        OTPType    `json:"type" db:"type"`
	Purpose     OTPPurpose `json:"purpose" db:"purpose"`
	Recipient   string     `json:"recipient" db:"recipient"` // email or phone number
	ExpiresAt   time.Time  `json:"expires_at" db:"expires_at"`
	Used        bool       `json:"used" db:"used"`
	Attempts    int        `json:"attempts" db:"attempts"`
	MaxAttempts int        `json:"max_attempts" db:"max_attempts"`
	CreatedAt   time.Time  `json:"created_at" db:"created_at"`

	// Transient field for plain text code (not stored in DB)
	Code string `json:"code,omitempty" db:"-"`
}

// OTPPurpose represents the purpose of an OTP
type OTPPurpose string

const (
	OTPPurposeLogin        OTPPurpose = "login"
	OTPPurposeRegistration OTPPurpose = "registration"
	OTPPurposeVerification OTPPurpose = "verification"
)

// OTPRequest represents a request to send an OTP
type OTPRequest struct {
	Type      OTPType    `json:"type" validate:"required,oneof=email sms"`
	Recipient string     `json:"recipient" validate:"required"`
	Purpose   OTPPurpose `json:"purpose" validate:"required,oneof=login registration verification"`
}

// VerifyOTPRequest represents a request to verify an OTP
type VerifyOTPRequest struct {
	Type      OTPType `json:"type" validate:"required,oneof=email sms"`
	Recipient string  `json:"recipient" validate:"required"`
	Code      string  `json:"code" validate:"required,len=6"`
}

// CustomAuthRequest represents a request for custom authentication
type CustomAuthRequest struct {
	Provider    string                 `json:"provider" validate:"required"`
	Credentials map[string]interface{} `json:"credentials" validate:"required"`
}

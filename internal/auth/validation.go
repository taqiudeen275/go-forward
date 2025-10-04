package auth

import (
	"fmt"
	"regexp"
	"strings"
)

// Validator handles input validation for auth operations
type Validator struct{}

// NewValidator creates a new validator
func NewValidator() *Validator {
	return &Validator{}
}

// ValidateCreateUserRequest validates a create user request
func (v *Validator) ValidateCreateUserRequest(req *CreateUserRequest) error {
	if req == nil {
		return fmt.Errorf("request cannot be nil")
	}

	// At least one identifier must be provided
	if req.Email == nil && req.Phone == nil && req.Username == nil {
		return fmt.Errorf("at least one identifier (email, phone, or username) must be provided")
	}

	// Validate email if provided
	if req.Email != nil {
		if err := v.ValidateEmail(*req.Email); err != nil {
			return fmt.Errorf("invalid email: %w", err)
		}
	}

	// Validate phone if provided
	if req.Phone != nil {
		if err := v.ValidatePhone(*req.Phone); err != nil {
			return fmt.Errorf("invalid phone: %w", err)
		}
	}

	// Validate username if provided
	if req.Username != nil {
		if err := v.ValidateUsername(*req.Username); err != nil {
			return fmt.Errorf("invalid username: %w", err)
		}
	}

	// Validate password
	if err := v.ValidatePassword(req.Password); err != nil {
		return fmt.Errorf("invalid password: %w", err)
	}

	return nil
}

// ValidateUpdateUserRequest validates an update user request
func (v *Validator) ValidateUpdateUserRequest(req *UpdateUserRequest) error {
	if req == nil {
		return fmt.Errorf("request cannot be nil")
	}

	// Validate email if provided
	if req.Email != nil {
		if err := v.ValidateEmail(*req.Email); err != nil {
			return fmt.Errorf("invalid email: %w", err)
		}
	}

	// Validate phone if provided
	if req.Phone != nil {
		if err := v.ValidatePhone(*req.Phone); err != nil {
			return fmt.Errorf("invalid phone: %w", err)
		}
	}

	// Validate username if provided
	if req.Username != nil {
		if err := v.ValidateUsername(*req.Username); err != nil {
			return fmt.Errorf("invalid username: %w", err)
		}
	}

	return nil
}

// ValidateLoginRequest validates a login request
func (v *Validator) ValidateLoginRequest(req *LoginRequest) error {
	if req == nil {
		return fmt.Errorf("request cannot be nil")
	}

	if strings.TrimSpace(req.Identifier) == "" {
		return fmt.Errorf("identifier cannot be empty")
	}

	if strings.TrimSpace(req.Password) == "" {
		return fmt.Errorf("password cannot be empty")
	}

	return nil
}

// ValidateEmail validates an email address
func (v *Validator) ValidateEmail(email string) error {
	if strings.TrimSpace(email) == "" {
		return fmt.Errorf("email cannot be empty")
	}

	// Basic email regex pattern
	emailRegex := regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)
	if !emailRegex.MatchString(email) {
		return fmt.Errorf("invalid email format")
	}

	if len(email) > 255 {
		return fmt.Errorf("email too long (max 255 characters)")
	}

	return nil
}

// ValidatePhone validates a phone number
func (v *Validator) ValidatePhone(phone string) error {
	if strings.TrimSpace(phone) == "" {
		return fmt.Errorf("phone cannot be empty")
	}

	// Remove common phone number characters for validation
	cleanPhone := strings.ReplaceAll(phone, " ", "")
	cleanPhone = strings.ReplaceAll(cleanPhone, "-", "")
	cleanPhone = strings.ReplaceAll(cleanPhone, "(", "")
	cleanPhone = strings.ReplaceAll(cleanPhone, ")", "")
	cleanPhone = strings.ReplaceAll(cleanPhone, "+", "")

	// Check if remaining characters are digits
	phoneRegex := regexp.MustCompile(`^\d{10,15}$`)
	if !phoneRegex.MatchString(cleanPhone) {
		return fmt.Errorf("invalid phone format (must be 10-15 digits)")
	}

	if len(phone) > 20 {
		return fmt.Errorf("phone too long (max 20 characters)")
	}

	return nil
}

// ValidateUsername validates a username
func (v *Validator) ValidateUsername(username string) error {
	if strings.TrimSpace(username) == "" {
		return fmt.Errorf("username cannot be empty")
	}

	if len(username) < 3 {
		return fmt.Errorf("username too short (min 3 characters)")
	}

	if len(username) > 100 {
		return fmt.Errorf("username too long (max 100 characters)")
	}

	// Username can contain letters, numbers, underscores, and hyphens
	usernameRegex := regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)
	if !usernameRegex.MatchString(username) {
		return fmt.Errorf("username can only contain letters, numbers, underscores, and hyphens")
	}

	return nil
}

// ValidatePassword validates a password
func (v *Validator) ValidatePassword(password string) error {
	if strings.TrimSpace(password) == "" {
		return fmt.Errorf("password cannot be empty")
	}

	if len(password) < 8 {
		return fmt.Errorf("password too short (min 8 characters)")
	}

	if len(password) > 128 {
		return fmt.Errorf("password too long (max 128 characters)")
	}

	// Check for at least one uppercase letter
	hasUpper := regexp.MustCompile(`[A-Z]`).MatchString(password)
	if !hasUpper {
		return fmt.Errorf("password must contain at least one uppercase letter")
	}

	// Check for at least one lowercase letter
	hasLower := regexp.MustCompile(`[a-z]`).MatchString(password)
	if !hasLower {
		return fmt.Errorf("password must contain at least one lowercase letter")
	}

	// Check for at least one digit
	hasDigit := regexp.MustCompile(`\d`).MatchString(password)
	if !hasDigit {
		return fmt.Errorf("password must contain at least one digit")
	}

	// Check for at least one special character
	hasSpecial := regexp.MustCompile(`[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]`).MatchString(password)
	if !hasSpecial {
		return fmt.Errorf("password must contain at least one special character")
	}

	return nil
}

// ValidateUserID validates a user ID
func (v *Validator) ValidateUserID(id string) error {
	if strings.TrimSpace(id) == "" {
		return fmt.Errorf("user ID cannot be empty")
	}

	// Check if it's a valid UUID format
	uuidRegex := regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	if !uuidRegex.MatchString(id) {
		return fmt.Errorf("invalid user ID format")
	}

	return nil
}

// ValidatePasswordResetRequest validates a password reset request
func (v *Validator) ValidatePasswordResetRequest(req *PasswordResetRequest) error {
	if req == nil {
		return fmt.Errorf("request cannot be nil")
	}

	if strings.TrimSpace(req.Identifier) == "" {
		return fmt.Errorf("identifier cannot be empty")
	}

	return nil
}

// ValidatePasswordResetConfirmRequest validates a password reset confirmation request
func (v *Validator) ValidatePasswordResetConfirmRequest(req *PasswordResetConfirmRequest) error {
	if req == nil {
		return fmt.Errorf("request cannot be nil")
	}

	if strings.TrimSpace(req.Token) == "" {
		return fmt.Errorf("token cannot be empty")
	}

	if err := v.ValidatePassword(req.NewPassword); err != nil {
		return fmt.Errorf("invalid new password: %w", err)
	}

	return nil
}

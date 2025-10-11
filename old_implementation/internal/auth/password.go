package auth

import (
	"fmt"

	"golang.org/x/crypto/bcrypt"
)

const (
	// DefaultBcryptCost is the default cost for bcrypt hashing
	DefaultBcryptCost = 12
)

// PasswordHasher handles password hashing and validation
type PasswordHasher struct {
	cost int
}

// NewPasswordHasher creates a new password hasher with default cost
func NewPasswordHasher() *PasswordHasher {
	return &PasswordHasher{
		cost: DefaultBcryptCost,
	}
}

// NewPasswordHasherWithCost creates a new password hasher with custom cost
func NewPasswordHasherWithCost(cost int) *PasswordHasher {
	return &PasswordHasher{
		cost: cost,
	}
}

// HashPassword hashes a password using bcrypt
func (ph *PasswordHasher) HashPassword(password string) (string, error) {
	if password == "" {
		return "", fmt.Errorf("password cannot be empty")
	}

	hashedBytes, err := bcrypt.GenerateFromPassword([]byte(password), ph.cost)
	if err != nil {
		return "", fmt.Errorf("failed to hash password: %w", err)
	}

	return string(hashedBytes), nil
}

// ValidatePassword validates a password against its hash
func (ph *PasswordHasher) ValidatePassword(password, hash string) error {
	if password == "" {
		return fmt.Errorf("password cannot be empty")
	}

	if hash == "" {
		return fmt.Errorf("password hash cannot be empty")
	}

	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	if err != nil {
		return fmt.Errorf("invalid password")
	}

	return nil
}

// NeedsRehash checks if a password hash needs to be rehashed due to cost changes
func (ph *PasswordHasher) NeedsRehash(hash string) bool {
	cost, err := bcrypt.Cost([]byte(hash))
	if err != nil {
		return true // If we can't determine cost, assume it needs rehashing
	}

	return cost != ph.cost
}

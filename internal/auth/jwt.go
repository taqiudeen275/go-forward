package auth

import (
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// JWTManager handles JWT token operations
type JWTManager struct {
	secretKey         []byte
	accessExpiration  time.Duration
	refreshExpiration time.Duration
	blacklist         *TokenBlacklist
}

// NewJWTManager creates a new JWT manager
func NewJWTManager(secretKey string, accessExpiration, refreshExpiration time.Duration) *JWTManager {
	return &JWTManager{
		secretKey:         []byte(secretKey),
		accessExpiration:  accessExpiration,
		refreshExpiration: refreshExpiration,
		blacklist:         NewTokenBlacklist(),
	}
}

// Claims represents JWT claims
type Claims struct {
	UserID    string                 `json:"user_id"`
	Email     string                 `json:"email"`
	Username  string                 `json:"username"`
	Phone     string                 `json:"phone"`
	Metadata  map[string]interface{} `json:"metadata"`
	TokenType string                 `json:"token_type"` // "access" or "refresh"
	jwt.RegisteredClaims
}

// TokenPair represents access and refresh tokens
type TokenPair struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int64  `json:"expires_in"`
}

// GenerateTokenPair generates both access and refresh tokens for a user
func (jm *JWTManager) GenerateTokenPair(user *User) (*TokenPair, error) {
	// Generate access token
	accessToken, err := jm.generateToken(user, "access", jm.accessExpiration)
	if err != nil {
		return nil, fmt.Errorf("failed to generate access token: %w", err)
	}

	// Generate refresh token
	refreshToken, err := jm.generateToken(user, "refresh", jm.refreshExpiration)
	if err != nil {
		return nil, fmt.Errorf("failed to generate refresh token: %w", err)
	}

	return &TokenPair{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresIn:    int64(jm.accessExpiration.Seconds()),
	}, nil
}

// generateToken generates a JWT token for a user
func (jm *JWTManager) generateToken(user *User, tokenType string, expiration time.Duration) (string, error) {
	now := time.Now()
	expiresAt := now.Add(expiration)

	// Create claims
	claims := &Claims{
		UserID:    user.ID,
		TokenType: tokenType,
		RegisteredClaims: jwt.RegisteredClaims{
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(expiresAt),
			NotBefore: jwt.NewNumericDate(now),
			Issuer:    "go-forward",
			Subject:   user.ID,
		},
	}

	// Add user information to claims
	if user.Email != nil {
		claims.Email = *user.Email
	}
	if user.Username != nil {
		claims.Username = *user.Username
	}
	if user.Phone != nil {
		claims.Phone = *user.Phone
	}
	if user.Metadata != nil {
		claims.Metadata = user.Metadata
	}

	// Create token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	// Sign token
	tokenString, err := token.SignedString(jm.secretKey)
	if err != nil {
		return "", fmt.Errorf("failed to sign token: %w", err)
	}

	return tokenString, nil
}

// ValidateToken validates a JWT token and returns the claims
func (jm *JWTManager) ValidateToken(tokenString string) (*Claims, error) {
	// Check if token is blacklisted
	if jm.blacklist.IsBlacklisted(tokenString) {
		return nil, fmt.Errorf("token has been revoked")
	}

	// Parse token
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		// Validate signing method
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return jm.secretKey, nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to parse token: %w", err)
	}

	// Extract claims
	claims, ok := token.Claims.(*Claims)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("invalid token")
	}

	// Check if token is expired
	if claims.ExpiresAt != nil && claims.ExpiresAt.Time.Before(time.Now()) {
		return nil, fmt.Errorf("token has expired")
	}

	return claims, nil
}

// ValidateAccessToken validates an access token specifically
func (jm *JWTManager) ValidateAccessToken(tokenString string) (*Claims, error) {
	claims, err := jm.ValidateToken(tokenString)
	if err != nil {
		return nil, err
	}

	if claims.TokenType != "access" {
		return nil, fmt.Errorf("invalid token type: expected access token")
	}

	return claims, nil
}

// ValidateRefreshToken validates a refresh token specifically
func (jm *JWTManager) ValidateRefreshToken(tokenString string) (*Claims, error) {
	claims, err := jm.ValidateToken(tokenString)
	if err != nil {
		return nil, err
	}

	if claims.TokenType != "refresh" {
		return nil, fmt.Errorf("invalid token type: expected refresh token")
	}

	return claims, nil
}

// RefreshTokenPair generates a new token pair using a valid refresh token
func (jm *JWTManager) RefreshTokenPair(refreshTokenString string, user *User) (*TokenPair, error) {
	// Validate refresh token
	claims, err := jm.ValidateRefreshToken(refreshTokenString)
	if err != nil {
		return nil, fmt.Errorf("invalid refresh token: %w", err)
	}

	// Blacklist the old refresh token to prevent reuse
	if claims.ExpiresAt != nil {
		jm.blacklist.BlacklistToken(refreshTokenString, claims.ExpiresAt.Time)
	}

	// Generate new token pair
	return jm.GenerateTokenPair(user)
}

// ExtractUserID extracts user ID from a token without full validation
func (jm *JWTManager) ExtractUserID(tokenString string) (string, error) {
	// Parse token without validation to extract claims
	token, _, err := new(jwt.Parser).ParseUnverified(tokenString, &Claims{})
	if err != nil {
		return "", fmt.Errorf("failed to parse token: %w", err)
	}

	claims, ok := token.Claims.(*Claims)
	if !ok {
		return "", fmt.Errorf("invalid token claims")
	}

	return claims.UserID, nil
}

// GetTokenExpiration returns the expiration time of a token
func (jm *JWTManager) GetTokenExpiration(tokenString string) (time.Time, error) {
	claims, err := jm.ValidateToken(tokenString)
	if err != nil {
		return time.Time{}, err
	}

	if claims.ExpiresAt == nil {
		return time.Time{}, fmt.Errorf("token has no expiration")
	}

	return claims.ExpiresAt.Time, nil
}

// IsTokenExpired checks if a token is expired
func (jm *JWTManager) IsTokenExpired(tokenString string) bool {
	expiration, err := jm.GetTokenExpiration(tokenString)
	if err != nil {
		return true // Consider invalid tokens as expired
	}

	return expiration.Before(time.Now())
}

// BlacklistToken adds a token to the blacklist (for logout)
func (jm *JWTManager) BlacklistToken(tokenString string) error {
	claims, err := jm.ValidateToken(tokenString)
	if err != nil {
		// Even if token is invalid, we might want to blacklist it
		// Extract expiration without validation
		token, _, parseErr := new(jwt.Parser).ParseUnverified(tokenString, &Claims{})
		if parseErr != nil {
			return fmt.Errorf("cannot blacklist invalid token: %w", parseErr)
		}

		if claims, ok := token.Claims.(*Claims); ok && claims.ExpiresAt != nil {
			jm.blacklist.BlacklistToken(tokenString, claims.ExpiresAt.Time)
			return nil
		}

		return fmt.Errorf("cannot determine token expiration: %w", err)
	}

	if claims.ExpiresAt != nil {
		jm.blacklist.BlacklistToken(tokenString, claims.ExpiresAt.Time)
	}

	return nil
}

// GetBlacklistStats returns blacklist statistics
func (jm *JWTManager) GetBlacklistStats() map[string]interface{} {
	return jm.blacklist.GetBlacklistStats()
}

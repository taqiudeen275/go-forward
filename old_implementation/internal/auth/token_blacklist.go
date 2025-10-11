package auth

import (
	"sync"
	"time"
)

// TokenBlacklist manages blacklisted tokens
type TokenBlacklist struct {
	// In-memory blacklist (in production, use Redis or database)
	blacklistedTokens map[string]time.Time
	mutex             sync.RWMutex
	cleanupInterval   time.Duration
}

// NewTokenBlacklist creates a new token blacklist
func NewTokenBlacklist() *TokenBlacklist {
	blacklist := &TokenBlacklist{
		blacklistedTokens: make(map[string]time.Time),
		cleanupInterval:   1 * time.Hour,
	}

	// Start cleanup routine
	go blacklist.cleanupRoutine()

	return blacklist
}

// BlacklistToken adds a token to the blacklist
func (tb *TokenBlacklist) BlacklistToken(tokenString string, expiresAt time.Time) {
	tb.mutex.Lock()
	defer tb.mutex.Unlock()

	tb.blacklistedTokens[tokenString] = expiresAt
}

// IsBlacklisted checks if a token is blacklisted
func (tb *TokenBlacklist) IsBlacklisted(tokenString string) bool {
	tb.mutex.RLock()
	defer tb.mutex.RUnlock()

	expiresAt, exists := tb.blacklistedTokens[tokenString]
	if !exists {
		return false
	}

	// If token has expired, it's effectively not blacklisted anymore
	if time.Now().After(expiresAt) {
		// Clean up expired entry
		go func() {
			tb.mutex.Lock()
			defer tb.mutex.Unlock()
			delete(tb.blacklistedTokens, tokenString)
		}()
		return false
	}

	return true
}

// cleanupRoutine periodically removes expired tokens from blacklist
func (tb *TokenBlacklist) cleanupRoutine() {
	ticker := time.NewTicker(tb.cleanupInterval)
	defer ticker.Stop()

	for range ticker.C {
		tb.cleanup()
	}
}

// cleanup removes expired tokens from the blacklist
func (tb *TokenBlacklist) cleanup() {
	tb.mutex.Lock()
	defer tb.mutex.Unlock()

	now := time.Now()
	for token, expiresAt := range tb.blacklistedTokens {
		if now.After(expiresAt) {
			delete(tb.blacklistedTokens, token)
		}
	}
}

// GetBlacklistStats returns statistics about the blacklist
func (tb *TokenBlacklist) GetBlacklistStats() map[string]interface{} {
	tb.mutex.RLock()
	defer tb.mutex.RUnlock()

	return map[string]interface{}{
		"total_blacklisted_tokens": len(tb.blacklistedTokens),
		"cleanup_interval_minutes": int(tb.cleanupInterval.Minutes()),
	}
}

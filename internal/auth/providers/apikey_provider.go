package providers

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/taqiudeen275/go-foward/internal/auth"
)

// APIKeyConfig represents API key authentication configuration
type APIKeyConfig struct {
	KeyPrefix     string        `json:"key_prefix" yaml:"key_prefix"`         // e.g., "gf_"
	KeyLength     int           `json:"key_length" yaml:"key_length"`         // Length of the random part
	HashAlgorithm string        `json:"hash_algorithm" yaml:"hash_algorithm"` // "sha256"
	CacheTimeout  time.Duration `json:"cache_timeout" yaml:"cache_timeout"`   // Cache timeout for key validation
	AllowedScopes []string      `json:"allowed_scopes" yaml:"allowed_scopes"` // Allowed scopes for API keys
	RequireScopes bool          `json:"require_scopes" yaml:"require_scopes"` // Whether scopes are required
}

// APIKey represents an API key
type APIKey struct {
	ID         string                 `json:"id"`
	UserID     string                 `json:"user_id"`
	Name       string                 `json:"name"`
	KeyHash    string                 `json:"key_hash"` // Hashed version of the key
	Scopes     []string               `json:"scopes"`   // Permissions/scopes for this key
	Metadata   map[string]interface{} `json:"metadata"`
	ExpiresAt  *time.Time             `json:"expires_at"` // Optional expiration
	LastUsedAt *time.Time             `json:"last_used_at"`
	IsActive   bool                   `json:"is_active"`
	CreatedAt  time.Time              `json:"created_at"`
	UpdatedAt  time.Time              `json:"updated_at"`
}

// APIKeyStore defines the interface for storing and retrieving API keys
type APIKeyStore interface {
	GetAPIKeyByHash(ctx context.Context, keyHash string) (*APIKey, error)
	CreateAPIKey(ctx context.Context, apiKey *APIKey) error
	UpdateAPIKey(ctx context.Context, id string, updates map[string]interface{}) error
	DeleteAPIKey(ctx context.Context, id string) error
	ListAPIKeys(ctx context.Context, userID string) ([]*APIKey, error)
	UpdateLastUsed(ctx context.Context, id string) error
}

// InMemoryAPIKeyStore provides an in-memory implementation of APIKeyStore
type InMemoryAPIKeyStore struct {
	keys  map[string]*APIKey // keyHash -> APIKey
	mutex sync.RWMutex
}

// NewInMemoryAPIKeyStore creates a new in-memory API key store
func NewInMemoryAPIKeyStore() *InMemoryAPIKeyStore {
	return &InMemoryAPIKeyStore{
		keys: make(map[string]*APIKey),
	}
}

// GetAPIKeyByHash retrieves an API key by its hash
func (s *InMemoryAPIKeyStore) GetAPIKeyByHash(ctx context.Context, keyHash string) (*APIKey, error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	key, exists := s.keys[keyHash]
	if !exists {
		return nil, fmt.Errorf("API key not found")
	}

	// Check if key is active
	if !key.IsActive {
		return nil, fmt.Errorf("API key is inactive")
	}

	// Check if key is expired
	if key.ExpiresAt != nil && time.Now().After(*key.ExpiresAt) {
		return nil, fmt.Errorf("API key has expired")
	}

	return key, nil
}

// CreateAPIKey creates a new API key
func (s *InMemoryAPIKeyStore) CreateAPIKey(ctx context.Context, apiKey *APIKey) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	s.keys[apiKey.KeyHash] = apiKey
	return nil
}

// UpdateAPIKey updates an API key
func (s *InMemoryAPIKeyStore) UpdateAPIKey(ctx context.Context, id string, updates map[string]interface{}) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	// Find the key by ID
	var targetKey *APIKey
	for _, key := range s.keys {
		if key.ID == id {
			targetKey = key
			break
		}
	}

	if targetKey == nil {
		return fmt.Errorf("API key not found")
	}

	// Apply updates
	if name, ok := updates["name"].(string); ok {
		targetKey.Name = name
	}
	if scopes, ok := updates["scopes"].([]string); ok {
		targetKey.Scopes = scopes
	}
	if isActive, ok := updates["is_active"].(bool); ok {
		targetKey.IsActive = isActive
	}
	if expiresAt, ok := updates["expires_at"].(*time.Time); ok {
		targetKey.ExpiresAt = expiresAt
	}
	if metadata, ok := updates["metadata"].(map[string]interface{}); ok {
		targetKey.Metadata = metadata
	}

	targetKey.UpdatedAt = time.Now()
	return nil
}

// DeleteAPIKey deletes an API key
func (s *InMemoryAPIKeyStore) DeleteAPIKey(ctx context.Context, id string) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	// Find and delete the key by ID
	for keyHash, key := range s.keys {
		if key.ID == id {
			delete(s.keys, keyHash)
			return nil
		}
	}

	return fmt.Errorf("API key not found")
}

// ListAPIKeys lists all API keys for a user
func (s *InMemoryAPIKeyStore) ListAPIKeys(ctx context.Context, userID string) ([]*APIKey, error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	var keys []*APIKey
	for _, key := range s.keys {
		if key.UserID == userID {
			keys = append(keys, key)
		}
	}

	return keys, nil
}

// UpdateLastUsed updates the last used timestamp
func (s *InMemoryAPIKeyStore) UpdateLastUsed(ctx context.Context, id string) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	// Find the key by ID
	for _, key := range s.keys {
		if key.ID == id {
			now := time.Now()
			key.LastUsedAt = &now
			return nil
		}
	}

	return fmt.Errorf("API key not found")
}

// APIKeyAuthProvider implements API key authentication
type APIKeyAuthProvider struct {
	*auth.BaseCustomAuthProvider
	config *APIKeyConfig
	store  APIKeyStore
	cache  map[string]*APIKey // Simple cache for validated keys
	mutex  sync.RWMutex
}

// NewAPIKeyAuthProvider creates a new API key authentication provider
func NewAPIKeyAuthProvider(config *APIKeyConfig, store APIKeyStore) *APIKeyAuthProvider {
	if config == nil {
		config = &APIKeyConfig{
			KeyPrefix:     "gf_",
			KeyLength:     32,
			HashAlgorithm: "sha256",
			CacheTimeout:  5 * time.Minute,
			AllowedScopes: []string{"read", "write", "admin"},
			RequireScopes: false,
		}
	}

	if store == nil {
		store = NewInMemoryAPIKeyStore()
	}

	required := []string{"api_key"}
	optional := []string{"scopes"}

	return &APIKeyAuthProvider{
		BaseCustomAuthProvider: auth.NewBaseCustomAuthProvider("api_key", required, optional),
		config:                 config,
		store:                  store,
		cache:                  make(map[string]*APIKey),
	}
}

// Authenticate validates API key and returns associated user
func (p *APIKeyAuthProvider) Authenticate(ctx context.Context, credentials map[string]interface{}) (*auth.User, error) {
	// Extract API key
	apiKeyStr, ok := credentials["api_key"].(string)
	if !ok || apiKeyStr == "" {
		return nil, fmt.Errorf("api_key is required")
	}

	// Validate key format
	if !strings.HasPrefix(apiKeyStr, p.config.KeyPrefix) {
		return nil, fmt.Errorf("invalid API key format")
	}

	// Hash the API key
	keyHash := p.hashAPIKey(apiKeyStr)

	// Check cache first
	if cachedKey := p.getCachedKey(keyHash); cachedKey != nil {
		// Update last used
		go p.store.UpdateLastUsed(ctx, cachedKey.ID)
		return p.createUserFromAPIKey(cachedKey), nil
	}

	// Retrieve from store
	apiKey, err := p.store.GetAPIKeyByHash(ctx, keyHash)
	if err != nil {
		return nil, fmt.Errorf("invalid API key: %w", err)
	}

	// Validate scopes if provided
	if requestedScopes, exists := credentials["scopes"]; exists {
		if scopes, ok := requestedScopes.([]string); ok {
			if !p.validateScopes(apiKey.Scopes, scopes) {
				return nil, fmt.Errorf("insufficient scopes")
			}
		}
	}

	// Cache the key
	p.cacheKey(keyHash, apiKey)

	// Update last used
	go p.store.UpdateLastUsed(ctx, apiKey.ID)

	return p.createUserFromAPIKey(apiKey), nil
}

// ValidateCredentials validates API key credential format
func (p *APIKeyAuthProvider) ValidateCredentials(credentials map[string]interface{}) error {
	// First call base validation
	if err := p.BaseCustomAuthProvider.ValidateCredentials(credentials); err != nil {
		return err
	}

	// Additional API key-specific validation
	apiKey, ok := credentials["api_key"].(string)
	if !ok {
		return fmt.Errorf("api_key must be a string")
	}

	if !strings.HasPrefix(apiKey, p.config.KeyPrefix) {
		return fmt.Errorf("API key must start with prefix '%s'", p.config.KeyPrefix)
	}

	expectedLength := len(p.config.KeyPrefix) + p.config.KeyLength
	if len(apiKey) != expectedLength {
		return fmt.Errorf("API key has invalid length")
	}

	// Validate scopes if provided
	if scopes, exists := credentials["scopes"]; exists {
		if scopeSlice, ok := scopes.([]string); ok {
			for _, scope := range scopeSlice {
				if !p.isValidScope(scope) {
					return fmt.Errorf("invalid scope: %s", scope)
				}
			}
		} else {
			return fmt.Errorf("scopes must be an array of strings")
		}
	}

	return nil
}

// GenerateAPIKey generates a new API key
func (p *APIKeyAuthProvider) GenerateAPIKey(ctx context.Context, userID, name string, scopes []string, expiresAt *time.Time) (*APIKey, string, error) {
	// Generate random key
	randomBytes := make([]byte, p.config.KeyLength/2) // Hex encoding doubles the length
	if _, err := rand.Read(randomBytes); err != nil {
		return nil, "", fmt.Errorf("failed to generate random key: %w", err)
	}

	keyStr := p.config.KeyPrefix + hex.EncodeToString(randomBytes)
	keyHash := p.hashAPIKey(keyStr)

	// Create API key object
	apiKey := &APIKey{
		ID:        uuid.New().String(),
		UserID:    userID,
		Name:      name,
		KeyHash:   keyHash,
		Scopes:    scopes,
		Metadata:  make(map[string]interface{}),
		ExpiresAt: expiresAt,
		IsActive:  true,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	// Store the API key
	if err := p.store.CreateAPIKey(ctx, apiKey); err != nil {
		return nil, "", fmt.Errorf("failed to store API key: %w", err)
	}

	return apiKey, keyStr, nil
}

// RevokeAPIKey revokes an API key
func (p *APIKeyAuthProvider) RevokeAPIKey(ctx context.Context, keyID string) error {
	updates := map[string]interface{}{
		"is_active": false,
	}
	return p.store.UpdateAPIKey(ctx, keyID, updates)
}

// ListAPIKeys lists API keys for a user
func (p *APIKeyAuthProvider) ListAPIKeys(ctx context.Context, userID string) ([]*APIKey, error) {
	return p.store.ListAPIKeys(ctx, userID)
}

// hashAPIKey hashes an API key using the configured algorithm
func (p *APIKeyAuthProvider) hashAPIKey(key string) string {
	switch p.config.HashAlgorithm {
	case "sha256":
		hash := sha256.Sum256([]byte(key))
		return hex.EncodeToString(hash[:])
	default:
		// Fallback to sha256
		hash := sha256.Sum256([]byte(key))
		return hex.EncodeToString(hash[:])
	}
}

// getCachedKey retrieves a key from cache
func (p *APIKeyAuthProvider) getCachedKey(keyHash string) *APIKey {
	p.mutex.RLock()
	defer p.mutex.RUnlock()
	return p.cache[keyHash]
}

// cacheKey stores a key in cache
func (p *APIKeyAuthProvider) cacheKey(keyHash string, apiKey *APIKey) {
	p.mutex.Lock()
	defer p.mutex.Unlock()
	p.cache[keyHash] = apiKey

	// Set up cache expiration
	go func() {
		time.Sleep(p.config.CacheTimeout)
		p.mutex.Lock()
		delete(p.cache, keyHash)
		p.mutex.Unlock()
	}()
}

// validateScopes checks if requested scopes are allowed
func (p *APIKeyAuthProvider) validateScopes(keyScopes, requestedScopes []string) bool {
	if !p.config.RequireScopes {
		return true
	}

	for _, requested := range requestedScopes {
		found := false
		for _, keyScope := range keyScopes {
			if keyScope == requested {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

// isValidScope checks if a scope is in the allowed list
func (p *APIKeyAuthProvider) isValidScope(scope string) bool {
	for _, allowed := range p.config.AllowedScopes {
		if allowed == scope {
			return true
		}
	}
	return false
}

// createUserFromAPIKey creates a user object from API key information
func (p *APIKeyAuthProvider) createUserFromAPIKey(apiKey *APIKey) *auth.User {
	user := &auth.User{
		ID:            apiKey.UserID,
		EmailVerified: true, // API keys are considered verified
		PhoneVerified: false,
		Metadata:      make(map[string]interface{}),
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
	}

	// Add API key metadata
	user.Metadata["auth_provider"] = "api_key"
	user.Metadata["api_key_id"] = apiKey.ID
	user.Metadata["api_key_name"] = apiKey.Name
	user.Metadata["api_key_scopes"] = apiKey.Scopes
	if apiKey.LastUsedAt != nil {
		user.Metadata["api_key_last_used"] = apiKey.LastUsedAt
	}

	// Copy API key metadata
	for k, v := range apiKey.Metadata {
		user.Metadata["api_key_"+k] = v
	}

	return user
}

// UpdateConfig updates the API key configuration
func (p *APIKeyAuthProvider) UpdateConfig(config *APIKeyConfig) {
	p.config = config
}

// GetConfig returns the current API key configuration
func (p *APIKeyAuthProvider) GetConfig() map[string]interface{} {
	return map[string]interface{}{
		"key_prefix":     p.config.KeyPrefix,
		"key_length":     p.config.KeyLength,
		"hash_algorithm": p.config.HashAlgorithm,
		"cache_timeout":  p.config.CacheTimeout.String(),
		"allowed_scopes": p.config.AllowedScopes,
		"require_scopes": p.config.RequireScopes,
	}
}

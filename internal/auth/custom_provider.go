package auth

import (
	"context"
	"fmt"
	"sync"
)

// CustomAuthProvider defines the interface for custom authentication providers
type CustomAuthProvider interface {
	// Name returns the unique name/identifier for this provider
	Name() string

	// Authenticate validates credentials and returns a user if successful
	// The credentials map contains provider-specific authentication data
	Authenticate(ctx context.Context, credentials map[string]interface{}) (*User, error)

	// ValidateCredentials validates the format and requirements of credentials
	// without performing actual authentication
	ValidateCredentials(credentials map[string]interface{}) error

	// GetRequiredFields returns the list of required credential fields
	GetRequiredFields() []string

	// GetOptionalFields returns the list of optional credential fields
	GetOptionalFields() []string

	// IsEnabled returns whether this provider is currently enabled
	IsEnabled() bool

	// SetEnabled enables or disables this provider
	SetEnabled(enabled bool)
}

// CustomAuthProviderManager manages custom authentication providers
type CustomAuthProviderManager struct {
	providers map[string]CustomAuthProvider
	mutex     sync.RWMutex
}

// NewCustomAuthProviderManager creates a new provider manager
func NewCustomAuthProviderManager() *CustomAuthProviderManager {
	return &CustomAuthProviderManager{
		providers: make(map[string]CustomAuthProvider),
	}
}

// RegisterProvider registers a new custom authentication provider
func (m *CustomAuthProviderManager) RegisterProvider(provider CustomAuthProvider) error {
	if provider == nil {
		return fmt.Errorf("provider cannot be nil")
	}

	name := provider.Name()
	if name == "" {
		return fmt.Errorf("provider name cannot be empty")
	}

	m.mutex.Lock()
	defer m.mutex.Unlock()

	if _, exists := m.providers[name]; exists {
		return fmt.Errorf("provider with name '%s' already registered", name)
	}

	m.providers[name] = provider
	return nil
}

// UnregisterProvider removes a custom authentication provider
func (m *CustomAuthProviderManager) UnregisterProvider(name string) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	if _, exists := m.providers[name]; !exists {
		return fmt.Errorf("provider with name '%s' not found", name)
	}

	delete(m.providers, name)
	return nil
}

// GetProvider retrieves a provider by name
func (m *CustomAuthProviderManager) GetProvider(name string) (CustomAuthProvider, error) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	provider, exists := m.providers[name]
	if !exists {
		return nil, fmt.Errorf("provider with name '%s' not found", name)
	}

	return provider, nil
}

// ListProviders returns all registered providers
func (m *CustomAuthProviderManager) ListProviders() map[string]CustomAuthProvider {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	// Return a copy to prevent external modification
	result := make(map[string]CustomAuthProvider)
	for name, provider := range m.providers {
		result[name] = provider
	}

	return result
}

// GetEnabledProviders returns only enabled providers
func (m *CustomAuthProviderManager) GetEnabledProviders() map[string]CustomAuthProvider {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	result := make(map[string]CustomAuthProvider)
	for name, provider := range m.providers {
		if provider.IsEnabled() {
			result[name] = provider
		}
	}

	return result
}

// ValidateCredentials validates credentials for a specific provider
func (m *CustomAuthProviderManager) ValidateCredentials(providerName string, credentials map[string]interface{}) error {
	provider, err := m.GetProvider(providerName)
	if err != nil {
		return err
	}

	if !provider.IsEnabled() {
		return fmt.Errorf("provider '%s' is disabled", providerName)
	}

	return provider.ValidateCredentials(credentials)
}

// Authenticate performs authentication using a specific provider
func (m *CustomAuthProviderManager) Authenticate(ctx context.Context, providerName string, credentials map[string]interface{}) (*User, error) {
	provider, err := m.GetProvider(providerName)
	if err != nil {
		return nil, err
	}

	if !provider.IsEnabled() {
		return nil, fmt.Errorf("provider '%s' is disabled", providerName)
	}

	// Validate credentials first
	if err := provider.ValidateCredentials(credentials); err != nil {
		return nil, fmt.Errorf("credential validation failed: %w", err)
	}

	// Perform authentication
	return provider.Authenticate(ctx, credentials)
}

// GetProviderInfo returns information about a provider
func (m *CustomAuthProviderManager) GetProviderInfo(providerName string) (map[string]interface{}, error) {
	provider, err := m.GetProvider(providerName)
	if err != nil {
		return nil, err
	}

	return map[string]interface{}{
		"name":            provider.Name(),
		"enabled":         provider.IsEnabled(),
		"required_fields": provider.GetRequiredFields(),
		"optional_fields": provider.GetOptionalFields(),
	}, nil
}

// BaseCustomAuthProvider provides a base implementation for custom auth providers
type BaseCustomAuthProvider struct {
	name     string
	enabled  bool
	required []string
	optional []string
	mutex    sync.RWMutex
}

// NewBaseCustomAuthProvider creates a new base provider
func NewBaseCustomAuthProvider(name string, required, optional []string) *BaseCustomAuthProvider {
	return &BaseCustomAuthProvider{
		name:     name,
		enabled:  true,
		required: required,
		optional: optional,
	}
}

// Name returns the provider name
func (p *BaseCustomAuthProvider) Name() string {
	return p.name
}

// GetRequiredFields returns required fields
func (p *BaseCustomAuthProvider) GetRequiredFields() []string {
	return p.required
}

// GetOptionalFields returns optional fields
func (p *BaseCustomAuthProvider) GetOptionalFields() []string {
	return p.optional
}

// IsEnabled returns whether the provider is enabled
func (p *BaseCustomAuthProvider) IsEnabled() bool {
	p.mutex.RLock()
	defer p.mutex.RUnlock()
	return p.enabled
}

// SetEnabled sets the provider enabled state
func (p *BaseCustomAuthProvider) SetEnabled(enabled bool) {
	p.mutex.Lock()
	defer p.mutex.Unlock()
	p.enabled = enabled
}

// ValidateCredentials validates that all required fields are present
func (p *BaseCustomAuthProvider) ValidateCredentials(credentials map[string]interface{}) error {
	if credentials == nil {
		return fmt.Errorf("credentials cannot be nil")
	}

	// Check required fields
	for _, field := range p.required {
		if _, exists := credentials[field]; !exists {
			return fmt.Errorf("required field '%s' is missing", field)
		}

		// Check that the field is not empty
		if value, ok := credentials[field].(string); ok && value == "" {
			return fmt.Errorf("required field '%s' cannot be empty", field)
		}
	}

	return nil
}

// Authenticate must be implemented by concrete providers
func (p *BaseCustomAuthProvider) Authenticate(ctx context.Context, credentials map[string]interface{}) (*User, error) {
	return nil, fmt.Errorf("authenticate method must be implemented by concrete provider")
}

package providers

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/taqiudeen275/go-foward/internal/auth"
)

// ExampleUsage demonstrates how to use the custom authentication providers
func ExampleUsage() {
	// Create a mock auth service (in real usage, this would be your actual auth service)
	authService := createMockAuthService()

	// Example 1: LDAP Authentication Provider
	fmt.Println("=== LDAP Authentication Provider Example ===")
	ldapConfig := &LDAPConfig{
		Host:              "ldap.example.com",
		Port:              389,
		UseSSL:            false,
		BindDN:            "cn=admin,dc=example,dc=com",
		BindPassword:      "admin_password",
		BaseDN:            "ou=users,dc=example,dc=com",
		UserFilter:        "(uid=%s)",
		EmailAttribute:    "mail",
		NameAttribute:     "cn",
		UsernameAttribute: "uid",
		ConnectionTimeout: 10 * time.Second,
		RequestTimeout:    30 * time.Second,
	}

	ldapProvider := NewLDAPAuthProvider(ldapConfig)

	// Register the LDAP provider
	if err := authService.RegisterCustomAuthProvider(ldapProvider); err != nil {
		log.Printf("Failed to register LDAP provider: %v", err)
	} else {
		fmt.Println("✓ LDAP provider registered successfully")
	}

	// Example LDAP authentication
	ldapCredentials := map[string]interface{}{
		"username": "john.doe",
		"password": "user_password",
		"domain":   "example.com", // optional
	}

	ldapAuthReq := &auth.CustomAuthRequest{
		Provider:    "ldap",
		Credentials: ldapCredentials,
	}

	fmt.Println("Attempting LDAP authentication...")
	// Note: This would fail in real usage without a real LDAP server
	// authResp, err := authService.AuthenticateWithCustomProvider(context.Background(), ldapAuthReq)
	_ = ldapAuthReq // Suppress unused variable warning

	// Example 2: API Key Authentication Provider
	fmt.Println("\n=== API Key Authentication Provider Example ===")
	apiKeyConfig := &APIKeyConfig{
		KeyPrefix:     "gf_",
		KeyLength:     32,
		HashAlgorithm: "sha256",
		CacheTimeout:  5 * time.Minute,
		AllowedScopes: []string{"read", "write", "admin"},
		RequireScopes: false,
	}

	apiKeyStore := NewInMemoryAPIKeyStore()
	apiKeyProvider := NewAPIKeyAuthProvider(apiKeyConfig, apiKeyStore)

	// Register the API key provider
	if err := authService.RegisterCustomAuthProvider(apiKeyProvider); err != nil {
		log.Printf("Failed to register API key provider: %v", err)
	} else {
		fmt.Println("✓ API key provider registered successfully")
	}

	// Generate an API key for a user
	userID := "user-123"
	apiKey, keyString, err := apiKeyProvider.GenerateAPIKey(
		context.Background(),
		userID,
		"My API Key",
		[]string{"read", "write"},
		nil, // no expiration
	)
	if err != nil {
		log.Printf("Failed to generate API key: %v", err)
	} else {
		fmt.Printf("✓ Generated API key: %s (ID: %s)\n", keyString, apiKey.ID)
	}

	// Example API key authentication
	apiKeyCredentials := map[string]interface{}{
		"api_key": keyString,
		"scopes":  []string{"read"}, // optional
	}

	apiKeyAuthReq := &auth.CustomAuthRequest{
		Provider:    "api_key",
		Credentials: apiKeyCredentials,
	}

	fmt.Println("Attempting API key authentication...")
	authResp, err := authService.AuthenticateWithCustomProvider(context.Background(), apiKeyAuthReq)
	if err != nil {
		log.Printf("API key authentication failed: %v", err)
	} else {
		fmt.Printf("✓ API key authentication successful for user: %s\n", authResp.User.ID)
	}

	// Example 3: Social Login Provider (Google)
	fmt.Println("\n=== Social Login Provider Example ===")
	googleConfig := &SocialConfig{
		ProviderType:    SocialProviderGoogle,
		ClientID:        "your-google-client-id",
		ClientSecret:    "your-google-client-secret",
		RedirectURL:     "https://yourapp.com/auth/callback/google",
		Scopes:          []string{"openid", "email", "profile"},
		RequestTimeout:  30 * time.Second,
		AllowSignup:     true,
		RequireVerified: true,
	}

	googleProvider := NewSocialAuthProvider(googleConfig)

	// Register the Google provider
	if err := authService.RegisterCustomAuthProvider(googleProvider); err != nil {
		log.Printf("Failed to register Google provider: %v", err)
	} else {
		fmt.Println("✓ Google provider registered successfully")
	}

	// Generate authorization URL
	state := "random-state-string"
	authURL := googleProvider.GetAuthURL(state, nil)
	fmt.Printf("Google OAuth URL: %s\n", authURL)

	// Example social login authentication (after OAuth callback)
	socialCredentials := map[string]interface{}{
		"code":  "authorization-code-from-callback",
		"state": state,
	}

	socialAuthReq := &auth.CustomAuthRequest{
		Provider:    "google",
		Credentials: socialCredentials,
	}

	fmt.Println("Attempting social login authentication...")
	// Note: This would fail without a real OAuth callback
	// authResp, err = authService.AuthenticateWithCustomProvider(context.Background(), socialAuthReq)
	_ = socialAuthReq // Suppress unused variable warning

	// List all registered providers
	fmt.Println("\n=== Registered Providers ===")
	providers := authService.ListCustomAuthProviders()
	for name, provider := range providers {
		info, _ := authService.GetCustomAuthProviderInfo(name)
		fmt.Printf("Provider: %s, Enabled: %v, Required Fields: %v\n",
			name,
			provider.IsEnabled(),
			info["required_fields"])
	}
}

// ExampleCustomProvider demonstrates how to create a custom authentication provider
func ExampleCustomProvider() {
	fmt.Println("\n=== Custom Provider Implementation Example ===")

	// Create a simple custom provider
	customProvider := &SimpleCustomProvider{
		BaseCustomAuthProvider: auth.NewBaseCustomAuthProvider(
			"simple",
			[]string{"token"},
			[]string{"user_id"},
		),
		validTokens: map[string]string{
			"token123": "user-456",
			"token456": "user-789",
		},
	}

	// Create mock auth service and register the custom provider
	authService := createMockAuthService()
	if err := authService.RegisterCustomAuthProvider(customProvider); err != nil {
		log.Printf("Failed to register custom provider: %v", err)
	} else {
		fmt.Println("✓ Custom provider registered successfully")
	}

	// Test the custom provider
	credentials := map[string]interface{}{
		"token": "token123",
	}

	authReq := &auth.CustomAuthRequest{
		Provider:    "simple",
		Credentials: credentials,
	}

	authResp, err := authService.AuthenticateWithCustomProvider(context.Background(), authReq)
	if err != nil {
		log.Printf("Custom authentication failed: %v", err)
	} else {
		fmt.Printf("✓ Custom authentication successful for user: %s\n", authResp.User.ID)
	}
}

// SimpleCustomProvider is an example of a simple custom authentication provider
type SimpleCustomProvider struct {
	*auth.BaseCustomAuthProvider
	validTokens map[string]string // token -> userID mapping
}

// Authenticate validates a simple token and returns a user
func (p *SimpleCustomProvider) Authenticate(ctx context.Context, credentials map[string]interface{}) (*auth.User, error) {
	token, ok := credentials["token"].(string)
	if !ok || token == "" {
		return nil, fmt.Errorf("token is required")
	}

	userID, exists := p.validTokens[token]
	if !exists {
		return nil, fmt.Errorf("invalid token")
	}

	// Create user object
	user := &auth.User{
		ID:            userID,
		EmailVerified: true,
		PhoneVerified: false,
		Metadata: map[string]interface{}{
			"auth_provider": "simple",
			"token":         token,
		},
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	// Set user ID from credentials if provided
	if providedUserID, exists := credentials["user_id"].(string); exists {
		user.ID = providedUserID
	}

	return user, nil
}

// createMockAuthService creates a mock auth service for examples
func createMockAuthService() *auth.Service {
	// In real usage, you would use your actual database and configuration
	// This is just for demonstration purposes
	return &auth.Service{
		// Mock implementation - in real usage, initialize with proper dependencies
	}
}

// ExampleProviderConfiguration shows how to configure providers with different settings
func ExampleProviderConfiguration() {
	fmt.Println("\n=== Provider Configuration Examples ===")

	// LDAP with SSL
	ldapSSLConfig := &LDAPConfig{
		Host:          "secure-ldap.example.com",
		Port:          636,
		UseSSL:        true,
		SkipTLSVerify: false, // Verify SSL certificates
		// ... other config
	}
	fmt.Printf("LDAP SSL Config: %+v\n", ldapSSLConfig)

	// API Key with strict scopes
	strictAPIKeyConfig := &APIKeyConfig{
		KeyPrefix:     "strict_",
		KeyLength:     64, // Longer keys for better security
		AllowedScopes: []string{"read"},
		RequireScopes: true,            // Require scopes to be specified
		CacheTimeout:  1 * time.Minute, // Short cache timeout
	}
	fmt.Printf("Strict API Key Config: %+v\n", strictAPIKeyConfig)

	// GitHub social provider
	githubConfig := &SocialConfig{
		ProviderType:    SocialProviderGitHub,
		ClientID:        "your-github-client-id",
		ClientSecret:    "your-github-client-secret",
		RedirectURL:     "https://yourapp.com/auth/callback/github",
		Scopes:          []string{"user:email", "read:user"},
		AllowSignup:     false, // Don't allow new user registration
		RequireVerified: true,
	}
	fmt.Printf("GitHub Config: %+v\n", githubConfig)
}

package config

import (
	"fmt"

	"github.com/taqiudeen275/go-foward/internal/auth"
	"github.com/taqiudeen275/go-foward/internal/auth/providers"
)

// InitializeCustomAuthProviders initializes and registers custom auth providers based on configuration
func InitializeCustomAuthProviders(authService *auth.Service, config *Config) error {
	customConfig := config.Auth.CustomProviders

	// Initialize LDAP provider if enabled
	if customConfig.LDAP.Enabled {
		ldapConfig := &providers.LDAPConfig{
			Host:              customConfig.LDAP.Host,
			Port:              customConfig.LDAP.Port,
			UseSSL:            customConfig.LDAP.UseSSL,
			SkipTLSVerify:     customConfig.LDAP.SkipTLSVerify,
			BindDN:            customConfig.LDAP.BindDN,
			BindPassword:      customConfig.LDAP.BindPassword,
			BaseDN:            customConfig.LDAP.BaseDN,
			UserFilter:        customConfig.LDAP.UserFilter,
			EmailAttribute:    customConfig.LDAP.EmailAttribute,
			NameAttribute:     customConfig.LDAP.NameAttribute,
			UsernameAttribute: customConfig.LDAP.UsernameAttribute,
			ConnectionTimeout: customConfig.LDAP.ConnectionTimeout,
			RequestTimeout:    customConfig.LDAP.RequestTimeout,
		}

		ldapProvider := providers.NewLDAPAuthProvider(ldapConfig)
		if err := authService.RegisterCustomAuthProvider(ldapProvider); err != nil {
			return fmt.Errorf("failed to register LDAP provider: %w", err)
		}
	}

	// Initialize API Key provider if enabled
	if customConfig.APIKey.Enabled {
		apiKeyConfig := &providers.APIKeyConfig{
			KeyPrefix:     customConfig.APIKey.KeyPrefix,
			KeyLength:     customConfig.APIKey.KeyLength,
			HashAlgorithm: customConfig.APIKey.HashAlgorithm,
			CacheTimeout:  customConfig.APIKey.CacheTimeout,
			AllowedScopes: customConfig.APIKey.AllowedScopes,
			RequireScopes: customConfig.APIKey.RequireScopes,
		}

		// Use in-memory store for now - in production, you might want to use a database store
		apiKeyStore := providers.NewInMemoryAPIKeyStore()
		apiKeyProvider := providers.NewAPIKeyAuthProvider(apiKeyConfig, apiKeyStore)
		if err := authService.RegisterCustomAuthProvider(apiKeyProvider); err != nil {
			return fmt.Errorf("failed to register API Key provider: %w", err)
		}
	}

	// Initialize social providers
	socialConfig := customConfig.Social

	// Google OAuth
	if socialConfig.Google.Enabled {
		googleConfig := &providers.SocialConfig{
			ProviderType:    providers.SocialProviderGoogle,
			ClientID:        socialConfig.Google.ClientID,
			ClientSecret:    socialConfig.Google.ClientSecret,
			RedirectURL:     socialConfig.Google.RedirectURL,
			Scopes:          socialConfig.Google.Scopes,
			AuthURL:         socialConfig.Google.AuthURL,
			TokenURL:        socialConfig.Google.TokenURL,
			UserInfoURL:     socialConfig.Google.UserInfoURL,
			RequestTimeout:  socialConfig.Google.RequestTimeout,
			AllowSignup:     socialConfig.Google.AllowSignup,
			RequireVerified: socialConfig.Google.RequireVerified,
		}

		googleProvider := providers.NewSocialAuthProvider(googleConfig)
		if err := authService.RegisterCustomAuthProvider(googleProvider); err != nil {
			return fmt.Errorf("failed to register Google OAuth provider: %w", err)
		}
	}

	// GitHub OAuth
	if socialConfig.GitHub.Enabled {
		githubConfig := &providers.SocialConfig{
			ProviderType:    providers.SocialProviderGitHub,
			ClientID:        socialConfig.GitHub.ClientID,
			ClientSecret:    socialConfig.GitHub.ClientSecret,
			RedirectURL:     socialConfig.GitHub.RedirectURL,
			Scopes:          socialConfig.GitHub.Scopes,
			AuthURL:         socialConfig.GitHub.AuthURL,
			TokenURL:        socialConfig.GitHub.TokenURL,
			UserInfoURL:     socialConfig.GitHub.UserInfoURL,
			RequestTimeout:  socialConfig.GitHub.RequestTimeout,
			AllowSignup:     socialConfig.GitHub.AllowSignup,
			RequireVerified: socialConfig.GitHub.RequireVerified,
		}

		githubProvider := providers.NewSocialAuthProvider(githubConfig)
		if err := authService.RegisterCustomAuthProvider(githubProvider); err != nil {
			return fmt.Errorf("failed to register GitHub OAuth provider: %w", err)
		}
	}

	// Facebook OAuth
	if socialConfig.Facebook.Enabled {
		facebookConfig := &providers.SocialConfig{
			ProviderType:    providers.SocialProviderFacebook,
			ClientID:        socialConfig.Facebook.ClientID,
			ClientSecret:    socialConfig.Facebook.ClientSecret,
			RedirectURL:     socialConfig.Facebook.RedirectURL,
			Scopes:          socialConfig.Facebook.Scopes,
			AuthURL:         socialConfig.Facebook.AuthURL,
			TokenURL:        socialConfig.Facebook.TokenURL,
			UserInfoURL:     socialConfig.Facebook.UserInfoURL,
			RequestTimeout:  socialConfig.Facebook.RequestTimeout,
			AllowSignup:     socialConfig.Facebook.AllowSignup,
			RequireVerified: socialConfig.Facebook.RequireVerified,
		}

		facebookProvider := providers.NewSocialAuthProvider(facebookConfig)
		if err := authService.RegisterCustomAuthProvider(facebookProvider); err != nil {
			return fmt.Errorf("failed to register Facebook OAuth provider: %w", err)
		}
	}

	// Twitter OAuth
	if socialConfig.Twitter.Enabled {
		twitterConfig := &providers.SocialConfig{
			ProviderType:    providers.SocialProviderTwitter,
			ClientID:        socialConfig.Twitter.ClientID,
			ClientSecret:    socialConfig.Twitter.ClientSecret,
			RedirectURL:     socialConfig.Twitter.RedirectURL,
			Scopes:          socialConfig.Twitter.Scopes,
			RequestTimeout:  socialConfig.Twitter.RequestTimeout,
			AllowSignup:     socialConfig.Twitter.AllowSignup,
			RequireVerified: socialConfig.Twitter.RequireVerified,
		}

		twitterProvider := providers.NewSocialAuthProvider(twitterConfig)
		if err := authService.RegisterCustomAuthProvider(twitterProvider); err != nil {
			return fmt.Errorf("failed to register Twitter OAuth provider: %w", err)
		}
	}

	// LinkedIn OAuth
	if socialConfig.LinkedIn.Enabled {
		linkedinConfig := &providers.SocialConfig{
			ProviderType:    providers.SocialProviderLinkedIn,
			ClientID:        socialConfig.LinkedIn.ClientID,
			ClientSecret:    socialConfig.LinkedIn.ClientSecret,
			RedirectURL:     socialConfig.LinkedIn.RedirectURL,
			Scopes:          socialConfig.LinkedIn.Scopes,
			RequestTimeout:  socialConfig.LinkedIn.RequestTimeout,
			AllowSignup:     socialConfig.LinkedIn.AllowSignup,
			RequireVerified: socialConfig.LinkedIn.RequireVerified,
		}

		linkedinProvider := providers.NewSocialAuthProvider(linkedinConfig)
		if err := authService.RegisterCustomAuthProvider(linkedinProvider); err != nil {
			return fmt.Errorf("failed to register LinkedIn OAuth provider: %w", err)
		}
	}

	return nil
}

// GetCustomAuthProviderConfig returns the custom auth provider configuration
func GetCustomAuthProviderConfig(config *Config) *CustomAuthProvidersConfig {
	return &config.Auth.CustomProviders
}

// ValidateCustomAuthProviders validates custom auth provider configurations
func ValidateCustomAuthProviders(config *CustomAuthProvidersConfig) error {
	// Validate LDAP configuration
	if config.LDAP.Enabled {
		if config.LDAP.Host == "" {
			return fmt.Errorf("LDAP host is required when LDAP is enabled")
		}
		if config.LDAP.Port <= 0 || config.LDAP.Port > 65535 {
			return fmt.Errorf("invalid LDAP port: %d", config.LDAP.Port)
		}
		if config.LDAP.BaseDN == "" {
			return fmt.Errorf("LDAP base DN is required when LDAP is enabled")
		}
		if config.LDAP.UserFilter == "" {
			return fmt.Errorf("LDAP user filter is required when LDAP is enabled")
		}
	}

	// Validate API Key configuration
	if config.APIKey.Enabled {
		if config.APIKey.KeyPrefix == "" {
			return fmt.Errorf("API key prefix is required when API key auth is enabled")
		}
		if config.APIKey.KeyLength < 16 {
			return fmt.Errorf("API key length must be at least 16 characters")
		}
		if config.APIKey.HashAlgorithm == "" {
			return fmt.Errorf("API key hash algorithm is required when API key auth is enabled")
		}
	}

	// Validate social provider configurations
	socialProviders := []struct {
		name     string
		enabled  bool
		clientID string
		secret   string
		redirect string
	}{
		{"Google", config.Social.Google.Enabled, config.Social.Google.ClientID, config.Social.Google.ClientSecret, config.Social.Google.RedirectURL},
		{"GitHub", config.Social.GitHub.Enabled, config.Social.GitHub.ClientID, config.Social.GitHub.ClientSecret, config.Social.GitHub.RedirectURL},
		{"Facebook", config.Social.Facebook.Enabled, config.Social.Facebook.ClientID, config.Social.Facebook.ClientSecret, config.Social.Facebook.RedirectURL},
		{"Twitter", config.Social.Twitter.Enabled, config.Social.Twitter.ClientID, config.Social.Twitter.ClientSecret, config.Social.Twitter.RedirectURL},
		{"LinkedIn", config.Social.LinkedIn.Enabled, config.Social.LinkedIn.ClientID, config.Social.LinkedIn.ClientSecret, config.Social.LinkedIn.RedirectURL},
	}

	for _, provider := range socialProviders {
		if provider.enabled {
			if provider.clientID == "" {
				return fmt.Errorf("%s OAuth client ID is required when %s OAuth is enabled", provider.name, provider.name)
			}
			if provider.secret == "" {
				return fmt.Errorf("%s OAuth client secret is required when %s OAuth is enabled", provider.name, provider.name)
			}
			if provider.redirect == "" {
				return fmt.Errorf("%s OAuth redirect URL is required when %s OAuth is enabled", provider.name, provider.name)
			}
		}
	}

	return nil
}

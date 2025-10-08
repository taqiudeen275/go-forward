package providers

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/taqiudeen275/go-foward/internal/auth"
)

// SocialProviderType represents different social login providers
type SocialProviderType string

const (
	SocialProviderGoogle   SocialProviderType = "google"
	SocialProviderGitHub   SocialProviderType = "github"
	SocialProviderFacebook SocialProviderType = "facebook"
	SocialProviderTwitter  SocialProviderType = "twitter"
	SocialProviderLinkedIn SocialProviderType = "linkedin"
)

// SocialConfig represents social login configuration
type SocialConfig struct {
	ProviderType    SocialProviderType `json:"provider_type" yaml:"provider_type"`
	ClientID        string             `json:"client_id" yaml:"client_id"`
	ClientSecret    string             `json:"client_secret" yaml:"client_secret"`
	RedirectURL     string             `json:"redirect_url" yaml:"redirect_url"`
	Scopes          []string           `json:"scopes" yaml:"scopes"`
	AuthURL         string             `json:"auth_url" yaml:"auth_url"`
	TokenURL        string             `json:"token_url" yaml:"token_url"`
	UserInfoURL     string             `json:"user_info_url" yaml:"user_info_url"`
	RequestTimeout  time.Duration      `json:"request_timeout" yaml:"request_timeout"`
	AllowSignup     bool               `json:"allow_signup" yaml:"allow_signup"`
	RequireVerified bool               `json:"require_verified" yaml:"require_verified"`
}

// SocialUserInfo represents user information from social provider
type SocialUserInfo struct {
	ID            string                 `json:"id"`
	Email         string                 `json:"email"`
	Name          string                 `json:"name"`
	Username      string                 `json:"username"`
	AvatarURL     string                 `json:"avatar_url"`
	EmailVerified bool                   `json:"email_verified"`
	Locale        string                 `json:"locale"`
	Provider      SocialProviderType     `json:"provider"`
	RawData       map[string]interface{} `json:"raw_data"`
}

// TokenResponse represents OAuth token response
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
	Scope        string `json:"scope"`
}

// SocialAuthProvider implements social login authentication
type SocialAuthProvider struct {
	*auth.BaseCustomAuthProvider
	config     *SocialConfig
	httpClient *http.Client
}

// NewSocialAuthProvider creates a new social authentication provider
func NewSocialAuthProvider(config *SocialConfig) *SocialAuthProvider {
	if config == nil {
		config = &SocialConfig{
			ProviderType:    SocialProviderGoogle,
			Scopes:          []string{"openid", "email", "profile"},
			RequestTimeout:  30 * time.Second,
			AllowSignup:     true,
			RequireVerified: true,
		}
	}

	// Set default URLs based on provider type
	if config.AuthURL == "" || config.TokenURL == "" || config.UserInfoURL == "" {
		setDefaultURLs(config)
	}

	required := []string{"code", "state"}
	optional := []string{"redirect_uri"}

	provider := &SocialAuthProvider{
		BaseCustomAuthProvider: auth.NewBaseCustomAuthProvider(string(config.ProviderType), required, optional),
		config:                 config,
		httpClient: &http.Client{
			Timeout: config.RequestTimeout,
		},
	}

	return provider
}

// Authenticate validates social login credentials and returns a user
func (p *SocialAuthProvider) Authenticate(ctx context.Context, credentials map[string]interface{}) (*auth.User, error) {
	// Extract authorization code
	code, ok := credentials["code"].(string)
	if !ok || code == "" {
		return nil, fmt.Errorf("authorization code is required")
	}

	// Extract state for CSRF protection
	state, ok := credentials["state"].(string)
	if !ok || state == "" {
		return nil, fmt.Errorf("state parameter is required for CSRF protection")
	}

	// Optional redirect URI override
	redirectURI := p.config.RedirectURL
	if uri, exists := credentials["redirect_uri"].(string); exists && uri != "" {
		redirectURI = uri
	}

	// Exchange authorization code for access token
	tokenResp, err := p.exchangeCodeForToken(ctx, code, redirectURI)
	if err != nil {
		return nil, fmt.Errorf("failed to exchange code for token: %w", err)
	}

	// Get user information using access token
	userInfo, err := p.getUserInfo(ctx, tokenResp.AccessToken)
	if err != nil {
		return nil, fmt.Errorf("failed to get user info: %w", err)
	}

	// Validate user information
	if err := p.validateUserInfo(userInfo); err != nil {
		return nil, fmt.Errorf("user validation failed: %w", err)
	}

	// Create user object
	user := p.createUserFromSocialInfo(userInfo, tokenResp)

	return user, nil
}

// ValidateCredentials validates social login credential format
func (p *SocialAuthProvider) ValidateCredentials(credentials map[string]interface{}) error {
	// First call base validation
	if err := p.BaseCustomAuthProvider.ValidateCredentials(credentials); err != nil {
		return err
	}

	// Additional social-specific validation
	code, ok := credentials["code"].(string)
	if !ok {
		return fmt.Errorf("code must be a string")
	}

	state, ok := credentials["state"].(string)
	if !ok {
		return fmt.Errorf("state must be a string")
	}

	if len(code) == 0 {
		return fmt.Errorf("authorization code cannot be empty")
	}

	if len(state) == 0 {
		return fmt.Errorf("state cannot be empty")
	}

	// Validate redirect URI if provided
	if redirectURI, exists := credentials["redirect_uri"]; exists {
		if uri, ok := redirectURI.(string); ok {
			if _, err := url.Parse(uri); err != nil {
				return fmt.Errorf("invalid redirect URI format: %w", err)
			}
		} else {
			return fmt.Errorf("redirect_uri must be a string")
		}
	}

	return nil
}

// GetAuthURL generates the authorization URL for social login
func (p *SocialAuthProvider) GetAuthURL(state string, additionalParams map[string]string) string {
	params := url.Values{}
	params.Set("client_id", p.config.ClientID)
	params.Set("redirect_uri", p.config.RedirectURL)
	params.Set("response_type", "code")
	params.Set("scope", strings.Join(p.config.Scopes, " "))
	params.Set("state", state)

	// Add provider-specific parameters
	switch p.config.ProviderType {
	case SocialProviderGoogle:
		params.Set("access_type", "offline")
		params.Set("prompt", "consent")
	case SocialProviderGitHub:
		params.Set("allow_signup", fmt.Sprintf("%t", p.config.AllowSignup))
	}

	// Add additional parameters
	for key, value := range additionalParams {
		params.Set(key, value)
	}

	return p.config.AuthURL + "?" + params.Encode()
}

// exchangeCodeForToken exchanges authorization code for access token
func (p *SocialAuthProvider) exchangeCodeForToken(ctx context.Context, code, redirectURI string) (*TokenResponse, error) {
	data := url.Values{}
	data.Set("client_id", p.config.ClientID)
	data.Set("client_secret", p.config.ClientSecret)
	data.Set("code", code)
	data.Set("grant_type", "authorization_code")
	data.Set("redirect_uri", redirectURI)

	req, err := http.NewRequestWithContext(ctx, "POST", p.config.TokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("token exchange failed with status %d: %s", resp.StatusCode, string(body))
	}

	var tokenResp TokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return nil, fmt.Errorf("failed to decode token response: %w", err)
	}

	return &tokenResp, nil
}

// getUserInfo retrieves user information using access token
func (p *SocialAuthProvider) getUserInfo(ctx context.Context, accessToken string) (*SocialUserInfo, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", p.config.UserInfoURL, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/json")

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("user info request failed with status %d: %s", resp.StatusCode, string(body))
	}

	var rawData map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&rawData); err != nil {
		return nil, fmt.Errorf("failed to decode user info response: %w", err)
	}

	// Parse user info based on provider
	userInfo := p.parseUserInfo(rawData)
	userInfo.Provider = p.config.ProviderType
	userInfo.RawData = rawData

	return userInfo, nil
}

// parseUserInfo parses user information based on provider format
func (p *SocialAuthProvider) parseUserInfo(rawData map[string]interface{}) *SocialUserInfo {
	userInfo := &SocialUserInfo{}

	switch p.config.ProviderType {
	case SocialProviderGoogle:
		userInfo.ID = getStringValue(rawData, "sub")
		userInfo.Email = getStringValue(rawData, "email")
		userInfo.Name = getStringValue(rawData, "name")
		userInfo.Username = getStringValue(rawData, "preferred_username")
		userInfo.AvatarURL = getStringValue(rawData, "picture")
		userInfo.EmailVerified = getBoolValue(rawData, "email_verified")
		userInfo.Locale = getStringValue(rawData, "locale")

	case SocialProviderGitHub:
		userInfo.ID = fmt.Sprintf("%.0f", getFloatValue(rawData, "id"))
		userInfo.Email = getStringValue(rawData, "email")
		userInfo.Name = getStringValue(rawData, "name")
		userInfo.Username = getStringValue(rawData, "login")
		userInfo.AvatarURL = getStringValue(rawData, "avatar_url")
		userInfo.EmailVerified = true // GitHub emails are considered verified
		userInfo.Locale = getStringValue(rawData, "location")

	case SocialProviderFacebook:
		userInfo.ID = getStringValue(rawData, "id")
		userInfo.Email = getStringValue(rawData, "email")
		userInfo.Name = getStringValue(rawData, "name")
		userInfo.Username = getStringValue(rawData, "username")
		if picture := getMapValue(rawData, "picture"); picture != nil {
			if data := getMapValue(picture, "data"); data != nil {
				userInfo.AvatarURL = getStringValue(data, "url")
			}
		}
		userInfo.EmailVerified = true // Facebook emails are considered verified
		userInfo.Locale = getStringValue(rawData, "locale")

	default:
		// Generic parsing
		userInfo.ID = getStringValue(rawData, "id")
		userInfo.Email = getStringValue(rawData, "email")
		userInfo.Name = getStringValue(rawData, "name")
		userInfo.Username = getStringValue(rawData, "username")
		userInfo.AvatarURL = getStringValue(rawData, "avatar_url")
		userInfo.EmailVerified = getBoolValue(rawData, "email_verified")
		userInfo.Locale = getStringValue(rawData, "locale")
	}

	return userInfo
}

// validateUserInfo validates the retrieved user information
func (p *SocialAuthProvider) validateUserInfo(userInfo *SocialUserInfo) error {
	if userInfo.ID == "" {
		return fmt.Errorf("user ID is required")
	}

	if userInfo.Email == "" {
		return fmt.Errorf("email is required")
	}

	if p.config.RequireVerified && !userInfo.EmailVerified {
		return fmt.Errorf("email must be verified")
	}

	return nil
}

// createUserFromSocialInfo creates a user object from social provider information
func (p *SocialAuthProvider) createUserFromSocialInfo(userInfo *SocialUserInfo, tokenResp *TokenResponse) *auth.User {
	user := &auth.User{
		ID:            uuid.New().String(),
		Email:         &userInfo.Email,
		EmailVerified: userInfo.EmailVerified,
		PhoneVerified: false,
		Metadata:      make(map[string]interface{}),
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
	}

	if userInfo.Username != "" {
		user.Username = &userInfo.Username
	}

	// Add social provider metadata
	user.Metadata["auth_provider"] = "social"
	user.Metadata["social_provider"] = string(userInfo.Provider)
	user.Metadata["social_id"] = userInfo.ID
	user.Metadata["social_name"] = userInfo.Name
	user.Metadata["social_avatar_url"] = userInfo.AvatarURL
	user.Metadata["social_locale"] = userInfo.Locale
	user.Metadata["social_access_token"] = tokenResp.AccessToken
	if tokenResp.RefreshToken != "" {
		user.Metadata["social_refresh_token"] = tokenResp.RefreshToken
	}
	if tokenResp.ExpiresIn > 0 {
		expiresAt := time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second)
		user.Metadata["social_token_expires_at"] = expiresAt
	}

	// Store raw social data for reference
	user.Metadata["social_raw_data"] = userInfo.RawData

	return user
}

// Helper functions for parsing social provider responses
func getStringValue(data map[string]interface{}, key string) string {
	if value, exists := data[key]; exists {
		if str, ok := value.(string); ok {
			return str
		}
	}
	return ""
}

func getBoolValue(data map[string]interface{}, key string) bool {
	if value, exists := data[key]; exists {
		if b, ok := value.(bool); ok {
			return b
		}
	}
	return false
}

func getFloatValue(data map[string]interface{}, key string) float64 {
	if value, exists := data[key]; exists {
		if f, ok := value.(float64); ok {
			return f
		}
	}
	return 0
}

func getMapValue(data map[string]interface{}, key string) map[string]interface{} {
	if value, exists := data[key]; exists {
		if m, ok := value.(map[string]interface{}); ok {
			return m
		}
	}
	return nil
}

// setDefaultURLs sets default OAuth URLs based on provider type
func setDefaultURLs(config *SocialConfig) {
	switch config.ProviderType {
	case SocialProviderGoogle:
		if config.AuthURL == "" {
			config.AuthURL = "https://accounts.google.com/o/oauth2/v2/auth"
		}
		if config.TokenURL == "" {
			config.TokenURL = "https://oauth2.googleapis.com/token"
		}
		if config.UserInfoURL == "" {
			config.UserInfoURL = "https://openidconnect.googleapis.com/v1/userinfo"
		}

	case SocialProviderGitHub:
		if config.AuthURL == "" {
			config.AuthURL = "https://github.com/login/oauth/authorize"
		}
		if config.TokenURL == "" {
			config.TokenURL = "https://github.com/login/oauth/access_token"
		}
		if config.UserInfoURL == "" {
			config.UserInfoURL = "https://api.github.com/user"
		}

	case SocialProviderFacebook:
		if config.AuthURL == "" {
			config.AuthURL = "https://www.facebook.com/v18.0/dialog/oauth"
		}
		if config.TokenURL == "" {
			config.TokenURL = "https://graph.facebook.com/v18.0/oauth/access_token"
		}
		if config.UserInfoURL == "" {
			config.UserInfoURL = "https://graph.facebook.com/v18.0/me?fields=id,name,email,picture"
		}
	}
}

// UpdateConfig updates the social provider configuration
func (p *SocialAuthProvider) UpdateConfig(config *SocialConfig) {
	p.config = config
	p.httpClient.Timeout = config.RequestTimeout
}

// GetConfig returns the current social provider configuration (without sensitive data)
func (p *SocialAuthProvider) GetConfig() map[string]interface{} {
	return map[string]interface{}{
		"provider_type":    string(p.config.ProviderType),
		"redirect_url":     p.config.RedirectURL,
		"scopes":           p.config.Scopes,
		"auth_url":         p.config.AuthURL,
		"token_url":        p.config.TokenURL,
		"user_info_url":    p.config.UserInfoURL,
		"request_timeout":  p.config.RequestTimeout.String(),
		"allow_signup":     p.config.AllowSignup,
		"require_verified": p.config.RequireVerified,
		// Note: client_id and client_secret are not included for security
	}
}

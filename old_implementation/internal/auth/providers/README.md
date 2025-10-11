# Custom Authentication Providers

This package provides example implementations of custom authentication providers for the Go Forward framework. These providers demonstrate how to extend the authentication system with different authentication methods.

## Available Providers

### 1. LDAP Authentication Provider

The LDAP provider allows authentication against LDAP/Active Directory servers.

**Features:**
- SSL/TLS support
- Configurable user search filters
- Attribute mapping for user information
- Connection pooling and timeouts

**Required Credentials:**
- `username`: LDAP username
- `password`: User password

**Optional Credentials:**
- `domain`: Domain for username (will be appended as `username@domain`)

**Configuration:**
```go
ldapConfig := &LDAPConfig{
    Host:               "ldap.example.com",
    Port:               389,
    UseSSL:             false,
    BindDN:             "cn=admin,dc=example,dc=com",
    BindPassword:       "admin_password",
    BaseDN:             "ou=users,dc=example,dc=com",
    UserFilter:         "(uid=%s)",
    EmailAttribute:     "mail",
    NameAttribute:      "cn",
    UsernameAttribute:  "uid",
    ConnectionTimeout:  10 * time.Second,
    RequestTimeout:     30 * time.Second,
}

provider := NewLDAPAuthProvider(ldapConfig)
```

### 2. API Key Authentication Provider

The API key provider enables authentication using API keys with scope-based permissions.

**Features:**
- Configurable key prefixes and lengths
- Scope-based access control
- Key expiration support
- In-memory or database storage
- Secure key hashing

**Required Credentials:**
- `api_key`: The API key string

**Optional Credentials:**
- `scopes`: Array of requested scopes

**Configuration:**
```go
apiKeyConfig := &APIKeyConfig{
    KeyPrefix:      "gf_",
    KeyLength:      32,
    HashAlgorithm:  "sha256",
    CacheTimeout:   5 * time.Minute,
    AllowedScopes:  []string{"read", "write", "admin"},
    RequireScopes:  false,
}

store := NewInMemoryAPIKeyStore()
provider := NewAPIKeyAuthProvider(apiKeyConfig, store)
```

### 3. Social Login Provider

The social login provider supports OAuth2-based authentication with popular social platforms.

**Supported Providers:**
- Google
- GitHub
- Facebook
- Twitter
- LinkedIn

**Features:**
- OAuth2 authorization code flow
- Configurable scopes
- User information retrieval
- Token management
- CSRF protection with state parameter

**Required Credentials:**
- `code`: OAuth authorization code
- `state`: CSRF protection state parameter

**Optional Credentials:**
- `redirect_uri`: Override redirect URI

**Configuration:**
```go
googleConfig := &SocialConfig{
    ProviderType:     SocialProviderGoogle,
    ClientID:         "your-google-client-id",
    ClientSecret:     "your-google-client-secret",
    RedirectURL:      "https://yourapp.com/auth/callback/google",
    Scopes:           []string{"openid", "email", "profile"},
    RequestTimeout:   30 * time.Second,
    AllowSignup:      true,
    RequireVerified:  true,
}

provider := NewSocialAuthProvider(googleConfig)
```

## Usage Examples

### Registering Providers

```go
// Create auth service
authService := auth.NewService(db)

// Register LDAP provider
ldapProvider := NewLDAPAuthProvider(ldapConfig)
err := authService.RegisterCustomAuthProvider(ldapProvider)

// Register API key provider
apiKeyProvider := NewAPIKeyAuthProvider(apiKeyConfig, apiKeyStore)
err = authService.RegisterCustomAuthProvider(apiKeyProvider)

// Register social provider
googleProvider := NewSocialAuthProvider(googleConfig)
err = authService.RegisterCustomAuthProvider(googleProvider)
```

### Authentication

```go
// LDAP authentication
ldapReq := &auth.CustomAuthRequest{
    Provider: "ldap",
    Credentials: map[string]interface{}{
        "username": "john.doe",
        "password": "secret123",
    },
}
authResp, err := authService.AuthenticateWithCustomProvider(ctx, ldapReq)

// API key authentication
apiKeyReq := &auth.CustomAuthRequest{
    Provider: "api_key",
    Credentials: map[string]interface{}{
        "api_key": "gf_abcd1234...",
        "scopes":  []string{"read"},
    },
}
authResp, err = authService.AuthenticateWithCustomProvider(ctx, apiKeyReq)

// Social login authentication
socialReq := &auth.CustomAuthRequest{
    Provider: "google",
    Credentials: map[string]interface{}{
        "code":  "oauth_authorization_code",
        "state": "csrf_state_token",
    },
}
authResp, err = authService.AuthenticateWithCustomProvider(ctx, socialReq)
```

### Managing Providers

```go
// List all providers
providers := authService.ListCustomAuthProviders()

// Get provider information
info, err := authService.GetCustomAuthProviderInfo("ldap")

// Enable/disable provider
provider, err := authService.GetCustomAuthProvider("ldap")
provider.SetEnabled(false)

// Validate credentials without authentication
err = authService.ValidateCustomAuthCredentials("api_key", credentials)
```

## Creating Custom Providers

To create your own custom authentication provider, implement the `CustomAuthProvider` interface:

```go
type MyCustomProvider struct {
    *auth.BaseCustomAuthProvider
    // Your custom fields
}

func NewMyCustomProvider() *MyCustomProvider {
    required := []string{"my_field"}
    optional := []string{"optional_field"}
    
    return &MyCustomProvider{
        BaseCustomAuthProvider: auth.NewBaseCustomAuthProvider("my_provider", required, optional),
    }
}

func (p *MyCustomProvider) Authenticate(ctx context.Context, credentials map[string]interface{}) (*auth.User, error) {
    // Your authentication logic here
    // Return a *auth.User on success
}
```

## Security Considerations

### LDAP Provider
- Use SSL/TLS for production deployments
- Implement proper certificate validation
- Use service accounts with minimal privileges
- Implement connection timeouts

### API Key Provider
- Use strong, cryptographically secure random keys
- Hash keys before storage
- Implement key rotation policies
- Use scopes to limit access
- Monitor key usage

### Social Login Provider
- Validate state parameters to prevent CSRF attacks
- Use HTTPS for redirect URIs
- Implement proper token validation
- Store tokens securely
- Respect provider rate limits

## Dependencies

The providers require the following external dependencies:

- LDAP Provider: `github.com/go-ldap/ldap/v3`
- All providers: `github.com/google/uuid`

Install dependencies:
```bash
go get github.com/go-ldap/ldap/v3
go get github.com/google/uuid
```

## Testing

See `examples.go` for comprehensive usage examples and test scenarios.

## Contributing

When adding new providers:

1. Implement the `CustomAuthProvider` interface
2. Extend `BaseCustomAuthProvider` for common functionality
3. Add comprehensive validation
4. Include configuration options
5. Add usage examples
6. Document security considerations
7. Add appropriate tests
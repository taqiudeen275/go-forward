# Custom Authentication Configuration

This document explains how to configure custom authentication providers in the Go Forward framework using the configuration file and environment variables.

## Configuration File

Custom authentication providers are configured in the `auth.custom_providers` section of your `config.yaml` file.

### LDAP Authentication

Configure LDAP authentication to authenticate users against an LDAP/Active Directory server:

```yaml
auth:
  custom_providers:
    ldap:
      enabled: true
      host: "ldap.company.com"
      port: 389
      use_ssl: false
      skip_tls_verify: false
      bind_dn: "cn=service,dc=company,dc=com"
      bind_password: "service_password"
      base_dn: "ou=users,dc=company,dc=com"
      user_filter: "(uid=%s)"
      email_attribute: "mail"
      name_attribute: "cn"
      username_attribute: "uid"
      connection_timeout: "10s"
      request_timeout: "30s"
```

**Configuration Options:**
- `enabled`: Enable/disable LDAP authentication
- `host`: LDAP server hostname
- `port`: LDAP server port (389 for LDAP, 636 for LDAPS)
- `use_ssl`: Use SSL/TLS connection
- `skip_tls_verify`: Skip TLS certificate verification (not recommended for production)
- `bind_dn`: Service account DN for binding
- `bind_password`: Service account password
- `base_dn`: Base DN for user searches
- `user_filter`: LDAP filter for finding users (use %s as placeholder for username)
- `email_attribute`: LDAP attribute containing user's email
- `name_attribute`: LDAP attribute containing user's full name
- `username_attribute`: LDAP attribute containing username
- `connection_timeout`: Connection timeout
- `request_timeout`: Request timeout

### API Key Authentication

Configure API key authentication for programmatic access:

```yaml
auth:
  custom_providers:
    api_key:
      enabled: true
      key_prefix: "myapp_"
      key_length: 32
      hash_algorithm: "sha256"
      cache_timeout: "5m"
      allowed_scopes: ["read", "write", "admin"]
      require_scopes: false
```

**Configuration Options:**
- `enabled`: Enable/disable API key authentication
- `key_prefix`: Prefix for generated API keys
- `key_length`: Length of the random part of the key
- `hash_algorithm`: Algorithm for hashing keys (sha256)
- `cache_timeout`: How long to cache validated keys
- `allowed_scopes`: List of allowed scopes for API keys
- `require_scopes`: Whether scopes are required for authentication

### Social Authentication

Configure OAuth providers for social login:

#### Google OAuth

```yaml
auth:
  custom_providers:
    social:
      google:
        enabled: true
        client_id: "your-google-client-id"
        client_secret: "your-google-client-secret"
        redirect_url: "https://yourapp.com/auth/callback/google"
        scopes: ["openid", "email", "profile"]
        request_timeout: "30s"
        allow_signup: true
        require_verified: true
```

#### GitHub OAuth

```yaml
auth:
  custom_providers:
    social:
      github:
        enabled: true
        client_id: "your-github-client-id"
        client_secret: "your-github-client-secret"
        redirect_url: "https://yourapp.com/auth/callback/github"
        scopes: ["user:email", "read:user"]
        request_timeout: "30s"
        allow_signup: true
        require_verified: true
```

#### Facebook OAuth

```yaml
auth:
  custom_providers:
    social:
      facebook:
        enabled: true
        client_id: "your-facebook-app-id"
        client_secret: "your-facebook-app-secret"
        redirect_url: "https://yourapp.com/auth/callback/facebook"
        scopes: ["email", "public_profile"]
        request_timeout: "30s"
        allow_signup: true
        require_verified: true
```

**Social Provider Options:**
- `enabled`: Enable/disable the provider
- `client_id`: OAuth client ID from the provider
- `client_secret`: OAuth client secret from the provider
- `redirect_url`: Callback URL for OAuth flow
- `scopes`: OAuth scopes to request
- `request_timeout`: Timeout for OAuth requests
- `allow_signup`: Allow new user registration via this provider
- `require_verified`: Require email verification from the provider

## Environment Variables

You can override configuration values using environment variables:

### LDAP Configuration

```bash
LDAP_ENABLED=true
LDAP_HOST=ldap.company.com
LDAP_PORT=389
LDAP_BIND_DN="cn=service,dc=company,dc=com"
LDAP_BIND_PASSWORD=service_password
LDAP_BASE_DN="ou=users,dc=company,dc=com"
```

### API Key Configuration

```bash
API_KEY_ENABLED=true
API_KEY_PREFIX=myapp_
```

### Social Provider Configuration

```bash
# Google OAuth
GOOGLE_OAUTH_ENABLED=true
GOOGLE_CLIENT_ID=your-google-client-id
GOOGLE_CLIENT_SECRET=your-google-client-secret
GOOGLE_REDIRECT_URL=https://yourapp.com/auth/callback/google

# GitHub OAuth
GITHUB_OAUTH_ENABLED=true
GITHUB_CLIENT_ID=your-github-client-id
GITHUB_CLIENT_SECRET=your-github-client-secret
GITHUB_REDIRECT_URL=https://yourapp.com/auth/callback/github

# Facebook OAuth
FACEBOOK_OAUTH_ENABLED=true
FACEBOOK_CLIENT_ID=your-facebook-app-id
FACEBOOK_CLIENT_SECRET=your-facebook-app-secret
FACEBOOK_REDIRECT_URL=https://yourapp.com/auth/callback/facebook
```

## Initialization

The custom auth providers are automatically initialized when the application starts if they are enabled in the configuration. The initialization happens in your main application setup:

```go
package main

import (
    "log"
    "github.com/taqiudeen275/go-foward/internal/config"
    "github.com/taqiudeen275/go-foward/internal/auth"
    "github.com/taqiudeen275/go-foward/internal/database"
)

func main() {
    // Load configuration
    cfg, err := config.Load()
    if err != nil {
        log.Fatal("Failed to load config:", err)
    }

    // Initialize database
    db, err := database.New(&cfg.Database)
    if err != nil {
        log.Fatal("Failed to connect to database:", err)
    }

    // Initialize auth service
    authService := auth.NewServiceWithConfig(
        db, 
        cfg.Auth.JWTSecret, 
        cfg.Auth.JWTExpiration, 
        cfg.Auth.RefreshExpiration,
    )

    // Initialize custom auth providers from configuration
    if err := config.InitializeCustomAuthProviders(authService, cfg); err != nil {
        log.Fatal("Failed to initialize custom auth providers:", err)
    }

    // Continue with application setup...
}
```

## Usage Examples

### LDAP Authentication

```bash
curl -X POST http://localhost:8080/auth/custom \
  -H "Content-Type: application/json" \
  -d '{
    "provider": "ldap",
    "credentials": {
      "username": "john.doe",
      "password": "user_password",
      "domain": "company.com"
    }
  }'
```

### API Key Authentication

First, generate an API key (this would typically be done through an admin interface):

```go
// Generate API key for a user
apiKey, keyString, err := apiKeyProvider.GenerateAPIKey(
    ctx,
    "user-123",
    "My API Key",
    []string{"read", "write"},
    nil, // no expiration
)
```

Then use the API key:

```bash
curl -X POST http://localhost:8080/auth/custom \
  -H "Content-Type: application/json" \
  -d '{
    "provider": "api_key",
    "credentials": {
      "api_key": "myapp_abcd1234...",
      "scopes": ["read"]
    }
  }'
```

### Social Authentication

1. Redirect user to OAuth provider:
```bash
GET https://yourapp.com/auth/google
# This redirects to Google OAuth with proper parameters
```

2. Handle OAuth callback:
```bash
curl -X POST http://localhost:8080/auth/custom \
  -H "Content-Type: application/json" \
  -d '{
    "provider": "google",
    "credentials": {
      "code": "oauth_authorization_code",
      "state": "csrf_state_token"
    }
  }'
```

## Security Considerations

### LDAP
- Always use SSL/TLS in production (`use_ssl: true`)
- Use a dedicated service account with minimal privileges
- Validate TLS certificates (`skip_tls_verify: false`)
- Implement proper connection timeouts

### API Keys
- Use strong, cryptographically secure keys
- Implement key rotation policies
- Use scopes to limit access
- Monitor key usage and implement rate limiting
- Store keys securely (hashed)

### Social Providers
- Always validate state parameters to prevent CSRF attacks
- Use HTTPS for all redirect URLs
- Store OAuth tokens securely
- Implement proper token refresh logic
- Respect provider rate limits

## Troubleshooting

### LDAP Issues
- Check network connectivity to LDAP server
- Verify bind credentials
- Test LDAP queries manually using tools like `ldapsearch`
- Check firewall rules for LDAP ports

### API Key Issues
- Verify key format and prefix
- Check key expiration
- Validate scopes if required
- Monitor cache timeout settings

### Social Provider Issues
- Verify OAuth app configuration in provider console
- Check redirect URL matches exactly
- Validate client ID and secret
- Monitor OAuth rate limits
- Check network connectivity to OAuth endpoints

## Migration

When migrating from other authentication systems:

1. **From Basic Auth**: Gradually migrate users to API keys
2. **From LDAP**: Update LDAP configuration and test with a subset of users
3. **From Other OAuth**: Update OAuth app configurations and redirect URLs

Always test authentication flows thoroughly before deploying to production.
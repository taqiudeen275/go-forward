package config

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// Service manages system configuration with runtime updates
type Service struct {
	config *Config
	mutex  sync.RWMutex

	// Configuration update callbacks
	callbacks map[string][]func(*Config)
}

// NewService creates a new configuration service
func NewService(config *Config) *Service {
	return &Service{
		config:    config,
		callbacks: make(map[string][]func(*Config)),
	}
}

// GetConfig returns a copy of the current configuration
func (s *Service) GetConfig() *Config {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	// Return a deep copy to prevent external modification
	configCopy := *s.config
	return &configCopy
}

// UpdateConfig updates the configuration with the provided values
func (s *Service) UpdateConfig(ctx context.Context, updates map[string]interface{}) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	// Apply updates to configuration
	for key, value := range updates {
		if err := s.applyConfigUpdate(key, value); err != nil {
			return fmt.Errorf("failed to apply config update for key %s: %w", key, err)
		}
	}

	// Notify callbacks
	s.notifyCallbacks()

	return nil
}

// GetConfigValue retrieves a specific configuration value by key
func (s *Service) GetConfigValue(key string) (interface{}, error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	switch key {
	case "server.host":
		return s.config.Server.Host, nil
	case "server.port":
		return s.config.Server.Port, nil
	case "server.log_level":
		return s.config.Server.LogLevel, nil
	case "auth.jwt_secret":
		return s.config.Auth.JWTSecret, nil
	case "auth.access_token_expiry":
		return s.config.Auth.AccessTokenExpiry, nil
	case "auth.refresh_token_expiry":
		return s.config.Auth.RefreshTokenExpiry, nil
	case "auth.max_login_attempts":
		return s.config.Auth.MaxLoginAttempts, nil
	case "database.max_connections":
		return s.config.Database.MaxConns, nil
	case "database.max_idle_connections":
		return s.config.Database.MaxIdleConns, nil
	case "server.rate_limit.enabled":
		return s.config.Server.RateLimit.Enabled, nil
	case "server.rate_limit.requests_per_minute":
		return s.config.Server.RateLimit.RequestsPerMinute, nil
	case "server.cors.allowed_origins":
		return s.config.Server.CORS.AllowedOrigins, nil
	case "logging.level":
		return s.config.Logging.Level, nil
	case "logging.format":
		return s.config.Logging.Format, nil
	default:
		return nil, fmt.Errorf("unknown config key: %s", key)
	}
}

// SetConfigValue sets a specific configuration value by key
func (s *Service) SetConfigValue(ctx context.Context, key string, value interface{}) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if err := s.applyConfigUpdate(key, value); err != nil {
		return fmt.Errorf("failed to set config value for key %s: %w", key, err)
	}

	// Notify callbacks
	s.notifyCallbacks()

	return nil
}

// RegisterCallback registers a callback function to be called when configuration is updated
func (s *Service) RegisterCallback(name string, callback func(*Config)) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	s.callbacks[name] = append(s.callbacks[name], callback)
}

// UnregisterCallback removes a callback function
func (s *Service) UnregisterCallback(name string) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	delete(s.callbacks, name)
}

// GetDatabaseConfig returns the database configuration
func (s *Service) GetDatabaseConfig() DatabaseConfig {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	return s.config.Database
}

// GetAuthConfig returns the authentication configuration
func (s *Service) GetAuthConfig() AuthConfig {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	return s.config.Auth
}

// GetServerConfig returns the server configuration
func (s *Service) GetServerConfig() ServerConfig {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	return s.config.Server
}

// ValidateConfig validates the current configuration
func (s *Service) ValidateConfig() error {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	// Validate server configuration
	if s.config.Server.Port <= 0 || s.config.Server.Port > 65535 {
		return fmt.Errorf("invalid server port: %d", s.config.Server.Port)
	}

	// Validate database configuration
	if s.config.Database.Host == "" {
		return fmt.Errorf("database host cannot be empty")
	}

	if s.config.Database.Name == "" {
		return fmt.Errorf("database name cannot be empty")
	}

	if s.config.Database.User == "" {
		return fmt.Errorf("database user cannot be empty")
	}

	// Validate auth configuration
	if s.config.Auth.JWTSecret == "" {
		return fmt.Errorf("JWT secret cannot be empty")
	}

	if s.config.Auth.AccessTokenExpiry <= 0 {
		return fmt.Errorf("access token expiry must be positive")
	}

	if s.config.Auth.RefreshTokenExpiry <= 0 {
		return fmt.Errorf("refresh token expiry must be positive")
	}

	return nil
}

// ReloadConfig reloads configuration from file
func (s *Service) ReloadConfig(ctx context.Context, configPath string) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	// Load new configuration
	newConfig, err := LoadFromPath(configPath)
	if err != nil {
		return fmt.Errorf("failed to reload config: %w", err)
	}

	// Update current config
	s.config = newConfig

	// Notify callbacks
	s.notifyCallbacks()

	return nil
}

// applyConfigUpdate applies a single configuration update
func (s *Service) applyConfigUpdate(key string, value interface{}) error {
	switch key {
	case "server.host":
		if host, ok := value.(string); ok {
			s.config.Server.Host = host
		} else {
			return fmt.Errorf("invalid type for server.host: expected string")
		}
	case "server.port":
		if port, ok := value.(int); ok {
			if port <= 0 || port > 65535 {
				return fmt.Errorf("invalid port number: %d", port)
			}
			s.config.Server.Port = port
		} else {
			return fmt.Errorf("invalid type for server.port: expected int")
		}
	case "server.log_level":
		if logLevel, ok := value.(string); ok {
			s.config.Server.LogLevel = logLevel
		} else {
			return fmt.Errorf("invalid type for server.log_level: expected string")
		}
	case "auth.jwt_secret":
		if secret, ok := value.(string); ok {
			if len(secret) < 32 {
				return fmt.Errorf("JWT secret must be at least 32 characters long")
			}
			s.config.Auth.JWTSecret = secret
		} else {
			return fmt.Errorf("invalid type for auth.jwt_secret: expected string")
		}
	case "auth.access_token_expiry":
		if expiry, ok := value.(time.Duration); ok {
			s.config.Auth.AccessTokenExpiry = expiry
		} else if expiryStr, ok := value.(string); ok {
			expiry, err := time.ParseDuration(expiryStr)
			if err != nil {
				return fmt.Errorf("invalid duration format for auth.access_token_expiry: %w", err)
			}
			s.config.Auth.AccessTokenExpiry = expiry
		} else {
			return fmt.Errorf("invalid type for auth.access_token_expiry: expected duration or string")
		}
	case "auth.refresh_token_expiry":
		if expiry, ok := value.(time.Duration); ok {
			s.config.Auth.RefreshTokenExpiry = expiry
		} else if expiryStr, ok := value.(string); ok {
			expiry, err := time.ParseDuration(expiryStr)
			if err != nil {
				return fmt.Errorf("invalid duration format for auth.refresh_token_expiry: %w", err)
			}
			s.config.Auth.RefreshTokenExpiry = expiry
		} else {
			return fmt.Errorf("invalid type for auth.refresh_token_expiry: expected duration or string")
		}
	case "auth.max_login_attempts":
		if attempts, ok := value.(int); ok {
			if attempts <= 0 {
				return fmt.Errorf("max login attempts must be positive")
			}
			s.config.Auth.MaxLoginAttempts = attempts
		} else {
			return fmt.Errorf("invalid type for auth.max_login_attempts: expected int")
		}
	case "database.max_connections":
		if maxConns, ok := value.(int); ok {
			if maxConns <= 0 {
				return fmt.Errorf("max connections must be positive")
			}
			s.config.Database.MaxConns = maxConns
		} else {
			return fmt.Errorf("invalid type for database.max_connections: expected int")
		}
	case "database.max_idle_connections":
		if maxIdleConns, ok := value.(int); ok {
			if maxIdleConns < 0 {
				return fmt.Errorf("max idle connections cannot be negative")
			}
			s.config.Database.MaxIdleConns = maxIdleConns
		} else {
			return fmt.Errorf("invalid type for database.max_idle_connections: expected int")
		}
	case "server.rate_limit.enabled":
		if enabled, ok := value.(bool); ok {
			s.config.Server.RateLimit.Enabled = enabled
		} else {
			return fmt.Errorf("invalid type for server.rate_limit.enabled: expected bool")
		}
	case "server.rate_limit.requests_per_minute":
		if rpm, ok := value.(int); ok {
			if rpm <= 0 {
				return fmt.Errorf("requests per minute must be positive")
			}
			s.config.Server.RateLimit.RequestsPerMinute = rpm
		} else {
			return fmt.Errorf("invalid type for server.rate_limit.requests_per_minute: expected int")
		}
	case "server.cors.allowed_origins":
		if origins, ok := value.([]string); ok {
			s.config.Server.CORS.AllowedOrigins = origins
		} else {
			return fmt.Errorf("invalid type for server.cors.allowed_origins: expected []string")
		}
	case "logging.level":
		if level, ok := value.(string); ok {
			s.config.Logging.Level = level
		} else {
			return fmt.Errorf("invalid type for logging.level: expected string")
		}
	case "logging.format":
		if format, ok := value.(string); ok {
			s.config.Logging.Format = format
		} else {
			return fmt.Errorf("invalid type for logging.format: expected string")
		}
	default:
		return fmt.Errorf("unknown config key: %s", key)
	}

	return nil
}

// notifyCallbacks notifies all registered callbacks of configuration changes
func (s *Service) notifyCallbacks() {
	for _, callbacks := range s.callbacks {
		for _, callback := range callbacks {
			go callback(s.config)
		}
	}
}

// GetSecurityConfig returns security-related configuration settings
func (s *Service) GetSecurityConfig() map[string]interface{} {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	return map[string]interface{}{
		"max_login_attempts":       s.config.Auth.MaxLoginAttempts,
		"access_token_expiry":      s.config.Auth.AccessTokenExpiry,
		"refresh_token_expiry":     s.config.Auth.RefreshTokenExpiry,
		"password_min_length":      s.config.Auth.PasswordMinLength,
		"mfa_enabled":              s.config.Auth.MFA.Enabled,
		"rate_limit_enabled":       s.config.Server.RateLimit.Enabled,
		"rate_limit_rpm":           s.config.Server.RateLimit.RequestsPerMinute,
		"session_timeout":          s.config.Auth.SessionTimeout,
		"account_lockout_enabled":  s.config.Auth.AccountLockout.Enabled,
		"account_lockout_duration": s.config.Auth.AccountLockout.LockoutDuration,
	}
}

// UpdateSecurityConfig updates security-related configuration
func (s *Service) UpdateSecurityConfig(ctx context.Context, updates map[string]interface{}) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	// Validate and apply security configuration updates
	for key, value := range updates {
		switch key {
		case "max_login_attempts":
			if attempts, ok := value.(int); ok && attempts > 0 {
				s.config.Auth.MaxLoginAttempts = attempts
			} else {
				return fmt.Errorf("invalid max_login_attempts: must be positive integer")
			}
		case "password_min_length":
			if length, ok := value.(int); ok && length >= 8 {
				s.config.Auth.PasswordMinLength = length
			} else {
				return fmt.Errorf("invalid password_min_length: must be at least 8")
			}
		case "mfa_enabled":
			if enabled, ok := value.(bool); ok {
				s.config.Auth.MFA.Enabled = enabled
			} else {
				return fmt.Errorf("invalid mfa_enabled: must be boolean")
			}
		case "rate_limit_enabled":
			if enabled, ok := value.(bool); ok {
				s.config.Server.RateLimit.Enabled = enabled
			} else {
				return fmt.Errorf("invalid rate_limit_enabled: must be boolean")
			}
		case "rate_limit_rpm":
			if rpm, ok := value.(int); ok && rpm > 0 {
				s.config.Server.RateLimit.RequestsPerMinute = rpm
			} else {
				return fmt.Errorf("invalid rate_limit_rpm: must be positive integer")
			}
		case "account_lockout_enabled":
			if enabled, ok := value.(bool); ok {
				s.config.Auth.AccountLockout.Enabled = enabled
			} else {
				return fmt.Errorf("invalid account_lockout_enabled: must be boolean")
			}
		case "account_lockout_duration":
			if duration, ok := value.(time.Duration); ok {
				s.config.Auth.AccountLockout.LockoutDuration = duration
			} else if durationStr, ok := value.(string); ok {
				duration, err := time.ParseDuration(durationStr)
				if err != nil {
					return fmt.Errorf("invalid account_lockout_duration format: %w", err)
				}
				s.config.Auth.AccountLockout.LockoutDuration = duration
			} else {
				return fmt.Errorf("invalid account_lockout_duration: must be duration or string")
			}
		default:
			return fmt.Errorf("unknown security config key: %s", key)
		}
	}

	// Notify callbacks
	s.notifyCallbacks()

	return nil
}

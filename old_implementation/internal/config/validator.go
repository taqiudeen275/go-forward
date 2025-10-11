package config

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

// ValidationError represents a configuration validation error
type ValidationError struct {
	Field   string
	Message string
}

func (e *ValidationError) Error() string {
	return fmt.Sprintf("validation error for field '%s': %s", e.Field, e.Message)
}

// ValidationErrors represents multiple validation errors
type ValidationErrors []ValidationError

func (e ValidationErrors) Error() string {
	var messages []string
	for _, err := range e {
		messages = append(messages, err.Error())
	}
	return strings.Join(messages, "; ")
}

// ConfigValidator provides comprehensive configuration validation
type ConfigValidator struct {
	errors ValidationErrors
}

// NewConfigValidator creates a new configuration validator
func NewConfigValidator() *ConfigValidator {
	return &ConfigValidator{
		errors: make(ValidationErrors, 0),
	}
}

// Validate validates the entire configuration
func (cv *ConfigValidator) Validate(config *Config) error {
	cv.errors = make(ValidationErrors, 0)

	cv.validateServer(&config.Server)
	cv.validateDatabase(&config.Database)
	cv.validateAuth(&config.Auth)
	cv.validateStorage(&config.Storage)
	cv.validateRealtime(&config.Realtime)
	cv.validateDashboard(&config.Dashboard)
	cv.validateLogging(&config.Logging)

	if len(cv.errors) > 0 {
		return cv.errors
	}

	return nil
}

// validateServer validates server configuration
func (cv *ConfigValidator) validateServer(config *ServerConfig) {
	if config.Port <= 0 || config.Port > 65535 {
		cv.addError("server.port", fmt.Sprintf("port must be between 1 and 65535, got %d", config.Port))
	}

	if config.Host == "" {
		cv.addError("server.host", "host cannot be empty")
	}

	if config.ReadTimeout <= 0 {
		cv.addError("server.read_timeout", "read timeout must be positive")
	}

	if config.WriteTimeout <= 0 {
		cv.addError("server.write_timeout", "write timeout must be positive")
	}

	validLogLevels := []string{"debug", "info", "warn", "error", "fatal", "panic"}
	if !cv.isValidChoice(config.LogLevel, validLogLevels) {
		cv.addError("server.log_level", fmt.Sprintf("log level must be one of: %s", strings.Join(validLogLevels, ", ")))
	}

	cv.validateCORS(&config.CORS)
	cv.validateRateLimit(&config.RateLimit)
}

// validateCORS validates CORS configuration
func (cv *ConfigValidator) validateCORS(config *CORSConfig) {
	if len(config.AllowedOrigins) == 0 {
		cv.addError("server.cors.allowed_origins", "at least one allowed origin must be specified")
	}

	for i, origin := range config.AllowedOrigins {
		if origin != "*" && !cv.isValidURL(origin) {
			cv.addError(fmt.Sprintf("server.cors.allowed_origins[%d]", i), fmt.Sprintf("invalid origin URL: %s", origin))
		}
	}

	if len(config.AllowedMethods) == 0 {
		cv.addError("server.cors.allowed_methods", "at least one allowed method must be specified")
	}

	validMethods := []string{"GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"}
	for i, method := range config.AllowedMethods {
		if !cv.isValidChoice(method, validMethods) {
			cv.addError(fmt.Sprintf("server.cors.allowed_methods[%d]", i), fmt.Sprintf("invalid HTTP method: %s", method))
		}
	}

	if config.MaxAge < 0 {
		cv.addError("server.cors.max_age", "max age cannot be negative")
	}
}

// validateRateLimit validates rate limiting configuration
func (cv *ConfigValidator) validateRateLimit(config *RateLimitConfig) {
	if config.Enabled {
		if config.RequestsPerMinute <= 0 {
			cv.addError("server.rate_limit.requests_per_minute", "requests per minute must be positive when rate limiting is enabled")
		}

		if config.BurstSize <= 0 {
			cv.addError("server.rate_limit.burst_size", "burst size must be positive when rate limiting is enabled")
		}

		if config.CleanupInterval <= 0 {
			cv.addError("server.rate_limit.cleanup_interval", "cleanup interval must be positive when rate limiting is enabled")
		}
	}
}

// validateDatabase validates database configuration
func (cv *ConfigValidator) validateDatabase(config *DatabaseConfig) {
	if config.Host == "" {
		cv.addError("database.host", "host cannot be empty")
	}

	if config.Port <= 0 || config.Port > 65535 {
		cv.addError("database.port", fmt.Sprintf("port must be between 1 and 65535, got %d", config.Port))
	}

	if config.Name == "" {
		cv.addError("database.name", "database name cannot be empty")
	}

	if config.User == "" {
		cv.addError("database.user", "database user cannot be empty")
	}

	validSSLModes := []string{"disable", "require", "verify-ca", "verify-full"}
	if !cv.isValidChoice(config.SSLMode, validSSLModes) {
		cv.addError("database.ssl_mode", fmt.Sprintf("SSL mode must be one of: %s", strings.Join(validSSLModes, ", ")))
	}

	if config.MaxConns <= 0 {
		cv.addError("database.max_connections", "max connections must be positive")
	}

	if config.MaxIdleConns < 0 {
		cv.addError("database.max_idle_connections", "max idle connections cannot be negative")
	}

	if config.MaxIdleConns > config.MaxConns {
		cv.addError("database.max_idle_connections", "max idle connections cannot exceed max connections")
	}

	if config.MaxLifetime <= 0 {
		cv.addError("database.max_lifetime", "max lifetime must be positive")
	}
}

// validateAuth validates authentication configuration
func (cv *ConfigValidator) validateAuth(config *AuthConfig) {
	if config.JWTSecret == "" {
		cv.addError("auth.jwt_secret", "JWT secret cannot be empty")
	} else if len(config.JWTSecret) < 32 {
		cv.addError("auth.jwt_secret", "JWT secret should be at least 32 characters long for security")
	}

	if config.JWTExpiration <= 0 {
		cv.addError("auth.jwt_expiration", "JWT expiration must be positive")
	}

	if config.RefreshExpiration <= 0 {
		cv.addError("auth.refresh_expiration", "refresh token expiration must be positive")
	}

	if config.RefreshExpiration <= config.JWTExpiration {
		cv.addError("auth.refresh_expiration", "refresh token expiration should be longer than JWT expiration")
	}

	if config.OTPExpiration <= 0 {
		cv.addError("auth.otp_expiration", "OTP expiration must be positive")
	}

	if config.PasswordMinLength < 4 {
		cv.addError("auth.password_min_length", "password minimum length must be at least 4")
	}

	if !config.EnableEmailAuth && !config.EnablePhoneAuth && !config.EnableUsernameAuth {
		cv.addError("auth", "at least one authentication method must be enabled")
	}

	cv.validateSMTP(&config.SMTP)
	cv.validateSMS(&config.SMS)
	cv.validateCustomAuthProviders(&config.CustomProviders)
}

// validateSMTP validates SMTP configuration
func (cv *ConfigValidator) validateSMTP(config *SMTPConfig) {
	if config.Host != "" {
		if config.Port <= 0 || config.Port > 65535 {
			cv.addError("auth.smtp.port", fmt.Sprintf("SMTP port must be between 1 and 65535, got %d", config.Port))
		}

		if config.Username == "" {
			cv.addError("auth.smtp.username", "SMTP username cannot be empty when host is specified")
		}

		if config.From == "" {
			cv.addError("auth.smtp.from", "SMTP from address cannot be empty when host is specified")
		} else if !cv.isValidEmail(config.From) {
			cv.addError("auth.smtp.from", fmt.Sprintf("invalid email address: %s", config.From))
		}
	}
}

// validateSMS validates SMS configuration
func (cv *ConfigValidator) validateSMS(config *SMSConfig) {
	validProviders := []string{"arkesel", "twilio"}
	if config.Provider != "" && !cv.isValidChoice(config.Provider, validProviders) {
		cv.addError("auth.sms.provider", fmt.Sprintf("SMS provider must be one of: %s", strings.Join(validProviders, ", ")))
	}

	if config.Provider == "arkesel" {
		if config.Arkesel.ApiKey == "" {
			cv.addError("auth.sms.arkesel.api_key", "Arkesel API key cannot be empty when Arkesel is selected")
		}
		if config.Arkesel.Sender == "" {
			cv.addError("auth.sms.arkesel.sender", "Arkesel sender cannot be empty when Arkesel is selected")
		}
	}
}

// validateCustomAuthProviders validates custom authentication providers
func (cv *ConfigValidator) validateCustomAuthProviders(config *CustomAuthProvidersConfig) {
	if err := ValidateCustomAuthProviders(config); err != nil {
		cv.addError("auth.custom_providers", err.Error())
	}
}

// validateStorage validates storage configuration
func (cv *ConfigValidator) validateStorage(config *StorageConfig) {
	validProviders := []string{"local", "s3"}
	if !cv.isValidChoice(config.Provider, validProviders) {
		cv.addError("storage.provider", fmt.Sprintf("storage provider must be one of: %s", strings.Join(validProviders, ", ")))
	}

	if config.Provider == "local" {
		if config.LocalPath == "" {
			cv.addError("storage.local_path", "local path cannot be empty when using local storage")
		}
	}

	if config.Provider == "s3" {
		if config.S3.Region == "" {
			cv.addError("storage.s3.region", "S3 region cannot be empty when using S3 storage")
		}
		if config.S3.Bucket == "" {
			cv.addError("storage.s3.bucket", "S3 bucket cannot be empty when using S3 storage")
		}
		if config.S3.AccessKeyID == "" {
			cv.addError("storage.s3.access_key_id", "S3 access key ID cannot be empty when using S3 storage")
		}
		if config.S3.SecretAccessKey == "" {
			cv.addError("storage.s3.secret_access_key", "S3 secret access key cannot be empty when using S3 storage")
		}
	}

	if config.MaxFileSize <= 0 {
		cv.addError("storage.max_file_size", "max file size must be positive")
	}
}

// validateRealtime validates real-time configuration
func (cv *ConfigValidator) validateRealtime(config *RealtimeConfig) {
	if config.Enabled {
		if config.MaxConnections <= 0 {
			cv.addError("realtime.max_connections", "max connections must be positive when real-time is enabled")
		}

		if config.HeartbeatInterval <= 0 {
			cv.addError("realtime.heartbeat_interval", "heartbeat interval must be positive when real-time is enabled")
		}

		if config.ReadBufferSize <= 0 {
			cv.addError("realtime.read_buffer_size", "read buffer size must be positive when real-time is enabled")
		}

		if config.WriteBufferSize <= 0 {
			cv.addError("realtime.write_buffer_size", "write buffer size must be positive when real-time is enabled")
		}

		cv.validateRedis(&config.Redis)
	}
}

// validateRedis validates Redis configuration
func (cv *ConfigValidator) validateRedis(config *RedisConfig) {
	if config.Host == "" {
		cv.addError("realtime.redis.host", "Redis host cannot be empty when real-time is enabled")
	}

	if config.Port <= 0 || config.Port > 65535 {
		cv.addError("realtime.redis.port", fmt.Sprintf("Redis port must be between 1 and 65535, got %d", config.Port))
	}

	if config.DB < 0 || config.DB > 15 {
		cv.addError("realtime.redis.db", fmt.Sprintf("Redis DB must be between 0 and 15, got %d", config.DB))
	}
}

// validateDashboard validates dashboard configuration
func (cv *ConfigValidator) validateDashboard(config *DashboardConfig) {
	if config.Enabled {
		if config.Path == "" {
			cv.addError("dashboard.path", "dashboard path cannot be empty when dashboard is enabled")
		} else if !strings.HasPrefix(config.Path, "/") {
			cv.addError("dashboard.path", "dashboard path must start with '/'")
		}

		if config.StaticDir == "" {
			cv.addError("dashboard.static_dir", "static directory cannot be empty when dashboard is enabled")
		}
	}
}

// validateLogging validates logging configuration
func (cv *ConfigValidator) validateLogging(config *LoggingConfig) {
	validLevels := []string{"debug", "info", "warn", "error", "fatal", "panic"}
	if !cv.isValidChoice(config.Level, validLevels) {
		cv.addError("logging.level", fmt.Sprintf("log level must be one of: %s", strings.Join(validLevels, ", ")))
	}

	validFormats := []string{"json", "text"}
	if !cv.isValidChoice(config.Format, validFormats) {
		cv.addError("logging.format", fmt.Sprintf("log format must be one of: %s", strings.Join(validFormats, ", ")))
	}

	validOutputs := []string{"stdout", "file"}
	if !cv.isValidChoice(config.Output, validOutputs) {
		cv.addError("logging.output", fmt.Sprintf("log output must be one of: %s", strings.Join(validOutputs, ", ")))
	}

	if config.Output == "file" {
		if config.FilePath == "" {
			cv.addError("logging.file_path", "file path cannot be empty when using file output")
		}

		if config.MaxSize <= 0 {
			cv.addError("logging.max_size", "max size must be positive when using file output")
		}

		if config.MaxBackups < 0 {
			cv.addError("logging.max_backups", "max backups cannot be negative")
		}

		if config.MaxAge <= 0 {
			cv.addError("logging.max_age", "max age must be positive when using file output")
		}
	}
}

// Helper methods

func (cv *ConfigValidator) addError(field, message string) {
	cv.errors = append(cv.errors, ValidationError{
		Field:   field,
		Message: message,
	})
}

func (cv *ConfigValidator) isValidChoice(value string, choices []string) bool {
	for _, choice := range choices {
		if value == choice {
			return true
		}
	}
	return false
}

func (cv *ConfigValidator) isValidURL(urlStr string) bool {
	_, err := url.Parse(urlStr)
	return err == nil
}

func (cv *ConfigValidator) isValidEmail(email string) bool {
	emailRegex := regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)
	return emailRegex.MatchString(email)
}

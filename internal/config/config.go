package config

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"gopkg.in/yaml.v3"
)

// Config represents the main application configuration
type Config struct {
	Server    ServerConfig    `yaml:"server"`
	Database  DatabaseConfig  `yaml:"database"`
	Auth      AuthConfig      `yaml:"auth"`
	Storage   StorageConfig   `yaml:"storage"`
	Realtime  RealtimeConfig  `yaml:"realtime"`
	Dashboard DashboardConfig `yaml:"dashboard"`
	Logging   LoggingConfig   `yaml:"logging"`
	Plugins   PluginsConfig   `yaml:"plugins"`
}

// ServerConfig represents server configuration
type ServerConfig struct {
	Host         string          `yaml:"host"`
	Port         int             `yaml:"port"`
	ReadTimeout  time.Duration   `yaml:"read_timeout"`
	WriteTimeout time.Duration   `yaml:"write_timeout"`
	LogLevel     string          `yaml:"log_level"`
	CORS         CORSConfig      `yaml:"cors"`
	RateLimit    RateLimitConfig `yaml:"rate_limit"`
}

// DatabaseConfig represents database configuration
type DatabaseConfig struct {
	Host         string        `yaml:"host"`
	Port         int           `yaml:"port"`
	Name         string        `yaml:"name"`
	User         string        `yaml:"user"`
	Password     string        `yaml:"password"`
	SSLMode      string        `yaml:"ssl_mode"`
	MaxConns     int           `yaml:"max_connections"`
	MaxIdleConns int           `yaml:"max_idle_connections"`
	MaxLifetime  time.Duration `yaml:"max_lifetime"`
}

// AuthConfig represents authentication configuration
type AuthConfig struct {
	JWTSecret           string                    `yaml:"jwt_secret"`
	JWTExpiration       time.Duration             `yaml:"jwt_expiration"`
	RefreshExpiration   time.Duration             `yaml:"refresh_expiration"`
	AccessTokenExpiry   time.Duration             `yaml:"access_token_expiry"`
	RefreshTokenExpiry  time.Duration             `yaml:"refresh_token_expiry"`
	OTPExpiration       time.Duration             `yaml:"otp_expiration"`
	PasswordMinLength   int                       `yaml:"password_min_length"`
	MaxLoginAttempts    int                       `yaml:"max_login_attempts"`
	SessionTimeout      time.Duration             `yaml:"session_timeout"`
	EnableEmailAuth     bool                      `yaml:"enable_email_auth"`
	EnablePhoneAuth     bool                      `yaml:"enable_phone_auth"`
	EnableUsernameAuth  bool                      `yaml:"enable_username_auth"`
	RequireVerification bool                      `yaml:"require_verification"`
	MFA                 MFAConfig                 `yaml:"mfa"`
	AccountLockout      AccountLockoutConfig      `yaml:"account_lockout"`
	SMTP                SMTPConfig                `yaml:"smtp"`
	SMS                 SMSConfig                 `yaml:"sms"`
	CustomProviders     CustomAuthProvidersConfig `yaml:"custom_providers"`
}

// StorageConfig represents storage configuration
type StorageConfig struct {
	Provider    string   `yaml:"provider"` // local, s3
	LocalPath   string   `yaml:"local_path"`
	MaxFileSize int64    `yaml:"max_file_size"`
	S3          S3Config `yaml:"s3"`
}

// RealtimeConfig represents real-time configuration
type RealtimeConfig struct {
	Enabled           bool          `yaml:"enabled"`
	MaxConnections    int           `yaml:"max_connections"`
	HeartbeatInterval time.Duration `yaml:"heartbeat_interval"`
	ReadBufferSize    int           `yaml:"read_buffer_size"`
	WriteBufferSize   int           `yaml:"write_buffer_size"`
	Redis             RedisConfig   `yaml:"redis"`
}

// DashboardConfig represents dashboard configuration
type DashboardConfig struct {
	Enabled   bool   `yaml:"enabled"`
	Path      string `yaml:"path"`
	StaticDir string `yaml:"static_dir"`
}

// LoggingConfig represents logging configuration
type LoggingConfig struct {
	Level      string `yaml:"level"`
	Format     string `yaml:"format"` // json, text
	Output     string `yaml:"output"` // stdout, file
	FilePath   string `yaml:"file_path"`
	MaxSize    int    `yaml:"max_size"` // MB
	MaxBackups int    `yaml:"max_backups"`
	MaxAge     int    `yaml:"max_age"` // days
}

// CORSConfig represents CORS configuration
type CORSConfig struct {
	AllowedOrigins   []string `yaml:"allowed_origins"`
	AllowedMethods   []string `yaml:"allowed_methods"`
	AllowedHeaders   []string `yaml:"allowed_headers"`
	ExposedHeaders   []string `yaml:"exposed_headers"`
	AllowCredentials bool     `yaml:"allow_credentials"`
	MaxAge           int      `yaml:"max_age"`
}

// RateLimitConfig represents rate limiting configuration
type RateLimitConfig struct {
	Enabled           bool          `yaml:"enabled"`
	RequestsPerMinute int           `yaml:"requests_per_minute"`
	BurstSize         int           `yaml:"burst_size"`
	CleanupInterval   time.Duration `yaml:"cleanup_interval"`
}

// SMTPConfig represents SMTP configuration
type SMTPConfig struct {
	Host     string `yaml:"host"`
	Port     int    `yaml:"port"`
	Username string `yaml:"username"`
	Password string `yaml:"password"`
	From     string `yaml:"from"`
	UseTLS   bool   `yaml:"use_tls"`
}

// SMSConfig represents SMS configuration
type SMSConfig struct {
	Provider string        `yaml:"provider"` // Arkesel, twilio
	Arkesel  ArkeselConfig `yaml:"arkesel"`
}

// ArkeselConfig repesent Arkesel Configration
type ArkeselConfig struct {
	ApiKey string `yaml:"api_key"`
	Sender string `yaml:"sender"`
}

// TwilioConfig represents Twilio configuration
type TwilioConfig struct {
	AccountSID string `yaml:"account_sid"`
	AuthToken  string `yaml:"auth_token"`
	FromNumber string `yaml:"from_number"`
}

// S3Config represents S3 configuration
type S3Config struct {
	Region          string `yaml:"region"`
	Bucket          string `yaml:"bucket"`
	AccessKeyID     string `yaml:"access_key_id"`
	SecretAccessKey string `yaml:"secret_access_key"`
	Endpoint        string `yaml:"endpoint"`
	UseSSL          bool   `yaml:"use_ssl"`
}

// RedisConfig represents Redis configuration
type RedisConfig struct {
	Host     string `yaml:"host"`
	Port     int    `yaml:"port"`
	Password string `yaml:"password"`
	DB       int    `yaml:"db"`
}

// CustomAuthProvidersConfig represents custom authentication providers configuration
type CustomAuthProvidersConfig struct {
	LDAP   LDAPProviderConfig    `yaml:"ldap"`
	APIKey APIKeyProviderConfig  `yaml:"api_key"`
	Social SocialProvidersConfig `yaml:"social"`
}

// LDAPProviderConfig represents LDAP authentication provider configuration
type LDAPProviderConfig struct {
	Enabled           bool          `yaml:"enabled"`
	Host              string        `yaml:"host"`
	Port              int           `yaml:"port"`
	UseSSL            bool          `yaml:"use_ssl"`
	SkipTLSVerify     bool          `yaml:"skip_tls_verify"`
	BindDN            string        `yaml:"bind_dn"`
	BindPassword      string        `yaml:"bind_password"`
	BaseDN            string        `yaml:"base_dn"`
	UserFilter        string        `yaml:"user_filter"`
	EmailAttribute    string        `yaml:"email_attribute"`
	NameAttribute     string        `yaml:"name_attribute"`
	UsernameAttribute string        `yaml:"username_attribute"`
	ConnectionTimeout time.Duration `yaml:"connection_timeout"`
	RequestTimeout    time.Duration `yaml:"request_timeout"`
}

// APIKeyProviderConfig represents API key authentication provider configuration
type APIKeyProviderConfig struct {
	Enabled       bool          `yaml:"enabled"`
	KeyPrefix     string        `yaml:"key_prefix"`
	KeyLength     int           `yaml:"key_length"`
	HashAlgorithm string        `yaml:"hash_algorithm"`
	CacheTimeout  time.Duration `yaml:"cache_timeout"`
	AllowedScopes []string      `yaml:"allowed_scopes"`
	RequireScopes bool          `yaml:"require_scopes"`
}

// SocialProvidersConfig represents social authentication providers configuration
type SocialProvidersConfig struct {
	Google   SocialProviderConfig `yaml:"google"`
	GitHub   SocialProviderConfig `yaml:"github"`
	Facebook SocialProviderConfig `yaml:"facebook"`
	Twitter  SocialProviderConfig `yaml:"twitter"`
	LinkedIn SocialProviderConfig `yaml:"linkedin"`
}

// SocialProviderConfig represents individual social provider configuration
type SocialProviderConfig struct {
	Enabled         bool          `yaml:"enabled"`
	ClientID        string        `yaml:"client_id"`
	ClientSecret    string        `yaml:"client_secret"`
	RedirectURL     string        `yaml:"redirect_url"`
	Scopes          []string      `yaml:"scopes"`
	AuthURL         string        `yaml:"auth_url"`
	TokenURL        string        `yaml:"token_url"`
	UserInfoURL     string        `yaml:"user_info_url"`
	RequestTimeout  time.Duration `yaml:"request_timeout"`
	AllowSignup     bool          `yaml:"allow_signup"`
	RequireVerified bool          `yaml:"require_verified"`
}

// MFAConfig represents multi-factor authentication configuration
type MFAConfig struct {
	Enabled       bool          `yaml:"enabled"`
	Issuer        string        `yaml:"issuer"`
	TOTPWindow    int           `yaml:"totp_window"`
	BackupCodes   bool          `yaml:"backup_codes"`
	RequiredRoles []string      `yaml:"required_roles"`
	GracePeriod   time.Duration `yaml:"grace_period"`
}

// AccountLockoutConfig represents account lockout configuration
type AccountLockoutConfig struct {
	Enabled         bool          `yaml:"enabled"`
	MaxAttempts     int           `yaml:"max_attempts"`
	LockoutDuration time.Duration `yaml:"lockout_duration"`
	ResetOnSuccess  bool          `yaml:"reset_on_success"`
	NotifyOnLockout bool          `yaml:"notify_on_lockout"`
}

// Load loads configuration from file and environment variables
func Load() (*Config, error) {
	return LoadWithPrefix("GOFORWARD")
}

// LoadWithPrefix loads configuration with a custom environment variable prefix
func LoadWithPrefix(envPrefix string) (*Config, error) {
	loader := NewConfigLoader(envPrefix)
	config, err := loader.LoadConfig()
	if err != nil {
		return nil, err
	}

	// Apply defaults for any missing values
	ApplyDefaults(config)

	return config, nil
}

// LoadFromPath loads configuration from a specific file path
func LoadFromPath(configPath string) (*Config, error) {
	loader := NewConfigLoader("GOFORWARD")
	loader.AddConfigPath(configPath)

	config, err := loader.LoadConfig()
	if err != nil {
		return nil, err
	}

	// Apply defaults for any missing values
	ApplyDefaults(config)

	return config, nil
}

// getDefaultConfig returns default configuration
func getDefaultConfig() *Config {
	return &Config{
		Server: ServerConfig{
			Host:         "localhost",
			Port:         8080,
			ReadTimeout:  30 * time.Second,
			WriteTimeout: 30 * time.Second,
			LogLevel:     "info",
			CORS: CORSConfig{
				AllowedOrigins: []string{"*"},
				AllowedMethods: []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
				AllowedHeaders: []string{"*"},
				MaxAge:         86400,
			},
			RateLimit: RateLimitConfig{
				Enabled:           true,
				RequestsPerMinute: 100,
				BurstSize:         10,
				CleanupInterval:   time.Minute,
			},
		},
		Database: DatabaseConfig{
			Host:         "localhost",
			Port:         5432,
			Name:         "goforward",
			User:         "postgres",
			Password:     "password",
			SSLMode:      "disable",
			MaxConns:     25,
			MaxIdleConns: 5,
			MaxLifetime:  time.Hour,
		},
		Auth: AuthConfig{
			JWTSecret:           "your-secret-key",
			JWTExpiration:       24 * time.Hour,
			RefreshExpiration:   7 * 24 * time.Hour,
			OTPExpiration:       10 * time.Minute,
			PasswordMinLength:   8,
			EnableEmailAuth:     true,
			EnablePhoneAuth:     true,
			EnableUsernameAuth:  true,
			RequireVerification: false,
			CustomProviders: CustomAuthProvidersConfig{
				LDAP: LDAPProviderConfig{
					Enabled:           false,
					Host:              "ldap.example.com",
					Port:              389,
					UseSSL:            false,
					SkipTLSVerify:     false,
					BindDN:            "",
					BindPassword:      "",
					BaseDN:            "ou=users,dc=example,dc=com",
					UserFilter:        "(uid=%s)",
					EmailAttribute:    "mail",
					NameAttribute:     "cn",
					UsernameAttribute: "uid",
					ConnectionTimeout: 10 * time.Second,
					RequestTimeout:    30 * time.Second,
				},
				APIKey: APIKeyProviderConfig{
					Enabled:       false,
					KeyPrefix:     "gf_",
					KeyLength:     32,
					HashAlgorithm: "sha256",
					CacheTimeout:  5 * time.Minute,
					AllowedScopes: []string{"read", "write", "admin"},
					RequireScopes: false,
				},
				Social: SocialProvidersConfig{
					Google: SocialProviderConfig{
						Enabled:         false,
						ClientID:        "",
						ClientSecret:    "",
						RedirectURL:     "",
						Scopes:          []string{"openid", "email", "profile"},
						AuthURL:         "https://accounts.google.com/o/oauth2/v2/auth",
						TokenURL:        "https://oauth2.googleapis.com/token",
						UserInfoURL:     "https://openidconnect.googleapis.com/v1/userinfo",
						RequestTimeout:  30 * time.Second,
						AllowSignup:     true,
						RequireVerified: true,
					},
					GitHub: SocialProviderConfig{
						Enabled:         false,
						ClientID:        "",
						ClientSecret:    "",
						RedirectURL:     "",
						Scopes:          []string{"user:email", "read:user"},
						AuthURL:         "https://github.com/login/oauth/authorize",
						TokenURL:        "https://github.com/login/oauth/access_token",
						UserInfoURL:     "https://api.github.com/user",
						RequestTimeout:  30 * time.Second,
						AllowSignup:     true,
						RequireVerified: true,
					},
					Facebook: SocialProviderConfig{
						Enabled:         false,
						ClientID:        "",
						ClientSecret:    "",
						RedirectURL:     "",
						Scopes:          []string{"email", "public_profile"},
						AuthURL:         "https://www.facebook.com/v18.0/dialog/oauth",
						TokenURL:        "https://graph.facebook.com/v18.0/oauth/access_token",
						UserInfoURL:     "https://graph.facebook.com/v18.0/me?fields=id,name,email,picture",
						RequestTimeout:  30 * time.Second,
						AllowSignup:     true,
						RequireVerified: true,
					},
					Twitter: SocialProviderConfig{
						Enabled:         false,
						ClientID:        "",
						ClientSecret:    "",
						RedirectURL:     "",
						Scopes:          []string{"tweet.read", "users.read"},
						RequestTimeout:  30 * time.Second,
						AllowSignup:     true,
						RequireVerified: true,
					},
					LinkedIn: SocialProviderConfig{
						Enabled:         false,
						ClientID:        "",
						ClientSecret:    "",
						RedirectURL:     "",
						Scopes:          []string{"r_liteprofile", "r_emailaddress"},
						RequestTimeout:  30 * time.Second,
						AllowSignup:     true,
						RequireVerified: true,
					},
				},
			},
		},
		Storage: StorageConfig{
			Provider:    "local",
			LocalPath:   "./storage",
			MaxFileSize: 10 * 1024 * 1024, // 10MB
		},
		Realtime: RealtimeConfig{
			Enabled:           true,
			MaxConnections:    1000,
			HeartbeatInterval: 30 * time.Second,
			ReadBufferSize:    1024,
			WriteBufferSize:   1024,
		},
		Dashboard: DashboardConfig{
			Enabled:   true,
			Path:      "/admin",
			StaticDir: "./dashboard/dist",
		},
		Logging: LoggingConfig{
			Level:      "info",
			Format:     "json",
			Output:     "stdout",
			MaxSize:    100,
			MaxBackups: 3,
			MaxAge:     28,
		},
		Plugins: GetDefaultPluginsConfig(),
	}
}

// getConfigPath returns the configuration file path
func getConfigPath() string {
	if path := os.Getenv("CONFIG_PATH"); path != "" {
		return path
	}

	// Check common locations
	locations := []string{
		"./config.yaml",
		"./config.yml",
		"./configs/config.yaml",
		"./configs/config.yml",
	}

	for _, location := range locations {
		if _, err := os.Stat(location); err == nil {
			return location
		}
	}

	return "./config.yaml"
}

// loadFromFile loads configuration from YAML file
func loadFromFile(config *Config, path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	return yaml.Unmarshal(data, config)
}

// loadFromEnv loads configuration from environment variables
func loadFromEnv(config *Config) {
	// Server configuration
	if host := os.Getenv("SERVER_HOST"); host != "" {
		config.Server.Host = host
	}
	if port := os.Getenv("SERVER_PORT"); port != "" {
		if p, err := parsePort(port); err == nil {
			config.Server.Port = p
		}
	}
	if logLevel := os.Getenv("LOG_LEVEL"); logLevel != "" {
		config.Server.LogLevel = logLevel
	}

	// Database configuration
	if host := os.Getenv("DB_HOST"); host != "" {
		config.Database.Host = host
	}
	if port := os.Getenv("DB_PORT"); port != "" {
		if p, err := parsePort(port); err == nil {
			config.Database.Port = p
		}
	}
	if name := os.Getenv("DB_NAME"); name != "" {
		config.Database.Name = name
	}
	if user := os.Getenv("DB_USER"); user != "" {
		config.Database.User = user
	}
	if password := os.Getenv("DB_PASSWORD"); password != "" {
		config.Database.Password = password
	}

	// Auth configuration
	if secret := os.Getenv("JWT_SECRET"); secret != "" {
		config.Auth.JWTSecret = secret
	}

	// LDAP Provider configuration
	if enabled := os.Getenv("LDAP_ENABLED"); enabled == "true" {
		config.Auth.CustomProviders.LDAP.Enabled = true
	}
	if host := os.Getenv("LDAP_HOST"); host != "" {
		config.Auth.CustomProviders.LDAP.Host = host
	}
	if port := os.Getenv("LDAP_PORT"); port != "" {
		if p, err := parsePort(port); err == nil {
			config.Auth.CustomProviders.LDAP.Port = p
		}
	}
	if bindDN := os.Getenv("LDAP_BIND_DN"); bindDN != "" {
		config.Auth.CustomProviders.LDAP.BindDN = bindDN
	}
	if bindPassword := os.Getenv("LDAP_BIND_PASSWORD"); bindPassword != "" {
		config.Auth.CustomProviders.LDAP.BindPassword = bindPassword
	}
	if baseDN := os.Getenv("LDAP_BASE_DN"); baseDN != "" {
		config.Auth.CustomProviders.LDAP.BaseDN = baseDN
	}

	// API Key Provider configuration
	if enabled := os.Getenv("API_KEY_ENABLED"); enabled == "true" {
		config.Auth.CustomProviders.APIKey.Enabled = true
	}
	if prefix := os.Getenv("API_KEY_PREFIX"); prefix != "" {
		config.Auth.CustomProviders.APIKey.KeyPrefix = prefix
	}

	// Google OAuth configuration
	if enabled := os.Getenv("GOOGLE_OAUTH_ENABLED"); enabled == "true" {
		config.Auth.CustomProviders.Social.Google.Enabled = true
	}
	if clientID := os.Getenv("GOOGLE_CLIENT_ID"); clientID != "" {
		config.Auth.CustomProviders.Social.Google.ClientID = clientID
	}
	if clientSecret := os.Getenv("GOOGLE_CLIENT_SECRET"); clientSecret != "" {
		config.Auth.CustomProviders.Social.Google.ClientSecret = clientSecret
	}
	if redirectURL := os.Getenv("GOOGLE_REDIRECT_URL"); redirectURL != "" {
		config.Auth.CustomProviders.Social.Google.RedirectURL = redirectURL
	}

	// GitHub OAuth configuration
	if enabled := os.Getenv("GITHUB_OAUTH_ENABLED"); enabled == "true" {
		config.Auth.CustomProviders.Social.GitHub.Enabled = true
	}
	if clientID := os.Getenv("GITHUB_CLIENT_ID"); clientID != "" {
		config.Auth.CustomProviders.Social.GitHub.ClientID = clientID
	}
	if clientSecret := os.Getenv("GITHUB_CLIENT_SECRET"); clientSecret != "" {
		config.Auth.CustomProviders.Social.GitHub.ClientSecret = clientSecret
	}
	if redirectURL := os.Getenv("GITHUB_REDIRECT_URL"); redirectURL != "" {
		config.Auth.CustomProviders.Social.GitHub.RedirectURL = redirectURL
	}

	// Facebook OAuth configuration
	if enabled := os.Getenv("FACEBOOK_OAUTH_ENABLED"); enabled == "true" {
		config.Auth.CustomProviders.Social.Facebook.Enabled = true
	}
	if clientID := os.Getenv("FACEBOOK_CLIENT_ID"); clientID != "" {
		config.Auth.CustomProviders.Social.Facebook.ClientID = clientID
	}
	if clientSecret := os.Getenv("FACEBOOK_CLIENT_SECRET"); clientSecret != "" {
		config.Auth.CustomProviders.Social.Facebook.ClientSecret = clientSecret
	}
	if redirectURL := os.Getenv("FACEBOOK_REDIRECT_URL"); redirectURL != "" {
		config.Auth.CustomProviders.Social.Facebook.RedirectURL = redirectURL
	}
}

// validate validates the configuration using the comprehensive validator
func validate(config *Config) error {
	validator := NewConfigValidator()
	return validator.Validate(config)
}

// parsePort parses port string to integer
func parsePort(port string) (int, error) {
	var p int
	if _, err := fmt.Sscanf(port, "%d", &p); err != nil {
		return 0, err
	}
	return p, nil
}

// SaveExample saves an example configuration file
func SaveExample(path string) error {
	config := getDefaultConfig()

	data, err := yaml.Marshal(config)
	if err != nil {
		return err
	}

	// Create directory if it doesn't exist
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}

	return os.WriteFile(path, data, 0644)
}

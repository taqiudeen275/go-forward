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
	JWTSecret           string        `yaml:"jwt_secret"`
	JWTExpiration       time.Duration `yaml:"jwt_expiration"`
	RefreshExpiration   time.Duration `yaml:"refresh_expiration"`
	OTPExpiration       time.Duration `yaml:"otp_expiration"`
	PasswordMinLength   int           `yaml:"password_min_length"`
	EnableEmailAuth     bool          `yaml:"enable_email_auth"`
	EnablePhoneAuth     bool          `yaml:"enable_phone_auth"`
	EnableUsernameAuth  bool          `yaml:"enable_username_auth"`
	RequireVerification bool          `yaml:"require_verification"`
	SMTP                SMTPConfig    `yaml:"smtp"`
	SMS                 SMSConfig     `yaml:"sms"`
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
	Provider string       `yaml:"provider"` // Arkesel, twilio
	Arkesel   ArkeselConfig `yaml:"arkesel"`
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

// Load loads configuration from file and environment variables
func Load() (*Config, error) {
	config := getDefaultConfig()

	// Load from config file
	configPath := getConfigPath()
	if _, err := os.Stat(configPath); err == nil {
		if err := loadFromFile(config, configPath); err != nil {
			return nil, fmt.Errorf("failed to load config from file: %w", err)
		}
	}

	// Override with environment variables
	loadFromEnv(config)

	// Validate configuration
	if err := validate(config); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

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
}

// validate validates the configuration
func validate(config *Config) error {
	if config.Server.Port <= 0 || config.Server.Port > 65535 {
		return fmt.Errorf("invalid server port: %d", config.Server.Port)
	}

	if config.Database.Port <= 0 || config.Database.Port > 65535 {
		return fmt.Errorf("invalid database port: %d", config.Database.Port)
	}

	if config.Auth.JWTSecret == "" {
		return fmt.Errorf("JWT secret is required")
	}

	if config.Auth.PasswordMinLength < 4 {
		return fmt.Errorf("password minimum length must be at least 4")
	}

	return nil
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

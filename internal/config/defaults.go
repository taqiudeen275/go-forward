package config

import (
	"time"
)

// DefaultConfig contains all default configuration values
type DefaultConfig struct {
	Server    DefaultServerConfig    `yaml:"server"`
	Database  DefaultDatabaseConfig  `yaml:"database"`
	Auth      DefaultAuthConfig      `yaml:"auth"`
	Storage   DefaultStorageConfig   `yaml:"storage"`
	Realtime  DefaultRealtimeConfig  `yaml:"realtime"`
	Dashboard DefaultDashboardConfig `yaml:"dashboard"`
	Logging   DefaultLoggingConfig   `yaml:"logging"`
}

// DefaultServerConfig contains default server configuration
type DefaultServerConfig struct {
	Host         string          `yaml:"host"`
	Port         int             `yaml:"port"`
	ReadTimeout  time.Duration   `yaml:"read_timeout"`
	WriteTimeout time.Duration   `yaml:"write_timeout"`
	LogLevel     string          `yaml:"log_level"`
	CORS         CORSConfig      `yaml:"cors"`
	RateLimit    RateLimitConfig `yaml:"rate_limit"`
}

// DefaultDatabaseConfig contains default database configuration
type DefaultDatabaseConfig struct {
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

// DefaultAuthConfig contains default authentication configuration
type DefaultAuthConfig struct {
	JWTSecret           string        `yaml:"jwt_secret"`
	JWTExpiration       time.Duration `yaml:"jwt_expiration"`
	RefreshExpiration   time.Duration `yaml:"refresh_expiration"`
	OTPExpiration       time.Duration `yaml:"otp_expiration"`
	PasswordMinLength   int           `yaml:"password_min_length"`
	EnableEmailAuth     bool          `yaml:"enable_email_auth"`
	EnablePhoneAuth     bool          `yaml:"enable_phone_auth"`
	EnableUsernameAuth  bool          `yaml:"enable_username_auth"`
	RequireVerification bool          `yaml:"require_verification"`
}

// DefaultStorageConfig contains default storage configuration
type DefaultStorageConfig struct {
	Provider    string `yaml:"provider"`
	LocalPath   string `yaml:"local_path"`
	MaxFileSize int64  `yaml:"max_file_size"`
}

// DefaultRealtimeConfig contains default real-time configuration
type DefaultRealtimeConfig struct {
	Enabled           bool          `yaml:"enabled"`
	MaxConnections    int           `yaml:"max_connections"`
	HeartbeatInterval time.Duration `yaml:"heartbeat_interval"`
	ReadBufferSize    int           `yaml:"read_buffer_size"`
	WriteBufferSize   int           `yaml:"write_buffer_size"`
}

// DefaultDashboardConfig contains default dashboard configuration
type DefaultDashboardConfig struct {
	Enabled   bool   `yaml:"enabled"`
	Path      string `yaml:"path"`
	StaticDir string `yaml:"static_dir"`
}

// DefaultLoggingConfig contains default logging configuration
type DefaultLoggingConfig struct {
	Level      string `yaml:"level"`
	Format     string `yaml:"format"`
	Output     string `yaml:"output"`
	FilePath   string `yaml:"file_path"`
	MaxSize    int    `yaml:"max_size"`
	MaxBackups int    `yaml:"max_backups"`
	MaxAge     int    `yaml:"max_age"`
}

// GetDefaults returns the default configuration values
func GetDefaults() *DefaultConfig {
	return &DefaultConfig{
		Server: DefaultServerConfig{
			Host:         "localhost",
			Port:         8080,
			ReadTimeout:  30 * time.Second,
			WriteTimeout: 30 * time.Second,
			LogLevel:     "info",
			CORS: CORSConfig{
				AllowedOrigins:   []string{"*"},
				AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
				AllowedHeaders:   []string{"*"},
				ExposedHeaders:   []string{},
				AllowCredentials: false,
				MaxAge:           86400,
			},
			RateLimit: RateLimitConfig{
				Enabled:           true,
				RequestsPerMinute: 100,
				BurstSize:         10,
				CleanupInterval:   time.Minute,
			},
		},
		Database: DefaultDatabaseConfig{
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
		Auth: DefaultAuthConfig{
			JWTSecret:           "change-this-secret-key-in-production-make-it-at-least-32-characters-long",
			JWTExpiration:       24 * time.Hour,
			RefreshExpiration:   7 * 24 * time.Hour,
			OTPExpiration:       10 * time.Minute,
			PasswordMinLength:   8,
			EnableEmailAuth:     true,
			EnablePhoneAuth:     true,
			EnableUsernameAuth:  true,
			RequireVerification: false,
		},
		Storage: DefaultStorageConfig{
			Provider:    "local",
			LocalPath:   "./storage",
			MaxFileSize: 10 * 1024 * 1024, // 10MB
		},
		Realtime: DefaultRealtimeConfig{
			Enabled:           true,
			MaxConnections:    1000,
			HeartbeatInterval: 30 * time.Second,
			ReadBufferSize:    1024,
			WriteBufferSize:   1024,
		},
		Dashboard: DefaultDashboardConfig{
			Enabled:   true,
			Path:      "/admin",
			StaticDir: "./dashboard/dist",
		},
		Logging: DefaultLoggingConfig{
			Level:      "info",
			Format:     "json",
			Output:     "stdout",
			FilePath:   "./logs/app.log",
			MaxSize:    100,
			MaxBackups: 3,
			MaxAge:     28,
		},
	}
}

// ApplyDefaults applies default values to a configuration
func ApplyDefaults(config *Config) {
	defaults := GetDefaults()

	// Apply server defaults
	if config.Server.Host == "" {
		config.Server.Host = defaults.Server.Host
	}
	if config.Server.Port == 0 {
		config.Server.Port = defaults.Server.Port
	}
	if config.Server.ReadTimeout == 0 {
		config.Server.ReadTimeout = defaults.Server.ReadTimeout
	}
	if config.Server.WriteTimeout == 0 {
		config.Server.WriteTimeout = defaults.Server.WriteTimeout
	}
	if config.Server.LogLevel == "" {
		config.Server.LogLevel = defaults.Server.LogLevel
	}

	// Apply CORS defaults
	if len(config.Server.CORS.AllowedOrigins) == 0 {
		config.Server.CORS.AllowedOrigins = defaults.Server.CORS.AllowedOrigins
	}
	if len(config.Server.CORS.AllowedMethods) == 0 {
		config.Server.CORS.AllowedMethods = defaults.Server.CORS.AllowedMethods
	}
	if len(config.Server.CORS.AllowedHeaders) == 0 {
		config.Server.CORS.AllowedHeaders = defaults.Server.CORS.AllowedHeaders
	}
	if config.Server.CORS.MaxAge == 0 {
		config.Server.CORS.MaxAge = defaults.Server.CORS.MaxAge
	}

	// Apply rate limit defaults
	if config.Server.RateLimit.RequestsPerMinute == 0 {
		config.Server.RateLimit.RequestsPerMinute = defaults.Server.RateLimit.RequestsPerMinute
	}
	if config.Server.RateLimit.BurstSize == 0 {
		config.Server.RateLimit.BurstSize = defaults.Server.RateLimit.BurstSize
	}
	if config.Server.RateLimit.CleanupInterval == 0 {
		config.Server.RateLimit.CleanupInterval = defaults.Server.RateLimit.CleanupInterval
	}

	// Apply database defaults
	if config.Database.Host == "" {
		config.Database.Host = defaults.Database.Host
	}
	if config.Database.Port == 0 {
		config.Database.Port = defaults.Database.Port
	}
	if config.Database.Name == "" {
		config.Database.Name = defaults.Database.Name
	}
	if config.Database.User == "" {
		config.Database.User = defaults.Database.User
	}
	if config.Database.SSLMode == "" {
		config.Database.SSLMode = defaults.Database.SSLMode
	}
	if config.Database.MaxConns == 0 {
		config.Database.MaxConns = defaults.Database.MaxConns
	}
	if config.Database.MaxIdleConns == 0 {
		config.Database.MaxIdleConns = defaults.Database.MaxIdleConns
	}
	if config.Database.MaxLifetime == 0 {
		config.Database.MaxLifetime = defaults.Database.MaxLifetime
	}

	// Apply auth defaults
	if config.Auth.JWTSecret == "" {
		config.Auth.JWTSecret = defaults.Auth.JWTSecret
	}
	if config.Auth.JWTExpiration == 0 {
		config.Auth.JWTExpiration = defaults.Auth.JWTExpiration
	}
	if config.Auth.RefreshExpiration == 0 {
		config.Auth.RefreshExpiration = defaults.Auth.RefreshExpiration
	}
	if config.Auth.OTPExpiration == 0 {
		config.Auth.OTPExpiration = defaults.Auth.OTPExpiration
	}
	if config.Auth.PasswordMinLength == 0 {
		config.Auth.PasswordMinLength = defaults.Auth.PasswordMinLength
	}

	// Apply storage defaults
	if config.Storage.Provider == "" {
		config.Storage.Provider = defaults.Storage.Provider
	}
	if config.Storage.LocalPath == "" {
		config.Storage.LocalPath = defaults.Storage.LocalPath
	}
	if config.Storage.MaxFileSize == 0 {
		config.Storage.MaxFileSize = defaults.Storage.MaxFileSize
	}

	// Apply realtime defaults
	if config.Realtime.MaxConnections == 0 {
		config.Realtime.MaxConnections = defaults.Realtime.MaxConnections
	}
	if config.Realtime.HeartbeatInterval == 0 {
		config.Realtime.HeartbeatInterval = defaults.Realtime.HeartbeatInterval
	}
	if config.Realtime.ReadBufferSize == 0 {
		config.Realtime.ReadBufferSize = defaults.Realtime.ReadBufferSize
	}
	if config.Realtime.WriteBufferSize == 0 {
		config.Realtime.WriteBufferSize = defaults.Realtime.WriteBufferSize
	}

	// Apply dashboard defaults
	if config.Dashboard.Path == "" {
		config.Dashboard.Path = defaults.Dashboard.Path
	}
	if config.Dashboard.StaticDir == "" {
		config.Dashboard.StaticDir = defaults.Dashboard.StaticDir
	}

	// Apply logging defaults
	if config.Logging.Level == "" {
		config.Logging.Level = defaults.Logging.Level
	}
	if config.Logging.Format == "" {
		config.Logging.Format = defaults.Logging.Format
	}
	if config.Logging.Output == "" {
		config.Logging.Output = defaults.Logging.Output
	}
	if config.Logging.FilePath == "" {
		config.Logging.FilePath = defaults.Logging.FilePath
	}
	if config.Logging.MaxSize == 0 {
		config.Logging.MaxSize = defaults.Logging.MaxSize
	}
	if config.Logging.MaxBackups == 0 {
		config.Logging.MaxBackups = defaults.Logging.MaxBackups
	}
	if config.Logging.MaxAge == 0 {
		config.Logging.MaxAge = defaults.Logging.MaxAge
	}
}

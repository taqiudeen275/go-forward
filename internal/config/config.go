package config

import (
	"fmt"
	"os"
	"reflect"
	"strings"
	"time"

	"github.com/spf13/viper"
	"github.com/taqiudeen275/go-foward/pkg/errors"
)

// Config represents the complete framework configuration
type Config struct {
	Environment string         `mapstructure:"environment" yaml:"environment" json:"environment"`
	Server      ServerConfig   `mapstructure:"server" yaml:"server" json:"server"`
	Database    DatabaseConfig `mapstructure:"database" yaml:"database" json:"database"`
	Redis       RedisConfig    `mapstructure:"redis" yaml:"redis" json:"redis"`
	Auth        AuthConfig     `mapstructure:"auth" yaml:"auth" json:"auth"`
	Admin       AdminConfig    `mapstructure:"admin" yaml:"admin" json:"admin"`
	Security    SecurityConfig `mapstructure:"security" yaml:"security" json:"security"`
	Logging     LoggingConfig  `mapstructure:"logging" yaml:"logging" json:"logging"`
	Email       EmailConfig    `mapstructure:"email" yaml:"email" json:"email"`
	SMS         SMSConfig      `mapstructure:"sms" yaml:"sms" json:"sms"`
	Storage     StorageConfig  `mapstructure:"storage" yaml:"storage" json:"storage"`
	Realtime    RealtimeConfig `mapstructure:"realtime" yaml:"realtime" json:"realtime"`
	Plugin      PluginConfig   `mapstructure:"plugin" yaml:"plugin" json:"plugin"`
	Cron        CronConfig     `mapstructure:"cron" yaml:"cron" json:"cron"`
}

// ServerConfig contains HTTP server configuration
type ServerConfig struct {
	Host            string        `mapstructure:"host" yaml:"host" json:"host"`
	Port            int           `mapstructure:"port" yaml:"port" json:"port"`
	ReadTimeout     time.Duration `mapstructure:"read_timeout" yaml:"read_timeout" json:"read_timeout"`
	WriteTimeout    time.Duration `mapstructure:"write_timeout" yaml:"write_timeout" json:"write_timeout"`
	IdleTimeout     time.Duration `mapstructure:"idle_timeout" yaml:"idle_timeout" json:"idle_timeout"`
	MaxHeaderBytes  int           `mapstructure:"max_header_bytes" yaml:"max_header_bytes" json:"max_header_bytes"`
	TrustedProxies  []string      `mapstructure:"trusted_proxies" yaml:"trusted_proxies" json:"trusted_proxies"`
	EnableProfiling bool          `mapstructure:"enable_profiling" yaml:"enable_profiling" json:"enable_profiling"`
}

// DatabaseConfig contains PostgreSQL configuration
type DatabaseConfig struct {
	Host            string        `mapstructure:"host" yaml:"host" json:"host"`
	Port            int           `mapstructure:"port" yaml:"port" json:"port"`
	Name            string        `mapstructure:"name" yaml:"name" json:"name"`
	User            string        `mapstructure:"user" yaml:"user" json:"user"`
	Password        string        `mapstructure:"password" yaml:"password" json:"password"`
	SSLMode         string        `mapstructure:"ssl_mode" yaml:"ssl_mode" json:"ssl_mode"`
	MaxOpenConns    int           `mapstructure:"max_open_conns" yaml:"max_open_conns" json:"max_open_conns"`
	MaxIdleConns    int           `mapstructure:"max_idle_conns" yaml:"max_idle_conns" json:"max_idle_conns"`
	ConnMaxLifetime time.Duration `mapstructure:"conn_max_lifetime" yaml:"conn_max_lifetime" json:"conn_max_lifetime"`
	ConnMaxIdleTime time.Duration `mapstructure:"conn_max_idle_time" yaml:"conn_max_idle_time" json:"conn_max_idle_time"`
}

// RedisConfig contains Redis configuration
type RedisConfig struct {
	Host         string        `mapstructure:"host" yaml:"host" json:"host"`
	Port         int           `mapstructure:"port" yaml:"port" json:"port"`
	Password     string        `mapstructure:"password" yaml:"password" json:"password"`
	DB           int           `mapstructure:"db" yaml:"db" json:"db"`
	PoolSize     int           `mapstructure:"pool_size" yaml:"pool_size" json:"pool_size"`
	MinIdleConns int           `mapstructure:"min_idle_conns" yaml:"min_idle_conns" json:"min_idle_conns"`
	DialTimeout  time.Duration `mapstructure:"dial_timeout" yaml:"dial_timeout" json:"dial_timeout"`
	ReadTimeout  time.Duration `mapstructure:"read_timeout" yaml:"read_timeout" json:"read_timeout"`
	WriteTimeout time.Duration `mapstructure:"write_timeout" yaml:"write_timeout" json:"write_timeout"`
}

// AuthConfig contains authentication configuration
type AuthConfig struct {
	JWTSecret           string        `mapstructure:"jwt_secret" yaml:"jwt_secret" json:"jwt_secret"`
	JWTExpiration       time.Duration `mapstructure:"jwt_expiration" yaml:"jwt_expiration" json:"jwt_expiration"`
	RefreshExpiration   time.Duration `mapstructure:"refresh_expiration" yaml:"refresh_expiration" json:"refresh_expiration"`
	OTPExpiration       time.Duration `mapstructure:"otp_expiration" yaml:"otp_expiration" json:"otp_expiration"`
	OTPLength           int           `mapstructure:"otp_length" yaml:"otp_length" json:"otp_length"`
	MaxFailedAttempts   int           `mapstructure:"max_failed_attempts" yaml:"max_failed_attempts" json:"max_failed_attempts"`
	LockoutDuration     time.Duration `mapstructure:"lockout_duration" yaml:"lockout_duration" json:"lockout_duration"`
	EnableMFA           bool          `mapstructure:"enable_mfa" yaml:"enable_mfa" json:"enable_mfa"`
	EnableCookieAuth    bool          `mapstructure:"enable_cookie_auth" yaml:"enable_cookie_auth" json:"enable_cookie_auth"`
	CookieSecure        bool          `mapstructure:"cookie_secure" yaml:"cookie_secure" json:"cookie_secure"`
	CookieHTTPOnly      bool          `mapstructure:"cookie_http_only" yaml:"cookie_http_only" json:"cookie_http_only"`
	CookieSameSite      string        `mapstructure:"cookie_same_site" yaml:"cookie_same_site" json:"cookie_same_site"`
	PasswordMinLength   int           `mapstructure:"password_min_length" yaml:"password_min_length" json:"password_min_length"`
	RequireSpecialChars bool          `mapstructure:"require_special_chars" yaml:"require_special_chars" json:"require_special_chars"`
}

// AdminConfig contains admin dashboard configuration
type AdminConfig struct {
	DashboardPrefix    string        `mapstructure:"dashboard_prefix" yaml:"dashboard_prefix" json:"dashboard_prefix"`
	EnableSQLEditor    bool          `mapstructure:"enable_sql_editor" yaml:"enable_sql_editor" json:"enable_sql_editor"`
	SQLEditorRoles     []string      `mapstructure:"sql_editor_roles" yaml:"sql_editor_roles" json:"sql_editor_roles"`
	MaxQueryTimeout    time.Duration `mapstructure:"max_query_timeout" yaml:"max_query_timeout" json:"max_query_timeout"`
	EnableAuditExport  bool          `mapstructure:"enable_audit_export" yaml:"enable_audit_export" json:"enable_audit_export"`
	SessionTimeout     time.Duration `mapstructure:"session_timeout" yaml:"session_timeout" json:"session_timeout"`
	RequireMFAForAdmin bool          `mapstructure:"require_mfa_for_admin" yaml:"require_mfa_for_admin" json:"require_mfa_for_admin"`
}

// SecurityConfig contains security-related configuration
type SecurityConfig struct {
	EnableRateLimit       bool     `mapstructure:"enable_rate_limit" yaml:"enable_rate_limit" json:"enable_rate_limit"`
	RateLimitPerMinute    int      `mapstructure:"rate_limit_per_minute" yaml:"rate_limit_per_minute" json:"rate_limit_per_minute"`
	EnableIPWhitelist     bool     `mapstructure:"enable_ip_whitelist" yaml:"enable_ip_whitelist" json:"enable_ip_whitelist"`
	WhitelistedIPs        []string `mapstructure:"whitelisted_ips" yaml:"whitelisted_ips" json:"whitelisted_ips"`
	EnableCSRF            bool     `mapstructure:"enable_csrf" yaml:"enable_csrf" json:"enable_csrf"`
	CSRFSecret            string   `mapstructure:"csrf_secret" yaml:"csrf_secret" json:"csrf_secret"`
	EnableCORS            bool     `mapstructure:"enable_cors" yaml:"enable_cors" json:"enable_cors"`
	AllowedOrigins        []string `mapstructure:"allowed_origins" yaml:"allowed_origins" json:"allowed_origins"`
	EnableSecurityHeaders bool     `mapstructure:"enable_security_headers" yaml:"enable_security_headers" json:"enable_security_headers"`
	ContentSecurityPolicy string   `mapstructure:"content_security_policy" yaml:"content_security_policy" json:"content_security_policy"`
	AuditRetentionDays    int      `mapstructure:"audit_retention_days" yaml:"audit_retention_days" json:"audit_retention_days"`
}

// LoggingConfig contains logging configuration
type LoggingConfig struct {
	Level           string `mapstructure:"level" yaml:"level" json:"level"`
	Format          string `mapstructure:"format" yaml:"format" json:"format"`
	EnableAuditLog  bool   `mapstructure:"enable_audit_log" yaml:"enable_audit_log" json:"enable_audit_log"`
	AuditLogPath    string `mapstructure:"audit_log_path" yaml:"audit_log_path" json:"audit_log_path"`
	EnableAccessLog bool   `mapstructure:"enable_access_log" yaml:"enable_access_log" json:"enable_access_log"`
	AccessLogPath   string `mapstructure:"access_log_path" yaml:"access_log_path" json:"access_log_path"`
	MaxFileSize     int    `mapstructure:"max_file_size" yaml:"max_file_size" json:"max_file_size"`
	MaxBackups      int    `mapstructure:"max_backups" yaml:"max_backups" json:"max_backups"`
	MaxAge          int    `mapstructure:"max_age" yaml:"max_age" json:"max_age"`
	Compress        bool   `mapstructure:"compress" yaml:"compress" json:"compress"`
}

// EmailConfig contains email provider configuration
type EmailConfig struct {
	Provider  string            `mapstructure:"provider" yaml:"provider" json:"provider"`
	SMTPHost  string            `mapstructure:"smtp_host" yaml:"smtp_host" json:"smtp_host"`
	SMTPPort  int               `mapstructure:"smtp_port" yaml:"smtp_port" json:"smtp_port"`
	SMTPUser  string            `mapstructure:"smtp_user" yaml:"smtp_user" json:"smtp_user"`
	SMTPPass  string            `mapstructure:"smtp_pass" yaml:"smtp_pass" json:"smtp_pass"`
	FromEmail string            `mapstructure:"from_email" yaml:"from_email" json:"from_email"`
	FromName  string            `mapstructure:"from_name" yaml:"from_name" json:"from_name"`
	EnableTLS bool              `mapstructure:"enable_tls" yaml:"enable_tls" json:"enable_tls"`
	Settings  map[string]string `mapstructure:"settings" yaml:"settings" json:"settings"`
}

// SMSConfig contains SMS provider configuration
type SMSConfig struct {
	Provider  string            `mapstructure:"provider" yaml:"provider" json:"provider"`
	APIKey    string            `mapstructure:"api_key" yaml:"api_key" json:"api_key"`
	APISecret string            `mapstructure:"api_secret" yaml:"api_secret" json:"api_secret"`
	From      string            `mapstructure:"from" yaml:"from" json:"from"`
	Settings  map[string]string `mapstructure:"settings" yaml:"settings" json:"settings"`
}

// StorageConfig contains file storage configuration
type StorageConfig struct {
	Provider     string            `mapstructure:"provider" yaml:"provider" json:"provider"`
	LocalPath    string            `mapstructure:"local_path" yaml:"local_path" json:"local_path"`
	MaxFileSize  int64             `mapstructure:"max_file_size" yaml:"max_file_size" json:"max_file_size"`
	AllowedTypes []string          `mapstructure:"allowed_types" yaml:"allowed_types" json:"allowed_types"`
	S3Config     map[string]string `mapstructure:"s3_config" yaml:"s3_config" json:"s3_config"`
}

// RealtimeConfig contains real-time features configuration
type RealtimeConfig struct {
	EnableWebSocket   bool          `mapstructure:"enable_websocket" yaml:"enable_websocket" json:"enable_websocket"`
	MaxConnections    int           `mapstructure:"max_connections" yaml:"max_connections" json:"max_connections"`
	PingInterval      time.Duration `mapstructure:"ping_interval" yaml:"ping_interval" json:"ping_interval"`
	WriteWait         time.Duration `mapstructure:"write_wait" yaml:"write_wait" json:"write_wait"`
	PongWait          time.Duration `mapstructure:"pong_wait" yaml:"pong_wait" json:"pong_wait"`
	EnablePresence    bool          `mapstructure:"enable_presence" yaml:"enable_presence" json:"enable_presence"`
	EnableDBStreaming bool          `mapstructure:"enable_db_streaming" yaml:"enable_db_streaming" json:"enable_db_streaming"`
}

// PluginConfig contains plugin system configuration
type PluginConfig struct {
	EnablePlugins  bool     `mapstructure:"enable_plugins" yaml:"enable_plugins" json:"enable_plugins"`
	PluginDir      string   `mapstructure:"plugin_dir" yaml:"plugin_dir" json:"plugin_dir"`
	AllowedPlugins []string `mapstructure:"allowed_plugins" yaml:"allowed_plugins" json:"allowed_plugins"`
	EnableSandbox  bool     `mapstructure:"enable_sandbox" yaml:"enable_sandbox" json:"enable_sandbox"`
	MaxMemoryMB    int      `mapstructure:"max_memory_mb" yaml:"max_memory_mb" json:"max_memory_mb"`
	MaxCPUPercent  int      `mapstructure:"max_cpu_percent" yaml:"max_cpu_percent" json:"max_cpu_percent"`
}

// CronConfig contains cron job configuration
type CronConfig struct {
	EnableCron     bool          `mapstructure:"enable_cron" yaml:"enable_cron" json:"enable_cron"`
	MaxConcurrent  int           `mapstructure:"max_concurrent" yaml:"max_concurrent" json:"max_concurrent"`
	DefaultTimeout time.Duration `mapstructure:"default_timeout" yaml:"default_timeout" json:"default_timeout"`
	LogRetention   int           `mapstructure:"log_retention" yaml:"log_retention" json:"log_retention"`
	EnableWebUI    bool          `mapstructure:"enable_web_ui" yaml:"enable_web_ui" json:"enable_web_ui"`
}

// ValidationResult contains configuration validation results
type ValidationResult struct {
	Valid    bool     `json:"valid"`
	Errors   []string `json:"errors"`
	Warnings []string `json:"warnings"`
}

// ConfigReflection contains information about configuration options
type ConfigReflection struct {
	Sections map[string]SectionInfo `json:"sections"`
}

// SectionInfo contains information about a configuration section
type SectionInfo struct {
	Name        string               `json:"name"`
	Description string               `json:"description"`
	Fields      map[string]FieldInfo `json:"fields"`
}

// FieldInfo contains information about a configuration field
type FieldInfo struct {
	Name        string      `json:"name"`
	Type        string      `json:"type"`
	Description string      `json:"description"`
	Default     interface{} `json:"default"`
	Required    bool        `json:"required"`
	Sensitive   bool        `json:"sensitive"`
}

// Load loads configuration from file and environment variables
func Load() (*Config, error) {
	viper.SetConfigName("config")
	viper.SetConfigType("yaml")
	viper.AddConfigPath(".")
	viper.AddConfigPath("./config")
	viper.AddConfigPath("/etc/go-forward")

	// Set defaults
	setDefaults()

	// Enable environment variable support
	viper.AutomaticEnv()
	viper.SetEnvPrefix("GF")
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))

	// Read config file
	if err := viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return nil, errors.NewConfigError(fmt.Sprintf("Failed to read config file: %v", err))
		}
		// Config file not found is OK, we'll use defaults and env vars
	}

	var config Config
	if err := viper.Unmarshal(&config); err != nil {
		return nil, errors.NewConfigError(fmt.Sprintf("Failed to unmarshal config: %v", err))
	}

	// Validate configuration
	if result := ValidateConfig(&config); !result.Valid {
		return nil, errors.NewConfigError(fmt.Sprintf("Configuration validation failed: %v", result.Errors))
	}

	return &config, nil
}

// setDefaults sets default configuration values
func setDefaults() {
	// Server defaults
	viper.SetDefault("environment", "development")
	viper.SetDefault("server.host", "localhost")
	viper.SetDefault("server.port", 8080)
	viper.SetDefault("server.read_timeout", "30s")
	viper.SetDefault("server.write_timeout", "30s")
	viper.SetDefault("server.idle_timeout", "60s")
	viper.SetDefault("server.max_header_bytes", 1048576) // 1MB

	// Database defaults
	viper.SetDefault("database.host", "localhost")
	viper.SetDefault("database.port", 5432)
	viper.SetDefault("database.name", "goforward")
	viper.SetDefault("database.user", "postgres")
	viper.SetDefault("database.ssl_mode", "disable")
	viper.SetDefault("database.max_open_conns", 25)
	viper.SetDefault("database.max_idle_conns", 5)
	viper.SetDefault("database.conn_max_lifetime", "5m")
	viper.SetDefault("database.conn_max_idle_time", "5m")

	// Redis defaults
	viper.SetDefault("redis.host", "localhost")
	viper.SetDefault("redis.port", 6379)
	viper.SetDefault("redis.db", 0)
	viper.SetDefault("redis.pool_size", 10)
	viper.SetDefault("redis.min_idle_conns", 2)
	viper.SetDefault("redis.dial_timeout", "5s")
	viper.SetDefault("redis.read_timeout", "3s")
	viper.SetDefault("redis.write_timeout", "3s")

	// Auth defaults
	viper.SetDefault("auth.jwt_expiration", "24h")
	viper.SetDefault("auth.refresh_expiration", "168h") // 7 days
	viper.SetDefault("auth.otp_expiration", "10m")
	viper.SetDefault("auth.otp_length", 6)
	viper.SetDefault("auth.max_failed_attempts", 5)
	viper.SetDefault("auth.lockout_duration", "15m")
	viper.SetDefault("auth.enable_mfa", false)
	viper.SetDefault("auth.enable_cookie_auth", true)
	viper.SetDefault("auth.cookie_secure", true)
	viper.SetDefault("auth.cookie_http_only", true)
	viper.SetDefault("auth.cookie_same_site", "Strict")
	viper.SetDefault("auth.password_min_length", 8)
	viper.SetDefault("auth.require_special_chars", true)

	// Admin defaults
	viper.SetDefault("admin.dashboard_prefix", "/_")
	viper.SetDefault("admin.enable_sql_editor", true)
	viper.SetDefault("admin.sql_editor_roles", []string{"system_admin"})
	viper.SetDefault("admin.max_query_timeout", "30s")
	viper.SetDefault("admin.enable_audit_export", true)
	viper.SetDefault("admin.session_timeout", "8h")
	viper.SetDefault("admin.require_mfa_for_admin", true)

	// Security defaults
	viper.SetDefault("security.enable_rate_limit", true)
	viper.SetDefault("security.rate_limit_per_minute", 60)
	viper.SetDefault("security.enable_ip_whitelist", false)
	viper.SetDefault("security.enable_csrf", true)
	viper.SetDefault("security.enable_cors", true)
	viper.SetDefault("security.allowed_origins", []string{"*"})
	viper.SetDefault("security.enable_security_headers", true)
	viper.SetDefault("security.audit_retention_days", 90)

	// Logging defaults
	viper.SetDefault("logging.level", "info")
	viper.SetDefault("logging.format", "json")
	viper.SetDefault("logging.enable_audit_log", true)
	viper.SetDefault("logging.enable_access_log", true)
	viper.SetDefault("logging.max_file_size", 100) // MB
	viper.SetDefault("logging.max_backups", 10)
	viper.SetDefault("logging.max_age", 30) // days
	viper.SetDefault("logging.compress", true)

	// Email defaults
	viper.SetDefault("email.provider", "smtp")
	viper.SetDefault("email.smtp_port", 587)
	viper.SetDefault("email.enable_tls", true)

	// SMS defaults
	viper.SetDefault("sms.provider", "arkesel")

	// Storage defaults
	viper.SetDefault("storage.provider", "local")
	viper.SetDefault("storage.local_path", "./storage")
	viper.SetDefault("storage.max_file_size", 10485760) // 10MB
	viper.SetDefault("storage.allowed_types", []string{"image/jpeg", "image/png", "image/gif", "application/pdf"})

	// Realtime defaults
	viper.SetDefault("realtime.enable_websocket", true)
	viper.SetDefault("realtime.max_connections", 1000)
	viper.SetDefault("realtime.ping_interval", "54s")
	viper.SetDefault("realtime.write_wait", "10s")
	viper.SetDefault("realtime.pong_wait", "60s")
	viper.SetDefault("realtime.enable_presence", true)
	viper.SetDefault("realtime.enable_db_streaming", true)

	// Plugin defaults
	viper.SetDefault("plugin.enable_plugins", false)
	viper.SetDefault("plugin.plugin_dir", "./plugins")
	viper.SetDefault("plugin.enable_sandbox", true)
	viper.SetDefault("plugin.max_memory_mb", 128)
	viper.SetDefault("plugin.max_cpu_percent", 50)

	// Cron defaults
	viper.SetDefault("cron.enable_cron", true)
	viper.SetDefault("cron.max_concurrent", 5)
	viper.SetDefault("cron.default_timeout", "30m")
	viper.SetDefault("cron.log_retention", 30) // days
	viper.SetDefault("cron.enable_web_ui", true)
}

// ValidateConfig validates the configuration
func ValidateConfig(config *Config) *ValidationResult {
	result := &ValidationResult{
		Valid:    true,
		Errors:   []string{},
		Warnings: []string{},
	}

	// Validate server config
	if config.Server.Port < 1 || config.Server.Port > 65535 {
		result.Valid = false
		result.Errors = append(result.Errors, "server.port must be between 1 and 65535")
	}

	// Validate database config
	if config.Database.Name == "" {
		result.Valid = false
		result.Errors = append(result.Errors, "database.name is required")
	}

	// Validate auth config
	if config.Auth.JWTSecret == "" {
		result.Valid = false
		result.Errors = append(result.Errors, "auth.jwt_secret is required")
	}

	if len(config.Auth.JWTSecret) < 32 {
		result.Warnings = append(result.Warnings, "auth.jwt_secret should be at least 32 characters for security")
	}

	// Validate admin config
	if !strings.HasPrefix(config.Admin.DashboardPrefix, "/") {
		result.Valid = false
		result.Errors = append(result.Errors, "admin.dashboard_prefix must start with '/'")
	}

	// Environment-specific validations
	if config.Environment == "production" {
		if config.Auth.JWTSecret == "your-secret-key" {
			result.Valid = false
			result.Errors = append(result.Errors, "auth.jwt_secret must be changed from default in production")
		}

		if !config.Auth.CookieSecure {
			result.Warnings = append(result.Warnings, "auth.cookie_secure should be true in production")
		}

		if config.Logging.Level == "debug" {
			result.Warnings = append(result.Warnings, "logging.level should not be debug in production")
		}
	}

	return result
}

// GetReflection returns configuration reflection information
func GetReflection() *ConfigReflection {
	reflection := &ConfigReflection{
		Sections: make(map[string]SectionInfo),
	}

	configType := reflect.TypeOf(Config{})
	for i := 0; i < configType.NumField(); i++ {
		field := configType.Field(i)
		sectionName := field.Tag.Get("mapstructure")

		if sectionName != "" {
			sectionInfo := SectionInfo{
				Name:   sectionName,
				Fields: make(map[string]FieldInfo),
			}

			// Get fields for this section
			sectionType := field.Type
			for j := 0; j < sectionType.NumField(); j++ {
				sectionField := sectionType.Field(j)
				fieldName := sectionField.Tag.Get("mapstructure")

				if fieldName != "" {
					fieldInfo := FieldInfo{
						Name: fieldName,
						Type: sectionField.Type.String(),
					}

					// Check if field is sensitive (contains password, secret, key)
					lowerName := strings.ToLower(fieldName)
					if strings.Contains(lowerName, "password") ||
						strings.Contains(lowerName, "secret") ||
						strings.Contains(lowerName, "key") {
						fieldInfo.Sensitive = true
					}

					sectionInfo.Fields[fieldName] = fieldInfo
				}
			}

			reflection.Sections[sectionName] = sectionInfo
		}
	}

	return reflection
}

// BackupConfig creates a backup of the current configuration
func BackupConfig() (string, error) {
	configFile := viper.ConfigFileUsed()
	if configFile == "" {
		return "", errors.NewConfigError("No config file found to backup")
	}

	backupPath := fmt.Sprintf("%s.backup.%d", configFile, time.Now().Unix())

	// Read original file
	data, err := os.ReadFile(configFile)
	if err != nil {
		return "", errors.NewConfigError(fmt.Sprintf("Failed to read config file: %v", err))
	}

	// Write backup
	if err := os.WriteFile(backupPath, data, 0644); err != nil {
		return "", errors.NewConfigError(fmt.Sprintf("Failed to write backup file: %v", err))
	}

	return backupPath, nil
}

// RestoreConfig restores configuration from a backup file
func RestoreConfig(backupPath string) error {
	configFile := viper.ConfigFileUsed()
	if configFile == "" {
		return errors.NewConfigError("No config file found to restore to")
	}

	// Check if backup file exists
	if _, err := os.Stat(backupPath); os.IsNotExist(err) {
		return errors.NewConfigError(fmt.Sprintf("Backup file does not exist: %s", backupPath))
	}

	// Read backup file
	data, err := os.ReadFile(backupPath)
	if err != nil {
		return errors.NewConfigError(fmt.Sprintf("Failed to read backup file: %v", err))
	}

	// Write to config file
	if err := os.WriteFile(configFile, data, 0644); err != nil {
		return errors.NewConfigError(fmt.Sprintf("Failed to restore config file: %v", err))
	}

	return nil
}

// GetConnectionString returns the database connection string
func (c *Config) GetConnectionString() string {
	return fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=%s",
		c.Database.Host,
		c.Database.Port,
		c.Database.User,
		c.Database.Password,
		c.Database.Name,
		c.Database.SSLMode,
	)
}

// GetRedisAddr returns the Redis address
func (c *Config) GetRedisAddr() string {
	return fmt.Sprintf("%s:%d", c.Redis.Host, c.Redis.Port)
}

// IsProduction returns true if running in production environment
func (c *Config) IsProduction() bool {
	return c.Environment == "production"
}

// IsDevelopment returns true if running in development environment
func (c *Config) IsDevelopment() bool {
	return c.Environment == "development"
}

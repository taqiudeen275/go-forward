package commands

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/taqiudeen275/go-foward/internal/auth"
	"github.com/taqiudeen275/go-foward/internal/config"
	"github.com/taqiudeen275/go-foward/internal/database"
)

// Environment represents the deployment environment
type Environment string

const (
	EnvDevelopment Environment = "development"
	EnvStaging     Environment = "staging"
	EnvProduction  Environment = "production"
)

// BaseCommand provides common functionality for all admin commands
type BaseCommand struct {
	DB          *database.DB
	db          *pgxpool.Pool
	AuthService *auth.Service
	rbacEngine  auth.RBACEngine
	Config      *config.Config
	Environment Environment
	Verbose     bool
	AutoYes     bool
}

// Colors for CLI output
var (
	ColorSuccess = color.New(color.FgGreen, color.Bold)
	ColorError   = color.New(color.FgRed, color.Bold)
	ColorWarning = color.New(color.FgYellow, color.Bold)
	ColorInfo    = color.New(color.FgCyan)
	ColorHeader  = color.New(color.FgHiBlue, color.Bold)
	ColorCommand = color.New(color.FgHiGreen)
)

// InitializeBase initializes the base command with database connection and services
func InitializeBase(cmd *cobra.Command) (*BaseCommand, error) {
	// Initialize configuration
	cfg, err := loadConfig(cmd)
	if err != nil {
		return nil, fmt.Errorf("failed to load config: %w", err)
	}

	// Detect environment
	env := detectEnvironment(cmd, cfg)

	// Get flags
	verbose, _ := cmd.Flags().GetBool("verbose")
	autoYes, _ := cmd.Flags().GetBool("yes")

	// Convert config.DatabaseConfig to database.Config
	dbConfig := &database.Config{
		Host:            cfg.Database.Host,
		Port:            int(cfg.Database.Port),
		Name:            cfg.Database.Name,
		User:            cfg.Database.User,
		Password:        cfg.Database.Password,
		SSLMode:         cfg.Database.SSLMode,
		MaxConns:        int32(cfg.Database.MaxConns),
		MinConns:        5, // Default
		MaxConnLifetime: cfg.Database.MaxLifetime,
		MaxConnIdleTime: 30 * time.Minute, // Default
	}

	// Initialize database
	db, err := database.New(dbConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to database: %w", err)
	}

	// Initialize auth service
	authService := auth.NewServiceWithConfig(
		db,
		cfg.Auth.JWTSecret,
		cfg.Auth.JWTExpiration,
		cfg.Auth.RefreshExpiration,
	)

	base := &BaseCommand{
		DB:          db,
		AuthService: authService,
		Config:      cfg,
		Environment: env,
		Verbose:     verbose,
		AutoYes:     autoYes,
	}

	return base, nil
}

// loadConfig loads the configuration from file or environment
func loadConfig(cmd *cobra.Command) (*config.Config, error) {
	configFile, _ := cmd.Flags().GetString("config")

	if configFile != "" {
		viper.SetConfigFile(configFile)
	} else {
		// Look for config in common locations
		viper.SetConfigName("config")
		viper.SetConfigType("yaml")
		viper.AddConfigPath(".")
		viper.AddConfigPath("$HOME/.go-forward")
		viper.AddConfigPath("/etc/go-forward")
	}

	// Enable environment variable support
	viper.AutomaticEnv()
	viper.SetEnvPrefix("GO_FORWARD")
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))

	// Read config file
	if err := viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return nil, fmt.Errorf("error reading config file: %w", err)
		}
		// Config file not found, continue with environment variables and defaults
	}

	// Unmarshal config
	var cfg config.Config
	if err := viper.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("unable to decode config: %w", err)
	}

	return &cfg, nil
}

// detectEnvironment determines the current deployment environment
func detectEnvironment(cmd *cobra.Command, cfg *config.Config) Environment {
	// Check for explicit override
	if envOverride, _ := cmd.Flags().GetString("env"); envOverride != "" {
		switch strings.ToLower(envOverride) {
		case "dev", "development":
			return EnvDevelopment
		case "stage", "staging":
			return EnvStaging
		case "prod", "production":
			return EnvProduction
		}
	}

	// Check environment variable
	if env := os.Getenv("GO_FORWARD_ENV"); env != "" {
		switch strings.ToLower(env) {
		case "development", "dev":
			return EnvDevelopment
		case "staging", "stage":
			return EnvStaging
		case "production", "prod":
			return EnvProduction
		}
	}

	// Check config file - for now we'll detect from other indicators
	// since the config struct doesn't have Environment field yet

	// Check for production indicators
	if isProductionEnvironment() {
		return EnvProduction
	}

	// Default to development
	return EnvDevelopment
}

// isProductionEnvironment checks for common production environment indicators
func isProductionEnvironment() bool {
	productionIndicators := []string{
		"KUBERNETES_SERVICE_HOST",
		"DOCKER_CONTAINER",
		"AWS_EXECUTION_ENV",
		"HEROKU_APP_NAME",
		"CF_INSTANCE_INDEX",
		"GAE_ENV",
	}

	for _, indicator := range productionIndicators {
		if os.Getenv(indicator) != "" {
			return true
		}
	}

	// Check hostname patterns
	hostname, _ := os.Hostname()
	productionPatterns := []string{
		"prod",
		"production",
		"live",
		"app-",
		"web-",
	}

	for _, pattern := range productionPatterns {
		if strings.Contains(strings.ToLower(hostname), pattern) {
			return true
		}
	}

	return false
}

// PrintHeader prints a formatted header
func (b *BaseCommand) PrintHeader(title string) {
	ColorHeader.Printf("\n=== %s ===\n", title)
}

// PrintSuccess prints a success message
func (b *BaseCommand) PrintSuccess(message string) {
	ColorSuccess.Printf("✓ %s\n", message)
}

// PrintError prints an error message
func (b *BaseCommand) PrintError(message string) {
	ColorError.Printf("✗ %s\n", message)
}

// PrintWarning prints a warning message
func (b *BaseCommand) PrintWarning(message string) {
	ColorWarning.Printf("⚠ %s\n", message)
}

// PrintInfo prints an info message
func (b *BaseCommand) PrintInfo(message string) {
	ColorInfo.Printf("ℹ %s\n", message)
}

// PrintVerbose prints a verbose message (only if verbose mode is enabled)
func (b *BaseCommand) PrintVerbose(message string) {
	if b.Verbose {
		fmt.Printf("[VERBOSE] %s\n", message)
	}
}

// Confirm prompts the user for confirmation
func (b *BaseCommand) Confirm(message string) bool {
	if b.AutoYes {
		b.PrintInfo(fmt.Sprintf("%s (auto-confirmed)", message))
		return true
	}

	fmt.Printf("%s [y/N]: ", message)
	reader := bufio.NewReader(os.Stdin)
	response, _ := reader.ReadString('\n')
	response = strings.TrimSpace(strings.ToLower(response))

	return response == "y" || response == "yes"
}

// ConfirmDangerous prompts for confirmation of dangerous operations
func (b *BaseCommand) ConfirmDangerous(message string, confirmText string) bool {
	if b.Environment == EnvProduction {
		ColorWarning.Printf("\n🚨 PRODUCTION ENVIRONMENT DETECTED 🚨\n")
		ColorWarning.Printf("This operation is potentially dangerous in production.\n\n")
	}

	if b.AutoYes && b.Environment == EnvProduction {
		b.PrintError("Auto-confirmation (--yes) is disabled for dangerous operations in production")
		return false
	}

	if b.AutoYes {
		b.PrintInfo(fmt.Sprintf("%s (auto-confirmed)", message))
		return true
	}

	ColorWarning.Printf("%s\n", message)
	fmt.Printf("Type '%s' to confirm: ", confirmText)

	reader := bufio.NewReader(os.Stdin)
	response, _ := reader.ReadString('\n')
	response = strings.TrimSpace(response)

	return response == confirmText
}

// RequireProductionConfirmation enforces additional security for production
func (b *BaseCommand) RequireProductionConfirmation(operation string) error {
	if b.Environment != EnvProduction {
		return nil
	}

	b.PrintHeader("Production Safety Check")
	b.PrintWarning(fmt.Sprintf("You are about to perform: %s", operation))
	b.PrintWarning("This operation will affect a PRODUCTION environment.")

	if !b.ConfirmDangerous("Are you sure you want to proceed?", "I UNDERSTAND THE RISKS") {
		return fmt.Errorf("operation cancelled by user")
	}

	// Additional confirmation for critical operations
	criticalOps := []string{"create-system-admin", "emergency-access", "bootstrap"}
	for _, op := range criticalOps {
		if strings.Contains(strings.ToLower(operation), op) {
			if !b.ConfirmDangerous("This is a critical operation. Final confirmation required.", "PROCEED") {
				return fmt.Errorf("operation cancelled by user")
			}
			break
		}
	}

	return nil
}

// ValidateEmail validates an email address format
func (b *BaseCommand) ValidateEmail(email string) error {
	if email == "" {
		return fmt.Errorf("email is required")
	}
	// Basic email validation - you might want to use a proper validator
	if !strings.Contains(email, "@") || !strings.Contains(email, ".") {
		return fmt.Errorf("invalid email format")
	}
	return nil
}

// ValidatePassword validates password strength
func (b *BaseCommand) ValidatePassword(password string) error {
	if len(password) < 8 {
		return fmt.Errorf("password must be at least 8 characters long")
	}

	hasUpper := false
	hasLower := false
	hasDigit := false
	hasSpecial := false

	for _, char := range password {
		switch {
		case char >= 'A' && char <= 'Z':
			hasUpper = true
		case char >= 'a' && char <= 'z':
			hasLower = true
		case char >= '0' && char <= '9':
			hasDigit = true
		default:
			hasSpecial = true
		}
	}

	if !hasUpper {
		return fmt.Errorf("password must contain at least one uppercase letter")
	}
	if !hasLower {
		return fmt.Errorf("password must contain at least one lowercase letter")
	}
	if !hasDigit {
		return fmt.Errorf("password must contain at least one digit")
	}
	if !hasSpecial {
		return fmt.Errorf("password must contain at least one special character")
	}

	return nil
}

// CheckDatabaseConnection verifies database connectivity
func (b *BaseCommand) CheckDatabaseConnection(ctx context.Context) error {
	b.PrintVerbose("Checking database connection...")

	if err := b.DB.Ping(ctx); err != nil {
		return fmt.Errorf("database connection failed: %w", err)
	}

	// Check if admin tables exist
	var tableCount int
	err := b.DB.Pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM information_schema.tables
		WHERE table_schema = 'public'
		AND table_name IN ('admin_roles', 'user_admin_roles', 'user_mfa_settings')
	`).Scan(&tableCount)
	if err != nil {
		return fmt.Errorf("failed to check admin tables: %w", err)
	}

	if tableCount < 3 {
		return fmt.Errorf("admin security tables not found - please run database migrations first")
	}

	b.PrintVerbose("Database connection and schema validated")
	return nil
}

// GetCurrentUser gets information about the current system user (not database user)
func (b *BaseCommand) GetCurrentUser() (string, error) {
	if user := os.Getenv("USER"); user != "" {
		return user, nil
	}
	if user := os.Getenv("USERNAME"); user != "" {
		return user, nil
	}
	return "unknown", nil
}

// LogAdminAction logs an administrative action for audit purposes
func (b *BaseCommand) LogAdminAction(ctx context.Context, userID, action, resourceType, resourceID string, details map[string]interface{}) error {
	if b.DB == nil {
		return nil // Skip if no database connection
	}

	_, err := b.DB.Pool.Exec(ctx, `
		SELECT log_admin_action($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
	`, userID, action, resourceType, resourceID, "", details, nil, nil, nil, true, nil)

	return err
}

// getCurrentAdminUser gets current admin user info (placeholder)
func (b *BaseCommand) getCurrentAdminUser() (*auth.User, error) {
	// TODO: Implement actual admin user retrieval
	email := "admin@example.com"
	return &auth.User{
		ID:    "admin-user-1",
		Email: &email,
	}, nil
}

// getCurrentAdminInfo gets current admin info for audit logging
func (b *BaseCommand) getCurrentAdminInfo() *auth.User {
	// TODO: Implement actual admin info retrieval
	email := "admin@example.com"
	return &auth.User{
		ID:    "admin-user-1",
		Email: &email,
	}
}

// promptString prompts for a string input
func (b *BaseCommand) promptString(prompt string) string {
	fmt.Printf("%s: ", prompt)
	var input string
	fmt.Scanln(&input)
	return strings.TrimSpace(input)
}

// promptPassword prompts for a password input
func (b *BaseCommand) promptPassword(prompt string) string {
	fmt.Printf("%s: ", prompt)
	var password string
	fmt.Scanln(&password)
	return strings.TrimSpace(password)
}

// promptSecure prompts for a password with hidden input
func (b *BaseCommand) promptSecure(prompt string) string {
	fmt.Printf("%s: ", prompt)

	// For now, use basic input - in production, use syscall for hidden input
	var password string
	fmt.Scanln(&password)
	return strings.TrimSpace(password)
}

// promptConfirm prompts for a yes/no confirmation
func (b *BaseCommand) promptConfirm(prompt string) bool {
	if b.AutoYes {
		return true
	}

	fmt.Printf("%s (y/N): ", prompt)
	var input string
	fmt.Scanln(&input)
	input = strings.ToLower(strings.TrimSpace(input))
	return input == "y" || input == "yes"
}

// initializeServices initializes database and services (placeholder)
func (b *BaseCommand) initializeServices() error {
	// TODO: Initialize actual services
	return nil
}

// Close cleans up resources
func (b *BaseCommand) Close() error {
	if b.DB != nil {
		b.DB.Close()
		return nil
	}
	return nil
}

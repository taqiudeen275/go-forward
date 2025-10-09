package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/spf13/cobra"
	"github.com/taqiudeen275/go-foward/internal/auth"
	"github.com/taqiudeen275/go-foward/internal/config"
	"github.com/taqiudeen275/go-foward/internal/database"
)

var (
	configPath string
	verbose    bool
	dryRun     bool
	format     string
)

// CLI represents the admin CLI application
type CLI struct {
	config           *config.Config
	db               *database.DB
	authService      auth.AuthServiceInterface
	adminManager     *AdminManager
	bootstrapService *BootstrapService
	envDetector      *EnvironmentDetector
}

func main() {
	rootCmd := &cobra.Command{
		Use:   "admin",
		Short: "Go Forward Framework Admin Management CLI",
		Long: `Admin Management CLI for Go Forward Framework

This CLI provides commands for managing system administrators, 
environment-specific security policies, and bootstrap operations.`,
		PersistentPreRunE: initializeCLI,
	}

	// Global flags
	rootCmd.PersistentFlags().StringVar(&configPath, "config", "", "Path to configuration file")
	rootCmd.PersistentFlags().BoolVar(&verbose, "verbose", false, "Enable verbose output")
	rootCmd.PersistentFlags().BoolVar(&dryRun, "dry-run", false, "Show what would be done without executing")
	rootCmd.PersistentFlags().StringVar(&format, "format", "table", "Output format: table, json")

	// Add subcommands
	rootCmd.AddCommand(createAdminCommands())
	rootCmd.AddCommand(createEnvironmentCommands())
	rootCmd.AddCommand(createBootstrapCommands())

	if err := rootCmd.Execute(); err != nil {
		log.Fatalf("Command failed: %v", err)
	}
}

// initializeCLI initializes the CLI with database and services
func initializeCLI(cmd *cobra.Command, args []string) error {
	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("failed to load configuration: %w", err)
	}

	// Convert config to database config
	dbConfig := &database.Config{
		Host:            cfg.Database.Host,
		Port:            cfg.Database.Port,
		Name:            cfg.Database.Name,
		User:            cfg.Database.User,
		Password:        cfg.Database.Password,
		SSLMode:         cfg.Database.SSLMode,
		MaxConns:        int32(cfg.Database.MaxConns),
		MinConns:        5,
		MaxConnLifetime: cfg.Database.MaxLifetime,
		MaxConnIdleTime: 30 * time.Minute,
	}

	// Initialize database
	db, err := database.New(dbConfig)
	if err != nil {
		return fmt.Errorf("failed to initialize database: %w", err)
	}

	// Initialize services
	userRepo := auth.NewUserRepository(db)
	authService := auth.NewService(db)
	adminRepo := auth.NewAdminRepository(db)
	mfaRepo := auth.NewMFARepository(db)
	jwtManager := auth.NewJWTManager(cfg.Auth.JWTSecret, cfg.Auth.JWTExpiration, cfg.Auth.RefreshExpiration)

	// Create CLI instance and store in command context
	cli := &CLI{
		config:           cfg,
		db:               db,
		authService:      authService,
		adminManager:     NewAdminManager(userRepo, adminRepo, mfaRepo, jwtManager),
		bootstrapService: NewBootstrapService(cfg, db, authService),
		envDetector:      NewEnvironmentDetector(cfg),
	}

	cmd.SetContext(context.WithValue(cmd.Context(), "cli", cli))
	return nil
}

// getCLI retrieves the CLI instance from command context
func getCLI(cmd *cobra.Command) *CLI {
	return cmd.Context().Value("cli").(*CLI)
}

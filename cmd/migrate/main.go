package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/taqiudeen275/go-foward/internal/config"
	"github.com/taqiudeen275/go-foward/internal/database"
)

const (
	usageText = `Migration CLI for Go Forward Framework

Usage:
  migrate [command] [options]

Commands:
  up                    Apply all pending migrations
  down                  Rollback one migration
  to <version>          Migrate to specific version (up or down)
  rollback <version>    Rollback to specific version
  create <name>         Create a new migration file
  create-from-template <name> <template> [params]  Create migration from template
  status                Show migration status
  history               Show migration history
  version               Show current migration version
  validate              Validate migration files
  repair                Repair dirty migration state
  templates             List available templates

Options:
  -migrations string    Path to migrations directory (default "./migrations")
  -format string        Output format: table, json (default "table")
  -verbose              Enable verbose output
  -dry-run              Show what would be done without executing

Examples:
  migrate up                                    # Apply all pending migrations
  migrate down                                  # Rollback one migration
  migrate to 5                                  # Migrate to version 5
  migrate rollback 3                            # Rollback to version 3
  migrate create add_users_table                # Create new migration
  migrate create-from-template add_users_table create_table TableName=users
  migrate status                                # Show migration status
  migrate history                               # Show migration history
`
)

type CLI struct {
	migrationService *database.MigrationService
	config           *config.Config
	verbose          bool
	dryRun           bool
	format           string
}

func main() {
	var (
		migrationsPath = flag.String("migrations", "./migrations", "Path to migrations directory")
		format         = flag.String("format", "table", "Output format: table, json")
		verbose        = flag.Bool("verbose", false, "Enable verbose output")
		dryRun         = flag.Bool("dry-run", false, "Show what would be done without executing")
		help           = flag.Bool("help", false, "Show help")
	)
	flag.Parse()

	if *help || len(os.Args) < 2 {
		fmt.Print(usageText)
		os.Exit(0)
	}

	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
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
		log.Fatalf("Failed to initialize database: %v", err)
	}
	defer db.Close()

	// Create migration service
	migrationService := database.NewMigrationService(db, *migrationsPath)

	// Create CLI instance
	cli := &CLI{
		migrationService: migrationService,
		config:           cfg,
		verbose:          *verbose,
		dryRun:           *dryRun,
		format:           *format,
	}

	// Parse command
	args := flag.Args()
	if len(args) == 0 {
		fmt.Print(usageText)
		os.Exit(1)
	}

	command := args[0]
	commandArgs := args[1:]

	// Execute command
	if err := cli.executeCommand(command, commandArgs); err != nil {
		log.Fatalf("Command failed: %v", err)
	}
}

func (cli *CLI) executeCommand(command string, args []string) error {
	switch command {
	case "up":
		return cli.migrateUp()
	case "down":
		return cli.migrateDown()
	case "to":
		if len(args) < 1 {
			return fmt.Errorf("version required for 'to' command")
		}
		version, err := strconv.ParseUint(args[0], 10, 32)
		if err != nil {
			return fmt.Errorf("invalid version: %v", err)
		}
		return cli.migrateTo(uint(version))
	case "rollback":
		if len(args) < 1 {
			return fmt.Errorf("version required for 'rollback' command")
		}
		version, err := strconv.ParseUint(args[0], 10, 32)
		if err != nil {
			return fmt.Errorf("invalid version: %v", err)
		}
		return cli.rollbackTo(uint(version))
	case "create":
		if len(args) < 1 {
			return fmt.Errorf("migration name required for 'create' command")
		}
		return cli.createMigration(args[0])
	case "create-from-template":
		if len(args) < 2 {
			return fmt.Errorf("migration name and template required for 'create-from-template' command")
		}
		return cli.createFromTemplate(args[0], args[1], args[2:])
	case "status":
		return cli.showStatus()
	case "history":
		return cli.showHistory()
	case "version":
		return cli.showVersion()
	case "validate":
		return cli.validateMigrations()
	case "repair":
		return cli.repairDirtyState()
	case "templates":
		return cli.listTemplates()
	default:
		return fmt.Errorf("unknown command: %s", command)
	}
}

func (cli *CLI) migrateUp() error {
	if cli.verbose {
		fmt.Println("Applying all pending migrations...")
	}

	if cli.dryRun {
		ctx := context.Background()
		migrations, err := cli.migrationService.GetMigrationStatus(ctx)
		if err != nil {
			return fmt.Errorf("failed to get migration status: %w", err)
		}

		fmt.Println("Migrations that would be applied:")
		for _, migration := range migrations {
			if !migration.Applied {
				fmt.Printf("  %06d_%s\n", migration.Version, migration.Name)
			}
		}
		return nil
	}

	results, err := cli.migrationService.ApplyMigrationsWithCallback(func(result *database.MigrationResult) {
		if cli.verbose {
			if result.Success {
				fmt.Printf("✓ Applied migration %d_%s (took %v)\n", result.Version, result.Name, result.Duration)
			} else {
				fmt.Printf("✗ Failed migration %d_%s: %s\n", result.Version, result.Name, result.Error)
			}
		}
	})

	if err != nil {
		return fmt.Errorf("failed to apply migrations: %w", err)
	}

	cli.printResults(results)
	return nil
}

func (cli *CLI) migrateDown() error {
	if cli.verbose {
		fmt.Println("Rolling back one migration...")
	}

	if cli.dryRun {
		version, _, err := cli.migrationService.GetCurrentVersion()
		if err != nil {
			return fmt.Errorf("failed to get current version: %w", err)
		}
		fmt.Printf("Would rollback migration version %d\n", version)
		return nil
	}

	result, err := cli.migrationService.RollbackOne()
	if err != nil {
		return fmt.Errorf("failed to rollback migration: %w", err)
	}

	cli.printResults([]*database.MigrationResult{result})
	return nil
}

func (cli *CLI) migrateTo(targetVersion uint) error {
	currentVersion, _, err := cli.migrationService.GetCurrentVersion()
	if err != nil {
		return fmt.Errorf("failed to get current version: %w", err)
	}

	if cli.verbose {
		fmt.Printf("Migrating from version %d to %d...\n", currentVersion, targetVersion)
	}

	if cli.dryRun {
		if targetVersion > currentVersion {
			fmt.Printf("Would apply migrations up to version %d\n", targetVersion)
		} else if targetVersion < currentVersion {
			fmt.Printf("Would rollback to version %d\n", targetVersion)
		} else {
			fmt.Println("Already at target version")
		}
		return nil
	}

	if targetVersion > currentVersion {
		// Apply migrations up to target version
		result, err := cli.migrationService.ApplyMigration(targetVersion)
		if err != nil {
			return fmt.Errorf("failed to migrate to version %d: %w", targetVersion, err)
		}
		cli.printResults([]*database.MigrationResult{result})
	} else if targetVersion < currentVersion {
		// Rollback to target version
		results, err := cli.migrationService.RollbackToVersion(targetVersion)
		if err != nil {
			return fmt.Errorf("failed to rollback to version %d: %w", targetVersion, err)
		}
		cli.printResults(results)
	} else {
		fmt.Println("Already at target version")
	}

	return nil
}

func (cli *CLI) rollbackTo(targetVersion uint) error {
	if cli.verbose {
		fmt.Printf("Rolling back to version %d...\n", targetVersion)
	}

	// Validate rollback first
	if err := cli.migrationService.ValidateRollback(targetVersion); err != nil {
		return fmt.Errorf("rollback validation failed: %w", err)
	}

	if cli.dryRun {
		fmt.Printf("Would rollback to version %d\n", targetVersion)
		return nil
	}

	results, err := cli.migrationService.RollbackToVersion(targetVersion)
	if err != nil {
		return fmt.Errorf("failed to rollback to version %d: %w", targetVersion, err)
	}

	cli.printResults(results)
	return nil
}

func (cli *CLI) createMigration(name string) error {
	if cli.verbose {
		fmt.Printf("Creating migration: %s\n", name)
	}

	if cli.dryRun {
		fmt.Printf("Would create migration files for: %s\n", name)
		return nil
	}

	migration, err := cli.migrationService.CreateMigration(name, "-- Add your migration SQL here\n", "-- Add your rollback SQL here\n")
	if err != nil {
		return fmt.Errorf("failed to create migration: %w", err)
	}

	fmt.Printf("Created migration: %s\n", migration.ID)
	return nil
}

func (cli *CLI) createFromTemplate(name, templateName string, paramArgs []string) error {
	if cli.verbose {
		fmt.Printf("Creating migration from template: %s -> %s\n", templateName, name)
	}

	// Parse parameters
	params := make(map[string]interface{})
	for _, arg := range paramArgs {
		parts := strings.SplitN(arg, "=", 2)
		if len(parts) == 2 {
			params[parts[0]] = parts[1]
		}
	}

	if cli.dryRun {
		fmt.Printf("Would create migration from template '%s' with params: %v\n", templateName, params)
		return nil
	}

	migration, err := cli.migrationService.CreateMigrationFromTemplate(name, templateName, params)
	if err != nil {
		return fmt.Errorf("failed to create migration from template: %w", err)
	}

	fmt.Printf("Created migration from template: %s\n", migration.ID)
	return nil
}

func (cli *CLI) showStatus() error {
	ctx := context.Background()
	migrations, err := cli.migrationService.GetMigrationStatus(ctx)
	if err != nil {
		return fmt.Errorf("failed to get migration status: %w", err)
	}

	if cli.format == "json" {
		return json.NewEncoder(os.Stdout).Encode(migrations)
	}

	// Table format
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "VERSION\tNAME\tSTATUS\tAPPLIED AT")
	fmt.Fprintln(w, "-------\t----\t------\t----------")

	for _, migration := range migrations {
		status := "pending"
		appliedAt := "-"

		if migration.Applied {
			status = "applied"
			if migration.AppliedAt != nil {
				appliedAt = migration.AppliedAt.Format("2006-01-02 15:04:05")
			}
		}

		fmt.Fprintf(w, "%06d\t%s\t%s\t%s\n", migration.Version, migration.Name, status, appliedAt)
	}

	return w.Flush()
}

func (cli *CLI) showHistory() error {
	ctx := context.Background()
	migrations, err := cli.migrationService.GetMigrationHistory(ctx)
	if err != nil {
		return fmt.Errorf("failed to get migration history: %w", err)
	}

	if cli.format == "json" {
		return json.NewEncoder(os.Stdout).Encode(migrations)
	}

	// Table format
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "VERSION\tNAME\tSTATUS\tAPPLIED AT\tDIRTY")
	fmt.Fprintln(w, "-------\t----\t------\t----------\t-----")

	for _, migration := range migrations {
		appliedAt := "-"
		if migration.AppliedAt != nil {
			appliedAt = migration.AppliedAt.Format("2006-01-02 15:04:05")
		}

		dirty := ""
		if migration.Dirty {
			dirty = "YES"
		}

		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n", migration.Version, migration.Name, migration.Status, appliedAt, dirty)
	}

	return w.Flush()
}

func (cli *CLI) showVersion() error {
	version, dirty, err := cli.migrationService.GetCurrentVersion()
	if err != nil {
		return fmt.Errorf("failed to get current version: %w", err)
	}

	if cli.format == "json" {
		data := map[string]interface{}{
			"version": version,
			"dirty":   dirty,
		}
		return json.NewEncoder(os.Stdout).Encode(data)
	}

	fmt.Printf("Current migration version: %d", version)
	if dirty {
		fmt.Print(" (dirty)")
	}
	fmt.Println()

	return nil
}

func (cli *CLI) validateMigrations() error {
	if cli.verbose {
		fmt.Println("Validating migration files...")
	}

	if err := cli.migrationService.ValidateMigrationFiles(); err != nil {
		return fmt.Errorf("migration validation failed: %w", err)
	}

	fmt.Println("All migration files are valid")
	return nil
}

func (cli *CLI) repairDirtyState() error {
	if cli.verbose {
		fmt.Println("Repairing dirty migration state...")
	}

	if cli.dryRun {
		version, dirty, err := cli.migrationService.GetCurrentVersion()
		if err != nil {
			return fmt.Errorf("failed to get current version: %w", err)
		}
		if dirty {
			fmt.Printf("Would repair dirty state at version %d\n", version)
		} else {
			fmt.Println("Database is not in dirty state")
		}
		return nil
	}

	if err := cli.migrationService.RepairDirtyState(); err != nil {
		return fmt.Errorf("failed to repair dirty state: %w", err)
	}

	fmt.Println("Dirty state repaired successfully")
	return nil
}

func (cli *CLI) listTemplates() error {
	templates := cli.migrationService.GetAvailableTemplates()

	if cli.format == "json" {
		return json.NewEncoder(os.Stdout).Encode(templates)
	}

	// Table format
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "NAME\tDESCRIPTION")
	fmt.Fprintln(w, "----\t-----------")

	for name, template := range templates {
		fmt.Fprintf(w, "%s\t%s\n", name, template.Description)
	}

	return w.Flush()
}

func (cli *CLI) printResults(results []*database.MigrationResult) {
	if cli.format == "json" {
		json.NewEncoder(os.Stdout).Encode(results)
		return
	}

	for _, result := range results {
		if result.Success {
			fmt.Printf("✓ %s migration %d_%s (took %v)\n",
				strings.Title(result.Direction), result.Version, result.Name, result.Duration)
		} else {
			fmt.Printf("✗ Failed %s migration %d_%s: %s\n",
				result.Direction, result.Version, result.Name, result.Error)
		}
	}
}

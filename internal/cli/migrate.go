package cli

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"github.com/taqiudeen275/go-foward/internal/config"
	"github.com/taqiudeen275/go-foward/internal/database"
	"github.com/taqiudeen275/go-foward/pkg/logger"
)

// ExecuteMigrationCLI handles migration CLI commands
func ExecuteMigrationCLI() {
	var rootCmd = &cobra.Command{
		Use:   "migrate",
		Short: "Database migration commands",
		Long:  "Database migration management for the Unified Go Forward Framework",
		PersistentPreRun: func(cmd *cobra.Command, args []string) {
			// Set logger to quiet mode for CLI operations
			setupQuietLogger()
		},
	}

	// Add migration subcommands
	rootCmd.AddCommand(migrateUpCmd())
	rootCmd.AddCommand(migrateDownCmd())
	rootCmd.AddCommand(migrateStatusCmd())
	rootCmd.AddCommand(migrateCreateCmd())

	// Remove the first argument (migrate) and execute
	os.Args = append(os.Args[:1], os.Args[2:]...)

	if err := rootCmd.Execute(); err != nil {
		fmt.Printf("✗ Error: %v\n", err)
		os.Exit(1)
	}
}

// setupQuietLogger configures logger for CLI operations
func setupQuietLogger() {
	// Set environment variable to suppress verbose logs
	os.Setenv("LOG_LEVEL", "ERROR")

	// Also try to configure the logger directly
	if l := logger.GetLogger(); l != nil {
		// Suppress all logs during CLI operations
		os.Setenv("SUPPRESS_LOGS", "true")
	}
}

func migrateUpCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "up",
		Short: "Apply all pending migrations",
		Long:  "Apply all pending database migrations",
		Run: func(cmd *cobra.Command, args []string) {
			ctx := context.Background()

			fmt.Print("🔌 Connecting to database...")

			// Load configuration
			cfg, err := config.Load()
			if err != nil {
				fmt.Printf("\r✗ Failed to load configuration: %v\n", err)
				os.Exit(1)
			}

			// Initialize database
			db, err := database.New(cfg)
			if err != nil {
				fmt.Printf("\r✗ Failed to connect to database: %v\n", err)
				os.Exit(1)
			}
			defer db.Close()

			// Initialize migration manager
			mm := database.NewMigrationManager(db)
			if err := mm.InitializeQuiet(ctx); err != nil {
				fmt.Printf("\r✗ Failed to initialize migration system: %v\n", err)
				os.Exit(1)
			}

			fmt.Print("\r🔍 Checking for pending migrations...")

			// Check for pending migrations first
			allMigrations, appliedCount, pendingCount, err := mm.GetComprehensiveMigrationStatus(ctx)
			if err != nil {
				fmt.Printf("\r✗ Failed to get migration status: %v\n", err)
				os.Exit(1)
			}

			// Clear loading message
			fmt.Print("\r" + strings.Repeat(" ", 50) + "\r")

			if pendingCount == 0 {
				fmt.Println("✅ All migrations are already applied")
				fmt.Printf("📊 Total: %d migrations (%d applied)\n", len(allMigrations), appliedCount)
				return
			}

			fmt.Printf("⬆️ Applying %d pending migrations...\n", pendingCount)
			fmt.Println()

			// Apply pending migrations
			if err := mm.ApplyPendingMigrationsWithProgress(ctx, "cli"); err != nil {
				fmt.Printf("✗ Failed to apply migrations: %v\n", err)
				os.Exit(1)
			}

			fmt.Println()
			fmt.Println("✓ All migrations applied successfully!")
		},
	}
}

func migrateDownCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "down",
		Short: "Rollback last migration",
		Long:  "Rollback the last applied migration",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println("⬇️ Migration down will be implemented in database foundation task")
			fmt.Println("This command will rollback the last migration")
		},
	}
}

func migrateStatusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Show migration status",
		Long:  "Display the current status of all migrations",
		Run: func(cmd *cobra.Command, args []string) {
			ctx := context.Background()

			// Show connecting message
			fmt.Print("🔌 Connecting to database...")

			// Load configuration
			cfg, err := config.Load()
			if err != nil {
				fmt.Printf("\r✗ Failed to load configuration: %v\n", err)
				os.Exit(1)
			}

			// Initialize database
			db, err := database.New(cfg)
			if err != nil {
				fmt.Printf("\r✗ Failed to connect to database: %v\n", err)
				os.Exit(1)
			}
			defer db.Close()

			// Initialize migration manager
			mm := database.NewMigrationManager(db)
			if err := mm.InitializeQuiet(ctx); err != nil {
				fmt.Printf("\r✗ Failed to initialize migration system: %v\n", err)
				os.Exit(1)
			}

			fmt.Print("\r🔍 Scanning migrations...")

			// Get comprehensive migration status (filesystem + database)
			allMigrations, appliedCount, pendingCount, err := mm.GetComprehensiveMigrationStatus(ctx)
			if err != nil {
				fmt.Printf("\r✗ Failed to get migration status: %v\n", err)
				os.Exit(1)
			}

			// Clear the loading message
			fmt.Print("\r" + strings.Repeat(" ", 50) + "\r")

			// Print header with better formatting
			fmt.Println("┌─────────────────────────────────────────────────────────────────┐")
			fmt.Println("│                        📊 Migration Status                      │")
			fmt.Println("├─────────────────────────────────────────────────────────────────┤")
			fmt.Printf("│ 📈 Summary: %d applied, %d pending, %d total%s│\n",
				appliedCount, pendingCount, len(allMigrations),
				strings.Repeat(" ", 65-len(fmt.Sprintf("Summary: %d applied, %d pending, %d total", appliedCount, pendingCount, len(allMigrations)))))
			fmt.Println("└─────────────────────────────────────────────────────────────────┘")
			fmt.Println()

			if len(allMigrations) == 0 {
				fmt.Println("📂 No migrations found in migrations/ directory")
				fmt.Println("   Use 'migrate create <name>' to create your first migration")
				return
			}

			// Group migrations by status for better presentation
			var applied, pending, failed, rolledBack []*database.Migration
			for _, migration := range allMigrations {
				switch migration.Status {
				case "applied":
					applied = append(applied, migration)
				case "pending":
					pending = append(pending, migration)
				case "failed":
					failed = append(failed, migration)
				case "rolled_back":
					rolledBack = append(rolledBack, migration)
				}
			}

			// Show applied migrations
			if len(applied) > 0 {
				fmt.Printf("✓ Applied Migrations (%d)\n", len(applied))
				fmt.Println("─────────────────────────")
				for _, migration := range applied {
					fmt.Printf("  %s - %s\n", migration.Version, migration.Name)
					if migration.AppliedAt != nil {
						fmt.Printf("    📅 %s", migration.AppliedAt.Format("Jan 02, 2006 15:04:05"))
						if migration.AppliedBy != nil {
							fmt.Printf(" by %s", *migration.AppliedBy)
						}
						if migration.ExecutionTime != nil {
							fmt.Printf(" ⏱️ %s", migration.ExecutionTime.String())
						}
						fmt.Println()
					}
				}
				fmt.Println()
			}

			// Show pending migrations
			if len(pending) > 0 {
				fmt.Printf("⏳ Pending Migrations (%d)\n", len(pending))
				fmt.Println("─────────────────────────")
				for _, migration := range pending {
					fmt.Printf("  %s - %s\n", migration.Version, migration.Name)
				}
				fmt.Println()
				fmt.Println("💡 Run 'migrate up' to apply pending migrations")
				fmt.Println()
			}

			// Show failed migrations
			if len(failed) > 0 {
				fmt.Printf("✗ Failed Migrations (%d)\n", len(failed))
				fmt.Println("─────────────────────────")
				for _, migration := range failed {
					fmt.Printf("  %s - %s\n", migration.Version, migration.Name)
					if migration.ErrorMessage != nil && *migration.ErrorMessage != "" {
						fmt.Printf("    💥 %s\n", *migration.ErrorMessage)
					}
				}
				fmt.Println()
			}

			// Show rolled back migrations
			if len(rolledBack) > 0 {
				fmt.Printf("↩️ Rolled Back Migrations (%d)\n", len(rolledBack))
				fmt.Println("─────────────────────────────")
				for _, migration := range rolledBack {
					fmt.Printf("  %s - %s\n", migration.Version, migration.Name)
					if migration.RolledBackAt != nil {
						fmt.Printf("    📅 Rolled back: %s", migration.RolledBackAt.Format("Jan 02, 2006 15:04:05"))
						if migration.RolledBackBy != nil {
							fmt.Printf(" by %s", *migration.RolledBackBy)
						}
						fmt.Println()
					}
				}
				fmt.Println()
			}
		},
	}
}

func migrateCreateCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "create [name]",
		Short: "Create new migration",
		Long:  "Create a new migration file with the given name",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			name := args[0]

			fmt.Print("🔌 Connecting to database...")

			// Load configuration (for database connection if needed)
			cfg, err := config.Load()
			if err != nil {
				fmt.Printf("\r✗ Failed to load configuration: %v\n", err)
				os.Exit(1)
			}

			// Initialize database
			db, err := database.New(cfg)
			if err != nil {
				fmt.Printf("\r✗ Failed to connect to database: %v\n", err)
				os.Exit(1)
			}
			defer db.Close()

			// Initialize migration manager
			mm := database.NewMigrationManager(db)

			fmt.Print("\r📝 Creating migration files...")

			// Create migration
			migration, err := mm.CreateMigrationQuiet(name, "")
			if err != nil {
				fmt.Printf("\r✗ Failed to create migration: %v\n", err)
				os.Exit(1)
			}

			// Clear loading message
			fmt.Print("\r" + strings.Repeat(" ", 50) + "\r")

			fmt.Println("┌─────────────────────────────────────────────────────────────────┐")
			fmt.Println("│                     📝 Migration Created                        │")
			fmt.Println("├─────────────────────────────────────────────────────────────────┤")
			fmt.Printf("│ Name: %-56s │\n", name)
			fmt.Printf("│ ID: %-58s │\n", migration.ID)
			fmt.Printf("│ Version: %-53s │\n", migration.Version)
			fmt.Println("└─────────────────────────────────────────────────────────────────┘")
			fmt.Println()
			fmt.Println("📁 Files created:")
			fmt.Printf("   📄 migrations/%s_%s.up.sql\n", migration.Version, strings.ReplaceAll(strings.ToLower(name), " ", "_"))
			fmt.Printf("   📄 migrations/%s_%s.down.sql\n", migration.Version, strings.ReplaceAll(strings.ToLower(name), " ", "_"))
			fmt.Println()
			fmt.Println("💡 Next steps:")
			fmt.Println("   1. Edit the .up.sql file to add your migration SQL")
			fmt.Println("   2. Edit the .down.sql file to add rollback SQL")
			fmt.Println("   3. Run 'migrate up' to apply the migration")
		},
	}
}

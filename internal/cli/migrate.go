package cli

import (
	"context"
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/taqiudeen275/go-foward/internal/config"
	"github.com/taqiudeen275/go-foward/internal/database"
)

// ExecuteMigrationCLI handles migration CLI commands
func ExecuteMigrationCLI() {
	var rootCmd = &cobra.Command{
		Use:   "migrate",
		Short: "Database migration commands",
		Long:  "Database migration management for the Unified Go Forward Framework",
	}

	// Add migration subcommands
	rootCmd.AddCommand(migrateUpCmd())
	rootCmd.AddCommand(migrateDownCmd())
	rootCmd.AddCommand(migrateStatusCmd())
	rootCmd.AddCommand(migrateCreateCmd())

	// Remove the first argument (migrate) and execute
	os.Args = append(os.Args[:1], os.Args[2:]...)

	if err := rootCmd.Execute(); err != nil {
		fmt.Printf("Error executing migration command: %v\n", err)
		os.Exit(1)
	}
}

func migrateUpCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "up",
		Short: "Apply all pending migrations",
		Long:  "Apply all pending database migrations",
		Run: func(cmd *cobra.Command, args []string) {
			ctx := context.Background()

			// Load configuration
			cfg, err := config.Load()
			if err != nil {
				fmt.Printf("✗ Failed to load configuration: %v\n", err)
				os.Exit(1)
			}

			// Initialize database
			db, err := database.New(cfg)
			if err != nil {
				fmt.Printf("✗ Failed to connect to database: %v\n", err)
				os.Exit(1)
			}
			defer db.Close()

			// Initialize migration manager
			mm := database.NewMigrationManager(db)
			if err := mm.Initialize(ctx); err != nil {
				fmt.Printf("✗ Failed to initialize migration system: %v\n", err)
				os.Exit(1)
			}

			// Apply pending migrations
			fmt.Println("⬆️ Applying pending migrations...")
			if err := mm.ApplyPendingMigrations(ctx, "cli"); err != nil {
				fmt.Printf("✗ Failed to apply migrations: %v\n", err)
				os.Exit(1)
			}

			fmt.Println("✓ All migrations applied successfully")
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

			// Load configuration
			cfg, err := config.Load()
			if err != nil {
				fmt.Printf("✗ Failed to load configuration: %v\n", err)
				os.Exit(1)
			}

			// Initialize database
			db, err := database.New(cfg)
			if err != nil {
				fmt.Printf("✗ Failed to connect to database: %v\n", err)
				os.Exit(1)
			}
			defer db.Close()

			// Initialize migration manager
			mm := database.NewMigrationManager(db)
			if err := mm.Initialize(ctx); err != nil {
				fmt.Printf("✗ Failed to initialize migration system: %v\n", err)
				os.Exit(1)
			}

			// Get migration status
			migrations, err := mm.GetMigrationStatus(ctx)
			if err != nil {
				fmt.Printf("✗ Failed to get migration status: %v\n", err)
				os.Exit(1)
			}

			fmt.Println("📊 Migration Status:")
			fmt.Println("==================")

			if len(migrations) == 0 {
				fmt.Println("No migrations found")
				return
			}

			for _, migration := range migrations {
				status := "✗ FAILED"
				switch migration.Status {
				case "applied":
					status = "✓ APPLIED"
				case "pending":
					status = "⏳ PENDING"
				case "rolled_back":
					status = "↩️ ROLLED BACK"
				}

				fmt.Printf("%s %s - %s\n", status, migration.Version, migration.Name)
				if migration.AppliedAt != nil {
					fmt.Printf("    Applied: %s\n", migration.AppliedAt.Format("2006-01-02 15:04:05"))
				}
				if migration.ExecutionTime != nil {
					fmt.Printf("    Duration: %s\n", migration.ExecutionTime.String())
				}
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

			// Load configuration (for database connection if needed)
			cfg, err := config.Load()
			if err != nil {
				fmt.Printf("✗ Failed to load configuration: %v\n", err)
				os.Exit(1)
			}

			// Initialize database
			db, err := database.New(cfg)
			if err != nil {
				fmt.Printf("✗ Failed to connect to database: %v\n", err)
				os.Exit(1)
			}
			defer db.Close()

			// Initialize migration manager
			mm := database.NewMigrationManager(db)

			// Create migration
			fmt.Printf("📝 Creating migration: %s\n", name)
			migration, err := mm.CreateMigration(name, "")
			if err != nil {
				fmt.Printf("✗ Failed to create migration: %v\n", err)
				os.Exit(1)
			}

			fmt.Printf("✓ Migration created successfully\n")
			fmt.Printf("   ID: %s\n", migration.ID)
			fmt.Printf("   Version: %s\n", migration.Version)
			fmt.Printf("   Files created in migrations/ directory\n")
		},
	}
}

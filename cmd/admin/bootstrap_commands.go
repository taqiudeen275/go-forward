package main

import (
	"encoding/json"
	"fmt"
	"os"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/term"
)

// createBootstrapCommands creates bootstrap and emergency access commands
func createBootstrapCommands() *cobra.Command {
	bootstrapCmd := &cobra.Command{
		Use:   "bootstrap",
		Short: "Framework initialization and emergency access commands",
		Long:  "Commands for initializing the framework, creating emergency access, and deployment validation",
	}

	bootstrapCmd.AddCommand(initFrameworkCmd())
	bootstrapCmd.AddCommand(createEmergencyAccessCmd())
	bootstrapCmd.AddCommand(validateDeploymentCmd())
	bootstrapCmd.AddCommand(backupConfigCmd())
	bootstrapCmd.AddCommand(restoreConfigCmd())

	return bootstrapCmd
}

// initFrameworkCmd creates the init command
func initFrameworkCmd() *cobra.Command {
	var (
		adminEmail     string
		adminUsername  string
		adminPassword  string
		skipMigrations bool
		force          bool
	)

	cmd := &cobra.Command{
		Use:   "init",
		Short: "Initialize the Go Forward framework",
		Long: `Initialize the Go Forward framework for first-time deployment.

This command will:
- Run database migrations
- Create initial system administrator
- Apply environment-specific security policies
- Validate deployment configuration`,
		RunE: func(cmd *cobra.Command, args []string) error {
			cli := getCLI(cmd)
			ctx := cmd.Context()

			// Detect environment
			env, err := cli.envDetector.DetectEnvironment()
			if err != nil {
				return fmt.Errorf("failed to detect environment: %w", err)
			}

			if verbose {
				fmt.Printf("Initializing framework for %s environment\n", env)
			}

			// Check if framework is already initialized
			isInitialized, err := cli.bootstrapService.IsFrameworkInitialized(ctx)
			if err != nil {
				return fmt.Errorf("failed to check initialization status: %w", err)
			}

			if isInitialized && !force {
				return fmt.Errorf("framework is already initialized (use --force to reinitialize)")
			}

			// Collect admin details if not provided
			if adminEmail == "" {
				fmt.Print("System Admin Email: ")
				fmt.Scanln(&adminEmail)
			}

			if adminUsername == "" {
				fmt.Print("System Admin Username: ")
				fmt.Scanln(&adminUsername)
			}

			if adminPassword == "" {
				fmt.Print("System Admin Password: ")
				passwordBytes, err := term.ReadPassword(int(syscall.Stdin))
				if err != nil {
					return fmt.Errorf("failed to read password: %w", err)
				}
				adminPassword = string(passwordBytes)
				fmt.Println() // New line after password input
			}

			// Production environment confirmation
			if env == EnvironmentProduction && !force {
				fmt.Printf("\n⚠️  WARNING: Initializing framework in PRODUCTION environment\n")
				fmt.Printf("This will create the initial system administrator and apply security policies.\n\n")

				fmt.Print("Type 'INITIALIZE PRODUCTION' to confirm: ")
				var confirmation string
				fmt.Scanln(&confirmation)

				if confirmation != "INITIALIZE PRODUCTION" {
					return fmt.Errorf("operation cancelled")
				}
			}

			if dryRun {
				fmt.Printf("Would initialize framework with:\n")
				fmt.Printf("  Environment: %s\n", env)
				fmt.Printf("  Admin Email: %s\n", adminEmail)
				fmt.Printf("  Admin Username: %s\n", adminUsername)
				fmt.Printf("  Skip Migrations: %v\n", skipMigrations)
				return nil
			}

			// Initialize framework
			req := &InitializeFrameworkRequest{
				Environment:    env,
				AdminEmail:     adminEmail,
				AdminUsername:  adminUsername,
				AdminPassword:  adminPassword,
				SkipMigrations: skipMigrations,
				InitializedBy:  "CLI",
			}

			result, err := cli.bootstrapService.InitializeFramework(ctx, req)
			if err != nil {
				return fmt.Errorf("failed to initialize framework: %w", err)
			}

			if format == "json" {
				return json.NewEncoder(os.Stdout).Encode(result)
			}

			fmt.Printf("✓ Framework initialized successfully\n")
			fmt.Printf("  Environment: %s\n", result.Environment)
			fmt.Printf("  System Admin ID: %s\n", result.SystemAdminID)
			fmt.Printf("  Migrations Applied: %d\n", result.MigrationsApplied)
			fmt.Printf("  Policies Applied: %d\n", result.PoliciesApplied)
			fmt.Printf("  Initialized At: %s\n", result.InitializedAt.Format("2006-01-02 15:04:05"))

			if len(result.Warnings) > 0 {
				fmt.Printf("\nWarnings:\n")
				for _, warning := range result.Warnings {
					fmt.Printf("  ⚠ %s\n", warning)
				}
			}

			if len(result.NextSteps) > 0 {
				fmt.Printf("\nNext Steps:\n")
				for _, step := range result.NextSteps {
					fmt.Printf("  • %s\n", step)
				}
			}

			return nil
		},
	}

	cmd.Flags().StringVar(&adminEmail, "admin-email", "", "System administrator email")
	cmd.Flags().StringVar(&adminUsername, "admin-username", "", "System administrator username")
	cmd.Flags().StringVar(&adminPassword, "admin-password", "", "System administrator password")
	cmd.Flags().BoolVar(&skipMigrations, "skip-migrations", false, "Skip database migrations")
	cmd.Flags().BoolVar(&force, "force", false, "Force initialization even if already initialized")

	return cmd
}

// createEmergencyAccessCmd creates the emergency-access command
func createEmergencyAccessCmd() *cobra.Command {
	var (
		reason   string
		duration string
		email    string
		force    bool
	)

	cmd := &cobra.Command{
		Use:   "emergency-access",
		Short: "Create emergency access for system recovery",
		Long: `Create temporary emergency access for system recovery scenarios.

Emergency access provides temporary system administrator privileges
with automatic expiration and comprehensive audit logging.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			cli := getCLI(cmd)
			ctx := cmd.Context()

			// Parse duration
			var accessDuration time.Duration
			var err error
			if duration != "" {
				accessDuration, err = time.ParseDuration(duration)
				if err != nil {
					return fmt.Errorf("invalid duration format: %w", err)
				}
			} else {
				accessDuration = 1 * time.Hour // Default 1 hour
			}

			// Validate reason is provided
			if reason == "" {
				fmt.Print("Emergency Access Reason: ")
				fmt.Scanln(&reason)
			}

			if email == "" {
				fmt.Print("Emergency Access Email: ")
				fmt.Scanln(&email)
			}

			// Detect environment for security policies
			env, err := cli.envDetector.DetectEnvironment()
			if err != nil {
				return fmt.Errorf("failed to detect environment: %w", err)
			}

			// Production environment confirmation
			if env == EnvironmentProduction && !force {
				fmt.Printf("\n🚨 CRITICAL: Creating emergency access in PRODUCTION\n")
				fmt.Printf("Reason: %s\n", reason)
				fmt.Printf("Email: %s\n", email)
				fmt.Printf("Duration: %s\n", accessDuration)
				fmt.Printf("\nEmergency access provides full system administrator privileges.\n")
				fmt.Printf("This action will be comprehensively audited.\n\n")

				fmt.Print("Type 'CREATE EMERGENCY ACCESS' to confirm: ")
				var confirmation string
				fmt.Scanln(&confirmation)

				if confirmation != "CREATE EMERGENCY ACCESS" {
					return fmt.Errorf("operation cancelled")
				}
			}

			if dryRun {
				fmt.Printf("Would create emergency access:\n")
				fmt.Printf("  Email: %s\n", email)
				fmt.Printf("  Duration: %s\n", accessDuration)
				fmt.Printf("  Reason: %s\n", reason)
				fmt.Printf("  Environment: %s\n", env)
				return nil
			}

			// Create emergency access
			req := &CreateEmergencyAccessRequest{
				Email:     email,
				Reason:    reason,
				Duration:  accessDuration,
				CreatedBy: "CLI",
			}

			access, err := cli.bootstrapService.CreateEmergencyAccess(ctx, req)
			if err != nil {
				return fmt.Errorf("failed to create emergency access: %w", err)
			}

			if format == "json" {
				return json.NewEncoder(os.Stdout).Encode(access)
			}

			fmt.Printf("🚨 Emergency access created\n")
			fmt.Printf("  Access ID: %s\n", access.ID)
			fmt.Printf("  Email: %s\n", access.Email)
			fmt.Printf("  Temporary Password: %s\n", access.TempPassword)
			fmt.Printf("  Expires At: %s\n", access.ExpiresAt.Format("2006-01-02 15:04:05"))
			fmt.Printf("  Reason: %s\n", access.Reason)

			fmt.Printf("\n⚠️  IMPORTANT SECURITY NOTES:\n")
			fmt.Printf("  • This password is shown only once\n")
			fmt.Printf("  • Access will automatically expire at the specified time\n")
			fmt.Printf("  • All actions will be comprehensively audited\n")
			fmt.Printf("  • Revoke access immediately after use\n")

			return nil
		},
	}

	cmd.Flags().StringVar(&reason, "reason", "", "Reason for emergency access (required)")
	cmd.Flags().StringVar(&duration, "duration", "1h", "Access duration (e.g., 1h, 30m, 2h)")
	cmd.Flags().StringVar(&email, "email", "", "Email for emergency access account")
	cmd.Flags().BoolVar(&force, "force", false, "Skip confirmation prompts")

	cmd.MarkFlagRequired("reason")

	return cmd
}

// validateDeploymentCmd creates the validate-deployment command
func validateDeploymentCmd() *cobra.Command {
	var (
		comprehensive bool
		fix           bool
	)

	cmd := &cobra.Command{
		Use:   "validate-deployment",
		Short: "Validate deployment configuration and health",
		Long: `Validate deployment configuration, database connectivity, 
security settings, and overall system health.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			cli := getCLI(cmd)
			ctx := cmd.Context()

			if verbose {
				fmt.Printf("Validating deployment configuration...\n")
			}

			// Perform deployment validation
			validation, err := cli.bootstrapService.ValidateDeployment(ctx, comprehensive)
			if err != nil {
				return fmt.Errorf("deployment validation failed: %w", err)
			}

			if format == "json" {
				return json.NewEncoder(os.Stdout).Encode(validation)
			}

			// Display validation results
			fmt.Printf("Deployment Validation Results:\n\n")

			if validation.IsHealthy {
				fmt.Printf("✓ Deployment is healthy\n")
			} else {
				fmt.Printf("✗ Deployment has issues\n")
			}

			if len(validation.Passed) > 0 {
				fmt.Printf("\nPassed Checks:\n")
				for _, check := range validation.Passed {
					fmt.Printf("  ✓ %s\n", check)
				}
			}

			if len(validation.Failed) > 0 {
				fmt.Printf("\nFailed Checks:\n")
				for _, check := range validation.Failed {
					fmt.Printf("  ✗ %s\n", check)
				}
			}

			if len(validation.Warnings) > 0 {
				fmt.Printf("\nWarnings:\n")
				for _, warning := range validation.Warnings {
					fmt.Printf("  ⚠ %s\n", warning)
				}
			}

			if len(validation.Performance) > 0 {
				fmt.Printf("\nPerformance Metrics:\n")
				for metric, value := range validation.Performance {
					fmt.Printf("  • %s: %v\n", metric, value)
				}
			}

			// Auto-fix if requested
			if fix && !validation.IsHealthy {
				fmt.Printf("\nAttempting to fix deployment issues...\n")

				if dryRun {
					fmt.Printf("Would attempt to fix the following issues:\n")
					for _, issue := range validation.Failed {
						fmt.Printf("  - %s\n", issue)
					}
					return nil
				}

				fixResult, err := cli.bootstrapService.FixDeploymentIssues(ctx, validation.Failed)
				if err != nil {
					return fmt.Errorf("failed to fix deployment issues: %w", err)
				}

				fmt.Printf("Fix Results:\n")
				for issue, result := range fixResult {
					if result {
						fmt.Printf("  ✓ Fixed: %s\n", issue)
					} else {
						fmt.Printf("  ✗ Could not fix: %s\n", issue)
					}
				}
			}

			return nil
		},
	}

	cmd.Flags().BoolVar(&comprehensive, "comprehensive", false, "Perform comprehensive validation including performance tests")
	cmd.Flags().BoolVar(&fix, "fix", false, "Attempt to automatically fix deployment issues")

	return cmd
}

// backupConfigCmd creates the backup-config command
func backupConfigCmd() *cobra.Command {
	var (
		outputPath string
		include    []string
	)

	cmd := &cobra.Command{
		Use:   "backup-config",
		Short: "Backup framework configuration and security settings",
		Long:  "Create a backup of framework configuration, security policies, and admin settings",
		RunE: func(cmd *cobra.Command, args []string) error {
			cli := getCLI(cmd)
			ctx := cmd.Context()

			if outputPath == "" {
				outputPath = fmt.Sprintf("goforward-backup-%s.json", time.Now().Format("20060102-150405"))
			}

			if verbose {
				fmt.Printf("Creating configuration backup...\n")
			}

			// Create backup
			req := &BackupConfigRequest{
				OutputPath:      outputPath,
				IncludeSections: include,
				CreatedBy:       "CLI",
			}

			backup, err := cli.bootstrapService.BackupConfiguration(ctx, req)
			if err != nil {
				return fmt.Errorf("failed to create backup: %w", err)
			}

			if format == "json" {
				return json.NewEncoder(os.Stdout).Encode(backup)
			}

			fmt.Printf("✓ Configuration backup created\n")
			fmt.Printf("  File: %s\n", backup.FilePath)
			fmt.Printf("  Size: %d bytes\n", backup.FileSize)
			fmt.Printf("  Sections: %v\n", backup.Sections)
			fmt.Printf("  Created At: %s\n", backup.CreatedAt.Format("2006-01-02 15:04:05"))

			return nil
		},
	}

	cmd.Flags().StringVar(&outputPath, "output", "", "Output file path (auto-generated if not specified)")
	cmd.Flags().StringSliceVar(&include, "include", []string{"config", "security", "admins"}, "Sections to include in backup")

	return cmd
}

// restoreConfigCmd creates the restore-config command
func restoreConfigCmd() *cobra.Command {
	var (
		backupPath string
		sections   []string
		force      bool
	)

	cmd := &cobra.Command{
		Use:   "restore-config",
		Short: "Restore framework configuration from backup",
		Long:  "Restore framework configuration, security policies, and admin settings from a backup file",
		RunE: func(cmd *cobra.Command, args []string) error {
			cli := getCLI(cmd)
			ctx := cmd.Context()

			if backupPath == "" {
				return fmt.Errorf("backup file path is required")
			}

			// Check if backup file exists
			if _, err := os.Stat(backupPath); os.IsNotExist(err) {
				return fmt.Errorf("backup file not found: %s", backupPath)
			}

			// Detect environment for confirmation
			env, err := cli.envDetector.DetectEnvironment()
			if err != nil {
				return fmt.Errorf("failed to detect environment: %w", err)
			}

			// Production environment confirmation
			if env == EnvironmentProduction && !force {
				fmt.Printf("⚠️  WARNING: Restoring configuration in PRODUCTION environment\n")
				fmt.Printf("Backup File: %s\n", backupPath)
				fmt.Printf("Sections: %v\n", sections)
				fmt.Printf("\nThis will overwrite current configuration settings.\n\n")

				fmt.Print("Type 'RESTORE CONFIGURATION' to confirm: ")
				var confirmation string
				fmt.Scanln(&confirmation)

				if confirmation != "RESTORE CONFIGURATION" {
					return fmt.Errorf("operation cancelled")
				}
			}

			if dryRun {
				fmt.Printf("Would restore configuration from:\n")
				fmt.Printf("  Backup File: %s\n", backupPath)
				fmt.Printf("  Sections: %v\n", sections)
				return nil
			}

			// Restore configuration
			req := &RestoreConfigRequest{
				BackupPath:      backupPath,
				RestoreSections: sections,
				RestoredBy:      "CLI",
			}

			result, err := cli.bootstrapService.RestoreConfiguration(ctx, req)
			if err != nil {
				return fmt.Errorf("failed to restore configuration: %w", err)
			}

			if format == "json" {
				return json.NewEncoder(os.Stdout).Encode(result)
			}

			fmt.Printf("✓ Configuration restored successfully\n")
			fmt.Printf("  Backup File: %s\n", result.BackupFile)
			fmt.Printf("  Sections Restored: %v\n", result.SectionsRestored)
			fmt.Printf("  Items Restored: %d\n", result.ItemsRestored)
			fmt.Printf("  Restored At: %s\n", result.RestoredAt.Format("2006-01-02 15:04:05"))

			if len(result.Warnings) > 0 {
				fmt.Printf("\nWarnings:\n")
				for _, warning := range result.Warnings {
					fmt.Printf("  ⚠ %s\n", warning)
				}
			}

			return nil
		},
	}

	cmd.Flags().StringVar(&backupPath, "backup", "", "Path to backup file (required)")
	cmd.Flags().StringSliceVar(&sections, "sections", []string{"config", "security", "admins"}, "Sections to restore")
	cmd.Flags().BoolVar(&force, "force", false, "Skip confirmation prompts")

	cmd.MarkFlagRequired("backup")

	return cmd
}

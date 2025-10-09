package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"syscall"
	"text/tabwriter"

	"github.com/spf13/cobra"
	"github.com/taqiudeen275/go-foward/internal/auth"
	"golang.org/x/term"
)

// createAdminCommands creates admin management commands
func createAdminCommands() *cobra.Command {
	adminCmd := &cobra.Command{
		Use:   "admin",
		Short: "Admin management commands",
		Long:  "Commands for creating, promoting, demoting, and listing system administrators",
	}

	adminCmd.AddCommand(createSystemAdminCmd())
	adminCmd.AddCommand(promoteAdminCmd())
	adminCmd.AddCommand(demoteAdminCmd())
	adminCmd.AddCommand(listAdminsCmd())

	return adminCmd
}

// createSystemAdminCmd creates the create-system-admin command
func createSystemAdminCmd() *cobra.Command {
	var (
		email    string
		username string
		password string
		force    bool
	)

	cmd := &cobra.Command{
		Use:   "create-system-admin",
		Short: "Create a new system administrator",
		Long: `Create a new system administrator with full framework access.

In production environments, this command requires additional security measures
including MFA setup and confirmation prompts.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			cli := getCLI(cmd)
			ctx := cmd.Context()

			// Detect environment and apply security policies
			env, err := cli.envDetector.DetectEnvironment()
			if err != nil {
				return fmt.Errorf("failed to detect environment: %w", err)
			}

			if verbose {
				fmt.Printf("Detected environment: %s\n", env)
			}

			// Apply environment-specific security policies
			if err := cli.envDetector.ValidateEnvironmentRequirements(env, force); err != nil {
				return fmt.Errorf("environment validation failed: %w", err)
			}

			// Collect admin details if not provided
			if email == "" {
				fmt.Print("Email: ")
				fmt.Scanln(&email)
			}

			if username == "" {
				fmt.Print("Username: ")
				fmt.Scanln(&username)
			}

			if password == "" {
				fmt.Print("Password: ")
				passwordBytes, err := term.ReadPassword(int(syscall.Stdin))
				if err != nil {
					return fmt.Errorf("failed to read password: %w", err)
				}
				password = string(passwordBytes)
				fmt.Println() // New line after password input
			}

			// Validate inputs
			if err := cli.adminManager.ValidateSystemAdminRequest(email, username, password); err != nil {
				return fmt.Errorf("validation failed: %w", err)
			}

			// Production environment confirmation
			if env == EnvironmentProduction && !force {
				fmt.Printf("\n⚠️  WARNING: Creating system admin in PRODUCTION environment\n")
				fmt.Printf("System admins have unrestricted access to:\n")
				fmt.Printf("  - SQL execution and database management\n")
				fmt.Printf("  - System configuration and security settings\n")
				fmt.Printf("  - All user data and administrative functions\n\n")

				fmt.Print("Type 'CREATE SYSTEM ADMIN' to confirm: ")
				var confirmation string
				fmt.Scanln(&confirmation)

				if confirmation != "CREATE SYSTEM ADMIN" {
					return fmt.Errorf("operation cancelled")
				}
			}

			if dryRun {
				fmt.Printf("Would create system admin:\n")
				fmt.Printf("  Email: %s\n", email)
				fmt.Printf("  Username: %s\n", username)
				fmt.Printf("  Environment: %s\n", env)
				return nil
			}

			// Create system admin
			req := &CreateSystemAdminRequest{
				Email:       email,
				Username:    username,
				Password:    password,
				Environment: env,
				CreatedBy:   "CLI",
			}

			admin, err := cli.adminManager.CreateSystemAdmin(ctx, req)
			if err != nil {
				return fmt.Errorf("failed to create system admin: %w", err)
			}

			if format == "json" {
				return json.NewEncoder(os.Stdout).Encode(admin)
			}

			fmt.Printf("✓ System admin created successfully\n")
			fmt.Printf("  ID: %s\n", admin.ID)
			fmt.Printf("  Email: %s\n", admin.Email)
			fmt.Printf("  Username: %s\n", admin.Username)
			fmt.Printf("  Admin Level: %s\n", admin.AdminLevel)

			// Suggest MFA setup for production
			if env == EnvironmentProduction {
				fmt.Printf("\n🔐 SECURITY RECOMMENDATION:\n")
				fmt.Printf("Enable MFA for this system admin account using:\n")
				fmt.Printf("  admin mfa enable --user-id %s\n", admin.ID)
			}

			return nil
		},
	}

	cmd.Flags().StringVar(&email, "email", "", "Admin email address")
	cmd.Flags().StringVar(&username, "username", "", "Admin username")
	cmd.Flags().StringVar(&password, "password", "", "Admin password (will prompt if not provided)")
	cmd.Flags().BoolVar(&force, "force", false, "Skip confirmation prompts (use with caution)")

	return cmd
}

// promoteAdminCmd creates the promote-admin command
func promoteAdminCmd() *cobra.Command {
	var (
		userID  string
		toLevel string
		reason  string
		force   bool
	)

	cmd := &cobra.Command{
		Use:   "promote",
		Short: "Promote a user to admin or upgrade admin level",
		Long: `Promote a regular user to admin status or upgrade an existing admin to a higher level.

Valid promotion levels:
  - moderator: Read-only access with content moderation capabilities
  - regular_admin: Limited administrative access to assigned tables
  - super_admin: Business-level administrative capabilities
  - system_admin: Full framework access (requires existing system admin)`,
		RunE: func(cmd *cobra.Command, args []string) error {
			cli := getCLI(cmd)
			ctx := cmd.Context()

			// Validate required parameters
			if userID == "" {
				return fmt.Errorf("user-id is required")
			}

			if toLevel == "" {
				return fmt.Errorf("to-level is required")
			}

			// Validate admin level
			adminLevel := auth.AdminLevel(toLevel)
			if !isValidAdminLevel(adminLevel) {
				return fmt.Errorf("invalid admin level: %s", toLevel)
			}

			// Get current user info
			user, err := cli.authService.GetUserByID(ctx, userID)
			if err != nil {
				return fmt.Errorf("user not found: %w", err)
			}

			// Check current admin status
			currentLevel, err := cli.adminManager.GetUserAdminLevel(ctx, userID)
			if err != nil && !strings.Contains(err.Error(), "not an admin") {
				return fmt.Errorf("failed to check current admin level: %w", err)
			}

			// Detect environment for security policies
			env, err := cli.envDetector.DetectEnvironment()
			if err != nil {
				return fmt.Errorf("failed to detect environment: %w", err)
			}

			// Production environment confirmation for system admin promotion
			if adminLevel == auth.SystemAdmin && env == EnvironmentProduction && !force {
				fmt.Printf("\n  CRITICAL WARNING: Promoting to SYSTEM ADMIN in PRODUCTION\n")
				fmt.Printf("User: %s (%s)\n", user.Email, user.Username)
				fmt.Printf("Current Level: %s\n", currentLevel)
				fmt.Printf("New Level: %s\n", adminLevel)
				fmt.Printf("\nSystem admins have unrestricted access to all framework functions.\n\n")

				fmt.Print("Type 'PROMOTE TO SYSTEM ADMIN' to confirm: ")
				var confirmation string
				fmt.Scanln(&confirmation)

				if confirmation != "PROMOTE TO SYSTEM ADMIN" {
					return fmt.Errorf("operation cancelled")
				}
			}

			if dryRun {
				fmt.Printf("Would promote user:\n")
				fmt.Printf("  User ID: %s\n", userID)
				fmt.Printf("  Email: %s\n", *user.Email)
				fmt.Printf("  Current Level: %s\n", currentLevel)
				fmt.Printf("  New Level: %s\n", adminLevel)
				fmt.Printf("  Reason: %s\n", reason)
				return nil
			}

			// Perform promotion
			req := &PromoteAdminRequest{
				UserID:     userID,
				ToLevel:    adminLevel,
				Reason:     reason,
				PromotedBy: "CLI",
			}

			result, err := cli.adminManager.PromoteAdmin(ctx, req)
			if err != nil {
				return fmt.Errorf("failed to promote admin: %w", err)
			}

			if format == "json" {
				return json.NewEncoder(os.Stdout).Encode(result)
			}

			fmt.Printf("✓ User promoted successfully\n")
			fmt.Printf("  User: %s (%s)\n", *user.Email, *user.Username)
			fmt.Printf("  Previous Level: %s\n", result.PreviousLevel)
			fmt.Printf("  New Level: %s\n", result.NewLevel)
			fmt.Printf("  Promoted At: %s\n", result.PromotedAt.Format("2006-01-02 15:04:05"))

			return nil
		},
	}

	cmd.Flags().StringVar(&userID, "user-id", "", "ID of user to promote (required)")
	cmd.Flags().StringVar(&toLevel, "to-level", "", "Admin level to promote to (required)")
	cmd.Flags().StringVar(&reason, "reason", "", "Reason for promotion")
	cmd.Flags().BoolVar(&force, "force", false, "Skip confirmation prompts")

	cmd.MarkFlagRequired("user-id")
	cmd.MarkFlagRequired("to-level")

	return cmd
}

// demoteAdminCmd creates the demote-admin command
func demoteAdminCmd() *cobra.Command {
	var (
		userID  string
		toLevel string
		reason  string
		force   bool
	)

	cmd := &cobra.Command{
		Use:   "demote",
		Short: "Demote an admin to a lower level or remove admin status",
		Long: `Demote an existing admin to a lower level or remove admin status entirely.

Use 'user' as the to-level to completely remove admin privileges.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			cli := getCLI(cmd)
			ctx := cmd.Context()

			// Validate required parameters
			if userID == "" {
				return fmt.Errorf("user-id is required")
			}

			// Get current user info and admin level
			user, err := cli.authService.GetUserByID(ctx, userID)
			if err != nil {
				return fmt.Errorf("user not found: %w", err)
			}

			currentLevel, err := cli.adminManager.GetUserAdminLevel(ctx, userID)
			if err != nil {
				return fmt.Errorf("failed to get current admin level: %w", err)
			}

			// Validate demotion level
			var newLevel *auth.AdminLevel
			if toLevel != "" && toLevel != "user" {
				adminLevel := auth.AdminLevel(toLevel)
				if !isValidAdminLevel(adminLevel) {
					return fmt.Errorf("invalid admin level: %s", toLevel)
				}
				newLevel = &adminLevel
			}

			// Confirmation for demotion
			if !force {
				fmt.Printf("⚠️  Demoting admin user:\n")
				fmt.Printf("  User: %s (%s)\n", *user.Email, *user.Username)
				fmt.Printf("  Current Level: %s\n", currentLevel)
				if newLevel != nil {
					fmt.Printf("  New Level: %s\n", *newLevel)
				} else {
					fmt.Printf("  New Level: Regular User (no admin privileges)\n")
				}
				fmt.Printf("\nThis action will immediately revoke admin privileges.\n\n")

				fmt.Print("Type 'DEMOTE ADMIN' to confirm: ")
				var confirmation string
				fmt.Scanln(&confirmation)

				if confirmation != "DEMOTE ADMIN" {
					return fmt.Errorf("operation cancelled")
				}
			}

			if dryRun {
				fmt.Printf("Would demote admin:\n")
				fmt.Printf("  User ID: %s\n", userID)
				fmt.Printf("  Current Level: %s\n", currentLevel)
				if newLevel != nil {
					fmt.Printf("  New Level: %s\n", *newLevel)
				} else {
					fmt.Printf("  New Level: Regular User\n")
				}
				return nil
			}

			// Perform demotion
			req := &DemoteAdminRequest{
				UserID:    userID,
				ToLevel:   newLevel,
				Reason:    reason,
				DemotedBy: "CLI",
			}

			result, err := cli.adminManager.DemoteAdmin(ctx, req)
			if err != nil {
				return fmt.Errorf("failed to demote admin: %w", err)
			}

			if format == "json" {
				return json.NewEncoder(os.Stdout).Encode(result)
			}

			fmt.Printf("✓ Admin demoted successfully\n")
			fmt.Printf("  User: %s (%s)\n", *user.Email, *user.Username)
			fmt.Printf("  Previous Level: %s\n", result.PreviousLevel)
			if result.NewLevel != nil {
				fmt.Printf("  New Level: %s\n", *result.NewLevel)
			} else {
				fmt.Printf("  New Level: Regular User\n")
			}
			fmt.Printf("  Demoted At: %s\n", result.DemotedAt.Format("2006-01-02 15:04:05"))

			return nil
		},
	}

	cmd.Flags().StringVar(&userID, "user-id", "", "ID of admin to demote (required)")
	cmd.Flags().StringVar(&toLevel, "to-level", "", "Admin level to demote to (use 'user' to remove admin status)")
	cmd.Flags().StringVar(&reason, "reason", "", "Reason for demotion")
	cmd.Flags().BoolVar(&force, "force", false, "Skip confirmation prompts")

	cmd.MarkFlagRequired("user-id")

	return cmd
}

// listAdminsCmd creates the list-admins command
func listAdminsCmd() *cobra.Command {
	var (
		level        string
		showInactive bool
	)

	cmd := &cobra.Command{
		Use:   "list",
		Short: "List all administrators",
		Long:  "List all administrators with their roles, levels, and status information",
		RunE: func(cmd *cobra.Command, args []string) error {
			cli := getCLI(cmd)
			ctx := cmd.Context()

			// Build filter
			filter := &AdminFilter{
				ShowInactive: showInactive,
			}

			if level != "" {
				adminLevel := auth.AdminLevel(level)
				if !isValidAdminLevel(adminLevel) {
					return fmt.Errorf("invalid admin level: %s", level)
				}
				filter.Level = &adminLevel
			}

			// Get admin list
			admins, err := cli.adminManager.ListAdmins(ctx, filter)
			if err != nil {
				return fmt.Errorf("failed to list admins: %w", err)
			}

			if format == "json" {
				return json.NewEncoder(os.Stdout).Encode(admins)
			}

			// Display in table format
			w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "ID\tEMAIL\tUSERNAME\tLEVEL\tSTATUS\tCREATED\tLAST ACTIVE")
			fmt.Fprintln(w, "--\t-----\t--------\t-----\t------\t-------\t-----------")

			for _, admin := range admins {
				status := "Active"
				if !admin.IsActive {
					status = "Inactive"
				}

				lastActive := "Never"
				if admin.LastActiveAt != nil {
					lastActive = admin.LastActiveAt.Format("2006-01-02 15:04")
				}

				fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
					admin.ID,
					admin.Email,
					admin.Username,
					admin.AdminLevel,
					status,
					admin.CreatedAt.Format("2006-01-02"),
					lastActive,
				)
			}

			return w.Flush()
		},
	}

	cmd.Flags().StringVar(&level, "level", "", "Filter by admin level")
	cmd.Flags().BoolVar(&showInactive, "show-inactive", false, "Include inactive admins")

	return cmd
}

// isValidAdminLevel checks if the admin level is valid
func isValidAdminLevel(level auth.AdminLevel) bool {
	switch level {
	case auth.SystemAdmin, auth.SuperAdmin, auth.RegularAdmin, auth.Moderator:
		return true
	default:
		return false
	}
}

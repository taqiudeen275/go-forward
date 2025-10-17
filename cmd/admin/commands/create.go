package commands

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"github.com/taqiudeen275/go-foward/internal/auth"
	"golang.org/x/term"
)

// CreateSystemAdminCmd creates a new system administrator
var CreateSystemAdminCmd = &cobra.Command{
	Use:   "create-system-admin",
	Short: "Create a new system administrator",
	Long: `Create a new system administrator with full framework access.

System administrators have the highest level of access including:
- Full database access including SQL execution
- User management and role assignment
- System configuration changes
- Administrative interface access

In production environments, additional security measures are required:
- Stronger password requirements
- MFA setup during creation
- Additional confirmation steps
- Audit logging of the creation process

Examples:
  # Interactive creation (recommended)
  go-forward-admin create-system-admin

  # Non-interactive creation (development only)
  go-forward-admin create-system-admin --email admin@example.com --password mypassword123

  # Create with MFA enabled
  go-forward-admin create-system-admin --email admin@example.com --enable-mfa`,
	RunE: runCreateSystemAdmin,
}

func init() {
	CreateSystemAdminCmd.Flags().String("email", "", "Admin email address")
	CreateSystemAdminCmd.Flags().String("username", "", "Admin username (optional)")
	CreateSystemAdminCmd.Flags().String("password", "", "Admin password (not recommended for production)")
	CreateSystemAdminCmd.Flags().Bool("enable-mfa", false, "Enable MFA for the admin user")
	CreateSystemAdminCmd.Flags().Bool("skip-email-verification", false, "Skip email verification (development only)")
	CreateSystemAdminCmd.Flags().String("metadata", "", "Additional metadata as JSON string")
}

func runCreateSystemAdmin(cmd *cobra.Command, args []string) error {
	// Initialize base command
	base, err := InitializeBase(cmd)
	if err != nil {
		return fmt.Errorf("failed to initialize: %w", err)
	}
	defer base.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Check database connection and schema
	if err := base.CheckDatabaseConnection(ctx); err != nil {
		return fmt.Errorf("database validation failed: %w", err)
	}

	// Production safety checks
	if err := base.RequireProductionConfirmation("create system administrator"); err != nil {
		return err
	}

	base.PrintHeader("Create System Administrator")

	// Get admin details
	adminReq, err := getAdminDetails(cmd, base)
	if err != nil {
		return fmt.Errorf("failed to get admin details: %w", err)
	}

	// Validate admin details
	if err := validateAdminRequest(adminReq, base); err != nil {
		return fmt.Errorf("validation failed: %w", err)
	}

	// Check if admin with this email already exists
	if err := checkExistingAdmin(ctx, adminReq.Email, base); err != nil {
		return err
	}

	// Show summary and confirm
	if err := showAdminSummary(adminReq, base); err != nil {
		return err
	}

	// Create the admin user
	base.PrintInfo("Creating system administrator...")
	user, err := base.AuthService.CreateAdminUser(ctx, *adminReq)
	if err != nil {
		return fmt.Errorf("failed to create admin user: %w", err)
	}

	// Handle MFA setup if enabled
	mfaBackupCodes := []string{}
	if adminReq.EnableMFA {
		base.PrintInfo("Setting up Multi-Factor Authentication...")
		backupCodes, err := setupMFA(ctx, user.ID, base)
		if err != nil {
			base.PrintWarning(fmt.Sprintf("Admin created but MFA setup failed: %v", err))
		} else {
			mfaBackupCodes = backupCodes
		}
	}

	// Handle email verification
	if !getSkipEmailVerification(cmd) && adminReq.Email != nil {
		base.PrintInfo("Email verification will be required on first login")
	}

	// Log the admin creation
	currentUser, _ := base.GetCurrentUser()
	err = base.LogAdminAction(ctx, user.ID, "admin_created", "user", user.ID, map[string]interface{}{
		"role":        "system_admin",
		"created_by":  currentUser,
		"email":       adminReq.Email,
		"mfa_enabled": adminReq.EnableMFA,
	})
	if err != nil {
		base.PrintWarning(fmt.Sprintf("Failed to log admin creation: %v", err))
	}

	// Show success message and important information
	showCreationSuccess(user, mfaBackupCodes, base)

	return nil
}

// getAdminDetails collects admin details from flags or interactive prompts
func getAdminDetails(cmd *cobra.Command, base *BaseCommand) (*auth.CreateAdminUserRequest, error) {
	req := &auth.CreateAdminUserRequest{
		RoleName: "system_admin",
		Metadata: make(map[string]interface{}),
	}

	// Get email
	email, _ := cmd.Flags().GetString("email")
	if email == "" {
		email = promptForEmail(base)
	}
	req.Email = &email

	// Get username (optional)
	username, _ := cmd.Flags().GetString("username")
	if username == "" {
		username = promptForUsername(base)
	}
	if username != "" {
		req.Username = &username
	}

	// Get password
	password, _ := cmd.Flags().GetString("password")
	if password == "" {
		var err error
		password, err = promptForPassword(base)
		if err != nil {
			return nil, fmt.Errorf("failed to get password: %w", err)
		}
	}
	req.Password = password

	// Get MFA preference
	enableMFA, _ := cmd.Flags().GetBool("enable-mfa")
	if !enableMFA && base.Environment == EnvProduction {
		// In production, prompt for MFA
		enableMFA = base.Confirm("Enable Multi-Factor Authentication? (recommended for production)")
	}
	req.EnableMFA = enableMFA

	// Handle metadata
	if metadataStr, _ := cmd.Flags().GetString("metadata"); metadataStr != "" {
		// Parse JSON metadata (simplified - you might want proper JSON parsing)
		req.Metadata["cli_metadata"] = metadataStr
	}

	// Add creation context
	req.Metadata["created_via"] = "cli"
	req.Metadata["environment"] = string(base.Environment)
	req.Metadata["created_at"] = time.Now().UTC()

	return req, nil
}

// promptForEmail prompts the user for an email address
func promptForEmail(base *BaseCommand) string {
	reader := bufio.NewReader(os.Stdin)

	for {
		fmt.Print("Enter admin email address: ")
		email, _ := reader.ReadString('\n')
		email = strings.TrimSpace(email)

		if err := base.ValidateEmail(email); err != nil {
			base.PrintError(err.Error())
			continue
		}

		return email
	}
}

// promptForUsername prompts the user for a username
func promptForUsername(base *BaseCommand) string {
	reader := bufio.NewReader(os.Stdin)

	fmt.Print("Enter admin username (optional, press enter to skip): ")
	username, _ := reader.ReadString('\n')
	username = strings.TrimSpace(username)

	return username
}

// promptForPassword prompts the user for a secure password
func promptForPassword(base *BaseCommand) (string, error) {
	for {
		fmt.Print("Enter admin password: ")
		passwordBytes, err := term.ReadPassword(int(syscall.Stdin))
		if err != nil {
			return "", fmt.Errorf("failed to read password: %w", err)
		}
		fmt.Println() // New line after password input

		password := string(passwordBytes)

		if err := base.ValidatePassword(password); err != nil {
			base.PrintError(err.Error())
			continue
		}

		fmt.Print("Confirm admin password: ")
		confirmBytes, err := term.ReadPassword(int(syscall.Stdin))
		if err != nil {
			return "", fmt.Errorf("failed to read password confirmation: %w", err)
		}
		fmt.Println() // New line after password input

		if password != string(confirmBytes) {
			base.PrintError("Passwords do not match")
			continue
		}

		return password, nil
	}
}

// validateAdminRequest validates the admin creation request
func validateAdminRequest(req *auth.CreateAdminUserRequest, base *BaseCommand) error {
	if req.Email == nil || *req.Email == "" {
		return fmt.Errorf("email is required")
	}

	if err := base.ValidateEmail(*req.Email); err != nil {
		return err
	}

	if err := base.ValidatePassword(req.Password); err != nil {
		return err
	}

	// Production-specific validations
	if base.Environment == EnvProduction {
		if !req.EnableMFA {
			base.PrintWarning("MFA is strongly recommended for production system administrators")
		}

		// Ensure strong password in production
		if len(req.Password) < 12 {
			return fmt.Errorf("production environments require passwords with at least 12 characters")
		}
	}

	return nil
}

// checkExistingAdmin checks if an admin with the given email already exists
func checkExistingAdmin(ctx context.Context, email *string, base *BaseCommand) error {
	if email == nil {
		return nil
	}

	user, err := base.AuthService.GetUserByEmail(ctx, *email)
	if err != nil {
		// User not found is OK
		return nil
	}

	if user != nil {
		// Check if user already has admin role
		roles, err := base.AuthService.RBACEngine().GetUserRoles(ctx, user.ID)
		if err != nil {
			return fmt.Errorf("failed to check existing user roles: %w", err)
		}

		if len(roles) > 0 {
			return fmt.Errorf("user with email %s already exists and has admin roles", *email)
		}

		base.PrintWarning(fmt.Sprintf("User with email %s already exists but has no admin roles", *email))
		if !base.Confirm("Do you want to promote this existing user to system admin?") {
			return fmt.Errorf("operation cancelled")
		}
	}

	return nil
}

// showAdminSummary shows a summary of the admin to be created
func showAdminSummary(req *auth.CreateAdminUserRequest, base *BaseCommand) error {
	base.PrintInfo("Admin user summary:")
	fmt.Printf("  Email: %s\n", *req.Email)
	if req.Username != nil && *req.Username != "" {
		fmt.Printf("  Username: %s\n", *req.Username)
	}
	fmt.Printf("  Role: %s\n", req.RoleName)
	fmt.Printf("  MFA Enabled: %v\n", req.EnableMFA)
	fmt.Printf("  Environment: %s\n", base.Environment)

	if base.Environment == EnvProduction && !req.EnableMFA {
		base.PrintWarning("Creating system admin without MFA in production is not recommended")
	}

	if !base.Confirm("Create system administrator with these settings?") {
		return fmt.Errorf("operation cancelled by user")
	}

	return nil
}

// setupMFA sets up multi-factor authentication for the admin
func setupMFA(ctx context.Context, userID string, base *BaseCommand) ([]string, error) {
	secret, backupCodes, err := base.AuthService.MFAService().GenerateTOTPSecret(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to generate TOTP secret: %w", err)
	}

	base.PrintInfo("MFA has been initialized for this admin user")
	base.PrintWarning("The admin will need to complete MFA setup on first login")
	base.PrintVerbose(fmt.Sprintf("TOTP secret generated: %s", secret[:8]+"..."))

	return backupCodes, nil
}

// getSkipEmailVerification gets the skip email verification flag
func getSkipEmailVerification(cmd *cobra.Command) bool {
	skip, _ := cmd.Flags().GetBool("skip-email-verification")
	return skip
}

// showCreationSuccess displays the success message and important next steps
func showCreationSuccess(user *auth.User, mfaBackupCodes []string, base *BaseCommand) {
	base.PrintSuccess("System administrator created successfully!")

	fmt.Printf("\nAdmin Details:\n")
	fmt.Printf("  ID: %s\n", user.ID)
	fmt.Printf("  Email: %s\n", *user.Email)
	if user.Username != nil {
		fmt.Printf("  Username: %s\n", *user.Username)
	}
	fmt.Printf("  Role: system_admin\n")
	fmt.Printf("  Created: %s\n", user.CreatedAt.Format(time.RFC3339))

	// Show next steps
	fmt.Printf("\n" + strings.Repeat("=", 60) + "\n")
	ColorHeader.Printf("IMPORTANT: Next Steps\n")
	fmt.Printf(strings.Repeat("=", 60) + "\n")

	fmt.Printf("1. The admin can now log in using the provided credentials\n")

	if len(mfaBackupCodes) > 0 {
		fmt.Printf("2. MFA is enabled - the admin must complete TOTP setup on first login\n")
		fmt.Printf("3. Save these backup codes securely (they will not be shown again):\n")
		for i, code := range mfaBackupCodes {
			fmt.Printf("   %d. %s\n", i+1, code)
		}
	} else {
		fmt.Printf("2. Consider enabling MFA for enhanced security\n")
	}

	if base.Environment == EnvProduction {
		fmt.Printf("4. Review and configure additional security policies\n")
		fmt.Printf("5. Set up monitoring and alerting for admin actions\n")
	}

	fmt.Printf("\n")
	base.PrintWarning("Store the admin credentials securely and never share them")

	if base.Environment == EnvProduction {
		ColorWarning.Printf("🔒 Production environment: Ensure proper security procedures are followed\n")
	}
}

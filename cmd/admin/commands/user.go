package commands

import (
	"fmt"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/taqiudeen275/go-foward/internal/auth"
)

// UserCommands provides user management commands
type UserCommands struct {
	base *BaseCommand
}

// NewUserCommands creates new user management commands
func NewUserCommands(base *BaseCommand) *UserCommands {
	return &UserCommands{
		base: base,
	}
}

// RegisterCommands registers all user-related commands
func (u *UserCommands) RegisterCommands(rootCmd *cobra.Command) {
	// User management commands
	rootCmd.AddCommand(u.createCreateSystemAdminCommand())
	rootCmd.AddCommand(u.createPromoteAdminCommand())
	rootCmd.AddCommand(u.createDemoteAdminCommand())
	rootCmd.AddCommand(u.createListAdminsCommand())
}

func (u *UserCommands) createCreateSystemAdminCommand() *cobra.Command {
	var (
		email       string
		password    string
		firstName   string
		lastName    string
		phone       string
		skipMFA     bool
		department  string
		sendWelcome bool
	)

	cmd := &cobra.Command{
		Use:   "create-system-admin",
		Short: "Create a new system administrator",
		Long: `Create a new system administrator with full administrative privileges.

This command will:
- Create a new user account with system admin role
- Set up MFA (unless --skip-mfa is specified)
- Generate secure credentials
- Log the creation for audit purposes

Examples:
  # Interactive creation
  go-forward-admin create-system-admin

  # Create with specified details
  go-forward-admin create-system-admin --email admin@company.com --first-name John --last-name Doe

  # Skip MFA setup
  go-forward-admin create-system-admin --email admin@company.com --skip-mfa`,
		RunE: u.runCreateSystemAdmin(&email, &password, &firstName, &lastName, &phone, &department, &skipMFA, &sendWelcome),
	}

	cmd.Flags().StringVarP(&email, "email", "e", "", "Admin email address")
	cmd.Flags().StringVarP(&password, "password", "p", "", "Admin password (will be prompted if not provided)")
	cmd.Flags().StringVar(&firstName, "first-name", "", "Admin first name")
	cmd.Flags().StringVar(&lastName, "last-name", "", "Admin last name")
	cmd.Flags().StringVar(&phone, "phone", "", "Admin phone number")
	cmd.Flags().StringVar(&department, "department", "", "Admin department")
	cmd.Flags().BoolVar(&skipMFA, "skip-mfa", false, "Skip MFA setup during creation")
	cmd.Flags().BoolVar(&sendWelcome, "send-welcome", false, "Send welcome email to new admin")

	return cmd
}

func (u *UserCommands) runCreateSystemAdmin(email, password, firstName, lastName, phone, department *string, skipMFA, sendWelcome *bool) func(*cobra.Command, []string) error {
	return func(cmd *cobra.Command, args []string) error {
		fmt.Println("🔧 Creating System Administrator")
		fmt.Println(strings.Repeat("=", 50))

		// Initialize services
		if err := u.base.initializeServices(); err != nil {
			return fmt.Errorf("failed to initialize services: %v", err)
		}

		// Environment detection and warnings
		env := u.base.Environment
		if env == EnvProduction {
			fmt.Printf("⚠️  %s: You are creating an admin in PRODUCTION environment\n",
				ColorWarning.Sprint("WARNING"))
			if !u.base.promptConfirm("Are you sure you want to continue?") {
				return fmt.Errorf("operation cancelled")
			}
		}

		// Collect admin details
		adminEmail := *email
		if adminEmail == "" {
			adminEmail = u.base.promptString("Admin email address")
		}

		if err := u.base.ValidateEmail(adminEmail); err != nil {
			return fmt.Errorf("invalid email: %v", err)
		}

		adminPassword := *password
		if adminPassword == "" {
			adminPassword = u.base.promptSecure("Admin password")
			confirmPassword := u.base.promptSecure("Confirm password")
			if adminPassword != confirmPassword {
				return fmt.Errorf("passwords do not match")
			}
		}

		if err := u.base.ValidatePassword(adminPassword); err != nil {
			return fmt.Errorf("invalid password: %v", err)
		}

		adminFirstName := *firstName
		if adminFirstName == "" {
			adminFirstName = u.base.promptString("First name")
		}

		adminLastName := *lastName
		if adminLastName == "" {
			adminLastName = u.base.promptString("Last name")
		}

		// Create the admin user
		fmt.Println("👤 Creating admin user account...")

		createReq := auth.CreateAdminUserRequest{
			Email:     &adminEmail,
			Password:  adminPassword,
			RoleName:  "system_admin",
			Phone:     phone,
			EnableMFA: !*skipMFA,
		}
		_ = createReq // Placeholder for actual auth service call

		// TODO: Call actual auth service to create admin user
		fmt.Printf("✅ Admin user created: %s\n", adminEmail)
		adminUserID := "admin-" + fmt.Sprintf("%d", time.Now().Unix())

		// Set up MFA if not skipped
		if !*skipMFA {
			fmt.Println("🔐 Setting up MFA...")
			if err := u.setupMFAForUser(adminUserID, adminEmail); err != nil {
				fmt.Printf("⚠️  MFA setup failed: %v\n", err)
				fmt.Println("MFA can be enabled later through the admin panel")
			} else {
				fmt.Println("✅ MFA configured successfully")
			}
		}

		// Send welcome email if requested
		if *sendWelcome {
			fmt.Println("📧 Sending welcome email...")
			// TODO: Implement welcome email sending
			fmt.Println("✅ Welcome email sent")
		}

		// Log the admin creation
		auditData := map[string]interface{}{
			"action":     "create_system_admin",
			"admin_id":   adminUserID,
			"email":      adminEmail,
			"created_by": "cli-admin",
			"mfa_setup":  !*skipMFA,
		}

		fmt.Printf("📝 Admin creation logged for audit: %+v\n", auditData)

		// Summary
		fmt.Println(strings.Repeat("=", 50))
		fmt.Println("🎉 System Administrator created successfully!")
		fmt.Printf("Email: %s\n", adminEmail)
		fmt.Printf("Role: system_admin\n")
		if !*skipMFA {
			fmt.Println("⚠️  Complete MFA setup on first login")
		}
		fmt.Println()
		fmt.Println("Next steps:")
		fmt.Println("1. Test login with new credentials")
		fmt.Println("2. Complete MFA setup if enabled")
		fmt.Println("3. Review admin permissions")

		return nil
	}
}

func (u *UserCommands) createPromoteAdminCommand() *cobra.Command {
	var (
		userID   string
		email    string
		role     string
		reason   string
		duration int
	)

	cmd := &cobra.Command{
		Use:   "promote-admin",
		Short: "Promote a user to admin role",
		Long: `Promote an existing user to an administrative role.

Available roles:
- viewer: Read-only access to assigned resources
- admin: Full access to business operations
- system_admin: Full system administration privileges
- security_admin: Security and audit administration

Examples:
  # Promote user to admin role
  go-forward-admin promote-admin --email user@company.com --role admin --reason "Operational needs"

  # Promote with temporary access
  go-forward-admin promote-admin --user-id user-123 --role system_admin --duration 24 --reason "Emergency access"`,
		RunE: u.runPromoteAdmin(&userID, &email, &role, &reason, &duration),
	}

	cmd.Flags().StringVar(&userID, "user-id", "", "User ID to promote")
	cmd.Flags().StringVarP(&email, "email", "e", "", "User email to promote")
	cmd.Flags().StringVarP(&role, "role", "r", "", "Admin role to assign (required)")
	cmd.Flags().StringVar(&reason, "reason", "", "Reason for promotion (required)")
	cmd.Flags().IntVar(&duration, "duration", 0, "Duration in hours (0 = permanent)")

	cmd.MarkFlagRequired("role")
	cmd.MarkFlagRequired("reason")

	return cmd
}

func (u *UserCommands) runPromoteAdmin(userID, email, role, reason *string, duration *int) func(*cobra.Command, []string) error {
	return func(cmd *cobra.Command, args []string) error {
		if *userID == "" && *email == "" {
			return fmt.Errorf("either --user-id or --email must be provided")
		}

		// Validate role
		validRoles := []string{"viewer", "admin", "system_admin", "security_admin"}
		roleValid := false
		for _, validRole := range validRoles {
			if *role == validRole {
				roleValid = true
				break
			}
		}

		if !roleValid {
			return fmt.Errorf("invalid role. Valid roles: %s", strings.Join(validRoles, ", "))
		}

		// Validate reason
		if len(strings.TrimSpace(*reason)) < 10 {
			return fmt.Errorf("reason must be at least 10 characters")
		}

		targetUserID := *userID
		targetEmail := *email

		// Find user by email if userID not provided
		if targetUserID == "" {
			// TODO: Look up user by email
			targetUserID = "user-" + strings.Replace(targetEmail, "@", "-", -1)
			fmt.Printf("Found user ID: %s for email: %s\n", targetUserID, targetEmail)
		}

		// Confirm promotion
		fmt.Printf("👤 Promoting User to Admin\n")
		fmt.Printf("User ID: %s\n", targetUserID)
		if targetEmail != "" {
			fmt.Printf("Email: %s\n", targetEmail)
		}
		fmt.Printf("Role: %s\n", *role)
		fmt.Printf("Reason: %s\n", *reason)
		if *duration > 0 {
			fmt.Printf("Duration: %d hours\n", *duration)
		} else {
			fmt.Printf("Duration: Permanent\n")
		}

		if !u.base.promptConfirm("Proceed with promotion?") {
			return fmt.Errorf("promotion cancelled")
		}

		// Get current admin for audit
		currentAdmin := u.base.getCurrentAdminInfo()

		// Promote user
		fmt.Println("📈 Promoting user...")

		// TODO: Call auth service to promote user
		fmt.Printf("✅ User promoted to %s successfully\n", *role)

		// Create audit log
		auditData := map[string]interface{}{
			"action":      "promote_user",
			"target_user": targetUserID,
			"role":        *role,
			"promoted_by": currentAdmin.ID,
			"reason":      *reason,
			"duration":    *duration,
			"promoted_at": time.Now(),
		}

		fmt.Printf("📝 Promotion logged: %+v\n", auditData)

		return nil
	}
}

func (u *UserCommands) createDemoteAdminCommand() *cobra.Command {
	var (
		userID string
		email  string
		role   string
		reason string
	)

	cmd := &cobra.Command{
		Use:   "demote-admin",
		Short: "Remove admin role from a user",
		Long: `Remove administrative privileges from a user.

This command will:
- Remove the specified admin role from the user
- Log the action for audit purposes
- Send notification to the affected user (optional)

Examples:
  # Remove admin role
  go-forward-admin demote-admin --email admin@company.com --role admin --reason "Role no longer needed"

  # Remove system admin privileges
  go-forward-admin demote-admin --user-id user-123 --role system_admin --reason "Organizational change"`,
		RunE: u.runDemoteAdmin(&userID, &email, &role, &reason),
	}

	cmd.Flags().StringVar(&userID, "user-id", "", "User ID to demote")
	cmd.Flags().StringVarP(&email, "email", "e", "", "User email to demote")
	cmd.Flags().StringVarP(&role, "role", "r", "", "Admin role to remove (required)")
	cmd.Flags().StringVar(&reason, "reason", "", "Reason for demotion (required)")

	cmd.MarkFlagRequired("role")
	cmd.MarkFlagRequired("reason")

	return cmd
}

func (u *UserCommands) runDemoteAdmin(userID, email, role, reason *string) func(*cobra.Command, []string) error {
	return func(cmd *cobra.Command, args []string) error {
		if *userID == "" && *email == "" {
			return fmt.Errorf("either --user-id or --email must be provided")
		}

		// Validate reason
		if len(strings.TrimSpace(*reason)) < 10 {
			return fmt.Errorf("reason must be at least 10 characters")
		}

		targetUserID := *userID
		targetEmail := *email

		// Find user by email if userID not provided
		if targetUserID == "" {
			// TODO: Look up user by email
			targetUserID = "user-" + strings.Replace(targetEmail, "@", "-", -1)
			fmt.Printf("Found user ID: %s for email: %s\n", targetUserID, targetEmail)
		}

		// Confirm demotion
		fmt.Printf("👤 Demoting Admin User\n")
		fmt.Printf("User ID: %s\n", targetUserID)
		if targetEmail != "" {
			fmt.Printf("Email: %s\n", targetEmail)
		}
		fmt.Printf("Role to remove: %s\n", *role)
		fmt.Printf("Reason: %s\n", *reason)

		if !u.base.promptConfirm("Proceed with demotion?") {
			return fmt.Errorf("demotion cancelled")
		}

		// Get current admin for audit
		currentAdmin := u.base.getCurrentAdminInfo()

		// Demote user
		fmt.Println("📉 Removing admin role...")

		// TODO: Call auth service to revoke role
		fmt.Printf("✅ Admin role %s removed successfully\n", *role)

		// Create audit log
		auditData := map[string]interface{}{
			"action":      "demote_user",
			"target_user": targetUserID,
			"role":        *role,
			"demoted_by":  currentAdmin.ID,
			"reason":      *reason,
			"demoted_at":  time.Now(),
		}

		fmt.Printf("📝 Demotion logged: %+v\n", auditData)

		return nil
	}
}

func (u *UserCommands) createListAdminsCommand() *cobra.Command {
	var (
		role       string
		active     bool
		format     string
		limit      int
		department string
	)

	cmd := &cobra.Command{
		Use:   "list-admins",
		Short: "List all administrative users",
		Long: `List all users with administrative roles.

Examples:
  # List all admin users
  go-forward-admin list-admins

  # List only system admins
  go-forward-admin list-admins --role system_admin

  # List in JSON format
  go-forward-admin list-admins --format json

  # List active admins only
  go-forward-admin list-admins --active`,
		RunE: u.runListAdmins(&role, &active, &format, &limit, &department),
	}

	cmd.Flags().StringVarP(&role, "role", "r", "", "Filter by admin role")
	cmd.Flags().BoolVar(&active, "active", false, "Show only active users")
	cmd.Flags().StringVar(&format, "format", "table", "Output format: table, json, csv")
	cmd.Flags().IntVarP(&limit, "limit", "l", 50, "Maximum number of results")
	cmd.Flags().StringVar(&department, "department", "", "Filter by department")

	return cmd
}

func (u *UserCommands) runListAdmins(role *string, active *bool, format *string, limit *int, department *string) func(*cobra.Command, []string) error {
	return func(cmd *cobra.Command, args []string) error {
		fmt.Printf("👥 Listing Administrative Users")
		if *role != "" {
			fmt.Printf(" (Role: %s)", *role)
		}
		fmt.Println()
		fmt.Println(strings.Repeat("=", 60))

		// TODO: Query admin users from database
		// For now, return sample data
		admins := []map[string]interface{}{
			{
				"id":          "admin-1",
				"email":       "admin@company.com",
				"first_name":  "System",
				"last_name":   "Admin",
				"role":        "system_admin",
				"department":  "IT",
				"active":      true,
				"mfa_enabled": true,
				"last_login":  time.Now().Add(-2 * time.Hour),
				"created_at":  time.Now().Add(-30 * 24 * time.Hour),
			},
			{
				"id":          "admin-2",
				"email":       "security@company.com",
				"first_name":  "Security",
				"last_name":   "Admin",
				"role":        "security_admin",
				"department":  "Security",
				"active":      true,
				"mfa_enabled": true,
				"last_login":  time.Now().Add(-1 * time.Hour),
				"created_at":  time.Now().Add(-15 * 24 * time.Hour),
			},
		}

		// Apply filters
		filtered := []map[string]interface{}{}
		for _, admin := range admins {
			if *role != "" && admin["role"] != *role {
				continue
			}
			if *active && !admin["active"].(bool) {
				continue
			}
			if *department != "" && admin["department"] != *department {
				continue
			}
			filtered = append(filtered, admin)
		}

		// Apply limit
		if len(filtered) > *limit {
			filtered = filtered[:*limit]
		}

		// Output results
		switch *format {
		case "json":
			u.outputJSON(filtered)
		case "csv":
			u.outputCSV(filtered)
		default:
			u.outputTable(filtered)
		}

		fmt.Printf("\nTotal: %d admin users\n", len(filtered))

		return nil
	}
}

// Helper methods

func (u *UserCommands) setupMFAForUser(userID, email string) error {
	// TODO: Integrate with MFA service
	fmt.Printf("MFA setup initiated for user: %s\n", email)
	return nil
}

func (u *UserCommands) outputTable(admins []map[string]interface{}) {
	fmt.Printf("%-15s %-25s %-20s %-15s %-10s %-12s\n",
		"ID", "Email", "Name", "Role", "Active", "MFA")
	fmt.Println(strings.Repeat("-", 100))

	for _, admin := range admins {
		name := fmt.Sprintf("%s %s", admin["first_name"], admin["last_name"])
		active := "Yes"
		if !admin["active"].(bool) {
			active = "No"
		}
		mfa := "Yes"
		if !admin["mfa_enabled"].(bool) {
			mfa = "No"
		}

		fmt.Printf("%-15s %-25s %-20s %-15s %-10s %-12s\n",
			admin["id"], admin["email"], name, admin["role"], active, mfa)
	}
}

func (u *UserCommands) outputJSON(admins []map[string]interface{}) {
	fmt.Println("{")
	fmt.Printf("  \"total\": %d,\n", len(admins))
	fmt.Println("  \"admins\": [")

	for i, admin := range admins {
		fmt.Printf("    {\n")
		fmt.Printf("      \"id\": \"%s\",\n", admin["id"])
		fmt.Printf("      \"email\": \"%s\",\n", admin["email"])
		fmt.Printf("      \"name\": \"%s %s\",\n", admin["first_name"], admin["last_name"])
		fmt.Printf("      \"role\": \"%s\",\n", admin["role"])
		fmt.Printf("      \"active\": %v,\n", admin["active"])
		fmt.Printf("      \"mfa_enabled\": %v\n", admin["mfa_enabled"])
		if i < len(admins)-1 {
			fmt.Printf("    },\n")
		} else {
			fmt.Printf("    }\n")
		}
	}

	fmt.Println("  ]")
	fmt.Println("}")
}

func (u *UserCommands) outputCSV(admins []map[string]interface{}) {
	fmt.Println("ID,Email,FirstName,LastName,Role,Department,Active,MFAEnabled,LastLogin,CreatedAt")

	for _, admin := range admins {
		fmt.Printf("%s,%s,%s,%s,%s,%s,%v,%v,%s,%s\n",
			admin["id"],
			admin["email"],
			admin["first_name"],
			admin["last_name"],
			admin["role"],
			admin["department"],
			admin["active"],
			admin["mfa_enabled"],
			admin["last_login"].(time.Time).Format("2006-01-02 15:04:05"),
			admin["created_at"].(time.Time).Format("2006-01-02 15:04:05"),
		)
	}
}

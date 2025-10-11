package cli

import (
	"bufio"
	"context"
	"database/sql"
	"fmt"
	"os"
	"strings"
	"syscall"
	"time"

	"github.com/google/uuid"
	"github.com/spf13/cobra"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/term"

	"github.com/taqiudeen275/go-foward/internal/auth"
	"github.com/taqiudeen275/go-foward/internal/config"
	"github.com/taqiudeen275/go-foward/internal/database"
)

// CLIContext holds the CLI dependencies
type CLIContext struct {
	Config       *config.Config
	DB           *sql.DB
	Repository   auth.Repository
	AdminService auth.AdminService
}

var cliCtx *CLIContext

// ExecuteAdminCLI handles admin CLI commands
func ExecuteAdminCLI() {
	var rootCmd = &cobra.Command{
		Use:   "admin",
		Short: "Admin management commands",
		Long:  "Administrative commands for managing the Unified Go Forward Framework",
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			return initializeCLI()
		},
	}

	// Add admin subcommands
	rootCmd.AddCommand(createSystemAdminCmd())
	rootCmd.AddCommand(listAdminsCmd())
	rootCmd.AddCommand(promoteUserCmd())
	rootCmd.AddCommand(demoteAdminCmd())
	rootCmd.AddCommand(createEmergencyAccessCmd())
	rootCmd.AddCommand(revokeEmergencyAccessCmd())
	rootCmd.AddCommand(listEmergencyAccessCmd())

	// Remove the first argument (admin) and execute
	os.Args = append(os.Args[:1], os.Args[2:]...)

	if err := rootCmd.Execute(); err != nil {
		fmt.Printf("Error executing admin command: %v\n", err)
		os.Exit(1)
	}
}

// initializeCLI initializes the CLI context with database and services
func initializeCLI() error {
	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("failed to load configuration: %v", err)
	}

	// Initialize database connection
	db, err := database.Connect(cfg.GetConnectionString())
	if err != nil {
		return fmt.Errorf("failed to connect to database: %v", err)
	}

	// Initialize CLI repository and services
	repo := NewCLIRepository(db)
	auditService := auth.NewAuditService(repo)
	rbacService := auth.NewRBACService(repo)

	adminService := auth.NewAdminService(repo, rbacService, auditService)

	cliCtx = &CLIContext{
		Config:       cfg,
		DB:           db,
		Repository:   repo,
		AdminService: adminService,
	}

	return nil
}

func createSystemAdminCmd() *cobra.Command {
	var (
		email    string
		username string
		password string
		force    bool
	)

	cmd := &cobra.Command{
		Use:   "create-system-admin",
		Short: "Create a system administrator",
		Long:  "Create a new system administrator with full framework access",
		RunE: func(cmd *cobra.Command, args []string) error {
			return createSystemAdmin(email, username, password, force)
		},
	}

	cmd.Flags().StringVarP(&email, "email", "e", "", "Admin email address")
	cmd.Flags().StringVarP(&username, "username", "u", "", "Admin username")
	cmd.Flags().StringVarP(&password, "password", "p", "", "Admin password (will prompt if not provided)")
	cmd.Flags().BoolVarP(&force, "force", "f", false, "Skip production environment safety checks")

	return cmd
}

func listAdminsCmd() *cobra.Command {
	var (
		level  string
		search string
		limit  int
	)

	cmd := &cobra.Command{
		Use:   "list",
		Short: "List all administrators",
		Long:  "Display all administrators with their roles and status",
		RunE: func(cmd *cobra.Command, args []string) error {
			return listAdmins(level, search, limit)
		},
	}

	cmd.Flags().StringVarP(&level, "level", "l", "", "Filter by admin level (system_admin, super_admin, regular_admin, moderator)")
	cmd.Flags().StringVarP(&search, "search", "s", "", "Search term for email/username")
	cmd.Flags().IntVar(&limit, "limit", 50, "Maximum number of results")

	return cmd
}

func promoteUserCmd() *cobra.Command {
	var (
		level  string
		reason string
		tables []string
	)

	cmd := &cobra.Command{
		Use:   "promote [user-id-or-email]",
		Short: "Promote user to admin or upgrade admin level",
		Long:  "Promote a non-admin user to admin level or upgrade an existing admin to a higher level",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return promoteUser(args[0], level, reason, tables)
		},
	}

	cmd.Flags().StringVarP(&level, "level", "l", "regular_admin", "Admin level (system_admin, super_admin, regular_admin, moderator)")
	cmd.Flags().StringVarP(&reason, "reason", "r", "", "Reason for promotion")
	cmd.Flags().StringSliceVarP(&tables, "tables", "t", []string{}, "Assigned tables for regular admin")

	return cmd
}

func demoteAdminCmd() *cobra.Command {
	var (
		newLevel string
		reason   string
	)

	cmd := &cobra.Command{
		Use:   "demote [admin-id-or-email]",
		Short: "Demote admin or remove admin privileges",
		Long:  "Demote an admin to a lower level or remove admin privileges entirely",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return demoteAdmin(args[0], newLevel, reason)
		},
	}

	cmd.Flags().StringVarP(&newLevel, "level", "l", "", "New admin level (leave empty to remove admin privileges)")
	cmd.Flags().StringVarP(&reason, "reason", "r", "", "Reason for demotion")

	return cmd
}

func createEmergencyAccessCmd() *cobra.Command {
	var (
		reason   string
		duration string
		level    string
		ip       string
	)

	cmd := &cobra.Command{
		Use:   "create-emergency-access",
		Short: "Create emergency access with time limits",
		Long:  "Create emergency access for system recovery with automatic expiration",
		RunE: func(cmd *cobra.Command, args []string) error {
			return createEmergencyAccess(reason, duration, level, ip)
		},
	}

	cmd.Flags().StringVarP(&reason, "reason", "r", "", "Reason for emergency access (required)")
	cmd.Flags().StringVarP(&duration, "duration", "d", "1h", "Access duration (e.g., 1h, 30m, 2h)")
	cmd.Flags().StringVarP(&level, "level", "l", "system_admin", "Admin level for emergency access")
	cmd.Flags().StringVar(&ip, "ip", "", "Restrict access to specific IP address")

	cmd.MarkFlagRequired("reason")

	return cmd
}

func revokeEmergencyAccessCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "revoke-emergency-access [access-id]",
		Short: "Revoke emergency access",
		Long:  "Revoke an active emergency access entry",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return revokeEmergencyAccess(args[0])
		},
	}

	return cmd
}

func listEmergencyAccessCmd() *cobra.Command {
	var (
		active bool
		limit  int
	)

	cmd := &cobra.Command{
		Use:   "list-emergency-access",
		Short: "List emergency access entries",
		Long:  "Display emergency access entries with their status",
		RunE: func(cmd *cobra.Command, args []string) error {
			return listEmergencyAccess(active, limit)
		},
	}

	cmd.Flags().BoolVarP(&active, "active", "a", false, "Show only active (non-expired, non-revoked) entries")
	cmd.Flags().IntVar(&limit, "limit", 20, "Maximum number of results")

	return cmd
}

// Implementation functions

func createSystemAdmin(email, username, password string, force bool) error {
	ctx := context.Background()

	// Environment detection and production safety checks
	if cliCtx.Config.IsProduction() && !force {
		fmt.Println("🚨 Production environment detected!")
		fmt.Println("Creating system admins in production requires additional security measures.")
		fmt.Println("Use --force flag to bypass this check, but ensure you understand the security implications.")

		if !confirmAction("Do you want to continue with production system admin creation?") {
			return fmt.Errorf("system admin creation cancelled")
		}
	}

	// Interactive input if not provided
	if email == "" {
		email = promptInput("Enter admin email: ")
		if email == "" {
			return fmt.Errorf("email is required")
		}
	}

	if username == "" {
		username = promptInput("Enter admin username (optional): ")
	}

	if password == "" {
		password = promptPassword("Enter admin password: ")
		if password == "" {
			return fmt.Errorf("password is required")
		}

		confirmPassword := promptPassword("Confirm admin password: ")
		if password != confirmPassword {
			return fmt.Errorf("passwords do not match")
		}
	}

	// Validate password strength
	if len(password) < cliCtx.Config.Auth.PasswordMinLength {
		return fmt.Errorf("password must be at least %d characters long", cliCtx.Config.Auth.PasswordMinLength)
	}

	// Check if admin already exists
	existingUser, err := cliCtx.Repository.GetUserByEmail(ctx, email)
	if err == nil && existingUser != nil {
		if existingUser.IsAdmin() {
			return fmt.Errorf("user with email %s is already an admin", email)
		}

		if !confirmAction(fmt.Sprintf("User with email %s exists. Promote to system admin?", email)) {
			return fmt.Errorf("system admin creation cancelled")
		}

		// Directly promote existing user to system admin
		existingUser.AdminLevel = &[]auth.AdminLevel{auth.AdminLevelSystemAdmin}[0]
		capabilities := auth.GetDefaultCapabilities(auth.AdminLevelSystemAdmin)
		existingUser.Capabilities = &capabilities
		existingUser.UpdatedBy = &existingUser.ID
		existingUser.UpdatedAt = time.Now().UTC()

		if err := cliCtx.Repository.UpdateUser(ctx, existingUser); err != nil {
			return fmt.Errorf("failed to promote user to system admin: %v", err)
		}

		fmt.Printf("✅ Successfully promoted user %s to system admin\n", getStringValue(existingUser.Email))
		return nil
	}

	// Create new system admin
	var usernamePtr *string
	if username != "" {
		usernamePtr = &username
	}

	// Hash password
	cost := cliCtx.Config.Auth.BcryptCost
	if cost == 0 {
		cost = 12 // Default bcrypt cost
	}
	hashedBytes, err := bcrypt.GenerateFromPassword([]byte(password), cost)
	if err != nil {
		return fmt.Errorf("failed to hash password: %v", err)
	}

	// Create user directly
	userID := uuid.New()
	user := &auth.UnifiedUser{
		ID:            userID,
		Email:         &email,
		Username:      usernamePtr,
		PasswordHash:  string(hashedBytes),
		EmailVerified: true, // Auto-verify for CLI created users
		PhoneVerified: false,
		MFAEnabled:    false,
		Metadata:      make(map[string]interface{}),
		CreatedAt:     time.Now().UTC(),
		UpdatedAt:     time.Now().UTC(),
	}

	if err := cliCtx.Repository.CreateUser(ctx, user); err != nil {
		return fmt.Errorf("failed to create user: %v", err)
	}

	// Directly set admin level and capabilities for system admin creation
	user.AdminLevel = &[]auth.AdminLevel{auth.AdminLevelSystemAdmin}[0]
	capabilities := auth.GetDefaultCapabilities(auth.AdminLevelSystemAdmin)
	user.Capabilities = &capabilities
	user.UpdatedBy = &user.ID
	user.UpdatedAt = time.Now().UTC()

	// Update the user with admin privileges
	if err := cliCtx.Repository.UpdateUser(ctx, user); err != nil {
		return fmt.Errorf("failed to promote user to system admin: %v", err)
	}

	fmt.Printf("✅ Successfully created system admin: %s\n", email)
	if cliCtx.Config.IsProduction() {
		fmt.Println("🔐 Remember to enable MFA for this admin account through the dashboard")
	}

	return nil
}

func listAdmins(levelFilter, search string, limit int) error {
	ctx := context.Background()

	var adminLevel *auth.AdminLevel
	if levelFilter != "" {
		level := auth.AdminLevel(levelFilter)
		adminLevel = &level
	}

	filter := &auth.AdminManagementFilter{
		AdminLevel: adminLevel,
		SearchTerm: search,
		Limit:      limit,
	}

	admins, err := cliCtx.AdminService.ListAdmins(ctx, filter)
	if err != nil {
		return fmt.Errorf("failed to list admins: %v", err)
	}

	if len(admins) == 0 {
		fmt.Println("No administrators found")
		return nil
	}

	fmt.Printf("Found %d administrator(s):\n\n", len(admins))
	fmt.Printf("%-36s %-25s %-15s %-20s %-20s\n", "ID", "Email", "Level", "Last Login", "Status")
	fmt.Println(strings.Repeat("-", 120))

	for _, admin := range admins {
		var lastLogin string
		if admin.LastLogin != nil {
			lastLogin = admin.LastLogin.Format("2006-01-02 15:04")
		} else {
			lastLogin = "Never"
		}

		var status string
		if admin.IsLocked() {
			status = "🔒 Locked"
		} else if admin.MFAEnabled {
			status = "🔐 MFA Enabled"
		} else {
			status = "✅ Active"
		}

		var level string
		if admin.AdminLevel != nil {
			level = string(*admin.AdminLevel)
		} else {
			level = "user"
		}

		fmt.Printf("%-36s %-25s %-15s %-20s %-20s\n",
			admin.ID.String(),
			getStringValue(admin.Email),
			level,
			lastLogin,
			status,
		)
	}

	return nil
}

func promoteUser(userIdentifier, level, reason string, tables []string) error {
	ctx := context.Background()

	// Find user by ID or email
	var user *auth.UnifiedUser
	var err error

	if userID, parseErr := uuid.Parse(userIdentifier); parseErr == nil {
		user, err = cliCtx.Repository.GetUserByID(ctx, userID)
	} else {
		user, err = cliCtx.Repository.GetUserByEmail(ctx, userIdentifier)
	}

	if err != nil {
		return fmt.Errorf("failed to find user: %v", err)
	}

	// Validate admin level
	targetLevel := auth.AdminLevel(level)
	switch targetLevel {
	case auth.AdminLevelSystemAdmin, auth.AdminLevelSuperAdmin, auth.AdminLevelRegularAdmin, auth.AdminLevelModerator:
		// Valid levels
	default:
		return fmt.Errorf("invalid admin level: %s", level)
	}

	// Check if this is a promotion to a higher level or initial promotion
	if user.IsAdmin() {
		currentLevel := *user.AdminLevel
		targetLevelHierarchy := targetLevel.GetHierarchy()
		currentLevelHierarchy := currentLevel.GetHierarchy()

		if targetLevelHierarchy <= currentLevelHierarchy {
			return fmt.Errorf("user is already at %s level. Use demote command to lower admin level or promote to a higher level", currentLevel)
		}

		fmt.Printf("🔄 Promoting existing %s to %s\n", currentLevel, targetLevel)
	} else {
		fmt.Printf("⬆️ Promoting user to %s\n", targetLevel)
	}

	// Get system admin for promotion (CLI operations are performed by system admin)
	systemAdmins, err := cliCtx.AdminService.ListAdmins(ctx, &auth.AdminManagementFilter{
		AdminLevel: &[]auth.AdminLevel{auth.AdminLevelSystemAdmin}[0],
		Limit:      1,
	})
	if err != nil || len(systemAdmins) == 0 {
		return fmt.Errorf("no system admin found to perform promotion")
	}

	promoterAdmin := systemAdmins[0]

	// Validate that the promoter can perform this promotion
	if err := auth.ValidateAdminPromotion(promoterAdmin, targetLevel); err != nil {
		return fmt.Errorf("promotion not allowed: %v", err)
	}

	// For existing admins, we need to update their level directly since PromoteUserToAdmin is for non-admins
	if user.IsAdmin() {
		// Update admin level and capabilities directly
		user.AdminLevel = &targetLevel
		capabilities := auth.GetDefaultCapabilities(targetLevel)
		user.Capabilities = &capabilities

		// Add assigned tables for regular admins
		if targetLevel == auth.AdminLevelRegularAdmin && len(tables) > 0 {
			// Merge with existing tables to avoid duplicates
			existingTables := make(map[string]bool)
			for _, table := range user.AssignedTables {
				existingTables[table] = true
			}
			for _, table := range tables {
				if !existingTables[table] {
					user.AssignedTables = append(user.AssignedTables, table)
				}
			}
		}

		user.UpdatedBy = &promoterAdmin.ID
		user.UpdatedAt = time.Now().UTC()

		if err := cliCtx.Repository.UpdateUser(ctx, user); err != nil {
			return fmt.Errorf("failed to promote admin: %v", err)
		}

		fmt.Printf("✅ Successfully promoted admin %s to %s\n",
			getStringValue(user.Email),
			string(targetLevel))
	} else {
		// Use AdminService for promoting non-admin users
		req := &auth.PromoteUserRequest{
			UserID:         user.ID,
			AdminLevel:     targetLevel,
			PromotedBy:     promoterAdmin.ID,
			Reason:         reason,
			AssignedTables: tables,
		}

		promotedUser, err := cliCtx.AdminService.PromoteUserToAdmin(ctx, req)
		if err != nil {
			return fmt.Errorf("failed to promote user: %v", err)
		}

		fmt.Printf("✅ Successfully promoted user %s to %s\n",
			getStringValue(promotedUser.Email),
			string(targetLevel))
	}

	if len(tables) > 0 {
		fmt.Printf("📋 Assigned tables: %s\n", strings.Join(tables, ", "))
	}

	return nil
}

func demoteAdmin(adminIdentifier, newLevel, reason string) error {
	ctx := context.Background()

	// Find admin by ID or email
	var admin *auth.UnifiedUser
	var err error

	if adminID, parseErr := uuid.Parse(adminIdentifier); parseErr == nil {
		admin, err = cliCtx.AdminService.GetAdminByID(ctx, adminID)
	} else {
		admin, err = cliCtx.Repository.GetUserByEmail(ctx, adminIdentifier)
		if err == nil && !admin.IsAdmin() {
			return fmt.Errorf("user is not an admin")
		}
	}

	if err != nil {
		return fmt.Errorf("failed to find admin: %v", err)
	}

	// Get system admin for demotion
	systemAdmins, err := cliCtx.AdminService.ListAdmins(ctx, &auth.AdminManagementFilter{
		AdminLevel: &[]auth.AdminLevel{auth.AdminLevelSystemAdmin}[0],
		Limit:      1,
	})
	if err != nil || len(systemAdmins) == 0 {
		return fmt.Errorf("no system admin found to perform demotion")
	}

	demotingAdmin := systemAdmins[0]

	// Validate that the demoting admin can manage the target admin
	if !demotingAdmin.CanManageUser(admin) {
		return fmt.Errorf("insufficient privileges to demote this admin")
	}

	var newAdminLevel *auth.AdminLevel
	if newLevel != "" {
		level := auth.AdminLevel(newLevel)

		// Validate the new level is valid
		switch level {
		case auth.AdminLevelSystemAdmin, auth.AdminLevelSuperAdmin, auth.AdminLevelRegularAdmin, auth.AdminLevelModerator:
			// Valid levels
		default:
			return fmt.Errorf("invalid admin level: %s", newLevel)
		}

		// Ensure we're actually demoting (new level should be lower)
		currentLevel := *admin.AdminLevel
		if level.GetHierarchy() >= currentLevel.GetHierarchy() {
			return fmt.Errorf("new level %s is not lower than current level %s. Use promote command for upgrades", level, currentLevel)
		}

		newAdminLevel = &level
		fmt.Printf("🔄 Demoting %s from %s to %s\n", getStringValue(admin.Email), currentLevel, level)
	} else {
		fmt.Printf("🔄 Removing admin privileges from %s (current level: %s)\n", getStringValue(admin.Email), *admin.AdminLevel)
	}

	req := &auth.DemoteAdminRequest{
		AdminID:   admin.ID,
		DemotedBy: demotingAdmin.ID,
		Reason:    reason,
		NewLevel:  newAdminLevel,
	}

	err = cliCtx.AdminService.DemoteAdmin(ctx, req)
	if err != nil {
		return fmt.Errorf("failed to demote admin: %v", err)
	}

	if newAdminLevel != nil {
		fmt.Printf("✅ Successfully demoted admin %s to %s\n",
			getStringValue(admin.Email),
			string(*newAdminLevel))
	} else {
		fmt.Printf("✅ Successfully removed admin privileges from %s\n",
			getStringValue(admin.Email))
	}

	return nil
}

func createEmergencyAccess(reason, durationStr, level, ip string) error {
	ctx := context.Background()

	// Parse duration
	duration, err := time.ParseDuration(durationStr)
	if err != nil {
		return fmt.Errorf("invalid duration format: %v", err)
	}

	// Validate duration (max 24 hours)
	if duration > 24*time.Hour {
		return fmt.Errorf("emergency access duration cannot exceed 24 hours")
	}

	// Validate admin level
	adminLevel := auth.AdminLevel(level)
	switch adminLevel {
	case auth.AdminLevelSystemAdmin, auth.AdminLevelSuperAdmin, auth.AdminLevelRegularAdmin:
		// Valid levels for emergency access
	default:
		return fmt.Errorf("invalid admin level for emergency access: %s", level)
	}

	// Get system admin for creation
	systemAdmins, err := cliCtx.AdminService.ListAdmins(ctx, &auth.AdminManagementFilter{
		AdminLevel: &[]auth.AdminLevel{auth.AdminLevelSystemAdmin}[0],
		Limit:      1,
	})
	if err != nil || len(systemAdmins) == 0 {
		return fmt.Errorf("no system admin found to create emergency access")
	}

	var ipRestriction *string
	if ip != "" {
		ipRestriction = &ip
	}

	req := &auth.EmergencyAccessRequest{
		CreatedBy:     systemAdmins[0].ID,
		Reason:        reason,
		Duration:      duration,
		AdminLevel:    adminLevel,
		IPRestriction: ipRestriction,
	}

	emergencyAccess, err := cliCtx.AdminService.CreateEmergencyAccess(ctx, req)
	if err != nil {
		return fmt.Errorf("failed to create emergency access: %v", err)
	}

	fmt.Printf("✅ Emergency access created successfully\n")
	fmt.Printf("🆔 Access ID: %s\n", emergencyAccess.ID.String())
	fmt.Printf("🔑 Access Token: %s\n", emergencyAccess.AccessToken)
	fmt.Printf("⏰ Expires At: %s\n", emergencyAccess.ExpiresAt.Format("2006-01-02 15:04:05 UTC"))
	fmt.Printf("🔒 Admin Level: %s\n", string(emergencyAccess.AdminLevel))
	if emergencyAccess.IPRestriction != nil {
		fmt.Printf("🌐 IP Restriction: %s\n", *emergencyAccess.IPRestriction)
	}
	fmt.Printf("\n⚠️  Store this access token securely. It cannot be retrieved again.\n")

	return nil
}

func revokeEmergencyAccess(accessIDStr string) error {
	ctx := context.Background()

	accessID, err := uuid.Parse(accessIDStr)
	if err != nil {
		return fmt.Errorf("invalid access ID format: %v", err)
	}

	// Get system admin for revocation
	systemAdmins, err := cliCtx.AdminService.ListAdmins(ctx, &auth.AdminManagementFilter{
		AdminLevel: &[]auth.AdminLevel{auth.AdminLevelSystemAdmin}[0],
		Limit:      1,
	})
	if err != nil || len(systemAdmins) == 0 {
		return fmt.Errorf("no system admin found to revoke emergency access")
	}

	err = cliCtx.AdminService.RevokeEmergencyAccess(ctx, accessID, systemAdmins[0].ID)
	if err != nil {
		return fmt.Errorf("failed to revoke emergency access: %v", err)
	}

	fmt.Printf("✅ Emergency access %s has been revoked\n", accessID.String())
	return nil
}

func listEmergencyAccess(activeOnly bool, limit int) error {
	ctx := context.Background()

	filter := &auth.EmergencyAccessFilter{
		Limit: limit,
	}

	if activeOnly {
		filter.Active = &activeOnly
	}

	accessEntries, err := cliCtx.AdminService.ListEmergencyAccess(ctx, filter)
	if err != nil {
		return fmt.Errorf("failed to list emergency access: %v", err)
	}

	if len(accessEntries) == 0 {
		fmt.Println("No emergency access entries found")
		return nil
	}

	fmt.Printf("Found %d emergency access entr(ies):\n\n", len(accessEntries))
	fmt.Printf("%-36s %-15s %-20s %-20s %-10s\n", "ID", "Level", "Created", "Expires", "Status")
	fmt.Println(strings.Repeat("-", 105))

	for _, entry := range accessEntries {
		var status string
		if entry.RevokedAt != nil {
			status = "🚫 Revoked"
		} else if entry.ExpiresAt.Before(time.Now()) {
			status = "⏰ Expired"
		} else if entry.UsedAt != nil {
			status = "✅ Used"
		} else {
			status = "🟢 Active"
		}

		fmt.Printf("%-36s %-15s %-20s %-20s %-10s\n",
			entry.ID.String(),
			string(entry.AdminLevel),
			entry.CreatedAt.Format("2006-01-02 15:04"),
			entry.ExpiresAt.Format("2006-01-02 15:04"),
			status,
		)
	}

	return nil
}

// Helper functions

func promptInput(prompt string) string {
	fmt.Print(prompt)
	reader := bufio.NewReader(os.Stdin)
	input, _ := reader.ReadString('\n')
	return strings.TrimSpace(input)
}

func promptPassword(prompt string) string {
	fmt.Print(prompt)
	password, _ := term.ReadPassword(int(syscall.Stdin))
	fmt.Println()
	return string(password)
}

func confirmAction(prompt string) bool {
	fmt.Printf("%s (y/N): ", prompt)
	reader := bufio.NewReader(os.Stdin)
	response, _ := reader.ReadString('\n')
	response = strings.ToLower(strings.TrimSpace(response))
	return response == "y" || response == "yes"
}

func getStringValue(ptr *string) string {
	if ptr == nil {
		return ""
	}
	return *ptr
}

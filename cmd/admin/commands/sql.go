package commands

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/taqiudeen275/go-foward/internal/auth"
)

// SQLCommands provides SQL administration commands
type SQLCommands struct {
	base      *BaseCommand
	validator auth.SQLSecurityValidator
}

// NewSQLCommands creates new SQL admin commands
func NewSQLCommands(base *BaseCommand) *SQLCommands {
	return &SQLCommands{
		base: base,
	}
}

// RegisterCommands registers all SQL-related commands
func (s *SQLCommands) RegisterCommands(rootCmd *cobra.Command) {
	sqlCmd := &cobra.Command{
		Use:   "sql",
		Short: "SQL administration and security commands",
		Long:  "Commands for managing SQL execution, validation, and security",
	}

	// SQL execution and validation commands
	sqlCmd.AddCommand(s.createExecuteCommand())
	sqlCmd.AddCommand(s.createValidateCommand())
	sqlCmd.AddCommand(s.createHistoryCommand())

	// Approval management commands
	sqlCmd.AddCommand(s.createApprovalsCommand())
	sqlCmd.AddCommand(s.createApproveCommand())
	sqlCmd.AddCommand(s.createDenyCommand())

	// Security and monitoring commands
	sqlCmd.AddCommand(s.createSecurityCommand())
	sqlCmd.AddCommand(s.createStatsCommand())

	rootCmd.AddCommand(sqlCmd)
}

func (s *SQLCommands) createExecuteCommand() *cobra.Command {
	var (
		queryFile     string
		interactive   bool
		dryRun        bool
		reason        string
		timeout       int
		forceApproval bool
	)

	cmd := &cobra.Command{
		Use:   "execute [query]",
		Short: "Execute SQL query with security validation",
		Long: `Execute a SQL query with comprehensive security validation and audit logging.

The query will be validated for:
- Syntax and injection patterns
- Table access permissions
- Risk level assessment
- Approval requirements

Examples:
  # Execute a simple query
  go-forward-admin sql execute "SELECT COUNT(*) FROM users"

  # Execute query from file
  go-forward-admin sql execute --file query.sql --reason "Monthly report generation"

  # Interactive mode
  go-forward-admin sql execute --interactive

  # Dry run (validation only)
  go-forward-admin sql execute --dry-run "DELETE FROM old_logs WHERE created_at < '2023-01-01'"`,
		Args: func(cmd *cobra.Command, args []string) error {
			if !interactive && queryFile == "" && len(args) == 0 {
				return fmt.Errorf("query is required (use --interactive, --file, or provide as argument)")
			}
			return nil
		},
		RunE: s.runExecute(&queryFile, &interactive, &dryRun, &reason, &timeout, &forceApproval),
	}

	cmd.Flags().StringVarP(&queryFile, "file", "f", "", "Read query from file")
	cmd.Flags().BoolVarP(&interactive, "interactive", "i", false, "Interactive SQL mode")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "Validate query without executing")
	cmd.Flags().StringVarP(&reason, "reason", "r", "", "Reason for query execution (required for high-risk queries)")
	cmd.Flags().IntVar(&timeout, "timeout", 30000, "Query timeout in milliseconds")
	cmd.Flags().BoolVar(&forceApproval, "force-approval", false, "Execute even if approval is required (system admin only)")

	return cmd
}

func (s *SQLCommands) runExecute(queryFile *string, interactive *bool, dryRun *bool, reason *string, timeout *int, forceApproval *bool) func(*cobra.Command, []string) error {
	return func(cmd *cobra.Command, args []string) error {
		// Initialize services
		if err := s.initializeServices(); err != nil {
			return fmt.Errorf("failed to initialize services: %v", err)
		}

		// Get current admin user info (placeholder for now)
		email := "admin@example.com"
		adminUser := &auth.User{
			ID:    "admin-user",
			Email: &email,
		}

		if *interactive {
			return s.runInteractiveSQL(adminUser)
		}

		var query string
		if *queryFile != "" {
			queryBytes, err := os.ReadFile(*queryFile)
			if err != nil {
				return fmt.Errorf("failed to read query file: %v", err)
			}
			query = string(queryBytes)
		} else {
			query = args[0]
		}

		return s.executeQuery(query, adminUser, *dryRun, *reason, *timeout, *forceApproval)
	}
}

func (s *SQLCommands) createValidateCommand() *cobra.Command {
	var queryFile string

	cmd := &cobra.Command{
		Use:   "validate [query]",
		Short: "Validate SQL query for security and compliance",
		Long: `Validate a SQL query without executing it. This checks for:
- SQL injection patterns
- Table access permissions
- Risk level assessment
- Compliance with security policies

Examples:
  # Validate a query string
  go-forward-admin sql validate "SELECT * FROM users WHERE status = 'active'"

  # Validate query from file
  go-forward-admin sql validate --file complex_query.sql`,
		Args: func(cmd *cobra.Command, args []string) error {
			if queryFile == "" && len(args) == 0 {
				return fmt.Errorf("query is required (use --file or provide as argument)")
			}
			return nil
		},
		RunE: s.runValidate(&queryFile),
	}

	cmd.Flags().StringVarP(&queryFile, "file", "f", "", "Read query from file")

	return cmd
}

func (s *SQLCommands) runValidate(queryFile *string) func(*cobra.Command, []string) error {
	return func(cmd *cobra.Command, args []string) error {
		if err := s.initializeServices(); err != nil {
			return fmt.Errorf("failed to initialize services: %v", err)
		}

		email := "admin@example.com"
		adminUser := &auth.User{
			ID:    "admin-user",
			Email: &email,
		}

		var query string
		if *queryFile != "" {
			queryBytes, err := os.ReadFile(*queryFile)
			if err != nil {
				return fmt.Errorf("failed to read query file: %v", err)
			}
			query = string(queryBytes)
		} else {
			query = args[0]
		}

		return s.validateQuery(query, adminUser)
	}
}

func (s *SQLCommands) createHistoryCommand() *cobra.Command {
	var (
		userID string
		limit  int
		format string
	)

	cmd := &cobra.Command{
		Use:   "history",
		Short: "View SQL execution history",
		Long: `View SQL execution history with filtering options.

Examples:
  # View your own history
  go-forward-admin sql history

  # View specific user's history (system admin only)
  go-forward-admin sql history --user-id user-123

  # Limit results and format as JSON
  go-forward-admin sql history --limit 20 --format json`,
		RunE: s.runHistory(&userID, &limit, &format),
	}

	cmd.Flags().StringVar(&userID, "user-id", "", "User ID to view history for (system admin only)")
	cmd.Flags().IntVarP(&limit, "limit", "l", 50, "Maximum number of records to retrieve")
	cmd.Flags().StringVar(&format, "format", "table", "Output format: table, json, csv")

	return cmd
}

func (s *SQLCommands) runHistory(userID *string, limit *int, format *string) func(*cobra.Command, []string) error {
	return func(cmd *cobra.Command, args []string) error {
		if err := s.initializeServices(); err != nil {
			return fmt.Errorf("failed to initialize services: %v", err)
		}

		email := "admin@example.com"
		adminUser := &auth.User{
			ID:    "admin-user",
			Email: &email,
		}

		targetUserID := *userID
		if targetUserID == "" {
			targetUserID = adminUser.ID
		} else {
			// Check if current user can view other users' history (placeholder)
			if targetUserID != adminUser.ID {
				fmt.Println("Warning: Cross-user history access not fully implemented")
			}
		}

		history, err := s.validator.GetExecutionHistory(context.Background(), targetUserID, *limit)
		if err != nil {
			return fmt.Errorf("failed to retrieve execution history: %v", err)
		}

		return s.displayHistory(history, *format)
	}
}

func (s *SQLCommands) createApprovalsCommand() *cobra.Command {
	var (
		status    string
		riskLevel string
		limit     int
		format    string
	)

	cmd := &cobra.Command{
		Use:   "approvals",
		Short: "List pending query approvals",
		Long: `List query approvals with filtering options.

Examples:
  # List all pending approvals
  go-forward-admin sql approvals

  # List approved queries
  go-forward-admin sql approvals --status approved

  # List high-risk queries
  go-forward-admin sql approvals --risk-level high`,
		RunE: s.runApprovals(&status, &riskLevel, &limit, &format),
	}

	cmd.Flags().StringVar(&status, "status", "pending", "Filter by status: pending, approved, denied, expired")
	cmd.Flags().StringVar(&riskLevel, "risk-level", "", "Filter by risk level: low, medium, high, critical")
	cmd.Flags().IntVarP(&limit, "limit", "l", 50, "Maximum number of records to retrieve")
	cmd.Flags().StringVar(&format, "format", "table", "Output format: table, json")

	return cmd
}

func (s *SQLCommands) runApprovals(status, riskLevel *string, limit *int, format *string) func(*cobra.Command, []string) error {
	return func(cmd *cobra.Command, args []string) error {
		if err := s.initializeServices(); err != nil {
			return fmt.Errorf("failed to initialize services: %v", err)
		}

		email := "admin@example.com"
		_ = email // Unused variable placeholder
		// Check if user can view approvals (placeholder)
		fmt.Println("Permission check placeholder - assuming system admin")

		fmt.Printf("Listing query approvals (status: %s, limit: %d)\n", *status, *limit)
		fmt.Println("Note: This feature is not yet fully implemented in the backend")

		return nil
	}
}

func (s *SQLCommands) createApproveCommand() *cobra.Command {
	var (
		reason        string
		maxExecutions int
		expiryHours   int
	)

	cmd := &cobra.Command{
		Use:   "approve [approval-id]",
		Short: "Approve a pending query",
		Long: `Approve a pending query for execution.

Examples:
  # Approve a query
  go-forward-admin sql approve abc123 --reason "Approved for monthly reporting"

  # Approve with custom limits
  go-forward-admin sql approve abc123 --max-executions 5 --expiry-hours 48`,
		Args: cobra.ExactArgs(1),
		RunE: s.runApprove(&reason, &maxExecutions, &expiryHours),
	}

	cmd.Flags().StringVarP(&reason, "reason", "r", "", "Reason for approval (required)")
	cmd.Flags().IntVar(&maxExecutions, "max-executions", 1, "Maximum number of executions allowed")
	cmd.Flags().IntVar(&expiryHours, "expiry-hours", 24, "Hours until approval expires")

	cmd.MarkFlagRequired("reason")

	return cmd
}

func (s *SQLCommands) runApprove(reason *string, maxExecutions, expiryHours *int) func(*cobra.Command, []string) error {
	return func(cmd *cobra.Command, args []string) error {
		approvalID := args[0]

		if err := s.initializeServices(); err != nil {
			return fmt.Errorf("failed to initialize services: %v", err)
		}

		email := "admin@example.com"
		adminUser := &auth.User{
			ID:    "admin-user",
			Email: &email,
		}

		// Check if user can approve queries (placeholder)
		fmt.Println("Permission check placeholder - assuming system admin")

		fmt.Printf("Approving query: %s\n", approvalID)
		fmt.Printf("Approved by: %s\n", *adminUser.Email)
		fmt.Printf("Reason: %s\n", *reason)
		fmt.Printf("Max executions: %d\n", *maxExecutions)
		fmt.Printf("Expires in: %d hours\n", *expiryHours)
		fmt.Println("\nNote: This feature is not yet fully implemented in the backend")

		return nil
	}
}

func (s *SQLCommands) createDenyCommand() *cobra.Command {
	var reason string

	cmd := &cobra.Command{
		Use:   "deny [approval-id]",
		Short: "Deny a pending query",
		Long: `Deny a pending query execution request.

Examples:
  # Deny a query
  go-forward-admin sql deny abc123 --reason "Too risky for production environment"`,
		Args: cobra.ExactArgs(1),
		RunE: s.runDeny(&reason),
	}

	cmd.Flags().StringVarP(&reason, "reason", "r", "", "Reason for denial (required)")
	cmd.MarkFlagRequired("reason")

	return cmd
}

func (s *SQLCommands) runDeny(reason *string) func(*cobra.Command, []string) error {
	return func(cmd *cobra.Command, args []string) error {
		approvalID := args[0]

		if err := s.initializeServices(); err != nil {
			return fmt.Errorf("failed to initialize services: %v", err)
		}

		email := "admin@example.com"
		adminUser := &auth.User{
			ID:    "admin-user",
			Email: &email,
		}

		// Check if user can approve/deny queries (placeholder)
		fmt.Println("Permission check placeholder - assuming system admin")

		fmt.Printf("Denying query: %s\n", approvalID)
		fmt.Printf("Denied by: %s\n", *adminUser.Email)
		fmt.Printf("Reason: %s\n", *reason)
		fmt.Println("\nNote: This feature is not yet fully implemented in the backend")

		return nil
	}
}

func (s *SQLCommands) createSecurityCommand() *cobra.Command {
	var (
		eventType string
		severity  string
		limit     int
		format    string
		hours     int
	)

	cmd := &cobra.Command{
		Use:   "security",
		Short: "View SQL security events and alerts",
		Long: `View SQL-related security events and alerts.

Examples:
  # View recent security events
  go-forward-admin sql security

  # View failed SQL executions
  go-forward-admin sql security --event-type sql_execution_failed

  # View high severity events from last 48 hours
  go-forward-admin sql security --severity high --hours 48`,
		RunE: s.runSecurity(&eventType, &severity, &limit, &format, &hours),
	}

	cmd.Flags().StringVar(&eventType, "event-type", "", "Filter by event type")
	cmd.Flags().StringVar(&severity, "severity", "", "Filter by severity: low, medium, high, critical")
	cmd.Flags().IntVarP(&limit, "limit", "l", 50, "Maximum number of events to retrieve")
	cmd.Flags().StringVar(&format, "format", "table", "Output format: table, json")
	cmd.Flags().IntVar(&hours, "hours", 24, "Hours to look back for events")

	return cmd
}

func (s *SQLCommands) runSecurity(eventType, severity *string, limit *int, format *string, hours *int) func(*cobra.Command, []string) error {
	return func(cmd *cobra.Command, args []string) error {
		if err := s.initializeServices(); err != nil {
			return fmt.Errorf("failed to initialize services: %v", err)
		}

		email := "admin@example.com"
		_ = email // Unused variable placeholder
		// Check if user can view security events (placeholder)
		fmt.Println("Permission check placeholder - assuming security admin")

		fmt.Printf("Viewing SQL security events (last %d hours)\n", *hours)
		if *eventType != "" {
			fmt.Printf("Event type filter: %s\n", *eventType)
		}
		if *severity != "" {
			fmt.Printf("Severity filter: %s\n", *severity)
		}
		fmt.Println("Note: This feature is not yet fully implemented in the backend")

		return nil
	}
}

func (s *SQLCommands) createStatsCommand() *cobra.Command {
	var (
		format string
		hours  int
	)

	cmd := &cobra.Command{
		Use:   "stats",
		Short: "Display SQL execution statistics",
		Long: `Display comprehensive SQL execution statistics and metrics.

Examples:
  # View stats for last 24 hours
  go-forward-admin sql stats

  # View stats for last week
  go-forward-admin sql stats --hours 168

  # Output as JSON
  go-forward-admin sql stats --format json`,
		RunE: s.runStats(&format, &hours),
	}

	cmd.Flags().StringVar(&format, "format", "table", "Output format: table, json")
	cmd.Flags().IntVar(&hours, "hours", 24, "Hours to generate statistics for")

	return cmd
}

func (s *SQLCommands) runStats(format *string, hours *int) func(*cobra.Command, []string) error {
	return func(cmd *cobra.Command, args []string) error {
		if err := s.initializeServices(); err != nil {
			return fmt.Errorf("failed to initialize services: %v", err)
		}

		email := "admin@example.com"
		_ = email // Unused variable placeholder
		// Check if user can view statistics (placeholder)
		fmt.Println("Permission check placeholder - assuming system admin")

		fmt.Printf("SQL Execution Statistics (Last %d Hours)\n", *hours)
		fmt.Println(strings.Repeat("=", 50))
		fmt.Println("Note: This feature is not yet fully implemented in the backend")
		fmt.Println("\nPlaceholder statistics:")
		fmt.Println("- Total queries executed: 0")
		fmt.Println("- Failed queries: 0")
		fmt.Println("- High-risk queries: 0")
		fmt.Println("- Pending approvals: 0")
		fmt.Println("- Average execution time: 0ms")

		return nil
	}
}

// Helper methods

func (s *SQLCommands) runInteractiveSQL(adminUser *auth.User) error {
	fmt.Println("=== Interactive SQL Mode ===")
	fmt.Println("Type 'help' for commands, 'exit' to quit")
	fmt.Println("All queries are logged and subject to security validation")
	fmt.Println()

	for {
		fmt.Print("sql> ")
		var input string
		fmt.Scanln(&input)

		if input == "" {
			continue
		}

		switch strings.ToLower(input) {
		case "exit", "quit", "\\q":
			fmt.Println("Goodbye!")
			return nil
		case "help", "\\h":
			s.printSQLHelp()
		default:
			if err := s.executeQuery(input, adminUser, false, "Interactive session", 30000, false); err != nil {
				fmt.Printf("Error: %v\n\n", err)
			}
		}
	}
}

func (s *SQLCommands) printSQLHelp() {
	fmt.Println("Interactive SQL Commands:")
	fmt.Println("  help, \\h     - Show this help")
	fmt.Println("  exit, \\q     - Exit interactive mode")
	fmt.Println("  [SQL query]  - Execute SQL query")
	fmt.Println()
	fmt.Println("Examples:")
	fmt.Println("  SELECT COUNT(*) FROM users;")
	fmt.Println("  SHOW TABLES;")
	fmt.Println("  \\q")
	fmt.Println()
}

func (s *SQLCommands) executeQuery(query string, adminUser *auth.User, dryRun bool, reason string, timeout int, forceApproval bool) error {
	ctx := context.Background()

	// Create execution context
	execCtx := auth.SQLExecutionContext{
		UserID:      adminUser.ID,
		SessionID:   fmt.Sprintf("cli-%d", time.Now().Unix()),
		AdminRole:   "system_admin", // This should be determined from actual user roles
		IPAddress:   "127.0.0.1",
		UserAgent:   "go-forward-admin-cli",
		RequestPath: "/cli/sql/execute",
		AdditionalData: map[string]interface{}{
			"request_reason": reason,
			"timeout":        timeout,
			"force_approval": forceApproval,
		},
	}

	// Validate the query
	validation, err := s.validator.ValidateQuery(ctx, query, execCtx)
	if err != nil {
		return fmt.Errorf("validation failed: %v", err)
	}

	// Display validation results
	s.displayValidationResult(validation)

	if !validation.Valid {
		return fmt.Errorf("query validation failed")
	}

	if dryRun {
		fmt.Println("\n✓ Dry run completed successfully")
		return nil
	}

	// Check for approval requirement
	if validation.RequiresApproval && !forceApproval {
		fmt.Printf("\n⚠️  This query requires approval due to %s risk level\n", validation.RiskLevel)

		if !s.base.promptConfirm("Do you want to request approval for this query?") {
			return nil
		}

		if err := s.validator.RequestQueryApproval(ctx, validation.QueryHash, query, execCtx); err != nil {
			return fmt.Errorf("failed to request approval: %v", err)
		}

		fmt.Println("✓ Approval request submitted")
		return nil
	}

	// Execute the query
	fmt.Println("\n🔄 Executing query...")
	result, err := s.validator.ExecuteQuery(ctx, query, execCtx, forceApproval)
	if err != nil {
		return fmt.Errorf("execution failed: %v", err)
	}

	s.displayExecutionResult(result)
	return nil
}

func (s *SQLCommands) validateQuery(query string, adminUser *auth.User) error {
	ctx := context.Background()

	execCtx := auth.SQLExecutionContext{
		UserID:      adminUser.ID,
		SessionID:   fmt.Sprintf("cli-validate-%d", time.Now().Unix()),
		AdminRole:   "system_admin",
		IPAddress:   "127.0.0.1",
		UserAgent:   "go-forward-admin-cli",
		RequestPath: "/cli/sql/validate",
	}

	validation, err := s.validator.ValidateQuery(ctx, query, execCtx)
	if err != nil {
		return fmt.Errorf("validation failed: %v", err)
	}

	s.displayValidationResult(validation)
	return nil
}

func (s *SQLCommands) displayValidationResult(result *auth.SQLValidationResult) {
	fmt.Println("\n=== Query Validation Results ===")
	if result.Valid {
		fmt.Println("✓ Query is valid")
	} else {
		fmt.Println("❌ Query is invalid")
	}

	fmt.Printf("Query Type: %s\n", result.QueryType)
	fmt.Printf("Risk Level: %s\n", result.RiskLevel)
	fmt.Printf("Requires Approval: %v\n", result.RequiresApproval)

	if len(result.AffectedTables) > 0 {
		fmt.Printf("Affected Tables: %s\n", strings.Join(result.AffectedTables, ", "))
	}

	if result.EstimatedRows > 0 {
		fmt.Printf("Estimated Rows: %d\n", result.EstimatedRows)
	}

	fmt.Printf("Execution Time Limit: %dms\n", result.ExecutionTimeLimit)

	if len(result.Errors) > 0 {
		fmt.Println("\n❌ Errors:")
		for _, err := range result.Errors {
			fmt.Printf("  - %s\n", err)
		}
	}

	if len(result.Warnings) > 0 {
		fmt.Println("\n⚠️  Warnings:")
		for _, warning := range result.Warnings {
			fmt.Printf("  - %s\n", warning)
		}
	}

	fmt.Printf("\nQuery Hash: %s\n", result.QueryHash)
}

func (s *SQLCommands) displayExecutionResult(result *auth.SQLExecutionResult) {
	fmt.Println("\n=== Query Execution Results ===")

	if result.Success {
		fmt.Println("✓ Query executed successfully")
	} else {
		fmt.Println("❌ Query execution failed")
		if result.Error != "" {
			fmt.Printf("Error: %s\n", result.Error)
		}
		if result.ErrorCode != "" {
			fmt.Printf("Error Code: %s\n", result.ErrorCode)
		}
		return
	}

	fmt.Printf("Query Type: %s\n", result.QueryType)
	fmt.Printf("Execution Time: %dms\n", result.ExecutionTimeMs)

	if result.RowsAffected > 0 {
		fmt.Printf("Rows Affected: %d\n", result.RowsAffected)
	}

	if result.RowsReturned > 0 {
		fmt.Printf("Rows Returned: %d\n", result.RowsReturned)

		// Display result data if available
		if len(result.Columns) > 0 && len(result.Rows) > 0 {
			fmt.Println("\nResults:")
			fmt.Println(strings.Repeat("-", 50))

			// Print column headers
			fmt.Println(strings.Join(result.Columns, " | "))
			fmt.Println(strings.Repeat("-", 50))

			// Print rows (limit to first 10 for readability)
			maxRows := len(result.Rows)
			if maxRows > 10 {
				maxRows = 10
			}

			for i := 0; i < maxRows; i++ {
				fmt.Println(strings.Join(result.Rows[i], " | "))
			}

			if len(result.Rows) > 10 {
				fmt.Printf("\n... and %d more rows\n", len(result.Rows)-10)
			}
		}
	}
}

func (s *SQLCommands) displayHistory(history []*auth.SQLExecutionLog, format string) error {
	switch format {
	case "json":
		data, err := json.MarshalIndent(history, "", "  ")
		if err != nil {
			return fmt.Errorf("failed to marshal history as JSON: %v", err)
		}
		fmt.Println(string(data))
	case "csv":
		fmt.Println("ID,UserID,QueryType,Success,ExecutionTimeMs,RowsAffected,RiskLevel,CreatedAt")
		for _, entry := range history {
			fmt.Printf("%s,%s,%s,%v,%d,%d,%s,%s\n",
				entry.ID, entry.UserID, entry.QueryType, entry.Success,
				entry.ExecutionTimeMs, entry.RowsAffected, entry.RiskLevel,
				entry.CreatedAt.Format("2006-01-02 15:04:05"))
		}
	default: // table format
		fmt.Println("=== SQL Execution History ===")
		fmt.Println("ID | Query Type | Success | Time(ms) | Rows | Risk | Created")
		fmt.Println(strings.Repeat("-", 80))

		for _, entry := range history {
			status := "✓"
			if !entry.Success {
				status = "❌"
			}

			shortID := entry.ID
			if len(shortID) > 8 {
				shortID = shortID[:8] + "..."
			}

			fmt.Printf("%-12s | %-10s | %s | %8d | %4d | %-8s | %s\n",
				shortID, entry.QueryType, status, entry.ExecutionTimeMs,
				entry.RowsAffected, entry.RiskLevel,
				entry.CreatedAt.Format("01-02 15:04"))
		}

		if len(history) == 0 {
			fmt.Println("No execution history found")
		}
	}

	return nil
}

func (s *SQLCommands) initializeValidator() error {
	if s.validator != nil {
		return nil
	}

	// Initialize the SQL validator with database and RBAC engine
	s.validator = auth.NewSQLSecurityValidator(s.base.db, s.base.rbacEngine)
	return nil
}

// initializeServices initializes services including the validator
func (s *SQLCommands) initializeServices() error {
	// Initialize the SQL validator with database and RBAC engine
	if s.validator == nil {
		// For now, return nil as actual services initialization will be implemented later
		return nil
	}
	return s.initializeValidator()
}

package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"
	"golang.org/x/term"
)

// createEnvironmentCommands creates environment management commands
func createEnvironmentCommands() *cobra.Command {
	envCmd := &cobra.Command{
		Use:   "env",
		Short: "Environment detection and security policy commands",
		Long:  "Commands for detecting environment and managing environment-specific security policies",
	}

	envCmd.AddCommand(detectEnvironmentCmd())
	envCmd.AddCommand(validateEnvironmentCmd())
	envCmd.AddCommand(listPoliciesCmd())
	envCmd.AddCommand(applyPoliciesCmd())

	return envCmd
}

// detectEnvironmentCmd creates the detect command
func detectEnvironmentCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "detect",
		Short: "Detect current environment",
		Long:  "Detect the current deployment environment (development, staging, production)",
		RunE: func(cmd *cobra.Command, args []string) error {
			cli := getCLI(cmd)

			env, err := cli.envDetector.DetectEnvironment()
			if err != nil {
				return fmt.Errorf("failed to detect environment: %w", err)
			}

			if format == "json" {
				result := map[string]interface{}{
					"environment": env,
					"indicators":  cli.envDetector.GetEnvironmentIndicators(),
				}
				return json.NewEncoder(os.Stdout).Encode(result)
			}

			fmt.Printf("Detected Environment: %s\n", env)

			// Show environment indicators
			indicators := cli.envDetector.GetEnvironmentIndicators()
			if len(indicators) > 0 {
				fmt.Printf("\nEnvironment Indicators:\n")
				for key, value := range indicators {
					fmt.Printf("  %s: %v\n", key, value)
				}
			}

			// Show security requirements
			requirements := cli.envDetector.GetSecurityRequirements(env)
			if len(requirements) > 0 {
				fmt.Printf("\nSecurity Requirements for %s:\n", env)
				for _, req := range requirements {
					fmt.Printf("  • %s\n", req)
				}
			}

			return nil
		},
	}

	return cmd
}

// validateEnvironmentCmd creates the validate command
func validateEnvironmentCmd() *cobra.Command {
	var (
		environment string
		fix         bool
	)

	cmd := &cobra.Command{
		Use:   "validate",
		Short: "Validate environment configuration and security requirements",
		Long:  "Validate that the current environment meets security requirements and configuration standards",
		RunE: func(cmd *cobra.Command, args []string) error {
			cli := getCLI(cmd)

			// Use specified environment or detect current
			var env Environment
			var err error
			if environment != "" {
				env = Environment(environment)
			} else {
				env, err = cli.envDetector.DetectEnvironment()
				if err != nil {
					return fmt.Errorf("failed to detect environment: %w", err)
				}
			}

			if verbose {
				fmt.Printf("Validating environment: %s\n", env)
			}

			// Validate environment requirements
			validation, err := cli.envDetector.ValidateEnvironment(env)
			if err != nil {
				return fmt.Errorf("validation failed: %w", err)
			}

			if format == "json" {
				return json.NewEncoder(os.Stdout).Encode(validation)
			}

			// Display validation results
			fmt.Printf("Environment Validation Results for %s:\n\n", env)

			if validation.IsValid {
				fmt.Printf("✓ Environment configuration is valid\n")
			} else {
				fmt.Printf("✗ Environment configuration has issues\n")
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

			if len(validation.Recommendations) > 0 {
				fmt.Printf("\nRecommendations:\n")
				for _, rec := range validation.Recommendations {
					fmt.Printf("  💡 %s\n", rec)
				}
			}

			// Auto-fix if requested and possible
			if fix && !validation.IsValid {
				fmt.Printf("\nAttempting to fix configuration issues...\n")

				if dryRun {
					fmt.Printf("Would attempt to fix the following issues:\n")
					for _, issue := range validation.Failed {
						fmt.Printf("  - %s\n", issue)
					}
					return nil
				}

				fixResult, err := cli.envDetector.FixEnvironmentIssues(env, validation.Failed)
				if err != nil {
					return fmt.Errorf("failed to fix issues: %w", err)
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

	cmd.Flags().StringVar(&environment, "environment", "", "Environment to validate (auto-detect if not specified)")
	cmd.Flags().BoolVar(&fix, "fix", false, "Attempt to automatically fix configuration issues")

	return cmd
}

// listPoliciesCmd creates the list-policies command
func listPoliciesCmd() *cobra.Command {
	var environment string

	cmd := &cobra.Command{
		Use:   "list-policies",
		Short: "List security policies for environment",
		Long:  "List all security policies and requirements for a specific environment",
		RunE: func(cmd *cobra.Command, args []string) error {
			cli := getCLI(cmd)

			// Use specified environment or detect current
			var env Environment
			var err error
			if environment != "" {
				env = Environment(environment)
			} else {
				env, err = cli.envDetector.DetectEnvironment()
				if err != nil {
					return fmt.Errorf("failed to detect environment: %w", err)
				}
			}

			policies := cli.envDetector.GetSecurityPolicies(env)

			if format == "json" {
				return json.NewEncoder(os.Stdout).Encode(policies)
			}

			fmt.Printf("Security Policies for %s Environment:\n\n", env)

			w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "CATEGORY\tPOLICY\tREQUIRED\tDESCRIPTION")
			fmt.Fprintln(w, "--------\t------\t--------\t-----------")

			for _, policy := range policies {
				required := "No"
				if policy.Required {
					required = "Yes"
				}

				fmt.Fprintf(w, "%s\t%s\t%s\t%s\n",
					policy.Category,
					policy.Name,
					required,
					policy.Description,
				)
			}

			return w.Flush()
		},
	}

	cmd.Flags().StringVar(&environment, "environment", "", "Environment to list policies for (auto-detect if not specified)")

	return cmd
}

// applyPoliciesCmd creates the apply-policies command
func applyPoliciesCmd() *cobra.Command {
	var (
		environment string
		policyName  string
		force       bool
	)

	cmd := &cobra.Command{
		Use:   "apply-policies",
		Short: "Apply security policies to environment",
		Long:  "Apply security policies and configurations to the current or specified environment",
		RunE: func(cmd *cobra.Command, args []string) error {
			cli := getCLI(cmd)

			// Use specified environment or detect current
			var env Environment
			var err error
			if environment != "" {
				env = Environment(environment)
			} else {
				env, err = cli.envDetector.DetectEnvironment()
				if err != nil {
					return fmt.Errorf("failed to detect environment: %w", err)
				}
			}

			if verbose {
				fmt.Printf("Applying policies to environment: %s\n", env)
			}

			// Get policies to apply
			var policiesToApply []SecurityPolicy
			if policyName != "" {
				// Apply specific policy
				policy, err := cli.envDetector.GetSecurityPolicy(env, policyName)
				if err != nil {
					return fmt.Errorf("policy not found: %w", err)
				}
				policiesToApply = []SecurityPolicy{*policy}
			} else {
				// Apply all required policies
				allPolicies := cli.envDetector.GetSecurityPolicies(env)
				for _, policy := range allPolicies {
					if policy.Required {
						policiesToApply = append(policiesToApply, policy)
					}
				}
			}

			if len(policiesToApply) == 0 {
				fmt.Printf("No policies to apply for environment %s\n", env)
				return nil
			}

			// Confirmation for production environment
			if env == EnvironmentProduction && !force {
				fmt.Printf("⚠️  Applying security policies to PRODUCTION environment\n")
				fmt.Printf("Policies to apply:\n")
				for _, policy := range policiesToApply {
					fmt.Printf("  • %s: %s\n", policy.Name, policy.Description)
				}
				fmt.Printf("\nThis may affect system behavior and security settings.\n\n")

				// Check if we're in an interactive terminal
				if !term.IsTerminal(int(os.Stdin.Fd())) {
					return fmt.Errorf("operation cancelled - running in non-interactive mode (use --force to bypass confirmation)")
				}

				fmt.Print("Type 'APPLY POLICIES' to confirm: ")

				// Use bufio.Scanner for better input handling
				scanner := bufio.NewScanner(os.Stdin)

				var confirmation string
				if scanner.Scan() {
					confirmation = strings.TrimSpace(scanner.Text())
				} else {
					return fmt.Errorf("operation cancelled - failed to read input")
				}

				if confirmation != "APPLY POLICIES" {
					return fmt.Errorf("operation cancelled - incorrect confirmation (expected 'APPLY POLICIES', got '%s')", confirmation)
				}
			}

			if dryRun {
				fmt.Printf("Would apply the following policies:\n")
				for _, policy := range policiesToApply {
					fmt.Printf("  • %s (%s): %s\n", policy.Name, policy.Category, policy.Description)
				}
				return nil
			}

			// Apply policies
			results, err := cli.envDetector.ApplySecurityPolicies(env, policiesToApply)
			if err != nil {
				return fmt.Errorf("failed to apply policies: %w", err)
			}

			if format == "json" {
				return json.NewEncoder(os.Stdout).Encode(results)
			}

			fmt.Printf("Policy Application Results:\n\n")
			for _, result := range results {
				status := "✓ Applied"
				if !result.Success {
					status = "✗ Failed"
				}

				fmt.Printf("%s %s: %s\n", status, result.PolicyName, result.Message)
				if result.Error != "" {
					fmt.Printf("    Error: %s\n", result.Error)
				}
			}

			return nil
		},
	}

	cmd.Flags().StringVar(&environment, "environment", "", "Environment to apply policies to (auto-detect if not specified)")
	cmd.Flags().StringVar(&policyName, "policy", "", "Specific policy to apply (apply all required if not specified)")
	cmd.Flags().BoolVar(&force, "force", false, "Skip confirmation prompts")

	return cmd
}

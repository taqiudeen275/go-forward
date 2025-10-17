package main

import (
	"fmt"
	"os"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"github.com/taqiudeen275/go-foward/cmd/admin/commands"
)

var rootCmd = &cobra.Command{
	Use:   "go-forward-admin",
	Short: "Go Forward Admin CLI",
	Long: `Go Forward Admin CLI - Administrative command line interface for managing
the Go Forward backend framework.

This CLI provides tools for:
- Creating and managing system administrators
- Bootstrapping new deployments
- Managing user roles and permissions
- Emergency access procedures
- System maintenance tasks

Environment Detection:
The CLI automatically detects the environment (development/staging/production)
and applies appropriate security policies. Production environments require
additional confirmations and security measures.`,
	Version: "1.0.0",
}

func main() {
	// Initialize base command
	baseCmd, err := commands.InitializeBase(rootCmd)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to initialize base command: %v\n", err)
		os.Exit(1)
	}

	// Initialize command groups
	userCommands := commands.NewUserCommands(baseCmd)
	sqlCommands := commands.NewSQLCommands(baseCmd)
	systemCommands := commands.NewSystemCommands(baseCmd)

	// Register all command groups
	userCommands.RegisterCommands(rootCmd)
	sqlCommands.RegisterCommands(rootCmd)
	systemCommands.RegisterCommands(rootCmd)

	// Set global flags
	rootCmd.PersistentFlags().String("config", "", "config file (default is $HOME/.go-forward.yaml)")
	rootCmd.PersistentFlags().String("env", "", "environment override (dev/staging/prod)")
	rootCmd.PersistentFlags().Bool("verbose", false, "verbose output")
	rootCmd.PersistentFlags().Bool("yes", false, "answer yes to all prompts (use with caution)")
	rootCmd.PersistentFlags().String("log-level", "info", "log level (debug/info/warn/error)")

	// Execute the command
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func init() {
	// Set up command help and usage templates
	rootCmd.SetHelpCommand(&cobra.Command{
		Use:   "help [command]",
		Short: "Help about any command",
		Long: `Help provides help for any command in the application.
Simply type go-forward-admin help [path to command] for full details.`,
		Run: func(c *cobra.Command, args []string) {
			cmd, _, e := c.Root().Find(args)
			if cmd == nil || e != nil {
				c.Printf("Unknown help topic %#q\n", args)
			} else {
				cmd.InitDefaultHelpFlag() // make possible 'help' flag to be shown
				cmd.Help()
			}
		},
	})

	// Customize usage template
	cobra.AddTemplateFunc("StyleHeading", color.New(color.FgHiBlue, color.Bold).SprintFunc())
	cobra.AddTemplateFunc("StyleCommand", color.New(color.FgHiGreen).SprintFunc())
	cobra.AddTemplateFunc("StyleFlag", color.New(color.FgHiYellow).SprintFunc())

	rootCmd.SetUsageTemplate(`Usage:{{if .Runnable}}
  {{.UseLine}}{{end}}{{if .HasAvailableSubCommands}}
  {{.CommandPath}} [command]{{end}}{{if gt (len .Aliases) 0}}

Aliases:
  {{.NameAndAliases}}{{end}}{{if .HasExample}}

Examples:
{{.Example}}{{end}}{{if .HasAvailableSubCommands}}

{{StyleHeading "Available Commands:"}}{{range .Commands}}{{if (or .IsAvailableCommand (eq .Name "help"))}}
  {{StyleCommand .Name | printf "%-15s"}} {{.Short}}{{end}}{{end}}{{end}}{{if .HasAvailableLocalFlags}}

{{StyleHeading "Flags:"}}
{{.LocalFlags.FlagUsages | trimTrailingWhitespaces}}{{end}}{{if .HasAvailableInheritedFlags}}

{{StyleHeading "Global Flags:"}}
{{.InheritedFlags.FlagUsages | trimTrailingWhitespaces}}{{end}}{{if .HasHelpSubCommands}}

{{StyleHeading "Additional help topics:"}}{{range .Commands}}{{if .IsAdditionalHelpTopicCommand}}
  {{rpad .Name .NamePadding }} {{.Short}}{{end}}{{end}}{{end}}{{if .HasAvailableSubCommands}}

Use "{{.CommandPath}} [command] --help" for more information about a command.{{end}}
`)
}

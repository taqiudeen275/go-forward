package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/taqiudeen275/go-foward/internal/cli"
	"github.com/taqiudeen275/go-foward/internal/server"
)

func main() {
	// Detect execution mode based on arguments
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "admin":
			// CLI admin mode
			cli.ExecuteAdminCLI()
		case "migrate":
			// Migration mode
			cli.ExecuteMigrationCLI()
		case "help", "--help", "-h":
			// Help mode
			showHelp()
		default:
			// Check if it's a server flag
			if strings.HasPrefix(os.Args[1], "-") {
				// Server mode with flags
				server.Start()
			} else {
				fmt.Printf("Unknown command: %s\n", os.Args[1])
				showHelp()
				os.Exit(1)
			}
		}
	} else {
		// Default: server mode
		server.Start()
	}
}

func showHelp() {
	fmt.Println(`Unified Go Forward Framework

Usage:
  go-forward                    Start the server (default mode)
  go-forward admin <command>    Execute admin CLI commands
  go-forward migrate <command>  Execute migration commands
  go-forward --help            Show this help message

Server Mode:
  The server mode starts the HTTP server with embedded admin dashboard.
  All admin endpoints are prefixed with /_/

Admin CLI Mode:
  go-forward admin create-system-admin  Create a system administrator
  go-forward admin list                 List all administrators
  go-forward admin promote <user-id>    Promote user to admin

Migration Mode:
  go-forward migrate up                 Apply all pending migrations
  go-forward migrate down               Rollback last migration
  go-forward migrate status             Show migration status
  go-forward migrate create <name>      Create new migration

Examples:
  go-forward                           # Start server on default port
  go-forward --port 8080               # Start server on port 8080
  go-forward admin create-system-admin # Create system admin via CLI
  go-forward migrate up                # Apply migrations`)
}

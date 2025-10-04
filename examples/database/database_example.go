package main

import (
	"context"
	"fmt"
	"log"
	"os"

	"github.com/taqiudeen275/go-foward/internal/database"
)

func main() {
	// Create database configuration
	config := &database.Config{
		Host:     getEnv("DB_HOST", "localhost"),
		Port:     5432,
		Name:     getEnv("DB_NAME", "postgres"), // Use postgres database for testing
		User:     getEnv("DB_USER", "postgres"),
		Password: getEnv("DB_PASSWORD", "postgres"), // Use postgres password
		SSLMode:  getEnv("DB_SSL_MODE", "disable"),
		MaxConns: 25,
		MinConns: 5,
	}

	// Create database service
	dbService, err := database.NewService(config)
	if err != nil {
		log.Fatalf("Failed to create database service: %v", err)
	}
	defer dbService.Close()

	ctx := context.Background()

	// Initialize database (apply migrations)
	fmt.Println("Initializing database...")
	if err := dbService.Initialize(ctx); err != nil {
		log.Fatalf("Failed to initialize database: %v", err)
	}
	fmt.Println("Database initialized successfully!")

	// Check database health
	if err := dbService.Health(ctx); err != nil {
		log.Fatalf("Database health check failed: %v", err)
	}
	fmt.Println("Database health check passed!")

	// Example: Get all tables
	tables, err := dbService.Utils.GetTables(ctx, "public")
	if err != nil {
		log.Fatalf("Failed to get tables: %v", err)
	}

	fmt.Printf("Found %d tables:\n", len(tables))
	for _, table := range tables {
		fmt.Printf("- %s (%d columns)\n", table.Name, len(table.Columns))
		for _, col := range table.Columns {
			fmt.Printf("  - %s: %s\n", col.Name, col.DataType)
		}
	}

	// Example: Using query builder
	qb := database.NewQueryBuilder(dbService.DB)
	query, args := qb.Table("users").
		Select("id", "email", "username").
		Where("email_verified = ?", true).
		OrderBy("created_at", "DESC").
		Limit(10).
		Build()

	fmt.Printf("\nGenerated query: %s\n", query)
	fmt.Printf("Arguments: %v\n", args)

	// Example: Execute raw SQL
	results, err := dbService.Utils.ExecuteSQL(ctx, "SELECT COUNT(*) as user_count FROM users")
	if err != nil {
		log.Printf("Failed to execute SQL: %v", err)
	} else {
		fmt.Printf("Query results: %v\n", results)
	}

	fmt.Println("Database example completed successfully!")
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

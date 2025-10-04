package main

import (
	"flag"
	"log"
	"time"

	"github.com/taqiudeen275/go-foward/internal/config"
	"github.com/taqiudeen275/go-foward/internal/database"
)

func main() {
	var (
		up   = flag.Bool("up", false, "Apply all pending migrations")
		down = flag.Bool("down", false, "Rollback one migration")
	)
	flag.Parse()

	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	// Convert config to database config
	dbConfig := &database.Config{
		Host:            cfg.Database.Host,
		Port:            cfg.Database.Port,
		Name:            cfg.Database.Name,
		User:            cfg.Database.User,
		Password:        cfg.Database.Password,
		SSLMode:         cfg.Database.SSLMode,
		MaxConns:        int32(cfg.Database.MaxConns),
		MinConns:        5,
		MaxConnLifetime: cfg.Database.MaxLifetime,
		MaxConnIdleTime: 30 * time.Minute,
	}

	// Initialize database
	db, err := database.New(dbConfig)
	if err != nil {
		log.Fatalf("Failed to initialize database: %v", err)
	}
	defer db.Close()

	// Create migration service
	migrationService := database.NewMigrationService(db, "./migrations")

	if *up {
		log.Println("Applying migrations...")
		if err := migrationService.ApplyMigrations(); err != nil {
			log.Fatalf("Failed to apply migrations: %v", err)
		}
		log.Println("Migrations applied successfully")
	} else if *down {
		log.Println("Rolling back one migration...")
		if err := migrationService.RollbackOne(); err != nil {
			log.Fatalf("Failed to rollback migration: %v", err)
		}
		log.Println("Migration rolled back successfully")
	} else {
		// Show current version
		version, dirty, err := migrationService.GetCurrentVersion()
		if err != nil {
			log.Fatalf("Failed to get current version: %v", err)
		}
		log.Printf("Current migration version: %d (dirty: %t)", version, dirty)
	}
}

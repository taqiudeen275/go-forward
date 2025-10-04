package main

import (
	"log"
	"time"

	"github.com/taqiudeen275/go-foward/internal/config"
	"github.com/taqiudeen275/go-foward/internal/database"
	"github.com/taqiudeen275/go-foward/internal/server"
)

func main() {
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
		MinConns:        5, // Default value
		MaxConnLifetime: cfg.Database.MaxLifetime,
		MaxConnIdleTime: 30 * time.Minute, // Default value
	}

	// Initialize database
	db, err := database.New(dbConfig)
	if err != nil {
		log.Fatalf("Failed to initialize database: %v", err)
	}
	defer db.Close()

	// Create and start server
	srv := server.New(cfg, db)
	if err := srv.Start(); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}

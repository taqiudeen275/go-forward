package database

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
)

// Service represents the database service with all components
type Service struct {
	DB        *DB
	Migration *MigrationService
	Utils     *DatabaseUtils
	config    *Config
}

// NewService creates a new database service with all components
func NewService(config *Config) (*Service, error) {
	if config == nil {
		config = DefaultConfig()
	}

	// Create database connection
	db, err := New(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create database connection: %w", err)
	}

	// Find migrations directory - check multiple possible locations
	migrationsPath := findMigrationsPath()
	if err := ensureDir(migrationsPath); err != nil {
		return nil, fmt.Errorf("failed to create migrations directory: %w", err)
	}

	// Get absolute path for migrations
	absMigrationsPath, err := filepath.Abs(migrationsPath)
	if err != nil {
		return nil, fmt.Errorf("failed to get absolute migrations path: %w", err)
	}

	// Create migration service
	migrationService := NewMigrationService(db, absMigrationsPath)

	// Create database utils
	utils := NewDatabaseUtils(db)

	service := &Service{
		DB:        db,
		Migration: migrationService,
		Utils:     utils,
		config:    config,
	}

	return service, nil
}

// Initialize sets up the database with initial schema
func (s *Service) Initialize(ctx context.Context) error {
	// Apply initial migrations
	if err := s.Migration.ApplyMigrations(); err != nil {
		return fmt.Errorf("failed to apply migrations: %w", err)
	}

	return nil
}

// Close closes all database connections
func (s *Service) Close() {
	if s.DB != nil {
		s.DB.Close()
	}
}

// Health checks the database connection health
func (s *Service) Health(ctx context.Context) error {
	return s.DB.Ping(ctx)
}

// GetConfig returns the database configuration
func (s *Service) GetConfig() *Config {
	return s.config
}

// ensureDir creates a directory if it doesn't exist
func ensureDir(path string) error {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return os.MkdirAll(path, 0755)
	}
	return nil
}

// GetAbsoluteMigrationsPath returns the absolute path to migrations directory
func (s *Service) GetAbsoluteMigrationsPath() (string, error) {
	return filepath.Abs("migrations")
}

// findMigrationsPath finds the migrations directory from various possible locations
func findMigrationsPath() string {
	// Try different possible paths
	possiblePaths := []string{
		"migrations",       // From project root
		"../../migrations", // From internal/database when running tests
		"../migrations",    // From internal when running tests
	}

	for _, path := range possiblePaths {
		if _, err := os.Stat(path); err == nil {
			// Check if it actually contains migration files
			if hasMigrationFiles(path) {
				return path
			}
		}
	}

	// Default to "migrations" if none found
	return "migrations"
}

// hasMigrationFiles checks if a directory contains migration files
func hasMigrationFiles(path string) bool {
	files, err := os.ReadDir(path)
	if err != nil {
		return false
	}

	for _, file := range files {
		if !file.IsDir() && (filepath.Ext(file.Name()) == ".sql") {
			return true
		}
	}
	return false
}

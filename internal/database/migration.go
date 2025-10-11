package database

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/taqiudeen275/go-foward/pkg/errors"
	"github.com/taqiudeen275/go-foward/pkg/logger"
)

// MigrationStatus represents the status of a migration
type MigrationStatus string

const (
	MigrationStatusPending    MigrationStatus = "pending"
	MigrationStatusApplied    MigrationStatus = "applied"
	MigrationStatusFailed     MigrationStatus = "failed"
	MigrationStatusRolledBack MigrationStatus = "rolled_back"
)

// Migration represents a database migration
type Migration struct {
	ID            string          `json:"id"`
	Version       string          `json:"version"`
	Name          string          `json:"name"`
	Description   string          `json:"description"`
	UpSQL         string          `json:"up_sql"`
	DownSQL       string          `json:"down_sql"`
	CreatedBy     string          `json:"created_by"`
	CreatedAt     time.Time       `json:"created_at"`
	AppliedAt     *time.Time      `json:"applied_at"`
	AppliedBy     *string         `json:"applied_by"`
	RolledBackAt  *time.Time      `json:"rolled_back_at"`
	RolledBackBy  *string         `json:"rolled_back_by"`
	ExecutionTime *time.Duration  `json:"execution_time"`
	Status        MigrationStatus `json:"status"`
	ErrorMessage  *string         `json:"error_message"`
	Checksum      string          `json:"checksum"`
	Dependencies  []string        `json:"dependencies"`
}

// MigrationManager handles database migrations
type MigrationManager struct {
	db     *Database
	logger *logger.Logger
}

// NewMigrationManager creates a new migration manager
func NewMigrationManager(db *Database) *MigrationManager {
	return &MigrationManager{
		db:     db,
		logger: logger.GetLogger(),
	}
}

// Initialize creates the migration tracking table
func (mm *MigrationManager) Initialize(ctx context.Context) error {
	query := `
		CREATE TABLE IF NOT EXISTS migrations (
			id VARCHAR(255) PRIMARY KEY,
			version VARCHAR(50) NOT NULL,
			name VARCHAR(255) NOT NULL,
			description TEXT,
			up_sql TEXT NOT NULL,
			down_sql TEXT,
			created_by VARCHAR(255),
			created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
			applied_at TIMESTAMP WITH TIME ZONE,
			applied_by VARCHAR(255),
			rolled_back_at TIMESTAMP WITH TIME ZONE,
			rolled_back_by VARCHAR(255),
			execution_time INTERVAL,
			status VARCHAR(20) NOT NULL DEFAULT 'pending',
			error_message TEXT,
			checksum VARCHAR(64) NOT NULL,
			dependencies TEXT[]
		);

		CREATE INDEX IF NOT EXISTS idx_migrations_version ON migrations(version);
		CREATE INDEX IF NOT EXISTS idx_migrations_status ON migrations(status);
		CREATE INDEX IF NOT EXISTS idx_migrations_applied_at ON migrations(applied_at);
	`

	_, err := mm.db.ExecuteExec(ctx, query)
	if err != nil {
		return errors.NewDatabaseError(fmt.Sprintf("Failed to initialize migration table: %v", err))
	}

	mm.logger.Info("Migration system initialized")
	return nil
}

// LoadMigrationsFromDirectory loads migrations from the migrations directory
func (mm *MigrationManager) LoadMigrationsFromDirectory(ctx context.Context, dir string) ([]*Migration, error) {
	var migrations []*Migration

	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if d.IsDir() || !strings.HasSuffix(path, ".up.sql") {
			return nil
		}

		// Parse migration file
		migration, err := mm.parseMigrationFile(path)
		if err != nil {
			mm.logger.Warn("Failed to parse migration file", "file", path, "error", err)
			return nil // Continue with other files
		}

		migrations = append(migrations, migration)
		return nil
	})

	if err != nil {
		return nil, errors.NewDatabaseError(fmt.Sprintf("Failed to load migrations: %v", err))
	}

	// Sort migrations by version
	sort.Slice(migrations, func(i, j int) bool {
		return migrations[i].Version < migrations[j].Version
	})

	return migrations, nil
}

// parseMigrationFile parses a migration file and returns a Migration
func (mm *MigrationManager) parseMigrationFile(upPath string) (*Migration, error) {
	// Read up migration
	upSQL, err := os.ReadFile(upPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read up migration: %v", err)
	}

	// Try to read down migration
	downPath := strings.Replace(upPath, ".up.sql", ".down.sql", 1)
	var downSQL []byte
	if _, err := os.Stat(downPath); err == nil {
		downSQL, _ = os.ReadFile(downPath)
	}

	// Parse filename to extract version and name
	filename := filepath.Base(upPath)
	parts := strings.SplitN(filename, "_", 2)
	if len(parts) < 2 {
		return nil, fmt.Errorf("invalid migration filename format: %s", filename)
	}

	version := parts[0]
	name := strings.TrimSuffix(parts[1], ".up.sql")
	name = strings.ReplaceAll(name, "_", " ")

	migration := &Migration{
		ID:        fmt.Sprintf("%s_%s", version, strings.ReplaceAll(name, " ", "_")),
		Version:   version,
		Name:      name,
		UpSQL:     string(upSQL),
		DownSQL:   string(downSQL),
		CreatedAt: time.Now().UTC(),
		Status:    MigrationStatusPending,
		Checksum:  mm.calculateChecksum(string(upSQL)),
	}

	return migration, nil
}

// calculateChecksum calculates a checksum for the migration SQL
func (mm *MigrationManager) calculateChecksum(sql string) string {
	// Simple checksum - in production, use a proper hash function
	return fmt.Sprintf("%x", len(sql))
}

// GetMigrationStatus returns the status of all migrations
func (mm *MigrationManager) GetMigrationStatus(ctx context.Context) ([]*Migration, error) {
	query := `
		SELECT id, version, name, description, up_sql, down_sql, 
			   created_by, created_at, applied_at, applied_by, 
			   rolled_back_at, rolled_back_by, execution_time, 
			   status, error_message, checksum, dependencies
		FROM migrations 
		ORDER BY version
	`

	rows, err := mm.db.ExecuteQuery(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var migrations []*Migration
	for rows.Next() {
		migration := &Migration{}
		err := rows.Scan(
			&migration.ID, &migration.Version, &migration.Name, &migration.Description,
			&migration.UpSQL, &migration.DownSQL, &migration.CreatedBy, &migration.CreatedAt,
			&migration.AppliedAt, &migration.AppliedBy, &migration.RolledBackAt, &migration.RolledBackBy,
			&migration.ExecutionTime, &migration.Status, &migration.ErrorMessage, &migration.Checksum,
			&migration.Dependencies,
		)
		if err != nil {
			return nil, errors.NewDatabaseError(fmt.Sprintf("Failed to scan migration: %v", err))
		}
		migrations = append(migrations, migration)
	}

	return migrations, nil
}

// ApplyMigration applies a single migration
func (mm *MigrationManager) ApplyMigration(ctx context.Context, migration *Migration, appliedBy string) error {
	start := time.Now()

	// Start transaction
	return mm.db.WithTx(ctx, func(tx pgx.Tx) error {
		// Execute migration SQL
		_, err := tx.Exec(ctx, migration.UpSQL)
		if err != nil {
			// Record failed migration
			mm.recordMigrationResult(ctx, tx, migration, appliedBy, MigrationStatusFailed, err.Error(), time.Since(start))
			return errors.NewDatabaseError(fmt.Sprintf("Migration %s failed: %v", migration.ID, err))
		}

		// Record successful migration
		return mm.recordMigrationResult(ctx, tx, migration, appliedBy, MigrationStatusApplied, "", time.Since(start))
	})
}

// RollbackMigration rolls back a single migration
func (mm *MigrationManager) RollbackMigration(ctx context.Context, migration *Migration, rolledBackBy string) error {
	if migration.DownSQL == "" {
		return errors.NewDatabaseError(fmt.Sprintf("Migration %s has no down SQL", migration.ID))
	}

	start := time.Now()

	// Start transaction
	return mm.db.WithTx(ctx, func(tx pgx.Tx) error {
		// Execute rollback SQL
		_, err := tx.Exec(ctx, migration.DownSQL)
		if err != nil {
			return errors.NewDatabaseError(fmt.Sprintf("Rollback %s failed: %v", migration.ID, err))
		}

		// Update migration record
		query := `
			UPDATE migrations 
			SET rolled_back_at = NOW(), 
				rolled_back_by = $1, 
				status = $2,
				execution_time = $3
			WHERE id = $4
		`
		_, err = tx.Exec(ctx, query, rolledBackBy, MigrationStatusRolledBack, time.Since(start), migration.ID)
		if err != nil {
			return errors.NewDatabaseError(fmt.Sprintf("Failed to update migration record: %v", err))
		}

		mm.logger.Info("Migration rolled back", "migration", migration.ID, "duration", time.Since(start))
		return nil
	})
}

// recordMigrationResult records the result of a migration
func (mm *MigrationManager) recordMigrationResult(ctx context.Context, tx pgx.Tx, migration *Migration, appliedBy string, status MigrationStatus, errorMsg string, duration time.Duration) error {
	query := `
		INSERT INTO migrations (id, version, name, description, up_sql, down_sql, 
							   created_by, applied_at, applied_by, execution_time, 
							   status, error_message, checksum, dependencies)
		VALUES ($1, $2, $3, $4, $5, $6, $7, NOW(), $8, $9, $10, $11, $12, $13)
		ON CONFLICT (id) DO UPDATE SET
			applied_at = NOW(),
			applied_by = $8,
			execution_time = $9,
			status = $10,
			error_message = $11
	`

	var errorMessage *string
	if errorMsg != "" {
		errorMessage = &errorMsg
	}

	_, err := tx.Exec(ctx, query,
		migration.ID, migration.Version, migration.Name, migration.Description,
		migration.UpSQL, migration.DownSQL, migration.CreatedBy,
		appliedBy, duration, status, errorMessage, migration.Checksum, migration.Dependencies,
	)

	if err != nil {
		return errors.NewDatabaseError(fmt.Sprintf("Failed to record migration result: %v", err))
	}

	if status == MigrationStatusApplied {
		mm.logger.Info("Migration applied", "migration", migration.ID, "duration", duration)
	}

	return nil
}

// ApplyPendingMigrations applies all pending migrations
func (mm *MigrationManager) ApplyPendingMigrations(ctx context.Context, appliedBy string) error {
	// Load migrations from directory
	migrations, err := mm.LoadMigrationsFromDirectory(ctx, "migrations")
	if err != nil {
		return err
	}

	// Get current migration status
	appliedMigrations, err := mm.GetMigrationStatus(ctx)
	if err != nil {
		return err
	}

	// Create map of applied migrations
	appliedMap := make(map[string]bool)
	for _, m := range appliedMigrations {
		if m.Status == MigrationStatusApplied {
			appliedMap[m.ID] = true
		}
	}

	// Apply pending migrations
	for _, migration := range migrations {
		if !appliedMap[migration.ID] {
			mm.logger.Info("Applying migration", "migration", migration.ID)
			if err := mm.ApplyMigration(ctx, migration, appliedBy); err != nil {
				return err
			}
		}
	}

	return nil
}

// CreateMigration creates a new migration file
func (mm *MigrationManager) CreateMigration(name, description string) (*Migration, error) {
	// Generate version (timestamp)
	version := strconv.FormatInt(time.Now().Unix(), 10)

	// Clean name
	cleanName := strings.ReplaceAll(strings.ToLower(name), " ", "_")

	migration := &Migration{
		ID:          fmt.Sprintf("%s_%s", version, cleanName),
		Version:     version,
		Name:        name,
		Description: description,
		CreatedAt:   time.Now().UTC(),
		Status:      MigrationStatusPending,
	}

	// Create migration files
	upPath := fmt.Sprintf("migrations/%s_%s.up.sql", version, cleanName)
	downPath := fmt.Sprintf("migrations/%s_%s.down.sql", version, cleanName)

	// Create up migration file
	upContent := fmt.Sprintf(`-- Migration: %s
-- Description: %s
-- Created: %s

-- Add your up migration SQL here

`, name, description, time.Now().Format(time.RFC3339))

	if err := os.WriteFile(upPath, []byte(upContent), 0644); err != nil {
		return nil, errors.NewDatabaseError(fmt.Sprintf("Failed to create up migration file: %v", err))
	}

	// Create down migration file
	downContent := fmt.Sprintf(`-- Rollback Migration: %s
-- Description: %s
-- Created: %s

-- Add your down migration SQL here

`, name, description, time.Now().Format(time.RFC3339))

	if err := os.WriteFile(downPath, []byte(downContent), 0644); err != nil {
		return nil, errors.NewDatabaseError(fmt.Sprintf("Failed to create down migration file: %v", err))
	}

	mm.logger.Info("Migration files created", "up", upPath, "down", downPath)
	return migration, nil
}

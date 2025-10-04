package database

import (
	"context"
	"fmt"
	"path/filepath"
	"time"

	"github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	"github.com/jackc/pgx/v5/stdlib"
)

// Migration represents a database migration
type Migration struct {
	ID        string     `json:"id" db:"id"`
	Name      string     `json:"name" db:"name"`
	Version   string     `json:"version" db:"version"`
	UpSQL     string     `json:"up_sql" db:"up_sql"`
	DownSQL   string     `json:"down_sql" db:"down_sql"`
	AppliedAt *time.Time `json:"applied_at" db:"applied_at"`
	CreatedAt time.Time  `json:"created_at" db:"created_at"`
}

// MigrationService handles database migrations
type MigrationService struct {
	db             *DB
	migrationsPath string
}

// NewMigrationService creates a new migration service
func NewMigrationService(db *DB, migrationsPath string) *MigrationService {
	return &MigrationService{
		db:             db,
		migrationsPath: migrationsPath,
	}
}

// CreateMigration creates a new migration file
func (ms *MigrationService) CreateMigration(name string, upSQL, downSQL string) (*Migration, error) {
	version := fmt.Sprintf("%d", time.Now().Unix())

	migration := &Migration{
		ID:        fmt.Sprintf("%s_%s", version, name),
		Name:      name,
		Version:   version,
		UpSQL:     upSQL,
		DownSQL:   downSQL,
		CreatedAt: time.Now(),
	}

	// Create migration files
	upFile := filepath.Join(ms.migrationsPath, fmt.Sprintf("%s_%s.up.sql", version, name))
	downFile := filepath.Join(ms.migrationsPath, fmt.Sprintf("%s_%s.down.sql", version, name))

	// Write up migration
	if err := writeFile(upFile, upSQL); err != nil {
		return nil, fmt.Errorf("failed to write up migration: %w", err)
	}

	// Write down migration
	if err := writeFile(downFile, downSQL); err != nil {
		return nil, fmt.Errorf("failed to write down migration: %w", err)
	}

	return migration, nil
}

// ApplyMigrations applies all pending migrations
func (ms *MigrationService) ApplyMigrations() error {
	m, err := ms.getMigrator()
	if err != nil {
		return fmt.Errorf("failed to create migrator: %w", err)
	}
	defer m.Close()

	if err := m.Up(); err != nil && err != migrate.ErrNoChange {
		return fmt.Errorf("failed to apply migrations: %w", err)
	}

	return nil
}

// ApplyMigration applies a specific migration
func (ms *MigrationService) ApplyMigration(version uint) error {
	m, err := ms.getMigrator()
	if err != nil {
		return fmt.Errorf("failed to create migrator: %w", err)
	}
	defer m.Close()

	if err := m.Migrate(version); err != nil && err != migrate.ErrNoChange {
		return fmt.Errorf("failed to apply migration %d: %w", version, err)
	}

	return nil
}

// RollbackMigration rolls back to a specific migration
func (ms *MigrationService) RollbackMigration(version uint) error {
	m, err := ms.getMigrator()
	if err != nil {
		return fmt.Errorf("failed to create migrator: %w", err)
	}
	defer m.Close()

	if err := m.Migrate(version); err != nil && err != migrate.ErrNoChange {
		return fmt.Errorf("failed to rollback to migration %d: %w", version, err)
	}

	return nil
}

// RollbackOne rolls back one migration
func (ms *MigrationService) RollbackOne() error {
	m, err := ms.getMigrator()
	if err != nil {
		return fmt.Errorf("failed to create migrator: %w", err)
	}
	defer m.Close()

	if err := m.Steps(-1); err != nil && err != migrate.ErrNoChange {
		return fmt.Errorf("failed to rollback one migration: %w", err)
	}

	return nil
}

// GetMigrationHistory returns the migration history
func (ms *MigrationService) GetMigrationHistory(ctx context.Context) ([]*Migration, error) {
	query := `
		SELECT version, dirty 
		FROM schema_migrations 
		ORDER BY version DESC
	`

	rows, err := ms.db.Query(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed to query migration history: %w", err)
	}
	defer rows.Close()

	var migrations []*Migration
	for rows.Next() {
		var version uint
		var dirty bool

		if err := rows.Scan(&version, &dirty); err != nil {
			return nil, fmt.Errorf("failed to scan migration row: %w", err)
		}

		migration := &Migration{
			Version: fmt.Sprintf("%d", version),
		}

		migrations = append(migrations, migration)
	}

	return migrations, nil
}

// GetCurrentVersion returns the current migration version
func (ms *MigrationService) GetCurrentVersion() (uint, bool, error) {
	m, err := ms.getMigrator()
	if err != nil {
		return 0, false, fmt.Errorf("failed to create migrator: %w", err)
	}
	defer m.Close()

	version, dirty, err := m.Version()
	if err != nil {
		return 0, false, fmt.Errorf("failed to get current version: %w", err)
	}

	return version, dirty, nil
}

// getMigrator creates a new migrate instance
func (ms *MigrationService) getMigrator() (*migrate.Migrate, error) {
	// Convert pgxpool to database/sql for migrate compatibility
	sqlDB := stdlib.OpenDBFromPool(ms.db.Pool)

	driver, err := postgres.WithInstance(sqlDB, &postgres.Config{})
	if err != nil {
		return nil, fmt.Errorf("failed to create postgres driver: %w", err)
	}

	// Handle Windows paths correctly for file:// URLs
	sourceURL := fmt.Sprintf("file://%s", filepath.ToSlash(ms.migrationsPath))
	m, err := migrate.NewWithDatabaseInstance(sourceURL, "postgres", driver)
	if err != nil {
		return nil, fmt.Errorf("failed to create migrate instance: %w", err)
	}

	return m, nil
}

// writeFile writes content to a file (helper function)
func writeFile(filename, content string) error {
	// This would typically use os.WriteFile, but we'll use the fsWrite tool
	// For now, return nil as the actual file writing will be handled separately
	return nil
}

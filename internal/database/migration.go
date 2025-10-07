package database

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
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
	Status    string     `json:"status"` // pending, applied, failed
	Dirty     bool       `json:"dirty"`  // indicates if migration is in inconsistent state
}

// MigrationTemplate represents a migration template
type MigrationTemplate struct {
	Name         string
	Description  string
	UpTemplate   string
	DownTemplate string
}

// MigrationInfo represents migration file information
type MigrationInfo struct {
	Version   uint
	Name      string
	UpFile    string
	DownFile  string
	Applied   bool
	AppliedAt *time.Time
}

// MigrationService handles database migrations
type MigrationService struct {
	db             *DB
	migrationsPath string
	templates      map[string]*MigrationTemplate
}

// Migration templates for common operations
var defaultTemplates = map[string]*MigrationTemplate{
	"create_table": {
		Name:        "create_table",
		Description: "Create a new table",
		UpTemplate: `-- Create {{.TableName}} table
CREATE TABLE IF NOT EXISTS {{.TableName}} (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Create indexes for {{.TableName}} table
CREATE INDEX IF NOT EXISTS idx_{{.TableName}}_created_at ON {{.TableName}}(created_at);

-- Create trigger for {{.TableName}} table
CREATE TRIGGER update_{{.TableName}}_updated_at 
    BEFORE UPDATE ON {{.TableName}} 
    FOR EACH ROW 
    EXECUTE FUNCTION update_updated_at_column();`,
		DownTemplate: `-- Drop {{.TableName}} table
DROP TRIGGER IF EXISTS update_{{.TableName}}_updated_at ON {{.TableName}};
DROP INDEX IF EXISTS idx_{{.TableName}}_created_at;
DROP TABLE IF EXISTS {{.TableName}};`,
	},
	"add_column": {
		Name:        "add_column",
		Description: "Add a column to an existing table",
		UpTemplate: `-- Add {{.ColumnName}} column to {{.TableName}} table
ALTER TABLE {{.TableName}} ADD COLUMN {{.ColumnName}} {{.ColumnType}}{{if .NotNull}} NOT NULL{{end}}{{if .DefaultValue}} DEFAULT {{.DefaultValue}}{{end}};

{{if .CreateIndex}}-- Create index for {{.ColumnName}}
CREATE INDEX IF NOT EXISTS idx_{{.TableName}}_{{.ColumnName}} ON {{.TableName}}({{.ColumnName}});{{end}}`,
		DownTemplate: `-- Remove {{.ColumnName}} column from {{.TableName}} table
{{if .CreateIndex}}DROP INDEX IF EXISTS idx_{{.TableName}}_{{.ColumnName}};{{end}}
ALTER TABLE {{.TableName}} DROP COLUMN IF EXISTS {{.ColumnName}};`,
	},
	"create_index": {
		Name:        "create_index",
		Description: "Create an index on a table",
		UpTemplate: `-- Create {{.IndexType}} index on {{.TableName}}
CREATE {{if .Unique}}UNIQUE {{end}}INDEX IF NOT EXISTS {{.IndexName}} ON {{.TableName}}({{.Columns}});`,
		DownTemplate: `-- Drop index {{.IndexName}}
DROP INDEX IF EXISTS {{.IndexName}};`,
	},
	"empty": {
		Name:         "empty",
		Description:  "Empty migration template",
		UpTemplate:   "-- Add your migration SQL here\n",
		DownTemplate: "-- Add your rollback SQL here\n",
	},
}

// NewMigrationService creates a new migration service
func NewMigrationService(db *DB, migrationsPath string) *MigrationService {
	ms := &MigrationService{
		db:             db,
		migrationsPath: migrationsPath,
		templates:      make(map[string]*MigrationTemplate),
	}

	// Load default templates
	for name, template := range defaultTemplates {
		ms.templates[name] = template
	}

	// Ensure migrations directory exists
	if err := os.MkdirAll(migrationsPath, 0755); err != nil {
		// Log error but don't fail initialization
		fmt.Printf("Warning: failed to create migrations directory: %v\n", err)
	}

	return ms
}

// CreateMigration creates a new migration file with proper versioning
func (ms *MigrationService) CreateMigration(name string, upSQL, downSQL string) (*Migration, error) {
	// Generate next version number
	version, err := ms.getNextVersion()
	if err != nil {
		return nil, fmt.Errorf("failed to get next version: %w", err)
	}

	// Sanitize migration name
	sanitizedName := ms.sanitizeMigrationName(name)

	migration := &Migration{
		ID:        uuid.New().String(),
		Name:      sanitizedName,
		Version:   fmt.Sprintf("%d", version),
		UpSQL:     upSQL,
		DownSQL:   downSQL,
		CreatedAt: time.Now(),
		Status:    "pending",
	}

	// Create migration files with proper naming convention
	upFile := filepath.Join(ms.migrationsPath, fmt.Sprintf("%06d_%s.up.sql", version, sanitizedName))
	downFile := filepath.Join(ms.migrationsPath, fmt.Sprintf("%06d_%s.down.sql", version, sanitizedName))

	// Write up migration
	if err := ms.writeFile(upFile, upSQL); err != nil {
		return nil, fmt.Errorf("failed to write up migration: %w", err)
	}

	// Write down migration
	if err := ms.writeFile(downFile, downSQL); err != nil {
		return nil, fmt.Errorf("failed to write down migration: %w", err)
	}

	// Store migration metadata in database
	if err := ms.storeMigrationMetadata(migration); err != nil {
		return nil, fmt.Errorf("failed to store migration metadata: %w", err)
	}

	return migration, nil
}

// CreateMigrationFromTemplate creates a migration using a template
func (ms *MigrationService) CreateMigrationFromTemplate(name, templateName string, params map[string]interface{}) (*Migration, error) {
	template, exists := ms.templates[templateName]
	if !exists {
		return nil, fmt.Errorf("template '%s' not found", templateName)
	}

	// Process template with parameters
	upSQL, err := ms.processTemplate(template.UpTemplate, params)
	if err != nil {
		return nil, fmt.Errorf("failed to process up template: %w", err)
	}

	downSQL, err := ms.processTemplate(template.DownTemplate, params)
	if err != nil {
		return nil, fmt.Errorf("failed to process down template: %w", err)
	}

	return ms.CreateMigration(name, upSQL, downSQL)
}

// getNextVersion generates the next migration version number
func (ms *MigrationService) getNextVersion() (uint, error) {
	files, err := os.ReadDir(ms.migrationsPath)
	if err != nil {
		return 1, nil // Start with version 1 if directory doesn't exist or is empty
	}

	var maxVersion uint = 0
	versionRegex := regexp.MustCompile(`^(\d+)_.*\.(up|down)\.sql$`)

	for _, file := range files {
		if file.IsDir() {
			continue
		}

		matches := versionRegex.FindStringSubmatch(file.Name())
		if len(matches) >= 2 {
			version, err := strconv.ParseUint(matches[1], 10, 32)
			if err != nil {
				continue
			}
			if uint(version) > maxVersion {
				maxVersion = uint(version)
			}
		}
	}

	return maxVersion + 1, nil
}

// sanitizeMigrationName sanitizes the migration name for file naming
func (ms *MigrationService) sanitizeMigrationName(name string) string {
	// Convert to lowercase and replace spaces/special chars with underscores
	reg := regexp.MustCompile(`[^a-zA-Z0-9_]`)
	sanitized := reg.ReplaceAllString(strings.ToLower(name), "_")

	// Remove multiple consecutive underscores
	reg = regexp.MustCompile(`_+`)
	sanitized = reg.ReplaceAllString(sanitized, "_")

	// Trim leading/trailing underscores
	sanitized = strings.Trim(sanitized, "_")

	if sanitized == "" {
		sanitized = "migration"
	}

	return sanitized
}

// processTemplate processes a template string with parameters
func (ms *MigrationService) processTemplate(template string, params map[string]interface{}) (string, error) {
	result := template

	// Simple template processing - replace {{.Key}} with values
	for key, value := range params {
		placeholder := fmt.Sprintf("{{.%s}}", key)
		result = strings.ReplaceAll(result, placeholder, fmt.Sprintf("%v", value))
	}

	// Handle conditional blocks like {{if .NotNull}}
	// This is a simplified implementation - in production, you might want to use text/template
	result = ms.processConditionals(result, params)

	return result, nil
}

// processConditionals handles simple conditional blocks in templates
func (ms *MigrationService) processConditionals(template string, params map[string]interface{}) string {
	// Handle {{if .Key}}...{{end}} blocks
	ifRegex := regexp.MustCompile(`\{\{if \.(\w+)\}\}(.*?)\{\{end\}\}`)

	return ifRegex.ReplaceAllStringFunc(template, func(match string) string {
		matches := ifRegex.FindStringSubmatch(match)
		if len(matches) >= 3 {
			key := matches[1]
			content := matches[2]

			if value, exists := params[key]; exists {
				// Check if value is truthy
				if ms.isTruthy(value) {
					return content
				}
			}
		}
		return ""
	})
}

// isTruthy checks if a value is considered truthy
func (ms *MigrationService) isTruthy(value interface{}) bool {
	switch v := value.(type) {
	case bool:
		return v
	case string:
		return v != ""
	case int, int32, int64:
		return v != 0
	case nil:
		return false
	default:
		return true
	}
}

// MigrationResult represents the result of a migration operation
type MigrationResult struct {
	Version   uint          `json:"version"`
	Name      string        `json:"name"`
	Direction string        `json:"direction"` // up or down
	Success   bool          `json:"success"`
	Error     string        `json:"error,omitempty"`
	Duration  time.Duration `json:"duration"`
	AppliedAt time.Time     `json:"applied_at"`
}

// ApplyMigrations applies all pending migrations with transaction safety
func (ms *MigrationService) ApplyMigrations() ([]*MigrationResult, error) {
	return ms.ApplyMigrationsWithCallback(nil)
}

// ApplyMigrationsWithCallback applies all pending migrations with progress callback
func (ms *MigrationService) ApplyMigrationsWithCallback(callback func(*MigrationResult)) ([]*MigrationResult, error) {
	ctx := context.Background()

	// Get pending migrations
	migrations, err := ms.GetMigrationStatus(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get migration status: %w", err)
	}

	var results []*MigrationResult

	for _, migration := range migrations {
		if migration.Applied {
			continue // Skip already applied migrations
		}

		result := ms.applyMigrationWithTransaction(ctx, migration.Version, migration.Name, "up")
		results = append(results, result)

		if callback != nil {
			callback(result)
		}

		// Stop on first error
		if !result.Success {
			break
		}
	}

	return results, nil
}

// ApplyMigration applies a specific migration with transaction safety
func (ms *MigrationService) ApplyMigration(version uint) (*MigrationResult, error) {
	ctx := context.Background()

	// Get migration info
	migrations, err := ms.getMigrationFiles()
	if err != nil {
		return nil, fmt.Errorf("failed to get migration files: %w", err)
	}

	var targetMigration *MigrationInfo
	for _, m := range migrations {
		if m.Version == version {
			targetMigration = m
			break
		}
	}

	if targetMigration == nil {
		return nil, fmt.Errorf("migration version %d not found", version)
	}

	result := ms.applyMigrationWithTransaction(ctx, version, targetMigration.Name, "up")
	return result, nil
}

// applyMigrationWithTransaction applies a single migration within a transaction
func (ms *MigrationService) applyMigrationWithTransaction(ctx context.Context, version uint, name, direction string) *MigrationResult {
	startTime := time.Now()
	result := &MigrationResult{
		Version:   version,
		Name:      name,
		Direction: direction,
		AppliedAt: startTime,
	}

	// Start transaction
	tx, err := ms.db.Begin(ctx)
	if err != nil {
		result.Error = fmt.Sprintf("failed to start transaction: %v", err)
		result.Duration = time.Since(startTime)
		return result
	}

	defer func() {
		if !result.Success {
			tx.Rollback(ctx)
		}
	}()

	// Use golang-migrate for the actual migration
	m, err := ms.getMigrator()
	if err != nil {
		result.Error = fmt.Sprintf("failed to create migrator: %v", err)
		result.Duration = time.Since(startTime)
		return result
	}
	defer m.Close()

	// Apply the migration
	if direction == "up" {
		err = m.Migrate(version)
	} else {
		// For rollback, we need to go to the previous version
		if version > 0 {
			err = m.Migrate(version - 1)
		} else {
			err = m.Down()
		}
	}

	if err != nil && err != migrate.ErrNoChange {
		result.Error = fmt.Sprintf("migration failed: %v", err)
		result.Duration = time.Since(startTime)
		return result
	}

	// Update metadata
	if direction == "up" {
		err = ms.updateMigrationAppliedStatus(ctx, tx, version, true)
	} else {
		err = ms.updateMigrationAppliedStatus(ctx, tx, version, false)
	}

	if err != nil {
		result.Error = fmt.Sprintf("failed to update migration metadata: %v", err)
		result.Duration = time.Since(startTime)
		return result
	}

	// Commit transaction
	if err := tx.Commit(ctx); err != nil {
		result.Error = fmt.Sprintf("failed to commit transaction: %v", err)
		result.Duration = time.Since(startTime)
		return result
	}

	result.Success = true
	result.Duration = time.Since(startTime)
	return result
}

// RollbackMigration rolls back to a specific migration with validation
func (ms *MigrationService) RollbackMigration(version uint) (*MigrationResult, error) {
	ctx := context.Background()

	// Validate rollback is safe
	currentVersion, dirty, err := ms.GetCurrentVersion()
	if err != nil {
		return nil, fmt.Errorf("failed to get current version: %w", err)
	}

	if dirty {
		return nil, fmt.Errorf("database is in dirty state, cannot rollback safely")
	}

	if version >= currentVersion {
		return nil, fmt.Errorf("cannot rollback to version %d, current version is %d", version, currentVersion)
	}

	// Get migration info
	migrations, err := ms.getMigrationFiles()
	if err != nil {
		return nil, fmt.Errorf("failed to get migration files: %w", err)
	}

	var targetMigration *MigrationInfo
	for _, m := range migrations {
		if m.Version == currentVersion {
			targetMigration = m
			break
		}
	}

	if targetMigration == nil {
		return nil, fmt.Errorf("current migration version %d not found", currentVersion)
	}

	result := ms.applyMigrationWithTransaction(ctx, currentVersion, targetMigration.Name, "down")
	return result, nil
}

// RollbackOne rolls back one migration with validation
func (ms *MigrationService) RollbackOne() (*MigrationResult, error) {
	currentVersion, dirty, err := ms.GetCurrentVersion()
	if err != nil {
		return nil, fmt.Errorf("failed to get current version: %w", err)
	}

	if dirty {
		return nil, fmt.Errorf("database is in dirty state, cannot rollback safely")
	}

	if currentVersion == 0 {
		return nil, fmt.Errorf("no migrations to rollback")
	}

	return ms.RollbackMigration(currentVersion - 1)
}

// RollbackToVersion rolls back to a specific version, applying multiple rollbacks if needed
func (ms *MigrationService) RollbackToVersion(targetVersion uint) ([]*MigrationResult, error) {
	currentVersion, dirty, err := ms.GetCurrentVersion()
	if err != nil {
		return nil, fmt.Errorf("failed to get current version: %w", err)
	}

	if dirty {
		return nil, fmt.Errorf("database is in dirty state, cannot rollback safely")
	}

	if targetVersion >= currentVersion {
		return nil, fmt.Errorf("target version %d must be less than current version %d", targetVersion, currentVersion)
	}

	var results []*MigrationResult

	// Rollback migrations one by one from current to target
	for version := currentVersion; version > targetVersion; version-- {
		result, err := ms.RollbackMigration(version - 1)
		if err != nil {
			return results, fmt.Errorf("failed to rollback migration %d: %w", version, err)
		}

		results = append(results, result)

		if !result.Success {
			return results, fmt.Errorf("rollback failed at version %d: %s", version, result.Error)
		}
	}

	return results, nil
}

// updateMigrationAppliedStatus updates the applied status of a migration
func (ms *MigrationService) updateMigrationAppliedStatus(ctx context.Context, tx pgx.Tx, version uint, applied bool) error {
	var appliedAt *time.Time
	if applied {
		now := time.Now()
		appliedAt = &now
	}

	query := `
		UPDATE migrations_metadata 
		SET applied_at = $1 
		WHERE version = $2
	`

	_, err := tx.Exec(ctx, query, appliedAt, fmt.Sprintf("%d", version))
	return err
}

// ValidateRollback validates if a rollback operation is safe
func (ms *MigrationService) ValidateRollback(targetVersion uint) error {
	currentVersion, dirty, err := ms.GetCurrentVersion()
	if err != nil {
		return fmt.Errorf("failed to get current version: %w", err)
	}

	if dirty {
		return fmt.Errorf("database is in dirty state, rollback not safe")
	}

	if targetVersion >= currentVersion {
		return fmt.Errorf("target version %d must be less than current version %d", targetVersion, currentVersion)
	}

	// Check if all migrations between current and target have down files
	migrations, err := ms.getMigrationFiles()
	if err != nil {
		return fmt.Errorf("failed to get migration files: %w", err)
	}

	for _, migration := range migrations {
		if migration.Version > targetVersion && migration.Version <= currentVersion {
			if migration.DownFile == "" {
				return fmt.Errorf("migration %d_%s has no down file, rollback not possible", migration.Version, migration.Name)
			}
		}
	}

	return nil
}

// RepairDirtyState attempts to repair a dirty migration state
func (ms *MigrationService) RepairDirtyState() error {
	currentVersion, dirty, err := ms.GetCurrentVersion()
	if err != nil {
		return fmt.Errorf("failed to get current version: %w", err)
	}

	if !dirty {
		return fmt.Errorf("database is not in dirty state")
	}

	m, err := ms.getMigrator()
	if err != nil {
		return fmt.Errorf("failed to create migrator: %w", err)
	}
	defer m.Close()

	// Force the version to be clean
	if err := m.Force(int(currentVersion)); err != nil {
		return fmt.Errorf("failed to force clean state: %w", err)
	}

	return nil
}

// GetMigrationHistory returns the migration history with detailed information
func (ms *MigrationService) GetMigrationHistory(ctx context.Context) ([]*Migration, error) {
	// First get applied migrations from schema_migrations table
	appliedQuery := `
		SELECT version, dirty 
		FROM schema_migrations 
		ORDER BY version DESC
	`

	appliedRows, err := ms.db.Query(ctx, appliedQuery)
	if err != nil {
		return nil, fmt.Errorf("failed to query applied migrations: %w", err)
	}
	defer appliedRows.Close()

	appliedMigrations := make(map[uint]bool)
	dirtyMigrations := make(map[uint]bool)

	for appliedRows.Next() {
		var version uint
		var dirty bool

		if err := appliedRows.Scan(&version, &dirty); err != nil {
			return nil, fmt.Errorf("failed to scan applied migration row: %w", err)
		}

		appliedMigrations[version] = true
		if dirty {
			dirtyMigrations[version] = true
		}
	}

	// Get migration metadata from our custom table
	metadataQuery := `
		SELECT id, name, version, up_sql, down_sql, applied_at, created_at
		FROM migrations_metadata 
		ORDER BY version DESC
	`

	metadataRows, err := ms.db.Query(ctx, metadataQuery)
	if err != nil {
		// If table doesn't exist, continue with file-based approach
		return ms.getMigrationHistoryFromFiles(appliedMigrations, dirtyMigrations)
	}
	defer metadataRows.Close()

	var migrations []*Migration
	for metadataRows.Next() {
		migration := &Migration{}

		if err := metadataRows.Scan(
			&migration.ID,
			&migration.Name,
			&migration.Version,
			&migration.UpSQL,
			&migration.DownSQL,
			&migration.AppliedAt,
			&migration.CreatedAt,
		); err != nil {
			return nil, fmt.Errorf("failed to scan migration metadata row: %w", err)
		}

		// Parse version to check if applied
		if version, err := strconv.ParseUint(migration.Version, 10, 32); err == nil {
			versionUint := uint(version)
			if appliedMigrations[versionUint] {
				migration.Status = "applied"
			} else {
				migration.Status = "pending"
			}
			migration.Dirty = dirtyMigrations[versionUint]
		}

		migrations = append(migrations, migration)
	}

	// If no metadata found, fall back to file-based approach
	if len(migrations) == 0 {
		return ms.getMigrationHistoryFromFiles(appliedMigrations, dirtyMigrations)
	}

	return migrations, nil
}

// getMigrationHistoryFromFiles builds migration history from migration files
func (ms *MigrationService) getMigrationHistoryFromFiles(applied, dirty map[uint]bool) ([]*Migration, error) {
	migrationInfos, err := ms.getMigrationFiles()
	if err != nil {
		return nil, fmt.Errorf("failed to get migration files: %w", err)
	}

	var migrations []*Migration
	for _, info := range migrationInfos {
		status := "pending"
		if applied[info.Version] {
			status = "applied"
		}

		migration := &Migration{
			ID:      fmt.Sprintf("%06d_%s", info.Version, info.Name),
			Name:    info.Name,
			Version: fmt.Sprintf("%d", info.Version),
			Status:  status,
			Dirty:   dirty[info.Version],
		}

		if info.Applied && info.AppliedAt != nil {
			migration.AppliedAt = info.AppliedAt
		}

		migrations = append(migrations, migration)
	}

	// Sort by version descending
	sort.Slice(migrations, func(i, j int) bool {
		vi, _ := strconv.ParseUint(migrations[i].Version, 10, 32)
		vj, _ := strconv.ParseUint(migrations[j].Version, 10, 32)
		return vi > vj
	})

	return migrations, nil
}

// getMigrationFiles scans the migrations directory for migration files
func (ms *MigrationService) getMigrationFiles() ([]*MigrationInfo, error) {
	files, err := os.ReadDir(ms.migrationsPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read migrations directory: %w", err)
	}

	migrationMap := make(map[uint]*MigrationInfo)
	versionRegex := regexp.MustCompile(`^(\d+)_(.+)\.(up|down)\.sql$`)

	for _, file := range files {
		if file.IsDir() {
			continue
		}

		matches := versionRegex.FindStringSubmatch(file.Name())
		if len(matches) >= 4 {
			version, err := strconv.ParseUint(matches[1], 10, 32)
			if err != nil {
				continue
			}

			versionUint := uint(version)
			name := matches[2]
			direction := matches[3]

			if _, exists := migrationMap[versionUint]; !exists {
				migrationMap[versionUint] = &MigrationInfo{
					Version: versionUint,
					Name:    name,
				}
			}

			if direction == "up" {
				migrationMap[versionUint].UpFile = filepath.Join(ms.migrationsPath, file.Name())
			} else {
				migrationMap[versionUint].DownFile = filepath.Join(ms.migrationsPath, file.Name())
			}
		}
	}

	// Convert map to slice and sort
	var migrations []*MigrationInfo
	for _, migration := range migrationMap {
		migrations = append(migrations, migration)
	}

	sort.Slice(migrations, func(i, j int) bool {
		return migrations[i].Version < migrations[j].Version
	})

	return migrations, nil
}

// storeMigrationMetadata stores migration metadata in the database
func (ms *MigrationService) storeMigrationMetadata(migration *Migration) error {
	ctx := context.Background()

	query := `
		INSERT INTO migrations_metadata (id, name, version, up_sql, down_sql, created_at)
		VALUES ($1, $2, $3, $4, $5, $6)
		ON CONFLICT (id) DO UPDATE SET
			name = EXCLUDED.name,
			up_sql = EXCLUDED.up_sql,
			down_sql = EXCLUDED.down_sql
	`

	err := ms.db.Exec(ctx, query,
		migration.ID,
		migration.Name,
		migration.Version,
		migration.UpSQL,
		migration.DownSQL,
		migration.CreatedAt,
	)

	if err != nil {
		return fmt.Errorf("failed to store migration metadata: %w", err)
	}

	return nil
}

// GetMigrationStatus returns the status of all migrations
func (ms *MigrationService) GetMigrationStatus(ctx context.Context) ([]*MigrationInfo, error) {
	migrations, err := ms.getMigrationFiles()
	if err != nil {
		return nil, fmt.Errorf("failed to get migration files: %w", err)
	}

	// Get applied migrations
	appliedQuery := `SELECT version FROM schema_migrations`
	rows, err := ms.db.Query(ctx, appliedQuery)
	if err != nil {
		// If schema_migrations doesn't exist, all migrations are pending
		return migrations, nil
	}
	defer rows.Close()

	appliedVersions := make(map[uint]bool)
	for rows.Next() {
		var version uint
		if err := rows.Scan(&version); err != nil {
			continue
		}
		appliedVersions[version] = true
	}

	// Update migration status
	for _, migration := range migrations {
		migration.Applied = appliedVersions[migration.Version]
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

// writeFile writes content to a file
func (ms *MigrationService) writeFile(filename, content string) error {
	return os.WriteFile(filename, []byte(content), 0644)
}

// GetAvailableTemplates returns all available migration templates
func (ms *MigrationService) GetAvailableTemplates() map[string]*MigrationTemplate {
	return ms.templates
}

// AddTemplate adds a custom migration template
func (ms *MigrationService) AddTemplate(name string, template *MigrationTemplate) {
	ms.templates[name] = template
}

// ValidateMigrationFiles validates that migration files are properly paired
func (ms *MigrationService) ValidateMigrationFiles() error {
	migrations, err := ms.getMigrationFiles()
	if err != nil {
		return fmt.Errorf("failed to get migration files: %w", err)
	}

	var errors []string
	for _, migration := range migrations {
		if migration.UpFile == "" {
			errors = append(errors, fmt.Sprintf("missing up file for migration %d_%s", migration.Version, migration.Name))
		}
		if migration.DownFile == "" {
			errors = append(errors, fmt.Sprintf("missing down file for migration %d_%s", migration.Version, migration.Name))
		}
	}

	if len(errors) > 0 {
		return fmt.Errorf("migration validation failed:\n%s", strings.Join(errors, "\n"))
	}

	return nil
}

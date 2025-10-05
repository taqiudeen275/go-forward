package storage

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/taqiudeen275/go-foward/internal/database"
	"github.com/taqiudeen275/go-foward/pkg/interfaces"
)

// FileVersion represents a version of a file
type FileVersion struct {
	ID        string            `json:"id"`
	FileID    string            `json:"file_id"`
	Version   int               `json:"version"`
	Size      int64             `json:"size"`
	Checksum  string            `json:"checksum"`
	Metadata  map[string]string `json:"metadata"`
	CreatedAt time.Time         `json:"created_at"`
}

// VersioningService handles file versioning operations
type VersioningService struct {
	db   *database.DB
	repo *Repository
}

// NewVersioningService creates a new versioning service
func NewVersioningService(db *database.DB, repo *Repository) *VersioningService {
	return &VersioningService{
		db:   db,
		repo: repo,
	}
}

// CreateVersion creates a new version of a file
func (v *VersioningService) CreateVersion(ctx context.Context, fileInfo *interfaces.FileInfo) (*FileVersion, error) {
	// Get current version count for this file
	currentVersion, err := v.getCurrentVersion(ctx, fileInfo.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to get current version: %w", err)
	}

	// Create new version
	version := &FileVersion{
		ID:        uuid.New().String(),
		FileID:    fileInfo.ID,
		Version:   currentVersion + 1,
		Size:      fileInfo.Size,
		Checksum:  fileInfo.Checksum,
		Metadata:  fileInfo.Metadata,
		CreatedAt: time.Now(),
	}

	// Store version in database
	if err := v.storeVersion(ctx, version); err != nil {
		return nil, fmt.Errorf("failed to store version: %w", err)
	}

	return version, nil
}

// GetVersions retrieves all versions of a file
func (v *VersioningService) GetVersions(ctx context.Context, fileID string) ([]*FileVersion, error) {
	query := `
		SELECT id, file_id, version, size, checksum, metadata, created_at
		FROM file_versions
		WHERE file_id = $1
		ORDER BY version DESC
	`

	rows, err := v.db.Query(ctx, query, fileID)
	if err != nil {
		return nil, fmt.Errorf("failed to query versions: %w", err)
	}
	defer rows.Close()

	var versions []*FileVersion
	for rows.Next() {
		version := &FileVersion{}
		var metadataJSON []byte

		err := rows.Scan(
			&version.ID,
			&version.FileID,
			&version.Version,
			&version.Size,
			&version.Checksum,
			&metadataJSON,
			&version.CreatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan version: %w", err)
		}

		// Unmarshal metadata
		if len(metadataJSON) > 0 {
			if err := v.repo.unmarshalJSON(metadataJSON, &version.Metadata); err != nil {
				return nil, fmt.Errorf("failed to unmarshal metadata: %w", err)
			}
		}

		versions = append(versions, version)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating versions: %w", err)
	}

	return versions, nil
}

// GetVersion retrieves a specific version of a file
func (v *VersioningService) GetVersion(ctx context.Context, fileID string, version int) (*FileVersion, error) {
	query := `
		SELECT id, file_id, version, size, checksum, metadata, created_at
		FROM file_versions
		WHERE file_id = $1 AND version = $2
	`

	row := v.db.QueryRow(ctx, query, fileID, version)

	fileVersion := &FileVersion{}
	var metadataJSON []byte

	err := row.Scan(
		&fileVersion.ID,
		&fileVersion.FileID,
		&fileVersion.Version,
		&fileVersion.Size,
		&fileVersion.Checksum,
		&metadataJSON,
		&fileVersion.CreatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to get version: %w", err)
	}

	// Unmarshal metadata
	if len(metadataJSON) > 0 {
		if err := v.repo.unmarshalJSON(metadataJSON, &fileVersion.Metadata); err != nil {
			return nil, fmt.Errorf("failed to unmarshal metadata: %w", err)
		}
	}

	return fileVersion, nil
}

// DeleteVersion removes a specific version of a file
func (v *VersioningService) DeleteVersion(ctx context.Context, fileID string, version int) error {
	query := `DELETE FROM file_versions WHERE file_id = $1 AND version = $2`

	err := v.db.Exec(ctx, query, fileID, version)
	if err != nil {
		return fmt.Errorf("failed to delete version: %w", err)
	}

	return nil
}

// CleanupOldVersions removes old versions beyond the retention limit
func (v *VersioningService) CleanupOldVersions(ctx context.Context, fileID string, retentionCount int) error {
	if retentionCount <= 0 {
		return nil // No cleanup needed
	}

	query := `
		DELETE FROM file_versions
		WHERE file_id = $1
		AND version NOT IN (
			SELECT version
			FROM file_versions
			WHERE file_id = $1
			ORDER BY version DESC
			LIMIT $2
		)
	`

	err := v.db.Exec(ctx, query, fileID, retentionCount)
	if err != nil {
		return fmt.Errorf("failed to cleanup old versions: %w", err)
	}

	return nil
}

// getCurrentVersion gets the current highest version number for a file
func (v *VersioningService) getCurrentVersion(ctx context.Context, fileID string) (int, error) {
	query := `
		SELECT COALESCE(MAX(version), 0)
		FROM file_versions
		WHERE file_id = $1
	`

	row := v.db.QueryRow(ctx, query, fileID)

	var version int
	err := row.Scan(&version)
	if err != nil {
		return 0, fmt.Errorf("failed to get current version: %w", err)
	}

	return version, nil
}

// storeVersion stores a version in the database
func (v *VersioningService) storeVersion(ctx context.Context, version *FileVersion) error {
	query := `
		INSERT INTO file_versions (id, file_id, version, size, checksum, metadata, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
	`

	metadataJSON, err := v.repo.marshalJSON(version.Metadata)
	if err != nil {
		return fmt.Errorf("failed to marshal metadata: %w", err)
	}

	err = v.db.Exec(ctx, query,
		version.ID,
		version.FileID,
		version.Version,
		version.Size,
		version.Checksum,
		metadataJSON,
		version.CreatedAt,
	)

	if err != nil {
		return fmt.Errorf("failed to insert version: %w", err)
	}

	return nil
}

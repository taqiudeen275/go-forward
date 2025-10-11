package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/taqiudeen275/go-foward/internal/database"
	"github.com/taqiudeen275/go-foward/pkg/interfaces"
)

// Repository handles database operations for storage
type Repository struct {
	db *database.DB
}

// NewRepository creates a new storage repository
func NewRepository(db *database.DB) *Repository {
	return &Repository{db: db}
}

// CreateFile stores file metadata in database
func (r *Repository) CreateFile(ctx context.Context, fileInfo *interfaces.FileInfo) error {
	query := `
		INSERT INTO files (id, bucket, path, name, size, mime_type, checksum, metadata, permissions, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
	`

	// Convert metadata and permissions to JSON
	metadataJSON, err := json.Marshal(fileInfo.Metadata)
	if err != nil {
		return fmt.Errorf("failed to marshal metadata: %w", err)
	}

	var permissionsJSON []byte
	if fileInfo.Permissions != nil {
		permissionsJSON, err = json.Marshal(fileInfo.Permissions)
		if err != nil {
			return fmt.Errorf("failed to marshal permissions: %w", err)
		}
	}

	err = r.db.Exec(ctx, query,
		fileInfo.ID,
		fileInfo.Bucket,
		fileInfo.Path,
		fileInfo.Name,
		fileInfo.Size,
		fileInfo.MimeType,
		fileInfo.Checksum,
		metadataJSON,
		permissionsJSON,
		fileInfo.CreatedAt,
		fileInfo.UpdatedAt,
	)

	if err != nil {
		return fmt.Errorf("failed to insert file: %w", err)
	}

	return nil
}

// GetFileByPath retrieves file information by bucket and path
func (r *Repository) GetFileByPath(ctx context.Context, bucket, path string) (*interfaces.FileInfo, error) {
	query := `
		SELECT id, bucket, path, name, size, mime_type, checksum, metadata, permissions, created_at, updated_at
		FROM files
		WHERE bucket = $1 AND path = $2
	`

	row := r.db.QueryRow(ctx, query, bucket, path)

	fileInfo := &interfaces.FileInfo{}
	var metadataJSON, permissionsJSON []byte

	err := row.Scan(
		&fileInfo.ID,
		&fileInfo.Bucket,
		&fileInfo.Path,
		&fileInfo.Name,
		&fileInfo.Size,
		&fileInfo.MimeType,
		&fileInfo.Checksum,
		&metadataJSON,
		&permissionsJSON,
		&fileInfo.CreatedAt,
		&fileInfo.UpdatedAt,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("file not found: %s/%s", bucket, path)
		}
		return nil, fmt.Errorf("failed to get file: %w", err)
	}

	// Unmarshal metadata
	if len(metadataJSON) > 0 {
		if err := json.Unmarshal(metadataJSON, &fileInfo.Metadata); err != nil {
			return nil, fmt.Errorf("failed to unmarshal metadata: %w", err)
		}
	}

	// Unmarshal permissions
	if len(permissionsJSON) > 0 {
		fileInfo.Permissions = &interfaces.FilePermissions{}
		if err := json.Unmarshal(permissionsJSON, fileInfo.Permissions); err != nil {
			return nil, fmt.Errorf("failed to unmarshal permissions: %w", err)
		}
	}

	return fileInfo, nil
}

// GetFileByID retrieves file information by ID
func (r *Repository) GetFileByID(ctx context.Context, fileID string) (*interfaces.FileInfo, error) {
	query := `
		SELECT id, bucket, path, name, size, mime_type, checksum, metadata, permissions, created_at, updated_at
		FROM files
		WHERE id = $1
	`

	row := r.db.QueryRow(ctx, query, fileID)

	fileInfo := &interfaces.FileInfo{}
	var metadataJSON, permissionsJSON []byte

	err := row.Scan(
		&fileInfo.ID,
		&fileInfo.Bucket,
		&fileInfo.Path,
		&fileInfo.Name,
		&fileInfo.Size,
		&fileInfo.MimeType,
		&fileInfo.Checksum,
		&metadataJSON,
		&permissionsJSON,
		&fileInfo.CreatedAt,
		&fileInfo.UpdatedAt,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("file not found: %s", fileID)
		}
		return nil, fmt.Errorf("failed to get file: %w", err)
	}

	// Unmarshal metadata
	if len(metadataJSON) > 0 {
		if err := json.Unmarshal(metadataJSON, &fileInfo.Metadata); err != nil {
			return nil, fmt.Errorf("failed to unmarshal metadata: %w", err)
		}
	}

	// Unmarshal permissions
	if len(permissionsJSON) > 0 {
		fileInfo.Permissions = &interfaces.FilePermissions{}
		if err := json.Unmarshal(permissionsJSON, fileInfo.Permissions); err != nil {
			return nil, fmt.Errorf("failed to unmarshal permissions: %w", err)
		}
	}

	return fileInfo, nil
}

// ListFiles retrieves files with optional prefix filtering
func (r *Repository) ListFiles(ctx context.Context, bucket, prefix string, limit, offset int) ([]*interfaces.FileInfo, error) {
	var query string
	var args []interface{}

	if prefix != "" {
		query = `
			SELECT id, bucket, path, name, size, mime_type, checksum, metadata, permissions, created_at, updated_at
			FROM files
			WHERE bucket = $1 AND path LIKE $2
			ORDER BY created_at DESC
			LIMIT $3 OFFSET $4
		`
		args = []interface{}{bucket, prefix + "%", limit, offset}
	} else {
		query = `
			SELECT id, bucket, path, name, size, mime_type, checksum, metadata, permissions, created_at, updated_at
			FROM files
			WHERE bucket = $1
			ORDER BY created_at DESC
			LIMIT $2 OFFSET $3
		`
		args = []interface{}{bucket, limit, offset}
	}

	rows, err := r.db.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to list files: %w", err)
	}
	defer rows.Close()

	var files []*interfaces.FileInfo

	for rows.Next() {
		fileInfo := &interfaces.FileInfo{}
		var metadataJSON, permissionsJSON []byte

		err := rows.Scan(
			&fileInfo.ID,
			&fileInfo.Bucket,
			&fileInfo.Path,
			&fileInfo.Name,
			&fileInfo.Size,
			&fileInfo.MimeType,
			&fileInfo.Checksum,
			&metadataJSON,
			&permissionsJSON,
			&fileInfo.CreatedAt,
			&fileInfo.UpdatedAt,
		)

		if err != nil {
			return nil, fmt.Errorf("failed to scan file: %w", err)
		}

		// Unmarshal metadata
		if len(metadataJSON) > 0 {
			if err := json.Unmarshal(metadataJSON, &fileInfo.Metadata); err != nil {
				return nil, fmt.Errorf("failed to unmarshal metadata: %w", err)
			}
		}

		// Unmarshal permissions
		if len(permissionsJSON) > 0 {
			fileInfo.Permissions = &interfaces.FilePermissions{}
			if err := json.Unmarshal(permissionsJSON, fileInfo.Permissions); err != nil {
				return nil, fmt.Errorf("failed to unmarshal permissions: %w", err)
			}
		}

		files = append(files, fileInfo)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating files: %w", err)
	}

	return files, nil
}

// DeleteFile removes file metadata from database
func (r *Repository) DeleteFile(ctx context.Context, fileID string) error {
	query := `DELETE FROM files WHERE id = $1`

	err := r.db.Exec(ctx, query, fileID)
	if err != nil {
		return fmt.Errorf("failed to delete file: %w", err)
	}

	return nil
}

// UpdateFileAccessTime updates the last access time for a file
func (r *Repository) UpdateFileAccessTime(ctx context.Context, fileID string) error {
	query := `UPDATE files SET updated_at = $1 WHERE id = $2`

	err := r.db.Exec(ctx, query, time.Now(), fileID)
	if err != nil {
		return fmt.Errorf("failed to update file access time: %w", err)
	}

	return nil
}

// CreateBucket stores bucket metadata in database
func (r *Repository) CreateBucket(ctx context.Context, bucket string, config interfaces.BucketConfig) error {
	query := `
		INSERT INTO buckets (name, config, created_at, updated_at)
		VALUES ($1, $2, $3, $4)
		ON CONFLICT (name) DO UPDATE SET
			config = EXCLUDED.config,
			updated_at = EXCLUDED.updated_at
	`

	configJSON, err := json.Marshal(config)
	if err != nil {
		return fmt.Errorf("failed to marshal bucket config: %w", err)
	}

	now := time.Now()
	err = r.db.Exec(ctx, query, bucket, configJSON, now, now)
	if err != nil {
		return fmt.Errorf("failed to create bucket: %w", err)
	}

	return nil
}

// DeleteBucket removes bucket metadata from database
func (r *Repository) DeleteBucket(ctx context.Context, bucket string) error {
	query := `DELETE FROM buckets WHERE name = $1`

	err := r.db.Exec(ctx, query, bucket)
	if err != nil {
		return fmt.Errorf("failed to delete bucket: %w", err)
	}

	return nil
}

// DeleteBucketFiles removes all files in a bucket from database
func (r *Repository) DeleteBucketFiles(ctx context.Context, bucket string) error {
	query := `DELETE FROM files WHERE bucket = $1`

	err := r.db.Exec(ctx, query, bucket)
	if err != nil {
		return fmt.Errorf("failed to delete bucket files: %w", err)
	}

	return nil
}

// GetBuckets retrieves all buckets with file statistics
func (r *Repository) GetBuckets(ctx context.Context) ([]*interfaces.BucketInfo, error) {
	query := `
		SELECT 
			b.name,
			b.config,
			b.created_at,
			b.updated_at,
			COALESCE(f.file_count, 0) as file_count,
			COALESCE(f.total_size, 0) as total_size
		FROM buckets b
		LEFT JOIN (
			SELECT 
				bucket,
				COUNT(*) as file_count,
				SUM(size) as total_size
			FROM files
			GROUP BY bucket
		) f ON b.name = f.bucket
		ORDER BY b.created_at DESC
	`

	rows, err := r.db.Query(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed to get buckets: %w", err)
	}
	defer rows.Close()

	var buckets []*interfaces.BucketInfo

	for rows.Next() {
		bucketInfo := &interfaces.BucketInfo{}
		var configJSON []byte

		err := rows.Scan(
			&bucketInfo.Name,
			&configJSON,
			&bucketInfo.CreatedAt,
			&bucketInfo.UpdatedAt,
			&bucketInfo.FileCount,
			&bucketInfo.TotalSize,
		)

		if err != nil {
			return nil, fmt.Errorf("failed to scan bucket: %w", err)
		}

		// Unmarshal config
		if len(configJSON) > 0 {
			if err := json.Unmarshal(configJSON, &bucketInfo.Config); err != nil {
				return nil, fmt.Errorf("failed to unmarshal bucket config: %w", err)
			}
		}

		buckets = append(buckets, bucketInfo)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating buckets: %w", err)
	}

	return buckets, nil
}

// SearchFiles performs advanced file search with multiple criteria
func (r *Repository) SearchFiles(ctx context.Context, criteria SearchCriteria) ([]*interfaces.FileInfo, error) {
	query := `
		SELECT id, bucket, path, name, size, mime_type, checksum, metadata, permissions, created_at, updated_at
		FROM files
		WHERE 1=1
	`
	args := []interface{}{}
	argIndex := 1

	// Build dynamic WHERE clause
	if criteria.Bucket != "" {
		query += fmt.Sprintf(" AND bucket = $%d", argIndex)
		args = append(args, criteria.Bucket)
		argIndex++
	}

	if criteria.NamePattern != "" {
		query += fmt.Sprintf(" AND name ILIKE $%d", argIndex)
		args = append(args, "%"+criteria.NamePattern+"%")
		argIndex++
	}

	if criteria.MimeType != "" {
		query += fmt.Sprintf(" AND mime_type = $%d", argIndex)
		args = append(args, criteria.MimeType)
		argIndex++
	}

	if criteria.MinSize > 0 {
		query += fmt.Sprintf(" AND size >= $%d", argIndex)
		args = append(args, criteria.MinSize)
		argIndex++
	}

	if criteria.MaxSize > 0 {
		query += fmt.Sprintf(" AND size <= $%d", argIndex)
		args = append(args, criteria.MaxSize)
		argIndex++
	}

	if criteria.CreatedFrom != nil {
		query += fmt.Sprintf(" AND created_at >= $%d", argIndex)
		args = append(args, *criteria.CreatedFrom)
		argIndex++
	}

	if criteria.CreatedTo != nil {
		query += fmt.Sprintf(" AND created_at <= $%d", argIndex)
		args = append(args, *criteria.CreatedTo)
		argIndex++
	}

	// Add metadata search if provided
	for key, value := range criteria.Metadata {
		query += fmt.Sprintf(" AND metadata->>'%s' = $%d", key, argIndex)
		args = append(args, value)
		argIndex++
	}

	// Add ordering and pagination
	query += " ORDER BY created_at DESC"

	if criteria.Limit > 0 {
		query += fmt.Sprintf(" LIMIT $%d", argIndex)
		args = append(args, criteria.Limit)
		argIndex++
	}

	if criteria.Offset > 0 {
		query += fmt.Sprintf(" OFFSET $%d", argIndex)
		args = append(args, criteria.Offset)
		argIndex++
	}

	rows, err := r.db.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to search files: %w", err)
	}
	defer rows.Close()

	var files []*interfaces.FileInfo
	for rows.Next() {
		fileInfo := &interfaces.FileInfo{}
		var metadataJSON, permissionsJSON []byte

		err := rows.Scan(
			&fileInfo.ID,
			&fileInfo.Bucket,
			&fileInfo.Path,
			&fileInfo.Name,
			&fileInfo.Size,
			&fileInfo.MimeType,
			&fileInfo.Checksum,
			&metadataJSON,
			&permissionsJSON,
			&fileInfo.CreatedAt,
			&fileInfo.UpdatedAt,
		)

		if err != nil {
			return nil, fmt.Errorf("failed to scan file: %w", err)
		}

		// Unmarshal metadata
		if len(metadataJSON) > 0 {
			if err := json.Unmarshal(metadataJSON, &fileInfo.Metadata); err != nil {
				return nil, fmt.Errorf("failed to unmarshal metadata: %w", err)
			}
		}

		// Unmarshal permissions
		if len(permissionsJSON) > 0 {
			fileInfo.Permissions = &interfaces.FilePermissions{}
			if err := json.Unmarshal(permissionsJSON, fileInfo.Permissions); err != nil {
				return nil, fmt.Errorf("failed to unmarshal permissions: %w", err)
			}
		}

		files = append(files, fileInfo)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating files: %w", err)
	}

	return files, nil
}

// UpdateFileMetadata updates file metadata without changing the file content
func (r *Repository) UpdateFileMetadata(ctx context.Context, bucket, path string, metadata map[string]string) error {
	query := `
		UPDATE files 
		SET metadata = $1, updated_at = $2
		WHERE bucket = $3 AND path = $4
	`

	metadataJSON, err := json.Marshal(metadata)
	if err != nil {
		return fmt.Errorf("failed to marshal metadata: %w", err)
	}

	err = r.db.Exec(ctx, query, metadataJSON, time.Now(), bucket, path)
	if err != nil {
		return fmt.Errorf("failed to update file metadata: %w", err)
	}

	return nil
}

// GetFilesByMetadata retrieves files based on metadata queries
func (r *Repository) GetFilesByMetadata(ctx context.Context, bucket string, metadataQuery map[string]string) ([]*interfaces.FileInfo, error) {
	query := `
		SELECT id, bucket, path, name, size, mime_type, checksum, metadata, permissions, created_at, updated_at
		FROM files
		WHERE bucket = $1
	`
	args := []interface{}{bucket}
	argIndex := 2

	// Add metadata conditions
	for key, value := range metadataQuery {
		query += fmt.Sprintf(" AND metadata->>'%s' = $%d", key, argIndex)
		args = append(args, value)
		argIndex++
	}

	query += " ORDER BY created_at DESC"

	rows, err := r.db.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to query files by metadata: %w", err)
	}
	defer rows.Close()

	var files []*interfaces.FileInfo
	for rows.Next() {
		fileInfo := &interfaces.FileInfo{}
		var metadataJSON, permissionsJSON []byte

		err := rows.Scan(
			&fileInfo.ID,
			&fileInfo.Bucket,
			&fileInfo.Path,
			&fileInfo.Name,
			&fileInfo.Size,
			&fileInfo.MimeType,
			&fileInfo.Checksum,
			&metadataJSON,
			&permissionsJSON,
			&fileInfo.CreatedAt,
			&fileInfo.UpdatedAt,
		)

		if err != nil {
			return nil, fmt.Errorf("failed to scan file: %w", err)
		}

		// Unmarshal metadata
		if len(metadataJSON) > 0 {
			if err := json.Unmarshal(metadataJSON, &fileInfo.Metadata); err != nil {
				return nil, fmt.Errorf("failed to unmarshal metadata: %w", err)
			}
		}

		// Unmarshal permissions
		if len(permissionsJSON) > 0 {
			fileInfo.Permissions = &interfaces.FilePermissions{}
			if err := json.Unmarshal(permissionsJSON, fileInfo.Permissions); err != nil {
				return nil, fmt.Errorf("failed to unmarshal permissions: %w", err)
			}
		}

		files = append(files, fileInfo)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating files: %w", err)
	}

	return files, nil
}

// GetFileStats retrieves statistics about files in a bucket
func (r *Repository) GetFileStats(ctx context.Context, bucket string) (*FileStats, error) {
	// Get basic stats
	statsQuery := `
		SELECT 
			COUNT(*) as total_files,
			COALESCE(SUM(size), 0) as total_size,
			COALESCE(AVG(size), 0) as avg_size
		FROM files
		WHERE bucket = $1
	`

	row := r.db.QueryRow(ctx, statsQuery, bucket)

	stats := &FileStats{
		MimeTypes: make(map[string]int64),
	}

	err := row.Scan(&stats.TotalFiles, &stats.TotalSize, &stats.AvgSize)
	if err != nil {
		return nil, fmt.Errorf("failed to get file stats: %w", err)
	}

	// Get MIME type distribution
	mimeQuery := `
		SELECT mime_type, COUNT(*)
		FROM files
		WHERE bucket = $1
		GROUP BY mime_type
		ORDER BY COUNT(*) DESC
	`

	rows, err := r.db.Query(ctx, mimeQuery, bucket)
	if err != nil {
		return nil, fmt.Errorf("failed to get mime type stats: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var mimeType string
		var count int64

		err := rows.Scan(&mimeType, &count)
		if err != nil {
			return nil, fmt.Errorf("failed to scan mime type stats: %w", err)
		}

		stats.MimeTypes[mimeType] = count
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating mime type stats: %w", err)
	}

	return stats, nil
}

// Helper methods for JSON marshaling/unmarshaling
func (r *Repository) marshalJSON(v interface{}) ([]byte, error) {
	return json.Marshal(v)
}

func (r *Repository) unmarshalJSON(data []byte, v interface{}) error {
	return json.Unmarshal(data, v)
}

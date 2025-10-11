package storage

import (
	"context"
	"fmt"

	"github.com/taqiudeen275/go-foward/internal/database"
	"github.com/taqiudeen275/go-foward/pkg/interfaces"
)

// AccessControlService implements permission-based file access control
type AccessControlService struct {
	db   *database.DB
	repo *Repository
}

// NewAccessControlService creates a new access control service
func NewAccessControlService(db *database.DB) *AccessControlService {
	return &AccessControlService{
		db:   db,
		repo: NewRepository(db),
	}
}

// CanRead checks if a user can read a file or bucket
func (ac *AccessControlService) CanRead(ctx context.Context, userID string, bucket string, path string) bool {
	// Check bucket-level permissions first
	if !ac.canAccessBucket(ctx, userID, bucket, "read") {
		return false
	}

	// If path is empty, we're checking bucket-level access
	if path == "" {
		return true
	}

	// Check file-level permissions
	return ac.canAccessFile(ctx, userID, bucket, path, "read")
}

// CanWrite checks if a user can write/upload a file to a bucket
func (ac *AccessControlService) CanWrite(ctx context.Context, userID string, bucket string, path string) bool {
	// Check bucket-level permissions first
	if !ac.canAccessBucket(ctx, userID, bucket, "write") {
		return false
	}

	// If path is empty, we're checking bucket-level access
	if path == "" {
		return true
	}

	// For new files, check bucket permissions
	// For existing files, check file-level permissions
	fileInfo, err := ac.repo.GetFileByPath(ctx, bucket, path)
	if err != nil {
		// File doesn't exist, check bucket permissions
		return true
	}

	// File exists, check file-level permissions
	return ac.canAccessFile(ctx, userID, bucket, fileInfo.Path, "write")
}

// CanDelete checks if a user can delete a file
func (ac *AccessControlService) CanDelete(ctx context.Context, userID string, bucket string, path string) bool {
	// Check bucket-level permissions first
	if !ac.canAccessBucket(ctx, userID, bucket, "delete") {
		return false
	}

	// If path is empty, we're checking bucket-level access
	if path == "" {
		return true
	}

	// Check file-level permissions
	return ac.canAccessFile(ctx, userID, bucket, path, "delete")
}

// SetPermissions sets file-level permissions
func (ac *AccessControlService) SetPermissions(ctx context.Context, bucket string, path string, permissions interfaces.FilePermissions) error {
	// Get the file first
	fileInfo, err := ac.repo.GetFileByPath(ctx, bucket, path)
	if err != nil {
		return fmt.Errorf("file not found: %w", err)
	}

	// Update permissions in database
	query := `UPDATE files SET permissions = $1, updated_at = NOW() WHERE id = $2`

	permissionsJSON, err := ac.marshalPermissions(&permissions)
	if err != nil {
		return fmt.Errorf("failed to marshal permissions: %w", err)
	}

	err = ac.db.Exec(ctx, query, permissionsJSON, fileInfo.ID)
	if err != nil {
		return fmt.Errorf("failed to update file permissions: %w", err)
	}

	return nil
}

// GetPermissions retrieves file-level permissions
func (ac *AccessControlService) GetPermissions(ctx context.Context, bucket string, path string) (*interfaces.FilePermissions, error) {
	fileInfo, err := ac.repo.GetFileByPath(ctx, bucket, path)
	if err != nil {
		return nil, fmt.Errorf("file not found: %w", err)
	}

	return fileInfo.Permissions, nil
}

// canAccessBucket checks bucket-level permissions
func (ac *AccessControlService) canAccessBucket(ctx context.Context, userID string, bucket string, operation string) bool {
	// Get bucket configuration
	bucketInfo, err := ac.getBucketInfo(ctx, bucket)
	if err != nil {
		// If bucket doesn't exist or error occurred, deny access
		return false
	}

	// If bucket is public and operation is read, allow access
	if bucketInfo.Config.Public && operation == "read" {
		return true
	}

	// If user is not authenticated, deny access to non-public operations
	if userID == "" {
		return false
	}

	// TODO: Implement role-based access control
	// For now, authenticated users can perform all operations on non-public buckets
	// This should be enhanced with proper role/permission system

	return true
}

// canAccessFile checks file-level permissions
func (ac *AccessControlService) canAccessFile(ctx context.Context, userID string, bucket string, path string, operation string) bool {
	// Get file info with permissions
	fileInfo, err := ac.repo.GetFileByPath(ctx, bucket, path)
	if err != nil {
		// File doesn't exist, deny access
		return false
	}

	// If no file-level permissions are set, fall back to bucket permissions
	if fileInfo.Permissions == nil {
		return ac.canAccessBucket(ctx, userID, bucket, operation)
	}

	permissions := fileInfo.Permissions

	// If file is public and operation is read, allow access
	if permissions.Public && operation == "read" {
		return true
	}

	// If user is not authenticated, deny access to non-public operations
	if userID == "" {
		return false
	}

	// Check specific permissions based on operation
	switch operation {
	case "read":
		return ac.hasPermission(userID, permissions.Read)
	case "write":
		return ac.hasPermission(userID, permissions.Write)
	case "delete":
		return ac.hasPermission(userID, permissions.Delete)
	default:
		return false
	}
}

// hasPermission checks if user has specific permission
func (ac *AccessControlService) hasPermission(userID string, allowedUsers []string) bool {
	if len(allowedUsers) == 0 {
		// If no specific permissions are set, allow access for authenticated users
		return true
	}

	// Check if user ID is in the allowed list
	for _, allowedUser := range allowedUsers {
		if allowedUser == userID {
			return true
		}

		// Check for wildcard permissions
		if allowedUser == "*" {
			return true
		}

		// TODO: Implement role-based permissions
		// For now, we only support direct user ID matching
	}

	return false
}

// getBucketInfo retrieves bucket information
func (ac *AccessControlService) getBucketInfo(ctx context.Context, bucket string) (*interfaces.BucketInfo, error) {
	query := `
		SELECT name, config, created_at, updated_at
		FROM buckets
		WHERE name = $1
	`

	row := ac.db.QueryRow(ctx, query, bucket)

	bucketInfo := &interfaces.BucketInfo{}
	var configJSON []byte

	err := row.Scan(
		&bucketInfo.Name,
		&configJSON,
		&bucketInfo.CreatedAt,
		&bucketInfo.UpdatedAt,
	)

	if err != nil {
		return nil, fmt.Errorf("failed to get bucket info: %w", err)
	}

	// Unmarshal config
	if len(configJSON) > 0 {
		if err := ac.unmarshalBucketConfig(configJSON, &bucketInfo.Config); err != nil {
			return nil, fmt.Errorf("failed to unmarshal bucket config: %w", err)
		}
	}

	return bucketInfo, nil
}

// Helper methods for JSON marshaling/unmarshaling
func (ac *AccessControlService) marshalPermissions(permissions *interfaces.FilePermissions) ([]byte, error) {
	if permissions == nil {
		return nil, nil
	}

	// Use the same JSON marshaling as the repository
	return ac.repo.marshalJSON(permissions)
}

func (ac *AccessControlService) unmarshalBucketConfig(data []byte, config *interfaces.BucketConfig) error {
	// Use the same JSON unmarshaling as the repository
	return ac.repo.unmarshalJSON(data, config)
}

// CreateDefaultPermissions creates default permissions for a file based on bucket configuration
func (ac *AccessControlService) CreateDefaultPermissions(ctx context.Context, bucket string, userID string) *interfaces.FilePermissions {
	// Get bucket info to determine default permissions
	bucketInfo, err := ac.getBucketInfo(ctx, bucket)
	if err != nil {
		// If we can't get bucket info, create restrictive permissions
		return &interfaces.FilePermissions{
			Public: false,
			Read:   []string{userID},
			Write:  []string{userID},
			Delete: []string{userID},
		}
	}

	// If bucket is public, make file public for reading
	if bucketInfo.Config.Public {
		return &interfaces.FilePermissions{
			Public: true,
			Read:   []string{"*"},
			Write:  []string{userID},
			Delete: []string{userID},
		}
	}

	// For private buckets, only the uploader has access
	return &interfaces.FilePermissions{
		Public: false,
		Read:   []string{userID},
		Write:  []string{userID},
		Delete: []string{userID},
	}
}

// ValidatePermissions validates permission structure
func (ac *AccessControlService) ValidatePermissions(permissions *interfaces.FilePermissions) error {
	if permissions == nil {
		return nil
	}

	// Validate user IDs in permission lists
	for _, userID := range permissions.Read {
		if err := ac.validateUserID(userID); err != nil {
			return fmt.Errorf("invalid read permission: %w", err)
		}
	}

	for _, userID := range permissions.Write {
		if err := ac.validateUserID(userID); err != nil {
			return fmt.Errorf("invalid write permission: %w", err)
		}
	}

	for _, userID := range permissions.Delete {
		if err := ac.validateUserID(userID); err != nil {
			return fmt.Errorf("invalid delete permission: %w", err)
		}
	}

	return nil
}

// validateUserID validates a user ID or role
func (ac *AccessControlService) validateUserID(userID string) error {
	if userID == "" {
		return fmt.Errorf("user ID cannot be empty")
	}

	// Allow wildcard
	if userID == "*" {
		return nil
	}

	// TODO: Add more validation rules
	// - Check if user exists in database
	// - Validate role names
	// - Check for valid UUID format

	return nil
}

// GetUserPermissions returns all permissions for a specific user across all files
func (ac *AccessControlService) GetUserPermissions(ctx context.Context, userID string) (map[string]*interfaces.FilePermissions, error) {
	query := `
		SELECT bucket, path, permissions
		FROM files
		WHERE permissions IS NOT NULL
		AND (
			permissions->>'public' = 'true'
			OR permissions->'read' ? $1
			OR permissions->'write' ? $1
			OR permissions->'delete' ? $1
		)
	`

	rows, err := ac.db.Query(ctx, query, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user permissions: %w", err)
	}
	defer rows.Close()

	permissions := make(map[string]*interfaces.FilePermissions)

	for rows.Next() {
		var bucket, path string
		var permissionsJSON []byte

		err := rows.Scan(&bucket, &path, &permissionsJSON)
		if err != nil {
			return nil, fmt.Errorf("failed to scan permissions: %w", err)
		}

		fileKey := fmt.Sprintf("%s/%s", bucket, path)

		if len(permissionsJSON) > 0 {
			filePermissions := &interfaces.FilePermissions{}
			if err := ac.repo.unmarshalJSON(permissionsJSON, filePermissions); err != nil {
				return nil, fmt.Errorf("failed to unmarshal permissions: %w", err)
			}
			permissions[fileKey] = filePermissions
		}
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating permissions: %w", err)
	}

	return permissions, nil
}

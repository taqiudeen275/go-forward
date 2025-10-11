package storage

import (
	"context"
	"crypto/md5"
	"fmt"
	"io"
	"mime"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/taqiudeen275/go-foward/internal/database"
	"github.com/taqiudeen275/go-foward/pkg/interfaces"
)

// Service implements the StorageService interface
type Service struct {
	db         *database.DB
	basePath   string
	repo       *Repository
	versioning *VersioningService
}

// NewService creates a new storage service
func NewService(db *database.DB, basePath string) *Service {
	if basePath == "" {
		basePath = "./storage"
	}

	// Ensure base directory exists
	if err := os.MkdirAll(basePath, 0755); err != nil {
		panic(fmt.Sprintf("Failed to create storage directory: %v", err))
	}

	repo := NewRepository(db)
	return &Service{
		db:         db,
		basePath:   basePath,
		repo:       repo,
		versioning: NewVersioningService(db, repo),
	}
}

// Upload implements file upload with multipart form support
func (s *Service) Upload(ctx context.Context, bucket string, path string, file io.Reader, metadata interfaces.FileMetadata) (*interfaces.FileInfo, error) {
	// Validate bucket name
	if bucket == "" {
		return nil, fmt.Errorf("bucket name cannot be empty")
	}

	// Validate path
	if path == "" {
		return nil, fmt.Errorf("file path cannot be empty")
	}

	// Clean and validate the path to prevent directory traversal
	cleanPath := filepath.Clean(path)
	if strings.Contains(cleanPath, "..") {
		return nil, fmt.Errorf("invalid file path: directory traversal not allowed")
	}

	// Create bucket directory if it doesn't exist
	bucketPath := filepath.Join(s.basePath, bucket)
	if err := os.MkdirAll(bucketPath, 0755); err != nil {
		return nil, fmt.Errorf("failed to create bucket directory: %w", err)
	}

	// Generate unique file ID
	fileID := uuid.New().String()

	// Create full file path
	fullPath := filepath.Join(bucketPath, cleanPath)

	// Ensure parent directory exists
	if err := os.MkdirAll(filepath.Dir(fullPath), 0755); err != nil {
		return nil, fmt.Errorf("failed to create file directory: %w", err)
	}

	// Create the file
	outFile, err := os.Create(fullPath)
	if err != nil {
		return nil, fmt.Errorf("failed to create file: %w", err)
	}
	defer outFile.Close()

	// Copy file content and calculate checksum
	hash := md5.New()
	multiWriter := io.MultiWriter(outFile, hash)

	size, err := io.Copy(multiWriter, file)
	if err != nil {
		// Clean up the file if copy failed
		os.Remove(fullPath)
		return nil, fmt.Errorf("failed to write file: %w", err)
	}

	// Calculate checksum
	checksum := fmt.Sprintf("%x", hash.Sum(nil))

	// Detect MIME type if not provided
	mimeType := metadata.MimeType
	if mimeType == "" {
		mimeType = mime.TypeByExtension(filepath.Ext(cleanPath))
		if mimeType == "" {
			mimeType = "application/octet-stream"
		}
	}

	// Create file info
	fileInfo := &interfaces.FileInfo{
		ID:          fileID,
		Bucket:      bucket,
		Path:        cleanPath,
		Name:        metadata.Name,
		Size:        size,
		MimeType:    mimeType,
		Checksum:    checksum,
		Metadata:    metadata.Metadata,
		Permissions: metadata.Permissions,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}

	// Store file metadata in database
	if err := s.repo.CreateFile(ctx, fileInfo); err != nil {
		// Clean up the file if database operation failed
		os.Remove(fullPath)
		return nil, fmt.Errorf("failed to store file metadata: %w", err)
	}

	return fileInfo, nil
}

// Download implements file download with proper MIME type handling
func (s *Service) Download(ctx context.Context, bucket string, path string) (io.Reader, error) {
	// Validate inputs
	if bucket == "" {
		return nil, fmt.Errorf("bucket name cannot be empty")
	}
	if path == "" {
		return nil, fmt.Errorf("file path cannot be empty")
	}

	// Clean path to prevent directory traversal
	cleanPath := filepath.Clean(path)
	if strings.Contains(cleanPath, "..") {
		return nil, fmt.Errorf("invalid file path: directory traversal not allowed")
	}

	// Check if file exists in database
	fileInfo, err := s.repo.GetFileByPath(ctx, bucket, cleanPath)
	if err != nil {
		return nil, fmt.Errorf("file not found in database: %w", err)
	}

	// Build full file path
	fullPath := filepath.Join(s.basePath, bucket, cleanPath)

	// Check if file exists on disk
	if _, err := os.Stat(fullPath); os.IsNotExist(err) {
		return nil, fmt.Errorf("file not found on disk: %s", cleanPath)
	}

	// Open file for reading
	file, err := os.Open(fullPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %w", err)
	}

	// Update access time in database (optional)
	go func() {
		s.repo.UpdateFileAccessTime(context.Background(), fileInfo.ID)
	}()

	return file, nil
}

// Delete implements file deletion with cleanup
func (s *Service) Delete(ctx context.Context, bucket string, path string) error {
	// Validate inputs
	if bucket == "" {
		return fmt.Errorf("bucket name cannot be empty")
	}
	if path == "" {
		return fmt.Errorf("file path cannot be empty")
	}

	// Clean path to prevent directory traversal
	cleanPath := filepath.Clean(path)
	if strings.Contains(cleanPath, "..") {
		return fmt.Errorf("invalid file path: directory traversal not allowed")
	}

	// Check if file exists in database
	fileInfo, err := s.repo.GetFileByPath(ctx, bucket, cleanPath)
	if err != nil {
		return fmt.Errorf("file not found in database: %w", err)
	}

	// Build full file path
	fullPath := filepath.Join(s.basePath, bucket, cleanPath)

	// Delete file from disk
	if err := os.Remove(fullPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to delete file from disk: %w", err)
	}

	// Delete file metadata from database
	if err := s.repo.DeleteFile(ctx, fileInfo.ID); err != nil {
		return fmt.Errorf("failed to delete file metadata: %w", err)
	}

	return nil
}

// GetFileInfo retrieves file information
func (s *Service) GetFileInfo(ctx context.Context, bucket string, path string) (*interfaces.FileInfo, error) {
	// Validate inputs
	if bucket == "" {
		return nil, fmt.Errorf("bucket name cannot be empty")
	}
	if path == "" {
		return nil, fmt.Errorf("file path cannot be empty")
	}

	// Clean path to prevent directory traversal
	cleanPath := filepath.Clean(path)
	if strings.Contains(cleanPath, "..") {
		return nil, fmt.Errorf("invalid file path: directory traversal not allowed")
	}

	return s.repo.GetFileByPath(ctx, bucket, cleanPath)
}

// ListFiles implements file search and listing
func (s *Service) ListFiles(ctx context.Context, bucket string, prefix string, limit int, offset int) ([]*interfaces.FileInfo, error) {
	// Validate bucket
	if bucket == "" {
		return nil, fmt.Errorf("bucket name cannot be empty")
	}

	// Set default limit if not provided
	if limit <= 0 {
		limit = 100
	}

	// Ensure offset is not negative
	if offset < 0 {
		offset = 0
	}

	return s.repo.ListFiles(ctx, bucket, prefix, limit, offset)
}

// CreateBucket creates a new storage bucket
func (s *Service) CreateBucket(ctx context.Context, bucket string, config interfaces.BucketConfig) error {
	// Validate bucket name
	if bucket == "" {
		return fmt.Errorf("bucket name cannot be empty")
	}

	// Create bucket directory
	bucketPath := filepath.Join(s.basePath, bucket)
	if err := os.MkdirAll(bucketPath, 0755); err != nil {
		return fmt.Errorf("failed to create bucket directory: %w", err)
	}

	// Store bucket metadata in database
	return s.repo.CreateBucket(ctx, bucket, config)
}

// DeleteBucket deletes a storage bucket and all its files
func (s *Service) DeleteBucket(ctx context.Context, bucket string) error {
	// Validate bucket name
	if bucket == "" {
		return fmt.Errorf("bucket name cannot be empty")
	}

	// Delete all files in the bucket from database
	if err := s.repo.DeleteBucketFiles(ctx, bucket); err != nil {
		return fmt.Errorf("failed to delete bucket files from database: %w", err)
	}

	// Delete bucket metadata from database
	if err := s.repo.DeleteBucket(ctx, bucket); err != nil {
		return fmt.Errorf("failed to delete bucket from database: %w", err)
	}

	// Delete bucket directory from disk
	bucketPath := filepath.Join(s.basePath, bucket)
	if err := os.RemoveAll(bucketPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to delete bucket directory: %w", err)
	}

	return nil
}

// GetBuckets retrieves all storage buckets
func (s *Service) GetBuckets(ctx context.Context) ([]*interfaces.BucketInfo, error) {
	return s.repo.GetBuckets(ctx)
}

// SearchFiles performs advanced file search with multiple criteria
func (s *Service) SearchFiles(ctx context.Context, criteria SearchCriteria) ([]*interfaces.FileInfo, error) {
	return s.repo.SearchFiles(ctx, criteria)
}

// UpdateFileMetadata updates file metadata without changing the file content
func (s *Service) UpdateFileMetadata(ctx context.Context, bucket string, path string, metadata map[string]string) error {
	// Validate inputs
	if bucket == "" {
		return fmt.Errorf("bucket name cannot be empty")
	}
	if path == "" {
		return fmt.Errorf("file path cannot be empty")
	}

	// Clean path to prevent directory traversal
	cleanPath := filepath.Clean(path)
	if strings.Contains(cleanPath, "..") {
		return fmt.Errorf("invalid file path: directory traversal not allowed")
	}

	return s.repo.UpdateFileMetadata(ctx, bucket, cleanPath, metadata)
}

// GetFilesByMetadata retrieves files based on metadata queries
func (s *Service) GetFilesByMetadata(ctx context.Context, bucket string, metadataQuery map[string]string) ([]*interfaces.FileInfo, error) {
	if bucket == "" {
		return nil, fmt.Errorf("bucket name cannot be empty")
	}

	return s.repo.GetFilesByMetadata(ctx, bucket, metadataQuery)
}

// GetFileStats retrieves statistics about files in a bucket
func (s *Service) GetFileStats(ctx context.Context, bucket string) (*FileStats, error) {
	if bucket == "" {
		return nil, fmt.Errorf("bucket name cannot be empty")
	}

	return s.repo.GetFileStats(ctx, bucket)
}

// SearchCriteria represents search parameters for file search
type SearchCriteria struct {
	Bucket      string            `json:"bucket"`
	NamePattern string            `json:"name_pattern"`
	MimeType    string            `json:"mime_type"`
	MinSize     int64             `json:"min_size"`
	MaxSize     int64             `json:"max_size"`
	Metadata    map[string]string `json:"metadata"`
	CreatedFrom *time.Time        `json:"created_from"`
	CreatedTo   *time.Time        `json:"created_to"`
	Limit       int               `json:"limit"`
	Offset      int               `json:"offset"`
}

// FileStats represents file statistics for a bucket
type FileStats struct {
	TotalFiles int64            `json:"total_files"`
	TotalSize  int64            `json:"total_size"`
	AvgSize    int64            `json:"avg_size"`
	MimeTypes  map[string]int64 `json:"mime_types"`
}

// CreateFileVersion creates a new version of an existing file
func (s *Service) CreateFileVersion(ctx context.Context, bucket string, path string) (*FileVersion, error) {
	// Get current file info
	fileInfo, err := s.GetFileInfo(ctx, bucket, path)
	if err != nil {
		return nil, fmt.Errorf("failed to get file info: %w", err)
	}

	// Create version
	return s.versioning.CreateVersion(ctx, fileInfo)
}

// GetFileVersions retrieves all versions of a file
func (s *Service) GetFileVersions(ctx context.Context, bucket string, path string) ([]*FileVersion, error) {
	// Get file info to get file ID
	fileInfo, err := s.GetFileInfo(ctx, bucket, path)
	if err != nil {
		return nil, fmt.Errorf("failed to get file info: %w", err)
	}

	return s.versioning.GetVersions(ctx, fileInfo.ID)
}

// GetFileVersion retrieves a specific version of a file
func (s *Service) GetFileVersion(ctx context.Context, bucket string, path string, version int) (*FileVersion, error) {
	// Get file info to get file ID
	fileInfo, err := s.GetFileInfo(ctx, bucket, path)
	if err != nil {
		return nil, fmt.Errorf("failed to get file info: %w", err)
	}

	return s.versioning.GetVersion(ctx, fileInfo.ID, version)
}

// DeleteFileVersion removes a specific version of a file
func (s *Service) DeleteFileVersion(ctx context.Context, bucket string, path string, version int) error {
	// Get file info to get file ID
	fileInfo, err := s.GetFileInfo(ctx, bucket, path)
	if err != nil {
		return fmt.Errorf("failed to get file info: %w", err)
	}

	return s.versioning.DeleteVersion(ctx, fileInfo.ID, version)
}

// CleanupOldFileVersions removes old versions beyond the retention limit
func (s *Service) CleanupOldFileVersions(ctx context.Context, bucket string, path string, retentionCount int) error {
	// Get file info to get file ID
	fileInfo, err := s.GetFileInfo(ctx, bucket, path)
	if err != nil {
		return fmt.Errorf("failed to get file info: %w", err)
	}

	return s.versioning.CleanupOldVersions(ctx, fileInfo.ID, retentionCount)
}

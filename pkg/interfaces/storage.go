package interfaces

import (
	"context"
	"io"
	"time"
)

// StorageService defines the file storage service interface
type StorageService interface {
	Upload(ctx context.Context, bucket string, path string, file io.Reader, metadata FileMetadata) (*FileInfo, error)
	Download(ctx context.Context, bucket string, path string) (io.Reader, error)
	Delete(ctx context.Context, bucket string, path string) error
	GetFileInfo(ctx context.Context, bucket string, path string) (*FileInfo, error)
	ListFiles(ctx context.Context, bucket string, prefix string, limit int, offset int) ([]*FileInfo, error)
	CreateBucket(ctx context.Context, bucket string, config BucketConfig) error
	DeleteBucket(ctx context.Context, bucket string) error
	GetBuckets(ctx context.Context) ([]*BucketInfo, error)
}

// AccessControl defines interface for file access control
type AccessControl interface {
	CanRead(ctx context.Context, userID string, bucket string, path string) bool
	CanWrite(ctx context.Context, userID string, bucket string, path string) bool
	CanDelete(ctx context.Context, userID string, bucket string, path string) bool
	SetPermissions(ctx context.Context, bucket string, path string, permissions FilePermissions) error
	GetPermissions(ctx context.Context, bucket string, path string) (*FilePermissions, error)
}

// FileInfo represents stored file metadata
type FileInfo struct {
	ID          string            `json:"id"`
	Bucket      string            `json:"bucket"`
	Path        string            `json:"path"`
	Name        string            `json:"name"`
	Size        int64             `json:"size"`
	MimeType    string            `json:"mime_type"`
	Checksum    string            `json:"checksum"`
	Metadata    map[string]string `json:"metadata"`
	Permissions *FilePermissions  `json:"permissions"`
	CreatedAt   time.Time         `json:"created_at"`
	UpdatedAt   time.Time         `json:"updated_at"`
}

// FileMetadata represents file upload metadata
type FileMetadata struct {
	Name        string            `json:"name"`
	MimeType    string            `json:"mime_type"`
	Size        int64             `json:"size"`
	Metadata    map[string]string `json:"metadata"`
	Permissions *FilePermissions  `json:"permissions"`
}

// BucketInfo represents storage bucket information
type BucketInfo struct {
	Name      string       `json:"name"`
	Config    BucketConfig `json:"config"`
	FileCount int64        `json:"file_count"`
	TotalSize int64        `json:"total_size"`
	CreatedAt time.Time    `json:"created_at"`
	UpdatedAt time.Time    `json:"updated_at"`
}

// BucketConfig represents bucket configuration
type BucketConfig struct {
	Public           bool     `json:"public"`
	MaxFileSize      int64    `json:"max_file_size"`
	AllowedMimeTypes []string `json:"allowed_mime_types"`
	Versioning       bool     `json:"versioning"`
}

// FilePermissions represents file access permissions
type FilePermissions struct {
	Public bool     `json:"public"`
	Read   []string `json:"read"`   // user IDs or roles
	Write  []string `json:"write"`  // user IDs or roles
	Delete []string `json:"delete"` // user IDs or roles
}

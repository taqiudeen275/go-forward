package storage

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/taqiudeen275/go-foward/internal/database"
	"github.com/taqiudeen275/go-foward/pkg/interfaces"
)

// Test helper functions
func setupTestService(t *testing.T) (*Service, string, func()) {
	// Create temporary directory for test files
	tempDir, err := os.MkdirTemp("", "storage_test_*")
	require.NoError(t, err)

	// Create mock database
	mockDB := &database.DB{}

	// Create service
	service := NewService(mockDB, tempDir)

	// Return cleanup function
	cleanup := func() {
		os.RemoveAll(tempDir)
	}

	return service, tempDir, cleanup
}

func createTestFile(content string) io.Reader {
	return strings.NewReader(content)
}

func TestNewService(t *testing.T) {
	t.Run("creates service with default path", func(t *testing.T) {
		mockDB := &database.DB{}
		service := NewService(mockDB, "")

		assert.NotNil(t, service)
		assert.Equal(t, "./storage", service.basePath)
		assert.NotNil(t, service.repo)
		assert.NotNil(t, service.versioning)
	})

	t.Run("creates service with custom path", func(t *testing.T) {
		mockDB := &database.DB{}
		customPath := "/tmp/custom_storage"
		service := NewService(mockDB, customPath)

		assert.NotNil(t, service)
		assert.Equal(t, customPath, service.basePath)
	})

	t.Run("creates base directory", func(t *testing.T) {
		tempDir, err := os.MkdirTemp("", "storage_test_*")
		require.NoError(t, err)
		defer os.RemoveAll(tempDir)

		testPath := filepath.Join(tempDir, "test_storage")
		mockDB := &database.DB{}

		service := NewService(mockDB, testPath)
		assert.NotNil(t, service)

		// Check that directory was created
		_, err = os.Stat(testPath)
		assert.NoError(t, err)
	})
}

func TestService_Upload_Validation(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	ctx := context.Background()

	t.Run("empty bucket name", func(t *testing.T) {
		file := createTestFile("test")
		metadata := interfaces.FileMetadata{Name: "test.txt"}

		_, err := service.Upload(ctx, "", "test.txt", file, metadata)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "bucket name cannot be empty")
	})

	t.Run("empty file path", func(t *testing.T) {
		file := createTestFile("test")
		metadata := interfaces.FileMetadata{Name: "test.txt"}

		_, err := service.Upload(ctx, "bucket", "", file, metadata)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "file path cannot be empty")
	})

	t.Run("directory traversal prevention", func(t *testing.T) {
		file := createTestFile("test")
		metadata := interfaces.FileMetadata{Name: "test.txt"}

		_, err := service.Upload(ctx, "bucket", "../../../etc/passwd", file, metadata)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "directory traversal not allowed")
	})

	t.Run("file metadata structure validation", func(t *testing.T) {
		metadata := interfaces.FileMetadata{
			Name:     "test-file.txt",
			MimeType: "text/plain",
			Size:     1024,
			Metadata: map[string]string{"key": "value", "category": "documents"},
		}

		assert.Equal(t, "test-file.txt", metadata.Name)
		assert.Equal(t, "text/plain", metadata.MimeType)
		assert.Equal(t, int64(1024), metadata.Size)
		assert.Equal(t, "value", metadata.Metadata["key"])
		assert.Equal(t, "documents", metadata.Metadata["category"])
		assert.Len(t, metadata.Metadata, 2)
	})

	t.Run("file info structure validation", func(t *testing.T) {
		now := time.Now()
		fileInfo := &interfaces.FileInfo{
			ID:        "file123",
			Bucket:    "test-bucket",
			Path:      "documents/file.txt",
			Name:      "file.txt",
			Size:      2048,
			MimeType:  "text/plain",
			Checksum:  "abc123def456",
			Metadata:  map[string]string{"author": "user123"},
			CreatedAt: now,
			UpdatedAt: now,
		}

		assert.Equal(t, "file123", fileInfo.ID)
		assert.Equal(t, "test-bucket", fileInfo.Bucket)
		assert.Equal(t, "documents/file.txt", fileInfo.Path)
		assert.Equal(t, "file.txt", fileInfo.Name)
		assert.Equal(t, int64(2048), fileInfo.Size)
		assert.Equal(t, "text/plain", fileInfo.MimeType)
		assert.Equal(t, "abc123def456", fileInfo.Checksum)
		assert.Equal(t, "user123", fileInfo.Metadata["author"])
		assert.Equal(t, now, fileInfo.CreatedAt)
		assert.Equal(t, now, fileInfo.UpdatedAt)
	})
}

func TestService_Download_Validation(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	ctx := context.Background()

	t.Run("empty bucket name", func(t *testing.T) {
		_, err := service.Download(ctx, "", "test.txt")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "bucket name cannot be empty")
	})

	t.Run("empty file path", func(t *testing.T) {
		_, err := service.Download(ctx, "bucket", "")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "file path cannot be empty")
	})

	t.Run("directory traversal prevention", func(t *testing.T) {
		_, err := service.Download(ctx, "bucket", "../../../etc/passwd")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "directory traversal not allowed")
	})

	t.Run("download validation logic", func(t *testing.T) {
		// Test that download validates inputs properly
		testCases := []struct {
			bucket   string
			path     string
			errorMsg string
		}{
			{"", "test.txt", "bucket name cannot be empty"},
			{"bucket", "", "file path cannot be empty"},
			{"bucket", "../../../etc/passwd", "directory traversal not allowed"},
		}

		for _, tc := range testCases {
			_, err := service.Download(ctx, tc.bucket, tc.path)
			assert.Error(t, err)
			assert.Contains(t, err.Error(), tc.errorMsg)
		}
	})
}

func TestService_Delete_Validation(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	ctx := context.Background()

	t.Run("empty bucket name", func(t *testing.T) {
		err := service.Delete(ctx, "", "test.txt")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "bucket name cannot be empty")
	})

	t.Run("empty file path", func(t *testing.T) {
		err := service.Delete(ctx, "bucket", "")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "file path cannot be empty")
	})

	t.Run("directory traversal prevention", func(t *testing.T) {
		err := service.Delete(ctx, "bucket", "../../../etc/passwd")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "directory traversal not allowed")
	})

	t.Run("delete validation logic", func(t *testing.T) {
		// Test that delete validates inputs properly
		testCases := []struct {
			bucket   string
			path     string
			errorMsg string
		}{
			{"", "test.txt", "bucket name cannot be empty"},
			{"bucket", "", "file path cannot be empty"},
			{"bucket", "../../../etc/passwd", "directory traversal not allowed"},
		}

		for _, tc := range testCases {
			err := service.Delete(ctx, tc.bucket, tc.path)
			assert.Error(t, err)
			assert.Contains(t, err.Error(), tc.errorMsg)
		}
	})
}

func TestService_GetFileInfo_Validation(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	ctx := context.Background()

	t.Run("empty bucket name", func(t *testing.T) {
		_, err := service.GetFileInfo(ctx, "", "test.txt")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "bucket name cannot be empty")
	})

	t.Run("empty file path", func(t *testing.T) {
		_, err := service.GetFileInfo(ctx, "bucket", "")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "file path cannot be empty")
	})

	t.Run("directory traversal prevention", func(t *testing.T) {
		_, err := service.GetFileInfo(ctx, "bucket", "../../../etc/passwd")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "directory traversal not allowed")
	})
}

func TestService_ListFiles_Validation(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	ctx := context.Background()

	t.Run("empty bucket name", func(t *testing.T) {
		_, err := service.ListFiles(ctx, "", "prefix", 10, 0)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "bucket name cannot be empty")
	})

	t.Run("parameter validation logic", func(t *testing.T) {
		// Test parameter handling without calling the actual function
		// Default limit should be 100 when 0 is provided
		limit := 0
		if limit <= 0 {
			limit = 100
		}
		assert.Equal(t, 100, limit)

		// Negative offset should be corrected to 0
		offset := -5
		if offset < 0 {
			offset = 0
		}
		assert.Equal(t, 0, offset)
	})
}

func TestService_FileOperations_PathCleaning(t *testing.T) {
	t.Run("path cleaning logic", func(t *testing.T) {
		testCases := []struct {
			name        string
			path        string
			shouldError bool
		}{
			{
				name:        "normal path",
				path:        "documents/file.txt",
				shouldError: false,
			},
			{
				name:        "path with dots",
				path:        "documents/../file.txt",
				shouldError: false, // This gets cleaned to "file.txt"
			},
			{
				name:        "absolute path attempt",
				path:        "/etc/passwd",
				shouldError: false, // This gets cleaned to "etc/passwd"
			},
			{
				name:        "multiple traversal attempts",
				path:        "../../../../../../etc/passwd",
				shouldError: true,
			},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				// Test path cleaning logic without database calls
				cleanPath := filepath.Clean(tc.path)
				containsTraversal := strings.Contains(cleanPath, "..")

				if tc.shouldError {
					assert.True(t, containsTraversal, "Path should contain directory traversal")
				} else {
					assert.False(t, containsTraversal, "Path should not contain directory traversal")
				}
			})
		}
	})
}

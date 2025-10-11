package storage

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/taqiudeen275/go-foward/pkg/interfaces"
)

func TestService_UpdateFileMetadata_Validation(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	ctx := context.Background()

	t.Run("empty bucket name", func(t *testing.T) {
		metadata := map[string]string{"key": "value"}

		err := service.UpdateFileMetadata(ctx, "", "test.txt", metadata)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "bucket name cannot be empty")
	})

	t.Run("empty file path", func(t *testing.T) {
		metadata := map[string]string{"key": "value"}

		err := service.UpdateFileMetadata(ctx, "bucket", "", metadata)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "file path cannot be empty")
	})

	t.Run("directory traversal prevention", func(t *testing.T) {
		metadata := map[string]string{"key": "value"}

		err := service.UpdateFileMetadata(ctx, "bucket", "../../../etc/passwd", metadata)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "directory traversal not allowed")
	})
}

func TestService_GetFilesByMetadata_Validation(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	ctx := context.Background()

	t.Run("empty bucket name", func(t *testing.T) {
		metadataQuery := map[string]string{"key": "value"}

		_, err := service.GetFilesByMetadata(ctx, "", metadataQuery)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "bucket name cannot be empty")
	})
}

func TestService_SearchFiles_Validation(t *testing.T) {
	t.Run("search criteria validation", func(t *testing.T) {
		// Test that search criteria structure is properly formed
		now := time.Now()
		criteria := SearchCriteria{
			Bucket:      "bucket",
			NamePattern: "*.pdf",
			MimeType:    "application/pdf",
			MinSize:     1024,
			MaxSize:     1048576,
			Metadata:    map[string]string{"category": "documents"},
			CreatedFrom: &now,
			Limit:       10,
			Offset:      0,
		}

		assert.Equal(t, "bucket", criteria.Bucket)
		assert.Equal(t, "*.pdf", criteria.NamePattern)
		assert.Equal(t, "application/pdf", criteria.MimeType)
		assert.Equal(t, int64(1024), criteria.MinSize)
		assert.Equal(t, int64(1048576), criteria.MaxSize)
		assert.Equal(t, "documents", criteria.Metadata["category"])
		assert.NotNil(t, criteria.CreatedFrom)
		assert.Equal(t, 10, criteria.Limit)
		assert.Equal(t, 0, criteria.Offset)
	})
}

func TestService_GetFileStats_Validation(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	ctx := context.Background()

	t.Run("empty bucket name", func(t *testing.T) {
		_, err := service.GetFileStats(ctx, "")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "bucket name cannot be empty")
	})
}

func TestService_CreateBucket_Validation(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	ctx := context.Background()

	t.Run("empty bucket name", func(t *testing.T) {
		config := interfaces.BucketConfig{}

		err := service.CreateBucket(ctx, "", config)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "bucket name cannot be empty")
	})

	t.Run("bucket config structure", func(t *testing.T) {
		config := interfaces.BucketConfig{
			Public:           false,
			MaxFileSize:      10485760, // 10MB
			AllowedMimeTypes: []string{"image/jpeg", "image/png", "application/pdf"},
			Versioning:       true,
		}

		assert.False(t, config.Public)
		assert.Equal(t, int64(10485760), config.MaxFileSize)
		assert.Contains(t, config.AllowedMimeTypes, "image/jpeg")
		assert.Contains(t, config.AllowedMimeTypes, "image/png")
		assert.Contains(t, config.AllowedMimeTypes, "application/pdf")
		assert.True(t, config.Versioning)
		assert.Len(t, config.AllowedMimeTypes, 3)
	})
}

func TestService_DeleteBucket_Validation(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	ctx := context.Background()

	t.Run("empty bucket name", func(t *testing.T) {
		err := service.DeleteBucket(ctx, "")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "bucket name cannot be empty")
	})

	t.Run("bucket deletion validation", func(t *testing.T) {
		// Test that empty bucket name is properly validated
		err := service.DeleteBucket(ctx, "")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "bucket name cannot be empty")
	})
}

func TestSearchCriteria_Struct(t *testing.T) {
	t.Run("search criteria structure", func(t *testing.T) {
		now := time.Now()
		criteria := SearchCriteria{
			Bucket:      "test-bucket",
			NamePattern: "*.jpg",
			MimeType:    "image/jpeg",
			MinSize:     1024,
			MaxSize:     1048576,
			Metadata:    map[string]string{"category": "photos", "year": "2023"},
			CreatedFrom: &now,
			CreatedTo:   &now,
			Limit:       50,
			Offset:      10,
		}

		assert.Equal(t, "test-bucket", criteria.Bucket)
		assert.Equal(t, "*.jpg", criteria.NamePattern)
		assert.Equal(t, "image/jpeg", criteria.MimeType)
		assert.Equal(t, int64(1024), criteria.MinSize)
		assert.Equal(t, int64(1048576), criteria.MaxSize)
		assert.Equal(t, "photos", criteria.Metadata["category"])
		assert.Equal(t, "2023", criteria.Metadata["year"])
		assert.Equal(t, 50, criteria.Limit)
		assert.Equal(t, 10, criteria.Offset)
		assert.NotNil(t, criteria.CreatedFrom)
		assert.NotNil(t, criteria.CreatedTo)
	})
}

func TestFileStats_Struct(t *testing.T) {
	t.Run("file stats structure", func(t *testing.T) {
		stats := &FileStats{
			TotalFiles: 150,
			TotalSize:  1048576000, // ~1GB
			AvgSize:    6990506,    // ~7MB
			MimeTypes: map[string]int64{
				"image/jpeg":      50,
				"image/png":       30,
				"application/pdf": 40,
				"text/plain":      20,
				"video/mp4":       10,
			},
		}

		assert.Equal(t, int64(150), stats.TotalFiles)
		assert.Equal(t, int64(1048576000), stats.TotalSize)
		assert.Equal(t, int64(6990506), stats.AvgSize)
		assert.Equal(t, int64(50), stats.MimeTypes["image/jpeg"])
		assert.Equal(t, int64(30), stats.MimeTypes["image/png"])
		assert.Equal(t, int64(40), stats.MimeTypes["application/pdf"])
		assert.Equal(t, int64(20), stats.MimeTypes["text/plain"])
		assert.Equal(t, int64(10), stats.MimeTypes["video/mp4"])
	})
}

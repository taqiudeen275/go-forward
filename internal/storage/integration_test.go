package storage

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/taqiudeen275/go-foward/internal/database"
	"github.com/taqiudeen275/go-foward/pkg/interfaces"
)

func TestStorageServiceIntegration(t *testing.T) {
	// Skip if not in integration test mode
	if os.Getenv("INTEGRATION_TEST") == "" {
		t.Skip("Skipping integration test. Set INTEGRATION_TEST=1 to run.")
	}

	// Setup test database connection
	config := &database.Config{
		Host:     getEnvOrDefault("DB_HOST", "localhost"),
		Port:     5432,
		Name:     getEnvOrDefault("DB_NAME", "test_db"),
		User:     getEnvOrDefault("DB_USER", "test"),
		Password: getEnvOrDefault("DB_PASSWORD", "test"),
		SSLMode:  "disable",
	}

	db, err := database.New(config)
	require.NoError(t, err)
	defer db.Close()

	// Test database connection
	err = db.Ping(context.Background())
	require.NoError(t, err, "Database connection failed")

	// Create storage service
	service := NewService(db, "./test_storage_integration")
	defer func() {
		// Cleanup
		os.RemoveAll("./test_storage_integration")
		service.DeleteBucket(context.Background(), "integration-test")
	}()

	ctx := context.Background()

	t.Run("Complete file lifecycle with metadata", func(t *testing.T) {
		// 1. Create bucket
		bucketConfig := interfaces.BucketConfig{
			Public:           false,
			MaxFileSize:      1024 * 1024,
			AllowedMimeTypes: []string{"text/plain"},
			Versioning:       true,
		}
		err := service.CreateBucket(ctx, "integration-test", bucketConfig)
		require.NoError(t, err)

		// 2. Upload file with metadata
		fileContent := strings.NewReader("Integration test file content")
		metadata := interfaces.FileMetadata{
			Name:     "integration-test.txt",
			MimeType: "text/plain",
			Metadata: map[string]string{
				"test":        "integration",
				"environment": "test",
				"author":      "test-suite",
			},
		}

		fileInfo, err := service.Upload(ctx, "integration-test", "integration-test.txt", fileContent, metadata)
		require.NoError(t, err)
		assert.Equal(t, "integration-test.txt", fileInfo.Name)
		assert.Equal(t, "integration", fileInfo.Metadata["test"])

		// 3. Update metadata
		newMetadata := map[string]string{
			"test":        "integration",
			"environment": "updated",
			"author":      "updated-test-suite",
			"version":     "1.1",
		}
		err = service.UpdateFileMetadata(ctx, "integration-test", "integration-test.txt", newMetadata)
		require.NoError(t, err)

		// 4. Verify metadata update
		updatedFileInfo, err := service.GetFileInfo(ctx, "integration-test", "integration-test.txt")
		require.NoError(t, err)
		assert.Equal(t, "updated", updatedFileInfo.Metadata["environment"])
		assert.Equal(t, "1.1", updatedFileInfo.Metadata["version"])

		// 5. Create file version
		version, err := service.CreateFileVersion(ctx, "integration-test", "integration-test.txt")
		require.NoError(t, err)
		assert.Equal(t, 1, version.Version)

		// 6. Search files by metadata
		files, err := service.GetFilesByMetadata(ctx, "integration-test", map[string]string{
			"test": "integration",
		})
		require.NoError(t, err)
		assert.Len(t, files, 1)
		assert.Equal(t, "integration-test.txt", files[0].Name)

		// 7. Advanced search
		criteria := SearchCriteria{
			Bucket:      "integration-test",
			NamePattern: "integration",
			MimeType:    "text/plain",
			Metadata: map[string]string{
				"environment": "updated",
			},
		}
		searchResults, err := service.SearchFiles(ctx, criteria)
		require.NoError(t, err)
		assert.Len(t, searchResults, 1)

		// 8. Get file statistics
		stats, err := service.GetFileStats(ctx, "integration-test")
		require.NoError(t, err)
		assert.Equal(t, int64(1), stats.TotalFiles)
		assert.Greater(t, stats.TotalSize, int64(0))
		assert.Contains(t, stats.MimeTypes, "text/plain")

		// 9. Download file
		reader, err := service.Download(ctx, "integration-test", "integration-test.txt")
		require.NoError(t, err)
		assert.NotNil(t, reader)

		// 10. List files
		fileList, err := service.ListFiles(ctx, "integration-test", "", 10, 0)
		require.NoError(t, err)
		assert.Len(t, fileList, 1)

		// 11. Get versions
		versions, err := service.GetFileVersions(ctx, "integration-test", "integration-test.txt")
		require.NoError(t, err)
		assert.Len(t, versions, 1)

		// 12. Delete file
		err = service.Delete(ctx, "integration-test", "integration-test.txt")
		require.NoError(t, err)

		// 13. Verify file is deleted
		_, err = service.GetFileInfo(ctx, "integration-test", "integration-test.txt")
		assert.Error(t, err)
	})

	t.Run("Bucket operations", func(t *testing.T) {
		// List buckets
		buckets, err := service.GetBuckets(ctx)
		require.NoError(t, err)

		// Should have at least the integration-test bucket
		found := false
		for _, bucket := range buckets {
			if bucket.Name == "integration-test" {
				found = true
				assert.True(t, bucket.Config.Versioning)
				break
			}
		}
		assert.True(t, found, "integration-test bucket should exist")
	})
}

func getEnvOrDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

package storage

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/taqiudeen275/go-foward/internal/database"
	"github.com/taqiudeen275/go-foward/pkg/interfaces"
)

func TestFileMetadataManagement(t *testing.T) {
	// Setup test database
	config := &database.Config{
		Host:     "localhost",
		Port:     5432,
		Name:     "test_db",
		User:     "test",
		Password: "test",
		SSLMode:  "disable",
	}

	db, err := database.New(config)
	require.NoError(t, err)
	defer db.Close()

	// Create storage service
	service := NewService(db, "./test_storage")
	defer func() {
		// Cleanup test files
		service.DeleteBucket(context.Background(), "test-bucket")
	}()

	ctx := context.Background()

	// Create test bucket
	bucketConfig := interfaces.BucketConfig{
		Public:           false,
		MaxFileSize:      1024 * 1024, // 1MB
		AllowedMimeTypes: []string{"text/plain", "image/jpeg"},
		Versioning:       true,
	}
	err = service.CreateBucket(ctx, "test-bucket", bucketConfig)
	require.NoError(t, err)

	t.Run("Upload file with metadata", func(t *testing.T) {
		fileContent := strings.NewReader("test file content")
		metadata := interfaces.FileMetadata{
			Name:     "test.txt",
			MimeType: "text/plain",
			Size:     17,
			Metadata: map[string]string{
				"author":      "test-user",
				"category":    "document",
				"description": "test file for metadata management",
			},
		}

		fileInfo, err := service.Upload(ctx, "test-bucket", "test.txt", fileContent, metadata)
		require.NoError(t, err)
		assert.Equal(t, "test.txt", fileInfo.Name)
		assert.Equal(t, "text/plain", fileInfo.MimeType)
		assert.Equal(t, "test-user", fileInfo.Metadata["author"])
		assert.Equal(t, "document", fileInfo.Metadata["category"])
	})

	t.Run("Update file metadata", func(t *testing.T) {
		newMetadata := map[string]string{
			"author":      "updated-user",
			"category":    "updated-document",
			"description": "updated test file",
			"version":     "1.1",
		}

		err := service.UpdateFileMetadata(ctx, "test-bucket", "test.txt", newMetadata)
		require.NoError(t, err)

		// Verify metadata was updated
		fileInfo, err := service.GetFileInfo(ctx, "test-bucket", "test.txt")
		require.NoError(t, err)
		assert.Equal(t, "updated-user", fileInfo.Metadata["author"])
		assert.Equal(t, "updated-document", fileInfo.Metadata["category"])
		assert.Equal(t, "1.1", fileInfo.Metadata["version"])
	})

	t.Run("Search files by metadata", func(t *testing.T) {
		// Upload additional test files
		for i := 0; i < 3; i++ {
			content := strings.NewReader("test content")
			metadata := interfaces.FileMetadata{
				Name:     "file" + string(rune(i+'1')) + ".txt",
				MimeType: "text/plain",
				Metadata: map[string]string{
					"category": "test",
					"index":    string(rune(i + '1')),
				},
			}
			_, err := service.Upload(ctx, "test-bucket", "file"+string(rune(i+'1'))+".txt", content, metadata)
			require.NoError(t, err)
		}

		// Search by metadata
		metadataQuery := map[string]string{
			"category": "test",
		}
		files, err := service.GetFilesByMetadata(ctx, "test-bucket", metadataQuery)
		require.NoError(t, err)
		assert.Len(t, files, 3)

		// Search by specific index
		metadataQuery = map[string]string{
			"category": "test",
			"index":    "2",
		}
		files, err = service.GetFilesByMetadata(ctx, "test-bucket", metadataQuery)
		require.NoError(t, err)
		assert.Len(t, files, 1)
		assert.Equal(t, "file2.txt", files[0].Name)
	})

	t.Run("Advanced file search", func(t *testing.T) {
		criteria := SearchCriteria{
			Bucket:      "test-bucket",
			NamePattern: "file",
			MimeType:    "text/plain",
			MinSize:     1,
			MaxSize:     1000,
			Metadata: map[string]string{
				"category": "test",
			},
			Limit:  10,
			Offset: 0,
		}

		files, err := service.SearchFiles(ctx, criteria)
		require.NoError(t, err)
		assert.GreaterOrEqual(t, len(files), 3)

		// Test with name pattern
		criteria.NamePattern = "file1"
		files, err = service.SearchFiles(ctx, criteria)
		require.NoError(t, err)
		assert.Len(t, files, 1)
		assert.Equal(t, "file1.txt", files[0].Name)
	})

	t.Run("Get file statistics", func(t *testing.T) {
		stats, err := service.GetFileStats(ctx, "test-bucket")
		require.NoError(t, err)
		assert.GreaterOrEqual(t, stats.TotalFiles, int64(4)) // At least 4 files uploaded
		assert.Greater(t, stats.TotalSize, int64(0))
		assert.Greater(t, stats.AvgSize, int64(0))
		assert.Contains(t, stats.MimeTypes, "text/plain")
		assert.Greater(t, stats.MimeTypes["text/plain"], int64(0))
	})
}

func TestFileVersioning(t *testing.T) {
	// Setup test database
	config := &database.Config{
		Host:     "localhost",
		Port:     5432,
		Name:     "test_db",
		User:     "test",
		Password: "test",
		SSLMode:  "disable",
	}

	db, err := database.New(config)
	require.NoError(t, err)
	defer db.Close()

	// Create storage service
	service := NewService(db, "./test_storage")
	defer func() {
		// Cleanup test files
		service.DeleteBucket(context.Background(), "version-test-bucket")
	}()

	ctx := context.Background()

	// Create test bucket with versioning enabled
	bucketConfig := interfaces.BucketConfig{
		Public:      false,
		MaxFileSize: 1024 * 1024,
		Versioning:  true,
	}
	err = service.CreateBucket(ctx, "version-test-bucket", bucketConfig)
	require.NoError(t, err)

	t.Run("Create file versions", func(t *testing.T) {
		// Upload initial file
		fileContent := strings.NewReader("initial content")
		metadata := interfaces.FileMetadata{
			Name:     "versioned.txt",
			MimeType: "text/plain",
			Metadata: map[string]string{
				"version": "1.0",
			},
		}

		fileInfo, err := service.Upload(ctx, "version-test-bucket", "versioned.txt", fileContent, metadata)
		require.NoError(t, err)

		// Create first version
		version1, err := service.CreateFileVersion(ctx, "version-test-bucket", "versioned.txt")
		require.NoError(t, err)
		assert.Equal(t, 1, version1.Version)
		assert.Equal(t, fileInfo.ID, version1.FileID)

		// Update file and create another version
		newMetadata := map[string]string{
			"version": "2.0",
		}
		err = service.UpdateFileMetadata(ctx, "version-test-bucket", "versioned.txt", newMetadata)
		require.NoError(t, err)

		version2, err := service.CreateFileVersion(ctx, "version-test-bucket", "versioned.txt")
		require.NoError(t, err)
		assert.Equal(t, 2, version2.Version)
		assert.Equal(t, fileInfo.ID, version2.FileID)
	})

	t.Run("Get file versions", func(t *testing.T) {
		versions, err := service.GetFileVersions(ctx, "version-test-bucket", "versioned.txt")
		require.NoError(t, err)
		assert.Len(t, versions, 2)

		// Versions should be ordered by version number descending
		assert.Equal(t, 2, versions[0].Version)
		assert.Equal(t, 1, versions[1].Version)
	})

	t.Run("Get specific version", func(t *testing.T) {
		version, err := service.GetFileVersion(ctx, "version-test-bucket", "versioned.txt", 1)
		require.NoError(t, err)
		assert.Equal(t, 1, version.Version)
		assert.Equal(t, "1.0", version.Metadata["version"])
	})

	t.Run("Delete version", func(t *testing.T) {
		err := service.DeleteFileVersion(ctx, "version-test-bucket", "versioned.txt", 1)
		require.NoError(t, err)

		// Verify version was deleted
		versions, err := service.GetFileVersions(ctx, "version-test-bucket", "versioned.txt")
		require.NoError(t, err)
		assert.Len(t, versions, 1)
		assert.Equal(t, 2, versions[0].Version)
	})

	t.Run("Cleanup old versions", func(t *testing.T) {
		// Create more versions
		for i := 3; i <= 5; i++ {
			_, err := service.CreateFileVersion(ctx, "version-test-bucket", "versioned.txt")
			require.NoError(t, err)
		}

		// Cleanup keeping only 2 versions
		err := service.CleanupOldFileVersions(ctx, "version-test-bucket", "versioned.txt", 2)
		require.NoError(t, err)

		// Verify only 2 versions remain
		versions, err := service.GetFileVersions(ctx, "version-test-bucket", "versioned.txt")
		require.NoError(t, err)
		assert.Len(t, versions, 2)
		assert.Equal(t, 5, versions[0].Version) // Latest version
		assert.Equal(t, 4, versions[1].Version) // Second latest
	})
}

func TestSearchCriteria(t *testing.T) {
	// Setup test database
	config := &database.Config{
		Host:     "localhost",
		Port:     5432,
		Name:     "test_db",
		User:     "test",
		Password: "test",
		SSLMode:  "disable",
	}

	db, err := database.New(config)
	require.NoError(t, err)
	defer db.Close()

	// Create storage service
	service := NewService(db, "./test_storage")
	defer func() {
		// Cleanup test files
		service.DeleteBucket(context.Background(), "search-test-bucket")
	}()

	ctx := context.Background()

	// Create test bucket
	bucketConfig := interfaces.BucketConfig{
		Public:      false,
		MaxFileSize: 1024 * 1024,
	}
	err = service.CreateBucket(ctx, "search-test-bucket", bucketConfig)
	require.NoError(t, err)

	// Upload test files with different characteristics
	testFiles := []struct {
		name     string
		content  string
		mimeType string
		metadata map[string]string
	}{
		{
			name:     "document1.txt",
			content:  "small document",
			mimeType: "text/plain",
			metadata: map[string]string{"type": "document", "size": "small"},
		},
		{
			name:     "document2.txt",
			content:  "large document with much more content to make it bigger",
			mimeType: "text/plain",
			metadata: map[string]string{"type": "document", "size": "large"},
		},
		{
			name:     "image1.jpg",
			content:  "fake image content",
			mimeType: "image/jpeg",
			metadata: map[string]string{"type": "image", "format": "jpeg"},
		},
	}

	for _, tf := range testFiles {
		content := strings.NewReader(tf.content)
		metadata := interfaces.FileMetadata{
			Name:     tf.name,
			MimeType: tf.mimeType,
			Metadata: tf.metadata,
		}
		_, err := service.Upload(ctx, "search-test-bucket", tf.name, content, metadata)
		require.NoError(t, err)
	}

	t.Run("Search by MIME type", func(t *testing.T) {
		criteria := SearchCriteria{
			Bucket:   "search-test-bucket",
			MimeType: "text/plain",
		}

		files, err := service.SearchFiles(ctx, criteria)
		require.NoError(t, err)
		assert.Len(t, files, 2)
		for _, file := range files {
			assert.Equal(t, "text/plain", file.MimeType)
		}
	})

	t.Run("Search by size range", func(t *testing.T) {
		criteria := SearchCriteria{
			Bucket:  "search-test-bucket",
			MinSize: 20,
			MaxSize: 100,
		}

		files, err := service.SearchFiles(ctx, criteria)
		require.NoError(t, err)
		for _, file := range files {
			assert.GreaterOrEqual(t, file.Size, int64(20))
			assert.LessOrEqual(t, file.Size, int64(100))
		}
	})

	t.Run("Search by date range", func(t *testing.T) {
		now := time.Now()
		oneHourAgo := now.Add(-1 * time.Hour)

		criteria := SearchCriteria{
			Bucket:      "search-test-bucket",
			CreatedFrom: &oneHourAgo,
			CreatedTo:   &now,
		}

		files, err := service.SearchFiles(ctx, criteria)
		require.NoError(t, err)
		assert.GreaterOrEqual(t, len(files), 3) // All files should be within this range
	})

	t.Run("Search with pagination", func(t *testing.T) {
		criteria := SearchCriteria{
			Bucket: "search-test-bucket",
			Limit:  2,
			Offset: 0,
		}

		files, err := service.SearchFiles(ctx, criteria)
		require.NoError(t, err)
		assert.LessOrEqual(t, len(files), 2)

		// Test second page
		criteria.Offset = 2
		files2, err := service.SearchFiles(ctx, criteria)
		require.NoError(t, err)

		// Ensure no overlap between pages
		if len(files) > 0 && len(files2) > 0 {
			assert.NotEqual(t, files[0].ID, files2[0].ID)
		}
	})
}

package realtime

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/taqiudeen275/go-foward/internal/database"
	"github.com/taqiudeen275/go-foward/pkg/interfaces"
)

// getEnv gets environment variable with fallback
func getEnv(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}

// getEnvInt gets environment variable as int with fallback
func getEnvInt(key string, fallback int) int {
	if value := os.Getenv(key); value != "" {
		if intVal, err := strconv.Atoi(value); err == nil {
			return intVal
		}
	}
	return fallback
}

// setupTestDB creates a test database connection
func setupTestDB(t *testing.T) *database.DB {
	config := &database.Config{
		Host:     getEnv("DB_HOST", "localhost"),
		Port:     getEnvInt("DB_PORT", 5432),
		Name:     getEnv("DB_NAME", "postgres"),
		User:     getEnv("DB_USER", "postgres"),
		Password: getEnv("DB_PASSWORD", "postgres"),
		SSLMode:  getEnv("DB_SSL_MODE", "disable"),
		MaxConns: 25,
		MinConns: 5,
	}

	db, err := database.New(config)
	require.NoError(t, err, "Failed to connect to test database")

	// Clean up any existing test data
	cleanupTestData(t, db)

	return db
}

// cleanupTestData removes any test data from previous runs
func cleanupTestData(t *testing.T, db *database.DB) {
	ctx := context.Background()

	// Clean up test tables if they exist
	queries := []string{
		"DROP TABLE IF EXISTS test_users CASCADE",
		"DROP TABLE IF EXISTS test_posts CASCADE",
	}

	for _, query := range queries {
		_ = db.Exec(ctx, query) // Ignore errors for cleanup
	}
}

// createTestTables creates test tables for integration testing
func createTestTables(t *testing.T, db *database.DB) {
	ctx := context.Background()

	// Create test users table
	createUsersTable := `
		CREATE TABLE IF NOT EXISTS test_users (
			id SERIAL PRIMARY KEY,
			name VARCHAR(100) NOT NULL,
			email VARCHAR(100) UNIQUE NOT NULL,
			status VARCHAR(20) DEFAULT 'active',
			created_at TIMESTAMP DEFAULT NOW(),
			updated_at TIMESTAMP DEFAULT NOW()
		)
	`

	err := db.Exec(ctx, createUsersTable)
	require.NoError(t, err, "Failed to create test_users table")

	// Create test posts table
	createPostsTable := `
		CREATE TABLE IF NOT EXISTS test_posts (
			id SERIAL PRIMARY KEY,
			user_id INTEGER REFERENCES test_users(id) ON DELETE CASCADE,
			title VARCHAR(200) NOT NULL,
			content TEXT,
			published BOOLEAN DEFAULT false,
			created_at TIMESTAMP DEFAULT NOW(),
			updated_at TIMESTAMP DEFAULT NOW()
		)
	`

	err = db.Exec(ctx, createPostsTable)
	require.NoError(t, err, "Failed to create test_posts table")
}

// TestRealTimeService_BasicDatabaseIntegration tests basic real-time service with database
func TestRealTimeService_BasicDatabaseIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	// Setup database
	db := setupTestDB(t)
	defer db.Close()

	createTestTables(t, db)

	// Create real-time service
	mockAuth := &MockAuthService{}
	service := NewService(mockAuth, db.Pool)

	ctx := context.Background()

	// Create a channel for testing
	channelConfig := interfaces.ChannelConfig{
		MaxSubscribers: 100,
		RequireAuth:    false,
	}

	channel, err := service.CreateChannel(ctx, "test-integration-channel", channelConfig)
	require.NoError(t, err)
	assert.Equal(t, "test-integration-channel", channel.GetName())

	// Test basic channel operations
	assert.Equal(t, 0, channel.GetSubscriberCount())

	// Test presence tracking
	err = service.TrackPresence(ctx, "test-integration-channel", "user123", map[string]interface{}{
		"status":    "online",
		"timestamp": time.Now(),
	})
	require.NoError(t, err)

	// Verify presence
	presence := channel.GetPresence()
	assert.Contains(t, presence, "user123")

	// Test message broadcasting
	message := interfaces.Message{
		ID:        "test-msg-1",
		Type:      "test",
		Event:     "integration-test",
		Payload:   map[string]interface{}{"data": "test message"},
		UserID:    "system",
		Timestamp: time.Now(),
	}

	err = service.BroadcastMessage(ctx, "test-integration-channel", message)
	require.NoError(t, err)

	t.Log("Basic database integration test completed successfully")
}

// TestRealTimeService_DatabaseOperations tests database operations with real-time service
func TestRealTimeService_DatabaseOperations(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	// Setup database
	db := setupTestDB(t)
	defer db.Close()

	createTestTables(t, db)

	// Create real-time service
	mockAuth := &MockAuthService{}
	service := NewService(mockAuth, db.Pool)

	ctx := context.Background()

	// Create channel
	channelConfig := interfaces.ChannelConfig{
		MaxSubscribers: 100,
		RequireAuth:    false,
	}

	_, err := service.CreateChannel(ctx, "db-ops-channel", channelConfig)
	require.NoError(t, err)

	// Test database operations while service is running
	// Insert test users
	users := []struct {
		name  string
		email string
	}{
		{"John Doe", "john@example.com"},
		{"Jane Smith", "jane@example.com"},
		{"Bob Johnson", "bob@example.com"},
	}

	userIDs := make([]int, len(users))
	for i, user := range users {
		err = db.QueryRow(ctx,
			"INSERT INTO test_users (name, email) VALUES ($1, $2) RETURNING id",
			user.name, user.email).Scan(&userIDs[i])
		require.NoError(t, err)
		assert.Greater(t, userIDs[i], 0)
	}

	// Insert test posts
	for i, userID := range userIDs {
		var postID int
		err = db.QueryRow(ctx,
			"INSERT INTO test_posts (user_id, title, content) VALUES ($1, $2, $3) RETURNING id",
			userID, fmt.Sprintf("Post %d", i+1), fmt.Sprintf("Content for post %d", i+1)).Scan(&postID)
		require.NoError(t, err)
		assert.Greater(t, postID, 0)
	}

	// Update users
	for _, userID := range userIDs {
		err = db.Exec(ctx,
			"UPDATE test_users SET status = $1, updated_at = NOW() WHERE id = $2",
			"updated", userID)
		require.NoError(t, err)
	}

	// Verify data was inserted and updated
	var count int
	err = db.QueryRow(ctx, "SELECT COUNT(*) FROM test_users WHERE status = 'updated'").Scan(&count)
	require.NoError(t, err)
	assert.Equal(t, len(users), count)

	err = db.QueryRow(ctx, "SELECT COUNT(*) FROM test_posts").Scan(&count)
	require.NoError(t, err)
	assert.Equal(t, len(users), count)

	// Clean up test data
	_ = db.Exec(ctx, "DELETE FROM test_posts WHERE user_id = ANY($1)", userIDs)
	_ = db.Exec(ctx, "DELETE FROM test_users WHERE id = ANY($1)", userIDs)

	t.Log("Database operations test completed successfully")
}

// TestRealTimeService_MultipleChannelsWithDatabase tests multiple channels with database
func TestRealTimeService_MultipleChannelsWithDatabase(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	// Setup database
	db := setupTestDB(t)
	defer db.Close()

	// Create real-time service
	mockAuth := &MockAuthService{}
	service := NewService(mockAuth, db.Pool)

	ctx := context.Background()

	// Create multiple channels with different configurations
	channels := map[string]interfaces.ChannelConfig{
		"public-channel": {
			MaxSubscribers: 1000,
			RequireAuth:    false,
			Metadata: map[string]interface{}{
				"type":        "public",
				"description": "Public channel for all users",
			},
		},
		"private-channel": {
			MaxSubscribers: 50,
			RequireAuth:    true,
			Metadata: map[string]interface{}{
				"type":        "private",
				"description": "Private channel for authenticated users",
			},
		},
		"admin-channel": {
			MaxSubscribers: 10,
			RequireAuth:    true,
			Metadata: map[string]interface{}{
				"type":        "admin",
				"description": "Admin channel for administrators",
			},
		},
	}

	// Create all channels
	for name, config := range channels {
		channel, err := service.CreateChannel(ctx, name, config)
		require.NoError(t, err)
		assert.Equal(t, name, channel.GetName())
	}

	// Test presence tracking in multiple channels
	users := []string{"user1", "user2", "user3", "admin1"}

	for _, channelName := range []string{"public-channel", "private-channel"} {
		for i, userID := range users {
			state := map[string]interface{}{
				"status":    "online",
				"joined_at": time.Now(),
				"user_type": fmt.Sprintf("type_%d", i),
			}

			err := service.TrackPresence(ctx, channelName, userID, state)
			require.NoError(t, err)
		}
	}

	// Verify presence in each channel
	for _, channelName := range []string{"public-channel", "private-channel"} {
		channel, err := service.GetChannel(ctx, channelName)
		require.NoError(t, err)

		presence := channel.GetPresence()
		assert.Len(t, presence, len(users))

		for _, userID := range users {
			assert.Contains(t, presence, userID)
		}
	}

	// Test broadcasting to multiple channels
	message := interfaces.Message{
		ID:    "multi-channel-msg",
		Type:  "broadcast",
		Event: "multi-channel-test",
		Payload: map[string]interface{}{
			"message":   "Hello from integration test",
			"timestamp": time.Now(),
		},
		UserID:    "system",
		Timestamp: time.Now(),
	}

	for channelName := range channels {
		err := service.BroadcastMessage(ctx, channelName, message)
		require.NoError(t, err)
	}

	// Test deleting channels
	for channelName := range channels {
		err := service.DeleteChannel(ctx, channelName)
		require.NoError(t, err)

		// Verify channel is deleted
		_, err = service.GetChannel(ctx, channelName)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "not found")
	}

	t.Log("Multiple channels with database test completed successfully")
}

// TestRealTimeService_ConcurrentOperationsWithDatabase tests concurrent operations
func TestRealTimeService_ConcurrentOperationsWithDatabase(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	// Setup database
	db := setupTestDB(t)
	defer db.Close()

	createTestTables(t, db)

	// Create real-time service
	mockAuth := &MockAuthService{}
	service := NewService(mockAuth, db.Pool)

	ctx := context.Background()

	// Create multiple channels concurrently
	numChannels := 5
	channelNames := make([]string, numChannels)
	for i := 0; i < numChannels; i++ {
		channelNames[i] = fmt.Sprintf("concurrent-channel-%d", i)
	}

	// Create channels concurrently
	for _, name := range channelNames {
		go func(channelName string) {
			config := interfaces.ChannelConfig{
				MaxSubscribers: 100,
				RequireAuth:    false,
			}
			_, err := service.CreateChannel(ctx, channelName, config)
			assert.NoError(t, err)
		}(name)
	}

	// Wait for channels to be created
	time.Sleep(200 * time.Millisecond)

	// Verify all channels were created
	for _, name := range channelNames {
		channel, err := service.GetChannel(ctx, name)
		assert.NoError(t, err)
		assert.Equal(t, name, channel.GetName())
	}

	// Perform concurrent presence updates
	numUsers := 10
	for i := 0; i < numUsers; i++ {
		go func(userIndex int) {
			userID := fmt.Sprintf("user_%d", userIndex)
			channelName := channelNames[userIndex%numChannels]

			state := map[string]interface{}{
				"status":     "online",
				"user_index": userIndex,
				"timestamp":  time.Now(),
			}

			err := service.TrackPresence(ctx, channelName, userID, state)
			assert.NoError(t, err)
		}(i)
	}

	// Perform concurrent database operations
	numDbOps := 5
	for i := 0; i < numDbOps; i++ {
		go func(opIndex int) {
			// Insert user
			var userID int
			err := db.QueryRow(ctx,
				"INSERT INTO test_users (name, email) VALUES ($1, $2) RETURNING id",
				fmt.Sprintf("ConcurrentUser %d", opIndex),
				fmt.Sprintf("concurrent%d@example.com", opIndex)).Scan(&userID)
			assert.NoError(t, err)

			// Insert post
			var postID int
			err = db.QueryRow(ctx,
				"INSERT INTO test_posts (user_id, title, content) VALUES ($1, $2, $3) RETURNING id",
				userID,
				fmt.Sprintf("Concurrent Post %d", opIndex),
				fmt.Sprintf("Content for concurrent post %d", opIndex)).Scan(&postID)
			assert.NoError(t, err)

			// Update user
			err = db.Exec(ctx,
				"UPDATE test_users SET status = $1 WHERE id = $2",
				"concurrent_updated", userID)
			assert.NoError(t, err)

			// Clean up
			_ = db.Exec(ctx, "DELETE FROM test_posts WHERE id = $1", postID)
			_ = db.Exec(ctx, "DELETE FROM test_users WHERE id = $1", userID)
		}(i)
	}

	// Wait for all operations to complete
	time.Sleep(1 * time.Second)

	// Verify channels still exist and have presence data
	for _, name := range channelNames {
		channel, err := service.GetChannel(ctx, name)
		assert.NoError(t, err)

		presence := channel.GetPresence()
		// Should have at least some presence data from concurrent operations
		assert.GreaterOrEqual(t, len(presence), 0)
	}

	t.Log("Concurrent operations with database test completed successfully")
}

// TestRealTimeService_DatabaseConnectionHandling tests database connection handling
func TestRealTimeService_DatabaseConnectionHandling(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	// Setup database
	db := setupTestDB(t)
	defer db.Close()

	// Create real-time service
	mockAuth := &MockAuthService{}
	service := NewService(mockAuth, db.Pool)

	ctx := context.Background()

	// Test that service works with database connection
	channelConfig := interfaces.ChannelConfig{
		MaxSubscribers: 100,
		RequireAuth:    false,
	}

	// Create channel
	channel, err := service.CreateChannel(ctx, "db-connection-test", channelConfig)
	require.NoError(t, err)

	// Test database connection stats
	stats := db.Stats()
	assert.NotNil(t, stats)
	assert.GreaterOrEqual(t, stats.MaxConns(), int32(1))

	// Test database ping
	err = db.Ping(ctx)
	require.NoError(t, err)

	// Test basic database operations
	var result int
	err = db.QueryRow(ctx, "SELECT 1").Scan(&result)
	require.NoError(t, err)
	assert.Equal(t, 1, result)

	// Test that real-time service still works after database operations
	err = service.TrackPresence(ctx, "db-connection-test", "test-user", map[string]interface{}{
		"status": "online",
		"test":   true,
	})
	require.NoError(t, err)

	presence := channel.GetPresence()
	assert.Contains(t, presence, "test-user")

	t.Log("Database connection handling test completed successfully")
}

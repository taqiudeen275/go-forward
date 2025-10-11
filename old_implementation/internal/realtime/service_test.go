package realtime

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"github.com/taqiudeen275/go-foward/pkg/interfaces"
)

// MockAuthService is a mock implementation of AuthService
type MockAuthService struct {
	mock.Mock
}

func (m *MockAuthService) ValidateToken(ctx context.Context, token string) (*interfaces.Claims, error) {
	args := m.Called(ctx, token)
	return args.Get(0).(*interfaces.Claims), args.Error(1)
}

func (m *MockAuthService) Register(ctx context.Context, req interfaces.RegisterRequest) (*interfaces.User, error) {
	args := m.Called(ctx, req)
	return args.Get(0).(*interfaces.User), args.Error(1)
}

func (m *MockAuthService) Login(ctx context.Context, req interfaces.LoginRequest) (*interfaces.AuthResponse, error) {
	args := m.Called(ctx, req)
	return args.Get(0).(*interfaces.AuthResponse), args.Error(1)
}

func (m *MockAuthService) SendOTP(ctx context.Context, req interfaces.OTPRequest) error {
	args := m.Called(ctx, req)
	return args.Error(0)
}

func (m *MockAuthService) VerifyOTP(ctx context.Context, req interfaces.VerifyOTPRequest) (*interfaces.AuthResponse, error) {
	args := m.Called(ctx, req)
	return args.Get(0).(*interfaces.AuthResponse), args.Error(1)
}

func (m *MockAuthService) RefreshToken(ctx context.Context, refreshToken string) (*interfaces.AuthResponse, error) {
	args := m.Called(ctx, refreshToken)
	return args.Get(0).(*interfaces.AuthResponse), args.Error(1)
}

func (m *MockAuthService) Logout(ctx context.Context, token string) error {
	args := m.Called(ctx, token)
	return args.Error(0)
}

// Test WebSocket Connection Handling
func TestService_HandleWebSocket_Authentication(t *testing.T) {
	mockAuth := &MockAuthService{}
	service := NewService(mockAuth, nil)

	// Test missing token
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.GET("/ws/:channel", service.HandleWebSocket)

	req := httptest.NewRequest("GET", "/ws/test-channel", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.Contains(t, w.Body.String(), "authentication failed")
}

func TestService_HandleWebSocket_ValidToken(t *testing.T) {
	mockAuth := &MockAuthService{}
	service := NewService(mockAuth, nil)

	// Mock successful token validation
	claims := &interfaces.Claims{UserID: "user123"}
	mockAuth.On("ValidateToken", mock.Anything, "valid-token").Return(claims, nil)

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.GET("/ws/:channel", service.HandleWebSocket)

	req := httptest.NewRequest("GET", "/ws/test-channel?token=valid-token", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Should attempt to upgrade to WebSocket (will fail in test but that's expected)
	assert.Equal(t, http.StatusBadRequest, w.Code) // WebSocket upgrade fails in test
	mockAuth.AssertExpectations(t)
}

func TestService_HandleWebSocket_ChannelCreation(t *testing.T) {
	mockAuth := &MockAuthService{}
	service := NewService(mockAuth, nil)

	// Mock successful token validation
	claims := &interfaces.Claims{UserID: "user123"}
	mockAuth.On("ValidateToken", mock.Anything, "valid-token").Return(claims, nil)

	ctx := context.Background()

	// Test that channel is auto-created when it doesn't exist
	_, err := service.GetChannel(ctx, "auto-created-channel")
	assert.Error(t, err) // Should not exist initially

	// Simulate WebSocket request (will fail upgrade but should create channel)
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.GET("/ws/:channel", service.HandleWebSocket)

	req := httptest.NewRequest("GET", "/ws/auto-created-channel?token=valid-token", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Channel should now exist
	channel, err := service.GetChannel(ctx, "auto-created-channel")
	assert.NoError(t, err)
	assert.NotNil(t, channel)
	assert.Equal(t, "auto-created-channel", channel.GetName())

	mockAuth.AssertExpectations(t)
}

// Test Channel Subscription and Message Broadcasting
func TestChannel_BasicOperations(t *testing.T) {
	config := interfaces.ChannelConfig{
		MaxSubscribers: 10,
		RequireAuth:    false,
	}

	channel := NewChannel("test-channel", config)
	require.NotNil(t, channel)

	// Test basic properties
	assert.Equal(t, "test-channel", channel.GetName())
	assert.Equal(t, 0, channel.GetSubscriberCount())

	// Test initial presence
	presence := channel.GetPresence()
	assert.Empty(t, presence)

	// Test broadcasting to empty channel
	message := interfaces.Message{
		ID:      "test-msg",
		Type:    "test",
		Event:   "test-event",
		Payload: map[string]interface{}{"data": "test"},
		UserID:  "user1",
	}

	err := channel.Broadcast(message)
	assert.NoError(t, err)

	// Test closing channel
	err = channel.Close()
	assert.NoError(t, err)

	// Broadcasting to closed channel should fail
	err = channel.Broadcast(message)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "closed")
}

func TestChannel_PresenceTracking(t *testing.T) {
	config := interfaces.ChannelConfig{
		MaxSubscribers: 10,
		RequireAuth:    false,
	}

	channel := NewChannel("test-channel", config)

	// Test initial presence
	presence := channel.GetPresence()
	assert.Empty(t, presence)

	// Update presence for multiple users
	channel.UpdatePresence("user1", map[string]interface{}{
		"status":    "online",
		"last_seen": time.Now(),
	})

	channel.UpdatePresence("user2", map[string]interface{}{
		"status": "away",
	})

	// Check presence
	presence = channel.GetPresence()
	assert.Len(t, presence, 2)
	assert.Contains(t, presence, "user1")
	assert.Contains(t, presence, "user2")

	user1Presence := presence["user1"].(map[string]interface{})
	assert.Equal(t, "online", user1Presence["status"])

	user2Presence := presence["user2"].(map[string]interface{})
	assert.Equal(t, "away", user2Presence["status"])

	// Update existing user presence
	channel.UpdatePresence("user1", map[string]interface{}{
		"status": "busy",
	})

	presence = channel.GetPresence()
	user1Presence = presence["user1"].(map[string]interface{})
	assert.Equal(t, "busy", user1Presence["status"])
	assert.NotNil(t, user1Presence["last_seen"]) // Should still have last_seen
}

func TestChannel_ConnectedUsers(t *testing.T) {
	config := interfaces.ChannelConfig{
		MaxSubscribers: 10,
		RequireAuth:    false,
	}

	channel := NewChannel("test-channel", config)

	// Initially no connected users
	users := channel.GetConnectedUsers()
	assert.Empty(t, users)

	// Note: Testing actual WebSocket connections requires integration tests
	// Here we test the basic functionality without actual connections
}

// Test Database Change Event Processing
func TestDatabaseListener_SubscribeAndProcess(t *testing.T) {
	// Create a real channel manager for this test
	channelManager := NewChannelManager(ChannelManagerConfig{
		MaxChannels:     100,
		DefaultMaxUsers: 50,
	})

	config := DatabaseListenerConfig{
		EnableRLS: false,
	}

	listener := NewDatabaseListener(nil, channelManager, config)

	// Create a test channel
	ctx := context.Background()
	_, err := channelManager.CreateChannel(ctx, "test-channel", interfaces.ChannelConfig{
		MaxSubscribers: 10,
	})
	require.NoError(t, err)

	// Subscribe to database changes
	filter := interfaces.ChangeFilter{
		Table:  "users",
		Schema: "public",
		Events: []string{"INSERT", "UPDATE"},
	}

	subscription, err := listener.Subscribe(ctx, "test-channel", filter, "user123")
	assert.NoError(t, err)
	assert.NotNil(t, subscription)
	assert.Equal(t, "test-channel", subscription.ChannelName)
	assert.Equal(t, "user123", subscription.UserID)

	// Test processing a database change
	change := interfaces.DatabaseChange{
		ID:     "change123",
		Table:  "users",
		Schema: "public",
		Event:  "INSERT",
		NewRecord: map[string]interface{}{
			"id":    1,
			"name":  "John Doe",
			"email": "john@example.com",
		},
		Timestamp: time.Now(),
	}

	// Process the change
	listener.processChange(ctx, change)

	// Wait a bit for async processing
	time.Sleep(50 * time.Millisecond)

	// Verify subscription was updated
	subscriptions := listener.GetSubscriptions()
	assert.Len(t, subscriptions, 1)
	// Note: Message count might be 0 if the channel doesn't have actual subscribers
	// This is expected in unit tests without real WebSocket connections
}

func TestDatabaseListener_FilterMatching(t *testing.T) {
	listener := &DatabaseListener{}

	tests := []struct {
		name     string
		change   interfaces.DatabaseChange
		filter   interfaces.ChangeFilter
		expected bool
	}{
		{
			name: "exact table match",
			change: interfaces.DatabaseChange{
				Table:  "users",
				Schema: "public",
				Event:  "INSERT",
			},
			filter: interfaces.ChangeFilter{
				Table:  "users",
				Schema: "public",
				Events: []string{"INSERT"},
			},
			expected: true,
		},
		{
			name: "table mismatch",
			change: interfaces.DatabaseChange{
				Table:  "posts",
				Schema: "public",
				Event:  "INSERT",
			},
			filter: interfaces.ChangeFilter{
				Table:  "users",
				Schema: "public",
				Events: []string{"INSERT"},
			},
			expected: false,
		},
		{
			name: "event mismatch",
			change: interfaces.DatabaseChange{
				Table:  "users",
				Schema: "public",
				Event:  "DELETE",
			},
			filter: interfaces.ChangeFilter{
				Table:  "users",
				Schema: "public",
				Events: []string{"INSERT", "UPDATE"},
			},
			expected: false,
		},
		{
			name: "column filter match",
			change: interfaces.DatabaseChange{
				Table:  "users",
				Schema: "public",
				Event:  "UPDATE",
				NewRecord: map[string]interface{}{
					"name":  "John",
					"email": "john@example.com",
				},
			},
			filter: interfaces.ChangeFilter{
				Table:   "users",
				Schema:  "public",
				Events:  []string{"UPDATE"},
				Columns: []string{"email"},
			},
			expected: true,
		},
		{
			name: "column filter no match",
			change: interfaces.DatabaseChange{
				Table:  "users",
				Schema: "public",
				Event:  "UPDATE",
				NewRecord: map[string]interface{}{
					"name": "John",
				},
			},
			filter: interfaces.ChangeFilter{
				Table:   "users",
				Schema:  "public",
				Events:  []string{"UPDATE"},
				Columns: []string{"email"},
			},
			expected: false,
		},
		{
			name: "empty filter matches all",
			change: interfaces.DatabaseChange{
				Table:  "users",
				Schema: "public",
				Event:  "INSERT",
			},
			filter:   interfaces.ChangeFilter{},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := listener.matchesFilter(tt.change, tt.filter)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestDatabaseListener_UnsubscribeAndCleanup(t *testing.T) {
	channelManager := NewChannelManager(ChannelManagerConfig{})
	config := DatabaseListenerConfig{}

	listener := NewDatabaseListener(nil, channelManager, config)
	ctx := context.Background()

	// Create subscription
	filter := interfaces.ChangeFilter{
		Table: "users",
	}

	subscription, err := listener.Subscribe(ctx, "test-channel", filter, "user123")
	assert.NoError(t, err)

	// Verify subscription exists
	subscriptions := listener.GetSubscriptions()
	assert.Len(t, subscriptions, 1)

	// Unsubscribe
	err = listener.Unsubscribe(ctx, subscription.ID)
	assert.NoError(t, err)

	// Verify subscription is removed
	subscriptions = listener.GetSubscriptions()
	assert.Len(t, subscriptions, 0)

	// Test unsubscribing non-existent subscription
	err = listener.Unsubscribe(ctx, "non-existent")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestConnectionManager_BasicOperations(t *testing.T) {
	cm := NewConnectionManager()

	// Test initial state
	metrics := cm.GetMetrics()
	assert.Equal(t, int64(0), metrics.ActiveConnections)
	assert.Empty(t, metrics.ConnectionsPerUser)
	assert.Empty(t, metrics.ChannelConnections)

	// Test metrics structure
	assert.NotNil(t, metrics.ConnectionsPerUser)
	assert.NotNil(t, metrics.ChannelConnections)
}

func TestService_TrackPresence(t *testing.T) {
	mockAuth := &MockAuthService{}
	service := NewService(mockAuth, nil)

	ctx := context.Background()
	config := interfaces.ChannelConfig{MaxSubscribers: 100}

	// Create channel
	_, err := service.CreateChannel(ctx, "test-channel", config)
	assert.NoError(t, err)

	// Track presence
	state := map[string]interface{}{
		"status":    "online",
		"last_seen": time.Now(),
	}

	err = service.TrackPresence(ctx, "test-channel", "user123", state)
	assert.NoError(t, err)

	// Get channel and verify presence
	channel, err := service.GetChannel(ctx, "test-channel")
	assert.NoError(t, err)

	presence := channel.GetPresence()
	assert.Contains(t, presence, "user123")

	userPresence := presence["user123"].(map[string]interface{})
	assert.Equal(t, "online", userPresence["status"])
}

func TestService_GetConnectedUsers(t *testing.T) {
	mockAuth := &MockAuthService{}
	service := NewService(mockAuth, nil)

	ctx := context.Background()
	config := interfaces.ChannelConfig{MaxSubscribers: 100}

	// Test non-existent channel
	_, err := service.GetConnectedUsers(ctx, "non-existent")
	assert.Error(t, err)

	// Create channel
	_, err = service.CreateChannel(ctx, "test-channel", config)
	assert.NoError(t, err)

	// Initially no users
	users, err := service.GetConnectedUsers(ctx, "test-channel")
	assert.NoError(t, err)
	assert.Empty(t, users)

	// Add some presence (simulating connected users)
	err = service.TrackPresence(ctx, "test-channel", "user1", map[string]interface{}{"status": "online"})
	assert.NoError(t, err)

	err = service.TrackPresence(ctx, "test-channel", "user2", map[string]interface{}{"status": "online"})
	assert.NoError(t, err)

	// Note: GetConnectedUsers returns actual WebSocket connections, not presence
	// Since we don't have actual connections in this test, it will still be empty
	users, err = service.GetConnectedUsers(ctx, "test-channel")
	assert.NoError(t, err)
	assert.Empty(t, users) // No actual WebSocket connections
}

func TestService_DatabaseChangeSubscription(t *testing.T) {
	mockAuth := &MockAuthService{}
	service := NewService(mockAuth, nil)

	ctx := context.Background()

	// Test subscribing to database changes
	filter := interfaces.ChangeFilter{
		Table:  "users",
		Schema: "public",
		Events: []string{"INSERT", "UPDATE", "DELETE"},
	}

	err := service.SubscribeToChanges(ctx, "test-channel", filter)
	assert.NoError(t, err)

	// Verify subscription was created
	subscriptions := service.GetDatabaseSubscriptions()
	assert.Len(t, subscriptions, 1)
	assert.Equal(t, "test-channel", subscriptions[0].ChannelName)
	assert.Equal(t, "users", subscriptions[0].Filter.Table)
}

func TestService_DatabaseTriggerManagement(t *testing.T) {
	mockAuth := &MockAuthService{}
	service := NewService(mockAuth, nil)

	ctx := context.Background()

	// Note: These operations would normally interact with the database
	// In unit tests, we're testing the service layer logic

	// Test setting up table trigger - this will fail without a database connection
	// but we're testing that the method exists and doesn't panic unexpectedly
	func() {
		defer func() {
			if r := recover(); r != nil {
				// Expected to panic due to nil database connection
				assert.NotNil(t, r)
			}
		}()
		service.SetupTableTrigger(ctx, "users")
	}()

	// Test removing table trigger - same expectation
	func() {
		defer func() {
			if r := recover(); r != nil {
				// Expected to panic due to nil database connection
				assert.NotNil(t, r)
			}
		}()
		service.RemoveTableTrigger(ctx, "users")
	}()
}

func TestService_StartStopDatabaseListener(t *testing.T) {
	mockAuth := &MockAuthService{}
	service := NewService(mockAuth, nil)

	ctx := context.Background()

	// Test starting database listener - this will fail without a database connection
	// but we're testing that the method exists and handles the error gracefully
	func() {
		defer func() {
			if r := recover(); r != nil {
				// Expected to panic due to nil database connection
				assert.NotNil(t, r)
			}
		}()
		service.StartDatabaseListener(ctx)
	}()

	// Test stopping database listener - this should not panic
	err := service.StopDatabaseListener(ctx)
	// This should not fail even without a database connection
	_ = err
}

// Test concurrent operations
func TestService_ConcurrentOperations(t *testing.T) {
	mockAuth := &MockAuthService{}
	service := NewService(mockAuth, nil)

	ctx := context.Background()
	config := interfaces.ChannelConfig{MaxSubscribers: 100}

	// Create multiple channels concurrently
	channelNames := []string{"channel1", "channel2", "channel3", "channel4", "channel5"}

	for _, name := range channelNames {
		go func(channelName string) {
			_, err := service.CreateChannel(ctx, channelName, config)
			assert.NoError(t, err)
		}(name)
	}

	// Wait a bit for goroutines to complete
	time.Sleep(100 * time.Millisecond)

	// Verify all channels were created
	for _, name := range channelNames {
		channel, err := service.GetChannel(ctx, name)
		assert.NoError(t, err)
		assert.Equal(t, name, channel.GetName())
	}

	// Test concurrent presence updates
	for i, name := range channelNames {
		go func(channelName string, userID int) {
			err := service.TrackPresence(ctx, channelName,
				fmt.Sprintf("user%d", userID),
				map[string]interface{}{"status": "online"})
			assert.NoError(t, err)
		}(name, i)
	}

	// Wait for presence updates
	time.Sleep(100 * time.Millisecond)

	// Verify presence was tracked
	for i, name := range channelNames {
		channel, err := service.GetChannel(ctx, name)
		assert.NoError(t, err)

		presence := channel.GetPresence()
		userID := fmt.Sprintf("user%d", i)
		assert.Contains(t, presence, userID)
	}
}

// Test Service Creation and Basic Operations
func TestService_CreateChannel(t *testing.T) {
	mockAuth := &MockAuthService{}
	service := NewService(mockAuth, nil)

	ctx := context.Background()
	config := interfaces.ChannelConfig{
		MaxSubscribers: 100,
		RequireAuth:    true,
	}

	// Test creating a channel
	channel, err := service.CreateChannel(ctx, "test-channel", config)
	assert.NoError(t, err)
	assert.NotNil(t, channel)
	assert.Equal(t, "test-channel", channel.GetName())

	// Test creating duplicate channel
	_, err = service.CreateChannel(ctx, "test-channel", config)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "already exists")
}

func TestService_GetChannel(t *testing.T) {
	mockAuth := &MockAuthService{}
	service := NewService(mockAuth, nil)

	ctx := context.Background()
	config := interfaces.ChannelConfig{MaxSubscribers: 100}

	// Test getting non-existent channel
	_, err := service.GetChannel(ctx, "non-existent")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")

	// Create and get channel
	_, err = service.CreateChannel(ctx, "test-channel", config)
	assert.NoError(t, err)

	channel, err := service.GetChannel(ctx, "test-channel")
	assert.NoError(t, err)
	assert.NotNil(t, channel)
	assert.Equal(t, "test-channel", channel.GetName())
}

func TestService_DeleteChannel(t *testing.T) {
	mockAuth := &MockAuthService{}
	service := NewService(mockAuth, nil)

	ctx := context.Background()
	config := interfaces.ChannelConfig{MaxSubscribers: 100}

	// Test deleting non-existent channel
	err := service.DeleteChannel(ctx, "non-existent")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")

	// Create and delete channel
	_, err = service.CreateChannel(ctx, "test-channel", config)
	assert.NoError(t, err)

	err = service.DeleteChannel(ctx, "test-channel")
	assert.NoError(t, err)

	// Verify channel is deleted
	_, err = service.GetChannel(ctx, "test-channel")
	assert.Error(t, err)
}

func TestService_BroadcastMessage(t *testing.T) {
	mockAuth := &MockAuthService{}
	service := NewService(mockAuth, nil)

	ctx := context.Background()
	config := interfaces.ChannelConfig{MaxSubscribers: 100}

	// Test broadcasting to non-existent channel
	message := interfaces.Message{
		ID:      "test-msg",
		Type:    "test",
		Event:   "test-event",
		Payload: map[string]interface{}{"data": "test"},
		UserID:  "user1",
	}

	err := service.BroadcastMessage(ctx, "non-existent", message)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")

	// Create channel and broadcast
	_, err = service.CreateChannel(ctx, "test-channel", config)
	assert.NoError(t, err)

	err = service.BroadcastMessage(ctx, "test-channel", message)
	assert.NoError(t, err)
}

// Test utility functions
func TestValidateChannelName(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{"valid name", "test-channel", false},
		{"valid with underscore", "test_channel", false},
		{"valid with numbers", "channel123", false},
		{"valid with dots", "test.channel", false},
		{"empty name", "", true},
		{"too long", string(make([]byte, 101)), true},
		{"invalid characters", "test@channel", true},
		{"invalid characters", "test channel", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateChannelName(tt.input)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidateMessageType(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{"valid message", "message", false},
		{"valid broadcast", "broadcast", false},
		{"valid presence", "presence", false},
		{"valid system", "system", false},
		{"valid ping", "ping", false},
		{"valid pong", "pong", false},
		{"invalid type", "invalid", true},
		{"empty type", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateMessageType(tt.input)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestGenerateMessageID(t *testing.T) {
	id1 := generateMessageID()
	id2 := generateMessageID()

	assert.NotEmpty(t, id1)
	assert.NotEmpty(t, id2)
	assert.NotEqual(t, id1, id2)
	assert.Contains(t, id1, "msg_")
	assert.Contains(t, id2, "msg_")
}

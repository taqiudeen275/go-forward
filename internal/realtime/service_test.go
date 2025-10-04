package realtime

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
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

func TestService_CreateChannel(t *testing.T) {
	mockAuth := &MockAuthService{}
	service := &Service{
		channels:    make(map[string]*Channel),
		authService: mockAuth,
	}

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
	service := &Service{
		channels:    make(map[string]*Channel),
		authService: mockAuth,
	}

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
	service := &Service{
		channels:    make(map[string]*Channel),
		authService: mockAuth,
	}

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
	service := &Service{
		channels:    make(map[string]*Channel),
		authService: mockAuth,
	}

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

func TestChannel_Subscribe(t *testing.T) {
	config := interfaces.ChannelConfig{
		MaxSubscribers: 2,
		RequireAuth:    false,
	}

	channel := NewChannel("test-channel", config)
	assert.NotNil(t, channel)

	// Note: We can't easily test WebSocket connections in unit tests
	// This would require integration tests with actual WebSocket connections
}

func TestChannel_Broadcast(t *testing.T) {
	config := interfaces.ChannelConfig{
		MaxSubscribers: 100,
		RequireAuth:    false,
	}

	channel := NewChannel("test-channel", config)
	assert.NotNil(t, channel)

	message := interfaces.Message{
		ID:      "test-msg",
		Type:    "test",
		Event:   "test-event",
		Payload: map[string]interface{}{"data": "test"},
		UserID:  "user1",
	}

	// Broadcasting to empty channel should not error
	err := channel.Broadcast(message)
	assert.NoError(t, err)
}

func TestChannel_Presence(t *testing.T) {
	config := interfaces.ChannelConfig{
		MaxSubscribers: 100,
		RequireAuth:    false,
	}

	channel := NewChannel("test-channel", config)
	assert.NotNil(t, channel)

	// Test initial presence
	presence := channel.GetPresence()
	assert.Empty(t, presence)

	// Update presence
	channel.UpdatePresence("user1", map[string]interface{}{
		"status":    "online",
		"last_seen": time.Now(),
	})

	presence = channel.GetPresence()
	assert.Len(t, presence, 1)
	assert.Contains(t, presence, "user1")

	userPresence := presence["user1"].(map[string]interface{})
	assert.Equal(t, "online", userPresence["status"])
}

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

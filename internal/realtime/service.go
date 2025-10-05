package realtime

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"sync"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/taqiudeen275/go-foward/pkg/interfaces"
)

// Service implements the RealtimeService interface
type Service struct {
	channels       map[string]*Channel
	channelsMux    sync.RWMutex
	upgrader       websocket.Upgrader
	authService    interfaces.AuthService
	dbListener     *DatabaseListener
	triggerManager *TriggerManager
	connManager    *ConnectionManager
}

// NewService creates a new realtime service
func NewService(authService interfaces.AuthService, pool *pgxpool.Pool) *Service {
	channelManager := NewChannelManager(ChannelManagerConfig{
		MaxChannels:     1000,
		DefaultMaxUsers: 100,
		EnableMetrics:   true,
		EnablePresence:  true,
		EnableBroadcast: true,
	})

	dbListener := NewDatabaseListener(pool, channelManager, DatabaseListenerConfig{
		EnableRLS: true,
	})

	triggerManager := NewTriggerManager(pool)
	connManager := NewConnectionManager()

	return &Service{
		channels:    make(map[string]*Channel),
		channelsMux: sync.RWMutex{},
		upgrader: websocket.Upgrader{
			CheckOrigin: func(r *http.Request) bool {
				// TODO: Implement proper origin checking based on configuration
				return true
			},
			ReadBufferSize:  1024,
			WriteBufferSize: 1024,
		},
		authService:    authService,
		dbListener:     dbListener,
		triggerManager: triggerManager,
		connManager:    connManager,
	}
}

// CreateChannel creates a new real-time channel
func (s *Service) CreateChannel(ctx context.Context, name string, config interfaces.ChannelConfig) (interfaces.Channel, error) {
	s.channelsMux.Lock()
	defer s.channelsMux.Unlock()

	if _, exists := s.channels[name]; exists {
		return nil, fmt.Errorf("channel %s already exists", name)
	}

	channel := NewChannel(name, config)
	s.channels[name] = channel

	log.Printf("Created channel: %s", name)
	return channel, nil
}

// GetChannel retrieves an existing channel
func (s *Service) GetChannel(ctx context.Context, name string) (interfaces.Channel, error) {
	s.channelsMux.RLock()
	defer s.channelsMux.RUnlock()

	channel, exists := s.channels[name]
	if !exists {
		return nil, fmt.Errorf("channel %s not found", name)
	}

	return channel, nil
}

// DeleteChannel removes a channel
func (s *Service) DeleteChannel(ctx context.Context, name string) error {
	s.channelsMux.Lock()
	defer s.channelsMux.Unlock()

	channel, exists := s.channels[name]
	if !exists {
		return fmt.Errorf("channel %s not found", name)
	}

	channel.Close()
	delete(s.channels, name)

	log.Printf("Deleted channel: %s", name)
	return nil
}

// BroadcastMessage broadcasts a message to all subscribers of a channel
func (s *Service) BroadcastMessage(ctx context.Context, channelName string, message interfaces.Message) error {
	s.channelsMux.RLock()
	channel, exists := s.channels[channelName]
	s.channelsMux.RUnlock()

	if !exists {
		return fmt.Errorf("channel %s not found", channelName)
	}

	return channel.Broadcast(message)
}

// SubscribeToChanges subscribes to database changes for a channel
func (s *Service) SubscribeToChanges(ctx context.Context, channelName string, filter interfaces.ChangeFilter) error {
	// Get user ID from context if available
	userID := "system"
	if uid, ok := ctx.Value("user_id").(string); ok {
		userID = uid
	}

	// Subscribe to database changes
	subscription, err := s.dbListener.Subscribe(ctx, channelName, filter, userID)
	if err != nil {
		return fmt.Errorf("failed to subscribe to database changes: %v", err)
	}

	log.Printf("Subscribed to database changes for channel %s (subscription: %s)", channelName, subscription.ID)
	return nil
}

// TrackPresence tracks user presence in a channel
func (s *Service) TrackPresence(ctx context.Context, channelName string, userID string, state map[string]interface{}) error {
	s.channelsMux.RLock()
	channel, exists := s.channels[channelName]
	s.channelsMux.RUnlock()

	if !exists {
		return fmt.Errorf("channel %s not found", channelName)
	}

	channel.UpdatePresence(userID, state)
	return nil
}

// GetConnectedUsers returns list of connected users in a channel
func (s *Service) GetConnectedUsers(ctx context.Context, channelName string) ([]string, error) {
	s.channelsMux.RLock()
	channel, exists := s.channels[channelName]
	s.channelsMux.RUnlock()

	if !exists {
		return nil, fmt.Errorf("channel %s not found", channelName)
	}

	return channel.GetConnectedUsers(), nil
}

// HandleWebSocket handles WebSocket upgrade and connection
func (s *Service) HandleWebSocket(c *gin.Context) {
	// Extract channel name from URL parameter
	channelName := c.Param("name")
	if channelName == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "channel name is required"})
		return
	}

	// Authenticate user if required
	userID, err := s.authenticateConnection(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "authentication failed"})
		return
	}

	// Get or create channel
	s.channelsMux.RLock()
	channel, exists := s.channels[channelName]
	s.channelsMux.RUnlock()

	if !exists {
		// Auto-create channel with default config
		defaultConfig := interfaces.ChannelConfig{
			MaxSubscribers: 1000,
			RequireAuth:    true,
			Permissions:    make(map[string]interface{}),
			Metadata:       make(map[string]interface{}),
		}

		ctx := context.Background()
		_, err := s.CreateChannel(ctx, channelName, defaultConfig)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create channel"})
			return
		}

		s.channelsMux.RLock()
		channel = s.channels[channelName]
		s.channelsMux.RUnlock()
	}

	// Upgrade connection to WebSocket
	conn, err := s.upgrader.Upgrade(c.Writer, c.Request, nil)
	if err != nil {
		log.Printf("Failed to upgrade connection: %v", err)
		return
	}

	// Subscribe to channel
	err = channel.Subscribe(conn, userID)
	if err != nil {
		log.Printf("Failed to subscribe to channel: %v", err)
		conn.Close()
		return
	}

	log.Printf("User %s connected to channel %s", userID, channelName)
}

// authenticateConnection authenticates WebSocket connection
func (s *Service) authenticateConnection(c *gin.Context) (string, error) {
	// Try to get token from query parameter or header
	token := c.Query("token")
	if token == "" {
		token = c.GetHeader("Authorization")
		if token != "" && len(token) > 7 && token[:7] == "Bearer " {
			token = token[7:]
		}
	}

	if token == "" {
		return "", fmt.Errorf("no authentication token provided")
	}

	// Validate token using auth service
	claims, err := s.authService.ValidateToken(context.Background(), token)
	if err != nil {
		return "", fmt.Errorf("invalid token: %v", err)
	}

	return claims.UserID, nil
}

// StartDatabaseListener starts the database change listener
func (s *Service) StartDatabaseListener(ctx context.Context) error {
	if err := s.dbListener.Start(ctx); err != nil {
		return fmt.Errorf("failed to start database listener: %v", err)
	}

	// Setup triggers for existing tables
	if err := s.triggerManager.SetupTableTriggers(ctx); err != nil {
		log.Printf("Warning: failed to setup database triggers: %v", err)
		// Don't fail the service start if triggers can't be set up
	}

	log.Printf("Database listener started successfully")
	return nil
}

// StopDatabaseListener stops the database change listener
func (s *Service) StopDatabaseListener(ctx context.Context) error {
	if err := s.dbListener.Stop(ctx); err != nil {
		return fmt.Errorf("failed to stop database listener: %v", err)
	}

	log.Printf("Database listener stopped successfully")
	return nil
}

// SetupTableTrigger sets up change notification trigger for a specific table
func (s *Service) SetupTableTrigger(ctx context.Context, tableName string) error {
	return s.triggerManager.SetupTriggers(ctx, []string{tableName})
}

// RemoveTableTrigger removes change notification trigger from a table
func (s *Service) RemoveTableTrigger(ctx context.Context, tableName string) error {
	return s.triggerManager.RemoveTrigger(ctx, tableName)
}

// GetDatabaseSubscriptions returns all active database change subscriptions
func (s *Service) GetDatabaseSubscriptions() []*ChangeSubscription {
	return s.dbListener.GetSubscriptions()
}

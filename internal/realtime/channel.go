package realtime

import (
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/taqiudeen275/go-foward/pkg/interfaces"
)

// Connection represents a WebSocket connection with metadata
type Connection struct {
	Conn     *websocket.Conn
	UserID   string
	LastSeen time.Time
	Metadata map[string]interface{}
	writeMux sync.Mutex
}

// Channel implements the Channel interface
type Channel struct {
	name        string
	config      interfaces.ChannelConfig
	connections map[*websocket.Conn]*Connection
	connMux     sync.RWMutex
	presence    map[string]map[string]interface{}
	presenceMux sync.RWMutex
	closed      bool
	closeChan   chan struct{}
}

// NewChannel creates a new channel
func NewChannel(name string, config interfaces.ChannelConfig) *Channel {
	channel := &Channel{
		name:        name,
		config:      config,
		connections: make(map[*websocket.Conn]*Connection),
		connMux:     sync.RWMutex{},
		presence:    make(map[string]map[string]interface{}),
		presenceMux: sync.RWMutex{},
		closed:      false,
		closeChan:   make(chan struct{}),
	}

	// Start cleanup goroutine
	go channel.cleanupRoutine()

	return channel
}

// GetName returns the channel name
func (c *Channel) GetName() string {
	return c.name
}

// Subscribe adds a WebSocket connection to the channel
func (c *Channel) Subscribe(conn *websocket.Conn, userID string) error {
	if c.closed {
		return fmt.Errorf("channel is closed")
	}

	c.connMux.Lock()
	defer c.connMux.Unlock()

	// Check max subscribers limit
	if c.config.MaxSubscribers > 0 && len(c.connections) >= c.config.MaxSubscribers {
		return fmt.Errorf("channel has reached maximum subscribers limit")
	}

	// Create connection metadata
	connection := &Connection{
		Conn:     conn,
		UserID:   userID,
		LastSeen: time.Now(),
		Metadata: make(map[string]interface{}),
		writeMux: sync.Mutex{},
	}

	c.connections[conn] = connection

	// Set up connection handlers
	go c.handleConnection(connection)

	// Update presence
	c.UpdatePresence(userID, map[string]interface{}{
		"online_at": time.Now(),
		"status":    "online",
	})

	// Send welcome message
	welcomeMsg := interfaces.Message{
		ID:        generateMessageID(),
		Type:      "system",
		Event:     "connected",
		Payload:   map[string]interface{}{"channel": c.name},
		UserID:    "system",
		Timestamp: time.Now(),
	}

	c.sendToConnection(connection, welcomeMsg)

	log.Printf("User %s subscribed to channel %s", userID, c.name)
	return nil
}

// Unsubscribe removes a WebSocket connection from the channel
func (c *Channel) Unsubscribe(conn *websocket.Conn) error {
	c.connMux.Lock()
	defer c.connMux.Unlock()

	connection, exists := c.connections[conn]
	if !exists {
		return fmt.Errorf("connection not found in channel")
	}

	// Remove from connections
	delete(c.connections, conn)

	// Update presence to offline
	c.UpdatePresence(connection.UserID, map[string]interface{}{
		"offline_at": time.Now(),
		"status":     "offline",
	})

	// Close connection
	conn.Close()

	log.Printf("User %s unsubscribed from channel %s", connection.UserID, c.name)
	return nil
}

// Broadcast sends a message to all subscribers in the channel
func (c *Channel) Broadcast(message interfaces.Message) error {
	if c.closed {
		return fmt.Errorf("channel is closed")
	}

	c.connMux.RLock()
	connections := make([]*Connection, 0, len(c.connections))
	for _, conn := range c.connections {
		connections = append(connections, conn)
	}
	c.connMux.RUnlock()

	// Send message to all connections
	for _, connection := range connections {
		go c.sendToConnection(connection, message)
	}

	log.Printf("Broadcasted message to %d subscribers in channel %s", len(connections), c.name)
	return nil
}

// GetPresence returns the current presence information
func (c *Channel) GetPresence() map[string]interface{} {
	c.presenceMux.RLock()
	defer c.presenceMux.RUnlock()

	// Create a copy to avoid race conditions
	presence := make(map[string]interface{})
	for userID, state := range c.presence {
		presence[userID] = state
	}

	return presence
}

// GetSubscriberCount returns the number of active subscribers
func (c *Channel) GetSubscriberCount() int {
	c.connMux.RLock()
	defer c.connMux.RUnlock()
	return len(c.connections)
}

// Close closes the channel and all connections
func (c *Channel) Close() error {
	if c.closed {
		return nil
	}

	c.closed = true
	close(c.closeChan)

	c.connMux.Lock()
	defer c.connMux.Unlock()

	// Close all connections
	for conn, connection := range c.connections {
		c.sendToConnection(connection, interfaces.Message{
			ID:        generateMessageID(),
			Type:      "system",
			Event:     "channel_closed",
			Payload:   map[string]interface{}{"reason": "Channel is being closed"},
			UserID:    "system",
			Timestamp: time.Now(),
		})
		conn.Close()
	}

	c.connections = make(map[*websocket.Conn]*Connection)

	log.Printf("Channel %s closed", c.name)
	return nil
}

// UpdatePresence updates user presence information
func (c *Channel) UpdatePresence(userID string, state map[string]interface{}) {
	c.presenceMux.Lock()
	defer c.presenceMux.Unlock()

	if c.presence[userID] == nil {
		c.presence[userID] = make(map[string]interface{})
	}

	// Merge state
	for key, value := range state {
		c.presence[userID][key] = value
	}

	// Broadcast presence update
	presenceMsg := interfaces.Message{
		ID:    generateMessageID(),
		Type:  "presence",
		Event: "update",
		Payload: map[string]interface{}{
			"user_id": userID,
			"state":   c.presence[userID],
		},
		UserID:    "system",
		Timestamp: time.Now(),
	}

	go c.Broadcast(presenceMsg)
}

// GetConnectedUsers returns list of connected user IDs
func (c *Channel) GetConnectedUsers() []string {
	c.connMux.RLock()
	defer c.connMux.RUnlock()

	users := make([]string, 0, len(c.connections))
	userSet := make(map[string]bool)

	for _, connection := range c.connections {
		if !userSet[connection.UserID] {
			users = append(users, connection.UserID)
			userSet[connection.UserID] = true
		}
	}

	return users
}

// handleConnection handles individual WebSocket connection
func (c *Channel) handleConnection(connection *Connection) {
	defer func() {
		c.Unsubscribe(connection.Conn)
	}()

	// Set up ping/pong handlers
	connection.Conn.SetReadDeadline(time.Now().Add(60 * time.Second))
	connection.Conn.SetPongHandler(func(string) error {
		connection.LastSeen = time.Now()
		connection.Conn.SetReadDeadline(time.Now().Add(60 * time.Second))
		return nil
	})

	// Read messages from client
	for {
		if c.closed {
			break
		}

		var message interfaces.Message
		err := connection.Conn.ReadJSON(&message)
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				log.Printf("WebSocket error: %v", err)
			}
			break
		}

		// Update last seen
		connection.LastSeen = time.Now()

		// Handle different message types
		c.handleMessage(connection, message)
	}
}

// handleMessage processes incoming messages from clients
func (c *Channel) handleMessage(connection *Connection, message interfaces.Message) {
	switch message.Type {
	case "ping":
		// Respond with pong
		pongMsg := interfaces.Message{
			ID:        generateMessageID(),
			Type:      "pong",
			Event:     "pong",
			Payload:   map[string]interface{}{},
			UserID:    "system",
			Timestamp: time.Now(),
		}
		c.sendToConnection(connection, pongMsg)

	case "presence":
		// Update presence
		if state, ok := message.Payload["state"].(map[string]interface{}); ok {
			c.UpdatePresence(connection.UserID, state)
		}

	case "broadcast":
		// Broadcast message to all subscribers
		broadcastMsg := interfaces.Message{
			ID:        generateMessageID(),
			Type:      "message",
			Event:     message.Event,
			Payload:   message.Payload,
			UserID:    connection.UserID,
			Timestamp: time.Now(),
		}
		go c.Broadcast(broadcastMsg)

	default:
		log.Printf("Unknown message type: %s", message.Type)
	}
}

// sendToConnection sends a message to a specific connection
func (c *Channel) sendToConnection(connection *Connection, message interfaces.Message) {
	connection.writeMux.Lock()
	defer connection.writeMux.Unlock()

	connection.Conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	err := connection.Conn.WriteJSON(message)
	if err != nil {
		log.Printf("Failed to send message to connection: %v", err)
		// Connection will be cleaned up by the read handler
	}
}

// cleanupRoutine periodically cleans up stale connections
func (c *Channel) cleanupRoutine() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			c.cleanupStaleConnections()
		case <-c.closeChan:
			return
		}
	}
}

// cleanupStaleConnections removes connections that haven't been seen recently
func (c *Channel) cleanupStaleConnections() {
	c.connMux.Lock()
	defer c.connMux.Unlock()

	staleThreshold := time.Now().Add(-2 * time.Minute)
	staleConnections := make([]*websocket.Conn, 0)

	for conn, connection := range c.connections {
		if connection.LastSeen.Before(staleThreshold) {
			staleConnections = append(staleConnections, conn)
		}
	}

	// Remove stale connections
	for _, conn := range staleConnections {
		connection := c.connections[conn]
		delete(c.connections, conn)

		// Update presence to offline
		c.UpdatePresence(connection.UserID, map[string]interface{}{
			"offline_at": time.Now(),
			"status":     "offline",
		})

		conn.Close()
		log.Printf("Cleaned up stale connection for user %s in channel %s", connection.UserID, c.name)
	}
}

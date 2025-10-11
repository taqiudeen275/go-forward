package realtime

import (
	"log"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

// ConnectionManager manages WebSocket connections across all channels
type ConnectionManager struct {
	connections map[string]*ConnectionPool // userID -> connection pool
	connMux     sync.RWMutex
	metrics     *ConnectionMetrics
}

// ConnectionPool holds multiple connections for a single user
type ConnectionPool struct {
	UserID      string
	Connections map[*websocket.Conn]*ConnectionInfo
	connMux     sync.RWMutex
	LastActive  time.Time
}

// ConnectionInfo holds metadata about a connection
type ConnectionInfo struct {
	Conn        *websocket.Conn
	ChannelName string
	ConnectedAt time.Time
	LastPing    time.Time
	UserAgent   string
	RemoteAddr  string
}

// ConnectionMetrics tracks connection statistics
type ConnectionMetrics struct {
	TotalConnections   int64
	ActiveConnections  int64
	ConnectionsPerUser map[string]int
	ChannelConnections map[string]int
	metricsMux         sync.RWMutex
}

// NewConnectionManager creates a new connection manager
func NewConnectionManager() *ConnectionManager {
	cm := &ConnectionManager{
		connections: make(map[string]*ConnectionPool),
		connMux:     sync.RWMutex{},
		metrics: &ConnectionMetrics{
			ConnectionsPerUser: make(map[string]int),
			ChannelConnections: make(map[string]int),
			metricsMux:         sync.RWMutex{},
		},
	}

	// Start cleanup routine
	go cm.cleanupRoutine()

	return cm
}

// AddConnection adds a new connection to the manager
func (cm *ConnectionManager) AddConnection(userID string, conn *websocket.Conn, channelName string, userAgent, remoteAddr string) {
	cm.connMux.Lock()
	defer cm.connMux.Unlock()

	// Get or create connection pool for user
	pool, exists := cm.connections[userID]
	if !exists {
		pool = &ConnectionPool{
			UserID:      userID,
			Connections: make(map[*websocket.Conn]*ConnectionInfo),
			connMux:     sync.RWMutex{},
			LastActive:  time.Now(),
		}
		cm.connections[userID] = pool
	}

	// Add connection to pool
	pool.connMux.Lock()
	pool.Connections[conn] = &ConnectionInfo{
		Conn:        conn,
		ChannelName: channelName,
		ConnectedAt: time.Now(),
		LastPing:    time.Now(),
		UserAgent:   userAgent,
		RemoteAddr:  remoteAddr,
	}
	pool.LastActive = time.Now()
	pool.connMux.Unlock()

	// Update metrics
	cm.updateMetrics(userID, channelName, 1)

	log.Printf("Added connection for user %s to channel %s (total: %d)", userID, channelName, cm.getTotalConnections())
}

// RemoveConnection removes a connection from the manager
func (cm *ConnectionManager) RemoveConnection(userID string, conn *websocket.Conn) {
	cm.connMux.Lock()
	defer cm.connMux.Unlock()

	pool, exists := cm.connections[userID]
	if !exists {
		return
	}

	pool.connMux.Lock()
	connInfo, exists := pool.Connections[conn]
	if exists {
		channelName := connInfo.ChannelName
		delete(pool.Connections, conn)

		// Update metrics
		cm.updateMetrics(userID, channelName, -1)
	}

	// Remove pool if no connections left
	if len(pool.Connections) == 0 {
		delete(cm.connections, userID)
	}
	pool.connMux.Unlock()

	log.Printf("Removed connection for user %s (total: %d)", userID, cm.getTotalConnections())
}

// GetUserConnections returns all connections for a user
func (cm *ConnectionManager) GetUserConnections(userID string) []*websocket.Conn {
	cm.connMux.RLock()
	defer cm.connMux.RUnlock()

	pool, exists := cm.connections[userID]
	if !exists {
		return nil
	}

	pool.connMux.RLock()
	defer pool.connMux.RUnlock()

	connections := make([]*websocket.Conn, 0, len(pool.Connections))
	for conn := range pool.Connections {
		connections = append(connections, conn)
	}

	return connections
}

// GetChannelConnections returns all connections for a specific channel
func (cm *ConnectionManager) GetChannelConnections(channelName string) []*websocket.Conn {
	cm.connMux.RLock()
	defer cm.connMux.RUnlock()

	var connections []*websocket.Conn

	for _, pool := range cm.connections {
		pool.connMux.RLock()
		for conn, connInfo := range pool.Connections {
			if connInfo.ChannelName == channelName {
				connections = append(connections, conn)
			}
		}
		pool.connMux.RUnlock()
	}

	return connections
}

// UpdateLastPing updates the last ping time for a connection
func (cm *ConnectionManager) UpdateLastPing(userID string, conn *websocket.Conn) {
	cm.connMux.RLock()
	pool, exists := cm.connections[userID]
	cm.connMux.RUnlock()

	if !exists {
		return
	}

	pool.connMux.Lock()
	if connInfo, exists := pool.Connections[conn]; exists {
		connInfo.LastPing = time.Now()
		pool.LastActive = time.Now()
	}
	pool.connMux.Unlock()
}

// GetMetrics returns current connection metrics
func (cm *ConnectionManager) GetMetrics() ConnectionMetrics {
	cm.metrics.metricsMux.RLock()
	defer cm.metrics.metricsMux.RUnlock()

	// Create a copy to avoid race conditions
	metrics := ConnectionMetrics{
		TotalConnections:   cm.metrics.TotalConnections,
		ActiveConnections:  cm.metrics.ActiveConnections,
		ConnectionsPerUser: make(map[string]int),
		ChannelConnections: make(map[string]int),
	}

	for k, v := range cm.metrics.ConnectionsPerUser {
		metrics.ConnectionsPerUser[k] = v
	}

	for k, v := range cm.metrics.ChannelConnections {
		metrics.ChannelConnections[k] = v
	}

	return metrics
}

// BroadcastToUser sends a message to all connections of a specific user
func (cm *ConnectionManager) BroadcastToUser(userID string, message interface{}) error {
	connections := cm.GetUserConnections(userID)

	for _, conn := range connections {
		go func(c *websocket.Conn) {
			c.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if err := c.WriteJSON(message); err != nil {
				log.Printf("Failed to send message to user %s: %v", userID, err)
			}
		}(conn)
	}

	return nil
}

// BroadcastToChannel sends a message to all connections in a specific channel
func (cm *ConnectionManager) BroadcastToChannel(channelName string, message interface{}) error {
	connections := cm.GetChannelConnections(channelName)

	for _, conn := range connections {
		go func(c *websocket.Conn) {
			c.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if err := c.WriteJSON(message); err != nil {
				log.Printf("Failed to send message to channel %s: %v", channelName, err)
			}
		}(conn)
	}

	return nil
}

// cleanupRoutine periodically cleans up stale connections
func (cm *ConnectionManager) cleanupRoutine() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		cm.cleanupStaleConnections()
	}
}

// cleanupStaleConnections removes connections that haven't pinged recently
func (cm *ConnectionManager) cleanupStaleConnections() {
	cm.connMux.Lock()
	defer cm.connMux.Unlock()

	staleThreshold := time.Now().Add(-3 * time.Minute)
	staleConnections := make(map[string][]*websocket.Conn)

	for userID, pool := range cm.connections {
		pool.connMux.Lock()
		for conn, connInfo := range pool.Connections {
			if connInfo.LastPing.Before(staleThreshold) {
				if staleConnections[userID] == nil {
					staleConnections[userID] = make([]*websocket.Conn, 0)
				}
				staleConnections[userID] = append(staleConnections[userID], conn)
			}
		}
		pool.connMux.Unlock()
	}

	// Remove stale connections
	for userID, connections := range staleConnections {
		for _, conn := range connections {
			cm.RemoveConnection(userID, conn)
			conn.Close()
		}
		log.Printf("Cleaned up %d stale connections for user %s", len(connections), userID)
	}
}

// updateMetrics updates connection metrics
func (cm *ConnectionManager) updateMetrics(userID, channelName string, delta int) {
	cm.metrics.metricsMux.Lock()
	defer cm.metrics.metricsMux.Unlock()

	if delta > 0 {
		cm.metrics.TotalConnections++
		cm.metrics.ActiveConnections++
	} else {
		cm.metrics.ActiveConnections--
	}

	cm.metrics.ConnectionsPerUser[userID] += delta
	if cm.metrics.ConnectionsPerUser[userID] <= 0 {
		delete(cm.metrics.ConnectionsPerUser, userID)
	}

	cm.metrics.ChannelConnections[channelName] += delta
	if cm.metrics.ChannelConnections[channelName] <= 0 {
		delete(cm.metrics.ChannelConnections, channelName)
	}
}

// getTotalConnections returns the total number of active connections
func (cm *ConnectionManager) getTotalConnections() int {
	cm.connMux.RLock()
	defer cm.connMux.RUnlock()

	total := 0
	for _, pool := range cm.connections {
		pool.connMux.RLock()
		total += len(pool.Connections)
		pool.connMux.RUnlock()
	}

	return total
}

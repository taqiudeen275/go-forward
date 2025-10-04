package realtime

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/taqiudeen275/go-foward/pkg/interfaces"
)

// Handlers provides HTTP handlers for realtime service
type Handlers struct {
	service *Service
}

// NewHandlers creates new realtime handlers
func NewHandlers(service *Service) *Handlers {
	return &Handlers{
		service: service,
	}
}

// CreateChannelRequest represents channel creation request
type CreateChannelRequest struct {
	Name           string                 `json:"name" binding:"required"`
	MaxSubscribers int                    `json:"max_subscribers"`
	RequireAuth    bool                   `json:"require_auth"`
	Permissions    map[string]interface{} `json:"permissions"`
	Metadata       map[string]interface{} `json:"metadata"`
}

// CreateChannel handles channel creation
func (h *Handlers) CreateChannel(c *gin.Context) {
	var req CreateChannelRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Set defaults
	if req.MaxSubscribers == 0 {
		req.MaxSubscribers = 1000
	}
	if req.Permissions == nil {
		req.Permissions = make(map[string]interface{})
	}
	if req.Metadata == nil {
		req.Metadata = make(map[string]interface{})
	}

	config := interfaces.ChannelConfig{
		MaxSubscribers: req.MaxSubscribers,
		RequireAuth:    req.RequireAuth,
		Permissions:    req.Permissions,
		Metadata:       req.Metadata,
	}

	channel, err := h.service.CreateChannel(c.Request.Context(), req.Name, config)
	if err != nil {
		c.JSON(http.StatusConflict, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusCreated, gin.H{
		"name":             channel.GetName(),
		"subscriber_count": channel.GetSubscriberCount(),
		"config":           config,
	})
}

// GetChannel handles channel retrieval
func (h *Handlers) GetChannel(c *gin.Context) {
	channelName := c.Param("name")
	if channelName == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "channel name is required"})
		return
	}

	channel, err := h.service.GetChannel(c.Request.Context(), channelName)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"name":             channel.GetName(),
		"subscriber_count": channel.GetSubscriberCount(),
		"presence":         channel.GetPresence(),
	})
}

// DeleteChannel handles channel deletion
func (h *Handlers) DeleteChannel(c *gin.Context) {
	channelName := c.Param("name")
	if channelName == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "channel name is required"})
		return
	}

	err := h.service.DeleteChannel(c.Request.Context(), channelName)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "channel deleted successfully"})
}

// ListChannels handles listing all channels
func (h *Handlers) ListChannels(c *gin.Context) {
	h.service.channelsMux.RLock()
	defer h.service.channelsMux.RUnlock()

	channels := make([]map[string]interface{}, 0, len(h.service.channels))
	for name, channel := range h.service.channels {
		channels = append(channels, map[string]interface{}{
			"name":             name,
			"subscriber_count": channel.GetSubscriberCount(),
			"presence_count":   len(channel.GetPresence()),
		})
	}

	c.JSON(http.StatusOK, gin.H{
		"channels": channels,
		"total":    len(channels),
	})
}

// BroadcastMessageRequest represents message broadcast request
type BroadcastMessageRequest struct {
	Type    string                 `json:"type" binding:"required"`
	Event   string                 `json:"event" binding:"required"`
	Payload map[string]interface{} `json:"payload"`
}

// BroadcastMessage handles message broadcasting to a channel
func (h *Handlers) BroadcastMessage(c *gin.Context) {
	channelName := c.Param("name")
	if channelName == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "channel name is required"})
		return
	}

	var req BroadcastMessageRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Get user ID from context (set by auth middleware)
	userID, exists := c.Get("user_id")
	if !exists {
		userID = "system"
	}

	message := interfaces.Message{
		ID:        generateMessageID(),
		Type:      req.Type,
		Event:     req.Event,
		Payload:   req.Payload,
		UserID:    userID.(string),
		Timestamp: generateTimestamp(),
	}

	err := h.service.BroadcastMessage(c.Request.Context(), channelName, message)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "message broadcasted successfully",
		"id":      message.ID,
	})
}

// GetChannelPresence handles getting channel presence information
func (h *Handlers) GetChannelPresence(c *gin.Context) {
	channelName := c.Param("name")
	if channelName == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "channel name is required"})
		return
	}

	channel, err := h.service.GetChannel(c.Request.Context(), channelName)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}

	presence := channel.GetPresence()
	connectedUsers, _ := h.service.GetConnectedUsers(c.Request.Context(), channelName)

	c.JSON(http.StatusOK, gin.H{
		"channel":         channelName,
		"presence":        presence,
		"connected_users": connectedUsers,
		"total_users":     len(connectedUsers),
	})
}

// UpdatePresenceRequest represents presence update request
type UpdatePresenceRequest struct {
	State map[string]interface{} `json:"state" binding:"required"`
}

// UpdatePresence handles updating user presence in a channel
func (h *Handlers) UpdatePresence(c *gin.Context) {
	channelName := c.Param("name")
	if channelName == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "channel name is required"})
		return
	}

	// Get user ID from context (set by auth middleware)
	userID, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "user authentication required"})
		return
	}

	var req UpdatePresenceRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	err := h.service.TrackPresence(c.Request.Context(), channelName, userID.(string), req.State)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "presence updated successfully"})
}

// GetChannelStats handles getting channel statistics
func (h *Handlers) GetChannelStats(c *gin.Context) {
	channelName := c.Param("name")
	if channelName == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "channel name is required"})
		return
	}

	channel, err := h.service.GetChannel(c.Request.Context(), channelName)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}

	connectedUsers, _ := h.service.GetConnectedUsers(c.Request.Context(), channelName)

	c.JSON(http.StatusOK, gin.H{
		"channel":          channelName,
		"subscriber_count": channel.GetSubscriberCount(),
		"presence_count":   len(channel.GetPresence()),
		"connected_users":  len(connectedUsers),
		"users":            connectedUsers,
	})
}

// HandleWebSocket handles WebSocket connections (delegated to service)
func (h *Handlers) HandleWebSocket(c *gin.Context) {
	h.service.HandleWebSocket(c)
}

// GetSystemStats handles getting system-wide realtime statistics
func (h *Handlers) GetSystemStats(c *gin.Context) {
	h.service.channelsMux.RLock()
	defer h.service.channelsMux.RUnlock()

	totalChannels := len(h.service.channels)
	totalSubscribers := 0
	totalPresence := 0

	channelStats := make([]map[string]interface{}, 0, totalChannels)
	for name, channel := range h.service.channels {
		subscriberCount := channel.GetSubscriberCount()
		presenceCount := len(channel.GetPresence())

		totalSubscribers += subscriberCount
		totalPresence += presenceCount

		channelStats = append(channelStats, map[string]interface{}{
			"name":             name,
			"subscriber_count": subscriberCount,
			"presence_count":   presenceCount,
		})
	}

	c.JSON(http.StatusOK, gin.H{
		"total_channels":    totalChannels,
		"total_subscribers": totalSubscribers,
		"total_presence":    totalPresence,
		"channels":          channelStats,
	})
}

// SubscribeToChangesRequest represents database change subscription request
type SubscribeToChangesRequest struct {
	Table     string   `json:"table"`
	Schema    string   `json:"schema"`
	Events    []string `json:"events"`
	Columns   []string `json:"columns"`
	Condition string   `json:"condition"`
}

// SubscribeToChanges handles database change subscription
func (h *Handlers) SubscribeToChanges(c *gin.Context) {
	channelName := c.Param("name")
	if channelName == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "channel name is required"})
		return
	}

	var req SubscribeToChangesRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Set defaults
	if req.Schema == "" {
		req.Schema = "public"
	}
	if len(req.Events) == 0 {
		req.Events = []string{"INSERT", "UPDATE", "DELETE"}
	}

	filter := interfaces.ChangeFilter{
		Table:     req.Table,
		Schema:    req.Schema,
		Events:    req.Events,
		Columns:   req.Columns,
		Condition: req.Condition,
	}

	err := h.service.SubscribeToChanges(c.Request.Context(), channelName, filter)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "subscribed to database changes",
		"channel": channelName,
		"filter":  filter,
	})
}

// GetDatabaseSubscriptions handles getting all database subscriptions
func (h *Handlers) GetDatabaseSubscriptions(c *gin.Context) {
	subscriptions := h.service.GetDatabaseSubscriptions()

	c.JSON(http.StatusOK, gin.H{
		"subscriptions": subscriptions,
		"total":         len(subscriptions),
	})
}

// SetupTableTrigger handles setting up database trigger for a table
func (h *Handlers) SetupTableTrigger(c *gin.Context) {
	tableName := c.Param("table")
	if tableName == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "table name is required"})
		return
	}

	err := h.service.SetupTableTrigger(c.Request.Context(), tableName)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "trigger setup successfully",
		"table":   tableName,
	})
}

// RemoveTableTrigger handles removing database trigger from a table
func (h *Handlers) RemoveTableTrigger(c *gin.Context) {
	tableName := c.Param("table")
	if tableName == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "table name is required"})
		return
	}

	err := h.service.RemoveTableTrigger(c.Request.Context(), tableName)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "trigger removed successfully",
		"table":   tableName,
	})
}

// RegisterRoutes registers all realtime routes
func (h *Handlers) RegisterRoutes(router *gin.RouterGroup) {
	// Channel management routes
	router.POST("/channels", h.CreateChannel)
	router.GET("/channels", h.ListChannels)
	router.GET("/channels/:name", h.GetChannel)
	router.DELETE("/channels/:name", h.DeleteChannel)

	// Message broadcasting
	router.POST("/channels/:name/broadcast", h.BroadcastMessage)

	// Presence management
	router.GET("/channels/:name/presence", h.GetChannelPresence)
	router.POST("/channels/:name/presence", h.UpdatePresence)

	// Database change streaming
	router.POST("/channels/:name/subscribe", h.SubscribeToChanges)
	router.GET("/subscriptions", h.GetDatabaseSubscriptions)

	// Database trigger management
	router.POST("/triggers/:table", h.SetupTableTrigger)
	router.DELETE("/triggers/:table", h.RemoveTableTrigger)

	// Statistics
	router.GET("/channels/:name/stats", h.GetChannelStats)
	router.GET("/stats", h.GetSystemStats)

	// WebSocket endpoint
	router.GET("/channels/:channel/ws", h.HandleWebSocket)
}

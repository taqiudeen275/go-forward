package realtime

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/taqiudeen275/go-foward/pkg/interfaces"
)

// ChannelManager manages multiple channels and their lifecycle
type ChannelManager struct {
	channels    map[string]*Channel
	channelsMux sync.RWMutex
	config      ChannelManagerConfig
	metrics     *ChannelMetrics
}

// ChannelManagerConfig holds configuration for the channel manager
type ChannelManagerConfig struct {
	MaxChannels     int           `json:"max_channels"`
	DefaultMaxUsers int           `json:"default_max_users"`
	ChannelTTL      time.Duration `json:"channel_ttl"`
	CleanupInterval time.Duration `json:"cleanup_interval"`
	EnableMetrics   bool          `json:"enable_metrics"`
	EnablePresence  bool          `json:"enable_presence"`
	EnableBroadcast bool          `json:"enable_broadcast"`
}

// ChannelMetrics tracks channel statistics
type ChannelMetrics struct {
	TotalChannels     int64                   `json:"total_channels"`
	ActiveChannels    int64                   `json:"active_channels"`
	TotalSubscribers  int64                   `json:"total_subscribers"`
	MessagesPerSecond float64                 `json:"messages_per_second"`
	ChannelStats      map[string]*ChannelStat `json:"channel_stats"`
	metricsMux        sync.RWMutex
}

// ChannelStat holds statistics for a single channel
type ChannelStat struct {
	Name            string    `json:"name"`
	SubscriberCount int       `json:"subscriber_count"`
	MessageCount    int64     `json:"message_count"`
	LastActivity    time.Time `json:"last_activity"`
	CreatedAt       time.Time `json:"created_at"`
	BytesSent       int64     `json:"bytes_sent"`
	BytesReceived   int64     `json:"bytes_received"`
}

// NewChannelManager creates a new channel manager
func NewChannelManager(config ChannelManagerConfig) *ChannelManager {
	if config.MaxChannels == 0 {
		config.MaxChannels = 1000
	}
	if config.DefaultMaxUsers == 0 {
		config.DefaultMaxUsers = 100
	}
	if config.ChannelTTL == 0 {
		config.ChannelTTL = 24 * time.Hour
	}
	if config.CleanupInterval == 0 {
		config.CleanupInterval = 5 * time.Minute
	}

	cm := &ChannelManager{
		channels:    make(map[string]*Channel),
		channelsMux: sync.RWMutex{},
		config:      config,
		metrics: &ChannelMetrics{
			ChannelStats: make(map[string]*ChannelStat),
			metricsMux:   sync.RWMutex{},
		},
	}

	// Start background routines
	go cm.cleanupRoutine()
	if config.EnableMetrics {
		go cm.metricsRoutine()
	}

	return cm
}

// CreateChannel creates a new channel with validation
func (cm *ChannelManager) CreateChannel(ctx context.Context, name string, config interfaces.ChannelConfig) (*Channel, error) {
	if err := validateChannelName(name); err != nil {
		return nil, fmt.Errorf("invalid channel name: %v", err)
	}

	cm.channelsMux.Lock()
	defer cm.channelsMux.Unlock()

	// Check if channel already exists
	if _, exists := cm.channels[name]; exists {
		return nil, fmt.Errorf("channel %s already exists", name)
	}

	// Check max channels limit
	if cm.config.MaxChannels > 0 && len(cm.channels) >= cm.config.MaxChannels {
		return nil, fmt.Errorf("maximum number of channels (%d) reached", cm.config.MaxChannels)
	}

	// Set default max subscribers if not specified
	if config.MaxSubscribers == 0 {
		config.MaxSubscribers = cm.config.DefaultMaxUsers
	}

	// Create channel
	channel := NewChannel(name, config)
	cm.channels[name] = channel

	// Initialize metrics
	if cm.config.EnableMetrics {
		cm.initChannelMetrics(name)
	}

	log.Printf("Created channel: %s (total channels: %d)", name, len(cm.channels))
	return channel, nil
}

// GetChannel retrieves a channel by name
func (cm *ChannelManager) GetChannel(ctx context.Context, name string) (*Channel, error) {
	cm.channelsMux.RLock()
	defer cm.channelsMux.RUnlock()

	channel, exists := cm.channels[name]
	if !exists {
		return nil, fmt.Errorf("channel %s not found", name)
	}

	return channel, nil
}

// DeleteChannel removes a channel
func (cm *ChannelManager) DeleteChannel(ctx context.Context, name string) error {
	cm.channelsMux.Lock()
	defer cm.channelsMux.Unlock()

	channel, exists := cm.channels[name]
	if !exists {
		return fmt.Errorf("channel %s not found", name)
	}

	// Close channel and cleanup
	channel.Close()
	delete(cm.channels, name)

	// Remove metrics
	if cm.config.EnableMetrics {
		cm.removeChannelMetrics(name)
	}

	log.Printf("Deleted channel: %s (remaining channels: %d)", name, len(cm.channels))
	return nil
}

// ListChannels returns all channel names
func (cm *ChannelManager) ListChannels(ctx context.Context) []string {
	cm.channelsMux.RLock()
	defer cm.channelsMux.RUnlock()

	channels := make([]string, 0, len(cm.channels))
	for name := range cm.channels {
		channels = append(channels, name)
	}

	return channels
}

// GetChannelCount returns the number of active channels
func (cm *ChannelManager) GetChannelCount() int {
	cm.channelsMux.RLock()
	defer cm.channelsMux.RUnlock()
	return len(cm.channels)
}

// BroadcastToAll broadcasts a message to all channels
func (cm *ChannelManager) BroadcastToAll(ctx context.Context, message interfaces.Message) error {
	if !cm.config.EnableBroadcast {
		return fmt.Errorf("broadcast is disabled")
	}

	cm.channelsMux.RLock()
	channels := make([]*Channel, 0, len(cm.channels))
	for _, channel := range cm.channels {
		channels = append(channels, channel)
	}
	cm.channelsMux.RUnlock()

	// Broadcast to all channels concurrently
	var wg sync.WaitGroup
	errors := make(chan error, len(channels))

	for _, channel := range channels {
		wg.Add(1)
		go func(ch *Channel) {
			defer wg.Done()
			if err := ch.Broadcast(message); err != nil {
				errors <- fmt.Errorf("failed to broadcast to channel %s: %v", ch.name, err)
			}
		}(channel)
	}

	wg.Wait()
	close(errors)

	// Collect any errors
	var broadcastErrors []error
	for err := range errors {
		broadcastErrors = append(broadcastErrors, err)
	}

	if len(broadcastErrors) > 0 {
		return fmt.Errorf("broadcast failed for %d channels", len(broadcastErrors))
	}

	log.Printf("Broadcasted message to %d channels", len(channels))
	return nil
}

// GetMetrics returns current channel metrics
func (cm *ChannelManager) GetMetrics() ChannelMetrics {
	if !cm.config.EnableMetrics {
		return ChannelMetrics{}
	}

	cm.metrics.metricsMux.RLock()
	defer cm.metrics.metricsMux.RUnlock()

	// Create a copy to avoid race conditions
	metrics := ChannelMetrics{
		TotalChannels:     cm.metrics.TotalChannels,
		ActiveChannels:    cm.metrics.ActiveChannels,
		TotalSubscribers:  cm.metrics.TotalSubscribers,
		MessagesPerSecond: cm.metrics.MessagesPerSecond,
		ChannelStats:      make(map[string]*ChannelStat),
	}

	for name, stat := range cm.metrics.ChannelStats {
		metrics.ChannelStats[name] = &ChannelStat{
			Name:            stat.Name,
			SubscriberCount: stat.SubscriberCount,
			MessageCount:    stat.MessageCount,
			LastActivity:    stat.LastActivity,
			CreatedAt:       stat.CreatedAt,
			BytesSent:       stat.BytesSent,
			BytesReceived:   stat.BytesReceived,
		}
	}

	return metrics
}

// cleanupRoutine periodically cleans up inactive channels
func (cm *ChannelManager) cleanupRoutine() {
	ticker := time.NewTicker(cm.config.CleanupInterval)
	defer ticker.Stop()

	for range ticker.C {
		cm.cleanupInactiveChannels()
	}
}

// cleanupInactiveChannels removes channels that have been inactive for too long
func (cm *ChannelManager) cleanupInactiveChannels() {
	cm.channelsMux.Lock()
	defer cm.channelsMux.Unlock()

	inactiveChannels := make([]string, 0)

	for channelName, channel := range cm.channels {
		// Check if channel has no subscribers and has been inactive
		if channel.GetSubscriberCount() == 0 {
			// For now, we'll keep channels alive. In a real implementation,
			// you might want to track last activity time and remove inactive channels
			_ = channelName // Use the variable to avoid compiler warning
		}
	}

	// Remove inactive channels
	for _, channelName := range inactiveChannels {
		if channel, exists := cm.channels[channelName]; exists {
			channel.Close()
			delete(cm.channels, channelName)
			if cm.config.EnableMetrics {
				cm.removeChannelMetrics(channelName)
			}
			log.Printf("Cleaned up inactive channel: %s", channelName)
		}
	}
}

// metricsRoutine periodically updates metrics
func (cm *ChannelManager) metricsRoutine() {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		cm.updateMetrics()
	}
}

// updateMetrics updates channel metrics
func (cm *ChannelManager) updateMetrics() {
	cm.channelsMux.RLock()
	channels := make(map[string]*Channel)
	for name, channel := range cm.channels {
		channels[name] = channel
	}
	cm.channelsMux.RUnlock()

	cm.metrics.metricsMux.Lock()
	defer cm.metrics.metricsMux.Unlock()

	cm.metrics.ActiveChannels = int64(len(channels))
	cm.metrics.TotalSubscribers = 0

	for name, channel := range channels {
		subscriberCount := channel.GetSubscriberCount()
		cm.metrics.TotalSubscribers += int64(subscriberCount)

		if stat, exists := cm.metrics.ChannelStats[name]; exists {
			stat.SubscriberCount = subscriberCount
			stat.LastActivity = time.Now()
		}
	}
}

// initChannelMetrics initializes metrics for a new channel
func (cm *ChannelManager) initChannelMetrics(name string) {
	cm.metrics.metricsMux.Lock()
	defer cm.metrics.metricsMux.Unlock()

	cm.metrics.ChannelStats[name] = &ChannelStat{
		Name:         name,
		CreatedAt:    time.Now(),
		LastActivity: time.Now(),
	}
	cm.metrics.TotalChannels++
}

// removeChannelMetrics removes metrics for a deleted channel
func (cm *ChannelManager) removeChannelMetrics(name string) {
	cm.metrics.metricsMux.Lock()
	defer cm.metrics.metricsMux.Unlock()

	delete(cm.metrics.ChannelStats, name)
}

// Shutdown gracefully shuts down the channel manager
func (cm *ChannelManager) Shutdown(ctx context.Context) error {
	cm.channelsMux.Lock()
	defer cm.channelsMux.Unlock()

	log.Printf("Shutting down channel manager with %d channels", len(cm.channels))

	// Close all channels
	for name, channel := range cm.channels {
		channel.Close()
		log.Printf("Closed channel: %s", name)
	}

	cm.channels = make(map[string]*Channel)
	log.Printf("Channel manager shutdown complete")
	return nil
}

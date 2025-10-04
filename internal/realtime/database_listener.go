package realtime

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/taqiudeen275/go-foward/pkg/interfaces"
)

// DatabaseListener listens for database changes and streams them to channels
type DatabaseListener struct {
	pool             *pgxpool.Pool
	conn             *pgx.Conn
	subscriptions    map[string]*ChangeSubscription
	subscriptionsMux sync.RWMutex
	channelManager   *ChannelManager
	running          bool
	stopChan         chan struct{}
	config           DatabaseListenerConfig
}

// DatabaseListenerConfig holds configuration for the database listener
type DatabaseListenerConfig struct {
	ReplicationSlot   string        `json:"replication_slot"`
	PublicationName   string        `json:"publication_name"`
	HeartbeatInterval time.Duration `json:"heartbeat_interval"`
	MaxReconnectDelay time.Duration `json:"max_reconnect_delay"`
	EnableRLS         bool          `json:"enable_rls"`
	FilterTables      []string      `json:"filter_tables"`
	ExcludeTables     []string      `json:"exclude_tables"`
}

// ChangeSubscription represents a subscription to database changes
type ChangeSubscription struct {
	ID           string                  `json:"id"`
	ChannelName  string                  `json:"channel_name"`
	Filter       interfaces.ChangeFilter `json:"filter"`
	UserID       string                  `json:"user_id"`
	CreatedAt    time.Time               `json:"created_at"`
	LastActivity time.Time               `json:"last_activity"`
	MessageCount int64                   `json:"message_count"`
}

// NewDatabaseListener creates a new database listener
func NewDatabaseListener(pool *pgxpool.Pool, channelManager *ChannelManager, config DatabaseListenerConfig) *DatabaseListener {
	if config.ReplicationSlot == "" {
		config.ReplicationSlot = "realtime_slot"
	}
	if config.PublicationName == "" {
		config.PublicationName = "realtime_publication"
	}
	if config.HeartbeatInterval == 0 {
		config.HeartbeatInterval = 30 * time.Second
	}
	if config.MaxReconnectDelay == 0 {
		config.MaxReconnectDelay = 30 * time.Second
	}

	return &DatabaseListener{
		pool:             pool,
		subscriptions:    make(map[string]*ChangeSubscription),
		subscriptionsMux: sync.RWMutex{},
		channelManager:   channelManager,
		running:          false,
		stopChan:         make(chan struct{}),
		config:           config,
	}
}

// Start starts the database listener
func (dl *DatabaseListener) Start(ctx context.Context) error {
	if dl.running {
		return fmt.Errorf("database listener is already running")
	}

	// Setup replication
	if err := dl.setupReplication(ctx); err != nil {
		return fmt.Errorf("failed to setup replication: %v", err)
	}

	// Create dedicated connection for listening
	conn, err := dl.pool.Acquire(ctx)
	if err != nil {
		return fmt.Errorf("failed to acquire connection: %v", err)
	}
	dl.conn = conn.Conn()

	dl.running = true

	// Start listening in background
	go dl.listenForChanges(ctx)

	log.Printf("Database listener started with replication slot: %s", dl.config.ReplicationSlot)
	return nil
}

// Stop stops the database listener
func (dl *DatabaseListener) Stop(ctx context.Context) error {
	if !dl.running {
		return nil
	}

	dl.running = false
	close(dl.stopChan)

	if dl.conn != nil {
		dl.conn.Close(ctx)
	}

	log.Printf("Database listener stopped")
	return nil
}

// Subscribe subscribes a channel to database changes
func (dl *DatabaseListener) Subscribe(ctx context.Context, channelName string, filter interfaces.ChangeFilter, userID string) (*ChangeSubscription, error) {
	subscriptionID := generateSubscriptionID()

	subscription := &ChangeSubscription{
		ID:           subscriptionID,
		ChannelName:  channelName,
		Filter:       filter,
		UserID:       userID,
		CreatedAt:    time.Now(),
		LastActivity: time.Now(),
		MessageCount: 0,
	}

	dl.subscriptionsMux.Lock()
	dl.subscriptions[subscriptionID] = subscription
	dl.subscriptionsMux.Unlock()

	log.Printf("Created database change subscription %s for channel %s", subscriptionID, channelName)
	return subscription, nil
}

// Unsubscribe removes a database change subscription
func (dl *DatabaseListener) Unsubscribe(ctx context.Context, subscriptionID string) error {
	dl.subscriptionsMux.Lock()
	defer dl.subscriptionsMux.Unlock()

	subscription, exists := dl.subscriptions[subscriptionID]
	if !exists {
		return fmt.Errorf("subscription %s not found", subscriptionID)
	}

	delete(dl.subscriptions, subscriptionID)
	log.Printf("Removed database change subscription %s for channel %s", subscriptionID, subscription.ChannelName)
	return nil
}

// setupReplication sets up PostgreSQL logical replication
func (dl *DatabaseListener) setupReplication(ctx context.Context) error {
	conn, err := dl.pool.Acquire(ctx)
	if err != nil {
		return fmt.Errorf("failed to acquire connection: %v", err)
	}
	defer conn.Release()

	// Create publication if it doesn't exist
	publicationSQL := fmt.Sprintf(`
		DO $$
		BEGIN
			IF NOT EXISTS (SELECT 1 FROM pg_publication WHERE pubname = '%s') THEN
				CREATE PUBLICATION %s FOR ALL TABLES;
			END IF;
		END $$;
	`, dl.config.PublicationName, dl.config.PublicationName)

	_, err = conn.Exec(ctx, publicationSQL)
	if err != nil {
		return fmt.Errorf("failed to create publication: %v", err)
	}

	// Create replication slot if it doesn't exist
	slotSQL := fmt.Sprintf(`
		SELECT pg_create_logical_replication_slot('%s', 'pgoutput')
		WHERE NOT EXISTS (
			SELECT 1 FROM pg_replication_slots WHERE slot_name = '%s'
		);
	`, dl.config.ReplicationSlot, dl.config.ReplicationSlot)

	_, err = conn.Exec(ctx, slotSQL)
	if err != nil {
		// Ignore error if slot already exists
		if !strings.Contains(err.Error(), "already exists") {
			return fmt.Errorf("failed to create replication slot: %v", err)
		}
	}

	log.Printf("Replication setup complete: publication=%s, slot=%s",
		dl.config.PublicationName, dl.config.ReplicationSlot)
	return nil
}

// listenForChanges listens for database changes using LISTEN/NOTIFY
func (dl *DatabaseListener) listenForChanges(ctx context.Context) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("Database listener panic: %v", r)
		}
	}()

	// For this implementation, we'll use LISTEN/NOTIFY as a simpler alternative
	// to logical replication for demonstration purposes

	// Listen to database notifications
	_, err := dl.conn.Exec(ctx, "LISTEN table_changes")
	if err != nil {
		log.Printf("Failed to listen for notifications: %v", err)
		return
	}

	log.Printf("Listening for database changes...")

	for dl.running {
		select {
		case <-dl.stopChan:
			return
		case <-ctx.Done():
			return
		default:
			// Wait for notification with timeout
			notification, err := dl.conn.WaitForNotification(ctx)
			if err != nil {
				if ctx.Err() != nil {
					return
				}
				log.Printf("Error waiting for notification: %v", err)
				time.Sleep(1 * time.Second)
				continue
			}

			if notification != nil {
				dl.handleNotification(ctx, notification)
			}
		}
	}
}

// handleNotification processes database change notifications
func (dl *DatabaseListener) handleNotification(ctx context.Context, notification *pgconn.Notification) {
	// Parse the notification payload
	var changeData map[string]interface{}
	if err := json.Unmarshal([]byte(notification.Payload), &changeData); err != nil {
		log.Printf("Failed to parse notification payload: %v", err)
		return
	}

	// Create database change event
	change := interfaces.DatabaseChange{
		ID:        generateMessageID(),
		Table:     getStringFromMap(changeData, "table"),
		Schema:    getStringFromMap(changeData, "schema"),
		Event:     getStringFromMap(changeData, "event"),
		OldRecord: getMapFromMap(changeData, "old_record"),
		NewRecord: getMapFromMap(changeData, "new_record"),
		Timestamp: time.Now(),
	}

	// Process change through subscriptions
	dl.processChange(ctx, change)
}

// processChange processes a database change and sends it to subscribed channels
func (dl *DatabaseListener) processChange(ctx context.Context, change interfaces.DatabaseChange) {
	dl.subscriptionsMux.RLock()
	subscriptions := make([]*ChangeSubscription, 0, len(dl.subscriptions))
	for _, sub := range dl.subscriptions {
		subscriptions = append(subscriptions, sub)
	}
	dl.subscriptionsMux.RUnlock()

	for _, subscription := range subscriptions {
		if dl.matchesFilter(change, subscription.Filter) {
			// Apply RLS if enabled
			if dl.config.EnableRLS {
				if !dl.checkRLSPermission(ctx, change, subscription.UserID) {
					continue
				}
			}

			// Create message
			message := interfaces.Message{
				ID:    generateMessageID(),
				Type:  "database_change",
				Event: fmt.Sprintf("%s.%s", change.Event, change.Table),
				Payload: map[string]interface{}{
					"change": change,
				},
				UserID:    "system",
				Timestamp: time.Now(),
			}

			// Send to channel
			if channel, err := dl.channelManager.GetChannel(ctx, subscription.ChannelName); err == nil {
				go func(ch *Channel, msg interfaces.Message, sub *ChangeSubscription) {
					if err := ch.Broadcast(msg); err != nil {
						log.Printf("Failed to broadcast change to channel %s: %v", sub.ChannelName, err)
					} else {
						// Update subscription metrics
						dl.subscriptionsMux.Lock()
						sub.LastActivity = time.Now()
						sub.MessageCount++
						dl.subscriptionsMux.Unlock()
					}
				}(channel, message, subscription)
			}
		}
	}
}

// matchesFilter checks if a database change matches a subscription filter
func (dl *DatabaseListener) matchesFilter(change interfaces.DatabaseChange, filter interfaces.ChangeFilter) bool {
	// Check table filter
	if filter.Table != "" && filter.Table != change.Table {
		return false
	}

	// Check schema filter
	if filter.Schema != "" && filter.Schema != change.Schema {
		return false
	}

	// Check event filter
	if len(filter.Events) > 0 {
		eventMatch := false
		for _, event := range filter.Events {
			if strings.EqualFold(event, change.Event) {
				eventMatch = true
				break
			}
		}
		if !eventMatch {
			return false
		}
	}

	// Check column filter (if specified, at least one column must be present)
	if len(filter.Columns) > 0 {
		columnMatch := false
		for _, column := range filter.Columns {
			if change.NewRecord != nil {
				if _, exists := change.NewRecord[column]; exists {
					columnMatch = true
					break
				}
			}
			if change.OldRecord != nil {
				if _, exists := change.OldRecord[column]; exists {
					columnMatch = true
					break
				}
			}
		}
		if !columnMatch {
			return false
		}
	}

	// TODO: Implement condition filter evaluation
	// This would require a more sophisticated expression evaluator

	return true
}

// checkRLSPermission checks if user has permission to see this change (RLS enforcement)
func (dl *DatabaseListener) checkRLSPermission(ctx context.Context, change interfaces.DatabaseChange, userID string) bool {
	// This is a simplified RLS check. In a real implementation, you would:
	// 1. Query the database with the user's context
	// 2. Check if the user can access the specific row
	// 3. Apply table-level and row-level security policies

	// For now, we'll allow all changes (RLS would be enforced at the database level)
	return true
}

// GetSubscriptions returns all active subscriptions
func (dl *DatabaseListener) GetSubscriptions() []*ChangeSubscription {
	dl.subscriptionsMux.RLock()
	defer dl.subscriptionsMux.RUnlock()

	subscriptions := make([]*ChangeSubscription, 0, len(dl.subscriptions))
	for _, sub := range dl.subscriptions {
		subscriptions = append(subscriptions, sub)
	}

	return subscriptions
}

// Helper functions

func generateSubscriptionID() string {
	return fmt.Sprintf("sub_%d", time.Now().UnixNano())
}

func getStringFromMap(m map[string]interface{}, key string) string {
	if val, ok := m[key]; ok {
		if str, ok := val.(string); ok {
			return str
		}
	}
	return ""
}

func getMapFromMap(m map[string]interface{}, key string) map[string]interface{} {
	if val, ok := m[key]; ok {
		if mapVal, ok := val.(map[string]interface{}); ok {
			return mapVal
		}
	}
	return nil
}

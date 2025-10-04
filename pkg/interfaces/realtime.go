package interfaces

import (
	"context"
	"time"

	"github.com/gorilla/websocket"
)

// RealtimeService defines the real-time service interface
type RealtimeService interface {
	CreateChannel(ctx context.Context, name string, config ChannelConfig) (*Channel, error)
	GetChannel(ctx context.Context, name string) (*Channel, error)
	DeleteChannel(ctx context.Context, name string) error
	BroadcastMessage(ctx context.Context, channelName string, message Message) error
	SubscribeToChanges(ctx context.Context, channelName string, filter ChangeFilter) error
	TrackPresence(ctx context.Context, channelName string, userID string, state map[string]interface{}) error
	GetConnectedUsers(ctx context.Context, channelName string) ([]string, error)
}

// Channel defines interface for real-time channels
type Channel interface {
	GetName() string
	Subscribe(conn *websocket.Conn, userID string) error
	Unsubscribe(conn *websocket.Conn) error
	Broadcast(message Message) error
	GetPresence() map[string]interface{}
	GetSubscriberCount() int
	Close() error
}

// ChannelConfig represents channel configuration
type ChannelConfig struct {
	MaxSubscribers int                    `json:"max_subscribers"`
	RequireAuth    bool                   `json:"require_auth"`
	Permissions    map[string]interface{} `json:"permissions"`
	Metadata       map[string]interface{} `json:"metadata"`
}

// Message represents a real-time message
type Message struct {
	ID        string                 `json:"id"`
	Type      string                 `json:"type"`
	Event     string                 `json:"event"`
	Payload   map[string]interface{} `json:"payload"`
	UserID    string                 `json:"user_id"`
	Timestamp time.Time              `json:"timestamp"`
}

// ChangeFilter represents database change filter
type ChangeFilter struct {
	Table     string   `json:"table"`
	Schema    string   `json:"schema"`
	Events    []string `json:"events"` // INSERT, UPDATE, DELETE
	Columns   []string `json:"columns"`
	Condition string   `json:"condition"`
}

// DatabaseChange represents a database change event
type DatabaseChange struct {
	ID        string                 `json:"id"`
	Table     string                 `json:"table"`
	Schema    string                 `json:"schema"`
	Event     string                 `json:"event"`
	OldRecord map[string]interface{} `json:"old_record"`
	NewRecord map[string]interface{} `json:"new_record"`
	Timestamp time.Time              `json:"timestamp"`
}

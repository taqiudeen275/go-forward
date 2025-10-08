package plugin

import (
	"context"
	"net/http"
)

// Plugin represents the base interface that all plugins must implement
type Plugin interface {
	// Name returns the unique name of the plugin
	Name() string

	// Version returns the version of the plugin
	Version() string

	// Description returns a description of what the plugin does
	Description() string

	// Initialize initializes the plugin with the given context and configuration
	Initialize(ctx context.Context, config map[string]interface{}) error

	// Start starts the plugin (called after all plugins are initialized)
	Start(ctx context.Context) error

	// Stop stops the plugin gracefully
	Stop(ctx context.Context) error

	// Health returns the health status of the plugin
	Health(ctx context.Context) error
}

// HTTPPlugin represents a plugin that can handle HTTP requests
type HTTPPlugin interface {
	Plugin

	// Routes returns the HTTP routes that this plugin handles
	Routes() []Route

	// Middleware returns HTTP middleware functions
	Middleware() []func(http.Handler) http.Handler
}

// DatabasePlugin represents a plugin that interacts with the database
type DatabasePlugin interface {
	Plugin

	// Migrations returns database migrations that this plugin requires
	Migrations() []Migration

	// Hooks returns database hooks (triggers, etc.)
	Hooks() []DatabaseHook
}

// AuthPlugin represents a plugin that provides authentication functionality
type AuthPlugin interface {
	Plugin

	// AuthMethods returns the authentication methods this plugin provides
	AuthMethods() []AuthMethod

	// ValidateCredentials validates user credentials
	ValidateCredentials(ctx context.Context, method string, credentials map[string]interface{}) (*AuthResult, error)
}

// StoragePlugin represents a plugin that provides storage functionality
type StoragePlugin interface {
	Plugin

	// StorageProviders returns the storage providers this plugin implements
	StorageProviders() []StorageProvider
}

// RealtimePlugin represents a plugin that provides real-time functionality
type RealtimePlugin interface {
	Plugin

	// Channels returns the real-time channels this plugin manages
	Channels() []RealtimeChannel

	// MessageHandlers returns message handlers for real-time events
	MessageHandlers() []MessageHandler
}

// Route represents an HTTP route
type Route struct {
	Method  string
	Path    string
	Handler http.HandlerFunc
}

// Migration represents a database migration
type Migration struct {
	ID      string
	Name    string
	UpSQL   string
	DownSQL string
}

// DatabaseHook represents a database hook
type DatabaseHook struct {
	Name     string
	Table    string
	Event    string // INSERT, UPDATE, DELETE
	Function string
}

// AuthMethod represents an authentication method
type AuthMethod struct {
	Name        string
	Type        string // password, oauth, api_key, etc.
	Description string
}

// AuthResult represents the result of authentication
type AuthResult struct {
	Success   bool
	UserID    string
	UserData  map[string]interface{}
	Token     string
	ExpiresAt int64
}

// StorageProvider represents a storage provider
type StorageProvider struct {
	Name        string
	Type        string // local, s3, gcs, etc.
	Description string
}

// RealtimeChannel represents a real-time channel
type RealtimeChannel struct {
	Name        string
	Pattern     string
	Description string
}

// MessageHandler represents a real-time message handler
type MessageHandler struct {
	Channel string
	Event   string
	Handler func(ctx context.Context, message interface{}) error
}

// PluginMetadata contains metadata about a plugin
type PluginMetadata struct {
	Name         string                 `json:"name"`
	Version      string                 `json:"version"`
	Description  string                 `json:"description"`
	Author       string                 `json:"author"`
	License      string                 `json:"license"`
	Homepage     string                 `json:"homepage"`
	Repository   string                 `json:"repository"`
	Dependencies []string               `json:"dependencies"`
	Config       map[string]interface{} `json:"config"`
	Enabled      bool                   `json:"enabled"`
}

// PluginConfig represents plugin configuration
type PluginConfig struct {
	Enabled      bool                   `yaml:"enabled"`
	Config       map[string]interface{} `yaml:"config"`
	Dependencies []string               `yaml:"dependencies"`
	Priority     int                    `yaml:"priority"`
}

// PluginRegistry manages plugin registration and lifecycle
type PluginRegistry interface {
	// Register registers a plugin
	Register(plugin Plugin) error

	// Unregister unregisters a plugin
	Unregister(name string) error

	// Get returns a plugin by name
	Get(name string) (Plugin, error)

	// List returns all registered plugins
	List() []Plugin

	// ListByType returns plugins of a specific type
	ListByType(pluginType string) []Plugin

	// Initialize initializes all registered plugins
	Initialize(ctx context.Context) error

	// Start starts all registered plugins
	Start(ctx context.Context) error

	// Stop stops all registered plugins
	Stop(ctx context.Context) error

	// Health checks the health of all plugins
	Health(ctx context.Context) map[string]error
}

// PluginLoader loads plugins from various sources
type PluginLoader interface {
	// LoadFromDirectory loads plugins from a directory
	LoadFromDirectory(dir string) ([]Plugin, error)

	// LoadFromFile loads a plugin from a file
	LoadFromFile(path string) (Plugin, error)

	// LoadFromConfig loads plugins based on configuration
	LoadFromConfig(config map[string]PluginConfig) ([]Plugin, error)
}

// PluginManager manages the entire plugin system
type PluginManager interface {
	PluginRegistry
	PluginLoader

	// SetConfig sets the plugin configuration
	SetConfig(config map[string]PluginConfig)

	// GetConfig returns the plugin configuration
	GetConfig() map[string]PluginConfig

	// Reload reloads all plugins
	Reload(ctx context.Context) error
}

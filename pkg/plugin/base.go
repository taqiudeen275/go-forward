package plugin

import (
	"context"
	"fmt"
	"net/http"
)

// BasePlugin provides a base implementation of the Plugin interface
// Other plugins can embed this to get default implementations
type BasePlugin struct {
	name        string
	version     string
	description string
	initialized bool
	started     bool
}

// NewBasePlugin creates a new base plugin
func NewBasePlugin(name, version, description string) *BasePlugin {
	return &BasePlugin{
		name:        name,
		version:     version,
		description: description,
	}
}

// Name returns the plugin name
func (p *BasePlugin) Name() string {
	return p.name
}

// Version returns the plugin version
func (p *BasePlugin) Version() string {
	return p.version
}

// Description returns the plugin description
func (p *BasePlugin) Description() string {
	return p.description
}

// Initialize initializes the plugin
func (p *BasePlugin) Initialize(ctx context.Context, config map[string]interface{}) error {
	if p.initialized {
		return fmt.Errorf("plugin %s is already initialized", p.name)
	}

	p.initialized = true
	return nil
}

// Start starts the plugin
func (p *BasePlugin) Start(ctx context.Context) error {
	if !p.initialized {
		return fmt.Errorf("plugin %s is not initialized", p.name)
	}

	if p.started {
		return fmt.Errorf("plugin %s is already started", p.name)
	}

	p.started = true
	return nil
}

// Stop stops the plugin
func (p *BasePlugin) Stop(ctx context.Context) error {
	if !p.started {
		return nil // Already stopped
	}

	p.started = false
	return nil
}

// Health returns the health status of the plugin
func (p *BasePlugin) Health(ctx context.Context) error {
	if !p.initialized {
		return fmt.Errorf("plugin %s is not initialized", p.name)
	}

	if !p.started {
		return fmt.Errorf("plugin %s is not started", p.name)
	}

	return nil
}

// IsInitialized returns whether the plugin is initialized
func (p *BasePlugin) IsInitialized() bool {
	return p.initialized
}

// IsStarted returns whether the plugin is started
func (p *BasePlugin) IsStarted() bool {
	return p.started
}

// ExampleHTTPPlugin demonstrates how to create an HTTP plugin
type ExampleHTTPPlugin struct {
	*BasePlugin
	routes []Route
}

// NewExampleHTTPPlugin creates a new example HTTP plugin
func NewExampleHTTPPlugin() *ExampleHTTPPlugin {
	return &ExampleHTTPPlugin{
		BasePlugin: NewBasePlugin("example-http", "1.0.0", "Example HTTP plugin"),
		routes:     []Route{},
	}
}

// Routes returns the HTTP routes
func (p *ExampleHTTPPlugin) Routes() []Route {
	return p.routes
}

// Middleware returns HTTP middleware
func (p *ExampleHTTPPlugin) Middleware() []func(http.Handler) http.Handler {
	return []func(http.Handler) http.Handler{}
}

// Initialize initializes the HTTP plugin
func (p *ExampleHTTPPlugin) Initialize(ctx context.Context, config map[string]interface{}) error {
	if err := p.BasePlugin.Initialize(ctx, config); err != nil {
		return err
	}

	// Initialize routes based on config
	// This is where you would set up your routes

	return nil
}

// ExampleAuthPlugin demonstrates how to create an auth plugin
type ExampleAuthPlugin struct {
	*BasePlugin
	authMethods []AuthMethod
}

// NewExampleAuthPlugin creates a new example auth plugin
func NewExampleAuthPlugin() *ExampleAuthPlugin {
	return &ExampleAuthPlugin{
		BasePlugin: NewBasePlugin("example-auth", "1.0.0", "Example auth plugin"),
		authMethods: []AuthMethod{
			{
				Name:        "custom",
				Type:        "custom",
				Description: "Custom authentication method",
			},
		},
	}
}

// AuthMethods returns the authentication methods
func (p *ExampleAuthPlugin) AuthMethods() []AuthMethod {
	return p.authMethods
}

// ValidateCredentials validates user credentials
func (p *ExampleAuthPlugin) ValidateCredentials(ctx context.Context, method string, credentials map[string]interface{}) (*AuthResult, error) {
	if method != "custom" {
		return nil, fmt.Errorf("unsupported auth method: %s", method)
	}

	// Implement your custom authentication logic here
	// This is just an example
	username, ok := credentials["username"].(string)
	if !ok {
		return nil, fmt.Errorf("username is required")
	}

	password, ok := credentials["password"].(string)
	if !ok {
		return nil, fmt.Errorf("password is required")
	}

	// Simple validation (in real implementation, you'd check against a database)
	if username == "admin" && password == "password" {
		return &AuthResult{
			Success:  true,
			UserID:   "admin",
			UserData: map[string]interface{}{"role": "admin"},
			Token:    "example-token",
		}, nil
	}

	return &AuthResult{
		Success: false,
	}, nil
}

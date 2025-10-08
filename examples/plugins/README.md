# Plugin Development Guide

This directory contains examples and documentation for developing plugins for the Go Forward framework.

## Plugin Architecture

The Go Forward framework supports a plugin architecture that allows you to extend functionality without modifying the core framework. Plugins can provide:

- HTTP endpoints and middleware
- Authentication methods
- Database operations and migrations
- Storage providers
- Real-time functionality

## Plugin Types

### 1. HTTP Plugins
HTTP plugins can register new routes and middleware:

```go
type HTTPPlugin interface {
    Plugin
    Routes() []Route
    Middleware() []func(http.Handler) http.Handler
}
```

### 2. Authentication Plugins
Auth plugins provide custom authentication methods:

```go
type AuthPlugin interface {
    Plugin
    AuthMethods() []AuthMethod
    ValidateCredentials(ctx context.Context, method string, credentials map[string]interface{}) (*AuthResult, error)
}
```

### 3. Database Plugins
Database plugins can provide migrations and hooks:

```go
type DatabasePlugin interface {
    Plugin
    Migrations() []Migration
    Hooks() []DatabaseHook
}
```

### 4. Storage Plugins
Storage plugins provide custom storage backends:

```go
type StoragePlugin interface {
    Plugin
    StorageProviders() []StorageProvider
}
```

### 5. Real-time Plugins
Real-time plugins provide custom channels and message handlers:

```go
type RealtimePlugin interface {
    Plugin
    Channels() []RealtimeChannel
    MessageHandlers() []MessageHandler
}
```

## Creating a Plugin

### Step 1: Implement the Plugin Interface

All plugins must implement the base `Plugin` interface:

```go
type Plugin interface {
    Name() string
    Version() string
    Description() string
    Initialize(ctx context.Context, config map[string]interface{}) error
    Start(ctx context.Context) error
    Stop(ctx context.Context) error
    Health(ctx context.Context) error
}
```

### Step 2: Use BasePlugin for Common Functionality

You can embed `BasePlugin` to get default implementations:

```go
package main

import (
    "context"
    "github.com/taqiudeen275/go-foward/pkg/plugin"
)

type MyPlugin struct {
    *plugin.BasePlugin
}

func NewMyPlugin() *MyPlugin {
    return &MyPlugin{
        BasePlugin: plugin.NewBasePlugin("my-plugin", "1.0.0", "My custom plugin"),
    }
}

// Implement additional interfaces as needed
```

### Step 3: Build as Shared Library

Build your plugin as a shared library:

```bash
go build -buildmode=plugin -o my-plugin.so my-plugin.go
```

### Step 4: Create Plugin Metadata (Optional)

Create a JSON metadata file with the same name:

```json
{
    "name": "my-plugin",
    "version": "1.0.0",
    "description": "My custom plugin",
    "author": "Your Name",
    "license": "MIT",
    "homepage": "https://github.com/yourname/my-plugin",
    "dependencies": [],
    "config": {
        "default_setting": "value"
    },
    "enabled": true
}
```

### Step 5: Configure the Plugin

Add your plugin to the configuration:

```yaml
plugins:
  enabled: true
  directory: "./plugins"
  plugins:
    my-plugin:
      enabled: true
      priority: 10
      config:
        custom_setting: "value"
      dependencies: []
```

## Plugin Lifecycle

1. **Loading**: Plugins are loaded from the configured directory
2. **Registration**: Loaded plugins are registered with the plugin manager
3. **Initialization**: Plugins are initialized with their configuration
4. **Starting**: Plugins are started in priority order
5. **Running**: Plugins handle requests and perform their functions
6. **Stopping**: Plugins are stopped in reverse priority order

## Configuration

Plugins can be configured through the main configuration file:

```yaml
plugins:
  enabled: true                    # Enable/disable plugin system
  directory: "./plugins"           # Directory to load plugins from
  plugins:
    plugin-name:
      enabled: true                # Enable/disable this plugin
      priority: 10                 # Loading priority (higher = first)
      config:                      # Plugin-specific configuration
        setting1: "value1"
        setting2: "value2"
      dependencies: ["other-plugin"] # Plugin dependencies
```

## Environment Variables

Plugin configuration can be overridden with environment variables:

```bash
GOFORWARD_PLUGINS_ENABLED=true
GOFORWARD_PLUGINS_DIRECTORY=./plugins
GOFORWARD_PLUGINS_PLUGIN_NAME_ENABLED=true
GOFORWARD_PLUGINS_PLUGIN_NAME_PRIORITY=10
```

## Best Practices

1. **Error Handling**: Always handle errors gracefully and return meaningful error messages
2. **Resource Cleanup**: Implement proper cleanup in the `Stop` method
3. **Health Checks**: Implement meaningful health checks
4. **Configuration Validation**: Validate configuration during initialization
5. **Logging**: Use structured logging for debugging and monitoring
6. **Dependencies**: Clearly specify plugin dependencies
7. **Versioning**: Use semantic versioning for your plugins
8. **Documentation**: Document your plugin's configuration options and usage

## Example Plugins

See the `examples/` directory for complete plugin examples:

- `http-plugin/`: Example HTTP plugin with routes and middleware
- `auth-plugin/`: Example authentication plugin
- `storage-plugin/`: Example storage plugin

## Debugging

To debug plugin loading and execution:

1. Enable debug logging in the main configuration
2. Check plugin health endpoints
3. Use the plugin management CLI commands
4. Review plugin logs and error messages

## Security Considerations

1. **Input Validation**: Always validate input from external sources
2. **Access Control**: Implement proper access control in your plugins
3. **Resource Limits**: Implement resource limits to prevent abuse
4. **Secure Defaults**: Use secure default configurations
5. **Audit Logging**: Log security-relevant events
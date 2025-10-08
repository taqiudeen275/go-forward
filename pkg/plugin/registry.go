package plugin

import (
	"context"
	"fmt"
	"sort"
	"sync"
)

// DefaultPluginRegistry implements the PluginRegistry interface
type DefaultPluginRegistry struct {
	plugins map[string]Plugin
	config  map[string]PluginConfig
	mutex   sync.RWMutex
}

// NewDefaultPluginRegistry creates a new default plugin registry
func NewDefaultPluginRegistry() *DefaultPluginRegistry {
	return &DefaultPluginRegistry{
		plugins: make(map[string]Plugin),
		config:  make(map[string]PluginConfig),
	}
}

// Register registers a plugin
func (r *DefaultPluginRegistry) Register(plugin Plugin) error {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	name := plugin.Name()
	if name == "" {
		return fmt.Errorf("plugin name cannot be empty")
	}

	if _, exists := r.plugins[name]; exists {
		return fmt.Errorf("plugin %s is already registered", name)
	}

	r.plugins[name] = plugin
	return nil
}

// Unregister unregisters a plugin
func (r *DefaultPluginRegistry) Unregister(name string) error {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	if _, exists := r.plugins[name]; !exists {
		return fmt.Errorf("plugin %s is not registered", name)
	}

	delete(r.plugins, name)
	return nil
}

// Get returns a plugin by name
func (r *DefaultPluginRegistry) Get(name string) (Plugin, error) {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	plugin, exists := r.plugins[name]
	if !exists {
		return nil, fmt.Errorf("plugin %s not found", name)
	}

	return plugin, nil
}

// List returns all registered plugins
func (r *DefaultPluginRegistry) List() []Plugin {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	plugins := make([]Plugin, 0, len(r.plugins))
	for _, plugin := range r.plugins {
		plugins = append(plugins, plugin)
	}

	// Sort plugins by name for consistent ordering
	sort.Slice(plugins, func(i, j int) bool {
		return plugins[i].Name() < plugins[j].Name()
	})

	return plugins
}

// ListByType returns plugins of a specific type
func (r *DefaultPluginRegistry) ListByType(pluginType string) []Plugin {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	var plugins []Plugin
	for _, plugin := range r.plugins {
		switch pluginType {
		case "http":
			if _, ok := plugin.(HTTPPlugin); ok {
				plugins = append(plugins, plugin)
			}
		case "database":
			if _, ok := plugin.(DatabasePlugin); ok {
				plugins = append(plugins, plugin)
			}
		case "auth":
			if _, ok := plugin.(AuthPlugin); ok {
				plugins = append(plugins, plugin)
			}
		case "storage":
			if _, ok := plugin.(StoragePlugin); ok {
				plugins = append(plugins, plugin)
			}
		case "realtime":
			if _, ok := plugin.(RealtimePlugin); ok {
				plugins = append(plugins, plugin)
			}
		default:
			plugins = append(plugins, plugin)
		}
	}

	// Sort plugins by priority (if configured) and then by name
	sort.Slice(plugins, func(i, j int) bool {
		iPriority := r.getPluginPriority(plugins[i].Name())
		jPriority := r.getPluginPriority(plugins[j].Name())

		if iPriority != jPriority {
			return iPriority > jPriority // Higher priority first
		}

		return plugins[i].Name() < plugins[j].Name()
	})

	return plugins
}

// Initialize initializes all registered plugins
func (r *DefaultPluginRegistry) Initialize(ctx context.Context) error {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	// Get plugins sorted by priority
	plugins := r.getSortedPlugins()

	for _, plugin := range plugins {
		config := r.getPluginConfig(plugin.Name())
		if !config.Enabled {
			continue
		}

		if err := plugin.Initialize(ctx, config.Config); err != nil {
			return fmt.Errorf("failed to initialize plugin %s: %w", plugin.Name(), err)
		}
	}

	return nil
}

// Start starts all registered plugins
func (r *DefaultPluginRegistry) Start(ctx context.Context) error {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	// Get plugins sorted by priority
	plugins := r.getSortedPlugins()

	for _, plugin := range plugins {
		config := r.getPluginConfig(plugin.Name())
		if !config.Enabled {
			continue
		}

		if err := plugin.Start(ctx); err != nil {
			return fmt.Errorf("failed to start plugin %s: %w", plugin.Name(), err)
		}
	}

	return nil
}

// Stop stops all registered plugins
func (r *DefaultPluginRegistry) Stop(ctx context.Context) error {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	// Get plugins sorted by priority (reverse order for stopping)
	plugins := r.getSortedPlugins()

	// Reverse the order for stopping
	for i := len(plugins) - 1; i >= 0; i-- {
		plugin := plugins[i]
		config := r.getPluginConfig(plugin.Name())
		if !config.Enabled {
			continue
		}

		if err := plugin.Stop(ctx); err != nil {
			// Log error but continue stopping other plugins
			fmt.Printf("Error stopping plugin %s: %v\n", plugin.Name(), err)
		}
	}

	return nil
}

// Health checks the health of all plugins
func (r *DefaultPluginRegistry) Health(ctx context.Context) map[string]error {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	health := make(map[string]error)

	for name, plugin := range r.plugins {
		config := r.getPluginConfig(name)
		if !config.Enabled {
			continue
		}

		health[name] = plugin.Health(ctx)
	}

	return health
}

// SetConfig sets the plugin configuration
func (r *DefaultPluginRegistry) SetConfig(config map[string]PluginConfig) {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	r.config = config
}

// GetConfig returns the plugin configuration
func (r *DefaultPluginRegistry) GetConfig() map[string]PluginConfig {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	// Return a copy to prevent external modification
	config := make(map[string]PluginConfig)
	for k, v := range r.config {
		config[k] = v
	}

	return config
}

// getSortedPlugins returns plugins sorted by priority
func (r *DefaultPluginRegistry) getSortedPlugins() []Plugin {
	plugins := make([]Plugin, 0, len(r.plugins))
	for _, plugin := range r.plugins {
		plugins = append(plugins, plugin)
	}

	sort.Slice(plugins, func(i, j int) bool {
		iPriority := r.getPluginPriority(plugins[i].Name())
		jPriority := r.getPluginPriority(plugins[j].Name())

		if iPriority != jPriority {
			return iPriority > jPriority // Higher priority first
		}

		return plugins[i].Name() < plugins[j].Name()
	})

	return plugins
}

// getPluginConfig returns the configuration for a plugin
func (r *DefaultPluginRegistry) getPluginConfig(name string) PluginConfig {
	if config, exists := r.config[name]; exists {
		return config
	}

	// Return default config
	return PluginConfig{
		Enabled:      true,
		Config:       make(map[string]interface{}),
		Dependencies: []string{},
		Priority:     0,
	}
}

// getPluginPriority returns the priority for a plugin
func (r *DefaultPluginRegistry) getPluginPriority(name string) int {
	config := r.getPluginConfig(name)
	return config.Priority
}

package config

import (
	"fmt"

	"github.com/taqiudeen275/go-foward/pkg/plugin"
)

// PluginsConfig represents the plugins configuration section
type PluginsConfig struct {
	Enabled   bool                           `yaml:"enabled"`
	Directory string                         `yaml:"directory"`
	Plugins   map[string]plugin.PluginConfig `yaml:"plugins"`
}

// GetDefaultPluginsConfig returns the default plugins configuration
func GetDefaultPluginsConfig() PluginsConfig {
	return PluginsConfig{
		Enabled:   true,
		Directory: "./plugins",
		Plugins: map[string]plugin.PluginConfig{
			"example-http": {
				Enabled:      false,
				Config:       map[string]interface{}{},
				Dependencies: []string{},
				Priority:     0,
			},
			"example-auth": {
				Enabled:      false,
				Config:       map[string]interface{}{},
				Dependencies: []string{},
				Priority:     0,
			},
		},
	}
}

// ValidatePluginsConfig validates the plugins configuration
func ValidatePluginsConfig(config *PluginsConfig) error {
	if config.Enabled {
		if config.Directory == "" {
			return fmt.Errorf("plugin directory cannot be empty when plugins are enabled")
		}

		// Validate individual plugin configurations
		for name, pluginConfig := range config.Plugins {
			if err := validatePluginConfig(name, &pluginConfig); err != nil {
				return fmt.Errorf("invalid configuration for plugin %s: %w", name, err)
			}
		}
	}

	return nil
}

// validatePluginConfig validates a single plugin configuration
func validatePluginConfig(name string, config *plugin.PluginConfig) error {
	if name == "" {
		return fmt.Errorf("plugin name cannot be empty")
	}

	if config.Priority < 0 {
		return fmt.Errorf("plugin priority cannot be negative")
	}

	// Validate dependencies
	for _, dep := range config.Dependencies {
		if dep == "" {
			return fmt.Errorf("dependency name cannot be empty")
		}
		if dep == name {
			return fmt.Errorf("plugin cannot depend on itself")
		}
	}

	return nil
}

// InitializePluginManager initializes the plugin manager with configuration
func InitializePluginManager(config *Config) (*plugin.DefaultPluginManager, error) {
	manager := plugin.NewDefaultPluginManager()

	// Set plugin configuration
	if config.Plugins.Enabled {
		manager.SetConfig(config.Plugins.Plugins)

		// Load plugins from directory
		plugins, err := manager.LoadFromDirectory(config.Plugins.Directory)
		if err != nil {
			return nil, fmt.Errorf("failed to load plugins from directory: %w", err)
		}

		// Register loaded plugins
		for _, p := range plugins {
			if err := manager.Register(p); err != nil {
				return nil, fmt.Errorf("failed to register plugin %s: %w", p.Name(), err)
			}
		}
	}

	return manager, nil
}

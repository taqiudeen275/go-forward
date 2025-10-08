package plugin

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"plugin"
	"strings"
)

// DefaultPluginLoader implements the PluginLoader interface
type DefaultPluginLoader struct {
	registry PluginRegistry
}

// NewDefaultPluginLoader creates a new default plugin loader
func NewDefaultPluginLoader(registry PluginRegistry) *DefaultPluginLoader {
	return &DefaultPluginLoader{
		registry: registry,
	}
}

// LoadFromDirectory loads plugins from a directory
func (l *DefaultPluginLoader) LoadFromDirectory(dir string) ([]Plugin, error) {
	var plugins []Plugin

	// Check if directory exists
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		return plugins, nil // Return empty slice if directory doesn't exist
	}

	// Walk through the directory
	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Skip directories
		if info.IsDir() {
			return nil
		}

		// Load plugin based on file extension
		switch filepath.Ext(path) {
		case ".so": // Shared object (Go plugin)
			plugin, err := l.loadGoPlugin(path)
			if err != nil {
				return fmt.Errorf("failed to load Go plugin %s: %w", path, err)
			}
			if plugin != nil {
				plugins = append(plugins, plugin)
			}
		case ".json": // Plugin metadata
			// Skip metadata files, they're loaded with the actual plugin
			return nil
		default:
			// Skip unknown file types
			return nil
		}

		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to walk plugin directory %s: %w", dir, err)
	}

	return plugins, nil
}

// LoadFromFile loads a plugin from a file
func (l *DefaultPluginLoader) LoadFromFile(path string) (Plugin, error) {
	switch filepath.Ext(path) {
	case ".so":
		return l.loadGoPlugin(path)
	default:
		return nil, fmt.Errorf("unsupported plugin file type: %s", filepath.Ext(path))
	}
}

// LoadFromConfig loads plugins based on configuration
func (l *DefaultPluginLoader) LoadFromConfig(config map[string]PluginConfig) ([]Plugin, error) {
	var plugins []Plugin

	for name, pluginConfig := range config {
		if !pluginConfig.Enabled {
			continue
		}

		// Try to find the plugin file
		pluginPath := l.findPluginFile(name)
		if pluginPath == "" {
			return nil, fmt.Errorf("plugin file not found for %s", name)
		}

		plugin, err := l.LoadFromFile(pluginPath)
		if err != nil {
			return nil, fmt.Errorf("failed to load plugin %s: %w", name, err)
		}

		plugins = append(plugins, plugin)
	}

	return plugins, nil
}

// loadGoPlugin loads a Go plugin from a shared object file
func (l *DefaultPluginLoader) loadGoPlugin(path string) (Plugin, error) {
	// Load the plugin
	p, err := plugin.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open plugin: %w", err)
	}

	// Look for the plugin symbol
	symbol, err := p.Lookup("Plugin")
	if err != nil {
		return nil, fmt.Errorf("plugin symbol not found: %w", err)
	}

	// Assert that the symbol implements the Plugin interface
	pluginInstance, ok := symbol.(Plugin)
	if !ok {
		return nil, fmt.Errorf("plugin does not implement Plugin interface")
	}

	// Load metadata if available
	metadata, err := l.loadPluginMetadata(path)
	if err != nil {
		// Metadata is optional, so we just log the error
		fmt.Printf("Warning: failed to load metadata for plugin %s: %v\n", path, err)
	}

	// Wrap the plugin with metadata if available
	if metadata != nil {
		return &PluginWrapper{
			Plugin:   pluginInstance,
			Metadata: *metadata,
		}, nil
	}

	return pluginInstance, nil
}

// loadPluginMetadata loads plugin metadata from a JSON file
func (l *DefaultPluginLoader) loadPluginMetadata(pluginPath string) (*PluginMetadata, error) {
	// Look for metadata file with same name but .json extension
	metadataPath := strings.TrimSuffix(pluginPath, filepath.Ext(pluginPath)) + ".json"

	if _, err := os.Stat(metadataPath); os.IsNotExist(err) {
		return nil, nil // Metadata file doesn't exist
	}

	data, err := os.ReadFile(metadataPath)
	if err != nil {
		return nil, err
	}

	var metadata PluginMetadata
	if err := json.Unmarshal(data, &metadata); err != nil {
		return nil, err
	}

	return &metadata, nil
}

// findPluginFile finds the plugin file for a given plugin name
func (l *DefaultPluginLoader) findPluginFile(name string) string {
	// Common plugin directories
	pluginDirs := []string{
		"./plugins",
		"./plugins/bin",
		"/usr/local/lib/goforward/plugins",
		"/opt/goforward/plugins",
	}

	// Common plugin file patterns
	patterns := []string{
		name + ".so",
		"lib" + name + ".so",
		name + "_plugin.so",
	}

	for _, dir := range pluginDirs {
		for _, pattern := range patterns {
			path := filepath.Join(dir, pattern)
			if _, err := os.Stat(path); err == nil {
				return path
			}
		}
	}

	return ""
}

// PluginWrapper wraps a plugin with its metadata
type PluginWrapper struct {
	Plugin
	Metadata PluginMetadata
}

// GetMetadata returns the plugin metadata
func (w *PluginWrapper) GetMetadata() PluginMetadata {
	return w.Metadata
}

// DefaultPluginManager implements the PluginManager interface
type DefaultPluginManager struct {
	*DefaultPluginRegistry
	*DefaultPluginLoader
	config map[string]PluginConfig
}

// NewDefaultPluginManager creates a new default plugin manager
func NewDefaultPluginManager() *DefaultPluginManager {
	registry := NewDefaultPluginRegistry()
	loader := NewDefaultPluginLoader(registry)

	return &DefaultPluginManager{
		DefaultPluginRegistry: registry,
		DefaultPluginLoader:   loader,
		config:                make(map[string]PluginConfig),
	}
}

// SetConfig sets the plugin configuration
func (m *DefaultPluginManager) SetConfig(config map[string]PluginConfig) {
	m.config = config
	m.DefaultPluginRegistry.SetConfig(config)
}

// GetConfig returns the plugin configuration
func (m *DefaultPluginManager) GetConfig() map[string]PluginConfig {
	return m.config
}

// Reload reloads all plugins
func (m *DefaultPluginManager) Reload(ctx context.Context) error {
	// Stop all plugins
	if err := m.Stop(ctx); err != nil {
		return fmt.Errorf("failed to stop plugins during reload: %w", err)
	}

	// Clear registry
	m.plugins = make(map[string]Plugin)

	// Load plugins from config
	plugins, err := m.LoadFromConfig(m.config)
	if err != nil {
		return fmt.Errorf("failed to load plugins during reload: %w", err)
	}

	// Register plugins
	for _, plugin := range plugins {
		if err := m.Register(plugin); err != nil {
			return fmt.Errorf("failed to register plugin %s during reload: %w", plugin.Name(), err)
		}
	}

	// Initialize and start plugins
	if err := m.Initialize(ctx); err != nil {
		return fmt.Errorf("failed to initialize plugins during reload: %w", err)
	}

	if err := m.Start(ctx); err != nil {
		return fmt.Errorf("failed to start plugins during reload: %w", err)
	}

	return nil
}

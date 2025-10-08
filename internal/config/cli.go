package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"


	"gopkg.in/yaml.v3"
)

// ConfigCLI provides command-line interface for configuration management
type ConfigCLI struct {
	loader *ConfigLoader
}

// NewConfigCLI creates a new configuration CLI
func NewConfigCLI() *ConfigCLI {
	return &ConfigCLI{
		loader: NewConfigLoader("GOFORWARD"),
	}
}

// GenerateExample generates an example configuration file
func (cli *ConfigCLI) GenerateExample(outputPath string) error {
	config := getDefaultConfig()

	// Create directory if it doesn't exist
	if err := os.MkdirAll(filepath.Dir(outputPath), 0755); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}

	return cli.loader.SaveConfig(config, outputPath)
}

// ValidateFile validates a configuration file
func (cli *ConfigCLI) ValidateFile(configPath string) error {
	return cli.loader.ValidateConfigFile(configPath)
}

// ShowConfig displays the current configuration
func (cli *ConfigCLI) ShowConfig() (*Config, error) {
	return cli.loader.LoadConfig()
}

// ShowDefaults displays the default configuration values
func (cli *ConfigCLI) ShowDefaults() *DefaultConfig {
	return GetDefaults()
}

// ConvertToEnv converts configuration to environment variables format
func (cli *ConfigCLI) ConvertToEnv(config *Config, prefix string) ([]string, error) {
	var envVars []string

	// Convert config to map for easier processing
	data, err := yaml.Marshal(config)
	if err != nil {
		return nil, err
	}

	var configMap map[string]interface{}
	if err := yaml.Unmarshal(data, &configMap); err != nil {
		return nil, err
	}

	// Recursively convert to environment variables
	cli.convertMapToEnv(configMap, prefix, "", &envVars)

	return envVars, nil
}

// convertMapToEnv recursively converts a map to environment variables
func (cli *ConfigCLI) convertMapToEnv(m map[string]interface{}, prefix, path string, envVars *[]string) {
	for key, value := range m {
		currentPath := key
		if path != "" {
			currentPath = path + "_" + key
		}

		envName := strings.ToUpper(prefix + "_" + currentPath)

		switch v := value.(type) {
		case map[string]interface{}:
			cli.convertMapToEnv(v, prefix, currentPath, envVars)
		case []interface{}:
			// Convert slice to comma-separated string
			var strValues []string
			for _, item := range v {
				strValues = append(strValues, fmt.Sprintf("%v", item))
			}
			*envVars = append(*envVars, fmt.Sprintf("%s=%s", envName, strings.Join(strValues, ",")))
		default:
			*envVars = append(*envVars, fmt.Sprintf("%s=%v", envName, v))
		}
	}
}

// MergeConfigs merges multiple configuration files
func (cli *ConfigCLI) MergeConfigs(configPaths []string, outputPath string) error {
	var mergedConfig *Config

	for i, path := range configPaths {
		config, err := cli.loadConfigFromFile(path)
		if err != nil {
			return fmt.Errorf("failed to load config from %s: %w", path, err)
		}

		if i == 0 {
			mergedConfig = config
		} else {
			if err := cli.mergeConfig(mergedConfig, config); err != nil {
				return fmt.Errorf("failed to merge config from %s: %w", path, err)
			}
		}
	}

	return cli.loader.SaveConfig(mergedConfig, outputPath)
}

// loadConfigFromFile loads configuration from a specific file
func (cli *ConfigCLI) loadConfigFromFile(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var config Config
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, err
	}

	return &config, nil
}

// mergeConfig merges source config into target config
func (cli *ConfigCLI) mergeConfig(target, source *Config) error {
	// Convert both configs to maps for easier merging
	targetData, err := yaml.Marshal(target)
	if err != nil {
		return err
	}

	sourceData, err := yaml.Marshal(source)
	if err != nil {
		return err
	}

	var targetMap, sourceMap map[string]interface{}

	if err := yaml.Unmarshal(targetData, &targetMap); err != nil {
		return err
	}

	if err := yaml.Unmarshal(sourceData, &sourceMap); err != nil {
		return err
	}

	// Merge maps
	cli.mergeMaps(targetMap, sourceMap)

	// Convert back to config struct
	mergedData, err := yaml.Marshal(targetMap)
	if err != nil {
		return err
	}

	return yaml.Unmarshal(mergedData, target)
}

// mergeMaps recursively merges source map into target map
func (cli *ConfigCLI) mergeMaps(target, source map[string]interface{}) {
	for key, sourceValue := range source {
		if targetValue, exists := target[key]; exists {
			// If both values are maps, merge recursively
			if targetMap, targetIsMap := targetValue.(map[string]interface{}); targetIsMap {
				if sourceMap, sourceIsMap := sourceValue.(map[string]interface{}); sourceIsMap {
					cli.mergeMaps(targetMap, sourceMap)
					continue
				}
			}
		}
		// Otherwise, overwrite with source value
		target[key] = sourceValue
	}
}

// GetConfigInfo returns information about the current configuration
func (cli *ConfigCLI) GetConfigInfo() (*ConfigInfo, error) {
	configPath := cli.loader.findConfigFile()

	info := &ConfigInfo{
		ConfigPath:   configPath,
		ConfigExists: configPath != "",
		EnvPrefix:    cli.loader.envPrefix,
		SearchPaths:  cli.loader.configPaths,
	}

	if configPath != "" {
		if stat, err := os.Stat(configPath); err == nil {
			info.LastModified = stat.ModTime()
			info.FileSize = stat.Size()
		}
	}

	// Check for environment variables
	info.EnvVarsFound = cli.getEnvVarsFound()

	return info, nil
}

// getEnvVarsFound returns a list of environment variables that would be used
func (cli *ConfigCLI) getEnvVarsFound() []string {
	var found []string

	// Common environment variables to check
	envVars := []string{
		"CONFIG_PATH",
		"GOFORWARD_SERVER_HOST",
		"GOFORWARD_SERVER_PORT",
		"GOFORWARD_DATABASE_HOST",
		"GOFORWARD_DATABASE_PORT",
		"GOFORWARD_DATABASE_NAME",
		"GOFORWARD_DATABASE_USER",
		"GOFORWARD_DATABASE_PASSWORD",
		"GOFORWARD_AUTH_JWT_SECRET",
		"GOFORWARD_STORAGE_PROVIDER",
		"GOFORWARD_REALTIME_ENABLED",
	}

	for _, envVar := range envVars {
		if value := os.Getenv(envVar); value != "" {
			found = append(found, fmt.Sprintf("%s=%s", envVar, value))
		}
	}

	return found
}

// ConfigInfo contains information about the configuration
type ConfigInfo struct {
	ConfigPath   string    `json:"config_path"`
	ConfigExists bool      `json:"config_exists"`
	EnvPrefix    string    `json:"env_prefix"`
	SearchPaths  []string  `json:"search_paths"`
	LastModified time.Time `json:"last_modified,omitempty"`
	FileSize     int64     `json:"file_size,omitempty"`
	EnvVarsFound []string  `json:"env_vars_found"`
}

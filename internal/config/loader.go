package config

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// ConfigLoader handles loading configuration from multiple sources
type ConfigLoader struct {
	configPaths []string
	envPrefix   string
}

// NewConfigLoader creates a new configuration loader
func NewConfigLoader(envPrefix string) *ConfigLoader {
	return &ConfigLoader{
		configPaths: []string{
			"./config.yaml",
			"./config.yml",
			"./configs/config.yaml",
			"./configs/config.yml",
			"/etc/goforward/config.yaml",
			"/etc/goforward/config.yml",
		},
		envPrefix: envPrefix,
	}
}

// AddConfigPath adds a configuration file path to search
func (cl *ConfigLoader) AddConfigPath(path string) {
	cl.configPaths = append(cl.configPaths, path)
}

// LoadConfig loads configuration from files and environment variables
func (cl *ConfigLoader) LoadConfig() (*Config, error) {
	config := getDefaultConfig()

	// Load from config file
	configPath := cl.findConfigFile()
	if configPath != "" {
		if err := cl.loadFromFile(config, configPath); err != nil {
			return nil, fmt.Errorf("failed to load config from file %s: %w", configPath, err)
		}
	}

	// Override with environment variables
	if err := cl.loadFromEnv(config); err != nil {
		return nil, fmt.Errorf("failed to load config from environment: %w", err)
	}

	// Validate configuration
	if err := validate(config); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	return config, nil
}

// findConfigFile finds the first existing configuration file
func (cl *ConfigLoader) findConfigFile() string {
	// Check environment variable first
	if path := os.Getenv("CONFIG_PATH"); path != "" {
		if _, err := os.Stat(path); err == nil {
			return path
		}
	}

	// Check predefined paths
	for _, path := range cl.configPaths {
		if _, err := os.Stat(path); err == nil {
			return path
		}
	}

	return ""
}

// loadFromFile loads configuration from YAML file
func (cl *ConfigLoader) loadFromFile(config *Config, path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	return yaml.Unmarshal(data, config)
}

// loadFromEnv loads configuration from environment variables using reflection
func (cl *ConfigLoader) loadFromEnv(config *Config) error {
	return cl.loadStructFromEnv(reflect.ValueOf(config).Elem(), "")
}

// loadStructFromEnv recursively loads struct fields from environment variables
func (cl *ConfigLoader) loadStructFromEnv(v reflect.Value, prefix string) error {
	t := v.Type()

	for i := 0; i < v.NumField(); i++ {
		field := v.Field(i)
		fieldType := t.Field(i)

		// Skip unexported fields
		if !field.CanSet() {
			continue
		}

		// Get the yaml tag or use field name
		yamlTag := fieldType.Tag.Get("yaml")
		if yamlTag == "" || yamlTag == "-" {
			continue
		}

		// Parse yaml tag to get field name
		yamlName := strings.Split(yamlTag, ",")[0]
		if yamlName == "" {
			yamlName = strings.ToLower(fieldType.Name)
		}

		// Build environment variable name
		envName := cl.buildEnvName(prefix, yamlName)

		// Handle different field types
		switch field.Kind() {
		case reflect.Struct:
			// Recursively handle nested structs
			if err := cl.loadStructFromEnv(field, envName); err != nil {
				return err
			}
		case reflect.Slice:
			// Handle slices (for arrays in config)
			if envValue := os.Getenv(envName); envValue != "" {
				if err := cl.setSliceValue(field, envValue); err != nil {
					return fmt.Errorf("failed to set slice value for %s: %w", envName, err)
				}
			}
		default:
			// Handle primitive types
			if envValue := os.Getenv(envName); envValue != "" {
				if err := cl.setFieldValue(field, envValue); err != nil {
					return fmt.Errorf("failed to set field value for %s: %w", envName, err)
				}
			}
		}
	}

	return nil
}

// buildEnvName builds environment variable name from prefix and field name
func (cl *ConfigLoader) buildEnvName(prefix, fieldName string) string {
	envName := strings.ToUpper(fieldName)
	if prefix != "" {
		envName = strings.ToUpper(prefix) + "_" + envName
	}
	if cl.envPrefix != "" {
		envName = cl.envPrefix + "_" + envName
	}
	return envName
}

// setFieldValue sets a field value from string
func (cl *ConfigLoader) setFieldValue(field reflect.Value, value string) error {
	switch field.Kind() {
	case reflect.String:
		field.SetString(value)
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		if field.Type() == reflect.TypeOf(time.Duration(0)) {
			// Handle time.Duration
			duration, err := time.ParseDuration(value)
			if err != nil {
				return err
			}
			field.SetInt(int64(duration))
		} else {
			// Handle regular integers
			intValue, err := strconv.ParseInt(value, 10, 64)
			if err != nil {
				return err
			}
			field.SetInt(intValue)
		}
	case reflect.Bool:
		boolValue, err := strconv.ParseBool(value)
		if err != nil {
			return err
		}
		field.SetBool(boolValue)
	case reflect.Float32, reflect.Float64:
		floatValue, err := strconv.ParseFloat(value, 64)
		if err != nil {
			return err
		}
		field.SetFloat(floatValue)
	default:
		return fmt.Errorf("unsupported field type: %s", field.Kind())
	}
	return nil
}

// setSliceValue sets a slice value from comma-separated string
func (cl *ConfigLoader) setSliceValue(field reflect.Value, value string) error {
	if field.Type().Elem().Kind() != reflect.String {
		return fmt.Errorf("only string slices are supported")
	}

	values := strings.Split(value, ",")
	slice := reflect.MakeSlice(field.Type(), len(values), len(values))

	for i, v := range values {
		slice.Index(i).SetString(strings.TrimSpace(v))
	}

	field.Set(slice)
	return nil
}

// SaveConfig saves configuration to a file
func (cl *ConfigLoader) SaveConfig(config *Config, path string) error {
	data, err := yaml.Marshal(config)
	if err != nil {
		return err
	}

	// Create directory if it doesn't exist
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}

	return os.WriteFile(path, data, 0644)
}

// ValidateConfigFile validates a configuration file without loading it
func (cl *ConfigLoader) ValidateConfigFile(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	var config Config
	if err := yaml.Unmarshal(data, &config); err != nil {
		return fmt.Errorf("invalid YAML format: %w", err)
	}

	return validate(&config)
}

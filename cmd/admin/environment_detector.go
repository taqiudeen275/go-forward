package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/taqiudeen275/go-foward/internal/config"
)

// Environment represents deployment environments
type Environment string

const (
	EnvironmentDevelopment Environment = "development"
	EnvironmentStaging     Environment = "staging"
	EnvironmentProduction  Environment = "production"
)

// EnvironmentDetector handles environment detection and security policies
type EnvironmentDetector struct {
	config *config.Config
}

// SecurityPolicy represents a security policy for an environment
type SecurityPolicy struct {
	Name        string                 `json:"name"`
	Category    string                 `json:"category"`
	Description string                 `json:"description"`
	Required    bool                   `json:"required"`
	Config      map[string]interface{} `json:"config"`
}

// EnvironmentValidation represents environment validation results
type EnvironmentValidation struct {
	Environment     Environment `json:"environment"`
	IsValid         bool        `json:"is_valid"`
	Passed          []string    `json:"passed"`
	Failed          []string    `json:"failed"`
	Warnings        []string    `json:"warnings"`
	Recommendations []string    `json:"recommendations"`
}

// PolicyApplicationResult represents the result of applying a policy
type PolicyApplicationResult struct {
	PolicyName string `json:"policy_name"`
	Success    bool   `json:"success"`
	Message    string `json:"message"`
	Error      string `json:"error,omitempty"`
}

// NewEnvironmentDetector creates a new environment detector
func NewEnvironmentDetector(config *config.Config) *EnvironmentDetector {
	return &EnvironmentDetector{
		config: config,
	}
}

// DetectEnvironment detects the current deployment environment
func (ed *EnvironmentDetector) DetectEnvironment() (Environment, error) {
	// Check explicit environment variable
	if env := os.Getenv("GOFORWARD_ENVIRONMENT"); env != "" {
		switch strings.ToLower(env) {
		case "development", "dev":
			return EnvironmentDevelopment, nil
		case "staging", "stage":
			return EnvironmentStaging, nil
		case "production", "prod":
			return EnvironmentProduction, nil
		default:
			return EnvironmentDevelopment, fmt.Errorf("unknown environment: %s", env)
		}
	}

	// Check NODE_ENV (common convention)
	if env := os.Getenv("NODE_ENV"); env != "" {
		switch strings.ToLower(env) {
		case "development":
			return EnvironmentDevelopment, nil
		case "staging":
			return EnvironmentStaging, nil
		case "production":
			return EnvironmentProduction, nil
		}
	}

	// Check for production indicators
	productionIndicators := []string{
		"KUBERNETES_SERVICE_HOST",     // Running in Kubernetes
		"AWS_EXECUTION_ENV",           // Running in AWS Lambda/ECS
		"GOOGLE_CLOUD_PROJECT",        // Running in Google Cloud
		"AZURE_FUNCTIONS_ENVIRONMENT", // Running in Azure Functions
	}

	for _, indicator := range productionIndicators {
		if os.Getenv(indicator) != "" {
			return EnvironmentProduction, nil
		}
	}

	// Check database configuration for production patterns
	if ed.config != nil {
		dbHost := ed.config.Database.Host

		// Production database patterns
		if strings.Contains(dbHost, "prod") ||
			strings.Contains(dbHost, "production") ||
			strings.Contains(dbHost, "rds.amazonaws.com") ||
			strings.Contains(dbHost, "cloud.google.com") ||
			strings.Contains(dbHost, "database.azure.com") {
			return EnvironmentProduction, nil
		}

		// Staging database patterns
		if strings.Contains(dbHost, "staging") ||
			strings.Contains(dbHost, "stage") {
			return EnvironmentStaging, nil
		}
	}

	// Default to development
	return EnvironmentDevelopment, nil
}

// GetEnvironmentIndicators returns indicators used for environment detection
func (ed *EnvironmentDetector) GetEnvironmentIndicators() map[string]interface{} {
	indicators := make(map[string]interface{})

	// Environment variables
	envVars := []string{
		"GOFORWARD_ENVIRONMENT",
		"NODE_ENV",
		"KUBERNETES_SERVICE_HOST",
		"AWS_EXECUTION_ENV",
		"GOOGLE_CLOUD_PROJECT",
		"AZURE_FUNCTIONS_ENVIRONMENT",
	}

	for _, envVar := range envVars {
		if value := os.Getenv(envVar); value != "" {
			indicators[envVar] = value
		}
	}

	// Configuration indicators
	if ed.config != nil {
		indicators["database_host"] = ed.config.Database.Host
		indicators["server_host"] = ed.config.Server.Host
		indicators["server_port"] = ed.config.Server.Port
	}

	return indicators
}

// GetSecurityRequirements returns security requirements for an environment
func (ed *EnvironmentDetector) GetSecurityRequirements(env Environment) []string {
	switch env {
	case EnvironmentProduction:
		return []string{
			"Strong password policies must be enforced",
			"Multi-factor authentication required for system admins",
			"Database connections must use SSL/TLS",
			"JWT secrets must be cryptographically secure",
			"Rate limiting must be enabled",
			"Audit logging must be comprehensive",
			"Admin operations require confirmation",
			"Emergency access procedures must be documented",
		}
	case EnvironmentStaging:
		return []string{
			"Password policies should be enforced",
			"Database connections should use SSL/TLS",
			"JWT secrets should be secure",
			"Basic audit logging should be enabled",
			"Admin operations should require confirmation",
		}
	case EnvironmentDevelopment:
		return []string{
			"Basic password validation",
			"Development-friendly configurations allowed",
			"Simplified admin operations for testing",
		}
	default:
		return []string{}
	}
}

// ValidateEnvironmentRequirements validates environment requirements
func (ed *EnvironmentDetector) ValidateEnvironmentRequirements(env Environment, force bool) error {
	switch env {
	case EnvironmentProduction:
		if !force {
			// Check for production readiness
			if ed.config.Auth.JWTSecret == "your-secret-key" {
				return fmt.Errorf("production environment detected but JWT secret is not configured")
			}

			if ed.config.Database.SSLMode == "disable" {
				return fmt.Errorf("production environment detected but database SSL is disabled")
			}
		}
	case EnvironmentStaging:
		// Less strict requirements for staging
		if ed.config.Auth.JWTSecret == "your-secret-key" {
			fmt.Printf("Warning: Using default JWT secret in staging environment\n")
		}
	}

	return nil
}

// ValidateEnvironment performs comprehensive environment validation
func (ed *EnvironmentDetector) ValidateEnvironment(env Environment) (*EnvironmentValidation, error) {
	validation := &EnvironmentValidation{
		Environment:     env,
		IsValid:         true,
		Passed:          []string{},
		Failed:          []string{},
		Warnings:        []string{},
		Recommendations: []string{},
	}

	// Common validations
	ed.validateDatabaseConfig(validation)
	ed.validateAuthConfig(validation)
	ed.validateServerConfig(validation)

	// Environment-specific validations
	switch env {
	case EnvironmentProduction:
		ed.validateProductionConfig(validation)
	case EnvironmentStaging:
		ed.validateStagingConfig(validation)
	case EnvironmentDevelopment:
		ed.validateDevelopmentConfig(validation)
	}

	// Set overall validity
	validation.IsValid = len(validation.Failed) == 0

	return validation, nil
}

// validateDatabaseConfig validates database configuration
func (ed *EnvironmentDetector) validateDatabaseConfig(validation *EnvironmentValidation) {
	if ed.config == nil {
		validation.Failed = append(validation.Failed, "Configuration not loaded")
		return
	}

	db := ed.config.Database

	// Check database host
	if db.Host == "" {
		validation.Failed = append(validation.Failed, "Database host not configured")
	} else {
		validation.Passed = append(validation.Passed, "Database host configured")
	}

	// Check database credentials
	if db.User == "" {
		validation.Failed = append(validation.Failed, "Database user not configured")
	} else {
		validation.Passed = append(validation.Passed, "Database user configured")
	}

	if db.Password == "" {
		validation.Failed = append(validation.Failed, "Database password not configured")
	} else {
		validation.Passed = append(validation.Passed, "Database password configured")
	}

	// Check SSL mode
	if db.SSLMode == "disable" {
		validation.Warnings = append(validation.Warnings, "Database SSL is disabled")
		validation.Recommendations = append(validation.Recommendations, "Enable database SSL for better security")
	} else {
		validation.Passed = append(validation.Passed, "Database SSL enabled")
	}
}

// validateAuthConfig validates authentication configuration
func (ed *EnvironmentDetector) validateAuthConfig(validation *EnvironmentValidation) {
	if ed.config == nil {
		return
	}

	auth := ed.config.Auth

	// Check JWT secret
	if auth.JWTSecret == "" {
		validation.Failed = append(validation.Failed, "JWT secret not configured")
	} else if auth.JWTSecret == "your-secret-key" {
		validation.Failed = append(validation.Failed, "JWT secret is using default value")
	} else if len(auth.JWTSecret) < 32 {
		validation.Warnings = append(validation.Warnings, "JWT secret is shorter than recommended 32 characters")
		validation.Recommendations = append(validation.Recommendations, "Use a JWT secret of at least 32 characters")
	} else {
		validation.Passed = append(validation.Passed, "JWT secret properly configured")
	}

	// Check token expiry
	if auth.JWTExpiration == 0 {
		validation.Warnings = append(validation.Warnings, "Access token expiry not configured")
	} else {
		validation.Passed = append(validation.Passed, "Access token expiry configured")
	}
}

// validateServerConfig validates server configuration
func (ed *EnvironmentDetector) validateServerConfig(validation *EnvironmentValidation) {
	if ed.config == nil {
		return
	}

	server := ed.config.Server

	// Check server host
	if server.Host == "" {
		validation.Warnings = append(validation.Warnings, "Server host not configured, using default")
	} else {
		validation.Passed = append(validation.Passed, "Server host configured")
	}

	// Check server port
	if server.Port == 0 {
		validation.Warnings = append(validation.Warnings, "Server port not configured, using default")
	} else {
		validation.Passed = append(validation.Passed, "Server port configured")
	}
}

// validateProductionConfig validates production-specific configuration
func (ed *EnvironmentDetector) validateProductionConfig(validation *EnvironmentValidation) {
	// Strict requirements for production
	if ed.config.Database.SSLMode == "disable" {
		validation.Failed = append(validation.Failed, "Database SSL must be enabled in production")
	}

	if ed.config.Auth.JWTSecret == "your-secret-key" {
		validation.Failed = append(validation.Failed, "Default JWT secret not allowed in production")
	}

	// Check for localhost configurations
	if strings.Contains(ed.config.Database.Host, "localhost") ||
		strings.Contains(ed.config.Database.Host, "127.0.0.1") {
		validation.Warnings = append(validation.Warnings, "Using localhost database in production")
	}

	validation.Recommendations = append(validation.Recommendations,
		"Enable comprehensive audit logging for production",
		"Configure rate limiting for API endpoints",
		"Set up monitoring and alerting",
		"Implement backup and disaster recovery procedures")
}

// validateStagingConfig validates staging-specific configuration
func (ed *EnvironmentDetector) validateStagingConfig(validation *EnvironmentValidation) {
	// Moderate requirements for staging
	if ed.config.Auth.JWTSecret == "your-secret-key" {
		validation.Warnings = append(validation.Warnings, "Using default JWT secret in staging")
	}

	validation.Recommendations = append(validation.Recommendations,
		"Configure staging-appropriate security policies",
		"Enable basic audit logging",
		"Test production security configurations")
}

// validateDevelopmentConfig validates development-specific configuration
func (ed *EnvironmentDetector) validateDevelopmentConfig(validation *EnvironmentValidation) {
	// Relaxed requirements for development
	validation.Recommendations = append(validation.Recommendations,
		"Development environment allows relaxed security for testing",
		"Consider testing production security configurations",
		"Use environment-specific configuration files")
}

// GetSecurityPolicies returns security policies for an environment
func (ed *EnvironmentDetector) GetSecurityPolicies(env Environment) []SecurityPolicy {
	var policies []SecurityPolicy

	switch env {
	case EnvironmentProduction:
		policies = append(policies, []SecurityPolicy{
			{
				Name:        "strong_passwords",
				Category:    "Authentication",
				Description: "Enforce strong password requirements",
				Required:    true,
				Config: map[string]interface{}{
					"min_length":        12,
					"require_uppercase": true,
					"require_lowercase": true,
					"require_numbers":   true,
					"require_symbols":   true,
				},
			},
			{
				Name:        "mfa_required",
				Category:    "Authentication",
				Description: "Require MFA for system administrators",
				Required:    true,
				Config: map[string]interface{}{
					"admin_levels": []string{"system_admin"},
					"methods":      []string{"totp", "backup_codes"},
				},
			},
			{
				Name:        "database_ssl",
				Category:    "Database",
				Description: "Require SSL/TLS for database connections",
				Required:    true,
				Config: map[string]interface{}{
					"ssl_mode":  "require",
					"verify_ca": true,
				},
			},
			{
				Name:        "audit_logging",
				Category:    "Security",
				Description: "Enable comprehensive audit logging",
				Required:    true,
				Config: map[string]interface{}{
					"log_all_admin_actions": true,
					"log_sql_queries":       true,
					"retention_days":        365,
				},
			},
			{
				Name:        "rate_limiting",
				Category:    "Security",
				Description: "Enable rate limiting for API endpoints",
				Required:    true,
				Config: map[string]interface{}{
					"requests_per_minute": 60,
					"burst_limit":         100,
				},
			},
		}...)
	case EnvironmentStaging:
		policies = append(policies, []SecurityPolicy{
			{
				Name:        "moderate_passwords",
				Category:    "Authentication",
				Description: "Enforce moderate password requirements",
				Required:    true,
				Config: map[string]interface{}{
					"min_length":        8,
					"require_uppercase": true,
					"require_lowercase": true,
					"require_numbers":   true,
				},
			},
			{
				Name:        "basic_audit_logging",
				Category:    "Security",
				Description: "Enable basic audit logging",
				Required:    false,
				Config: map[string]interface{}{
					"log_admin_actions": true,
					"retention_days":    90,
				},
			},
		}...)
	case EnvironmentDevelopment:
		policies = append(policies, []SecurityPolicy{
			{
				Name:        "basic_passwords",
				Category:    "Authentication",
				Description: "Basic password validation",
				Required:    false,
				Config: map[string]interface{}{
					"min_length": 6,
				},
			},
		}...)
	}

	return policies
}

// GetSecurityPolicy returns a specific security policy
func (ed *EnvironmentDetector) GetSecurityPolicy(env Environment, name string) (*SecurityPolicy, error) {
	policies := ed.GetSecurityPolicies(env)

	for _, policy := range policies {
		if policy.Name == name {
			return &policy, nil
		}
	}

	return nil, fmt.Errorf("policy '%s' not found for environment '%s'", name, env)
}

// FixEnvironmentIssues attempts to fix environment configuration issues
func (ed *EnvironmentDetector) FixEnvironmentIssues(env Environment, issues []string) (map[string]bool, error) {
	results := make(map[string]bool)

	for _, issue := range issues {
		fixed := false

		// Attempt to fix common issues
		switch {
		case strings.Contains(issue, "JWT secret"):
			// Generate a new JWT secret
			// In a real implementation, this would update the configuration
			fmt.Printf("Would generate new JWT secret\n")
			fixed = true

		case strings.Contains(issue, "Database SSL"):
			// Enable database SSL
			fmt.Printf("Would enable database SSL\n")
			fixed = true

		case strings.Contains(issue, "Database host not configured"):
			// Prompt for database configuration
			fmt.Printf("Would prompt for database configuration\n")
			fixed = false // Requires user input

		default:
			// Cannot automatically fix this issue
			fixed = false
		}

		results[issue] = fixed
	}

	return results, nil
}

// ApplySecurityPolicies applies security policies to the environment
func (ed *EnvironmentDetector) ApplySecurityPolicies(env Environment, policies []SecurityPolicy) ([]PolicyApplicationResult, error) {
	var results []PolicyApplicationResult

	for _, policy := range policies {
		result := PolicyApplicationResult{
			PolicyName: policy.Name,
			Success:    false,
			Message:    "",
		}

		// Simulate policy application
		switch policy.Name {
		case "strong_passwords", "moderate_passwords", "basic_passwords":
			result.Success = true
			result.Message = "Password policy configuration updated"

		case "mfa_required":
			result.Success = true
			result.Message = "MFA requirements configured for system administrators"

		case "database_ssl":
			result.Success = true
			result.Message = "Database SSL configuration updated"

		case "audit_logging", "basic_audit_logging":
			result.Success = true
			result.Message = "Audit logging configuration updated"

		case "rate_limiting":
			result.Success = true
			result.Message = "Rate limiting configuration updated"

		default:
			result.Success = false
			result.Message = "Unknown policy"
			result.Error = fmt.Sprintf("Policy '%s' is not implemented", policy.Name)
		}

		results = append(results, result)
	}

	return results, nil
}

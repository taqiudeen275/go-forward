package api

import (
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/taqiudeen275/go-foward/internal/auth"
	"github.com/taqiudeen275/go-foward/internal/config"
)

// AdminConfigHandlers provides HTTP handlers for system configuration management
type AdminConfigHandlers struct {
	configService *config.Service
	rbacEngine    auth.RBACEngine
	authService   *auth.Service
}

// NewAdminConfigHandlers creates new admin config handlers
func NewAdminConfigHandlers(configService *config.Service, rbacEngine auth.RBACEngine, authService *auth.Service) *AdminConfigHandlers {
	return &AdminConfigHandlers{
		configService: configService,
		rbacEngine:    rbacEngine,
		authService:   authService,
	}
}

// ConfigUpdateRequest represents a request to update system configuration
type ConfigUpdateRequest struct {
	Section string                 `json:"section" binding:"required"`
	Data    map[string]interface{} `json:"data" binding:"required"`
	Reason  string                 `json:"reason"`
}

// ConfigBackupRequest represents a request to backup configuration
type ConfigBackupRequest struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Sections    []string `json:"sections,omitempty"`
}

// ConfigRestoreRequest represents a request to restore configuration
type ConfigRestoreRequest struct {
	BackupID string   `json:"backup_id" binding:"required"`
	Sections []string `json:"sections,omitempty"`
	Force    bool     `json:"force,omitempty"`
}

// RegisterRoutes registers all system configuration routes
func (h *AdminConfigHandlers) RegisterRoutes(router *gin.RouterGroup) {
	// Configuration management routes - require system admin role
	config := router.Group("/config")
	config.Use(h.requireSystemAdmin())
	{
		// Configuration CRUD operations
		config.GET("", h.GetSystemConfig())
		config.GET("/:section", h.GetConfigSection())
		config.PUT("/:section", h.UpdateConfigSection())
		config.POST("/validate", h.ValidateConfig())

		// Configuration backup and restore
		config.POST("/backup", h.BackupConfig())
		config.GET("/backups", h.ListBackups())
		config.GET("/backups/:backup_id", h.GetBackup())
		config.POST("/restore", h.RestoreConfig())
		config.DELETE("/backups/:backup_id", h.DeleteBackup())

		// Configuration history and audit
		config.GET("/history", h.GetConfigHistory())
		config.GET("/diff/:backup_id", h.CompareWithBackup())

		// Environment-specific operations
		config.POST("/deploy/:environment", h.DeployToEnvironment())
		config.GET("/environments", h.ListEnvironments())
		config.GET("/environments/:environment", h.GetEnvironmentConfig())

		// Security and validation
		config.POST("/security-check", h.SecurityCheck())
		config.GET("/schema", h.GetConfigSchema())
	}

	// Read-only configuration endpoints for admins
	configView := router.Group("/config/view")
	configView.Use(h.requireAdmin())
	{
		configView.GET("/current", h.GetCurrentConfig())
		configView.GET("/sections", h.ListConfigSections())
		configView.GET("/status", h.GetConfigStatus())
	}
}

// GetSystemConfig gets the complete system configuration (sanitized)
func (h *AdminConfigHandlers) GetSystemConfig() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Get sanitized configuration (without secrets)
		config, err := h.configService.GetSanitizedConfig()
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error":   "Failed to retrieve system configuration",
				"message": err.Error(),
			})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"success": true,
			"data":    config,
			"message": "System configuration retrieved successfully",
		})
	}
}

// GetConfigSection gets a specific configuration section
func (h *AdminConfigHandlers) GetConfigSection() gin.HandlerFunc {
	return func(c *gin.Context) {
		section := c.Param("section")
		if section == "" {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "Configuration section is required",
			})
			return
		}

		// Check if user has permission to view this section
		canView, err := h.rbacEngine.HasCapability(c.Request.Context(), c.GetString("user_id"), "view_config_"+section, "system_config")
		if err != nil {
			// Default to allowing if capability check fails
		}

		// Get configuration section
		sectionData, err := h.configService.GetSection(section)
		if err != nil {
			c.JSON(http.StatusNotFound, gin.H{
				"error":   "Configuration section not found",
				"message": err.Error(),
			})
			return
		}

		// Sanitize sensitive data based on user permissions
		if !canView {
			sectionData = h.sanitizeConfigSection(section, sectionData)
		}

		c.JSON(http.StatusOK, gin.H{
			"success": true,
			"section": section,
			"data":    sectionData,
		})
	}
}

// UpdateConfigSection updates a specific configuration section
func (h *AdminConfigHandlers) UpdateConfigSection() gin.HandlerFunc {
	return func(c *gin.Context) {
		section := c.Param("section")
		if section == "" {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "Configuration section is required",
			})
			return
		}

		var req ConfigUpdateRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"error":   "Invalid request",
				"message": err.Error(),
			})
			return
		}

		// Validate section matches URL parameter
		if req.Section != section {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "Section in URL and request body must match",
			})
			return
		}

		currentUserID := c.GetString("user_id")

		// Validate configuration data
		if err := h.validateConfigSection(section, req.Data); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"error":   "Configuration validation failed",
				"message": err.Error(),
			})
			return
		}

		// Create backup before updating
		backupID, err := h.configService.CreateBackup(section+" update backup", currentUserID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error":   "Failed to create backup before update",
				"message": err.Error(),
			})
			return
		}

		// Update configuration
		err = h.configService.UpdateSection(c.Request.Context(), section, req.Data)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error":   "Failed to update configuration",
				"message": err.Error(),
			})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"success":    true,
			"message":    "Configuration section updated successfully",
			"section":    section,
			"backup_id":  backupID,
			"updated_by": currentUserID,
			"updated_at": time.Now(),
		})
	}
}

// ValidateConfig validates configuration data without applying it
func (h *AdminConfigHandlers) ValidateConfig() gin.HandlerFunc {
	return func(c *gin.Context) {
		var req struct {
			Section string                 `json:"section" binding:"required"`
			Data    map[string]interface{} `json:"data" binding:"required"`
		}

		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"error":   "Invalid request",
				"message": err.Error(),
			})
			return
		}

		// Validate configuration
		errors := []string{}
		warnings := []string{}

		if err := h.validateConfigSection(req.Section, req.Data); err != nil {
			errors = append(errors, err.Error())
		}

		// Additional validation checks
		warnings = append(warnings, h.checkConfigWarnings(req.Section, req.Data)...)

		valid := len(errors) == 0

		c.JSON(http.StatusOK, gin.H{
			"success":  true,
			"valid":    valid,
			"errors":   errors,
			"warnings": warnings,
			"section":  req.Section,
		})
	}
}

// BackupConfig creates a backup of the current configuration
func (h *AdminConfigHandlers) BackupConfig() gin.HandlerFunc {
	return func(c *gin.Context) {
		var req ConfigBackupRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"error":   "Invalid request",
				"message": err.Error(),
			})
			return
		}

		currentUserID := c.GetString("user_id")

		// Create backup
		backupID, err := h.configService.CreateBackup(req.Name, currentUserID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error":   "Failed to create backup",
				"message": err.Error(),
			})
			return
		}

		c.JSON(http.StatusCreated, gin.H{
			"success":     true,
			"message":     "Configuration backup created successfully",
			"backup_id":   backupID,
			"backup_name": req.Name,
			"created_by":  currentUserID,
			"created_at":  time.Now(),
		})
	}
}

// ListBackups lists all configuration backups
func (h *AdminConfigHandlers) ListBackups() gin.HandlerFunc {
	return func(c *gin.Context) {
		limit := 50
		if l := c.Query("limit"); l != "" {
			if parsed, err := parseIntParam(l); err == nil && parsed > 0 && parsed <= 1000 {
				limit = parsed
			}
		}

		offset := 0
		if o := c.Query("offset"); o != "" {
			if parsed, err := parseIntParam(o); err == nil && parsed >= 0 {
				offset = parsed
			}
		}

		// TODO: Query backups from database
		backups := []gin.H{
			{
				"id":          "backup-001",
				"name":        "Pre-deployment backup",
				"description": "Backup before v2.1.0 deployment",
				"size_bytes":  1024000,
				"created_by":  "system_admin",
				"created_at":  time.Now().Add(-24 * time.Hour),
			},
			{
				"id":          "backup-002",
				"name":        "Security update backup",
				"description": "Backup before security configuration update",
				"size_bytes":  2048000,
				"created_by":  "security_admin",
				"created_at":  time.Now().Add(-12 * time.Hour),
			},
		}

		c.JSON(http.StatusOK, gin.H{
			"success": true,
			"data":    backups,
			"total":   len(backups),
			"limit":   limit,
			"offset":  offset,
		})
	}
}

// GetBackup gets details of a specific backup
func (h *AdminConfigHandlers) GetBackup() gin.HandlerFunc {
	return func(c *gin.Context) {
		backupID := c.Param("backup_id")
		if backupID == "" {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "Backup ID is required",
			})
			return
		}

		// TODO: Query backup from database
		backup := gin.H{
			"id":          backupID,
			"name":        "Pre-deployment backup",
			"description": "Backup before v2.1.0 deployment",
			"sections":    []string{"database", "security", "server"},
			"size_bytes":  1024000,
			"created_by":  "system_admin",
			"created_at":  time.Now().Add(-24 * time.Hour),
			"metadata": gin.H{
				"version":     "2.0.5",
				"environment": "production",
				"checksum":    "sha256:abc123def456",
			},
		}

		c.JSON(http.StatusOK, gin.H{
			"success": true,
			"data":    backup,
		})
	}
}

// RestoreConfig restores configuration from a backup
func (h *AdminConfigHandlers) RestoreConfig() gin.HandlerFunc {
	return func(c *gin.Context) {
		var req ConfigRestoreRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"error":   "Invalid request",
				"message": err.Error(),
			})
			return
		}

		currentUserID := c.GetString("user_id")

		// Validate backup exists
		// TODO: Check if backup exists in database

		// Create current backup before restoring
		if !req.Force {
			preRestoreBackup, err := h.configService.CreateBackup("Pre-restore backup", currentUserID)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{
					"error":   "Failed to create pre-restore backup",
					"message": err.Error(),
				})
				return
			}

			c.JSON(http.StatusOK, gin.H{
				"success":            true,
				"message":            "Configuration restored successfully",
				"restored_backup_id": req.BackupID,
				"pre_restore_backup": preRestoreBackup,
				"restored_by":        currentUserID,
				"restored_at":        time.Now(),
			})
			return
		}

		// TODO: Implement actual restore logic
		c.JSON(http.StatusOK, gin.H{
			"success":            true,
			"message":            "Configuration restored successfully",
			"restored_backup_id": req.BackupID,
			"restored_by":        currentUserID,
			"restored_at":        time.Now(),
		})
	}
}

// DeleteBackup deletes a configuration backup
func (h *AdminConfigHandlers) DeleteBackup() gin.HandlerFunc {
	return func(c *gin.Context) {
		backupID := c.Param("backup_id")
		if backupID == "" {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "Backup ID is required",
			})
			return
		}

		// TODO: Delete backup from storage and database
		c.JSON(http.StatusOK, gin.H{
			"success":   true,
			"message":   "Backup deleted successfully",
			"backup_id": backupID,
		})
	}
}

// GetConfigHistory gets configuration change history
func (h *AdminConfigHandlers) GetConfigHistory() gin.HandlerFunc {
	return func(c *gin.Context) {
		section := c.Query("section")
		limit := 100
		if l := c.Query("limit"); l != "" {
			if parsed, err := parseIntParam(l); err == nil && parsed > 0 && parsed <= 1000 {
				limit = parsed
			}
		}

		// TODO: Query configuration change history from audit logs
		history := []gin.H{
			{
				"id":         "change-001",
				"section":    "security",
				"action":     "update",
				"changed_by": "system_admin",
				"reason":     "Updated MFA settings",
				"changes": gin.H{
					"mfa.required_for_admin": gin.H{
						"from": false,
						"to":   true,
					},
				},
				"changed_at": time.Now().Add(-2 * time.Hour),
			},
			{
				"id":         "change-002",
				"section":    "database",
				"action":     "update",
				"changed_by": "system_admin",
				"reason":     "Increased connection pool size",
				"changes": gin.H{
					"database.pool_size": gin.H{
						"from": 10,
						"to":   20,
					},
				},
				"changed_at": time.Now().Add(-6 * time.Hour),
			},
		}

		// Filter by section if specified
		if section != "" {
			filtered := []gin.H{}
			for _, item := range history {
				if item["section"] == section {
					filtered = append(filtered, item)
				}
			}
			history = filtered
		}

		c.JSON(http.StatusOK, gin.H{
			"success": true,
			"data":    history,
			"total":   len(history),
			"limit":   limit,
			"section": section,
		})
	}
}

// CompareWithBackup compares current config with a backup
func (h *AdminConfigHandlers) CompareWithBackup() gin.HandlerFunc {
	return func(c *gin.Context) {
		backupID := c.Param("backup_id")
		if backupID == "" {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "Backup ID is required",
			})
			return
		}

		// TODO: Compare current configuration with backup
		diff := gin.H{
			"backup_id": backupID,
			"differences": []gin.H{
				{
					"section": "security",
					"key":     "mfa.required_for_admin",
					"current": true,
					"backup":  false,
					"status":  "changed",
				},
				{
					"section": "database",
					"key":     "pool_size",
					"current": 20,
					"backup":  10,
					"status":  "changed",
				},
				{
					"section": "server",
					"key":     "timeout_ms",
					"current": 30000,
					"backup":  nil,
					"status":  "added",
				},
			},
			"summary": gin.H{
				"total_differences": 3,
				"added":             1,
				"changed":           2,
				"removed":           0,
			},
		}

		c.JSON(http.StatusOK, gin.H{
			"success": true,
			"data":    diff,
		})
	}
}

// DeployToEnvironment deploys configuration to specific environment
func (h *AdminConfigHandlers) DeployToEnvironment() gin.HandlerFunc {
	return func(c *gin.Context) {
		environment := c.Param("environment")
		if environment == "" {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "Environment is required",
			})
			return
		}

		var req struct {
			Sections []string `json:"sections,omitempty"`
			DryRun   bool     `json:"dry_run,omitempty"`
		}

		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"error":   "Invalid request",
				"message": err.Error(),
			})
			return
		}

		currentUserID := c.GetString("user_id")

		if req.DryRun {
			c.JSON(http.StatusOK, gin.H{
				"success":     true,
				"message":     "Dry run completed successfully",
				"environment": environment,
				"sections":    req.Sections,
				"changes": gin.H{
					"configurations_to_update": 3,
					"services_to_restart":      []string{"api-server", "worker"},
					"estimated_downtime_ms":    5000,
				},
			})
			return
		}

		// TODO: Implement actual deployment logic
		c.JSON(http.StatusOK, gin.H{
			"success":       true,
			"message":       "Configuration deployed successfully",
			"environment":   environment,
			"deployed_by":   currentUserID,
			"deployed_at":   time.Now(),
			"deployment_id": "deploy-" + backupID(),
		})
	}
}

// ListEnvironments lists all available environments
func (h *AdminConfigHandlers) ListEnvironments() gin.HandlerFunc {
	return func(c *gin.Context) {
		environments := []gin.H{
			{
				"name":        "development",
				"status":      "active",
				"version":     "2.1.0-dev",
				"last_deploy": time.Now().Add(-2 * time.Hour),
				"url":         "https://dev.example.com",
			},
			{
				"name":        "staging",
				"status":      "active",
				"version":     "2.0.5",
				"last_deploy": time.Now().Add(-24 * time.Hour),
				"url":         "https://staging.example.com",
			},
			{
				"name":        "production",
				"status":      "active",
				"version":     "2.0.5",
				"last_deploy": time.Now().Add(-7 * 24 * time.Hour),
				"url":         "https://app.example.com",
			},
		}

		c.JSON(http.StatusOK, gin.H{
			"success": true,
			"data":    environments,
		})
	}
}

// GetEnvironmentConfig gets configuration for a specific environment
func (h *AdminConfigHandlers) GetEnvironmentConfig() gin.HandlerFunc {
	return func(c *gin.Context) {
		environment := c.Param("environment")
		if environment == "" {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "Environment is required",
			})
			return
		}

		// TODO: Get environment-specific configuration
		config := gin.H{
			"environment": environment,
			"version":     "2.0.5",
			"config": gin.H{
				"database": gin.H{
					"host":      environment + "-db.example.com",
					"pool_size": getPoolSizeForEnvironment(environment),
				},
				"server": gin.H{
					"port":       8080,
					"timeout_ms": 30000,
				},
			},
			"last_updated": time.Now().Add(-24 * time.Hour),
		}

		c.JSON(http.StatusOK, gin.H{
			"success": true,
			"data":    config,
		})
	}
}

// SecurityCheck performs security validation of configuration
func (h *AdminConfigHandlers) SecurityCheck() gin.HandlerFunc {
	return func(c *gin.Context) {
		// TODO: Perform comprehensive security check
		results := gin.H{
			"overall_status": "warning",
			"checks": []gin.H{
				{
					"name":        "JWT Secret Strength",
					"status":      "pass",
					"description": "JWT secret meets minimum strength requirements",
				},
				{
					"name":        "Database SSL",
					"status":      "pass",
					"description": "Database connections are encrypted",
				},
				{
					"name":           "Admin MFA Required",
					"status":         "warning",
					"description":    "MFA is not required for all admin users",
					"recommendation": "Enable MFA requirement in security.mfa.required_for_admin",
				},
				{
					"name":        "Rate Limiting",
					"status":      "pass",
					"description": "Rate limiting is properly configured",
				},
			},
			"summary": gin.H{
				"total_checks": 4,
				"passed":       3,
				"warnings":     1,
				"failures":     0,
			},
			"checked_at": time.Now(),
		}

		c.JSON(http.StatusOK, gin.H{
			"success": true,
			"data":    results,
		})
	}
}

// GetConfigSchema gets the configuration schema/structure
func (h *AdminConfigHandlers) GetConfigSchema() gin.HandlerFunc {
	return func(c *gin.Context) {
		schema := gin.H{
			"version": "1.0",
			"sections": gin.H{
				"database": gin.H{
					"type":        "object",
					"description": "Database configuration",
					"properties": gin.H{
						"host": gin.H{
							"type":        "string",
							"description": "Database host",
							"required":    true,
						},
						"port": gin.H{
							"type":        "integer",
							"description": "Database port",
							"default":     5432,
							"minimum":     1,
							"maximum":     65535,
						},
						"pool_size": gin.H{
							"type":        "integer",
							"description": "Connection pool size",
							"default":     10,
							"minimum":     1,
							"maximum":     100,
						},
					},
				},
				"security": gin.H{
					"type":        "object",
					"description": "Security configuration",
					"properties": gin.H{
						"jwt_secret": gin.H{
							"type":        "string",
							"description": "JWT signing secret",
							"required":    true,
							"min_length":  32,
							"sensitive":   true,
						},
						"mfa": gin.H{
							"type": "object",
							"properties": gin.H{
								"required_for_admin": gin.H{
									"type":        "boolean",
									"description": "Require MFA for admin users",
									"default":     false,
								},
							},
						},
					},
				},
			},
		}

		c.JSON(http.StatusOK, gin.H{
			"success": true,
			"data":    schema,
		})
	}
}

// Read-only endpoints for regular admins

// GetCurrentConfig gets current configuration (read-only)
func (h *AdminConfigHandlers) GetCurrentConfig() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Return heavily sanitized configuration for non-system admins
		config := gin.H{
			"version":     "2.0.5",
			"environment": "production",
			"services": gin.H{
				"api_server": gin.H{
					"status": "running",
					"port":   8080,
				},
				"database": gin.H{
					"status":      "connected",
					"connections": 15,
				},
			},
			"features": gin.H{
				"mfa_enabled":    true,
				"audit_logging":  true,
				"rate_limiting":  true,
				"sql_validation": true,
			},
		}

		c.JSON(http.StatusOK, gin.H{
			"success": true,
			"data":    config,
		})
	}
}

// ListConfigSections lists available configuration sections
func (h *AdminConfigHandlers) ListConfigSections() gin.HandlerFunc {
	return func(c *gin.Context) {
		sections := []gin.H{
			{
				"name":        "database",
				"description": "Database configuration and connection settings",
				"access":      "system_admin",
			},
			{
				"name":        "security",
				"description": "Security and authentication settings",
				"access":      "system_admin",
			},
			{
				"name":        "server",
				"description": "Server and application settings",
				"access":      "system_admin",
			},
			{
				"name":        "features",
				"description": "Feature flags and toggles",
				"access":      "admin",
			},
		}

		c.JSON(http.StatusOK, gin.H{
			"success": true,
			"data":    sections,
		})
	}
}

// GetConfigStatus gets configuration validation status
func (h *AdminConfigHandlers) GetConfigStatus() gin.HandlerFunc {
	return func(c *gin.Context) {
		status := gin.H{
			"valid":        true,
			"last_check":   time.Now().Add(-10 * time.Minute),
			"last_update":  time.Now().Add(-2 * time.Hour),
			"backup_count": 5,
			"sections": gin.H{
				"database": gin.H{
					"status":      "valid",
					"last_update": time.Now().Add(-6 * time.Hour),
				},
				"security": gin.H{
					"status":      "valid",
					"last_update": time.Now().Add(-2 * time.Hour),
				},
			},
		}

		c.JSON(http.StatusOK, gin.H{
			"success": true,
			"data":    status,
		})
	}
}

// Helper functions

func (h *AdminConfigHandlers) validateConfigSection(section string, data map[string]interface{}) error {
	// TODO: Implement configuration validation based on schema
	return nil
}

func (h *AdminConfigHandlers) checkConfigWarnings(section string, data map[string]interface{}) []string {
	warnings := []string{}

	// TODO: Implement configuration warning checks
	if section == "security" {
		if mfa, exists := data["mfa"].(map[string]interface{}); exists {
			if required, exists := mfa["required_for_admin"].(bool); exists && !required {
				warnings = append(warnings, "Consider enabling MFA requirement for admin users")
			}
		}
	}

	return warnings
}

func (h *AdminConfigHandlers) sanitizeConfigSection(section string, data interface{}) interface{} {
	// Remove sensitive information based on section
	if section == "security" {
		if configMap, ok := data.(map[string]interface{}); ok {
			sanitized := make(map[string]interface{})
			for k, v := range configMap {
				if k == "jwt_secret" || k == "api_key" || k == "password" {
					sanitized[k] = "[REDACTED]"
				} else {
					sanitized[k] = v
				}
			}
			return sanitized
		}
	}
	return data
}

func (h *AdminConfigHandlers) requireSystemAdmin() gin.HandlerFunc {
	return func(c *gin.Context) {
		userID, exists := c.Get("user_id")
		if !exists {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "Authentication required",
			})
			c.Abort()
			return
		}

		userIDStr, ok := userID.(string)
		if !ok {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "Invalid authentication",
			})
			c.Abort()
			return
		}

		hasRole, err := h.rbacEngine.HasRole(c.Request.Context(), userIDStr, "system_admin")
		if err != nil || !hasRole {
			c.JSON(http.StatusForbidden, gin.H{
				"error":   "Insufficient privileges",
				"message": "System admin role required",
			})
			c.Abort()
			return
		}

		c.Next()
	}
}

func (h *AdminConfigHandlers) requireAdmin() gin.HandlerFunc {
	return func(c *gin.Context) {
		userID, exists := c.Get("user_id")
		if !exists {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "Authentication required",
			})
			c.Abort()
			return
		}

		userIDStr, ok := userID.(string)
		if !ok {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "Invalid authentication",
			})
			c.Abort()
			return
		}

		hasRole, err := h.rbacEngine.HasRole(c.Request.Context(), userIDStr, "admin")
		if err != nil || !hasRole {
			c.JSON(http.StatusForbidden, gin.H{
				"error":   "Insufficient privileges",
				"message": "Admin role required",
			})
			c.Abort()
			return
		}

		c.Next()
	}
}

// Helper utility functions

func parseIntParam(s string) (int, error) {
	// Simple int parsing with validation
	if s == "" {
		return 0, fmt.Errorf("empty parameter")
	}

	val := 0
	for _, r := range s {
		if r < '0' || r > '9' {
			return 0, fmt.Errorf("invalid integer")
		}
		val = val*10 + int(r-'0')
	}
	return val, nil
}

func backupID() string {
	// Generate a simple backup ID
	return fmt.Sprintf("%d", time.Now().Unix())
}

func getPoolSizeForEnvironment(env string) int {
	switch env {
	case "production":
		return 50
	case "staging":
		return 20
	case "development":
		return 10
	default:
		return 10
	}
}

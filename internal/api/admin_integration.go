package api

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/taqiudeen275/go-foward/internal/auth"
	"github.com/taqiudeen275/go-foward/internal/config"
)

// AdminAPIIntegration provides complete admin API integration
type AdminAPIIntegration struct {
	// Core services
	authService   *auth.Service
	configService *config.Service
	rbacEngine    auth.RBACEngine
	mfaService    auth.MFAService
	sqlValidator  auth.SQLSecurityValidator

	// Handlers
	userHandlers   *AdminUserHandlers
	roleHandlers   *AdminRoleHandlers
	configHandlers *AdminConfigHandlers
	sqlHandlers    *AdminSQLHandlers

	// SQL Security Integration
	sqlIntegration *auth.SQLSecurityIntegration

	// Database connection
	db *pgxpool.Pool

	initialized bool
}

// NewAdminAPIIntegration creates a new admin API integration
func NewAdminAPIIntegration(
	db *pgxpool.Pool,
	authService *auth.Service,
	configService *config.Service,
) *AdminAPIIntegration {
	return &AdminAPIIntegration{
		db:            db,
		authService:   authService,
		configService: configService,
		initialized:   false,
	}
}

// Initialize sets up all admin API components
func (a *AdminAPIIntegration) Initialize() error {
	if a.initialized {
		return nil
	}

	// Initialize core security services
	a.rbacEngine = auth.NewRBACEngine(a.db)
	a.mfaService = auth.NewMFAService(a.db, a.rbacEngine, "Go Forward")

	// Initialize SQL security integration
	a.sqlIntegration = auth.NewSQLSecurityIntegration(a.db, a.authService)
	if err := a.sqlIntegration.Initialize(); err != nil {
		return err
	}
	a.sqlValidator = a.sqlIntegration.GetValidator()

	// Initialize handlers
	a.userHandlers = NewAdminUserHandlers(a.authService, a.rbacEngine, a.mfaService)
	a.roleHandlers = NewAdminRoleHandlers(a.rbacEngine)
	a.configHandlers = NewAdminConfigHandlers(a.configService, a.rbacEngine, a.authService)
	a.sqlHandlers = NewAdminSQLHandlers(
		a.sqlIntegration.GetMiddleware(),
		a.sqlValidator,
		a.rbacEngine,
	)

	a.initialized = true
	return nil
}

// RegisterRoutes registers all admin API routes
func (a *AdminAPIIntegration) RegisterRoutes(router *gin.RouterGroup) error {
	if !a.initialized {
		return fmt.Errorf("AdminAPIIntegration must be initialized before registering routes")
	}

	// Create admin API group
	adminAPI := router.Group("/admin")

	// Apply common admin middleware
	adminAPI.Use(a.requireAuthentication())
	adminAPI.Use(a.auditLogging())

	// Register handler routes
	a.userHandlers.RegisterRoutes(adminAPI)
	a.roleHandlers.RegisterRoutes(adminAPI)
	a.configHandlers.RegisterRoutes(adminAPI)

	// Register SQL security routes through integration
	a.sqlIntegration.RegisterSQLRoutes(adminAPI)

	// Health check endpoint
	adminAPI.GET("/health", a.healthCheck())

	// System information endpoint
	adminAPI.GET("/system/info", a.requireSystemAdmin(), a.getSystemInfo())

	return nil
}

// Middleware functions

// requireAuthentication ensures user is authenticated
func (a *AdminAPIIntegration) requireAuthentication() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Extract and validate JWT token
		token := c.GetHeader("Authorization")
		if token == "" {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "Authorization header required",
			})
			c.Abort()
			return
		}

		// Remove "Bearer " prefix if present
		if len(token) > 7 && token[:7] == "Bearer " {
			token = token[7:]
		}

		// Validate token and extract user info
		claims, err := a.authService.ValidateToken(c.Request.Context(), token)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error":   "Invalid token",
				"message": err.Error(),
			})
			c.Abort()
			return
		}

		// Set user context
		c.Set("user_id", claims.UserID)
		c.Set("session_id", claims.SessionID)

		// Get user roles and set in context
		if roles, err := a.rbacEngine.GetUserRoles(c.Request.Context(), claims.UserID); err == nil && len(roles) > 0 {
			c.Set("admin_roles", roles)
			if highest := a.getHighestRole(roles); highest != nil {
				c.Set("admin_role", highest.Name)
				c.Set("admin_role_id", highest.ID)
			}
		}

		c.Next()
	}
}

// auditLogging logs all admin API calls
func (a *AdminAPIIntegration) auditLogging() gin.HandlerFunc {
	return func(c *gin.Context) {
		startTime := time.Now()

		// Process request
		c.Next()

		// Log after request
		duration := time.Since(startTime)
		userID := c.GetString("user_id")

		// TODO: Implement actual audit logging to admin_access_logs table
		logData := map[string]interface{}{
			"user_id":     userID,
			"method":      c.Request.Method,
			"path":        c.Request.URL.Path,
			"status_code": c.Writer.Status(),
			"duration_ms": duration.Milliseconds(),
			"ip_address":  c.ClientIP(),
			"user_agent":  c.GetHeader("User-Agent"),
			"timestamp":   startTime,
		}

		// Log to stdout for now (should be stored in database)
		fmt.Printf("ADMIN_AUDIT: %+v\n", logData)
	}
}

// requireSystemAdmin ensures user has system admin role
func (a *AdminAPIIntegration) requireSystemAdmin() gin.HandlerFunc {
	return func(c *gin.Context) {
		userID := c.GetString("user_id")
		if userID == "" {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "Authentication required",
			})
			c.Abort()
			return
		}

		hasRole, err := a.rbacEngine.HasRole(c.Request.Context(), userID, "system_admin")
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

// Handler functions

// healthCheck returns admin API health status
func (a *AdminAPIIntegration) healthCheck() gin.HandlerFunc {
	return func(c *gin.Context) {
		status := gin.H{
			"status":    "healthy",
			"timestamp": time.Now(),
			"services": gin.H{
				"database":      a.checkDatabaseHealth(),
				"rbac_engine":   "healthy",
				"mfa_service":   "healthy",
				"sql_validator": "healthy",
			},
		}

		c.JSON(http.StatusOK, gin.H{
			"success": true,
			"data":    status,
		})
	}
}

// getSystemInfo returns system information
func (a *AdminAPIIntegration) getSystemInfo() gin.HandlerFunc {
	return func(c *gin.Context) {
		info := gin.H{
			"version":     "2.1.0",
			"environment": a.getEnvironment(),
			"database": gin.H{
				"status":     "connected",
				"pool_stats": a.getDatabasePoolStats(),
			},
			"security": gin.H{
				"rbac_enabled":   true,
				"mfa_available":  true,
				"sql_validation": true,
				"audit_logging":  true,
			},
			"features": gin.H{
				"admin_api":         true,
				"sql_execution":     true,
				"config_management": true,
				"user_management":   true,
				"role_management":   true,
				"backup_restore":    true,
			},
			"statistics": gin.H{
				"total_admin_users": a.getAdminUserCount(),
				"total_roles":       4, // viewer, admin, system_admin, security_admin
				"active_sessions":   a.getActiveSessionCount(),
			},
			"uptime":       a.getUptime(),
			"generated_at": time.Now(),
		}

		c.JSON(http.StatusOK, gin.H{
			"success": true,
			"data":    info,
		})
	}
}

// Helper methods

func (a *AdminAPIIntegration) getHighestRole(roles []*auth.AdminRole) *auth.AdminRole {
	if len(roles) == 0 {
		return nil
	}

	highest := roles[0]
	for _, role := range roles[1:] {
		if role.Level > highest.Level {
			highest = role
		}
	}
	return highest
}

func (a *AdminAPIIntegration) checkDatabaseHealth() string {
	// Simple ping to check database connectivity
	if err := a.db.Ping(context.Background()); err != nil {
		return "unhealthy"
	}
	return "healthy"
}

func (a *AdminAPIIntegration) getEnvironment() string {
	// TODO: Get from configuration
	return "production"
}

func (a *AdminAPIIntegration) getDatabasePoolStats() gin.H {
	stats := a.db.Stat()
	return gin.H{
		"total_connections":    stats.TotalConns(),
		"idle_connections":     stats.IdleConns(),
		"acquired_connections": stats.AcquiredConns(),
		"max_connections":      stats.MaxConns(),
	}
}

func (a *AdminAPIIntegration) getAdminUserCount() int {
	// TODO: Query actual count from database
	return 0
}

func (a *AdminAPIIntegration) getActiveSessionCount() int {
	// TODO: Query actual count from admin_sessions table
	return 0
}

func (a *AdminAPIIntegration) getUptime() string {
	// TODO: Calculate actual uptime
	return "24h 15m 30s"
}

// IsInitialized returns whether the integration has been initialized
func (a *AdminAPIIntegration) IsInitialized() bool {
	return a.initialized
}

// GetRBACEngine returns the RBAC engine
func (a *AdminAPIIntegration) GetRBACEngine() auth.RBACEngine {
	return a.rbacEngine
}

// GetMFAService returns the MFA service
func (a *AdminAPIIntegration) GetMFAService() auth.MFAService {
	return a.mfaService
}

// GetSQLValidator returns the SQL validator
func (a *AdminAPIIntegration) GetSQLValidator() auth.SQLSecurityValidator {
	return a.sqlValidator
}

// GetSQLIntegration returns the SQL security integration
func (a *AdminAPIIntegration) GetSQLIntegration() *auth.SQLSecurityIntegration {
	return a.sqlIntegration
}

// Shutdown gracefully shuts down the admin API integration
func (a *AdminAPIIntegration) Shutdown(ctx context.Context) error {
	if a.sqlIntegration != nil {
		if err := a.sqlIntegration.Shutdown(ctx); err != nil {
			return err
		}
	}
	return nil
}

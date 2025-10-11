package server

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/taqiudeen275/go-foward/internal/config"
)

// Start initializes and starts the HTTP server
func Start() {
	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	// Initialize logger
	logger.Init(logger.LogLevel(cfg.Logging.Level))
	appLogger := logger.GetLogger()

	appLogger.Info("Starting Unified Go Forward Framework",
		"version", "1.0.0",
		"environment", cfg.Environment,
		"host", cfg.Server.Host,
		"port", cfg.Server.Port,
	)

	// Validate configuration
	if result := config.ValidateConfig(cfg); !result.Valid {
		appLogger.Error("Configuration validation failed", "errors", result.Errors)
		os.Exit(1)
	}

	if len(result.Warnings) > 0 {
		appLogger.Warn("Configuration warnings", "warnings", result.Warnings)
	}

	// Initialize Gin router
	router := setupRouter(cfg)

	// Create HTTP server with configuration
	srv := &http.Server{
		Addr:           fmt.Sprintf("%s:%d", cfg.Server.Host, cfg.Server.Port),
		Handler:        router,
		ReadTimeout:    cfg.Server.ReadTimeout,
		WriteTimeout:   cfg.Server.WriteTimeout,
		IdleTimeout:    cfg.Server.IdleTimeout,
		MaxHeaderBytes: cfg.Server.MaxHeaderBytes,
	}

	// Start server in a goroutine
	go func() {
		appLogger.Info("Server starting",
			"address", srv.Addr,
			"dashboard_url", fmt.Sprintf("http://%s:%d%s/", cfg.Server.Host, cfg.Server.Port, cfg.Admin.DashboardPrefix),
		)

		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			appLogger.Error("Failed to start server", "error", err)
			os.Exit(1)
		}
	}()

	// Wait for interrupt signal to gracefully shutdown
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	appLogger.Info("Shutting down server...")

	// Graceful shutdown with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		appLogger.Error("Server forced to shutdown", "error", err)
		os.Exit(1)
	}

	appLogger.Info("Server exited gracefully")
}

// setupRouter configures the Gin router with all routes and middleware
func setupRouter(cfg *config.Config) *gin.Engine {
	// Set Gin mode based on environment
	if cfg.Environment == "production" {
		gin.SetMode(gin.ReleaseMode)
	}

	router := gin.New()

	// Add basic middleware
	router.Use(gin.Logger())
	router.Use(gin.Recovery())

	// Health check endpoint
	router.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"status":    "healthy",
			"timestamp": time.Now().UTC(),
			"version":   "1.0.0",
		})
	})

	// API routes (will be expanded in later tasks)
	api := router.Group("/api")
	{
		api.GET("/", func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{
				"message": "Unified Go Forward Framework API",
				"version": "1.0.0",
			})
		})
	}

	// Admin dashboard routes (configurable prefix)
	admin := router.Group(cfg.Admin.DashboardPrefix)
	{
		admin.GET("/", func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{
				"message": "Admin Dashboard",
				"note":    "Dashboard will be embedded in later tasks",
				"prefix":  cfg.Admin.DashboardPrefix,
			})
		})

		// Configuration reflection endpoint
		admin.GET("/config/reflection", func(c *gin.Context) {
			reflection := config.GetReflection()
			c.JSON(http.StatusOK, reflection)
		})

		// Configuration validation endpoint
		admin.GET("/config/validate", func(c *gin.Context) {
			result := config.ValidateConfig(cfg)
			c.JSON(http.StatusOK, result)
		})
	}

	return router
}

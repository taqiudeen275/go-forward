package gateway

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/taqiudeen275/go-foward/internal/config"
	"github.com/taqiudeen275/go-foward/pkg/logger"
)

// ServiceHandler represents a service that can be registered with the gateway
type ServiceHandler interface {
	RegisterRoutes(router gin.IRouter)
	Name() string
}

// Gateway represents the API gateway
type Gateway struct {
	config     *config.Config
	router     *gin.Engine
	logger     logger.Logger
	server     *http.Server
	services   map[string]ServiceHandler
	middleware []gin.HandlerFunc
	mu         sync.RWMutex
}

// New creates a new API gateway instance
func New(cfg *config.Config, logger logger.Logger) *Gateway {
	// Set gin mode based on log level
	if cfg.Server.LogLevel == "debug" {
		gin.SetMode(gin.DebugMode)
	} else {
		gin.SetMode(gin.ReleaseMode)
	}

	router := gin.New()

	return &Gateway{
		config:     cfg,
		router:     router,
		logger:     logger,
		services:   make(map[string]ServiceHandler),
		middleware: make([]gin.HandlerFunc, 0),
	}
}

// RegisterService registers a service with the gateway
func (g *Gateway) RegisterService(service ServiceHandler) error {
	g.mu.Lock()
	defer g.mu.Unlock()

	name := service.Name()
	if _, exists := g.services[name]; exists {
		return fmt.Errorf("service %s already registered", name)
	}

	g.services[name] = service
	g.logger.Info("Registered service: %s", name)

	return nil
}

// AddMiddleware adds middleware to the gateway
func (g *Gateway) AddMiddleware(middleware gin.HandlerFunc) {
	g.mu.Lock()
	defer g.mu.Unlock()

	g.middleware = append(g.middleware, middleware)
}

// setupMiddleware sets up all middleware
func (g *Gateway) setupMiddleware() {
	// Built-in middleware
	g.router.Use(gin.Recovery())
	g.router.Use(g.loggingMiddleware())

	// Custom middleware
	for _, middleware := range g.middleware {
		g.router.Use(middleware)
	}
}

// setupRoutes sets up all routes including health checks and service routes
func (g *Gateway) setupRoutes() {
	// Health check endpoints
	g.setupHealthRoutes()

	// Register service routes
	g.mu.RLock()
	for name, service := range g.services {
		g.logger.Info("Setting up routes for service: %s", name)
		service.RegisterRoutes(g.router)
	}
	g.mu.RUnlock()
}

// setupHealthRoutes sets up health check endpoints
func (g *Gateway) setupHealthRoutes() {
	health := g.router.Group("/health")
	{
		health.GET("", g.healthCheck)
		health.GET("/ready", g.readinessCheck)
		health.GET("/live", g.livenessCheck)
	}
}

// Start starts the API gateway server
func (g *Gateway) Start() error {
	// Setup middleware and routes
	g.setupMiddleware()
	g.setupRoutes()

	// Create HTTP server
	g.server = &http.Server{
		Addr:         fmt.Sprintf("%s:%d", g.config.Server.Host, g.config.Server.Port),
		Handler:      g.router,
		ReadTimeout:  g.config.Server.ReadTimeout,
		WriteTimeout: g.config.Server.WriteTimeout,
	}

	// Start server in a goroutine
	go func() {
		g.logger.Info("Starting API gateway on %s", g.server.Addr)
		if err := g.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			g.logger.Error("Failed to start server: %v", err)
		}
	}()

	// Wait for interrupt signal to gracefully shutdown
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	g.logger.Info("Shutting down API gateway...")

	// Graceful shutdown with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	return g.server.Shutdown(ctx)
}

// Stop stops the API gateway server
func (g *Gateway) Stop() error {
	if g.server == nil {
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	return g.server.Shutdown(ctx)
}

// GetRouter returns the gin router for advanced configuration
func (g *Gateway) GetRouter() *gin.Engine {
	return g.router
}

// Setup initializes middleware and routes (useful for testing)
func (g *Gateway) Setup() {
	g.setupMiddleware()
	g.setupRoutes()
}

// loggingMiddleware provides request logging
func (g *Gateway) loggingMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		path := c.Request.URL.Path
		raw := c.Request.URL.RawQuery

		// Process request
		c.Next()

		// Calculate latency
		latency := time.Since(start)

		// Get client IP
		clientIP := c.ClientIP()

		// Get status code
		statusCode := c.Writer.Status()

		// Get request size
		bodySize := c.Writer.Size()

		// Build query string
		if raw != "" {
			path = path + "?" + raw
		}

		// Log request
		g.logger.Info("Request: %s %s %d %v %s %d",
			c.Request.Method,
			path,
			statusCode,
			latency,
			clientIP,
			bodySize,
		)
	}
}

// healthCheck handles basic health check
func (g *Gateway) healthCheck(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"status":    "ok",
		"timestamp": time.Now().UTC(),
		"version":   "1.0.0",
		"services":  g.getServiceNames(),
	})
}

// readinessCheck handles readiness probe
func (g *Gateway) readinessCheck(c *gin.Context) {
	// Check if all services are ready
	// For now, just return ok if gateway is running
	c.JSON(http.StatusOK, gin.H{
		"status": "ready",
		"checks": gin.H{
			"gateway": "ok",
		},
	})
}

// livenessCheck handles liveness probe
func (g *Gateway) livenessCheck(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"status": "alive",
	})
}

// getServiceNames returns a list of registered service names
func (g *Gateway) getServiceNames() []string {
	g.mu.RLock()
	defer g.mu.RUnlock()

	names := make([]string, 0, len(g.services))
	for name := range g.services {
		names = append(names, name)
	}
	return names
}

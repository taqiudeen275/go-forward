package server

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/taqiudeen275/go-foward/internal/config"
	"github.com/taqiudeen275/go-foward/internal/database"
)

func TestServer_Integration(t *testing.T) {
	// Skip integration test if no database is available
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	// Create test configuration
	cfg := &config.Config{
		Server: config.ServerConfig{
			Host:         "localhost",
			Port:         0, // Use random port for testing
			ReadTimeout:  5 * time.Second,
			WriteTimeout: 5 * time.Second,
			LogLevel:     "debug",
			CORS: config.CORSConfig{
				AllowedOrigins: []string{"*"},
				AllowedMethods: []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
				AllowedHeaders: []string{"*"},
			},
			RateLimit: config.RateLimitConfig{
				Enabled:           false, // Disable for testing
				RequestsPerMinute: 100,
				BurstSize:         10,
				CleanupInterval:   time.Minute,
			},
		},
		Database: config.DatabaseConfig{
			Host:         "localhost",
			Port:         5432,
			Name:         "test_goforward",
			User:         "postgres",
			Password:     "password",
			SSLMode:      "disable",
			MaxConns:     5,
			MaxIdleConns: 2,
			MaxLifetime:  time.Hour,
		},
		Storage: config.StorageConfig{
			Provider:    "local",
			LocalPath:   "./test_storage",
			MaxFileSize: 10 * 1024 * 1024,
		},
	}

	// Try to create database connection (skip test if not available)
	dbConfig := &database.Config{
		Host:            cfg.Database.Host,
		Port:            cfg.Database.Port,
		Name:            cfg.Database.Name,
		User:            cfg.Database.User,
		Password:        cfg.Database.Password,
		SSLMode:         cfg.Database.SSLMode,
		MaxConns:        int32(cfg.Database.MaxConns),
		MinConns:        2,
		MaxConnLifetime: cfg.Database.MaxLifetime,
		MaxConnIdleTime: 30 * time.Minute,
	}

	db, err := database.New(dbConfig)
	if err != nil {
		t.Skipf("Skipping integration test - database not available: %v", err)
	}
	defer db.Close()

	// Create server
	server := New(cfg, db)
	require.NotNil(t, server)

	// Test that server can be created without errors
	assert.NotNil(t, server.config)
	assert.NotNil(t, server.logger)
	assert.NotNil(t, server.db)
	assert.NotNil(t, server.gateway)
	assert.NotNil(t, server.authService)
	assert.NotNil(t, server.authHandler)
	assert.NotNil(t, server.realtimeService)
	assert.NotNil(t, server.realtimeHandlers)
	assert.NotNil(t, server.storageService)
	assert.NotNil(t, server.storageHandlers)
	assert.NotNil(t, server.metaService)
}

func TestServer_HealthEndpoints(t *testing.T) {
	// Create minimal configuration for testing
	cfg := &config.Config{
		Server: config.ServerConfig{
			Host:         "localhost",
			Port:         0,
			ReadTimeout:  5 * time.Second,
			WriteTimeout: 5 * time.Second,
			LogLevel:     "debug",
			CORS: config.CORSConfig{
				AllowedOrigins: []string{"*"},
				AllowedMethods: []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
				AllowedHeaders: []string{"*"},
			},
			RateLimit: config.RateLimitConfig{
				Enabled: false,
			},
		},
		Storage: config.StorageConfig{
			Provider:  "local",
			LocalPath: "./test_storage",
		},
	}

	// Create mock database for testing
	db := &database.DB{} // This is a minimal mock for testing

	// Create server
	server := New(cfg, db)
	require.NotNil(t, server)

	// Setup middleware and register services
	server.setupMiddleware()
	server.registerServices()

	// Setup gateway (this is normally done in Start())
	server.gateway.Setup()

	// Get the router for testing
	router := server.gateway.GetRouter()
	require.NotNil(t, router)

	// Test health endpoints by checking if they're registered
	routes := router.Routes()

	healthRoutes := []string{"/health", "/health/ready", "/health/live"}
	foundRoutes := make(map[string]bool)

	for _, route := range routes {
		for _, healthRoute := range healthRoutes {
			if route.Path == healthRoute && route.Method == "GET" {
				foundRoutes[healthRoute] = true
			}
		}
	}

	// Verify all health routes are registered
	for _, route := range healthRoutes {
		assert.True(t, foundRoutes[route], "Health route %s should be registered", route)
	}
}

func TestServer_ServiceRegistration(t *testing.T) {
	// Create minimal configuration
	cfg := &config.Config{
		Server: config.ServerConfig{
			LogLevel: "debug",
			CORS: config.CORSConfig{
				AllowedOrigins: []string{"*"},
			},
			RateLimit: config.RateLimitConfig{
				Enabled: false,
			},
		},
		Storage: config.StorageConfig{
			Provider:  "local",
			LocalPath: "./test_storage",
		},
	}

	// Create mock database
	db := &database.DB{}

	// Create server
	server := New(cfg, db)
	require.NotNil(t, server)

	// Test that services are properly initialized
	assert.NotNil(t, server.authHandler, "Auth handler should be initialized")
	assert.NotNil(t, server.realtimeHandlers, "Realtime handlers should be initialized")
	assert.NotNil(t, server.storageHandlers, "Storage handlers should be initialized")

	// Test service registration
	server.registerServices()

	// Setup gateway to actually register routes
	server.gateway.Setup()

	// Verify services are registered with gateway
	router := server.gateway.GetRouter()
	routes := router.Routes()

	// Should have routes from registered services
	assert.Greater(t, len(routes), 0, "Should have registered routes from services")
}

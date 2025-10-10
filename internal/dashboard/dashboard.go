package dashboard

import (
	"github.com/gin-gonic/gin"
	"github.com/taqiudeen275/go-foward/internal/dashboard/embed"
)

// Config holds dashboard configuration
type Config struct {
	Enabled  bool   `yaml:"enabled" json:"enabled"`
	BasePath string `yaml:"base_path" json:"base_path"`
	DevMode  bool   `yaml:"dev_mode" json:"dev_mode"`
	DevURL   string `yaml:"dev_url" json:"dev_url"`
}

// DefaultConfig returns default dashboard configuration
func DefaultConfig() Config {
	return Config{
		Enabled:  true,
		BasePath: "/admin",
		DevMode:  false,
		DevURL:   "http://localhost:5173",
	}
}

// Setup configures the admin dashboard routes
func Setup(router *gin.Engine, config Config) error {
	if !config.Enabled {
		return nil
	}

	// Create dashboard service
	service := NewService(embed.StaticAssets, config.BasePath)

	// Setup routes under the configured base path
	dashboardGroup := router.Group(config.BasePath)
	service.SetupRoutes(dashboardGroup)

	return nil
}

// SetupWithAuth configures the admin dashboard with authentication middleware
func SetupWithAuth(router *gin.Engine, config Config, authMiddleware gin.HandlerFunc) error {
	if !config.Enabled {
		return nil
	}

	// Create dashboard service
	service := NewService(embed.StaticAssets, config.BasePath)

	// Setup routes under the configured base path with auth
	dashboardGroup := router.Group(config.BasePath)
	dashboardGroup.Use(authMiddleware)
	service.SetupRoutes(dashboardGroup)

	return nil
}

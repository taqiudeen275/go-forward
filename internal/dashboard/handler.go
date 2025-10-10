package dashboard

import (
	"github.com/gin-gonic/gin"
	"github.com/taqiudeen275/go-foward/internal/dashboard/embed"
)

// Handler implements the ServiceHandler interface for the gateway
type Handler struct {
	service *Service
	config  Config
}

// NewHandler creates a new dashboard handler
func NewHandler(config Config) *Handler {
	service := NewService(embed.StaticAssets, config.BasePath)
	return &Handler{
		service: service,
		config:  config,
	}
}

// Name returns the service name for the gateway
func (h *Handler) Name() string {
	return "dashboard"
}

// RegisterRoutes registers the dashboard routes with the gateway
func (h *Handler) RegisterRoutes(router gin.IRouter) {
	if !h.config.Enabled {
		return
	}

	// Create dashboard group under the configured base path
	dashboardGroup := router.Group(h.config.BasePath)

	// Setup routes with the service
	h.service.SetupRoutes(dashboardGroup)
}

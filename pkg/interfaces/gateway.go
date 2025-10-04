package interfaces

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// Gateway defines the API gateway interface
type Gateway interface {
	RegisterService(name string, handler http.Handler)
	RegisterServiceWithPrefix(name string, prefix string, handler http.Handler)
	AddMiddleware(middleware gin.HandlerFunc)
	AddGlobalMiddleware(middleware gin.HandlerFunc)
	Start(port string) error
	Stop() error
	GetRouter() *gin.Engine
	GetRegisteredServices() map[string]ServiceInfo
}

// Middleware defines interface for custom middleware
type Middleware interface {
	Handle() gin.HandlerFunc
	GetName() string
	GetPriority() int
}

// ServiceInfo represents registered service information
type ServiceInfo struct {
	Name    string      `json:"name"`
	Prefix  string      `json:"prefix"`
	Handler string      `json:"handler"`
	Routes  []RouteInfo `json:"routes"`
}

// RouteInfo represents route information
type RouteInfo struct {
	Method      string `json:"method"`
	Path        string `json:"path"`
	HandlerName string `json:"handler_name"`
}

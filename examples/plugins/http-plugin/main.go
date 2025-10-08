package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/taqiudeen275/go-foward/pkg/plugin"
)

// HTTPExamplePlugin is an example HTTP plugin
type HTTPExamplePlugin struct {
	*plugin.BasePlugin
	config map[string]interface{}
}

// NewHTTPExamplePlugin creates a new HTTP example plugin
func NewHTTPExamplePlugin() *HTTPExamplePlugin {
	return &HTTPExamplePlugin{
		BasePlugin: plugin.NewBasePlugin(
			"http-example",
			"1.0.0",
			"Example HTTP plugin that provides custom endpoints",
		),
	}
}

// Initialize initializes the plugin with configuration
func (p *HTTPExamplePlugin) Initialize(ctx context.Context, config map[string]interface{}) error {
	if err := p.BasePlugin.Initialize(ctx, config); err != nil {
		return err
	}

	p.config = config
	return nil
}

// Routes returns the HTTP routes provided by this plugin
func (p *HTTPExamplePlugin) Routes() []plugin.Route {
	return []plugin.Route{
		{
			Method:  "GET",
			Path:    "/api/plugin/example",
			Handler: p.handleExample,
		},
		{
			Method:  "GET",
			Path:    "/api/plugin/health",
			Handler: p.handleHealth,
		},
		{
			Method:  "POST",
			Path:    "/api/plugin/echo",
			Handler: p.handleEcho,
		},
	}
}

// Middleware returns HTTP middleware provided by this plugin
func (p *HTTPExamplePlugin) Middleware() []func(http.Handler) http.Handler {
	return []func(http.Handler) http.Handler{
		p.loggingMiddleware,
		p.corsMiddleware,
	}
}

// handleExample handles the example endpoint
func (p *HTTPExamplePlugin) handleExample(w http.ResponseWriter, r *http.Request) {
	response := map[string]interface{}{
		"message": "Hello from HTTP Example Plugin!",
		"plugin":  p.Name(),
		"version": p.Version(),
		"config":  p.config,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// handleHealth handles the health check endpoint
func (p *HTTPExamplePlugin) handleHealth(w http.ResponseWriter, r *http.Request) {
	health := map[string]interface{}{
		"status":      "healthy",
		"plugin":      p.Name(),
		"version":     p.Version(),
		"initialized": p.IsInitialized(),
		"started":     p.IsStarted(),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(health)
}

// handleEcho handles the echo endpoint
func (p *HTTPExamplePlugin) handleEcho(w http.ResponseWriter, r *http.Request) {
	var body map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	response := map[string]interface{}{
		"echo":    body,
		"plugin":  p.Name(),
		"method":  r.Method,
		"path":    r.URL.Path,
		"headers": r.Header,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// loggingMiddleware logs HTTP requests
func (p *HTTPExamplePlugin) loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Printf("[%s] %s %s %s\n", p.Name(), r.Method, r.URL.Path, r.RemoteAddr)
		next.ServeHTTP(w, r)
	})
}

// corsMiddleware adds CORS headers
func (p *HTTPExamplePlugin) corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// Plugin is the exported symbol that the plugin loader looks for
var Plugin = NewHTTPExamplePlugin()

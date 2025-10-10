package dashboard

import (
	"embed"
	"io"
	"net/http"
	"path"
	"strings"

	"github.com/gin-gonic/gin"
)

// Service handles serving the embedded admin dashboard
type Service struct {
	assets embed.FS
	prefix string
}

// NewService creates a new dashboard service
func NewService(assets embed.FS, prefix string) *Service {
	return &Service{
		assets: assets,
		prefix: strings.TrimSuffix(prefix, "/"),
	}
}

// SetupRoutes configures the dashboard routes with security middleware
func (s *Service) SetupRoutes(router *gin.RouterGroup) {
	// Apply security middleware
	router.Use(s.securityHeadersMiddleware())
	router.Use(s.cacheControlMiddleware())

	// Serve static assets - this will handle SPA routing in the handler
	router.GET("/*filepath", s.serveStaticAssets())
}

// securityHeadersMiddleware adds security headers to all dashboard responses
func (s *Service) securityHeadersMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Security headers
		c.Header("X-Content-Type-Options", "nosniff")
		c.Header("X-Frame-Options", "DENY")
		c.Header("X-XSS-Protection", "1; mode=block")
		c.Header("Referrer-Policy", "strict-origin-when-cross-origin")
		c.Header("Permissions-Policy", "geolocation=(), microphone=(), camera=()")

		// CSP for admin dashboard
		csp := "default-src 'self'; " +
			"script-src 'self' 'unsafe-inline'; " +
			"style-src 'self' 'unsafe-inline'; " +
			"img-src 'self' data: blob:; " +
			"font-src 'self'; " +
			"connect-src 'self'; " +
			"frame-ancestors 'none'; " +
			"base-uri 'self'; " +
			"form-action 'self'"
		c.Header("Content-Security-Policy", csp)

		c.Next()
	}
}

// cacheControlMiddleware sets appropriate cache headers
func (s *Service) cacheControlMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		filepath := c.Param("filepath")

		// Cache static assets (JS, CSS, images) for longer
		if isStaticAsset(filepath) {
			c.Header("Cache-Control", "public, max-age=31536000, immutable")
		} else {
			// Don't cache HTML files
			c.Header("Cache-Control", "no-cache, no-store, must-revalidate")
			c.Header("Pragma", "no-cache")
			c.Header("Expires", "0")
		}

		c.Next()
	}
}

// serveStaticAssets serves embedded static files
func (s *Service) serveStaticAssets() gin.HandlerFunc {
	return func(c *gin.Context) {
		filepath := c.Param("filepath")
		if filepath == "" || filepath == "/" {
			filepath = "/index.html"
		}

		// Clean the path to prevent directory traversal
		cleanPath := path.Clean(filepath)
		if strings.HasPrefix(cleanPath, "../") {
			c.AbortWithStatus(http.StatusForbidden)
			return
		}

		// Try to serve the file from embedded assets
		fullPath := "build" + cleanPath

		file, err := s.assets.Open(fullPath)
		if err != nil {
			// If file not found and it's not a static asset, serve index.html for SPA routing
			if !isStaticAsset(cleanPath) {
				s.serveIndexHTML(c)
				return
			}
			c.AbortWithStatus(http.StatusNotFound)
			return
		}
		defer file.Close()

		// Get file info for content type detection
		stat, err := file.Stat()
		if err != nil {
			c.AbortWithStatus(http.StatusInternalServerError)
			return
		}

		// Serve the file
		if seeker, ok := file.(io.ReadSeeker); ok {
			http.ServeContent(c.Writer, c.Request, cleanPath, stat.ModTime(), seeker)
		} else {
			c.AbortWithStatus(http.StatusInternalServerError)
		}
	}
}

// serveIndexHTML serves the main index.html file
func (s *Service) serveIndexHTML(c *gin.Context) {
	file, err := s.assets.Open("build/index.html")
	if err != nil {
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	}
	defer file.Close()

	stat, err := file.Stat()
	if err != nil {
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	}

	c.Header("Content-Type", "text/html; charset=utf-8")
	if seeker, ok := file.(io.ReadSeeker); ok {
		http.ServeContent(c.Writer, c.Request, "index.html", stat.ModTime(), seeker)
	} else {
		c.AbortWithStatus(http.StatusInternalServerError)
	}
}

// isStaticAsset checks if the path is for a static asset
func isStaticAsset(filepath string) bool {
	staticExtensions := []string{".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff", ".woff2", ".ttf", ".eot"}

	for _, ext := range staticExtensions {
		if strings.HasSuffix(strings.ToLower(filepath), ext) {
			return true
		}
	}

	// Check if it's in assets directory
	return strings.HasPrefix(filepath, "/assets/") || strings.HasPrefix(filepath, "assets/")
}
